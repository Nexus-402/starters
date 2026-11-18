//! A Nexus402 request verifier for Rust.
//!
//! Machine-checked: `../starters_test.go` builds `main.rs`, which uses this
//! file, and drives it with the gateway's REAL signer -- the hello, a paid
//! call, and forged calls that must be refused. `../field_order_test.go` also
//! reads the canonical string between the markers below.
//!
//! Needs: `ed25519-dalek`, `sha2`, `base64`, `subtle`.

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// The fixed first line of the response proof's digested bytes. Copy exactly.
pub const PROOF_DOMAIN: &str = "nexus-endpoint-proof-v1";

/// Must match the gateway's 60 seconds. Wider accepts older replays;
/// narrower rejects honest requests on ordinary clock skew.
pub const SIGNATURE_WINDOW_SECONDS: i64 = 60;

/// Lowercase hex SHA-256 of the RAW body bytes, before any JSON parse.
pub fn body_hash_hex(raw_body: &[u8]) -> String {
    let digest = Sha256::digest(raw_body);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Six fields joined by single newlines. No trailing newline.
pub fn canonical_string(
    method: &str,
    registered_host: &str,
    path_with_query: &str,
    timestamp: &str,
    correlation_id: &str,
    body_sha256_hex: &str,
) -> String {
    // nexus:canonical-begin
    [
        method,
        registered_host,
        path_with_query,
        timestamp,
        correlation_id,
        body_sha256_hex,
    ]
    .join("\n")
    // nexus:canonical-end
}

/// The value Nexus402 requires on EVERY response, including your own errors.
pub fn proof(correlation_id: &str, timestamp: &str, signature: &str) -> String {
    let message = [PROOF_DOMAIN, correlation_id, timestamp, signature].join("\n");
    let digest = Sha256::digest(message.as_bytes());
    format!("sha256:{}", URL_SAFE_NO_PAD.encode(digest))
}

pub struct Request<'a> {
    pub creator_key_header: &'a str,
    pub signature_header: &'a str,
    pub timestamp_header: &'a str,
    pub correlation_id: &'a str,
    pub raw_body: &'a [u8],
    pub method: &'a str,
    pub path_with_query: &'a str,
}

pub struct Endpoint {
    pub registered_host: String,
    pub creator_key: String,
    pub public_key_base64: String,
}

impl Endpoint {
    /// `Ok(proof)` on success; `Err(reason)` otherwise.
    pub fn verify(&self, request: &Request<'_>, now_unix_seconds: i64) -> Result<String, String> {
        // THE HELLO (ADR-0143): the publish check is a signed POST with an
        // EMPTY body and NO creator key. Answer it 200 with the proof and run
        // no tool. Only the key check is skipped; the signature is verified.
        let hello = request.raw_body.is_empty();

        // Constant time: a byte-at-a-time compare returns faster the earlier
        // it finds a difference, leaking the key one position at a time.
        let presented_key = request.creator_key_header.as_bytes();
        if !hello && presented_key.ct_eq(self.creator_key.as_bytes()).unwrap_u8() != 1 {
            return Err("creator key mismatch".into());
        }

        let seconds: i64 = request
            .timestamp_header
            .parse()
            .map_err(|_| "timestamp is not an integer".to_string())?;
        // BOTH directions. Without an upper bound a future-dated request is
        // valid forever; without a lower one a capture replays forever.
        if (now_unix_seconds - seconds).abs() > SIGNATURE_WINDOW_SECONDS {
            return Err("timestamp outside the 60-second window".into());
        }

        let encoded = request
            .signature_header
            .strip_prefix("ed25519:")
            .ok_or("signature is not ed25519:")?;
        let raw = STANDARD
            .decode(encoded)
            .map_err(|_| "signature is not base64".to_string())?;
        let bytes: [u8; 64] = raw
            .try_into()
            .map_err(|_| "signature is not 64 bytes".to_string())?;

        let key_bytes: [u8; 32] = STANDARD
            .decode(&self.public_key_base64)
            .map_err(|_| "public key is not base64".to_string())?
            .try_into()
            .map_err(|_| "public key is not 32 bytes".to_string())?;
        let key = VerifyingKey::from_bytes(&key_bytes).map_err(|error| error.to_string())?;

        let message = canonical_string(
            request.method,
            &self.registered_host,
            request.path_with_query,
            request.timestamp_header,
            request.correlation_id,
            &body_hash_hex(request.raw_body),
        );
        key.verify(message.as_bytes(), &Signature::from_bytes(&bytes))
            .map_err(|_| "signature does not verify".to_string())?;

        Ok(proof(
            request.correlation_id,
            request.timestamp_header,
            request.signature_header,
        ))
    }
}

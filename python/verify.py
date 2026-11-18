"""A Nexus402 request verifier for Python.

Machine-checked: `../starters_test.go` starts `server.py`, which uses this
file, and drives it with the gateway's REAL signer -- the hello, a paid call,
and forged calls that must be refused. `../field_order_test.go` also reads the
canonical string between the markers below.

Needs: `pip install cryptography`.
"""

from __future__ import annotations

import hashlib
import hmac
import time
import binascii
from base64 import b64decode, urlsafe_b64encode

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# The fixed first line of the response proof's digested bytes. Copy exactly.
PROOF_DOMAIN = "nexus-endpoint-proof-v1"

# Must match the gateway's 60 seconds. Wider accepts older replays; narrower
# rejects honest requests on ordinary clock skew.
SIGNATURE_WINDOW_SECONDS = 60


def body_hash_hex(raw_body: bytes) -> str:
    """Lowercase hex SHA-256 of the RAW body bytes, before any JSON parse."""
    return hashlib.sha256(raw_body).hexdigest()


def canonical_string(
    method: str,
    registered_host: str,
    path_with_query: str,
    timestamp: str,
    correlation_id: str,
    body_sha256_hex: str,
) -> str:
    """Six fields joined by single newlines. No trailing newline."""
    # nexus:canonical-begin
    return "\n".join(
        [
            method,
            registered_host,
            path_with_query,
            timestamp,
            correlation_id,
            body_sha256_hex,
        ]
    )
    # nexus:canonical-end


def proof(correlation_id: str, timestamp: str, signature: str) -> str:
    """The value Nexus402 requires on EVERY response, including your errors."""
    digest = hashlib.sha256(
        "\n".join([PROOF_DOMAIN, correlation_id, timestamp, signature]).encode("utf-8")
    ).digest()
    return "sha256:" + urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def verify_request(
    headers: dict[str, str],
    raw_body: bytes,
    method: str,
    path_with_query: str,
    registered_host: str,
    creator_key: str,
    public_key_base64: str,
    now_unix_seconds: int | None = None,
) -> tuple[bool, str]:
    """Returns (ok, proof) on success, or (False, reason)."""
    now = int(time.time()) if now_unix_seconds is None else now_unix_seconds

    # Header names are case-insensitive, and a client may send any case.
    lowered = {key.lower(): value for key, value in headers.items()}

    def header(name: str) -> str:
        return lowered.get(name.lower()) or ""

    # THE HELLO (ADR-0143): the publish check is a signed POST with an EMPTY
    # body and NO creator key. Answer it 200 with the proof and run no tool.
    # Only the key check is skipped; the signature below is still verified.
    hello = len(raw_body) == 0

    # Constant time. A byte-at-a-time `==` returns faster the earlier it finds
    # a difference, leaking the key one position at a time.
    if not hello and not hmac.compare_digest(header("X-Nexus-Creator-Key").encode(), creator_key.encode()):
        return False, "creator key mismatch"

    timestamp = header("X-Nexus-Timestamp")
    if not timestamp.isdigit():
        return False, "timestamp is not an integer"
    # BOTH directions: without an upper bound a future-dated request is valid
    # forever; without a lower one a captured request replays forever.
    if abs(now - int(timestamp)) > SIGNATURE_WINDOW_SECONDS:
        return False, "timestamp outside the 60-second window"

    presented = header("X-Nexus-Signature")
    if not presented.startswith("ed25519:"):
        return False, "signature is not ed25519:"
    try:
        signature = b64decode(presented[len("ed25519:") :], validate=True)
    except (binascii.Error, ValueError):
        return False, "signature is not base64"
    if len(signature) != 64:
        return False, "signature is not 64 bytes"

    correlation_id = header("X-Correlation-ID")
    message = canonical_string(
        method,
        registered_host,
        path_with_query,
        timestamp,
        correlation_id,
        body_hash_hex(raw_body),
    ).encode("utf-8")

    try:
        Ed25519PublicKey.from_public_bytes(b64decode(public_key_base64)).verify(
            signature, message
        )
    except (InvalidSignature, ValueError):
        return False, "signature does not verify"

    return True, proof(correlation_id, timestamp, presented)

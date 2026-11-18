// A complete Nexus402 request verifier for Node.js. NO DEPENDENCIES.
//
// Copy this file. It is not a package to import, so it can never version-skew
// against the gateway — the same reasoning as `examples/creator-pingback`.
//
// `agreement_test.go` beside this directory drives the gateway's REAL signer
// (`egress.DevSigner`, the one `cmd/gateway` uses) against this code and
// refuses to pass if the two ever disagree on the canonical string. That test
// is what makes this documentation rather than a guess: a verifier can be
// perfectly self-consistent and still disagree with the gateway, and then
// every creator who copies it gets a dead endpoint and no clue why.
//
// Two checks, and you want both. The creator key is a shared secret on your
// server; if it leaks, anyone can impersonate Nexus402 to you and take free
// tool calls. The signature is asymmetric — you hold only a public key — and
// it is also what binds a request to YOUR host and to a 60-second window, so
// losing it loses replay protection too.

import { createHash, createPublicKey, timingSafeEqual, verify } from "node:crypto";

/**
 * The fixed first line of the response proof's digested bytes.
 *
 * Copy it exactly. It is part of the contract, and it exists so this digest
 * can never be confused with another defined over the same fields.
 */
export const PROOF_DOMAIN = "nexus-endpoint-proof-v1";

/**
 * Must match the gateway's 60 seconds. Wider accepts older replays; narrower
 * rejects honest requests on ordinary clock skew.
 */
export const SIGNATURE_WINDOW_SECONDS = 60;

// An Ed25519 public key arrives as 32 raw bytes in base64. `createPublicKey`
// wants DER, and for Ed25519 the SPKI header is a fixed 12-byte prefix, so
// wrapping is a concatenation rather than a dependency.
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Wraps the 32 raw bytes Nexus402 gives you into a usable KeyObject. */
export function publicKeyFromBase64(base64) {
  const raw = Buffer.from(base64, "base64");
  if (raw.length !== 32) {
    throw new Error(`ed25519 public key must be 32 bytes, got ${raw.length}`);
  }
  return createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

/**
 * Lowercase hex SHA-256 of the RAW body bytes.
 *
 * Hash before any JSON parse or re-serialise: re-encoding changes the bytes
 * and the hash will not match.
 */
export function bodyHashHex(rawBody) {
  return createHash("sha256").update(rawBody).digest("hex");
}

/**
 * The signed message: six fields joined by single newlines, in this order.
 *
 * No trailing newline, no spaces, no carriage returns. `host` is the host you
 * REGISTERED, never the inbound `Host` header — behind a proxy or a managed
 * platform router that header may have been rewritten, and a verifier reading
 * it will then reject every valid request.
 */
export function canonicalString({
  method,
  registeredHost,
  pathWithQuery,
  timestamp,
  correlationId,
  bodySha256Hex,
}) {
  return [method, registeredHost, pathWithQuery, timestamp, correlationId, bodySha256Hex].join("\n");
}

/**
 * Constant-time string compare.
 *
 * `timingSafeEqual` throws when the lengths differ, and the throw is itself a
 * length oracle, so both sides are hashed to a fixed width first. A
 * byte-at-a-time `===` returns faster the earlier it finds a difference,
 * which leaks the key one position at a time to anyone who can measure your
 * response.
 */
export function constantTimeEquals(presented, expected) {
  const left = createHash("sha256").update(String(presented), "utf8").digest();
  const right = createHash("sha256").update(String(expected), "utf8").digest();
  return timingSafeEqual(left, right);
}

/** The value Nexus402 requires on EVERY response, including your own errors. */
export function proof({ correlationId, timestamp, signature }) {
  const digest = createHash("sha256")
    .update([PROOF_DOMAIN, correlationId, timestamp, signature].join("\n"), "utf8")
    .digest("base64url");
  return `sha256:${digest}`;
}

/**
 * Verifies one inbound request.
 *
 * Returns `{ ok: true, hello, proof }` — set that proof on your response
 * BEFORE you write the status, because once the header block is committed
 * anything set afterwards is dropped in silence. On failure,
 * `{ ok: false, reason }`.
 *
 * THE HELLO (ADR-0143). When you publish, and again when Nexus402 checks a
 * refusal of yours, it sends one signed POST with an EMPTY body and NO creator
 * key: there is no caller yet. `hello` is true for that request. Answer it
 * `200` with the proof and run no tool. The signature is still verified, so a
 * stranger cannot fake one; the key check is what is skipped, because without
 * that exception the hello is refused and you can never publish.
 */
export function verifyRequest({
  headers,
  rawBody,
  method,
  pathWithQuery,
  registeredHost,
  creatorKey,
  publicKey,
  nowUnixSeconds = Math.floor(Date.now() / 1000),
}) {
  const header = (name) => headers[name] ?? headers[name.toLowerCase()] ?? "";
  const hello = rawBody.length === 0;

  if (!hello && !constantTimeEquals(header("X-Nexus-Creator-Key"), creatorKey)) {
    return { ok: false, reason: "creator key mismatch" };
  }

  const timestamp = header("X-Nexus-Timestamp");
  const seconds = Number(timestamp);
  if (!Number.isInteger(seconds)) {
    return { ok: false, reason: "timestamp is not an integer" };
  }
  // BOTH directions. Without an upper bound a future-dated request is valid
  // forever; without a lower one a captured request replays forever.
  if (Math.abs(nowUnixSeconds - seconds) > SIGNATURE_WINDOW_SECONDS) {
    return { ok: false, reason: "timestamp outside the 60-second window" };
  }

  const presented = header("X-Nexus-Signature");
  if (!presented.startsWith("ed25519:")) {
    return { ok: false, reason: "signature is not ed25519:" };
  }
  const signatureBytes = Buffer.from(presented.slice("ed25519:".length), "base64");
  if (signatureBytes.length !== 64) {
    return { ok: false, reason: "signature is not 64 bytes" };
  }

  const correlationId = header("X-Correlation-ID");
  const message = Buffer.from(
    canonicalString({
      method,
      registeredHost,
      pathWithQuery,
      timestamp,
      correlationId,
      bodySha256Hex: bodyHashHex(rawBody),
    }),
    "utf8",
  );

  if (!verify(null, message, publicKey, signatureBytes)) {
    return { ok: false, reason: "signature does not verify" };
  }

  return { ok: true, hello, proof: proof({ correlationId, timestamp, signature: presented }) };
}

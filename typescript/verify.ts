// A complete Nexus402 request verifier for TypeScript. NO RUNTIME DEPENDENCIES.
//
// The same verifier as `../node/verify.mjs`, typed. Node 22.18 or later runs
// this file directly (it strips the types), so there is no build step.
// `../starters_test.go` starts the server beside it and drives it with the
// gateway's REAL signer: the hello, a paid call, and forged calls.
//
// Two checks, and you want both. The creator key is a shared secret on your
// server; if it leaks, anyone can impersonate Nexus402 to you. The signature
// is asymmetric (you hold only a public key), and it binds a request to YOUR
// host and to a 60-second window, so it also stops replays.

import { createHash, createPublicKey, timingSafeEqual, verify, type KeyObject } from "node:crypto";

/** The fixed first line of the response proof's digested bytes. Copy exactly. */
export const PROOF_DOMAIN = "nexus-endpoint-proof-v1";

/** Must match the gateway's 60 seconds, in both directions. */
export const SIGNATURE_WINDOW_SECONDS = 60;

// Ed25519 public keys arrive as 32 raw bytes in base64; createPublicKey wants
// DER, and for Ed25519 the SPKI header is this fixed 12-byte prefix.
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function publicKeyFromBase64(base64: string): KeyObject {
  const raw = Buffer.from(base64, "base64");
  if (raw.length !== 32) {
    throw new Error(`ed25519 public key must be 32 bytes, got ${raw.length}`);
  }
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });
}

/** Lowercase hex SHA-256 of the RAW body bytes, before any JSON parse. */
export function bodyHashHex(rawBody: Buffer): string {
  return createHash("sha256").update(rawBody).digest("hex");
}

/**
 * Six fields joined by single newlines, in this order, no trailing newline.
 * `registeredHost` is the host you PUBLISHED, never the inbound Host header,
 * which a proxy may rewrite.
 */
export function canonicalString(
  method: string,
  registeredHost: string,
  pathWithQuery: string,
  timestamp: string,
  correlationId: string,
  bodySha256Hex: string,
): string {
  // nexus:canonical-begin
  return [method, registeredHost, pathWithQuery, timestamp, correlationId, bodySha256Hex].join("\n");
  // nexus:canonical-end
}

/** Constant-time compare: both sides hashed to a fixed width first. */
export function constantTimeEquals(presented: string, expected: string): boolean {
  const left = createHash("sha256").update(presented, "utf8").digest();
  const right = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(left, right);
}

/** The value Nexus402 requires on EVERY answer to a verified request. */
export function proof(correlationId: string, timestamp: string, signature: string): string {
  const digest = createHash("sha256")
    .update([PROOF_DOMAIN, correlationId, timestamp, signature].join("\n"), "utf8")
    .digest("base64url");
  return `sha256:${digest}`;
}

export type Verdict = { ok: true; hello: boolean; proof: string } | { ok: false; reason: string };

export interface InboundRequest {
  /** Header names in any case. */
  headers: Record<string, string | string[] | undefined>;
  rawBody: Buffer;
  method: string;
  /** The request target exactly as sent: path plus query, not re-encoded. */
  pathWithQuery: string;
}

export interface EndpointConfig {
  registeredHost: string;
  creatorKey: string;
  publicKey: KeyObject;
}

/**
 * Verifies one inbound request.
 *
 * THE HELLO: when you publish, Nexus402 sends one signed POST with an EMPTY
 * body and NO creator key. `hello` is true for it; answer 200 with the proof
 * and run no tool. Its signature is still verified.
 */
export function verifyRequest(
  request: InboundRequest,
  config: EndpointConfig,
  nowUnixSeconds: number = Math.floor(Date.now() / 1000),
): Verdict {
  const header = (name: string): string => {
    const value = request.headers[name] ?? request.headers[name.toLowerCase()];
    return Array.isArray(value) ? (value[0] ?? "") : (value ?? "");
  };
  const hello = request.rawBody.length === 0;

  if (!hello && !constantTimeEquals(header("X-Nexus-Creator-Key"), config.creatorKey)) {
    return { ok: false, reason: "creator key mismatch" };
  }

  const timestamp = header("X-Nexus-Timestamp");
  if (!/^\d+$/.test(timestamp)) {
    return { ok: false, reason: "timestamp is not an integer" };
  }
  // BOTH directions: no upper bound means a future-dated request is valid
  // forever; no lower bound means a captured one replays forever.
  if (Math.abs(nowUnixSeconds - Number(timestamp)) > SIGNATURE_WINDOW_SECONDS) {
    return { ok: false, reason: "timestamp outside the 60-second window" };
  }

  const presented = header("X-Nexus-Signature");
  if (!presented.startsWith("ed25519:")) {
    return { ok: false, reason: "signature is not ed25519:" };
  }
  const signature = Buffer.from(presented.slice("ed25519:".length), "base64");
  if (signature.length !== 64) {
    return { ok: false, reason: "signature is not 64 bytes" };
  }

  const correlationId = header("X-Correlation-ID");
  const message = canonicalString(
    request.method,
    config.registeredHost,
    request.pathWithQuery,
    timestamp,
    correlationId,
    bodyHashHex(request.rawBody),
  );
  if (!verify(null, Buffer.from(message, "utf8"), config.publicKey, signature)) {
    return { ok: false, reason: "signature does not verify" };
  }
  return { ok: true, hello, proof: proof(correlationId, timestamp, presented) };
}

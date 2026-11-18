<?php

declare(strict_types=1);

/**
 * A Nexus402 request verifier for PHP.
 *
 * Machine-checked: `../starters_test.go` serves `index.php`, which uses this
 * file, and drives it with the gateway's REAL signer -- the hello, a paid
 * call, and forged calls that must be refused. `../field_order_test.go` also
 * reads the canonical string between the markers below.
 *
 * Needs NO third-party package: `sodium` has been bundled with PHP since
 * 7.2. If `sodium_crypto_sign_verify_detached` is missing, your build was
 * compiled without it, or the extension is not enabled in php.ini.
 */

/** The fixed first line of the response proof's digested bytes. Copy exactly. */
const NEXUS_PROOF_DOMAIN = 'nexus-endpoint-proof-v1';

/**
 * Must match the gateway's 60 seconds. Wider accepts older replays; narrower
 * rejects honest requests on ordinary clock skew.
 */
const NEXUS_SIGNATURE_WINDOW_SECONDS = 60;

/** Lowercase hex SHA-256 of the RAW body bytes, before any JSON parse. */
function nexus_body_hash_hex(string $rawBody): string
{
    return hash('sha256', $rawBody);
}

/** Six fields joined by single newlines. No trailing newline. */
function nexus_canonical_string(
    string $method,
    string $registeredHost,
    string $pathWithQuery,
    string $timestamp,
    string $correlationId,
    string $bodySha256Hex,
): string {
    // nexus:canonical-begin
    return implode("\n", [
        $method,
        $registeredHost,
        $pathWithQuery,
        $timestamp,
        $correlationId,
        $bodySha256Hex,
    ]);
    // nexus:canonical-end
}

/** The value Nexus402 requires on EVERY response, including your own errors. */
function nexus_proof(string $correlationId, string $timestamp, string $signature): string
{
    $message = implode("\n", [NEXUS_PROOF_DOMAIN, $correlationId, $timestamp, $signature]);
    $digest = hash('sha256', $message, true);

    // base64url without padding.
    return 'sha256:' . rtrim(strtr(base64_encode($digest), '+/', '-_'), '=');
}

/**
 * @param array<string, string> $headers
 * @return array{0: bool, 1: string} [true, proof] or [false, reason]
 */
function nexus_verify_request(
    array $headers,
    string $rawBody,
    string $method,
    string $pathWithQuery,
    string $registeredHost,
    string $creatorKey,
    string $publicKeyBase64,
    ?int $nowUnixSeconds = null,
): array {
    $now = $nowUnixSeconds ?? time();
    // Header names are case-insensitive, and a client may send any case.
    $lowered = array_change_key_case($headers, CASE_LOWER);
    $header = static function (string $name) use ($lowered): string {
        return (string) ($lowered[strtolower($name)] ?? '');
    };

    // THE HELLO (ADR-0143): the publish check is a signed POST with an EMPTY
    // body and NO creator key. Answer it 200 with the proof and run no tool.
    // Only the key check is skipped; the signature below is still verified.
    $hello = $rawBody === '';

    // Constant time. A byte-at-a-time compare returns faster the earlier it
    // finds a difference, leaking the key one position at a time.
    if (!$hello && !hash_equals($creatorKey, $header('X-Nexus-Creator-Key'))) {
        return [false, 'creator key mismatch'];
    }

    $timestamp = $header('X-Nexus-Timestamp');
    if (preg_match('/^\d+$/', $timestamp) !== 1) {
        return [false, 'timestamp is not an integer'];
    }
    // BOTH directions. Without an upper bound a future-dated request is valid
    // forever; without a lower one a captured request replays forever.
    if (abs($now - (int) $timestamp) > NEXUS_SIGNATURE_WINDOW_SECONDS) {
        return [false, 'timestamp outside the 60-second window'];
    }

    $presented = $header('X-Nexus-Signature');
    if (!str_starts_with($presented, 'ed25519:')) {
        return [false, 'signature is not ed25519:'];
    }
    $signature = base64_decode(substr($presented, strlen('ed25519:')), true);
    if ($signature === false || strlen($signature) !== 64) {
        return [false, 'signature is not 64 bytes'];
    }

    $publicKey = base64_decode($publicKeyBase64, true);
    if ($publicKey === false || strlen($publicKey) !== 32) {
        return [false, 'public key is not 32 bytes'];
    }

    $correlationId = $header('X-Correlation-ID');
    $message = nexus_canonical_string(
        $method,
        $registeredHost,
        $pathWithQuery,
        $timestamp,
        $correlationId,
        nexus_body_hash_hex($rawBody),
    );

    if (!sodium_crypto_sign_verify_detached($signature, $message, $publicKey)) {
        return [false, 'signature does not verify'];
    }

    return [true, nexus_proof($correlationId, $timestamp, $presented)];
}

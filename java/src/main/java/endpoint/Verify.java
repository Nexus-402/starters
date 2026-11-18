package endpoint;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;

/**
 * A complete Nexus402 request verifier for Java 17 or later. Ed25519 is in the
 * JDK, so this file needs no library.
 *
 * <p>Machine-checked: {@code ../starters_test.go} builds this kit from an empty
 * directory and drives it with the gateway's REAL signer -- the hello, a paid
 * call, and forged calls that must be refused.
 *
 * <p>Two checks, and you want both. The creator key is a shared secret on your
 * server; if it leaks, anyone can impersonate Nexus402 to you. The signature is
 * asymmetric (you hold only a public key), and it binds a request to YOUR host
 * and to a 60-second window, so it also stops replays.
 */
public final class Verify {
  /** The fixed first line of the response proof's digested bytes. Copy exactly. */
  public static final String PROOF_DOMAIN = "nexus-endpoint-proof-v1";

  /** Must match the gateway's 60 seconds, in both directions. */
  public static final long SIGNATURE_WINDOW_SECONDS = 60;

  // Ed25519 keys arrive as 32 raw bytes; the JDK wants X.509 SPKI, whose
  // Ed25519 header is this fixed 12-byte prefix.
  private static final byte[] SPKI_ED25519_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");

  /** {@code ok} with the proof and whether it is the hello, or a reason. */
  public record Verdict(boolean ok, boolean hello, String proof, String reason) {
    static Verdict refused(String reason) {
      return new Verdict(false, false, "", reason);
    }
  }

  private Verify() {}

  /** Wraps the 32 raw bytes Nexus402 gives you into a JDK public key. */
  public static PublicKey publicKeyFromBase64(String base64) throws Exception {
    byte[] raw = Base64.getDecoder().decode(base64.trim());
    if (raw.length != 32) {
      throw new IllegalArgumentException("ed25519 public key must be 32 bytes, got " + raw.length);
    }
    byte[] der = new byte[SPKI_ED25519_PREFIX.length + raw.length];
    System.arraycopy(SPKI_ED25519_PREFIX, 0, der, 0, SPKI_ED25519_PREFIX.length);
    System.arraycopy(raw, 0, der, SPKI_ED25519_PREFIX.length, raw.length);
    return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(der));
  }

  /** Lowercase hex SHA-256 of the RAW body bytes, before any JSON parse. */
  public static String bodyHashHex(byte[] rawBody) {
    return HexFormat.of().formatHex(sha256(rawBody));
  }

  /**
   * Six fields joined by single newlines, in this order, no trailing newline.
   * {@code registeredHost} is the host you PUBLISHED, never the inbound Host
   * header, which a proxy may rewrite.
   */
  public static String canonicalString(
      String method,
      String registeredHost,
      String pathWithQuery,
      String timestamp,
      String correlationId,
      String bodySha256Hex) {
    // nexus:canonical-begin
    return String.join("\n", method, registeredHost, pathWithQuery, timestamp, correlationId, bodySha256Hex);
    // nexus:canonical-end
  }

  /** The value Nexus402 requires on EVERY answer to a verified request. */
  public static String proof(String correlationId, String timestamp, String signature) {
    byte[] digest = sha256(String.join("\n", PROOF_DOMAIN, correlationId, timestamp, signature).getBytes(StandardCharsets.UTF_8));
    return "sha256:" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
  }

  /**
   * Verifies one request. {@code headers} must be keyed by LOWERCASE name.
   *
   * <p>THE HELLO: when you publish, Nexus402 sends one signed POST with an EMPTY
   * body and NO creator key. {@code hello} is true for it; answer 200 with the
   * proof and run no tool. Its signature is still verified.
   */
  public static Verdict verifyRequest(
      Map<String, String> headers,
      byte[] rawBody,
      String method,
      String pathWithQuery,
      String registeredHost,
      String creatorKey,
      PublicKey publicKey,
      long nowUnixSeconds) {
    boolean hello = rawBody.length == 0;

    // Constant time: MessageDigest.isEqual does not stop at the first
    // difference, so it leaks nothing about where the keys differ.
    byte[] presentedKey = sha256(headers.getOrDefault("x-nexus-creator-key", "").getBytes(StandardCharsets.UTF_8));
    byte[] expectedKey = sha256(creatorKey.getBytes(StandardCharsets.UTF_8));
    if (!hello && !MessageDigest.isEqual(presentedKey, expectedKey)) {
      return Verdict.refused("creator key mismatch");
    }

    String timestamp = headers.getOrDefault("x-nexus-timestamp", "");
    if (!timestamp.matches("\\d{1,18}")) {
      return Verdict.refused("timestamp is not an integer");
    }
    // BOTH directions: no upper bound means a future-dated request is valid
    // forever; no lower bound means a captured one replays forever.
    if (Math.abs(nowUnixSeconds - Long.parseLong(timestamp)) > SIGNATURE_WINDOW_SECONDS) {
      return Verdict.refused("timestamp outside the 60-second window");
    }

    String presented = headers.getOrDefault("x-nexus-signature", "");
    if (!presented.startsWith("ed25519:")) {
      return Verdict.refused("signature is not ed25519:");
    }
    byte[] signature;
    try {
      signature = Base64.getDecoder().decode(presented.substring("ed25519:".length()));
    } catch (IllegalArgumentException notBase64) {
      return Verdict.refused("signature is not base64");
    }
    if (signature.length != 64) {
      return Verdict.refused("signature is not 64 bytes");
    }

    String correlationId = headers.getOrDefault("x-correlation-id", "");
    String message = canonicalString(method, registeredHost, pathWithQuery, timestamp, correlationId, bodyHashHex(rawBody));
    try {
      Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(publicKey);
      verifier.update(message.getBytes(StandardCharsets.UTF_8));
      if (!verifier.verify(signature)) {
        return Verdict.refused("signature does not verify");
      }
    } catch (Exception invalid) {
      return Verdict.refused("signature does not verify");
    }
    return new Verdict(true, hello, proof(correlationId, timestamp, presented), "");
  }

  private static byte[] sha256(byte[] bytes) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(bytes);
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException(impossible);
    }
  }
}

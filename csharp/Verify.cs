// A complete Nexus402 request verifier for C# / .NET 8 or later.
//
// .NET has no built-in Ed25519, so this uses BouncyCastle.Cryptography for
// that one check; SHA-256 and the constant-time compare are in the runtime.
// `../starters_test.go` builds this kit from an empty directory and drives it
// with the gateway's REAL signer -- the hello, a paid call, and forged calls
// that must be refused.
//
// Two checks, and you want both. The creator key is a shared secret on your
// server; if it leaks, anyone can impersonate Nexus402 to you. The signature
// is asymmetric (you hold only a public key), and it binds a request to YOUR
// host and to a 60-second window, so it also stops replays.

using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace NexusEndpoint;

/// <summary>Ok with the proof and whether it is the hello, or a reason.</summary>
public sealed record Verdict(bool Ok, bool Hello, string Proof, string Reason)
{
    public static Verdict Refused(string reason) => new(false, false, "", reason);
}

public static class Verify
{
    /// <summary>The fixed first line of the response proof's digested bytes. Copy exactly.</summary>
    public const string ProofDomain = "nexus-endpoint-proof-v1";

    /// <summary>Must match the gateway's 60 seconds, in both directions.</summary>
    public const long SignatureWindowSeconds = 60;

    /// <summary>Reads the 32 raw bytes Nexus402 gives you, base64.</summary>
    public static Ed25519PublicKeyParameters PublicKeyFromBase64(string base64)
    {
        var raw = Convert.FromBase64String(base64.Trim());
        if (raw.Length != 32)
        {
            throw new ArgumentException($"ed25519 public key must be 32 bytes, got {raw.Length}");
        }
        return new Ed25519PublicKeyParameters(raw, 0);
    }

    /// <summary>Lowercase hex SHA-256 of the RAW body bytes, before any JSON parse.</summary>
    public static string BodyHashHex(byte[] rawBody) => Convert.ToHexString(SHA256.HashData(rawBody)).ToLowerInvariant();

    /// <summary>
    /// Six fields joined by single newlines, in this order, no trailing newline.
    /// registeredHost is the host you PUBLISHED, never the inbound Host header,
    /// which a proxy may rewrite.
    /// </summary>
    public static string CanonicalString(
        string method,
        string registeredHost,
        string pathWithQuery,
        string timestamp,
        string correlationId,
        string bodySha256Hex)
    {
        // nexus:canonical-begin
        return string.Join("\n", method, registeredHost, pathWithQuery, timestamp, correlationId, bodySha256Hex);
        // nexus:canonical-end
    }

    /// <summary>The value Nexus402 requires on EVERY answer to a verified request.</summary>
    public static string Proof(string correlationId, string timestamp, string signature)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", ProofDomain, correlationId, timestamp, signature)));
        return "sha256:" + Convert.ToBase64String(digest).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>
    /// Verifies one request. THE HELLO: when you publish, Nexus402 sends one
    /// signed POST with an EMPTY body and NO creator key. Hello is true for it;
    /// answer 200 with the proof and run no tool. Its signature is still verified.
    /// </summary>
    public static Verdict VerifyRequest(
        Func<string, string> header,
        byte[] rawBody,
        string method,
        string pathWithQuery,
        string registeredHost,
        string creatorKey,
        Ed25519PublicKeyParameters publicKey,
        long nowUnixSeconds)
    {
        var hello = rawBody.Length == 0;

        // Constant time: FixedTimeEquals does not stop at the first difference.
        var presentedKey = SHA256.HashData(Encoding.UTF8.GetBytes(header("X-Nexus-Creator-Key")));
        var expectedKey = SHA256.HashData(Encoding.UTF8.GetBytes(creatorKey));
        if (!hello && !CryptographicOperations.FixedTimeEquals(presentedKey, expectedKey))
        {
            return Verdict.Refused("creator key mismatch");
        }

        var timestamp = header("X-Nexus-Timestamp");
        if (timestamp.Length == 0 || timestamp.Length > 18 || !timestamp.All(char.IsAsciiDigit))
        {
            return Verdict.Refused("timestamp is not an integer");
        }
        // BOTH directions: no upper bound means a future-dated request is valid
        // forever; no lower bound means a captured one replays forever.
        if (Math.Abs(nowUnixSeconds - long.Parse(timestamp)) > SignatureWindowSeconds)
        {
            return Verdict.Refused("timestamp outside the 60-second window");
        }

        var presented = header("X-Nexus-Signature");
        if (!presented.StartsWith("ed25519:", StringComparison.Ordinal))
        {
            return Verdict.Refused("signature is not ed25519:");
        }
        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(presented["ed25519:".Length..]);
        }
        catch (FormatException)
        {
            return Verdict.Refused("signature is not base64");
        }
        if (signature.Length != 64)
        {
            return Verdict.Refused("signature is not 64 bytes");
        }

        var correlationId = header("X-Correlation-ID");
        var message = Encoding.UTF8.GetBytes(
            CanonicalString(method, registeredHost, pathWithQuery, timestamp, correlationId, BodyHashHex(rawBody)));
        var verifier = new Ed25519Signer();
        verifier.Init(false, publicKey);
        verifier.BlockUpdate(message, 0, message.Length);
        if (!verifier.VerifySignature(signature))
        {
            return Verdict.Refused("signature does not verify");
        }
        return new Verdict(true, hello, Proof(correlationId, timestamp, presented), "");
    }
}

# frozen_string_literal: true

# A complete Nexus402 request verifier for Ruby 3.1 or later.
#
# Ed25519 comes from Ruby's own OpenSSL (openssl gem 3.0, OpenSSL 1.1.1 or
# later), so this file
# needs no gem. `../starters_test.go` serves `server.rb`, which uses this file,
# and drives it with the gateway's REAL signer -- the hello, a paid call, and
# forged calls that must be refused.
#
# Two checks, and you want both. The creator key is a shared secret on your
# server; if it leaks, anyone can impersonate Nexus402 to you. The signature
# is asymmetric (you hold only a public key), and it binds a request to YOUR
# host and to a 60-second window, so it also stops replays.

require "digest"
require "openssl"

module NexusVerify
  # The fixed first line of the response proof's digested bytes. Copy exactly.
  PROOF_DOMAIN = "nexus-endpoint-proof-v1"

  # Must match the gateway's 60 seconds, in both directions.
  SIGNATURE_WINDOW_SECONDS = 60

  # Ed25519 keys arrive as 32 raw bytes; OpenSSL wants DER SPKI, whose Ed25519
  # header is this fixed 12-byte prefix.
  SPKI_ED25519_PREFIX = ["302a300506032b6570032100"].pack("H*")

  Verdict = Struct.new(:ok, :hello, :proof, :reason, keyword_init: true)

  module_function

  # Wraps the 32 raw bytes Nexus402 gives you into an OpenSSL key.
  def public_key_from_base64(base64)
    raw = base64.strip.unpack1("m0")
    raise ArgumentError, "ed25519 public key must be 32 bytes, got #{raw.bytesize}" unless raw.bytesize == 32

    OpenSSL::PKey.read(SPKI_ED25519_PREFIX + raw)
  end

  # Lowercase hex SHA-256 of the RAW body bytes, before any JSON parse.
  def body_hash_hex(raw_body)
    Digest::SHA256.hexdigest(raw_body)
  end

  # Six fields joined by single newlines, in this order, no trailing newline.
  # registered_host is the host you PUBLISHED, never the inbound Host header,
  # which a proxy may rewrite.
  def canonical_string(method, registered_host, path_with_query, timestamp, correlation_id, body_sha256_hex)
    # nexus:canonical-begin
    [method, registered_host, path_with_query, timestamp, correlation_id, body_sha256_hex].join("\n")
    # nexus:canonical-end
  end

  # The value Nexus402 requires on EVERY answer to a verified request.
  def proof(correlation_id, timestamp, signature)
    digest = Digest::SHA256.digest([PROOF_DOMAIN, correlation_id, timestamp, signature].join("\n"))
    # base64url without padding.
    "sha256:#{[digest].pack("m0").tr("+/", "-_").delete("=")}"
  end

  # Verifies one request. `header` is a lambda taking a header name, in any case.
  #
  # THE HELLO: when you publish, Nexus402 sends one signed POST with an EMPTY
  # body and NO creator key. `hello` is true for it; answer 200 with the proof
  # and run no tool. Its signature is still verified.
  def verify_request(header:, raw_body:, method:, path_with_query:, registered_host:, creator_key:, public_key:,
                     now_unix_seconds: Time.now.to_i)
    hello = raw_body.empty?

    # Constant time: secure_compare does not stop at the first difference.
    presented_key = Digest::SHA256.digest(header.call("X-Nexus-Creator-Key").to_s)
    expected_key = Digest::SHA256.digest(creator_key)
    if !hello && !OpenSSL.fixed_length_secure_compare(presented_key, expected_key)
      return Verdict.new(ok: false, reason: "creator key mismatch")
    end

    timestamp = header.call("X-Nexus-Timestamp").to_s
    return Verdict.new(ok: false, reason: "timestamp is not an integer") unless timestamp.match?(/\A\d{1,18}\z/)
    # BOTH directions: no upper bound means a future-dated request is valid
    # forever; no lower bound means a captured one replays forever.
    if (now_unix_seconds - timestamp.to_i).abs > SIGNATURE_WINDOW_SECONDS
      return Verdict.new(ok: false, reason: "timestamp outside the 60-second window")
    end

    presented = header.call("X-Nexus-Signature").to_s
    return Verdict.new(ok: false, reason: "signature is not ed25519:") unless presented.start_with?("ed25519:")

    begin
      signature = presented.delete_prefix("ed25519:").unpack1("m0")
    rescue ArgumentError
      return Verdict.new(ok: false, reason: "signature is not base64")
    end
    return Verdict.new(ok: false, reason: "signature is not 64 bytes") unless signature.bytesize == 64

    correlation_id = header.call("X-Correlation-ID").to_s
    message = canonical_string(method, registered_host, path_with_query, timestamp, correlation_id,
                               body_hash_hex(raw_body))
    verified = begin
      public_key.verify(nil, signature, message)
    rescue OpenSSL::PKey::PKeyError
      false
    end
    return Verdict.new(ok: false, reason: "signature does not verify") unless verified

    Verdict.new(ok: true, hello: hello, proof: proof(correlation_id, timestamp, presented))
  end
end

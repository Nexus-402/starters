# frozen_string_literal: true

# A complete Nexus402 creator endpoint for Ruby 3.1 or later. One gem: webrick.
#
# `bundle install && bundle exec ruby server.rb`. Set four environment
# variables, put it behind HTTPS, and publish its URL. `../starters_test.go`
# serves this exact file and drives it with the gateway's REAL signer.
#
# The gateway answers `initialize`, `tools/list` and notifications itself,
# from the description and input schema you publish; only `tools/call`
# reaches you, already charged.
#
#   PORT                    where to listen (default 8080)
#   NEXUS_REGISTERED_HOST   the host you published, e.g. mcp.acme.example
#   NEXUS_CREATOR_KEY       your nx_crt_ key, shown once when you claimed a handle
#   NEXUS_PUBLIC_KEY        the gateway's Ed25519 key(s), base64, comma-separated
#                           (GET https://api.nexus402.dev/v1/signing-key lists them)

require "json"
require "webrick"
require_relative "verify"

# The gateway's own cap on a request body. Anything larger did not come from it.
MAX_BODY_BYTES = 10 * 1024 * 1024

def required(name)
  value = ENV.fetch(name, "").strip
  abort "#{name} is not set" if value.empty?
  value
end

# YOUR TOOLS. `tool` is the last segment of the published name
# (`acme/text@v2/word_count` arrives as `word_count`).
#
# Return [status, the bare MCP result]. The gateway wraps the result in the
# JSON-RPC envelope, so your own envelope would nest. `isError: true` is
# still a CHARGED call; return a 4xx when the caller should not pay.
def run_tool(tool, args)
  case tool
  when "word_count"
    text = args["text"].is_a?(String) ? args["text"] : ""
    [200, { content: [{ type: "text", text: text.split.length.to_s }] }]
  else
    [404, { error: "unknown tool #{tool}" }]
  end
end

PORT = Integer(ENV.fetch("PORT", "8080"))
REGISTERED_HOST = required("NEXUS_REGISTERED_HOST")
CREATOR_KEY = required("NEXUS_CREATOR_KEY")
# More than one while the gateway rotates its key: accept any of them.
PUBLIC_KEYS = required("NEXUS_PUBLIC_KEY").split(",").map { |key| NexusVerify.public_key_from_base64(key) }

# The proof goes on EVERY answer to a verified request, errors included.
def answer(response, status, proof, body)
  response.status = status
  response["Content-Type"] = "application/json"
  response["X-Nexus-Proof"] = proof
  response.body = body.nil? ? "" : JSON.generate(body)
end

class Endpoint < WEBrick::HTTPServlet::AbstractServlet
  def do_GET(_request, response) # rubocop:disable Naming/MethodName
    response.status = 405
    response["Allow"] = "POST"
  end

  def do_POST(request, response) # rubocop:disable Naming/MethodName
    raw_body = (request.body || "").b
    if raw_body.bytesize > MAX_BODY_BYTES
      response.status = 413
      return
    end

    header = ->(name) { request[name] }
    verdict = NexusVerify::Verdict.new(ok: false, reason: "no public key")
    PUBLIC_KEYS.each do |public_key|
      verdict = NexusVerify.verify_request(
        header: header,
        raw_body: raw_body,
        method: request.request_method,
        # The request target exactly as sent: path plus query, still encoded.
        path_with_query: request.unparsed_uri,
        registered_host: REGISTERED_HOST,
        creator_key: CREATOR_KEY,
        public_key: public_key
      )
      break if verdict.ok
    end
    unless verdict.ok
      # No detail in the body: a reason tells a prober how close they are.
      warn "refused: #{verdict.reason}"
      response.status = 401
      response["Content-Type"] = "text/plain"
      response.body = "unauthorized"
      return
    end

    # THE HELLO: the signed, empty-body check sent when you publish.
    # Answer with the proof and run nothing.
    return answer(response, 200, verdict.proof, nil) if verdict.hello

    begin
      call = JSON.parse(raw_body)
    rescue JSON::ParserError
      return answer(response, 400, verdict.proof, { error: "body is not JSON" })
    end
    params = call.is_a?(Hash) && call["params"].is_a?(Hash) ? call["params"] : {}
    name = params["name"].is_a?(String) ? params["name"] : ""
    args = params["arguments"].is_a?(Hash) ? params["arguments"] : {}
    status, result = run_tool(name.split("/").last.to_s, args)
    answer(response, status, verdict.proof, result)
  end
end

server = WEBrick::HTTPServer.new(
  Port: PORT,
  BindAddress: "0.0.0.0",
  MaxRequestBodySize: MAX_BODY_BYTES,
  # Request lines carry paths and queries a caller chose; keep them out.
  AccessLog: [],
  Logger: WEBrick::Log.new($stderr, WEBrick::Log::WARN)
)
server.mount("/", Endpoint)
trap("INT") { server.shutdown }
trap("TERM") { server.shutdown }
puts "listening on :#{PORT} for #{REGISTERED_HOST}"
$stdout.flush
server.start

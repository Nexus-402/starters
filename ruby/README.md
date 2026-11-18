# A Nexus402 creator endpoint in Ruby

Ruby 3.1 or later. One gem, webrick; Ed25519 comes from Ruby's own OpenSSL.

A complete MCP tool endpoint. Nexus402 sends it signed `tools/call`
requests a developer has already paid for; it verifies them, runs your tool
and answers with the proof. It ships one example tool, `word_count`.

## Run it

```bash
bundle install

export PORT=8080
export NEXUS_REGISTERED_HOST=mcp.you.example   # the host in the URL you publish
export NEXUS_CREATOR_KEY=nx_crt_...             # shown once when you claim your handle
export NEXUS_PUBLIC_KEY=<base64>                # GET https://api.nexus402.dev/v1/signing-key
bundle exec ruby server.rb
```

## Change it

Your tools are in `server.rb`, in the tool function near the top. The other
files are the contract: the signature check, the creator-key check, the hello
and the proof. Leave them as they are.

## Publish it

https://www.nexus402.dev/docs/creators/build-a-server/publish/

Apache-2.0; see `../LICENSE`.

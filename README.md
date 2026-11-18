# Nexus402 creator starter kits

A complete, minimal MCP tool endpoint in nine languages. Each one verifies
the signed, already-paid calls Nexus402 sends, runs your tool and answers
with the proof. Pick your language, change the tool function, host it on
HTTPS and publish it.

| Kit | Runtime |
|---|---|
| [Node.js](node/) | Node.js 18 or later. No dependencies. |
| [TypeScript](typescript/) | Node.js 22.18 or later, which runs TypeScript directly. No runtime dependencies. |
| [Python](python/) | Python 3.10 or later and one package, cryptography. |
| [Go](go/) | Go 1.22 or later. Standard library only. |
| [PHP](php/) | PHP 8.1 or later with sodium, which is bundled since 7.2. No packages. |
| [Rust](rust/) | Rust 1.75 or later. Crates: ed25519-dalek, sha2, base64, subtle, tiny_http, serde_json. |
| [Java](java/) | Java 17 or later and Maven. One library, Jackson, for JSON; Ed25519 is in the JDK. |
| [C# / .NET](csharp/) | .NET 8 or later. One package, BouncyCastle.Cryptography, because .NET has no built-in Ed25519. |
| [Ruby](ruby/) | Ruby 3.1 or later. One gem, webrick; Ed25519 comes from Ruby's own OpenSSL. |

Guide: https://www.nexus402.dev/docs/creators/build-a-server/

## How these are kept correct

This repository is a read-only copy. The kits are developed and tested in
Nexus402's own repository, where every kit is built from these exact files
and sent the gateway's real hello, a real signed call and seven forged
requests it must refuse; only a copy that passed is published here. A change
you make in a fork is not tested by us. Issues and pull requests are
welcome; an accepted change arrives here with the next copy.

The contract the kits implement: https://www.nexus402.dev/docs/creators/requirements/

## License

Apache License 2.0. See `LICENSE` and `NOTICE`.

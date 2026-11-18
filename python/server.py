"""A complete Nexus402 creator endpoint for Python. One package: cryptography.

Put `verify.py` beside this file, `pip install -r requirements.txt`, set four
environment variables, put it behind HTTPS, and publish its URL.
`../starters_test.go` starts this exact file and drives it with the gateway's
REAL signer: the hello, a paid call, and forged calls.

The gateway answers `initialize`, `tools/list` and notifications itself, from
the description and input schema you publish; only `tools/call` reaches you,
already charged. Standard library HTTP server, so nothing else to install; it
is threaded, and meant to sit behind your HTTPS proxy or platform router.

  PORT                    where to listen (default 8080)
  NEXUS_REGISTERED_HOST   the host you published, e.g. mcp.acme.example
  NEXUS_CREATOR_KEY       your nx_crt_ key, shown once when you claimed a handle
  NEXUS_PUBLIC_KEY        the gateway's Ed25519 key(s), base64, comma-separated
                          (GET https://api.nexus402.dev/v1/signing-key lists them)
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from verify import verify_request

# The gateway's own cap on a request body. Anything larger did not come from it.
MAX_BODY_BYTES = 10 * 1024 * 1024


def required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if value == "":
        sys.exit(f"{name} is not set")
    return value


PORT = int(os.environ.get("PORT", "8080"))
REGISTERED_HOST = required("NEXUS_REGISTERED_HOST")
CREATOR_KEY = required("NEXUS_CREATOR_KEY")
# More than one while the gateway rotates its key: accept any of them.
PUBLIC_KEYS = [key.strip() for key in required("NEXUS_PUBLIC_KEY").split(",") if key.strip()]


def run_tool(tool: str, args: dict) -> tuple[int, dict]:
    """YOUR TOOLS. `tool` is the last segment of the published name
    (`acme/text@v2/word_count` arrives as `word_count`).

    Return (status, the bare MCP result). The gateway wraps the result in the
    JSON-RPC envelope, so your own envelope would nest. `isError: True` is
    still a CHARGED call: use it only when the caller's input made your tool fail
    after it did work. When your tool itself fails, return a 5xx; when the
    request is wrong before any work, a 4xx. Both refund the caller.
    """
    if tool == "word_count":
        text = args.get("text") if isinstance(args.get("text"), str) else ""
        return 200, {"content": [{"type": "text", "text": str(len(text.split()))}]}
    return 404, {"error": f"unknown tool {tool}"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 (the name http.server calls)
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            self.send_response(413)
            self.end_headers()
            return
        raw_body = self.rfile.read(length) if length > 0 else b""

        headers = {name: value for name, value in self.headers.items()}
        ok, detail = False, "no public key"
        for public_key in PUBLIC_KEYS:
            ok, detail = verify_request(
                headers=headers,
                raw_body=raw_body,
                method=self.command,
                # The request target exactly as sent: path plus query.
                path_with_query=self.path,
                registered_host=REGISTERED_HOST,
                creator_key=CREATOR_KEY,
                public_key_base64=public_key,
            )
            if ok:
                break
        if not ok:
            # No detail in the body: a reason tells a prober how close they are.
            print(f"refused: {detail}", file=sys.stderr)
            self.reply(401, None, b"unauthorized", "text/plain")
            return
        proof = detail

        # THE HELLO: the signed, empty-body check sent when you publish.
        # Answer with the proof and run nothing.
        if raw_body == b"":
            self.reply(200, proof, b"")
            return

        try:
            call = json.loads(raw_body)
        except ValueError:
            self.reply(400, proof, json.dumps({"error": "body is not JSON"}).encode())
            return
        params = call.get("params") if isinstance(call, dict) else None
        params = params if isinstance(params, dict) else {}
        name = params.get("name") if isinstance(params.get("name"), str) else ""
        args = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
        status, result = run_tool(name.rsplit("/", 1)[-1], args)
        self.reply(status, proof, json.dumps(result).encode())

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(405)
        self.send_header("Allow", "POST")
        self.end_headers()

    def reply(self, status: int, proof: str | None, body: bytes, content_type: str = "application/json") -> None:
        # The proof goes on EVERY answer to a verified request, errors included,
        # and before the headers are finished.
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if proof is not None:
            self.send_header("X-Nexus-Proof", proof)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        # Request lines carry paths and queries a caller chose; keep them out.
        return


if __name__ == "__main__":
    print(f"listening on :{PORT} for {REGISTERED_HOST}", flush=True)
    ThreadingHTTPServer(("", PORT), Handler).serve_forever()

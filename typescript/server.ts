// A complete Nexus402 creator endpoint in TypeScript. NO RUNTIME DEPENDENCIES.
//
// Node 22.18 or later runs this file as it is: `node server.ts`. Set four
// environment variables, put it behind HTTPS, and publish its URL.
// `../starters_test.go` starts this exact file and drives it with the
// gateway's REAL signer.
//
// The gateway answers `initialize`, `tools/list` and notifications itself,
// from the description and input schema you publish; only `tools/call`
// reaches you, already charged.
//
//   PORT                    where to listen (default 8080)
//   NEXUS_REGISTERED_HOST   the host you published, e.g. mcp.acme.example
//   NEXUS_CREATOR_KEY       your nx_crt_ key, shown once when you claimed a handle
//   NEXUS_PUBLIC_KEY        the gateway's Ed25519 key(s), base64, comma-separated
//                           (GET https://api.nexus402.dev/v1/signing-key lists them)

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { publicKeyFromBase64, verifyRequest, type Verdict } from "./verify.ts";

// The gateway's own cap on a request body. Anything larger did not come from it.
const MAX_BODY_BYTES = 10 * 1024 * 1024;

function required(name: string): string {
  const value = (process.env[name] ?? "").trim();
  if (value === "") {
    throw new Error(`${name} is not set`);
  }
  return value;
}

const port = Number(process.env.PORT ?? 8080);
const registeredHost = required("NEXUS_REGISTERED_HOST");
const creatorKey = required("NEXUS_CREATOR_KEY");
// More than one while the gateway rotates its key: accept any of them.
const publicKeys = required("NEXUS_PUBLIC_KEY")
  .split(",")
  .map((key) => publicKeyFromBase64(key.trim()));

interface ToolAnswer {
  status: number;
  result: unknown;
}

/**
 * YOUR TOOLS. `tool` is the last segment of the published name
 * (`acme/text@v2/word_count` arrives as `word_count`).
 *
 * Return the bare MCP result. The gateway wraps it in the JSON-RPC envelope,
 * so your own envelope would nest. `isError: true` is still a
 * CHARGED call: use it only when the caller's input made your tool fail
 * after it did work. When your tool itself fails, return a 5xx; when the
 * request is wrong before any work, a 4xx. Both refund the caller.
 */
function runTool(tool: string, args: Record<string, unknown>): ToolAnswer {
  switch (tool) {
    case "word_count": {
      const text = typeof args.text === "string" ? args.text.trim() : "";
      const words = text === "" ? 0 : text.split(/\s+/).length;
      return { status: 200, result: { content: [{ type: "text", text: String(words) }] } };
    }
    default:
      return { status: 404, result: { error: `unknown tool ${tool}` } };
  }
}

function readBody(request: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    request.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error("body too large"));
        request.destroy();
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => resolve(Buffer.concat(chunks)));
    request.on("error", reject);
  });
}

function verify(request: IncomingMessage, rawBody: Buffer): Verdict {
  let verdict: Verdict = { ok: false, reason: "no public key" };
  for (const publicKey of publicKeys) {
    verdict = verifyRequest(
      { headers: request.headers, rawBody, method: request.method ?? "", pathWithQuery: request.url ?? "" },
      { registeredHost, creatorKey, publicKey },
    );
    if (verdict.ok) return verdict;
  }
  return verdict;
}

// The proof goes on EVERY answer to a verified request, errors included.
function answer(response: ServerResponse, status: number, proof: string, body?: unknown): void {
  response.writeHead(status, { "Content-Type": "application/json", "X-Nexus-Proof": proof });
  response.end(body === undefined ? "" : JSON.stringify(body));
}

function argumentsOf(call: unknown): { name: string; args: Record<string, unknown> } {
  const params = (call as { params?: { name?: unknown; arguments?: unknown } } | null)?.params;
  const name = typeof params?.name === "string" ? params.name : "";
  const args = typeof params?.arguments === "object" && params.arguments !== null ? (params.arguments as Record<string, unknown>) : {};
  return { name, args };
}

const server = createServer(async (request, response) => {
  if (request.method !== "POST") {
    response.writeHead(405, { Allow: "POST" }).end();
    return;
  }
  let rawBody: Buffer;
  try {
    rawBody = await readBody(request);
  } catch {
    response.writeHead(413).end();
    return;
  }

  const verdict = verify(request, rawBody);
  if (!verdict.ok) {
    // No detail in the body: a reason tells a prober how close they are.
    console.warn(`refused: ${verdict.reason}`);
    response.writeHead(401, { "Content-Type": "text/plain" }).end("unauthorized");
    return;
  }
  // THE HELLO: answer with the proof and run nothing.
  if (verdict.hello) {
    answer(response, 200, verdict.proof);
    return;
  }

  let call: unknown;
  try {
    call = JSON.parse(rawBody.toString("utf8"));
  } catch {
    answer(response, 400, verdict.proof, { error: "body is not JSON" });
    return;
  }
  const { name, args } = argumentsOf(call);
  const { status, result } = runTool(name.slice(name.lastIndexOf("/") + 1), args);
  answer(response, status, verdict.proof, result);
});

server.listen(port, () => {
  console.log(`listening on :${port} for ${registeredHost}`);
});

// A complete Nexus402 creator endpoint for Node.js 18 or later. NO DEPENDENCIES.
//
// Copy this file and `verify.mjs` beside it, set four environment variables,
// put it behind HTTPS, and publish its URL. `../starters_test.go` copies this
// kit into an empty directory, starts it and drives it with the gateway's REAL
// signer, so what the creator docs show is what our gate runs.
//
// Nexus402 hosts nothing: this runs wherever you run it. The gateway sends it
// signed MCP `tools/call` requests and meters them; `initialize`,
// `tools/list` and notifications never reach you, because the gateway answers
// them from your published description and input schema.
//
//   PORT                    where to listen (default 8080)
//   NEXUS_REGISTERED_HOST   the host you published, e.g. mcp.acme.example
//   NEXUS_CREATOR_KEY       your nx_crt_ key, shown once when you claimed a handle
//   NEXUS_PUBLIC_KEY        the gateway's Ed25519 key(s), base64, comma-separated
//                           (GET https://api.nexus402.dev/v1/signing-key lists them)

import { createServer } from "node:http";
import { publicKeyFromBase64, verifyRequest } from "./verify.mjs";

// The gateway's own cap on a request body. Anything larger did not come from it.
const MAX_BODY_BYTES = 10 * 1024 * 1024;

function required(name) {
  const value = (process.env[name] ?? "").trim();
  if (value === "") {
    throw new Error(`${name} is not set`);
  }
  return value;
}

const config = {
  port: Number(process.env.PORT ?? 8080),
  registeredHost: required("NEXUS_REGISTERED_HOST"),
  creatorKey: required("NEXUS_CREATOR_KEY"),
  // More than one while the gateway rotates its key: accept any of them.
  publicKeys: required("NEXUS_PUBLIC_KEY")
    .split(",")
    .map((key) => publicKeyFromBase64(key.trim())),
};

/**
 * YOUR TOOLS. The gateway sends the full published name in `params.name`,
 * e.g. `acme/text@v2/word_count`; the last segment is the tool.
 *
 * Return the bare MCP result object. The gateway wraps it in the JSON-RPC
 * envelope for the developer, so returning your own envelope would nest it.
 * A result with `isError: true` is still a successful, CHARGED call: use it
 * only when the caller's input made your tool fail after it did work. When your tool itself fails, return a 5xx; when the
 * request is wrong before any work, a 4xx. Both refund the caller.
 */
function runTool(tool, args) {
  switch (tool) {
    case "word_count": {
      const text = typeof args?.text === "string" ? args.text : "";
      const words = text.trim() === "" ? 0 : text.trim().split(/\s+/).length;
      return { status: 200, result: { content: [{ type: "text", text: String(words) }] } };
    }
    default:
      return { status: 404, result: { error: `unknown tool ${tool}` } };
  }
}

function readBody(request) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    request.on("data", (chunk) => {
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

function verify(request, rawBody) {
  let verdict = { ok: false, reason: "no public key" };
  for (const publicKey of config.publicKeys) {
    verdict = verifyRequest({
      headers: request.headers,
      rawBody,
      method: request.method,
      // The request target exactly as sent: path plus query, not re-encoded.
      pathWithQuery: request.url,
      registeredHost: config.registeredHost,
      creatorKey: config.creatorKey,
      publicKey,
    });
    if (verdict.ok) {
      return verdict;
    }
  }
  return verdict;
}

// Sends a JSON answer with the proof. The proof goes on EVERY answer to a
// verified request, errors included: a 4xx you prove is a refusal the caller
// is refunded for, not a fault against your endpoint.
function answer(response, status, proof, body) {
  response.writeHead(status, { "Content-Type": "application/json", "X-Nexus-Proof": proof });
  response.end(body === undefined ? "" : JSON.stringify(body));
}

const server = createServer(async (request, response) => {
  if (request.method !== "POST") {
    response.writeHead(405, { Allow: "POST" }).end();
    return;
  }
  let rawBody;
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

  // THE HELLO: the signed, empty-body check the gateway sends when you
  // publish. Answer with the proof and run nothing.
  if (verdict.hello) {
    answer(response, 200, verdict.proof);
    return;
  }

  let call;
  try {
    call = JSON.parse(rawBody.toString("utf8"));
  } catch {
    answer(response, 400, verdict.proof, { error: "body is not JSON" });
    return;
  }
  const name = typeof call?.params?.name === "string" ? call.params.name : "";
  const tool = name.slice(name.lastIndexOf("/") + 1);
  const { status, result } = runTool(tool, call?.params?.arguments);
  answer(response, status, verdict.proof, result);
});

server.listen(config.port, () => {
  console.log(`listening on :${config.port} for ${config.registeredHost}`);
});

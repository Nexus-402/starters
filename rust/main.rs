//! A complete Nexus402 creator endpoint for Rust.
//!
//! Set four environment variables, put it behind HTTPS, and publish its URL.
//! `../starters_test.go` builds this kit from an empty directory, exactly as a
//! creator downloads it, and drives it with the gateway's REAL signer.
//!
//! The gateway answers `initialize`, `tools/list` and notifications itself,
//! from the description and input schema you publish; only `tools/call`
//! reaches you, already charged.
//!
//!   PORT                    where to listen (default 8080)
//!   NEXUS_REGISTERED_HOST   the host you published, e.g. mcp.acme.example
//!   NEXUS_CREATOR_KEY       your nx_crt_ key, shown once when you claimed a handle
//!   NEXUS_PUBLIC_KEY        the gateway's Ed25519 key(s), base64, comma-separated
//!                           (GET https://api.nexus402.dev/v1/signing-key lists them)

mod verify;

use serde_json::{json, Value};
use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Method, Response, Server};
use verify::{Endpoint, Request};

/// The gateway's own cap on a request body. Anything larger did not come from it.
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// YOUR TOOLS. `tool` is the last segment of the published name
/// (`acme/text@v2/word_count` arrives as `word_count`).
///
/// Return the status and the bare MCP result. The gateway wraps the result in
/// the JSON-RPC envelope, so your own envelope would nest. `isError: true` is
/// still a CHARGED call: use it only when the caller's input made your tool fail
/// after it did work. When your tool itself fails, return a 5xx; when the
/// request is wrong before any work, a 4xx. Both refund the caller.
fn run_tool(tool: &str, args: &Value) -> (u16, Value) {
    match tool {
        "word_count" => {
            let text = args.get("text").and_then(Value::as_str).unwrap_or("");
            let words = text.split_whitespace().count();
            (200, json!({ "content": [{ "type": "text", "text": words.to_string() }] }))
        }
        _ => (404, json!({ "error": format!("unknown tool {tool}") })),
    }
}

fn required(name: &str) -> String {
    let value = std::env::var(name).unwrap_or_default().trim().to_string();
    if value.is_empty() {
        eprintln!("{name} is not set");
        std::process::exit(1);
    }
    value
}

fn header(request: &tiny_http::Request, name: &str) -> String {
    request
        .headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_default()
}

fn json_response(status: u16, proof: &str, body: Option<&Value>) -> Response<std::io::Cursor<Vec<u8>>> {
    // The proof goes on EVERY answer to a verified request, errors included.
    let bytes = body.map(|b| b.to_string().into_bytes()).unwrap_or_default();
    Response::from_data(bytes)
        .with_status_code(status)
        .with_header(Header::from_bytes("Content-Type", "application/json").expect("static header"))
        .with_header(Header::from_bytes("X-Nexus-Proof", proof).expect("the proof is ASCII"))
}

fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    let registered_host = required("NEXUS_REGISTERED_HOST");
    let creator_key = required("NEXUS_CREATOR_KEY");
    // More than one while the gateway rotates its key: accept any of them.
    let endpoints: Vec<Endpoint> = required("NEXUS_PUBLIC_KEY")
        .split(',')
        .map(|key| Endpoint {
            registered_host: registered_host.clone(),
            creator_key: creator_key.clone(),
            public_key_base64: key.trim().to_string(),
        })
        .collect();

    let server = Server::http(format!("0.0.0.0:{port}")).expect("listen");
    println!("listening on :{port} for {registered_host}");

    for mut request in server.incoming_requests() {
        if *request.method() != Method::Post {
            let _ = request.respond(Response::empty(405).with_header(Header::from_bytes("Allow", "POST").expect("static header")));
            continue;
        }
        let mut raw_body = Vec::new();
        let read = request.as_reader().take(MAX_BODY_BYTES as u64 + 1).read_to_end(&mut raw_body);
        if read.is_err() || raw_body.len() > MAX_BODY_BYTES {
            let _ = request.respond(Response::empty(413));
            continue;
        }

        let (creator_key_header, signature, timestamp, correlation_id) = (
            header(&request, "X-Nexus-Creator-Key"),
            header(&request, "X-Nexus-Signature"),
            header(&request, "X-Nexus-Timestamp"),
            header(&request, "X-Correlation-ID"),
        );
        let method = request.method().as_str().to_string();
        // The request target exactly as sent: path plus query.
        let target = request.url().to_string();
        let inbound = Request {
            creator_key_header: &creator_key_header,
            signature_header: &signature,
            timestamp_header: &timestamp,
            correlation_id: &correlation_id,
            raw_body: &raw_body,
            method: &method,
            path_with_query: &target,
        };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let mut verdict = Err("no public key".to_string());
        for endpoint in &endpoints {
            verdict = endpoint.verify(&inbound, now);
            if verdict.is_ok() {
                break;
            }
        }
        let proof = match verdict {
            Ok(proof) => proof,
            Err(reason) => {
                // No detail in the body: a reason tells a prober how close they are.
                eprintln!("refused: {reason}");
                let _ = request.respond(Response::from_string("unauthorized").with_status_code(401));
                continue;
            }
        };

        // THE HELLO: the signed, empty-body check sent when you publish.
        // Answer with the proof and run nothing.
        if raw_body.is_empty() {
            let _ = request.respond(json_response(200, &proof, None));
            continue;
        }

        let response = match serde_json::from_slice::<Value>(&raw_body) {
            Err(_) => json_response(400, &proof, Some(&json!({ "error": "body is not JSON" }))),
            Ok(call) => {
                let params = call.get("params").cloned().unwrap_or(Value::Null);
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                let tool = name.rsplit('/').next().unwrap_or("");
                let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                let (status, result) = run_tool(tool, &args);
                json_response(status, &proof, Some(&result))
            }
        };
        let _ = request.respond(response);
    }
}

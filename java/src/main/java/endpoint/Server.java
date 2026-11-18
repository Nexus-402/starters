package endpoint;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

/**
 * A complete Nexus402 creator endpoint for Java 17 or later. One library,
 * Jackson, for JSON; the HTTP server and Ed25519 are in the JDK.
 *
 * <p>{@code mvn -q package && java -jar target/nexus-endpoint.jar}. Set four
 * environment variables, put it behind HTTPS, and publish its URL.
 * {@code ../starters_test.go} builds this kit from an empty directory and drives
 * it with the gateway's REAL signer.
 *
 * <p>The gateway answers {@code initialize}, {@code tools/list} and
 * notifications itself, from the description and input schema you publish;
 * only {@code tools/call} reaches you, already charged.
 *
 * <pre>
 *   PORT                    where to listen (default 8080)
 *   NEXUS_REGISTERED_HOST   the host you published, e.g. mcp.acme.example
 *   NEXUS_CREATOR_KEY       your nx_crt_ key, shown once when you claimed a handle
 *   NEXUS_PUBLIC_KEY        the gateway's Ed25519 key(s), base64, comma-separated
 *                           (GET https://api.nexus402.dev/v1/signing-key lists them)
 * </pre>
 */
public final class Server {
  /** The gateway's own cap on a request body. Anything larger did not come from it. */
  private static final int MAX_BODY_BYTES = 10 * 1024 * 1024;

  private static final ObjectMapper JSON = new ObjectMapper();

  /** A status and the bare MCP result. */
  record ToolAnswer(int status, Object result) {}

  /**
   * YOUR TOOLS. {@code tool} is the last segment of the published name
   * ({@code acme/text@v2/word_count} arrives as {@code word_count}).
   *
   * <p>Return the bare MCP result. The gateway wraps it in the JSON-RPC
   * envelope, so your own envelope would nest. {@code isError: true} is still
   * a CHARGED call; return a 4xx when the caller should not pay.
   */
  static ToolAnswer runTool(String tool, JsonNode args) {
    switch (tool) {
      case "word_count": {
        String text = args.path("text").isTextual() ? args.path("text").asText().trim() : "";
        int words = text.isEmpty() ? 0 : text.split("\\s+").length;
        return new ToolAnswer(200, Map.of("content", List.of(Map.of("type", "text", "text", String.valueOf(words)))));
      }
      default:
        return new ToolAnswer(404, Map.of("error", "unknown tool " + tool));
    }
  }

  private final String registeredHost;
  private final String creatorKey;
  private final List<PublicKey> publicKeys;

  private Server(String registeredHost, String creatorKey, List<PublicKey> publicKeys) {
    this.registeredHost = registeredHost;
    this.creatorKey = creatorKey;
    this.publicKeys = publicKeys;
  }

  private static String required(String name) {
    String value = System.getenv(name) == null ? "" : System.getenv(name).trim();
    if (value.isEmpty()) {
      System.err.println(name + " is not set");
      System.exit(1);
    }
    return value;
  }

  public static void main(String[] args) throws Exception {
    String portValue = System.getenv("PORT");
    int port = portValue == null || portValue.isBlank() ? 8080 : Integer.parseInt(portValue.trim());
    String registeredHost = required("NEXUS_REGISTERED_HOST");
    String creatorKey = required("NEXUS_CREATOR_KEY");
    // More than one while the gateway rotates its key: accept any of them.
    List<PublicKey> keys = new ArrayList<>();
    for (String key : required("NEXUS_PUBLIC_KEY").split(",")) {
      keys.add(Verify.publicKeyFromBase64(key));
    }
    Server endpoint = new Server(registeredHost, creatorKey, keys);

    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
    server.createContext("/", endpoint::handle);
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
    System.out.println("listening on :" + port + " for " + registeredHost);
  }

  private void handle(HttpExchange exchange) throws IOException {
    try {
      if (!"POST".equals(exchange.getRequestMethod())) {
        exchange.getResponseHeaders().set("Allow", "POST");
        exchange.sendResponseHeaders(405, -1);
        return;
      }
      byte[] rawBody;
      try (InputStream in = exchange.getRequestBody()) {
        rawBody = in.readNBytes(MAX_BODY_BYTES + 1);
      }
      if (rawBody.length > MAX_BODY_BYTES) {
        exchange.sendResponseHeaders(413, -1);
        return;
      }

      Map<String, String> headers = new HashMap<>();
      exchange.getRequestHeaders().forEach((name, values) -> headers.put(name.toLowerCase(), values.get(0)));
      // The request target exactly as sent: path plus query, still encoded.
      String target = exchange.getRequestURI().getRawPath();
      if (exchange.getRequestURI().getRawQuery() != null) {
        target += "?" + exchange.getRequestURI().getRawQuery();
      }

      long now = System.currentTimeMillis() / 1000;
      Verify.Verdict verdict = Verify.Verdict.refused("no public key");
      for (PublicKey key : publicKeys) {
        verdict = Verify.verifyRequest(headers, rawBody, "POST", target, registeredHost, creatorKey, key, now);
        if (verdict.ok()) {
          break;
        }
      }
      if (!verdict.ok()) {
        // No detail in the body: a reason tells a prober how close they are.
        System.err.println("refused: " + verdict.reason());
        send(exchange, 401, null, "unauthorized".getBytes(StandardCharsets.UTF_8), "text/plain");
        return;
      }

      // THE HELLO: the signed, empty-body check sent when you publish.
      // Answer with the proof and run nothing.
      if (verdict.hello()) {
        send(exchange, 200, verdict.proof(), new byte[0], "application/json");
        return;
      }

      JsonNode call;
      try {
        call = JSON.readTree(rawBody);
      } catch (IOException notJson) {
        send(exchange, 400, verdict.proof(), JSON.writeValueAsBytes(Map.of("error", "body is not JSON")), "application/json");
        return;
      }
      String name = call.path("params").path("name").asText("");
      ToolAnswer answer = runTool(name.substring(name.lastIndexOf('/') + 1), call.path("params").path("arguments"));
      send(exchange, answer.status(), verdict.proof(), JSON.writeValueAsBytes(answer.result()), "application/json");
    } finally {
      exchange.close();
    }
  }

  // The proof goes on EVERY answer to a verified request, errors included, and
  // before sendResponseHeaders: a header set afterwards is never sent.
  private static void send(HttpExchange exchange, int status, String proof, byte[] body, String contentType)
      throws IOException {
    exchange.getResponseHeaders().set("Content-Type", contentType);
    if (proof != null) {
      exchange.getResponseHeaders().set("X-Nexus-Proof", proof);
    }
    exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
    if (body.length > 0) {
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    }
  }
}

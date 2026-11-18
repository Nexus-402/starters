// A complete Nexus402 creator endpoint for C# / .NET 8 or later.
//
// `dotnet run -c Release`. Set four environment variables, put it behind
// HTTPS, and publish its URL. `../starters_test.go` builds this kit from an
// empty directory and drives it with the gateway's REAL signer.
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

using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http.Features;
using NexusEndpoint;

// The gateway's own cap on a request body. Anything larger did not come from it.
const int MaxBodyBytes = 10 * 1024 * 1024;

static string Required(string name)
{
    var value = (Environment.GetEnvironmentVariable(name) ?? "").Trim();
    if (value.Length == 0)
    {
        Console.Error.WriteLine($"{name} is not set");
        Environment.Exit(1);
    }
    return value;
}

// YOUR TOOLS. `tool` is the last segment of the published name
// (`acme/text@v2/word_count` arrives as `word_count`).
//
// Return the status and the bare MCP result. The gateway wraps the result in
// the JSON-RPC envelope, so your own envelope would nest. `isError: true` is
// still a CHARGED call; return a 4xx when the caller should not pay.
static (int Status, object Result) RunTool(string tool, JsonNode? args)
{
    switch (tool)
    {
        case "word_count":
            var text = args?["text"] is JsonValue value && value.TryGetValue(out string? s) ? s.Trim() : "";
            var words = text.Length == 0 ? 0 : text.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries).Length;
            return (200, new { content = new[] { new { type = "text", text = words.ToString() } } });
        default:
            return (404, new { error = $"unknown tool {tool}" });
    }
}

var port = Environment.GetEnvironmentVariable("PORT") is { Length: > 0 } p ? int.Parse(p) : 8080;
var registeredHost = Required("NEXUS_REGISTERED_HOST");
var creatorKey = Required("NEXUS_CREATOR_KEY");
// More than one while the gateway rotates its key: accept any of them.
var publicKeys = Required("NEXUS_PUBLIC_KEY").Split(',').Select(Verify.PublicKeyFromBase64).ToList();

var builder = WebApplication.CreateSlimBuilder(args);
builder.Logging.ClearProviders();
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenAnyIP(port);
    options.Limits.MaxRequestBodySize = MaxBodyBytes;
});
var app = builder.Build();

// The proof goes on EVERY answer to a verified request, errors included.
static async Task Answer(HttpContext context, int status, string? proof, byte[] body, string contentType = "application/json")
{
    context.Response.StatusCode = status;
    context.Response.ContentType = contentType;
    if (proof is not null)
    {
        context.Response.Headers["X-Nexus-Proof"] = proof;
    }
    await context.Response.Body.WriteAsync(body);
}

app.Run(async context =>
{
    if (!HttpMethods.IsPost(context.Request.Method))
    {
        context.Response.Headers.Allow = "POST";
        context.Response.StatusCode = 405;
        return;
    }
    byte[] rawBody;
    try
    {
        using var buffer = new MemoryStream();
        await context.Request.Body.CopyToAsync(buffer);
        rawBody = buffer.ToArray();
    }
    catch (BadHttpRequestException)
    {
        context.Response.StatusCode = 413;
        return;
    }

    string Header(string name) => context.Request.Headers.TryGetValue(name, out var v) ? v.ToString() : "";
    // The request target exactly as sent: path plus query, still encoded.
    // Request.Path is DECODED, so it would not match what the gateway signed.
    var target = context.Features.Get<IHttpRequestFeature>()?.RawTarget ?? "";
    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    var verdict = Verdict.Refused("no public key");
    foreach (var key in publicKeys)
    {
        verdict = Verify.VerifyRequest(Header, rawBody, context.Request.Method, target, registeredHost, creatorKey, key, now);
        if (verdict.Ok)
        {
            break;
        }
    }
    if (!verdict.Ok)
    {
        // No detail in the body: a reason tells a prober how close they are.
        Console.Error.WriteLine($"refused: {verdict.Reason}");
        await Answer(context, 401, null, "unauthorized"u8.ToArray(), "text/plain");
        return;
    }

    // THE HELLO: the signed, empty-body check sent when you publish.
    // Answer with the proof and run nothing.
    if (verdict.Hello)
    {
        await Answer(context, 200, verdict.Proof, []);
        return;
    }

    JsonNode? call;
    try
    {
        call = JsonNode.Parse(rawBody);
    }
    catch (JsonException)
    {
        await Answer(context, 400, verdict.Proof, JsonSerializer.SerializeToUtf8Bytes(new { error = "body is not JSON" }));
        return;
    }
    var name = call?["params"]?["name"] is JsonValue n && n.TryGetValue(out string? s) ? s : "";
    var (status, result) = RunTool(name[(name.LastIndexOf('/') + 1)..], call?["params"]?["arguments"]);
    await Answer(context, status, verdict.Proof, JsonSerializer.SerializeToUtf8Bytes(result));
});

Console.WriteLine($"listening on :{port} for {registeredHost}");
app.Run();

<?php

declare(strict_types=1);

/**
 * A complete Nexus402 creator endpoint for PHP. NO PACKAGES: sodium has been
 * bundled with PHP since 7.2.
 *
 * Put `verify.php` beside this file, set four environment variables, route
 * every request to this file behind HTTPS, and publish its URL. Locally:
 * `php -S 0.0.0.0:8080 index.php`. `../starters_test.go` serves this exact
 * file and drives it with the gateway's REAL signer.
 *
 * The gateway answers `initialize`, `tools/list` and notifications itself,
 * from the description and input schema you publish; only `tools/call`
 * reaches you, already charged.
 *
 *   NEXUS_REGISTERED_HOST   the host you published, e.g. mcp.acme.example
 *   NEXUS_CREATOR_KEY       your nx_crt_ key, shown once when you claimed a handle
 *   NEXUS_PUBLIC_KEY        the gateway's Ed25519 key(s), base64, comma-separated
 *                           (GET https://api.nexus402.dev/v1/signing-key lists them)
 */

require __DIR__ . '/verify.php';

// The gateway's own cap on a request body. Anything larger did not come from it.
const MAX_BODY_BYTES = 10 * 1024 * 1024;

/**
 * YOUR TOOLS. `$tool` is the last segment of the published name
 * (`acme/text@v2/word_count` arrives as `word_count`).
 *
 * Return [status, the bare MCP result]. The gateway wraps the result in the
 * JSON-RPC envelope, so your own envelope would nest. `isError: true` is
 * still a CHARGED call: use it only when the caller's input made your tool fail
 * after it did work. When your tool itself fails, return a 5xx; when the
 * request is wrong before any work, a 4xx. Both refund the caller.
 *
 * @param array<string, mixed> $args
 * @return array{0: int, 1: array<string, mixed>}
 */
function run_tool(string $tool, array $args): array
{
    switch ($tool) {
        case 'word_count':
            $text = is_string($args['text'] ?? null) ? trim($args['text']) : '';
            $words = $text === '' ? 0 : count(preg_split('/\s+/u', $text) ?: []);
            return [200, ['content' => [['type' => 'text', 'text' => (string) $words]]]];
        default:
            return [404, ['error' => "unknown tool {$tool}"]];
    }
}

function required(string $name): string
{
    $value = trim((string) getenv($name));
    if ($value === '') {
        error_log("{$name} is not set");
        http_response_code(500);
        exit;
    }
    return $value;
}

/** @param array<string, mixed>|null $body */
function answer(int $status, ?string $proof, ?array $body): void
{
    // The proof goes on EVERY answer to a verified request, errors included.
    http_response_code($status);
    header('Content-Type: application/json');
    if ($proof !== null) {
        header('X-Nexus-Proof: ' . $proof);
    }
    if ($body !== null) {
        echo json_encode($body, JSON_UNESCAPED_SLASHES);
    }
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit;
}

$registeredHost = required('NEXUS_REGISTERED_HOST');
$creatorKey = required('NEXUS_CREATOR_KEY');
// More than one while the gateway rotates its key: accept any of them.
$publicKeys = array_filter(array_map('trim', explode(',', required('NEXUS_PUBLIC_KEY'))));

$rawBody = (string) file_get_contents('php://input', false, null, 0, MAX_BODY_BYTES + 1);
if (strlen($rawBody) > MAX_BODY_BYTES) {
    http_response_code(413);
    exit;
}

// Header names are case-insensitive; the verifier reads them lowercased.
$headers = array_change_key_case(getallheaders(), CASE_LOWER);

$verdict = [false, 'no public key'];
foreach ($publicKeys as $publicKey) {
    $verdict = nexus_verify_request(
        $headers,
        $rawBody,
        $_SERVER['REQUEST_METHOD'],
        // The request target exactly as sent: path plus query.
        (string) ($_SERVER['REQUEST_URI'] ?? ''),
        $registeredHost,
        $creatorKey,
        $publicKey,
    );
    if ($verdict[0]) {
        break;
    }
}
[$ok, $detail] = $verdict;
if (!$ok) {
    // No detail in the body: a reason tells a prober how close they are.
    error_log("refused: {$detail}");
    http_response_code(401);
    header('Content-Type: text/plain');
    echo 'unauthorized';
    exit;
}
$proof = $detail;

// THE HELLO: the signed, empty-body check sent when you publish. Answer with
// the proof and run nothing.
if ($rawBody === '') {
    answer(200, $proof, null);
    exit;
}

$call = json_decode($rawBody, true);
if (!is_array($call)) {
    answer(400, $proof, ['error' => 'body is not JSON']);
    exit;
}
$params = is_array($call['params'] ?? null) ? $call['params'] : [];
$name = is_string($params['name'] ?? null) ? $params['name'] : '';
$args = is_array($params['arguments'] ?? null) ? $params['arguments'] : [];
$slash = strrpos($name, '/');
[$status, $result] = run_tool($slash === false ? $name : substr($name, $slash + 1), $args);
answer($status, $proof, $result);

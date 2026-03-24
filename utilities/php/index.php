<?php
/**
 * rfed → APNs Push Bridge — Entry Point / Router
 *
 * Deploy as an HTTPS endpoint (nginx/Apache).  All three request paths
 * must be reachable from their callers:
 *
 *   POST /register  — iOS app registers its APNs device token
 *   DELETE /register— iOS app removes its token (on logout / opt-out)
 *   POST /wake      — rns_relay.py notifies bridge of an incoming wake packet
 *   GET  /health    — liveness probe (returns 200 + registration count)
 *
 * Security model
 * ──────────────
 *   /register + DELETE /register:
 *     Callers supply their RNS subscriber hash.  Any caller can register
 *     a token for any hash they claim — this is acceptable because the
 *     hash is derived deterministically from the caller's public key, and
 *     a rogue registration for someone else's hash only wastes one push
 *     (the real device ignores pushes for an unknown subscriber).
 *
 *   /wake:
 *     Protected by the shared bridge_secret in the X-Bridge-Secret header.
 *     Only rns_relay.py (running on the same host) should call this path.
 *     Bind the bridge to 127.0.0.1 and also check the secret for defence
 *     in depth.
 *
 *   /health:
 *     Unauthenticated; returns only a registration count (not hashes).
 *
 * Input validation
 * ─────────────────
 *   subscriber_hash  — must be exactly 32 lowercase hex characters
 *   apns_token       — must be exactly 64 lowercase hex characters
 *   receiver/sender/channel in /wake — same 32-hex rule
 */

declare(strict_types=1);

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/apns.php';

// ── Bootstrap ─────────────────────────────────────────────────────────────────

$cfgFile = file_exists(__DIR__ . '/config.local.php')
    ? __DIR__ . '/config.local.php'
    : __DIR__ . '/config.php';

$cfg = require $cfgFile;

$db   = new TokenDB($cfg['db']['path']);
$apns = new ApnsClient($cfg['apns']);

// ── Routing ───────────────────────────────────────────────────────────────────

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path   = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$path   = rtrim($path, '/') ?: '/';

try {
    match (true) {
        $method === 'POST'   && $path === '/register' => handleRegister($db, $cfg),
        $method === 'DELETE' && $path === '/register' => handleUnregister($db),
        $method === 'POST'   && $path === '/wake'     => handleWake($db, $apns, $cfg),
        $method === 'GET'    && $path === '/health'   => handleHealth($db),
        default                                       => jsonResponse(404, ['error' => 'not found']),
    };
} catch (Throwable $e) {
    bridgeLog('error', 'unhandled exception: ' . $e->getMessage(), $cfg);
    jsonResponse(500, ['error' => 'internal error']);
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/**
 * POST /register
 *
 * Called by the iOS app to register (or refresh) an APNs device token.
 *
 * Request body (JSON):
 *   {
 *     "subscriber_hash": "<32 hex chars>",   // RNS destination hash
 *     "apns_token":      "<64 hex chars>"    // APNs device token
 *   }
 *
 * Response 200:  { "status": "registered" }
 * Response 400:  { "error": "..." }
 */
function handleRegister(TokenDB $db, array $cfg): void
{
    $body = readJsonBody();

    $hash  = validateHash32($body['subscriber_hash'] ?? null, 'subscriber_hash');
    $token = validateHex64($body['apns_token'] ?? null);

    $db->register($hash, $token);
    bridgeLog('info', "registered apns_token for $hash", $cfg);
    jsonResponse(200, ['status' => 'registered']);
}

/**
 * DELETE /register
 *
 * Called by the iOS app to remove its token (logout / notification opt-out).
 *
 * Request body (JSON):
 *   { "subscriber_hash": "<32 hex chars>" }
 *
 * Response 200:  { "status": "unregistered" }
 * Response 404:  { "error": "not found" }
 */
function handleUnregister(TokenDB $db): void
{
    $body = readJsonBody();
    $hash = validateHash32($body['subscriber_hash'] ?? null, 'subscriber_hash');

    if ($db->unregister($hash)) {
        jsonResponse(200, ['status' => 'unregistered']);
    } else {
        jsonResponse(404, ['error' => 'not found']);
    }
}

/**
 * POST /wake
 *
 * Called by rns_relay.py when rfed sends a notify wake packet to the relay.
 * Protected by the X-Bridge-Secret header.
 *
 * Request body (JSON):
 *   {
 *     "receiver": "<32 hex chars>",           // always present
 *     "sender":   "<32 hex chars>",           // optional
 *     "channel":  "<32 hex chars>"            // optional
 *   }
 *
 * Response 200:  { "status": "pushed" | "no_token" }
 * Response 401:  { "error": "forbidden" }
 * Response 400:  { "error": "..." }
 */
function handleWake(TokenDB $db, ApnsClient $apns, array $cfg): void
{
    // Validate the internal shared secret.
    $provided = $_SERVER['HTTP_X_BRIDGE_SECRET'] ?? '';
    if (!hash_equals($cfg['bridge_secret'], $provided)) {
        jsonResponse(401, ['error' => 'forbidden']);
        return;
    }

    $body         = readJsonBody();
    $receiverHash = validateHash32($body['receiver'] ?? null, 'receiver');
    $senderHash   = isset($body['sender'])  ? validateHash32($body['sender'],  'sender')  : null;
    $channelHash  = isset($body['channel']) ? validateHash32($body['channel'], 'channel') : null;

    $apnsToken = $db->getToken($receiverHash);
    if ($apnsToken === null) {
        bridgeLog('debug', "no token for receiver $receiverHash — skipping push", $cfg);
        jsonResponse(200, ['status' => 'no_token']);
        return;
    }

    $result = $apns->send($apnsToken, $receiverHash, $senderHash, $channelHash);

    if ($result->success) {
        bridgeLog('info', "push sent for receiver $receiverHash", $cfg);
        jsonResponse(200, ['status' => 'pushed']);
        return;
    }

    // APNs told us the token is no longer valid — remove it so we don't
    // keep sending to a dead token.
    if ($result->shouldInvalidateToken()) {
        $db->invalidateToken($apnsToken);
        bridgeLog('info',
            "token invalidated for $receiverHash (APNs reason: {$result->reason})", $cfg);
        jsonResponse(200, ['status' => 'token_invalidated']);
        return;
    }

    bridgeLog('error',
        "APNs error for $receiverHash: HTTP {$result->httpCode} reason={$result->reason}", $cfg);
    jsonResponse(502, ['error' => 'apns_error', 'reason' => $result->reason]);
}

/**
 * GET /health
 *
 * Returns 200 and the number of registered tokens.  Useful for uptime
 * monitors.
 */
function handleHealth(TokenDB $db): void
{
    jsonResponse(200, ['status' => 'ok', 'registered_tokens' => $db->count()]);
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Read, decode, and return the JSON request body. */
function readJsonBody(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        jsonResponse(400, ['error' => 'empty request body']);
        exit;
    }
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        jsonResponse(400, ['error' => 'invalid JSON']);
        exit;
    }
    return $decoded;
}

/**
 * Validate a 32-char lowercase hex RNS destination hash.
 * Exits with a 400 response on failure.
 */
function validateHash32(mixed $value, string $field): string
{
    if (!is_string($value) || !preg_match('/^[0-9a-f]{32}$/', $value)) {
        jsonResponse(400, ['error' => "$field must be a 32-char lowercase hex string"]);
        exit;
    }
    return $value;
}

/**
 * Validate a 64-char lowercase hex APNs device token.
 * Exits with a 400 response on failure.
 */
function validateHex64(mixed $value): string
{
    if (!is_string($value) || !preg_match('/^[0-9a-f]{64}$/', $value)) {
        jsonResponse(400, ['error' => 'apns_token must be a 64-char lowercase hex string']);
        exit;
    }
    return $value;
}

/** Emit a JSON response and exit. */
function jsonResponse(int $code, array $data): void
{
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

/** Append a line to the bridge log file. */
function bridgeLog(string $level, string $message, array $cfg): void
{
    $cfgLevel = $cfg['log']['level'] ?? 'info';
    $levels   = ['debug' => 0, 'info' => 1, 'error' => 2];
    if (($levels[$level] ?? 1) < ($levels[$cfgLevel] ?? 1)) {
        return;
    }
    $line = sprintf("[%s] [%s] %s\n", date('Y-m-d H:i:s'), strtoupper($level), $message);
    file_put_contents($cfg['log']['path'] ?? '/tmp/bridge.log', $line, FILE_APPEND | LOCK_EX);
}

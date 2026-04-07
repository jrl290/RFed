<?php
/**
 * rfed → APNs Bridge — APNs HTTP/2 Client
 *
 * Sends push notifications to Apple APNs using token-based auth (p8 key).
 *
 * Requirements
 * ────────────
 *   PHP >= 8.1
 *   - ext-curl compiled with HTTP/2 (libcurl + nghttp2)
 *   - ext-openssl
 *
 * Verify HTTP/2 support:
 *   php -r "var_dump(defined('CURL_HTTP_VERSION_2'));"
 *   php -r "echo curl_version()['features'] & CURL_VERSION_HTTP2 ? 'HTTP/2 OK' : 'no HTTP/2';"
 *
 * APNs token-based auth overview
 * ───────────────────────────────
 * Each request carries a short-lived ES256 JWT in the Authorization header.
 * The JWT is generated from the p8 private key and is valid for up to 1 hour.
 * A single cached token is reused across requests until it ages past the
 * configured TTL, then a fresh one is generated.
 *
 * Apple documentation:
 *   https://developer.apple.com/documentation/usernotifications/setting_up_a_remote_notification_server/establishing_a_token-based_connection_to_apns
 */

class ApnsClient
{
    // APNs HTTP/2 endpoints
    private const PROD_HOST    = 'https://api.push.apple.com';
    private const SANDBOX_HOST = 'https://api.sandbox.push.apple.com';

    private string $keyFile;
    private string $keyId;
    private string $teamId;
    private string $bundleId;
    private bool   $sandbox;
    private string $pushType;
    private string $alertTitle;
    private string $alertBody;
    private int    $tokenTtl;

    /** Cached JWT and the Unix timestamp it was signed. */
    private ?string $cachedJwt       = null;
    private int     $cachedJwtIssuedAt = 0;

    /** @param array $cfg  The 'apns' sub-array from config.php */
    public function __construct(array $cfg)
    {
        $this->keyFile    = $cfg['key_file'];
        $this->keyId      = $cfg['key_id'];
        $this->teamId     = $cfg['team_id'];
        $this->bundleId   = $cfg['bundle_id'];
        $this->sandbox    = (bool) ($cfg['sandbox'] ?? false);
        $this->pushType   = $cfg['push_type']   ?? 'alert';
        $this->alertTitle = $cfg['alert_title'] ?? 'New message';
        $this->alertBody  = $cfg['alert_body']  ?? 'You have a new message.';
        $this->tokenTtl   = (int) ($cfg['token_ttl'] ?? 3000);
    }

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Send a wake-up push to a device.
     *
     * @param string      $apnsToken       64-char hex APNs device token
     * @param string      $receiverHash    32-char hex subscriber destination hash
     * @param string|null $senderHash      32-char hex sender hash (optional)
     * @param string|null $channelHash     32-char hex channel hash (optional)
     * @return ApnsResult
     */
    public function send(
        string  $apnsToken,
        string  $receiverHash,
        ?string $senderHash  = null,
        ?string $channelHash = null,
    ): ApnsResult {
        $host  = $this->sandbox ? self::SANDBOX_HOST : self::PROD_HOST;
        $url   = $host . '/3/device/' . $apnsToken;
        $jwt   = $this->freshJwt();

        // Build the notification payload.  No message content is included —
        // only the subscriber hash so the app can trigger a targeted fetch.
        $payload = $this->buildPayload($receiverHash, $senderHash, $channelHash);

        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_2,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $payload,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 10,
            CURLOPT_HTTPHEADER     => [
                'Authorization: bearer ' . $jwt,
                'apns-topic: '    . $this->bundleId,
                'apns-push-type: ' . $this->pushType,
                'apns-priority: 5',    // 10 = immediate, 5 = conserve power
                'Content-Type: application/json',
            ],
        ]);

        $body       = curl_exec($ch);
        $httpCode   = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError  = curl_error($ch);
        curl_close($ch);

        if ($curlError !== '') {
            return new ApnsResult(false, 0, null, 'curl: ' . $curlError);
        }

        // APNs returns 200 on success.  Any other status carries a JSON body
        // with {"reason": "..."}  (and optionally "timestamp" for 410).
        if ($httpCode === 200) {
            return new ApnsResult(true, 200);
        }

        $decoded = is_string($body) ? json_decode($body, true) : null;
        $reason  = $decoded['reason'] ?? 'unknown';

        return new ApnsResult(false, $httpCode, $reason, $body ?: '');
    }

    // ── JWT generation ────────────────────────────────────────────────────

    /**
     * Return the cached JWT if still fresh, otherwise generate a new one.
     *
     * The JWT is an ES256 (ECDSA P-256 + SHA-256) token.  Apple rejects
     * tokens signed more than 1 hour ago.  We regenerate after $tokenTtl
     * seconds (default 50 min) to provide comfortable headroom.
     */
    private function freshJwt(): string
    {
        if ($this->cachedJwt !== null && (time() - $this->cachedJwtIssuedAt) < $this->tokenTtl) {
            return $this->cachedJwt;
        }

        $this->cachedJwtIssuedAt = time();
        $this->cachedJwt         = $this->generateJwt($this->cachedJwtIssuedAt);
        return $this->cachedJwt;
    }

    /**
     * Generate an APNs ES256 JWT.
     *
     * Steps:
     *   1. Build JOSE header and payload, base64url-encode each.
     *   2. Sign the concatenation with the p8 EC private key using SHA-256.
     *   3. Convert DER-encoded ECDSA signature to raw R‖S (64 bytes).
     *   4. Return the three-part dot-joined JWT string.
     *
     * @param int $iat  Unix timestamp for the iat claim
     */
    private function generateJwt(int $iat): string
    {
        $header  = $this->base64url(json_encode([
            'alg' => 'ES256',
            'kid' => $this->keyId,
        ]));
        $payload = $this->base64url(json_encode([
            'iss' => $this->teamId,
            'iat' => $iat,
        ]));

        $signingInput = $header . '.' . $payload;

        $pemKey = file_get_contents($this->keyFile);
        if ($pemKey === false) {
            throw new RuntimeException('APNs: cannot read key file: ' . $this->keyFile);
        }

        // Apple p8 files are PKCS#8 PEM; openssl_sign accepts them directly.
        $privateKey = openssl_pkey_get_private($pemKey);
        if ($privateKey === false) {
            throw new RuntimeException('APNs: cannot parse key file: ' . openssl_error_string());
        }

        // openssl_sign with SHA256 on an EC key produces DER-encoded ECDSA.
        $derSig = '';
        if (!openssl_sign($signingInput, $derSig, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('APNs: signing failed: ' . openssl_error_string());
        }

        $rawSig = $this->derToRawEcdsa($derSig);
        return $signingInput . '.' . $this->base64url($rawSig);
    }

    /**
     * Convert a DER-encoded ECDSA signature to the raw R‖S format (64 bytes)
     * required by ES256 JWT.
     *
     * DER layout:
     *   30 len
     *     02 rLen r…
     *     02 sLen s…
     *
     * Both R and S may be padded with a leading 0x00 byte when the high bit
     * is set (to indicate a positive integer in DER) — strip that padding and
     * left-pad the output value to exactly 32 bytes.
     */
    private function derToRawEcdsa(string $der): string
    {
        $offset = 0;

        if (ord($der[$offset++]) !== 0x30) {
            throw new RuntimeException('APNs JWT: invalid DER: missing SEQUENCE tag');
        }

        // Skip length byte(s) — the overall sequence length.
        $seqLen = ord($der[$offset++]);
        if ($seqLen & 0x80) {
            $offset += $seqLen & 0x7f;  // long-form length (rare for P-256)
        }

        $extractInt = function (string $der, int &$pos): string {
            if (ord($der[$pos++]) !== 0x02) {
                throw new RuntimeException('APNs JWT: invalid DER: missing INTEGER tag');
            }
            $len = ord($der[$pos++]);
            $val = substr($der, $pos, $len);
            $pos += $len;
            // Strip optional leading 0x00 padding byte.
            if ($len > 32 && ord($val[0]) === 0x00) {
                $val = substr($val, 1);
            }
            // Left-pad to 32 bytes if shorter.
            return str_pad($val, 32, "\x00", STR_PAD_LEFT);
        };

        $r = $extractInt($der, $offset);
        $s = $extractInt($der, $offset);

        return $r . $s;
    }

    // ── Payload builder ───────────────────────────────────────────────────

    /**
     * Build the APNs JSON payload.
     *
     * The `rfed` section carries the RNS hashes so the app can display a
     * targeted notification and trigger the correct data fetch.  No message
     * content is included (privacy-by-design).
     */
    private function buildPayload(
        string  $receiverHash,
        ?string $senderHash,
        ?string $channelHash,
    ): string {
        $rfed = ['receiver' => $receiverHash];
        if ($senderHash  !== null) $rfed['sender']  = $senderHash;
        if ($channelHash !== null) $rfed['channel'] = $channelHash;

        $payload = [
            'aps' => [
                'alert' => [
                    'title' => $this->alertTitle,
                    'body'  => $this->alertBody,
                ],
                'sound'             => 'default',
                'content-available' => 1,  // allow silent background fetch
            ],
            'rfed' => $rfed,
        ];

        return json_encode($payload, JSON_UNESCAPED_SLASHES);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /** RFC 4648 §5 base64url encoding (no padding). */
    private function base64url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }
}

// ── Value object for APNs send results ───────────────────────────────────────

class ApnsResult
{
    public function __construct(
        public readonly bool    $success,
        public readonly int     $httpCode,
        public readonly ?string $reason   = null,
        public readonly string  $rawBody  = '',
    ) {}

    /**
     * Whether the APNs token should be removed from the registry.
     *
     * Apple returns these reasons for permanently invalid tokens:
     *   410 Unregistered  — device unregistered; uses "timestamp" field
     *   400 BadDeviceToken — malformed token
     */
    public function shouldInvalidateToken(): bool
    {
        return $this->httpCode === 410
            || ($this->httpCode === 400 && $this->reason === 'BadDeviceToken');
    }
}

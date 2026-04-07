<?php
/**
 * rfed → APNs Push Bridge — Configuration
 *
 * Copy this file to config.local.php and fill in your values.
 * config.local.php is gitignored; never commit credentials.
 *
 * Architecture summary:
 *   [rfed node] ──rfed.notify packet─▶ [rns_relay.py]
 *               ──HTTP POST /wake────▶ [this bridge]
 *               ──HTTP POST /register▶ [this bridge]
 *                                            │
 *                                       APNs HTTP/2
 *                                            │
 *                                       iOS device
 */

return [

    // ── APNs JWT credentials ────────────────────────────────────────────────
    // Use token-based auth (p8 key).  Never commit these.
    //
    'apns' => [
        // Absolute path to the .p8 private key file downloaded from
        // App Store Connect → Keys → APNs.
        'key_file'   => '/var/secrets/apns/AuthKey_XXXXXXXXXX.p8',

        // 10-character Key ID from App Store Connect (e.g. "XXXXXXXXXX").
        'key_id'     => 'XXXXXXXXXX',

        // 10-character Apple Team ID from App Store Connect.
        'team_id'    => 'XXXXXXXXXX',

        // Bundle ID of the iOS application (must match the APNs entitlement).
        'bundle_id'  => 'com.example.retichat',

        // true  → use APNs sandbox (development builds)
        // false → use APNs production
        'sandbox'    => false,

        // APNs push type: 'alert', 'background', 'voip', 'complication',
        // 'fileprovider', 'mdm'.  'alert' is correct for most apps.
        'push_type'  => 'alert',

        // Default alert title sent to the device.  The app sees no message
        // content — only the subscriber hash — so keep this generic.
        'alert_title' => 'New message',
        'alert_body'  => 'You have a new message waiting.',

        // JWT lifespan in seconds.  Apple rejects tokens older than 1 hour.
        // Regenerate if the cached token is older than this threshold.
        'token_ttl'  => 3000,  // 50 minutes — well within the 60-minute limit
    ],

    // ── SQLite token registry ───────────────────────────────────────────────
    // Maps subscriber RNS destination hashes to APNs device tokens.
    'db' => [
        'path' => __DIR__ . '/tokens.db',
    ],

    // ── Internal bridge security ────────────────────────────────────────────
    // The /wake endpoint is called by rns_relay.py running on the same host.
    // This shared secret prevents external callers from triggering pushes.
    // Generate with: openssl rand -hex 32
    'bridge_secret' => 'REPLACE_WITH_SECURE_RANDOM_HEX_STRING',

    // ── Logging ─────────────────────────────────────────────────────────────
    'log' => [
        'path'  => __DIR__ . '/bridge.log',
        'level' => 'info',   // 'debug' | 'info' | 'error'
    ],
];

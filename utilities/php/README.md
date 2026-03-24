# rfed → APNs Push Bridge

A PHP HTTP bridge + Python Reticulum relay listener that connects the rfed
notify system (§9 of the SPEC) to Apple APNs push notifications.

## Architecture

```
┌────────────┐  rfed.notify  ┌────────────────┐  HTTP POST  ┌──────────────────┐
│  rfed node │──────────────▶│  rns_relay.py  │────────────▶│  PHP bridge      │
└────────────┘               │  (RNS Single   │  /wake       │  (index.php)     │
                             │   destination) │              │                  │
                             └────────────────┘              │  APNs HTTP/2 API │
                                                             │        │         │
                                                             └────────┼─────────┘
                                                                      │ APNs push
┌────────────┐  HTTP POST    ┌──────────────────┐                    ▼
│  iOS app   │──────────────▶│  PHP bridge      │             ┌──────────────┐
│            │   /register   │  (index.php)     │             │  iOS device  │
└────────────┘               └──────────────────┘             └──────────────┘
```

**rfed never holds APNs credentials.**  The relay operator manages all
platform integrations:

- `rns_relay.py` acts as the `rfed.notify` Reticulum destination that rfed
  addresses when dispatching wake packets.
- The PHP bridge stores APNs device tokens (indexed by subscriber RNS hash)
  and sends pushes via APNs HTTP/2.
- No message content leaves rfed — only subscriber/sender/channel hashes
  are transmitted.

---

## Files

| File | Purpose |
|------|---------|
| `config.php` | Configuration template — copy to `config.local.php` and fill in |
| `db.php` | SQLite token registry (`subscriber_hash → apns_token`) |
| `apns.php` | APNs HTTP/2 client with ES256 JWT auth |
| `index.php` | HTTP router: `/register`, `/wake`, `/health` |
| `rns_relay.py` | Python Reticulum `rfed.notify` relay listener |
| `rns_relay.conf.example` | Example config for `rns_relay.py` |

---

## Requirements

### PHP bridge
- PHP ≥ 8.1
- `ext-curl` compiled with HTTP/2 support (libcurl + nghttp2)
- `ext-openssl`
- `ext-pdo_sqlite`
- An HTTPS-accessible web server (nginx or Apache)

Verify HTTP/2 curl support:
```bash
php -r "echo curl_version()['features'] & CURL_VERSION_HTTP2 ? 'HTTP/2 OK' : 'no HTTP/2';"
```

### Python relay listener
- Python ≥ 3.10
- `pip install rns msgpack`

---

## Setup

### 1. APNs key

In App Store Connect → Certificates, Identifiers & Profiles → Keys:
1. Create an "Apple Push Notifications service (APNs)" key.
2. Download the `.p8` file — **you can only download it once**.
3. Note the **Key ID** (10 chars) and your **Team ID** (from your account).

### 2. PHP bridge

```bash
cp config.php config.local.php
# Edit config.local.php: fill in apns.key_file, key_id, team_id, bundle_id
# and generate a bridge_secret with: openssl rand -hex 32

# Deploy index.php, apns.php, db.php, config.local.php to your web root.
# The SQLite database is created automatically on first request.
```

Nginx config fragment:
```nginx
server {
    listen 443 ssl;
    server_name notify.example.com;

    root /var/www/rfed-bridge;
    index index.php;

    location / {
        try_files $uri /index.php?$query_string;
    }
    location ~ \.php$ {
        fastcgi_pass unix:/run/php/php8.1-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    # Block external access to /wake — only rns_relay.py on localhost calls it.
    location /wake {
        allow 127.0.0.1;
        deny all;
        try_files $uri /index.php;
    }
}
```

### 3. Python relay listener

```bash
cp rns_relay.conf.example rns_relay.conf
# Edit rns_relay.conf: set bridge_secret to match config.local.php

pip install rns msgpack
python3 rns_relay.py --config rns_relay.conf
```

On first run, a new Reticulum identity is created at `identity_path`.
Note the logged hex hash — this is the relay destination hash you register
in rfed.

### 4. Register the relay with rfed

In rfed.toml, set `allow_push_registration = true` (already default).  Then
from the iOS app (or a test script), send an `/rfed/notify/register` packet
to the rfed node containing the relay's 32-char hex destination hash.

### 5. Register APNs token from the iOS app

The iOS app calls `POST /register` on the PHP bridge at startup and whenever
`UIApplication.didRegisterForRemoteNotificationsWithDeviceToken` fires:

```swift
// Swift example (URLSession)
struct RegisterBody: Encodable {
    let subscriber_hash: String  // RNS destination hash (hex)
    let apns_token: String       // device token (hex, lowercase)
}

let body = RegisterBody(
    subscriber_hash: identity.hexHash,
    apns_token: deviceToken.map { String(format: "%02x", $0) }.joined()
)
var req = URLRequest(url: URL(string: "https://notify.example.com/register")!)
req.httpMethod = "POST"
req.setValue("application/json", forHTTPHeaderField: "Content-Type")
req.httpBody = try JSONEncoder().encode(body)
URLSession.shared.dataTask(with: req).resume()
```

---

## HTTP API

### `POST /register`

Register or refresh an APNs device token.

**Request body**
```json
{
  "subscriber_hash": "aabbccdd11223344aabbccdd11223344",
  "apns_token": "0123456789abcdef..."
}
```

**Response**
```json
{ "status": "registered" }
```

---

### `DELETE /register`

Remove a device token (call on logout / push opt-out).

**Request body**
```json
{ "subscriber_hash": "aabbccdd11223344aabbccdd11223344" }
```

---

### `POST /wake`  *(internal — localhost only)*

Called by `rns_relay.py` when rfed sends a wake packet.  Requires
`X-Bridge-Secret` header.

**Request body**
```json
{
  "receiver": "aabbccdd11223344aabbccdd11223344",
  "sender":   "11223344aabbccdd11223344aabbccdd",
  "channel":  "deadbeefdeadbeefdeadbeefdeadbeef"
}
```

`sender` and `channel` are optional.

**Response**
```json
{ "status": "pushed" }
```

---

### `GET /health`

Unauthenticated liveness probe.

**Response**
```json
{ "status": "ok", "registered_tokens": 42 }
```

---

## Privacy

- The PHP bridge stores only `subscriber_hash → apns_token` mappings.
- No message content, sender identities, or channel names are ever
  transmitted to APNs — only a generic "wake up" alert.
- The optional `rfed` payload key in the APNs notification carries only
  destination hashes, enabling the app to trigger a targeted fetch without
  revealing content.
- `rns_relay.py` never stores any data.

---

## Security notes

- Deploy the bridge behind HTTPS only.
- Restrict `/wake` to `127.0.0.1` at the web server level (see nginx
  config above) **and** verify `X-Bridge-Secret` in PHP (defence in depth).
- Store `config.local.php` outside the web root or deny access to it:
  ```nginx
  location ~ \.php$ { ... }
  location = /config.local.php { deny all; }
  ```
- The SQLite database file must not be web-accessible.  Place it outside
  the document root or deny access explicitly.
- Rotate `bridge_secret` if the host is compromised.

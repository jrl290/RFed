//! Reticulum bridge: wires up `rfed.notify` and `rfed.apns` destinations,
//! dispatches wake packets to APNs, and handles token registration.

use std::io::Cursor;
use std::sync::{Arc, Mutex, atomic::{AtomicU64, Ordering}};
use std::thread;
use std::time::Duration;

use log::{debug, error, info, warn};
use rmpv::decode::read_value;
use rmpv::Value;

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::link::LinkHandle;
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::transport::Transport;

use crate::apns::{ApnsSender, SendResult};
use crate::config::BridgeConfig;
use crate::db::{ApnsEnv, TokenDB};

const NOTIFY_APP:    &str = "rfed";
const NOTIFY_ASPECT: &str = "notify";
const APNS_APP:      &str = "rfed";
const APNS_ASPECT:   &str = "apns";

const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(600);

// ── Shared state ──────────────────────────────────────────────────────────────

struct BridgeState {
    db:           Arc<Mutex<TokenDB>>,
    apns:         Arc<ApnsSender>,
    notify_count: AtomicU64,
    push_count:   AtomicU64,
    push_fail:    AtomicU64,
}

// ── Bridge entry point ─────────────────────────────────────────────────────────

pub fn run(cfg: &BridgeConfig, db: TokenDB, apns: ApnsSender) -> Result<(), String> {
    // ── Init Reticulum ────────────────────────────────────────────────────────
    let _rns_dir = init_reticulum(cfg)?;

    // ── Load / create identity ────────────────────────────────────────────────
    let identity = load_or_create_identity(&cfg.identity_path)?;
    if let Some(h) = &identity.hash {
        info!("Bridge identity: {}", hex::encode(h));
    }

    // ── Shared state ──────────────────────────────────────────────────────────
    let state = Arc::new(BridgeState {
        db:           Arc::new(Mutex::new(db)),
        apns:         Arc::new(apns),
        notify_count: AtomicU64::new(0),
        push_count:   AtomicU64::new(0),
        push_fail:    AtomicU64::new(0),
    });

    // ── rfed.notify destination ───────────────────────────────────────────────
    let mut notify_dest = Destination::new_inbound(
        Some(identity.clone()),
        DestinationType::Single,
        NOTIFY_APP.to_string(),
        vec![NOTIFY_ASPECT.to_string()],
    )
    .map_err(|e| format!("cannot create rfed.notify destination: {e}"))?;
    info!("rfed.notify hash: {}", hex_dest(&notify_dest));

    // Plain-packet callback (fire-and-forget wake packet, no Link)
    {
        let state2 = Arc::clone(&state);
        notify_dest.set_packet_callback(Some(Arc::new(move |data: &[u8], _pkt| {
            debug!("[rfed.notify] inbound packet from transport, size={}", data.len());
            let raw = data.to_vec();
            let s = Arc::clone(&state2);
            thread::spawn(move || dispatch_wake(raw, &s));
        })));
    }

    // Link-established callback — rfed nodes may also open a Link first
    {
        let state2 = Arc::clone(&state);
        notify_dest.set_link_established_callback(Some(Arc::new(move |link: LinkHandle| {
            debug!("[rfed.notify] link established");
            let s = Arc::clone(&state2);
            link.set_packet_callback(Some(Arc::new(move |data: &[u8], _pkt| {
                debug!("[rfed.notify] inbound packet from link, size={}", data.len());
                let raw = data.to_vec();
                let s2 = Arc::clone(&s);
                thread::spawn(move || dispatch_wake(raw, &s2));
            })));
        })));
    }

    Transport::register_destination(notify_dest.clone());

    // ── rfed.apns registration destination ───────────────────────────────────
    let mut apns_dest = Destination::new_inbound(
        Some(identity.clone()),
        DestinationType::Single,
        APNS_APP.to_string(),
        vec![APNS_ASPECT.to_string()],
    )
    .map_err(|e| format!("cannot create rfed.apns destination: {e}"))?;
    info!("rfed.apns  hash: {}", hex_dest(&apns_dest));

    {
        let state2 = Arc::clone(&state);
        apns_dest.set_packet_callback(Some(Arc::new(move |data: &[u8], _pkt| {
            handle_register(data, &state2);
        })));
    }

    {
        let state2 = Arc::clone(&state);
        apns_dest.set_link_established_callback(Some(Arc::new(move |link: LinkHandle| {
            debug!("[rfed.apns] link established");
            let s = Arc::clone(&state2);
            link.set_packet_callback(Some(Arc::new(move |data: &[u8], _pkt| {
                debug!("[rfed.apns] inbound packet from link, size={}", data.len());
                handle_register(data, &s);
            })));
        })));
    }

    Transport::register_destination(apns_dest.clone());

    // ── Initial announces ─────────────────────────────────────────────────────
    notify_dest.announce(None, false, None, None, true)
        .map_err(|e| format!("announce failed: {e}"))?;
    apns_dest.announce(None, false, None, None, true)
        .map_err(|e| format!("announce failed: {e}"))?;

    let reg_count = state.db.lock().unwrap().count().unwrap_or(0);
    info!("Bridge running — {} tokens registered", reg_count);

    // ── Main loop (periodic re-announce) ──────────────────────────────────────
    loop {        thread::sleep(ANNOUNCE_INTERVAL);
        let _ = notify_dest.announce(None, false, None, None, true);
        let _ = apns_dest.announce(None, false, None, None, true);
        debug!("Periodic announces sent");
    }
}

// ── Reticulum initialisation ──────────────────────────────────────────────────

fn init_reticulum(cfg: &BridgeConfig) -> Result<std::path::PathBuf, String> {
    if let Some(rns_config) = &cfg.rns_config {
        let dir = std::path::PathBuf::from(rns_config);
        info!("Using external Reticulum config dir {}", dir.display());
        Reticulum::init(Some(dir.clone()), None, None, None, false, None)
            .map_err(|e| format!("Reticulum init failed: {e}"))?;
        return Ok(dir);
    }

    let endpoints = cfg.legacy_tcp_endpoints();
    if cfg.has_legacy_tcp_config() {
        if endpoints.is_empty() {
            return Err(
                "legacy bridge transport config is incomplete; use bridge.rns_config or native [reticulum]/[interfaces] sections instead".to_string(),
            );
        }

        warn!(
            "bridge.rns_tcp_host / rns_tcp_port / rns_tcp_endpoints is deprecated; use native [interfaces] entries in the main config file"
        );

        // Compatibility path: synthesize a minimal Reticulum config next to the
        // identity file for older bridge configs that still use bridge.rns_tcp_*.
        let identity_path = std::path::Path::new(&cfg.identity_path);
        let config_dir = identity_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("reticulum");
        std::fs::create_dir_all(&config_dir)
            .map_err(|e| format!("cannot create reticulum dir: {e}"))?;

        let mut config_text = String::new();
        config_text.push_str("[reticulum]\n  enable_transport = false\n  share_instance = false\n\n");
        config_text.push_str("[interfaces]\n");
        for (idx, (host, port)) in endpoints.iter().enumerate() {
            config_text.push_str(&format!(
                "\n  [[ApnsBridgeTCP{n}]]\n    type = TCPClientInterface\n    target_host = {host}\n    target_port = {port}\n    enabled = yes\n",
                n = idx + 1,
            ));
        }

        let config_file = config_dir.join("config");
        std::fs::write(&config_file, &config_text)
            .map_err(|e| format!("cannot write reticulum config: {e}"))?;

        let summary = endpoints
            .iter()
            .map(|(h, p)| format!("{h}:{p}"))
            .collect::<Vec<_>>()
            .join(", ");
        info!(
            "Using {} legacy TCP interface(s) → {} (configdir: {})",
            endpoints.len(),
            summary,
            config_dir.display(),
        );

        Reticulum::init(Some(config_dir.clone()), None, None, None, false, None)
            .map_err(|e| format!("Reticulum init failed: {e}"))?;
        return Ok(config_dir);
    }

    if !cfg.has_native_reticulum_config() {
        return Err(
            "config must include native [reticulum] and [interfaces] sections, or use the legacy bridge.rns_config / bridge.rns_tcp_* keys"
                .to_string(),
        );
    }

    // Preferred path: use the same config file format as rfed/rnsd. Copy the
    // whole bridge config into a private `_rns/config` so Reticulum reads the
    // native `[reticulum]` / `[interfaces]` sections directly and ignores the
    // bridge-specific `[bridge]` / `[apns]` sections.
    let config_dir = cfg
        .config_file
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("_rns");
    std::fs::create_dir_all(&config_dir)
        .map_err(|e| format!("cannot create reticulum dir: {e}"))?;
    let config_file = config_dir.join("config");
    if cfg.config_file != config_file {
        std::fs::copy(&cfg.config_file, &config_file)
            .map_err(|e| format!("cannot prepare reticulum config: {e}"))?;
    }
    info!(
        "Using native Reticulum config from {} (configdir: {})",
        cfg.config_file.display(),
        config_dir.display(),
    );

    Reticulum::init(Some(config_dir.clone()), None, None, None, false, None)
        .map_err(|e| format!("Reticulum init failed: {e}"))?;
    Ok(config_dir)
}

// ── Identity ──────────────────────────────────────────────────────────────────

fn load_or_create_identity(path_str: &str) -> Result<Identity, String> {
    let path = std::path::Path::new(path_str);
    if path.exists() {
        let id = Identity::from_file(path)
            .map_err(|e| format!("failed to load identity from {}: {e}", path.display()))?;
        info!("Loaded identity from {}", path.display());
        Ok(id)
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create identity dir: {e}"))?;
        }
        let id = Identity::new(true);
        id.to_file(path)
            .map_err(|e| format!("failed to save identity to {}: {e}", path.display()))?;
        info!("Created new identity at {}", path.display());
        Ok(id)
    }
}

// ── Wake packet dispatch ──────────────────────────────────────────────────────

fn dispatch_wake(raw: Vec<u8>, state: &BridgeState) {
    debug!("[dispatch_wake] inbound packet received, size={} bytes", raw.len());
    
    let map = match parse_msgpack_map(&raw) {
        Some(m) => m,
        None => {
            warn!("[dispatch_wake] cannot parse msgpack map (raw_size={})", raw.len());
            return;
        }
    };

    let receiver = match map_get_bin(&map, "receiver") {
        Some(b) if b.len() == 16 => b,
        _ => {
            warn!("[dispatch_wake] missing valid 'receiver' key");
            return;
        }
    };
    let receiver_hex = hex::encode(&receiver);
    let sender_hex   = map_get_bin(&map, "sender").filter(|b| b.len() == 16).map(|b| hex::encode(&b));
    let channel_hex  = map_get_bin(&map, "channel").filter(|b| b.len() == 16).map(|b| hex::encode(&b));

    let n = state.notify_count.fetch_add(1, Ordering::Relaxed) + 1;
    info!("NOTIFY #{n} received  receiver={receiver_hex} sender={} channel={}",
          sender_hex.as_deref().unwrap_or("-"),
          channel_hex.as_deref().unwrap_or("-"));

    let (apns_token, env) = match state.db.lock().unwrap().get_token(&receiver_hex) {
        Ok(Some(t)) => t,
        Ok(None) => {
            info!("NOTIFY #{n} skipped   receiver={receiver_hex} (no APNs token registered)");
            return;
        }
        Err(e) => {
            error!("NOTIFY #{n} db error: {e}");
            return;
        }
    };

    // When the registered env is Sandbox, also push to Production. macOS
    // Catalyst Debug builds carry aps-environment=development but their
    // device token is sometimes bound to the production gateway, so the
    // sandbox push returns 200 OK from Apple while apsd never sees it.
    // Fanning out covers both binding cases without retrying.
    let envs: &[ApnsEnv] = match env {
        ApnsEnv::Sandbox    => &[ApnsEnv::Sandbox, ApnsEnv::Production],
        ApnsEnv::Production => &[ApnsEnv::Production],
    };

    let mut primary_result: Option<SendResult> = None;
    for &send_env in envs {
        let result = state.apns.send(
            &apns_token,
            send_env,
            &receiver_hex,
            sender_hex.as_deref(),
            channel_hex.as_deref(),
        );

        if result.success {
            let pushed = state.push_count.fetch_add(1, Ordering::Relaxed) + 1;
            info!("NOTIFY #{n} pushed    receiver={receiver_hex} env={} → APNs OK  (total pushed: {pushed})",
                  send_env.as_db_str());
        } else if ApnsSender::should_invalidate(result.http_code, result.reason.as_deref()) {
            let failed = state.push_fail.fetch_add(1, Ordering::Relaxed) + 1;
            // Only purge the stored token if the *registered* env reported the
            // token as invalid; a BadDeviceToken from the fanout gateway just
            // means the token doesn't belong to that environment and is
            // expected for one of the two sends.
            if send_env == env {
                state.db.lock().unwrap().invalidate_token(&apns_token, env).ok();
                warn!("NOTIFY #{n} purged    receiver={receiver_hex} env={} — stale token (reason={:?}), total failed: {failed}",
                      send_env.as_db_str(), result.reason);
            } else {
                info!("NOTIFY #{n} fanout    receiver={receiver_hex} env={} rejected token (reason={:?}) — expected, not purging",
                      send_env.as_db_str(), result.reason);
            }
        } else {
            let failed = state.push_fail.fetch_add(1, Ordering::Relaxed) + 1;
            error!("NOTIFY #{n} FAILED    receiver={receiver_hex} env={} — HTTP {} reason={:?}  (total failed: {failed})",
                   send_env.as_db_str(), result.http_code, result.reason);
        }

        if send_env == env {
            primary_result = Some(result);
        }
    }
    let _ = primary_result;
}

// ── Registration packet handler ───────────────────────────────────────────────

fn handle_register(data: &[u8], state: &BridgeState) {
    let result = try_handle_register(data, state);
    if let Err(e) = result {
        warn!("Registration packet: rejected — {e}");
    }
}

fn try_handle_register(data: &[u8], state: &BridgeState) -> Result<(), String> {
    let map = parse_msgpack_map(data).ok_or("cannot parse msgpack map")?;

    let sub_bytes = map_get_bin(&map, "subscriber_hash")
        .ok_or("subscriber_hash must be 16 bytes")?;
    if sub_bytes.len() != 16 {
        return Err("subscriber_hash must be 16 bytes".to_string());
    }
    let sub_hex = hex::encode(&sub_bytes);

    match map_get_str(&map, "apns_token") {
        Some(token) => {
            // Register / refresh
            if token.len() != 64 || !token.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("apns_token must be 64-char lowercase hex".to_string());
            }
            let token_lower = token.to_lowercase();

            // Optional `env` field (v2 protocol).  Falls back to the
            // bridge's configured default for v1 clients that don't send it.
            let env = match map_get_str(&map, "env") {
                Some(s) => ApnsEnv::parse(&s)
                    .ok_or_else(|| format!("env must be 'sandbox' or 'production', got {s:?}"))?,
                None => state.apns.default_env(),
            };

            state.db.lock().unwrap()
                .register(&sub_hex, &token_lower, env)
                .map_err(|e| format!("db register error: {e}"))?;
            info!("Register: token stored for {sub_hex} env={}", env.as_db_str());
        }
        None => {
            // Unregister
            let removed = state.db.lock().unwrap()
                .unregister(&sub_hex)
                .map_err(|e| format!("db unregister error: {e}"))?;
            info!("Unregister: {} for {sub_hex}", if removed { "removed" } else { "not found" });
        }
    }
    Ok(())
}

// ── msgpack helpers ───────────────────────────────────────────────────────────

fn parse_msgpack_map(data: &[u8]) -> Option<Vec<(Value, Value)>> {
    let mut cursor = Cursor::new(data);
    match read_value(&mut cursor) {
        Ok(Value::Map(m)) => Some(m),
        _ => None,
    }
}

fn map_get_bin(map: &[(Value, Value)], key: &str) -> Option<Vec<u8>> {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .and_then(|(_, v)| match v {
            Value::Binary(b) => Some(b.clone()),
            _ => None,
        })
}

fn map_get_str(map: &[(Value, Value)], key: &str) -> Option<String> {
    map.iter()
        .find(|(k, _)| k.as_str() == Some(key))
        .and_then(|(_, v)| v.as_str().map(|s| s.to_string()))
}

fn hex_dest(dest: &Destination) -> String {
    hex::encode(&dest.hash)
}

#[cfg(test)]
mod tests {
    use rmpv::encode::write_value;
    use rmpv::Value;

    use super::{map_get_bin, parse_msgpack_map};

    fn encode_map(entries: Vec<(Value, Value)>) -> Vec<u8> {
        let mut payload = Vec::new();
        write_value(&mut payload, &Value::Map(entries)).expect("encode msgpack map");
        payload
    }

    #[test]
    fn wake_parser_accepts_binary_receiver_field() {
        let receiver = vec![0x55u8; 16];
        let payload = encode_map(vec![
            (
                Value::String("receiver".into()),
                Value::Binary(receiver.clone()),
            ),
        ]);

        let map = parse_msgpack_map(&payload).expect("parse wake map");
        assert_eq!(map_get_bin(&map, "receiver"), Some(receiver));
    }

    #[test]
    fn wake_parser_rejects_string_receiver_field() {
        let payload = encode_map(vec![
            (
                Value::String("receiver".into()),
                Value::String("00112233445566778899aabbccddeeff".into()),
            ),
        ]);

        let map = parse_msgpack_map(&payload).expect("parse wake map");
        assert_eq!(map_get_bin(&map, "receiver"), None);
    }

    #[test]
    fn registration_parser_accepts_binary_subscriber_hash() {
        let subscriber = vec![0x66u8; 16];
        let payload = encode_map(vec![
            (
                Value::String("subscriber_hash".into()),
                Value::Binary(subscriber.clone()),
            ),
            (
                Value::String("apns_token".into()),
                Value::String(
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
                ),
            ),
        ]);

        let map = parse_msgpack_map(&payload).expect("parse registration map");
        assert_eq!(map_get_bin(&map, "subscriber_hash"), Some(subscriber));
    }
}

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
use reticulum_rust::link::{Link, LinkHandle};
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::transport::Transport;

use crate::apns::ApnsSender;
use crate::config::BridgeConfig;
use crate::db::TokenDB;

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
            let raw = data.to_vec();
            let s = Arc::clone(&state2);
            thread::spawn(move || dispatch_wake(raw, &s));
        })));
    }

    // Link-established callback — rfed nodes may also open a Link first
    {
        let state2 = Arc::clone(&state);
        notify_dest.set_link_established_callback(Some(Arc::new(move |link: LinkHandle| {
            let s = Arc::clone(&state2);
            link.set_packet_callback(Some(Arc::new(move |data: &[u8], _pkt| {
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
        Reticulum::init(Some(dir.clone()), None, None, None, false, None)
            .map_err(|e| format!("Reticulum init failed: {e}"))?;
        return Ok(dir);
    }

    // Build a minimal config dir next to the identity file
    let identity_path = std::path::Path::new(&cfg.identity_path);
    let config_dir = identity_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("reticulum");
    std::fs::create_dir_all(&config_dir)
        .map_err(|e| format!("cannot create reticulum dir: {e}"))?;

    let config_text = if let (Some(host), Some(port)) = (&cfg.rns_tcp_host, cfg.rns_tcp_port) {
        format!(
            "[reticulum]\n  enable_transport = false\n  share_instance = false\n\n\
             [interfaces]\n\n  [[ApnsBridgeTCP]]\n    type = TCPClientInterface\n\
             enabled = yes\n    target_host = {host}\n    target_port = {port}\n"
        )
    } else {
        // Default interface (localhost shared instance)
        "[reticulum]\n  enable_transport = false\n  share_instance = true\n".to_string()
    };

    let config_file = config_dir.join("config");
    std::fs::write(&config_file, &config_text)
        .map_err(|e| format!("cannot write reticulum config: {e}"))?;

    if let Some(host) = &cfg.rns_tcp_host {
        info!(
            "Using TCP interface → {}:{} (configdir: {})",
            host,
            cfg.rns_tcp_port.unwrap_or(4242),
            config_dir.display()
        );
    }

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
    let map = match parse_msgpack_map(&raw) {
        Some(m) => m,
        None => {
            warn!("Wake: cannot parse msgpack map");
            return;
        }
    };

    let receiver = match map_get_bin(&map, "receiver") {
        Some(b) if b.len() == 16 => b,
        _ => {
            warn!("Wake: missing valid 'receiver' key");
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

    let apns_token = match state.db.lock().unwrap().get_token(&receiver_hex) {
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

    let result = state.apns.send(
        &apns_token,
        &receiver_hex,
        sender_hex.as_deref(),
        channel_hex.as_deref(),
    );

    if result.success {
        let pushed = state.push_count.fetch_add(1, Ordering::Relaxed) + 1;
        info!("NOTIFY #{n} pushed    receiver={receiver_hex} → APNs OK  (total pushed: {pushed})");
    } else if ApnsSender::should_invalidate(result.http_code, result.reason.as_deref()) {
        let failed = state.push_fail.fetch_add(1, Ordering::Relaxed) + 1;
        state.db.lock().unwrap().invalidate_token(&apns_token).ok();
        warn!("NOTIFY #{n} purged    receiver={receiver_hex} — stale token (reason={:?}), total failed: {failed}",
              result.reason);
    } else {
        let failed = state.push_fail.fetch_add(1, Ordering::Relaxed) + 1;
        error!("NOTIFY #{n} FAILED    receiver={receiver_hex} — HTTP {} reason={:?}  (total failed: {failed})",
               result.http_code, result.reason);
    }
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
            state.db.lock().unwrap()
                .register(&sub_hex, &token_lower)
                .map_err(|e| format!("db register error: {e}"))?;
            info!("Register: token stored for {sub_hex}");
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

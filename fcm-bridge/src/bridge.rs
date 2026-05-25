//! Reticulum bridge: wires up the current Android notify relay path and the
//! canonical `fcm.*` token destinations used by the FCM push relay:
//!   * `rfed.notify`    — wake-packet endpoint (rfed → bridge → FCM)
//!   * `fcm.register`   — FCM token registration (client → bridge)
//!   * `fcm.unregister` — FCM token removal       (client → bridge)
//!
//! The current Android app derives its relay hash from `rfed.notify` and sends
//! token upserts to `fcm.register`, so the bridge keeps that mixed-aspect shape
//! for compatibility with the shipped client path.

use std::io::Cursor;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
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

use crate::config::BridgeConfig;
use crate::db::TokenDB;
use crate::fcm::FcmSender;

const RELAY_APP: &str = "rfed";
const RELAY_ASPECT: &str = "notify";
const REGISTER_APP: &str = "fcm";
const REGISTER_ASPECT: &str = "register";
const UNREGISTER_APP: &str = "fcm";
const UNREGISTER_ASPECT: &str = "unregister";

const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(600);

struct BridgeState {
    db: Arc<Mutex<TokenDB>>,
    fcm: Arc<FcmSender>,
    notify_count: AtomicU64,
    push_count: AtomicU64,
    push_fail: AtomicU64,
}

pub fn run(cfg: &BridgeConfig, db: TokenDB, fcm: FcmSender) -> Result<(), String> {
    let _rns_dir = init_reticulum(cfg)?;

    let identity = load_or_create_identity(&cfg.identity_path)?;
    if let Some(h) = &identity.hash {
        info!("Bridge identity: {}", hex::encode(h));
    }

    let state = Arc::new(BridgeState {
        db: Arc::new(Mutex::new(db)),
        fcm: Arc::new(fcm),
        notify_count: AtomicU64::new(0),
        push_count: AtomicU64::new(0),
        push_fail: AtomicU64::new(0),
    });

    let mut relay_dest = Destination::new_inbound(
        Some(identity.clone()),
        DestinationType::Single,
        RELAY_APP.to_string(),
        vec![RELAY_ASPECT.to_string()],
    )
    .map_err(|e| format!("cannot create rfed.notify destination: {e}"))?;
    info!("rfed.notify     hash: {}", hex_dest(&relay_dest));

    {
        let state2 = Arc::clone(&state);
        relay_dest.set_packet_callback(Some(Arc::new(move |data: &[u8], _pkt| {
            debug!("[rfed.notify] inbound packet from transport, size={}", data.len());
            let raw = data.to_vec();
            let s = Arc::clone(&state2);
            thread::spawn(move || dispatch_wake(raw, &s));
        })));
    }

    {
        let state2 = Arc::clone(&state);
        relay_dest.set_link_established_callback(Some(Arc::new(move |link: LinkHandle| {
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

    Transport::register_destination(relay_dest.clone());

    let mut register_dest = Destination::new_inbound(
        Some(identity.clone()),
        DestinationType::Single,
        REGISTER_APP.to_string(),
        vec![REGISTER_ASPECT.to_string()],
    )
    .map_err(|e| format!("cannot create fcm.register destination: {e}"))?;
    info!("fcm.register    hash: {}", hex_dest(&register_dest));

    {
        let state2 = Arc::clone(&state);
        register_dest.set_packet_callback(Some(Arc::new(move |data: &[u8], _pkt| {
            handle_register(data, &state2);
        })));
    }

    {
        let state2 = Arc::clone(&state);
        register_dest.set_link_established_callback(Some(Arc::new(move |link: LinkHandle| {
            debug!("[fcm.register] link established");
            let s = Arc::clone(&state2);
            link.set_packet_callback(Some(Arc::new(move |data: &[u8], _pkt| {
                debug!("[fcm.register] inbound packet from link, size={}", data.len());
                handle_register(data, &s);
            })));
        })));
    }

    Transport::register_destination(register_dest.clone());

    let mut unregister_dest = Destination::new_inbound(
        Some(identity.clone()),
        DestinationType::Single,
        UNREGISTER_APP.to_string(),
        vec![UNREGISTER_ASPECT.to_string()],
    )
    .map_err(|e| format!("cannot create fcm.unregister destination: {e}"))?;
    info!("fcm.unregister  hash: {}", hex_dest(&unregister_dest));

    {
        let state2 = Arc::clone(&state);
        unregister_dest.set_packet_callback(Some(Arc::new(move |data: &[u8], _pkt| {
            handle_unregister(data, &state2);
        })));
    }

    {
        let state2 = Arc::clone(&state);
        unregister_dest.set_link_established_callback(Some(Arc::new(move |link: LinkHandle| {
            debug!("[fcm.unregister] link established");
            let s = Arc::clone(&state2);
            link.set_packet_callback(Some(Arc::new(move |data: &[u8], _pkt| {
                debug!("[fcm.unregister] inbound packet from link, size={}", data.len());
                handle_unregister(data, &s);
            })));
        })));
    }

    Transport::register_destination(unregister_dest.clone());

    relay_dest
        .announce(None, false, None, None, true)
        .map_err(|e| format!("announce failed: {e}"))?;
    register_dest
        .announce(None, false, None, None, true)
        .map_err(|e| format!("announce failed: {e}"))?;
    unregister_dest
        .announce(None, false, None, None, true)
        .map_err(|e| format!("announce failed: {e}"))?;

    let reg_count = state.db.lock().unwrap_or_else(|e| e.into_inner()).count().unwrap_or(0);
    info!("Bridge running — {} tokens registered", reg_count);

    loop {
        thread::sleep(ANNOUNCE_INTERVAL);
        let _ = relay_dest.announce(None, false, None, None, true);
        let _ = register_dest.announce(None, false, None, None, true);
        let _ = unregister_dest.announce(None, false, None, None, true);
        debug!("Periodic announces sent");
    }
}

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
                "legacy bridge transport config is incomplete; use bridge.rns_config or native [reticulum]/[interfaces] sections instead"
                    .to_string(),
            );
        }

        warn!(
            "bridge.rns_tcp_host / rns_tcp_port / rns_tcp_endpoints is deprecated; use native [interfaces] entries in the main config file"
        );

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
                "\n  [[FcmBridgeTCP{n}]]\n    type = TCPClientInterface\n    target_host = {host}\n    target_port = {port}\n    enabled = yes\n",
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
    let sender_hex = map_get_bin(&map, "sender")
        .filter(|b| b.len() == 16)
        .map(|b| hex::encode(&b));
    let channel_hex = map_get_bin(&map, "channel")
        .filter(|b| b.len() == 16)
        .map(|b| hex::encode(&b));

    let n = state.notify_count.fetch_add(1, Ordering::Relaxed) + 1;
    info!(
        "NOTIFY #{n} received  receiver={receiver_hex} sender={} channel={}",
        sender_hex.as_deref().unwrap_or("-"),
        channel_hex.as_deref().unwrap_or("-")
    );

    let fcm_token = match state
        .db
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_token(&receiver_hex)
    {
        Ok(Some(token)) => token,
        Ok(None) => {
            info!("NOTIFY #{n} skipped   receiver={receiver_hex} (no FCM token registered)");
            return;
        }
        Err(e) => {
            error!("NOTIFY #{n} db error: {e}");
            return;
        }
    };

    let result = state.fcm.send(
        &fcm_token,
        &receiver_hex,
        sender_hex.as_deref(),
        channel_hex.as_deref(),
    );

    if result.success {
        let pushed = state.push_count.fetch_add(1, Ordering::Relaxed) + 1;
        info!(
            "NOTIFY #{n} pushed    receiver={receiver_hex} → FCM OK  (total pushed: {pushed})"
        );
    } else if FcmSender::should_invalidate(result.http_code, result.reason.as_deref()) {
        let failed = state.push_fail.fetch_add(1, Ordering::Relaxed) + 1;
        state
            .db
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .invalidate_token(&fcm_token)
            .ok();
        warn!(
            "NOTIFY #{n} purged    receiver={receiver_hex} — stale token (reason={:?}), total failed: {failed}",
            result.reason,
        );
    } else {
        let failed = state.push_fail.fetch_add(1, Ordering::Relaxed) + 1;
        error!(
            "NOTIFY #{n} FAILED    receiver={receiver_hex} — HTTP {} reason={:?}  (total failed: {failed})",
            result.http_code,
            result.reason,
        );
    }
}

fn handle_register(data: &[u8], state: &BridgeState) {
    if let Err(e) = try_handle_register(data, state) {
        warn!("fcm.register: rejected — {e}");
    }
}

fn handle_unregister(data: &[u8], state: &BridgeState) {
    if let Err(e) = try_handle_unregister(data, state) {
        warn!("fcm.unregister: rejected — {e}");
    }
}

fn try_handle_unregister(data: &[u8], state: &BridgeState) -> Result<(), String> {
    let map = parse_msgpack_map(data).ok_or("cannot parse msgpack map")?;
    let sub_bytes = map_get_bin(&map, "subscriber_hash")
        .ok_or("subscriber_hash must be 16 bytes")?;
    if sub_bytes.len() != 16 {
        return Err("subscriber_hash must be 16 bytes".to_string());
    }
    let sub_hex = hex::encode(&sub_bytes);
    let removed = state
        .db
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .unregister(&sub_hex)
        .map_err(|e| format!("db unregister error: {e}"))?;
    info!(
        "fcm.unregister: {} for {sub_hex}",
        if removed { "removed" } else { "not found" }
    );
    Ok(())
}

fn try_handle_register(data: &[u8], state: &BridgeState) -> Result<(), String> {
    let map = parse_msgpack_map(data).ok_or("cannot parse msgpack map")?;

    let sub_bytes = map_get_bin(&map, "subscriber_hash")
        .ok_or("subscriber_hash must be 16 bytes")?;
    if sub_bytes.len() != 16 {
        return Err("subscriber_hash must be 16 bytes".to_string());
    }
    let sub_hex = hex::encode(&sub_bytes);

    match map_get_str(&map, "fcm_token") {
        Some(token) => {
            let token = token.trim();
            if token.is_empty() {
                return Err("fcm_token must not be empty".to_string());
            }

            state
                .db
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .register(&sub_hex, token)
                .map_err(|e| format!("db register error: {e}"))?;
            info!("fcm.register: token stored for {sub_hex}");
        }
        None => {
            let removed = state
                .db
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .unregister(&sub_hex)
                .map_err(|e| format!("db unregister error: {e}"))?;
            info!(
                "fcm.register: {} for {sub_hex} (unregister via missing token)",
                if removed { "removed" } else { "not found" }
            );
        }
    }
    Ok(())
}

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

    use reticulum_rust::destination::Destination;

    use super::{
        map_get_bin, parse_msgpack_map, REGISTER_APP, REGISTER_ASPECT, RELAY_APP, RELAY_ASPECT,
        UNREGISTER_APP, UNREGISTER_ASPECT,
    };

    const TEST_IDENTITY_HASH: [u8; 16] = [
        0xc2, 0x87, 0xb8, 0x44, 0xb2, 0xb6, 0xf8, 0xd6, 0x01, 0x3b, 0x0a, 0x96,
        0x2e, 0xb2, 0x10, 0x7b,
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn dest_hash(app: &str, aspect: &str) -> Vec<u8> {
        Destination::hash(Some(&TEST_IDENTITY_HASH), app, &[aspect])
    }

    fn encode_map(entries: Vec<(Value, Value)>) -> Vec<u8> {
        let mut payload = Vec::new();
        write_value(&mut payload, &Value::Map(entries)).expect("encode msgpack map");
        payload
    }

    #[test]
    fn wake_parser_accepts_binary_receiver_field() {
        let receiver = vec![0x55u8; 16];
        let payload = encode_map(vec![(
            Value::String("receiver".into()),
            Value::Binary(receiver.clone()),
        )]);

        let map = parse_msgpack_map(&payload).expect("parse wake map");
        assert_eq!(map_get_bin(&map, "receiver"), Some(receiver));
    }

    #[test]
    fn wake_parser_rejects_string_receiver_field() {
        let payload = encode_map(vec![(
            Value::String("receiver".into()),
            Value::String("00112233445566778899aabbccddeeff".into()),
        )]);

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
                Value::String("fcm_token".into()),
                Value::String("example-fcm-token".into()),
            ),
        ]);

        let map = parse_msgpack_map(&payload).expect("parse registration map");
        assert_eq!(map_get_bin(&map, "subscriber_hash"), Some(subscriber));
    }

    #[test]
    fn aspect_strings_are_pinned() {
        assert_eq!(RELAY_APP, "rfed");
        assert_eq!(RELAY_ASPECT, "notify");
        assert_eq!(REGISTER_APP, "fcm");
        assert_eq!(REGISTER_ASPECT, "register");
        assert_eq!(UNREGISTER_APP, "fcm");
        assert_eq!(UNREGISTER_ASPECT, "unregister");
    }

    #[test]
    fn rfed_notify_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash(RELAY_APP, RELAY_ASPECT)),
            "9233db1eefe3c75832ead85956111fbe",
        );
    }

    #[test]
    fn fcm_register_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash(REGISTER_APP, REGISTER_ASPECT)),
            "801545c957276b70c78a47658eb84430",
        );
    }

    #[test]
    fn fcm_unregister_hash_is_pinned() {
        assert_eq!(
            hex(&dest_hash(UNREGISTER_APP, UNREGISTER_ASPECT)),
            "bf09edc8239200bb7c0fa558cf543067",
        );
    }

    #[test]
    fn bridge_aspect_hashes_are_pairwise_distinct() {
        let triples = [
            (RELAY_APP, RELAY_ASPECT),
            (REGISTER_APP, REGISTER_ASPECT),
            (UNREGISTER_APP, UNREGISTER_ASPECT),
        ];
        for i in 0..triples.len() {
            for j in (i + 1)..triples.len() {
                assert_ne!(
                    dest_hash(triples[i].0, triples[i].1),
                    dest_hash(triples[j].0, triples[j].1),
                    "{}.{} and {}.{} must hash to distinct destinations",
                    triples[i].0,
                    triples[i].1,
                    triples[j].0,
                    triples[j].1,
                );
            }
        }
    }
}
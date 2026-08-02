//! rfed — Reticulum Federation Node
//!
//! A superset of the LXMF Propagation Node.  Does NOT join the
//! `lxmf.propagation` network but adopts the same anti-spam (stamps),
//! transfer/sync limits, and peering cost mechanisms.  Adds channel fan-out
//! and notify delivery on top.
//!
//! RNS destinations:
//!   rfed.node      — Federation Node announce and peer sync
//!   rfed.delivery  — Universal client inbox (all message types exit here)
//!   rfed.channel   — Channel post inbound + subscription control plane
//!   rfed.channel.stream      — Live per-channel fanout stream over a persistent Link
//!   rfed.propagation.stream  — Live LXMF propagation stream over a persistent Link
//!   rfed.notify    — Notify registration
//!
//! Usage:
//!     rfed [OPTIONS]
//!
//! Options:
//!     --config <DIR>            rfed config/storage directory (default: ~/.rfed)
//!     --identity <FILE>         Path to identity file (default: <config>/identity)
//!     --name <NAME>             Node display name
//!     --announce-interval <M>   Announce interval in minutes (default: 360)
//!     --no-announce-at-start    Don't announce on startup
//!     --stamp-cost <N>          Stamp cost target (default: 16)
//!     --stamp-flexibility <N>   Stamp cost flexibility (default: 3)
//!     --peering-cost <N>        Peering cost (default: 18)
//!     --storage-limit <MB>      Storage limit in megabytes (default: 2000)
//!     --static-peer <HASH>      Add a static peer (repeatable)
//!     --secondary-node <HASH>   Add a secondary/backup node (repeatable)
//!     --owner-offline-secs <S>  Seconds before owner deemed offline (default: 90)
//!     --from-static-only        Only accept blobs/peers from static peers
//!     -v, --verbose             Increase log verbosity
//!     -q, --quiet               Decrease log verbosity
//!     -h, --help                Show this help

use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use reticulum_rust::identity::Identity;
use reticulum_rust::reticulum::Reticulum;
use reticulum_rust::transport::get_state_snapshot;
use reticulum_rust::{hexrep, log, LOG_NOTICE};

mod config;
mod announce;
mod subscription;
mod channel;
mod blob_store;
mod deferred_queue;
mod distro;
mod fanout;
mod sync;
mod toml_config;
mod destinations;
mod lxmf_propagation;
mod stream_registry;
pub mod notify;

use config::{NodeConfig, TierPolicy};
use destinations::FedNode;
use toml_config::{IniConfig, CONFIG_FILENAME};

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ── CLI helpers ──────────────────────────────────────────────────────────────

fn print_help() {
    eprintln!(
        r#"rfed v{VERSION} — Reticulum Federation Node

Interfaces and Reticulum settings are in ~/.rfed/config
using Reticulum's native config format.

Usage: rfed [OPTIONS]

Options:
  --config <DIR>            rfed config/storage directory (default: ~/.rfed)
  --identity <FILE>         Path to identity file (default: <config>/identity)
  --name <NAME>             Node display name
  --announce-interval <M>   Announce interval in minutes (default: 360)
  --no-announce-at-start    Don't announce on startup
  --stamp-cost <N>          Stamp cost target (default: 16)
  --stamp-flexibility <N>   Stamp cost flexibility (default: 3)
  --peering-cost <N>        Peering cost (default: 18)
  --storage-limit <MB>      Storage limit in MB (default: 2000)
  --static-peer <HASH>      Add a static peer (repeatable)
  --secondary-node <HASH>   Add a secondary/backup node (repeatable)
  --owner-offline-secs <S>  Seconds before owner deemed offline (default: 90)
  --from-static-only        Only accept blobs/peers from static peers
  -v, --verbose             Increase log verbosity
  -q, --quiet               Decrease log verbosity
  -h, --help                Show this help"#
    );
}

fn arg_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].as_str())
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn home_dir() -> PathBuf {
    env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/root"))
}

fn format_bytes(b: u64) -> String {
    if b < 1024 {
        format!("{} B", b)
    } else if b < 1024 * 1024 {
        format!("{:.1} KiB", b as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", b as f64 / (1024.0 * 1024.0))
    }
}

/// Write a `status.json` file into the config directory with all destination
/// hashes and runtime info.  Any tool can `cat ~/.rfed/status.json` while rfed
/// is running to inspect keys without restarting.
fn write_status_file(
    node: &Arc<Mutex<FedNode>>,
    lxmf_prop: &Option<Arc<Mutex<lxmf_propagation::LxmfPropagationNode>>>,
    startup: &Instant,
) {
    let Ok(guard) = node.lock() else { return };
    let config_dir = &guard.config.config_dir;
    let identity_hash = guard.identity.hash.as_ref()
        .map(|h| hexrep(h, false))
        .unwrap_or_default();

    let prop_hash = lxmf_prop.as_ref().and_then(|arc| {
        arc.lock().ok().map(|g| hexrep(&g.destination.hash, false))
    }).unwrap_or_default();

    let sub_count = guard.subscription_table.lock()
        .map(|s| s.len()).unwrap_or(0);
    let blob_count = guard.blob_store.lock()
        .map(|b| b.index.len()).unwrap_or(0);
    let notify_count = guard.notify_registry.lock()
        .map(|n| n.count()).unwrap_or(0);

    let uptime_secs = startup.elapsed().as_secs();
    let name = &guard.config.display_name;

    // MARKER: Prove deployment includes distro code (persists in status.json)
    let distro_marker = "DISTRO_ENABLED_v1";

    // Commit hash from build environment (set by GitHub Action)
    let commit_hash = option_env!("GITHUB_SHA").unwrap_or("unknown");
    let commit_short = if commit_hash.len() >= 7 { &commit_hash[..7] } else { commit_hash };

    // Build interfaces JSON array
    let snap = get_state_snapshot();
    let mut interfaces_json = String::new();
    for (i, iface) in snap.interfaces.iter().enumerate() {
        if i > 0 {
            interfaces_json.push_str(",\n");
        }
        let mut iface_entry = format!(
            "    {{\n      \"name\": \"{}\",\n      \"connected\": {},",
            iface.name, iface.online
        );
        if let Some(addr) = &iface.address {
            iface_entry.push_str(&format!("\n      \"address\": \"{}\",", addr));
        }
        if let Some(port) = iface.port {
            iface_entry.push_str(&format!("\n      \"port\": {},", port));
        }
        iface_entry.push_str(&format!(
            "\n      \"rx_bytes\": {},\n      \"tx_bytes\": {}\n    }}",
            iface.rxb, iface.txb
        ));
        interfaces_json.push_str(&iface_entry);
    }

    let json = if interfaces_json.is_empty() {
        format!(
            concat!(
                "{{\n",
                "  \"node_name\": \"{}\",\n",
                "  \"identity\": \"{}\",\n",
                "  \"destinations\": {{\n",
                "    \"rfed.node\": \"{}\",\n",
                "    \"rfed.delivery\": \"{}\",\n",
                "    \"rfed.channel\": \"{}\",\n",
                "    \"rfed.notify\": \"{}\",\n",
                "    \"rfed.channel.subscribe\": \"{}\",\n",
                "    \"rfed.channel.unsubscribe\": \"{}\",\n",
                "    \"rfed.channel.publish\": \"{}\",\n",
                "    \"rfed.channel.pull\": \"{}\",\n",
                "    \"rfed.channel.stream\": \"{}\",\n",
                "    \"rfed.propagation.stream\": \"{}\",\n",
                "    \"rfed.notify.register\": \"{}\",\n",
                "    \"rfed.notify.unregister\": \"{}\",\n",
                "    \"rfed.distro.register\": \"{}\",\n",
                "    \"rfed.distro.unregister\": \"{}\",\n",
                "    \"rfed.distro.list\": \"{}\",\n",
                "    \"lxmf.propagation\": \"{}\"\n",
                "  }},\n",
                "  \"distro_marker\": \"{}\",\n",
                "  \"commit_hash\": \"{}\",\n",
                "  \"interfaces\": [],\n",
                "  \"stats\": {{\n",
                "    \"uptime_secs\": {},\n",
                "    \"subscribers\": {},\n",
                "    \"blobs\": {},\n",
                "    \"notify_registrations\": {}\n",
                "  }}\n",
                "}}\n"
            ),
            name, identity_hash,
            hexrep(&guard.node_dest.hash, false),
            hexrep(&guard.delivery_dest.hash, false),
            hexrep(&guard.channel_dest.hash, false),
            hexrep(&guard.notify_dest.hash, false),
            hexrep(&guard.channel_subscribe_dest.hash, false),
            hexrep(&guard.channel_unsubscribe_dest.hash, false),
            hexrep(&guard.channel_publish_dest.hash, false),
            hexrep(&guard.channel_pull_dest.hash, false),
            hexrep(&guard.channel_stream_dest.hash, false),
            hexrep(&guard.propagation_stream_dest.hash, false),
            hexrep(&guard.notify_register_dest.hash, false),
            hexrep(&guard.notify_unregister_dest.hash, false),
            hexrep(&guard.distro_register_dest.hash, false),
            hexrep(&guard.distro_unregister_dest.hash, false),
            hexrep(&guard.distro_list_dest.hash, false),
            prop_hash,
            distro_marker,
            commit_short,
            uptime_secs, sub_count, blob_count, notify_count,
        )
    } else {
        format!(
            concat!(
                "{{\n",
                "  \"node_name\": \"{}\",\n",
                "  \"identity\": \"{}\",\n",
                "  \"destinations\": {{\n",
                "    \"rfed.node\": \"{}\",\n",
                "    \"rfed.delivery\": \"{}\",\n",
                "    \"rfed.channel\": \"{}\",\n",
                "    \"rfed.notify\": \"{}\",\n",
                "    \"rfed.channel.subscribe\": \"{}\",\n",
                "    \"rfed.channel.unsubscribe\": \"{}\",\n",
                "    \"rfed.channel.publish\": \"{}\",\n",
                "    \"rfed.channel.pull\": \"{}\",\n",
                "    \"rfed.channel.stream\": \"{}\",\n",
                "    \"rfed.propagation.stream\": \"{}\",\n",
                "    \"rfed.notify.register\": \"{}\",\n",
                "    \"rfed.notify.unregister\": \"{}\",\n",
                "    \"rfed.distro.register\": \"{}\",\n",
                "    \"rfed.distro.unregister\": \"{}\",\n",
                "    \"rfed.distro.list\": \"{}\",\n",
                "    \"lxmf.propagation\": \"{}\"\n",
                "  }},\n",
                "  \"distro_marker\": \"{}\",\n",
                "  \"commit_hash\": \"{}\",\n",
                "  \"interfaces\": [\n",
                "{}\n",
                "  ],\n",
                "  \"stats\": {{\n",
                "    \"uptime_secs\": {},\n",
                "    \"subscribers\": {},\n",
                "    \"blobs\": {},\n",
                "    \"notify_registrations\": {}\n",
                "  }}\n",
                "}}\n"
            ),
            name, identity_hash,
            hexrep(&guard.node_dest.hash, false),
            hexrep(&guard.delivery_dest.hash, false),
            hexrep(&guard.channel_dest.hash, false),
            hexrep(&guard.notify_dest.hash, false),
            hexrep(&guard.channel_subscribe_dest.hash, false),
            hexrep(&guard.channel_unsubscribe_dest.hash, false),
            hexrep(&guard.channel_publish_dest.hash, false),
            hexrep(&guard.channel_pull_dest.hash, false),
            hexrep(&guard.channel_stream_dest.hash, false),
            hexrep(&guard.propagation_stream_dest.hash, false),
            hexrep(&guard.notify_register_dest.hash, false),
            hexrep(&guard.notify_unregister_dest.hash, false),
            hexrep(&guard.distro_register_dest.hash, false),
            hexrep(&guard.distro_unregister_dest.hash, false),
            hexrep(&guard.distro_list_dest.hash, false),
            prop_hash,
            distro_marker,
            commit_short,
            interfaces_json,
            uptime_secs, sub_count, blob_count, notify_count,
        )
    };

    let path = config_dir.join("status.json");
    let _ = fs::write(&path, json);
}

/// Copy rfed's config to `_rns/` for Reticulum to read directly.
fn prepare_rns_config(config_dir: &PathBuf) -> Result<PathBuf, String> {
    let rns_dir = config_dir.join("_rns");
    fs::create_dir_all(&rns_dir)
        .map_err(|e| format!("Cannot create {:?}: {e}", rns_dir))?;
    fs::copy(config_dir.join("config"), rns_dir.join("config"))
        .map_err(|e| format!("Cannot prepare RNS config: {e}"))?;
    Ok(rns_dir)
}

// ── main() ───────────────────────────────────────────────────────────────────

fn main() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if has_flag(&args, "-h") || has_flag(&args, "--help") {
        print_help();
        return Ok(());
    }

    // ── Config directory ─────────────────────────────────────────────
    let config_dir: PathBuf = arg_value(&args, "--config")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".rfed"));

    // ── Load config ──────────────────────────────────────────────────
    let conf_path = config_dir.join(CONFIG_FILENAME);
    if !conf_path.exists() {
        if let Err(e) = fs::create_dir_all(&config_dir) {
            if !config_dir.is_dir() {
                return Err(format!("Cannot create config dir {:?}: {e}", config_dir));
            }
        }
        if config_dir.join("rfed.conf").exists() {
            eprintln!("[rfed] NOTE: config format has changed to Reticulum's native format.");
            eprintln!("[rfed]       Please migrate your settings from rfed.conf to config.");
        }
        let _ = fs::write(&conf_path, toml_config::SAMPLE_CONFIG);
        eprintln!("[rfed] Wrote sample config to {}", conf_path.display());
    }
    let cfg = IniConfig::load(&conf_path)?;

    // ── Merge: CLI wins over file wins over compiled default ──────────
    let identity_path: PathBuf = arg_value(&args, "--identity")
        .map(PathBuf::from)
        .unwrap_or_else(|| config_dir.join("identity"));

    let node_name: String = arg_value(&args, "--name")
        .map(|s| s.to_string())
        .or_else(|| cfg.node.name.clone())
        .unwrap_or_else(|| "rfed".to_string());

    // Parse as f64 to support fractional minutes (e.g. 0.1 = 6 seconds).
    let announce_interval_secs: u64 = arg_value(&args, "--announce-interval")
        .and_then(|s| s.parse::<f64>().ok())
        .map(|m| (m * 60.0).max(1.0) as u64)
        .or_else(|| cfg.node.announce_interval_minutes.map(|m| m * 60))
        .unwrap_or(360 * 60);

    let announce_at_start: bool = if has_flag(&args, "--no-announce-at-start") {
        false
    } else {
        cfg.node.announce_at_start.unwrap_or(true)
    };

    // ── Default policy ────────────────────────────────────────────────
    let default_stamp_cost: Option<u32> =
        arg_value(&args, "--stamp-cost").and_then(|s| s.parse().ok())
        .or(cfg.default_policy.stamp_cost);
    let default_stamp_flex: Option<u32> =
        arg_value(&args, "--stamp-flexibility").and_then(|s| s.parse().ok())
        .or(cfg.default_policy.stamp_flexibility);
    let default_deferred_limit: usize =
        cfg.default_policy.deferred_queue_limit.unwrap_or(256);
    let default_deferred_pull_limit: Option<usize> =
        cfg.default_policy.deferred_pull_batch_limit;
    let default_allow_notify_reg: bool =
        cfg.default_policy.allow_notify_registration.unwrap_or(true);
    let default_allow_sub: bool =
        cfg.default_policy.allow_subscription.unwrap_or(true);
    let default_trusted_backup_only: bool =
        cfg.default_policy.trusted_backup_only.unwrap_or(false);

    // ── VIP policy ────────────────────────────────────────────────────
    let vip_stamp_cost: Option<u32> =
        cfg.vip_policy.stamp_cost.or(Some(8));
    let vip_stamp_flex: Option<u32> =
        cfg.vip_policy.stamp_flexibility.or(Some(2));
    let vip_deferred_limit: usize =
        cfg.vip_policy.deferred_queue_limit.unwrap_or(1024);
    let vip_deferred_pull_limit: Option<usize> =
        cfg.vip_policy.deferred_pull_batch_limit;
    let vip_allow_notify_reg: bool =
        cfg.vip_policy.allow_notify_registration.unwrap_or(true);
    let vip_allow_sub: bool =
        cfg.vip_policy.allow_subscription.unwrap_or(true);
    let vip_trusted_backup_only: bool =
        cfg.vip_policy.trusted_backup_only.unwrap_or(false);

    // ── VIP subscriber list ───────────────────────────────────────────
    let mut vip_subscribers: Vec<Vec<u8>> = Vec::new();
    for hex_str in &cfg.vip.subscribers {
        match reticulum_rust::decode_hex(hex_str.trim()) {
            Some(bytes) => vip_subscribers.push(bytes),
            None => return Err(format!("Invalid VIP subscriber hash in config: {hex_str}")),
        }
    }

    // ── Trusted backup peers ──────────────────────────────────────────
    let mut trusted_backup_peers: Vec<Vec<u8>> = Vec::new();
    for hex_str in &cfg.peering.trusted_backup_peers {
        match reticulum_rust::decode_hex(hex_str.trim()) {
            Some(bytes) => trusted_backup_peers.push(bytes),
            None => return Err(format!("Invalid trusted_backup_peer hash in config: {hex_str}")),
        }
    }
    let primary_node: Option<Vec<u8>> = cfg.peering.primary_node.as_deref()
        .and_then(|hex_str| reticulum_rust::decode_hex(hex_str.trim()))
        .and_then(|bytes| if bytes.len() == 16 { Some(bytes) } else { None });

    let secondary_nodes: Vec<Vec<u8>> = cfg.peering.secondary_nodes.iter()
        .filter_map(|hex_str| reticulum_rust::decode_hex(hex_str.trim()))
        .filter(|bytes| bytes.len() == 16)
        .collect();

    let owner_offline_secs: f64 =
        arg_value(&args, "--owner-offline-secs").and_then(|s| s.parse().ok())
        .or(cfg.peering.owner_offline_secs)
        .unwrap_or(90.0);

    // ── Peering / storage ─────────────────────────────────────────────
    let peering_cost: Option<u32> =
        arg_value(&args, "--peering-cost").and_then(|s| s.parse().ok())
        .or(cfg.peering.peering_cost)
        .or(Some(18));

    let storage_limit_mb: u64 =
        arg_value(&args, "--storage-limit").and_then(|s| s.parse().ok())
        .or(cfg.storage.limit_mb)
        .unwrap_or(2000);

    let transfer_limit_mb: Option<u64> = cfg.storage.transfer_limit_mb;
    let sync_limit_mb: Option<u64>     = cfg.storage.sync_limit_mb;

    // Collect --static-peer CLI flags (repeatable), then fall back to config.
    let mut static_peers: Vec<Vec<u8>> = Vec::new();
    let mut idx = 1;
    while idx < args.len() {
        if args[idx] == "--static-peer" {
            if let Some(hex_str) = args.get(idx + 1) {
                match reticulum_rust::decode_hex(hex_str.trim()) {
                    Some(bytes) => static_peers.push(bytes),
                    None => return Err(format!("Invalid --static-peer hash: {hex_str}")),
                }
                idx += 2;
                continue;
            }
        }
        idx += 1;
    }
    if static_peers.is_empty() {
        for hex_str in &cfg.peering.static_peers {
            match reticulum_rust::decode_hex(hex_str.trim()) {
                Some(bytes) => static_peers.push(bytes),
                None => return Err(format!("Invalid static_peer in config: {hex_str}")),
            }
        }
    }

    // Collect --secondary-node CLI flags (repeatable), then fall back to config.
    let mut cli_secondary_nodes: Vec<Vec<u8>> = Vec::new();
    let mut idx2 = 1;
    while idx2 < args.len() {
        if args[idx2] == "--secondary-node" {
            if let Some(hex_str) = args.get(idx2 + 1) {
                match reticulum_rust::decode_hex(hex_str.trim()) {
                    Some(bytes) => cli_secondary_nodes.push(bytes),
                    None => return Err(format!("Invalid --secondary-node hash: {hex_str}")),
                }
                idx2 += 2;
                continue;
            }
        }
        idx2 += 1;
    }
    let secondary_nodes: Vec<Vec<u8>> = if !cli_secondary_nodes.is_empty() {
        cli_secondary_nodes
    } else {
        secondary_nodes
    };

    let from_static_only: bool =
        has_flag(&args, "--from-static-only")
        || cfg.peering.from_static_only.unwrap_or(false);

    // ── LXMF propagation ───────────────────────────────────────────
    let lxmf_propagation_enabled: bool =
        cfg.node.lxmf_propagation.unwrap_or(false);
    let lxmf_propagation_autopeer: bool =
        cfg.node.lxmf_propagation_autopeer.unwrap_or(false);

    let mut lxmf_propagation_peers: Vec<Vec<u8>> = Vec::new();
    for hex_str in &cfg.peering.propagation_peers {
        match reticulum_rust::decode_hex(hex_str.trim()) {
            Some(bytes) => lxmf_propagation_peers.push(bytes),
            None => return Err(format!("Invalid propagation_peer hash in config: {hex_str}")),
        }
    }

    // ── Prepare Reticulum config ─────────────────────────────────
    let rns_config_dir = prepare_rns_config(&config_dir)?;

    // ── Print banner ─────────────────────────────────────────────────
    eprintln!("┌──────────────────────────────────────────────────────┐");
    eprintln!("│  rfed v{VERSION:<46}│");
    eprintln!("├──────────────────────────────────────────────────────┤");
    eprintln!("│  Config dir     : {:<34}│", config_dir.display());
    eprintln!("│  Node name      : {:<34}│", node_name);
    eprintln!("│  Announce int.  : {:<3} secs{:<27}│", announce_interval_secs, "");
    eprintln!("│  Storage limit  : {:<4} MB{:<27}│", storage_limit_mb, "");
    eprintln!("│  Static peers   : {:<34}│", static_peers.len());
    eprintln!("│  VIP subs       : {:<34}│", vip_subscribers.len());
    eprintln!("│  Stamp cost     : {:<34}│",
        default_stamp_cost.map(|c| c.to_string()).as_deref().unwrap_or("disabled"));
    eprintln!("│  lxmf.propagation: {:<33}│", if lxmf_propagation_enabled { "yes" } else { "no" });
    eprintln!("└──────────────────────────────────────────────────────┘");

    // ── Ensure directories exist ─────────────────────────────────────
    for dir in [&config_dir] {
        if let Err(e) = fs::create_dir_all(dir) {
            if !dir.is_dir() {
                return Err(format!(
                    "Cannot create {:?}: {e}\n\
                     Hint: pre-create the directory and ensure it is writable.",
                    dir
                ));
            }
        }
    }

    // ── Global panic hook ────────────────────────────────────────────
    // Captures panics from any background thread and prints them with a
    // timestamp to stderr (visible in Portainer / docker logs) before the
    // process exits.  Without this, thread panics are silent in rfed.log.
    std::panic::set_hook(Box::new(|info| {
        let location = info.location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".to_string());
        let msg = if let Some(s) = info.payload().downcast_ref::<&str>() {
            (*s).to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "(non-string payload)".to_string()
        };
        eprintln!("[rfed] PANIC at {location}: {msg}");
    }));

    // ── Ctrl-C handler ───────────────────────────────────────────────
    let interrupted = Arc::new(AtomicBool::new(false));
    {
        let flag = Arc::clone(&interrupted);
        if let Err(e) = ctrlc::set_handler(move || {
            flag.store(true, Ordering::Relaxed);
        }) {
            eprintln!("[warn] Failed to install SIGINT handler: {e}");
        }
    }

    // ── Reticulum init ───────────────────────────────────────────────
    eprintln!("[rfed] Initialising Reticulum...");
    let rns_init = std::panic::catch_unwind(|| {
        Reticulum::init(Some(rns_config_dir.clone()), None, None, None, false, None)
    });
    match rns_init {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return Err(format!("Reticulum init failed: {e}")),
        Err(panic) => {
            let detail = if let Some(msg) = panic.downcast_ref::<&str>() {
                (*msg).to_string()
            } else if let Some(msg) = panic.downcast_ref::<String>() {
                msg.clone()
            } else {
                "unknown panic".to_string()
            };
            return Err(format!("Reticulum init panicked: {detail}"));
        }
    }
    eprintln!("[rfed] Reticulum ready");

    // Log interface status
    {
        let snap = get_state_snapshot();
        if snap.interfaces.is_empty() {
            eprintln!("[rfed] Warning: no active interfaces yet (will keep trying)");
        } else {
            for iface in &snap.interfaces {
                eprintln!("[rfed] Interface up: {}", iface.name);
            }
        }
    }

    // ── Identity ─────────────────────────────────────────────────────
    let identity = if identity_path.exists() {
        eprintln!("[rfed] Loading identity from {}", identity_path.display());
        Identity::from_file(&identity_path)?
    } else {
        eprintln!("[rfed] Creating new node identity...");
        let id = Identity::new(true);
        id.to_file(&identity_path)?;
        eprintln!("[rfed] Saved new identity to {}", identity_path.display());
        id
    };

    if let Some(hash) = &identity.hash {
        eprintln!("[rfed] Identity hash: {}", hexrep(hash, false));
    }

    // ── NodeConfig ───────────────────────────────────────────────────
    let config = NodeConfig {
        config_dir,
        rns_config_dir: Some(rns_config_dir),

        identity_file: identity_path,
        display_name: node_name,
        announce_interval_secs,
        announce_at_start,
        default_policy: TierPolicy {
            stamp_cost: default_stamp_cost,
            stamp_flexibility: default_stamp_flex,
            deferred_queue_limit: default_deferred_limit,
            deferred_pull_batch_limit: default_deferred_pull_limit,
            allow_notify_registration: default_allow_notify_reg,
            allow_subscription: default_allow_sub,
            trusted_backup_only: default_trusted_backup_only,
        },
        vip_policy: TierPolicy {
            stamp_cost: vip_stamp_cost,
            stamp_flexibility: vip_stamp_flex,
            deferred_queue_limit: vip_deferred_limit,
            deferred_pull_batch_limit: vip_deferred_pull_limit,
            allow_notify_registration: vip_allow_notify_reg,
            allow_subscription: vip_allow_sub,
            trusted_backup_only: vip_trusted_backup_only,
        },
        vip_subscribers,
        peering_cost,
        storage_limit_bytes: storage_limit_mb * 1024 * 1024,
        transfer_limit_bytes: transfer_limit_mb.map(|m| m * 1024 * 1024),
        sync_limit_bytes: sync_limit_mb.map(|m| m * 1024 * 1024),
        static_peers,
        from_static_only,
        trusted_backup_peers,
        primary_node,
        secondary_nodes,
        owner_offline_secs,
        lxmf_propagation_enabled,
        lxmf_propagation_autopeer,
        lxmf_propagation_peers,
    };

    // ── Federation Node ──────────────────────────────────────────────
    eprintln!("[rfed] Creating Federation Node...");
    let node = FedNode::new(identity, config)?;
    let node = Arc::new(Mutex::new(node));

    // Extract timing constants before the event loop to avoid repeated locking.
    const BACKUP_TICK_SECS: u64 = 30;

    destinations::enable(Arc::clone(&node))?;
    eprintln!("[rfed] Federation Node active");

    // ── Optional full lxmf.propagation node ─────────────────────────
    let lxmf_prop_arc: Option<Arc<Mutex<lxmf_propagation::LxmfPropagationNode>>> =
    if lxmf_propagation_enabled {
        let notify_reg = node.lock().map_err(|_| "lock")?.notify_registry.clone();
        let propagation_streams = node.lock().map_err(|_| "lock")?.propagation_streams.clone();
        let node_config = node.lock().map_err(|_| "lock")?.config.clone();
        let prop_identity = node.lock().map_err(|_| "lock")?.identity.clone();
        let distro_table = node.lock().map_err(|_| "lock")?.distro_table.clone();
        let blob_store = node.lock().map_err(|_| "lock")?.blob_store.clone();
        let hook_registry = node.lock().map_err(|_| "lock")?.hook_registry.clone();
        let deferred_queue = node.lock().map_err(|_| "lock")?.deferred_queue.clone();
        let prop = lxmf_propagation::LxmfPropagationNode::new(
            prop_identity,
            &node_config,
            notify_reg,
            propagation_streams,
            Some(distro_table),
            Some(blob_store),
            Some(hook_registry),
            Some(deferred_queue),
        )?;
        lxmf_propagation::LxmfPropagationNode::enable(&prop)?;

        // Register announce handler so we discover other propagation peers
        let ah = lxmf_propagation::LxmfPropagationNode::announce_handler(&prop);
        reticulum_rust::transport::Transport::register_announce_handler(ah);

        node.lock().map_err(|_| "lock")?.lxmf_propagation = Some(Arc::clone(&prop));
        if let Ok(guard) = prop.lock() {
            log(
                format!("[rfed] lxmf.propagation dest hash: {}", hexrep(&guard.destination.hash, false)),
                LOG_NOTICE,
                false,
                false,
            );
        }
        eprintln!("[rfed] lxmf.propagation node active (full mode)");
        Some(prop)
    } else {
        None
    };

    // ── Publish destinations + initial announce ───────────────────────
    //
    // `Transport::publish_destination` opts each destination into the
    // announce daemon: it auto-re-announces once on every interface
    // false→true online transition AND on every `refresh_interval` tick.
    // No sleeps, no startup-burst, no periodic main-loop announce ticks
    // (see DESIGN_PRINCIPLES.md §3-§4).
    if let Ok(guard) = node.lock() {
        guard.publish_destinations();
    }
    if let Some(ref prop) = lxmf_prop_arc {
        lxmf_propagation::LxmfPropagationNode::publish_destination(prop);
    }

    if announce_at_start {
        if let Ok(mut guard) = node.lock() {
            guard.announce();
        }
        if let Some(ref prop) = lxmf_prop_arc {
            lxmf_propagation::LxmfPropagationNode::announce(prop);
        }
        eprintln!("[rfed] Initial announce sent");
    }

    // ── Network status ─────────────────────────────────────────────────
    {
        let snap = get_state_snapshot();
        eprintln!("[rfed] ── Network status ──");
        for iface in &snap.interfaces {
            let rx = format_bytes(iface.rxb);
            let tx = format_bytes(iface.txb);
            eprintln!("[rfed]   Interface: {} (rx {}, tx {})", iface.name, rx, tx);
        }
        if snap.interfaces.is_empty() {
            eprintln!("[rfed]   No active interfaces");
        }
        eprintln!("[rfed]   Known paths: {}", snap.path_table.len());
    }

    let mut last_evict        = Instant::now();
    let mut last_backup_tick  = Instant::now();
    let mut last_heartbeat    = Instant::now();
    let heartbeat_interval    = Duration::from_secs(5 * 60);
    let evict_interval        = Duration::from_secs(3600);
    let backup_tick_interval  = Duration::from_secs(BACKUP_TICK_SECS);
    let evict_max_age         = 7.0 * 24.0 * 3600.0_f64;
    let startup = Instant::now();

    eprintln!("[rfed] Node running. Press Ctrl-C to stop.");

    // Write initial status file so operators can inspect keys immediately.
    write_status_file(&node, &lxmf_prop_arc, &startup);

    // ── Main loop ────────────────────────────────────────────────────
    loop {
        if interrupted.load(Ordering::Relaxed) {
            eprintln!(
                "\n[rfed] Shutting down (uptime: {:.1}h)",
                startup.elapsed().as_secs_f64() / 3600.0
            );

            // ── Graceful shutdown: persist all state ─────────────────
            if let Ok(guard) = node.lock() {
                guard.save_all();
                let _ = fs::remove_file(guard.config.config_dir.join("status.json"));
            }
            if let Some(ref prop) = lxmf_prop_arc {
                if let Ok(guard) = prop.lock() {
                    guard.save_all();
                }
            }

            return Ok(());
        }

        // Periodic re-announces are handled by Transport::publish_destination
        // (registered at startup): up-edge on interface online + refresh
        // interval per destination. No bespoke timers here.

        // Drive pending peer sync sessions
        if let Ok(mut guard) = node.lock() {
            guard.tick_sync();
        }

        // Drive LXMF propagation peer sync
        if let Some(ref prop) = lxmf_prop_arc {
            lxmf_propagation::LxmfPropagationNode::tick_sync(prop);
        }

        // Backup delivery: forward pending registrations + check owner failover.
        if last_backup_tick.elapsed() >= backup_tick_interval {
            if let Ok(mut guard) = node.lock() {
                guard.tick_backup_delivery();
            }
            write_status_file(&node, &lxmf_prop_arc, &startup);
            last_backup_tick = Instant::now();
        }

        // Evict stale deferred-queue entries for gone-forever subscribers.
        if last_evict.elapsed() >= evict_interval {
            if let Ok(guard) = node.lock() {
                if let Ok(mut q) = guard.deferred_queue.lock() {
                    q.evict_expired(evict_max_age);
                }
            }
            // Also evict expired LXMF propagation messages
            if let Some(ref prop) = lxmf_prop_arc {
                if let Ok(mut guard) = prop.lock() {
                    guard.evict_expired();
                    guard.enforce_storage_limit();
                }
            }
            last_evict = Instant::now();
        }

        // Periodic heartbeat — confirms the process is alive and provides
        // a fine-grained timestamp for diagnosing unexpected deaths.
        if last_heartbeat.elapsed() >= heartbeat_interval {
            let snap = reticulum_rust::transport::get_state_snapshot();
            eprintln!(
                "[rfed] heartbeat uptime={:.1}h links={} paths={}",
                startup.elapsed().as_secs_f64() / 3600.0,
                snap.link_table_len,
                snap.path_table.len(),
            );
            last_heartbeat = Instant::now();
        }

        thread::sleep(Duration::from_millis(500));
    }
}

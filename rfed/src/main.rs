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
//!   rfed.notify    — Notify registration
//!
//! Usage:
//!     rfed [OPTIONS]
//!
//! Options:
//!     --config <DIR>            rfed config/storage directory (default: ~/.rfed)
//!     --rnsconfig <DIR>         Reticulum config directory (default: ~/.reticulum)
//!     --identity <FILE>         Path to identity file (default: <config>/identity)
//!     --name <NAME>             Node display name
//!     --announce-interval <M>   Announce interval in minutes (default: 360)
//!     --no-announce-at-start    Don't announce on startup
//!     --stamp-cost <N>          Stamp cost target (default: 16)
//!     --stamp-flexibility <N>   Stamp cost flexibility (default: 3)
//!     --peering-cost <N>        Peering cost (default: 18)
//!     --storage-limit <MB>      Storage limit in megabytes (default: 2000)
//!     --static-peer <HASH>      Add a static peer (repeatable)
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
use reticulum_rust::hexrep;

mod config;
mod announce;
mod subscription;
mod channel;
mod blob_store;
mod deferred_queue;
mod fanout;
mod sync;
mod toml_config;
mod destinations;
mod lxmf_propagation;
pub mod notify;

use config::{NodeConfig, TierPolicy};
use destinations::FedNode;
use toml_config::TomlFile;

const VERSION: &str = env!("CARGO_PKG_VERSION");

// ── CLI helpers ──────────────────────────────────────────────────────────────

fn print_help() {
    eprintln!(
        r#"rfed v{VERSION} — Reticulum Federation Node

Usage: rfed [OPTIONS]

Options:
  --config <DIR>            rfed config/storage directory (default: ~/.rfed)
  --rnsconfig <DIR>         Reticulum config directory
  --identity <FILE>         Path to identity file (default: <config>/identity)
  --name <NAME>             Node display name
  --announce-interval <M>   Announce interval in minutes (default: 360)
  --no-announce-at-start    Don't announce on startup
  --stamp-cost <N>          Stamp cost target (default: 16)
  --stamp-flexibility <N>   Stamp cost flexibility (default: 3)
  --peering-cost <N>        Peering cost (default: 18)
  --storage-limit <MB>      Storage limit in MB (default: 2000)
  --static-peer <HASH>      Add a static peer (repeatable)
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

    // ── Load TOML config (before CLI merge) ──────────────────────────
    let toml_path = config_dir.join("rfed.toml");
    // Write sample config on first run so the operator has a documented template.
    if !toml_path.exists() {
        if let Err(e) = fs::create_dir_all(&config_dir) {
            if !config_dir.is_dir() {
                return Err(format!("Cannot create config dir {:?}: {e}", config_dir));
            }
        }
        let _ = fs::write(&toml_path, toml_config::SAMPLE_CONFIG);
        eprintln!("[rfed] Wrote sample config to {}", toml_path.display());
    }
    let toml = TomlFile::load(&toml_path)?;
    let toml_node    = toml.node.as_ref();
    let toml_storage = toml.storage.as_ref();
    let toml_peering = toml.peering.as_ref();
    let toml_def_pol = toml.policy.as_ref().and_then(|p| p.default.as_ref());
    let toml_vip_pol = toml.policy.as_ref().and_then(|p| p.vip.as_ref());
    let toml_vip     = toml.vip.as_ref();

    // ── Merge: CLI wins over TOML wins over compiled default ──────────
    let rns_config_dir: Option<PathBuf> = arg_value(&args, "--rnsconfig").map(PathBuf::from);

    let identity_path: PathBuf = arg_value(&args, "--identity")
        .map(PathBuf::from)
        .unwrap_or_else(|| config_dir.join("identity"));

    let node_name: String = arg_value(&args, "--name")
        .map(|s| s.to_string())
        .or_else(|| toml_node.and_then(|n| n.name.clone()))
        .unwrap_or_else(|| "rfed".to_string());

    let announce_interval_minutes: u64 = arg_value(&args, "--announce-interval")
        .and_then(|s| s.parse().ok())
        .or_else(|| toml_node.and_then(|n| n.announce_interval_minutes))
        .unwrap_or(360);

    let announce_at_start: bool = if has_flag(&args, "--no-announce-at-start") {
        false
    } else {
        toml_node.and_then(|n| n.announce_at_start).unwrap_or(true)
    };

    // ── Default policy ────────────────────────────────────────────────
    let default_stamp_cost: Option<u32> =
        arg_value(&args, "--stamp-cost").and_then(|s| s.parse().ok())
        .or_else(|| toml_def_pol.and_then(|p| p.stamp_cost))
        .or(Some(16));
    let default_stamp_flex: Option<u32> =
        arg_value(&args, "--stamp-flexibility").and_then(|s| s.parse().ok())
        .or_else(|| toml_def_pol.and_then(|p| p.stamp_flexibility))
        .or(Some(3));
    let default_deferred_limit: usize =
        toml_def_pol.and_then(|p| p.deferred_queue_limit).unwrap_or(256);
    let default_allow_notify_reg: bool =
        toml_def_pol.and_then(|p| p.allow_notify_registration).unwrap_or(true);
    let default_allow_sub: bool =
        toml_def_pol.and_then(|p| p.allow_subscription).unwrap_or(true);
    let default_trusted_backup_only: bool =
        toml_def_pol.and_then(|p| p.trusted_backup_only).unwrap_or(false);

    // ── VIP policy ────────────────────────────────────────────────────
    let vip_stamp_cost: Option<u32> =
        toml_vip_pol.and_then(|p| p.stamp_cost).or(Some(8));
    let vip_stamp_flex: Option<u32> =
        toml_vip_pol.and_then(|p| p.stamp_flexibility).or(Some(2));
    let vip_deferred_limit: usize =
        toml_vip_pol.and_then(|p| p.deferred_queue_limit).unwrap_or(1024);
    let vip_allow_notify_reg: bool =
        toml_vip_pol.and_then(|p| p.allow_notify_registration).unwrap_or(true);
    let vip_allow_sub: bool =
        toml_vip_pol.and_then(|p| p.allow_subscription).unwrap_or(true);
    let vip_trusted_backup_only: bool =
        toml_vip_pol.and_then(|p| p.trusted_backup_only).unwrap_or(false);

    // ── VIP subscriber list ───────────────────────────────────────────
    let mut vip_subscribers: Vec<Vec<u8>> = Vec::new();
    if let Some(hex_list) = toml_vip.and_then(|v| v.subscribers.as_ref()) {
        for hex_str in hex_list {
            match reticulum_rust::decode_hex(hex_str.trim()) {
                Some(bytes) => vip_subscribers.push(bytes),
                None => return Err(format!("Invalid VIP subscriber hash in rfed.toml: {hex_str}")),
            }
        }
    }

    // ── Trusted backup peers ──────────────────────────────────────────
    let mut trusted_backup_peers: Vec<Vec<u8>> = Vec::new();
    if let Some(hex_list) = toml_peering.and_then(|p| p.trusted_backup_peers.as_ref()) {
        for hex_str in hex_list {
            match reticulum_rust::decode_hex(hex_str.trim()) {
                Some(bytes) => trusted_backup_peers.push(bytes),
                None => return Err(format!("Invalid trusted_backup_peer hash in rfed.toml: {hex_str}")),
            }
        }
    }
    let primary_node: Option<Vec<u8>> = toml_peering
        .and_then(|p| p.primary_node.as_deref())
        .and_then(|hex_str| reticulum_rust::decode_hex(hex_str.trim()))
        .and_then(|bytes| if bytes.len() == 16 { Some(bytes) } else { None });

    let secondary_nodes: Vec<Vec<u8>> = toml_peering
        .and_then(|p| p.secondary_nodes.as_ref())
        .map(|list| {
            list.iter()
                .filter_map(|hex_str| reticulum_rust::decode_hex(hex_str.trim()))
                .filter(|bytes| bytes.len() == 16)
                .collect()
        })
        .unwrap_or_default();


    let owner_offline_secs: f64 =
        toml_peering.and_then(|p| p.owner_offline_secs).unwrap_or(90.0);

    // ── Peering / storage ─────────────────────────────────────────────
    let peering_cost: Option<u32> =
        arg_value(&args, "--peering-cost").and_then(|s| s.parse().ok())
        .or_else(|| toml_peering.and_then(|p| p.peering_cost))
        .or(Some(18));

    let storage_limit_mb: u64 =
        arg_value(&args, "--storage-limit").and_then(|s| s.parse().ok())
        .or_else(|| toml_storage.and_then(|s| s.limit_mb))
        .unwrap_or(2000);

    let transfer_limit_mb: Option<u64> = toml_storage.and_then(|s| s.transfer_limit_mb);
    let sync_limit_mb: Option<u64>     = toml_storage.and_then(|s| s.sync_limit_mb);

    // Collect --static-peer CLI flags (repeatable), then fall back to TOML.
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
        if let Some(hex_list) = toml_peering.and_then(|p| p.static_peers.as_ref()) {
            for hex_str in hex_list {
                match reticulum_rust::decode_hex(hex_str.trim()) {
                    Some(bytes) => static_peers.push(bytes),
                    None => return Err(format!("Invalid static_peer in rfed.toml: {hex_str}")),
                }
            }
        }
    }

    let from_static_only: bool =
        has_flag(&args, "--from-static-only")
        || toml_peering.and_then(|p| p.from_static_only).unwrap_or(false);

    // ── LXMF propagation (notify-receive) ─────────────────────────────

    // The node operator enables this; clients self-register notify relay hashes.
    let lxmf_propagation_enabled: bool =
        toml_node.and_then(|n| n.lxmf_propagation).unwrap_or(false);

    // ── Print banner ─────────────────────────────────────────────────
    eprintln!("┌──────────────────────────────────────────────────────┐");
    eprintln!("│  rfed v{VERSION:<46}│");
    eprintln!("├──────────────────────────────────────────────────────┤");
    eprintln!("│  Config dir     : {:<34}│", config_dir.display());
    eprintln!("│  Node name      : {:<34}│", node_name);
    eprintln!("│  Announce int.  : {:<3} minutes{:<24}│", announce_interval_minutes, "");
    eprintln!("│  Storage limit  : {:<4} MB{:<27}│", storage_limit_mb, "");
    eprintln!("│  Static peers   : {:<34}│", static_peers.len());
    eprintln!("│  VIP subs       : {:<34}│", vip_subscribers.len());
    eprintln!("│  Stamp cost     : {:<34}│",
        default_stamp_cost.map(|c| c.to_string()).as_deref().unwrap_or("disabled"));
    eprintln!("│  lxmf.prop.     : {:<34}│", if lxmf_propagation_enabled { "yes" } else { "no" });
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
        Reticulum::init(rns_config_dir.clone(), None, None, None, false, None)
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
        rns_config_dir,
        identity_file: identity_path,
        display_name: node_name,
        announce_interval_secs: announce_interval_minutes * 60,
        announce_at_start,
        default_policy: TierPolicy {
            stamp_cost: default_stamp_cost,
            stamp_flexibility: default_stamp_flex,
            deferred_queue_limit: default_deferred_limit,
            allow_notify_registration: default_allow_notify_reg,
            allow_subscription: default_allow_sub,
            trusted_backup_only: default_trusted_backup_only,
        },
        vip_policy: TierPolicy {
            stamp_cost: vip_stamp_cost,
            stamp_flexibility: vip_stamp_flex,
            deferred_queue_limit: vip_deferred_limit,
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
    };

    // ── Federation Node ──────────────────────────────────────────────
    eprintln!("[rfed] Creating Federation Node...");
    let node = FedNode::new(identity, config)?;
    let node = Arc::new(Mutex::new(node));

    // Extract timing constants before the event loop to avoid repeated locking.
    const BACKUP_TICK_SECS: u64 = 30;

    destinations::enable(Arc::clone(&node))?;
    eprintln!("[rfed] Federation Node active");

    // ── Optional lxmf.propagation service ───────────────────────────
    if lxmf_propagation_enabled {
        let notify_reg = node.lock().map_err(|_| "lock")?.notify_registry.clone();
        let node_config = node.lock().map_err(|_| "lock")?.config.clone();
        // Use the node identity (clone required; identity is non-Copy).
        let prop_identity = node.lock().map_err(|_| "lock")?.identity.clone();
        let prop = lxmf_propagation::LxmfPropagation::new(prop_identity, &node_config, notify_reg)?;
        lxmf_propagation::LxmfPropagation::wire(&prop)?;
        lxmf_propagation::LxmfPropagation::announce(&prop);
        node.lock().map_err(|_| "lock")?.lxmf_propagation = Some(prop);
        eprintln!("[rfed] lxmf.propagation active (push-receive mode)");
    }

    // ── Initial announce ─────────────────────────────────────────────
    let announce_interval = Duration::from_secs(
        node.lock().map_err(|_| "lock")?.config.announce_interval_secs
    );

    if announce_at_start {
        thread::sleep(Duration::from_secs(3));
        if let Ok(guard) = node.lock() {
            guard.announce();
        }
        eprintln!("[rfed] Initial announce queued");
    }

    let mut last_announce     = Instant::now();
    let mut last_evict        = Instant::now();
    let mut last_backup_tick  = Instant::now();
    let evict_interval        = Duration::from_secs(3600);
    let backup_tick_interval  = Duration::from_secs(BACKUP_TICK_SECS);
    let evict_max_age         = 7.0 * 24.0 * 3600.0_f64;
    let startup = Instant::now();

    eprintln!("[rfed] Node running. Press Ctrl-C to stop.");

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
            }

            return Ok(());
        }

        // Periodic re-announce
        if last_announce.elapsed() >= announce_interval {
            if let Ok(guard) = node.lock() {
                guard.announce();
            }
            last_announce = Instant::now();
        }

        // Drive pending peer sync sessions
        if let Ok(mut guard) = node.lock() {
            guard.tick_sync();
        }

        // Backup delivery: forward pending registrations + check owner failover.
        if last_backup_tick.elapsed() >= backup_tick_interval {
            if let Ok(mut guard) = node.lock() {
                guard.tick_backup_delivery();
            }
            last_backup_tick = Instant::now();
        }

        // Evict stale deferred-queue entries for gone-forever subscribers.
        if last_evict.elapsed() >= evict_interval {
            if let Ok(guard) = node.lock() {
                if let Ok(mut q) = guard.deferred_queue.lock() {
                    q.evict_expired(evict_max_age);
                }
            }
            last_evict = Instant::now();
        }

        thread::sleep(Duration::from_millis(500));
    }
}

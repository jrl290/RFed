//! Configuration loader for rfed.
//!
//! rfed uses a single config file (`<config_dir>/config`) in Reticulum's
//! native INI format.  The `[reticulum]` and `[interfaces]` sections are
//! read by Reticulum directly; the rfed-specific sections (`[node]`,
//! `[storage]`, `[peering]`, etc.) are parsed here.
//!
//! On first run a sample config is written as a starting point.

use std::collections::HashMap;
use std::path::Path;

use configparser::ini::Ini;

type SectionMap = HashMap<String, Option<String>>;

// ── Per-section structs ───────────────────────────────────────────────────────

pub struct IniNode {
    pub name: Option<String>,
    pub announce_interval_minutes: Option<u64>,
    pub announce_at_start: Option<bool>,
    pub lxmf_propagation: Option<bool>,
    pub lxmf_propagation_autopeer: Option<bool>,
}

pub struct IniStorage {
    pub limit_mb: Option<u64>,
    pub transfer_limit_mb: Option<u64>,
    pub sync_limit_mb: Option<u64>,
}

pub struct IniPeering {
    pub static_peers: Vec<String>,
    pub from_static_only: Option<bool>,
    pub peering_cost: Option<u32>,
    pub trusted_backup_peers: Vec<String>,
    pub primary_node: Option<String>,
    pub secondary_nodes: Vec<String>,
    pub owner_offline_secs: Option<f64>,
    pub propagation_peers: Vec<String>,
}

pub struct IniTierPolicy {
    pub stamp_cost: Option<u32>,
    pub stamp_flexibility: Option<u32>,
    pub deferred_queue_limit: Option<usize>,
    pub deferred_pull_batch_limit: Option<usize>,
    pub allow_notify_registration: Option<bool>,
    pub allow_subscription: Option<bool>,
    pub trusted_backup_only: Option<bool>,
}

pub struct IniVip {
    pub subscribers: Vec<String>,
}

// ── Top-level parsed config ───────────────────────────────────────────────────

pub struct IniConfig {
    pub node:           IniNode,
    pub storage:        IniStorage,
    pub peering:        IniPeering,
    pub default_policy: IniTierPolicy,
    pub vip_policy:     IniTierPolicy,
    pub vip:            IniVip,
}

impl IniConfig {
    /// Load and parse `rfed.conf`.  Returns an all-defaults config if the
    /// file does not exist (caller should write the sample and continue).
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(IniConfig::empty());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {:?}: {e}", path))?;
        Self::parse(&text).map_err(|e| format!("Config parse error in {:?}: {e}", path))
    }

    fn parse(text: &str) -> Result<Self, String> {
        let mut ini = Ini::new();
        // configparser lowercases section names and keys, which matches
        // how Reticulum itself treats its config.
        ini.read(text.to_string())
            .map_err(|e| format!("INI parse error: {e}"))?;
        let map = ini.get_map().unwrap_or_default();

        // ── [node] ────────────────────────────────────────────────────
        let n = map.get("node");
        let node = IniNode {
            name:                          flat_str(n, "name"),
            announce_interval_minutes:     flat_uint(n, "announce_interval_minutes")?,
            announce_at_start:             flat_bool(n, "announce_at_start")?,
            lxmf_propagation:              flat_bool(n, "lxmf_propagation")?,
            lxmf_propagation_autopeer:     flat_bool(n, "lxmf_propagation_autopeer")?,
        };

        // ── [storage] ─────────────────────────────────────────────────
        let s = map.get("storage");
        let storage = IniStorage {
            limit_mb:          flat_uint(s, "limit_mb")?,
            transfer_limit_mb: flat_uint(s, "transfer_limit_mb")?,
            sync_limit_mb:     flat_uint(s, "sync_limit_mb")?,
        };

        // ── [peering] ─────────────────────────────────────────────────
        let p = map.get("peering");
        let peering = IniPeering {
            static_peers:         flat_csv(p, "static_peers"),
            from_static_only:     flat_bool(p, "from_static_only")?,
            peering_cost:         flat_uint(p, "peering_cost")?.map(|v| v as u32),
            trusted_backup_peers: flat_csv(p, "trusted_backup_peers"),
            primary_node:         flat_str(p, "primary_node"),
            secondary_nodes:      flat_csv(p, "secondary_nodes"),
            owner_offline_secs:   flat_float(p, "owner_offline_secs")?,
            propagation_peers:    flat_csv(p, "propagation_peers"),
        };

        // ── [policy.default] / [policy.vip] ───────────────────────────
        let default_policy = parse_tier_policy(map.get("policy.default"))?;
        let vip_policy     = parse_tier_policy(map.get("policy.vip"))?;

        // ── [vip] ─────────────────────────────────────────────────────
        let vip = IniVip {
            subscribers: flat_csv(map.get("vip"), "subscribers"),
        };

        Ok(IniConfig { node, storage, peering, default_policy, vip_policy, vip })
    }

    fn empty() -> Self {
        IniConfig {
            node: IniNode {
                name: None, announce_interval_minutes: None,
                announce_at_start: None, lxmf_propagation: None,
                lxmf_propagation_autopeer: None,
            },
            storage: IniStorage {
                limit_mb: None, transfer_limit_mb: None, sync_limit_mb: None,
            },
            peering: IniPeering {
                static_peers: vec![], from_static_only: None, peering_cost: None,
                trusted_backup_peers: vec![], primary_node: None,
                secondary_nodes: vec![], owner_offline_secs: None,
                propagation_peers: vec![],
            },
            default_policy: IniTierPolicy {
                stamp_cost: None, stamp_flexibility: None, deferred_queue_limit: None,
                deferred_pull_batch_limit: None,
                allow_notify_registration: None, allow_subscription: None,
                trusted_backup_only: None,
            },
            vip_policy: IniTierPolicy {
                stamp_cost: None, stamp_flexibility: None, deferred_queue_limit: None,
                deferred_pull_batch_limit: None,
                allow_notify_registration: None, allow_subscription: None,
                trusted_backup_only: None,
            },
            vip: IniVip { subscribers: vec![] },
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn flat_str(sec: Option<&SectionMap>, key: &str) -> Option<String> {
    sec?.get(key)?.clone()
}

fn flat_bool(sec: Option<&SectionMap>, key: &str) -> Result<Option<bool>, String> {
    let Some(val) = flat_str(sec, key) else { return Ok(None) };
    match val.trim().to_lowercase().as_str() {
        "yes" | "true" | "1" | "on"  => Ok(Some(true)),
        "no"  | "false"| "0" | "off" => Ok(Some(false)),
        other => Err(format!("Invalid boolean '{}' for key '{}'", other, key)),
    }
}

fn flat_uint(sec: Option<&SectionMap>, key: &str) -> Result<Option<u64>, String> {
    let Some(val) = flat_str(sec, key) else { return Ok(None) };
    val.trim().parse::<u64>()
        .map(Some)
        .map_err(|_| format!("Expected integer for '{}', got '{}'", key, val))
}

fn flat_float(sec: Option<&SectionMap>, key: &str) -> Result<Option<f64>, String> {
    let Some(val) = flat_str(sec, key) else { return Ok(None) };
    val.trim().parse::<f64>()
        .map(Some)
        .map_err(|_| format!("Expected number for '{}', got '{}'", key, val))
}

fn flat_csv(sec: Option<&SectionMap>, key: &str) -> Vec<String> {
    let Some(val) = flat_str(sec, key) else { return vec![] };
    val.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_tier_policy(sec: Option<&SectionMap>) -> Result<IniTierPolicy, String> {
    Ok(IniTierPolicy {
        stamp_cost:                flat_uint(sec, "stamp_cost")?.map(|v| v as u32),
        stamp_flexibility:         flat_uint(sec, "stamp_flexibility")?.map(|v| v as u32),
        deferred_queue_limit:      flat_uint(sec, "deferred_queue_limit")?.map(|v| v as usize),
        deferred_pull_batch_limit: flat_uint(sec, "deferred_pull_batch_limit")?.map(|v| v as usize),
        allow_notify_registration: flat_bool(sec, "allow_notify_registration")?,
        allow_subscription:        flat_bool(sec, "allow_subscription")?,
        trusted_backup_only:       flat_bool(sec, "trusted_backup_only")?,
    })
}

// ── Sample config ─────────────────────────────────────────────────────────────

pub const CONFIG_FILENAME: &str = "config";

/// Sample config written on first run.
pub const SAMPLE_CONFIG: &str = r#"# rfed — Reticulum Federation Node configuration
#
# This file uses Reticulum's native config format.
# The [reticulum] and [interfaces] sections are read by Reticulum directly.
# The remaining sections are rfed-specific.
#
# CLI flags override rfed values for the current run only.

[reticulum]
  # Required for rfed — do not change these.
  share_instance = No
  enable_transport = No
  panic_on_interface_error = No


# ── Reticulum interfaces ─────────────────────────────────────────────────────
# Use standard Reticulum format: [[double brackets]] for each interface.
# Uncomment at least one interface for network connectivity.

[interfaces]

  # [[Default Interface]]
  #   type = AutoInterface
  #   enabled = Yes

  # [[TCP Transport]]
  #   type = TCPClientInterface
  #   enabled = Yes
  #   target_host = rmap.world
  #   target_port = 4242


# ── rfed settings ────────────────────────────────────────────────────────────

[node]

  # name                         = rfed
  # announce_interval_minutes    = 360
  # announce_at_start            = yes
  # lxmf_propagation             = no
  # lxmf_propagation_autopeer    = no


[storage]

  # limit_mb          = 2000
  # transfer_limit_mb = 500
  # sync_limit_mb     = 1000


[peering]

  # static_peers      = aabbccddaabbccddaabbccddaabbccdd
  # from_static_only  = no
  # peering_cost      = 18
  # trusted_backup_peers = aabbccddaabbccddaabbccddaabbccdd
  # primary_node = aabbccddaabbccddaabbccddaabbccdd
  # secondary_nodes = aabbccddaabbccddaabbccddaabbccdd, 11223344112233441122334411223344
  # owner_offline_secs = 90
  # propagation_peers = aabbccddaabbccddaabbccddaabbccdd


[policy.default]

  # ── PoW stamps on channel SEND are DISABLED BY DEFAULT ──────────
  # Leave `stamp_cost` unset (or set to 0) to keep channel SEND
  # PoW-free. Subscribe responses then return nil for stamp_cost so
  # clients skip stamping entirely. Opt-in by setting a value > 0.
  # stamp_cost                = 16
  # stamp_flexibility         = 3
  # deferred_queue_limit      = 256
  # allow_notify_registration = yes
  # allow_subscription        = yes
  # trusted_backup_only       = no


[policy.vip]

  # See [policy.default] for stamp semantics; stamps are disabled
  # by default for VIPs as well.
  # stamp_cost                = 4
  # stamp_flexibility         = 2
  # deferred_queue_limit      = 2048
  # allow_notify_registration = yes
  # allow_subscription        = yes
  # trusted_backup_only       = no


[vip]

  # subscribers = aabbccddaabbccddaabbccddaabbccdd, 11223344112233441122334411223344
"#;


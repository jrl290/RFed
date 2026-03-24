//! INI-format configuration file loader (Reticulum ecosystem format).
//!
//! Reads `<config_dir>/rfed.conf`.  All sections and keys are optional;
//! a missing file or missing key silently falls back to the compiled-in
//! default.  CLI flags always override file values.
//!
//! On first run (no rfed.conf found) a commented sample is written so the
//! operator has a self-documenting starting point.
//!
//! # Interface sections
//!
//! Any section whose `type` value ends with `Interface` (case-insensitive)
//! is treated as a Reticulum interface definition.  These sections are
//! collected in `IniConfig::interfaces` and merged into a temporary
//! Reticulum config at startup, making them additive to whatever interfaces
//! Reticulum itself has configured in `~/.reticulum/config`.

use std::collections::HashMap;
use std::path::Path;

use configparser::ini::Ini;

type SectionMap = HashMap<String, Option<String>>;

// ── Per-section structs ───────────────────────────────────────────────────────

pub struct IniNode {
    pub name: Option<String>,
    pub announce_interval_minutes: Option<u64>,
    pub announce_at_start: Option<bool>,
    pub lxmf_propagation_notification: Option<bool>,
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
}

pub struct IniTierPolicy {
    pub stamp_cost: Option<u32>,
    pub stamp_flexibility: Option<u32>,
    pub deferred_queue_limit: Option<usize>,
    pub allow_notify_registration: Option<bool>,
    pub allow_subscription: Option<bool>,
    pub trusted_backup_only: Option<bool>,
}

pub struct IniVip {
    pub subscribers: Vec<String>,
}

/// A Reticulum interface section declared in rfed.conf.
/// `name` is the section header; `entries` are the raw key/value pairs
/// in the order they will be written to the merged Reticulum config.
pub struct InterfaceSection {
    pub name: String,
    pub entries: Vec<(String, String)>,
}

// ── Top-level parsed config ───────────────────────────────────────────────────

pub struct IniConfig {
    pub node:           IniNode,
    pub storage:        IniStorage,
    pub peering:        IniPeering,
    pub default_policy: IniTierPolicy,
    pub vip_policy:     IniTierPolicy,
    pub vip:            IniVip,
    /// Reticulum interface sections to be merged into the RNS config at startup.
    pub interfaces:     Vec<InterfaceSection>,
}

// Section names that belong to rfed — everything else with type=*Interface
// is an RNS interface definition.
const RFED_SECTIONS: &[&str] = &[
    "node", "storage", "peering",
    "policy.default", "policy.vip",
    "vip",
];

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
            lxmf_propagation_notification: flat_bool(n, "lxmf_propagation_notification")?,
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
        };

        // ── [policy.default] / [policy.vip] ───────────────────────────
        let default_policy = parse_tier_policy(map.get("policy.default"))?;
        let vip_policy     = parse_tier_policy(map.get("policy.vip"))?;

        // ── [vip] ─────────────────────────────────────────────────────
        let vip = IniVip {
            subscribers: flat_csv(map.get("vip"), "subscribers"),
        };

        // ── Interface sections ─────────────────────────────────────────
        // Any section with type = *Interface and not a known rfed section.
        let mut interfaces: Vec<InterfaceSection> = Vec::new();
        for (section, kvs) in &map {
            if section == "default" || RFED_SECTIONS.contains(&section.as_str()) {
                continue;
            }
            let type_val = kvs.get("type")
                .and_then(|v| v.as_deref())
                .unwrap_or("")
                .to_lowercase();
            if type_val.ends_with("interface") {
                let mut entries: Vec<(String, String)> = kvs
                    .iter()
                    .filter_map(|(k, v)| v.as_ref().map(|val| (k.clone(), val.clone())))
                    .collect();
                // type first, then enabled, then the rest alphabetically
                entries.sort_by(|a, b| {
                    let rank = |k: &str| match k {
                        "type"    => 0,
                        "enabled" => 1,
                        _         => 2,
                    };
                    rank(&a.0).cmp(&rank(&b.0)).then(a.0.cmp(&b.0))
                });
                interfaces.push(InterfaceSection { name: section.clone(), entries });
            }
        }
        // Stable order across runs
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(IniConfig { node, storage, peering, default_policy, vip_policy, vip, interfaces })
    }

    fn empty() -> Self {
        IniConfig {
            node: IniNode {
                name: None, announce_interval_minutes: None,
                announce_at_start: None, lxmf_propagation_notification: None,
            },
            storage: IniStorage {
                limit_mb: None, transfer_limit_mb: None, sync_limit_mb: None,
            },
            peering: IniPeering {
                static_peers: vec![], from_static_only: None, peering_cost: None,
                trusted_backup_peers: vec![], primary_node: None,
                secondary_nodes: vec![], owner_offline_secs: None,
            },
            default_policy: IniTierPolicy {
                stamp_cost: None, stamp_flexibility: None, deferred_queue_limit: None,
                allow_notify_registration: None, allow_subscription: None,
                trusted_backup_only: None,
            },
            vip_policy: IniTierPolicy {
                stamp_cost: None, stamp_flexibility: None, deferred_queue_limit: None,
                allow_notify_registration: None, allow_subscription: None,
                trusted_backup_only: None,
            },
            vip: IniVip { subscribers: vec![] },
            interfaces: vec![],
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
        allow_notify_registration: flat_bool(sec, "allow_notify_registration")?,
        allow_subscription:        flat_bool(sec, "allow_subscription")?,
        trusted_backup_only:       flat_bool(sec, "trusted_backup_only")?,
    })
}

// ── Sample config ─────────────────────────────────────────────────────────────

pub const CONFIG_FILENAME: &str = "rfed.conf";

/// Commented sample written on first run.
pub const SAMPLE_CONFIG: &str = r#"# rfed.conf — Reticulum Federation Node configuration
# All settings are optional; defaults are shown in comments.
# CLI flags override these values for the current run only.
#
# This file uses the same INI format as ~/.reticulum/config and lxmd.

[node]

  # name                         = rfed
  # announce_interval_minutes    = 360
  # announce_at_start            = yes
  # lxmf_propagation_notification = no


[storage]

  # limit_mb          = 2000
  # transfer_limit_mb = 500    # max bytes sent to a single peer per sync session
  # sync_limit_mb     = 1000   # max bytes transferred across all peers per period


[peering]

  # Federation peers — 16-byte destination hashes (32 hex chars), comma-separated.
  # static_peers      = aabbccddaabbccddaabbccddaabbccdd

  # from_static_only  = no
  # peering_cost      = 18

  # Nodes trusted as subscriber backup delivery nodes (comma-separated hashes).
  # trusted_backup_peers = aabbccddaabbccddaabbccddaabbccdd

  # Designated primary backup node for this node's subscribers.
  # primary_node = aabbccddaabbccddaabbccddaabbccdd

  # Ordered fallback list of secondary backup nodes (comma-separated).
  # secondary_nodes = aabbccddaabbccddaabbccddaabbccdd, 11223344112233441122334411223344

  # Seconds of silence before a backup node considers the primary offline.
  # owner_offline_secs = 90


# ── Delivery policy ──────────────────────────────────────────────────────────
# Two tiers: default (all subscribers) and vip (listed in [vip]).
#
# stamp_cost       — required PoW leading-zero bits for inbound channel posts.
# stamp_flexibility — accept stamps with cost >= (stamp_cost - flexibility).

[policy.default]

  # stamp_cost                = 16
  # stamp_flexibility         = 3
  # deferred_queue_limit      = 256   # max blobs held while subscriber is offline
  # allow_notify_registration = yes
  # allow_subscription        = yes
  # trusted_backup_only       = no    # require backup nodes in [peering] trusted_backup_peers


[policy.vip]

  # stamp_cost                = 4
  # stamp_flexibility         = 2
  # deferred_queue_limit      = 2048
  # allow_notify_registration = yes
  # allow_subscription        = yes
  # trusted_backup_only       = no


[vip]

  # Destination hashes (32 hex chars) of VIP subscribers, comma-separated.
  # subscribers = aabbccddaabbccddaabbccddaabbccdd, 11223344112233441122334411223344


# ── Reticulum interfaces (additive) ──────────────────────────────────────────
#
# Any section whose type ends with Interface is treated as a Reticulum
# interface definition and merged into Reticulum's config at startup —
# additive to any interfaces already configured in ~/.reticulum/config.
#
# Use the exact same syntax as ~/.reticulum/config.  For example:
#
# [TCP Seed Server]
#
#   type        = TCPClientInterface
#   enabled     = yes
#   target_host = reticulum.betweentheborders.com
#   target_port = 4965
#
#
# [RNode LoRa]
#
#   type      = RNodeInterface
#   enabled   = yes
#   port      = /dev/ttyUSB0
#   frequency = 868000000
#   bandwidth = 125000
#   txpower   = 7
#   sf        = 7
#   cr        = 5
"#;


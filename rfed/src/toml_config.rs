//! TOML configuration file loader.
//!
//! Reads `<config_dir>/rfed.toml`.  All sections and keys are optional;
//! a missing file or missing key silently falls back to the compiled-in
//! default.  CLI flags always override TOML values — TOML sets persistent
//! defaults, CLI does per-run overrides.
//!
//! On first run (no rfed.toml found) a commented sample is written so the
//! operator has a self-documenting starting point.

use std::path::Path;

use serde::Deserialize;

// ── Per-section structs ───────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct TomlNode {
    pub name: Option<String>,
    pub announce_interval_minutes: Option<u64>,
    pub announce_at_start: Option<bool>,
    /// Accept inbound LXMF messages solely for triggering notify wake-ups.
    /// This is NOT full LXMF propagation — messages are never stored or forwarded.
    pub lxmf_propagation_notification: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct TomlStorage {
    pub limit_mb: Option<u64>,
    pub transfer_limit_mb: Option<u64>,
    pub sync_limit_mb: Option<u64>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct TomlPeering {
    /// Hex-encoded 16-byte (32 hex char) destination hashes.
    pub static_peers: Option<Vec<String>>,
    pub from_static_only: Option<bool>,
    pub peering_cost: Option<u32>,
    /// Nodes trusted as subscriber backup nodes (hex dest hashes).
    pub trusted_backup_peers: Option<Vec<String>>,
    /// Designated primary backup node for this node's subscribers (hex dest
    /// hash, 32 hex chars).  This is the first-choice backup target.
    pub primary_node: Option<String>,
    /// Ordered fallback list of secondary backup nodes (hex dest hashes).
    /// If the primary is unreachable, the first alive secondary is used.
    /// After all designated nodes are exhausted, auto-selection kicks in.
    pub secondary_nodes: Option<Vec<String>>,

    /// Seconds of silence before a backup node considers the primary offline.
    /// Should be > the primary's announce interval. Default: 90.
    pub owner_offline_secs: Option<f64>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct TomlTierPolicy {
    pub stamp_cost: Option<u32>,
    pub stamp_flexibility: Option<u32>,
    pub deferred_queue_limit: Option<usize>,
    /// Whether subscribers on this tier may register for notify relays.
    pub allow_notify_registration: Option<bool>,
    /// Whether subscribers on this tier may subscribe to channels.
    pub allow_subscription: Option<bool>,
    /// Require nominated backup nodes to appear in peering.trusted_backup_peers.
    pub trusted_backup_only: Option<bool>,
}

/// Holds `[policy.default]` and `[policy.vip]` sub-tables.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct TomlPolicy {
    pub default: Option<TomlTierPolicy>,
    pub vip: Option<TomlTierPolicy>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct TomlVip {
    /// Hex-encoded 16-byte dest hashes of VIP subscribers.
    pub subscribers: Option<Vec<String>>,
}

// ── Top-level file struct ─────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct TomlFile {
    pub node: Option<TomlNode>,
    pub storage: Option<TomlStorage>,
    pub peering: Option<TomlPeering>,
    pub policy: Option<TomlPolicy>,
    pub vip: Option<TomlVip>,
}

impl TomlFile {
    /// Parse a TOML config file.  Returns `Ok(Default)` if the file does not
    /// exist (caller should write the sample and proceed with defaults).
    pub fn load(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Ok(TomlFile::default());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Cannot read {:?}: {e}", path))?;
        toml::from_str(&text)
            .map_err(|e| format!("TOML parse error in {:?}: {e}", path))
    }
}

// ── Sample config written at first run ───────────────────────────────────────

/// Commented sample written to `<config_dir>/rfed.toml` when no config
/// file exists.  Contains every available knob with its default shown.
pub const SAMPLE_CONFIG: &str = r#"# rfed.toml — Reticulum Federation Node configuration
# All settings are optional; defaults are shown in comments.
# CLI flags override these values for the current run only.

[node]
# name                      = "rfed"
# announce_interval_minutes = 360
# announce_at_start         = true
# lxmf_propagation_notification = false  # set true to accept LXMF PUTs solely for notify wake-ups (not full propagation)

[storage]
# limit_mb          = 2000
# transfer_limit_mb = 500    # max bytes sent to a single peer per sync session
# sync_limit_mb     = 1000   # max bytes sent across all peers per period

[peering]
# Federation peers — 16-byte destination hashes (hex, 32 chars each).
# static_peers     = ["aabbccddaabbccddaabbccddaabbccdd"]
# from_static_only = false
# peering_cost     = 18
#
# Nodes trusted as subscriber backup delivery nodes.
# Subscribers may nominate backup nodes; when trusted_backup_only = true
# (per policy tier) only nodes in this list are accepted.
# trusted_backup_peers = [
#   "aabbccddaabbccddaabbccddaabbccdd",  # backup-node-1.example
# ]
#
# Designated primary backup node for this node's subscribers.
# Subscriber registrations are forwarded to the primary backup; it will
# deliver blobs if this node's path decays (owner offline).
# primary_node = "aabbccddaabbccddaabbccddaabbccdd"
#
# Ordered fallback list of secondary backup nodes.  If the primary is
# unreachable, the first alive secondary is used.  After all designated
# nodes are exhausted, an alive peer is auto-selected.
# Only ONE node receives pushes at a time.  The active backup re-pushes
# to ITS own backup on failover (chain of custody).
# Entries not refreshed within 2× owner_offline_secs are pruned.
# secondary_nodes = [
#   "aabbccddaabbccddaabbccddaabbccdd",
#   "11223344556677881122334455667788",
# ]

# ── Delivery policy ─────────────────────────────────────────────────────────
# Two tiers: "default" (all subscribers) and "vip" (listed in [vip]).
#
# stamp_cost — required PoW leading-zero bits for inbound channel posts.
# stamp_flexibility — accept stamps with cost >= (stamp_cost - flexibility).
#
# Channel SEND packets are anonymous so default stamp_cost applies to all
# senders.  Per-VIP stamp bypass requires the authenticated /rfed/send path
# (future feature).

[policy.default]
# stamp_cost              = 16
# stamp_flexibility       = 3
# deferred_queue_limit    = 256    # max blobs held while subscriber is offline
# allow_notify_registration = true  # can register for notify relays
# allow_subscription      = true   # can subscribe to channels
# trusted_backup_only     = false  # require backup nodes in trusted_backup_peers

[policy.vip]
# stamp_cost              = 4
# stamp_flexibility       = 2
# deferred_queue_limit    = 2048
# allow_notify_registration = true
# allow_subscription      = true
# trusted_backup_only     = false

[vip]
# Destination hashes (hex, 16 bytes = 32 hex chars) of VIP subscribers.
# subscribers = [
#   "aabbccddaabbccddaabbccddaabbccdd",  # Alice
#   "11223344112233441122334411223344",  # Bob
# ]


"#;

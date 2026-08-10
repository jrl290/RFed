use std::path::PathBuf;

// ── TierPolicy ────────────────────────────────────────────────────────────────

/// Per-subscriber-tier delivery and anti-spam parameters.
///
/// Two tiers are maintained: `default_policy` (everyone) and `vip_policy`
/// (subscribers listed in `NodeConfig::vip_subscribers`).  Use
/// `NodeConfig::policy_for` to select the right tier for a given hash.
///
/// # Stamp and sender anonymity
///
/// `stamp_cost` on the channel SEND packet path applies node-wide via the
/// default policy because fire-and-forget channel SEND packets carry no
/// sender identity.  Per-VIP stamp bypass requires a future authenticated
/// `/rfed/send` request path where `caller: Option<&Identity>` is available.
#[derive(Clone, Debug)]
pub struct TierPolicy {
    /// Required PoW leading-zero bits for incoming blobs (None = disabled).
    pub stamp_cost: Option<u32>,
    /// Accept stamps down to `stamp_cost - stamp_flexibility`.
    pub stamp_flexibility: Option<u32>,
    /// Maximum blobs held in the deferred delivery queue for a subscriber
    /// on this tier while they are offline.
    pub deferred_queue_limit: usize,
    /// Maximum blobs returned in a single PULL response for this tier.
    /// `None` means unlimited (drain the entire queue in one request).
    pub deferred_pull_batch_limit: Option<usize>,
    /// Whether subscribers on this tier may register for notify relays.
    pub allow_notify_registration: bool,
    /// Whether subscribers on this tier may subscribe to channels.
    pub allow_subscription: bool,
    /// When true, nominated backup nodes must appear in
    /// `NodeConfig::trusted_backup_peers`.
    pub trusted_backup_only: bool,
}

// ─────────────────────────────────────────────────────────────────────────────
//  ANTI-SPAM POW STAMPS — DO NOT BREAK THIS AGAIN
// ─────────────────────────────────────────────────────────────────────────────
//
// Channel SEND packets carry a PoW stamp to deter spam. The wire format is:
//
//     [ channel_id_hash(16) | inner_blob(*) | stamp(LXStamper::STAMP_SIZE) ]
//
// Stamp material binds the stamp to this exact (channel_hash || inner_blob)
// payload — recompute by `LXStamper::stamp_workblock(full_hash(material), 16)`.
//
// `stamp_cost`        — required PoW leading-zero bits (None or 0 = disabled)
// `stamp_flexibility` — accept stamps down to `stamp_cost - flexibility`
//
// CONTRACT (must hold across rfed + retichat-ffi + iOS forever):
//   1. The advertised cost in `[bool, stamp_cost_or_nil]` from
//      `/rfed/subscribe` IS the cost the client must produce.
//   2. RFed validates with the SAME workblock the client used:
//        transient_id = identity::full_hash(channel_hash || inner_blob)
//        workblock    = LXStamper::stamp_workblock(transient_id, 16)
//      `STAMP_EXPAND_ROUNDS` MUST stay 16 on both sides — bumping it
//      silently invalidates every previously-cached stamp_cost.
//   3. `flexibility` must be respected on validation; otherwise stamps
//      generated against an older `stamp_cost` are wrongly rejected.
//   4. `Some(0)` in config means "disabled" — same as `None`. Both
//      subscribe response (returns nil) and SEND validation (skipped)
//      MUST honor this. Required to prevent a 0-cost foot-gun.
//   5. If the operator changes `stamp_cost`, every subscriber MUST
//      re-subscribe to learn the new value (cached `stampCost` on the
//      client is stale otherwise → all SENDs rejected).
//
// SEE ALSO:
//   * SPEC.md §"3. Wire Formats / SEND Packet" and §"17. Capabilities"
//   * README.md §"Channel Messages on the Wire"
//   * rfed/src/destinations.rs (channel SEND handler ~line 1480)
//   * Reticulum-rust/src/lxstamper.rs (LXStamper)
//   * Retichat-ios/rust/retichat-ffi/src/lib.rs `retichat_compute_channel_stamp`
//   * Retichat-ios/Retichat/Services/RfedChannelClient.swift `sendMessage`
//   * /memories/repo/retichat-rfed-channel-integration.md
//
// HISTORICAL FAILURE MODES (do not repeat):
//   * Cached client `stampCost=8` against rfed running cost=16 → all SENDs
//     rejected. Fix: client always re-subscribes on app start AND on the
//     first SEND failure of the session. (See `RfedChannelClient`.)
//   * Bumping STAMP_EXPAND_ROUNDS without bumping protocol_version →
//     silently invalidates every existing stamp. Don't.
//   * Forgetting `Some(0)==None` → 0-cost server still requires a stamp.
//
// ─────────────────────────────────────────────────────────────────────────────

impl Default for TierPolicy {
    fn default() -> Self {
        TierPolicy {
            stamp_cost: Some(16),
            stamp_flexibility: Some(3),
            deferred_queue_limit: 256,
            deferred_pull_batch_limit: None,
            allow_notify_registration: true,
            allow_subscription: true,
            trusted_backup_only: false,
        }
    }
}

impl TierPolicy {
    /// A relaxed VIP policy: lower stamp cost, larger deferred queue.
    pub fn vip_default() -> Self {
        TierPolicy {
            stamp_cost: Some(8),
            stamp_flexibility: Some(2),
            deferred_queue_limit: 1024,
            deferred_pull_batch_limit: None,
            allow_notify_registration: true,
            allow_subscription: true,
            trusted_backup_only: false,
        }
    }
}

// ── NodeConfig ────────────────────────────────────────────────────────────────

/// Full runtime configuration for an rfed node.
#[derive(Clone)]
pub struct NodeConfig {
    // ── Paths ────────────────────────────────────────────────────────
    /// rfed config/storage directory (e.g. ~/.rfed)
    pub config_dir: PathBuf,
    /// Reticulum config directory generated by rfed (e.g. ~/.rfed/_rns)
    pub rns_config_dir: Option<PathBuf>,
    /// Path to the node identity file
    pub identity_file: PathBuf,

    // ── Node identity ─────────────────────────────────────────────────
    /// Human-readable node name sent in announces
    pub display_name: String,
    /// How often the node re-announces itself (seconds)
    pub announce_interval_secs: u64,
    /// Whether to announce immediately on startup
    pub announce_at_start: bool,

    // ── Tiered delivery policy ────────────────────────────────────────
    /// Policy applied to non-VIP subscribers/senders.
    pub default_policy: TierPolicy,
    /// Policy applied to VIP subscribers (listed in `vip_subscribers`).
    pub vip_policy: TierPolicy,
    /// 16-byte truncated dest hashes of VIP subscribers.
    pub vip_subscribers: Vec<Vec<u8>>,

    // ── Node-wide anti-spam ───────────────────────────────────────────
    /// PoW cost advertised to peers for peering establishment.
    pub peering_cost: Option<u32>,

    // ── Storage limits ────────────────────────────────────────────────
    /// Maximum total bytes of stored inner blobs
    pub storage_limit_bytes: u64,
    /// Maximum bytes transferred to a peer in a single sync session
    pub transfer_limit_bytes: Option<u64>,
    /// Maximum bytes transferred to a peer across all sessions per period
    pub sync_limit_bytes: Option<u64>,

    // ── Peering ───────────────────────────────────────────────────────
    /// Explicitly configured peer destination hashes (16-byte truncated)
    pub static_peers: Vec<Vec<u8>>,
    /// When true, only accept blobs from static peers
    pub from_static_only: bool,

    // ── Backup node peering ───────────────────────────────────────────
    /// Destination hashes of nodes trusted as subscriber backup nodes.
    /// Referenced by `TierPolicy::trusted_backup_only`.
    pub trusted_backup_peers: Vec<Vec<u8>>,
    /// Designated primary backup node for THIS node's subscribers.
    /// First-choice target for subscription pushes.
    pub primary_node: Option<Vec<u8>>,
    /// Ordered fallback list of secondary backup nodes.  If the primary is
    /// unreachable, the first alive secondary is used.  After all designated
    /// nodes are exhausted, auto-selection picks the best alive peer.
    /// Only ONE node receives pushes at a time; the active backup re-pushes
    /// to ITS own backup on failover (chain of custody).
    pub secondary_nodes: Vec<Vec<u8>>,

    /// Seconds since the last rfed.node announce before a backup node
    /// considers the primary offline and starts delivering. Default: 90.
    pub owner_offline_secs: f64,

    // ── LXMF propagation ─────────────────────────────────────────────
    /// When true, rfed runs a full `lxmf.propagation` node: stores LXMF
    /// messages, peers with other propagation nodes, and fires notify
    /// wake-ups for registered destinations.
    pub lxmf_propagation_enabled: bool,
    /// When true, automatically peer with discovered propagation nodes.
    /// When false, only static propagation peers are used.
    pub lxmf_propagation_autopeer: bool,
    /// Explicit propagation peer hashes (16-byte truncated destination hashes).
    pub lxmf_propagation_peers: Vec<Vec<u8>>,

}

impl NodeConfig {
    /// Returns the delivery policy for `subscriber_hash`.
    ///
    /// VIP match is O(n) on the VIP list; in practice this list is small.
    pub fn policy_for(&self, subscriber_hash: &[u8]) -> &TierPolicy {
        if self.vip_subscribers.iter().any(|h| h.as_slice() == subscriber_hash) {
            &self.vip_policy
        } else {
            &self.default_policy
        }
    }

    pub fn blob_store_dir(&self) -> PathBuf {
        self.config_dir.join("blobs")
    }
    pub fn subscription_file(&self) -> PathBuf {
        self.config_dir.join("subscriptions.rmp")
    }
    pub fn notify_registry_file(&self) -> PathBuf {
        self.config_dir.join("notify_registrations.rmp")
    }
    pub fn deferred_queue_file(&self) -> PathBuf {
        self.config_dir.join("deferred_delivery.rmp")
    }
    pub fn distro_file(&self) -> PathBuf {
        self.config_dir.join("distro.rmp")
    }
    pub fn distro_announce_file(&self) -> PathBuf {
        self.config_dir.join("distro_announces.rmp")
    }
    pub fn peer_state_file(&self) -> PathBuf {
        self.config_dir.join("peers.rmp")
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────
//
// Stamp-cost retrieval tests.  The contract these tests guard is the
// "ANTI-SPAM POW STAMPS — DO NOT BREAK THIS AGAIN" block above:
//
//   * Default tier MUST advertise a non-zero `stamp_cost` and non-zero
//     `stamp_flexibility` so SUBSCRIBE responses tell clients the right
//     PoW target and SEND validation has the right floor.
//   * VIP tier MUST be a relaxation, not a tightening (lower cost, larger
//     queue) — bumping VIP cost above default would punish privileged users.
//   * `policy_for(vip_hash)` MUST return the VIP policy; everyone else falls
//     through to the default policy.
//   * `deferred_pull_batch_limit` defaults to None (server falls back to
//     `DEFAULT_PULL_PAGE_SIZE`).  Per-tier override is wired through
//     `policy_for(...).deferred_pull_batch_limit`.

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_config(default: TierPolicy, vip: TierPolicy, vips: Vec<Vec<u8>>) -> NodeConfig {
        NodeConfig {
            config_dir: PathBuf::from("/tmp/rfed_test_cfg"),
            rns_config_dir: None,
            identity_file: PathBuf::from("/tmp/rfed_test_cfg/identity"),
            display_name: "test".into(),
            announce_interval_secs: 600,
            announce_at_start: false,
            default_policy: default,
            vip_policy: vip,
            vip_subscribers: vips,
            peering_cost: None,
            storage_limit_bytes: 0,
            transfer_limit_bytes: None,
            sync_limit_bytes: None,
            static_peers: Vec::new(),
            from_static_only: false,
            trusted_backup_peers: Vec::new(),
            primary_node: None,
            secondary_nodes: Vec::new(),
            owner_offline_secs: 90.0,
            lxmf_propagation_enabled: false,
            lxmf_propagation_autopeer: false,
            lxmf_propagation_peers: Vec::new(),
        }
    }

    #[test]
    fn default_tier_advertises_nonzero_stamp_cost_and_flexibility() {
        let p = TierPolicy::default();
        let cost = p.stamp_cost.expect("default tier MUST set stamp_cost");
        assert!(cost > 0, "default stamp_cost must be > 0 (Some(0)==disabled foot-gun)");
        let flex = p.stamp_flexibility.expect("default tier MUST set stamp_flexibility");
        assert!(flex > 0, "default stamp_flexibility must be > 0 to tolerate stale clients");
        assert!(flex < cost, "flexibility must not exceed cost");
    }

    #[test]
    fn vip_tier_relaxes_default_tier() {
        let d = TierPolicy::default();
        let v = TierPolicy::vip_default();
        let dc = d.stamp_cost.unwrap();
        let vc = v.stamp_cost.unwrap();
        assert!(vc <= dc, "VIP stamp_cost must not exceed default ({vc} > {dc})");
        assert!(
            v.deferred_queue_limit >= d.deferred_queue_limit,
            "VIP deferred_queue_limit must not be smaller than default",
        );
    }

    #[test]
    fn deferred_pull_batch_limit_defaults_to_none() {
        // None means the server uses DEFAULT_PULL_PAGE_SIZE.  If a future
        // change sets a default here, update the destinations.rs constant
        // documentation in lockstep.
        assert!(TierPolicy::default().deferred_pull_batch_limit.is_none());
        assert!(TierPolicy::vip_default().deferred_pull_batch_limit.is_none());
    }

    #[test]
    fn policy_for_returns_vip_for_listed_hashes() {
        let vip_hash = vec![0xAAu8; 16];
        let other_hash = vec![0xBBu8; 16];
        let cfg = empty_config(
            TierPolicy::default(),
            TierPolicy::vip_default(),
            vec![vip_hash.clone()],
        );
        let vip_cost = cfg.policy_for(&vip_hash).stamp_cost.unwrap();
        let other_cost = cfg.policy_for(&other_hash).stamp_cost.unwrap();
        assert_eq!(vip_cost, TierPolicy::vip_default().stamp_cost.unwrap());
        assert_eq!(other_cost, TierPolicy::default().stamp_cost.unwrap());
        assert_ne!(vip_cost, other_cost, "VIP and default tiers must differ in this fixture");
    }

    #[test]
    fn policy_for_pull_batch_limit_override_is_honored() {
        // Simulate an operator setting a per-VIP page size override.
        let mut vip = TierPolicy::vip_default();
        vip.deferred_pull_batch_limit = Some(50);
        let vip_hash = vec![0x77u8; 16];
        let cfg = empty_config(TierPolicy::default(), vip, vec![vip_hash.clone()]);

        assert_eq!(
            cfg.policy_for(&vip_hash).deferred_pull_batch_limit,
            Some(50),
            "VIP override must be exposed via policy_for so destinations.rs picks it up",
        );
        assert_eq!(
            cfg.policy_for(&[0u8; 16]).deferred_pull_batch_limit,
            None,
            "non-VIP tier must continue returning None (uses DEFAULT_PULL_PAGE_SIZE)",
        );
    }
}

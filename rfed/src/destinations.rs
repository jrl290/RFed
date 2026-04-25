//! RNS destination setup and handler wiring for the Federation Node.
//!
//! Four inbound destinations are registered:
//!
//!   rfed.node      — Node announce + peer manifest/sync (OFFER, MESSAGE_GET)
//!                    Backup push, capabilities query
//!   rfed.delivery  — Client inbox pull (PULL request proves private key)
//!   rfed.channel   — Inbound inner blobs + subscription control
//!                    (SEND packet, SUBSCRIBE / UNSUBSCRIBE requests)
//!   rfed.notify    — Notify registration (REGISTER / UNREGISTER / CLEAR requests)
//!
//! # Wire format (CHANNEL MESSAGES ARE LXMF PACKAGES)
//!
//! Channel send/fanout packet payload:
//!     [ channel_id_hash(16) | inner_blob(*) ]
//!
//! * `channel_id_hash` is the channel **identity hash** — i.e. what
//!   subscribers register with `/rfed/subscribe`, what RFed routes on
//!   in `subscription_table`, and what the Retichat clients call
//!   `Channel.id`. RFed never inspects, decrypts or re-derives this.
//! * `inner_blob` is byte-identical to the EC-encrypted authentication
//!   payload `lxmf_rust::LXMessage::pack(PROPAGATED)` produces — the
//!   tail after the destination_hash:
//!     `EC_encrypted(source_hash || signature || msgpack_payload)`.
//!   Receivers reconstruct the canonical LXMF block by prepending the
//!   `lxmf.delivery` destination_hash for the channel identity (re-derived
//!   from the channel name) and feed that to
//!   `LXMessage::unpack_from_bytes(_, Some(PROPAGATED))`, which validates
//!   the Ed25519 signature against the cached source identity.
//! RFed treats `inner_blob` OPAQUELY — never decrypts, parses, or modifies it.
//!
//! # Delivery model
//!
//! The blob store (keyed by channel_hash) is used **only** for inter-node sync.
//! It is never queried by clients directly.
//!
//! Client delivery has two paths:
//!   1. **Live fanout** — subscriber is online, outer envelope sent immediately.
//!   2. **Deferred queue** — subscriber offline; inner blob held in the deferred
//!      queue (keyed by subscriber_hash).  Flushed on announce or on PULL.

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::Duration;

use reticulum_rust::destination::{Destination, DestinationType, ALLOW_ALL};
use reticulum_rust::identity::{self, Identity};
use reticulum_rust::link::{Link, LinkHandle, RequestReceipt, MODE_AES256_CBC, register_runtime_link_handle};
use reticulum_rust::lxstamper::LXStamper;
use reticulum_rust::transport::{AnnounceHandler, Transport};
use reticulum_rust::{hexrep, log, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};

use crate::announce;
use crate::blob_store::BlobStore;

/// Decode a msgpack binary value (bin8/bin16/bin32) to Vec<u8>.
/// rmp_serde::from_slice::<Vec<u8>> treats Vec<u8> as a msgpack array;
/// use this helper when the peer sends raw bytes encoded as msgpack bin.
fn decode_msgpack_bin(data: &[u8]) -> Vec<u8> {
    let mut cur = Cursor::new(data);
    match rmpv::decode::read_value(&mut cur) {
        Ok(rmpv::Value::Binary(b)) => b,
        _ => Vec::new(),
    }
}

/// Parse and verify a signed payload: msgpack fixarray-3 [bin/str value, bin(64) pubkey, bin(64) sig].
///
/// Returns `(value_bytes, subscriber_identity_hash)` on success, or an error string.
/// The subscriber hash is derived from the pubkey using `Identity::from_public_key` — identical
/// to how Reticulum derives it, so no separate identity-lookup is needed.
fn verify_signed_payload(data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut cur = Cursor::new(data);
    let top = rmpv::decode::read_value(&mut cur)
        .map_err(|e| format!("msgpack decode: {e}"))?;
    let arr = match top {
        rmpv::Value::Array(a) if a.len() == 3 => a,
        _ => return Err(format!("expected fixarray-3, got {:?}", top)),
    };

    let value: Vec<u8> = match &arr[0] {
        rmpv::Value::Binary(b) => b.clone(),
        rmpv::Value::String(s) => s.as_bytes().to_vec(),
        other => return Err(format!("payload[0] not bin/str: {:?}", other)),
    };
    let pubkey: Vec<u8> = match &arr[1] {
        rmpv::Value::Binary(b) => b.clone(),
        _ => return Err("payload[1] not bin (pubkey)".into()),
    };
    let sig: Vec<u8> = match &arr[2] {
        rmpv::Value::Binary(b) => b.clone(),
        _ => return Err("payload[2] not bin (sig)".into()),
    };

    if pubkey.len() != 64 { return Err(format!("pubkey len {} != 64", pubkey.len())); }
    if sig.len()    != 64 { return Err(format!("sig len {} != 64", sig.len())); }

    let id = Identity::from_public_key(&pubkey)
        .map_err(|e| format!("from_public_key: {e}"))?;
    if !id.validate(&sig, &value) {
        return Err("signature verification failed".into());
    }
    let subscriber_hash = id.hash.ok_or("identity has no hash after from_public_key")?;
    Ok((value, subscriber_hash))
}

use crate::config::NodeConfig;
use crate::deferred_queue::DeferredQueue;
use crate::fanout;
use crate::lxmf_propagation::LxmfPropagationNode;
use crate::notify::{dispatch_notify, HookRegistry, NotifyRegistry, validate_relay_hash};
use crate::subscription::SubscriptionTable;
use crate::sync::{FedSync, OFFER_PATH, MESSAGE_GET_PATH, BACKUP_PUSH_PATH};

// ── Request paths ────────────────────────────────────────────────────────────

/// Client proves ownership of a destination by signing; server drains and returns pending blobs.
pub const PULL_PATH: &str = "/rfed/pull";
/// Client subscribes to a channel.
pub const SUBSCRIBE_PATH: &str = "/rfed/subscribe";
/// Client unsubscribes from a channel.
pub const UNSUBSCRIBE_PATH: &str = "/rfed/unsubscribe";
/// Client registers a notify relay.
pub const NOTIFY_REGISTER_PATH: &str = "/rfed/notify/register";
/// Client deregisters a specific notify relay.
pub const NOTIFY_UNREGISTER_PATH: &str = "/rfed/notify/unregister";
/// Client clears all notify relay registrations.
pub const NOTIFY_CLEAR_PATH: &str = "/rfed/notify/clear";
/// Client queries node capabilities and enabled features.
pub const CAPABILITIES_PATH: &str = "/rfed/capabilities";

/// RNS app namespace for all rfed destinations.
pub const APP_NAME: &str = "rfed";

/// Delay before the first announce fires (seconds).  Matches lxmd convention.
const NODE_ANNOUNCE_DELAY: u64 = 2;

/// Number of workblock expansion rounds for rfed stamp PoW.
/// The actual anti-spam difficulty is controlled by `stamp_cost` (required leading
/// zero bits); these expansion rounds just bind the workblock to the blob hash.
const STAMP_EXPAND_ROUNDS: u32 = 16;

// ── FedNode ──────────────────────────────────────────────────────────────────

/// Central state for a running Federation Node.
///
/// Owns all four RNS inbound destinations, the blob store, subscription table,
/// deferred delivery queue, notify registry, and inter-node sync engine.
/// Wrapped in `Arc<Mutex<FedNode>>` and shared across all callback closures
/// via a `Weak` self-reference to avoid reference cycles.
pub struct FedNode {
    pub identity: Identity,
    pub config: NodeConfig,

    pub blob_store: Arc<Mutex<BlobStore>>,
    pub subscription_table: Arc<Mutex<SubscriptionTable>>,
    pub hook_registry: Arc<Mutex<HookRegistry>>,
    pub notify_registry: Arc<Mutex<NotifyRegistry>>,
    pub sync: Arc<Mutex<FedSync>>,
    pub deferred_queue: Arc<Mutex<DeferredQueue>>,

    /// Optional full `lxmf.propagation` node (None when disabled).
    pub lxmf_propagation: Option<Arc<Mutex<LxmfPropagationNode>>>,

    // Inbound RNS destinations
    pub node_dest: Destination,
    pub delivery_dest: Destination,
    pub channel_dest: Destination,
    pub notify_dest: Destination,

    /// Active outbound sync links keyed by peer destination hash.
    /// Pruned each tick_sync — dead links are removed so a new link can be
    /// opened on the next attempt.
    pub sync_links: HashMap<Vec<u8>, LinkHandle>,

    /// Pending (subscriber_hash, channel_hash) pairs awaiting backup delivery to
    /// the configured backup node.  Drained by `tick_backup_delivery`.
    pub pending_backup_pushes: Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>,

    /// Auto-selected backup node destination hash.  Set by `tick_backup_delivery`
    /// when no explicit primary/secondary nodes cover the need.
    /// Cleared when the selected peer stops being alive.
    pub selected_backups: Vec<Vec<u8>>,

    /// Weak self-reference so callbacks can reach FedNode without a cycle.
    pub(crate) self_handle: Option<Weak<Mutex<FedNode>>>,
}

impl FedNode {
    pub fn new(identity: Identity, config: NodeConfig) -> Result<Self, String> {
        // ── Ensure directories exist ─────────────────────────────────
        for dir in [config.blob_store_dir()] {
            if let Err(e) = std::fs::create_dir_all(&dir) {
                if !dir.is_dir() {
                    return Err(format!("Cannot create {:?}: {e}", dir));
                }
            }
        }

        // ── Subsystem initialisation ─────────────────────────────────
        let storage_limit = config.storage_limit_bytes;

        let blob_store = Arc::new(Mutex::new(BlobStore::open(
            config.blob_store_dir(),
            storage_limit,
        )));

        let subscription_table = Arc::new(Mutex::new(SubscriptionTable::load(
            config.subscription_file(),
        )));

        let hook_registry = Arc::new(Mutex::new(HookRegistry::new()));
        let notify_registry = Arc::new(Mutex::new(NotifyRegistry::load(
            config.notify_registry_file(),
        )));
        let deferred_queue = Arc::new(Mutex::new(DeferredQueue::load(
            config.deferred_queue_file(),
        )));

        let mut fed_sync = FedSync::new(
            Arc::clone(&blob_store),
            Arc::clone(&subscription_table),
        );
        fed_sync.from_static_only = config.from_static_only;
        fed_sync.static_peers = config.static_peers.clone();
        fed_sync.peer_state_file = Some(config.peer_state_file());
        if let Some(lim) = config.transfer_limit_bytes {
            fed_sync.transfer_limit_bytes = Some(lim as f64);
        }
        if let Some(lim) = config.sync_limit_bytes {
            fed_sync.sync_limit_bytes = Some(lim as f64);
        }
        let sync = Arc::new(Mutex::new(fed_sync));

        // ── RNS destinations ────────────────────────────────────────
        let node_dest = Destination::new_inbound(
            Some(identity.clone()),
            DestinationType::Single,
            APP_NAME.to_string(),
            vec!["node".to_string()],
        )?;

        let delivery_dest = Destination::new_inbound(
            Some(identity.clone()),
            DestinationType::Single,
            APP_NAME.to_string(),
            vec!["delivery".to_string()],
        )?;

        let channel_dest = Destination::new_inbound(
            Some(identity.clone()),
            DestinationType::Single,
            APP_NAME.to_string(),
            vec!["channel".to_string()],
        )?;

        let notify_dest = Destination::new_inbound(
            Some(identity.clone()),
            DestinationType::Single,
            APP_NAME.to_string(),
            vec!["notify".to_string()],
        )?;;

        if let Ok(mut s) = sync.lock() {
            s.set_local_node_hash(node_dest.hash.clone());
        }

        Ok(FedNode {
            identity,
            config,
            blob_store,
            subscription_table,
            hook_registry,
            notify_registry,
            sync,
            deferred_queue,
            lxmf_propagation: None,
            node_dest,
            delivery_dest,
            channel_dest,
            notify_dest,
            sync_links: HashMap::new(),
            pending_backup_pushes: Arc::new(Mutex::new(Vec::new())),
            selected_backups: Vec::new(),
            self_handle: None,
        })
    }

    /// Broadcast the rfed.node announce with current app_data.
    ///
    /// The announce is delayed by `NODE_ANNOUNCE_DELAY` seconds on a background
    /// thread to let interfaces settle.  Also announces the three service
    /// destinations (channel, delivery, notify) so clients can discover them.
    pub fn announce(&self) {
        let _app_data = announce::encode_node_announce(
            &self.config.display_name,
            self.config.default_policy.stamp_cost,
        );
        let weak = self.self_handle.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(NODE_ANNOUNCE_DELAY));
            // The actual announce is done from enable() where we hold the Arc.
            // This stub fires the delay then re-locks via the weak handle.
            if let Some(arc) = weak.as_ref().and_then(|w| w.upgrade()) {
                if let Ok(mut node) = arc.lock() {
                    let ad = announce::encode_node_announce(
                        &node.config.display_name,
                        node.config.default_policy.stamp_cost,
                    );
                    node.node_dest.set_default_app_data(Some(ad.clone()));
                    let _ = node.node_dest.announce(Some(&ad), false, None, None, true);
                    log(
                        format!("[rfed] announced node {}", hexrep(
                            &node.node_dest.hash
                        , false)),
                        LOG_NOTICE,
                        false,
                        false,
                    );
                    // Announce service destinations so clients can discover
                    // them via path requests without knowing the hash in advance.
                    let _ = node.channel_dest.announce(None, false, None, None, true);
                    let _ = node.delivery_dest.announce(None, false, None, None, true);
                    let _ = node.notify_dest.announce(None, false, None, None, true);
                }
            }
        });
    }

    /// Announce only the three lightweight service destinations (channel,
    /// delivery, notify) without the heavyweight rfed.node payload.
    ///
    /// Call on a short interval (e.g. every 15 minutes) to keep paths alive
    /// within the Reticulum path TTL (~1 hour).  Unlike `announce()`, this
    /// does NOT re-broadcast the node identity or subscription manifest.
    pub fn announce_services(&self) {
        let weak = self.self_handle.clone();
        thread::spawn(move || {
            if let Some(arc) = weak.as_ref().and_then(|w| w.upgrade()) {
                if let Ok(mut node) = arc.lock() {
                    let _ = node.channel_dest.announce(None, false, None, None, true);
                    let _ = node.delivery_dest.announce(None, false, None, None, true);
                    let _ = node.notify_dest.announce(None, false, None, None, true);
                    log("[rfed] service paths refreshed (channel/delivery/notify)",
                        LOG_NOTICE, false, false);
                }
            }
        });
    }

    /// Explicitly persist all in-memory state to disk.
    ///
    /// Called during graceful shutdown so that no pending mutations are lost.
    pub fn save_all(&self) {
        if let Ok(s) = self.sync.lock() {
            s.save_peers();
        }
        if let Ok(s) = self.subscription_table.lock() {
            let _ = s.save();
        }
        if let Ok(n) = self.notify_registry.lock() {
            let _ = n.save();
        }
        if let Ok(q) = self.deferred_queue.lock() {
            let _ = q.save();
        }
        log("[rfed] all state persisted to disk", LOG_NOTICE, false, false);
    }

    /// Called from the main event loop — drives pending peer sync sessions.
    ///
    /// For each peer that is due for a sync attempt, opens an outbound encrypted
    /// Link to their rfed.node destination.  The link_established callback then
    /// runs `run_sync_session()` which handles the OFFER → MESSAGE_GET flow.
    pub fn tick_sync(&mut self) {
        // Prune links that have closed since the last tick.
        // Retaining only live links prevents stale entries from blocking
        // new connection attempts.
        self.sync_links.retain(|_, link| link.is_alive());

        let due: Vec<Vec<u8>> = if let Ok(mut s) = self.sync.lock() {
            s.tick()
        } else {
            return;
        };

        for peer_hash in due {
            // Skip if we already have a live link to this peer.
            if self.sync_links.contains_key(&peer_hash) {
                continue;
            }

            // Ensure we have a path; if not, request one and try again shortly.
            // Do not penalise with sync_err/backoff — a missing path is a
            // transient routing condition, not a sync failure.
            if !Transport::has_path(&peer_hash) {
                Transport::request_path(&peer_hash, None, None, None, None);
                if let Ok(mut s) = self.sync.lock() {
                    // Reschedule for a short retry, not a full backoff cycle.
                    if let Some(p) = s.peers.get_mut(&peer_hash) {
                        p.next_sync_attempt = crate::sync::now_secs() + 5.0;
                    }
                }
                continue;
            }

            let identity = match Identity::recall(&peer_hash) {
                Some(id) => id,
                None => {
                    Transport::request_path(&peer_hash, None, None, None, None);
                    if let Ok(mut s) = self.sync.lock() {
                        if let Some(p) = s.peers.get_mut(&peer_hash) {
                            p.next_sync_attempt = crate::sync::now_secs() + 5.0;
                        }
                    }
                    continue;
                }
            };

            let dest = match Destination::new_outbound(
                Some(identity),
                DestinationType::Single,
                APP_NAME.to_string(),
                vec!["node".to_string()],
            ) {
                Ok(d) => d,
                Err(e) => {
                    log(format!("[sync] dest error for {}: {e}",
                        hexrep(&peer_hash, false)), LOG_WARNING, false, false);
                    continue;
                }
            };

            let link = match Link::new_outbound(dest, MODE_AES256_CBC) {
                Ok(l) => l,
                Err(e) => {
                    log(format!("[sync] link error for {}: {e}",
                        hexrep(&peer_hash, false)), LOG_WARNING, false, false);
                    continue;
                }
            };

            let handle = LinkHandle::spawn(link);
            let node_weak = self.self_handle.as_ref().cloned();
            let ph = peer_hash.clone();

            // link_established → start the OFFER → MESSAGE_GET session.
            // The callback receives the live LinkHandle `h` from the actor.
            let pw_est = node_weak.clone();
            let ph_est = ph.clone();
            handle.set_link_established_callback(Some(Arc::new(move |h: LinkHandle| {
                run_sync_session(h, ph_est.clone(), pw_est.clone());
            })));

            // link_closed → clean up the sync link entry so tick_sync knows
            // the link is dead and a new attempt may be scheduled.
            let pw_cls = node_weak.clone();
            let ph_cls = ph.clone();
            handle.set_link_closed_callback(Some(Arc::new(move |_: LinkHandle| {
                if let Some(arc) = pw_cls.as_ref().and_then(|w| w.upgrade()) {
                    if let Ok(mut node) = arc.lock() {
                        node.sync_links.remove(&ph_cls);
                    }
                }
            })));

            if let Err(e) = handle.initiate() {
                log(format!("[sync] link initiate failed for {}: {e}",
                    hexrep(&peer_hash, false)), LOG_WARNING, false, false);
                continue;
            }
            // Register AFTER initiate() so link_id is populated in the handle.
            register_runtime_link_handle(handle.clone());

            log(format!("[sync] link opening to {}", hexrep(&peer_hash, false)),
                LOG_DEBUG, false, false);

            if let Ok(mut s) = self.sync.lock() {
                s.sync_started(&peer_hash);
            }
            self.sync_links.insert(peer_hash, handle);
        }
    }

    /// Three backup-related tasks run every 30 seconds:
    ///
    /// 1. **Push own subscriptions**: drain `pending_backup_pushes` and
    ///    forward to ONE backup node (designated or auto-selected).
    /// 2. **Failover + chain-of-custody re-push**: scan backup entries WE hold;
    ///    when an owner's path has decayed, deliver blobs AND re-push those
    ///    entries to our backup so the chain extends.
    /// 3. **Prune**: remove stale backup entries whose upstream custodian
    ///    stopped refreshing them (owner recovered → chain unravels).
    pub fn tick_backup_delivery(&mut self) {
        // ── Helper: resolve a backup node from config or auto-select ───
        let resolve_backup = |selected: &mut Vec<Vec<u8>>,
                              sync: &Arc<Mutex<FedSync>>,
                              config: &NodeConfig|
            -> Option<Vec<u8>>
        {
            let is_alive = |h: &[u8]| -> bool {
                sync.lock().ok()
                    .map(|s| s.peers.get(h)
                        .map(|p| p.alive).unwrap_or(false))
                    .unwrap_or(false)
            };

            // Priority 1: primary_node if alive.
            if let Some(ref h) = config.primary_node {
                if is_alive(h) {
                    return Some(h.clone());
                }
            }
            // Priority 2: first alive secondary.
            if let Some(h) = config.secondary_nodes.iter().find(|h| is_alive(h)) {
                return Some(h.clone());
            }
            // Priority 3: primary even if not alive (will retry next tick).
            if let Some(ref h) = config.primary_node {
                return Some(h.clone());
            }
            // Priority 4: first secondary even if not alive.
            if let Some(h) = config.secondary_nodes.first() {
                return Some(h.clone());
            }
            // Priority 5: auto-select best alive peer.
            let still_alive = selected.first().map(|h| is_alive(h)).unwrap_or(false);
            if still_alive {
                return selected.first().cloned();
            }
            let best = sync.lock().ok().and_then(|s| {
                s.peers.values()
                    .filter(|p| p.alive)
                    .max_by(|a, b| {
                        a.last_heard.partial_cmp(&b.last_heard)
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .map(|p| p.destination_hash.clone())
            });
            match &best {
                Some(h) => {
                    log(
                        format!("[backup] auto-selected backup node {}",
                            hexrep(h, false)),
                        LOG_NOTICE, false, false,
                    );
                    *selected = vec![h.clone()];
                }
                None => {
                    if !selected.is_empty() {
                        log("[backup] no alive peers \u{2014} backup node deselected",
                            LOG_NOTICE, false, false);
                    }
                    selected.clear();
                }
            }
            best
        };

        let backup_hash = resolve_backup(
            &mut self.selected_backups, &self.sync, &self.config,
        );

        // ── Part 1: push OWN pending registrations ────────────────────
        let pending: Vec<(Vec<u8>, Vec<u8>)> = self
            .pending_backup_pushes
            .lock()
            .ok()
            .map(|mut q| q.drain(..).collect())
            .unwrap_or_default();
        if !pending.is_empty() {
            if let Some(ref hash) = backup_hash {
                push_subscriptions_to_backup(
                    hash.clone(),
                    pending,
                    self.self_handle.clone(),
                    self.identity.clone(),
                );
            } else {
                // No backup available — put them back for next tick.
                if let Ok(mut q) = self.pending_backup_pushes.lock() {
                    q.extend(pending);
                }
            }
        }

        // ── Part 2: prune stale backup entries (chain unravel) ────────
        // TTL must be at least 3× the backup push tick (90s) so that backup
        // subscriptions survive multiple tick cycles before being pruned.
        // owner_offline_secs * 2 can be < BACKUP_TICK_SECS (30s) when
        // owner_offline_secs is configured small (e.g. 12s → TTL=24s < 30s).
        let ttl = (self.config.owner_offline_secs * 2.0).max(90.0);
        if let Ok(mut table) = self.subscription_table.lock() {
            let pruned = table.prune_stale_backups(ttl);
            if pruned > 0 {
                log(
                    format!("[backup] pruned {pruned} stale backup entry(ies) (TTL {ttl:.0}s)"),
                    LOG_NOTICE, false, false,
                );
            }
        }

        // ── Part 3: failover delivery + chain-of-custody re-push ──────
        let adopted = backup_delivery_tick(
            Arc::clone(&self.subscription_table),
            Arc::clone(&self.blob_store),
            Arc::clone(&self.deferred_queue),
            Arc::clone(&self.notify_registry),
            &self.config,
            Arc::clone(&self.sync),
            self.config.owner_offline_secs,
        );

        // Re-push adopted entries so the chain extends.
        if !adopted.is_empty() {
            if let Some(ref hash) = backup_hash {
                log(
                    format!(
                        "[backup] re-pushing {} adopted entry(ies) to backup {}",
                        adopted.len(),
                        hexrep(hash, false),
                    ),
                    LOG_NOTICE, false, false,
                );
                push_subscriptions_to_backup(
                    hash.clone(),
                    adopted,
                    self.self_handle.clone(),
                    self.identity.clone(),
                );
            }
        }
    }
}

// ── Sync session (runs inside link_established callback) ────────────────────

/// Drive a single OFFER → MESSAGE_GET sync session over an established link.
///
/// Called from the `link_established` callback on a background thread.
///
/// Flow:
///   1. Send OFFER with our local manifest → receive peer's manifest.
///   2. Compute gap = peer's manifest − our locally held IDs.
///   3. If gap is non-empty, send MESSAGE_GET for those IDs → receive blobs.
///   4. Ingest blobs and tear the link down.
fn run_sync_session(
    link_handle: LinkHandle,
    peer_hash: Vec<u8>,
    node_weak: Option<Weak<Mutex<FedNode>>>,
) {
    // Build our local manifest — send only the IDs (no channel hashes needed
    // in the outgoing OFFER; the peer uses them just for filtering channels
    // it has subscribers for).
    let our_ids: Vec<Vec<u8>> = if let Some(arc) =
        node_weak.as_ref().and_then(|w| w.upgrade())
    {
        let sync_arc = arc.lock().ok().map(|n| Arc::clone(&n.sync));
        sync_arc.and_then(|s| s.lock().ok().map(|g| {
            g.local_manifest().into_iter().map(|(_, id)| id).collect()
        }))
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    let offer_payload = match rmp_serde::to_vec(&our_ids) {
        Ok(b) => b,
        Err(e) => {
            log(format!("[sync] offer encode error: {e}"), LOG_WARNING, false, false);
            return;
        }
    };

    let ph_ok = peer_hash.clone();
    let ph_fail = peer_hash.clone();
    let nw_ok = node_weak.clone();
    let nw_fail = node_weak.clone();
    let la_ok = link_handle.clone();
    let la_fail = link_handle.clone();

    // OFFER response callback: receives the peer's manifest, computes the
    // gap (IDs they have that we don't, filtered to our subscribed channels),
    // then issues a MESSAGE_GET for the missing blobs.
    let offer_response: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
        Arc::new(move |receipt| {
            let response = match receipt.response {
                Some(r) => {
                    r
                },
                None => {
                    teardown_sync(&la_ok, &nw_ok, &ph_ok, false);
                    return;
                }
            };

            // Peer manifest is (channel_hash, message_id) pairs — this lets
            // us filter to only channels we have local subscribers for.
            // The gap_from_peer() call acquires blob_store and subscription_table
            // locks exactly once each to avoid potential double-locking.
            let peer_pairs: Vec<(Vec<u8>, Vec<u8>)> = rmp_serde::from_slice(&response)
                .unwrap_or_default();

            // Compute gap: IDs peer has for our subscribed channels that we
            // don't already hold.  gap_from_peer acquires both inner locks
            // exactly once, avoiding a double-lock of subscription_table.
            let want_ids: Vec<Vec<u8>> = if let Some(arc) =
                nw_ok.as_ref().and_then(|w| w.upgrade())
            {
                let sync_arc = arc.lock().ok().map(|n| Arc::clone(&n.sync));
                sync_arc
                    .and_then(|s| s.lock().ok().map(|g| g.gap_from_peer(peer_pairs)))
                    .unwrap_or_default()
            } else {
                Vec::new()
            };

            if want_ids.is_empty() {
                log(format!("[sync] already up to date with {}",
                    hexrep(&ph_ok, false)), LOG_DEBUG, false, false);
                teardown_sync(&la_ok, &nw_ok, &ph_ok, true);
                return;
            }

            log(format!("[sync] requesting {} blob(s) from {}",
                want_ids.len(), hexrep(&ph_ok, false)), LOG_NOTICE, false, false);

            let get_payload = rmp_serde::to_vec(&want_ids).unwrap_or_default();

            let ph2 = ph_ok.clone();
            let nw2 = nw_ok.clone();
            let la2 = la_ok.clone();
            let la_fail2 = la_ok.clone();
            let ph_fail2 = ph_ok.clone();
            let nw_fail2 = nw_ok.clone();

            let get_response: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
                Arc::new(move |receipt| {
                    let data = receipt.response.unwrap_or_default();

                    // Ingest blobs into the store, then fanout each new one to
                    // local subscribers — same delivery path as a direct SEND packet.
                    // Missed subscribers (offline) are enqueued in the deferred queue
                    // and get a notify wake-up.
                    let ingested: Vec<(Vec<u8>, Vec<u8>)> = if let Some(arc) =
                        nw2.as_ref().and_then(|w| w.upgrade())
                    {
                        let sync_arc = arc.lock().ok().map(|n| Arc::clone(&n.sync));
                        sync_arc
                            .and_then(|s| s.lock().ok().map(|mut g| {
                                g.ingest_message_get_response(&ph2, &data)
                            }))
                            .unwrap_or_default()
                    } else { Vec::new() };

                    let count = ingested.len();

                    // Fanout each newly ingested blob to local subscribers.
                    if !ingested.is_empty() {
                        if let Some(arc) = nw2.as_ref().and_then(|w| w.upgrade()) {
                            if let Ok(guard) = arc.lock() {
                                let subs  = guard.subscription_table.lock().ok();
                                let hooks = guard.hook_registry.lock().ok();
                                if let (Some(subs), Some(hooks)) = (subs, hooks) {
                                    for (channel_hash, blob) in &ingested {
                                        let missed = fanout::fanout_blob(
                                            blob, channel_hash, &subs, &hooks,
                                        );
                                        if !missed.is_empty() {
                                            if let Ok(mut deferred) = guard.deferred_queue.lock() {
                                                for sub_hash in &missed {
                                                    let limit = guard.config
                                                        .policy_for(sub_hash)
                                                        .deferred_queue_limit;
                                                    deferred.enqueue(
                                                        sub_hash.clone(),
                                                        channel_hash.clone(),
                                                        blob.clone(),
                                                        limit,
                                                    );
                                                }
                                            }
                                            // Fire notify wake-ups for deferred subscribers.
                                            if let Ok(notify) = guard.notify_registry.lock() {
                                                for sub_hash in &missed {
                                                    for reg in notify.get_for_channel(sub_hash, Some(channel_hash)) {
                                                        dispatch_notify(reg, None, Some(channel_hash));
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    log(format!("[sync] ingested {count} blob(s) from {}",
                        hexrep(&ph2, false)), LOG_NOTICE, false, false);
                    teardown_sync(&la2, &nw2, &ph2, true);
                });

            let get_failed: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
                Arc::new(move |_| {
                    log(format!("[sync] MESSAGE_GET failed for {}",
                        hexrep(&ph_fail2, false)), LOG_WARNING, false, false);
                    teardown_sync(&la_fail2, &nw_fail2, &ph_fail2, false);
                });

            let _ = la_ok.request(
                crate::sync::MESSAGE_GET_PATH.to_string(),
                get_payload,
                Some(get_response),
                Some(get_failed),
                None,
            );
        });

    // OFFER failed callback
    let offer_failed: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
        Arc::new(move |_| {
            log(format!("[sync] OFFER failed for {}",
                hexrep(&ph_fail, false)), LOG_WARNING, false, false);
            teardown_sync(&la_fail, &nw_fail, &ph_fail, false);
        });

    if link_handle.request(
        crate::sync::OFFER_PATH.to_string(),
        offer_payload,
        Some(offer_response),
        Some(offer_failed),
        None,
    ).is_err() {
        log(format!("[sync] link gone for {} — tearing down",
            hexrep(&peer_hash, false)), LOG_WARNING, false, false);
        teardown_sync(&link_handle, &node_weak, &peer_hash, false);
    }
}

/// Tear down a sync link and record the outcome in FedSync.
fn teardown_sync(
    link: &LinkHandle,
    node_weak: &Option<Weak<Mutex<FedNode>>>,
    peer_hash: &[u8],
    success: bool,
) {
    link.teardown();
    if let Some(arc) = node_weak.as_ref().and_then(|w| w.upgrade()) {
        if let Ok(node) = arc.lock() {
            if let Ok(mut s) = node.sync.lock() {
                if success { s.sync_ok(peer_hash); } else { s.sync_err(peer_hash); }
                s.save_peers();
            }
        }
    }
}

// ── Backup delivery helpers ───────────────────────────────────────────────────

/// Open a link to a backup node and send a batch of backup subscription
/// registrations.  Fire-and-forget: if the path is unavailable, pairs are
/// re-enqueued for the next `tick_backup_delivery` attempt.
///
/// The pattern is:
///   1. Verify path/identity to backup node; re-enqueue pairs if missing.
///   2. Open encrypted Link; in link_established callback:
///      a. Identify ourselves (so backup knows the owner).
///      b. Send BACKUP_PUSH request with the subscription pairs.
///      c. Tear down the link on response (success or failure).
fn push_subscriptions_to_backup(
    backup_hash: Vec<u8>,
    pairs: Vec<(Vec<u8>, Vec<u8>)>,
    node_weak: Option<Weak<Mutex<FedNode>>>,
    our_identity: Identity,
) {
    if !Transport::has_path(&backup_hash) {
        Transport::request_path(&backup_hash, None, None, None, None);
        log("[backup] no path to backup node — will retry on next tick",
            LOG_DEBUG, false, false);
        if let Some(arc) = node_weak.as_ref().and_then(|w| w.upgrade()) {
            if let Ok(node) = arc.lock() {
                if let Ok(mut q) = node.pending_backup_pushes.lock() {
                    q.extend(pairs);
                }
            }
        }
        return;
    }

    let identity = match Identity::recall(&backup_hash) {
        Some(id) => {
            id
        },
        None => {
            Transport::request_path(&backup_hash, None, None, None, None);
            if let Some(arc) = node_weak.as_ref().and_then(|w| w.upgrade()) {
                if let Ok(node) = arc.lock() {
                    if let Ok(mut q) = node.pending_backup_pushes.lock() {
                        q.extend(pairs);
                    }
                }
            }
            return;
        }
    };

    let dest = match Destination::new_outbound(
        Some(identity),
        DestinationType::Single,
        APP_NAME.to_string(),
        vec!["node".to_string()],
    ) {
        Ok(d) => {
            d
        },
        Err(e) => {
            log(format!("[backup] dest error for backup node: {e}"),
                LOG_WARNING, false, false);
            return;
        }
    };

    let link = match Link::new_outbound(dest, MODE_AES256_CBC) {
        Ok(l) => {
            l
        },
        Err(e) => {
            log(format!("[backup] link error to backup node: {e}"),
                LOG_WARNING, false, false);
            return;
        }
    };

    let handle = LinkHandle::spawn(link);
    let payload = rmp_serde::to_vec(&pairs).unwrap_or_default();

    // The callback body uses the live LinkHandle `h` passed by the actor,
    // avoiding the old Arc<Mutex<Link>> pattern entirely.
    let payload_for_est = payload.clone();
    handle.set_link_established_callback(Some(Arc::new(move |h: LinkHandle| {
        // Identify first so the remote side knows our identity.
        let _ = h.identify(&our_identity);
        let pay = payload_for_est.clone();
        let h_ok  = h.clone();
        let h_err = h.clone();
        let ok_cb: Arc<dyn Fn(RequestReceipt) + Send + Sync> = Arc::new(move |_| {
            log("[backup] backup push accepted by peer", LOG_NOTICE, false, false);
            h_ok.teardown();
        });
        let err_cb: Arc<dyn Fn(RequestReceipt) + Send + Sync> = Arc::new(move |_| {
            log("[backup] backup push rejected by peer", LOG_WARNING, false, false);
            h_err.teardown();
        });
        let _result = h.request(
            BACKUP_PUSH_PATH.to_string(), pay, Some(ok_cb), Some(err_cb), None,
        );
    })));
    let _ = handle.initiate();
    // Register AFTER initiate() so link_id is populated in the handle.
    register_runtime_link_handle(handle);
}

/// Scan backup subscriptions held by this node.  For each owner node whose
/// path has decayed (not heard within `owner_offline_secs`), copy that owner's
/// subscribers' channel blobs into the deferred delivery queue so they flush
/// when the subscriber next comes online or PULLs.
///
/// Returns the list of `(subscriber_hash, channel_hash)` pairs that were
/// actually delivered ("adopted").  The caller re-pushes these to its own
/// backup node so the chain of custody extends further.
fn backup_delivery_tick(
    subscription_table: Arc<Mutex<crate::subscription::SubscriptionTable>>,
    blob_store: Arc<Mutex<crate::blob_store::BlobStore>>,
    deferred_queue: Arc<Mutex<crate::deferred_queue::DeferredQueue>>,
    notify_registry: Arc<Mutex<crate::notify::NotifyRegistry>>,
    config: &crate::config::NodeConfig,
    sync: Arc<Mutex<crate::sync::FedSync>>,
    owner_offline_secs: f64,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let entries = subscription_table
        .lock()
        .ok()
        .map(|s| s.backup_entries_for_tick())
        .unwrap_or_default();
    if entries.is_empty() {
        return Vec::new();
    }

    // Group by owner — one liveness check per owner node.
    // This avoids locking sync once per (sub, channel) pair.
    let mut by_owner: std::collections::HashMap<Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>> =
        std::collections::HashMap::new();
    for (sub_hash, ch_hash, owner_hash) in entries {
        by_owner.entry(owner_hash).or_default().push((sub_hash, ch_hash));
    }

    let mut adopted: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

    for (owner_hash, subs) in &by_owner {
        // Suppress delivery if the owner node was heard recently via sync peer state.
        let owner_recently_heard = sync.lock().ok()
            .and_then(|s| s.peers.get(owner_hash.as_slice())
                .map(|p| p.alive && (crate::sync::now_secs() - p.last_heard) < owner_offline_secs))
            .unwrap_or(false);
        if owner_recently_heard {
            continue;
        }

        log(
            format!(
                "[backup] owner {} offline \u{2014} checking {} backup subscriber(s)",
                hexrep(owner_hash, false),
                subs.len()
            ),
            LOG_NOTICE, false, false,
        );

        for (sub_hash, ch_hash) in subs {
            // Skip if we already have pending entries; they will flush on announce.
            let has_pending = deferred_queue.lock().ok()
                .map(|q| q.has_pending(sub_hash.as_slice()))
                .unwrap_or(false);
            if has_pending {
                adopted.push((sub_hash.clone(), ch_hash.clone()));
                continue;
            }

            // Collect all blobs for this channel in one lock acquisition.
            let blobs: Vec<(Vec<u8>, Vec<u8>)> = {
                let store_guard = blob_store.lock().ok();
                if let Some(s) = store_guard {
                    s.message_ids_for_channel(ch_hash.as_slice())
                        .into_iter()
                        .filter_map(|id| s.get(&id).map(|b| (ch_hash.clone(), b)))
                        .collect()
                } else {
                    Vec::new()
                }
            };

            if blobs.is_empty() {
                continue;
            }

            let limit = config.policy_for(sub_hash.as_slice()).deferred_queue_limit;
            let mut enqueued = 0usize;
            if let Ok(mut q) = deferred_queue.lock() {
                for (ch, blob) in &blobs {
                    q.enqueue(sub_hash.clone(), ch.clone(), blob.clone(), limit);
                    enqueued += 1;
                }
            }
            if enqueued > 0 {
                log(
                    format!(
                        "[backup] queued {enqueued} blob(s) for subscriber {} (owner offline)",
                        hexrep(sub_hash, false)
                    ),
                    LOG_NOTICE, false, false,
                );
                adopted.push((sub_hash.clone(), ch_hash.clone()));
                if let Ok(notify) = notify_registry.lock() {
                    for reg in notify.get_for_channel(sub_hash.as_slice(), Some(ch_hash.as_slice())) {
                        dispatch_notify(reg, None, Some(ch_hash.as_slice()));
                    }
                }
            }
        }
    }
    adopted
}

// ── enable() ────────────────────────────────────────────────────────────────

/// Register all four destinations with Reticulum Transport and wire up
/// packet callbacks + request handlers.  Must be called once after
/// `FedNode::new`.
///
/// Initialization order:
///   1. Inject weak self-reference into `FedNode` for callback use.
///   2. Wire all four destinations (node, channel, delivery, notify).
///   3. Load persisted sync peers and request paths.
///   4. Print destination hashes for operator convenience.
///   5. Register announce handlers:
///      - `rfed.node`     → detect/update sync peers.
///      - `rfed.delivery` → flush deferred blobs when subscriber comes online.
pub fn enable(node: Arc<Mutex<FedNode>>) -> Result<(), String> {
    // Inject weak self-reference so callbacks can lock FedNode.
    {
        let mut guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
        guard.self_handle = Some(Arc::downgrade(&node));
    }

    wire_node_destination(&node)?;
    wire_channel_destination(&node)?;
    wire_delivery_destination(&node)?;
    wire_notify_destination(&node)?;

    // Load persisted peer state and seed static peers, then request paths
    // for all known/static peers so Reticulum starts routing to them.
    let startup_peer_hashes: Vec<Vec<u8>> = {
        let sync_arc = {
            let guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
            Arc::clone(&guard.sync)
        };
        sync_arc.lock().ok().map(|mut s| {
            s.load_peers();
            s.seed_static_peers();
            s.peers.keys().cloned().collect::<Vec<_>>()
        }).unwrap_or_default()
    };
    for hash in &startup_peer_hashes {
        Transport::request_path(hash, None, None, None, None);
    }

    // Print destination hashes for operator convenience.
    {
        let guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
        for (label, dest) in [
            ("node",     &guard.node_dest),
            ("delivery", &guard.delivery_dest),
            ("channel",  &guard.channel_dest),
            ("notify",   &guard.notify_dest),
        ] {
            log(
                format!("[rfed] rfed.{} dest hash: {}", label, hexrep(&dest.hash, false)),
                LOG_NOTICE,
                false,
                false,
            );
        }
    }

    // Register rfed.node announce handler so we detect peers.
    let node_weak = Arc::downgrade(&node);
    Transport::register_announce_handler(AnnounceHandler {
        aspect_filter: Some(format!("{APP_NAME}.node")),
        receive_path_responses: false,
        callback: Arc::new(move |dest_hash, _identity, app_data, _ann_hash, _is_path| {
            let ann = announce::decode_node_announce(app_data);
            let peering_cost = ann.as_ref().and_then(|a| a.stamp_cost);
            if let Some(arc) = node_weak.upgrade() {
                if let Ok(guard) = arc.lock() {
                    // Never sync with ourselves — skip our own announce.
                    if dest_hash == guard.node_dest.hash.as_slice() {
                        return;
                    }
                    if let Ok(mut s) = guard.sync.lock() { s.peer_heard(dest_hash.to_vec(), peering_cost); }
                }
            }
        }),
    });

    // Register rfed.delivery announce handler — flush deferred blobs when a
    // subscriber comes online.  Subscribers announce on their rfed.delivery
    // destination so we observe `APP_NAME.delivery` aspects here.
    //
    // Flow: announce heard → check deferred queue → drain → build outbound
    //   single dest for this subscriber → send each blob as a DATA packet.
    //   If dest build fails, re-enqueue for retry on next announce.
    let delivery_weak = Arc::downgrade(&node);
    Transport::register_announce_handler(AnnounceHandler {
        aspect_filter: Some(format!("{APP_NAME}.delivery")),
        receive_path_responses: false,
        callback: Arc::new(move |dest_hash, identity, _app_data, _ann_hash, _is_path| {
            // The deferred queue is keyed by IDENTITY HASH (not the delivery
            // destination hash).  The identity hash is truncated_hash(pub_key).
            let sub_id_hash: Vec<u8> = match identity.hash.as_ref() {
                Some(h) => h.clone(),
                None => return,
            };

            let arc = match delivery_weak.upgrade() {
                Some(a) => a,
                None => return,
            };
            let guard = match arc.lock() {
                Ok(g) => g,
                Err(_) => return,
            };

            // Fast-path: skip the lock chain if nothing is queued.
            let has_pending = guard
                .deferred_queue
                .lock()
                .ok()
                .map(|q| q.has_pending(&sub_id_hash))
                .unwrap_or(false);
            if !has_pending {
                return;
            }

            // Drain the queue for this subscriber (keyed by identity hash).
            let pending = guard
                .deferred_queue
                .lock()
                .ok()
                .map(|mut q| q.drain(&sub_id_hash))
                .unwrap_or_default();

            if pending.is_empty() {
                return;
            }

            log(
                format!(
                    "[deferred] subscriber {} (delivery {}) back online — flushing {} blob(s)",
                    hexrep(&sub_id_hash, false),
                    hexrep(dest_hash, false),
                    pending.len()
                ),
                LOG_NOTICE,
                false,
                false,
            );

            // Build the outbound delivery destination using the now-known identity.
            let dest_result = reticulum_rust::destination::Destination::new_outbound(
                Some(identity.clone()),
                reticulum_rust::destination::DestinationType::Single,
                APP_NAME.to_string(),
                vec!["delivery".to_string()],
            );
            let dest = match dest_result {
                Ok(d) => d,
                Err(e) => {
                    log(
                        format!("[deferred] failed to build dest for {}: {e}",
                            hexrep(&sub_id_hash, false)),
                        LOG_WARNING,
                        false,
                        false,
                    );
                    // Re-enqueue everything — we'll try again on next announce.
                    if let Ok(mut q) = guard.deferred_queue.lock() {
                        let limit = guard.config.policy_for(&sub_id_hash).deferred_queue_limit;
                        for pb in pending {
                            q.enqueue(sub_id_hash.clone(), pb.channel_hash, pb.blob, limit);
                        }
                    }
                    return;
                }
            };

            let hooks = guard.hook_registry.lock().ok();
            for pb in &pending {
                // Delivery packet payload: channel_hash(16) | inner_blob
                // Matches the format expected by the subscriber's onRfedBlob handler.
                let mut payload = pb.channel_hash.clone();
                payload.extend_from_slice(&pb.blob);
                let mut packet = reticulum_rust::packet::Packet::new(
                    Some(dest.clone()),
                    payload,
                    reticulum_rust::packet::DATA,
                    reticulum_rust::packet::NONE,
                    reticulum_rust::transport::BROADCAST,
                    reticulum_rust::packet::HEADER_1,
                    None,
                    None,
                    false,
                    reticulum_rust::packet::FLAG_UNSET,
                );
                if let Err(e) = packet.send() {
                    log(
                        format!("[deferred] send to {} failed: {e}",
                            hexrep(&sub_id_hash, false)),
                        LOG_WARNING,
                        false,
                        false,
                    );
                }
                if let Some(ref hooks) = hooks {
                    hooks.on_deliver(&sub_id_hash, &pb.blob);
                }
            }
        }),
    });

    Ok(())
}

// ── rfed.node ────────────────────────────────────────────────────────────────

fn wire_node_destination(node: &Arc<Mutex<FedNode>>) -> Result<(), String> {
    // OFFER — peer sends its manifest (IDs it has); we return our manifest
    //         so the caller can compute the gap and pull via MESSAGE_GET.
    let sync_offer = {
        let n = Arc::clone(node);
        Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                       _caller: Option<&Identity>, _timeout: f64| -> Vec<u8> {
            let offered: Vec<Vec<u8>> = rmp_serde::from_slice(data).unwrap_or_default();
            if let Ok(s) = n.lock().map(|g| Arc::clone(&g.sync)) {
                if let Ok(sync) = s.lock() {
                    // handle_offer accepts offered_ids (future: rate limiting)
                    // and returns our own manifest.
                    let manifest = sync.handle_offer(offered);
                    return rmp_serde::to_vec(&manifest).unwrap_or_default();
                }
            }
            Vec::new()
        })
    };

    // MESSAGE_GET — peer requests specific blobs by ID.
    let sync_get = {
        let n = Arc::clone(node);
        Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                       _caller: Option<&Identity>, _timeout: f64| -> Vec<u8> {
            let ids: Vec<Vec<u8>> = rmp_serde::from_slice(data).unwrap_or_default();
            if let Ok(s) = n.lock().map(|g| Arc::clone(&g.sync)) {
                if let Ok(mut sync) = s.lock() {
                    return sync.handle_message_get(&ids);
                }
            }
            Vec::new()
        })
    };

    // BACKUP_PUSH — owner node registers backup subscriptions on this node.
    // The caller's identity is used to derive their rfed.node destination hash
    // (unforgeable — computed from their actual public key material).
    // This prevents spoofed owner_hash values; only the real key holder can
    // produce the matching link authentication.
    let backup_push_node = Arc::clone(node);
    let backup_push_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                        caller: Option<&Identity>, _timeout: f64| -> Vec<u8> {
        let owner_hash = match caller {
            Some(id) => match Destination::new_outbound(
                Some(id.clone()),
                DestinationType::Single,
                APP_NAME.to_string(),
                vec!["node".to_string()],
            ) {
                Ok(d) => d.hash,
                Err(_) => return rmp_serde::to_vec(&false).unwrap_or_default(),
            },
            None => return rmp_serde::to_vec(&false).unwrap_or_default(),
        };

        let pairs: Vec<(Vec<u8>, Vec<u8>)> = rmp_serde::from_slice(data).unwrap_or_default();

        let guard = match backup_push_node.lock() {
            Ok(g) => g,
            Err(_) => return rmp_serde::to_vec(&false).unwrap_or_default(),
        };

        // If trusted_backup_peers is non-empty, only accept from listed nodes.
        let trusted = guard.config.trusted_backup_peers.is_empty()
            || guard.config.trusted_backup_peers.iter().any(|h| h == &owner_hash);
        if !trusted {
            log(
                format!("[backup] rejected BACKUP_PUSH from untrusted owner {}",
                    hexrep(&owner_hash, false)),
                LOG_WARNING, false, false,
            );
            return rmp_serde::to_vec(&false).unwrap_or_default();
        }

        if let Ok(mut subs) = guard.subscription_table.lock() {
            for (sub_hash, ch_hash) in &pairs {
                subs.subscribe_backup(sub_hash.clone(), ch_hash.clone(), owner_hash.clone());
            }
        }
        log(
            format!("[backup] registered {} backup sub(s) from owner {}",
                pairs.len(), hexrep(&owner_hash, false)),
            LOG_NOTICE, false, false,
        );
        rmp_serde::to_vec(&true).unwrap_or_default()
    });

    // CAPABILITIES — public query returning node features and config surface.
    // Response is a msgpack map that can be extended over time without
    // breaking older clients (unknown keys are simply ignored).
    let caps_node = Arc::clone(node);
    let capabilities_cb = Arc::new(move |_path: &str, _data: &[u8], _req_id: &[u8],
                                         _caller: Option<&Identity>, _timeout: f64| -> Vec<u8> {
        let guard = match caps_node.lock() {
            Ok(g) => g,
            Err(_) => return Vec::new(),
        };
        let cfg = &guard.config;

        let mut caps: Vec<(rmpv::Value, rmpv::Value)> = Vec::new();

        // Protocol version — bump when wire formats change.
        caps.push((
            rmpv::Value::String("protocol_version".into()),
            rmpv::Value::Integer(1.into()),
        ));

        // Node display name.
        caps.push((
            rmpv::Value::String("display_name".into()),
            rmpv::Value::String(cfg.display_name.clone().into()),
        ));

        // Feature flags — reflects what this node has enabled.
        caps.push((
            rmpv::Value::String("subscription".into()),
            rmpv::Value::Boolean(cfg.default_policy.allow_subscription),
        ));
        caps.push((
            rmpv::Value::String("notify".into()),
            rmpv::Value::Boolean(cfg.default_policy.allow_notify_registration),
        ));
        caps.push((
            rmpv::Value::String("lxmf_propagation".into()),
            rmpv::Value::Boolean(cfg.lxmf_propagation_enabled),
        ));
        caps.push((
            rmpv::Value::String("backup".into()),
            rmpv::Value::Boolean(cfg.primary_node.is_some() || !cfg.secondary_nodes.is_empty()),
        ));

        // Anti-spam parameters.
        caps.push((
            rmpv::Value::String("stamp_cost".into()),
            match cfg.default_policy.stamp_cost {
                Some(c) => rmpv::Value::Integer(c.into()),
                None    => rmpv::Value::Nil,
            },
        ));

        let mut buf = Vec::new();
        if rmpv::encode::write_value(&mut buf, &rmpv::Value::Map(caps)).is_ok() {
            buf
        } else {
            Vec::new()
        }
    });

    let mut guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
    guard.node_dest.register_request_handler(
        OFFER_PATH.to_string(), Some(sync_offer), ALLOW_ALL, None, false,
    )?;
    guard.node_dest.register_request_handler(
        MESSAGE_GET_PATH.to_string(), Some(sync_get), ALLOW_ALL, None, false,
    )?;
    guard.node_dest.register_request_handler(
        BACKUP_PUSH_PATH.to_string(), Some(backup_push_cb), ALLOW_ALL, None, false,
    )?;
    guard.node_dest.register_request_handler(
        CAPABILITIES_PATH.to_string(), Some(capabilities_cb), ALLOW_ALL, None, false,
    )?;
    Transport::register_destination(guard.node_dest.clone());
    Ok(())
}

// ── rfed.channel ─────────────────────────────────────────────────────────────

fn wire_channel_destination(node: &Arc<Mutex<FedNode>>) -> Result<(), String> {
    // Snapshot anti-spam knobs once — both are Copy so no lock required later.
    let (stamp_cost, stamp_flexibility) = {
        let guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
        (guard.config.default_policy.stamp_cost, guard.config.default_policy.stamp_flexibility)
    };

    // SEND — fire-and-forget packet; payload is the inner blob (± stamp).
    //
    // Wire format WITHOUT stamp (stamp_cost == None):
    //   channel_hash(16) | inner_blob(*)
    //
    // Wire format WITH stamp (stamp_cost is Some):
    //   channel_hash(16) | inner_blob(*) | stamp(LXStamper::STAMP_SIZE)
    //
    // When a stamp is required the node validates PoW before accepting the blob.
    // The stamp is stripped before storage so peers receive clean blobs.
    let send_node = Arc::clone(node);
    let packet_cb = Arc::new(move |data: &[u8], _packet: &reticulum_rust::packet::Packet| {
        if data.len() < 17 {
            log("[channel] malformed SEND packet (too short)", LOG_WARNING, false, false);
            return;
        }

        // ── Stamp validation (when configured) ───────────────────────
        let (channel_hash, inner_blob): (&[u8], &[u8]) = if let Some(cost) = stamp_cost {
            // Must have at least 16 (channel) + 1 (blob) + STAMP_SIZE bytes.
            let min_len = 16 + LXStamper::STAMP_SIZE + 1;
            if data.len() < min_len {
                log("[channel] SEND rejected: too short to contain stamp",
                    LOG_WARNING, false, false);
                return;
            }
            let stamp_start = data.len() - LXStamper::STAMP_SIZE;
            let stamp    = &data[stamp_start..];
            let material = &data[..stamp_start]; // channel_hash || inner_blob

            // transient_id binds the stamp to this exact blob+channel pair.
            let transient_id = identity::full_hash(material);
            let workblock    = LXStamper::stamp_workblock(&transient_id, STAMP_EXPAND_ROUNDS);

            // Allow downward flexibility so stamps generated against a slightly
            // older/different cost announcement are still accepted.
            let min_cost = cost.saturating_sub(stamp_flexibility.unwrap_or(0));
            if !LXStamper::stamp_valid(stamp, min_cost, &workblock) {
                log("[channel] SEND rejected: stamp does not meet required cost",
                    LOG_WARNING, false, false);
                return;
            }
            log(format!("[channel] stamp accepted (cost>={min_cost})"),
                LOG_DEBUG, false, false);

            (&data[..16], &data[16..stamp_start])
        } else {
            (&data[..16], &data[16..])
        };

        // Store the blob.
        let msg_id_opt = send_node.lock().ok().and_then(|guard| {
            guard.blob_store.lock().ok().and_then(|mut store| {
                store.store(channel_hash, inner_blob).ok()
            })
        });

        if let Some(_msg_id) = msg_id_opt {
            // Fanout to subscribers.
            if let Ok(guard) = send_node.lock() {
                let subs  = guard.subscription_table.lock().ok();
                let hooks = guard.hook_registry.lock().ok();
                if let (Some(subs), Some(hooks)) = (subs, hooks) {
                    log(
                        format!("[CHANNEL-RX] channel={} blob_bytes={} → fanning out to {} subscriber(s)",
                            hexrep(channel_hash, false),
                            inner_blob.len(),
                            subs.get_subscribers_with_owner(channel_hash).len(),
                        ),
                        LOG_NOTICE, false, false,
                    );
                    let missed = fanout::fanout_blob(inner_blob, channel_hash, &subs, &hooks);
                    if !missed.is_empty() {
                        if let Ok(mut deferred) = guard.deferred_queue.lock() {
                            for sub_hash in &missed {
                                let limit = guard.config.policy_for(sub_hash)
                                    .deferred_queue_limit;
                                deferred.enqueue(
                                    sub_hash.clone(),
                                    channel_hash.to_vec(),
                                    inner_blob.to_vec(),
                                    limit,
                                );
                            }
                        }
                        // Fire notify wake-ups for deferred subscribers.
                        if let Ok(notify) = guard.notify_registry.lock() {
                            for sub_hash in &missed {
                                for reg in notify.get_for_channel(sub_hash, Some(channel_hash)) {
                                    dispatch_notify(reg, None, Some(channel_hash));
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // SUBSCRIBE — client registers (subscriber_hash, channel_hash).
    let sub_node = Arc::clone(node);
    let subscribe_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                      _caller: Option<&Identity>, _timeout: f64| -> Vec<u8> {
        // Payload: fixarray-3 [bin(16) channel_hash, bin(64) pubkey, bin(64) sig].
        // Subscriber identity is derived from pubkey; sig proves key ownership.
        let (channel_hash, subscriber_hash) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(e) => {
                log(format!("[rfed] subscribe_cb: {e}"), LOG_WARNING, false, false);
                return rmp_serde::to_vec(&false).unwrap_or_default();
            }
        };

        if channel_hash.len() != 16 {
            log(format!("[rfed] subscribe_cb: bad channel_hash len={}", channel_hash.len()), LOG_WARNING, false, false);
            return rmp_serde::to_vec(&false).unwrap_or_default();
        }
        if let Ok(guard) = sub_node.lock() {
            if !guard.config.policy_for(&subscriber_hash).allow_subscription {
                log(
                    format!(
                        "[rfed] subscription denied for {} (policy)",
                        reticulum_rust::hexrep(&subscriber_hash, false),
                    ),
                    LOG_WARNING,
                    false,
                    false,
                );
                return rmp_serde::to_vec(&false).unwrap_or_default();
            }
            if let Ok(mut subs) = guard.subscription_table.lock() {
                subs.subscribe(subscriber_hash.clone(), channel_hash.clone());
            }
            // Queue for backup push.
            {
                if let Ok(mut q) = guard.pending_backup_pushes.lock() {
                    const PENDING_BACKUP_CAP: usize = 1024;
                    if q.len() < PENDING_BACKUP_CAP {
                        q.push((subscriber_hash, channel_hash));
                    }
                }
            }
            // Response: [true, stamp_cost_or_nil]
            // stamp_cost is None when disabled so client can skip PoW.
            let cost = guard.config.default_policy.stamp_cost;
            let resp = rmpv::Value::Array(vec![
                rmpv::Value::Boolean(true),
                match cost {
                    Some(c) => rmpv::Value::Integer(rmpv::Integer::from(c as i64)),
                    None    => rmpv::Value::Nil,
                },
            ]);
            let mut buf = Vec::new();
            rmpv::encode::write_value(&mut buf, &resp).unwrap_or_default();
            return buf;
        }
        rmp_serde::to_vec(&false).unwrap_or_default()
    });

    // UNSUBSCRIBE
    let unsub_node = Arc::clone(node);
    let unsubscribe_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                        _caller: Option<&Identity>, _timeout: f64| -> Vec<u8> {
        let (channel_hash, subscriber_hash) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(_) => return rmp_serde::to_vec(&false).unwrap_or_default(),
        };
        if let Ok(guard) = unsub_node.lock() {
            if let Ok(mut subs) = guard.subscription_table.lock() {
                subs.unsubscribe(&subscriber_hash, &channel_hash);
            }
        }
        rmp_serde::to_vec(&true).unwrap_or_default()
    });

    let mut guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
    guard.channel_dest.set_packet_callback(Some(packet_cb));
    guard.channel_dest.register_request_handler(
        SUBSCRIBE_PATH.to_string(), Some(subscribe_cb), ALLOW_ALL, None, false,
    )?;
    guard.channel_dest.register_request_handler(
        UNSUBSCRIBE_PATH.to_string(), Some(unsubscribe_cb), ALLOW_ALL, None, false,
    )?;
    Transport::register_destination(guard.channel_dest.clone());
    Ok(())
}

// ── rfed.delivery ────────────────────────────────────────────────────────────

fn wire_delivery_destination(node: &Arc<Mutex<FedNode>>) -> Result<(), String> {
    // PULL — client proves key ownership via the request's authenticated caller.
    //
    // The server drains the deferred queue for the caller and returns all
    // pending inner blobs as a msgpack list of [channel_hash, blob] pairs.
    //
    // Draining is atomic from the caller's perspective: the blobs are removed
    // on return.  If the client crashes before processing, the blobs will have
    // been delivered by live fanout to any other session, or will re-arrive via
    // a future sync from the origin node.
    //
    // Wire format (response): msgpack [[bin(16), bin], ...] — each sub-array
    // is [channel_hash, blob].  Uses rmpv so Python receives `bytes` objects.
    let pull_node = Arc::clone(node);
    let pull_cb = Arc::new(move |_path: &str, _data: &[u8], _req_id: &[u8],
                                  caller: Option<&Identity>, _timeout: f64| -> Vec<u8> {
        let subscriber_hash = match caller.and_then(|id| id.hash.clone()) {
            Some(h) => h,
            None => return Vec::new(),
        };
        if let Ok(guard) = pull_node.lock() {
            let batch_limit = guard.config.policy_for(&subscriber_hash).deferred_pull_batch_limit;
            if let Ok(mut deferred) = guard.deferred_queue.lock() {
                let pending = if let Some(limit) = batch_limit {
                    deferred.drain_batch(&subscriber_hash, limit)
                } else {
                    deferred.drain(&subscriber_hash)
                };
                // Build msgpack array-of-[bin(channel_hash), bin(blob)] pairs
                // using rmpv so Python receives proper bytes objects, not lists.
                let pairs_val: Vec<rmpv::Value> = pending
                    .into_iter()
                    .map(|pb| rmpv::Value::Array(vec![
                        rmpv::Value::Binary(pb.channel_hash),
                        rmpv::Value::Binary(pb.blob),
                    ]))
                    .collect();
                let mut buf = Vec::new();
                let _ = rmpv::encode::write_value(&mut buf, &rmpv::Value::Array(pairs_val));
                return buf;
            }
        }
        Vec::new()
    });

    let mut guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
    guard.delivery_dest.register_request_handler(
        PULL_PATH.to_string(), Some(pull_cb), ALLOW_ALL, None, false,
    )?;
    Transport::register_destination(guard.delivery_dest.clone());
    Ok(())
}

// ── rfed.notify ──────────────────────────────────────────────────────────────

fn wire_notify_destination(node: &Arc<Mutex<FedNode>>) -> Result<(), String> {
    // NOTIFY_REGISTER — client sends a 32-char hex relay destination hash.
    // Multiple calls with different hashes register additional relays for the
    // same subscriber; duplicate hashes refresh the timestamp only.
    //
    // Two entries are inserted per registration:
    //   1. subscriber_identity_hash → relay_hash  (for channel notify)
    //   2. lxmf.delivery_dest_hash  → relay_hash  (for LXMF propagation notify)
    // This dual-hash approach ensures the propagation handler (which only knows
    // the lxmf.delivery dest hash from message headers) can look up the relay.
    let reg_node = Arc::clone(node);
    let register_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                      _caller: Option<&Identity>, _timeout: f64| -> Vec<u8> {
        // Payload: fixarray-3 [str(relayHex), bin(64) pubkey, bin(64) sig].
        // Subscriber identity is derived from pubkey; sig proves key ownership.
        let (value_bytes, subscriber_hash) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(e) => {
                log(format!("[rfed] notify/register: {e}"), LOG_WARNING, false, false);
                return rmp_serde::to_vec(&false).unwrap_or_default();
            }
        };
        // value_bytes is msgpack [str(relay_hex), bin(16 channel_hash) | nil].
        // Fall back to treating the raw bytes as a UTF-8 relay hex string for
        // backward compatibility with pre-channel clients (channel = None).
        let (relay_hash, channel_hash_opt): (String, Option<Vec<u8>>) = {
            let mut cur = Cursor::new(&value_bytes[..]);
            match rmpv::decode::read_value(&mut cur) {
                Ok(rmpv::Value::Array(mut arr)) if arr.len() >= 2 => {
                    let relay = match arr.remove(0) {
                        rmpv::Value::String(s) => s.into_str().unwrap_or_default().to_string(),
                        _ => String::new(),
                    };
                    let ch = match arr.remove(0) {
                        rmpv::Value::Binary(b) if b.len() == 16 => Some(b),
                        _ => None,
                    };
                    (relay, ch)
                }
                _ => (String::from_utf8(value_bytes).unwrap_or_default(), None),
            }
        };
        if relay_hash.is_empty() {
            log("[rfed] notify/register: empty relay hash", LOG_WARNING, false, false);
            return rmp_serde::to_vec(&false).unwrap_or_default();
        }

        if let Err(reason) = validate_relay_hash(&relay_hash) {
            log(
                format!("[rfed] notify registration rejected: {reason}"),
                LOG_WARNING,
                false,
                false,
            );
            return rmp_serde::to_vec(&false).unwrap_or_default();
        }

        if let Ok(guard) = reg_node.lock() {
            // Enforce per-tier notify registration policy.
            if !guard.config.policy_for(&subscriber_hash).allow_notify_registration {
                log(
                    format!(
                        "[rfed] notify registration denied for {} (policy)",
                        reticulum_rust::hexrep(&subscriber_hash, false),
                    ),
                    LOG_WARNING,
                    false,
                    false,
                );
                return rmp_serde::to_vec(&false).unwrap_or_default();
            }
            if let Ok(mut notify) = guard.notify_registry.lock() {
                if let Some(ref ch) = channel_hash_opt {
                    // Per-channel registration: key = (subscriber_hash, channel_hash).
                    notify.register(subscriber_hash.clone(), Some(ch.clone()), relay_hash);
                } else {
                    // LXMF registration: key = (lxmf.delivery dest hash, None).
                    let lxmf_delivery_hash = Destination::hash(
                        Some(&subscriber_hash), "lxmf", &["delivery"],
                    );
                    notify.register(lxmf_delivery_hash, None, relay_hash);
                }
            }
        }
        rmp_serde::to_vec(&true).unwrap_or_default()
    });

    // NOTIFY_UNREGISTER — remove a specific relay hash for the caller.
    // Payload: msgpack [str(relay_hex), bin(16 channel_hash) | nil], same as REGISTER.
    let unreg_node = Arc::clone(node);
    let unregister_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                        _caller: Option<&Identity>, _timeout: f64| -> Vec<u8> {
        let (value_bytes, subscriber_hash) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(_) => return rmp_serde::to_vec(&false).unwrap_or_default(),
        };
        let (relay_hash, channel_hash_opt): (String, Option<Vec<u8>>) = {
            let mut cur = Cursor::new(&value_bytes[..]);
            match rmpv::decode::read_value(&mut cur) {
                Ok(rmpv::Value::Array(mut arr)) if arr.len() >= 2 => {
                    let relay = match arr.remove(0) {
                        rmpv::Value::String(s) => s.into_str().unwrap_or_default().to_string(),
                        _ => String::new(),
                    };
                    let ch = match arr.remove(0) {
                        rmpv::Value::Binary(b) if b.len() == 16 => Some(b),
                        _ => None,
                    };
                    (relay, ch)
                }
                _ => (String::from_utf8(value_bytes).unwrap_or_default(), None),
            }
        };
        if relay_hash.is_empty() {
            return rmp_serde::to_vec(&false).unwrap_or_default();
        }
        if let Ok(guard) = unreg_node.lock() {
            if let Ok(mut notify) = guard.notify_registry.lock() {
                if let Some(ref ch) = channel_hash_opt {
                    notify.unregister(&subscriber_hash, Some(ch.as_slice()), &relay_hash);
                } else {
                    let lxmf_delivery_hash = Destination::hash(
                        Some(&subscriber_hash), "lxmf", &["delivery"],
                    );
                    notify.unregister(&lxmf_delivery_hash, None, &relay_hash);
                }
            }
        }
        rmp_serde::to_vec(&true).unwrap_or_default()
    });

    // NOTIFY_CLEAR — remove ALL relay registrations for the caller.
    // No payload required.
    let clear_node = Arc::clone(node);
    let clear_cb = Arc::new(move |_path: &str, data: &[u8], _req_id: &[u8],
                                    _caller: Option<&Identity>, _timeout: f64| -> Vec<u8> {
        // For clear, payload is fixarray-3 [str(""), bin(64) pubkey, bin(64) sig_over_empty].
        // We only need the subscriber hash from the verified pubkey.
        let (_value, subscriber_hash) = match verify_signed_payload(data) {
            Ok(v) => v,
            Err(_) => return rmp_serde::to_vec(&false).unwrap_or_default(),
        };
        if let Ok(guard) = clear_node.lock() {
            if let Ok(mut notify) = guard.notify_registry.lock() {
                notify.clear(&subscriber_hash);
            }
        }
        rmp_serde::to_vec(&true).unwrap_or_default()
    });

    let mut guard = node.lock().map_err(|_| "FedNode lock poisoned")?;
    guard.notify_dest.register_request_handler(
        NOTIFY_REGISTER_PATH.to_string(), Some(register_cb), ALLOW_ALL, None, false,
    )?;
    guard.notify_dest.register_request_handler(
        NOTIFY_UNREGISTER_PATH.to_string(), Some(unregister_cb), ALLOW_ALL, None, false,
    )?;
    guard.notify_dest.register_request_handler(
        NOTIFY_CLEAR_PATH.to_string(), Some(clear_cb), ALLOW_ALL, None, false,
    )?;
    Transport::register_destination(guard.notify_dest.clone());
    Ok(())
}

#[cfg(test)]
mod hash_tests {
    //! Pin the on-the-wire destination hashes for `rfed.{node,delivery,channel,notify}`.
    //!
    //! These hashes are part of the protocol: every client computes them from
    //! the server identity hash to pick the right inbox. If `Destination::hash`,
    //! `APP_NAME`, or any aspect string ever changes, this test must fail loudly
    //! before a new build ships.
    //!
    //! The expected values were independently derived from the canonical formula:
    //!     name_hash = sha256("rfed.<aspect>")[..10]
    //!     dest_hash = sha256(name_hash || identity_hash)[..16]
    //! using identity hash `c287b844b2b6f8d6013b0a962eb2107b`.
    //!
    //! The test also guards against accidental collision with the well-known
    //! `rnstransport.path.request` control hash, which is what tripped us up
    //! during a long debugging session.

    use super::APP_NAME;
    use reticulum_rust::destination::Destination;

    /// Fixed identity hash used for hash derivation in this test.
    /// (Truncated 128-bit identity hash — same shape Reticulum uses everywhere.)
    const TEST_IDENTITY_HASH: [u8; 16] = [
        0xc2, 0x87, 0xb8, 0x44, 0xb2, 0xb6, 0xf8, 0xd6,
        0x01, 0x3b, 0x0a, 0x96, 0x2e, 0xb2, 0x10, 0x7b,
    ];

    /// Hash of the network-wide `rnstransport.path.request` control destination.
    /// The rfed aspects MUST NOT collide with this.
    const RNS_PATH_REQUEST_HASH_HEX: &str = "6b9f66014d9853faab220fba47d02761";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn dest_hash(aspect: &str) -> Vec<u8> {
        Destination::hash(Some(&TEST_IDENTITY_HASH), APP_NAME, &[aspect])
    }

    #[test]
    fn app_name_is_rfed() {
        assert_eq!(APP_NAME, "rfed", "rfed APP_NAME constant must remain \"rfed\"");
    }

    #[test]
    fn rfed_node_hash_is_pinned() {
        assert_eq!(hex(&dest_hash("node")), "0ae25bc66f4cd593dcf7028c50b5a06c");
    }

    #[test]
    fn rfed_delivery_hash_is_pinned() {
        assert_eq!(hex(&dest_hash("delivery")), "bc675d73690974e490e261ec19b4c5d7");
    }

    #[test]
    fn rfed_channel_hash_is_pinned() {
        assert_eq!(hex(&dest_hash("channel")), "b95521001a9c9af5bc0e33904bca56fb");
    }

    #[test]
    fn rfed_notify_hash_is_pinned() {
        assert_eq!(hex(&dest_hash("notify")), "9233db1eefe3c75832ead85956111fbe");
    }

    #[test]
    fn rfed_hashes_do_not_collide_with_rns_path_request() {
        for aspect in ["node", "delivery", "channel", "notify"] {
            let h = hex(&dest_hash(aspect));
            assert_ne!(
                h, RNS_PATH_REQUEST_HASH_HEX,
                "rfed.{aspect} hash must not collide with rnstransport.path.request"
            );
        }
    }

    #[test]
    fn rfed_hashes_are_pairwise_distinct() {
        let aspects = ["node", "delivery", "channel", "notify"];
        for i in 0..aspects.len() {
            for j in (i + 1)..aspects.len() {
                assert_ne!(
                    dest_hash(aspects[i]),
                    dest_hash(aspects[j]),
                    "rfed.{} and rfed.{} must hash to distinct destinations",
                    aspects[i], aspects[j],
                );
            }
        }
    }
}

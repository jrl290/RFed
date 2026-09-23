//! Full LXMF Propagation Node for RFed.
//!
//! RFed is a one-stop-shop Federation services node.  This module implements
//! a full `lxmf.propagation` node: it stores LXMF messages, peers with other
//! propagation nodes (both LXMF-rust lxmd instances and other RFed nodes),
//! handles the standard OFFER/GET sync protocol, and fires notify wake-ups
//! for registered destinations.
//!
//! # Wire protocol
//!
//! The propagation destination accepts:
//!
//! 1. **Client PUT** — link packet `[type, [[lxmf_payload], ...]]`
//!    Each `lxmf_payload` has the destination hash in the first 16 bytes.
//!    Messages are stamped-validated, stored, queued to all peers, and
//!    notify is fired for registered destinations.
//!
//! 2. **Peer OFFER** — request on `/offer` path
//!    `[peering_key, [transient_id, ...]]`
//!    We respond with `false` (have all), `true` (want all), or `[wanted_ids]`.
//!
//! 3. **Client GET** — request on `/get` path
//!    `[wants, haves, limit_kb]`
//!    `wants=nil` → list all messages for the requesting identity.
//!    `haves` array → delete those messages (client already has them).
//!    Returns `[lxmf_data, ...]` up to the limit.
//!
//! # Announce format
//!
//! Standard LXMF propagation announce:
//! ```text
//! [false, timestamp, is_active, transfer_limit, sync_limit,
//!  [stamp_cost, flexibility, peering_cost], {PN_META_NAME: name}]
//! ```
//!
//! # Peer sync
//!
//! On a timer, the node iterates peers with unhandled messages and initiates
//! outbound links to send OFFER requests.  The remote responds with which
//! transient_ids it wants, and we transfer those messages via resource.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use app_links::AppLinks;
use lxmf_rust::lx_stamper;
use reticulum_rust::destination::{Destination, DestinationType, ALLOW_ALL};
use reticulum_rust::identity::Identity;
use reticulum_rust::link::{Link, LinkHandle, MODE_AES256_CBC, RequestReceipt};
use reticulum_rust::transport::{AnnounceHandler, AnnounceCallback, Transport};
use reticulum_rust::{hexrep, log, LOG_DEBUG, LOG_NOTICE, LOG_WARNING, LOG_ERROR};
use rmpv::decode::read_value;
use rmpv::encode::write_value;
use rmpv::Value;

use crate::config::NodeConfig;
use crate::distro::DistroTable;
use crate::notify::NotifyRegistry;
use crate::link_session::LinkSessionRegistry;
use crate::stream_registry::{PropagationStreamRegistry, StreamDispatchResult};

// ── Constants ─────────────────────────────────────────────────────────────────

const LXMF_APP: &str = "lxmf";
const PROP_ASPECT: &str = "propagation";
const DESTINATION_LENGTH: usize = 16;

/// Standard propagation stamp cost.
pub const DEFAULT_STAMP_COST: u32 = 16;
/// Stamp flexibility window.
pub const DEFAULT_STAMP_FLEXIBILITY: u32 = 3;
/// Default peering cost.
pub const DEFAULT_PEERING_COST: u32 = 18;
/// Maximum peering cost we accept from remote peers.
pub const MAX_PEERING_COST: u32 = 26;
/// Default per-transfer limit in KB.
pub const DEFAULT_TRANSFER_LIMIT_KB: f64 = 256.0;
/// Default per-sync limit in KB.
pub const DEFAULT_SYNC_LIMIT_KB: f64 = 10240.0;
/// Message expiry: 7 days.  Matches BlobStore TTL.
pub const MESSAGE_EXPIRY_SECS: f64 = 7.0 * 24.0 * 3600.0;
/// Peer sync interval in seconds.
pub const PEER_SYNC_INTERVAL_SECS: f64 = 6.0;
/// Peer sync backoff step.
pub const SYNC_BACKOFF_STEP_SECS: f64 = 12.0 * 60.0;
const DISTRO_DEFERRED_QUEUE_LIMIT: usize = 256;
/// Max messages to offer in a single OFFER request. Prevents the offer
/// building from exceeding the 5-second send budget when the messagestore
/// is large (197k+ messages).
pub const MAX_OFFER_IDS: usize = 500;

/// The backlog — every message already stored when this node started — is
/// held back from outbound peer sync for this long after start. A restart
/// used to open with announces, peer links and a full-rate drain of that
/// backlog all at once (2026-09-23). Messages received after start are not
/// backlog: they sync immediately, hold or no hold.
pub const STARTUP_BACKLOG_HOLD_SECS: f64 = 3600.0;

/// Outbound peer-sync budget: messages we push to peers per minute, all
/// peers together. The reference paces syncs only by each peer's sync_limit
/// per session every 6 s, which with 20 peers and a 264k-message store meant
/// ~2000 messages/min for hours after every restart (2026-09-23). The budget
/// caps the aggregate; a full minute's worth is still ten offers.
pub const DEFAULT_OUTBOUND_SYNC_MSGS_PER_MIN: u64 = 600;
/// Max time a peer is unreachable before removal (14 days).
pub const MAX_UNREACHABLE_SECS: f64 = 14.0 * 24.0 * 3600.0;
/// Peer OFFER request path.
pub const OFFER_PATH: &str = "/offer";
/// Client/peer GET request path.
pub const GET_PATH: &str = "/get";
/// Maximum number of peers.
pub const MAX_PEERS: usize = 20;
/// LXMF propagation node metadata key for name.
pub const PN_META_NAME: u8 = 0x01;
/// Path request grace period.
const PATH_REQUEST_GRACE_SECS: f64 = 7.5;

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveDispatchOutcome {
    Streamed,
    Notified,
    None,
}

// ── PropagationEntry ──────────────────────────────────────────────────────────

/// In-memory index entry for a stored LXMF message.
#[derive(Clone)]
pub struct PropagationEntry {
    pub destination_hash: Vec<u8>,
    pub filepath: String,
    pub received: f64,
    pub size: usize,
    pub stamp_value: u32,
}

// ── PropPeer ──────────────────────────────────────────────────────────────────

/// Tracks sync state with a single LXMF propagation peer.
///
/// Each peer goes through a lifecycle:  IDLE → LINK_ESTABLISHING → LINK_READY
/// → REQUEST_SENT → RESPONSE_RECEIVED → IDLE.  Sync backoff increases on
/// failure and resets when the peer is heard via announce.
pub struct PropPeer {
    /// 16-byte truncated destination hash of the peer's `lxmf.propagation` dest.
    pub destination_hash: Vec<u8>,
    /// Whether this peer has been heard recently (set by announce handler).
    pub alive: bool,
    /// Unix timestamp of the last announce or successful interaction.
    pub last_heard: f64,
    /// Timestamp from the peer's announce — used to detect stale data.
    pub peering_timebase: f64,
    /// PoW cost the peer requires on inbound stamps (from announce app_data).
    pub propagation_stamp_cost: Option<u32>,
    /// How many bits below stamp_cost the peer will still accept.
    pub propagation_stamp_flexibility: Option<u32>,
    /// PoW cost for the peering handshake key (from announce app_data).
    pub peering_cost: Option<u32>,
    /// Max bytes the peer will accept in a single transfer (from announce).
    pub propagation_transfer_limit: Option<f64>,
    /// Max bytes the peer will sync in aggregate per period (from announce).
    pub propagation_sync_limit: Option<f64>,
    /// Raw msgpack-encoded metadata from announce (e.g. node name).
    pub metadata: Option<Vec<u8>>,

    /// Pre-computed PoW peering key: `(stamp_bytes, achieved_value)`.
    /// Generated in a background thread via `spawn_peering_key_gen()` to avoid
    /// blocking the main loop during the expensive Hashcash grind.
    pub peering_key: Option<(Vec<u8>, u32)>,
    /// Current exponential backoff interval in seconds (doubles on failure).
    pub sync_backoff: f64,
    /// Earliest Unix timestamp when the next sync attempt is allowed.
    pub next_sync_attempt: f64,
    /// Unix timestamp of the most recent sync attempt (success or failure).
    pub last_sync_attempt: f64,
    /// Rolling average bytes/sec achieved during transfers (unused, reserved).
    pub sync_transfer_rate: f64,

    /// Transient IDs this peer has already received (or declined).
    pub handled_ids: IdQueue,
    /// Transient IDs this peer has NOT yet received — drives the OFFER payload.
    pub unhandled_ids: IdQueue,

    /// Messages currently being transferred (in-flight guard).
    pub transferring: Option<Vec<Vec<u8>>>,
    /// The last set of IDs we offered — used to reconcile the response.
    pub last_offer: Vec<Vec<u8>>,
    /// Session-scoped mirror of the active AppLinks-owned link while a sync
    /// exchange is in flight.
    pub link: Option<LinkHandle>,
    /// Link id of the currently identified AppLinks-owned sync link.
    pub identified_link_id: Option<Vec<u8>>,
    /// Current sync state machine position (see `IDLE`, `LINK_ESTABLISHING`, etc.).
    pub state: u8,
}

impl PropPeer {
    pub const IDLE: u8 = 0;
    pub const LINK_ESTABLISHING: u8 = 1;
    pub const LINK_READY: u8 = 2;
    pub const REQUEST_SENT: u8 = 3;
    pub const RESPONSE_RECEIVED: u8 = 4;

    pub fn new(destination_hash: Vec<u8>) -> Self {
        PropPeer {
            destination_hash,
            alive: false,
            last_heard: 0.0,
            peering_timebase: 0.0,
            propagation_stamp_cost: None,
            propagation_stamp_flexibility: None,
            peering_cost: None,
            propagation_transfer_limit: None,
            propagation_sync_limit: None,
            metadata: None,
            peering_key: None,
            sync_backoff: 0.0,
            next_sync_attempt: 0.0,
            last_sync_attempt: 0.0,
            sync_transfer_rate: 0.0,
            handled_ids: IdQueue::default(),
            unhandled_ids: IdQueue::default(),
            transferring: None,
            last_offer: Vec::new(),
            link: None,
            identified_link_id: None,
            state: Self::IDLE,
        }
    }

    /// Check whether peer has all parameters needed to initiate sync:
    /// stamp costs populated from announce AND a valid (sufficiently strong)
    /// peering key already ground.
    pub fn sync_ready(&self) -> bool {
        self.propagation_stamp_cost.is_some()
            && self.propagation_stamp_flexibility.is_some()
            && self.peering_cost.is_some()
            && self.peering_key_ready()
    }

    /// A peering key is "ready" when its achieved PoW value meets or exceeds
    /// the peer's advertised peering cost.
    pub fn peering_key_ready(&self) -> bool {
        if let Some((_, value)) = &self.peering_key {
            if let Some(cost) = self.peering_cost {
                return *value >= cost;
            }
        }
        false
    }

    pub fn generate_peering_key(&mut self, router_identity: &Identity) -> bool {
        let peering_cost = match self.peering_cost {
            Some(cost) => cost,
            None => return false,
        };
        if self.peering_key_ready() {
            return true;
        }

        let identity = match Identity::recall(&self.destination_hash) {
            Some(id) => id,
            None => {
                log(
                    format!("[lxmf.prop] cannot recall identity for peer {}", hexrep(&self.destination_hash, false)),
                    LOG_WARNING, false, false,
                );
                return false;
            }
        };

        let identity_hash = match identity.hash.as_ref() {
            Some(h) => h.clone(),
            None => return false,
        };
        let router_hash = match router_identity.hash.as_ref() {
            Some(h) => h.clone(),
            None => return false,
        };

        let mut material = Vec::with_capacity(identity_hash.len() + router_hash.len());
        material.extend_from_slice(&identity_hash);
        material.extend_from_slice(&router_hash);
        let (key, value) = lx_stamper::generate_stamp(
            &material,
            peering_cost,
            lx_stamper::WORKBLOCK_EXPAND_ROUNDS_PEERING,
        );
        if value >= peering_cost {
            if let Some(key) = key {
                self.peering_key = Some((key, value));
                log(
                    format!("[lxmf.prop] peering key generated for {}", hexrep(&self.destination_hash, false)),
                    LOG_NOTICE, false, false,
                );
                return true;
            }
        }
        false
    }

    /// Queue a transient_id for delivery to this peer.  Deduplicates against
    /// both the unhandled and handled sets.
    pub fn add_unhandled(&mut self, transient_id: Vec<u8>) {
        if !self.handled_ids.contains(&transient_id) {
            self.unhandled_ids.push_unique(transient_id);
        }
    }

    /// Move a transient_id from unhandled → handled (peer accepted or declined it).
    pub fn mark_handled(&mut self, transient_id: &[u8]) {
        self.unhandled_ids.remove(transient_id);
        self.handled_ids.push_unique(transient_id.to_vec());
    }
}

/// An insertion-ordered set of transient ids with O(log n) insert, remove and
/// membership.
///
/// These were `Vec<Vec<u8>>`, deduplicated with `contains` and pruned with
/// `retain` — both linear. Every stored message is queued for every peer, so
/// one store cost `peers x ids` comparisons: measured at 3.6 ms per message
/// with 20 peers and the production store's ~150,000 messages (release build),
/// all of it while holding the node lock that `/get` and `/offer` wait on.
/// Expiry paid the same price per expired message.
#[derive(Clone, Debug, Default)]
pub struct IdQueue {
    order: BTreeMap<u64, Vec<u8>>,
    index: HashMap<Vec<u8>, u64>,
    next: u64,
}

impl IdQueue {
    /// Append `id` unless it is already present. Returns whether it was added.
    pub fn push_unique(&mut self, id: Vec<u8>) -> bool {
        if self.index.contains_key(&id) {
            return false;
        }
        let seq = self.next;
        self.next += 1;
        self.index.insert(id.clone(), seq);
        self.order.insert(seq, id);
        true
    }

    pub fn remove(&mut self, id: &[u8]) -> bool {
        match self.index.remove(id) {
            Some(seq) => { self.order.remove(&seq); true }
            None => false,
        }
    }

    pub fn contains(&self, id: &[u8]) -> bool { self.index.contains_key(id) }
    pub fn len(&self) -> usize { self.index.len() }
    pub fn is_empty(&self) -> bool { self.index.is_empty() }

    /// Ids in the order they were added.
    pub fn iter(&self) -> impl Iterator<Item = &Vec<u8>> { self.order.values() }
    pub fn to_vec(&self) -> Vec<Vec<u8>> { self.iter().cloned().collect() }
}

// ── LxmfPropagationNode ──────────────────────────────────────────────────────

/// Full LXMF Propagation Node.
///
/// Stores messages, peers with other propagation nodes, handles OFFER/GET,
/// and fires notify wake-ups for registered destinations.
pub struct LxmfPropagationNode {
    /// The `lxmf.propagation` RNS destination (inbound).
    pub destination: Destination,
    /// Node identity.
    pub identity: Identity,
    /// Shared notify registry — checked for every inbound LXMF message.
    registry: Arc<Mutex<NotifyRegistry>>,
    /// Distro device registry — checked for intercept after message storage.
    /// When set, messages for distro identities are stored in BlobStore
    /// (not messagestore) and fanned out to registered devices.
    distro_table: Option<Arc<Mutex<DistroTable>>>,
    /// BlobStore for distro message persistence (shared with FedSync).
    /// Only used when `distro_table` is Some.
    distro_blob_store: Option<Arc<Mutex<crate::blob_store::BlobStore>>>,
    /// Shared hook registry for delivery events.
    distro_hook_registry: Option<Arc<Mutex<crate::notify::HookRegistry>>>,
    /// Deferred delivery queue for distro messages (shared with FedNode).
    deferred_queue: Option<Arc<Mutex<crate::deferred_queue::DeferredQueue>>>,
    /// Active rfed.propagation.stream sessions keyed by link.
    stream_registry: Arc<Mutex<PropagationStreamRegistry>>,
    /// `rfed.link` sessions (RFed-spec/Link.md). Tried before
    /// `stream_registry`: a client that has migrated must not also receive the
    /// legacy stream copy.
    link_sessions: Arc<Mutex<LinkSessionRegistry>>,

    // ── Configuration ─────────────────────────────────────────────────
    pub stamp_cost: u32,
    pub stamp_flexibility: u32,
    pub peering_cost: u32,
    pub transfer_limit_kb: f64,
    pub sync_limit_kb: f64,
    pub storage_limit_bytes: u64,
    pub node_name: String,
    pub autopeer: bool,
    pub from_static_only: bool,
    pub static_peers: Vec<Vec<u8>>,

    // ── Message store ─────────────────────────────────────────────────
    /// Path to the messagestore directory.
    pub messagestore_path: PathBuf,
    /// In-memory index: transient_id → entry.
    pub entries: HashMap<Vec<u8>, PropagationEntry>,

    // ── Peer tracking ─────────────────────────────────────────────────
    pub peers: HashMap<Vec<u8>, PropPeer>,

    /// Dedup guard: peer hashes for which a peering-key PoW thread is
    /// currently in flight.  Without this, tick_sync (every ~6 s) re-spawns
    /// cost-N stamp generation for every peer whose key isn't cached yet,
    /// saturating CPU with redundant PoW work.  Insert before spawning,
    /// remove when the thread completes (success or failure).
    /// // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md (no duplicate work)
    pub in_flight_keys: HashSet<Vec<u8>>,

    // ── State files ───────────────────────────────────────────────────
    pub storage_path: PathBuf,

    // ── Stats ─────────────────────────────────────────────────────────
    pub messages_received: u64,
    pub messages_served: u64,

    // ── Sync timing ───────────────────────────────────────────────────
    pub last_sync_tick: f64,
    /// When this node started (unix seconds). Everything stored before this
    /// is backlog and waits STARTUP_BACKLOG_HOLD_SECS; see `sync_pool`.
    pub started_at: f64,
    /// Transient ids received since start, in arrival order. During the
    /// backlog hold these are the only ids offered to peers.
    pub fresh_since_start: Vec<Vec<u8>>,
    pub backlog_hold_logged: bool,
    /// Outbound sync budget window: start (unix seconds) and messages sent
    /// to peers within it.
    pub outbound_sync_window_start: f64,
    pub outbound_sync_window_count: u64,
    pub outbound_sync_msgs_per_min: u64,
    /// Set while the budget or the grace holds sync, so the hold is logged
    /// once per episode rather than every tick.
    pub outbound_sync_hold_logged: bool,

    // ── Self-reference ────────────────────────────────────────────────
    pub self_handle: Option<Weak<Mutex<LxmfPropagationNode>>>,
}

impl LxmfPropagationNode {
    // ── Construction ─────────────────────────────────────────────────────────

    pub fn new(
        identity: Identity,
        config: &NodeConfig,
        registry: Arc<Mutex<NotifyRegistry>>,
        stream_registry: Arc<Mutex<PropagationStreamRegistry>>,
        link_sessions: Arc<Mutex<LinkSessionRegistry>>,
        distro_table: Option<Arc<Mutex<DistroTable>>>,
        distro_blob_store: Option<Arc<Mutex<crate::blob_store::BlobStore>>>,
        distro_hook_registry: Option<Arc<Mutex<crate::notify::HookRegistry>>>,
        deferred_queue: Option<Arc<Mutex<crate::deferred_queue::DeferredQueue>>>,
    ) -> Result<Arc<Mutex<Self>>, String> {
        let destination = Destination::new_inbound(
            Some(identity.clone()),
            DestinationType::Single,
            LXMF_APP.to_string(),
            vec![PROP_ASPECT.to_string()],
        )?;

        let stamp_cost = config.default_policy.stamp_cost.unwrap_or(DEFAULT_STAMP_COST);
        let stamp_flexibility = config.default_policy.stamp_flexibility.unwrap_or(DEFAULT_STAMP_FLEXIBILITY);
        let transfer_limit_kb = config.transfer_limit_bytes
            .map(|b| b as f64 / 1024.0)
            .unwrap_or(DEFAULT_TRANSFER_LIMIT_KB);
        let sync_limit_kb = config.sync_limit_bytes
            .map(|b| b as f64 / 1024.0)
            .unwrap_or(DEFAULT_SYNC_LIMIT_KB);

        let storage_path = config.config_dir.join("lxmf_propagation");
        let messagestore_path = storage_path.join("messagestore");

        // Create directories.
        fs::create_dir_all(&storage_path)
            .map_err(|e| format!("Cannot create lxmf propagation dir: {e}"))?;
        fs::create_dir_all(&messagestore_path)
            .map_err(|e| format!("Cannot create messagestore dir: {e}"))?;

        let this = Arc::new(Mutex::new(LxmfPropagationNode {
            destination,
            identity,
            registry,
            distro_table,
            distro_blob_store,
            distro_hook_registry,
            deferred_queue,
            stream_registry,
            link_sessions,
            stamp_cost,
            stamp_flexibility,
            peering_cost: config.peering_cost.unwrap_or(DEFAULT_PEERING_COST),
            transfer_limit_kb,
            sync_limit_kb,
            storage_limit_bytes: config.storage_limit_bytes,
            node_name: config.display_name.clone(),
            autopeer: config.lxmf_propagation_autopeer,
            from_static_only: !config.lxmf_propagation_autopeer,
            static_peers: config.lxmf_propagation_peers.clone(),
            messagestore_path,
            entries: HashMap::new(),
            peers: HashMap::new(),
            in_flight_keys: HashSet::new(),
            storage_path,
            messages_received: 0,
            messages_served: 0,
            last_sync_tick: 0.0,
            started_at: now(),
            fresh_since_start: Vec::new(),
            backlog_hold_logged: false,
            outbound_sync_window_start: now(),
            outbound_sync_window_count: 0,
            outbound_sync_msgs_per_min: DEFAULT_OUTBOUND_SYNC_MSGS_PER_MIN,
            outbound_sync_hold_logged: false,
            self_handle: None,
        }));

        {
            let mut guard = this.lock().map_err(|_| "lock poisoned")?;
            guard.self_handle = Some(Arc::downgrade(&this));
        }

        Ok(this)
    }

    // ── Startup ──────────────────────────────────────────────────────────────

    /// Index the messagestore and rebuild peer state.  Must be called after new().
    pub fn enable(arc: &Arc<Mutex<Self>>) -> Result<(), String> {
        let mut guard = arc.lock().map_err(|_| "lock poisoned")?;

        // Index messagestore
        guard.index_messagestore();

        // Load peers
        guard.load_peers();

        // Activate static peers
        for static_peer in guard.static_peers.clone() {
            if !guard.peers.contains_key(&static_peer) {
                log(
                    format!("[lxmf.prop] activating static peer {}", hexrep(&static_peer, false)),
                    LOG_NOTICE, false, false,
                );
                let peer = PropPeer::new(static_peer.clone());
                guard.peers.insert(static_peer.clone(), peer);
            }
            // Always request path for static peers so announce handler fires
            // and marks them alive with fresh peering data
            Transport::request_path(&static_peer, None, None, None, None);
        }

        // Register request handlers
        let weak_offer = Arc::downgrade(arc);
        guard.destination.register_request_handler(
            OFFER_PATH.to_string(),
            Some(Arc::new(move |path, data, request_id, remote_identity, _link, requested_at| {
                if let Some(arc) = weak_offer.upgrade() {
                    if let Some(mut node) = lock_node(&arc, "/offer") {
                        return node.handle_offer(path, data, request_id, remote_identity, requested_at);
                    }
                }
                Vec::new()
            })),
            ALLOW_ALL,
            None,
            false,
        )?;

        let weak_get = Arc::downgrade(arc);
        guard.destination.register_request_handler(
            GET_PATH.to_string(),
            Some(Arc::new(move |path, data, request_id, remote_identity, _link, requested_at| {
                if let Some(arc) = weak_get.upgrade() {
                    if let Some(mut node) = lock_node(&arc, "/get") {
                        return node.handle_get(path, data, request_id, remote_identity, requested_at);
                    }
                }
                Vec::new()
            })),
            ALLOW_ALL,
            None,
            false,
        )?;

        // Set link established callback
        let weak_link = Arc::downgrade(arc);
        guard.destination.set_link_established_callback(Some(Arc::new(move |link| {
            if let Some(arc) = weak_link.upgrade() {
                if let Ok(mut node) = arc.lock() {
                    node.link_established(link);
                }
            }
        })));

        // Register destination with Transport
        Transport::register_destination(guard.destination.clone());

        // Set default app_data for path responses
        let app_data = guard.build_app_data();
        guard.destination.set_default_app_data(Some(app_data));
        Transport::update_destination(guard.destination.clone());

        log(
            format!(
                "[lxmf.prop] enabled: {} messages indexed, {} peers",
                guard.entries.len(),
                guard.peers.len(),
            ),
            LOG_NOTICE, false, false,
        );

        Ok(())
    }

    // ── Announce ──────────────────────────────────────────────────────────────

    pub fn build_app_data(&self) -> Vec<u8> {
        let ts = now() as i64;
        let stamp_costs = Value::Array(vec![
            Value::Integer((self.stamp_cost as i64).into()),
            Value::Integer((self.stamp_flexibility as i64).into()),
            Value::Integer((self.peering_cost as i64).into()),
        ]);
        let metadata = Value::Map(vec![(
            Value::Integer((PN_META_NAME as i64).into()),
            Value::Binary(self.node_name.as_bytes().to_vec()),
        )]);
        let announce_data = Value::Array(vec![
            Value::Boolean(false),
            Value::Integer(ts.into()),
            Value::Boolean(true),
            Value::Integer(((self.transfer_limit_kb / 1024.0) as i64).into()),
            Value::Integer(((self.sync_limit_kb / 1024.0) as i64).into()),
            stamp_costs,
            metadata,
        ]);
        let mut buf = Vec::new();
        let _ = write_value(&mut buf, &announce_data);
        buf
    }

    pub fn announce(arc: &Arc<Mutex<Self>>) {
        if let Ok(mut guard) = arc.lock() {
            let app_data = guard.build_app_data();
            guard.destination.set_default_app_data(Some(app_data.clone()));
            let _ = guard.destination.announce(Some(&app_data), false, None, None, true);
            log("[lxmf.prop] announced propagation node", LOG_NOTICE, false, false);
        }
    }

    /// Opt the propagation destination into Transport's announce daemon
    /// so it is re-announced every `SERVICE_REFRESH_INTERVAL_SECS` (6 h).
    /// See DESIGN_PRINCIPLES.md §3-§4.
    ///
    /// Transport announces it once on each interface up-edge and on the
    /// refresh, both held per interface to the refresh period
    /// (Reticulum-rust B22); the one immediate announce fired here covers
    /// interfaces that are already up. `announce` with `send=true` routes through
    /// `Transport::outbound`, which skips offline interfaces, so this is
    /// safe regardless of current link state. This is a single untargeted
    /// announce (it starts the period on every interface it goes out on),
    /// not a periodic timer.
    pub fn publish_destination(arc: &Arc<Mutex<Self>>) {
        use reticulum_rust::transport::Transport;
        let mut immediate: Option<(Vec<u8>, Destination)> = None;
        if let Ok(guard) = arc.lock() {
            let app_data = guard.build_app_data();
            Transport::publish_destination(
                guard.destination.hash.clone(),
                Some(Duration::from_secs(
                    crate::destinations::SERVICE_REFRESH_INTERVAL_SECS,
                )),
                Some(app_data.clone()),
            );
            immediate = Some((app_data, guard.destination.clone()));
        }
        // Announce outside the lock: Destination::announce re-enters TRANSPORT
        // via remember_ratchet, which would deadlock against the guard above.
        if let Some((app_data, mut dest)) = immediate {
            dest.set_default_app_data(Some(app_data.clone()));
            let _ = dest.announce(Some(&app_data), false, None, None, true);
            log("[lxmf.prop] announced propagation node (post-publish immediate)", LOG_NOTICE, false, false);
        }
    }

    // ── Announce handler (discover peers) ─────────────────────────────────────

    pub fn announce_handler(arc: &Arc<Mutex<Self>>) -> AnnounceHandler {
        let weak = Arc::downgrade(arc);
        let callback: AnnounceCallback = Arc::new(move |destination_hash, _identity, app_data, _announce_hash, is_path_response| {
            if let Some(arc) = weak.upgrade() {
                match arc.lock() {
                    Ok(mut node) => {
                        node.handle_propagation_announce(destination_hash, app_data, is_path_response);
                    },
                    Err(e) => {
                        log(format!("[lxmf.prop] POISONED LOCK in announce callback: {}", e), LOG_ERROR, false, false);
                    }
                }
            }
        });
        AnnounceHandler {
            aspect_filter: Some(format!("{}.{}", LXMF_APP, PROP_ASPECT)),
            receive_path_responses: true,
            callback,
        }
    }

    fn handle_propagation_announce(&mut self, destination_hash: &[u8], app_data: &[u8], is_path_response: bool) {
        log(
            format!("[lxmf.prop] handle_propagation_announce {} app_data_len={} is_path_response={}", hexrep(destination_hash, false), app_data.len(), is_path_response),
            LOG_DEBUG, false, false,
        );
        // Don't peer with ourselves
        if destination_hash == self.destination.hash.as_slice() {
            log("[lxmf.prop] announce is from ourselves, ignoring", LOG_DEBUG, false, false);
            return;
        }

        if !lxmf_rust::lxmf::pn_announce_data_is_valid(app_data) {
            log(format!("[lxmf.prop] announce app_data INVALID for {}", hexrep(destination_hash, false)), LOG_DEBUG, false, false);
            return;
        }

        let config = match read_value(&mut Cursor::new(app_data)) {
            Ok(Value::Array(items)) if items.len() >= 7 => {
                log(
                    format!("[lxmf.prop] announce config parsed: {} items", items.len()),
                    LOG_DEBUG, false, false,
                );
                items
            },
            Ok(other) => {
                log(
                    format!("[lxmf.prop] announce config not array or <7 items: {:?}", other),
                    LOG_DEBUG, false, false,
                );
                return;
            },
            Err(e) => {
                log(
                    format!("[lxmf.prop] announce config parse error: {}", e),
                    LOG_DEBUG, false, false,
                );
                return;
            },
        };

        let node_timebase = config[1].as_i64().unwrap_or(0) as f64;
        let propagation_enabled = config[2].as_bool().unwrap_or(false);
        let transfer_limit = config[3].as_f64().unwrap_or(0.0);
        let sync_limit = config[4].as_f64().unwrap_or(0.0);
        let (stamp_cost, stamp_flex, peer_cost) = match &config[5] {
            Value::Array(costs) if costs.len() >= 3 => (
                costs[0].as_i64().unwrap_or(0) as u32,
                costs[1].as_i64().unwrap_or(0) as u32,
                costs[2].as_i64().unwrap_or(0) as u32,
            ),
            _ => (0, 0, 0),
        };
        let mut metadata = Vec::new();
        let _ = write_value(&mut metadata, &config[6]);

        log(
            format!("[lxmf.prop] announce values: timebase={} enabled={} transfer_limit={} sync_limit={} stamp_cost={} stamp_flex={} peer_cost={} is_static={}",
                node_timebase, propagation_enabled, transfer_limit, sync_limit, stamp_cost, stamp_flex, peer_cost,
                self.static_peers.contains(&destination_hash.to_vec())),
            LOG_DEBUG, false, false,
        );

        let is_static = self.static_peers.contains(&destination_hash.to_vec());

        if is_static {
            // Always update static peers, including from path responses
            self.peer(
                destination_hash.to_vec(), node_timebase, transfer_limit,
                if sync_limit > 0.0 { Some(sync_limit) } else { None },
                stamp_cost, stamp_flex, peer_cost, metadata,
            );
        } else if self.autopeer && !is_path_response && propagation_enabled {
            self.peer(
                destination_hash.to_vec(), node_timebase, transfer_limit,
                if sync_limit > 0.0 { Some(sync_limit) } else { None },
                stamp_cost, stamp_flex, peer_cost, metadata,
            );
        }
    }

    // ── Peering ──────────────────────────────────────────────────────────────

    fn peer(
        &mut self,
        destination_hash: Vec<u8>,
        timebase: f64,
        transfer_limit: f64,
        sync_limit: Option<f64>,
        stamp_cost: u32,
        stamp_flex: u32,
        peer_cost: u32,
        metadata: Vec<u8>,
    ) {
        if peer_cost > MAX_PEERING_COST {
            log(
                format!("[lxmf.prop] peering cost {} exceeds max {}, ignoring {}", peer_cost, MAX_PEERING_COST, hexrep(&destination_hash, false)),
                LOG_NOTICE, false, false,
            );
            return;
        }

        if let Some(peer) = self.peers.get_mut(&destination_hash) {
            if timebase > peer.peering_timebase {
                peer.alive = true;
                peer.last_heard = now();
                peer.peering_timebase = timebase;
                peer.propagation_stamp_cost = Some(stamp_cost);
                peer.propagation_stamp_flexibility = Some(stamp_flex);
                peer.peering_cost = Some(peer_cost);
                peer.propagation_transfer_limit = Some(transfer_limit);
                peer.propagation_sync_limit = sync_limit.or(Some(transfer_limit));
                peer.metadata = Some(metadata);
                // NOTE: deliberately do NOT reset `sync_backoff` /
                // `next_sync_attempt` here.  Mesh peers re-announce every
                // ~30-60 s, so wiping the backoff on every announce defeats
                // it entirely — observed in production: a peer that fails
                // 39 LRs in a row keeps getting hammered with one LR per
                // announce because each `updated peer` zeroed the backoff.
                // Backoff is owned exclusively by the link-result path:
                //   * cleared to 0 in the link_established callback
                //     (real evidence the path works), or
                //   * incremented in the link_closed callback (real
                //     evidence the path failed).
                log(
                    format!("[lxmf.prop] updated peer {}", hexrep(&destination_hash, false)),
                    LOG_NOTICE, false, false,
                );
            }
        } else if self.peers.len() < MAX_PEERS {
            let mut peer = PropPeer::new(destination_hash.clone());
            peer.alive = true;
            peer.last_heard = now();
            peer.peering_timebase = timebase;
            peer.propagation_stamp_cost = Some(stamp_cost);
            peer.propagation_stamp_flexibility = Some(stamp_flex);
            peer.peering_cost = Some(peer_cost);
            peer.propagation_transfer_limit = Some(transfer_limit);
            peer.propagation_sync_limit = sync_limit.or(Some(transfer_limit));
            peer.metadata = Some(metadata);
            self.peers.insert(destination_hash.clone(), peer);
            log(
                format!("[lxmf.prop] peered with {}", hexrep(&destination_hash, false)),
                LOG_NOTICE, false, false,
            );
        }
    }

    fn unpeer(&mut self, destination_hash: &[u8]) {
        self.peers.remove(destination_hash);
        log(
            format!("[lxmf.prop] unpeered {}", hexrep(destination_hash, false)),
            LOG_NOTICE, false, false,
        );
    }

    // ── Message store ────────────────────────────────────────────────────────

    fn index_messagestore(&mut self) {
        self.entries.clear();
        let start = now();

        let dir_entries = match fs::read_dir(&self.messagestore_path) {
            Ok(entries) => entries,
            Err(e) => {
                log(format!("[lxmf.prop] cannot read messagestore: {e}"), LOG_ERROR, false, false);
                return;
            }
        };

        for entry in dir_entries.flatten() {
            let filename = entry.file_name().to_string_lossy().to_string();
            let components: Vec<&str> = filename.split('_').collect();
            if components.len() < 3 {
                continue;
            }

            // Filename format: {transient_id_hex}_{unix_timestamp}_{stamp_value}
            // transient_id = full_hash(lxmf_data) = 32 bytes = 64 hex chars
            let hex_len = 32 * 2;
            if components[0].len() != hex_len {
                continue;
            }

            let received: f64 = match components[1].parse() {
                Ok(v) if v > 0.0 => v,
                _ => continue,
            };
            let stamp_value: u32 = match components[2].parse() {
                Ok(v) => v,
                _ => continue,
            };

            let filepath = entry.path().to_string_lossy().to_string();
            let msg_size = entry.metadata().map(|m| m.len() as usize).unwrap_or(0);

            // Read the first DESTINATION_LENGTH bytes for the dest hash
            let destination_hash = match fs::read(&filepath) {
                Ok(data) if data.len() >= DESTINATION_LENGTH => {
                    data[..DESTINATION_LENGTH].to_vec()
                }
                _ => continue,
            };

            let transient_id = match reticulum_rust::decode_hex(components[0]) {
                Some(bytes) => bytes,
                None => continue,
            };

            self.entries.insert(
                transient_id,
                PropagationEntry {
                    destination_hash,
                    filepath,
                    received,
                    size: msg_size,
                    stamp_value,
                },
            );
        }

        let elapsed = now() - start;
        log(
            format!(
                "[lxmf.prop] indexed {} messages in {:.2}s",
                self.entries.len(), elapsed,
            ),
            LOG_NOTICE, false, false,
        );
    }

    /// Store an incoming LXMF message on disk and index it in memory.
    ///
    /// Returns the transient_id (full SHA-256 hash of lxmf_data) if the
    /// message was stored, or `None` if it's a duplicate or too short.
    ///
    /// `from_peer` — if the message came from a sync peer, that peer's
    /// destination hash is passed so we skip queueing it back to them.
    fn store_message(
        &mut self,
        lxmf_data: &[u8],
        stamp_value: u32,
        stamp_data: Option<&[u8]>,
        from_peer: Option<&[u8]>,
    ) -> Option<Vec<u8>> {
        if lxmf_data.len() < DESTINATION_LENGTH {
            return None;
        }

        let transient_id = reticulum_rust::identity::full_hash(lxmf_data);

        // Dedup
        if self.entries.contains_key(&transient_id) {
            return None;
        }

        let received = now();
        let destination_hash = lxmf_data[..DESTINATION_LENGTH].to_vec();

        // Write to disk: lxmf_data + optional stamp appended.
        // The stamp is kept on disk so it can be forwarded to peers during
        // sync, but is stripped before serving to clients via GET.
        let mut file_data = lxmf_data.to_vec();
        if let Some(stamp) = stamp_data {
            file_data.extend_from_slice(stamp);
        }

        let filepath = format!(
            "{}/{}_{}_{}", 
            self.messagestore_path.display(),
            hexrep(&transient_id, false),
            received,
            stamp_value,
        );

        if let Err(e) = fs::write(&filepath, &file_data) {
            log(format!("[lxmf.prop] cannot write message: {e}"), LOG_ERROR, false, false);
            return None;
        }

        let entry = PropagationEntry {
            destination_hash: destination_hash.clone(),
            filepath,
            received,
            size: file_data.len(),
            stamp_value,
        };
        self.entries.insert(transient_id.clone(), entry);

        // Queue for all peers except the one that sent it to us —
        // avoids echoing a message back to its originator.
        for (peer_hash, peer) in self.peers.iter_mut() {
            if from_peer.map(|fp| fp != peer_hash.as_slice()).unwrap_or(true) {
                peer.add_unhandled(transient_id.clone());
            }
        }
        self.fresh_since_start.push(transient_id.clone());

        self.messages_received += 1;

        log(
            format!(
                "[lxmf.prop] stored message {} for {} ({} bytes), queued for {} peers",
                hexrep(&transient_id, false),
                hexrep(&destination_hash, false),
                file_data.len(),
                self.peers.len(),
            ),
            // Per message, so DEBUG: at production ingest rates this one line
            // filled the 5 MB log every ~11 minutes and rotated the startup
            // banner and every diagnostic away within twenty. The per-batch
            // "processed N msgs" summary carries the same counts at NOTICE.
            LOG_DEBUG, false, false,
        );

        Some(transient_id)
    }

    /// Evict expired messages (older than MESSAGE_EXPIRY_SECS).
    pub fn evict_expired(&mut self) {
        let cutoff = now() - MESSAGE_EXPIRY_SECS;
        let expired: Vec<Vec<u8>> = self.entries.iter()
            .filter(|(_, e)| e.received < cutoff)
            .map(|(id, _)| id.clone())
            .collect();

        for transient_id in &expired {
            if let Some(entry) = self.entries.remove(transient_id) {
                let _ = fs::remove_file(&entry.filepath);
            }
            for (_, peer) in self.peers.iter_mut() {
                peer.handled_ids.remove(transient_id);
                peer.unhandled_ids.remove(transient_id);
            }
        }

        if !expired.is_empty() {
            log(
                format!("[lxmf.prop] evicted {} expired messages", expired.len()),
                LOG_NOTICE, false, false,
            );
        }
    }

    /// Enforce storage limit by removing oldest messages.
    /// Uses age-only sorting (O(n log n) but no weight calculation per entry).
    /// Hard cap: stops once we're under the limit.
    pub fn enforce_storage_limit(&mut self) {
        let total_size: u64 = self.entries.values().map(|e| e.size as u64).sum();
        if total_size <= self.storage_limit_bytes {
            return;
        }

        // Sort by age only (oldest first) — no weight calculation
        let mut by_age: Vec<(Vec<u8>, f64)> = self.entries.iter()
            .map(|(id, e)| (id.clone(), e.received))
            .collect();
        by_age.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        let mut current_size = total_size;
        for (transient_id, _received) in by_age {
            if current_size <= self.storage_limit_bytes {
                break;
            }
            if let Some(entry) = self.entries.remove(&transient_id) {
                current_size = current_size.saturating_sub(entry.size as u64);
                let _ = fs::remove_file(&entry.filepath);
            }
            for (_, peer) in self.peers.iter_mut() {
                peer.handled_ids.remove(&transient_id);
                peer.unhandled_ids.remove(&transient_id);
            }
        }
    }

    // ── Link established ─────────────────────────────────────────────────────

    fn link_established(&mut self, link: LinkHandle) {
        log("[lxmf.prop] link established", LOG_DEBUG, false, false);

        let weak = self.self_handle.clone();
        link.set_packet_callback(Some(Arc::new({
            let weak = weak.clone();
            move |data, packet| {
                // NOT under the node lock — see `ingest_propagation_batch`.
                let _ = packet;
                if let Some(arc) = weak.as_ref().and_then(|w| w.upgrade()) {
                    LxmfPropagationNode::ingest_propagation_batch(&arc, data);
                }
            }
        })));

        // Accept resources for large batch transfers from peers/clients.
        // The wire format inside the assembled resource is identical to the
        // single-packet propagation payload (msgpack [timebase, [messages]]),
        // so the concluded callback dispatches into the same ingest helper.
        link.set_resource_strategy(reticulum_rust::link::ACCEPT_APP);

        // Resource-advertised callback: accepts every advertisement (its
        // return value is the ACCEPT_APP verdict, RNS/Link.py:1108).
        // Resource-concluded callback: invoked once the multi-segment
        // transfer is fully assembled. Decode and ingest the same way as
        // single-packet inbound propagation data.
        let weak_concluded = self.self_handle.clone();
        link.set_resource_callbacks(
            Some(Arc::new(|_advertisement: &reticulum_rust::resource::ResourceAdvertisement| -> bool {
                // Accept all advertised propagation resources.
                true
            })),
            None,
            Some(Arc::new(move |resource| {
                let data: Vec<u8> = match resource.lock() {
                    Ok(r) => {
                        if r.status != reticulum_rust::resource::ResourceStatus::Complete {
                            return;
                        }
                        match r.data.clone() {
                            Some(d) => d,
                            None => return,
                        }
                    }
                    Err(_) => return,
                };
                // NOT under the node lock — see `ingest_propagation_batch`.
                if let Some(arc) = weak_concluded.as_ref().and_then(|w| w.upgrade()) {
                    LxmfPropagationNode::ingest_propagation_batch(&arc, &data);
                }
            })),
        );
    }

    // ── Packet handler (client PUTs) ─────────────────────────────────────────
    //
    // Incoming link packet format (standard LXMF propagation wire protocol):
    //   msgpack Array: [type_marker, [lxmf_payload_1, lxmf_payload_2, ...]]
    // Each lxmf_payload has the destination hash in the first 16 bytes.

    /// Decode and ingest a propagation payload — a client PUT packet or an
    /// assembled batch Resource from a peer (same wire format for both).
    ///
    /// Takes the `Arc`, not `&mut self`, ON PURPOSE. The node mutex is the one
    /// `/get` and `/offer` wait on, so it is held here only for the one step
    /// that needs the node — recording a message in the store — and for one
    /// message at a time. Everything else runs with it released:
    ///
    ///   * stamp validation. Each stamp costs a workblock expansion, ~8 ms in a
    ///     release build, and a peer sync delivers hundreds per batch;
    ///   * the distro path, which only touches the BlobStore and DistroTable;
    ///   * live delivery and notify wakes, which are network sends.
    ///
    /// NEVER move any of those back under the node lock. This was one
    /// `&mut self` method called with the lock held for the whole batch. Under
    /// a sustained ingest of ~30 messages/s in production, `/get` — a client
    /// asking for its own mail — waited 73 s and then 182 s for a 1-byte
    /// answer, long after the client had given up, and nothing logged the
    /// wait. Same class as the FedNode fan-out wedge of 2026-08-17: a lock held
    /// across work whose duration the holder does not control.
    /// `ingest_lock_scope_tests` holds this in place.
    pub(crate) fn ingest_propagation_batch(arc: &Arc<Mutex<Self>>, data: &[u8]) {
        let Some(messages) = decode_propagation_batch(data) else { return };
        if messages.is_empty() {
            return;
        }

        let (min_cost, delivery) = {
            let Some(node) = lock_node(arc, "ingest (setup)") else { return };
            (node.stamp_cost.saturating_sub(node.stamp_flexibility), node.delivery_handles())
        };

        // Validate PN (Propagation Node) stamps on all messages. Stamps below
        // `min_cost` are rejected; only validated messages proceed.
        let validated = lx_stamper::validate_pn_stamps(&messages, min_cost);

        let mut stored = 0usize;
        let mut streamed = 0usize;
        let mut notified = 0usize;

        for (_transient_id, lxmf_data, stamp_value, stamp_raw) in &validated {
            let dest_hash = if lxmf_data.len() >= DESTINATION_LENGTH {
                &lxmf_data[..DESTINATION_LENGTH]
            } else {
                &[]
            };

            // ── Distro intercept ──────────────────────────────────────
            // If the destination is a registered distro identity, store the
            // LXMF blob in BlobStore (for rfed→rfed sync) instead of the
            // propagation messagestore, and fan out to registered devices.
            // This prevents distro messages from polluting the lxmd mesh.
            if delivery.is_distro(dest_hash) {
                log(
                    format!("[distro] intercepted propagated message for {}", hexrep(dest_hash, false)),
                    LOG_NOTICE, false, false,
                );
                // Fan out to registered devices immediately — but only on
                // first sight. See `ingest_distro_blob`.
                if delivery.ingest_distro_blob(dest_hash, lxmf_data, &mut stored) {
                    delivery.distro_fanout(dest_hash, lxmf_data);
                }
                continue;
            }

            // ── Normal propagation path ───────────────────────────────
            // The only step that needs the node. One message per acquisition,
            // so a waiting request handler gets in between any two of them.
            let was_stored = match lock_node(arc, "ingest (store)") {
                Some(mut node) => node.store_message(lxmf_data, *stamp_value, Some(stamp_raw), None).is_some(),
                None => return,
            };
            if was_stored {
                stored += 1;
            }

            match delivery.dispatch_live_or_notify(lxmf_data, "") {
                LiveDispatchOutcome::Streamed => streamed += 1,
                LiveDispatchOutcome::Notified => notified += 1,
                LiveDispatchOutcome::None => {}
            }
        }

        let total = messages.len();
        let invalid_stamps = total - validated.len();
        log(
            format!(
                "[lxmf.prop] processed {} msgs: {} stored, {} streamed, {} notified, {} bad-stamp",
                total, stored, streamed, notified, invalid_stamps,
            ),
            LOG_NOTICE, false, false,
        );
    }

    /// The shared handles delivery works through. Cloning them out is the only
    /// thing ingest needs the node for besides `store_message`.
    fn delivery_handles(&self) -> DeliveryHandles {
        DeliveryHandles {
            registry: self.registry.clone(),
            stream_registry: self.stream_registry.clone(),
            link_sessions: self.link_sessions.clone(),
            distro_table: self.distro_table.clone(),
            distro_blob_store: self.distro_blob_store.clone(),
            distro_hook_registry: self.distro_hook_registry.clone(),
            deferred_queue: self.deferred_queue.clone(),
        }
    }
}

/// Acquire the propagation node lock, and say so when it was not free.
///
/// A request handler that waits here is a client that waits, and until this
/// existed the wait was invisible: the log showed the request arriving and,
/// minutes later, the response leaving, with nothing in between. Anything over
/// a second is reported — enough to stay quiet under ordinary contention and
/// to speak long before DESIGN_PRINCIPLES §1's five.
fn lock_node<'a>(
    arc: &'a Arc<Mutex<LxmfPropagationNode>>,
    who: &str,
) -> Option<std::sync::MutexGuard<'a, LxmfPropagationNode>> {
    let started = std::time::Instant::now();
    let guard = arc.lock().ok()?;
    let waited = started.elapsed().as_secs_f64();
    if waited >= NODE_LOCK_WAIT_WARN_SECS {
        log(
            format!("[lxmf.prop] LOCK-WARN {who}: waited {waited:.2}s for the propagation node lock"),
            LOG_WARNING, false, false,
        );
    }
    Some(guard)
}

const NODE_LOCK_WAIT_WARN_SECS: f64 = 1.0;

/// `[timebase, [lxmf_payload, ...]]` — the propagation wire format.
fn decode_propagation_batch(data: &[u8]) -> Option<Vec<Vec<u8>>> {
    let items = match read_value(&mut Cursor::new(data)) {
        Ok(Value::Array(a)) => a,
        _ => {
            log("[lxmf.prop] malformed packet", LOG_WARNING, false, false);
            return None;
        }
    };
    match items.get(1) {
        Some(Value::Array(values)) => {
            let messages: Vec<Vec<u8>> = values.iter()
                .filter_map(|v| match v { Value::Binary(b) => Some(b.clone()), _ => None })
                .collect();
            // An entry that is not msgpack bin is not a message and is dropped —
            // but a batch that decodes to nothing must not vanish in silence.
            // A sender packing bytes as msgpack str (PyPI `msgpack` without
            // use_bin_type, where LXMF itself uses umsgpack) delivered a
            // 6000-message flood of which rfed stored nothing, with no log line
            // anywhere, while the sender saw every batch proven. Reference:
            // LXMF/LXMRouter.py takes the same `[timebase, [bytes, ...]]` shape.
            if messages.len() < values.len() {
                log(
                    format!(
                        "[lxmf.prop] batch of {} entries: {} dropped for not being msgpack bin (sender packs bytes as {})",
                        values.len(), values.len() - messages.len(),
                        values.iter().find(|v| !matches!(v, Value::Binary(_))).map(|v| match v {
                            Value::String(_) => "str", Value::Array(_) => "array", Value::Nil => "nil", _ => "another type",
                        }).unwrap_or("?"),
                    ),
                    LOG_WARNING, false, false,
                );
            }
            Some(messages)
        }
        _ => {
            log("[lxmf.prop] packet missing message array", LOG_DEBUG, false, false);
            None
        }
    }
}

/// Everything message delivery needs that is not the node itself: shared
/// handles, each with its own lock. Delivery runs on these precisely so that
/// it never needs — and never holds — the node lock.
#[derive(Clone)]
struct DeliveryHandles {
    registry: Arc<Mutex<NotifyRegistry>>,
    stream_registry: Arc<Mutex<PropagationStreamRegistry>>,
    link_sessions: Arc<Mutex<LinkSessionRegistry>>,
    distro_table: Option<Arc<Mutex<DistroTable>>>,
    distro_blob_store: Option<Arc<Mutex<crate::blob_store::BlobStore>>>,
    distro_hook_registry: Option<Arc<Mutex<crate::notify::HookRegistry>>>,
    deferred_queue: Option<Arc<Mutex<crate::deferred_queue::DeferredQueue>>>,
}

impl DeliveryHandles {
    fn is_distro(&self, dest_hash: &[u8]) -> bool {
        self.distro_table
            .as_ref()
            .and_then(|dt| dt.lock().ok().map(|t| t.is_distro(dest_hash)))
            .unwrap_or(false)
    }

    fn distro_fanout(&self, dest_hash: &[u8], lxmf_data: &[u8]) {
        // NEVER REMOVE the snapshot-then-drop. The distro_table lock is
        // released before distro_fanout does any network work — holding
        // it across the fan-out wedged /rfed/distro/register in
        // production (see distro::distro_fanout's doc comment).
        let Some(ref dt) = self.distro_table else { return };
        let devices = match dt.lock() {
            Ok(table) => table.devices_snapshot(dest_hash),
            Err(_) => Vec::new(),
        };
        if devices.is_empty() {
            return;
        }
        let hook_guard = self.distro_hook_registry.as_ref().and_then(|h| h.lock().ok());
        let default_hooks = crate::notify::HookRegistry::new();
        let hooks: &crate::notify::HookRegistry = match &hook_guard {
            Some(g) => &**g,
            None => &default_hooks,
        };
        let on_missed: Option<Arc<dyn Fn(Vec<u8>) + Send + Sync>> = self.deferred_queue.as_ref().map(|queue| {
            let queue = Arc::clone(queue);
            let distro_hash = dest_hash.to_vec();
            let blob = lxmf_data.to_vec();
            let hook: Arc<dyn Fn(Vec<u8>) + Send + Sync> = Arc::new(move |device_id_hash: Vec<u8>| {
                enqueue_distro_misses(Some(&queue), vec![device_id_hash], &distro_hash, &blob);
            });
            hook
        });
        let missed = crate::distro::distro_fanout(
            dest_hash,
            lxmf_data,
            &devices,
            hooks,
            Some(&self.stream_registry),
            Some(&self.link_sessions),
            on_missed,
        );
        if !missed.is_empty() {
            log(
                format!(
                    "[distro] {} device(s) unreachable for distro {} — enqueuing in deferred queue",
                    missed.len(),
                    hexrep(dest_hash, false),
                ),
                LOG_NOTICE,
                false,
                false,
            );
            enqueue_distro_misses(self.deferred_queue.as_ref(), missed, dest_hash, lxmf_data);
        }
    }

    fn dispatch_live_or_notify(&self, lxmf_data: &[u8], log_suffix: &str) -> LiveDispatchOutcome {
        if lxmf_data.len() < DESTINATION_LENGTH {
            return LiveDispatchOutcome::None;
        }

        let dest_hash = &lxmf_data[..DESTINATION_LENGTH];

        // ── rfed.link session first (RFed-spec/Link.md) ──────────────
        // `/lxmf/delivery` on the link the client already has open. No
        // `on_failed` hook: an unanswered push here still leaves the message in
        // the messagestore, where the client's next propagation sync finds it.
        let link_result = self
            .link_sessions
            .lock()
            .ok()
            .map(|mut registry| registry.dispatch_lxmf(dest_hash, lxmf_data, None))
            .unwrap_or_else(StreamDispatchResult::default);

        if link_result.delivered() {
            log(
                format!(
                    "[lxmf.prop] rfed.link pushed recipient {} on {} link(s){}",
                    hexrep(dest_hash, false),
                    link_result.sent,
                    log_suffix,
                ),
                LOG_NOTICE,
                false,
                false,
            );
            return LiveDispatchOutcome::Streamed;
        }

        if link_result.had_sessions() {
            log(
                format!(
                    "[lxmf.prop] rfed.link push failed for recipient {} — falling through{}",
                    hexrep(dest_hash, false),
                    log_suffix,
                ),
                LOG_WARNING,
                false,
                false,
            );
        }

        let stream_result = self
            .stream_registry
            .lock()
            .ok()
            .map(|mut registry| registry.dispatch(dest_hash, lxmf_data))
            .unwrap_or_else(StreamDispatchResult::default);

        if stream_result.delivered() {
            log(
                format!(
                    "[lxmf.prop] streamed recipient {} on {} live link(s){}",
                    hexrep(dest_hash, false),
                    stream_result.sent,
                    log_suffix,
                ),
                LOG_NOTICE,
                false,
                false,
            );
            return LiveDispatchOutcome::Streamed;
        }

        if stream_result.had_sessions() {
            log(
                format!(
                    "[lxmf.prop] propagation.stream delivery failed for recipient {} — notify fallback{}",
                    hexrep(dest_hash, false),
                    log_suffix,
                ),
                LOG_WARNING,
                false,
                false,
            );
        }

        if let Ok(reg) = self.registry.lock() {
            let regs = reg.get_for_channel(dest_hash, None);
            if !regs.is_empty() {
                log(
                    format!(
                        "[lxmf.prop] found {} notify registrations for recipient {}{}",
                        regs.len(),
                        hexrep(dest_hash, false),
                        log_suffix,
                    ),
                    LOG_DEBUG,
                    false,
                    false,
                );
                let sender = if lxmf_data.len() >= DESTINATION_LENGTH * 2 {
                    Some(&lxmf_data[DESTINATION_LENGTH..DESTINATION_LENGTH * 2])
                } else {
                    None
                };
                for registration in &regs {
                    crate::notify::dispatch_notify(registration, sender, None);
                }
                return LiveDispatchOutcome::Notified;
            }
            log(
                format!(
                    "[lxmf.prop] NO notify registrations found for recipient {}{}",
                    hexrep(dest_hash, false),
                    log_suffix,
                ),
                LOG_DEBUG,
                false,
                false,
            );
        }

        LiveDispatchOutcome::None
    }

    /// Persist a distro blob and report whether this node had never seen it.
    ///
    /// The BlobStore is the idempotency record for distro delivery. The same
    /// LXMF message arrives here repeatedly — a client that re-PUTs, and once
    /// per federation peer that offers it on a sync round — and the fan-out
    /// used to run on every arrival, so a device with two peers upstream
    /// received the message once per peer, forever. Storage was already
    /// deduplicated; delivery now follows the same verdict.
    ///
    /// Returns `true` when the caller should fan out. A store that is
    /// unreachable or full answers `true`: dropping a message is worse than
    /// delivering it twice, and that is exactly the pre-existing behaviour.
    fn ingest_distro_blob(
        &self,
        dest_hash: &[u8],
        lxmf_data: &[u8],
        stored: &mut usize,
    ) -> bool {
        let Some(ref blob_store) = self.distro_blob_store else { return true };
        let Ok(mut store) = blob_store.lock() else { return true };

        let msg_id = crate::distro::distro_message_id(lxmf_data);
        if store.index.contains_key(&msg_id) {
            log(
                format!(
                    "[distro] already hold blob {} for {} — not re-fanning",
                    hexrep(&msg_id, false),
                    hexrep(dest_hash, false),
                ),
                LOG_DEBUG, false, false,
            );
            return false;
        }

        match store.store_with_id(dest_hash, &msg_id, lxmf_data) {
            Ok(_) => {
                *stored += 1;
                true
            }
            Err(e) => {
                log(
                    format!("[distro] BlobStore store error: {e}"),
                    LOG_WARNING, false, false,
                );
                true
            }
        }
    }
}

impl LxmfPropagationNode {

    // ── OFFER handler ────────────────────────────────────────────────────────
    //
    // OFFER request format:  [peering_key: Binary, [transient_id: Binary, ...]]
    //
    // Response variants:
    //   false            — we have all offered messages
    //   true             — we want ALL offered messages
    //   [Binary, ...]    — we want only these specific transient_ids
    //   Integer(0xF?)    — error code

    fn handle_offer(
        &mut self,
        _path: &str,
        data: &[u8],
        _request_id: &[u8],
        remote_identity: Option<&Identity>,
        _requested_at: f64,
    ) -> Vec<u8> {
        let remote_identity = match remote_identity {
            Some(id) => id,
            None => return encode_error(0xF0), // ERROR_NO_IDENTITY
        };

        if self.from_static_only {
            let remote_hash = Destination::hash_from_name_and_identity(
                &format!("{}.{}", LXMF_APP, PROP_ASPECT),
                Some(remote_identity),
            );
            if !self.static_peers.contains(&remote_hash) {
                return encode_error(0xF1); // ERROR_NO_ACCESS
            }
        }

        let request = match read_value(&mut Cursor::new(data)) {
            Ok(Value::Array(items)) if items.len() >= 2 => items,
            _ => return encode_error(0xF4), // ERROR_INVALID_DATA
        };

        let peering_key = match &request[0] {
            Value::Binary(b) => b.clone(),
            _ => return encode_error(0xF4),
        };
        let offered_ids: Vec<Vec<u8>> = match &request[1] {
            Value::Array(list) => list.iter()
                .filter_map(|v| match v { Value::Binary(b) => Some(b.clone()), _ => None })
                .collect(),
            _ => Vec::new(),
        };

        // Validate peering key: proves the caller did PoW binding their
        // identity to ours.  Material = our_identity_hash || their_identity_hash.
        let mut peering_id = self.identity.hash.clone().unwrap_or_default();
        peering_id.extend_from_slice(&remote_identity.hash.clone().unwrap_or_default());
        if !lx_stamper::validate_peering_key(&peering_id, &peering_key, self.peering_cost) {
            return encode_error(0xF3); // ERROR_INVALID_KEY
        }

        // Compare offered IDs against our local store; collect the ones we lack.
        let mut wanted = Vec::new();
        for tid in &offered_ids {
            if !self.entries.contains_key(tid) {
                wanted.push(Value::Binary(tid.clone()));
            }
        }

        if wanted.is_empty() {
            encode_value(Value::Boolean(false))
        } else if wanted.len() == offered_ids.len() {
            encode_value(Value::Boolean(true))
        } else {
            encode_value(Value::Array(wanted))
        }
    }

    // ── GET handler ──────────────────────────────────────────────────────────
    //
    // Client GET has two phases:
    //   Phase 1 (wants=nil, haves=nil): List available message transient_ids
    //           for the requesting identity.
    //   Phase 2 (wants=[ids], haves=[ids]): Delete "haves" from the store,
    //           then return the requested "wants" messages up to limit.

    fn handle_get(
        &mut self,
        _path: &str,
        data: &[u8],
        _request_id: &[u8],
        remote_identity: Option<&Identity>,
        _requested_at: f64,
    ) -> Vec<u8> {
        let remote_identity = match remote_identity {
            Some(id) => id,
            None => return encode_error(0xF0),
        };

        // Build the requesting client's lxmf.delivery destination hash
        // so we can match messages stored for that identity.
        let remote_dest = match Destination::new_outbound(
            Some(remote_identity.clone()),
            DestinationType::Single,
            LXMF_APP.to_string(),
            vec!["delivery".to_string()],
        ) {
            Ok(d) => d,
            Err(_) => return encode_error(0xF4),
        };

        let request = match read_value(&mut Cursor::new(data)) {
            Ok(Value::Array(items)) => items,
            _ => return encode_error(0xF4),
        };

        let wants = request.first().cloned().unwrap_or(Value::Nil);
        let haves = request.get(1).cloned().unwrap_or(Value::Nil);
        let client_limit_bytes = request.get(2).and_then(|v| v.as_f64()).map(|v| v * 1000.0);

        // Phase 1: Client sends nil/nil to discover what messages are waiting.
        // Return transient_ids sorted by size (smallest first for efficient pulls).
        if wants == Value::Nil && haves == Value::Nil {
            let mut available: Vec<(Vec<u8>, usize)> = self.entries.iter()
                .filter(|(_, e)| e.destination_hash == remote_dest.hash)
                .map(|(tid, e)| (tid.clone(), e.size))
                .collect();
            available.sort_by_key(|(_, size)| *size);
            let ids: Vec<Value> = available.into_iter()
                .map(|(id, _)| Value::Binary(id))
                .collect();
            return encode_value(Value::Array(ids));
        }

        // Process "haves" — client already has these messages locally.
        // Safe to delete from the propagation store (fire-and-forget; the
        // client accepted responsibility by including them in haves).
        if let Value::Array(haves_list) = haves {
            for value in haves_list {
                if let Value::Binary(tid) = value {
                    if let Some(entry) = self.entries.get(&tid) {
                        if entry.destination_hash == remote_dest.hash {
                            let fp = entry.filepath.clone();
                            self.entries.remove(&tid);
                            let _ = fs::remove_file(&fp);
                        }
                    }
                }
            }
        }

        // Process "wants" — return requested messages, respecting the
        // client's size limit (limit_kb, converted to bytes).
        let mut response_messages = Vec::new();
        if let Value::Array(want_list) = wants {
            let per_message_overhead = 16.0_f64;  // msgpack framing per entry
            let mut cumulative_size = 24.0_f64;  // response header overhead

            for value in want_list {
                if let Value::Binary(tid) = value {
                    if let Some(entry) = self.entries.get(&tid) {
                        if entry.destination_hash == remote_dest.hash {
                            if let Ok(file_data) = fs::read(&entry.filepath) {
                                let lxm_size = file_data.len() as f64;
                                let next_size = cumulative_size + lxm_size + per_message_overhead;
                                if client_limit_bytes.map(|limit| next_size <= limit).unwrap_or(true) {
                                    // Trim off appended stamp before serving.
                                    // Stamps are stored on disk for peer sync
                                    // but clients must not receive them.
                                    let trim_size = file_data.len().saturating_sub(lx_stamper::STAMP_SIZE);
                                    response_messages.push(Value::Binary(file_data[..trim_size].to_vec()));
                                    cumulative_size = next_size;
                                }
                            }
                        }
                    }
                }
            }
        }

        self.messages_served += response_messages.len() as u64;
        encode_value(Value::Array(response_messages))
    }

    // ── Peer sync tick ───────────────────────────────────────────────────────

    /// Called from the main event loop.  Drives outbound peer sync sessions.
    ///
    /// Flow: select best candidate peer with unhandled messages → ensure
    /// peering key is ready → initiate outbound link + OFFER request.
    /// Is the startup backlog still held back from peer sync?
    pub fn backlog_held(&self) -> bool {
        now() - self.started_at < STARTUP_BACKLOG_HOLD_SECS
    }

    /// The ids this peer may be offered right now: during the backlog hold
    /// only messages received since start that it still lacks; afterwards
    /// everything it still lacks. Cheap during the hold because it walks the
    /// fresh list, not the peer's (possibly 150k-entry) queue.
    pub fn sync_pool(&self, peer: &PropPeer) -> Vec<Vec<u8>> {
        Self::sync_pool_for(self.backlog_held(), &self.fresh_since_start, peer)
    }

    /// `sync_pool` without `&self`, for callers already holding a mutable
    /// borrow of one peer.
    pub fn sync_pool_for(backlog_held: bool, fresh_since_start: &[Vec<u8>], peer: &PropPeer) -> Vec<Vec<u8>> {
        if backlog_held {
            fresh_since_start.iter()
                .filter(|tid| peer.unhandled_ids.contains(tid))
                .cloned()
                .collect()
        } else {
            peer.unhandled_ids.to_vec()
        }
    }

    /// Log the hold once and its release once.
    fn note_backlog_hold(&mut self) {
        let held = self.backlog_held();
        if held && !self.backlog_hold_logged {
            log(
                format!(
                    "[lxmf.prop] startup backlog held from peer sync for {:.0}s; messages received from now on sync immediately",
                    STARTUP_BACKLOG_HOLD_SECS
                ),
                LOG_NOTICE, false, false,
            );
            self.backlog_hold_logged = true;
        } else if !held && self.backlog_hold_logged {
            log("[lxmf.prop] startup backlog released to peer sync", LOG_NOTICE, false, false);
            self.backlog_hold_logged = false;
            // No longer consulted once the hold is over; do not let it grow
            // for the rest of the uptime.
            self.fresh_since_start = Vec::new();
            self.fresh_since_start.shrink_to_fit();
        }
    }

    /// May this tick start an outbound peer sync? False once the per-minute
    /// budget is spent. Logs the hold once and the release once, so the log
    /// tells the story without repeating it every 6 s.
    pub fn outbound_sync_allowed(&mut self) -> bool {
        let t = now();
        if t - self.outbound_sync_window_start >= 60.0 {
            self.outbound_sync_window_start = t;
            self.outbound_sync_window_count = 0;
        }
        let held = if self.outbound_sync_window_count >= self.outbound_sync_msgs_per_min {
            Some(format!(
                "budget spent, {}/{} messages this minute",
                self.outbound_sync_window_count, self.outbound_sync_msgs_per_min
            ))
        } else {
            None
        };
        match held {
            Some(reason) => {
                if !self.outbound_sync_hold_logged {
                    log(format!("[lxmf.prop] outbound peer sync held: {reason}"), LOG_NOTICE, false, false);
                    self.outbound_sync_hold_logged = true;
                }
                false
            }
            None => {
                if self.outbound_sync_hold_logged {
                    log("[lxmf.prop] outbound peer sync resumed", LOG_NOTICE, false, false);
                    self.outbound_sync_hold_logged = false;
                }
                true
            }
        }
    }

    pub fn tick_sync(arc: &Arc<Mutex<Self>>) {
        let mut guard = match arc.lock() {
            Ok(g) => g,
            Err(_) => return,
        };

        if now() - guard.last_sync_tick < PEER_SYNC_INTERVAL_SECS {
            return;
        }
        guard.last_sync_tick = now();
        guard.note_backlog_hold();
        if !guard.outbound_sync_allowed() {
            return;
        }

        // Cull non-static peers we haven't heard from in MAX_UNREACHABLE_SECS.
        // Static peers are never culled — they're operator-configured.
        let culled: Vec<Vec<u8>> = guard.peers.iter()
            .filter(|(hash, peer)| {
                now() > peer.last_heard + MAX_UNREACHABLE_SECS
                    && !guard.static_peers.contains(hash)
            })
            .map(|(hash, _)| hash.clone())
            .collect();
        for hash in culled {
            guard.unpeer(&hash);
        }

        // Find the first IDLE peer with unhandled messages, alive, and past
        // its backoff timer.  Only one sync session at a time.
        let sync_candidate: Option<Vec<u8>> = guard.peers.iter()
            .filter(|(_, peer)| {
                peer.state == PropPeer::IDLE
                    && !peer.unhandled_ids.is_empty()
                    && peer.alive
                    && now() >= peer.next_sync_attempt
                    && !guard.sync_pool(peer).is_empty()
            })
            .map(|(hash, _)| hash.clone())
            .next();

        // Debug: log peer states
        for (hash, peer) in &guard.peers {
            if !peer.unhandled_ids.is_empty() || !peer.alive {
                log(
                    format!("[lxmf.prop] tick_sync peer {} alive={} state={} unhandled={} stamp_cost={:?} peer_cost={:?} peering_key_ready={}",
                        hexrep(hash, false), peer.alive, peer.state, peer.unhandled_ids.len(),
                        peer.propagation_stamp_cost, peer.peering_cost, peer.peering_key_ready()),
                    LOG_DEBUG, false, false,
                );
            }
        }

        if let Some(peer_hash) = sync_candidate {
            log(
                format!("[lxmf.prop] tick_sync: found sync candidate {}", hexrep(&peer_hash, false)),
                LOG_NOTICE, false, false,
            );
            // Check if peer needs a peering key — spawn background generation
            let identity_clone = guard.identity.clone();
            let sync_ready = guard.peers.get(&peer_hash).map(|p| p.sync_ready()).unwrap_or(true);
            if !sync_ready {
                // Must drop guard before spawn_peering_key_gen, which re-acquires the lock
                drop(guard);
                Self::spawn_peering_key_gen(arc, &peer_hash, &identity_clone);
                return;
            }

            // Initiate sync — drop the guard before the expensive offer building
            // to avoid blocking client links.  initiate_sync re-acquires the lock
            // internally for each peer access.
            drop(guard);
            Self::initiate_sync_locked(arc, &peer_hash);
            return;
        }

        // Also check for peers that need peering keys generated — spawn background
        let needs_keys: Vec<Vec<u8>> = guard.peers.iter()
            .filter(|(_, peer)| {
                peer.alive && peer.peering_cost.is_some() && !peer.peering_key_ready()
            })
            .map(|(hash, _)| hash.clone())
            .collect();

        let identity_clone = guard.identity.clone();
        // Must drop guard before spawn_peering_key_gen, which re-acquires the lock
        drop(guard);
        for hash in &needs_keys {
            Self::spawn_peering_key_gen(arc, hash, &identity_clone);
        }
    }

    /// Spawn a background thread to generate a peering key for `peer_hash`
    /// without holding the main lock during the expensive PoW computation.
    fn spawn_peering_key_gen(arc: &Arc<Mutex<Self>>, peer_hash: &[u8], router_identity: &Identity) {
        // Collect all inputs we need under the lock
        let (peering_cost, identity_hash, router_hash, dest_hash) = {
            let mut guard = match arc.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            // Dedup: skip if a generation thread is already running for this peer.
            // tick_sync runs every ~6 s; cost-N PoW takes seconds. Without this
            // guard, concurrent generations stack up and pin the CPU.
            // // NEVER REMOVE EVER
            if guard.in_flight_keys.contains(peer_hash) {
                return;
            }
            let peer = match guard.peers.get(peer_hash) {
                Some(p) => p,
                None => return,
            };
            let peering_cost = match peer.peering_cost {
                Some(c) => c,
                None => return,
            };
            if peer.peering_key_ready() {
                return;
            }
            let identity = match Identity::recall(&peer.destination_hash) {
                Some(id) => id,
                None => {
                    log(
                        format!("[lxmf.prop] cannot recall identity for peer {}", hexrep(&peer.destination_hash, false)),
                        LOG_WARNING, false, false,
                    );
                    return;
                }
            };
            let identity_hash = match identity.hash.as_ref() {
                Some(h) => h.clone(),
                None => return,
            };
            let router_hash = match router_identity.hash.as_ref() {
                Some(h) => h.clone(),
                None => return,
            };
            let dest_hash = peer.destination_hash.clone();
            // Mark in-flight before releasing the lock so concurrent callers bail.
            guard.in_flight_keys.insert(dest_hash.clone());
            (peering_cost, identity_hash, router_hash, dest_hash)
        };
        // Lock is dropped here — generate stamp without holding it

        let weak = Arc::downgrade(arc);
        std::thread::spawn(move || {
            log(
                format!("[lxmf.prop] generating peering key for {} (cost {}) in background...",
                    hexrep(&dest_hash, false), peering_cost),
                LOG_NOTICE, false, false,
            );
            let mut material = Vec::with_capacity(identity_hash.len() + router_hash.len());
            material.extend_from_slice(&identity_hash);
            material.extend_from_slice(&router_hash);
            let (key, value) = lx_stamper::generate_stamp(
                &material,
                peering_cost,
                lx_stamper::WORKBLOCK_EXPAND_ROUNDS_PEERING,
            );
            if let Some(arc) = weak.upgrade() {
                if let Ok(mut guard) = arc.lock() {
                    // Always clear the in-flight marker, success or failure.
                    guard.in_flight_keys.remove(&dest_hash);
                    if value >= peering_cost {
                        if let Some(key) = key {
                            if let Some(peer) = guard.peers.get_mut(&dest_hash) {
                                peer.peering_key = Some((key, value));
                                log(
                                    format!("[lxmf.prop] peering key generated for {}", hexrep(&dest_hash, false)),
                                    LOG_NOTICE, false, false,
                                );
                            }
                        }
                    }
                }
            }
        });
    }

    /// Initiate an outbound sync session with a peer (lock-free wrapper).
    ///
    /// Re-acquires the lock for each peer access to avoid blocking client
    /// links during the expensive offer building.
    fn initiate_sync_locked(arc: &Arc<Mutex<Self>>, peer_hash: &[u8]) {
        log(
            format!("[lxmf.prop] initiate_sync starting for {}", hexrep(peer_hash, false)),
            LOG_DEBUG, false, false,
        );

        // Phase 1: Collect peer data we need (short lock)
        let (unhandled_ids, peering_key_ready) = {
            let guard = match arc.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let peer = match guard.peers.get(peer_hash) {
                Some(p) => p,
                None => { log("[lxmf.prop] sync: peer not found", LOG_DEBUG, false, false); return; }
            };
            if peer.state != PropPeer::IDLE {
                log(format!("[lxmf.prop] sync: peer state={} not IDLE", peer.state), LOG_DEBUG, false, false);
                return;
            }
            (guard.sync_pool(peer), peer.peering_key.is_some())
        };

        if !peering_key_ready {
            return;
        }

        // Phase 2: Build offer WITHOUT holding the lock (expensive operation)
        let mut entries_with_weight: Vec<(Vec<u8>, f64, u64)> = Vec::new();
        {
            let guard = match arc.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            for tid in &unhandled_ids {
                if let Some(entry) = guard.entries.get(tid) {
                    let age = ((now() - entry.received) / 86400.0 / 4.0).max(1.0);
                    let weight = age * entry.size as f64;
                    entries_with_weight.push((tid.clone(), weight, entry.size as u64));
                }
            }
        }

        entries_with_weight.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        let per_message_overhead = 16.0;
        let mut cumulative_size = 24.0;
        let mut offer_ids = Vec::new();

        {
            let mut guard = match arc.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            let peer = match guard.peers.get_mut(peer_hash) {
                Some(p) => p,
                None => return,
            };

            for (tid, _, size) in &entries_with_weight {
                if offer_ids.len() >= MAX_OFFER_IDS {
                    break;
                }
                let msg_size = *size as f64 + per_message_overhead;
                let next_size = cumulative_size + msg_size;

                if let Some(limit) = peer.propagation_transfer_limit {
                    if msg_size > limit * 1000.0 {
                        peer.mark_handled(tid);
                        continue;
                    }
                }

                if let Some(sync_limit) = peer.propagation_sync_limit {
                    if next_size >= sync_limit * 1000.0 {
                        continue;
                    }
                }

                cumulative_size += msg_size;
                offer_ids.push(tid.clone());
            }
        }

        if offer_ids.is_empty() {
            return;
        }

        // Phase 3: Send offer (short lock)
        let mut guard = match arc.lock() {
            Ok(g) => g,
            Err(_) => return,
        };

        if let Some(handle) = AppLinks::get_handle(peer_hash)
            .filter(|link| link.status() == reticulum_rust::link::STATE_ACTIVE)
        {
            log(
                format!(
                    "[lxmf.prop] reusing AppLinks persistent link for {}",
                    hexrep(peer_hash, false),
                ),
                LOG_DEBUG,
                false,
                false,
            );
            guard.send_offer_on_link(&handle, peer_hash, &offer_ids);
            return;
        }

        AppLinks::open_persistent(peer_hash, LXMF_APP, &[PROP_ASPECT]);
    }

    /// Initiate an outbound sync session with a peer.
    ///
    /// Builds an OFFER payload containing unhandled transient_ids (sorted by
    /// weight = age × size, lightest first) and runs the OFFER request over
    /// the shared AppLinks-owned persistent `lxmf.propagation` link once it is
    /// active.
    fn initiate_sync(&mut self, peer_hash: &[u8]) {
        log(
            format!("[lxmf.prop] initiate_sync starting for {}", hexrep(peer_hash, false)),
            LOG_DEBUG, false, false,
        );
        let backlog_held = self.backlog_held();
        let fresh_since_start = if backlog_held { self.fresh_since_start.clone() } else { Vec::new() };
        let peer = match self.peers.get_mut(peer_hash) {
            Some(p) => p,
            None => { log("[lxmf.prop] sync: peer not found", LOG_DEBUG, false, false); return; }
        };

        peer.last_sync_attempt = now();

        if peer.state != PropPeer::IDLE {
            log(format!("[lxmf.prop] sync: peer state={} not IDLE", peer.state), LOG_DEBUG, false, false);
            return;
        }

        // Build offer candidates from the current peer state.
        match &peer.peering_key {
            Some(_) => {}
            None => return,
        };

        // Gather unhandled IDs, sorted by weight (age × size, lightest first).
        // This ensures small/recent messages are offered first, and oversized
        // messages that exceed the peer's transfer limit are auto-handled.
        let mut entries_with_weight: Vec<(Vec<u8>, f64, u64)> = Vec::new();
        let pool = Self::sync_pool_for(backlog_held, &fresh_since_start, peer);
        for tid in pool.iter() {
            if let Some(entry) = self.entries.get(tid) {
                let age = ((now() - entry.received) / 86400.0 / 4.0).max(1.0);
                let weight = age * entry.size as f64;
                entries_with_weight.push((tid.clone(), weight, entry.size as u64));
            }
        }
        entries_with_weight.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));

        let per_message_overhead = 16.0;
        let mut cumulative_size = 24.0;
        let mut offer_ids = Vec::new();

        for (tid, _, size) in &entries_with_weight {
            // Cap the number of offered IDs to stay within the 5-second send
            // budget.  With 197k+ messages the sort+filter alone takes >5s.
            if offer_ids.len() >= MAX_OFFER_IDS {
                break;
            }
            let msg_size = *size as f64 + per_message_overhead;
            let next_size = cumulative_size + msg_size;

            if let Some(limit) = peer.propagation_transfer_limit {
                if msg_size > limit * 1000.0 {
                    // Message too big for this peer, mark handled
                    peer.mark_handled(tid);
                    continue;
                }
            }

            if let Some(sync_limit) = peer.propagation_sync_limit {
                if next_size >= sync_limit * 1000.0 {
                    continue;
                }
            }

            cumulative_size += msg_size;
            offer_ids.push(tid.clone());
        }

        if offer_ids.is_empty() {
            return;
        }

        if let Some(handle) = AppLinks::get_handle(peer_hash)
            .filter(|link| link.status() == reticulum_rust::link::STATE_ACTIVE)
        {
            log(
                format!(
                    "[lxmf.prop] reusing AppLinks persistent link for {}",
                    hexrep(peer_hash, false),
                ),
                LOG_DEBUG,
                false,
                false,
            );
            self.send_offer_on_link(&handle, peer_hash, &offer_ids);
            return;
        }

        AppLinks::open_persistent(peer_hash, LXMF_APP, &[PROP_ASPECT]);
        log(
            format!(
                "[lxmf.prop] requested AppLinks persistent open for {}",
                hexrep(peer_hash, false),
            ),
            LOG_DEBUG,
            false,
            false,
        );
    }

    /// Send the OFFER request on an already-established link.
    ///
    /// Sets up response/failure callbacks that drive the rest of the sync
    /// session (handle_offer_response → send_messages_to_peer).
    fn send_offer_on_link(&mut self, link: &LinkHandle, peer_hash: &[u8], offer_ids: &[Vec<u8>]) {
        let peer = match self.peers.get_mut(peer_hash) {
            Some(p) => p,
            None => return,
        };

        peer.link = Some(link.clone());
        peer.last_offer = offer_ids.to_vec();
        peer.state = PropPeer::LINK_READY;
        peer.alive = true;
        peer.last_heard = now();
        peer.sync_backoff = 0.0;

        let current_link_id = link.link_id();
        let already_identified = peer
            .identified_link_id
            .as_ref()
            .map(|id| id == &current_link_id)
            .unwrap_or(false);

        if !already_identified {
            if let Err(e) = link.identify(&self.identity) {
                log(
                    format!("[lxmf.prop] identify before offer failed: {e}"),
                    LOG_WARNING,
                    false,
                    false,
                );
                link.teardown();
                peer.state = PropPeer::IDLE;
                peer.link = None;
                peer.identified_link_id = None;
                return;
            }

            peer.identified_link_id = Some(current_link_id);
            peer.state = PropPeer::IDLE;
            return;
        }

        let (peering_key, _) = match &peer.peering_key {
            Some(pk) => pk.clone(),
            None => return,
        };

        let offer = Value::Array(vec![
            Value::Binary(peering_key),
            Value::Array(offer_ids.iter().map(|id| Value::Binary(id.clone())).collect()),
        ]);
        let mut offer_data = Vec::new();
        let _ = write_value(&mut offer_data, &offer);

        // Set up response callback
        let weak = self.self_handle.clone();
        let peer_hash_clone = peer_hash.to_vec();
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        let offer_sent_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0);
        let response_cb: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>> = Some(Arc::new({
            let weak = weak.clone();
            let ph = peer_hash_clone.clone();
            move |receipt: RequestReceipt| {
                // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
                reticulum_rust::send_assertion::assert_send_completed_in_time(
                    "lxmf.propagation.offer", offer_sent_at,
                );
                if let Some(arc) = weak.as_ref().and_then(|w| w.upgrade()) {
                    if let Ok(mut node) = arc.lock() {
                        node.handle_offer_response(&ph, receipt);
                    }
                }
            }
        }));

        let failed_cb: Option<Arc<dyn Fn(RequestReceipt) + Send + Sync>> = Some(Arc::new({
            let weak = weak.clone();
            let ph = peer_hash_clone.clone();
            let link = link.clone();
            move |_receipt: RequestReceipt| {
                link.teardown();
                if let Some(arc) = weak.as_ref().and_then(|w| w.upgrade()) {
                    if let Ok(mut node) = arc.lock() {
                        if let Some(peer) = node.peers.get_mut(&ph) {
                            peer.state = PropPeer::IDLE;
                            peer.link = None;
                            peer.identified_link_id = None;
                        }
                    }
                }
            }
        }));

        match link.request(
            OFFER_PATH.to_string(),
            offer_data,
            response_cb,
            failed_cb,
            None,
        ) {
            Ok(_) => {
                peer.state = PropPeer::REQUEST_SENT;
            }
            Err(e) => {
                log(format!("[lxmf.prop] offer request failed: {e}"), LOG_WARNING, false, false);
                link.teardown();
                peer.state = PropPeer::IDLE;
                peer.link = None;
            }
        }
    }

    /// Process the peer's response to our OFFER.
    ///
    /// The response is one of:
    ///   - `false` (“have all”) — mark all offered IDs as handled.
    ///   - `true`  (“want all”) — send every offered message.
    ///   - `[id, ...]` (“want some”) — send only listed IDs; mark rest handled.
    ///   - Integer error code — diagnose and possibly unpeer.
    fn handle_offer_response(&mut self, peer_hash: &[u8], receipt: RequestReceipt) {
        let response = match receipt.response {
            Some(data) => read_value(&mut Cursor::new(data)).ok(),
            None => None,
        };

        let peer = match self.peers.get_mut(peer_hash) {
            Some(p) => p,
            None => return,
        };

        peer.state = PropPeer::RESPONSE_RECEIVED;

        // Check for error codes from the remote peer.
        // 0xF0 = no identity (transient, retry); 0xF1 = access denied (unpeer);
        // 0xF3 = invalid peering key (regenerate).
        if let Some(Value::Integer(code)) = response.as_ref() {
            let code = code.as_i64().unwrap_or(0) as u8;
            match code {
                0xF0 => {
                    log("[lxmf.prop] remote: no identity, retrying...", LOG_WARNING, false, false);
                    peer.identified_link_id = None;
                    peer.state = PropPeer::IDLE;
                    return;
                }
                0xF1 => {
                    log("[lxmf.prop] remote: access denied, breaking peering", LOG_WARNING, false, false);
                    let hash = peer_hash.to_vec();
                    self.unpeer(&hash);
                    return;
                }
                0xF3 => {
                    log("[lxmf.prop] remote: invalid peering key, regenerating", LOG_WARNING, false, false);
                    peer.peering_key = None;
                    peer.identified_link_id = None;
                    peer.state = PropPeer::IDLE;
                    return;
                }
                _ => {}
            }
        }

        let last_offer = peer.last_offer.clone();

        match response {
            Some(Value::Boolean(false)) => {
                // Peer has all messages — mark them handled
                for tid in &last_offer {
                    peer.mark_handled(tid);
                }
                log(
                    format!("[lxmf.prop] peer {} has all {} offered messages", hexrep(peer_hash, false), last_offer.len()),
                    LOG_DEBUG, false, false,
                );
            }
            Some(Value::Boolean(true)) => {
                // Peer wants all messages — send them via resource
                log(
                    format!("[lxmf.prop] peer {} wants all {} messages, sending...", hexrep(peer_hash, false), last_offer.len()),
                    LOG_DEBUG, false, false,
                );
                self.send_messages_to_peer(peer_hash, &last_offer);
            }
            Some(Value::Array(list)) => {
                // Peer wants specific messages
                let wanted: Vec<Vec<u8>> = list.iter()
                    .filter_map(|v| match v { Value::Binary(b) => Some(b.clone()), _ => None })
                    .collect();

                // Mark unwanted as handled
                for tid in &last_offer {
                    if !wanted.contains(tid) {
                        if let Some(peer) = self.peers.get_mut(peer_hash) {
                            peer.mark_handled(tid);
                        }
                    }
                }

                log(
                    format!("[lxmf.prop] peer {} wants {}/{} messages", hexrep(peer_hash, false), wanted.len(), last_offer.len()),
                    LOG_DEBUG, false, false,
                );
                self.send_messages_to_peer(peer_hash, &wanted);
            }
            _ => {
                log("[lxmf.prop] unexpected offer response", LOG_WARNING, false, false);
            }
        }

        // Reset peer state for next cycle
        if let Some(peer) = self.peers.get_mut(peer_hash) {
            peer.state = PropPeer::IDLE;
            peer.link = None;
        }
    }

    /// Package and send requested messages to a peer over the established link.
    ///
    /// Messages are bundled as a msgpack array `[type_marker, [lxmf_data, ...]]`
    /// matching the client PUT wire format, so the remote peer's
    /// `on_propagation_packet` callback ingests them directly.
    ///
    /// Delivery is fire-and-forget — the IDs are marked handled optimistically
    /// before the packet is sent.  If the packet is lost the peer will re-offer
    /// those IDs on the next sync cycle.
    fn send_messages_to_peer(&mut self, peer_hash: &[u8], transient_ids: &[Vec<u8>]) {
        // Collect message data
        let mut lxm_list = Vec::new();
        for tid in transient_ids {
            if let Some(entry) = self.entries.get(tid) {
                if let Ok(data) = fs::read(&entry.filepath) {
                    lxm_list.push(Value::Binary(data));
                }
            }
        }

        if lxm_list.is_empty() {
            return;
        }

        let link = match self.peers.get(peer_hash).and_then(|p| p.link.clone()) {
            Some(l) => l,
            None => return,
        };

        // Package as a msgpack array: [type_marker, [lxmf_data, ...]]
        // This is the same format as client PUT packets, so the remote's
        // on_propagation_packet callback will ingest the messages correctly.
        let transfer = Value::Array(vec![
            Value::Integer(0.into()), // type marker (same as client PUT)
            Value::Array(lxm_list),
        ]);
        let mut transfer_data = Vec::new();
        let _ = write_value(&mut transfer_data, &transfer);

        let msg_count = transient_ids.len();
        let peer_hash_str = hexrep(peer_hash, false);

        // Mark IDs as handled before sending (optimistic delivery).
        // If the packet is lost, the peer will re-offer those IDs on the next
        // sync cycle and we will resend.
        if let Some(peer) = self.peers.get_mut(peer_hash) {
            for tid in transient_ids {
                peer.mark_handled(tid);
            }
        }

        // Send as a raw link DATA packet.  This routes to the remote's
        // callbacks.packet handler (on_propagation_packet), NOT to any request
        // handler — which is what we need for the client PUT wire format.
        match link.send_packet(&transfer_data) {
            Ok(_) => {
                self.outbound_sync_window_count += msg_count as u64;
                log(
                    format!("[lxmf.prop] sent {} message(s) to peer {}", msg_count, peer_hash_str),
                    LOG_NOTICE, false, false,
                );
            }
            Err(e) => {
                log(format!("[lxmf.prop] message send failed for {peer_hash_str}: {e}"),
                    LOG_WARNING, false, false);
                link.teardown();
            }
        }

        if let Some(peer) = self.peers.get_mut(peer_hash) {
            peer.link = None;
        }
    }

    // ── Persistence ──────────────────────────────────────────────────────────

    /// Persist peer state to disk so backoff timers, peering keys, and
    /// handled/unhandled ID sets survive restarts.
    pub fn save_peers(&self) {
        let peers_path = self.storage_path.join("peers");
        let mut serialised = Vec::new();
        for (hash, peer) in &self.peers {
            let peer_data = PeerState {
                destination_hash: hash.clone(),
                alive: peer.alive,
                last_heard: peer.last_heard,
                peering_timebase: peer.peering_timebase,
                propagation_stamp_cost: peer.propagation_stamp_cost,
                propagation_stamp_flexibility: peer.propagation_stamp_flexibility,
                peering_cost: peer.peering_cost,
                propagation_transfer_limit: peer.propagation_transfer_limit,
                propagation_sync_limit: peer.propagation_sync_limit,
                peering_key: peer.peering_key.clone(),
                metadata: peer.metadata.clone(),
                sync_transfer_rate: peer.sync_transfer_rate,
                handled_ids: peer.handled_ids.to_vec(),
                unhandled_ids: peer.unhandled_ids.to_vec(),
            };
            if let Ok(bytes) = rmp_serde::to_vec(&peer_data) {
                serialised.push(bytes);
            }
        }
        if let Ok(data) = rmp_serde::to_vec(&serialised) {
            let _ = fs::write(&peers_path, data);
        }
    }

    /// Load persisted peer state from disk.  Rebuilds handled/unhandled sets
    /// by filtering against the current messagestore (expired messages that
    /// were evicted while offline are silently dropped from the lists).
    fn load_peers(&mut self) {
        let peers_path = self.storage_path.join("peers");
        let data = match fs::read(&peers_path) {
            Ok(d) => d,
            Err(_) => return,
        };
        if data.is_empty() {
            return;
        }

        let serialised: Vec<Vec<u8>> = match rmp_serde::from_slice(&data) {
            Ok(v) => v,
            Err(e) => {
                log(format!("[lxmf.prop] cannot load peers: {e}"), LOG_WARNING, false, false);
                return;
            }
        };

        for peer_bytes in serialised {
            let state: PeerState = match rmp_serde::from_slice(&peer_bytes) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let mut peer = PropPeer::new(state.destination_hash.clone());
            peer.alive = state.alive;
            peer.last_heard = state.last_heard;
            peer.peering_timebase = state.peering_timebase;
            peer.propagation_stamp_cost = state.propagation_stamp_cost;
            peer.propagation_stamp_flexibility = state.propagation_stamp_flexibility;
            peer.peering_cost = state.peering_cost;
            peer.propagation_transfer_limit = state.propagation_transfer_limit;
            peer.propagation_sync_limit = state.propagation_sync_limit;
            peer.peering_key = state.peering_key;
            peer.metadata = state.metadata;
            peer.sync_transfer_rate = state.sync_transfer_rate;

            // Rebuild handled/unhandled based on what's still in the store
            for tid in state.handled_ids {
                if self.entries.contains_key(&tid) {
                    peer.handled_ids.push_unique(tid);
                }
            }
            for tid in state.unhandled_ids {
                if self.entries.contains_key(&tid) {
                    peer.unhandled_ids.push_unique(tid);
                }
            }

            self.peers.insert(state.destination_hash, peer);
        }

        log(
            format!("[lxmf.prop] loaded {} peers", self.peers.len()),
            LOG_NOTICE, false, false,
        );
    }

    pub fn save_stats(&self) {
        let stats_path = self.storage_path.join("node_stats");
        let mut stats: HashMap<String, u64> = HashMap::new();
        stats.insert("messages_received".to_string(), self.messages_received);
        stats.insert("messages_served".to_string(), self.messages_served);
        if let Ok(data) = rmp_serde::to_vec(&stats) {
            let _ = fs::write(&stats_path, data);
        }
    }

    fn load_stats(&mut self) {
        let stats_path = self.storage_path.join("node_stats");
        if let Ok(data) = fs::read(&stats_path) {
            if let Ok(stats) = rmp_serde::from_slice::<HashMap<String, u64>>(&data) {
                if let Some(v) = stats.get("messages_received") {
                    self.messages_received = *v;
                }
                if let Some(v) = stats.get("messages_served") {
                    self.messages_served = *v;
                }
            }
        }
    }

    /// Save all propagation node state. Called during shutdown.
    pub fn save_all(&self) {
        self.save_peers();
        self.save_stats();
        log("[lxmf.prop] state persisted", LOG_NOTICE, false, false);
    }

    // ── Distro ingest ────────────────────────────────────────────────────────

    // ── Get statistics ───────────────────────────────────────────────────────

    /// Return node statistics: (received, served, stored_count, peer_count).
    pub fn get_stats(&self) -> (u64, u64, usize, usize) {
        (self.messages_received, self.messages_served, self.entries.len(), self.peers.len())
    }
}

// ── Serialisable peer state ──────────────────────────────────────────────────

/// Subset of `PropPeer` fields that survive serialisation to disk.
/// Volatile fields (link, state, transferring) are not persisted.
#[derive(serde::Serialize, serde::Deserialize)]
struct PeerState {
    destination_hash: Vec<u8>,
    alive: bool,
    last_heard: f64,
    peering_timebase: f64,
    propagation_stamp_cost: Option<u32>,
    propagation_stamp_flexibility: Option<u32>,
    peering_cost: Option<u32>,
    propagation_transfer_limit: Option<f64>,
    propagation_sync_limit: Option<f64>,
    peering_key: Option<(Vec<u8>, u32)>,
    metadata: Option<Vec<u8>>,
    sync_transfer_rate: f64,
    handled_ids: Vec<Vec<u8>>,
    unhandled_ids: Vec<Vec<u8>>,
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Encode an rmpv Value to bytes.  Shared helper for OFFER/GET response encoding.
fn encode_value(value: Value) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = write_value(&mut buf, &value);
    buf
}

/// Encode an error code (0xF0–0xFF) as a msgpack Integer.
///
/// Shared with the `/rfed/pull` handlers in destinations.rs: pull is the one
/// rfed request family that authenticates by link identity (SPEC.md §"PULL
/// paging"), and the reference implementation answers an unidentified caller
/// with an error code — LXMF/LXMRouter.py:1445 `return ERROR_NO_IDENTITY` —
/// rather than staying silent.
pub(crate) fn encode_error(code: u8) -> Vec<u8> {
    encode_value(Value::Integer((code as i64).into()))
}

fn enqueue_distro_misses(
    deferred_queue: Option<&Arc<Mutex<crate::deferred_queue::DeferredQueue>>>,
    missed: Vec<Vec<u8>>,
    distro_hash: &[u8],
    lxmf_data: &[u8],
) {
    let Some(deferred_queue) = deferred_queue else {
        return;
    };
    let Ok(mut queue) = deferred_queue.lock() else {
        return;
    };
    for device_hash in missed {
        queue.enqueue(
            device_hash,
            distro_hash.to_vec(),
            lxmf_data.to_vec(),
            DISTRO_DEFERRED_QUEUE_LIMIT,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    // ── The propagation node lock: who may hold it, and for how long ──────
    //
    // `/get` and `/offer` wait on the node mutex. In production `/get` waited
    // 73 s and 182 s for it behind message ingest, which held it for a whole
    // batch: stamp validation, a disk write and a linear scan of every peer's
    // queue per message, and live delivery. See `ingest_propagation_batch`.
    /// The outbound sync gate: a restart no longer opens with a full-rate
    /// sync, and the aggregate push to peers is budgeted per minute.
    mod outbound_sync_gate_tests {
        use super::ingest_lock_scope_tests::test_node;
        use super::super::*;

        fn entry(received: f64) -> PropagationEntry {
            PropagationEntry { destination_hash: vec![0; 16], filepath: String::new(), received, size: 100, stamp_value: 0 }
        }

        #[test]
        fn backlog_is_held_for_an_hour_but_fresh_messages_sync_at_once() {
            let node = test_node("backlog");
            let mut g = node.lock().unwrap();
            let old = vec![1u8; 32];
            let fresh = vec![2u8; 32];
            let t0 = g.started_at;
            g.entries.insert(old.clone(), entry(t0 - 100.0));
            g.entries.insert(fresh.clone(), entry(t0 + 1.0));
            g.fresh_since_start.push(fresh.clone());
            let mut peer = PropPeer::new(vec![9u8; 16]);
            peer.add_unhandled(old.clone());
            peer.add_unhandled(fresh.clone());
            assert!(g.backlog_held());
            assert_eq!(g.sync_pool(&peer), vec![fresh.clone()], "only the fresh message is offered during the hold");
            let mut backlog_only = PropPeer::new(vec![8u8; 16]);
            backlog_only.add_unhandled(old.clone());
            assert!(g.sync_pool(&backlog_only).is_empty(), "a peer lacking only backlog is not synced yet");
            g.started_at = now() - STARTUP_BACKLOG_HOLD_SECS - 1.0;
            assert!(!g.backlog_held());
            let pool = g.sync_pool(&peer);
            assert!(pool.contains(&old) && pool.contains(&fresh), "after the hold everything the peer lacks is offered");
        }

        #[test]
        fn outbound_sync_is_not_gated_by_the_backlog_hold() {
            let node = test_node("fresh_allowed");
            let mut g = node.lock().unwrap();
            assert!(g.backlog_held());
            assert!(g.outbound_sync_allowed(), "the budget alone gates the tick; fresh messages need no wait");
        }

        #[test]
        fn sync_is_held_once_the_minute_budget_is_spent_and_resets_next_minute() {
            let node = test_node("budget");
            let mut g = node.lock().unwrap();
            g.outbound_sync_window_count = g.outbound_sync_msgs_per_min;
            assert!(!g.outbound_sync_allowed(), "budget spent holds sync");
            assert!(g.outbound_sync_hold_logged, "the hold is logged once");
            assert!(!g.outbound_sync_allowed(), "still held within the window");
            g.outbound_sync_window_start = now() - 61.0;
            assert!(g.outbound_sync_allowed(), "a new minute resets the budget");
            assert_eq!(g.outbound_sync_window_count, 0);
            assert!(!g.outbound_sync_hold_logged, "the release clears the hold flag");
        }
    }

    mod ingest_lock_scope_tests {
        use super::super::*;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Instant;

        pub(super) fn test_node(tag: &str) -> Arc<Mutex<LxmfPropagationNode>> {
            let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let dir = std::env::temp_dir().join(format!("rfed_prop_{tag}_{unique}"));
            let config = NodeConfig {
                config_dir: dir.clone(),
                rns_config_dir: None,
                identity_file: dir.join("identity"),
                display_name: "test".into(),
                announce_interval_secs: 600,
                announce_at_start: false,
                default_policy: crate::config::TierPolicy::default(),
                vip_policy: crate::config::TierPolicy::vip_default(),
                vip_subscribers: Vec::new(),
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
                lxmf_propagation_enabled: true,
                lxmf_propagation_autopeer: false,
                lxmf_propagation_peers: Vec::new(),
            };
            LxmfPropagationNode::new(
                Identity::new(true),
                &config,
                Arc::new(Mutex::new(NotifyRegistry::load(dir.join("notify.rmp")))),
                Arc::new(Mutex::new(PropagationStreamRegistry::default())),
                Arc::new(Mutex::new(LinkSessionRegistry::default())),
                None, None, None, None,
            )
            .expect("propagation node")
        }

        /// A peer sync batch in the propagation wire format. The stamps are
        /// junk — every message will be rejected — which is all this needs:
        /// the cost of a stamp is validating it, valid or not.
        fn batch(messages: usize) -> Vec<u8> {
            let payloads: Vec<Value> = (0..messages)
                .map(|n| Value::Binary((0..320usize).map(|i| (i * 31 + n * 7) as u8).collect()))
                .collect();
            let mut out = Vec::new();
            write_value(&mut out, &Value::Array(vec![Value::F64(0.0), Value::Array(payloads)])).unwrap();
            out
        }

        #[test]
        fn get_is_served_while_a_batch_is_being_ingested() {
            let node = test_node("get_during_ingest");
            let ingesting = Arc::new(AtomicBool::new(true));

            let ingest_node = node.clone();
            let ingest_flag = ingesting.clone();
            let ingest = std::thread::spawn(move || {
                let started = Instant::now();
                LxmfPropagationNode::ingest_propagation_batch(&ingest_node, &batch(64));
                ingest_flag.store(false, Ordering::SeqCst);
                started.elapsed()
            });

            // Exactly what the registered `/get` callback does, for as long as
            // the ingest runs. A request is judged by when it was ASKED: one
            // asked mid-ingest and answered only after the ingest let go of the
            // lock is precisely the failure, and must not be discarded for
            // having finished late.
            let mut served_during_ingest = 0usize;
            let mut worst_wait = 0.0f64;
            while ingesting.load(Ordering::SeqCst) {
                let asked = Instant::now();
                let response = lock_node(&node, "/get (test)")
                    .map(|mut n| n.handle_get("", &[], &[], None, 0.0))
                    .expect("node lock");
                assert!(!response.is_empty(), "/get answers even an unidentified caller");
                served_during_ingest += 1;
                worst_wait = worst_wait.max(asked.elapsed().as_secs_f64());
                std::thread::yield_now();
            }
            let ingest_took = ingest.join().expect("ingest thread").as_secs_f64();

            assert!(
                ingest_took > 4.0 * NODE_LOCK_WAIT_WARN_SECS,
                "the ingest only took {ingest_took:.2}s — too short to prove anything; use a bigger batch"
            );
            assert!(
                worst_wait < NODE_LOCK_WAIT_WARN_SECS,
                "/get waited {worst_wait:.2}s for the node lock during a {ingest_took:.2}s ingest \
                 ({served_during_ingest} served). Something slow is back under the lock."
            );
        }

        /// Source-level guard, in the style of `fanout_lock_scope_tests`: stamp
        /// validation must never be reachable from a method that holds the
        /// node (`&self` / `&mut self`), because every caller of such a method
        /// holds the node lock.
        #[test]
        fn stamp_validation_is_never_called_with_the_node_borrowed() {
            let source = include_str!("lxmf_propagation.rs");
            let production = &source[..source.find("#[cfg(test)]").expect("test module")];
            let mut calls = 0;
            let mut offset = 0;
            while let Some(found) = production[offset..].find("validate_pn_stamps(") {
                let at = offset + found;
                let fn_start = production[..at].rfind("\n    fn ").max(production[..at].rfind("\n    pub(crate) fn "))
                    .expect("enclosing fn");
                let signature = &production[fn_start..production[fn_start..].find('{').map(|i| fn_start + i).unwrap()];
                assert!(
                    !signature.contains("self"),
                    "validate_pn_stamps is called from a method that borrows the node:{signature}"
                );
                calls += 1;
                offset = at + 1;
            }
            assert!(calls > 0, "validate_pn_stamps is no longer called at all — this guard needs updating");
        }
    }

    mod batch_decode_tests {
        use super::super::*;

        fn batch(entries: Vec<Value>) -> Vec<u8> {
            let mut out = Vec::new();
            write_value(&mut out, &Value::Array(vec![Value::F64(0.0), Value::Array(entries)])).unwrap();
            out
        }

        #[test]
        fn bin_entries_are_messages() {
            let m = decode_propagation_batch(&batch(vec![Value::Binary(vec![1; 40]), Value::Binary(vec![2; 40])])).unwrap();
            assert_eq!(m.len(), 2);
        }

        #[test]
        fn str_entries_are_dropped_not_messages() {
            // PyPI msgpack.packb(bytes) without use_bin_type=True produces exactly this.
            let m = decode_propagation_batch(&batch(vec![Value::String("x".repeat(40).into())])).unwrap();
            assert!(m.is_empty(), "a str entry is not a message");
        }

        #[test]
        fn a_non_batch_is_none() {
            let mut out = Vec::new();
            write_value(&mut out, &Value::Integer(7.into())).unwrap();
            assert!(decode_propagation_batch(&out).is_none());
        }
    }

    mod id_queue_tests {
        use super::super::IdQueue;

        fn id(n: u8) -> Vec<u8> { vec![n; 32] }

        #[test]
        fn keeps_insertion_order_and_refuses_duplicates() {
            let mut q = IdQueue::default();
            assert!(q.push_unique(id(3)));
            assert!(q.push_unique(id(1)));
            assert!(!q.push_unique(id(3)), "a duplicate is not added");
            assert!(q.push_unique(id(2)));
            assert_eq!(q.to_vec(), vec![id(3), id(1), id(2)]);
            assert_eq!(q.len(), 3);
        }

        #[test]
        fn remove_keeps_the_order_of_the_rest() {
            let mut q = IdQueue::default();
            for n in 1..=4 { q.push_unique(id(n)); }
            assert!(q.remove(&id(2)));
            assert!(!q.remove(&id(2)), "already gone");
            assert!(!q.contains(&id(2)));
            assert_eq!(q.to_vec(), vec![id(1), id(3), id(4)]);
            // A removed id may come back, and goes to the end.
            assert!(q.push_unique(id(2)));
            assert_eq!(q.to_vec(), vec![id(1), id(3), id(4), id(2)]);
        }

        #[test]
        fn a_peer_does_not_requeue_what_it_already_handled() {
            let mut peer = super::super::PropPeer::new(vec![9; 16]);
            peer.add_unhandled(id(1));
            peer.mark_handled(&id(1));
            peer.add_unhandled(id(1));
            assert!(peer.unhandled_ids.is_empty());
            assert!(peer.handled_ids.contains(&id(1)));
        }

        /// The regression this type exists for: queueing one message for every
        /// peer must not get slower as the queues grow.
        #[test]
        fn queueing_stays_cheap_at_production_scale() {
            let mut peers: Vec<super::super::PropPeer> =
                (0..20).map(|i| super::super::PropPeer::new(vec![i as u8; 16])).collect();
            let wide = |n: u32| { let mut v = vec![0u8; 32]; v[..4].copy_from_slice(&n.to_be_bytes()); v };
            for p in peers.iter_mut() { for n in 0..150_000u32 { p.add_unhandled(wide(n)); } }

            let started = std::time::Instant::now();
            for n in 0..200u32 { for p in peers.iter_mut() { p.add_unhandled(wide(150_000 + n)); } }
            let per_message_ms = started.elapsed().as_secs_f64() * 1000.0 / 200.0;
            // The Vec version measured 38 ms per message here in a debug build.
            assert!(per_message_ms < 2.0, "queueing for 20 peers took {per_message_ms:.2} ms per message");
        }
    }

    #[test]
    fn distro_misses_are_queued_for_pull() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rfed_distro_deferred_{unique}.rmp"));
        let queue = Arc::new(Mutex::new(crate::deferred_queue::DeferredQueue::load(path.clone())));
        let device_hash = vec![0x11; 16];
        let distro_hash = vec![0x22; 16];
        let lxmf_data = vec![0x33; 64];

        super::enqueue_distro_misses(
            Some(&queue),
            vec![device_hash.clone()],
            &distro_hash,
            &lxmf_data,
        );

        let pending = queue.lock().expect("queue lock").drain(&device_hash);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].channel_hash, distro_hash);
        assert_eq!(pending[0].blob, lxmf_data);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn initiate_sync_uses_persistent_app_links() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/lxmf_propagation.rs"
        ))
        .expect("read lxmf_propagation.rs");

        let start = source
            .find("fn initiate_sync(&mut self, peer_hash: &[u8])")
            .expect("initiate_sync present");
        let end = source[start..]
            .find("fn send_offer_on_link")
            .map(|offset| start + offset)
            .expect("send_offer_on_link present");
        let fragment = &source[start..end];

        assert!(
            fragment.contains("AppLinks::get_handle(peer_hash)"),
            "RFed propagation peer sync must reuse the AppLinks-owned persistent handle"
        );
        assert!(
            fragment.contains("AppLinks::open_persistent(peer_hash, LXMF_APP, &[PROP_ASPECT]);"),
            "RFed propagation peer sync must request a persistent AppLinks propagation link"
        );
        assert!(
            !fragment.contains("Link::new_outbound"),
            "RFed propagation peer sync must not construct raw outbound links directly"
        );
    }

    #[test]
    fn send_offer_identifies_link_before_request() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/lxmf_propagation.rs"
        ))
        .expect("read lxmf_propagation.rs");

        let start = source
            .find("fn send_offer_on_link(&mut self, link: &LinkHandle, peer_hash: &[u8], offer_ids: &[Vec<u8>])")
            .expect("send_offer_on_link present");
        let end = source[start..]
            .find("fn handle_offer_response")
            .map(|offset| start + offset)
            .expect("handle_offer_response present");
        let fragment = &source[start..end];

        assert!(
            fragment.contains("link.identify(&self.identity)"),
            "RFed propagation peer sync must identify the AppLinks-owned link before sending OFFER"
        );
    }

    #[test]
    fn send_offer_defers_request_until_link_identified() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/lxmf_propagation.rs"
        ))
        .expect("read lxmf_propagation.rs");

        let start = source
            .find("fn send_offer_on_link(&mut self, link: &LinkHandle, peer_hash: &[u8], offer_ids: &[Vec<u8>])")
            .expect("send_offer_on_link present");
        let end = source[start..]
            .find("fn handle_offer_response")
            .map(|offset| start + offset)
            .expect("handle_offer_response present");
        let fragment = &source[start..end];

        assert!(
            fragment.contains("identified_link_id") && fragment.contains("already_identified"),
            "RFed propagation peer sync must track whether the current AppLinks link has been identified"
        );
        assert!(
            fragment.contains("peer.state = PropPeer::IDLE;") && fragment.contains("return;"),
            "RFed propagation peer sync must defer OFFER until after link identification has been sent"
        );
    }
}

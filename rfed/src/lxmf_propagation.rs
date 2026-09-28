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
//! [false, timestamp, is_active, transfer_limit_kb, sync_limit_kb,
//!  [stamp_cost, flexibility, peering_cost], {PN_META_NAME: name}]
//! ```
//! The limits are kilobytes of 1000 bytes, as the reference announces them.
//!
//! # Peer sync
//!
//! As LXMF 1.1.1 does it (LXMRouter.sync_peers, LXMPeer): every 24 s one
//! ready peer with unhandled messages is chosen, at random among the fastest;
//! its session opens an AppLinks-held link, identifies, OFFERs a batch sized
//! to the peer's limits and to rfed's per-minute budget, and sends what the
//! peer wants as one Resource `[time, [lxm, ...]]`. Those ids are marked
//! handled only when the Resource concludes COMPLETE. Sessions run
//! concurrently, each on its own events. See "Outbound peer sync" below and
//! SPEC.md §10.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use app_links::AppLinks;
use rand::Rng;
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
use crate::notify::rns::{LiveStack, RelayStack};
use crate::notify::NotifyRegistry;
use crate::link_session::LinkSessionRegistry;
use crate::stream_registry::{OnUnproven, PropagationStreamRegistry, StreamDispatchResult};

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
/// Default per-transfer limit in KB of 1000 bytes (LXMRouter.PROPAGATION_LIMIT).
pub const DEFAULT_TRANSFER_LIMIT_KB: f64 = 256.0;
/// Default per-sync limit in KB of 1000 bytes (LXMRouter.SYNC_LIMIT).
pub const DEFAULT_SYNC_LIMIT_KB: f64 = 10240.0;
/// Message expiry: 7 days.  Matches BlobStore TTL.
pub const MESSAGE_EXPIRY_SECS: f64 = 7.0 * 24.0 * 3600.0;
/// How often one peer is chosen to start a sync: the reference runs
/// `LXMRouter.sync_peers` every JOB_PEERSYNC_INTERVAL (6) jobs of
/// PROCESSING_INTERVAL (4 s), i.e. every 24 s. This was 6 s — the job count
/// read as seconds — so rfed chose peers four times as often.
pub const PEER_SYNC_INTERVAL_SECS: f64 = 24.0;
/// Peer sync backoff step (LXMPeer.SYNC_BACKOFF_STEP), added each time a sync
/// link is attempted and cleared once one is established.
pub const SYNC_BACKOFF_STEP_SECS: f64 = 12.0 * 60.0;
/// LXMRouter.FASTEST_N_RANDOM_POOL: the sync choice is random among this many
/// of the fastest waiting peers, plus as many peers of unknown speed.
pub const FASTEST_N_RANDOM_POOL: usize = 2;
/// LXMRouter.PN_STAMP_THROTTLE: a peer that answers an offer with
/// ERROR_THROTTLED is not offered anything again for this long.
pub const PN_STAMP_THROTTLE_SECS: f64 = 180.0;
/// Largest peer sync Resource rfed sends: one Resource segment.
///
/// The reference packs any batch up to the peer's sync limit (10 MB by
/// default) into one `RNS.Resource`, which splits data over
/// `Resource.MAX_EFFICIENT_SIZE` into segments. Reticulum-rust's
/// `Resource::new_internal` sends `ResourceData::Bytes` as ONE segment
/// whatever its size, and a receiver refuses an advertisement over three
/// segments' worth (RNS/Resource.py `ResourceAdvertisement.unpack`). So a
/// batch is capped at one segment; what does not fit goes in the next batch,
/// which the persistent sync strategy starts as soon as this one completes.
pub const MAX_SYNC_RESOURCE_BYTES: usize = reticulum_rust::resource::Resource::MAX_EFFICIENT_SIZE;
const DISTRO_DEFERRED_QUEUE_LIMIT: usize = 256;
/// Max messages in one offer, and so in one sync batch. The reference has no
/// count cap (only the peer's sync limit in bytes); this bounds the offer
/// request and the batch alongside the per-minute outbound budget.
pub const MAX_OFFER_IDS: usize = 500;

/// Offer response error codes (LXMPeer.ERROR_*).
const ERROR_NO_IDENTITY: u8 = 0xF0;
const ERROR_NO_ACCESS: u8 = 0xF1;
const ERROR_INVALID_KEY: u8 = 0xF3;
const ERROR_THROTTLED: u8 = 0xF6;

/// The backlog — every message already stored when this node started — is
/// held back from outbound peer sync for this long after start. A restart
/// used to open with announces, peer links and a full-rate drain of that
/// backlog all at once (2026-09-23). Messages received after start are not
/// backlog: they sync immediately, hold or no hold.
pub const STARTUP_BACKLOG_HOLD_SECS: f64 = 3600.0;

/// Outbound peer-sync budget: messages we push to peers per minute, all
/// peers together. The reference paces syncs only by each peer's sync limit,
/// which with 20 peers and a 264k-message store meant ~2000 messages/min for
/// hours after every restart (2026-09-23). The budget caps the aggregate:
/// every offer is sized to what is left of it (`outbound_allowance`), so no
/// minute sends more than this.
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

/// The per-transfer and per-sync limits rfed announces, in the reference's
/// kilobytes of 1000 bytes: every reader multiplies them by 1000
/// (LXMPeer.sync, LXMRouter.propagation_resource_advertised). The config gives
/// them in bytes (`[storage] transfer_limit_mb` × 1024²); unset they are
/// LXMRouter's PROPAGATION_LIMIT and SYNC_LIMIT. As LXMRouter.__init__ does,
/// the sync limit is never below the per-transfer limit.
pub(crate) fn propagation_limits_kb(transfer_limit_bytes: Option<u64>, sync_limit_bytes: Option<u64>) -> (f64, f64) {
    let transfer = transfer_limit_bytes.map(|b| b as f64 / 1000.0).unwrap_or(DEFAULT_TRANSFER_LIMIT_KB);
    let sync = sync_limit_bytes.map(|b| b as f64 / 1000.0).unwrap_or(DEFAULT_SYNC_LIMIT_KB);
    (transfer, sync.max(transfer))
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
/// A sync session (LXMPeer.sync) goes IDLE → LINK_ESTABLISHING → LINK_READY
/// → REQUEST_SENT → RESPONSE_RECEIVED → RESOURCE_TRANSFERRING → IDLE, each
/// step on an event: the link coming up, the offer's response, the Resource
/// concluding. Any failure returns the peer to IDLE with its unhandled ids
/// untouched. Sync backoff grows by SYNC_BACKOFF_STEP_SECS with each link
/// attempt and is cleared once a link is established.
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
    /// The peering cost at which the key was discarded and ground once more
    /// after the peer answered ERROR_INVALID_KEY (0xF3).
    pub key_reground_at_cost: Option<u32>,
    /// The peering cost at which that second key was refused as well. A key
    /// ground at the same cost cannot fare better, so the peer is not synced
    /// until it announces another peering cost (see `sync_ready`).
    pub key_refused_at_cost: Option<u32>,
    /// Backoff in seconds: SYNC_BACKOFF_STEP_SECS more with each sync link
    /// attempt, cleared once a link is established (LXMPeer.sync_backoff).
    pub sync_backoff: f64,
    /// Earliest Unix timestamp when the next sync attempt is allowed.
    pub next_sync_attempt: f64,
    /// Until when the peer holds us off with ERROR_THROTTLED (0xF6). Kept
    /// apart from `next_sync_attempt`: a throttle is an answer, not a
    /// failure, so it never marks the peer unresponsive (see
    /// `select_sync_peer`).
    pub throttled_until: f64,
    /// Unix timestamp of the most recent sync attempt (success or failure).
    pub last_sync_attempt: f64,
    /// Bits per second of the last completed sync Resource
    /// (LXMPeer.sync_transfer_rate); 0 until one completes. Chooses the
    /// fastest-peer pool in `select_sync_peer`.
    pub sync_transfer_rate: f64,

    /// Transient IDs this peer has already received (or declined).
    pub handled_ids: IdQueue,
    /// Transient IDs this peer has NOT yet received — drives the OFFER payload.
    pub unhandled_ids: IdQueue,

    /// The ids in the sync Resource now in flight
    /// (LXMPeer.currently_transferring_messages). They are marked handled
    /// only when that Resource concludes COMPLETE.
    pub transferring: Option<Vec<Vec<u8>>>,
    /// When the in-flight sync Resource was started, for the transfer rate.
    pub current_sync_transfer_started: Option<f64>,
    /// The last set of IDs we offered — used to reconcile the response. While
    /// the peer is REQUEST_SENT these reserve outbound budget.
    pub last_offer: Vec<Vec<u8>>,
    /// Id of the AppLinks-held link this sync session runs on.
    pub link_id: Option<Vec<u8>>,
    /// Link id of the currently identified AppLinks-owned sync link.
    pub identified_link_id: Option<Vec<u8>>,
    /// Whether this link has already been identified a second time after the
    /// peer answered ERROR_NO_IDENTITY (the reference does so once per
    /// answer; rfed once per link, so a peer that never records the identity
    /// cannot keep the session looping).
    pub reidentified: bool,
    /// Bumped at each link attempt, each offer and each end of a session.
    /// Every network callback carries the value it was issued under, and one
    /// that no longer matches belongs to an ended session and is ignored.
    pub sync_session: u64,
    /// Current sync state machine position (see `IDLE`, `LINK_ESTABLISHING`, etc.).
    pub state: u8,
}

impl PropPeer {
    pub const IDLE: u8 = 0;
    pub const LINK_ESTABLISHING: u8 = 1;
    pub const LINK_READY: u8 = 2;
    pub const REQUEST_SENT: u8 = 3;
    pub const RESPONSE_RECEIVED: u8 = 4;
    pub const RESOURCE_TRANSFERRING: u8 = 5;

    pub fn state_name(state: u8) -> &'static str {
        match state {
            Self::IDLE => "IDLE",
            Self::LINK_ESTABLISHING => "LINK_ESTABLISHING",
            Self::LINK_READY => "LINK_READY",
            Self::REQUEST_SENT => "REQUEST_SENT",
            Self::RESPONSE_RECEIVED => "RESPONSE_RECEIVED",
            Self::RESOURCE_TRANSFERRING => "RESOURCE_TRANSFERRING",
            _ => "UNKNOWN",
        }
    }

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
            key_reground_at_cost: None,
            key_refused_at_cost: None,
            sync_backoff: 0.0,
            next_sync_attempt: 0.0,
            throttled_until: 0.0,
            last_sync_attempt: 0.0,
            sync_transfer_rate: 0.0,
            handled_ids: IdQueue::default(),
            unhandled_ids: IdQueue::default(),
            transferring: None,
            current_sync_transfer_started: None,
            last_offer: Vec::new(),
            link_id: None,
            identified_link_id: None,
            reidentified: false,
            sync_session: 0,
            state: Self::IDLE,
        }
    }

    /// Check whether peer has all parameters needed to initiate sync:
    /// stamp costs populated from announce AND a valid (sufficiently strong)
    /// peering key already ground, which the peer has not refused twice at
    /// its announced cost.
    pub fn sync_ready(&self) -> bool {
        self.propagation_stamp_cost.is_some()
            && self.propagation_stamp_flexibility.is_some()
            && self.peering_cost.is_some()
            && self.peering_key_ready()
            && !self.peering_key_refused()
    }

    /// Did the peer refuse a key ground again at its announced cost (see
    /// `key_refused_at_cost`)?
    pub fn peering_key_refused(&self) -> bool {
        self.key_refused_at_cost.is_some() && self.key_refused_at_cost == self.peering_cost
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

    // ── Outbound peer sync plumbing ───────────────────────────────────
    /// How outbound peer sync reaches the network: AppLinks-held links in
    /// production (`AppLinksSyncIo`), a recording fake in the unit tests.
    sync_io: Arc<dyn PeerSyncIo>,
    /// Where network callbacks deliver sync events: the channel of the one
    /// sync worker thread `enable` starts. `None` until then.
    sync_event_sink: Option<SyncEventSink>,

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
        let (transfer_limit_kb, sync_limit_kb) =
            propagation_limits_kb(config.transfer_limit_bytes, config.sync_limit_bytes);

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
            sync_io: Arc::new(AppLinksSyncIo),
            sync_event_sink: None,
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

        // Outbound peer sync: one worker thread takes every sync event in
        // arrival order — the offer responses, the Resources concluding, and
        // AppLinks' status for the peers' held links, subscribed here.
        // Only persistent AppLinks report ACTIVE with a link, and rfed opens
        // those only for sync; rfed.node's ephemeral links report ACTIVE
        // without one and are not forwarded. A DISCONNECTED for a destination
        // that is not a propagation peer is dropped by the worker.
        let sink = Self::start_sync_worker(arc, &mut guard);
        AppLinks::register_status_callback(Arc::new(move |dest: &[u8], status: u8, link: Option<LinkHandle>| {
            match (status, link) {
                (app_links::APP_LINK_ACTIVE, Some(handle)) => {
                    sink(SyncEvent::LinkActive { peer: dest.to_vec(), link_id: handle.link_id() })
                }
                (app_links::APP_LINK_DISCONNECTED, _) => sink(SyncEvent::LinkDown { peer: dest.to_vec() }),
                _ => {}
            }
        }));

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
        // [3] and [4] are kilobytes of 1000 bytes, as LXMF 1.1.1 announces
        // them and as every reader — LXMPeer.sync, and rfed's own
        // `plan_offer` — multiplies them back. Until 2026-09-28 rfed divided
        // its KB by 1024 once more and announced MB, truncated: a default
        // rfed announced a 0 KB per-message limit, so every peer, Python or
        // rfed, marked every message for it handled without sending it.
        let announce_data = Value::Array(vec![
            Value::Boolean(false),
            Value::Integer(ts.into()),
            Value::Boolean(true),
            Value::Integer((self.transfer_limit_kb as i64).into()),
            Value::Integer((self.sync_limit_kb as i64).into()),
            stamp_costs,
            metadata,
        ]);
        let mut buf = Vec::new();
        let _ = write_value(&mut buf, &announce_data);
        buf
    }

    /// Announce the propagation destination once. Returns its hash, or
    /// `None` when the lock is poisoned and nothing was sent. Called from
    /// `FedNode::announce`, in `ANNOUNCE_ORDER`.
    pub fn announce(arc: &Arc<Mutex<Self>>) -> Option<Vec<u8>> {
        let mut guard = arc.lock().ok()?;
        let app_data = guard.build_app_data();
        guard.destination.set_default_app_data(Some(app_data.clone()));
        let _ = guard.destination.announce(Some(&app_data), false, None, None, true);
        log("[lxmf.prop] announced propagation node", LOG_NOTICE, false, false);
        Some(guard.destination.hash.clone())
    }

    /// Opt the propagation destination into Transport's announce daemon
    /// so it is re-announced every `SERVICE_REFRESH_INTERVAL_SECS` (6 h).
    /// See DESIGN_PRINCIPLES.md §3-§4.
    ///
    /// Transport announces it once on each interface up-edge and on the
    /// refresh, both held per interface to the refresh period
    /// (Reticulum-rust B22). Interfaces already up are covered by the
    /// immediate announce in `FedNode::announce`, not here.
    ///
    /// Returns the published hash, or `None` when the lock is poisoned.
    /// Called from `FedNode::publish_destinations`, in `ANNOUNCE_ORDER`.
    pub fn publish_destination(arc: &Arc<Mutex<Self>>) -> Option<Vec<u8>> {
        use reticulum_rust::transport::Transport;
        // No immediate announce here: FedNode::announce announces at start
        // when announce_at_start is set, and otherwise Transport's daemon
        // announces a never-announced published destination on its next
        // sweep. The copy that used to fire here was a second announce of the
        // same destination within a second (2026-09-23 logs).
        let guard = arc.lock().ok()?;
        let app_data = guard.build_app_data();
        let hash = guard.destination.hash.clone();
        Transport::publish_destination(
            hash.clone(),
            Some(Duration::from_secs(
                crate::destinations::SERVICE_REFRESH_INTERVAL_SECS,
            )),
            Some(app_data),
        );
        Some(hash)
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
                if peer.peering_cost != Some(peer_cost) {
                    // A new cost: a refusal at the old one says nothing about it.
                    peer.key_reground_at_cost = None;
                    peer.key_refused_at_cost = None;
                }
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
        // A session in flight ends with the peer: its held link goes, and its
        // callbacks find no peer and are dropped.
        self.sync_io.close_link(destination_hash);
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
                // A client PUT: no sending peer, as LXMRouter.propagation_packet.
                let _ = packet;
                if let Some(arc) = weak.as_ref().and_then(|w| w.upgrade()) {
                    LxmfPropagationNode::ingest_propagation_batch(&arc, data, None);
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
                let (data, link): (Vec<u8>, LinkHandle) = match resource.lock() {
                    Ok(r) => {
                        if r.status != reticulum_rust::resource::ResourceStatus::Complete {
                            return;
                        }
                        match r.data.clone() {
                            Some(d) => (d, r.link.clone()),
                            None => return,
                        }
                    }
                    Err(_) => return,
                };
                // The sender is the identity it proved on this link, as
                // LXMRouter.propagation_resource_concluded takes it; asked
                // with the Resource released.
                let sender = link.remote_identity().ok().flatten();
                // NOT under the node lock — see `ingest_propagation_batch`.
                if let Some(arc) = weak_concluded.as_ref().and_then(|w| w.upgrade()) {
                    LxmfPropagationNode::ingest_propagation_batch(&arc, &data, sender.as_ref());
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
    ///
    /// `sender` is the identity the sender proved on its link, for a sync
    /// Resource. When its `lxmf.propagation` destination is one of our peers,
    /// every message in the batch is handled for that peer — it has them —
    /// and new ones are queued for the other peers only, as
    /// LXMRouter.propagation_resource_concluded does (`from_peer=peer`, then
    /// `peer.queue_handled_message` for every validated message, a duplicate
    /// included). Until 2026-09-28 rfed queued each one back to its sender,
    /// and outbound sync offered every inbound batch straight back.
    pub(crate) fn ingest_propagation_batch(arc: &Arc<Mutex<Self>>, data: &[u8], sender: Option<&Identity>) {
        let Some(messages) = decode_propagation_batch(data) else { return };
        if messages.is_empty() {
            return;
        }

        let (min_cost, delivery, from_peer) = {
            let Some(node) = lock_node(arc, "ingest (setup)") else { return };
            (
                node.stamp_cost.saturating_sub(node.stamp_flexibility),
                node.delivery_handles(),
                node.sending_peer(sender),
            )
        };

        // Validate PN (Propagation Node) stamps on all messages. Stamps below
        // `min_cost` are rejected; only validated messages proceed.
        let validated = lx_stamper::validate_pn_stamps(&messages, min_cost);

        let mut stored = 0usize;
        let mut streamed = 0usize;
        let mut notified = 0usize;

        for (transient_id, lxmf_data, stamp_value, stamp_raw) in &validated {
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
                Some(mut node) => {
                    let stored = node
                        .store_message(lxmf_data, *stamp_value, Some(stamp_raw), from_peer.as_deref())
                        .is_some();
                    if let Some(peer) = &from_peer {
                        node.mark_handled_for(peer, std::slice::from_ref(transient_id));
                    }
                    stored
                }
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

    /// The peer a sync batch came from: the `lxmf.propagation` destination of
    /// the identity its sender proved on the link, when that is one of our
    /// peers (LXMRouter.propagation_resource_concluded: `remote_hash in
    /// self.peers`). `None` for a client, or a sender that is not a peer.
    fn sending_peer(&self, sender: Option<&Identity>) -> Option<Vec<u8>> {
        let hash = Destination::hash_from_name_and_identity(
            &format!("{}.{}", LXMF_APP, PROP_ASPECT),
            Some(sender?),
        );
        self.peers.contains_key(&hash).then_some(hash)
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

/// Wake the recipient of `lxmf_data` through its notify registrations, so it
/// fetches the message from the messagestore. Returns whether any wake packet
/// left. Until 2026-09-25 it returned whether a registration existed, so a
/// relay with no path or no known identity counted as notified (X7). Used
/// when no live tier delivered the message, and when a stream push to the
/// recipient went unproven.
fn notify_recipient(
    stack: &dyn RelayStack,
    registry: &Arc<Mutex<NotifyRegistry>>,
    lxmf_data: &[u8],
    log_suffix: &str,
) -> bool {
    if lxmf_data.len() < DESTINATION_LENGTH {
        return false;
    }
    let dest_hash = &lxmf_data[..DESTINATION_LENGTH];
    // Snapshot, then wake with the registry released: a wake is a packet send.
    let regs: Vec<_> = match registry.lock() {
        Ok(reg) => reg.get_for_channel(dest_hash, None).into_iter().cloned().collect(),
        Err(_) => return false,
    };
    if regs.is_empty() {
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
        return false;
    }
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
    // Every registration gets its wake; `count` drives the whole iterator.
    let sent = regs
        .iter()
        .filter(|registration| crate::notify::dispatch_notify_via(stack, registration, sender, None).is_sent())
        .count();
    sent > 0
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
        let handed_off = crate::distro::distro_fanout(
            dest_hash,
            lxmf_data,
            &devices,
            hooks,
            Some(&self.stream_registry),
            Some(&self.link_sessions),
            self.distro_hand_off(Arc::new(LiveStack), dest_hash, lxmf_data),
        );
        if handed_off > 0 {
            log(
                format!(
                    "[distro] {} of {} device(s) with no live session for distro {} — queued for /rfed/pull and pushed",
                    handed_off,
                    devices.len(),
                    hexrep(dest_hash, false),
                ),
                LOG_NOTICE,
                false,
                false,
            );
        }
    }

    /// What a distro fan-out from propagation ingest does with a device it
    /// could not confirm: [`crate::distro::defer_then_wake`] on the deferred
    /// queue `/rfed/pull` drains and the notify registry the device registered
    /// with. Until 2026-09-26 it only queued: no device was ever woken.
    fn distro_hand_off(
        &self,
        stack: Arc<dyn RelayStack + Send + Sync>,
        dest_hash: &[u8],
        lxmf_data: &[u8],
    ) -> crate::distro::OnUnconfirmed {
        match &self.deferred_queue {
            Some(queue) => crate::distro::defer_then_wake(
                stack,
                Arc::clone(queue),
                Arc::clone(&self.registry),
                Arc::new(|_| DISTRO_DEFERRED_QUEUE_LIMIT),
                dest_hash,
                lxmf_data,
                None,
            ),
            None => {
                let distro = hexrep(dest_hash, false);
                Arc::new(move |device: crate::distro::Unconfirmed| {
                    log(
                        format!(
                            "[distro] device {} unconfirmed for distro {distro}, and this node has no deferred queue: NOT queued, NOT woken",
                            hexrep(&device.wake_key, false),
                        ),
                        LOG_WARNING,
                        false,
                        false,
                    );
                })
            }
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

        // Proof-driven (stream_registry::PushOutcome). The message stays in
        // the messagestore either way, so a push nobody proves loses no data
        // — but until 2026-09-24 the push counted as delivered and the notify
        // wake below was skipped, so a device that had died with its stream
        // link still up (an iOS app killed or suspended) got no push
        // notification for anything sent until rfed noticed the dead link.
        // An unproven push now wakes it, as a failed one does.
        let wake: OnUnproven = {
            let registry = Arc::clone(&self.registry);
            let data = lxmf_data.to_vec();
            let suffix = log_suffix.to_string();
            Arc::new(move || {
                log(
                    format!(
                        "[lxmf.prop] stream push to recipient {} unproven — notify fallback{}",
                        hexrep(&data[..DESTINATION_LENGTH], false),
                        suffix,
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                notify_recipient(&LiveStack, &registry, &data, &suffix);
            })
        };
        let stream_result = self
            .stream_registry
            .lock()
            .ok()
            .map(|mut registry| registry.dispatch(dest_hash, lxmf_data, Some(wake)))
            .unwrap_or_else(StreamDispatchResult::default);

        if stream_result.delivered() {
            log(
                format!(
                    "[lxmf.prop] streamed recipient {} on {} live link(s), awaiting its proof{}",
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

        if notify_recipient(&LiveStack, &self.registry, lxmf_data, log_suffix) {
            return LiveDispatchOutcome::Notified;
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

    // ── Outbound peer sync ───────────────────────────────────────────────────
    //
    // The reference is LXMF 1.1.1 (the workspace .venv): LXMRouter.sync_peers
    // chooses one peer per sync job, and LXMPeer.sync / offer_response /
    // resource_concluded carry that peer's session to its end:
    //
    //   IDLE ─open link─▶ LINK_ESTABLISHING ─link up─▶ LINK_READY
    //        ─identify + /offer─▶ REQUEST_SENT ─response─▶ RESPONSE_RECEIVED
    //        ─Resource [time, [lxm, ...]]─▶ RESOURCE_TRANSFERRING
    //        ─concluded─▶ IDLE (ids handled only when COMPLETE)
    //
    // Every step after the choice runs on an event — AppLinks reporting the
    // link up or down, the offer's response or failure, the Resource
    // concluding — delivered to one worker thread in arrival order
    // (`handle_sync_event`). Nothing waits on a clock, and nothing is retried:
    // a failed session leaves the peer IDLE with its ids unhandled, and the
    // next choice starts a new one. The departures from the reference, each
    // with its reason, are listed in SPEC.md §10 "Outbound peer sync".

    /// Is the startup backlog still held back from peer sync?
    pub fn backlog_held(&self) -> bool {
        now() - self.started_at < STARTUP_BACKLOG_HOLD_SECS
    }

    /// The ids this peer may be offered right now: during the backlog hold
    /// only messages received since start that it still lacks; afterwards
    /// everything it still lacks. Cheap during the hold because it walks the
    /// fresh list, not the peer's (possibly 150k-entry) queue. Sync itself
    /// calls `sync_pool_for`, holding a borrow of the peer.
    #[cfg(test)]
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

    /// `!sync_pool_for(..).is_empty()` without building the pool: this runs
    /// for every peer on every sync tick.
    pub fn has_sync_candidates(backlog_held: bool, fresh_since_start: &[Vec<u8>], peer: &PropPeer) -> bool {
        if backlog_held {
            fresh_since_start.iter().any(|tid| peer.unhandled_ids.contains(tid))
        } else {
            !peer.unhandled_ids.is_empty()
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

    // ── The per-minute outbound budget ───────────────────────────────────

    /// Start a new accounting minute once the current one is over.
    fn roll_outbound_window(&mut self, t: f64) {
        if t - self.outbound_sync_window_start >= 60.0 {
            self.outbound_sync_window_start = t;
            self.outbound_sync_window_count = 0;
        }
    }

    /// Messages that may still be offered this minute: the budget, less what
    /// was sent this minute, less what the offers still awaiting a response
    /// could send (a peer in REQUEST_SENT reserves its whole offer). The
    /// response releases the reservation and `charge_outbound` counts what
    /// the peer wanted, never more than it reserved. So
    /// `sent + reserved <= budget` holds after every step, and no minute
    /// sends more than the budget however many syncs run at once. Until
    /// 2026-09-28 the budget was checked once before a 500-message send, and
    /// 1000 went out in a 600-message minute (57 times in one staging run).
    pub fn outbound_allowance(&mut self) -> u64 {
        self.roll_outbound_window(now());
        let reserved: u64 = self.peers.values()
            .filter(|peer| peer.state == PropPeer::REQUEST_SENT)
            .map(|peer| peer.last_offer.len() as u64)
            .sum();
        self.outbound_sync_msgs_per_min
            .saturating_sub(self.outbound_sync_window_count.saturating_add(reserved))
    }

    /// Count `messages` leaving in a sync Resource against this minute.
    fn charge_outbound(&mut self, messages: u64) {
        self.roll_outbound_window(now());
        self.outbound_sync_window_count += messages;
    }

    /// May this tick start an outbound peer sync? False while nothing is
    /// left of this minute's budget. Logs the hold once and the release once,
    /// so the log tells the story without repeating it every tick.
    pub fn outbound_sync_allowed(&mut self) -> bool {
        let allowance = self.outbound_allowance();
        if allowance == 0 {
            if !self.outbound_sync_hold_logged {
                log(
                    format!(
                        "[lxmf.prop] outbound peer sync held: budget spent, {}/{} messages this minute",
                        self.outbound_sync_window_count, self.outbound_sync_msgs_per_min
                    ),
                    LOG_NOTICE, false, false,
                );
                self.outbound_sync_hold_logged = true;
            }
            false
        } else {
            if self.outbound_sync_hold_logged {
                log("[lxmf.prop] outbound peer sync resumed", LOG_NOTICE, false, false);
                self.outbound_sync_hold_logged = false;
            }
            true
        }
    }

    // ── Choosing a peer (LXMRouter.sync_peers) ───────────────────────────

    /// Called from the main event loop. Every PEER_SYNC_INTERVAL_SECS: cull
    /// long-unreachable peers, start peering-key generation where it is
    /// missing, and — while the minute's budget lasts — choose one peer and
    /// hand it to the sync worker. Sessions already running continue on their
    /// own events, so several peers sync at once, as in the reference.
    pub fn tick_sync(arc: &Arc<Mutex<Self>>) {
        let (needs_keys, identity) = {
            let Some(mut guard) = lock_node(arc, "tick_sync") else { return };
            let t = now();
            if t - guard.last_sync_tick < PEER_SYNC_INTERVAL_SECS {
                return;
            }
            guard.last_sync_tick = t;
            guard.note_backlog_hold();

            // Cull non-static peers we haven't heard from in MAX_UNREACHABLE_SECS.
            // Static peers are never culled — they're operator-configured.
            let culled: Vec<Vec<u8>> = guard.peers.iter()
                .filter(|(hash, peer)| {
                    t > peer.last_heard + MAX_UNREACHABLE_SECS
                        && !guard.static_peers.contains(hash)
                })
                .map(|(hash, _)| hash.clone())
                .collect();
            for hash in culled {
                log(
                    format!("[lxmf.prop] removing peer {} due to excessive unreachability", hexrep(&hash, false)),
                    LOG_WARNING, false, false,
                );
                guard.unpeer(&hash);
            }

            for (hash, peer) in &guard.peers {
                if !peer.unhandled_ids.is_empty() || !peer.alive {
                    log(
                        format!("[lxmf.prop] tick_sync peer {} alive={} state={} unhandled={} stamp_cost={:?} peer_cost={:?} peering_key_ready={}",
                            hexrep(hash, false), peer.alive, PropPeer::state_name(peer.state), peer.unhandled_ids.len(),
                            peer.propagation_stamp_cost, peer.peering_cost, peer.peering_key_ready()),
                        LOG_DEBUG, false, false,
                    );
                }
            }

            // Keys are ground in the background, and a peer without one is
            // simply not a candidate below: it can never hold up the others.
            let needs_keys: Vec<Vec<u8>> = guard.peers.iter()
                .filter(|(_, peer)| {
                    peer.alive && peer.peering_cost.is_some() && !peer.peering_key_ready()
                })
                .map(|(hash, _)| hash.clone())
                .collect();

            if guard.outbound_sync_allowed() {
                let mut rng = rand::thread_rng();
                if let Some(peer_hash) = guard.select_sync_peer(t, &mut |n| rng.gen_range(0..n)) {
                    log(
                        format!("[lxmf.prop] tick_sync: selected peer {} to sync", hexrep(&peer_hash, false)),
                        LOG_DEBUG, false, false,
                    );
                    (guard.event_sink())(SyncEvent::Start { peer: peer_hash });
                }
            }
            (needs_keys, guard.identity.clone())
        };

        // spawn_peering_key_gen takes the lock itself.
        for hash in &needs_keys {
            Self::spawn_peering_key_gen(arc, hash, &identity);
        }
    }

    /// LXMRouter.sync_peers: choose the peer to start a sync with.
    ///
    /// Candidates are IDLE peers with something to offer. Alive ones are
    /// "waiting"; the choice is random among the FASTEST_N_RANDOM_POOL
    /// fastest of them plus as many of unknown speed. Only when none is
    /// waiting is the choice random among the unresponsive peers whose
    /// backoff has run out. `pick(n)` returns an index below `n`.
    ///
    /// Two departures, both so that no peer can hold up the rest:
    ///   * a peer whose stamp costs are unknown or whose peering key is not
    ///     ready is not a candidate. The reference chooses it, and its
    ///     `sync()` only postpones and starts the key — a wasted choice.
    ///     rfed chose the FIRST idle peer every tick, so one peer grinding
    ///     its key blocked every other peer for 3.5 minutes (staging,
    ///     2026-09-27);
    ///   * an alive peer still in link-attempt backoff is marked not alive
    ///     here, which is what the reference's `sync()` does when it chooses
    ///     one, without spending the choice on it.
    ///
    /// A peer that throttled us (0xF6) is skipped until the throttle is over
    /// and is NOT marked unresponsive: the reference holds it on its link in
    /// RESPONSE_RECEIVED, where sync_peers never chooses it and sync() never
    /// demotes it, and it is alive and waiting again once its link closes.
    /// rfed ends that session at once, and marking the peer unresponsive
    /// then left it behind every alive peer until its next announce.
    pub fn select_sync_peer(&mut self, t: f64, pick: &mut dyn FnMut(usize) -> usize) -> Option<Vec<u8>> {
        let backlog_held = self.backlog_held();
        let fresh = &self.fresh_since_start;
        let mut waiting: Vec<(Vec<u8>, f64)> = Vec::new();
        let mut unresponsive: Vec<Vec<u8>> = Vec::new();
        let mut not_ready = 0usize;
        for (hash, peer) in self.peers.iter_mut() {
            if peer.state != PropPeer::IDLE || !Self::has_sync_candidates(backlog_held, fresh, peer) {
                continue;
            }
            if !peer.sync_ready() {
                not_ready += 1;
                continue;
            }
            if t <= peer.throttled_until {
                log(
                    format!(
                        "[lxmf.prop] not syncing with peer {} for {:.0}s more: it throttled us",
                        hexrep(hash, false), peer.throttled_until - t,
                    ),
                    LOG_DEBUG, false, false,
                );
                continue;
            }
            if peer.alive {
                if t <= peer.next_sync_attempt {
                    peer.alive = false;
                    log(
                        format!(
                            "[lxmf.prop] postponing sync with peer {} for {:.0}s due to previous failures",
                            hexrep(hash, false), peer.next_sync_attempt - t,
                        ),
                        LOG_DEBUG, false, false,
                    );
                    continue;
                }
                waiting.push((hash.clone(), peer.sync_transfer_rate));
            } else if t > peer.next_sync_attempt {
                unresponsive.push(hash.clone());
            }
        }
        if not_ready > 0 {
            log(
                format!("[lxmf.prop] {not_ready} peer(s) with messages to sync are waiting for stamp costs or a peering key"),
                LOG_DEBUG, false, false,
            );
        }

        let pool: Vec<Vec<u8>> = if !waiting.is_empty() {
            let mut fastest = waiting.clone();
            fastest.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
            fastest.truncate(FASTEST_N_RANDOM_POOL.min(waiting.len()));
            let fastest_count = fastest.len();
            let mut pool: Vec<Vec<u8>> = fastest.into_iter().map(|(hash, _)| hash).collect();
            pool.extend(
                waiting.iter()
                    .filter(|(_, rate)| *rate == 0.0)
                    .take(fastest_count)
                    .map(|(hash, _)| hash.clone()),
            );
            log(
                format!("[lxmf.prop] selecting peer to sync from {} waiting peers", waiting.len()),
                LOG_DEBUG, false, false,
            );
            pool
        } else if !unresponsive.is_empty() {
            log(
                format!(
                    "[lxmf.prop] no active peers available, randomly selecting peer to sync from {} unresponsive peers",
                    unresponsive.len(),
                ),
                LOG_DEBUG, false, false,
            );
            unresponsive
        } else {
            return None;
        };
        let index = pick(pool.len()).min(pool.len() - 1);
        Some(pool[index].clone())
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
            // tick_sync runs every PEER_SYNC_INTERVAL_SECS; cost-N PoW takes
            // seconds to minutes. Without this guard, concurrent generations
            // stack up and pin the CPU.
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
                    } else {
                        log(
                            format!(
                                "[lxmf.prop] peering key generation for {} reached value {} of the {} required; it is tried again on a later tick",
                                hexrep(&dest_hash, false), value, peering_cost,
                            ),
                            LOG_WARNING, false, false,
                        );
                    }
                }
            }
        });
    }

    // ── The sync worker ──────────────────────────────────────────────────

    /// Start the one thread that runs every sync event, and return the sink
    /// the network callbacks deliver to. Events are handled in the order they
    /// arrive, so a session's steps can never overtake one another.
    fn start_sync_worker(arc: &Arc<Mutex<Self>>, node: &mut Self) -> SyncEventSink {
        let (tx, rx) = std::sync::mpsc::channel::<SyncEvent>();
        let weak = Arc::downgrade(arc);
        let spawned = std::thread::Builder::new()
            .name("lxmf-prop-sync".into())
            .spawn(move || {
                for event in rx {
                    let Some(arc) = weak.upgrade() else { break };
                    Self::handle_sync_event(&arc, event);
                }
            });
        if let Err(e) = spawned {
            log(format!("[lxmf.prop] could not start the peer sync worker: {e}; outbound peer sync is OFF"), LOG_ERROR, false, false);
        }
        let sink: SyncEventSink = Arc::new(move |event: SyncEvent| {
            let described = event.describe();
            if tx.send(event).is_err() {
                log(format!("[lxmf.prop] sync event dropped, the sync worker has stopped: {described}"), LOG_WARNING, false, false);
            }
        });
        node.sync_event_sink = Some(Arc::clone(&sink));
        sink
    }

    /// Where this node's network callbacks deliver sync events.
    fn event_sink(&self) -> SyncEventSink {
        match &self.sync_event_sink {
            Some(sink) => Arc::clone(sink),
            None => Arc::new(|event: SyncEvent| {
                log(
                    format!("[lxmf.prop] sync event dropped, no sync worker is running: {}", event.describe()),
                    LOG_WARNING, false, false,
                );
            }),
        }
    }

    /// The sync worker's dispatcher.
    pub(crate) fn handle_sync_event(arc: &Arc<Mutex<Self>>, event: SyncEvent) {
        match event {
            SyncEvent::Start { peer } => Self::sync_peer(arc, &peer),
            SyncEvent::LinkActive { peer, link_id } => Self::on_link_active(arc, &peer, link_id),
            SyncEvent::LinkDown { peer } => Self::on_link_down(arc, &peer),
            SyncEvent::OfferResponse { peer, session, response } => {
                Self::on_offer_response(arc, &peer, session, response)
            }
            SyncEvent::OfferFailed { peer, session } => Self::on_offer_failed(arc, &peer, session),
            SyncEvent::ResourceConcluded { peer, session, outcome } => {
                Self::on_resource_concluded(arc, &peer, session, outcome)
            }
        }
    }

    /// End `peer_hash`'s session: release its held link (AppLinks::close, the
    /// reference's `link.teardown()`) and return it to IDLE. Its unhandled
    /// ids are untouched, and every callback still in flight for the session
    /// is made stale.
    fn end_sync(&mut self, peer_hash: &[u8]) {
        self.sync_io.close_link(peer_hash);
        if let Some(peer) = self.peers.get_mut(peer_hash) {
            peer.state = PropPeer::IDLE;
            peer.link_id = None;
            peer.identified_link_id = None;
            peer.reidentified = false;
            peer.transferring = None;
            peer.current_sync_transfer_started = None;
            peer.last_offer.clear();
            peer.sync_session += 1;
        }
    }

    /// Mark `ids` handled for `peer_hash`, for the ids still in the store
    /// (LXMPeer.add_handled_message only records stored ids).
    fn mark_handled_for(&mut self, peer_hash: &[u8], ids: &[Vec<u8>]) {
        let entries = &self.entries;
        if let Some(peer) = self.peers.get_mut(peer_hash) {
            for tid in ids {
                if entries.contains_key(tid) {
                    peer.mark_handled(tid);
                } else {
                    peer.unhandled_ids.remove(tid);
                }
            }
        }
    }

    // ── A session's steps (LXMPeer) ──────────────────────────────────────

    /// LXMPeer.sync(): advance `peer_hash`'s session one step — from IDLE,
    /// open the sync link (never one it did not open); once the link is
    /// ready, send the offer. The offer's candidates are sorted with the node
    /// released: a peer's queue can hold 150k ids.
    fn sync_peer(arc: &Arc<Mutex<Self>>, peer_hash: &[u8]) {
        let prepared = {
            let Some(mut node) = lock_node(arc, "peer sync") else { return };
            node.prepare_sync(peer_hash)
        };
        let Some(prepared) = prepared else { return };
        let plan = plan_offer(
            prepared.candidates,
            prepared.transfer_limit_kb,
            prepared.sync_limit_kb,
            MAX_OFFER_IDS,
        );
        let Some(mut node) = lock_node(arc, "peer sync (offer)") else { return };
        node.send_offer(peer_hash, prepared.session, plan);
    }

    /// The part of LXMPeer.sync() that needs the node: the readiness checks,
    /// opening the link from IDLE, and, once LINK_READY, the offer's
    /// candidates. `Some` only when an offer is to be planned.
    fn prepare_sync(&mut self, peer_hash: &[u8]) -> Option<PreparedOffer> {
        let t = now();
        let backlog_held = self.backlog_held();
        let io = Arc::clone(&self.sync_io);
        let peer_str = hexrep(peer_hash, false);

        enum Gate { Postpone(String), NothingToSync, Busy, Proceed }
        let (gate, state) = {
            let fresh = &self.fresh_since_start;
            let Some(peer) = self.peers.get_mut(peer_hash) else {
                log(format!("[lxmf.prop] sync requested for {peer_str}, which is not a peer"), LOG_DEBUG, false, false);
                return None;
            };
            // The reference calls sync() only on an IDLE peer (sync_peers) or
            // a LINK_READY one (link_established); a session already past
            // that is left to its own events.
            if peer.state != PropPeer::IDLE && peer.state != PropPeer::LINK_READY {
                log(
                    format!(
                        "[lxmf.prop] sync requested for peer {peer_str} in state {}; its session is already running",
                        PropPeer::state_name(peer.state),
                    ),
                    LOG_DEBUG, false, false,
                );
                return None;
            }
            peer.last_sync_attempt = t;
            let gate = if t <= peer.next_sync_attempt {
                if peer.last_sync_attempt > peer.last_heard {
                    peer.alive = false;
                }
                Gate::Postpone(format!("for {:.0}s due to previous failures", peer.next_sync_attempt - t))
            } else if t <= peer.throttled_until {
                // Not a failure: the peer stays alive (see select_sync_peer).
                Gate::Postpone(format!("for {:.0}s since it throttled us", peer.throttled_until - t))
            } else if peer.propagation_stamp_cost.is_none()
                || peer.propagation_stamp_flexibility.is_none()
                || peer.peering_cost.is_none()
            {
                Gate::Postpone("since its required stamp costs are not yet known".to_string())
            } else if !peer.peering_key_ready() {
                Gate::Postpone("since a peering key has not been generated yet".to_string())
            } else if peer.peering_key_refused() {
                Gate::Postpone("until it announces another peering cost, since it refused our key at this one twice".to_string())
            } else if !Self::has_sync_candidates(backlog_held, fresh, peer) {
                Gate::NothingToSync
            } else if peer.transferring.is_some() {
                Gate::Busy
            } else {
                Gate::Proceed
            };
            (gate, peer.state)
        };

        match gate {
            Gate::Proceed => {}
            Gate::Postpone(reason) => {
                log(format!("[lxmf.prop] postponing sync with peer {peer_str} {reason}"), LOG_DEBUG, false, false);
                // A session never waits in LINK_READY: that would hold the
                // link open with nothing coming.
                if state == PropPeer::LINK_READY {
                    self.end_sync(peer_hash);
                }
                return None;
            }
            Gate::NothingToSync => {
                log(
                    format!("[lxmf.prop] sync requested for peer {peer_str}, but no unhandled messages exist for it. Sync complete."),
                    LOG_DEBUG, false, false,
                );
                if state == PropPeer::LINK_READY {
                    self.end_sync(peer_hash);
                }
                return None;
            }
            Gate::Busy => {
                log(
                    format!("[lxmf.prop] sync requested for peer {peer_str}, but its current message transfer was not clear. Not starting another."),
                    LOG_ERROR, false, false,
                );
                return None;
            }
        }

        match state {
            PropPeer::IDLE => {
                // LXMPeer.sync builds a new link from IDLE, and so does every
                // session here: open_persistent registers the destination,
                // so AppLinks reports the link's loss. A link already held now
                // is not one a session opened — end_sync closes each
                // session's — but one AppLinks brought up on its own after
                // close() forgot the destination (its re-open of a link the
                // peer closed). Adopted, its loss went unreported and a
                // session could wait on it for good; it is closed instead.
                if let Some(stray) = io.active_link(peer_hash) {
                    log(
                        format!(
                            "[lxmf.prop] closing link {} to peer {peer_str}, which no sync opened, before the sync opens its own",
                            hexrep(&stray, false),
                        ),
                        LOG_DEBUG, false, false,
                    );
                    io.close_link(peer_hash);
                }
                let peer = self.peers.get_mut(peer_hash)?;
                peer.sync_backoff += SYNC_BACKOFF_STEP_SECS;
                peer.next_sync_attempt = t + peer.sync_backoff;
                peer.sync_session += 1;
                peer.link_id = None;
                peer.identified_link_id = None;
                peer.reidentified = false;
                peer.state = PropPeer::LINK_ESTABLISHING;
                log(
                    format!(
                        "[lxmf.prop] establishing link for sync to peer {peer_str} ({} unhandled)",
                        peer.unhandled_ids.len(),
                    ),
                    LOG_NOTICE, false, false,
                );
                // The outcome arrives as LinkActive or LinkDown.
                io.open_link(peer_hash);
                return None;
            }
            _ => {} // LINK_READY; other states returned above.
        }

        // LINK_READY: gather the offer's candidates.
        let fresh = &self.fresh_since_start;
        let entries = &self.entries;
        let peer = self.peers.get_mut(peer_hash)?;
        peer.alive = true;
        peer.last_heard = t;
        peer.sync_backoff = 0.0;
        let min_accepted_cost = peer.propagation_stamp_cost.unwrap_or(0)
            .saturating_sub(peer.propagation_stamp_flexibility.unwrap_or(0));

        let mut candidates = Vec::new();
        let mut purged = Vec::new();
        let mut low_value = Vec::new();
        for tid in Self::sync_pool_for(backlog_held, fresh, peer) {
            match entries.get(&tid) {
                None => purged.push(tid),
                Some(entry) if entry.stamp_value < min_accepted_cost => low_value.push(tid),
                Some(entry) => {
                    // LXMRouter.get_weight: age in 4-day units (at least 1) × size.
                    let age_weight = ((t - entry.received) / 86400.0 / 4.0).max(1.0);
                    candidates.push(OfferCandidate {
                        weight: age_weight * entry.size as f64,
                        size: entry.size,
                        tid,
                    });
                }
            }
        }
        for tid in purged.iter().chain(low_value.iter()) {
            peer.unhandled_ids.remove(tid);
        }
        if !purged.is_empty() {
            log(
                format!(
                    "[lxmf.prop] dropped {} unhandled message(s) for peer {peer_str} since they no longer exist in the message store",
                    purged.len(),
                ),
                LOG_DEBUG, false, false,
            );
        }
        if !low_value.is_empty() {
            log(
                format!(
                    "[lxmf.prop] dropped {} unhandled message(s) for peer {peer_str} since their stamp value is lower than the peer's requirement of {min_accepted_cost}",
                    low_value.len(),
                ),
                LOG_NOTICE, false, false,
            );
        }
        log(
            format!("[lxmf.prop] synchronisation link to peer {peer_str} established, preparing sync offer..."),
            LOG_DEBUG, false, false,
        );
        Some(PreparedOffer {
            session: peer.sync_session,
            candidates,
            transfer_limit_kb: peer.propagation_transfer_limit,
            sync_limit_kb: peer.propagation_sync_limit,
        })
    }

    /// Send the planned offer: mark what the peer can never take handled,
    /// size the offer to this minute's allowance, identify the link if it
    /// has not been, and request `/offer` on it.
    fn send_offer(&mut self, peer_hash: &[u8], prepared_session: u64, plan: OfferPlan) {
        let peer_str = hexrep(peer_hash, false);
        let transfer_limit_kb = match self.peers.get(peer_hash) {
            Some(peer) if peer.state == PropPeer::LINK_READY && peer.sync_session == prepared_session => {
                peer.propagation_transfer_limit
            }
            _ => {
                log(
                    format!("[lxmf.prop] sync with peer {peer_str} moved on while its offer was prepared; offer dropped"),
                    LOG_DEBUG, false, false,
                );
                return;
            }
        };

        // LXMPeer.sync: a message over the peer's per-message transfer limit
        // is marked handled and never sent.
        if !plan.too_big.is_empty() {
            self.mark_handled_for(peer_hash, &plan.too_big);
            log(
                format!(
                    "[lxmf.prop] {} message(s) over peer {peer_str}'s per-message transfer limit of {} KB marked handled without sending",
                    plan.too_big.len(),
                    transfer_limit_kb.map(|l| format!("{l}")).unwrap_or_else(|| "?".into()),
                ),
                LOG_WARNING, false, false,
            );
        }
        // rfed departure: a message no single sync Resource can carry.
        if !plan.over_resource.is_empty() {
            self.mark_handled_for(peer_hash, &plan.over_resource);
            log(
                format!(
                    "[lxmf.prop] {} message(s) larger than one sync Resource ({} B) marked handled for peer {peer_str} without sending",
                    plan.over_resource.len(), MAX_SYNC_RESOURCE_BYTES,
                ),
                LOG_WARNING, false, false,
            );
        }

        let allowance = self.outbound_allowance() as usize;
        let mut offer: Vec<Vec<u8>> = {
            let entries = &self.entries;
            let Some(peer) = self.peers.get(peer_hash) else { return };
            plan.offer.into_iter()
                .filter(|tid| entries.contains_key(tid) && peer.unhandled_ids.contains(tid))
                .collect()
        };
        if offer.len() > allowance {
            log(
                format!(
                    "[lxmf.prop] offer to peer {peer_str} cut from {} to {allowance} message(s) by this minute's outbound budget",
                    offer.len(),
                ),
                LOG_DEBUG, false, false,
            );
            offer.truncate(allowance);
        }
        if offer.is_empty() {
            let reason = if allowance == 0 {
                "this minute's outbound budget is spent"
            } else {
                "no unhandled messages fit the peer's limits"
            };
            log(
                format!("[lxmf.prop] sync requested for peer {peer_str}, but nothing can be offered: {reason}. Sync complete."),
                LOG_DEBUG, false, false,
            );
            self.end_sync(peer_hash);
            return;
        }

        let io = Arc::clone(&self.sync_io);
        let sink = self.event_sink();
        let identity = self.identity.clone();
        let (link_id, peering_key, identified_link_id) = match self.peers.get(peer_hash) {
            Some(peer) => (
                peer.link_id.clone(),
                peer.peering_key.clone().map(|(key, _)| key),
                peer.identified_link_id.clone(),
            ),
            None => return,
        };
        let (Some(link_id), Some(peering_key)) = (link_id, peering_key) else {
            log(
                format!("[lxmf.prop] sync with peer {peer_str} is LINK_READY without a link or a peering key; ending it"),
                LOG_ERROR, false, false,
            );
            self.end_sync(peer_hash);
            return;
        };
        let needs_identify = identified_link_id.as_ref() != Some(&link_id);

        // Identify, then offer, back to back on the same link: the link
        // actor sends them in this order (LXMPeer.link_established identifies
        // and calls sync() at once). Once per link.
        if needs_identify {
            if let Err(e) = io.identify(peer_hash, &link_id, &identity) {
                log(format!("[lxmf.prop] identify on the sync link to peer {peer_str} failed: {e}; sync ended"), LOG_WARNING, false, false);
                self.end_sync(peer_hash);
                return;
            }
        }

        let session = {
            let Some(peer) = self.peers.get_mut(peer_hash) else { return };
            if needs_identify {
                peer.identified_link_id = Some(link_id.clone());
            }
            peer.sync_session += 1;
            peer.last_offer = offer.clone();
            peer.state = PropPeer::REQUEST_SENT;
            peer.sync_session
        };

        let offer_data = encode_value(Value::Array(vec![
            Value::Binary(peering_key),
            Value::Array(offer.iter().map(|id| Value::Binary(id.clone())).collect()),
        ]));
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        let offer_sent_at = now();
        let on_response = offer_response_callback(Arc::clone(&sink), peer_hash.to_vec(), session, offer_sent_at);
        let on_failed: Arc<dyn Fn() + Send + Sync> = {
            let peer = peer_hash.to_vec();
            Arc::new(move || sink(SyncEvent::OfferFailed { peer: peer.clone(), session }))
        };
        log(
            format!("[lxmf.prop] offering {} message(s) to peer {peer_str}", offer.len()),
            LOG_NOTICE, false, false,
        );
        if let Err(e) = io.request_offer(peer_hash, &link_id, offer_data, on_response, on_failed) {
            log(format!("[lxmf.prop] offer request to peer {peer_str} could not be sent: {e}; sync ended"), LOG_WARNING, false, false);
            self.end_sync(peer_hash);
        }
    }

    /// LXMPeer.offer_response.
    fn on_offer_response(arc: &Arc<Mutex<Self>>, peer_hash: &[u8], session: u64, response: Option<Vec<u8>>) {
        let next = {
            let Some(mut node) = lock_node(arc, "offer response") else { return };
            node.apply_offer_response(peer_hash, session, response)
        };
        match next {
            OfferNext::Done => {}
            OfferNext::Resync => Self::sync_peer(arc, peer_hash),
            OfferNext::Send(files) => Self::send_sync_resource(arc, peer_hash, session, files),
        }
    }

    /// The node side of LXMPeer.offer_response: reconcile the response with
    /// the offer. Ids the peer already has are marked handled; the ones it
    /// wants are NOT — they are returned, to be sent, and are marked handled
    /// only when their Resource concludes COMPLETE.
    fn apply_offer_response(&mut self, peer_hash: &[u8], session: u64, response: Option<Vec<u8>>) -> OfferNext {
        let peer_str = hexrep(peer_hash, false);
        let last_offer = match self.peers.get_mut(peer_hash) {
            Some(peer) if peer.state == PropPeer::REQUEST_SENT && peer.sync_session == session => {
                peer.state = PropPeer::RESPONSE_RECEIVED;
                std::mem::take(&mut peer.last_offer)
            }
            _ => {
                log(format!("[lxmf.prop] offer response from peer {peer_str} belongs to an ended sync; ignored"), LOG_DEBUG, false, false);
                return OfferNext::Done;
            }
        };

        let value = response.as_deref().and_then(|data| read_value(&mut Cursor::new(data)).ok());
        let wanted: Vec<Vec<u8>> = match value {
            Some(Value::Integer(code)) => {
                let code = code.as_u64().unwrap_or(0) as u8;
                match code {
                    ERROR_NO_IDENTITY => {
                        let Some(peer) = self.peers.get_mut(peer_hash) else { return OfferNext::Done };
                        if !peer.reidentified {
                            log(
                                format!("[lxmf.prop] peer {peer_str} indicated that no identification was received; identifying again"),
                                LOG_NOTICE, false, false,
                            );
                            peer.reidentified = true;
                            peer.identified_link_id = None;
                            peer.state = PropPeer::LINK_READY;
                            return OfferNext::Resync;
                        }
                        log(
                            format!("[lxmf.prop] peer {peer_str} still received no identification after a second identify; sync ended"),
                            LOG_WARNING, false, false,
                        );
                        self.end_sync(peer_hash);
                    }
                    ERROR_NO_ACCESS => {
                        log(format!("[lxmf.prop] peer {peer_str} indicated that access was denied, breaking peering"), LOG_WARNING, false, false);
                        self.unpeer(peer_hash);
                    }
                    ERROR_THROTTLED => {
                        log(
                            format!("[lxmf.prop] peer {peer_str} indicated that we're throttled, postponing sync for {PN_STAMP_THROTTLE_SECS:.0}s"),
                            LOG_NOTICE, false, false,
                        );
                        // Held, but not as a failure: see `throttled_until`.
                        if let Some(peer) = self.peers.get_mut(peer_hash) {
                            peer.throttled_until = now() + PN_STAMP_THROTTLE_SECS;
                        }
                        self.end_sync(peer_hash);
                    }
                    ERROR_INVALID_KEY => {
                        if let Some(peer) = self.peers.get_mut(peer_hash) {
                            let cost = peer.peering_cost;
                            if cost.is_some() && peer.key_reground_at_cost == cost {
                                // Ground again at this cost and refused again:
                                // a third key at the same cost cannot fare
                                // better. The peer validates against another
                                // cost than it announced, and its newer
                                // announce has not reached us.
                                peer.key_refused_at_cost = cost;
                                log(
                                    format!(
                                        "[lxmf.prop] peer {peer_str} refused a peering key ground again at its announced cost {}: its peering cost must differ from its announce; no sync with it until it announces another",
                                        cost.unwrap_or(0),
                                    ),
                                    LOG_WARNING, false, false,
                                );
                            } else {
                                // Once per announced cost: this repairs a key
                                // that is bad for another reason (ground under
                                // another rfed identity, or persisted from an
                                // older stamper).
                                peer.peering_key = None;
                                peer.key_reground_at_cost = cost;
                                log(
                                    format!(
                                        "[lxmf.prop] peer {peer_str} rejected our peering key; generating a new one at cost {}, once",
                                        cost.unwrap_or(0),
                                    ),
                                    LOG_WARNING, false, false,
                                );
                            }
                        }
                        self.end_sync(peer_hash);
                    }
                    other => {
                        log(
                            format!("[lxmf.prop] peer {peer_str} refused the sync offer with error 0x{other:02x}; {} message(s) stay unhandled", last_offer.len()),
                            LOG_WARNING, false, false,
                        );
                        self.end_sync(peer_hash);
                    }
                }
                return OfferNext::Done;
            }
            Some(Value::Boolean(false)) => {
                // The peer already has every offered message.
                self.mark_handled_for(peer_hash, &last_offer);
                Vec::new()
            }
            Some(Value::Boolean(true)) => last_offer.clone(),
            Some(Value::Array(list)) => {
                let listed: Vec<Vec<u8>> = list.into_iter()
                    .filter_map(|v| match v { Value::Binary(b) => Some(b), _ => None })
                    .collect();
                // If the peer did not want a message, it already has it.
                let unwanted: Vec<Vec<u8>> = last_offer.iter()
                    .filter(|tid| !listed.contains(tid))
                    .cloned()
                    .collect();
                self.mark_handled_for(peer_hash, &unwanted);
                let wanted: Vec<Vec<u8>> = listed.iter().filter(|tid| last_offer.contains(tid)).cloned().collect();
                if wanted.len() < listed.len() {
                    log(
                        format!(
                            "[lxmf.prop] peer {peer_str} asked for {} message(s) that were not in the offer; not sent",
                            listed.len() - wanted.len(),
                        ),
                        LOG_WARNING, false, false,
                    );
                }
                wanted
            }
            other => {
                log(
                    format!(
                        "[lxmf.prop] unreadable offer response from peer {peer_str} ({}); {} message(s) stay unhandled, sync ended",
                        match other { None => "no response data".to_string(), Some(v) => format!("{v:?}") },
                        last_offer.len(),
                    ),
                    LOG_WARNING, false, false,
                );
                self.end_sync(peer_hash);
                return OfferNext::Done;
            }
        };

        if wanted.is_empty() {
            log(
                format!("[lxmf.prop] peer {peer_str} did not request any of the {} offered messages, sync completed", last_offer.len()),
                LOG_DEBUG, false, false,
            );
            self.end_sync(peer_hash);
            return OfferNext::Done;
        }

        let mut files = Vec::with_capacity(wanted.len());
        let mut gone = Vec::new();
        for tid in wanted {
            match self.entries.get(&tid) {
                Some(entry) => files.push((tid, entry.filepath.clone())),
                None => gone.push(tid),
            }
        }
        if let Some(peer) = self.peers.get_mut(peer_hash) {
            for tid in &gone {
                peer.unhandled_ids.remove(tid);
            }
        }
        if !gone.is_empty() {
            log(
                format!("[lxmf.prop] {} message(s) peer {peer_str} wanted left the message store before they could be sent", gone.len()),
                LOG_NOTICE, false, false,
            );
        }
        if files.is_empty() {
            self.end_sync(peer_hash);
            return OfferNext::Done;
        }

        log(
            format!("[lxmf.prop] peer {peer_str} wanted {} of the {} offered messages", files.len(), last_offer.len()),
            LOG_DEBUG, false, false,
        );
        // What the peer wants leaves in this minute; the offer's reservation
        // ended with REQUEST_SENT above.
        self.charge_outbound(files.len() as u64);
        if let Some(peer) = self.peers.get_mut(peer_hash) {
            peer.state = PropPeer::RESOURCE_TRANSFERRING;
        }
        OfferNext::Send(files)
    }

    /// Send the wanted messages as one Resource of msgpack
    /// `[time, [lxm, ...]]` — what LXMPeer.offer_response sends and what
    /// LXMRouter.propagation_resource_concluded (and rfed's own
    /// `ingest_propagation_batch`) ingest. Each lxm is the stored file:
    /// the message with its propagation stamp. The files are read and the
    /// Resource built with the node released.
    fn send_sync_resource(arc: &Arc<Mutex<Self>>, peer_hash: &[u8], session: u64, files: Vec<(Vec<u8>, String)>) {
        let peer_str = hexrep(peer_hash, false);
        let mut ids = Vec::with_capacity(files.len());
        let mut messages = Vec::with_capacity(files.len());
        let mut unreadable = Vec::new();
        for (tid, path) in files {
            match fs::read(&path) {
                Ok(data) => {
                    ids.push(tid);
                    messages.push(data);
                }
                Err(e) => unreadable.push((tid, path, e.to_string())),
            }
        }
        for (tid, path, error) in &unreadable {
            log(
                format!("[lxmf.prop] cannot read message {} ({path}) for peer {peer_str}: {error}; it stays unhandled", hexrep(tid, false)),
                LOG_WARNING, false, false,
            );
        }

        let (io, sink, link_id) = {
            let Some(mut node) = lock_node(arc, "sync resource") else { return };
            let link_id = match node.peers.get(peer_hash) {
                Some(peer) if peer.state == PropPeer::RESOURCE_TRANSFERRING && peer.sync_session == session => peer.link_id.clone(),
                _ => {
                    log(format!("[lxmf.prop] sync with peer {peer_str} ended before its Resource was built; not sent"), LOG_DEBUG, false, false);
                    return;
                }
            };
            let Some(link_id) = link_id else {
                node.end_sync(peer_hash);
                return;
            };
            if ids.is_empty() {
                node.end_sync(peer_hash);
                return;
            }
            if let Some(peer) = node.peers.get_mut(peer_hash) {
                peer.transferring = Some(ids.clone());
                peer.current_sync_transfer_started = Some(now());
            }
            (Arc::clone(&node.sync_io), node.event_sink(), link_id)
        };

        let count = messages.len();
        let data = pack_sync_batch(now(), messages);
        log(
            format!("[lxmf.prop] sending {count} message(s) to peer {peer_str} as a Resource ({} B)", data.len()),
            LOG_NOTICE, false, false,
        );
        let on_concluded: Arc<dyn Fn(ResourceOutcome) + Send + Sync> = {
            let peer = peer_hash.to_vec();
            Arc::new(move |outcome: ResourceOutcome| {
                sink(SyncEvent::ResourceConcluded { peer: peer.clone(), session, outcome })
            })
        };
        if let Err(e) = io.send_resource(peer_hash, &link_id, data, on_concluded) {
            let Some(mut node) = lock_node(arc, "sync resource (failed)") else { return };
            let current = node.peers.get(peer_hash)
                .map(|peer| peer.state == PropPeer::RESOURCE_TRANSFERRING && peer.sync_session == session)
                .unwrap_or(false);
            if current {
                log(
                    format!("[lxmf.prop] could not start the sync Resource to peer {peer_str}: {e}; {count} message(s) stay unhandled"),
                    LOG_WARNING, false, false,
                );
                node.end_sync(peer_hash);
            }
        }
    }

    /// LXMPeer.resource_concluded.
    fn on_resource_concluded(arc: &Arc<Mutex<Self>>, peer_hash: &[u8], session: u64, outcome: ResourceOutcome) {
        let continue_sync = {
            let Some(mut node) = lock_node(arc, "sync resource concluded") else { return };
            node.apply_resource_outcome(peer_hash, session, &outcome)
        };
        if continue_sync {
            Self::sync_peer(arc, peer_hash);
        }
    }

    /// The node side of LXMPeer.resource_concluded. COMPLETE marks the
    /// transferred ids handled; anything else leaves them unhandled. Returns
    /// whether the session carries on at once (the reference's
    /// STRATEGY_PERSISTENT: sync again while the peer still lacks messages).
    fn apply_resource_outcome(&mut self, peer_hash: &[u8], session: u64, outcome: &ResourceOutcome) -> bool {
        let t = now();
        let peer_str = hexrep(peer_hash, false);
        let (ids, started) = match self.peers.get_mut(peer_hash) {
            Some(peer)
                if peer.state == PropPeer::RESOURCE_TRANSFERRING
                    && peer.sync_session == session
                    && peer.transferring.is_some() =>
            {
                (peer.transferring.take().unwrap_or_default(), peer.current_sync_transfer_started.take())
            }
            _ => {
                log(
                    format!("[lxmf.prop] sync Resource to peer {peer_str} concluded ({}) for an ended sync; ignored", outcome.status),
                    LOG_DEBUG, false, false,
                );
                return false;
            }
        };

        if !outcome.complete {
            log(
                format!(
                    "[lxmf.prop] resource transfer for LXMF peer sync to {peer_str} failed ({}); {} message(s) stay unhandled",
                    outcome.status, ids.len(),
                ),
                LOG_WARNING, false, false,
            );
            self.end_sync(peer_hash);
            return false;
        }

        self.mark_handled_for(peer_hash, &ids);
        let backlog_held = self.backlog_held();
        let held_link = self.sync_io.active_link(peer_hash);
        let (more_to_sync, on_held_link) = {
            let fresh = &self.fresh_since_start;
            let Some(peer) = self.peers.get_mut(peer_hash) else { return false };
            let mut rate_str = String::new();
            if let Some(started) = started {
                let elapsed = (t - started).max(1e-3);
                peer.sync_transfer_rate = (outcome.transfer_size as f64 * 8.0) / elapsed;
                rate_str = format!(" at {:.0} bit/s", peer.sync_transfer_rate);
            }
            peer.alive = true;
            peer.last_heard = t;
            log(
                format!("[lxmf.prop] syncing {} messages to peer {peer_str} completed{rate_str}", ids.len()),
                LOG_NOTICE, false, false,
            );
            (
                Self::has_sync_candidates(backlog_held, fresh, peer),
                held_link.is_some() && held_link == peer.link_id,
            )
        };

        if !more_to_sync {
            self.end_sync(peer_hash);
            return false;
        }
        // The reference tears the link down and syncs again on a new one.
        // While the held link is still up, the next offer goes on it instead.
        if on_held_link {
            if let Some(peer) = self.peers.get_mut(peer_hash) {
                peer.state = PropPeer::LINK_READY;
            }
        } else {
            self.end_sync(peer_hash);
        }
        true
    }

    /// LXMPeer.request_failed: the offer got no response.
    fn on_offer_failed(arc: &Arc<Mutex<Self>>, peer_hash: &[u8], session: u64) {
        let Some(mut node) = lock_node(arc, "offer failed") else { return };
        let peer_str = hexrep(peer_hash, false);
        match node.peers.get(peer_hash) {
            Some(peer) if peer.state == PropPeer::REQUEST_SENT && peer.sync_session == session => {
                log(
                    format!("[lxmf.prop] sync request to peer {peer_str} failed; {} message(s) stay unhandled", peer.last_offer.len()),
                    LOG_WARNING, false, false,
                );
                node.end_sync(peer_hash);
            }
            _ => log(format!("[lxmf.prop] offer failure from peer {peer_str} belongs to an ended sync; ignored"), LOG_DEBUG, false, false),
        }
    }

    /// AppLinks reports the held link to `peer_hash` ACTIVE
    /// (LXMPeer.link_established).
    fn on_link_active(arc: &Arc<Mutex<Self>>, peer_hash: &[u8], link_id: Vec<u8>) {
        let proceed = {
            let Some(mut node) = lock_node(arc, "sync link up") else { return };
            let peer_str = hexrep(peer_hash, false);
            if !node.peers.contains_key(peer_hash) {
                // Only the sync links rfed opens report ACTIVE with a link
                // (rfed.node's AppLinks are ephemeral, reported without one).
                // This one's peer was removed while its attempt was in flight:
                // unpeer's close came first, so AppLinks no longer tracks the
                // destination and would neither close the link nor report it.
                log(format!("[lxmf.prop] closing a sync link to {peer_str}, which is no longer a peer"), LOG_NOTICE, false, false);
                node.sync_io.close_link(peer_hash);
                return;
            }
            let Some(peer) = node.peers.get_mut(peer_hash) else { return };
            match peer.state {
                PropPeer::LINK_ESTABLISHING => {
                    log(format!("[lxmf.prop] sync link to peer {peer_str} established"), LOG_DEBUG, false, false);
                    peer.link_id = Some(link_id);
                    peer.identified_link_id = None;
                    peer.reidentified = false;
                    peer.next_sync_attempt = 0.0;
                    peer.state = PropPeer::LINK_READY;
                    true
                }
                PropPeer::IDLE => {
                    // AppLinks brought a link up on its own (a re-open after
                    // a close, or an attempt that outlived its session):
                    // nothing uses it.
                    log(format!("[lxmf.prop] closing a link to peer {peer_str} that no sync is using"), LOG_DEBUG, false, false);
                    node.sync_io.close_link(peer_hash);
                    false
                }
                _ if peer.link_id.as_ref() == Some(&link_id) => false,
                state => {
                    log(
                        format!(
                            "[lxmf.prop] a new link to peer {peer_str} came up while its sync ({}) runs on another; closing it",
                            PropPeer::state_name(state),
                        ),
                        LOG_DEBUG, false, false,
                    );
                    node.sync_io.close_link(peer_hash);
                    false
                }
            }
        };
        if proceed {
            Self::sync_peer(arc, peer_hash);
        }
    }

    /// AppLinks reports the link to `peer_hash` down (LXMPeer.link_closed,
    /// and a path request that went unanswered).
    ///
    /// AppLinks reports DISCONNECTED for any link to the destination closing,
    /// including a previous session's, so the report counts only when this
    /// session's link attempt or link is really gone. A session whose link
    /// closed ends here even with a Resource in flight: a Resource that had
    /// not been advertised yet when the link closed never concludes
    /// (Reticulum-rust `advertise_shared` waits for the link forever), and
    /// its ids must not wait with it. They stay unhandled; if the Resource
    /// had in fact completed, the next offer finds the peer has them.
    fn on_link_down(arc: &Arc<Mutex<Self>>, peer_hash: &[u8]) {
        let Some(mut node) = lock_node(arc, "sync link down") else { return };
        let peer_str = hexrep(peer_hash, false);
        let Some(peer) = node.peers.get(peer_hash) else { return };
        match peer.state {
            PropPeer::IDLE => {}
            PropPeer::LINK_ESTABLISHING => {
                if node.sync_io.link_attempt_live(peer_hash) {
                    log(format!("[lxmf.prop] link-down report for peer {peer_str} while its link attempt is still live; ignored"), LOG_DEBUG, false, false);
                    return;
                }
                log(
                    format!(
                        "[lxmf.prop] could not establish a sync link to peer {peer_str}; next attempt in {:.0}s",
                        (peer.next_sync_attempt - now()).max(0.0),
                    ),
                    LOG_NOTICE, false, false,
                );
                node.end_sync(peer_hash);
            }
            state => {
                let held = node.sync_io.active_link(peer_hash);
                if held.is_some() && held == peer.link_id {
                    log(format!("[lxmf.prop] link-down report for peer {peer_str} while its sync link is up; ignored"), LOG_DEBUG, false, false);
                    return;
                }
                let pending = peer.transferring.as_ref().map(|t| t.len()).unwrap_or(peer.last_offer.len());
                log(
                    format!(
                        "[lxmf.prop] sync link to peer {peer_str} closed in state {}; {pending} message(s) stay unhandled",
                        PropPeer::state_name(state),
                    ),
                    LOG_WARNING, false, false,
                );
                node.end_sync(peer_hash);
            }
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

// ── Outbound peer sync: events, the network seam, offer planning ─────────────

/// One step's trigger for an outbound peer sync session. Network callbacks
/// and the sync tick produce these; the sync worker runs them in order.
pub(crate) enum SyncEvent {
    /// The tick chose this peer (LXMRouter.sync_peers → LXMPeer.sync).
    Start { peer: Vec<u8> },
    /// AppLinks reports the held link to the peer ACTIVE.
    LinkActive { peer: Vec<u8>, link_id: Vec<u8> },
    /// AppLinks reports a link to the peer DISCONNECTED (or the path race failed).
    LinkDown { peer: Vec<u8> },
    /// The `/offer` request's response (the msgpack-encoded value).
    OfferResponse { peer: Vec<u8>, session: u64, response: Option<Vec<u8>> },
    /// The `/offer` request failed (timed out, or its link closed).
    OfferFailed { peer: Vec<u8>, session: u64 },
    /// The sync Resource concluded, COMPLETE or not.
    ResourceConcluded { peer: Vec<u8>, session: u64, outcome: ResourceOutcome },
}

impl SyncEvent {
    fn describe(&self) -> String {
        match self {
            SyncEvent::Start { peer } => format!("start sync with {}", hexrep(peer, false)),
            SyncEvent::LinkActive { peer, link_id } => {
                format!("link {} to {} active", hexrep(link_id, false), hexrep(peer, false))
            }
            SyncEvent::LinkDown { peer } => format!("link to {} down", hexrep(peer, false)),
            SyncEvent::OfferResponse { peer, session, .. } => {
                format!("offer response from {} (session {session})", hexrep(peer, false))
            }
            SyncEvent::OfferFailed { peer, session } => {
                format!("offer to {} failed (session {session})", hexrep(peer, false))
            }
            SyncEvent::ResourceConcluded { peer, session, outcome } => format!(
                "sync Resource to {} concluded {} (session {session})",
                hexrep(peer, false), outcome.status,
            ),
        }
    }
}

/// Delivers a sync event to the sync worker.
pub(crate) type SyncEventSink = Arc<dyn Fn(SyncEvent) + Send + Sync>;

/// How a sync Resource concluded, as its callback reported it.
#[derive(Clone, Debug)]
pub(crate) struct ResourceOutcome {
    pub complete: bool,
    pub status: String,
    /// Bytes on the wire (after compression), for the transfer rate.
    pub transfer_size: usize,
}

/// Everything outbound peer sync does on the network. Each call returns at
/// once; outcomes arrive through the callbacks (and AppLinks' status
/// callback), never by waiting. `AppLinksSyncIo` is the only production
/// implementation; the unit tests drive the sync state machine through a
/// recording fake.
pub(crate) trait PeerSyncIo: Send + Sync {
    /// Id of the link held to `peer` when it is ACTIVE.
    fn active_link(&self, peer: &[u8]) -> Option<Vec<u8>>;
    /// Whether a link attempt to `peer` is in flight or its link is up.
    fn link_attempt_live(&self, peer: &[u8]) -> bool;
    /// Start establishing the held link to `peer`.
    fn open_link(&self, peer: &[u8]);
    /// Drop the held link to `peer` and forget it, with no re-open.
    fn close_link(&self, peer: &[u8]);
    /// Identify on the held link `link_id` to `peer`.
    fn identify(&self, peer: &[u8], link_id: &[u8], identity: &Identity) -> Result<(), String>;
    /// Request `/offer` with `data` on the held link `link_id` to `peer`.
    fn request_offer(
        &self,
        peer: &[u8],
        link_id: &[u8],
        data: Vec<u8>,
        on_response: Arc<dyn Fn(Option<Vec<u8>>) + Send + Sync>,
        on_failed: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), String>;
    /// Send `data` as a Resource on the held link `link_id` to `peer`.
    fn send_resource(
        &self,
        peer: &[u8],
        link_id: &[u8],
        data: Vec<u8>,
        on_concluded: Arc<dyn Fn(ResourceOutcome) + Send + Sync>,
    ) -> Result<(), String>;
}

/// Peer sync over AppLinks-held `lxmf.propagation` links. AppLinks owns the
/// link (path race, establishment, teardown — Reticulum-rust SUBSYSTEMS.md
/// §1); a session opens it with `open_persistent`, and releases it with
/// `close`, where the reference tears its per-sync link down. Every call on
/// a link names the link id the session runs on, so nothing lands on a
/// different link than the one the offer was identified and validated on.
struct AppLinksSyncIo;

impl AppLinksSyncIo {
    fn held(peer: &[u8], link_id: &[u8]) -> Result<LinkHandle, String> {
        AppLinks::get_handle(peer)
            .filter(|handle| handle.status() == reticulum_rust::link::STATE_ACTIVE && handle.link_id() == link_id)
            .ok_or_else(|| {
                format!("the sync link {} to {} is no longer held and active", hexrep(link_id, false), hexrep(peer, false))
            })
    }
}

impl PeerSyncIo for AppLinksSyncIo {
    fn active_link(&self, peer: &[u8]) -> Option<Vec<u8>> {
        AppLinks::get_handle(peer)
            .filter(|handle| handle.status() == reticulum_rust::link::STATE_ACTIVE)
            .map(|handle| handle.link_id())
    }

    fn link_attempt_live(&self, peer: &[u8]) -> bool {
        matches!(
            AppLinks::status(peer),
            app_links::APP_LINK_PATH_REQUESTED | app_links::APP_LINK_ESTABLISHING | app_links::APP_LINK_ACTIVE
        )
    }

    fn open_link(&self, peer: &[u8]) {
        AppLinks::open_persistent(peer, LXMF_APP, &[PROP_ASPECT]);
    }

    fn close_link(&self, peer: &[u8]) {
        AppLinks::close(peer);
    }

    fn identify(&self, peer: &[u8], link_id: &[u8], identity: &Identity) -> Result<(), String> {
        Self::held(peer, link_id)?
            .identify(identity)
            .map_err(|_| format!("the sync link to {} is gone", hexrep(peer, false)))
    }

    fn request_offer(
        &self,
        peer: &[u8],
        link_id: &[u8],
        data: Vec<u8>,
        on_response: Arc<dyn Fn(Option<Vec<u8>>) + Send + Sync>,
        on_failed: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), String> {
        let link = Self::held(peer, link_id)?;
        let response_cb: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
            Arc::new(move |receipt: RequestReceipt| on_response(receipt.response.clone()));
        let failed_cb: Arc<dyn Fn(RequestReceipt) + Send + Sync> =
            Arc::new(move |_receipt: RequestReceipt| on_failed());
        link.request(OFFER_PATH.to_string(), data, Some(response_cb), Some(failed_cb), None)
            .map(|_| ())
            .map_err(|_| format!("the sync link to {} is gone", hexrep(peer, false)))
    }

    fn send_resource(
        &self,
        peer: &[u8],
        link_id: &[u8],
        data: Vec<u8>,
        on_concluded: Arc<dyn Fn(ResourceOutcome) + Send + Sync>,
    ) -> Result<(), String> {
        use reticulum_rust::resource::{AutoCompressOption, Resource, ResourceData, ResourceStatus};
        let link = Self::held(peer, link_id)?;
        // The Resource's own RTT-scaled timeouts decide its outcome, and its
        // callback fires once, COMPLETE or not (a closed link cancels it).
        // It runs with the Resource locked: it only forwards the outcome.
        let concluded: Arc<dyn Fn(Arc<Mutex<Resource>>) + Send + Sync> = Arc::new(move |resource| {
            let outcome = match resource.lock() {
                Ok(r) => ResourceOutcome {
                    complete: r.status == ResourceStatus::Complete,
                    status: format!("{:?}", r.status),
                    transfer_size: r.get_transfer_size(),
                },
                Err(_) => ResourceOutcome { complete: false, status: "poisoned".to_string(), transfer_size: 0 },
            };
            on_concluded(outcome);
        });
        let resource = Resource::new_internal(
            Some(ResourceData::Bytes(data)),
            link,
            None,
            false,
            AutoCompressOption::Enabled,
            Some(concluded),
            None,
            None,
            1,
            None,
            None,
            false,
            0,
            None,
        )?;
        Resource::advertise_shared(Arc::new(Mutex::new(resource)));
        Ok(())
    }
}

/// A message that may go in an offer.
pub(crate) struct OfferCandidate {
    pub tid: Vec<u8>,
    /// Stored size: the message with its stamp.
    pub size: usize,
    /// LXMRouter.get_weight; lighter goes first.
    pub weight: f64,
}

/// What `plan_offer` decided.
#[derive(Debug, Default)]
pub(crate) struct OfferPlan {
    /// To offer, lightest first.
    pub offer: Vec<Vec<u8>>,
    /// Over the peer's per-message transfer limit: marked handled, never sent
    /// (the reference's rule).
    pub too_big: Vec<Vec<u8>>,
    /// Too large for any one sync Resource: marked handled, never sent (an
    /// rfed departure, see MAX_SYNC_RESOURCE_BYTES).
    pub over_resource: Vec<Vec<u8>>,
    /// The reference's estimate of the batch size in bytes.
    pub estimated_bytes: f64,
}

/// The offer-building part of LXMPeer.sync. Candidates go lightest first; a
/// message over the peer's per-message transfer limit (KB) is set aside to be
/// marked handled; the batch stays under the peer's sync limit (KB), counting
/// each message's size plus 16 B and 24 B for the batch, as the reference
/// estimates it. rfed also keeps the batch within one Resource segment and
/// within `max_ids` messages. The per-minute budget is applied by the caller.
pub(crate) fn plan_offer(
    mut candidates: Vec<OfferCandidate>,
    transfer_limit_kb: Option<f64>,
    sync_limit_kb: Option<f64>,
    max_ids: usize,
) -> OfferPlan {
    const PER_MESSAGE_OVERHEAD: f64 = 16.0;
    const BATCH_OVERHEAD: f64 = 24.0;
    let resource_limit = MAX_SYNC_RESOURCE_BYTES as f64;
    candidates.sort_by(|a, b| a.weight.partial_cmp(&b.weight).unwrap_or(std::cmp::Ordering::Equal));
    let mut plan = OfferPlan { estimated_bytes: BATCH_OVERHEAD, ..OfferPlan::default() };
    for candidate in candidates {
        let transfer_size = candidate.size as f64 + PER_MESSAGE_OVERHEAD;
        if let Some(limit) = transfer_limit_kb {
            if transfer_size > limit * 1000.0 {
                plan.too_big.push(candidate.tid);
                continue;
            }
        }
        if BATCH_OVERHEAD + transfer_size > resource_limit {
            plan.over_resource.push(candidate.tid);
            continue;
        }
        if plan.offer.len() >= max_ids {
            continue;
        }
        let next_size = plan.estimated_bytes + transfer_size;
        if let Some(limit) = sync_limit_kb {
            if next_size >= limit * 1000.0 {
                continue;
            }
        }
        if next_size > resource_limit {
            continue;
        }
        plan.estimated_bytes = next_size;
        plan.offer.push(candidate.tid);
    }
    plan
}

/// An offer's candidates, gathered under the node lock and planned without it.
struct PreparedOffer {
    session: u64,
    candidates: Vec<OfferCandidate>,
    transfer_limit_kb: Option<f64>,
    sync_limit_kb: Option<f64>,
}

/// What follows an offer response.
enum OfferNext {
    /// The session ended, or went on without a transfer.
    Done,
    /// Identify again and re-offer on the same link (ERROR_NO_IDENTITY).
    Resync,
    /// Send these `(transient id, message file)` as the sync Resource.
    Send(Vec<(Vec<u8>, String)>),
}

/// The `/offer` request's response callback: hand the response to the sync
/// worker, THEN hold the round trip to DESIGN_PRINCIPLES §1.
///
/// In a debug build a response more than 5 s after `offer_sent_at` panics in
/// the assertion, on the thread the link runs its response callbacks on. The
/// assertion used to come first, so that panic also lost the response: it had
/// already claimed the pending request, so no failure or timeout followed,
/// and the peer sat in REQUEST_SENT for good with its offer still reserving
/// the minute's budget — two such peers and outbound sync stopped. Forwarded
/// first, the violation is still loud and the session still concludes.
fn offer_response_callback(
    sink: SyncEventSink,
    peer: Vec<u8>,
    session: u64,
    offer_sent_at: f64,
) -> Arc<dyn Fn(Option<Vec<u8>>) + Send + Sync> {
    Arc::new(move |response: Option<Vec<u8>>| {
        sink(SyncEvent::OfferResponse { peer: peer.clone(), session, response });
        // NEVER REMOVE EVER — see DESIGN_PRINCIPLES.md §1
        reticulum_rust::send_assertion::assert_send_completed_in_time("lxmf.propagation.offer", offer_sent_at);
    })
}

/// A sync batch in the propagation wire format, msgpack `[timebase, [lxm, ...]]`
/// with native types (CHECK_THESE_THINGS_FIRST §11): a float and an array of
/// bin, as LXMPeer.offer_response packs `[time.time(), lxm_list]`.
fn pack_sync_batch(timebase: f64, messages: Vec<Vec<u8>>) -> Vec<u8> {
    encode_value(Value::Array(vec![
        Value::F64(timebase),
        Value::Array(messages.into_iter().map(Value::Binary).collect()),
    ]))
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
                LxmfPropagationNode::ingest_propagation_batch(&ingest_node, &batch(64), None);
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

    /// X7: a recipient counts as notified only when a wake packet left.
    mod notify_count_tests {
        use super::super::*;
        use crate::notify::rns::fake::FakeStack;

        const RECIPIENT: [u8; 16] = [0x71; 16];
        const SENDER: [u8; 16] = [0x72; 16];

        /// An LXMF message for RECIPIENT, as it sits in the messagestore.
        fn lxmf_data() -> Vec<u8> {
            [&RECIPIENT[..], &SENDER[..], &[0x73; 80][..]].concat()
        }

        /// A registry holding one apns.relay registration for RECIPIENT, and
        /// that relay's identity as an announce leaves it.
        fn registered(tag: &str) -> (Arc<Mutex<NotifyRegistry>>, Vec<u8>, Identity, std::path::PathBuf) {
            let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let dir = std::env::temp_dir().join(format!("rfed_notify_count_{tag}_{unique}"));
            std::fs::create_dir_all(&dir).expect("temp dir");
            let relay = Identity::new(true);
            let relay_hash = Destination::hash(relay.hash.as_deref(), "apns", &["relay"]);
            let recalled = Identity::from_public_key(&relay.get_public_key().unwrap()).unwrap();
            let mut registry = NotifyRegistry::load(dir.join("notify.rmp"));
            registry.register(RECIPIENT.to_vec(), None, hexrep(&relay_hash, false));
            (Arc::new(Mutex::new(registry)), relay_hash, recalled, dir)
        }

        #[test]
        fn a_wake_counts_as_notified_only_when_its_packet_left() {
            let (registry, relay_hash, relay, dir) = registered("counting");

            let no_path = FakeStack::new(&relay_hash, Some(relay.clone())).without_path();
            assert!(
                !notify_recipient(&no_path, &registry, &lxmf_data(), ""),
                "a registration whose relay has no path is not a notification",
            );
            assert_eq!(*no_path.path_requests.lock().unwrap(), vec![relay_hash.clone()]);

            let no_identity = FakeStack::new(&relay_hash, None);
            assert!(
                !notify_recipient(&no_identity, &registry, &lxmf_data(), ""),
                "a registration whose relay identity is unknown is not a notification",
            );

            let no_interface = FakeStack::new(&relay_hash, Some(relay.clone())).without_interface();
            assert!(
                !notify_recipient(&no_interface, &registry, &lxmf_data(), ""),
                "a packet no interface took is not a notification",
            );

            let live = FakeStack::new(&relay_hash, Some(relay));
            assert!(notify_recipient(&live, &registry, &lxmf_data(), ""), "a wake that left is");
            assert_eq!(live.packets.lock().unwrap().len(), 1);

            let _ = std::fs::remove_dir_all(dir);
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

    /// The propagation-ingest distro fan-out's hand-off both queues the blob
    /// for /rfed/pull and wakes the device. Until 2026-09-26 it only queued,
    /// so a device whose app was closed got no push for its distro.
    #[test]
    fn distro_misses_are_queued_for_pull_and_woken() {
        use crate::notify::rns::fake::FakeStack;
        use crate::notify::rns::RelayStack;

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("rfed_distro_hand_off_{unique}"));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let queue = Arc::new(Mutex::new(crate::deferred_queue::DeferredQueue::load(dir.join("deferred.rmp"))));
        let notify = Arc::new(Mutex::new(super::NotifyRegistry::load(dir.join("notify.rmp"))));
        let relay = reticulum_rust::identity::Identity::new(true);
        let relay_hash = reticulum_rust::destination::Destination::hash(relay.hash.as_deref(), "rfed", &["notify"]);
        let relay_public = reticulum_rust::identity::Identity::from_public_key(&relay.get_public_key().expect("key"))
            .expect("relay");
        let device = crate::distro::Unconfirmed { queue_key: vec![0x11; 16], wake_key: vec![0x44; 16] };
        notify
            .lock()
            .unwrap()
            .register(device.wake_key.clone(), None, reticulum_rust::hexrep(&relay_hash, false));
        let handles = super::DeliveryHandles {
            registry: Arc::clone(&notify),
            stream_registry: Arc::new(Mutex::new(super::PropagationStreamRegistry::default())),
            link_sessions: Arc::new(Mutex::new(super::LinkSessionRegistry::default())),
            distro_table: None,
            distro_blob_store: None,
            distro_hook_registry: None,
            deferred_queue: Some(Arc::clone(&queue)),
        };
        let stack = Arc::new(FakeStack::new(&relay_hash, Some(relay_public)));
        let distro_hash = vec![0x22; 16];
        let lxmf_data = vec![0x33; 64];

        let hand_off = handles.distro_hand_off(
            Arc::clone(&stack) as Arc<dyn RelayStack + Send + Sync>,
            &distro_hash,
            &lxmf_data,
        );
        hand_off(device.clone());

        let pending = queue.lock().expect("queue lock").drain(&device.queue_key);
        assert_eq!(pending.len(), 1, "queued under the identity hash");
        assert_eq!(pending[0].channel_hash, distro_hash);
        assert_eq!(pending[0].blob, lxmf_data);
        assert_eq!(stack.packets.lock().unwrap().len(), 1, "and the device's registration was woken");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Outbound peer sync goes through AppLinks-held links only: the
    /// production network seam opens them with `open_persistent`, uses the
    /// held handle, releases them with `close`, and never builds a raw link
    /// (Reticulum-rust SUBSYSTEMS.md §1: AppLinks owns link lifecycle).
    #[test]
    fn peer_sync_uses_persistent_app_links() {
        let source = include_str!("lxmf_propagation.rs");
        let start = source
            .find("impl PeerSyncIo for AppLinksSyncIo")
            .expect("AppLinksSyncIo present");
        let end = source[start..].find("\n}\n").map(|offset| start + offset).expect("end of impl");
        let fragment = &source[start..end];

        assert!(
            fragment.contains("AppLinks::get_handle(peer)"),
            "RFed propagation peer sync must use the AppLinks-held handle"
        );
        assert!(
            fragment.contains("AppLinks::open_persistent(peer, LXMF_APP, &[PROP_ASPECT]);"),
            "RFed propagation peer sync must request a persistent AppLinks propagation link"
        );
        assert!(
            fragment.contains("AppLinks::close(peer);"),
            "RFed propagation peer sync must release its link through AppLinks"
        );
        assert!(
            !fragment.contains("Link::new_outbound"),
            "RFed propagation peer sync must not construct raw outbound links directly"
        );
    }

    /// Outbound peer sync (LXMPeer / LXMRouter.sync_peers), driven end to end
    /// through a fake network: each test fires the callbacks the network
    /// would, in the order it would, and runs the events as the sync worker
    /// does.
    mod peer_sync_tests {
        use super::ingest_lock_scope_tests::test_node;
        use super::super::*;
        use std::collections::VecDeque;

        const LINK_1: [u8; 16] = [0xA1; 16];
        const LINK_2: [u8; 16] = [0xA2; 16];

        type OnResponse = Arc<dyn Fn(Option<Vec<u8>>) + Send + Sync>;
        type OnFailed = Arc<dyn Fn() + Send + Sync>;
        type OnConcluded = Arc<dyn Fn(ResourceOutcome) + Send + Sync>;

        /// The network as the sync state machine sees it. Records every call;
        /// keeps the callbacks for the test to fire.
        #[derive(Default)]
        struct FakeIo {
            calls: Mutex<Vec<String>>,
            active: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
            offers: Mutex<VecDeque<(Vec<u8>, OnResponse, OnFailed)>>,
            resources: Mutex<VecDeque<(Vec<u8>, OnConcluded)>>,
        }

        impl FakeIo {
            fn record(&self, call: String) {
                self.calls.lock().unwrap().push(call);
            }
            fn calls(&self) -> Vec<String> {
                self.calls.lock().unwrap().clone()
            }
            /// AppLinks now holds `link` to `peer`, ACTIVE.
            fn link_up(&self, peer: &[u8], link: &[u8]) {
                self.active.lock().unwrap().insert(peer.to_vec(), link.to_vec());
            }
            /// The held link to `peer` is gone.
            fn link_gone(&self, peer: &[u8]) {
                self.active.lock().unwrap().remove(peer);
            }
            fn offer_count(&self) -> usize {
                self.offers.lock().unwrap().len()
            }
            fn take_offer(&self) -> (Vec<u8>, OnResponse, OnFailed) {
                self.offers.lock().unwrap().pop_front().expect("an offer was requested")
            }
            fn take_resource(&self) -> (Vec<u8>, OnConcluded) {
                self.resources.lock().unwrap().pop_front().expect("a Resource was sent")
            }
            fn resource_count(&self) -> usize {
                self.resources.lock().unwrap().len()
            }
        }

        impl PeerSyncIo for FakeIo {
            fn active_link(&self, peer: &[u8]) -> Option<Vec<u8>> {
                self.active.lock().unwrap().get(peer).cloned()
            }
            fn link_attempt_live(&self, peer: &[u8]) -> bool {
                self.active_link(peer).is_some()
            }
            fn open_link(&self, peer: &[u8]) {
                self.record(format!("open {}", hexrep(&peer[..1], false)));
            }
            fn close_link(&self, peer: &[u8]) {
                self.link_gone(peer);
                self.record(format!("close {}", hexrep(&peer[..1], false)));
            }
            fn identify(&self, _peer: &[u8], link_id: &[u8], _identity: &Identity) -> Result<(), String> {
                self.record(format!("identify {}", hexrep(&link_id[..1], false)));
                Ok(())
            }
            fn request_offer(
                &self,
                _peer: &[u8],
                link_id: &[u8],
                data: Vec<u8>,
                on_response: OnResponse,
                on_failed: OnFailed,
            ) -> Result<(), String> {
                self.record(format!("offer {}", hexrep(&link_id[..1], false)));
                self.offers.lock().unwrap().push_back((data, on_response, on_failed));
                Ok(())
            }
            fn send_resource(
                &self,
                _peer: &[u8],
                link_id: &[u8],
                data: Vec<u8>,
                on_concluded: OnConcluded,
            ) -> Result<(), String> {
                self.record(format!("resource {}", hexrep(&link_id[..1], false)));
                self.resources.lock().unwrap().push_back((data, on_concluded));
                Ok(())
            }
        }

        struct Harness {
            node: Arc<Mutex<LxmfPropagationNode>>,
            io: Arc<FakeIo>,
            events: Arc<Mutex<VecDeque<SyncEvent>>>,
            next_message: std::cell::Cell<u32>,
        }

        impl Harness {
            fn new(tag: &str) -> Self {
                let node = test_node(tag);
                let io = Arc::new(FakeIo::default());
                let events: Arc<Mutex<VecDeque<SyncEvent>>> = Arc::new(Mutex::new(VecDeque::new()));
                {
                    let mut g = node.lock().unwrap();
                    g.sync_io = io.clone();
                    let queue = events.clone();
                    g.sync_event_sink = Some(Arc::new(move |event| queue.lock().unwrap().push_back(event)));
                }
                Harness { node, io, events, next_message: std::cell::Cell::new(0) }
            }

            /// Run every queued event in order, as the sync worker does.
            fn pump(&self) {
                loop {
                    let next = self.events.lock().unwrap().pop_front();
                    match next {
                        Some(event) => LxmfPropagationNode::handle_sync_event(&self.node, event),
                        None => break,
                    }
                }
            }

            fn event(&self, event: SyncEvent) {
                self.events.lock().unwrap().push_back(event);
                self.pump();
            }

            fn start(&self, peer: &[u8]) {
                self.event(SyncEvent::Start { peer: peer.to_vec() });
            }

            /// AppLinks brings `link` to `peer` up and says so.
            fn link_active(&self, peer: &[u8], link: &[u8]) {
                self.io.link_up(peer, link);
                self.event(SyncEvent::LinkActive { peer: peer.to_vec(), link_id: link.to_vec() });
            }

            /// A peer as an announce leaves it: alive, costs known, a
            /// peering key ready when `key_ready`.
            fn add_peer(&self, hash: &[u8], key_ready: bool) {
                let mut peer = PropPeer::new(hash.to_vec());
                peer.alive = true;
                peer.last_heard = now();
                peer.propagation_stamp_cost = Some(16);
                peer.propagation_stamp_flexibility = Some(3);
                peer.peering_cost = Some(18);
                peer.propagation_transfer_limit = Some(256.0);
                peer.propagation_sync_limit = Some(10240.0);
                if key_ready {
                    peer.peering_key = Some((vec![0x5A; 32], 18));
                }
                self.node.lock().unwrap().peers.insert(hash.to_vec(), peer);
            }

            /// Store `count` messages of `size` bytes (with their stamp);
            /// every peer then lacks them.
            fn store(&self, count: usize, size: usize) -> Vec<Vec<u8>> {
                let mut g = self.node.lock().unwrap();
                (0..count)
                    .map(|_| {
                        let n = self.next_message.get();
                        self.next_message.set(n + 1);
                        let mut lxmf = vec![0x77u8; size - lx_stamper::STAMP_SIZE];
                        lxmf[16..20].copy_from_slice(&n.to_be_bytes());
                        let stamp = vec![0x33u8; lx_stamper::STAMP_SIZE];
                        g.store_message(&lxmf, 16, Some(&stamp), None).expect("stored")
                    })
                    .collect()
            }

            fn peer<R>(&self, hash: &[u8], f: impl FnOnce(&PropPeer) -> R) -> R {
                f(self.node.lock().unwrap().peers.get(hash).expect("peer"))
            }

            fn state(&self, hash: &[u8]) -> u8 {
                self.peer(hash, |p| p.state)
            }

            fn unhandled(&self, hash: &[u8]) -> usize {
                self.peer(hash, |p| p.unhandled_ids.len())
            }

            fn handled(&self, hash: &[u8]) -> usize {
                self.peer(hash, |p| p.handled_ids.len())
            }
        }

        fn msgpack(value: Value) -> Option<Vec<u8>> {
            Some(encode_value(value))
        }

        fn failed() -> ResourceOutcome {
            ResourceOutcome { complete: false, status: "Failed".into(), transfer_size: 0 }
        }

        fn complete() -> ResourceOutcome {
            ResourceOutcome { complete: true, status: "Complete".into(), transfer_size: 4096 }
        }

        /// The ids in an `/offer` request `[peering_key, [id, ...]]`.
        fn offered_ids(data: &[u8]) -> Vec<Vec<u8>> {
            match read_value(&mut Cursor::new(data)).expect("offer msgpack") {
                Value::Array(items) => {
                    assert!(matches!(items[0], Value::Binary(_)), "the peering key is bin");
                    match &items[1] {
                        Value::Array(ids) => ids.iter()
                            .map(|v| match v { Value::Binary(b) => b.clone(), other => panic!("id not bin: {other:?}") })
                            .collect(),
                        other => panic!("offer ids not an array: {other:?}"),
                    }
                }
                other => panic!("offer not an array: {other:?}"),
            }
        }

        /// The staging defect (2026-09-27): ids were marked handled before the
        /// batch left, so every batch the peer never stored was lost for it.
        /// They are now handled only when the sync Resource concludes
        /// COMPLETE; a Resource that fails leaves every one unhandled.
        #[test]
        fn wanted_messages_are_handled_only_when_their_resource_completes() {
            let h = Harness::new("sync_handled_on_complete");
            let peer = [0x11u8; 16];
            h.add_peer(&peer, true);
            let ids = h.store(3, 300);
            assert_eq!(h.unhandled(&peer), 3);

            // No link is held: the session opens one and waits for it.
            h.start(&peer);
            assert_eq!(h.state(&peer), PropPeer::LINK_ESTABLISHING);
            assert_eq!(h.io.calls(), vec!["open 11"]);
            // A second choice of the same peer (a late tick) leaves the
            // running session alone.
            h.start(&peer);
            assert_eq!(h.state(&peer), PropPeer::LINK_ESTABLISHING);
            assert!(h.peer(&peer, |p| p.alive), "not demoted by its own session's backoff");
            assert_eq!(h.io.calls(), vec!["open 11"]);

            // The link comes up: identify, then the offer of all three.
            h.link_active(&peer, &LINK_1);
            assert_eq!(h.io.calls()[1..], ["identify a1", "offer a1"]);
            let (offer, respond, _) = h.io.take_offer();
            let mut offered = offered_ids(&offer);
            offered.sort();
            let mut expected = ids.clone();
            expected.sort();
            assert_eq!(offered, expected);
            assert_eq!(h.state(&peer), PropPeer::REQUEST_SENT);

            // The peer wants them all: they leave as ONE Resource, not a link
            // packet, and are not handled yet.
            respond(msgpack(Value::Boolean(true)));
            h.pump();
            assert_eq!(h.state(&peer), PropPeer::RESOURCE_TRANSFERRING);
            let (payload, concluded) = h.io.take_resource();
            match read_value(&mut Cursor::new(&payload)).expect("batch msgpack") {
                Value::Array(items) => {
                    assert_eq!(items.len(), 2);
                    assert!(matches!(items[0], Value::F64(_)), "timebase is a float, as time.time()");
                    assert!(matches!(&items[1], Value::Array(m) if m.len() == 3));
                }
                other => panic!("batch not an array: {other:?}"),
            }
            let messages = decode_propagation_batch(&payload).expect("rfed's own ingest reads the batch");
            assert_eq!(messages.len(), 3);
            assert!(messages.iter().all(|m| m.len() == 300), "each message goes with its stamp, as stored");
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (3, 0), "nothing is handled while the Resource is in flight");

            // The Resource fails: all three stay unhandled, the link is released.
            concluded(failed());
            h.pump();
            assert_eq!(h.state(&peer), PropPeer::IDLE);
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (3, 0), "a failed transfer hands nothing");
            assert_eq!(h.io.calls().last().unwrap(), "close 11");

            // The next session gets them there.
            h.start(&peer);
            h.link_active(&peer, &LINK_2);
            let (_, respond, _) = h.io.take_offer();
            respond(msgpack(Value::Boolean(true)));
            h.pump();
            let (_, concluded) = h.io.take_resource();
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (3, 0));
            concluded(complete());
            h.pump();
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (0, 3), "COMPLETE hands them");
            assert_eq!(h.state(&peer), PropPeer::IDLE, "nothing left: the session ends");
            assert!(h.peer(&peer, |p| p.sync_transfer_rate) > 0.0, "the transfer rate feeds the fastest-peer pool");
        }

        /// An offer that gets no response, and a link lost mid-transfer, end
        /// the session with every id still unhandled; a callback of an ended
        /// session cannot disturb the next one.
        #[test]
        fn an_offer_failure_or_a_lost_link_leaves_ids_unhandled() {
            let h = Harness::new("sync_failures");
            let peer = [0x12u8; 16];
            h.add_peer(&peer, true);
            h.store(2, 300);

            h.start(&peer);
            h.link_active(&peer, &LINK_1);
            let (_, _, offer_failed) = h.io.take_offer();
            offer_failed();
            h.pump();
            assert_eq!(h.state(&peer), PropPeer::IDLE);
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (2, 0));

            h.start(&peer);
            h.link_active(&peer, &LINK_2);
            // The first session's failure arrives again, late: the running
            // session is not ended by it.
            offer_failed();
            h.pump();
            assert_eq!(h.state(&peer), PropPeer::REQUEST_SENT, "a stale callback is ignored");
            let (_, respond, _) = h.io.take_offer();
            respond(msgpack(Value::Boolean(true)));
            h.pump();
            let (_, _concluded) = h.io.take_resource();

            // The link closes with the Resource in flight.
            h.io.link_gone(&peer);
            h.event(SyncEvent::LinkDown { peer: peer.to_vec() });
            assert_eq!(h.state(&peer), PropPeer::IDLE);
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (2, 0), "a transfer lost with its link hands nothing");
        }

        /// The peer answers with the ids it lacks: the rest are handled (it
        /// has them), the listed ones are sent and handled only on COMPLETE.
        #[test]
        fn a_partial_want_hands_only_the_unwanted_until_complete() {
            let h = Harness::new("sync_partial");
            let peer = [0x13u8; 16];
            h.add_peer(&peer, true);
            h.store(3, 300);
            h.start(&peer);
            h.link_active(&peer, &LINK_1);
            let (offer, respond, _) = h.io.take_offer();
            let offered = offered_ids(&offer);
            respond(msgpack(Value::Array(vec![Value::Binary(offered[0].clone())])));
            h.pump();
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (1, 2));
            let (payload, concluded) = h.io.take_resource();
            assert_eq!(decode_propagation_batch(&payload).unwrap().len(), 1);
            concluded(complete());
            h.pump();
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (0, 3));
        }

        /// Identify goes out before the offer, on the same link, once per
        /// link; the persistent strategy offers the next batch on the held
        /// link without identifying again. A peer that reports no
        /// identification gets one second identify on that link, not a loop.
        #[test]
        fn identify_precedes_the_offer_once_per_link() {
            let h = Harness::new("sync_identify");
            let peer = [0x14u8; 16];
            h.add_peer(&peer, true);
            // One message per batch: 24 + 316 + 316 > 500 B.
            h.node.lock().unwrap().peers.get_mut(&peer[..]).unwrap().propagation_sync_limit = Some(0.5);
            h.store(2, 300);

            h.start(&peer);
            h.link_active(&peer, &LINK_1);
            let (first, respond, _) = h.io.take_offer();
            assert_eq!(offered_ids(&first).len(), 1);
            respond(msgpack(Value::Boolean(true)));
            h.pump();
            let (_, concluded) = h.io.take_resource();
            concluded(complete());
            h.pump();
            assert_eq!(h.io.calls(), vec!["open 14", "identify a1", "offer a1", "resource a1", "offer a1"],
                "the second batch goes on the same link, not identified twice");

            // ERROR_NO_IDENTITY: identify once more and re-offer; a second
            // one ends the session.
            let (_, respond, _) = h.io.take_offer();
            respond(msgpack(Value::Integer((ERROR_NO_IDENTITY as i64).into())));
            h.pump();
            assert_eq!(h.io.calls()[5..], ["identify a1", "offer a1"]);
            let (_, respond, _) = h.io.take_offer();
            respond(msgpack(Value::Integer((ERROR_NO_IDENTITY as i64).into())));
            h.pump();
            assert_eq!(h.state(&peer), PropPeer::IDLE);
            assert_eq!(h.io.offer_count(), 0);
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (1, 1));
        }

        /// The staging defect (2026-09-27): the first IDLE peer was chosen
        /// every tick, so one peer grinding its peering key blocked all the
        /// others for 3.5 minutes. A peer whose key is not ready is not a
        /// candidate; the others are served.
        #[test]
        fn a_peer_without_a_ready_key_is_skipped_and_the_others_are_served() {
            let h = Harness::new("sync_skip_not_ready");
            let grinding = [0x21u8; 16];
            let ready = [0x22u8; 16];
            h.add_peer(&grinding, false);
            h.add_peer(&ready, true);
            h.store(2, 300);

            {
                let mut g = h.node.lock().unwrap();
                for i in 0..8usize {
                    assert_eq!(g.select_sync_peer(now(), &mut |n| i % n), Some(ready.to_vec()));
                }
            }

            {
                let mut g = h.node.lock().unwrap();
                g.last_sync_tick = 0.0;
                // Its key is still being ground (the generation thread's marker).
                g.in_flight_keys.insert(grinding.to_vec());
            }
            LxmfPropagationNode::tick_sync(&h.node);
            h.pump();
            assert_eq!(h.state(&ready), PropPeer::LINK_ESTABLISHING, "the ready peer is served");
            assert_eq!(h.state(&grinding), PropPeer::IDLE);
            assert_eq!(h.io.calls(), vec!["open 22"]);

            // With the ready peer busy, nothing else is chosen — the peer
            // without a key is still no candidate.
            assert_eq!(h.node.lock().unwrap().select_sync_peer(now(), &mut |_| 0), None);
        }

        /// LXMRouter.sync_peers: random among the FASTEST_N_RANDOM_POOL
        /// fastest waiting peers and as many of unknown speed; unresponsive
        /// peers only when none is waiting, and only after their backoff.
        #[test]
        fn the_choice_is_random_among_the_fastest_waiting_peers() {
            let h = Harness::new("sync_pool");
            let peers: Vec<([u8; 16], f64)> =
                vec![([0x31; 16], 9000.0), ([0x32; 16], 5000.0), ([0x33; 16], 100.0), ([0x34; 16], 0.0)];
            for (hash, rate) in &peers {
                h.add_peer(hash, true);
                h.node.lock().unwrap().peers.get_mut(&hash[..]).unwrap().sync_transfer_rate = *rate;
            }
            h.store(1, 300);

            let mut chosen = std::collections::HashSet::new();
            {
                let mut g = h.node.lock().unwrap();
                for i in 0..12usize {
                    chosen.insert(g.select_sync_peer(now(), &mut |n| i % n).unwrap()[0]);
                }
            }
            assert_eq!(chosen, [0x31u8, 0x32, 0x34].into_iter().collect(), "the slow known peer waits its turn");

            // No one alive: an unresponsive peer past its backoff is chosen;
            // one still in backoff is not.
            let mut g = h.node.lock().unwrap();
            for (hash, _) in &peers {
                let peer = g.peers.get_mut(&hash[..]).unwrap();
                peer.alive = false;
                peer.next_sync_attempt = now() + 600.0;
            }
            assert_eq!(g.select_sync_peer(now(), &mut |_| 0), None);
            g.peers.get_mut(&[0x33u8; 16][..]).unwrap().next_sync_attempt = 0.0;
            assert_eq!(g.select_sync_peer(now(), &mut |_| 0), Some(vec![0x33; 16]));

            // An alive peer still in backoff is not chosen, and is marked not
            // alive, as the reference's sync() does when it picks one.
            let peer = g.peers.get_mut(&[0x31u8; 16][..]).unwrap();
            peer.alive = true;
            assert_eq!(g.select_sync_peer(now(), &mut |_| 0), Some(vec![0x33; 16]));
            assert!(!g.peers[&[0x31u8; 16][..]].alive);
        }

        /// The staging defect (2026-09-27): the 600/min budget was checked
        /// before each 500-message send, so 1000 left in a minute (57
        /// times). Offers are now sized to what is left of the minute, and an
        /// offer awaiting its response reserves its size, so concurrent syncs
        /// cannot overshoot either.
        #[test]
        fn the_minute_budget_is_never_exceeded_by_concurrent_syncs() {
            let h = Harness::new("sync_budget");
            h.node.lock().unwrap().outbound_sync_msgs_per_min = 5;
            let a = [0x41u8; 16];
            let b = [0x42u8; 16];
            h.add_peer(&a, true);
            h.add_peer(&b, true);
            h.store(8, 300);

            // Both sessions reach LINK_READY before either offer is answered.
            h.start(&a);
            h.start(&b);
            h.link_active(&a, &LINK_1);
            h.link_active(&b, &LINK_2);
            assert_eq!(h.io.offer_count(), 1, "the first offer reserved the whole minute");
            assert_eq!(h.state(&b), PropPeer::IDLE, "the second ends with nothing to offer this minute");
            let (offer, respond, _) = h.io.take_offer();
            assert_eq!(offered_ids(&offer).len(), 5);
            {
                let mut g = h.node.lock().unwrap();
                assert_eq!(g.outbound_allowance(), 0);
                assert!(!g.outbound_sync_allowed(), "the tick starts nothing more this minute");
            }

            respond(msgpack(Value::Boolean(true)));
            h.pump();
            let (payload, concluded) = h.io.take_resource();
            assert_eq!(decode_propagation_batch(&payload).unwrap().len(), 5);
            assert_eq!(h.node.lock().unwrap().outbound_sync_window_count, 5);

            // Completing does not make room: the persistent strategy's next
            // offer finds the minute spent and ends the session.
            concluded(complete());
            h.pump();
            assert_eq!(h.io.offer_count(), 0);
            assert_eq!(h.state(&a), PropPeer::IDLE);
            assert_eq!(h.node.lock().unwrap().outbound_sync_window_count, 5, "never more than the budget");

            // A new minute with 3 already sent: the next offer is 2.
            {
                let mut g = h.node.lock().unwrap();
                g.outbound_sync_window_start = now() - 61.0;
                assert_eq!(g.outbound_allowance(), 5);
                g.outbound_sync_window_count = 3;
            }
            h.start(&b);
            h.link_active(&b, &LINK_2);
            let (offer, _, _) = h.io.take_offer();
            assert_eq!(offered_ids(&offer).len(), 2);
            assert_eq!(h.io.resource_count(), 0);
        }

        fn id(n: usize) -> Vec<u8> {
            let mut v = vec![0u8; 32];
            v[..8].copy_from_slice(&(n as u64).to_be_bytes());
            v
        }

        fn candidate(n: usize, size: usize, weight: f64) -> OfferCandidate {
            OfferCandidate { tid: id(n), size, weight }
        }

        /// A batch is sized as the reference sizes it — lightest first, the
        /// peer's per-message transfer limit and sync limit (KB) — and, in
        /// rfed, to one Resource segment and MAX_OFFER_IDS messages.
        #[test]
        fn batches_follow_the_peer_limits_and_one_resource_segment() {
            // 1 KB limits: #3 (2016 B) is over the per-message limit; the
            // batch takes #2 and #4 (24 + 416 + 416 = 856 B) and not #1.
            let plan = plan_offer(
                vec![candidate(1, 900, 3.0), candidate(2, 400, 1.0), candidate(3, 2000, 0.5), candidate(4, 400, 2.0)],
                Some(1.0),
                Some(1.0),
                MAX_OFFER_IDS,
            );
            assert_eq!(plan.too_big, vec![id(3)]);
            assert_eq!(plan.offer, vec![id(2), id(4)], "lightest first, within the sync limit");
            assert!(plan.estimated_bytes < 1000.0);

            // A later, lighter-fitting message still goes in after one that
            // did not fit (the reference skips, it does not stop).
            let plan = plan_offer(
                vec![candidate(1, 500, 1.0), candidate(2, 600, 2.0), candidate(3, 300, 3.0)],
                None,
                Some(1.0),
                MAX_OFFER_IDS,
            );
            assert_eq!(plan.offer, vec![id(1), id(3)]);

            // Generous peer limits: 600 × 5 KB is cut to one Resource segment.
            let many: Vec<OfferCandidate> = (0..600).map(|n| candidate(n, 5000, n as f64)).collect();
            let plan = plan_offer(many, Some(256.0), Some(10240.0), 600);
            assert_eq!(plan.offer.len(), (MAX_SYNC_RESOURCE_BYTES - 24) / 5016);
            assert!(plan.estimated_bytes <= MAX_SYNC_RESOURCE_BYTES as f64);

            // A message no one segment can carry is set aside.
            let plan = plan_offer(vec![candidate(1, 2_000_000, 1.0)], Some(4000.0), Some(10240.0), MAX_OFFER_IDS);
            assert_eq!((plan.over_resource, plan.offer.len()), (vec![id(1)], 0));

            // The count cap.
            let small: Vec<OfferCandidate> = (0..10).map(|n| candidate(n, 100, n as f64)).collect();
            assert_eq!(plan_offer(small, None, None, 4).offer.len(), 4);
        }

        /// LXMPeer.sync: a message over the peer's per-message transfer limit
        /// is marked handled and never sent — logged, since it is a drop.
        #[test]
        fn messages_over_the_peer_transfer_limit_are_handled_unsent() {
            let h = Harness::new("sync_transfer_limit");
            let peer = [0x51u8; 16];
            h.add_peer(&peer, true);
            h.node.lock().unwrap().peers.get_mut(&peer[..]).unwrap().propagation_transfer_limit = Some(0.2);
            h.store(2, 300);
            h.start(&peer);
            h.link_active(&peer, &LINK_1);
            assert_eq!(h.io.offer_count(), 0);
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (0, 2));
            assert_eq!(h.state(&peer), PropPeer::IDLE);
        }

        /// ERROR_INVALID_KEY (0xF3): the key is ground again once per announced
        /// peering cost. Refused again, the peer validates against a cost rfed
        /// has not heard yet, and a key at the same cost cannot fare better:
        /// it waits for an announce with another cost. Regenerating at the
        /// same cost after every refusal was a full PoW grind plus a link and
        /// an offer per cycle for as long as rfed's copy of the cost was stale.
        #[test]
        fn a_refused_peering_key_is_ground_again_once_per_announced_cost() {
            let h = Harness::new("sync_invalid_key");
            let peer = [0x19u8; 16];
            h.add_peer(&peer, true);
            h.store(2, 300);
            let refuse = |h: &Harness| {
                h.start(&peer);
                h.link_active(&peer, &LINK_1);
                let (_, respond, _) = h.io.take_offer();
                respond(msgpack(Value::Integer((ERROR_INVALID_KEY as i64).into())));
                h.pump();
                assert_eq!(h.state(&peer), PropPeer::IDLE);
                assert_eq!((h.unhandled(&peer), h.handled(&peer)), (2, 0), "a refused offer hands nothing");
            };
            let set_key = |h: &Harness, value: u32| {
                h.node.lock().unwrap().peers.get_mut(&peer[..]).unwrap().peering_key = Some((vec![0x5B; 32], value));
            };

            refuse(&h);
            assert!(h.peer(&peer, |p| p.peering_key.is_none()), "discarded, to be ground again");
            // The background grind delivers a new key at the same cost 18.
            set_key(&h, 18);
            assert_eq!(h.node.lock().unwrap().select_sync_peer(now(), &mut |_| 0), Some(peer.to_vec()));

            refuse(&h);
            assert!(h.peer(&peer, |p| p.peering_key.is_some()), "kept: no second grind at the same cost");
            assert!(!h.peer(&peer, |p| p.sync_ready()));
            assert_eq!(h.node.lock().unwrap().select_sync_peer(now(), &mut |_| 0), None, "not chosen at this cost");

            // The peer announces another cost: a key is ground for it and the
            // peer syncs again.
            h.node.lock().unwrap().peer(peer.to_vec(), 1.0, 256.0, Some(10240.0), 16, 3, 20, Vec::new());
            assert!(!h.peer(&peer, |p| p.peering_key_ready()), "the old key does not meet the new cost");
            set_key(&h, 20);
            assert_eq!(h.node.lock().unwrap().select_sync_peer(now(), &mut |_| 0), Some(peer.to_vec()));
            // A later announce back at 18 is a new cost too: the old refusal
            // no longer holds (the cost-20 key meets 18).
            h.node.lock().unwrap().peer(peer.to_vec(), 2.0, 256.0, Some(10240.0), 16, 3, 18, Vec::new());
            assert_eq!(h.node.lock().unwrap().select_sync_peer(now(), &mut |_| 0), Some(peer.to_vec()));
        }

        /// AppLinks brings links up that no session asked for: its re-open of
        /// a link the peer closed, or an attempt that outlived its session or
        /// its peer. Each is closed — none is adopted, none left held.
        #[test]
        fn links_no_session_opened_are_closed_never_adopted() {
            let h = Harness::new("sync_stray_links");
            let peer = [0x17u8; 16];
            h.add_peer(&peer, true);
            h.store(2, 300);

            // A link comes up for an IDLE peer: nothing uses it.
            h.link_active(&peer, &LINK_1);
            assert_eq!(h.io.calls(), vec!["close 17"]);
            assert_eq!(h.state(&peer), PropPeer::IDLE);

            // A link is already held when the peer is chosen: it is closed,
            // and the session opens its own, which AppLinks will report on.
            h.io.link_up(&peer, &LINK_1);
            h.start(&peer);
            assert_eq!(h.io.calls()[1..], ["close 17", "open 17"]);
            assert_eq!(h.state(&peer), PropPeer::LINK_ESTABLISHING);

            // A second link comes up while the session runs on the first:
            // closed, and the session carries on where it was.
            h.link_active(&peer, &LINK_1);
            assert_eq!(h.state(&peer), PropPeer::REQUEST_SENT);
            h.link_active(&peer, &LINK_2);
            assert_eq!(h.io.calls()[3..], ["identify a1", "offer a1", "close 17"]);
            assert_eq!(h.state(&peer), PropPeer::REQUEST_SENT);
            assert_eq!(h.peer(&peer, |p| p.link_id.clone()), Some(LINK_1.to_vec()));
            assert_eq!(h.io.offer_count(), 1, "no second offer");

            // A link comes up for a destination that is no longer a peer (it
            // was unpeered while the attempt was in flight): closed, too.
            let gone = [0x18u8; 16];
            h.link_active(&gone, &LINK_2);
            assert_eq!(h.io.calls().last().unwrap(), "close 18");
            assert!(h.io.active_link(&gone).is_none());
        }

        /// DESIGN_PRINCIPLES §1 panics in a debug build when an offer's
        /// response comes more than 5 s after it was sent. The callback
        /// asserted first and forwarded the response after, so the panic lost
        /// it: the peer stayed REQUEST_SENT for good and its offer kept its
        /// reservation of the minute's budget. The response goes first now.
        #[test]
        fn a_late_offer_response_is_forwarded_before_the_5_second_assertion() {
            let h = Harness::new("sync_late_response");
            let peer = [0x16u8; 16];
            h.add_peer(&peer, true);
            h.store(3, 300);
            h.start(&peer);
            h.link_active(&peer, &LINK_1);
            let _ = h.io.take_offer();
            let (session, sink) = {
                let mut g = h.node.lock().unwrap();
                assert_eq!(g.outbound_allowance(), g.outbound_sync_msgs_per_min - 3, "the offer reserves its size");
                (g.peers[&peer[..]].sync_session, g.event_sink())
            };

            // The response callback of an offer sent 10 s ago.
            let late = offer_response_callback(sink, peer.to_vec(), session, now() - 10.0);
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| late(msgpack(Value::Boolean(false)))));
            assert_eq!(outcome.is_err(), cfg!(debug_assertions), "the §1 assertion still trips in a debug build");
            h.pump();
            assert_eq!(h.state(&peer), PropPeer::IDLE, "the response was not lost with the panic");
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (0, 3));
            let mut g = h.node.lock().unwrap();
            assert_eq!(g.outbound_allowance(), g.outbound_sync_msgs_per_min, "the reservation is released");
        }

        /// ERROR_THROTTLED holds the peer PN_STAMP_THROTTLE_SECS, as an answer,
        /// not a failure. The reference keeps a throttled peer on its link,
        /// where it is neither chosen nor demoted, and alive when the link
        /// closes. rfed ends the session at once, and the next tick marked the
        /// peer unresponsive for the hold, so it waited behind every alive
        /// peer until its next announce (hours) — and a 1.1.1 PN throttles any
        /// offer that lands while it validates a batch.
        #[test]
        fn a_throttled_peer_is_held_but_stays_alive_and_waiting() {
            let h = Harness::new("sync_throttled");
            let peer = [0x15u8; 16];
            h.add_peer(&peer, true);
            h.store(2, 300);
            h.start(&peer);
            h.link_active(&peer, &LINK_1);
            let (_, respond, _) = h.io.take_offer();
            respond(msgpack(Value::Integer((ERROR_THROTTLED as i64).into())));
            h.pump();
            assert_eq!(h.state(&peer), PropPeer::IDLE);
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (2, 0), "nothing handled");
            assert_eq!(h.io.calls().last().unwrap(), "close 15");
            let until = h.peer(&peer, |p| p.throttled_until);
            assert!((until - now() - PN_STAMP_THROTTLE_SECS).abs() < 5.0, "held for the throttle");

            let mut g = h.node.lock().unwrap();
            // A tick inside the hold: not chosen, and not demoted either.
            assert_eq!(g.select_sync_peer(now(), &mut |_| 0), None);
            assert!(g.peers[&peer[..]].alive, "a throttle is not a failure: the peer stays alive");
            // Once the hold is over it is a waiting (alive) peer again.
            assert_eq!(g.select_sync_peer(until + 1.0, &mut |_| 0), Some(peer.to_vec()));
            assert!(g.peers[&peer[..]].alive);
        }

        /// LXMRouter.propagation_resource_concluded: a batch from a peer is
        /// handled for that peer — it has every message in it, one we already
        /// held included — and what is new is queued for the other peers only.
        /// rfed queued each message back to its sender, so every inbound batch
        /// was offered straight back. A client's batch (no peer) still goes to
        /// every peer.
        #[test]
        fn a_batch_from_a_peer_is_handled_for_it_and_queued_for_the_others() {
            let h = Harness::new("sync_from_peer");
            {
                // Any stamp meets cost 0; the test is about who gets what.
                let mut g = h.node.lock().unwrap();
                g.stamp_cost = 0;
                g.stamp_flexibility = 0;
            }
            let sender_identity = Identity::new(true);
            let sender = Destination::hash_from_name_and_identity("lxmf.propagation", Some(&sender_identity));
            let other = [0x72u8; 16];
            h.add_peer(&sender, true);
            h.add_peer(&other, true);
            // A message rfed already holds and had queued for both peers.
            let held = h.store(1, 300).remove(0);
            let held_file = {
                let g = h.node.lock().unwrap();
                fs::read(&g.entries[&held].filepath).expect("stored file")
            };
            let message = |fill: u8| {
                let mut lxmf = vec![fill; 300 - lx_stamper::STAMP_SIZE];
                lxmf[..16].copy_from_slice(&[0x5E; 16]);
                let id = reticulum_rust::identity::full_hash(&lxmf);
                ([lxmf, vec![0x33u8; lx_stamper::STAMP_SIZE]].concat(), id)
            };
            let (fresh, fresh_id) = message(0x78);
            let batch = |messages: Vec<Vec<u8>>| encode_value(Value::Array(vec![
                Value::F64(0.0),
                Value::Array(messages.into_iter().map(Value::Binary).collect()),
            ]));

            LxmfPropagationNode::ingest_propagation_batch(&h.node, &batch(vec![fresh, held_file]), Some(&sender_identity));
            assert!(h.node.lock().unwrap().entries.contains_key(&fresh_id), "the new message is stored");
            h.peer(&sender, |p| {
                assert!(!p.unhandled_ids.contains(&fresh_id), "not queued back to the peer that sent it");
                assert!(!p.unhandled_ids.contains(&held), "a duplicate it sent is no longer queued for it either");
                assert!(p.handled_ids.contains(&fresh_id) && p.handled_ids.contains(&held), "both handled for it");
            });
            h.peer(&other, |p| {
                assert!(p.unhandled_ids.contains(&fresh_id) && p.unhandled_ids.contains(&held), "the others still get both");
            });

            // A client PUT: no sending peer, so every peer gets it.
            let (client, client_id) = message(0x79);
            LxmfPropagationNode::ingest_propagation_batch(&h.node, &batch(vec![client]), None);
            assert!(h.peer(&sender, |p| p.unhandled_ids.contains(&client_id)));
            assert!(h.peer(&other, |p| p.unhandled_ids.contains(&client_id)));
        }

        /// The wire defect (2026-09-28): rfed announced its limits as MB where
        /// the reference and rfed's own reader take KB, so a default rfed
        /// announced a 0 KB per-message limit and every peer marked every
        /// message for it handled unsent. rfed's own announce, read back by an
        /// rfed peer, must let a 1 KB message through.
        #[test]
        fn rfed_announces_its_limits_in_kb_and_its_peers_offer_it_messages() {
            let h = Harness::new("limits_kb");
            let mut g = h.node.lock().unwrap();
            let app_data = g.build_app_data();
            assert!(lxmf_rust::lxmf::pn_announce_data_is_valid(&app_data));
            match read_value(&mut Cursor::new(&app_data)).expect("announce msgpack") {
                Value::Array(items) => {
                    assert_eq!(items[3], Value::Integer(256.into()), "per-message limit: LXMF 1.1.1's 256 KB");
                    assert_eq!(items[4], Value::Integer(10240.into()), "per-sync limit: LXMF 1.1.1's 10240 KB");
                }
                other => panic!("announce not an array: {other:?}"),
            }

            // Another rfed hears it (autopeer) and plans an offer to it.
            g.autopeer = true;
            let other = [0x61u8; 16];
            g.handle_propagation_announce(&other, &app_data, false);
            let peer = g.peers.get(&other[..]).expect("peered on the announce");
            assert_eq!((peer.propagation_transfer_limit, peer.propagation_sync_limit), (Some(256.0), Some(10240.0)));
            let plan = plan_offer(
                vec![OfferCandidate { tid: id(1), size: 1000, weight: 1.0 }],
                peer.propagation_transfer_limit,
                peer.propagation_sync_limit,
                MAX_OFFER_IDS,
            );
            assert!(plan.too_big.is_empty(), "a 1 KB message is not over the announced limit");
            assert_eq!(plan.offer, vec![id(1)]);

            // Configured limits (`[storage] transfer_limit_mb` is MB of 1024²
            // bytes) are divided by 1000, as the reference multiplies them
            // back, and the sync limit is never below the per-message one.
            assert_eq!(propagation_limits_kb(None, None), (256.0, 10240.0));
            assert_eq!(propagation_limits_kb(Some(100 * 1024 * 1024), Some(1000 * 1024 * 1024)), (104857.6, 1048576.0));
            assert_eq!(propagation_limits_kb(Some(2 * 1024 * 1024), Some(1024 * 1024)), (2097.152, 2097.152));
        }
    }
}

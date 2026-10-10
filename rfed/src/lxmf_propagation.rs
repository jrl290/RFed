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
//! concurrently, each on its own events. While the budget binds it is shared:
//! fair-share batches, no next batch on a held link while others wait, the
//! least recently served chosen. See "Outbound peer sync" below and SPEC.md
//! §10.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
use lxmf_rust::distro::{decode_sync_extension, verify_sync_claim, SyncClaim, SyncClaims};

use crate::config::NodeConfig;
use crate::distro::DistroTable;
use crate::handoff::Wake;
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
/// span of OUTBOUND_BUDGET_WINDOW_SECS carries more than this.
pub const DEFAULT_OUTBOUND_SYNC_MSGS_PER_MIN: u64 = 600;
/// The span the outbound budget is counted over. It rolls: at every moment
/// the sends of the last this-many seconds count, so no span of this length,
/// wherever it starts, carries more than the budget.
pub const OUTBOUND_BUDGET_WINDOW_SECS: f64 = 60.0;
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
        + test_clock::offset()
}

/// Seconds on a monotonic clock (since this process first asked). The
/// outbound budget counts spans on it, so a wall-clock step cannot stretch or
/// shrink one. (Both clocks add `test_clock::offset()`, 0 outside tests.)
fn monotonic_now() -> f64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_secs_f64() + test_clock::offset()
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
    /// The last set of IDs we offered — used to reconcile the response.
    pub last_offer: Vec<Vec<u8>>,
    /// Messages of the outbound budget this session holds: the whole offer
    /// while it awaits its answer, then the ids the peer wanted until their
    /// Resource is handed to the link (`record_outbound_send`), which counts
    /// them as sent. Zero at every other step (`end_sync` clears it).
    pub budget_reserved: u64,
    /// Messages this session has handed to its link (`record_outbound_send`),
    /// counted from its start. While the outbound budget binds, a session's
    /// turn is a fair share of messages sent, not one batch (see "Sharing
    /// the budget"). Zero at IDLE.
    pub turn_sent: u64,
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
            budget_reserved: 0,
            turn_sent: 0,
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
    /// The outbound budget's send record: every sync Resource handed to a
    /// link in the last OUTBOUND_BUDGET_WINDOW_SECS, as (monotonic time,
    /// messages), oldest first. See `outbound_allowance`.
    pub outbound_sends: VecDeque<(f64, u64)>,
    /// Monotonic time the send record starts: when this node was built. What
    /// the previous run sent before it stopped is not known, so nothing is
    /// sent until a whole window has passed since (`outbound_allowance`).
    pub outbound_record_start: f64,
    pub outbound_sync_msgs_per_min: u64,
    /// Set while the budget or the startup hold holds sync, so the hold is
    /// logged once per episode rather than every tick.
    pub outbound_sync_hold_logged: bool,

    // ── Outbound peer sync plumbing ───────────────────────────────────
    /// How outbound peer sync reaches the network: AppLinks-held links in
    /// production (`AppLinksSyncIo`), a recording fake in the unit tests.
    sync_io: Arc<dyn PeerSyncIo>,
    /// The stack a distro fan-out's hand-off wakes devices through: the
    /// running Reticulum stack (`LiveStack`) in production, a recording fake
    /// in the unit tests.
    relay_stack: Arc<dyn RelayStack + Send + Sync>,
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
            outbound_sends: VecDeque::new(),
            outbound_record_start: monotonic_now(),
            outbound_sync_msgs_per_min: DEFAULT_OUTBOUND_SYNC_MSGS_PER_MIN,
            outbound_sync_hold_logged: false,
            sync_io: Arc::new(AppLinksSyncIo),
            relay_stack: Arc::new(LiveStack),
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

    /// The per-transfer and per-sync limits as announced: whole KB of 1000 B
    /// (`build_app_data`). An inbound sync Resource is held to the announced
    /// per-sync limit (`inbound_resource_callbacks`), so what rfed accepts is
    /// exactly what it tells its peers.
    pub fn announced_limits_kb(&self) -> (i64, i64) {
        (self.transfer_limit_kb as i64, self.sync_limit_kb as i64)
    }

    pub fn build_app_data(&self) -> Vec<u8> {
        let ts = now() as i64;
        let (transfer_limit_kb, sync_limit_kb) = self.announced_limits_kb();
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
            Value::Integer(transfer_limit_kb.into()),
            Value::Integer(sync_limit_kb.into()),
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

        let (_, sync_limit_kb) = self.announced_limits_kb();
        let (advertised, concluded) = Self::inbound_resource_callbacks(self.self_handle.clone(), sync_limit_kb);
        link.set_resource_callbacks(Some(advertised), None, Some(concluded));
    }

    /// The Resource callbacks of an inbound link. Resource-advertised: the
    /// ACCEPT_APP verdict (RNS/Link.py:1108), which refuses a Resource whose
    /// data is larger than our announced per-sync limit — `sync_limit_kb`, in
    /// the reference's KB of 1000 B — and accepts the rest, as LXMF 1.1.1
    /// `LXMRouter.propagation_resource_advertised` does (`size >
    /// propagation_per_sync_limit*1000`, on the advertisement's data size).
    /// Resource-concluded: invoked once the multi-segment transfer is fully
    /// assembled; decodes and ingests the same way as single-packet inbound
    /// propagation data.
    ///
    /// The reference has no per-message size limit on what it receives: the
    /// per-transfer limit it announces is applied by the SENDER
    /// (`LXMPeer.sync`, rfed's `plan_offer`). Its one per-message check on
    /// receipt is `LXStamper.validate_pn_stamp`'s — a message no longer than
    /// LXMF_OVERHEAD + STAMP_SIZE, or with a stamp under the cost, is dropped —
    /// which rfed applies with the same code (`lx_stamper::validate_pn_stamps`
    /// in `ingest_propagation_batch`), and counts in its per-batch
    /// "bad-stamp" figure.
    ///
    /// The two share the identity the sender proved on the link, which says
    /// whose batch it is (`ingest_propagation_batch`). It is recorded when the
    /// Resource is advertised, not asked for when it concludes.
    /// LXMRouter.propagation_resource_concluded reads
    /// `resource.link.get_remote_identity()` at the end, an attribute that
    /// outlives the link. rfed's is a request to the link's actor, and by the
    /// time the concluded callback runs Reticulum-rust has already sent the
    /// proof (resource.rs `prove()` comes before the callback), on which the
    /// sender tears the link down (LXMPeer.resource_concluded, and rfed's own
    /// `end_sync`). When its LINKCLOSE got there first the actor had exited,
    /// the request came back LinkGone, and the batch was ingested as a
    /// client's: queued back to the peer that sent it, with no log line.
    ///
    /// At advertisement the link is up and the sender is waiting on us: the
    /// ACCEPT_APP callback runs off the actor thread and its verdict is what
    /// sends our first RESOURCE_REQ (Reticulum-rust link.rs, ACCEPT_APP), so
    /// no part, and so no proof, moves before the identity is recorded. The
    /// peer identified before it offered (LXMPeer.link_established), long
    /// before that. The remote-identified callback would not do: the actor
    /// spawns it and moves on, so nothing orders it before the conclusion.
    fn inbound_resource_callbacks(
        weak: Option<Weak<Mutex<Self>>>,
        sync_limit_kb: i64,
    ) -> (
        reticulum_rust::link::ResourceAcceptCallback,
        Arc<dyn Fn(Arc<Mutex<reticulum_rust::resource::Resource>>) + Send + Sync>,
    ) {
        let sender: Arc<Mutex<Option<Identity>>> = Arc::new(Mutex::new(None));

        let recorded = sender.clone();
        let limit_bytes = sync_limit_kb.max(0) as u64 * 1000;
        let advertised = Arc::new(move |advertisement: &reticulum_rust::resource::ResourceAdvertisement| -> bool {
            // Until 929a079 rfed announced MB where peers read KB, so none
            // could offer more than a few MB; announcing its real limits, it
            // must hold senders to them.
            let size = advertisement.get_data_size() as u64;
            if size > limit_bytes {
                log(
                    format!(
                        "[lxmf.prop] rejecting a {size} B propagation Resource on link {}: over our per-sync limit of {limit_bytes} B ({sync_limit_kb} KB announced)",
                        advertisement.link.as_ref().map(|link| hexrep(&link.link_id(), false)).unwrap_or_else(|| "?".into()),
                    ),
                    LOG_NOTICE, false, false,
                );
                return false;
            }
            if let Some(link) = &advertisement.link {
                match link.remote_identity() {
                    Ok(Some(identity)) => {
                        if let Ok(mut slot) = recorded.lock() {
                            *slot = Some(identity);
                        }
                    }
                    // A client that never identified: its batch is a client's.
                    Ok(None) => {}
                    Err(_) => log(
                        format!(
                            "[lxmf.prop] resource advertised on link {} after the link closed: it cannot be received",
                            hexrep(&link.link_id(), false),
                        ),
                        LOG_NOTICE, false, false,
                    ),
                }
            }
            // Within the limit: accepted.
            true
        });

        let concluded = Arc::new(move |resource: Arc<Mutex<reticulum_rust::resource::Resource>>| {
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
            let sender = sender.lock().ok().and_then(|s| s.clone());
            // NOT under the node lock — see `ingest_propagation_batch`.
            if let Some(arc) = weak.as_ref().and_then(|w| w.upgrade()) {
                LxmfPropagationNode::ingest_propagation_batch(&arc, &data, sender.as_ref());
            }
        });

        (advertised, concluded)
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
    ///
    /// A client's batch may carry RFed SPEC §17.13 sync claims. They are
    /// matched after the stamps, only to stamp-valid messages for a distro
    /// registered here: an accepted claim makes that message's fan-out a
    /// sync one (`Wake::QueueOnly`). Logging stays bounded by the stamp-valid
    /// distro messages: one verdict line for each that carried a claim, and
    /// at most one `[distro-sync]` summary line per batch.
    pub(crate) fn ingest_propagation_batch(arc: &Arc<Mutex<Self>>, data: &[u8], sender: Option<&Identity>) {
        let Some(PropagationBatch { messages, claims }) = decode_propagation_batch(data) else { return };
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
        let mut sync_claims = BatchClaims::of(claims, from_peer.is_some());

        // Whose batch it was, as the reference's "Received N messages from
        // {remote_str}": a batch treated as a client's says so. (The staging
        // harnesses parse the counts; the origin stays at the end.)
        let origin = match (sender, &from_peer) {
            (_, Some(peer)) => format!("peer {}", hexrep(peer, false)),
            (Some(identity), None) => format!(
                "{} (not a peer)",
                hexrep(
                    &Destination::hash_from_name_and_identity(&format!("{}.{}", LXMF_APP, PROP_ASPECT), Some(identity)),
                    false,
                ),
            ),
            (None, None) => "a sender with no identity (handled as a client's)".to_string(),
        };

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
                // RFed SPEC §17.13: an accepted sync proof makes the fan-out
                // a sync one, which queues unconfirmed devices without a
                // wake. A refused proof, or none, wakes as before. RFed never
                // refuses or drops a message for its claim.
                let verdict = sync_claims.verdict_for(transient_id, lxmf_data);
                let wake = if matches!(verdict, Some(Ok(()))) { Wake::QueueOnly } else { Wake::Push };
                // Fan out to registered devices immediately — but only on
                // first sight. See `ingest_distro_blob`.
                let first_sight = delivery.ingest_distro_blob(dest_hash, lxmf_data, &mut stored);
                if let Some(verdict) = &verdict {
                    let (level, line) = sync_verdict_line(transient_id, dest_hash, verdict, first_sight);
                    log(line, level, false, false);
                }
                if first_sight {
                    delivery.distro_fanout(dest_hash, lxmf_data, wake);
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
        if invalid_stamps > 0 && from_peer.is_none() {
            log(
                dropped_messages_line(&dropped_messages(&messages, &validated), min_cost, &origin),
                LOG_WARNING, false, false,
            );
        }
        if let Some(summary) = sync_claims.summary(&origin) {
            log(summary, LOG_NOTICE, false, false);
        }
        log(
            format!(
                "[lxmf.prop] processed {} msgs: {} stored, {} streamed, {} notified, {} bad-stamp, from {}",
                total, stored, streamed, notified, invalid_stamps, origin,
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
            relay_stack: Arc::clone(&self.relay_stack),
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

/// One decoded propagation upload: its messages, and the §17.13 sync
/// claims of its third element, if it has one.
struct PropagationBatch {
    /// The bin entries of `data[1]`, each `lxmf_data | stamp`.
    messages: Vec<Vec<u8>>,
    /// `data[2]` read by `lxmf_rust::distro::decode_sync_extension` (RFed
    /// SPEC §17.13): counts and at most one claim per message, never a
    /// string. `None` when the upload has no third element. Ingest honours
    /// them only in a client's batch (`ingest_propagation_batch`).
    claims: Option<SyncClaims>,
}

/// `[timebase, [lxmf_payload, ...]]` — the propagation wire format — and,
/// from a client to an RFed, `[timebase, [lxmf_payload, ...], {"rfed.distro.sync":
/// [claim, ...]}]` (RFed SPEC §17.13). Only `data[1]` and `data[2]` are read:
/// an RFed before §17.13 read `data[1]` alone, and so does every reader of
/// the messages here.
fn decode_propagation_batch(data: &[u8]) -> Option<PropagationBatch> {
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
            // Bounded by the message count (decode_sync_extension, rule 3),
            // and silent: what the claims came to is logged once per batch.
            let claims = items.get(2).map(|extension| decode_sync_extension(extension, messages.len()));
            Some(PropagationBatch { messages, claims })
        }
        _ => {
            log("[lxmf.prop] packet missing message array", LOG_DEBUG, false, false);
            None
        }
    }
}

/// The §17.13 sync claims of one batch as ingest uses them (RFed SPEC
/// §17.13 "At RFed"): each taken by the stamp-valid distro message it names,
/// verified there, and everything counted for the batch's one summary line.
/// Nothing is logged per claim.
struct BatchClaims {
    claims: SyncClaims,
    accepted: usize,
    refused: usize,
}

impl BatchClaims {
    /// The claims of a batch. Read only from a client's batch: a batch from
    /// one of our LXMF peers that carries an extension counts as ignored, and
    /// none of its claims is looked at (peers never send or forward one).
    fn of(claims: Option<SyncClaims>, from_peer: bool) -> Self {
        let claims = match (claims, from_peer) {
            (Some(claims), false) => claims,
            (Some(_), true) => SyncClaims { ignored: 1, ..SyncClaims::default() },
            (None, _) => SyncClaims::default(),
        };
        BatchClaims { claims, accepted: 0, refused: 0 }
    }

    /// The verdict on the claim naming this message, if one does. Called only
    /// for a message whose PN stamp is valid and whose destination is a
    /// distro registered here, so Ed25519 runs only for messages that paid a
    /// stamp. `transient_id` and `lxmf_data` are as `validate_pn_stamps`
    /// returns them. A claim is taken once: a second copy of the message in
    /// the batch finds none.
    fn verdict_for(&mut self, transient_id: &[u8], lxmf_data: &[u8]) -> Option<Result<(), &'static str>> {
        let id: [u8; lxmf_rust::distro::DISTRO_SYNC_ID_LEN] =
            transient_id.get(..lxmf_rust::distro::DISTRO_SYNC_ID_LEN)?.try_into().ok()?;
        let claim = self.claims.by_id.remove(&id)?;
        let verdict = verify_claim(&claim, transient_id, lxmf_data);
        match verdict {
            Ok(()) => self.accepted += 1,
            Err(_) => self.refused += 1,
        }
        Some(verdict)
    }

    /// The batch's summary line, when its claims had any problem: a refusal,
    /// a malformed or duplicate claim, a claim that matched no stamp-valid
    /// distro message (unmatched), or an extension ignored as a whole
    /// (ignored: a peer's batch, or claims that are not an array of 1 to N).
    fn summary(&self, origin: &str) -> Option<String> {
        let unmatched = self.claims.by_id.len();
        let SyncClaims { malformed, duplicate, ignored, .. } = self.claims;
        if self.refused + malformed + duplicate + unmatched + ignored == 0 {
            return None;
        }
        Some(format!(
            "[distro-sync] batch from {origin}: {} accepted, {} refused, {malformed} malformed, {duplicate} duplicate, {unmatched} unmatched, {ignored} ignored",
            self.accepted, self.refused,
        ))
    }
}

/// `lxmf_rust::distro::verify_sync_claim`, counted per thread in the tests
/// (they show that no Ed25519 runs for a claim whose message paid no stamp).
fn verify_claim(claim: &SyncClaim, transient_id: &[u8], lxmf_data: &[u8]) -> Result<(), &'static str> {
    #[cfg(test)]
    tests::sync_proof_tests::VERIFICATIONS.with(|n| n.set(n.get() + 1));
    verify_sync_claim(claim, transient_id, lxmf_data)
}

/// The one verdict line for a stamp-valid distro message that carried a
/// claim (RFed SPEC §17.13), with whether this node fans it out
/// (`first_sight`: a message fans out once, on first sight).
///
/// It is written before the fan-out, so it says what kind of fan-out follows
/// and never how a device fared: an accepted proof's hand-off still pushes a
/// device at a bound of §17.3, and the queue's global limit can refuse its
/// blob. Each device's `[handoff]` line says what was queued and who was
/// woken. Until 2026-10-10 this line said "unconfirmed devices queued, not
/// woken" for every accepted proof, also when a bound woke one.
fn sync_verdict_line(
    transient_id: &[u8],
    dest_hash: &[u8],
    verdict: &Result<(), &'static str>,
    first_sight: bool,
) -> (i32, String) {
    let id = hexrep(&transient_id[..transient_id.len().min(lxmf_rust::distro::DISTRO_SYNC_ID_LEN)], false);
    let distro = hexrep(dest_hash, false);
    match (verdict, first_sight) {
        (Ok(()), true) => (
            LOG_NOTICE,
            format!("[distro-sync] {id} for {distro}: proof accepted, fanning out as distro sync (each [handoff] line says whether its device was woken)"),
        ),
        (Ok(()), false) => (
            LOG_NOTICE,
            format!("[distro-sync] {id} for {distro}: proof accepted, already held: no fan-out"),
        ),
        (Err(reason), true) => (
            LOG_WARNING,
            format!("[distro-sync] {id} for {distro}: proof refused ({reason}), fanning out with wake"),
        ),
        (Err(reason), false) => (
            LOG_WARNING,
            format!("[distro-sync] {id} for {distro}: proof refused ({reason}), already held: no fan-out"),
        ),
    }
}

/// At most this many transient ids are named for each reason in the line
/// for a client batch's dropped messages; the rest are counted.
const DROPPED_IDS_LOGGED: usize = 4;

/// A message this long or shorter, its stamp included, is not an LXMF
/// message: `validate_pn_stamp` refuses it before it looks at the stamp
/// (LXStamper.validate_pn_stamp: `len(transient_data) <= LXMF_OVERHEAD +
/// STAMP_SIZE`).
const TOO_SHORT_FOR_LXMF: usize = lxmf_rust::LXMessage::LXMF_OVERHEAD + lx_stamper::STAMP_SIZE;

/// The messages of a client's batch that `validate_pn_stamps` dropped, by
/// why: too short to be an LXMF message, or a stamp under the cost. Each kind
/// is counted, and its first [`DROPPED_IDS_LOGGED`] are named by transient
/// id as LXMF computes it (SHA-256 of all but the last 32 bytes, the stamp).
#[derive(Debug, Default, PartialEq, Eq)]
struct DroppedMessages {
    too_short: usize,
    too_short_ids: Vec<Vec<u8>>,
    invalid_stamp: usize,
    invalid_stamp_ids: Vec<Vec<u8>>,
}

/// Sort the messages `validate_pn_stamps` dropped from `messages`.
/// `validated` is what it returned, in the batch's order (it keeps the
/// order), so one walk pairs each with its message by bytes; nothing is
/// hashed for a message that validated, or for a dropped one past the first
/// few of its kind. The batch is unauthenticated input up to the Resource
/// limit: until 2026-10-10 every dropped message was hashed and its id kept,
/// to print four.
///
/// RFed's link stack proves a client's upload before its stamps are checked
/// (RFed-spec LXMFProp.md §10.5; LXMF proves only when every stamp is valid),
/// so the sending client takes such a message as delivered: the line built
/// from this is the one place its drop can be seen.
fn dropped_messages(messages: &[Vec<u8>], validated: &[(Vec<u8>, Vec<u8>, u32, Vec<u8>)]) -> DroppedMessages {
    let id_of = |message: &[u8]| -> Vec<u8> {
        #[cfg(test)]
        tests::sync_proof_tests::DROPPED_IDS_HASHED.with(|n| n.set(n.get() + 1));
        reticulum_rust::identity::full_hash(&message[..message.len().saturating_sub(lx_stamper::STAMP_SIZE)])
    };
    let mut dropped = DroppedMessages::default();
    let mut next_valid = validated.iter().peekable();
    for message in messages {
        if message.len() <= TOO_SHORT_FOR_LXMF {
            dropped.too_short += 1;
            if dropped.too_short_ids.len() < DROPPED_IDS_LOGGED {
                dropped.too_short_ids.push(id_of(message));
            }
            continue;
        }
        let this_one = next_valid.peek().is_some_and(|(_, lxmf_data, _, stamp)| {
            message.len() == lxmf_data.len() + stamp.len()
                && message[..lxmf_data.len()] == lxmf_data[..]
                && message[lxmf_data.len()..] == stamp[..]
        });
        if this_one {
            next_valid.next();
            continue;
        }
        dropped.invalid_stamp += 1;
        if dropped.invalid_stamp_ids.len() < DROPPED_IDS_LOGGED {
            dropped.invalid_stamp_ids.push(id_of(message));
        }
    }
    dropped
}

/// The one WARNING for the messages of a client's batch that
/// `validate_pn_stamps` dropped, each counted under its reason with the
/// first few named (DISTRO-SYNC-PROOF-DESIGN Open question 5, James
/// 2026-10-10: the departure is tracked, but its drop must speak).
fn dropped_messages_line(dropped: &DroppedMessages, min_cost: u32, origin: &str) -> String {
    let named = |count: usize, ids: &[Vec<u8>]| -> String {
        let mut named: Vec<String> = ids.iter().map(|id| hexrep(id, false)).collect();
        if count > ids.len() {
            named.push(format!("and {} more", count - ids.len()));
        }
        named.join(", ")
    };
    let mut reasons = Vec::new();
    if dropped.invalid_stamp > 0 {
        reasons.push(format!(
            "{} with an invalid stamp (cost {min_cost} required): {}",
            dropped.invalid_stamp,
            named(dropped.invalid_stamp, &dropped.invalid_stamp_ids),
        ));
    }
    if dropped.too_short > 0 {
        reasons.push(format!(
            "{} too short to be an LXMF message ({TOO_SHORT_FOR_LXMF} bytes or fewer with its stamp): {}",
            dropped.too_short,
            named(dropped.too_short, &dropped.too_short_ids),
        ));
    }
    format!(
        "[lxmf.prop] {} message(s) from {origin} dropped, after the link proved the upload: {}",
        dropped.invalid_stamp + dropped.too_short,
        reasons.join("; "),
    )
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
    /// What a distro hand-off wakes through (`LxmfPropagationNode::relay_stack`).
    relay_stack: Arc<dyn RelayStack + Send + Sync>,
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

    /// Fan `lxmf_data`, a message to the distro `dest_hash`, out to its
    /// registered devices, every one of them, the sender's own included
    /// (RFed SPEC §17.13: a proof names no device). `wake` is the hand-off's
    /// for a device the fan-out cannot confirm: `QueueOnly` for a message
    /// with an accepted sync proof, else `Push`.
    fn distro_fanout(&self, dest_hash: &[u8], lxmf_data: &[u8], wake: Wake) {
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
            self.distro_hand_off(Arc::clone(&self.relay_stack), dest_hash, lxmf_data, wake),
        );
        // The summary names the kind of hand-off and not its outcome: each
        // hand-off's own `[handoff]` line says whether its blob was queued
        // (the global limit can refuse it) and whether its device was woken
        // (a sync hand-off still pushes at a bound of §17.3). Until 2026-10-10
        // it said "queued … not woken" for every sync hand-off, also for one
        // a bound woke, and "queued … and pushed" also for a refused blob.
        if handed_off > 0 {
            log(
                format!(
                    "[distro] {} of {} device(s) with no live session for distro {} — {}",
                    handed_off,
                    devices.len(),
                    hexrep(dest_hash, false),
                    match wake {
                        Wake::Push => "handed off with a push (each [handoff] line says what was queued and who was woken)",
                        Wake::QueueOnly => "handed off as distro sync, pushed only at a bound (each [handoff] line says what was queued and who was woken)",
                    },
                ),
                LOG_NOTICE,
                false,
                false,
            );
        }
    }

    /// What a distro fan-out from propagation ingest does with a device it
    /// could not confirm: the one distro hand-off builder,
    /// [`crate::handoff::distro_hand_off`], on the deferred queue
    /// `/rfed/pull` drains and the notify registry the device registered
    /// with, pushing or not as `wake` says. Until 2026-09-26 it only queued:
    /// no device was ever woken.
    fn distro_hand_off(
        &self,
        stack: Arc<dyn RelayStack + Send + Sync>,
        dest_hash: &[u8],
        lxmf_data: &[u8],
        wake: Wake,
    ) -> crate::distro::OnUnconfirmed {
        match &self.deferred_queue {
            Some(queue) => crate::handoff::distro_hand_off(
                stack,
                Arc::clone(queue),
                Arc::clone(&self.registry),
                Arc::new(|_| DISTRO_DEFERRED_QUEUE_LIMIT),
                dest_hash,
                lxmf_data,
                wake,
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
    //
    // What is guaranteed: for every moment t, the messages in sync Resources
    // handed to a link in (t - 60 s, t] number at most
    // `outbound_sync_msgs_per_min`, all peers together, including across a
    // restart. A message counts once its Resource is handed to the link
    // (`record_outbound_send`, just before the "sending N message(s)" log
    // line), whether or not that Resource then completes.

    /// Drop the sends that are out of the window ending at `t`.
    fn prune_outbound_sends(&mut self, t: f64) {
        while let Some(&(at, _)) = self.outbound_sends.front() {
            if t - at >= OUTBOUND_BUDGET_WINDOW_SECS {
                self.outbound_sends.pop_front();
            } else {
                break;
            }
        }
    }

    /// Messages handed to links in the budget window ending now.
    pub fn outbound_sent_in_window(&self) -> u64 {
        let t = monotonic_now();
        self.outbound_sends.iter()
            .filter(|(at, _)| t - at < OUTBOUND_BUDGET_WINDOW_SECS)
            .map(|(_, messages)| messages)
            .sum()
    }

    /// Messages the running sessions hold of the budget (`budget_reserved`).
    fn outbound_reserved(&self) -> u64 {
        self.peers.values().map(|peer| peer.budget_reserved).sum()
    }

    /// Seconds left of the startup hold: no outbound sync until a whole
    /// window has passed since this node was built.
    pub fn outbound_startup_hold_left(&self) -> f64 {
        (self.outbound_record_start + OUTBOUND_BUDGET_WINDOW_SECS - monotonic_now()).max(0.0)
    }

    /// Messages an offer may still reserve: the budget, less what was handed
    /// to links in the last 60 s (a rolling window, not a calendar minute),
    /// less what the running sessions reserve — a session holds its whole
    /// offer until the answer, then the wanted ids until their Resource is
    /// handed to the link, where `record_outbound_send` turns the reservation
    /// into a send. So `sent in the last 60 s + reserved <= budget` holds
    /// after every step, and since the sent part only ever leaves the window
    /// by ageing out, no 60-second span sends more than the budget however
    /// many sessions run.
    ///
    /// Across a restart: the previous run's sends are not known, so nothing
    /// may be reserved until 60 s after this node was built — as if that run
    /// had spent the whole budget the moment this one started. Its last send
    /// came before it stopped, so a restart cannot open a second full budget
    /// within 60 s of it. Chosen over persisting the send record: that holds
    /// only when the record was written after the last send, which a crash
    /// or a kill does not do (and writing it on every send puts a disk write
    /// in the send path), and it would compare this run's clock with the
    /// last one's across whatever step the wall clock took in between.
    ///
    /// Until 2026-09-28 the window was a fixed minute started lazily by the
    /// first query after the last one ended, and reset by a restart: 1200
    /// went out in 26 s in one process and 1200 in 58 s across a restart
    /// (staging). Before that the budget was checked once before a
    /// 500-message send, and 1000 went out in a 600-message minute.
    pub fn outbound_allowance(&mut self) -> u64 {
        let t = monotonic_now();
        if t - self.outbound_record_start < OUTBOUND_BUDGET_WINDOW_SECS {
            return 0;
        }
        self.prune_outbound_sends(t);
        let sent: u64 = self.outbound_sends.iter().map(|(_, messages)| messages).sum();
        self.outbound_sync_msgs_per_min
            .saturating_sub(sent.saturating_add(self.outbound_reserved()))
    }

    /// `peer_hash`'s sync Resource of `messages` is being handed to its link:
    /// record the send, release the session's reservation and count the
    /// messages to its turn.
    fn record_outbound_send(&mut self, peer_hash: &[u8], messages: u64) {
        let t = monotonic_now();
        self.prune_outbound_sends(t);
        self.outbound_sends.push_back((t, messages));
        if let Some(peer) = self.peers.get_mut(peer_hash) {
            peer.budget_reserved = 0;
            peer.turn_sent += messages;
        }
    }

    /// May this tick start an outbound peer sync? False during the startup
    /// hold and while nothing is left of the budget. Logs the hold once and
    /// the release once, so the log tells the story without repeating it
    /// every tick.
    pub fn outbound_sync_allowed(&mut self) -> bool {
        let allowance = self.outbound_allowance();
        if allowance == 0 {
            if !self.outbound_sync_hold_logged {
                let startup_left = self.outbound_startup_hold_left();
                let message = if startup_left > 0.0 {
                    format!(
                        "[lxmf.prop] outbound peer sync held for {startup_left:.0}s more after start: what the last run sent in its final {OUTBOUND_BUDGET_WINDOW_SECS:.0}s is not known",
                    )
                } else {
                    format!(
                        "[lxmf.prop] outbound peer sync held: budget spent, {} sent in the last {OUTBOUND_BUDGET_WINDOW_SECS:.0}s and {} reserved of {}",
                        self.outbound_sent_in_window(), self.outbound_reserved(), self.outbound_sync_msgs_per_min,
                    )
                };
                log(message, LOG_NOTICE, false, false);
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

    // ── Sharing the budget (rfed departure) ──────────────────────────────
    //
    // The budget is rfed's own departure, and the reference's choice was
    // never made to share one: its persistent strategy keeps a session going
    // while the peer lacks messages, and its pool favours the fastest peers.
    // Under the budget that starved peers (staging 2026-09-28): the first
    // session took the whole 600 (500, then 100 more on its held link), the
    // budget was spent until its sends aged out, so one peer was served per
    // ~73 s, and the same fast peers won the next choice — 7 of 20 peers got
    // nothing in 30 minutes. So while the budget binds — the ready peers the
    // tick could choose (`contends_for_sync`) want more than is left of it —
    // rfed shares it:
    //   * a session's turn is a fair share (`fair_share`) of messages SENT
    //     (`turn_sent`): each offer is cut to what is left of it, and the
    //     session takes its next batch on the held link until the share is
    //     sent (`apply_resource_outcome`), then yields while other ready
    //     peers wait. A turn of one batch left most of the budget unspent
    //     whenever a batch was smaller than the share: a byte-limited batch
    //     (52 messages of 20 KB in a ~1 MiB Resource), or a peer that wanted
    //     only part of an offer (review of bcc38cb: 22% and 10% of the
    //     budget spent);
    //   * the tick chooses the ready peer whose last turn is oldest
    //     (`select_sync_peer`), so every one gets a turn — unresponsive
    //     peers whose backoff has run out included. The reference chooses
    //     those only when no alive peer waits, which while the budget binds
    //     is never: one failed link attempt left a peer with nothing until
    //     its next announce (lxmd: every 6 h; review of bcc38cb).
    // While the budget does not bind, the reference's choice and persistent
    // strategy stand unchanged.

    /// Is `peer` one the tick could choose now, and so a contender for the
    /// budget: IDLE, ready to sync, out of backoff and throttle, lacking
    /// something it may be offered. Alive ("waiting" in the reference) or
    /// not ("unresponsive", its backoff run out): while the budget binds,
    /// both take their turn (see "Sharing the budget").
    fn contends_for_sync(peer: &PropPeer, t: f64, backlog_held: bool, fresh: &[Vec<u8>]) -> bool {
        peer.state == PropPeer::IDLE
            && peer.sync_ready()
            && t > peer.throttled_until
            && t > peer.next_sync_attempt
            && Self::has_sync_candidates(backlog_held, fresh, peer)
    }

    /// What `peer` would want of the budget next: what it may be offered, up
    /// to one offer (MAX_OFFER_IDS) and to `cap`.
    fn next_batch_demand(backlog_held: bool, fresh: &[Vec<u8>], peer: &PropPeer, cap: u64) -> u64 {
        let cap = cap.min(MAX_OFFER_IDS as u64) as usize;
        let lacking = if backlog_held {
            fresh.iter().filter(|tid| peer.unhandled_ids.contains(tid)).take(cap).count()
        } else {
            peer.unhandled_ids.len().min(cap)
        };
        lacking as u64
    }

    /// The peers other than `except` the tick could choose now (alive or
    /// unresponsive, `contends_for_sync`), and what they want of the budget,
    /// each up to one offer. The demand is counted only until it passes
    /// `enough`: past that the budget binds whatever the rest want.
    fn budget_contention(&self, t: f64, except: &[u8], enough: u64) -> BudgetContention {
        let backlog_held = self.backlog_held();
        let fresh = &self.fresh_since_start;
        let mut contention = BudgetContention { waiting: 0, demand: 0 };
        for (hash, peer) in &self.peers {
            if hash.as_slice() == except || !Self::contends_for_sync(peer, t, backlog_held, fresh) {
                continue;
            }
            contention.waiting += 1;
            if contention.demand <= enough {
                let room = enough - contention.demand + 1;
                contention.demand += Self::next_batch_demand(backlog_held, fresh, peer, room);
            }
        }
        contention
    }

    /// The most one session may send in its turn (`turn_sent`) while the
    /// budget binds and `contenders` ready peers (its own included) want it:
    /// an equal share of the budget, but never less than one tick's worth of
    /// it (the budget × PEER_SYNC_INTERVAL_SECS / 60 s, 240 of 600). A new
    /// session starts only on a tick, so at most 2.5 start in a minute: a
    /// smaller share would leave the budget unspent and serve no peer
    /// sooner. That holds only because a turn runs until its share is SENT,
    /// over as many batches as it takes, not for one batch.
    pub fn fair_share(&self, contenders: usize) -> u64 {
        let budget = self.outbound_sync_msgs_per_min as f64;
        let equal = budget / contenders.max(1) as f64;
        let per_tick = budget * PEER_SYNC_INTERVAL_SECS / OUTBOUND_BUDGET_WINDOW_SECS;
        (equal.max(per_tick).ceil() as u64).max(1)
    }

    // ── Choosing a peer (LXMRouter.sync_peers) ───────────────────────────

    /// Called from the main event loop. Every PEER_SYNC_INTERVAL_SECS: cull
    /// long-unreachable peers, start peering-key generation where it is
    /// missing, and — while the outbound budget lasts — choose one peer and
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
    ///
    /// And one departure for the budget (see "Sharing the budget"): while it
    /// binds — the peers the tick could choose, alive or unresponsive, want
    /// more than is left of it, each counted up to one offer — the choice is
    /// the one of them whose last turn (`last_sync_attempt`) is oldest, at
    /// random among equals, so every ready peer is served in turn. The
    /// fastest-peer pool served the same fast peers again and again while
    /// the others got nothing; and unresponsive peers, chosen only when no
    /// alive peer waits, were never chosen while the budget bound, so one
    /// failed link attempt left a peer without sync until it announced
    /// again.
    pub fn select_sync_peer(&mut self, t: f64, pick: &mut dyn FnMut(usize) -> usize) -> Option<Vec<u8>> {
        let allowance = self.outbound_allowance();
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

        // Does the budget bind? Every peer the tick could choose counts,
        // alive or unresponsive (`contends_for_sync`); the demand is counted
        // only as far as needed to tell.
        let contenders: Vec<&Vec<u8>> = waiting.iter().map(|(hash, _)| hash).chain(unresponsive.iter()).collect();
        let binds = {
            let mut demand = 0u64;
            for hash in &contenders {
                if demand > allowance {
                    break;
                }
                if let Some(peer) = self.peers.get(*hash) {
                    demand += Self::next_batch_demand(backlog_held, fresh, peer, allowance - demand + 1);
                }
            }
            demand > allowance
        };

        let pool: Vec<Vec<u8>> = if binds {
            // Unresponsive peers past their backoff take their turn too: the
            // reference's "only when no alive peer waits" never comes while
            // the budget binds.
            let last_turn = |hash: &Vec<u8>| self.peers.get(hash).map(|peer| peer.last_sync_attempt).unwrap_or(0.0);
            let oldest = contenders.iter().map(|hash| last_turn(hash)).fold(f64::INFINITY, f64::min);
            let pool: Vec<Vec<u8>> = contenders.iter()
                .filter(|hash| last_turn(hash) == oldest)
                .map(|hash| (*hash).clone())
                .collect();
            log(
                format!(
                    "[lxmf.prop] the outbound budget binds ({allowance} left): selecting the least recently served of {} waiting and {} unresponsive peers",
                    waiting.len(), unresponsive.len(),
                ),
                LOG_DEBUG, false, false,
            );
            pool
        } else if !waiting.is_empty() {
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
            peer.budget_reserved = 0;
            peer.turn_sent = 0;
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
                // A new turn.
                peer.turn_sent = 0;
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
    /// size the offer to the outbound budget's allowance, identify the link if it
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

        let allowance = self.outbound_allowance();
        let mut offer: Vec<Vec<u8>> = {
            let entries = &self.entries;
            let Some(peer) = self.peers.get(peer_hash) else { return };
            plan.offer.into_iter()
                .filter(|tid| entries.contains_key(tid) && peer.unhandled_ids.contains(tid))
                .collect()
        };
        // What is left of the budget, or, while it binds with other ready
        // peers waiting, what is left of this session's fair share of it:
        // its turn is the share SENT, over as many batches as it takes (see
        // "Sharing the budget").
        let wanted = offer.len() as u64;
        let turn_sent = self.peers.get(peer_hash).map(|peer| peer.turn_sent).unwrap_or(0);
        let contention = self.budget_contention(now(), peer_hash, allowance.saturating_sub(wanted));
        let mut share_used = false;
        let (cap, by) = if contention.waiting > 0 && wanted + contention.demand > allowance {
            let share = self.fair_share(contention.waiting + 1);
            let left_of_share = share.saturating_sub(turn_sent);
            share_used = left_of_share == 0;
            (
                allowance.min(left_of_share),
                format!(
                    "what is left of its fair share of the outbound budget ({left_of_share} of {share}, {turn_sent} sent this turn; {allowance} left, {} other peer(s) waiting)",
                    contention.waiting,
                ),
            )
        } else {
            (allowance, "the outbound budget".to_string())
        };
        if wanted > cap {
            log(
                format!("[lxmf.prop] offer to peer {peer_str} cut from {wanted} to {cap} message(s) by {by}"),
                LOG_DEBUG, false, false,
            );
            offer.truncate(cap as usize);
        }
        if offer.is_empty() {
            let reason = if allowance == 0 {
                "the outbound budget is spent"
            } else if share_used {
                "its fair share of the outbound budget is sent and other peers wait"
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
            // The whole offer is held of the budget until the answer.
            peer.budget_reserved = offer.len() as u64;
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
                            // The re-offer is sized afresh.
                            peer.budget_reserved = 0;
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
        // The session now holds only what the peer wants, until the Resource
        // is handed to the link (`send_sync_resource`).
        if let Some(peer) = self.peers.get_mut(peer_hash) {
            peer.budget_reserved = files.len() as u64;
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
        let mut missing = Vec::new();
        for (tid, path) in files {
            match fs::read(&path) {
                Ok(data) => {
                    ids.push(tid);
                    messages.push(data);
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => missing.push((tid, path)),
                Err(e) => unreadable.push((tid, path, e.to_string())),
            }
        }
        for (tid, path, error) in &unreadable {
            log(
                format!("[lxmf.prop] cannot read message {} ({path}) for peer {peer_str}: {error}; it stays unhandled", hexrep(tid, false)),
                LOG_WARNING, false, false,
            );
        }

        // Packed before the node is taken: it is only a copy, and the send
        // below is recorded against the budget the moment it is logged.
        let count = messages.len();
        let data = pack_sync_batch(now(), messages);

        let (io, sink, link_id) = {
            let Some(mut node) = lock_node(arc, "sync resource") else { return };
            node.forget_missing_messages(&missing);
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
            // These messages leave now: counted against the budget from this
            // moment, the reservation released. A Resource that then fails
            // to start still counts; the budget is a ceiling, never exceeded
            // by over-counting.
            node.record_outbound_send(peer_hash, count as u64);
            log(
                format!("[lxmf.prop] sending {count} message(s) to peer {peer_str} as a Resource ({} B)", data.len()),
                LOG_NOTICE, false, false,
            );
            (Arc::clone(&node.sync_io), node.event_sink(), link_id)
        };

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

    /// Drop messages whose file is gone (NotFound) from the store index and,
    /// as `evict_expired` does, from every peer's queues: nothing can ever be
    /// sent or served from them. The reference skips a missing file and marks
    /// it handled for that peer on COMPLETE; left in the index, rfed offered
    /// it again, and opened a link for it, to every peer lacking it until it
    /// expired (7 days). Only the entry the file belonged to goes: a message
    /// stored again since has a file of its own.
    fn forget_missing_messages(&mut self, missing: &[(Vec<u8>, String)]) {
        for (tid, path) in missing {
            if !self.entries.get(tid).map(|entry| &entry.filepath == path).unwrap_or(false) {
                continue;
            }
            self.entries.remove(tid);
            for peer in self.peers.values_mut() {
                peer.handled_ids.remove(tid);
                peer.unhandled_ids.remove(tid);
            }
            log(
                format!("[lxmf.prop] message {} has no file ({path}); dropped from the message store and every peer's queue", hexrep(tid, false)),
                LOG_WARNING, false, false,
            );
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
        // rfed departure (see "Sharing the budget"): while the budget binds
        // and ready peers wait, a session's turn is its fair share of
        // messages sent. Until it has sent that, it takes its next batch on
        // the held link (sized to what is left of the share, `send_offer`);
        // then it ends and waits its turn like them. A turn of one batch
        // left most of the budget unspent when batches were byte-limited or
        // peers wanted part of an offer.
        let (own, turn_sent) = {
            let Some(peer) = self.peers.get(peer_hash) else { return false };
            (
                Self::next_batch_demand(backlog_held, &self.fresh_since_start, peer, MAX_OFFER_IDS as u64),
                peer.turn_sent,
            )
        };
        let allowance = self.outbound_allowance();
        let contention = self.budget_contention(t, peer_hash, allowance.saturating_sub(own));
        if contention.waiting > 0 && own + contention.demand > allowance {
            let share = self.fair_share(contention.waiting + 1);
            let why = if turn_sent >= share {
                Some(format!("its turn sent {turn_sent} message(s), its fair share of {share}"))
            } else if allowance == 0 {
                Some(format!("the budget is spent ({turn_sent} of its fair share of {share} sent this turn)"))
            } else if !on_held_link {
                // Its next batch would need a new link: that is a new turn.
                Some(format!("its sync link is gone ({turn_sent} of its fair share of {share} sent this turn)"))
            } else {
                None
            };
            if let Some(why) = why {
                log(
                    format!(
                        "[lxmf.prop] sync with peer {peer_str} yields to {} waiting peer(s) while the outbound budget binds ({allowance} left): {why}",
                        contention.waiting,
                    ),
                    LOG_NOTICE, false, false,
                );
                self.end_sync(peer_hash);
                return false;
            }
            log(
                format!(
                    "[lxmf.prop] sync with peer {peer_str} takes its next batch on the held link: {turn_sent} of its fair share of {share} sent this turn",
                ),
                LOG_DEBUG, false, false,
            );
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
            // The link AppLinks holds for the peer now. A report of a link it
            // no longer holds is stale: the link was closed (a stray closed
            // at a session's start, whose report was still queued) or
            // replaced, and a session must not take it up or end on it.
            let held_now = node.sync_io.active_link(peer_hash);
            let Some(peer) = node.peers.get_mut(peer_hash) else { return };
            match peer.state {
                PropPeer::IDLE => {
                    // AppLinks brought a link up on its own (a re-open after
                    // a close, or an attempt that outlived its session):
                    // nothing uses it.
                    log(format!("[lxmf.prop] closing a link to peer {peer_str} that no sync is using"), LOG_DEBUG, false, false);
                    node.sync_io.close_link(peer_hash);
                    false
                }
                _ if held_now.as_ref() != Some(&link_id) => {
                    log(
                        format!(
                            "[lxmf.prop] link {} to peer {peer_str} reported up, but AppLinks no longer holds it; report ignored",
                            hexrep(&link_id, false),
                        ),
                        LOG_DEBUG, false, false,
                    );
                    false
                }
                PropPeer::LINK_ESTABLISHING => {
                    log(format!("[lxmf.prop] sync link to peer {peer_str} established"), LOG_DEBUG, false, false);
                    peer.link_id = Some(link_id);
                    peer.identified_link_id = None;
                    peer.reidentified = false;
                    peer.next_sync_attempt = 0.0;
                    peer.state = PropPeer::LINK_READY;
                    true
                }
                _ if peer.link_id.as_ref() == Some(&link_id) => false,
                state => {
                    // AppLinks reports ACTIVE only for the link it tracks, so
                    // this one replaced the session's (two attempts overlapped),
                    // and closing it drops the destination's registration as
                    // well: AppLinks would report the loss of neither. A
                    // session never runs on a link whose loss goes unreported;
                    // it ends, with its ids unhandled.
                    let pending = peer.transferring.as_ref().map(|t| t.len()).unwrap_or(peer.last_offer.len());
                    log(
                        format!(
                            "[lxmf.prop] a new link to peer {peer_str} came up while its sync ({}) runs on another; closing it and ending the sync, {pending} message(s) stay unhandled",
                            PropPeer::state_name(state),
                        ),
                        LOG_WARNING, false, false,
                    );
                    node.end_sync(peer_hash);
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
    /// closed ends here even with a Resource in flight, as the reference's
    /// `LXMPeer.link_closed` returns to IDLE. The Resource concludes FAILED
    /// on its own within one 0.25 s wait step of the close (Reticulum-rust
    /// 6e53dea), and that callback, of an ended session, is ignored by its
    /// session number (`apply_resource_outcome`). The ids stay unhandled; if
    /// the Resource had in fact completed, the next offer finds the peer has
    /// them.
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
        // callback fires once, COMPLETE or not: a closed link cancels one in
        // flight, and one whose link closes before it is advertised fails at
        // its next 0.25 s wait step (Reticulum-rust 6e53dea). A link that has
        // already closed cannot encrypt the batch, so no Resource is built
        // and the error comes back from here. The session does not wait on
        // the callback: the link's DISCONNECTED ends it (`on_link_down`).
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

/// The ready peers besides one the tick could choose, alive or unresponsive,
/// and what they want of the outbound budget (see `budget_contention`).
struct BudgetContention {
    waiting: usize,
    demand: u64,
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
/// worker, then log how long the round trip took.
///
/// No DESIGN_PRINCIPLES §1 assertion on this round trip (James, 2026-09-29).
/// It includes the remote peer working out which of up to MAX_OFFER_IDS ids it
/// wants, across however many hops it sits: 6-14 s to distant production
/// peers on 2026-09-29, time rfed does not control. The request itself still
/// goes out at once, and a missing answer still ends the session through the
/// request's own failure. The assertion was removed on James's word; do not
/// restore it for this round trip without his.
fn offer_response_callback(
    sink: SyncEventSink,
    peer: Vec<u8>,
    session: u64,
    offer_sent_at: f64,
) -> Arc<dyn Fn(Option<Vec<u8>>) + Send + Sync> {
    Arc::new(move |response: Option<Vec<u8>>| {
        let elapsed = now() - offer_sent_at;
        let answered = response.is_some();
        sink(SyncEvent::OfferResponse { peer: peer.clone(), session, response });
        log(
            format!(
                "[lxmf.prop] offer to peer {}: {} after {:.2}s",
                hexrep(&peer, false),
                if answered { "answered" } else { "no answer" },
                elapsed,
            ),
            LOG_NOTICE, false, false,
        );
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

// ── Simulated time for the unit tests ────────────────────────────────────────

/// An offset, per test thread, that `now()` and `monotonic_now()` add. The
/// peer sync tests run every event on the test's own thread, so advancing it
/// moves the whole state machine's time. Always 0 outside tests.
#[cfg(not(test))]
mod test_clock {
    #[inline(always)]
    pub(crate) fn offset() -> f64 { 0.0 }
}
#[cfg(test)]
pub(crate) mod test_clock {
    use std::cell::Cell;
    thread_local! { static OFFSET: Cell<f64> = const { Cell::new(0.0) }; }
    pub(crate) fn offset() -> f64 { OFFSET.with(|o| o.get()) }
    pub(crate) fn advance(secs: f64) { OFFSET.with(|o| o.set(o.get() + secs)); }
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
            test_clock::advance(OUTBOUND_BUDGET_WINDOW_SECS);
            let mut g = node.lock().unwrap();
            assert!(g.backlog_held());
            assert!(g.outbound_sync_allowed(), "past the startup hold the budget alone gates the tick; fresh messages need no wait");
        }

        /// The budget rolls: a send counts for exactly 60 s from the moment
        /// it was handed over, not until a calendar-like minute ends.
        #[test]
        fn sync_is_held_while_the_budget_is_spent_and_resumes_as_sends_age_out() {
            let node = test_node("budget");
            test_clock::advance(OUTBOUND_BUDGET_WINDOW_SECS);
            let mut g = node.lock().unwrap();
            let budget = g.outbound_sync_msgs_per_min;
            g.record_outbound_send(&[0x99; 16], budget);
            assert!(!g.outbound_sync_allowed(), "budget spent holds sync");
            assert!(g.outbound_sync_hold_logged, "the hold is logged once");
            test_clock::advance(OUTBOUND_BUDGET_WINDOW_SECS - 0.5);
            assert!(!g.outbound_sync_allowed(), "still held: the send is under 60 s old");
            test_clock::advance(0.5);
            assert!(g.outbound_sync_allowed(), "60 s after the send its messages no longer count");
            assert_eq!(g.outbound_allowance(), budget);
            assert!(!g.outbound_sync_hold_logged, "the release clears the hold flag");
        }

        /// A restart must not open a second full budget within 60 s of the
        /// last run's sends (staging 2026-09-28: 1200 in 58 s across one).
        /// The send record is not persisted; a node sends nothing until a
        /// whole window has passed since it was built.
        #[test]
        fn a_restart_sends_nothing_until_a_whole_window_has_passed() {
            // The last run spent its budget, then stopped at once.
            let before = test_node("restart_before");
            test_clock::advance(OUTBOUND_BUDGET_WINDOW_SECS);
            let last_send = monotonic_now();
            {
                let mut g = before.lock().unwrap();
                let budget = g.outbound_sync_msgs_per_min;
                g.record_outbound_send(&[0x99; 16], budget);
            }
            drop(before);

            // The next run, built the moment the last one stopped.
            let node = test_node("restart_after");
            let mut g = node.lock().unwrap();
            let budget = g.outbound_sync_msgs_per_min;
            assert_eq!(g.outbound_allowance(), 0, "nothing may be offered at start");
            assert!(!g.outbound_sync_allowed());
            assert!(g.outbound_sync_hold_logged, "the startup hold is logged");
            test_clock::advance(OUTBOUND_BUDGET_WINDOW_SECS - 0.5);
            assert_eq!(g.outbound_allowance(), 0, "nor 59.5 s later");
            test_clock::advance(0.5);
            assert!(monotonic_now() - last_send >= OUTBOUND_BUDGET_WINDOW_SECS);
            assert_eq!(g.outbound_allowance(), budget, "a whole window after the last send, the whole budget");
            assert!(g.outbound_sync_allowed());
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
                channel_transfer_limit_bytes: crate::sync::DEFAULT_CHANNEL_TRANSFER_LIMIT_BYTES,
                channel_sync_limit_bytes: crate::sync::DEFAULT_CHANNEL_SYNC_LIMIT_BYTES,
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
            let m = decode_propagation_batch(&batch(vec![Value::Binary(vec![1; 40]), Value::Binary(vec![2; 40])])).unwrap().messages;
            assert_eq!(m.len(), 2);
        }

        #[test]
        fn str_entries_are_dropped_not_messages() {
            // PyPI msgpack.packb(bytes) without use_bin_type=True produces exactly this.
            let m = decode_propagation_batch(&batch(vec![Value::String("x".repeat(40).into())])).unwrap().messages;
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
            relay_stack: Arc::new(crate::notify::rns::LiveStack),
        };
        let stack = Arc::new(FakeStack::new(&relay_hash, Some(relay_public)));
        let distro_hash = vec![0x22; 16];
        let lxmf_data = vec![0x33; 64];

        let hand_off = handles.distro_hand_off(
            Arc::clone(&stack) as Arc<dyn RelayStack + Send + Sync>,
            &distro_hash,
            &lxmf_data,
            crate::handoff::Wake::Push,
        );
        hand_off(device.clone());

        let pending = queue.lock().expect("queue lock").drain(&device.queue_key);
        assert_eq!(pending.len(), 1, "queued under the identity hash");
        assert_eq!(pending[0].channel_hash, distro_hash);
        assert_eq!(pending[0].blob, lxmf_data);
        assert_eq!(stack.packets.lock().unwrap().len(), 1, "and the device's registration was woken");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// RFed SPEC §17.13, the distro sync proof at ingest
    /// (DISTRO-SYNC-PROOF-DESIGN §6, §13.1 "RFed"). Each test ingests real
    /// uploads into a propagation node with a distro table, a BlobStore, a
    /// deferred queue and a relay stack that records every wake.
    pub(crate) mod sync_proof_tests {
        use super::super::*;
        use std::cell::Cell;

        use crate::blob_store::BlobStore;
        use crate::deferred_queue::DeferredQueue;
        use crate::distro::Unconfirmed;
        use crate::notify::rns::fake::FakeStack;
        use lxmf_rust::distro::{seal_for_sync, sync_signed_bytes, sync_transient_id, DISTRO_SYNC_KEY};

        thread_local! {
            /// How many claims this thread verified (`verify_claim`).
            pub(crate) static VERIFICATIONS: Cell<usize> = const { Cell::new(0) };
            /// How many dropped messages this thread hashed for their id
            /// (`dropped_messages`).
            pub(crate) static DROPPED_IDS_HASHED: Cell<usize> = const { Cell::new(0) };
        }

        fn verifications() -> usize {
            VERIFICATIONS.with(|n| n.get())
        }

        fn config(dir: &std::path::Path) -> NodeConfig {
            NodeConfig {
                config_dir: dir.to_path_buf(),
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
                channel_transfer_limit_bytes: crate::sync::DEFAULT_CHANNEL_TRANSFER_LIMIT_BYTES,
                channel_sync_limit_bytes: crate::sync::DEFAULT_CHANNEL_SYNC_LIMIT_BYTES,
                static_peers: Vec::new(),
                from_static_only: false,
                trusted_backup_peers: Vec::new(),
                primary_node: None,
                secondary_nodes: Vec::new(),
                owner_offline_secs: 90.0,
                lxmf_propagation_enabled: true,
                lxmf_propagation_autopeer: false,
                lxmf_propagation_peers: Vec::new(),
            }
        }

        /// A propagation node wired as main.rs wires it for distros.
        struct Rig {
            dir: std::path::PathBuf,
            node: Arc<Mutex<LxmfPropagationNode>>,
            table: Arc<Mutex<DistroTable>>,
            blobs: Arc<Mutex<BlobStore>>,
            queue: Arc<Mutex<DeferredQueue>>,
            notify: Arc<Mutex<NotifyRegistry>>,
            relay_hash: Vec<u8>,
            stack: Arc<FakeStack>,
        }

        impl Rig {
            /// Stamps are checked at exactly `stamp_cost` (no flexibility):
            /// 0 takes any 32 bytes, so a test needs no mining.
            fn new(tag: &str, stamp_cost: u32) -> Rig {
                let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
                let dir = std::env::temp_dir().join(format!("rfed_sync_proof_{tag}_{unique}"));
                std::fs::create_dir_all(&dir).expect("temp dir");
                let table_path = dir.join("distro.rmp");
                crate::store_db::remove_store_files(&table_path);
                let table = Arc::new(Mutex::new(DistroTable::load(table_path)));
                let blobs = Arc::new(Mutex::new(BlobStore::open(dir.join("blobs"), 1 << 24)));
                let queue = Arc::new(Mutex::new(DeferredQueue::load(dir.join("deferred.rmp"))));
                let notify = Arc::new(Mutex::new(NotifyRegistry::load(dir.join("notify.rmp"))));
                let relay = Identity::new(true);
                let relay_hash = Destination::hash(relay.hash.as_deref(), "rfed", &["notify"]);
                let recalled = Identity::from_public_key(&relay.get_public_key().unwrap()).unwrap();
                let stack = Arc::new(FakeStack::new(&relay_hash, Some(recalled)));
                let node = LxmfPropagationNode::new(
                    Identity::new(true),
                    &config(&dir),
                    Arc::clone(&notify),
                    Arc::new(Mutex::new(PropagationStreamRegistry::default())),
                    Arc::new(Mutex::new(LinkSessionRegistry::default())),
                    Some(Arc::clone(&table)),
                    Some(Arc::clone(&blobs)),
                    None,
                    Some(Arc::clone(&queue)),
                )
                .expect("propagation node");
                {
                    let mut n = node.lock().unwrap();
                    n.stamp_cost = stamp_cost;
                    n.stamp_flexibility = 0;
                    n.relay_stack = Arc::clone(&stack) as Arc<dyn RelayStack + Send + Sync>;
                }
                Rig { dir, node, table, blobs, queue, notify, relay_hash, stack }
            }

            /// Register a device for `distro`, with a notify registration
            /// for wakes, as the apps do. Its two hand-off keys.
            fn device(&self, distro: &[u8]) -> Unconfirmed {
                let identity = Identity::new(true);
                let pubkey = identity.get_public_key().unwrap();
                let lxmf = crate::distro::lxmf_delivery_hash_from_pubkey(&pubkey).unwrap();
                self.table.lock().unwrap().register(distro.to_vec(), lxmf.clone(), pubkey);
                self.notify.lock().unwrap().register(lxmf.clone(), None, hexrep(&self.relay_hash, false));
                Unconfirmed { queue_key: identity.hash.unwrap(), wake_key: lxmf }
            }

            fn ingest(&self, upload: &[u8]) {
                LxmfPropagationNode::ingest_propagation_batch(&self.node, upload, None);
            }

            fn rows(&self, device: &Unconfirmed, distro: &[u8]) -> usize {
                self.queue.lock().unwrap().count_matching(&device.queue_key, distro)
            }

            fn wakes(&self) -> usize {
                self.stack.packets.lock().unwrap().len()
            }

            fn holds(&self, id: &[u8]) -> bool {
                self.blobs.lock().unwrap().index.contains_key(id)
            }
        }

        impl Drop for Rig {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.dir);
            }
        }

        /// A distro D: its identity and `lxmf.delivery` hash.
        fn distro() -> (Identity, Vec<u8>) {
            let d = Identity::new(true);
            let hash = Destination::hash(d.hash.as_deref(), "lxmf", &["delivery"]);
            (d, hash)
        }

        /// A packed message to D (only its destination matters to RFed).
        fn packed_to(d_hash: &[u8], marker: u8) -> Vec<u8> {
            [d_hash, &[marker; 200][..]].concat()
        }

        /// `[bin16 id, bin64 distro_pubkey, bin64 sig]`.
        fn claim_value(id: &[u8], pubkey: &[u8], sig: &[u8]) -> Value {
            Value::Array(vec![Value::Binary(id.to_vec()), Value::Binary(pubkey.to_vec()), Value::Binary(sig.to_vec())])
        }

        /// The claim D's own device makes for `sealed`.
        fn own_claim(d: &Identity, sealed: &[u8]) -> Value {
            let tid = sync_transient_id(sealed);
            let d_hash: [u8; 16] = sealed[..16].try_into().unwrap();
            claim_value(&tid[..16], &d.get_public_key().unwrap(), &d.sign(&sync_signed_bytes(&d_hash, &tid)))
        }

        /// `[timebase, [message, ...]]`, and the extension as `data[2]`.
        fn upload(messages: &[Vec<u8>], claims: Option<Vec<Value>>) -> Vec<u8> {
            let mut items = vec![
                Value::F64(1_790_000_000.0),
                Value::Array(messages.iter().map(|m| Value::Binary(m.clone())).collect()),
            ];
            if let Some(claims) = claims {
                items.push(Value::Map(vec![(Value::String(DISTRO_SYNC_KEY.into()), Value::Array(claims))]));
            }
            let mut out = Vec::new();
            write_value(&mut out, &Value::Array(items)).unwrap();
            out
        }

        /// A sealed message to D, as its device seals it, with a stamp.
        fn sealed_message(d: &Identity, d_hash: &[u8], marker: u8) -> (Vec<u8>, Vec<u8>) {
            let sealed = seal_for_sync(d, &packed_to(d_hash, marker)).expect("seal").sealed;
            let message = [&sealed[..], &[marker; 32][..]].concat();
            (sealed, message)
        }

        /// What follows the `[time] [Level]` prefix of a captured line.
        fn text(line: &str) -> &str {
            let after_time = line.find("] ").map(|i| i + 2).unwrap_or(0);
            let rest = &line[after_time..];
            rest[rest.find("] ").map(|i| i + 2).unwrap_or(0)..].trim_start()
        }

        // ── Decoding ────────────────────────────────────────────────────

        /// An RFed before §17.13 read `data[1]` alone; this one still takes
        /// the messages whatever `data[2]` is, and only a map with the key
        /// carries claims.
        #[test]
        fn a_third_element_of_any_kind_leaves_the_messages_as_they_were() {
            let messages = vec![vec![0x11; 200], vec![0x22; 200]];
            for junk in [
                Value::Nil,
                Value::String("rfed.distro.sync".into()),
                Value::Binary(vec![0x81, 0xa1, 0x78, 0x01]),
                Value::Array(vec![Value::Integer(7.into())]),
                Value::Map(vec![(Value::String("other".into()), Value::Boolean(true))]),
            ] {
                let mut out = Vec::new();
                let items = vec![
                    Value::F64(0.0),
                    Value::Array(messages.iter().map(|m| Value::Binary(m.clone())).collect()),
                    junk.clone(),
                    Value::String("a fourth element".into()),
                ];
                write_value(&mut out, &Value::Array(items)).unwrap();
                let batch = decode_propagation_batch(&out).expect("a batch");
                assert_eq!(batch.messages, messages, "data[2] = {junk:?}");
                let claims = batch.claims.expect("a third element");
                assert!(claims.by_id.is_empty());
                assert_eq!(claims.ignored, 1, "ignored as a whole: {junk:?}");
            }
            let two = decode_propagation_batch(&upload(&messages, None)).unwrap();
            assert_eq!(two.messages, messages);
            assert!(two.claims.is_none(), "today's two-element upload has no claims at all");
        }

        // ── The golden vector (LXMF-rust tests/distro_sync_vectors.json) ─

        fn vector(key: &str) -> Vec<u8> {
            let json = include_str!("../../../LXMF-rust/tests/distro_sync_vectors.json");
            let start = json.find(&format!("\"{key}\": \"")).unwrap_or_else(|| panic!("{key} in the vector")) + key.len() + 5;
            let end = start + json[start..].find('"').unwrap();
            reticulum_rust::decode_hex(&json[start..end]).unwrap_or_else(|| panic!("{key} is hex"))
        }

        /// The upload Python built (RNS 1.5.2, LXMF 1.1.1, umsgpack), with
        /// its stamp at cost 16, is one RFed accepts: the device of D is
        /// queued and nobody is woken.
        #[test]
        fn the_golden_vector_is_accepted() {
            let d_hash = vector("lxmf_delivery_hash_hex");
            let id = vector("id_hex");
            let envelope = vector("envelope_hex");

            let batch = decode_propagation_batch(&envelope).expect("the vector's envelope");
            assert_eq!(batch.messages, vec![vector("lxmf_data_hex")]);
            let claims = batch.claims.expect("its extension");
            let claim = claims.by_id.get(&<[u8; 16]>::try_from(&id[..]).unwrap()).expect("its claim, by id");
            assert_eq!(claim.sig.to_vec(), vector("sig_hex"));
            assert_eq!(verify_sync_claim(claim, &vector("transient_id_hex"), &vector("sealed_hex")), Ok(()));

            let rig = Rig::new("golden", 16);
            let device = rig.device(&d_hash);
            let mark = crate::test_log::mark();
            rig.ingest(&envelope);

            assert!(rig.holds(&id), "stored under transient_id[0..16]");
            assert_eq!(rig.rows(&device, &d_hash), 1);
            assert_eq!(rig.wakes(), 0);
            let verdict = mark.containing("[distro-sync] ");
            assert_eq!(verdict.len(), 1, "{verdict:?}");
            assert_eq!(
                text(&verdict[0]),
                format!(
                    "[distro-sync] {} for {}: proof accepted, fanning out as distro sync (each [handoff] line says whether its device was woken)",
                    hexrep(&id, false),
                    hexrep(&d_hash, false),
                ),
            );
        }

        // ── Accepted, refused, none ─────────────────────────────────────

        /// An accepted proof: every registered device, the sender's own
        /// among them (RFed cannot tell which, and excludes none), queued
        /// once; no wake; the fan-out's summary says so.
        #[test]
        fn an_accepted_proof_queues_every_device_and_wakes_none() {
            let rig = Rig::new("accepted", 0);
            let (d, d_hash) = distro();
            let sender = rig.device(&d_hash);
            let sibling = rig.device(&d_hash);
            let (sealed, message) = sealed_message(&d, &d_hash, 1);
            let mark = crate::test_log::mark();
            rig.ingest(&upload(&[message], Some(vec![own_claim(&d, &sealed)])));

            assert!(rig.holds(&sync_transient_id(&sealed)[..16]));
            assert_eq!((rig.rows(&sender, &d_hash), rig.rows(&sibling, &d_hash)), (1, 1));
            assert_eq!(rig.wakes(), 0, "nobody woken");
            let lines = mark.lines();
            assert!(lines.iter().any(|l| l.contains("proof accepted, fanning out as distro sync")), "{lines:?}");
            assert!(lines.iter().any(|l| l.ends_with(&format!(
                "[distro] 2 of 2 device(s) with no live session for distro {} — handed off as distro sync, pushed only at a bound (each [handoff] line says what was queued and who was woken)",
                hexrep(&d_hash, false),
            ))), "{lines:?}");
            assert_eq!(lines.iter().filter(|l| l.contains("NOT woken (distro sync, 1 of 64 un-pulled)")).count(), 2);
            assert!(mark.containing("[distro-sync] batch").is_empty(), "a clean batch writes no summary");
        }

        /// At a bound of §17.3 an accepted proof's hand-off pushes after all,
        /// and no line of the upload says otherwise: the verdict and the
        /// fan-out's summary name the kind of fan-out, and the `[handoff]`
        /// lines say who was woken. (Until 2026-10-10 the verdict said "not
        /// woken" and the summary "queued for /rfed/pull, not woken" here,
        /// beside the `[handoff]` line that woke the device.)
        #[test]
        fn at_a_bound_no_line_says_a_woken_device_was_not_woken() {
            let rig = Rig::new("bound_lines", 0);
            let (d, d_hash) = distro();
            let device = rig.device(&d_hash);
            {
                let mut queue = rig.queue.lock().unwrap();
                for n in 0..63u8 {
                    queue.enqueue(device.queue_key.clone(), d_hash.clone(), vec![n], 256);
                }
            }
            let (sealed, message) = sealed_message(&d, &d_hash, 6);
            let mark = crate::test_log::mark();
            rig.ingest(&upload(&[message], Some(vec![own_claim(&d, &sealed)])));

            assert_eq!((rig.rows(&device, &d_hash), rig.wakes()), (64, 1), "the 64th un-pulled blob wakes its device");
            let lines = mark.lines();
            assert!(lines.iter().any(|l| l.ends_with(&format!(
                "[handoff] distro sync for {} of {} woken anyway: 64 un-pulled",
                hexrep(&device.wake_key, false),
                hexrep(&d_hash, false),
            ))), "{lines:?}");
            assert!(lines.iter().any(|l| l.contains("queued for pull, woken via 1 of 1 notify registration(s)")), "{lines:?}");
            for line in &lines {
                assert!(!line.to_lowercase().contains("not woken"), "a line denies the wake: {line}");
            }
        }

        /// The regression guard: with no claim, a signature over another
        /// message, a stranger's key, or a claim signed with another key
        /// for a stranger's message to D, the hand-off is today's: one
        /// enqueue and one wake per device.
        #[test]
        fn without_an_accepted_proof_every_device_is_woken_as_before() {
            let (d, d_hash) = distro();
            let stranger = Identity::new(true);
            let cases: Vec<(&str, Box<dyn Fn(&[u8]) -> Option<Vec<Value>>>)> = vec![
                ("no claim", Box::new(|_| None)),
                (
                    "a signature over another message",
                    Box::new(|sealed: &[u8]| {
                        let tid = sync_transient_id(sealed);
                        let other = sync_transient_id(b"another sealed message");
                        let d_hash: [u8; 16] = sealed[..16].try_into().unwrap();
                        Some(vec![claim_value(&tid[..16], &d.get_public_key().unwrap(), &d.sign(&sync_signed_bytes(&d_hash, &other)))])
                    }),
                ),
                (
                    "a stranger's key",
                    Box::new(|sealed: &[u8]| {
                        let tid = sync_transient_id(sealed);
                        let d_hash: [u8; 16] = sealed[..16].try_into().unwrap();
                        Some(vec![claim_value(&tid[..16], &stranger.get_public_key().unwrap(), &stranger.sign(&sync_signed_bytes(&d_hash, &tid)))])
                    }),
                ),
                (
                    "D's key, signed by a stranger",
                    Box::new(|sealed: &[u8]| {
                        let tid = sync_transient_id(sealed);
                        let d_hash: [u8; 16] = sealed[..16].try_into().unwrap();
                        Some(vec![claim_value(&tid[..16], &d.get_public_key().unwrap(), &stranger.sign(&sync_signed_bytes(&d_hash, &tid)))])
                    }),
                ),
            ];
            for (n, (case, claims)) in cases.iter().enumerate() {
                let rig = Rig::new("refused", 0);
                let device = rig.device(&d_hash);
                // A stranger's message to D: sealed to D by anyone, not proven by D.
                let (sealed, message) = sealed_message(&d, &d_hash, 0x40 + n as u8);
                let mark = crate::test_log::mark();
                rig.ingest(&upload(&[message], claims(&sealed)));

                assert_eq!(rig.rows(&device, &d_hash), 1, "{case}: queued");
                assert_eq!(rig.wakes(), 1, "{case}: and woken");
                let verdicts = mark.containing("[distro-sync] ");
                if claims(&sealed).is_none() {
                    assert!(verdicts.is_empty(), "{case}: no claim, no verdict: {verdicts:?}");
                    assert!(mark.lines().iter().any(|l| l.contains("— handed off with a push (each [handoff] line says")), "{case}");
                } else {
                    assert_eq!(verdicts.len(), 2, "{case}: the verdict and the batch summary: {verdicts:?}");
                    assert!(verdicts[0].contains("[Warning]"), "{case}: {}", verdicts[0]);
                    assert!(verdicts[0].contains(": proof refused ("), "{case}: {}", verdicts[0]);
                    assert!(verdicts[0].ends_with("), fanning out with wake"), "{case}: {}", verdicts[0]);
                    assert!(verdicts[1].ends_with(": 0 accepted, 1 refused, 0 malformed, 0 duplicate, 0 unmatched, 0 ignored"), "{case}: {}", verdicts[1]);
                }
            }
        }

        /// RFed reads claims only from a client's batch. A batch from one of
        /// our LXMF peers that carries one is ignored and counted, and its
        /// message to D wakes.
        #[test]
        fn a_peers_batch_is_not_read_for_claims() {
            let rig = Rig::new("peer_batch", 0);
            let (d, d_hash) = distro();
            let device = rig.device(&d_hash);
            let peer = Identity::new(true);
            let peer_prop = Destination::hash_from_name_and_identity(&format!("{}.{}", LXMF_APP, PROP_ASPECT), Some(&peer));
            rig.node.lock().unwrap().peers.insert(peer_prop.clone(), PropPeer::new(peer_prop.clone()));
            let (sealed, message) = sealed_message(&d, &d_hash, 2);
            let before = verifications();
            let mark = crate::test_log::mark();
            LxmfPropagationNode::ingest_propagation_batch(&rig.node, &upload(&[message], Some(vec![own_claim(&d, &sealed)])), Some(&peer));

            assert_eq!(verifications(), before, "no claim of a peer's batch is verified");
            assert_eq!((rig.rows(&device, &d_hash), rig.wakes()), (1, 1), "a peer's copy wakes, as FedSync's does");
            let summary = mark.containing("[distro-sync] ");
            assert_eq!(summary.len(), 1, "{summary:?}");
            assert!(summary[0].ends_with(&format!(
                "[distro-sync] batch from peer {}: 0 accepted, 0 refused, 0 malformed, 0 duplicate, 0 unmatched, 1 ignored",
                hexrep(&peer_prop, false),
            )), "{}", summary[0]);
        }

        /// A claim for a message whose destination is not a distro here: the
        /// message is stored and dispatched exactly as a plain upload's is,
        /// and the claim is counted unmatched, never verified.
        #[test]
        fn a_claim_for_a_message_that_is_not_a_distro_here_is_unmatched() {
            let (d, d_hash) = distro();
            let (sealed, message) = sealed_message(&d, &d_hash, 3);
            let processed = |claims: Option<Vec<Value>>| -> (String, usize, Vec<String>) {
                let rig = Rig::new("unmatched", 0);
                let mark = crate::test_log::mark();
                rig.ingest(&upload(&[message.clone()], claims));
                let line = mark.containing("[lxmf.prop] processed ").pop().expect("the processed line");
                let entries = rig.node.lock().unwrap().entries.len();
                (text(&line).to_string(), entries, mark.containing("[distro-sync] "))
            };
            let before = verifications();
            let plain = processed(None);
            let claimed = processed(Some(vec![own_claim(&d, &sealed)]));
            assert_eq!(verifications(), before, "no distro message, no verification");
            assert_eq!(plain.0, claimed.0, "the same processing");
            assert_eq!((plain.1, claimed.1), (1, 1), "stored in the messagestore both times");
            assert!(plain.2.is_empty());
            assert_eq!(claimed.2.len(), 1);
            assert!(claimed.2[0].ends_with(": 0 accepted, 0 refused, 0 malformed, 0 duplicate, 1 unmatched, 0 ignored"), "{}", claimed.2[0]);
        }

        // ── Dedup: a message fans out once, on first sight ──────────────

        /// The device seals once, so a re-upload after a lost proof carries
        /// the same sealed bytes with a new stamp: held, not fanned out again.
        #[test]
        fn a_reupload_with_a_new_stamp_does_not_fan_out_again() {
            let rig = Rig::new("reupload", 0);
            let (d, d_hash) = distro();
            let device = rig.device(&d_hash);
            let (sealed, first) = sealed_message(&d, &d_hash, 4);
            rig.ingest(&upload(&[first], Some(vec![own_claim(&d, &sealed)])));
            assert_eq!((rig.rows(&device, &d_hash), rig.wakes()), (1, 0));

            let second = [&sealed[..], &[0x99; 32][..]].concat();
            let mark = crate::test_log::mark();
            rig.ingest(&upload(&[second], Some(vec![own_claim(&d, &sealed)])));
            assert_eq!((rig.rows(&device, &d_hash), rig.wakes()), (1, 0), "no second fan-out");
            let verdict = mark.containing("[distro-sync] ");
            assert_eq!(verdict.len(), 1, "{verdict:?}");
            assert!(verdict[0].ends_with(": proof accepted, already held: no fan-out"), "{}", verdict[0]);
            assert!(mark.containing("[handoff] ").is_empty());
        }

        /// A valid claim on a blob first ingested without one does nothing.
        #[test]
        fn a_proof_for_a_blob_already_held_without_one_does_nothing() {
            let rig = Rig::new("held_unproven", 0);
            let (d, d_hash) = distro();
            let device = rig.device(&d_hash);
            let (sealed, message) = sealed_message(&d, &d_hash, 5);
            rig.ingest(&upload(&[message.clone()], None));
            assert_eq!((rig.rows(&device, &d_hash), rig.wakes()), (1, 1), "first sight, no proof: woken");

            let mark = crate::test_log::mark();
            rig.ingest(&upload(&[message], Some(vec![own_claim(&d, &sealed)])));
            assert_eq!((rig.rows(&device, &d_hash), rig.wakes()), (1, 1), "nothing more");
            let verdict = mark.containing("[distro-sync] ");
            assert_eq!(verdict.len(), 1);
            assert!(verdict[0].ends_with(&format!(
                "[distro-sync] {} for {}: proof accepted, already held: no fan-out",
                hexrep(&sync_transient_id(&sealed)[..16], false),
                hexrep(&d_hash, false),
            )), "{}", verdict[0]);
        }

        // ── Bounded and quiet ───────────────────────────────────────────

        /// 10^5 malformed claims on a one-message upload: the extension is
        /// ignored as a whole (more claims than messages), nothing is
        /// verified, and the batch writes two lines: its summary and the
        /// processed line. A malformed claim within the bound is counted.
        #[test]
        fn a_hundred_thousand_malformed_claims_write_two_lines() {
            let rig = Rig::new("flood", 0);
            let message = [&[0x5A; 16][..], &[0x5B; 200][..]].concat();
            let before = verifications();
            let mark = crate::test_log::mark();
            rig.ingest(&upload(&[message.clone()], Some(vec![Value::Nil; 100_000])));
            let lines = mark.lines();
            assert_eq!(verifications(), before);
            assert_eq!(lines.len(), 2, "{lines:?}");
            assert!(lines[0].ends_with(": 0 accepted, 0 refused, 0 malformed, 0 duplicate, 0 unmatched, 1 ignored"), "{}", lines[0]);
            assert!(text(&lines[1]).starts_with("[lxmf.prop] processed 1 msgs: 1 stored,"), "{}", lines[1]);

            let mark = crate::test_log::mark();
            let other = [&[0x5A; 16][..], &[0x5C; 200][..]].concat();
            rig.ingest(&upload(&[other], Some(vec![claim_value(&[1; 15], &[2; 64], &[3; 64])])));
            let lines = mark.lines();
            assert_eq!(lines.len(), 2, "{lines:?}");
            assert!(lines[0].ends_with(": 0 accepted, 0 refused, 1 malformed, 0 duplicate, 0 unmatched, 0 ignored"), "{}", lines[0]);
        }

        /// N messages to a registered distro whose stamps fail, with N
        /// well-formed claims: no Ed25519 runs (a claim is looked at only for
        /// a stamp-valid message), and the batch writes a fixed number of
        /// lines, whatever N is: the processed line, the claims' summary,
        /// and the one WARNING for the dropped messages (Open question 5).
        #[test]
        fn bad_stamps_with_claims_verify_nothing_and_write_a_fixed_number_of_lines() {
            let rig = Rig::new("bad_stamps", 40);
            let (d, d_hash) = distro();
            let device = rig.device(&d_hash);
            let n = 12;
            let mut messages = Vec::new();
            let mut claims = Vec::new();
            for i in 0..n {
                let (sealed, message) = sealed_message(&d, &d_hash, 0x60 + i as u8);
                messages.push(message);
                claims.push(if i % 2 == 0 {
                    own_claim(&d, &sealed)
                } else {
                    claim_value(&rand::random::<[u8; 16]>(), &[0x77; 64], &[0x78; 64])
                });
            }
            let before = verifications();
            let mark = crate::test_log::mark();
            rig.ingest(&upload(&messages, Some(claims)));
            assert_eq!(verifications(), before, "no claim verified for an unpaid message");
            assert_eq!((rig.rows(&device, &d_hash), rig.wakes()), (0, 0), "nothing stored, nobody queued");
            let lines = mark.lines();
            assert_eq!(lines.len(), 3, "{lines:?}");
            assert!(lines[0].contains("[Warning]") && text(&lines[0]).starts_with(&format!("[lxmf.prop] {n} message(s) from a sender with no identity (handled as a client's) dropped, after the link proved the upload: {n} with an invalid stamp (cost 40 required): ")), "{}", lines[0]);
            assert!(lines[1].ends_with(&format!(": 0 accepted, 0 refused, 0 malformed, 0 duplicate, {n} unmatched, 0 ignored")), "{}", lines[1]);
            assert_eq!(text(&lines[2]), format!("[lxmf.prop] processed {n} msgs: 0 stored, 0 streamed, 0 notified, {n} bad-stamp, from a sender with no identity (handled as a client's)"));
        }

        // ── Q5: a client's message dropped for its stamp speaks ─────────

        /// RFed proves a client's upload before checking its stamps, so the
        /// client takes a message RFed then drops as delivered. The drop is a
        /// WARNING naming the message's transient id (James, 2026-10-10). A
        /// peer's bad stamps are only counted, as before.
        #[test]
        fn a_clients_message_dropped_for_its_stamp_is_a_warning_with_its_id() {
            let rig = Rig::new("q5", 40);
            let message = [&[0x3A; 16][..], &[0x3B; 200][..]].concat();
            let tid = reticulum_rust::identity::full_hash(&message[..message.len() - 32]);
            let mark = crate::test_log::mark();
            rig.ingest(&upload(&[message.clone()], None));
            let warnings = mark.containing("dropped, after the link proved the upload");
            assert_eq!(warnings.len(), 1, "{:?}", mark.lines());
            assert!(warnings[0].contains("[Warning]"));
            assert!(text(&warnings[0]).ends_with(&format!(
                "dropped, after the link proved the upload: 1 with an invalid stamp (cost 40 required): {}",
                hexrep(&tid, false),
            )), "{}", warnings[0]);

            // Many: four named, the rest counted, still one line.
            let many: Vec<Vec<u8>> = (0..6u8).map(|i| [&[0x3A; 16][..], &[0x40 + i; 200][..]].concat()).collect();
            let mark = crate::test_log::mark();
            rig.ingest(&upload(&many, None));
            let warnings = mark.containing("dropped, after the link proved the upload");
            assert_eq!(warnings.len(), 1);
            assert!(warnings[0].ends_with(", and 2 more"), "{}", warnings[0]);
            let named = warnings[0].split("(cost 40 required): ").nth(1).expect("the ids");
            assert_eq!(named.split(", ").filter(|id| id.len() == 64).count(), 4, "{named}");

            // A peer's batch: counted in the processed line only.
            let peer = Identity::new(true);
            let peer_prop = Destination::hash_from_name_and_identity(&format!("{}.{}", LXMF_APP, PROP_ASPECT), Some(&peer));
            rig.node.lock().unwrap().peers.insert(peer_prop.clone(), PropPeer::new(peer_prop));
            let mark = crate::test_log::mark();
            LxmfPropagationNode::ingest_propagation_batch(&rig.node, &upload(&[message], None), Some(&peer));
            assert!(mark.containing("dropped, after the link proved").is_empty());
            assert_eq!(mark.containing("1 bad-stamp").len(), 1);
        }

        /// `validate_pn_stamp` drops a message of LXMF_OVERHEAD + STAMP_SIZE
        /// (144) bytes or fewer before it looks at the stamp. Such a message
        /// is counted and named as too short, not as a stamp failure (at
        /// cost 0, where every stamp is valid, it was logged as "an invalid
        /// stamp (cost 0 required)" until 2026-10-10). A batch with both
        /// kinds still writes one WARNING.
        #[test]
        fn a_message_too_short_for_lxmf_is_named_as_too_short() {
            let rig = Rig::new("q5_short", 0);
            let short = vec![0x3C; 100];
            let edge = vec![0x3D; TOO_SHORT_FOR_LXMF];
            assert_eq!(TOO_SHORT_FOR_LXMF, 144);
            let id = |m: &[u8]| hexrep(&reticulum_rust::identity::full_hash(&m[..m.len() - 32]), false);
            let mark = crate::test_log::mark();
            rig.ingest(&upload(&[short.clone(), edge.clone()], None));
            let warnings = mark.containing("dropped, after the link proved the upload");
            assert_eq!(warnings.len(), 1, "{:?}", mark.lines());
            assert!(text(&warnings[0]).ends_with(&format!(
                "2 message(s) from a sender with no identity (handled as a client's) dropped, after the link proved the upload: 2 too short to be an LXMF message (144 bytes or fewer with its stamp): {}, {}",
                id(&short),
                id(&edge),
            )), "{}", warnings[0]);
            assert!(!warnings[0].contains("invalid stamp"), "{}", warnings[0]);

            // Both kinds in one client batch: one line, the stamp failures first.
            let rig = Rig::new("q5_both", 40);
            let bad = [&[0x3A; 16][..], &[0x3E; 200][..]].concat();
            let mark = crate::test_log::mark();
            rig.ingest(&upload(&[short.clone(), bad.clone(), edge.clone()], None));
            let warnings = mark.containing("dropped, after the link proved the upload");
            assert_eq!(warnings.len(), 1, "{:?}", mark.lines());
            assert!(text(&warnings[0]).ends_with(&format!(
                "3 message(s) from a sender with no identity (handled as a client's) dropped, after the link proved the upload: 1 with an invalid stamp (cost 40 required): {}; 2 too short to be an LXMF message (144 bytes or fewer with its stamp): {}, {}",
                id(&bad),
                id(&short),
                id(&edge),
            )), "{}", warnings[0]);
        }

        /// The sorting walks the batch once and hashes only the dropped
        /// messages it names, whatever the batch holds: 10^5 empty entries
        /// (a ~200 KB client Resource) cost four hashes, not 10^5, and a
        /// message that validated is paired by its bytes, never hashed.
        #[test]
        fn sorting_the_dropped_messages_hashes_only_those_it_names() {
            let hashed = || DROPPED_IDS_HASHED.with(|n| n.get());
            let before = hashed();
            let junk = vec![Vec::new(); 100_000];
            let dropped = dropped_messages(&junk, &[]);
            assert_eq!((dropped.too_short, dropped.too_short_ids.len(), dropped.invalid_stamp), (100_000, 4, 0));
            assert_eq!(hashed() - before, 4);

            // Valid and invalid interleaved: each valid one is matched in
            // order, by its bytes; only the dropped ones are named.
            let messages: Vec<Vec<u8>> = (0..10u8).map(|i| [&[0x5D; 16][..], &[i; 200][..]].concat()).collect();
            let validated: Vec<(Vec<u8>, Vec<u8>, u32, Vec<u8>)> = messages
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 3 != 0)
                .map(|(_, m)| {
                    let split = m.len() - 32;
                    (reticulum_rust::identity::full_hash(&m[..split]), m[..split].to_vec(), 0, m[split..].to_vec())
                })
                .collect();
            let before = hashed();
            let dropped = dropped_messages(&messages, &validated);
            assert_eq!(hashed() - before, 4, "four of messages 0, 3, 6 and 9 named");
            assert_eq!(dropped.invalid_stamp, 4);
            let expected: Vec<Vec<u8>> =
                [0usize, 3, 6, 9].iter().map(|&i| reticulum_rust::identity::full_hash(&messages[i][..messages[i].len() - 32])).collect();
            assert_eq!(dropped.invalid_stamp_ids, expected);
            assert_eq!(dropped.too_short, 0);
        }

        // ── Pins ────────────────────────────────────────────────────────

        /// The staging harnesses parse the processed line; it is unchanged.
        #[test]
        fn the_processed_line_is_unchanged() {
            let source = include_str!("lxmf_propagation.rs");
            assert!(source.contains(concat!(
                "                \"[lxmf.prop] processed {} msgs: {} stored, {} streamed, {} notified, {} bad-stamp, from {}\",\n",
                "                total, stored, streamed, notified, invalid_stamps, origin,\n",
            )));
        }

        /// Both distro entry points build their hand-off with
        /// `handoff::distro_hand_off`; neither queues or wakes by hand
        /// (FedSync's is pinned in destinations.rs).
        #[test]
        fn the_ingest_distro_hand_off_is_the_shared_builder() {
            let source = include_str!("lxmf_propagation.rs");
            let start = source.find("    fn distro_hand_off(\n").expect("DeliveryHandles::distro_hand_off");
            let body = &source[start..start + source[start..].find("\n    }\n").expect("its end")];
            assert!(body.contains("crate::handoff::distro_hand_off("));
            assert!(body.contains("                wake,\n"), "with the ingest's wake");
            for forbidden in ["defer_then_wake(", ".enqueue(", "get_for_channel("] {
                assert!(!body.contains(forbidden), "no {forbidden} of its own");
            }
            let ingest = &source[source.find("if delivery.is_distro(dest_hash) {").unwrap()..];
            let ingest = &ingest[..ingest.find("continue;").unwrap()];
            assert!(ingest.contains("let first_sight = delivery.ingest_distro_blob(dest_hash, lxmf_data, &mut stored);"));
            assert!(ingest.contains("if first_sight {\n                    delivery.distro_fanout(dest_hash, lxmf_data, wake);"));
        }
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
        ///
        /// Like AppLinks, it knows a link attempt that is in flight with no
        /// link up yet (`attempting`, from `open_link` until the link comes
        /// up, the attempt fails, or `close_link`): `link_attempt_live` is
        /// true for it, as `AppLinks::status` reports PATH_REQUESTED or
        /// ESTABLISHING.
        #[derive(Default)]
        struct FakeIo {
            calls: Mutex<Vec<String>>,
            active: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
            attempting: Mutex<HashSet<Vec<u8>>>,
            offers: Mutex<VecDeque<(Vec<u8>, OnResponse, OnFailed)>>,
            resources: Mutex<VecDeque<(Vec<u8>, OnConcluded)>>,
            /// Every sync Resource handed over: (monotonic time, peer, messages).
            sent: Mutex<Vec<(f64, Vec<u8>, u64)>>,
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
                self.attempting.lock().unwrap().remove(peer);
                self.active.lock().unwrap().insert(peer.to_vec(), link.to_vec());
            }
            /// The held link to `peer` is gone.
            fn link_gone(&self, peer: &[u8]) {
                self.active.lock().unwrap().remove(peer);
            }
            /// The link attempt to `peer` failed (path race lost, or the link
            /// closed before it came up).
            fn attempt_failed(&self, peer: &[u8]) {
                self.attempting.lock().unwrap().remove(peer);
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
            fn sent(&self) -> Vec<(f64, Vec<u8>, u64)> {
                self.sent.lock().unwrap().clone()
            }
        }

        /// The most messages handed over in any span of
        /// OUTBOUND_BUDGET_WINDOW_SECS: every such span that holds a send
        /// ends at one, so checking the span ending at each send covers them
        /// all.
        fn most_in_any_window(sent: &[(f64, Vec<u8>, u64)]) -> u64 {
            sent.iter()
                .map(|(end, _, _)| {
                    sent.iter()
                        .filter(|(at, _, _)| at <= end && end - at < OUTBOUND_BUDGET_WINDOW_SECS)
                        .map(|(_, _, messages)| messages)
                        .sum::<u64>()
                })
                .max()
                .unwrap_or(0)
        }

        impl PeerSyncIo for FakeIo {
            fn active_link(&self, peer: &[u8]) -> Option<Vec<u8>> {
                self.active.lock().unwrap().get(peer).cloned()
            }
            fn link_attempt_live(&self, peer: &[u8]) -> bool {
                self.attempting.lock().unwrap().contains(peer) || self.active_link(peer).is_some()
            }
            fn open_link(&self, peer: &[u8]) {
                self.attempting.lock().unwrap().insert(peer.to_vec());
                self.record(format!("open {}", hexrep(&peer[..1], false)));
            }
            fn close_link(&self, peer: &[u8]) {
                self.attempt_failed(peer);
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
                peer: &[u8],
                link_id: &[u8],
                data: Vec<u8>,
                on_concluded: OnConcluded,
            ) -> Result<(), String> {
                self.record(format!("resource {}", hexrep(&link_id[..1], false)));
                let messages = decode_propagation_batch(&data).map(|b| b.messages.len()).unwrap_or(0) as u64;
                self.sent.lock().unwrap().push((monotonic_now(), peer.to_vec(), messages));
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
                    // As if the node had been up a whole budget window: the
                    // startup hold has its own test.
                    g.outbound_record_start = monotonic_now() - OUTBOUND_BUDGET_WINDOW_SECS;
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
            let messages = decode_propagation_batch(&payload).expect("rfed's own ingest reads the batch").messages;
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
            assert_eq!(decode_propagation_batch(&payload).unwrap().messages.len(), 1);
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
            assert_eq!(decode_propagation_batch(&payload).unwrap().messages.len(), 5);
            assert_eq!(h.node.lock().unwrap().outbound_sent_in_window(), 5);

            // Completing does not make room: the persistent strategy's next
            // offer finds the budget spent and ends the session.
            concluded(complete());
            h.pump();
            assert_eq!(h.io.offer_count(), 0);
            assert_eq!(h.state(&a), PropPeer::IDLE);
            assert_eq!(h.node.lock().unwrap().outbound_sent_in_window(), 5, "never more than the budget");

            // 30 s on, 3 more leave; 60 s after the first 5 only those 3
            // count, so the next offer is 2.
            test_clock::advance(30.0);
            h.node.lock().unwrap().record_outbound_send(&[0x99; 16], 3);
            test_clock::advance(OUTBOUND_BUDGET_WINDOW_SECS - 30.0);
            assert_eq!(h.node.lock().unwrap().outbound_allowance(), 2);
            h.start(&b);
            h.link_active(&b, &LINK_2);
            let (offer, _, _) = h.io.take_offer();
            assert_eq!(offered_ids(&offer).len(), 2);
            assert_eq!(h.io.resource_count(), 0);
        }

        /// The staging defect (2026-09-28): the budget was a fixed minute,
        /// started by the first check after the last one ended, so the
        /// sends at the end of one minute and the start of the next added
        /// up: 1200 left in 26 s against a budget of 600. It rolls now: the
        /// span ending at any moment holds at most the budget.
        #[test]
        fn no_60_second_span_carries_more_than_the_budget() {
            let h = Harness::new("sync_budget_rolls");
            h.node.lock().unwrap().outbound_sync_msgs_per_min = 10;
            // One peer, so the budget alone sizes each batch.
            let peer = [0x43u8; 16];
            h.add_peer(&peer, true);

            // A session that takes all the peer lacks, until the budget stops it.
            let session = || {
                h.start(&peer);
                h.link_active(&peer, &LINK_1);
                while h.io.offer_count() > 0 {
                    let (_, respond, _) = h.io.take_offer();
                    respond(msgpack(Value::Boolean(true)));
                    h.pump();
                    let (_, concluded) = h.io.take_resource();
                    concluded(complete());
                    h.pump();
                }
                assert_eq!(h.state(&peer), PropPeer::IDLE);
            };

            // t = 0: 4 go, all the peer lacks.
            h.store(4, 300);
            session();
            // t = 40: it lacks 20 more and gets the 6 that are left.
            test_clock::advance(40.0);
            h.store(20, 300);
            session();
            assert_eq!(h.node.lock().unwrap().outbound_allowance(), 0);
            // t = 60: the 4 have aged out, the 6 still count: 4 more.
            test_clock::advance(20.0);
            session();
            // t = 100: the 6 have aged out: 6 more.
            test_clock::advance(40.0);
            session();

            let sent: Vec<u64> = h.io.sent().iter().map(|(_, _, messages)| *messages).collect();
            assert_eq!(sent, vec![4, 6, 4, 6], "each batch gets what the last 60 s left over");
            assert_eq!(most_in_any_window(&h.io.sent()), 10, "no 60 s span carries more than the budget");
        }


        /// Run the network until nothing is pending: bring up every link
        /// being attempted, answer every offer "want all", conclude every
        /// Resource COMPLETE. Each step costs no simulated time.
        fn serve_everything(h: &Harness) {
            serve_answering(h, &|_| Value::Boolean(true));
        }

        /// `serve_everything`, answering each offer with `answer(offered ids)`.
        fn serve_answering(h: &Harness, answer: &dyn Fn(&[Vec<u8>]) -> Value) {
            loop {
                let attempting: Vec<Vec<u8>> = h.io.attempting.lock().unwrap().iter().cloned().collect();
                let mut progressed = !attempting.is_empty();
                for peer in attempting {
                    h.link_active(&peer, &[peer[0] ^ 0xFF; 16]);
                }
                while h.io.offer_count() > 0 {
                    let (offer, respond, _) = h.io.take_offer();
                    respond(msgpack(answer(&offered_ids(&offer))));
                    h.pump();
                    progressed = true;
                }
                while h.io.resource_count() > 0 {
                    let (_, concluded) = h.io.take_resource();
                    concluded(complete());
                    h.pump();
                    progressed = true;
                }
                if !progressed {
                    break;
                }
            }
        }

        /// Staging 2026-09-28: under the budget one session took the whole
        /// 600 (500, then 100 on its held link), one peer was served per
        /// ~73 s, and the fastest-peer pool chose the same fast peers again:
        /// 7 of 20 peers got nothing in 30 minutes. While the budget binds
        /// each batch is a fair share, a session yields its held link to
        /// waiting peers, and the tick chooses the least recently served, so
        /// with one session starting per tick (2.5 a minute) all 20 are
        /// served within ceil(20 / 2.5) = 8 minutes, the budget spent, never
        /// exceeded.
        #[test]
        fn every_ready_peer_gets_a_turn_while_the_budget_binds() {
            let h = Harness::new("sync_fair");
            let budget = h.node.lock().unwrap().outbound_sync_msgs_per_min;
            let peers: Vec<[u8; 16]> = (0..20u8).map(|i| [0x80 + i; 16]).collect();
            for (i, hash) in peers.iter().enumerate() {
                h.add_peer(hash, true);
                // Every speed known and each different: the reference's pool
                // is always the same two fastest.
                h.node.lock().unwrap().peers.get_mut(&hash[..]).unwrap().sync_transfer_rate = 1000.0 * (i + 1) as f64;
            }
            h.store(1000, 300);

            let sessions_per_minute = 60.0 / PEER_SYNC_INTERVAL_SECS;
            let minutes = (peers.len() as f64 / sessions_per_minute).ceil();
            let deadline = minutes * 60.0;
            let start = monotonic_now();
            // Simulated time in steps of a second, the tick choosing whenever
            // it is due, as the main loop calls it.
            while monotonic_now() - start < deadline {
                LxmfPropagationNode::tick_sync(&h.node);
                h.pump();
                serve_everything(&h);
                test_clock::advance(1.0);
            }

            let sent = h.io.sent();
            for peer in &peers {
                let first = sent.iter().find(|(_, to, _)| to == peer).map(|(at, _, _)| at - start);
                assert!(
                    first.is_some_and(|at| at <= deadline),
                    "peer {} first served at {first:?} s, not within {deadline} s", hexrep(peer, false),
                );
            }
            assert!(most_in_any_window(&sent) <= budget, "no 60 s span carries more than the budget");
            let largest = sent.iter().map(|(_, _, messages)| *messages).max().unwrap_or(0);
            assert!(largest < budget, "no single batch takes the whole budget (largest {largest})");
            // The share's floor: batches of one tick's worth keep the budget
            // spent. Equal shares of 30 would have served no one sooner and
            // sent an eighth of it.
            let total: u64 = sent.iter().map(|(_, _, messages)| messages).sum();
            assert!(
                total as f64 >= 0.75 * budget as f64 * minutes,
                "the budget is spent while it binds: {total} sent in {minutes} minutes",
            );
        }

        /// While the budget binds, the tick chooses the waiting peer whose
        /// last turn is oldest; while it does not, the reference's choice
        /// (random among the fastest) stands.
        #[test]
        fn the_least_recently_served_peer_is_chosen_only_while_the_budget_binds() {
            let h = Harness::new("sync_least_recent");
            let peers: Vec<([u8; 16], f64, f64)> = vec![
                ([0x51; 16], 9000.0, 300.0),
                ([0x52; 16], 5000.0, 200.0),
                ([0x53; 16], 100.0, 100.0),
                ([0x54; 16], 50.0, 400.0),
            ];
            for (hash, rate, last_turn) in &peers {
                h.add_peer(hash, true);
                let mut g = h.node.lock().unwrap();
                let peer = g.peers.get_mut(&hash[..]).unwrap();
                peer.sync_transfer_rate = *rate;
                peer.last_sync_attempt = now() - 1000.0 + *last_turn;
            }
            h.store(10, 300);

            let mut g = h.node.lock().unwrap();
            // 4 peers want 10 each; the budget of 600 does not bind: the two
            // fastest, as the reference.
            let chosen: HashSet<u8> = (0..8usize).map(|i| g.select_sync_peer(now(), &mut |n| i % n).unwrap()[0]).collect();
            assert_eq!(chosen, [0x51u8, 0x52].into_iter().collect());

            // 40 wanted, 30 left: it binds, and 0x53's turn is the oldest.
            g.outbound_sync_msgs_per_min = 30;
            for i in 0..8usize {
                assert_eq!(g.select_sync_peer(now(), &mut |n| i % n), Some(vec![0x53; 16]));
            }
        }

        /// The persistent strategy (next batch on the held link) stands while
        /// the budget does not bind. While it binds and other ready peers
        /// wait, a session's turn is its fair share of messages SENT: it
        /// takes its next batch on the held link until it has sent that,
        /// then ends and the next turn goes to them. (It used to end after
        /// its first batch however little that carried.)
        #[test]
        fn a_session_yields_its_link_once_its_share_is_sent_while_the_budget_binds() {
            let h = Harness::new("sync_yield");
            let a = [0x61u8; 16];
            let b = [0x62u8; 16];
            h.add_peer(&a, true);
            // No peering key yet: b cannot be chosen, so nothing binds.
            h.add_peer(&b, false);
            // A budget of 10: with a and b ready, a turn is fair_share(2) = 5.
            h.node.lock().unwrap().outbound_sync_msgs_per_min = 10;
            // One message per batch for a: 24 + 316 + 316 > 500 B.
            h.node.lock().unwrap().peers.get_mut(&a[..]).unwrap().propagation_sync_limit = Some(0.5);
            h.store(12, 300);
            let batch = || {
                let (offer, respond, _) = h.io.take_offer();
                assert_eq!(offered_ids(&offer).len(), 1);
                respond(msgpack(Value::Boolean(true)));
                h.pump();
                let (_, concluded) = h.io.take_resource();
                concluded(complete());
                h.pump();
            };

            h.start(&a);
            h.link_active(&a, &LINK_1);
            batch();
            batch();
            assert_eq!(h.state(&a), PropPeer::REQUEST_SENT, "persistent strategy: the next offer on the held link");
            assert_eq!(h.peer(&a, |p| p.turn_sent), 2);

            // b's key is ready: a and b want more than is left, it binds.
            h.node.lock().unwrap().peers.get_mut(&b[..]).unwrap().peering_key = Some((vec![0x5A; 32], 18));
            assert_eq!(h.node.lock().unwrap().fair_share(2), 5);
            batch();
            assert_eq!(h.state(&a), PropPeer::REQUEST_SENT, "3 of its share of 5 sent: a carries on on the held link");
            batch();
            assert_eq!(h.state(&a), PropPeer::REQUEST_SENT, "4 of 5 sent: a carries on");
            batch();
            assert_eq!(h.state(&a), PropPeer::IDLE, "its share sent, a yields");
            assert_eq!(h.io.offer_count(), 0);
            assert_eq!(h.io.sent().iter().map(|(_, _, m)| m).sum::<u64>(), 5, "a's turn: its share, in five batches");
            assert_eq!(h.unhandled(&a), 7, "what a still lacks waits for its next turn");
            assert_eq!(h.io.calls().last().unwrap(), "close 61", "the held link is released");
            assert_eq!(h.peer(&a, |p| p.turn_sent), 0, "the next session is a new turn");
        }

        /// Simulated time in steps of a second for `secs`, the tick choosing
        /// whenever it is due, as the main loop calls it, the network served
        /// as `serve_answering` does.
        fn run_for(h: &Harness, secs: f64, answer: &dyn Fn(&[Vec<u8>]) -> Value) {
            let start = monotonic_now();
            while monotonic_now() - start < secs {
                LxmfPropagationNode::tick_sync(&h.node);
                h.pump();
                serve_answering(h, answer);
                test_clock::advance(1.0);
            }
        }

        /// What each turn (a session, from its link attempt to its end) sent,
        /// in order: a session starts with an "open", and the i-th Resource
        /// handed over is `sent[i]`.
        fn turns(h: &Harness) -> Vec<u64> {
            let sent = h.io.sent();
            let mut resources = sent.iter();
            let mut running: HashMap<String, usize> = HashMap::new();
            let mut turns: Vec<u64> = Vec::new();
            for call in h.io.calls() {
                if let Some(peer) = call.strip_prefix("open ") {
                    running.insert(peer.to_string(), turns.len());
                    turns.push(0);
                } else if call.starts_with("resource ") {
                    let (_, to, messages) = resources.next().expect("a Resource for each call");
                    let index = *running.get(&hexrep(&to[..1], false)).expect("a Resource inside a session");
                    turns[index] += messages;
                }
            }
            turns
        }

        /// 20 peers, each lacking plenty, for 8 simulated minutes: the budget
        /// binds throughout. Past the startup backlog hold, as production is
        /// most of the time (the hold has its own tests).
        fn fair_run(tag: &str, count: usize, size: usize, answer: &dyn Fn(&[Vec<u8>]) -> Value) -> (Harness, f64) {
            let h = Harness::new(tag);
            h.node.lock().unwrap().started_at = now() - STARTUP_BACKLOG_HOLD_SECS - 1.0;
            for i in 0..20u8 {
                h.add_peer(&[0x80 + i; 16], true);
            }
            h.store(count, size);
            let minutes = 8.0;
            run_for(&h, minutes * 60.0, answer);
            (h, minutes)
        }

        /// Review of bcc38cb: the rotation covered alive peers only, and the
        /// reference chooses an unresponsive peer only when no alive peer
        /// waits — never, while the budget binds. One failed link attempt
        /// makes a peer unresponsive (backoff, then the next tick demotes
        /// it), and it got nothing until its next announce (lxmd: every
        /// 6 h). While the budget binds it now takes its turn in the same
        /// rotation once its backoff has run out: its last turn is the
        /// oldest, so it is chosen within a tick or two of that.
        #[test]
        fn an_unresponsive_peer_takes_its_turn_while_the_budget_binds() {
            let h = Harness::new("sync_fair_unresponsive");
            h.node.lock().unwrap().started_at = now() - STARTUP_BACKLOG_HOLD_SECS - 1.0;
            let budget = h.node.lock().unwrap().outbound_sync_msgs_per_min;
            let peers: Vec<[u8; 16]> = (0..20u8).map(|i| [0x80 + i; 16]).collect();
            for hash in &peers {
                h.add_peer(hash, true);
            }
            let x = [0x70u8; 16];
            h.add_peer(&x, true);
            h.store(3000, 300);

            // x's link attempt fails: it backs off, and the first tick finds
            // it in backoff and marks it unresponsive.
            h.start(&x);
            h.io.attempt_failed(&x);
            h.event(SyncEvent::LinkDown { peer: x.to_vec() });
            assert_eq!(h.state(&x), PropPeer::IDLE);
            let failed_at = monotonic_now();
            LxmfPropagationNode::tick_sync(&h.node);
            h.pump();
            assert!(!h.peer(&x, |p| p.alive), "one failed attempt: unresponsive");
            serve_everything(&h);
            test_clock::advance(1.0);

            // Its backoff, then as long again as the 21 contenders take to
            // go round once (2.5 turns a minute).
            let sessions_per_minute = 60.0 / PEER_SYNC_INTERVAL_SECS;
            let bound = SYNC_BACKOFF_STEP_SECS + ((peers.len() + 1) as f64 / sessions_per_minute).ceil() * 60.0;
            run_for(&h, bound, &|_| Value::Boolean(true));

            let sent = h.io.sent();
            let first = sent.iter().find(|(_, to, _)| to == &x).map(|(at, _, _)| at - failed_at);
            assert!(
                first.is_some_and(|at| at <= bound),
                "the unresponsive peer first served at {first:?} s, not within {bound} s",
            );
            assert!(h.peer(&x, |p| p.alive), "its link came up: alive again");
            assert!(most_in_any_window(&sent) <= budget, "no 60 s span carries more than the budget");
        }

        /// While the budget binds, an unresponsive peer past its backoff is a
        /// contender like an alive one: chosen when its turn is the oldest,
        /// though an alive peer waits, and counted in the share, so a
        /// running session yields to it once its share is sent.
        #[test]
        fn an_unresponsive_peer_past_its_backoff_contends_for_the_budget() {
            let h = Harness::new("sync_unresponsive_contends");
            h.node.lock().unwrap().started_at = now() - STARTUP_BACKLOG_HOLD_SECS - 1.0;
            let a = [0x91u8; 16];
            let x = [0x92u8; 16];
            h.add_peer(&a, true);
            h.add_peer(&x, true);
            {
                let mut g = h.node.lock().unwrap();
                let peer = g.peers.get_mut(&a[..]).unwrap();
                peer.last_sync_attempt = now() - 10.0;
                // x failed a link attempt 13 minutes ago; its 12-minute
                // backoff is over.
                let peer = g.peers.get_mut(&x[..]).unwrap();
                peer.alive = false;
                peer.sync_backoff = SYNC_BACKOFF_STEP_SECS;
                peer.last_sync_attempt = now() - 780.0;
                peer.next_sync_attempt = now() - 60.0;
            }
            h.store(2000, 300);

            // 500 + 500 wanted of 600: it binds, and x's turn is the oldest.
            {
                let mut g = h.node.lock().unwrap();
                for i in 0..4usize {
                    assert_eq!(g.select_sync_peer(now(), &mut |n| i % n), Some(x.to_vec()));
                }
                assert!(!g.peers[&x[..]].alive, "still unresponsive: chosen for its turn, not revived");
            }

            // a's session: with x contending, a's turn is fair_share(2) =
            // 300, not the 500 of a whole offer, and it yields once that is
            // sent.
            let share = h.node.lock().unwrap().fair_share(2);
            h.start(&a);
            h.link_active(&a, &LINK_1);
            let (offer, respond, _) = h.io.take_offer();
            assert_eq!(offered_ids(&offer).len() as u64, share, "the offer is cut to a's share");
            respond(msgpack(Value::Boolean(true)));
            h.pump();
            let (_, concluded) = h.io.take_resource();
            concluded(complete());
            h.pump();
            assert_eq!(h.state(&a), PropPeer::IDLE, "its share sent, a yields to x");
            assert_eq!(h.io.offer_count(), 0);
        }

        /// Review of bcc38cb: a turn was one batch, whatever that carried of
        /// the share. With messages of 20 KB a batch is ~52 (one ~1 MiB
        /// Resource), and 20 turns in 8 minutes sent 1040 of a budget of
        /// 4800. A turn is now the share sent, in as many batches on the held
        /// link as it takes: the budget is spent, never exceeded, and no turn
        /// sends more than its share.
        #[test]
        fn the_budget_is_spent_while_it_binds_when_batches_are_byte_limited() {
            let (h, minutes) = fair_run("sync_fair_bytes", 1000, 20_000, &|_| Value::Boolean(true));
            let (budget, share) = {
                let g = h.node.lock().unwrap();
                (g.outbound_sync_msgs_per_min, g.fair_share(20))
            };
            let sent = h.io.sent();
            let largest = sent.iter().map(|(_, _, messages)| *messages).max().unwrap_or(0);
            assert!(largest < 60, "a batch is limited by bytes, far under the share (largest {largest})");
            assert!(most_in_any_window(&sent) <= budget, "no 60 s span carries more than the budget");
            let most = turns(&h).into_iter().max().unwrap_or(0);
            assert!(most <= share, "no turn sends more than its share of {share} (most {most})");
            let total: u64 = sent.iter().map(|(_, _, messages)| messages).sum();
            assert!(
                total as f64 >= 0.75 * budget as f64 * minutes,
                "the budget is spent while it binds: {total} sent in {minutes} minutes",
            );
        }

        /// Review of bcc38cb: each peer already holds 9 in 10 of what it is
        /// offered (from other propagation nodes, normal in a mesh), so a
        /// turn of one batch sent a tenth of the share: 480 of a budget of
        /// 4800 in 8 minutes. The turn now carries on until the share is
        /// sent.
        #[test]
        fn the_budget_is_spent_while_it_binds_when_peers_want_part_of_each_offer() {
            let one_in_ten = |offered: &[Vec<u8>]| {
                Value::Array(
                    offered.iter().filter(|id| id[0] % 10 == 0).map(|id| Value::Binary(id.clone())).collect(),
                )
            };
            let (h, minutes) = fair_run("sync_fair_partial", 3000, 300, &one_in_ten);
            let budget = h.node.lock().unwrap().outbound_sync_msgs_per_min;
            let sent = h.io.sent();
            assert!(most_in_any_window(&sent) <= budget, "no 60 s span carries more than the budget");
            let total: u64 = sent.iter().map(|(_, _, messages)| messages).sum();
            assert!(
                total as f64 >= 0.75 * budget as f64 * minutes,
                "the budget is spent while it binds: {total} sent in {minutes} minutes",
            );
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

        /// LXMPeer.sync: each link attempt adds SYNC_BACKOFF_STEP_SECS to the
        /// peer's backoff; a failed attempt ends the session with every id
        /// unhandled, and the peer is not chosen again until the backoff has
        /// run out (it is marked unresponsive when found in it); an
        /// established link clears it. Without the backoff an unreachable
        /// peer is chosen again at every tick, crowding out the rest.
        #[test]
        fn a_failed_link_attempt_backs_the_peer_off_until_a_link_is_established() {
            let h = Harness::new("sync_backoff");
            let peer = [0x1Cu8; 16];
            h.add_peer(&peer, true);
            h.store(2, 300);

            let t0 = now();
            h.start(&peer);
            assert_eq!(h.state(&peer), PropPeer::LINK_ESTABLISHING);
            let (backoff, next) = h.peer(&peer, |p| (p.sync_backoff, p.next_sync_attempt));
            assert_eq!(backoff, SYNC_BACKOFF_STEP_SECS);
            assert!((next - t0 - SYNC_BACKOFF_STEP_SECS).abs() < 5.0, "the next attempt waits out the backoff");

            // The attempt fails: AppLinks reports the destination down with
            // no attempt left in flight.
            h.io.attempt_failed(&peer);
            h.event(SyncEvent::LinkDown { peer: peer.to_vec() });
            assert_eq!(h.state(&peer), PropPeer::IDLE);
            assert_eq!(h.io.calls(), vec!["open 1c", "close 1c"]);
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (2, 0), "a failed attempt hands nothing");

            {
                let mut g = h.node.lock().unwrap();
                assert_eq!(g.select_sync_peer(now(), &mut |_| 0), None, "not chosen during the backoff");
                assert!(!g.peers[&peer[..]].alive, "and marked unresponsive for it");
                assert_eq!(g.select_sync_peer(next + 1.0, &mut |_| 0), Some(peer.to_vec()), "chosen once it has run out");
                // Time passes: the backoff is over.
                g.peers.get_mut(&peer[..]).unwrap().next_sync_attempt = now() - 1.0;
            }

            // A second attempt: the backoff grows by another step.
            h.start(&peer);
            assert_eq!(h.peer(&peer, |p| p.sync_backoff), 2.0 * SYNC_BACKOFF_STEP_SECS);

            // The link comes up: backoff and next attempt cleared, alive again.
            h.link_active(&peer, &LINK_1);
            assert_eq!(h.state(&peer), PropPeer::REQUEST_SENT);
            assert_eq!(h.peer(&peer, |p| (p.sync_backoff, p.next_sync_attempt, p.alive)), (0.0, 0.0, true));
        }

        /// Every answer to an offer ends the session as LXMPeer.offer_response
        /// and SPEC §10 say, and releases the link: 0xF1 unpeers (the one
        /// answer that discards a peer's queues), 0xF3 discards the key, 0xF6
        /// holds the peer without demoting it, `false` hands every offered
        /// id, and any other code, nil, no data or bytes that are not msgpack
        /// leave every id unhandled.
        #[test]
        fn every_offer_answer_ends_the_session_as_the_reference_does() {
            #[derive(Debug)]
            enum Ends { Unpeered, KeyDiscarded, Throttled, AllUnhandled, AllHandled }
            let code = |c: u8| msgpack(Value::Integer((c as i64).into()));
            let cases: Vec<(&str, Option<Vec<u8>>, Ends)> = vec![
                ("0xF1 no access", code(ERROR_NO_ACCESS), Ends::Unpeered),
                ("0xF3 invalid key", code(ERROR_INVALID_KEY), Ends::KeyDiscarded),
                ("0xF6 throttled", code(ERROR_THROTTLED), Ends::Throttled),
                ("0xF4, another error", code(0xF4), Ends::AllUnhandled),
                ("nil", msgpack(Value::Nil), Ends::AllUnhandled),
                ("no response data", None, Ends::AllUnhandled),
                ("not msgpack", Some(vec![0xC1]), Ends::AllUnhandled),
                ("false", msgpack(Value::Boolean(false)), Ends::AllHandled),
            ];
            for (i, (answer, response, ends)) in cases.into_iter().enumerate() {
                let h = Harness::new(&format!("sync_answer_{i}"));
                let peer = [0x60 + i as u8; 16];
                h.add_peer(&peer, true);
                h.store(2, 300);
                h.start(&peer);
                h.link_active(&peer, &LINK_1);
                let (_, respond, _) = h.io.take_offer();
                respond(response);
                h.pump();
                assert_eq!(h.io.calls().last().unwrap(), &format!("close {:02x}", peer[0]), "{answer}: the link is released");
                if let Ends::Unpeered = ends {
                    assert!(!h.node.lock().unwrap().peers.contains_key(&peer[..]), "{answer}: unpeered");
                    continue;
                }
                assert_eq!(h.state(&peer), PropPeer::IDLE, "{answer}");
                let (key, throttled_until, alive) = h.peer(&peer, |p| (p.peering_key.is_some(), p.throttled_until, p.alive));
                let counts = (h.unhandled(&peer), h.handled(&peer));
                match ends {
                    Ends::KeyDiscarded => assert_eq!((key, counts), (false, (2, 0)), "{answer}"),
                    Ends::Throttled => {
                        assert!(throttled_until > now() + PN_STAMP_THROTTLE_SECS - 5.0, "{answer}: held");
                        assert_eq!((key, alive, counts), (true, true, (2, 0)), "{answer}");
                    }
                    Ends::AllUnhandled => assert_eq!((key, throttled_until, counts), (true, 0.0, (2, 0)), "{answer}"),
                    Ends::AllHandled => assert_eq!(counts, (0, 2), "{answer}"),
                    Ends::Unpeered => unreachable!(),
                }
            }
        }

        /// A callback of an ended session is recognised by its session number
        /// and ignored. A stale COMPLETE applied to the next session would
        /// hand that session's in-flight ids before their own Resource
        /// concludes — the handled-before-delivered loss this sync exists to
        /// prevent; a stale response or failure would drive or end a session
        /// it does not belong to.
        #[test]
        fn callbacks_of_an_ended_session_cannot_touch_the_next_one() {
            let h = Harness::new("sync_stale_callbacks");
            let peer = [0x1Eu8; 16];
            h.add_peer(&peer, true);
            h.store(2, 300);
            let lose_link = || {
                h.io.link_gone(&peer);
                h.event(SyncEvent::LinkDown { peer: peer.to_vec() });
                assert_eq!(h.state(&peer), PropPeer::IDLE);
            };

            // Session 1 loses its link with its offer unanswered.
            h.start(&peer);
            h.link_active(&peer, &LINK_1);
            let (_, old_respond, _) = h.io.take_offer();
            lose_link();

            // Session 2 has offered; session 1's response arrives now.
            h.start(&peer);
            h.link_active(&peer, &LINK_2);
            old_respond(msgpack(Value::Boolean(true)));
            h.pump();
            assert_eq!(h.state(&peer), PropPeer::REQUEST_SENT, "a stale response is ignored");
            assert_eq!(h.io.resource_count(), 0, "and sends nothing");

            // Session 2's Resource is in flight when its link goes.
            let (_, respond, _) = h.io.take_offer();
            respond(msgpack(Value::Boolean(true)));
            h.pump();
            let (_, old_concluded) = h.io.take_resource();
            lose_link();

            // Session 3's Resource is in flight; session 2's concludes now.
            h.start(&peer);
            h.link_active(&peer, &LINK_1);
            let (_, respond, _) = h.io.take_offer();
            respond(msgpack(Value::Boolean(true)));
            h.pump();
            let (_, concluded) = h.io.take_resource();
            old_concluded(complete());
            h.pump();
            assert_eq!(h.state(&peer), PropPeer::RESOURCE_TRANSFERRING, "a stale COMPLETE is ignored");
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (2, 0), "and hands nothing");
            old_concluded(failed());
            h.pump();
            assert_eq!(h.state(&peer), PropPeer::RESOURCE_TRANSFERRING, "a stale failure does not end it");

            concluded(complete());
            h.pump();
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (0, 2), "its own COMPLETE hands them");
        }

        /// AppLinks reports DISCONNECTED for any link to the destination,
        /// a previous session's included, and a report can arrive after the
        /// state it described has moved on. One that does not describe the
        /// running session's own attempt or link is ignored.
        #[test]
        fn a_stale_link_down_report_leaves_the_running_session_alone() {
            let h = Harness::new("sync_stale_link_down");
            let peer = [0x1Du8; 16];
            h.add_peer(&peer, true);
            // One message per batch, so a COMPLETE carries on.
            h.node.lock().unwrap().peers.get_mut(&peer[..]).unwrap().propagation_sync_limit = Some(0.5);
            h.store(2, 300);
            let link_down = || h.event(SyncEvent::LinkDown { peer: peer.to_vec() });

            // While the attempt is in flight.
            h.start(&peer);
            link_down();
            assert_eq!(h.state(&peer), PropPeer::LINK_ESTABLISHING, "the attempt is still live");
            assert_eq!(h.io.calls(), vec!["open 1d"]);

            // While the session's own link is up: REQUEST_SENT, then
            // RESOURCE_TRANSFERRING.
            h.link_active(&peer, &LINK_1);
            link_down();
            assert_eq!(h.state(&peer), PropPeer::REQUEST_SENT);
            let (_, respond, _) = h.io.take_offer();
            respond(msgpack(Value::Boolean(true)));
            h.pump();
            link_down();
            assert_eq!(h.state(&peer), PropPeer::RESOURCE_TRANSFERRING);
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (2, 0));
            assert!(!h.io.calls().contains(&"close 1d".to_string()), "nothing closed");

            // The link goes before the COMPLETE is handled: the next batch
            // opens a new link, and the old link's report, arriving now,
            // leaves that attempt alone.
            let (_, concluded) = h.io.take_resource();
            h.io.link_gone(&peer);
            concluded(complete());
            h.pump();
            assert_eq!(h.state(&peer), PropPeer::LINK_ESTABLISHING);
            assert_eq!(h.io.calls()[4..], ["close 1d", "open 1d"]);
            link_down();
            assert_eq!(h.state(&peer), PropPeer::LINK_ESTABLISHING, "the new attempt survives the old link's report");
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (1, 1));
        }

        /// A message whose file is gone from disk leaves the store and every
        /// peer's queue. Left unhandled, it was offered again — a link, an
        /// identify, an offer and a response for nothing — to every peer
        /// lacking it, every time it was chosen, until the message expired.
        #[test]
        fn a_message_whose_file_is_gone_leaves_the_store() {
            let h = Harness::new("sync_file_gone");
            let peer = [0x1Au8; 16];
            let other = [0x1Bu8; 16];
            h.add_peer(&peer, true);
            h.add_peer(&other, true);
            let ids = h.store(2, 300);
            let path_of = |tid: &Vec<u8>| h.node.lock().unwrap().entries[tid].filepath.clone();

            // One of two wanted files is gone: the other is sent.
            h.start(&peer);
            h.link_active(&peer, &LINK_1);
            let (_, respond, _) = h.io.take_offer();
            fs::remove_file(path_of(&ids[0])).expect("remove the file");
            respond(msgpack(Value::Boolean(true)));
            h.pump();
            let (payload, concluded) = h.io.take_resource();
            assert_eq!(decode_propagation_batch(&payload).unwrap().messages.len(), 1, "the readable one is sent");
            assert!(!h.node.lock().unwrap().entries.contains_key(&ids[0]), "the one without a file leaves the store");
            assert!(!h.peer(&other, |p| p.unhandled_ids.contains(&ids[0])), "and every peer's queue");
            concluded(complete());
            h.pump();
            assert_eq!((h.unhandled(&peer), h.handled(&peer)), (0, 1));
            assert_eq!(h.state(&peer), PropPeer::IDLE, "nothing is left for it");

            // The only file wanted is gone: the session ends with nothing left.
            h.start(&other);
            h.link_active(&other, &LINK_2);
            let (offer, respond, _) = h.io.take_offer();
            assert_eq!(offered_ids(&offer), vec![ids[1].clone()]);
            fs::remove_file(path_of(&ids[1])).expect("remove the file");
            respond(msgpack(Value::Boolean(true)));
            h.pump();
            assert_eq!(h.io.resource_count(), 0);
            assert_eq!(h.state(&other), PropPeer::IDLE);
            assert_eq!(h.unhandled(&other), 0, "not offered again");
            assert_eq!(h.node.lock().unwrap().select_sync_peer(now(), &mut |_| 0), None);
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
            // The closed link's own report, still queued, comes now: stale.
            h.event(SyncEvent::LinkActive { peer: peer.to_vec(), link_id: LINK_1.to_vec() });
            assert_eq!(h.state(&peer), PropPeer::LINK_ESTABLISHING, "a link AppLinks no longer holds is not taken up");
            assert_eq!(h.io.calls().len(), 3);

            // A second link comes up while the session runs on the first. It
            // replaced the session's link in AppLinks, and closing it drops
            // the registration: AppLinks would report the loss of neither, so
            // the session ends rather than run on unreported, ids unhandled;
            // the first link's late response is then stale.
            h.link_active(&peer, &LINK_1);
            assert_eq!(h.state(&peer), PropPeer::REQUEST_SENT);
            let (_, respond, _) = h.io.take_offer();
            h.event(SyncEvent::LinkActive { peer: peer.to_vec(), link_id: LINK_2.to_vec() });
            assert_eq!(h.state(&peer), PropPeer::REQUEST_SENT, "a stale report does not end the session");
            h.link_active(&peer, &LINK_2);
            assert_eq!(h.io.calls()[3..], ["identify a1", "offer a1", "close 17"]);
            assert_eq!(h.state(&peer), PropPeer::IDLE);
            respond(msgpack(Value::Boolean(true)));
            h.pump();
            assert_eq!(h.state(&peer), PropPeer::IDLE);
            assert_eq!((h.io.resource_count(), h.unhandled(&peer), h.handled(&peer)), (0, 2, 0));

            // A link comes up for a destination that is no longer a peer (it
            // was unpeered while the attempt was in flight): closed, too.
            let gone = [0x18u8; 16];
            h.link_active(&gone, &LINK_2);
            assert_eq!(h.io.calls().last().unwrap(), "close 18");
            assert!(h.io.active_link(&gone).is_none());
        }

        /// A response that comes long after the offer is still delivered and
        /// concludes the session, in every build. The callback once asserted
        /// DESIGN_PRINCIPLES §1 first, and in a debug build the panic lost the
        /// response: the peer stayed REQUEST_SENT for good and its offer kept
        /// its reservation of the minute's budget. The round trip is the
        /// remote peer's time, so it carries no assertion (James, 2026-09-29).
        #[test]
        fn a_late_offer_response_is_forwarded_and_concludes_the_session() {
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
            assert!(outcome.is_ok(), "a late answer does not panic in any build");
            h.pump();
            assert_eq!(h.state(&peer), PropPeer::IDLE, "the late response concluded the session");
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

        /// The sender of a sync Resource is the identity recorded when it
        /// advertised, while its link was up. rfed asked the link when the
        /// Resource concluded, after Reticulum-rust had sent the proof on
        /// which the sender tears the link down; when that LINKCLOSE won, the
        /// ask came back LinkGone and the batch went in as a client's, queued
        /// straight back to the peer that sent it, with no log line.
        #[test]
        fn a_peer_batch_stays_its_own_after_the_sender_closes_the_link() {
            use reticulum_rust::resource::{AutoCompressOption, Resource, ResourceAdvertisement, ResourceStatus};

            let h = Harness::new("sync_from_peer_link_gone");
            {
                // Any stamp meets cost 0; the test is about who gets what.
                let mut g = h.node.lock().unwrap();
                g.stamp_cost = 0;
                g.stamp_flexibility = 0;
            }
            let sender_identity = Identity::new(true);
            let sender = Destination::hash_from_name_and_identity("lxmf.propagation", Some(&sender_identity));
            let other = [0x73u8; 16];
            h.add_peer(&sender, true);
            h.add_peer(&other, true);

            // rfed's end of the sender's link, which the sender identified on
            // (LXMPeer.link_established identifies before it offers).
            let owner = Destination::new_inbound(
                Some(Identity::new(true)), DestinationType::Single, "lxmf".into(), vec!["propagation".into()],
            ).expect("destination");
            let mut link = Link::new_inbound(owner).expect("link");
            link.state = reticulum_rust::link::STATE_ACTIVE;
            link.status = reticulum_rust::link::STATE_ACTIVE;
            *link.remote_identity.lock().unwrap() = Some(sender_identity.clone());
            let link = LinkHandle::spawn(link);

            // The callbacks link_established installs on that link.
            let (weak, sync_limit_kb) = {
                let g = h.node.lock().unwrap();
                (g.self_handle.clone(), g.announced_limits_kb().1)
            };
            let (advertised, concluded) = LxmfPropagationNode::inbound_resource_callbacks(weak, sync_limit_kb);

            // The sender advertises its batch; rfed accepts it.
            let advertisement = ResourceAdvertisement {
                t: 0, d: 0, n: 0, h: vec![0xAD; 32], r: vec![0; 4], o: vec![0xAD; 32], i: 1, l: 1,
                q: None, f: 0, m: Vec::new(), e: true, c: false, s: false, u: false, p: false, x: false,
                link: Some(link.clone()),
            };
            assert!(advertised(&advertisement), "a propagation Resource within the limit is accepted");

            // The proof has gone out and the sender has closed the link: its
            // actor is gone before the concluded callback runs.
            link.teardown();
            assert!(link.remote_identity().is_err(), "the link can no longer be asked");

            let mut lxmf = vec![0x7Au8; 300 - lx_stamper::STAMP_SIZE];
            lxmf[..16].copy_from_slice(&[0x5E; 16]);
            let id = reticulum_rust::identity::full_hash(&lxmf);
            let batch = encode_value(Value::Array(vec![
                Value::F64(0.0),
                Value::Array(vec![Value::Binary([lxmf, vec![0x33u8; lx_stamper::STAMP_SIZE]].concat())]),
            ]));
            let mut resource = Resource::new_internal(
                None, link, None, false, AutoCompressOption::Disabled, None, None, None, 1, None, None, false, 0, None,
            ).expect("resource");
            resource.status = ResourceStatus::Complete;
            resource.data = Some(batch);
            concluded(Arc::new(Mutex::new(resource)));

            assert!(h.node.lock().unwrap().entries.contains_key(&id), "the batch is stored");
            h.peer(&sender, |p| {
                assert!(!p.unhandled_ids.contains(&id), "not queued back to the peer that sent it");
                assert!(p.handled_ids.contains(&id), "handled for it");
            });
            h.peer(&other, |p| assert!(p.unhandled_ids.contains(&id), "queued for the other peer"));
        }

        /// LXMF 1.1.1 LXMRouter.propagation_resource_advertised: a propagation
        /// Resource whose data is larger than the per-sync limit we announce
        /// (KB of 1000 B) is refused at its advertisement. Since 929a079 rfed
        /// announces its real limits (10240 KB unset; ~1 GB with the old
        /// NAS template), and nothing held a sender to them.
        #[test]
        fn a_propagation_resource_over_our_announced_sync_limit_is_refused() {
            use reticulum_rust::resource::ResourceAdvertisement;
            let advertisement = |size: u64| ResourceAdvertisement {
                t: size, d: size, n: 1, h: vec![0xAD; 32], r: vec![0; 4], o: vec![0xAD; 32], i: 1, l: 1,
                q: None, f: 0, m: Vec::new(), e: true, c: false, s: false, u: false, p: false, x: false,
                link: None,
            };
            for (tag, sync_limit_bytes) in [("limit_default", None), ("limit_configured", Some(3 * 1024 * 1024))] {
                let h = Harness::new(tag);
                let (weak, announced_kb) = {
                    let mut g = h.node.lock().unwrap();
                    if let Some(bytes) = sync_limit_bytes {
                        g.sync_limit_kb = propagation_limits_kb(None, Some(bytes)).1;
                    }
                    let announced = match read_value(&mut Cursor::new(&g.build_app_data())).expect("announce") {
                        Value::Array(items) => items[4].as_i64().expect("sync limit"),
                        other => panic!("announce not an array: {other:?}"),
                    };
                    (g.self_handle.clone(), announced)
                };
                assert_eq!(announced_kb, h.node.lock().unwrap().announced_limits_kb().1);
                let (advertised, _) = LxmfPropagationNode::inbound_resource_callbacks(weak, announced_kb);
                let limit = announced_kb as u64 * 1000;
                assert!(advertised(&advertisement(limit)), "{tag}: exactly the announced limit is accepted");
                assert!(!advertised(&advertisement(limit + 1)), "{tag}: one byte over it is refused");
                assert!(advertised(&advertisement(300)), "{tag}: a small batch is accepted");
            }
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

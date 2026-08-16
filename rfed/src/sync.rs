//! Inter-node manifest/gap-pull sync.
//!
//! Protocol (mirrors LXMF propagation node):
//!
//!   1. Node A connects to Node B's rfed.node destination via a Link.
//!   2. A sends an OFFER request with the set of message IDs it holds for
//!      channels where B also has local subscribers.
//!   3. B replies with the subset it hasn't seen yet (the "gap").
//!   4. A fetches those blobs via MESSAGE_GET requests.
//!
//! Only inner blobs are synced — never outer envelopes, push registrations,
//! or subscription tables.
//!
//! A node syncs a channel only when it has at least one local subscriber
//! for that channel.  This prevents unbounded storage growth on relay nodes.
//!
//! ## Topology note
//!
//! This filter is safe even when node B sits between nodes A and C at the RF
//! layer.  Reticulum's transport handles routing transparently: once A's
//! announce has propagated, C can open a Link directly to A and Reticulum
//! will route the packets through B at the network level — B does not need
//! to be a federation-aware relay or store blobs on C's behalf.  The only
//! scenario where this would break down is if C is completely unable to form
//! a path to A and must rely on B as a store-and-forward federation hop.
//! That case would require an explicit "relay" role (a node that stores blobs
//! for channels it has no local subscribers for) and is not currently in scope.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use reticulum_rust::{log, hexrep, LOG_NOTICE, LOG_WARNING};

#[allow(unused_imports)]  // re-exported for use by destinations.rs
pub use reticulum_rust::transport::Transport;

use crate::blob_store::BlobStore;
use crate::distro::DistroTable;
use crate::subscription::SubscriptionTable;

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Public alias so callers outside this module can get the current time in
/// the same units used by `FedPeer` timing fields.
pub fn now_secs() -> f64 { now() }

// ── Request paths on rfed.node ───────────────────────────────────────────────

/// Offer: client sends IDs it has; server replies with the subset it wants.
pub const OFFER_PATH: &str = "/rfed/offer";
/// Fetch: client requests specific blobs by ID.
pub const MESSAGE_GET_PATH: &str = "/rfed/get";
/// Backup subscribe: owner node registers subscriber backup entries on this node.
pub const BACKUP_PUSH_PATH: &str = "/rfed/backup/push";

// ── Constants mirroring LXMF propagation node ───────────────────────────────

const SYNC_BACKOFF_MIN: f64 = 10.0;
const SYNC_BACKOFF_MAX: f64 = 3600.0;

// ── FedPeer ──────────────────────────────────────────────────────────────────

/// State maintained for a known rfed peer node.
#[derive(Clone, Serialize, Deserialize)]
pub struct FedPeer {
    /// 16-byte truncated destination hash of the peer's rfed.node destination
    pub destination_hash: Vec<u8>,
    pub alive: bool,
    pub last_heard: f64,
    /// Unix timestamp of the next allowed sync attempt
    pub next_sync_attempt: f64,
    pub last_sync_attempt: f64,
    pub sync_backoff: f64,
    /// PoW cost the peer advertises (from announce app_data)
    pub peering_cost: Option<u32>,
    pub transfer_limit: Option<f64>,
    pub sync_limit: Option<f64>,
}

impl FedPeer {
    pub fn new(destination_hash: Vec<u8>) -> Self {
        FedPeer {
            destination_hash,
            alive: false,
            last_heard: 0.0,
            next_sync_attempt: 0.0,
            last_sync_attempt: 0.0,
            sync_backoff: SYNC_BACKOFF_MIN,
            peering_cost: None,
            transfer_limit: None,
            sync_limit: None,
        }
    }

    pub fn heard(&mut self, peering_cost: Option<u32>) {
        self.alive = true;
        self.last_heard = now();
        if peering_cost.is_some() {
            self.peering_cost = peering_cost;
        }
        // Reset backoff on heard
        self.sync_backoff = SYNC_BACKOFF_MIN;
        if self.next_sync_attempt > now() + self.sync_backoff {
            self.next_sync_attempt = now() + 5.0;
        }
    }

    pub fn sync_failed(&mut self) {
        self.sync_backoff = (self.sync_backoff * 2.0).min(SYNC_BACKOFF_MAX);
        self.last_sync_attempt = now();
        self.next_sync_attempt = now() + self.sync_backoff;
    }

    pub fn sync_succeeded(&mut self) {
        self.sync_backoff = SYNC_BACKOFF_MIN;
        self.last_sync_attempt = now();
        self.next_sync_attempt = now() + self.sync_backoff;
    }
}

// ── FedSync ──────────────────────────────────────────────────────────────────

/// Manifest-based sync engine for the federation node.
pub struct FedSync {
    /// Known peers, keyed by their 16-byte destination hash
    pub peers: HashMap<Vec<u8>, FedPeer>,
    pub blob_store: Arc<Mutex<BlobStore>>,
    pub subscription_table: Arc<Mutex<SubscriptionTable>>,
    /// Distro device registry — per-node, never synced.
    /// Checked during manifest filtering and post-ingest fanout dispatch.
    pub distro_table: Arc<Mutex<DistroTable>>,
    pub max_peering_cost: u32,
    pub transfer_limit_bytes: Option<f64>,
    pub sync_limit_bytes: Option<f64>,
    /// Local node's rfed.node destination hash. Used to ignore self-announces.
    pub local_node_hash: Option<Vec<u8>>,
    pub from_static_only: bool,
    pub static_peers: Vec<Vec<u8>>,
    /// Where to persist peer sync state across restarts.
    pub peer_state_file: Option<PathBuf>,
    /// Rolling counter: bytes sent to all peers in the current period.
    sync_bytes_sent: u64,
    /// Start time of the current sync-limit accounting period.
    sync_period_start: f64,
}

impl FedSync {
    pub fn new(
        blob_store: Arc<Mutex<BlobStore>>,
        subscription_table: Arc<Mutex<SubscriptionTable>>,
        distro_table: Arc<Mutex<DistroTable>>,
    ) -> Self {
        FedSync {
            peers: HashMap::new(),
            blob_store,
            subscription_table,
            distro_table,
            max_peering_cost: 26,
            transfer_limit_bytes: None,
            sync_limit_bytes: None,
            local_node_hash: None,
            from_static_only: false,
            static_peers: Vec::new(),
            peer_state_file: None,
            sync_bytes_sent: 0,
            sync_period_start: now(),
        }
    }

    /// Set the local node destination hash so self-announces can be ignored.
    pub fn set_local_node_hash(&mut self, hash: Vec<u8>) {
        self.local_node_hash = Some(hash);
    }

    /// Called by the rfed.node announce handler when a peer is seen.
    pub fn peer_heard(&mut self, dest_hash: Vec<u8>, peering_cost: Option<u32>) {
        if self.local_node_hash.as_ref().is_some_and(|h| h == &dest_hash) {
            log(
                format!("[sync] ignoring self announce: {}", hexrep(&dest_hash, false)),
                LOG_NOTICE,
                false,
                false,
            );
            return;
        }
        if self.from_static_only && !self.static_peers.iter().any(|p| p == &dest_hash) {
            return;
        }
        let peer = self.peers.entry(dest_hash.clone()).or_insert_with(|| {
            log(
                format!("[sync] new peer: {}", hexrep(&dest_hash, false)),
                LOG_NOTICE,
                false,
                false,
            );
            FedPeer::new(dest_hash)
        });
        peer.heard(peering_cost);
    }

    /// Called from the main event loop to trigger pending sync sessions.
    ///
    /// Actual link establishment and request/response is async; this method
    /// only selects peers that are due for a sync attempt.  The caller is
    /// responsible for spawning the connection.
    pub fn tick(&mut self) -> Vec<Vec<u8>> {
        let t = now();

        // Prune peers not heard from in 2× max backoff (2 hours).
        let stale_cutoff = t - SYNC_BACKOFF_MAX * 2.0;
        let before = self.peers.len();
        self.peers.retain(|_, p| {
            // Always keep static peers.
            if self.static_peers.iter().any(|s| s == &p.destination_hash) {
                return true;
            }
            p.last_heard >= stale_cutoff
        });
        let pruned = before - self.peers.len();
        if pruned > 0 {
            log(
                format!("[sync] pruned {pruned} stale peer(s)"),
                LOG_NOTICE, false, false,
            );
        }

        self.peers
            .values()
            .filter(|p| p.alive && p.next_sync_attempt <= t)
            .map(|p| p.destination_hash.clone())
            .collect()
    }

    /// Seed static peers as immediately-due sync targets.
    ///
    /// Called once at startup (from `destinations::enable`).  Static peers don't
    /// need to announce before we attempt to sync with them — we already know
    /// their destination hash from config.
    pub fn seed_static_peers(&mut self) {
        for hash in self.static_peers.clone() {
            let peer = self.peers.entry(hash.clone()).or_insert_with(|| {
                log(
                    format!("[sync] seeding static peer {}", hexrep(&hash, false)),
                    LOG_NOTICE, false, false,
                );
                FedPeer::new(hash)
            });
            peer.alive = true;
            // Always reset to 0.0 so sync fires immediately on startup,
            // even if an old backoff from a previous run was loaded from disk.
            peer.next_sync_attempt = 0.0;
            peer.sync_backoff = SYNC_BACKOFF_MIN;
        }
    }

    /// Persist peer state to disk so backoff and timing survive restarts.
    pub fn save_peers(&self) {
        let path = match &self.peer_state_file {
            Some(p) => p,
            None => return,
        };
        let peers: Vec<&FedPeer> = self.peers.values().collect();
        match rmp_serde::to_vec(&peers) {
            Ok(bytes) => {
                if let Err(e) = std::fs::write(path, &bytes) {
                    log(format!("[sync] failed to save peer state: {e}"),
                        LOG_WARNING, false, false);
                }
            }
            Err(e) => log(format!("[sync] peer state encode error: {e}"),
                LOG_WARNING, false, false),
        }
    }

    /// Load peer state from disk (called once at startup).
    pub fn load_peers(&mut self) {
        let path = match &self.peer_state_file {
            Some(p) => p.clone(),
            None => return,
        };
        if !path.exists() {
            return;
        }
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                log(format!("[sync] failed to read peer state: {e}"),
                    LOG_WARNING, false, false);
                return;
            }
        };
        match rmp_serde::from_slice::<Vec<FedPeer>>(&bytes) {
            Ok(peers) => {
                for p in peers {
                    // Skip self-entry that may have been persisted before the
                    // self-announce guard was introduced.
                    if self.local_node_hash.as_ref().is_some_and(|h| h == &p.destination_hash) {
                        log(format!("[sync] skipping self-entry in loaded peer state: {}",
                                hexrep(&p.destination_hash, false)),
                            LOG_NOTICE, false, false);
                        continue;
                    }
                    self.peers.entry(p.destination_hash.clone())
                        .or_insert(p);
                }
                log(format!("[sync] loaded {} peer(s) from disk", self.peers.len()),
                    LOG_NOTICE, false, false);
            }
            Err(e) => log(format!("[sync] peer state decode error: {e}"),
                LOG_WARNING, false, false),
        }
    }

    // ── Inbound request handlers (called from rfed.node request handlers) ────

    /// Returns `(channel_hash, message_id)` pairs for all blobs this node
    /// holds for channels that have at least one local subscriber, AND blobs
    /// for distro hashes that have at least one registered device.
    ///
    /// Including the routing hash lets the *requesting* peer filter out entries
    /// it doesn't care about (no local subs for that channel, no devices for
    /// that distro).
    pub fn local_manifest(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let store = self.blob_store.lock().unwrap();
        let subs  = self.subscription_table.lock().unwrap();
        let distro = self.distro_table.lock().unwrap();
        let local_channels: HashSet<Vec<u8>> =
            subs.subscribed_channel_hashes().into_iter().collect();
        let local_distros: HashSet<Vec<u8>> =
            distro.registered_distro_hashes();
        if local_channels.is_empty() && local_distros.is_empty() {
            // No local subscribers or distro devices yet — don't advertise anything.
            return Vec::new();
        }
        store
            .index
            .values()
            .filter(|m| {
                local_channels.contains(&m.destination_hash)
                    || local_distros.contains(&m.destination_hash)
            })
            .map(|m| (m.destination_hash.clone(), m.message_id.clone()))
            .collect()
    }

    /// OFFER server-side handler.
    ///
    /// The calling peer sends `offered_ids` (its local manifest IDs).  We
    /// return our *full* store manifest as `(channel_hash, message_id)` pairs
    /// so the caller can filter to only the channels it subscribes to via
    /// `gap_from_peer`.  We do NOT filter by our own local subscribers here —
    /// a peer may want blobs for channels that have no local subscribers on us.
    ///
    /// `offered_ids` is accepted but unused for now (future: rate limiting).
    pub fn handle_offer(&self, offered_ids: Vec<Vec<u8>>) -> Vec<(Vec<u8>, Vec<u8>)> {
        let _ = offered_ids;
        let store = self.blob_store.lock().unwrap();
        store
            .index
            .values()
            .map(|m| (m.destination_hash.clone(), m.message_id.clone()))
            .collect()
    }

    /// Compute the message IDs we should pull from a peer.
    ///
    /// Given the peer's manifest as `(routing_hash, message_id)` pairs, returns
    /// the IDs to request: blobs for channels we subscribe to OR distros we have
    /// devices for, that we don't already hold.
    pub fn gap_from_peer(&self, peer_pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<Vec<u8>> {
        let store = self.blob_store.lock().unwrap();
        let subs  = self.subscription_table.lock().unwrap();
        let distro = self.distro_table.lock().unwrap();
        let our_ids: HashSet<Vec<u8>> =
            store.index.keys().cloned().collect();
        let subscribed: HashSet<Vec<u8>> =
            subs.subscribed_channel_hashes().into_iter().collect();
        let distro_hashes: HashSet<Vec<u8>> =
            distro.registered_distro_hashes();
        peer_pairs.into_iter()
            .filter(|(routing_hash, id)| {
                (subscribed.contains(routing_hash) || distro_hashes.contains(routing_hash))
                    && !our_ids.contains(id)
            })
            .map(|(_, id)| id)
            .collect()
    }

    /// Record that a sync attempt has started (sets timing).
    pub fn sync_started(&mut self, dest_hash: &[u8]) {
        if let Some(peer) = self.peers.get_mut(dest_hash) {
            peer.last_sync_attempt = now();
        }
    }

    /// Record a successful sync outcome (resets backoff).
    pub fn sync_ok(&mut self, dest_hash: &[u8]) {
        if let Some(peer) = self.peers.get_mut(dest_hash) {
            peer.sync_succeeded();
        }
    }

    /// Record a failed sync outcome (increases backoff).
    pub fn sync_err(&mut self, dest_hash: &[u8]) {
        if let Some(peer) = self.peers.get_mut(dest_hash) {
            peer.sync_failed();
        }
    }

    /// Handle a MESSAGE_GET request from a peer.
    ///
    /// `requested_ids` = message IDs the peer wants.
    ///
    /// Wire format (per entry):
    ///   channel_hash  : 16 bytes
    ///   message_id    : 16 bytes
    ///   blob_len      : 4 bytes, big-endian u32
    ///   blob          : `blob_len` bytes
    ///
    /// Stops once `transfer_limit_bytes` or `sync_limit_bytes` would be exceeded.
    pub fn handle_message_get(&mut self, requested_ids: &[Vec<u8>]) -> Vec<u8> {
        // Reset rolling counter if the 1-hour period has elapsed.
        const SYNC_LIMIT_PERIOD: f64 = 3600.0;
        let t = now();
        if t - self.sync_period_start >= SYNC_LIMIT_PERIOD {
            self.sync_bytes_sent = 0;
            self.sync_period_start = t;
        }

        let store = self.blob_store.lock().unwrap();
        let mut out = Vec::new();
        let mut total_sent: u64 = 0;

        for id in requested_ids {
            let meta = match store.index.get(id.as_slice()) {
                Some(m) => m,
                None => continue,
            };
            // Enforce per-session transfer cap before reading the blob.
            if let Some(limit) = self.transfer_limit_bytes {
                if total_sent + meta.size as u64 > limit as u64 {
                    log(
                        format!("[sync] transfer limit reached ({}/{}B) — truncating response",
                            total_sent, limit as u64),
                        LOG_NOTICE, false, false,
                    );
                    break;
                }
            }
            // Enforce aggregate sync limit across all peers.
            if let Some(limit) = self.sync_limit_bytes {
                if self.sync_bytes_sent + meta.size as u64 > limit as u64 {
                    log(
                        format!("[sync] sync limit reached ({}/{}B) — refusing until next period",
                            self.sync_bytes_sent, limit as u64),
                        LOG_NOTICE, false, false,
                    );
                    break;
                }
            }
            let blob = match store.get(id) {
                Some(b) => b,
                None => continue,
            };
            // 16-byte channel hash (pad/truncate to 16)
            let ch = &meta.destination_hash;
            let ch_len = ch.len().min(16);
            out.extend_from_slice(&ch[..ch_len]);
            for _ in ch_len..16 { out.push(0); }
            // 16-byte message ID
            let id_len = id.len().min(16);
            out.extend_from_slice(&id[..id_len]);
            for _ in id_len..16 { out.push(0); }
            // 4-byte big-endian length + blob
            out.extend_from_slice(&(blob.len() as u32).to_be_bytes());
            out.extend_from_slice(&blob);
            total_sent += meta.size as u64;
            self.sync_bytes_sent += meta.size as u64;
        }
        // Wrap raw bytes in a msgpack Binary so handle_request_packet can embed
        // them safely in the [request_id, response_value] array without the binary
        // bytes being mis-parsed as a msgpack value (e.g. channel hashes whose
        // first byte happens to encode an ext8 marker like 0xc7).
        rmp_serde::to_vec(&out).unwrap_or_default()
    }

    /// Parse a MESSAGE_GET response, store new blobs, and return them so the
    /// caller can fanout to local subscribers.
    ///
    /// Wire format mirrors `handle_message_get`:
    ///   channel_hash(16) | message_id(16) | blob_len(4BE) | blob
    ///
    /// Stamp validation is intentionally **not** performed here.  Blobs transit
    /// between federation nodes in their clean, stamp-stripped form — the
    /// originating node already validated and stripped the stamp on first ingest
    /// (see `wire_channel_destination` in destinations.rs).  Re-validating on
    /// sync would fail because the stamp byte is gone.
    ///
    /// Returns `(channel_hash, blob)` pairs for every newly persisted blob so
    /// the caller can immediately fanout to local subscribers.
    pub fn ingest_message_get_response(
        &mut self,
        _peer_hash: &[u8],
        data: &[u8],
    ) -> Vec<(Vec<u8>, Vec<u8>)> {
        // Unwrap the msgpack Binary wrapper added by handle_message_get.
        let raw: Vec<u8> = rmp_serde::from_slice(data).unwrap_or_else(|_| data.to_vec());
        let data = raw.as_slice();
        let mut cursor = 0usize;
        let mut ingested: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        let mut store = self.blob_store.lock().unwrap();

        // Each record is at least 36 bytes (16 channel + 16 id + 4 len)
        while cursor + 36 <= data.len() {
            let channel_hash = data[cursor..cursor + 16].to_vec();
            cursor += 16;
            let message_id = data[cursor..cursor + 16].to_vec();
            cursor += 16;
            let blob_len = u32::from_be_bytes(
                data[cursor..cursor + 4].try_into().unwrap_or([0; 4]),
            ) as usize;
            cursor += 4;
            if cursor + blob_len > data.len() {
                break;
            }
            let blob = data[cursor..cursor + blob_len].to_vec();
            cursor += blob_len;

            if !store.index.contains_key(message_id.as_slice()) {
                match store.store_with_id(&channel_hash, &message_id, &blob) {
                    Ok(_) => ingested.push((channel_hash, blob)),
                    Err(e) => {
                        log(
                            format!("[sync] ingest error: {e}"),
                            LOG_WARNING,
                            false,
                            false,
                        );
                        break;
                    }
                }
            }
        }
        ingested
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> std::path::PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("rfed_sync_{label}_{unique}"))
    }

    #[test]
    fn ingest_message_get_response_preserves_upstream_message_ids() {
        let base = temp_path("preserve_ids");
        std::fs::create_dir_all(&base).expect("create temp dir");

        let blob_store = Arc::new(Mutex::new(BlobStore::open(
            base.join("blobs"),
            1024 * 1024,
        )));
        let subscription_table = Arc::new(Mutex::new(SubscriptionTable::load(
            base.join("subscriptions.rmp"),
        )));
        let distro_table = Arc::new(Mutex::new(DistroTable::load(
            base.join("distro.rmp"),
        )));
        let mut sync = FedSync::new(Arc::clone(&blob_store), subscription_table, distro_table);

        let channel_hash = vec![0x11; 16];
        let message_id = vec![0x22; 16];
        let blob = b"hello sync".to_vec();

        let mut wire = Vec::new();
        wire.extend_from_slice(&channel_hash);
        wire.extend_from_slice(&message_id);
        wire.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        wire.extend_from_slice(&blob);
        let payload = rmp_serde::to_vec(&wire).expect("encode response payload");

        let ingested = sync.ingest_message_get_response(&[0x33; 16], &payload);
        assert_eq!(ingested, vec![(channel_hash.clone(), blob.clone())]);

        {
            let guard = blob_store.lock().expect("lock blob store");
            assert!(guard.index.contains_key(message_id.as_slice()));
            assert_eq!(guard.get(message_id.as_slice()).as_deref(), Some(blob.as_slice()));
        }

        let ingested_again = sync.ingest_message_get_response(&[0x33; 16], &payload);
        assert!(ingested_again.is_empty(), "re-ingesting the same MESSAGE_GET payload must be a no-op");
        assert_eq!(blob_store.lock().expect("lock blob store").index.len(), 1);

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn gap_from_peer_includes_distro_hashes() {
        let base = temp_path("distro_gap");
        std::fs::create_dir_all(&base).expect("create temp dir");

        let blob_store = Arc::new(Mutex::new(BlobStore::open(
            base.join("blobs"), 1024 * 1024,
        )));
        let subscription_table = Arc::new(Mutex::new(SubscriptionTable::load(
            base.join("subscriptions.rmp"),
        )));
        let distro_table = Arc::new(Mutex::new(DistroTable::load(
            base.join("distro.rmp"),
        )));
        let sync = FedSync::new(
            Arc::clone(&blob_store),
            subscription_table,
            distro_table.clone(),
        );

        let distro_hash = vec![0xDD; 16];
        let message_id = vec![0xEE; 16];

        // Register a device for this distro so gap_from_peer should want it.
        distro_table.lock().unwrap().register(
            distro_hash.clone(),
            vec![0x01; 16],
            vec![0x01; 64],
        );

        // Offer a peer manifest containing a blob for the distro hash.
        let peer_manifest = vec![(distro_hash.clone(), message_id.clone())];
        let wanted = sync.gap_from_peer(peer_manifest);

        // We don't have this blob yet, and we have a distro device → should want it.
        assert_eq!(wanted, vec![message_id.clone()],
            "gap_from_peer should include blobs for distro hashes with registered devices");

        // Now store the blob locally → gap should be empty.
        blob_store.lock().unwrap().store_with_id(&distro_hash, &message_id, b"test").unwrap();
        let wanted2 = sync.gap_from_peer(vec![(distro_hash, message_id.clone())]);
        assert!(wanted2.is_empty(),
            "gap_from_peer should not request blobs we already have");

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A distro blob must carry the same message ID on every node.
    ///
    /// `handle_message_get` writes the ID as a fixed 16-byte field. Distro
    /// blobs used to be keyed by a 32-byte full hash, so the ID was truncated
    /// on the wire: the peer stored the blob under the short ID and advertised
    /// that, and the origin — holding only the long ID — read the manifest
    /// entry as a blob it had never seen, pulled it back, and fanned it out to
    /// every registered device a second time. Every sync round, one duplicate.
    #[test]
    fn distro_blob_ids_survive_the_message_get_wire_format() {
        let base = temp_path("distro_id_roundtrip");
        std::fs::create_dir_all(&base).expect("create temp dir");

        let distro_hash = vec![0xD1; 16];
        let blob = b"a distro lxmf message".to_vec();
        let message_id = crate::distro::distro_message_id(&blob);
        assert_eq!(
            message_id.len(), 16,
            "the MESSAGE_GET wire format has a fixed 16-byte ID field",
        );

        let make_node = |label: &str| {
            let dir = base.join(label);
            let store = Arc::new(Mutex::new(BlobStore::open(dir.join("blobs"), 1024 * 1024)));
            let distro = Arc::new(Mutex::new(DistroTable::load(dir.join("distro.rmp"))));
            distro.lock().unwrap().register(
                distro_hash.clone(), vec![0x01; 16], vec![0x01; 64],
            );
            let sync = FedSync::new(
                Arc::clone(&store),
                Arc::new(Mutex::new(SubscriptionTable::load(dir.join("subs.rmp")))),
                distro,
            );
            (store, sync)
        };

        // Origin ingests the blob the way the propagation path does.
        let (origin_store, mut origin) = make_node("origin");
        origin_store.lock().unwrap()
            .store_with_id(&distro_hash, &message_id, &blob)
            .expect("store distro blob");

        // Peer pulls it across the wire.
        let (_peer_store, mut peer) = make_node("peer");
        let wanted = peer.gap_from_peer(origin.local_manifest());
        assert_eq!(wanted, vec![message_id.clone()], "peer wants the blob");
        let response = origin.handle_message_get(&wanted);
        let ingested = peer.ingest_message_get_response(&[0x99; 16], &response);
        assert_eq!(ingested, vec![(distro_hash.clone(), blob.clone())]);

        // …and offers it straight back. The origin must recognise its own blob,
        // or it re-ingests and re-fans it.
        assert!(
            origin.gap_from_peer(peer.local_manifest()).is_empty(),
            "the origin already holds this blob — re-pulling it would re-fan it to every device",
        );

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn gap_from_peer_ignores_distro_without_devices() {
        let base = temp_path("distro_nogap");
        std::fs::create_dir_all(&base).expect("create temp dir");

        let blob_store = Arc::new(Mutex::new(BlobStore::open(
            base.join("blobs"), 1024 * 1024,
        )));
        let subscription_table = Arc::new(Mutex::new(SubscriptionTable::load(
            base.join("subscriptions.rmp"),
        )));
        let distro_table = Arc::new(Mutex::new(DistroTable::load(
            base.join("distro.rmp"),
        )));
        let sync = FedSync::new(Arc::clone(&blob_store), subscription_table, distro_table);

        // Don't register any devices — the distro hash should be ignored.
        let distro_hash = vec![0xDD; 16];
        let message_id = vec![0xEE; 16];
        let peer_manifest = vec![(distro_hash, message_id.clone())];
        let wanted = sync.gap_from_peer(peer_manifest);

        assert!(wanted.is_empty(),
            "gap_from_peer should ignore distro hashes that have no registered devices");

        let _ = std::fs::remove_dir_all(&base);
    }
}

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

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use reticulum_rust::{log, hexrep, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};

#[allow(unused_imports)]  // re-exported for use by destinations.rs
pub use reticulum_rust::transport::Transport;

use crate::blob_store::BlobStore;
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
    pub max_peering_cost: u32,
    pub transfer_limit_bytes: Option<f64>,
    pub sync_limit_bytes: Option<f64>,
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
    ) -> Self {
        FedSync {
            peers: HashMap::new(),
            blob_store,
            subscription_table,
            max_peering_cost: 26,
            transfer_limit_bytes: None,
            sync_limit_bytes: None,
            from_static_only: false,
            static_peers: Vec::new(),
            peer_state_file: None,
            sync_bytes_sent: 0,
            sync_period_start: now(),
        }
    }

    /// Called by the rfed.node announce handler when a peer is seen.
    pub fn peer_heard(&mut self, dest_hash: Vec<u8>, peering_cost: Option<u32>) {
        if self.from_static_only && !self.static_peers.iter().any(|p| p == &dest_hash) {
            return;
        }
        let peer = self.peers.entry(dest_hash.clone()).or_insert_with(|| {
            log(
                &format!("[sync] new peer: {}", hexrep(&dest_hash, false)),
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
                &format!("[sync] pruned {pruned} stale peer(s)"),
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
                    &format!("[sync] seeding static peer {}", hexrep(&hash, false)),
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
                    log(&format!("[sync] failed to save peer state: {e}"),
                        LOG_WARNING, false, false);
                }
            }
            Err(e) => log(&format!("[sync] peer state encode error: {e}"),
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
                log(&format!("[sync] failed to read peer state: {e}"),
                    LOG_WARNING, false, false);
                return;
            }
        };
        match rmp_serde::from_slice::<Vec<FedPeer>>(&bytes) {
            Ok(peers) => {
                for p in peers {
                    self.peers.entry(p.destination_hash.clone())
                        .or_insert(p);
                }
                log(&format!("[sync] loaded {} peer(s) from disk", self.peers.len()),
                    LOG_NOTICE, false, false);
            }
            Err(e) => log(&format!("[sync] peer state decode error: {e}"),
                LOG_WARNING, false, false),
        }
    }

    // ── Inbound request handlers (called from rfed.node request handlers) ────

    /// Returns `(channel_hash, message_id)` pairs for all blobs this node
    /// holds for channels that have at least one local subscriber.
    ///
    /// Including the channel hash lets the *requesting* peer filter out entries
    /// for channels it doesn't subscribe to, so it never pulls blobs it has no
    /// use for.
    pub fn local_manifest(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let store = self.blob_store.lock().unwrap();
        let subs  = self.subscription_table.lock().unwrap();
        let local_channels: std::collections::HashSet<Vec<u8>> =
            subs.subscribed_channel_hashes().into_iter().collect();
        if local_channels.is_empty() {
            // No local subscribers yet — don't advertise anything.
            return Vec::new();
        }
        store
            .index
            .values()
            .filter(|m| local_channels.contains(&m.destination_hash))
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
    /// Given the peer's manifest as `(channel_hash, message_id)` pairs, returns
    /// the IDs to request: blobs for channels we subscribe to that we don't
    /// already hold.  Acquires `blob_store` and `subscription_table` exactly
    /// once each — avoids the double-lock that a separate `local_manifest()` +
    /// `subscription_table.lock()` call would incur.
    pub fn gap_from_peer(&self, peer_pairs: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<Vec<u8>> {
        let store = self.blob_store.lock().unwrap();
        let subs  = self.subscription_table.lock().unwrap();
        let our_ids: std::collections::HashSet<Vec<u8>> =
            store.index.keys().cloned().collect();
        let subscribed: std::collections::HashSet<Vec<u8>> =
            subs.subscribed_channel_hashes().into_iter().collect();
        peer_pairs.into_iter()
            .filter(|(ch, id)| subscribed.contains(ch) && !our_ids.contains(id))
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
                        &format!("[sync] transfer limit reached ({}/{}B) — truncating response",
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
                        &format!("[sync] sync limit reached ({}/{}B) — refusing until next period",
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
                match store.store(&channel_hash, &blob) {
                    Ok(_) => ingested.push((channel_hash, blob)),
                    Err(e) => {
                        log(
                            &format!("[sync] ingest error: {e}"),
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

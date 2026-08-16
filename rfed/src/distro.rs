//! Distro — personal multi-device fanout for a shared LXMF identity.
//!
//! # Architecture
//!
//! A Distro is a standard LXMF identity whose private key is shared out-of-band
//! across multiple devices (phone, laptop, LoRa messenger, etc.).  Any LXMF
//! message sent to the distro's `lxmf.delivery` address is automatically fanned
//! out to all registered device addresses.
//!
//! The sender creates a normal LXMF message addressed to the distro identity —
//! no channel-specific knowledge or key derivation required.  RFed intercepts
//! the message at the `lxmf.propagation` ingress, stores it in the BlobStore
//! (NOT the propagation messagestore — to avoid polluting the lxmd mesh), and
//! fans it out to registered devices via `rfed.delivery`.
//!
//! Cross-node distribution uses FedSync (the same `rfed.node` OFFER/MESSAGE_GET
//! engine that channels use).  Devices on different RFed nodes register with
//! their local node; the sync engine distributes blobs to any node that has
//! at least one device registered for that distro hash.
//!
//! # Double-wrap delivery (identical pattern to channels)
//!
//!   Layer 1 (Reticulum transport):
//!     DATA packet, DestinationType::Single, addressed to device's rfed.delivery
//!     Payload: [ distro_lxmf_hash(16) | lxmf_blob(*) ]
//!
//!   Layer 2 (LXMF inner):
//!     Standard LXMF message encrypted to the distro identity's X25519 key.
//!     RFed NEVER decrypts this — it's opaque bytes from the node's perspective.
//!
//! The device receives on `rfed.delivery`, recognizes the `distro_lxmf_hash`,
//! and decrypts with the shared distro private key.
//!
//! # Registration
//!
//! A device (holding the distro private key) proves ownership by signing the
//! device's identity hash with the distro Ed25519 key:
//!
//!   Register:   msgpack [ bin(64) distro_pubkey, bin(64) sig(distro_identity_hash), bin(64) device_pubkey ]
//!   Unregister: same payload
//!   List:       msgpack [ bin(64) distro_pubkey, bin(64) sig(distro_identity_hash) ]
//!
//! Response (list): msgpack [ bin(16) device_lxmf_hash, ... ]
//!
//! # Naming convention
//!
//! Following the split-aspect pattern (REFACTOR.md 2026-05-17):
//!
//!   rfed.distro.register   — /rfed/distro/register
//!   rfed.distro.unregister — /rfed/distro/unregister
//!   rfed.distro.list       — /rfed/distro/list

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use reticulum_rust::destination::{Destination, DestinationType};
use reticulum_rust::identity::Identity;
use reticulum_rust::packet::{Packet, ANNOUNCE, DATA, NONE, HEADER_1, FLAG_SET, FLAG_UNSET};
use reticulum_rust::transport::Transport;
use reticulum_rust::{hexrep, log, LOG_DEBUG, LOG_NOTICE, LOG_WARNING};

use crate::notify::HookRegistry;
use crate::stream_registry::PropagationStreamRegistry;

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// ── DistroEntry ──────────────────────────────────────────────────────────────

/// A single device registration for a distro identity.
///
/// Mirrors `SubscriptionEntry` in schema so the backup failover mechanism
/// (`owner_node_hash`, `last_refreshed`) can be added without a migration.
#[derive(Clone, Serialize, Deserialize)]
pub struct DistroEntry {
    /// 16-byte `lxmf.delivery` destination hash of the distro identity.
    /// This is the routing key — it matches the first 16 bytes of the LXMF
    /// message received at `lxmf.propagation`.
    pub distro_lxmf_hash: Vec<u8>,
    /// 16-byte `lxmf.delivery` destination hash of the registered device.
    pub device_lxmf_hash: Vec<u8>,
    /// 64-byte device identity public key (X25519 enc || Ed25519 sign).
    /// Stored so `Identity::from_public_key` can reconstruct the identity
    /// for outbound delivery even when the device hasn't announced yet.
    pub device_pubkey: Vec<u8>,
    /// Unix timestamp when this entry was registered.
    pub added: f64,
    /// Reserved for future backup-node failover support.
    /// Set when another node pushes this entry as a backup subscription.
    #[serde(default)]
    pub owner_node_hash: Option<Vec<u8>>,
    /// Timestamp of the last refresh from the upstream custodian.
    /// Used for chain-of-custody TTL unwinding (same semantics as channels).
    #[serde(default)]
    pub last_refreshed: f64,
}

// ── DistroTable ──────────────────────────────────────────────────────────────

/// Per-node table mapping distro identities to registered device addresses.
///
/// Never synced between nodes.  Each device registers with its local RFed node.
/// Cross-node distribution happens via FedSync: every node pulls blobs for any
/// distro hash it has at least one local device registered for.
pub struct DistroTable {
    entries: Vec<DistroEntry>,
    file_path: PathBuf,
}

impl DistroTable {
    /// Load from disk, or start empty if the file doesn't exist.
    pub fn load(file_path: PathBuf) -> Self {
        let entries = if file_path.exists() {
            std::fs::read(&file_path)
                .ok()
                .and_then(|bytes| rmp_serde::from_slice::<Vec<DistroEntry>>(&bytes).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        DistroTable { entries, file_path }
    }

    /// Register a device for a distro identity.  Idempotent.
    pub fn register(
        &mut self,
        distro_lxmf_hash: Vec<u8>,
        device_lxmf_hash: Vec<u8>,
        device_pubkey: Vec<u8>,
    ) {
        let already = self.entries.iter().any(|e| {
            e.distro_lxmf_hash == distro_lxmf_hash
                && e.device_lxmf_hash == device_lxmf_hash
        });
        if !already {
            let t = now();
            self.entries.push(DistroEntry {
                distro_lxmf_hash,
                device_lxmf_hash,
                device_pubkey,
                added: t,
                owner_node_hash: None,
                last_refreshed: t,
            });
            let _ = self.save();
        }
    }

    /// Remove a device registration.  No-op if not found.
    pub fn unregister(&mut self, distro_lxmf_hash: &[u8], device_lxmf_hash: &[u8]) {
        let before = self.entries.len();
        self.entries.retain(|e| {
            !(e.distro_lxmf_hash.as_slice() == distro_lxmf_hash
                && e.device_lxmf_hash.as_slice() == device_lxmf_hash)
        });
        if self.entries.len() != before {
            let _ = self.save();
        }
    }

    /// List all device LXMF delivery hashes registered for a distro.
    pub fn get_devices(&self, distro_lxmf_hash: &[u8]) -> Vec<&DistroEntry> {
        self.entries
            .iter()
            .filter(|e| e.distro_lxmf_hash.as_slice() == distro_lxmf_hash)
            .collect()
    }

    /// Owned copy of the devices registered for `distro_lxmf_hash`.
    ///
    /// NEVER REMOVE. This exists so callers can take the `distro_table` mutex,
    /// snapshot, and release it BEFORE doing any network work. See the comment
    /// on `distro_fanout` for the production deadlock this prevents.
    pub fn devices_snapshot(&self, distro_lxmf_hash: &[u8]) -> Vec<DistroEntry> {
        self.entries
            .iter()
            .filter(|e| e.distro_lxmf_hash.as_slice() == distro_lxmf_hash)
            .cloned()
            .collect()
    }

    /// Whether any devices are registered for this distro hash.
    pub fn is_distro(&self, distro_lxmf_hash: &[u8]) -> bool {
        self.entries
            .iter()
            .any(|e| e.distro_lxmf_hash.as_slice() == distro_lxmf_hash)
    }

    /// All distinct distro hashes that have at least one local device.
    ///
    /// Used by the sync engine to decide which blobs to pull from peers:
    /// "I have a device for this distro → I want blobs for this hash."
    pub fn registered_distro_hashes(&self) -> HashSet<Vec<u8>> {
        self.entries
            .iter()
            .map(|e| e.distro_lxmf_hash.clone())
            .collect()
    }

    /// Number of registered entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Persist to disk.
    pub fn save(&self) -> Result<(), String> {
        let bytes = rmp_serde::to_vec(&self.entries)
            .map_err(|e| format!("DistroTable serialize: {e}"))?;
        std::fs::write(&self.file_path, &bytes)
            .map_err(|e| format!("DistroTable write: {e}"))?;
        Ok(())
    }
}

// ── Pre-signed announces ─────────────────────────────────────────────────────

/// Length of the X25519 ratchet public key carried in a ratchet-bearing announce.
const RATCHET_LEN: usize = 32;
/// `public_key(64) + name_hash(10) + random_hash(10) + signature(64)`.
const ANNOUNCE_FIXED_LEN: usize = 64 + 10 + 10 + 64;

/// A pre-signed announce for a distro identity, minted by a device that holds
/// the distro private key and replayed verbatim by this node.
///
/// RFed only ever receives the distro *public* key (see `handle_distro_registration`),
/// so it cannot mint an announce itself. Replaying a device-signed one is the
/// same operation a transport node performs when it answers a path request from
/// its announce cache: the packet is self-contained and signed by the identity
/// it describes, so relaying it neither requires nor grants key access.
#[derive(Clone, Serialize, Deserialize)]
pub struct DistroAnnounce {
    /// 16-byte `lxmf.delivery` destination hash the announce describes.
    pub distro_lxmf_hash: Vec<u8>,
    /// Wire announce payload: `pubkey | name_hash | random_hash | [ratchet] | sig | app_data`.
    pub announce_data: Vec<u8>,
    /// Whether `announce_data` carries a ratchet — becomes the packet context flag.
    pub ratchet: bool,
    /// Unix timestamp of the last submission that replaced this announce.
    pub updated: f64,
}

/// Per-node store of pre-signed distro announces.
///
/// Kept in its own file rather than folded into `DistroTable` so the existing
/// on-disk `Vec<DistroEntry>` shape needs no migration.
pub struct DistroAnnounceStore {
    entries: Vec<DistroAnnounce>,
    file_path: PathBuf,
}

impl DistroAnnounceStore {
    /// Load from disk, or start empty if the file doesn't exist.
    pub fn load(file_path: PathBuf) -> Self {
        let entries = if file_path.exists() {
            std::fs::read(&file_path)
                .ok()
                .and_then(|bytes| rmp_serde::from_slice::<Vec<DistroAnnounce>>(&bytes).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        DistroAnnounceStore { entries, file_path }
    }

    /// Store or replace the announce for a distro identity.
    ///
    /// A fresh submission always wins: the device re-signs with a new emission
    /// time (and possibly a new ratchet), and a stale announce would be ignored
    /// by receivers as an out-of-date duplicate.
    pub fn put(&mut self, distro_lxmf_hash: Vec<u8>, announce_data: Vec<u8>, ratchet: bool) {
        self.entries
            .retain(|e| e.distro_lxmf_hash != distro_lxmf_hash);
        self.entries.push(DistroAnnounce {
            distro_lxmf_hash,
            announce_data,
            ratchet,
            updated: now(),
        });
        let _ = self.save();
    }

    /// Drop the announce for a distro identity.  No-op if absent.
    pub fn remove(&mut self, distro_lxmf_hash: &[u8]) {
        let before = self.entries.len();
        self.entries
            .retain(|e| e.distro_lxmf_hash.as_slice() != distro_lxmf_hash);
        if self.entries.len() != before {
            let _ = self.save();
        }
    }

    /// The announce for one distro identity, if held.
    pub fn get(&self, distro_lxmf_hash: &[u8]) -> Option<&DistroAnnounce> {
        self.entries
            .iter()
            .find(|e| e.distro_lxmf_hash.as_slice() == distro_lxmf_hash)
    }

    /// Owned copy of every held announce, for replay without holding the lock.
    pub fn snapshot(&self) -> Vec<DistroAnnounce> {
        self.entries.clone()
    }

    /// Number of stored announces.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Persist to disk.
    pub fn save(&self) -> Result<(), String> {
        let bytes = rmp_serde::to_vec(&self.entries)
            .map_err(|e| format!("DistroAnnounceStore serialize: {e}"))?;
        std::fs::write(&self.file_path, &bytes)
            .map_err(|e| format!("DistroAnnounceStore write: {e}"))?;
        Ok(())
    }
}

/// Split a `/rfed/distro/announce` payload value into its ratchet flag and
/// announce bytes.
///
/// Wire format: `flags(1) | announce_data`, flags bit 0 = ratchet present.
/// The flag cannot be derived from the length because app_data is variable, and
/// it decides where the signature starts — so it travels explicitly.
pub fn parse_distro_announce_payload(value: &[u8]) -> Result<(bool, Vec<u8>), String> {
    if value.is_empty() {
        return Err("empty announce payload".into());
    }
    Ok((value[0] & 0x01 != 0, value[1..].to_vec()))
}

/// Verify a pre-signed announce and return the `lxmf.delivery` hash it describes.
///
/// NEVER WEAKEN THIS. The node rebroadcasts whatever this accepts, so an
/// unchecked path here would turn RFed into an open announce injector able to
/// bind any destination hash to attacker-chosen keys. Every field is pinned:
/// the embedded key must be the distro key the caller proved ownership of, the
/// aspect must be `lxmf.delivery`, and the signature must cover the whole thing.
pub fn verify_distro_announce(
    announce_data: &[u8],
    ratchet: bool,
    expected_distro_pubkey: &[u8],
) -> Result<Vec<u8>, String> {
    let ratchet_len = if ratchet { RATCHET_LEN } else { 0 };
    if announce_data.len() < ANNOUNCE_FIXED_LEN + ratchet_len {
        return Err(format!(
            "announce_data len {} < minimum {}",
            announce_data.len(),
            ANNOUNCE_FIXED_LEN + ratchet_len
        ));
    }

    let public_key = &announce_data[0..64];
    if public_key != expected_distro_pubkey {
        return Err("announce public key does not match the registering distro key".into());
    }

    let name_hash = &announce_data[64..74];
    let random_hash = &announce_data[74..84];
    let ratchet_bytes = &announce_data[84..84 + ratchet_len];
    let sig_start = 84 + ratchet_len;
    let signature = &announce_data[sig_start..sig_start + 64];
    let app_data = &announce_data[sig_start + 64..];

    // Reconstructing the destination pins both the hash and the aspect: a
    // submission for any aspect other than lxmf.delivery fails the name_hash
    // comparison, so this endpoint cannot be used to announce, say, a
    // propagation node under someone else's key.
    let identity = Identity::from_public_key(public_key)
        .map_err(|e| format!("distro pubkey invalid: {e}"))?;
    let destination = Destination::new_outbound(
        Some(identity.clone()),
        DestinationType::Single,
        "lxmf".to_string(),
        vec!["delivery".to_string()],
    )
    .map_err(|e| format!("lxmf.delivery destination: {e}"))?;

    if destination.name_hash != name_hash {
        return Err("announce name_hash is not lxmf.delivery".into());
    }

    let mut signed_data = Vec::with_capacity(16 + announce_data.len());
    signed_data.extend_from_slice(&destination.hash);
    signed_data.extend_from_slice(public_key);
    signed_data.extend_from_slice(name_hash);
    signed_data.extend_from_slice(random_hash);
    signed_data.extend_from_slice(ratchet_bytes);
    signed_data.extend_from_slice(app_data);

    if !identity.validate(signature, &signed_data) {
        return Err("announce signature verification failed".into());
    }

    Ok(destination.hash)
}

/// Rebroadcast a stored pre-signed announce onto the network.
///
/// Emitted as a HEADER_1 broadcast announce sourced from this node, so
/// neighbours install a path toward RFed for the distro address. Only
/// propagated LXMF delivery can be served over that path — RFed has no distro
/// private key and so cannot terminate a direct link for it.
pub fn replay_distro_announce(announce: &DistroAnnounce) -> Result<(), String> {
    if announce.announce_data.len() < 64 {
        return Err("stored announce too short".into());
    }
    let identity = Identity::from_public_key(&announce.announce_data[0..64])
        .map_err(|e| format!("stored announce pubkey invalid: {e}"))?;
    let destination = Destination::new_outbound(
        Some(identity),
        DestinationType::Single,
        "lxmf".to_string(),
        vec!["delivery".to_string()],
    )
    .map_err(|e| format!("lxmf.delivery destination: {e}"))?;

    let context_flag = if announce.ratchet { FLAG_SET } else { FLAG_UNSET };
    let mut packet = Packet::new(
        Some(destination),
        announce.announce_data.clone(),
        ANNOUNCE,
        NONE,
        reticulum_rust::transport::BROADCAST,
        HEADER_1,
        None,
        None,
        false,
        context_flag,
    );
    packet.send().map(|_| ()).map_err(|e| format!("announce send: {e}"))
}

// ── Distro fanout ────────────────────────────────────────────────────────────

/// Fanout an LXMF blob to all devices registered for `distro_lxmf_hash`.
///
/// Delivery path: `rfed.delivery` (same as channel blobs — the device
/// distinguishes by the routing hash prefix).
///
/// Returns the identity hashes of devices that could not be reached
/// (unknown identity or no path).  The caller is responsible for enqueuing
/// these in the DeferredQueue.
///
/// This mirrors `fanout::fanout_blob()` but uses `DistroTable` instead of
/// `SubscriptionTable`, targets `lxmf.delivery`-derived destinations, and
/// checks `PropagationStreamRegistry` instead of `ChannelStreamRegistry`.
/// Takes an already-snapshotted device list rather than the `DistroTable`.
///
/// NEVER REMOVE the `&[DistroEntry]` parameter in favour of `&DistroTable`.
/// This function performs unbounded network work per device (stream dispatch,
/// path lookup, link establishment, packet dispatch). When it took
/// `&DistroTable`, every caller necessarily held the `distro_table` mutex for
/// the whole fan-out, so a single stalled device delivery froze the table for
/// every other user of it. Verified in production 2026-08-09 00:56:54: two
/// `/rfed/distro/register` callbacks blocked forever on `distro_table.lock()`
/// and never reached `[REQ] callback completed`, so RFed sent no response and
/// the browser client hung. Identical registrations on the same build had
/// completed in well under a second earlier the same day (18:35, 18:38, 18:43),
/// i.e. the table had been wedged in between. Snapshot under the lock, release,
/// then fan out.
pub fn distro_fanout(
    distro_lxmf_hash: &[u8],
    lxmf_blob: &[u8],
    devices: &[DistroEntry],
    hook_registry: &HookRegistry,
    propagation_streams: Option<&Arc<Mutex<PropagationStreamRegistry>>>,
) -> Vec<Vec<u8>> {
    if devices.is_empty() {
        log(
            format!(
                "[distro] no devices registered for distro {}",
                hexrep(distro_lxmf_hash, false)
            ),
            LOG_DEBUG,
            false,
            false,
        );
        return Vec::new();
    }

    log(
        format!(
            "[distro] fanning out LXMF blob ({} bytes) to {} device(s) for distro {}",
            lxmf_blob.len(),
            devices.len(),
            hexrep(distro_lxmf_hash, false),
        ),
        LOG_NOTICE,
        false,
        false,
    );

    let mut missed: Vec<Vec<u8>> = Vec::new();

    for entry in devices {
        // Build delivery payload: [ distro_lxmf_hash(16) | lxmf_blob ]
        // Same format as channel delivery: [ routing_hash(16) | inner_blob ]
        let mut payload = distro_lxmf_hash.to_vec();
        payload.extend_from_slice(lxmf_blob);

        // ── Try propagation.stream live delivery ─────────────────────
        if let Some(streams) = propagation_streams {
            if let Ok(mut registry) = streams.lock() {
                let result = registry.dispatch(&entry.device_lxmf_hash, lxmf_blob);
                if result.delivered() {
                    log(
                        format!(
                            "[distro] streamed to device {} on {} live link(s)",
                            hexrep(&entry.device_lxmf_hash, false),
                            result.sent,
                        ),
                        LOG_DEBUG,
                        false,
                        false,
                    );
                    hook_registry.on_deliver(&entry.device_lxmf_hash, lxmf_blob);
                    continue;
                }
                if result.had_sessions() {
                    log(
                        format!(
                            "[distro] stream delivery failed for device {} — falling back to rfed.delivery",
                            hexrep(&entry.device_lxmf_hash, false),
                        ),
                        LOG_WARNING,
                        false,
                        false,
                    );
                }
            }
        }

        // ── Derive device identity from stored pubkey ─────────────────
        let device_identity = match Identity::from_public_key(&entry.device_pubkey) {
            Ok(id) => id,
            Err(e) => {
                log(
                    format!(
                        "[distro] device pubkey invalid for {}: {e} — will defer",
                        hexrep(&entry.device_lxmf_hash, false)
                    ),
                    LOG_WARNING,
                    false,
                    false,
                );
                missed.push(entry.device_lxmf_hash.clone());
                continue;
            }
        };

        let device_id_hash = match device_identity.hash.as_ref() {
            Some(h) => h.clone(),
            None => {
                missed.push(entry.device_lxmf_hash.clone());
                continue;
            }
        };

        // Ensure the device identity is known to Reticulum so we can
        // build an outbound destination.
        let _ = Identity::remember_destination(
            &entry.device_lxmf_hash,
            &entry.device_pubkey,
            None,
        );

        // ── Build outbound destination to device's rfed.delivery ──────
        let dest = match Destination::new_outbound(
            Some(device_identity),
            DestinationType::Single,
            "rfed".to_string(),
            vec!["delivery".to_string()],
        ) {
            Ok(d) => d,
            Err(e) => {
                log(
                    format!(
                        "[distro] failed to build rfed.delivery dest for device {}: {e}",
                        hexrep(&entry.device_lxmf_hash, false)
                    ),
                    LOG_WARNING,
                    false,
                    false,
                );
                missed.push(device_id_hash);
                continue;
            }
        };

        // Only attempt delivery if a network path is known.
        if !Transport::has_path(&dest.hash) {
            log(
                format!(
                    "[distro] no path to device {} — will defer",
                    hexrep(&entry.device_lxmf_hash, false)
                ),
                LOG_NOTICE,
                false,
                false,
            );
            missed.push(device_id_hash);
            continue;
        }

        // ── Send ──────────────────────────────────────────────────────
        // Capture the destination hash before `dest` is moved into the packet,
        // so the no-transmission branch can request a fresh path for it.
        let dest_hash_for_request = dest.hash.clone();
        let mut packet = Packet::new(
            Some(dest),
            payload,
            DATA,
            NONE,
            reticulum_rust::transport::BROADCAST,
            HEADER_1,
            None,
            None,
            false,
            FLAG_UNSET,
        );
        match packet.send() {
            Err(e) => {
                log(
                    format!(
                        "[distro] send to device {} failed: {e} — will defer",
                        hexrep(&entry.device_lxmf_hash, false)
                    ),
                    LOG_WARNING,
                    false,
                    false,
                );
                missed.push(device_id_hash.clone());
            }
            Ok(None) => {
                // Ok(None) = Transport::outbound returned sent=false: the path
                // to the device exists but has no usable (online) interface
                // right now.  Request a fresh path so the NEXT fanout / the
                // deferred flush finds a warm route, then defer.  Previously
                // this just deferred without re-resolving, so the blob sat in
                // the deferred queue while the path stayed cold.
                log(
                    format!(
                        "[distro] no interface for device {} — requesting path + will defer",
                        hexrep(&entry.device_lxmf_hash, false)
                    ),
                    LOG_WARNING,
                    false,
                    false,
                );
                Transport::request_path(&dest_hash_for_request, None, None, None, None);
                missed.push(device_id_hash.clone());
            }
            Ok(Some(_)) => {
                log(
                    format!(
                        "[DISTRO] SENT distro={} device={} payload_bytes={}",
                        hexrep(distro_lxmf_hash, false),
                        hexrep(&entry.device_lxmf_hash, false),
                        lxmf_blob.len() + distro_lxmf_hash.len(),
                    ),
                    LOG_NOTICE,
                    false,
                    false,
                );
                // Only report delivery on an actual transmission.  Previously
                // on_deliver fired unconditionally (even on defer/Ok(None)),
                // marking blobs delivered that never left the node.
                hook_registry.on_deliver(&device_id_hash, lxmf_blob);
            }
        }
    }

    missed
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Content-addressed BlobStore ID for a distro message.
///
/// **Must be 16 bytes.** The FedSync MESSAGE_GET wire format
/// (`sync::handle_message_get`) writes the message ID as a fixed 16-byte
/// field, so a longer ID is silently truncated on the way out. A peer then
/// stores the blob under the truncated ID and advertises *that* in its
/// manifest; this node, which knows only the long ID, sees an ID it has never
/// held, pulls the blob back, stores it a second time — and fans it out to
/// every registered device again. Same bytes in, same ID on every node.
pub fn distro_message_id(lxmf_data: &[u8]) -> Vec<u8> {
    reticulum_rust::identity::truncated_hash(lxmf_data)
}

/// Derive the `lxmf.delivery` destination hash from a 64-byte identity public key.
///
/// Used during registration: the device provides its pubkey, we compute the
/// delivery hash to store in the DistroTable and to match incoming LXMF messages.
pub fn lxmf_delivery_hash_from_pubkey(pubkey: &[u8]) -> Result<Vec<u8>, String> {
    let identity = Identity::from_public_key(pubkey)
        .map_err(|e| format!("from_public_key: {e}"))?;
    Destination::new_outbound(
        Some(identity),
        DestinationType::Single,
        "lxmf".to_string(),
        vec!["delivery".to_string()],
    )
    .map(|dest| dest.hash)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("rfed_distro_{label}_{unique}"))
    }

    fn make_table(label: &str) -> DistroTable {
        let path = temp_path(label);
        let _ = std::fs::remove_file(&path);
        DistroTable::load(path)
    }

    fn dummy_hash(byte: u8) -> Vec<u8> {
        vec![byte; 16]
    }

    fn dummy_pubkey(byte: u8) -> Vec<u8> {
        vec![byte; 64]
    }

    // ── Pre-signed announce helpers ──────────────────────────────────────

    /// Build a genuine, correctly signed `lxmf.delivery` announce for `identity`,
    /// mirroring `Destination::generate_announce_data` in reticulum_rust.
    fn build_announce(identity: &Identity, app_data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let destination = Destination::new_outbound(
            Some(identity.clone()),
            DestinationType::Single,
            "lxmf".to_string(),
            vec!["delivery".to_string()],
        )
        .expect("destination");

        let public_key = identity.get_public_key().expect("public key");
        let random_hash = vec![0x5Au8; 10];

        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&destination.hash);
        signed_data.extend_from_slice(&public_key);
        signed_data.extend_from_slice(&destination.name_hash);
        signed_data.extend_from_slice(&random_hash);
        signed_data.extend_from_slice(app_data);
        let signature = identity.sign(&signed_data);

        let mut announce_data = Vec::new();
        announce_data.extend_from_slice(&public_key);
        announce_data.extend_from_slice(&destination.name_hash);
        announce_data.extend_from_slice(&random_hash);
        announce_data.extend_from_slice(&signature);
        announce_data.extend_from_slice(app_data);

        (announce_data, destination.hash)
    }

    #[test]
    fn verify_accepts_a_genuine_announce_and_returns_the_delivery_hash() {
        let identity = Identity::new(true);
        let pubkey = identity.get_public_key().expect("public key");
        let (announce_data, expected_hash) = build_announce(&identity, b"");

        let hash = verify_distro_announce(&announce_data, false, &pubkey)
            .expect("a correctly signed announce must verify");

        assert_eq!(hash, expected_hash, "must return the lxmf.delivery hash");
    }

    #[test]
    fn verify_accepts_an_announce_carrying_app_data() {
        let identity = Identity::new(true);
        let pubkey = identity.get_public_key().expect("public key");
        let (announce_data, expected_hash) = build_announce(&identity, b"display name bytes");

        let hash = verify_distro_announce(&announce_data, false, &pubkey)
            .expect("app data is signed too, so it must still verify");

        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn verify_rejects_an_announce_for_a_different_key() {
        // The attack this blocks: prove ownership of distro key A during
        // registration, then submit an announce binding key B's destination.
        let attacker = Identity::new(true);
        let victim = Identity::new(true);
        let victim_pubkey = victim.get_public_key().expect("public key");
        let (announce_data, _) = build_announce(&attacker, b"");

        let err = verify_distro_announce(&announce_data, false, &victim_pubkey)
            .expect_err("an announce for another identity must be rejected");

        assert!(
            err.contains("does not match"),
            "expected a key-mismatch error, got: {err}"
        );
    }

    #[test]
    fn verify_rejects_a_tampered_signature() {
        let identity = Identity::new(true);
        let pubkey = identity.get_public_key().expect("public key");
        let (mut announce_data, _) = build_announce(&identity, b"");
        let sig_start = 84;
        announce_data[sig_start] ^= 0xFF;

        let err = verify_distro_announce(&announce_data, false, &pubkey)
            .expect_err("a corrupted signature must be rejected");

        assert!(
            err.contains("signature"),
            "expected a signature error, got: {err}"
        );
    }

    #[test]
    fn verify_rejects_tampered_app_data() {
        // app_data is inside the signed region, so flipping it must invalidate
        // the announce rather than sneak through as unsigned trailing bytes.
        let identity = Identity::new(true);
        let pubkey = identity.get_public_key().expect("public key");
        let (mut announce_data, _) = build_announce(&identity, b"display name bytes");
        let last = announce_data.len() - 1;
        announce_data[last] ^= 0xFF;

        let err = verify_distro_announce(&announce_data, false, &pubkey)
            .expect_err("modified app data must invalidate the signature");

        assert!(
            err.contains("signature"),
            "expected a signature error, got: {err}"
        );
    }

    #[test]
    fn verify_rejects_an_announce_for_a_non_delivery_aspect() {
        // Guards against using this endpoint to announce e.g. a propagation
        // node under the distro key.
        let identity = Identity::new(true);
        let pubkey = identity.get_public_key().expect("public key");
        let destination = Destination::new_outbound(
            Some(identity.clone()),
            DestinationType::Single,
            "lxmf".to_string(),
            vec!["propagation".to_string()],
        )
        .expect("destination");

        let public_key = identity.get_public_key().expect("public key");
        let random_hash = vec![0x5Au8; 10];
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&destination.hash);
        signed_data.extend_from_slice(&public_key);
        signed_data.extend_from_slice(&destination.name_hash);
        signed_data.extend_from_slice(&random_hash);
        let signature = identity.sign(&signed_data);

        let mut announce_data = Vec::new();
        announce_data.extend_from_slice(&public_key);
        announce_data.extend_from_slice(&destination.name_hash);
        announce_data.extend_from_slice(&random_hash);
        announce_data.extend_from_slice(&signature);

        let err = verify_distro_announce(&announce_data, false, &pubkey)
            .expect_err("only lxmf.delivery announces may be replayed");

        assert!(
            err.contains("name_hash"),
            "expected an aspect error, got: {err}"
        );
    }

    #[test]
    fn verify_rejects_a_truncated_announce() {
        let identity = Identity::new(true);
        let pubkey = identity.get_public_key().expect("public key");
        let (announce_data, _) = build_announce(&identity, b"");

        let err = verify_distro_announce(&announce_data[..100], false, &pubkey)
            .expect_err("a short announce must not be indexed out of bounds");

        assert!(err.contains("len"), "expected a length error, got: {err}");
    }

    #[test]
    fn verify_rejects_a_ratchet_announce_claiming_no_ratchet() {
        // The ratchet flag shifts where the signature starts, so a mismatched
        // flag must fail rather than silently misparse.
        let identity = Identity::new(true);
        let pubkey = identity.get_public_key().expect("public key");
        let (announce_data, _) = build_announce(&identity, b"");

        let err = verify_distro_announce(&announce_data, true, &pubkey)
            .expect_err("claiming a ratchet that is not present must be rejected");

        assert!(
            err.contains("len") || err.contains("signature"),
            "expected a parse or signature error, got: {err}"
        );
    }

    #[test]
    fn announce_payload_framing_round_trips_the_client_format() {
        // Mirrors what app.js sends: flags(1) then the announce bytes.
        let identity = Identity::new(true);
        let pubkey = identity.get_public_key().expect("public key");
        let (announce_data, expected_hash) = build_announce(&identity, b"");

        let mut value = vec![0x00];
        value.extend_from_slice(&announce_data);
        let (ratchet, parsed) =
            parse_distro_announce_payload(&value).expect("framing must parse");

        assert!(!ratchet, "flags bit 0 clear means no ratchet");
        let hash = verify_distro_announce(&parsed, ratchet, &pubkey)
            .expect("the unframed announce must still verify");
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn announce_payload_framing_reads_the_ratchet_flag() {
        let (ratchet, parsed) =
            parse_distro_announce_payload(&[0x01, 0xAA, 0xBB]).expect("framing must parse");

        assert!(ratchet, "flags bit 0 set means a ratchet is present");
        assert_eq!(parsed, vec![0xAA, 0xBB], "flags byte must not leak into the announce");
    }

    #[test]
    fn announce_payload_framing_rejects_an_empty_value() {
        assert!(
            parse_distro_announce_payload(&[]).is_err(),
            "an empty value must not panic on the flags byte"
        );
    }

    #[test]
    fn announce_store_replaces_on_resubmission() {
        let path = temp_path("announce_replace");
        let _ = std::fs::remove_file(&path);
        let mut store = DistroAnnounceStore::load(path);
        let hash = dummy_hash(0xAB);

        store.put(hash.clone(), vec![0x01; 200], false);
        store.put(hash.clone(), vec![0x02; 200], true);

        assert_eq!(store.len(), 1, "a resubmission must replace, not accumulate");
        let held = store.get(&hash).expect("announce present");
        assert_eq!(held.announce_data[0], 0x02, "the newest announce must win");
        assert!(held.ratchet, "the ratchet flag must be updated too");
    }

    #[test]
    fn announce_store_round_trips_through_disk() {
        let path = temp_path("announce_persist");
        let _ = std::fs::remove_file(&path);
        let hash = dummy_hash(0xCD);
        {
            let mut store = DistroAnnounceStore::load(path.clone());
            store.put(hash.clone(), vec![0x07; 180], true);
        }

        let reloaded = DistroAnnounceStore::load(path);

        let held = reloaded.get(&hash).expect("announce must survive a restart");
        assert_eq!(held.announce_data, vec![0x07; 180]);
        assert!(held.ratchet);
    }

    #[test]
    fn announce_store_remove_drops_the_entry() {
        let path = temp_path("announce_remove");
        let _ = std::fs::remove_file(&path);
        let mut store = DistroAnnounceStore::load(path);
        let hash = dummy_hash(0xEF);
        store.put(hash.clone(), vec![0x01; 180], false);

        store.remove(&hash);

        assert!(store.get(&hash).is_none(), "removed announce must be gone");
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn register_and_get_devices() {
        let mut t = make_table("reg_get");
        let distro_hash = dummy_hash(0xAA);
        let dev_hash = dummy_hash(0x11);
        let dev_pubkey = dummy_pubkey(0x11);

        t.register(distro_hash.clone(), dev_hash.clone(), dev_pubkey.clone());

        let devices = t.get_devices(&distro_hash);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].distro_lxmf_hash, distro_hash);
        assert_eq!(devices[0].device_lxmf_hash, dev_hash);
        assert_eq!(devices[0].device_pubkey, dev_pubkey);
    }

    #[test]
    fn register_is_idempotent() {
        let mut t = make_table("idemp");
        let dh = dummy_hash(0xAA);
        let dev_h = dummy_hash(0x11);
        let pk = dummy_pubkey(0x11);

        t.register(dh.clone(), dev_h.clone(), pk.clone());
        t.register(dh.clone(), dev_h.clone(), pk.clone());
        t.register(dh.clone(), dev_h.clone(), pk.clone());

        assert_eq!(t.get_devices(&dh).len(), 1);
    }

    #[test]
    fn multiple_devices_per_distro() {
        let mut t = make_table("multi");
        let dh = dummy_hash(0xAA);

        t.register(dh.clone(), dummy_hash(0x11), dummy_pubkey(0x11));
        t.register(dh.clone(), dummy_hash(0x22), dummy_pubkey(0x22));
        t.register(dh.clone(), dummy_hash(0x33), dummy_pubkey(0x33));

        assert_eq!(t.get_devices(&dh).len(), 3);
    }

    #[test]
    fn unregister_removes_device() {
        let mut t = make_table("unreg");
        let dh = dummy_hash(0xAA);
        let d1 = dummy_hash(0x11);
        let d2 = dummy_hash(0x22);

        t.register(dh.clone(), d1.clone(), dummy_pubkey(0x11));
        t.register(dh.clone(), d2.clone(), dummy_pubkey(0x22));
        assert_eq!(t.get_devices(&dh).len(), 2);

        t.unregister(&dh, &d1);
        let remaining = t.get_devices(&dh);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].device_lxmf_hash, d2);
    }

    #[test]
    fn unregister_nonexistent_is_noop() {
        let mut t = make_table("unreg_noop");
        let dh = dummy_hash(0xAA);
        t.register(dh.clone(), dummy_hash(0x11), dummy_pubkey(0x11));
        t.unregister(&dh, &dummy_hash(0xFF));
        assert_eq!(t.get_devices(&dh).len(), 1);
    }

    #[test]
    fn is_distro_positive_and_negative() {
        let mut t = make_table("is_distro");
        let dh = dummy_hash(0xAA);

        assert!(!t.is_distro(&dh));
        t.register(dh.clone(), dummy_hash(0x11), dummy_pubkey(0x11));
        assert!(t.is_distro(&dh));
        assert!(!t.is_distro(&dummy_hash(0xBB)));
    }

    #[test]
    fn registered_distro_hashes_is_distinct_set() {
        let mut t = make_table("hashes");
        let dh1 = dummy_hash(0xAA);
        let dh2 = dummy_hash(0xBB);

        t.register(dh1.clone(), dummy_hash(0x11), dummy_pubkey(0x11));
        t.register(dh2.clone(), dummy_hash(0x22), dummy_pubkey(0x22));
        t.register(dh1.clone(), dummy_hash(0x33), dummy_pubkey(0x33)); // second device, same distro

        let hashes = t.registered_distro_hashes();
        assert_eq!(hashes.len(), 2);
        assert!(hashes.contains(&dh1));
        assert!(hashes.contains(&dh2));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let path = temp_path("roundtrip");
        let _ = std::fs::remove_file(&path);

        let dh = dummy_hash(0xAA);
        let dev_h = dummy_hash(0x11);
        let pk = dummy_pubkey(0x11);

        // Write
        {
            let mut t = DistroTable::load(path.clone());
            t.register(dh.clone(), dev_h.clone(), pk.clone());
            assert_eq!(t.get_devices(&dh).len(), 1);
        }

        // Read back from disk
        {
            let t = DistroTable::load(path.clone());
            let devices = t.get_devices(&dh);
            assert_eq!(devices.len(), 1, "distro entry should survive save/load");
            assert_eq!(devices[0].distro_lxmf_hash, dh);
            assert_eq!(devices[0].device_lxmf_hash, dev_h);
            assert_eq!(devices[0].device_pubkey, pk);
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_table_returns_zero_len() {
        let t = make_table("empty");
        assert_eq!(t.len(), 0);
        assert!(t.get_devices(&dummy_hash(0xAA)).is_empty());
        assert!(t.registered_distro_hashes().is_empty());
    }

    #[test]
    fn get_devices_returns_only_matching_distro() {
        let mut t = make_table("match");
        let dh1 = dummy_hash(0xAA);
        let dh2 = dummy_hash(0xBB);

        t.register(dh1.clone(), dummy_hash(0x11), dummy_pubkey(0x11));
        t.register(dh2.clone(), dummy_hash(0x22), dummy_pubkey(0x22));

        let devices = t.get_devices(&dh1);
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_lxmf_hash, dummy_hash(0x11));
    }
}

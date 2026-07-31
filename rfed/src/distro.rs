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
use reticulum_rust::packet::{Packet, DATA, NONE, HEADER_1, FLAG_UNSET};
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
pub fn distro_fanout(
    distro_lxmf_hash: &[u8],
    lxmf_blob: &[u8],
    distro_table: &DistroTable,
    hook_registry: &HookRegistry,
    propagation_streams: Option<&Arc<Mutex<PropagationStreamRegistry>>>,
) -> Vec<Vec<u8>> {
    let devices = distro_table.get_devices(distro_lxmf_hash);

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

    for entry in &devices {
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
                log(
                    format!(
                        "[distro] no interface for device {} — will defer",
                        hexrep(&entry.device_lxmf_hash, false)
                    ),
                    LOG_WARNING,
                    false,
                    false,
                );
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
            }
        }

        hook_registry.on_deliver(&device_id_hash, lxmf_blob);
    }

    missed
}

// ── Helpers ──────────────────────────────────────────────────────────────────

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

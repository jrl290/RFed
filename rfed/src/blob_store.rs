//! Inner-blob store backed by the filesystem.
//!
//! Layout:
//!   {storage_dir}/{dest_hex}/{msg_id_hex}
//!
//! Each file IS the raw inner blob — no envelope, no framing.
//! The in-memory index is rebuilt from the directory tree at startup.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use reticulum_rust::{log, LOG_NOTICE};

const BLOB_TTL_SECS: f64 = 30.0 * 24.0 * 3600.0; // evict blobs older than 30 days
const EVICT_CHECK_INTERVAL_SECS: f64 = 3600.0;    // check for expired blobs at most once per hour

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Metadata kept in memory for each stored blob.
#[derive(Clone, Serialize, Deserialize)]
pub struct BlobMeta {
    /// 16-byte random message ID
    pub message_id: Vec<u8>,
    /// 16-byte truncated destination hash (channel or direct dest)
    pub destination_hash: Vec<u8>,
    /// When the blob was received (Unix timestamp, float seconds)
    pub received: f64,
    /// Byte length of the inner blob
    pub size: usize,
}

pub struct BlobStore {
    pub storage_dir: PathBuf,
    /// In-memory index: message_id → metadata
    pub index: HashMap<Vec<u8>, BlobMeta>,
    pub storage_limit_bytes: u64,
    pub used_bytes: u64,
    last_eviction: f64,
}

impl BlobStore {
    /// Create (or reopen) a BlobStore and rebuild the index from disk.
    pub fn open(storage_dir: PathBuf, storage_limit_bytes: u64) -> Self {
        let mut store = BlobStore {
            storage_dir,
            index: HashMap::new(),
            storage_limit_bytes,
            used_bytes: 0,
            last_eviction: 0.0,
        };
        store.rebuild_index();
        store
    }

    /// Persist an inner blob.  Returns the new message_id (16 random bytes).
    /// Returns an error if the storage limit would be exceeded.
    pub fn store(
        &mut self,
        destination_hash: &[u8],
        blob: &[u8],
    ) -> Result<Vec<u8>, String> {
        let blob_size = blob.len() as u64;

        // Periodic TTL eviction — runs at most once per EVICT_CHECK_INTERVAL_SECS.
        let t = now();
        if t - self.last_eviction > EVICT_CHECK_INTERVAL_SECS {
            self.evict_older_than(t - BLOB_TTL_SECS);
            self.last_eviction = t;
        }

        // If still over limit, evict oldest blobs to make room.
        if self.used_bytes + blob_size > self.storage_limit_bytes {
            self.evict_to_fit(blob_size);
        }

        if self.used_bytes + blob_size > self.storage_limit_bytes {
            return Err(format!(
                "Storage limit reached ({}/{} bytes)",
                self.used_bytes, self.storage_limit_bytes
            ));
        }

        // 16-byte random message ID
        let mut message_id = vec![0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut message_id);

        let dest_dir = self.storage_dir.join(hex(destination_hash));
        std::fs::create_dir_all(&dest_dir)
            .map_err(|e| format!("create_dir_all({:?}): {e}", dest_dir))?;

        let blob_path = dest_dir.join(hex(&message_id));
        std::fs::write(&blob_path, blob)
            .map_err(|e| format!("write blob {:?}: {e}", blob_path))?;

        let meta = BlobMeta {
            message_id: message_id.clone(),
            destination_hash: destination_hash.to_vec(),
            received: now(),
            size: blob.len(),
        };
        self.index.insert(message_id.clone(), meta);
        self.used_bytes += blob_size;

        Ok(message_id)
    }

    /// Read a blob from disk by its message_id.  Returns `None` if unknown.
    pub fn get(&self, message_id: &[u8]) -> Option<Vec<u8>> {
        let meta = self.index.get(message_id)?;
        let path = self.blob_path(&meta.destination_hash, message_id);
        std::fs::read(&path).ok()
    }

    /// All known message IDs (for sync manifest generation).
    pub fn all_message_ids(&self) -> Vec<Vec<u8>> {
        self.index.keys().cloned().collect()
    }

    /// All message IDs for blobs stored under the given channel hash.
    pub fn message_ids_for_channel(&self, channel_hash: &[u8]) -> Vec<Vec<u8>> {
        self.index.values()
            .filter(|m| m.destination_hash.as_slice() == channel_hash)
            .map(|m| m.message_id.clone())
            .collect()
    }

    /// Delete a blob from disk and remove it from the index.
    pub fn delete(&mut self, message_id: &[u8]) {
        if let Some(meta) = self.index.remove(message_id) {
            let path = self.blob_path(&meta.destination_hash, message_id);
            let _ = std::fs::remove_file(&path);
            self.used_bytes = self.used_bytes.saturating_sub(meta.size as u64);
        }
    }
    /// Evict all blobs whose `received` timestamp is older than `cutoff`.
    /// Blobs with `received == 0.0` (unknown age) are never evicted here;
    /// use `evict_to_fit` to free space unconditionally.
    pub fn evict_older_than(&mut self, cutoff: f64) -> usize {
        let stale: Vec<Vec<u8>> = self.index.values()
            .filter(|m| m.received > 0.0 && m.received < cutoff)
            .map(|m| m.message_id.clone())
            .collect();
        let count = stale.len();
        for msg_id in stale {
            self.delete(&msg_id);
        }
        if count > 0 {
            log(
                format!("[blob_store] evicted {count} expired blob(s)"),
                LOG_NOTICE, false, false,
            );
        }
        count
    }

    /// Evict the oldest blobs (by `received` timestamp) until there is room
    /// for `needed_bytes` more data.  Blobs with unknown age (`received == 0.0`)
    /// are evicted last.
    fn evict_to_fit(&mut self, needed_bytes: u64) {
        if self.used_bytes + needed_bytes <= self.storage_limit_bytes {
            return;
        }
        let mut entries: Vec<(Vec<u8>, f64)> = self.index.values()
            .map(|m| (m.message_id.clone(), m.received))
            .collect();
        // Oldest known-age blobs first; unknown-age (0.0) blobs last.
        entries.sort_by(|a, b| {
            let ra = if a.1 == 0.0 { f64::MAX } else { a.1 };
            let rb = if b.1 == 0.0 { f64::MAX } else { b.1 };
            ra.partial_cmp(&rb).unwrap_or(std::cmp::Ordering::Equal)
        });
        let mut evicted = 0usize;
        for (msg_id, _) in entries {
            if self.used_bytes + needed_bytes <= self.storage_limit_bytes {
                break;
            }
            self.delete(&msg_id);
            evicted += 1;
        }
        if evicted > 0 {
            log(
                format!("[blob_store] evicted {evicted} blob(s) to free space"),
                LOG_NOTICE, false, false,
            );
        }
    }
    // ── private helpers ──────────────────────────────────────────────

    fn blob_path(&self, destination_hash: &[u8], message_id: &[u8]) -> PathBuf {
        self.storage_dir.join(hex(destination_hash)).join(hex(message_id))
    }

    /// Walk storage_dir and rebuild the in-memory index from what's on disk.
    fn rebuild_index(&mut self) {
        let Ok(dest_entries) = std::fs::read_dir(&self.storage_dir) else { return };
        for dest_entry in dest_entries.flatten() {
            let dest_hex = dest_entry.file_name().to_string_lossy().to_string();
            let destination_hash = match reticulum_rust::decode_hex(&dest_hex) {
                Some(h) => h,
                None => continue,
            };
            let Ok(msg_entries) = std::fs::read_dir(dest_entry.path()) else { continue };
            for msg_entry in msg_entries.flatten() {
                let msg_hex = msg_entry.file_name().to_string_lossy().to_string();
                let message_id = match reticulum_rust::decode_hex(&msg_hex) {
                    Some(id) => id,
                    None => continue,
                };
                let (size, received) = msg_entry.metadata()
                    .map(|m| {
                        let size = m.len() as usize;
                        let received = m.modified()
                            .ok()
                            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                            .map(|d| d.as_secs_f64())
                            .unwrap_or(0.0);
                        (size, received)
                    })
                    .unwrap_or((0, 0.0));
                self.used_bytes += size as u64;
                self.index.insert(message_id.clone(), BlobMeta {
                    message_id,
                    destination_hash: destination_hash.clone(),
                    received,
                    size,
                });
            }
        }
    }
}

//! Deferred delivery queue.
//!
//! When a subscriber's identity is not yet known to the local Reticulum
//! node (i.e. `Identity::recall` returns `None`), the inner blob cannot be
//! delivered immediately.  The blob is held here and flushed the moment we
//! hear the subscriber announce itself on the network.
//!
//! # Storage format
//!
//! On disk: msgpack-encoded `Vec<DeferredEntry>`.
//! In memory: a `HashMap<subscriber_hash, VecDeque<PendingBlob>>`.
//!
//! Each `PendingBlob` stores the channel hash alongside the raw inner blob
//! so the delivery packet can be correctly addressed when flushing.
//!
//! # Backup-node note
//!
//! This queue is strictly per-node (never synced between federation nodes).
//! When the watchdog/failover backup mechanism is implemented, the backup
//! node will maintain its own shadow copy of subscriptions and will run its
//! own deferred queue for the subscribers it covers — keeping the semantics
//! identical to a primary node but fired only when the primary is silent.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

// ── Wire representation (for msgpack serialisation) ───────────────────────────

/// A single deferred delivery record as stored on disk.
#[derive(Clone, Serialize, Deserialize)]
struct DeferredEntry {
    /// 16-byte truncated RNS destination hash of the subscriber.
    subscriber_hash: Vec<u8>,
    /// 16-byte channel destination hash (used to re-address the packet).
    channel_hash: Vec<u8>,
    /// Raw inner blob (stamp already stripped).
    blob: Vec<u8>,
    /// Unix timestamp (seconds) when the entry was originally enqueued.
    enqueued_at: f64,
}

// ── In-memory pending blob ────────────────────────────────────────────────────

#[derive(Clone)]
pub struct PendingBlob {
    pub channel_hash: Vec<u8>,
    pub blob: Vec<u8>,
    pub enqueued_at: f64,
}

// ── DeferredQueue ─────────────────────────────────────────────────────────────

/// In-memory queue with disk backing; keyed by subscriber destination hash.
pub struct DeferredQueue {
    /// `subscriber_hash → ordered list of pending blobs`.
    queue: HashMap<Vec<u8>, VecDeque<PendingBlob>>,
    file_path: PathBuf,
    /// Maximum total entries across all subscribers.
    pub global_limit: usize,
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

impl DeferredQueue {
    /// Load (or create) a queue backed by `file_path`.
    pub fn load(file_path: PathBuf) -> Self {
        let entries: Vec<DeferredEntry> = if file_path.exists() {
            std::fs::read(&file_path)
                .ok()
                .and_then(|b| rmp_serde::from_slice(&b).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let mut queue: HashMap<Vec<u8>, VecDeque<PendingBlob>> = HashMap::new();
        for e in entries {
            queue.entry(e.subscriber_hash).or_default().push_back(PendingBlob {
                channel_hash: e.channel_hash,
                blob: e.blob,
                enqueued_at: e.enqueued_at,
            });
        }

        DeferredQueue {
            queue,
            file_path,
            global_limit: 4096,
        }
    }

    /// Enqueue a blob for a subscriber who is currently unreachable.
    ///
    /// `per_subscriber_limit` is supplied by the caller and should come from
    /// `NodeConfig::policy_for(subscriber_hash).deferred_queue_limit` so that
    /// VIP subscribers get a larger budget than regular ones.
    ///
    /// If the per-subscriber limit is hit, the *oldest* entry is evicted first.
    /// If the global limit would then still be exceeded, the enqueue is skipped
    /// entirely (back-pressure).
    pub fn enqueue(
        &mut self,
        subscriber_hash: Vec<u8>,
        channel_hash: Vec<u8>,
        blob: Vec<u8>,
        per_subscriber_limit: usize,
    ) {
        // Global back-pressure check.
        if self.total_len() >= self.global_limit {
            return;
        }

        let bucket = self.queue.entry(subscriber_hash).or_default();

        // Per-subscriber overflow: drop oldest.
        if bucket.len() >= per_subscriber_limit {
            bucket.pop_front();
        }

        bucket.push_back(PendingBlob {
            channel_hash,
            blob,
            enqueued_at: now(),
        });

        let _ = self.save();
    }

    /// Drain and return all pending blobs for `subscriber_hash`.
    ///
    /// The entries are removed from the queue.  The caller is responsible
    /// for actually delivering them; if delivery fails the caller may
    /// re-enqueue with `enqueue`.
    pub fn drain(&mut self, subscriber_hash: &[u8]) -> Vec<PendingBlob> {
        let removed: Vec<PendingBlob> = self
            .queue
            .remove(subscriber_hash)
            .map(|d| d.into_iter().collect())
            .unwrap_or_default();
        if !removed.is_empty() {
            let _ = self.save();
        }
        removed
    }

    /// Total number of entries across all subscribers.
    pub fn total_len(&self) -> usize {
        self.queue.values().map(|v| v.len()).sum()
    }

    /// Whether there are any pending entries for `subscriber_hash`.
    pub fn has_pending(&self, subscriber_hash: &[u8]) -> bool {
        self.queue.get(subscriber_hash).map(|v| !v.is_empty()).unwrap_or(false)
    }

    /// Flush expired entries older than `max_age_secs`.  Call periodically
    /// to prevent indefinite accumulation for gone-forever subscribers.
    pub fn evict_expired(&mut self, max_age_secs: f64) {
        let threshold = now() - max_age_secs;
        let mut changed = false;
        for bucket in self.queue.values_mut() {
            let before = bucket.len();
            bucket.retain(|e| e.enqueued_at >= threshold);
            if bucket.len() != before {
                changed = true;
            }
        }
        // Remove now-empty buckets.
        self.queue.retain(|_, v| !v.is_empty());
        if changed {
            let _ = self.save();
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let entries: Vec<DeferredEntry> = self
            .queue
            .iter()
            .flat_map(|(sub_hash, bucket)| {
                bucket.iter().map(|pb| DeferredEntry {
                    subscriber_hash: sub_hash.clone(),
                    channel_hash: pb.channel_hash.clone(),
                    blob: pb.blob.clone(),
                    enqueued_at: pb.enqueued_at,
                })
            })
            .collect();
        let bytes = rmp_serde::to_vec(&entries)
            .map_err(|e| format!("DeferredQueue serialize: {e}"))?;
        std::fs::write(&self.file_path, &bytes)
            .map_err(|e| format!("DeferredQueue write: {e}"))?;
        Ok(())
    }
}

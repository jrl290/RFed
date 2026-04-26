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

    /// Drain at most `max` pending blobs for `subscriber_hash`.
    ///
    /// Unlike `drain`, this leaves any excess entries in the queue so the
    /// subscriber can retrieve them on a subsequent PULL.  The caller is
    /// responsible for actually delivering the returned blobs; if delivery
    /// fails they may re-enqueue with `enqueue`.
    pub fn drain_batch(&mut self, subscriber_hash: &[u8], max: usize) -> Vec<PendingBlob> {
        let bucket = match self.queue.get_mut(subscriber_hash) {
            Some(b) => b,
            None => return Vec::new(),
        };
        let n = bucket.len().min(max);
        let removed: Vec<PendingBlob> = bucket.drain(..n).collect();
        if bucket.is_empty() {
            self.queue.remove(subscriber_hash);
        }
        if !removed.is_empty() {
            let _ = self.save();
        }
        removed
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

// ── Tests ────────────────────────────────────────────────────────────────────
//
// Regression tests for the paged PULL semantics added when "PULL never gets
// drained" was fixed.  The contract that MUST hold:
//
//   * `drain_batch(sub, max)` removes AT MOST `max` blobs from the FRONT of
//     the bucket and returns them in FIFO order.
//   * After draining, `has_pending(sub)` reflects whether anything remains —
//     this is the `more_pending` flag the server returns to the client.
//   * Drain is destructive; bytes returned to one PULL caller cannot be
//     re-served to a subsequent PULL on the same subscriber.
//   * An empty/missing bucket yields `Vec::new()` and `has_pending=false`.

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tmp_path() -> PathBuf {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "rfed_deferred_test_{}_{}.rmp",
            std::process::id(),
            n
        ))
    }

    fn fresh_queue() -> DeferredQueue {
        let p = tmp_path();
        let _ = std::fs::remove_file(&p);
        DeferredQueue::load(p)
    }

    fn enqueue_n(q: &mut DeferredQueue, sub: &[u8], chan: &[u8], n: usize) {
        for i in 0..n {
            q.enqueue(sub.to_vec(), chan.to_vec(), vec![i as u8], 1024);
        }
    }

    #[test]
    fn drain_batch_returns_at_most_max_in_fifo_order() {
        let mut q = fresh_queue();
        let sub = vec![0xAAu8; 16];
        let chan = vec![0xBBu8; 16];
        enqueue_n(&mut q, &sub, &chan, 30);

        let page = q.drain_batch(&sub, 25);
        assert_eq!(page.len(), 25, "first page should contain exactly 25");
        // FIFO: oldest first → blob bytes should be 0..=24.
        for (i, pb) in page.iter().enumerate() {
            assert_eq!(pb.blob, vec![i as u8]);
            assert_eq!(pb.channel_hash, chan);
        }
        assert!(q.has_pending(&sub), "5 entries remain after first page");

        let page2 = q.drain_batch(&sub, 25);
        assert_eq!(page2.len(), 5, "second page returns the remainder");
        for (i, pb) in page2.iter().enumerate() {
            assert_eq!(pb.blob, vec![(25 + i) as u8]);
        }
        assert!(!q.has_pending(&sub), "queue exhausted after final page");
    }

    #[test]
    fn drain_batch_is_destructive() {
        // Once a PULL has drained N blobs, a second PULL with the same `max`
        // MUST NOT return the same bytes again.
        let mut q = fresh_queue();
        let sub = vec![0x11u8; 16];
        let chan = vec![0x22u8; 16];
        enqueue_n(&mut q, &sub, &chan, 5);

        let first = q.drain_batch(&sub, 3);
        let second = q.drain_batch(&sub, 3);
        assert_eq!(first.len(), 3);
        assert_eq!(second.len(), 2);
        // No overlap.
        let first_bytes: Vec<u8> = first.iter().map(|b| b.blob[0]).collect();
        let second_bytes: Vec<u8> = second.iter().map(|b| b.blob[0]).collect();
        for b in &second_bytes {
            assert!(!first_bytes.contains(b), "byte {b} returned twice");
        }
        assert!(!q.has_pending(&sub));
    }

    #[test]
    fn drain_batch_empty_bucket_yields_empty_and_no_pending() {
        let mut q = fresh_queue();
        let sub = vec![0xCCu8; 16];
        assert_eq!(q.drain_batch(&sub, 25).len(), 0);
        assert!(!q.has_pending(&sub));
    }

    #[test]
    fn drain_batch_max_zero_returns_nothing_and_preserves_bucket() {
        let mut q = fresh_queue();
        let sub = vec![0xDDu8; 16];
        let chan = vec![0xEEu8; 16];
        enqueue_n(&mut q, &sub, &chan, 4);

        let page = q.drain_batch(&sub, 0);
        assert_eq!(page.len(), 0);
        assert!(q.has_pending(&sub), "max=0 must not drain anything");
        assert_eq!(q.total_len(), 4);
    }

    #[test]
    fn has_pending_is_per_subscriber() {
        let mut q = fresh_queue();
        let sub_a = vec![1u8; 16];
        let sub_b = vec![2u8; 16];
        let chan = vec![3u8; 16];
        enqueue_n(&mut q, &sub_a, &chan, 2);
        assert!(q.has_pending(&sub_a));
        assert!(!q.has_pending(&sub_b));
    }

    #[test]
    fn drain_batch_does_not_affect_other_subscribers() {
        let mut q = fresh_queue();
        let sub_a = vec![0xA1u8; 16];
        let sub_b = vec![0xB2u8; 16];
        let chan = vec![0xC3u8; 16];
        enqueue_n(&mut q, &sub_a, &chan, 5);
        enqueue_n(&mut q, &sub_b, &chan, 7);

        let _ = q.drain_batch(&sub_a, 100);
        assert!(!q.has_pending(&sub_a));
        assert!(q.has_pending(&sub_b));
        assert_eq!(q.total_len(), 7);
    }

    #[test]
    fn enqueue_persists_and_reload_preserves_order() {
        let p = tmp_path();
        let _ = std::fs::remove_file(&p);
        {
            let mut q = DeferredQueue::load(p.clone());
            let sub = vec![0xFFu8; 16];
            let chan = vec![0x00u8; 16];
            for i in 0..3u8 {
                q.enqueue(sub.clone(), chan.clone(), vec![i], 1024);
            }
        }
        let mut q2 = DeferredQueue::load(p.clone());
        let sub = vec![0xFFu8; 16];
        let page = q2.drain_batch(&sub, 10);
        assert_eq!(page.len(), 3);
        assert_eq!(page[0].blob, vec![0]);
        assert_eq!(page[2].blob, vec![2]);
        let _ = std::fs::remove_file(&p);
    }
}

//! Deferred delivery queue.
//!
//! When a subscriber's identity is not yet known to the local Reticulum
//! node (i.e. `Identity::recall` returns `None`), the inner blob cannot be
//! delivered immediately.  The blob is held here and flushed the moment we
//! hear the subscriber announce itself on the network.
//!
//! # Storage format
//!
//! On disk: `deferred_delivery.sqlite3`, one row per queued blob, its rowid
//! giving FIFO order (crate::store_db); each enqueue, eviction and drain
//! writes only its own rows. Until 2026-09-26 a msgpack `Vec<DeferredEntry>`
//! rewritten whole on every change (imported once if still present).
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

/// A single deferred delivery record as the old msgpack file stored it.
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
    /// Its row in the database (0 when it was not stored).
    id: i64,
}

// ── What a change to the queue came to ────────────────────────────────────────

/// What [`DeferredQueue::enqueue`] did with a blob (RFed SPEC §7 "Limits").
/// The queue itself logs nothing: the hand-off that asked says what became
/// of the blob, so every drop speaks once, under the recipient and routing
/// hash it was meant for (DESIGN_PRINCIPLES §2). Until 2026-10-10 an enqueue
/// at the global limit returned without a word, and the hand-off logged
/// "queued" anyway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// Queued.
    Queued,
    /// Queued, after the subscriber's oldest entry was evicted to stay within
    /// its per-subscriber limit. `evicted_routing_hash` is that entry's
    /// routing hash (a channel's hash, or a distro's `lxmf.delivery` hash).
    QueuedEvictingOldest { evicted_routing_hash: Vec<u8> },
    /// Not queued: the whole queue already holds `global_limit` entries.
    RefusedGlobalLimit,
}

impl EnqueueOutcome {
    /// Whether the blob is in the queue now.
    pub fn queued(&self) -> bool {
        !matches!(self, EnqueueOutcome::RefusedGlobalLimit)
    }
}

/// What a run of enqueues for one subscriber came to
/// ([`DeferredQueue::enqueue_all`]), for the callers that queue several
/// blobs at once: the backup node adopting an offline owner's subscriber, and
/// the announce flush putting back what it could not send. Their drops speak
/// as a hand-off's do ([`EnqueueTally::loss_lines`], RFed SPEC §7 "Limits").
/// Until 2026-10-10 they ignored the outcome, and the backup line counted a
/// refused blob as queued.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EnqueueTally {
    /// In the queue now.
    pub queued: usize,
    /// Of those, how many evicted the subscriber's oldest entry to fit.
    pub evicted: usize,
    /// Refused at the global limit: lost to the pull.
    pub refused: usize,
}

impl EnqueueTally {
    /// Count one enqueue's outcome.
    pub fn add(&mut self, outcome: &EnqueueOutcome) {
        match outcome {
            EnqueueOutcome::Queued => self.queued += 1,
            EnqueueOutcome::QueuedEvictingOldest { .. } => {
                self.queued += 1;
                self.evicted += 1;
            }
            EnqueueOutcome::RefusedGlobalLimit => self.refused += 1,
        }
    }

    /// The lines for what the run lost, for the caller to log with every
    /// lock released: a WARNING for the blobs the global limit refused, a
    /// NOTICE for the older entries evicted to make room. `tag` begins each
    /// line (`[backup]`, `[deferred]`); `why` says what the blobs were.
    pub fn loss_lines(&self, tag: &str, subscriber_hash: &[u8], why: &str) -> Vec<(i32, String)> {
        let subscriber = reticulum_rust::hexrep(subscriber_hash, false);
        let mut lines = Vec::new();
        if self.refused > 0 {
            lines.push((
                reticulum_rust::LOG_WARNING,
                format!(
                    "{tag} {} blob(s) for {subscriber} ({why}) NOT queued: global limit, lost to the pull",
                    self.refused,
                ),
            ));
        }
        if self.evicted > 0 {
            lines.push((
                reticulum_rust::LOG_NOTICE,
                format!(
                    "{tag} {subscriber} bucket full: its {} oldest entry(ies) evicted to queue blob(s) ({why})",
                    self.evicted,
                ),
            ));
        }
        lines
    }
}

/// The entries [`DeferredQueue::evict_expired`] removed for one subscriber and
/// one routing hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Expired {
    /// The bucket: a distro device's or a channel subscriber's identity hash.
    pub subscriber_hash: Vec<u8>,
    /// A channel's hash, or a distro's `lxmf.delivery` hash.
    pub routing_hash: Vec<u8>,
    /// How many of its entries expired unpulled.
    pub count: usize,
}

/// The log lines for entries that expired unpulled, one per subscriber and
/// routing hash: a WARNING for a distro registered here (`is_distro`), whose
/// device lost its sync or mail, and a NOTICE otherwise. `max_age_secs` is the
/// age they were evicted at. The caller logs them with every lock released.
pub fn expiry_lines(
    expired: &[Expired],
    is_distro: impl Fn(&[u8]) -> bool,
    max_age_secs: f64,
) -> Vec<(i32, String)> {
    let age = if max_age_secs >= 86_400.0 && max_age_secs % 86_400.0 == 0.0 {
        format!("{} days", (max_age_secs / 86_400.0) as u64)
    } else {
        format!("{max_age_secs:.0} s")
    };
    expired
        .iter()
        .map(|e| {
            let subscriber = reticulum_rust::hexrep(&e.subscriber_hash, false);
            let routing = reticulum_rust::hexrep(&e.routing_hash, false);
            if is_distro(&e.routing_hash) {
                (
                    reticulum_rust::LOG_WARNING,
                    format!(
                        "[deferred] {} distro blob(s) for device {subscriber} of {routing} expired unpulled after {age}",
                        e.count,
                    ),
                )
            } else {
                (
                    reticulum_rust::LOG_NOTICE,
                    format!(
                        "[deferred] {} blob(s) for {subscriber} on {routing} expired unpulled after {age}",
                        e.count,
                    ),
                )
            }
        })
        .collect()
}

// ── DeferredQueue ─────────────────────────────────────────────────────────────

/// In-memory queue with disk backing; keyed by subscriber destination hash.
pub struct DeferredQueue {
    /// `subscriber_hash → ordered list of pending blobs`.
    queue: HashMap<Vec<u8>, VecDeque<PendingBlob>>,
    db: Option<rusqlite::Connection>,
    /// Maximum total entries across all subscribers.
    pub global_limit: usize,
}

const DEFERRED_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS deferred (
        id              INTEGER PRIMARY KEY,
        subscriber_hash BLOB NOT NULL,
        channel_hash    BLOB NOT NULL,
        blob            BLOB NOT NULL,
        enqueued_at     REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS deferred_subscriber ON deferred (subscriber_hash);";

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn insert_row(
    conn: &rusqlite::Connection,
    subscriber_hash: &[u8],
    channel_hash: &[u8],
    blob: &[u8],
    enqueued_at: f64,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO deferred (subscriber_hash, channel_hash, blob, enqueued_at) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![subscriber_hash, channel_hash, blob, enqueued_at],
    )?;
    Ok(conn.last_insert_rowid())
}

impl DeferredQueue {
    /// Load the queue kept beside `file_path` (the old msgpack file,
    /// imported once if present, in its order).
    pub fn load(file_path: PathBuf) -> Self {
        let db = crate::store_db::open(&file_path, DEFERRED_SCHEMA);
        let mut queue: HashMap<Vec<u8>, VecDeque<PendingBlob>> = HashMap::new();
        match &db {
            Some(conn) => {
                crate::store_db::import_legacy(conn, &file_path, "deferred blobs", |tx, old: Vec<DeferredEntry>| {
                    for e in &old {
                        insert_row(tx, &e.subscriber_hash, &e.channel_hash, &e.blob, e.enqueued_at)?;
                    }
                    Ok(old.len())
                });
                if let Err(e) = Self::read_all(conn, &mut queue) {
                    reticulum_rust::log(
                        format!("[store] deferred blobs could not be read: {e}"),
                        reticulum_rust::LOG_ERROR,
                        false,
                        false,
                    );
                }
            }
            None => {
                let old: Vec<DeferredEntry> = crate::store_db::read_legacy(&file_path).unwrap_or_default();
                for e in old {
                    queue.entry(e.subscriber_hash).or_default().push_back(PendingBlob {
                        channel_hash: e.channel_hash,
                        blob: e.blob,
                        enqueued_at: e.enqueued_at,
                        id: 0,
                    });
                }
            }
        }

        DeferredQueue {
            queue,
            db,
            global_limit: 4096,
        }
    }

    fn read_all(
        conn: &rusqlite::Connection,
        queue: &mut HashMap<Vec<u8>, VecDeque<PendingBlob>>,
    ) -> rusqlite::Result<()> {
        let mut stmt =
            conn.prepare("SELECT id, subscriber_hash, channel_hash, blob, enqueued_at FROM deferred ORDER BY id")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let subscriber_hash: Vec<u8> = row.get(1)?;
            queue.entry(subscriber_hash).or_default().push_back(PendingBlob {
                channel_hash: row.get(2)?,
                blob: row.get(3)?,
                enqueued_at: row.get(4)?,
                id: row.get(0)?,
            });
        }
        Ok(())
    }

    /// Delete the rows of blobs that left the queue, in one transaction.
    fn delete_rows(&self, removed: &[PendingBlob], what: &str) {
        crate::store_db::write_all(self.db.as_ref(), what, |c| {
            let mut stmt = c.prepare_cached("DELETE FROM deferred WHERE id = ?1")?;
            for pb in removed.iter().filter(|pb| pb.id != 0) {
                stmt.execute([pb.id])?;
            }
            Ok(())
        });
    }

    /// Enqueue a blob for a subscriber who is currently unreachable.
    ///
    /// `per_subscriber_limit` is supplied by the caller and should come from
    /// `NodeConfig::policy_for(subscriber_hash).deferred_queue_limit` so that
    /// VIP subscribers get a larger budget than regular ones.
    ///
    /// If the queue already holds `global_limit` entries, the blob is refused
    /// (back-pressure), before any eviction. Otherwise, if the per-subscriber
    /// limit is hit, the subscriber's *oldest* entry is evicted first. The
    /// outcome says which: the caller logs it (see [`EnqueueOutcome`]).
    pub fn enqueue(
        &mut self,
        subscriber_hash: Vec<u8>,
        channel_hash: Vec<u8>,
        blob: Vec<u8>,
        per_subscriber_limit: usize,
    ) -> EnqueueOutcome {
        // Global back-pressure check.
        if self.total_len() >= self.global_limit {
            return EnqueueOutcome::RefusedGlobalLimit;
        }

        let enqueued_at = now();
        let bucket = self.queue.entry(subscriber_hash.clone()).or_default();

        // Per-subscriber overflow: drop oldest.
        let evicted = if bucket.len() >= per_subscriber_limit {
            bucket.pop_front()
        } else {
            None
        };

        // The eviction and the new row, together.
        let mut id = 0;
        crate::store_db::write_all(self.db.as_ref(), "deferred enqueue", |c| {
            if let Some(old) = evicted.as_ref().filter(|old| old.id != 0) {
                c.execute("DELETE FROM deferred WHERE id = ?1", [old.id])?;
            }
            id = insert_row(c, &subscriber_hash, &channel_hash, &blob, enqueued_at)?;
            Ok(())
        });

        bucket.push_back(PendingBlob {
            channel_hash,
            blob,
            enqueued_at,
            id,
        });
        match evicted {
            Some(old) => EnqueueOutcome::QueuedEvictingOldest { evicted_routing_hash: old.channel_hash },
            None => EnqueueOutcome::Queued,
        }
    }

    /// Enqueue each `(routing_hash, blob)` for `subscriber_hash`, in order,
    /// and tally what became of them (see [`EnqueueTally`]).
    pub fn enqueue_all(
        &mut self,
        subscriber_hash: &[u8],
        blobs: impl IntoIterator<Item = (Vec<u8>, Vec<u8>)>,
        per_subscriber_limit: usize,
    ) -> EnqueueTally {
        let mut tally = EnqueueTally::default();
        for (routing_hash, blob) in blobs {
            tally.add(&self.enqueue(subscriber_hash.to_vec(), routing_hash, blob, per_subscriber_limit));
        }
        tally
    }

    /// How many entries `subscriber_hash` has queued under `routing_hash` (a
    /// channel's hash, or a distro's `lxmf.delivery` hash): its un-pulled
    /// backlog of that kind. The bucket's other entries do not count.
    pub fn count_matching(&self, subscriber_hash: &[u8], routing_hash: &[u8]) -> usize {
        self.queue
            .get(subscriber_hash)
            .map(|bucket| bucket.iter().filter(|entry| entry.channel_hash == routing_hash).count())
            .unwrap_or(0)
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
            self.delete_rows(&removed, "deferred drain");
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
            self.delete_rows(&removed, "deferred drain");
        }
        removed
    }

    /// Drain at most `max` pending blobs for `subscriber_hash` that belong to
    /// `channel_hash`.
    ///
    /// Non-matching blobs remain queued in their original relative order.
    pub fn drain_channel_batch(
        &mut self,
        subscriber_hash: &[u8],
        channel_hash: &[u8],
        max: usize,
    ) -> Vec<PendingBlob> {
        self.drain_matching_batch(subscriber_hash, |routing| routing == channel_hash, max)
    }

    /// Drain at most `max` pending blobs for `subscriber_hash` whose routing
    /// hash (`channel_hash`: a channel's hash, or a distro's lxmf.delivery
    /// hash) satisfies `wanted`. Non-matching blobs remain queued in their
    /// original relative order.
    ///
    /// One bucket holds everything deferred for an identity, channel and
    /// distro blobs alike, so a pull that serves one kind must take only its
    /// own: until 2026-09-24 the distro pull drained the whole bucket and the
    /// clients, unwrapping every blob with the distro key, dropped the
    /// channel blobs it handed them.
    pub fn drain_matching_batch(
        &mut self,
        subscriber_hash: &[u8],
        wanted: impl Fn(&[u8]) -> bool,
        max: usize,
    ) -> Vec<PendingBlob> {
        let mut removed = Vec::new();

        let drop_bucket = {
            let bucket = match self.queue.get_mut(subscriber_hash) {
                Some(b) => b,
                None => return Vec::new(),
            };

            let mut kept = VecDeque::with_capacity(bucket.len());
            while let Some(entry) = bucket.pop_front() {
                if removed.len() < max && wanted(&entry.channel_hash) {
                    removed.push(entry);
                } else {
                    kept.push_back(entry);
                }
            }

            *bucket = kept;
            bucket.is_empty()
        };

        if drop_bucket {
            self.queue.remove(subscriber_hash);
        }
        if !removed.is_empty() {
            self.delete_rows(&removed, "deferred drain");
        }
        removed
    }

    /// Whether there are any pending entries for `subscriber_hash`.
    pub fn has_pending(&self, subscriber_hash: &[u8]) -> bool {
        self.queue.get(subscriber_hash).map(|v| !v.is_empty()).unwrap_or(false)
    }

    /// Whether there are any pending entries for `subscriber_hash` on the
    /// requested `channel_hash`.
    pub fn has_pending_channel(&self, subscriber_hash: &[u8], channel_hash: &[u8]) -> bool {
        self.has_pending_matching(subscriber_hash, |routing| routing == channel_hash)
    }

    /// Whether there are any pending entries for `subscriber_hash` whose
    /// routing hash satisfies `wanted` (see [`Self::drain_matching_batch`]).
    pub fn has_pending_matching(&self, subscriber_hash: &[u8], wanted: impl Fn(&[u8]) -> bool) -> bool {
        self.queue
            .get(subscriber_hash)
            .map(|bucket| bucket.iter().any(|entry| wanted(&entry.channel_hash)))
            .unwrap_or(false)
    }

    /// Flush expired entries older than `max_age_secs`.  Call periodically
    /// to prevent indefinite accumulation for gone-forever subscribers.
    ///
    /// Returns what was evicted, one count per subscriber and routing hash,
    /// ordered by both, for the caller to log once its locks are released
    /// ([`expiry_lines`]). Until 2026-10-10 expiry said nothing: a device that
    /// never pulled lost its entries without a line anywhere.
    pub fn evict_expired(&mut self, max_age_secs: f64) -> Vec<Expired> {
        let threshold = now() - max_age_secs;
        let mut counts: std::collections::BTreeMap<(Vec<u8>, Vec<u8>), usize> = Default::default();
        for (subscriber_hash, bucket) in self.queue.iter_mut() {
            bucket.retain(|e| {
                let keep = e.enqueued_at >= threshold;
                if !keep {
                    *counts.entry((subscriber_hash.clone(), e.channel_hash.clone())).or_default() += 1;
                }
                keep
            });
        }
        // Remove now-empty buckets.
        self.queue.retain(|_, v| !v.is_empty());
        if !counts.is_empty() {
            crate::store_db::write(self.db.as_ref(), "deferred expiry", |c| {
                c.execute("DELETE FROM deferred WHERE enqueued_at < ?1", [threshold]).map(|_| ())
            });
        }
        counts
            .into_iter()
            .map(|((subscriber_hash, routing_hash), count)| Expired { subscriber_hash, routing_hash, count })
            .collect()
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
        crate::store_db::remove_store_files(&p);
        DeferredQueue::load(p)
    }

    fn enqueue_n(q: &mut DeferredQueue, sub: &[u8], chan: &[u8], n: usize) {
        for i in 0..n {
            q.enqueue(sub.to_vec(), chan.to_vec(), vec![i as u8], 1024);
        }
    }

    /// One identity is both a channel subscriber and a distro device, so its
    /// bucket holds both kinds. The distro pull takes only the distro blobs;
    /// the channel blob stays for `/channel/pull`.
    #[test]
    fn a_distro_pull_leaves_the_channel_blobs_in_a_shared_bucket() {
        let mut q = fresh_queue();
        let identity = vec![0xA1u8; 16];
        let channel = vec![0xC1u8; 16];
        let distro = vec![0xD1u8; 16];
        q.enqueue(identity.clone(), channel.clone(), b"channel-1".to_vec(), 1024);
        q.enqueue(identity.clone(), distro.clone(), b"distro-1".to_vec(), 1024);
        q.enqueue(identity.clone(), channel.clone(), b"channel-2".to_vec(), 1024);
        q.enqueue(identity.clone(), distro.clone(), b"distro-2".to_vec(), 1024);

        let is_distro = |routing: &[u8]| routing == distro.as_slice();
        let pulled = q.drain_matching_batch(&identity, is_distro, 25);
        assert_eq!(
            pulled.iter().map(|p| p.blob.clone()).collect::<Vec<_>>(),
            vec![b"distro-1".to_vec(), b"distro-2".to_vec()],
            "only the distro blobs, oldest first"
        );
        assert!(!q.has_pending_matching(&identity, is_distro), "no distro blob left");
        assert!(q.has_pending_channel(&identity, &channel), "the channel blobs are still queued");
        let channel_pull = q.drain_channel_batch(&identity, &channel, 25);
        assert_eq!(channel_pull.len(), 2);
        assert!(!q.has_pending(&identity));
    }

    #[test]
    fn the_distro_pull_handler_drains_only_distro_blobs() {
        let source = include_str!("destinations.rs");
        let start = source.find("let pull_distro_cb = Arc::new(").expect("pull_distro_cb");
        let body = &source[start..start + source[start..].find("});").expect("end of pull_distro_cb")];
        assert!(!body.contains("drain_batch("), "a whole-bucket drain hands channel blobs to the distro clients");
        assert!(body.contains("drain_matching_batch(&subscriber_hash, is_distro, page_size)"));
        assert!(body.contains("registered_distro_hashes()"));
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
    fn drain_channel_batch_returns_only_requested_channel_in_fifo_order() {
        let mut q = fresh_queue();
        let sub = vec![0x44u8; 16];
        let chan_a = vec![0xAAu8; 16];
        let chan_b = vec![0xBBu8; 16];

        q.enqueue(sub.clone(), chan_a.clone(), vec![0], 1024);
        q.enqueue(sub.clone(), chan_b.clone(), vec![1], 1024);
        q.enqueue(sub.clone(), chan_a.clone(), vec![2], 1024);
        q.enqueue(sub.clone(), chan_b.clone(), vec![3], 1024);

        let page = q.drain_channel_batch(&sub, &chan_a, 10);
        assert_eq!(page.len(), 2);
        assert_eq!(page[0].channel_hash, chan_a);
        assert_eq!(page[0].blob, vec![0]);
        assert_eq!(page[1].channel_hash, chan_a);
        assert_eq!(page[1].blob, vec![2]);

        assert!(!q.has_pending_channel(&sub, &chan_a));
        assert!(q.has_pending_channel(&sub, &chan_b));

        let remaining = q.drain_batch(&sub, 10);
        assert_eq!(remaining.len(), 2);
        assert_eq!(remaining[0].channel_hash, chan_b);
        assert_eq!(remaining[0].blob, vec![1]);
        assert_eq!(remaining[1].channel_hash, chan_b);
        assert_eq!(remaining[1].blob, vec![3]);
    }

    #[test]
    fn drain_channel_batch_respects_max_and_channel_scoped_pending_flag() {
        let mut q = fresh_queue();
        let sub = vec![0x55u8; 16];
        let chan_a = vec![0x0Au8; 16];
        let chan_b = vec![0x0Bu8; 16];

        enqueue_n(&mut q, &sub, &chan_a, 3);
        enqueue_n(&mut q, &sub, &chan_b, 2);

        let first_page = q.drain_channel_batch(&sub, &chan_a, 2);
        assert_eq!(first_page.len(), 2);
        assert!(q.has_pending_channel(&sub, &chan_a));
        assert!(q.has_pending_channel(&sub, &chan_b));

        let second_page = q.drain_channel_batch(&sub, &chan_a, 10);
        assert_eq!(second_page.len(), 1);
        assert!(!q.has_pending_channel(&sub, &chan_a));
        assert!(q.has_pending_channel(&sub, &chan_b));
        assert!(q.has_pending(&sub));
    }

    #[test]
    fn enqueue_persists_and_reload_preserves_order() {
        let p = tmp_path();
        crate::store_db::remove_store_files(&p);
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
        crate::store_db::remove_store_files(&p);
    }

    // ── Every drop speaks (DISTRO-SYNC-PROOF-DESIGN §6.4) ────────────────

    /// At the global limit the blob is refused, before any eviction, and the
    /// outcome says so; the hand-off logs it (handoff.rs). Until 2026-10-10
    /// `enqueue` returned without a word and the hand-off logged "queued".
    #[test]
    fn an_enqueue_at_the_global_limit_is_refused_and_says_so() {
        let mut q = fresh_queue();
        q.global_limit = 3;
        let sub = vec![0x61u8; 16];
        let chan = vec![0x62u8; 16];
        for i in 0..3u8 {
            assert_eq!(q.enqueue(sub.clone(), chan.clone(), vec![i], 1024), EnqueueOutcome::Queued);
        }
        let refused = q.enqueue(vec![0x63; 16], chan.clone(), vec![9], 1024);
        assert_eq!(refused, EnqueueOutcome::RefusedGlobalLimit);
        assert!(!refused.queued());
        assert_eq!(q.total_len(), 3, "nothing added");
        assert!(!q.has_pending(&[0x63; 16]));
        // A full subscriber at the global limit is refused too: no eviction first.
        assert_eq!(q.enqueue(sub.clone(), chan.clone(), vec![10], 3), EnqueueOutcome::RefusedGlobalLimit);
        assert_eq!(q.drain(&sub).iter().map(|p| p.blob[0]).collect::<Vec<_>>(), vec![0, 1, 2], "nothing evicted");
    }

    /// Over the per-subscriber limit the oldest entry goes, and the outcome
    /// names its routing hash, so the hand-off can say what was lost.
    #[test]
    fn an_enqueue_over_the_subscriber_limit_evicts_the_oldest_and_names_it() {
        let mut q = fresh_queue();
        let sub = vec![0x71u8; 16];
        let distro = vec![0xD7u8; 16];
        let chan = vec![0xC7u8; 16];
        assert_eq!(q.enqueue(sub.clone(), distro.clone(), b"d-1".to_vec(), 2), EnqueueOutcome::Queued);
        assert_eq!(q.enqueue(sub.clone(), chan.clone(), b"c-1".to_vec(), 2), EnqueueOutcome::Queued);
        let outcome = q.enqueue(sub.clone(), chan.clone(), b"c-2".to_vec(), 2);
        assert_eq!(outcome, EnqueueOutcome::QueuedEvictingOldest { evicted_routing_hash: distro.clone() });
        assert!(outcome.queued());
        assert_eq!(q.drain(&sub).iter().map(|p| p.blob.clone()).collect::<Vec<_>>(), vec![b"c-1".to_vec(), b"c-2".to_vec()]);
    }

    /// The hand-off's 64 bound counts one device's entries for one distro:
    /// its channel posts and other subscribers' entries do not count.
    #[test]
    fn count_matching_counts_one_subscribers_entries_for_one_routing_hash() {
        let mut q = fresh_queue();
        let device = vec![0x81u8; 16];
        let other = vec![0x82u8; 16];
        let distro = vec![0xD8u8; 16];
        let chan = vec![0xC8u8; 16];
        enqueue_n(&mut q, &device, &distro, 3);
        enqueue_n(&mut q, &device, &chan, 5);
        enqueue_n(&mut q, &other, &distro, 7);
        assert_eq!(q.count_matching(&device, &distro), 3);
        assert_eq!(q.count_matching(&device, &chan), 5);
        assert_eq!(q.count_matching(&other, &distro), 7);
        assert_eq!(q.count_matching(&other, &chan), 0);
        assert_eq!(q.count_matching(&[0x83; 16], &distro), 0, "no bucket");
        let _ = q.drain_channel_batch(&device, &distro, 2);
        assert_eq!(q.count_matching(&device, &distro), 1, "a pull lowers the count");
    }

    /// Expiry returns what it evicted, per subscriber and routing hash, and
    /// keeps what is younger.
    #[test]
    fn evict_expired_returns_the_counts_per_subscriber_and_routing_hash() {
        let p = tmp_path();
        crate::store_db::remove_store_files(&p);
        let mut q = DeferredQueue::load(p.clone());
        let device = vec![0x91u8; 16];
        let other = vec![0x92u8; 16];
        let distro = vec![0xD9u8; 16];
        let chan = vec![0xC9u8; 16];
        enqueue_n(&mut q, &device, &distro, 2);
        enqueue_n(&mut q, &device, &chan, 1);
        enqueue_n(&mut q, &other, &distro, 3);

        assert!(q.evict_expired(3600.0).is_empty(), "nothing is an hour old");
        assert_eq!(q.total_len(), 6);

        // A negative age puts the threshold in the future: everything expires.
        let mut expired = q.evict_expired(-10.0);
        expired.sort_by(|a, b| (&a.subscriber_hash, &a.routing_hash).cmp(&(&b.subscriber_hash, &b.routing_hash)));
        assert_eq!(
            expired,
            vec![
                Expired { subscriber_hash: device.clone(), routing_hash: chan.clone(), count: 1 },
                Expired { subscriber_hash: device.clone(), routing_hash: distro.clone(), count: 2 },
                Expired { subscriber_hash: other.clone(), routing_hash: distro.clone(), count: 3 },
            ]
        );
        assert_eq!(q.total_len(), 0);
        assert!(q.evict_expired(-10.0).is_empty(), "each entry is counted once");
        drop(q);
        assert_eq!(DeferredQueue::load(p.clone()).total_len(), 0, "the rows are gone too");
        crate::store_db::remove_store_files(&p);
    }

    /// A distro device that lost its entries to expiry is a WARNING, naming
    /// the device and the distro; any other routing hash is a NOTICE.
    #[test]
    fn expiry_is_a_warning_for_a_distro_and_a_notice_otherwise() {
        let distro = vec![0xDAu8; 16];
        let lines = expiry_lines(
            &[
                Expired { subscriber_hash: vec![0xA1; 16], routing_hash: distro.clone(), count: 4 },
                Expired { subscriber_hash: vec![0xA2; 16], routing_hash: vec![0xCA; 16], count: 1 },
            ],
            |routing| routing == distro.as_slice(),
            7.0 * 24.0 * 3600.0,
        );
        assert_eq!(
            lines,
            vec![
                (
                    reticulum_rust::LOG_WARNING,
                    format!("[deferred] 4 distro blob(s) for device {} of {} expired unpulled after 7 days", "a1".repeat(16), "da".repeat(16)),
                ),
                (
                    reticulum_rust::LOG_NOTICE,
                    format!("[deferred] 1 blob(s) for {} on {} expired unpulled after 7 days", "a2".repeat(16), "ca".repeat(16)),
                ),
            ]
        );
    }

    /// main.rs takes the counts under the locks it already holds and logs
    /// them after releasing them: a log write is file I/O.
    #[test]
    fn main_logs_expiry_after_releasing_its_locks() {
        let main = include_str!("main.rs");
        let start = main.find("enter(\"evict\");").expect("the eviction step");
        let block = &main[start..start + main[start..].find("last_evict = Instant::now();").expect("its end")];
        let collect = block.find("expired = q.evict_expired(evict_max_age);").expect("the counts are kept");
        let lines = block.find("deferred_queue::expiry_lines(&expired,").expect("and logged");
        assert!(collect < lines);
        let between = &block[collect..lines];
        assert!(
            between.matches('}').count() >= 2,
            "the queue guard and the node guard are dropped before the lines are written"
        );
        assert!(!block[lines..].contains("node.lock()"), "no FedNode lock is held while logging");
        assert!(!block[lines..].contains("deferred_queue.lock()"), "nor the queue's");
    }

    /// `enqueue_all` tallies each enqueue: queued, queued by evicting the
    /// subscriber's oldest entry, refused at the global limit. The tally's
    /// lines say what was lost, a WARNING for a refusal and a NOTICE for an
    /// eviction, and nothing for a run that lost nothing.
    #[test]
    fn enqueue_all_tallies_what_became_of_each_blob() {
        let mut q = fresh_queue();
        q.global_limit = 4;
        let sub = vec![0xA1; 16];
        let blobs = |n: u8| (0..n).map(|i| (vec![0xC1; 16], vec![i])).collect::<Vec<_>>();

        let clean = q.enqueue_all(&sub, blobs(2), 3);
        assert_eq!(clean, EnqueueTally { queued: 2, evicted: 0, refused: 0 });
        assert!(clean.loss_lines("[x]", &sub, "why").is_empty());

        // Per-subscriber limit 3: the third fits, the fourth evicts the
        // oldest.
        let evicting = q.enqueue_all(&sub, blobs(2), 3);
        assert_eq!(evicting, EnqueueTally { queued: 2, evicted: 1, refused: 0 });
        assert_eq!(q.count_matching(&sub, &[0xC1; 16]), 3);

        // Another subscriber's blob fills the queue to its global limit of
        // 4: everything after it is refused.
        let other = vec![0xB2; 16];
        assert_eq!(q.enqueue(other.clone(), vec![0xC2; 16], vec![9], 3), EnqueueOutcome::Queued);
        let refused = q.enqueue_all(&other, blobs(2), 3);
        assert_eq!(refused, EnqueueTally { queued: 0, evicted: 0, refused: 2 });

        let run = EnqueueTally { queued: 2, evicted: 1, refused: 1 };
        let lines = run.loss_lines("[backup]", &sub, "owner offline");
        let sub_hex = reticulum_rust::hexrep(&sub, false);
        assert_eq!(
            lines,
            vec![
                (
                    reticulum_rust::LOG_WARNING,
                    format!("[backup] 1 blob(s) for {sub_hex} (owner offline) NOT queued: global limit, lost to the pull"),
                ),
                (
                    reticulum_rust::LOG_NOTICE,
                    format!("[backup] {sub_hex} bucket full: its 1 oldest entry(ies) evicted to queue blob(s) (owner offline)"),
                ),
            ]
        );
    }
}

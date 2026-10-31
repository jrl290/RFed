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

use std::collections::{HashMap, HashSet, VecDeque};
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
    /// Names the entry while this process runs ([`DeferredQueue::flush_copies`]).
    /// Not the row id: SQLite gives a deleted last row's id to the next
    /// insert, and an entry that was not stored has none.
    ticket: u64,
}

impl PendingBlob {
    /// The entry's name for [`DeferredQueue::confirm`] and
    /// [`DeferredQueue::release`].
    pub fn ticket(&self) -> u64 {
        self.ticket
    }
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
    /// Queued, after the oldest entry of the fullest bucket was evicted to
    /// keep the whole queue within `global_limit`: `evicted_subscriber`'s
    /// bucket (it can be this subscriber's own), an entry routed to
    /// `evicted_routing_hash`.
    QueuedEvictingFullest { evicted_subscriber: Vec<u8>, evicted_routing_hash: Vec<u8> },
    /// Not queued: the queue holds `global_limit` entries and all of them
    /// are in pages a pull holds, which nothing evicts.
    RefusedGlobalLimit,
}

impl EnqueueOutcome {
    /// Whether the blob is in the queue now.
    pub fn queued(&self) -> bool {
        !matches!(self, EnqueueOutcome::RefusedGlobalLimit)
    }
}

/// What a run of enqueues for one subscriber came to
/// ([`DeferredQueue::enqueue_all`]), for the backup node adopting an offline
/// owner's subscriber, which queues several blobs at once. Its drops speak as
/// a hand-off's do ([`EnqueueTally::loss_lines`], RFed SPEC §7 "Limits").
/// Until 2026-10-10 the outcome was ignored, and the backup line counted a
/// refused blob as queued.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EnqueueTally {
    /// In the queue now.
    pub queued: usize,
    /// Of those, how many evicted the subscriber's oldest entry to fit.
    pub evicted: usize,
    /// Of those, how many evicted the oldest entry of the fullest bucket to
    /// keep the queue within its global limit.
    pub evicted_fullest: usize,
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
            EnqueueOutcome::QueuedEvictingFullest { .. } => {
                self.queued += 1;
                self.evicted_fullest += 1;
            }
            EnqueueOutcome::RefusedGlobalLimit => self.refused += 1,
        }
    }

    /// The lines for what the run lost, for the caller to log with every
    /// lock released: a WARNING for the blobs the global limit refused, a
    /// NOTICE for the older entries evicted to make room. `tag` begins each
    /// line (`[backup]`); `why` says what the blobs were.
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
        if self.evicted_fullest > 0 {
            lines.push((
                reticulum_rust::LOG_NOTICE,
                format!(
                    "{tag} queue full: {} entry(ies), each the oldest of the fullest bucket, evicted to queue blob(s) for {subscriber} ({why})",
                    self.evicted_fullest,
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

/// A page a pull holds (PULL-PROOF-DESIGN.md): out of its bucket, its rows
/// kept, until [`DeferredQueue::settle_page`] says whether the requester
/// proved it.
struct HeldPage {
    subscriber_hash: Vec<u8>,
    blobs: Vec<PendingBlob>,
}

/// In-memory queue with disk backing; keyed by subscriber destination hash.
pub struct DeferredQueue {
    /// `subscriber_hash → ordered list of pending blobs`.
    queue: HashMap<Vec<u8>, VecDeque<PendingBlob>>,
    /// Pages handed to a pull and not yet proved, by page id.
    held: HashMap<u64, HeldPage>,
    /// The next page id; 0 is never one (an empty page holds nothing).
    next_page: u64,
    /// The next [`PendingBlob::ticket`]; 0 is never one.
    next_ticket: u64,
    /// The entries an announce flush sent and has not heard back about, by
    /// ticket ([`Self::flush_copies`]).
    in_flight: HashSet<u64>,
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
                        ticket: 0,
                    });
                }
            }
        }
        let mut next_ticket = 1;
        for entry in queue.values_mut().flat_map(|bucket| bucket.iter_mut()) {
            entry.ticket = next_ticket;
            next_ticket += 1;
        }

        DeferredQueue {
            queue,
            held: HashMap::new(),
            next_page: 1,
            next_ticket,
            in_flight: HashSet::new(),
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
                ticket: 0,
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
    /// If the subscriber's bucket is at its limit, its *oldest* entry is
    /// evicted. Otherwise, if the whole queue holds `global_limit` entries,
    /// the oldest entry of the fullest bucket is (RFed SPEC §7 "Limits"); the
    /// blob is refused only when every stored entry is in a page a pull
    /// holds. The outcome says which: the caller logs it (see
    /// [`EnqueueOutcome`]).
    ///
    /// Until 2026-10-30 the global limit refused every new blob, before any
    /// eviction, so subscribers that had stopped pulling kept everyone
    /// else's out. On 2026-10-30 production's queue stood at 4096, 82% of it
    /// week-old #public.general posts for devices that never came back, and
    /// new posts for live devices were dropped.
    pub fn enqueue(
        &mut self,
        subscriber_hash: Vec<u8>,
        channel_hash: Vec<u8>,
        blob: Vec<u8>,
        per_subscriber_limit: usize,
    ) -> EnqueueOutcome {
        let bucket_full = self
            .queue
            .get(&subscriber_hash)
            .is_some_and(|bucket| !bucket.is_empty() && bucket.len() >= per_subscriber_limit);
        let (evicted, outcome) = if bucket_full {
            let old = self.queue.get_mut(&subscriber_hash).and_then(VecDeque::pop_front);
            let outcome = match &old {
                Some(old) => EnqueueOutcome::QueuedEvictingOldest { evicted_routing_hash: old.channel_hash.clone() },
                None => EnqueueOutcome::Queued,
            };
            (old, outcome)
        } else if self.total_len() >= self.global_limit {
            let Some((evicted_subscriber, old)) = self.pop_oldest_of_fullest() else {
                return EnqueueOutcome::RefusedGlobalLimit;
            };
            let evicted_routing_hash = old.channel_hash.clone();
            (Some(old), EnqueueOutcome::QueuedEvictingFullest { evicted_subscriber, evicted_routing_hash })
        } else {
            (None, EnqueueOutcome::Queued)
        };

        // The eviction and the new row, together.
        let enqueued_at = now();
        let mut id = 0;
        crate::store_db::write_all(self.db.as_ref(), "deferred enqueue", |c| {
            if let Some(old) = evicted.as_ref().filter(|old| old.id != 0) {
                c.execute("DELETE FROM deferred WHERE id = ?1", [old.id])?;
            }
            id = insert_row(c, &subscriber_hash, &channel_hash, &blob, enqueued_at)?;
            Ok(())
        });

        let ticket = self.next_ticket;
        self.next_ticket += 1;
        self.queue.entry(subscriber_hash).or_default().push_back(PendingBlob {
            channel_hash,
            blob,
            enqueued_at,
            id,
            ticket,
        });
        outcome
    }

    /// Take the oldest entry of the fullest bucket, for an enqueue at the
    /// global limit; between buckets of one size, the one whose oldest entry
    /// is oldest. Pages a pull holds are out of their buckets and stay.
    /// Returns the bucket's subscriber and the entry, or `None` when every
    /// bucket is empty.
    fn pop_oldest_of_fullest(&mut self) -> Option<(Vec<u8>, PendingBlob)> {
        let fullest = self
            .queue
            .iter()
            .filter_map(|(subscriber, bucket)| bucket.front().map(|oldest| (subscriber, bucket.len(), oldest.enqueued_at)))
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.2.total_cmp(&a.2)))
            .map(|(subscriber, _, _)| subscriber.clone())?;
        let (old, emptied) = {
            let bucket = self.queue.get_mut(&fullest)?;
            (bucket.pop_front()?, bucket.is_empty())
        };
        if emptied {
            self.queue.remove(&fullest);
        }
        Some((fullest, old))
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

    /// Total number of entries across all subscribers, the held pages'
    /// included: they are still stored.
    pub fn total_len(&self) -> usize {
        self.queue.values().map(|v| v.len()).sum::<usize>()
            + self.held.values().map(|page| page.blobs.len()).sum::<usize>()
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

    /// Take one page for a pull from `subscriber_hash` (PULL-PROOF-DESIGN.md):
    /// its blobs whose routing hash satisfies `wanted`, in queue order, at
    /// most `max` of them and, after the first, only while their `cost`s stay
    /// within `budget`. A blob that does not fit ends the page, so no later
    /// blob overtakes it. The page leaves the bucket but keeps its rows: it is
    /// held until [`Self::settle_page`], and a restart before then reloads it.
    /// Returns the page's id, 0 for an empty page (which holds nothing), and
    /// a copy of its blobs for the response.
    pub fn take_page(
        &mut self,
        subscriber_hash: &[u8],
        wanted: impl Fn(&[u8]) -> bool,
        max: usize,
        budget: usize,
        cost: impl Fn(&PendingBlob) -> usize,
    ) -> (u64, Vec<PendingBlob>) {
        let mut taken: Vec<PendingBlob> = Vec::new();

        let drop_bucket = {
            let bucket = match self.queue.get_mut(subscriber_hash) {
                Some(b) => b,
                None => return (0, Vec::new()),
            };

            let mut kept = VecDeque::with_capacity(bucket.len());
            let mut spent = 0usize;
            let mut full = false;
            while let Some(entry) = bucket.pop_front() {
                if !full && taken.len() < max && wanted(&entry.channel_hash) {
                    let entry_cost = cost(&entry);
                    if taken.is_empty() || spent + entry_cost <= budget {
                        spent += entry_cost;
                        taken.push(entry);
                        continue;
                    }
                    full = true;
                }
                kept.push_back(entry);
            }

            *bucket = kept;
            bucket.is_empty()
        };

        if drop_bucket {
            self.queue.remove(subscriber_hash);
        }
        if taken.is_empty() {
            return (0, Vec::new());
        }
        let id = self.next_page;
        self.next_page += 1;
        let copy = taken.clone();
        self.held.insert(id, HeldPage { subscriber_hash: subscriber_hash.to_vec(), blobs: taken });
        (id, copy)
    }

    /// Settle a page [`Self::take_page`] held. Proved, its rows are deleted.
    /// Not proved, its blobs go back to the front of their bucket in their
    /// order, for the subscriber's next pull: rfed never sends them again on
    /// its own (DESIGN_PRINCIPLES §3, an event and never a timer). Nothing is
    /// evicted to make room, so the bucket can stand over its per-subscriber
    /// limit by the pages that came back until the subscriber pulls. Returns
    /// the subscriber and how many blobs the page held, for the caller's log
    /// line, or `None` when no such page is held.
    pub fn settle_page(&mut self, id: u64, proved: bool) -> Option<(Vec<u8>, usize)> {
        let page = self.held.remove(&id)?;
        let count = page.blobs.len();
        if proved {
            self.delete_rows(&page.blobs, "deferred pull proved");
        } else {
            let bucket = self.queue.entry(page.subscriber_hash.clone()).or_default();
            for blob in page.blobs.into_iter().rev() {
                bucket.push_front(blob);
            }
        }
        Some((page.subscriber_hash, count))
    }

    /// Copies of the entries the announce flush sends `subscriber_hash` (RFed
    /// SPEC §7 "Delivery Triggers"): those whose routing hash satisfies
    /// `wanted` and that no earlier flush has in flight, in queue order. Each
    /// is marked in flight and stays in its bucket, rows and all, so a pull
    /// meanwhile still gets it. [`Self::confirm`] deletes it once a route
    /// confirms it; [`Self::release`] ends its flight when none did.
    ///
    /// Until 2026-10-30 the flush drained the bucket and queued the blobs
    /// again when their receipts timed out, about 30 s later. A pull in that
    /// window found nothing (the web client pulls 2 s after its announce), a
    /// restart in it lost the blobs, and the re-queue could meet a full
    /// queue and drop them: eight #public.general posts were lost that way
    /// on 2026-10-30.
    pub fn flush_copies(&mut self, subscriber_hash: &[u8], wanted: impl Fn(&[u8]) -> bool) -> Vec<PendingBlob> {
        let Some(bucket) = self.queue.get(subscriber_hash) else {
            return Vec::new();
        };
        let copies: Vec<PendingBlob> = bucket
            .iter()
            .filter(|entry| wanted(&entry.channel_hash) && !self.in_flight.contains(&entry.ticket))
            .cloned()
            .collect();
        self.in_flight.extend(copies.iter().map(PendingBlob::ticket));
        copies
    }

    /// A route confirmed `subscriber_hash`'s entry `ticket` (a packet's
    /// proof, the answer to an rfed.link push): delete it from its bucket, or
    /// from the page a pull holds it in, so that page does not bring it back
    /// unproved. Returns whether it was still stored; a pull may have
    /// delivered it first.
    pub fn confirm(&mut self, subscriber_hash: &[u8], ticket: u64) -> bool {
        self.in_flight.remove(&ticket);
        let (mut removed, emptied) = match self.queue.get_mut(subscriber_hash) {
            Some(bucket) => {
                let removed = bucket.iter().position(|entry| entry.ticket == ticket).and_then(|at| bucket.remove(at));
                (removed, bucket.is_empty())
            }
            None => (None, false),
        };
        if emptied {
            self.queue.remove(subscriber_hash);
        }
        if removed.is_none() {
            removed = self
                .held
                .values_mut()
                .filter(|page| page.subscriber_hash == subscriber_hash)
                .find_map(|page| {
                    let at = page.blobs.iter().position(|entry| entry.ticket == ticket)?;
                    Some(page.blobs.remove(at))
                });
        }
        match removed {
            Some(entry) => {
                self.delete_rows(std::slice::from_ref(&entry), "deferred flush confirmed");
                true
            }
            None => false,
        }
    }

    /// No route confirmed `subscriber_hash`'s entry `ticket`: its flight
    /// ends, and it stays queued for the pull. Returns whether it is still
    /// waiting in its bucket, which is when the subscriber should be woken to
    /// pull it: not while a pull holds it, nor once it has left the queue.
    pub fn release(&mut self, subscriber_hash: &[u8], ticket: u64) -> bool {
        self.in_flight.remove(&ticket);
        self.queue
            .get(subscriber_hash)
            .is_some_and(|bucket| bucket.iter().any(|entry| entry.ticket == ticket))
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
        let mut evicted_ids: Vec<i64> = Vec::new();
        for (subscriber_hash, bucket) in self.queue.iter_mut() {
            bucket.retain(|e| {
                let keep = e.enqueued_at >= threshold;
                if !keep {
                    *counts.entry((subscriber_hash.clone(), e.channel_hash.clone())).or_default() += 1;
                    evicted_ids.push(e.id);
                }
                keep
            });
        }
        // Remove now-empty buckets.
        self.queue.retain(|_, v| !v.is_empty());
        // The evicted rows by id, not every row past the age: a page a pull
        // holds is out of its bucket, and its rows stay until it settles
        // (PULL-PROOF-DESIGN.md). Deleted by age, a page not proved and then a
        // restart would lose its blobs without a line; kept, it comes back and
        // expires here, counted.
        if !evicted_ids.is_empty() {
            crate::store_db::write_all(self.db.as_ref(), "deferred expiry", |c| {
                let mut stmt = c.prepare_cached("DELETE FROM deferred WHERE id = ?1")?;
                for id in evicted_ids.iter().filter(|id| **id != 0) {
                    stmt.execute([*id])?;
                }
                Ok(())
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
//
// The pulls themselves no longer drain (PULL-PROOF-DESIGN.md, 2026-10-12):
//
//   * `take_page` takes a page out of the bucket and holds it, rows kept;
//     `settle_page` deletes them once the requester proved the page, or puts
//     the page back at the front of the bucket, in order.
//   * A page stays within its byte budget but always carries one blob, and
//     no later blob overtakes one that did not fit.
//   * Held blobs still count toward the global limit, survive a restart, and
//     keep their rows through expiry.
//
// The announce flush no longer drains either (2026-10-30):
//
//   * `flush_copies` hands out copies, rows kept, each in flight until
//     `confirm` deletes it or `release` ends its flight; a later flush skips
//     what is in flight, and a pull still gets it.
//   * At the global limit an enqueue evicts the oldest entry of the fullest
//     bucket instead of refusing the new one.

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
    fn the_distro_pull_handler_takes_only_distro_blobs() {
        let source = include_str!("destinations.rs");
        let start = source.find("let pull_distro_cb = Arc::new(").expect("pull_distro_cb");
        let body = &source[start..start + source[start..].find("});").expect("end of pull_distro_cb")];
        assert!(!body.contains("drain_batch("), "a whole-bucket drain hands channel blobs to the distro clients");
        assert!(body.contains("pull_answer(&guard.deferred_queue, &mut deferred, &subscriber_hash, is_distro, page_size"));
        assert!(body.contains("registered_distro_hashes()"));
    }

    // ── Pages held until proven (PULL-PROOF-DESIGN.md) ─────────────────────

    fn blobs(page: &[PendingBlob]) -> Vec<Vec<u8>> {
        page.iter().map(|p| p.blob.clone()).collect()
    }

    fn rows(q: &DeferredQueue) -> i64 {
        q.db.as_ref()
            .expect("the test queue is stored")
            .query_row("SELECT COUNT(*) FROM deferred", [], |r| r.get(0))
            .expect("count rows")
    }

    fn take(q: &mut DeferredQueue, sub: &[u8], max: usize) -> (u64, Vec<PendingBlob>) {
        q.take_page(sub, |_| true, max, usize::MAX, |_| 1)
    }

    #[test]
    fn a_proved_page_is_deleted_and_one_not_proved_comes_back_first() {
        let mut q = fresh_queue();
        let sub = vec![0x71u8; 16];
        let chan = vec![0xC7u8; 16];
        enqueue_n(&mut q, &sub, &chan, 5);

        let (page, taken) = take(&mut q, &sub, 3);
        assert_ne!(page, 0);
        assert_eq!(blobs(&taken), vec![vec![0], vec![1], vec![2]]);
        assert!(q.has_pending(&sub), "two are left for the next page");
        assert_eq!(q.total_len(), 5, "a held page is still stored");
        assert_eq!(rows(&q), 5, "and keeps its rows");

        assert_eq!(q.settle_page(page, false), Some((sub.clone(), 3)));
        let (page, again) = take(&mut q, &sub, 25);
        assert_eq!(
            blobs(&again),
            vec![vec![0], vec![1], vec![2], vec![3], vec![4]],
            "the page not proved comes first, in its order"
        );

        assert_eq!(q.settle_page(page, true), Some((sub.clone(), 5)));
        assert_eq!(q.total_len(), 0);
        assert_eq!(rows(&q), 0, "proved, its rows are gone");
        assert!(!q.has_pending(&sub));
        assert_eq!(q.settle_page(page, true), None, "a page settles once");
    }

    #[test]
    fn an_empty_page_holds_nothing() {
        let mut q = fresh_queue();
        let sub = vec![0x72u8; 16];
        assert_eq!(take(&mut q, &sub, 25).0, 0, "nothing queued");
        enqueue_n(&mut q, &sub, &[0xC7u8; 16], 1);
        assert_eq!(take(&mut q, &sub, 0).0, 0, "max 0 takes nothing");
        let (page, taken) = q.take_page(&sub, |_| false, 25, usize::MAX, |_| 1);
        assert_eq!((page, taken.len()), (0, 0), "nothing wanted");
        assert!(q.has_pending(&sub));
        assert_eq!(q.settle_page(0, false), None);
    }

    #[test]
    fn a_held_page_comes_again_after_a_restart() {
        let p = tmp_path();
        crate::store_db::remove_store_files(&p);
        let sub = vec![0x73u8; 16];
        let chan = vec![0xC7u8; 16];
        {
            let mut q = DeferredQueue::load(p.clone());
            enqueue_n(&mut q, &sub, &chan, 4);
            let (_page, taken) = take(&mut q, &sub, 2);
            assert_eq!(taken.len(), 2);
        }
        let mut q = DeferredQueue::load(p.clone());
        let (_page, all) = take(&mut q, &sub, 25);
        assert_eq!(blobs(&all), vec![vec![0], vec![1], vec![2], vec![3]], "at least once, in order");
        drop(q);
        crate::store_db::remove_store_files(&p);
    }

    #[test]
    fn a_page_keeps_to_its_byte_budget_but_always_carries_one_blob() {
        let mut q = fresh_queue();
        let sub = vec![0x74u8; 16];
        let chan = vec![0xC7u8; 16];
        let cost = |pb: &PendingBlob| pb.blob.len();
        for size in [600usize, 600, 10, 2000, 10] {
            q.enqueue(sub.clone(), chan.clone(), vec![0xAB; size], 1024);
        }
        let sizes = |page: &[PendingBlob]| page.iter().map(|p| p.blob.len()).collect::<Vec<_>>();

        let (_, page) = q.take_page(&sub, |_| true, 25, 1000, cost);
        assert_eq!(sizes(&page), vec![600], "the second 600 does not fit, and the 10 behind it waits its turn");
        let (_, page) = q.take_page(&sub, |_| true, 25, 1000, cost);
        assert_eq!(sizes(&page), vec![600, 10], "the next page starts where that one stopped");
        let (_, page) = q.take_page(&sub, |_| true, 25, 1000, cost);
        assert_eq!(sizes(&page), vec![2000], "a blob over the budget goes alone");
        let (_, page) = q.take_page(&sub, |_| true, 25, 1000, cost);
        assert_eq!(sizes(&page), vec![10]);
        assert!(!q.has_pending(&sub));
    }

    #[test]
    fn a_page_keeps_to_its_count() {
        let mut q = fresh_queue();
        let sub = vec![0x75u8; 16];
        enqueue_n(&mut q, &sub, &[0xC7u8; 16], 30);
        assert_eq!(take(&mut q, &sub, 25).1.len(), 25);
        assert_eq!(take(&mut q, &sub, 25).1.len(), 5);
    }

    /// The iOS app and its notification extension can pull at once: each
    /// takes its own page. One not proved comes back ahead of what is left.
    #[test]
    fn two_pulls_at_once_take_disjoint_pages() {
        let mut q = fresh_queue();
        let sub = vec![0x76u8; 16];
        enqueue_n(&mut q, &sub, &[0xC7u8; 16], 6);
        let (first, a) = take(&mut q, &sub, 2);
        let (second, b) = take(&mut q, &sub, 2);
        assert_eq!(blobs(&a), vec![vec![0], vec![1]]);
        assert_eq!(blobs(&b), vec![vec![2], vec![3]]);
        assert_ne!(first, second);

        q.settle_page(second, true);
        q.settle_page(first, false);
        let (_, rest) = take(&mut q, &sub, 25);
        assert_eq!(blobs(&rest), vec![vec![0], vec![1], vec![4], vec![5]]);
    }

    /// The distro pull's page leaves the identity's channel blobs where they
    /// were, and one not proved goes back among them in its old place.
    #[test]
    fn a_distro_page_not_proved_goes_back_ahead_of_the_channel_blobs() {
        let mut q = fresh_queue();
        let identity = vec![0x77u8; 16];
        let channel = vec![0xC1u8; 16];
        let distro = vec![0xD1u8; 16];
        q.enqueue(identity.clone(), distro.clone(), b"distro-1".to_vec(), 1024);
        q.enqueue(identity.clone(), channel.clone(), b"channel-1".to_vec(), 1024);
        q.enqueue(identity.clone(), distro.clone(), b"distro-2".to_vec(), 1024);

        let is_distro = |routing: &[u8]| routing == distro.as_slice();
        let (page, taken) = q.take_page(&identity, is_distro, 25, usize::MAX, |_| 1);
        assert_eq!(blobs(&taken), vec![b"distro-1".to_vec(), b"distro-2".to_vec()]);
        assert!(!q.has_pending_matching(&identity, is_distro), "more_pending is false");
        assert!(q.has_pending_channel(&identity, &channel));

        q.settle_page(page, false);
        let (_, all) = take(&mut q, &identity, 25);
        assert_eq!(blobs(&all), vec![b"distro-1".to_vec(), b"distro-2".to_vec(), b"channel-1".to_vec()]);
    }

    /// Held blobs still count toward the global limit, and nothing evicts
    /// them: at the limit an enqueue takes the oldest entry still in a
    /// bucket, and is refused only when every stored entry is held.
    #[test]
    fn held_blobs_count_toward_the_global_limit_and_are_never_evicted() {
        let mut q = fresh_queue();
        q.global_limit = 3;
        let sub = vec![0x78u8; 16];
        let chan = vec![0xC7u8; 16];
        enqueue_n(&mut q, &sub, &chan, 3);
        let (page, _) = take(&mut q, &sub, 2);
        assert_eq!(
            q.enqueue(sub.clone(), chan.clone(), vec![9], 1024),
            EnqueueOutcome::QueuedEvictingFullest { evicted_subscriber: sub.clone(), evicted_routing_hash: chan.clone() },
            "the entry left in the bucket goes, not the held page"
        );
        assert_eq!(q.total_len(), 3);
        let (second, _) = take(&mut q, &sub, 1);
        assert_eq!(
            q.enqueue(sub.clone(), chan.clone(), vec![10], 1024),
            EnqueueOutcome::RefusedGlobalLimit,
            "every stored entry is held"
        );
        q.settle_page(page, true);
        q.settle_page(second, true);
        assert!(q.enqueue(sub.clone(), chan.clone(), vec![10], 1024).queued());
    }

    /// Expiry leaves a held page alone, rows and all, until it settles, even
    /// while another device's entries expire beside it. Not proved, it comes
    /// back and then expires counted like any other entry.
    #[test]
    fn expiry_keeps_the_rows_of_a_held_page() {
        let mut q = fresh_queue();
        let device = vec![0x79u8; 16];
        let other = vec![0x7Au8; 16];
        let distro = vec![0xD9u8; 16];
        enqueue_n(&mut q, &device, &distro, 2);
        enqueue_n(&mut q, &other, &distro, 1);
        let (page, taken) = take(&mut q, &device, 25);
        assert_eq!(taken.len(), 2);

        assert_eq!(
            q.evict_expired(-10.0),
            vec![Expired { subscriber_hash: other.clone(), routing_hash: distro.clone(), count: 1 }],
            "only what is in a bucket expires; a held page is out of its bucket"
        );
        assert_eq!(rows(&q), 2, "the held page's rows are kept");

        q.settle_page(page, false);
        assert_eq!(
            q.evict_expired(-10.0),
            vec![Expired { subscriber_hash: device.clone(), routing_hash: distro.clone(), count: 2 }]
        );
        assert_eq!(rows(&q), 0);
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

    /// At the global limit the oldest entry of the fullest bucket goes, and
    /// the outcome names whose it was and its routing hash; the hand-off
    /// logs it (handoff.rs). Until 2026-10-30 the new blob was refused
    /// instead, so subscribers that never pulled kept everyone else's out.
    #[test]
    fn an_enqueue_at_the_global_limit_evicts_the_oldest_of_the_fullest_bucket() {
        let mut q = fresh_queue();
        q.global_limit = 5;
        let gone = vec![0x61u8; 16];
        let live = vec![0x62u8; 16];
        let newcomer = vec![0x63u8; 16];
        let chan = vec![0x64u8; 16];
        let distro = vec![0xD6u8; 16];
        assert_eq!(q.enqueue(gone.clone(), distro.clone(), vec![0], 1024), EnqueueOutcome::Queued);
        for i in 1..3u8 {
            q.enqueue(gone.clone(), chan.clone(), vec![i], 1024);
        }
        for i in 3..5u8 {
            q.enqueue(live.clone(), chan.clone(), vec![i], 1024);
        }

        let outcome = q.enqueue(newcomer.clone(), chan.clone(), vec![9], 1024);
        assert_eq!(
            outcome,
            EnqueueOutcome::QueuedEvictingFullest { evicted_subscriber: gone.clone(), evicted_routing_hash: distro.clone() }
        );
        assert!(outcome.queued());
        assert_eq!(q.total_len(), 5, "one in, one out");
        assert_eq!(rows(&q), 5, "the evicted row went with the new one's insert");
        assert_eq!(blobs(&q.drain(&gone)), vec![vec![1], vec![2]], "the fullest bucket lost its oldest");
        assert_eq!(blobs(&q.drain(&live)), vec![vec![3], vec![4]], "the others keep theirs");
        assert_eq!(blobs(&q.drain(&newcomer)), vec![vec![9]]);
    }

    /// Between buckets of one size, the one whose oldest entry is older
    /// gives it up, whichever was filled first.
    #[test]
    fn between_equally_full_buckets_the_older_entry_goes() {
        let mut q = fresh_queue();
        q.global_limit = 4;
        let first = vec![0x66u8; 16];
        let second = vec![0x67u8; 16];
        let chan = vec![0x68u8; 16];
        enqueue_n(&mut q, &first, &chan, 2);
        enqueue_n(&mut q, &second, &chan, 2);
        q.queue.get_mut(&second).unwrap()[0].enqueued_at = 1.0;
        q.queue.get_mut(&first).unwrap()[0].enqueued_at = 2.0;

        assert_eq!(
            q.enqueue(vec![0x69; 16], chan.clone(), vec![9], 1024),
            EnqueueOutcome::QueuedEvictingFullest { evicted_subscriber: second.clone(), evicted_routing_hash: chan.clone() }
        );
        assert_eq!(q.drain(&second).len(), 1);
        assert_eq!(q.drain(&first).len(), 2);
    }

    /// A subscriber at its own limit gives up its own oldest entry, also at
    /// the global limit: the queue does not grow, and nobody else's goes.
    #[test]
    fn a_full_bucket_at_the_global_limit_evicts_its_own_oldest() {
        let mut q = fresh_queue();
        q.global_limit = 3;
        let sub = vec![0x6Au8; 16];
        let other = vec![0x6Bu8; 16];
        let chan = vec![0x6Cu8; 16];
        enqueue_n(&mut q, &other, &chan, 1);
        enqueue_n(&mut q, &sub, &chan, 2);

        assert_eq!(
            q.enqueue(sub.clone(), chan.clone(), vec![9], 2),
            EnqueueOutcome::QueuedEvictingOldest { evicted_routing_hash: chan.clone() }
        );
        assert_eq!(blobs(&q.drain(&sub)), vec![vec![1], vec![9]]);
        assert_eq!(q.drain(&other).len(), 1, "nobody else's entry went");
    }

    #[test]
    fn a_tally_counts_and_names_evictions_from_the_fullest_bucket() {
        let mut tally = EnqueueTally::default();
        tally.add(&EnqueueOutcome::QueuedEvictingFullest { evicted_subscriber: vec![1; 16], evicted_routing_hash: vec![2; 16] });
        assert_eq!(tally, EnqueueTally { queued: 1, evicted_fullest: 1, ..Default::default() });
        let lines = tally.loss_lines("[backup]", &[3; 16], "owner offline");
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert_eq!(lines[0].0, reticulum_rust::LOG_NOTICE);
        assert!(
            lines[0].1.starts_with("[backup] queue full: 1 entry(ies), each the oldest of the fullest bucket, evicted"),
            "{}",
            lines[0].1
        );
    }

    // ── The announce flush keeps what it sends (2026-10-30) ───────────────

    /// What the flush sends stays queued, and pullable, until a route
    /// confirms it: confirmed, it is deleted; unconfirmed, it waits for the
    /// pull, and the subscriber is to be woken for it.
    #[test]
    fn a_flushed_entry_stays_queued_until_a_route_confirms_it() {
        let mut q = fresh_queue();
        let sub = vec![0x91u8; 16];
        let chan = vec![0xC9u8; 16];
        enqueue_n(&mut q, &sub, &chan, 3);

        let sent = q.flush_copies(&sub, |_| true);
        assert_eq!(blobs(&sent), vec![vec![0], vec![1], vec![2]]);
        assert_eq!(rows(&q), 3, "copies: every row is kept");
        assert!(q.has_pending_channel(&sub, &chan), "a pull meanwhile still finds them");

        assert!(q.confirm(&sub, sent[1].ticket()), "the second one's proof");
        assert_eq!(rows(&q), 2);
        assert!(q.release(&sub, sent[0].ticket()), "unconfirmed and waiting: wake the subscriber");
        assert!(q.release(&sub, sent[2].ticket()));
        let (_, page) = take(&mut q, &sub, 25);
        assert_eq!(blobs(&page), vec![vec![0], vec![2]], "the pull gets what nothing confirmed, in order");
    }

    /// An announce while an earlier flush waits for its receipts sends
    /// nothing twice; what that flush released goes again.
    #[test]
    fn a_flush_skips_what_an_earlier_flush_has_in_flight() {
        let mut q = fresh_queue();
        let sub = vec![0x92u8; 16];
        let chan = vec![0xC9u8; 16];
        enqueue_n(&mut q, &sub, &chan, 2);
        let first = q.flush_copies(&sub, |_| true);
        assert_eq!(first.len(), 2);
        assert!(q.flush_copies(&sub, |_| true).is_empty(), "both still in flight");

        q.enqueue(sub.clone(), chan.clone(), vec![7], 1024);
        assert_eq!(blobs(&q.flush_copies(&sub, |_| true)), vec![vec![7]], "only the new one");
        q.release(&sub, first[0].ticket());
        assert_eq!(blobs(&q.flush_copies(&sub, |_| true)), vec![vec![0]], "the released one goes again");
    }

    /// The flush takes only what `wanted` admits (no distro blob).
    #[test]
    fn a_flush_copies_only_the_wanted_routing_hashes() {
        let mut q = fresh_queue();
        let sub = vec![0x93u8; 16];
        let chan = vec![0xC9u8; 16];
        let distro = vec![0xD9u8; 16];
        q.enqueue(sub.clone(), distro.clone(), b"distro".to_vec(), 1024);
        q.enqueue(sub.clone(), chan.clone(), b"channel".to_vec(), 1024);
        let sent = q.flush_copies(&sub, |routing| routing != distro.as_slice());
        assert_eq!(blobs(&sent), vec![b"channel".to_vec()]);
        assert_eq!(q.total_len(), 2);
    }

    /// A pull takes a page while the flush waits. The flush's proof deletes
    /// the entry from the held page, so the page, not proved, does not bring
    /// it back; the flush's timeout wakes nobody for an entry a pull holds.
    #[test]
    fn a_confirmed_entry_leaves_the_page_a_pull_holds() {
        let mut q = fresh_queue();
        let sub = vec![0x94u8; 16];
        let chan = vec![0xC9u8; 16];
        enqueue_n(&mut q, &sub, &chan, 2);
        let sent = q.flush_copies(&sub, |_| true);
        let (page, taken) = take(&mut q, &sub, 25);
        assert_eq!(taken.len(), 2, "the pull gets both while they are in flight");

        assert!(!q.release(&sub, sent[1].ticket()), "held by a pull: no wake");
        assert!(q.confirm(&sub, sent[0].ticket()), "deleted from the held page");
        assert_eq!(rows(&q), 1);
        q.settle_page(page, false);
        assert_eq!(blobs(&q.drain(&sub)), vec![vec![1]], "only the unconfirmed one comes back");
    }

    /// Delivered by the pull first: the flush's late proof and its timeout
    /// find nothing, and wake nobody.
    #[test]
    fn an_entry_the_pull_delivered_is_not_confirmed_or_woken_for_again() {
        let mut q = fresh_queue();
        let sub = vec![0x95u8; 16];
        let chan = vec![0xC9u8; 16];
        enqueue_n(&mut q, &sub, &chan, 1);
        let sent = q.flush_copies(&sub, |_| true);
        let (page, _) = take(&mut q, &sub, 25);
        q.settle_page(page, true);

        assert!(!q.confirm(&sub, sent[0].ticket()));
        assert!(!q.release(&sub, sent[0].ticket()));
        assert_eq!(rows(&q), 0);
    }

    /// A restart while the flush waits loses nothing: the entries never left.
    #[test]
    fn a_restart_during_a_flush_keeps_its_entries() {
        let path = tmp_path();
        crate::store_db::remove_store_files(&path);
        let sub = vec![0x96u8; 16];
        let chan = vec![0xC9u8; 16];
        {
            let mut q = DeferredQueue::load(path.clone());
            enqueue_n(&mut q, &sub, &chan, 2);
            assert_eq!(q.flush_copies(&sub, |_| true).len(), 2);
        }
        let mut q = DeferredQueue::load(path.clone());
        assert_eq!(q.total_len(), 2);
        assert_eq!(q.flush_copies(&sub, |_| true).len(), 2, "and the next flush sends them");
        crate::store_db::remove_store_files(&path);
    }

    /// SQLite gives a deleted last row's id to the next insert. A confirm
    /// names its entry by ticket, so it never deletes the newcomer.
    #[test]
    fn a_confirm_never_deletes_an_entry_that_reused_a_row_id() {
        let mut q = fresh_queue();
        let sub = vec![0x97u8; 16];
        let chan = vec![0xC9u8; 16];
        enqueue_n(&mut q, &sub, &chan, 1);
        let sent = q.flush_copies(&sub, |_| true);
        let (page, _) = take(&mut q, &sub, 25);
        q.settle_page(page, true);
        q.enqueue(sub.clone(), chan.clone(), vec![8], 1024);
        assert_eq!(q.queue[&sub][0].id, sent[0].id, "the row id came back");

        assert!(!q.confirm(&sub, sent[0].ticket()));
        assert_eq!(blobs(&q.drain(&sub)), vec![vec![8]], "the newcomer is still queued");
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
    /// subscriber's oldest entry or the fullest bucket's, refused at the
    /// global limit. The tally's lines say what was lost, a WARNING for a
    /// refusal and a NOTICE for an eviction, and nothing for a run that lost
    /// nothing.
    #[test]
    fn enqueue_all_tallies_what_became_of_each_blob() {
        let mut q = fresh_queue();
        q.global_limit = 4;
        let sub = vec![0xA1; 16];
        let blobs = |n: u8| (0..n).map(|i| (vec![0xC1; 16], vec![i])).collect::<Vec<_>>();

        let clean = q.enqueue_all(&sub, blobs(2), 3);
        assert_eq!(clean, EnqueueTally { queued: 2, ..Default::default() });
        assert!(clean.loss_lines("[x]", &sub, "why").is_empty());

        // Per-subscriber limit 3: the third fits, the fourth evicts the
        // oldest.
        let evicting = q.enqueue_all(&sub, blobs(2), 3);
        assert_eq!(evicting, EnqueueTally { queued: 2, evicted: 1, ..Default::default() });
        assert_eq!(q.count_matching(&sub, &[0xC1; 16]), 3);

        // Another subscriber's blob fills the queue to its global limit of
        // 4: each one after it evicts the oldest entry of the fullest
        // bucket, `sub`'s (until 2026-10-30 they were refused).
        let other = vec![0xB2; 16];
        assert_eq!(q.enqueue(other.clone(), vec![0xC2; 16], vec![9], 3), EnqueueOutcome::Queued);
        let crowding = q.enqueue_all(&other, blobs(2), 3);
        assert_eq!(crowding, EnqueueTally { queued: 2, evicted_fullest: 2, ..Default::default() });
        assert_eq!(q.count_matching(&sub, &[0xC1; 16]), 1);

        // With every entry held by a pull, nothing can be evicted.
        take(&mut q, &sub, 25);
        take(&mut q, &other, 25);
        let refused = q.enqueue_all(&other, blobs(2), 3);
        assert_eq!(refused, EnqueueTally { refused: 2, ..Default::default() });

        let run = EnqueueTally { queued: 2, evicted: 1, evicted_fullest: 0, refused: 1 };
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

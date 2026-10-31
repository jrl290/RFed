//! Subscription table — local to each node, never synced between peers.
//!
//! Schema: (subscriber_pubkey_hash, channel_pubkey_hash)
//!
//! Both keys are 16-byte truncated RNS destination hashes.  Clients
//! register/unregister via the rfed.channel destination.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// How long a node's own subscription lasts without a renewal (SPEC §6
/// "Renewal and expiry", James 2026-10-30). The Retichat apps and the web
/// client renew far more often: they subscribe again at every start or page
/// load, bind their channels on every rfed.link they open, and pull each
/// channel they read.
pub const LOCAL_SUBSCRIPTION_LIFETIME_SECS: f64 = 30.0 * 86_400.0;

/// A renewal is written at most this often per subscription: the web client
/// pulls every few minutes.
const RENEWAL_WRITE_INTERVAL_SECS: f64 = 3_600.0;

/// `PRAGMA user_version` once the renewal clock has been started.
const RENEWAL_CLOCK_VERSION: i64 = 1;

/// Renewals were not recorded before 2026-10-30, so a node's own row still
/// carries its first subscribe time, whether its device is in use or long
/// gone. Once per database, start every such row's clock now: nothing
/// expires until [`LOCAL_SUBSCRIPTION_LIFETIME_SECS`] after the upgrade,
/// time for every device in use to renew.
fn start_renewal_clock(conn: &rusqlite::Connection) {
    let version: i64 = match conn.query_row("PRAGMA user_version", [], |row| row.get(0)) {
        Ok(version) => version,
        Err(e) => {
            reticulum_rust::log(
                format!("[store] channel subscriptions: schema version unreadable ({e}); renewal clock not started"),
                reticulum_rust::LOG_ERROR,
                false,
                false,
            );
            return;
        }
    };
    if version >= RENEWAL_CLOCK_VERSION {
        return;
    }
    let started = now();
    let mut rows = 0;
    crate::store_db::write_all(Some(conn), "subscription renewal clock", |c| {
        rows = c.execute(
            "UPDATE subscriptions SET last_refreshed = ?1 WHERE owner_node_hash = X'' AND last_refreshed < ?1",
            [started],
        )?;
        c.execute_batch(&format!("PRAGMA user_version = {RENEWAL_CLOCK_VERSION}"))
    });
    if rows > 0 {
        reticulum_rust::log(
            format!(
                "[store] channel subscriptions: renewal clock started for {rows} row(s); none expires before {} days from now",
                (LOCAL_SUBSCRIPTION_LIFETIME_SECS / 86_400.0) as u64,
            ),
            reticulum_rust::LOG_NOTICE,
            false,
            false,
        );
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SubscriptionEntry {
    /// 16-byte truncated destination hash of the subscriber's RNS identity
    pub subscriber_hash: Vec<u8>,
    /// 16-byte truncated destination hash of the channel
    pub channel_hash: Vec<u8>,
    /// Unix timestamp when the subscription was registered
    pub added: f64,
    /// Set when this is a backup subscription for a subscriber owned by another node.
    /// The value is the 16-byte destination hash of the owner's `rfed.node` destination.
    #[serde(default)]
    pub owner_node_hash: Option<Vec<u8>>,
    /// Unix timestamp when this entry was last refreshed. A backup entry is
    /// refreshed by its upstream custodian, and entries not refreshed within
    /// `2 × owner_offline_secs` are pruned so the chain of custody unravels
    /// when the original owner recovers. A node's own entry is renewed by its
    /// subscriber ([`SubscriptionTable::renew`]) and expires after
    /// [`LOCAL_SUBSCRIPTION_LIFETIME_SECS`] without a renewal.
    #[serde(default)]
    pub last_refreshed: f64,
}

/// Persisted in `subscriptions.sqlite3`, one row per entry (crate::store_db);
/// a node's own subscription (no owner) stores its owner as an empty blob, so
/// (subscriber, channel, owner) stays unique.
pub struct SubscriptionTable {
    entries: Vec<SubscriptionEntry>,
    db: Option<rusqlite::Connection>,
}

const SUBSCRIPTION_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS subscriptions (
        subscriber_hash BLOB NOT NULL,
        channel_hash    BLOB NOT NULL,
        owner_node_hash BLOB NOT NULL,
        added           REAL NOT NULL,
        last_refreshed  REAL NOT NULL,
        UNIQUE (subscriber_hash, channel_hash, owner_node_hash)
    );";

fn put_entry(conn: &rusqlite::Connection, e: &SubscriptionEntry) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO subscriptions (subscriber_hash, channel_hash, owner_node_hash, added, last_refreshed)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT (subscriber_hash, channel_hash, owner_node_hash) DO UPDATE SET last_refreshed = excluded.last_refreshed",
        rusqlite::params![
            e.subscriber_hash,
            e.channel_hash,
            e.owner_node_hash.as_deref().unwrap_or(&[]),
            e.added,
            e.last_refreshed,
        ],
    )
}

impl SubscriptionTable {
    /// Load from disk, or start empty if the file doesn't exist yet.
    /// Load the subscriptions kept beside `file_path` (the old msgpack
    /// file, imported once if present).
    pub fn load(file_path: PathBuf) -> Self {
        let db = crate::store_db::open(&file_path, SUBSCRIPTION_SCHEMA);
        let entries = match &db {
            Some(conn) => {
                crate::store_db::import_legacy(conn, &file_path, "channel subscriptions", |tx, old: Vec<SubscriptionEntry>| {
                    let mut n = 0;
                    for e in &old {
                        n += put_entry(tx, e)?;
                    }
                    Ok(n)
                });
                start_renewal_clock(conn);
                Self::read_all(conn).unwrap_or_else(|e| {
                    reticulum_rust::log(
                        format!("[store] channel subscriptions could not be read: {e}"),
                        reticulum_rust::LOG_ERROR,
                        false,
                        false,
                    );
                    Vec::new()
                })
            }
            None => {
                // Nothing is stored without the database, so the renewal
                // clock starts at every load.
                let mut entries: Vec<SubscriptionEntry> = crate::store_db::read_legacy(&file_path).unwrap_or_default();
                let started = now();
                for e in entries.iter_mut().filter(|e| e.owner_node_hash.is_none()) {
                    e.last_refreshed = e.last_refreshed.max(started);
                }
                entries
            }
        };
        SubscriptionTable { entries, db }
    }

    fn read_all(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<SubscriptionEntry>> {
        let mut stmt = conn.prepare(
            "SELECT subscriber_hash, channel_hash, owner_node_hash, added, last_refreshed
             FROM subscriptions ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |row| {
            let owner: Vec<u8> = row.get(2)?;
            Ok(SubscriptionEntry {
                subscriber_hash: row.get(0)?,
                channel_hash: row.get(1)?,
                added: row.get(3)?,
                owner_node_hash: if owner.is_empty() { None } else { Some(owner) },
                last_refreshed: row.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// Register (subscriber_hash, channel_hash), or renew it when it is held
    /// already ([`Self::renew`]).
    pub fn subscribe(&mut self, subscriber_hash: Vec<u8>, channel_hash: Vec<u8>) {
        if self.renew(&subscriber_hash, &channel_hash) {
            return;
        }
        let t = now();
        self.entries.push(SubscriptionEntry {
            subscriber_hash,
            channel_hash,
            added: t,
            owner_node_hash: None,
            last_refreshed: t,
        });
        let e = self.entries.last().expect("just pushed");
        crate::store_db::write(self.db.as_ref(), "channel subscription", |c| put_entry(c, e).map(|_| ()));
    }

    /// Record that `subscriber_hash` still wants `channel_hash`: it
    /// subscribed again, pulled the channel, or bound it on its rfed.link.
    /// Renews this node's own subscription, on disk at most once an hour; a
    /// backup row is its owner's to refresh. Returns whether the subscriber
    /// holds the subscription here at all, backup rows included, as
    /// [`Self::is_subscribed`] does.
    ///
    /// Until 2026-10-30 nothing renewed a node's own subscription: its
    /// `last_refreshed` stayed its first subscribe, and a device gone for
    /// months could not be told from one in use.
    pub fn renew(&mut self, subscriber_hash: &[u8], channel_hash: &[u8]) -> bool {
        let t = now();
        let mut held = false;
        let mut renewed = None;
        for (i, e) in self.entries.iter_mut().enumerate() {
            if e.subscriber_hash.as_slice() != subscriber_hash || e.channel_hash.as_slice() != channel_hash {
                continue;
            }
            held = true;
            if e.owner_node_hash.is_none() && t - e.last_refreshed >= RENEWAL_WRITE_INTERVAL_SECS {
                e.last_refreshed = t;
                renewed = Some(i);
            }
        }
        if let Some(i) = renewed {
            let e = &self.entries[i];
            crate::store_db::write(self.db.as_ref(), "channel subscription renewal", |c| put_entry(c, e).map(|_| ()));
        }
        held
    }

    /// Remove this node's own subscriptions to `channel_hash` that nothing
    /// renewed within `max_age_secs`, and return their subscribers. The
    /// channel fan-out calls it as it plans (`channel_rows_plan`): a device
    /// that has not subscribed, pulled or bound the channel in that long is
    /// gone, and queueing for it only crowds out everyone else's blobs (SPEC
    /// §6, §7 "Limits"). A device that comes back subscribes again when it
    /// starts. Backup rows expire by [`Self::prune_stale_backups`].
    pub fn expire_stale(&mut self, channel_hash: &[u8], max_age_secs: f64) -> Vec<Vec<u8>> {
        let cutoff = now() - max_age_secs;
        let mut expired = Vec::new();
        self.entries.retain(|e| {
            let stale = e.owner_node_hash.is_none()
                && e.channel_hash.as_slice() == channel_hash
                && e.last_refreshed < cutoff;
            if stale {
                expired.push(e.subscriber_hash.clone());
            }
            !stale
        });
        if !expired.is_empty() {
            crate::store_db::write_all(self.db.as_ref(), "expired channel subscriptions", |c| {
                let mut stmt = c.prepare_cached(
                    "DELETE FROM subscriptions WHERE subscriber_hash = ?1 AND channel_hash = ?2 AND owner_node_hash = X''",
                )?;
                for subscriber in &expired {
                    stmt.execute(rusqlite::params![subscriber, channel_hash])?;
                }
                Ok(())
            });
        }
        expired
    }

    /// Register or refresh a backup subscription from an owner node.
    ///
    /// Tags the entry with the owner's `rfed.node` destination hash.  On fanout
    /// these entries are suppressed while the owner is reachable; delivery
    /// happens only when the owner's path has decayed.
    ///
    /// If an identical entry already exists the `last_refreshed` timestamp is
    /// updated — this acts as a heartbeat for the chain-of-custody TTL.
    pub fn subscribe_backup(
        &mut self,
        subscriber_hash: Vec<u8>,
        channel_hash: Vec<u8>,
        owner_hash: Vec<u8>,
    ) {
        let index = match self.entries.iter().position(|e| {
            e.subscriber_hash == subscriber_hash
                && e.channel_hash == channel_hash
                && e.owner_node_hash.as_deref() == Some(owner_hash.as_slice())
        }) {
            Some(i) => {
                self.entries[i].last_refreshed = now();
                i
            }
            None => {
                let t = now();
                self.entries.push(SubscriptionEntry {
                    subscriber_hash,
                    channel_hash,
                    added: t,
                    owner_node_hash: Some(owner_hash),
                    last_refreshed: t,
                });
                self.entries.len() - 1
            }
        };
        let e = &self.entries[index];
        crate::store_db::write(self.db.as_ref(), "backup subscription", |c| put_entry(c, e).map(|_| ()));
    }

    /// Unregister (subscriber_hash, channel_hash).
    pub fn unsubscribe(&mut self, subscriber_hash: &[u8], channel_hash: &[u8]) {
        let before = self.entries.len();
        self.entries.retain(|e| {
            !(e.subscriber_hash.as_slice() == subscriber_hash
                && e.channel_hash.as_slice() == channel_hash)
        });
        if self.entries.len() != before {
            crate::store_db::write(self.db.as_ref(), "channel unsubscription", |c| {
                c.execute(
                    "DELETE FROM subscriptions WHERE subscriber_hash = ?1 AND channel_hash = ?2",
                    rusqlite::params![subscriber_hash, channel_hash],
                )
                .map(|_| ())
            });
        }
    }

    /// Returns all subscriber hashes for a given channel.
    /// (Superseded by `get_subscribers_with_owner`; retained for future tooling.)
    #[allow(dead_code)]
    pub fn get_subscribers(&self, channel_hash: &[u8]) -> Vec<Vec<u8>> {
        self.entries
            .iter()
            .filter(|e| e.channel_hash.as_slice() == channel_hash)
            .map(|e| e.subscriber_hash.clone())
            .collect()
    }

    /// Distinct channel hashes that have at least one local subscriber.
    /// Used by sync to filter the manifest — only offer blobs for channels
    /// someone here actually wants.
    pub fn subscribed_channel_hashes(&self) -> Vec<Vec<u8>> {
        let mut seen = std::collections::HashSet::new();
        self.entries
            .iter()
            .filter(|e| seen.insert(e.channel_hash.clone()))
            .map(|e| e.channel_hash.clone())
            .collect()
    }

    /// Returns all channel hashes a subscriber has registered for.
    #[allow(dead_code)]
    pub fn get_channels_for(&self, subscriber_hash: &[u8]) -> Vec<Vec<u8>> {
        self.entries
            .iter()
            .filter(|e| e.subscriber_hash.as_slice() == subscriber_hash)
            .map(|e| e.channel_hash.clone())
            .collect()
    }

    /// Whether a subscriber currently has a registration for a channel.
    /// Whether `subscriber_hash` holds any subscription here. Subscriptions
    /// are keyed by identity hash, so a hash found here is one.
    pub fn has_subscriber(&self, subscriber_hash: &[u8]) -> bool {
        self.entries.iter().any(|e| e.subscriber_hash.as_slice() == subscriber_hash)
    }

    pub fn is_subscribed(&self, subscriber_hash: &[u8], channel_hash: &[u8]) -> bool {
        self.entries.iter().any(|e| {
            e.subscriber_hash.as_slice() == subscriber_hash
                && e.channel_hash.as_slice() == channel_hash
        })
    }

    /// Returns all subscriber hashes with their optional owner hash for a given channel.
    ///
    /// `owner_hash` is `Some(hash)` for backup subscriptions; `None` for primary.
    pub fn get_subscribers_with_owner(
        &self,
        channel_hash: &[u8],
    ) -> Vec<(Vec<u8>, Option<Vec<u8>>)> {
        self.entries
            .iter()
            .filter(|e| e.channel_hash.as_slice() == channel_hash)
            .map(|e| (e.subscriber_hash.clone(), e.owner_node_hash.clone()))
            .collect()
    }

    /// Returns `(subscriber_hash, channel_hash, owner_node_hash)` for every
    /// backup subscription held by this node.  Used by `tick_backup_delivery`
    /// to scan for offline owners and trigger failover delivery.
    pub fn backup_entries_for_tick(&self) -> Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        self.entries
            .iter()
            .filter_map(|e| {
                e.owner_node_hash.as_ref().map(|o| {
                    (e.subscriber_hash.clone(), e.channel_hash.clone(), o.clone())
                })
            })
            .collect()
    }

    /// Remove backup entries whose `last_refreshed` timestamp is older than
    /// `max_age_secs`.  Returns the number of pruned entries.
    ///
    /// This is the passive unravel mechanism: when an upstream custodian stops
    /// re-pushing (because the original owner recovered), entries expire and
    /// the chain of custody retracts naturally.
    pub fn prune_stale_backups(&mut self, max_age_secs: f64) -> usize {
        let cutoff = now() - max_age_secs;
        let before = self.entries.len();
        self.entries.retain(|e| {
            // Keep all local (non-backup) entries unconditionally.
            // Keep backup entries only if refreshed recently.
            e.owner_node_hash.is_none() || e.last_refreshed >= cutoff
        });
        let pruned = before - self.entries.len();
        if pruned > 0 {
            crate::store_db::write(self.db.as_ref(), "stale backup subscriptions", |c| {
                c.execute(
                    "DELETE FROM subscriptions WHERE owner_node_hash != X'' AND last_refreshed < ?1",
                    [cutoff],
                )
                .map(|_| ())
            });
        }
        pruned
    }

    /// Total number of subscription entries.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static TMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn tmp_path() -> PathBuf {
        let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("rfed_subscription_test_{}_{}.rmp", std::process::id(), n));
        crate::store_db::remove_store_files(&path);
        path
    }

    const DAY: f64 = 86_400.0;

    /// Set the subscription's `last_refreshed` `days` back, in memory and on disk.
    fn age(table: &mut SubscriptionTable, subscriber: &[u8], channel: &[u8], days: f64) {
        let then = now() - days * DAY;
        for e in table.entries.iter_mut().filter(|e| e.subscriber_hash == subscriber && e.channel_hash == channel) {
            e.last_refreshed = then;
        }
        table
            .db
            .as_ref()
            .expect("stored")
            .execute(
                "UPDATE subscriptions SET last_refreshed = ?1 WHERE subscriber_hash = ?2 AND channel_hash = ?3",
                rusqlite::params![then, subscriber, channel],
            )
            .expect("age the row");
    }

    fn last_refreshed(table: &SubscriptionTable, subscriber: &[u8], channel: &[u8]) -> f64 {
        table
            .entries
            .iter()
            .find(|e| e.subscriber_hash == subscriber && e.channel_hash == channel)
            .expect("held")
            .last_refreshed
    }

    /// Nothing renewed a node's own subscription in 30 days: the fan-out's
    /// plan expires it, on that channel only, and it stays gone on reload.
    #[test]
    fn a_subscription_nothing_renewed_for_30_days_expires() {
        let path = tmp_path();
        let mut table = SubscriptionTable::load(path.clone());
        let (gone, live) = (vec![0x01; 16], vec![0x02; 16]);
        let (channel, other) = (vec![0xC1; 16], vec![0xC2; 16]);
        table.subscribe(gone.clone(), channel.clone());
        table.subscribe(gone.clone(), other.clone());
        table.subscribe(live.clone(), channel.clone());
        age(&mut table, &gone, &channel, 31.0);
        age(&mut table, &gone, &other, 31.0);
        age(&mut table, &live, &channel, 29.0);

        assert_eq!(table.expire_stale(&channel, LOCAL_SUBSCRIPTION_LIFETIME_SECS), vec![gone.clone()]);
        assert!(!table.is_subscribed(&gone, &channel));
        assert!(table.is_subscribed(&live, &channel), "29 days is within its lifetime");
        assert!(table.is_subscribed(&gone, &other), "another channel's row waits for that channel's fan-out");
        assert!(table.expire_stale(&channel, LOCAL_SUBSCRIPTION_LIFETIME_SECS).is_empty(), "once");

        let reloaded = SubscriptionTable::load(path.clone());
        assert!(!reloaded.is_subscribed(&gone, &channel), "deleted on disk too");
        assert!(reloaded.is_subscribed(&live, &channel));
        crate::store_db::remove_store_files(&path);
    }

    /// Subscribing again, pulling the channel or binding it (all `renew`)
    /// restarts the subscription's lifetime, on disk too.
    #[test]
    fn a_renewal_restarts_the_lifetime() {
        let path = tmp_path();
        let mut table = SubscriptionTable::load(path.clone());
        let (subscriber, channel) = (vec![0x03; 16], vec![0xC3; 16]);
        table.subscribe(subscriber.clone(), channel.clone());
        age(&mut table, &subscriber, &channel, 31.0);

        table.subscribe(subscriber.clone(), channel.clone());
        assert!(table.expire_stale(&channel, LOCAL_SUBSCRIPTION_LIFETIME_SECS).is_empty(), "a repeat subscribe renews");
        assert_eq!(table.len(), 1, "and adds no second row");

        age(&mut table, &subscriber, &channel, 31.0);
        assert!(table.renew(&subscriber, &channel), "a pull or a bind");
        let reloaded = SubscriptionTable::load(path.clone());
        assert!(now() - last_refreshed(&reloaded, &subscriber, &channel) < 60.0, "written to disk");
        crate::store_db::remove_store_files(&path);
    }

    /// The web client pulls every few minutes: a renewal within the hour
    /// writes nothing.
    #[test]
    fn a_renewal_is_written_at_most_once_an_hour() {
        let path = tmp_path();
        let mut table = SubscriptionTable::load(path.clone());
        let (subscriber, channel) = (vec![0x04; 16], vec![0xC4; 16]);
        table.subscribe(subscriber.clone(), channel.clone());
        age(&mut table, &subscriber, &channel, 0.5 / 24.0);
        let half_an_hour_ago = last_refreshed(&table, &subscriber, &channel);

        assert!(table.renew(&subscriber, &channel));
        assert_eq!(last_refreshed(&table, &subscriber, &channel), half_an_hour_ago, "not yet an hour");
        age(&mut table, &subscriber, &channel, 2.0 / 24.0);
        assert!(table.renew(&subscriber, &channel));
        assert!(now() - last_refreshed(&table, &subscriber, &channel) < 60.0);
        crate::store_db::remove_store_files(&path);
    }

    /// `renew` answers for backup rows as `is_subscribed` does, but a backup
    /// row is refreshed only by its owner's push, and never expires here.
    #[test]
    fn a_backup_row_is_held_but_not_renewed_or_expired_by_its_subscriber() {
        let path = tmp_path();
        let mut table = SubscriptionTable::load(path.clone());
        let (subscriber, channel, owner) = (vec![0x05; 16], vec![0xC5; 16], vec![0x0E; 16]);
        table.subscribe_backup(subscriber.clone(), channel.clone(), owner);
        age(&mut table, &subscriber, &channel, 40.0);
        let aged = last_refreshed(&table, &subscriber, &channel);

        assert!(table.renew(&subscriber, &channel));
        assert_eq!(last_refreshed(&table, &subscriber, &channel), aged);
        assert!(table.expire_stale(&channel, LOCAL_SUBSCRIPTION_LIFETIME_SECS).is_empty());
        assert!(!table.renew(&[0x06; 16], &channel), "a stranger holds nothing");
        crate::store_db::remove_store_files(&path);
    }

    /// Before 2026-10-30 a node's own row kept its first subscribe time. The
    /// first load after the upgrade starts every such row's clock, once, so
    /// nothing expires for 30 days; backup rows keep theirs.
    #[test]
    fn the_renewal_clock_starts_once_at_the_upgrade() {
        let path = tmp_path();
        let (old, channel, owner) = (vec![0x07; 16], vec![0xC7; 16], vec![0x0F; 16]);
        let long_ago = now() - 200.0 * DAY;
        {
            let conn = crate::store_db::open(&path, SUBSCRIPTION_SCHEMA).expect("db");
            for (owner, subscriber) in [(None, old.clone()), (Some(owner.clone()), vec![0x08; 16])] {
                let e = SubscriptionEntry {
                    subscriber_hash: subscriber,
                    channel_hash: channel.clone(),
                    added: long_ago,
                    owner_node_hash: owner,
                    last_refreshed: long_ago,
                };
                put_entry(&conn, &e).expect("an old row");
            }
        }

        let mut table = SubscriptionTable::load(path.clone());
        assert!(now() - last_refreshed(&table, &old, &channel) < 60.0, "its clock starts at the upgrade");
        assert_eq!(last_refreshed(&table, &[0x08; 16], &channel), long_ago, "a backup row keeps its owner's refresh");
        assert!(table.expire_stale(&channel, LOCAL_SUBSCRIPTION_LIFETIME_SECS).is_empty());

        age(&mut table, &old, &channel, 31.0);
        let reloaded = SubscriptionTable::load(path.clone());
        assert!(now() - last_refreshed(&reloaded, &old, &channel) > 30.0 * DAY, "only once");
        crate::store_db::remove_store_files(&path);
    }
}

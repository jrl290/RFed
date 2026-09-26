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
    /// Unix timestamp when this backup entry was last refreshed by its upstream
    /// custodian.  Used for TTL expiry: entries not refreshed within
    /// `2 × owner_offline_secs` are pruned so the chain of custody unravels
    /// when the original owner recovers.
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
            None => crate::store_db::read_legacy(&file_path).unwrap_or_default(),
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

    /// Register (subscriber_hash, channel_hash).  Idempotent.
    pub fn subscribe(&mut self, subscriber_hash: Vec<u8>, channel_hash: Vec<u8>) {
        let already = self.entries.iter().any(|e| {
            e.subscriber_hash == subscriber_hash && e.channel_hash == channel_hash
        });
        if !already {
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

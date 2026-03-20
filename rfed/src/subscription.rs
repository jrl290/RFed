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

pub struct SubscriptionTable {
    entries: Vec<SubscriptionEntry>,
    file_path: PathBuf,
}

impl SubscriptionTable {
    /// Load from disk, or start empty if the file doesn't exist yet.
    pub fn load(file_path: PathBuf) -> Self {
        let entries = if file_path.exists() {
            std::fs::read(&file_path)
                .ok()
                .and_then(|bytes| rmp_serde::from_slice::<Vec<SubscriptionEntry>>(&bytes).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        SubscriptionTable { entries, file_path }
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
            let _ = self.save();
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
        if let Some(existing) = self.entries.iter_mut().find(|e| {
            e.subscriber_hash == subscriber_hash
                && e.channel_hash == channel_hash
                && e.owner_node_hash.as_deref() == Some(owner_hash.as_slice())
        }) {
            existing.last_refreshed = now();
            let _ = self.save();
        } else {
            let t = now();
            self.entries.push(SubscriptionEntry {
                subscriber_hash,
                channel_hash,
                added: t,
                owner_node_hash: Some(owner_hash),
                last_refreshed: t,
            });
            let _ = self.save();
        }
    }

    /// Unregister (subscriber_hash, channel_hash).
    pub fn unsubscribe(&mut self, subscriber_hash: &[u8], channel_hash: &[u8]) {
        let before = self.entries.len();
        self.entries.retain(|e| {
            !(e.subscriber_hash.as_slice() == subscriber_hash
                && e.channel_hash.as_slice() == channel_hash)
        });
        if self.entries.len() != before {
            let _ = self.save();
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
            let _ = self.save();
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

    pub fn save(&self) -> Result<(), String> {
        let bytes = rmp_serde::to_vec(&self.entries)
            .map_err(|e| format!("Serialize subscriptions: {e}"))?;
        std::fs::write(&self.file_path, bytes)
            .map_err(|e| format!("Write subscriptions: {e}"))?;
        Ok(())
    }
}

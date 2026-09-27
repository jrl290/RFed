//! Notify dispatch and registry.
//!
//! # Two separate notification paths
//!
//! ## 1. Mobile notify (`lxmf.propagation` → `dispatch_notify`)
//! When a sender uploads a message to rfed's `lxmf.propagation` node, the
//! propagation handler checks the `NotifyRegistry`. If the recipient has
//! registered a notify relay, [`dispatch_notify`] is called routing to the
//! RNS notify adapter.
//!
//! ## 2. Channel delivery hooks (`rfed.channel` → `HookRegistry`)
//! When rfed delivers a channel blob to an online subscriber, any registered
//! [`DeliveryHook`] implementations are fired.  These are for external
//! bridge adapters. Mobile notify adapters do NOT use this path — they are
//! dispatched via `dispatch_notify` only.
//!
//! # Notify relay registration
//! A subscriber registers one or more notify relay nodes by sending their
//! 32-char lowercase hex destination hash (16-byte RNS truncated hash).
//! Multiple relay hashes may be registered for the same subscriber — all
//! will be poked when the subscriber is unreachable.
//!
//! The relay is a Reticulum node operated by the app developer.  It receives
//! a msgpack-encoded Map containing the receiver (subscriber) destination
//! hash plus optional sender and channel hashes, and is responsible for
//! forwarding a wake-up to the device (FCM, APNs, SMS, etc.) using
//! whatever credentials it holds privately.  rfed never makes outbound IP
//! connections — the notify path stays entirely within the Reticulum mesh.
//!
//! Registration protocol paths (on `rfed.notify` destination):
//!   `/rfed/notify/register`   — add a relay hash (msgpack String, 32 hex chars)
//!   `/rfed/notify/unregister` — remove a specific relay hash (same format)
//!   `/rfed/notify/clear`      — remove ALL relay registrations for the caller
//!
//! # Privacy
//! Wake payloads contain destination hashes only (receiver, and optionally
//! sender and channel).  No message content is included.
//!
//! # NotifyRegistry
//! Per-node table mapping `(subscriber_dest_hash, relay_hash)` pairs.
//! Never synced between nodes.  Only the node holding the registration fires
//! the notify, ensuring exactly one wakeup per device regardless of how many
//! nodes the subscriber visits.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use reticulum_rust::{hexrep, log, LOG_DEBUG, LOG_NOTICE};
use serde::{Deserialize, Serialize};

pub mod rns;

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

// ── Registration key ──────────────────────────────────────────────────────────

/// The key every notify registration is stored under and every wake carries
/// as `receiver`: the subscriber's `lxmf.delivery` destination hash, derived
/// from the identity hash that signed the registration. The apps register
/// their push token with the bridges under this same hash (iOS
/// `ApnsTokenRegistrar`, Android `FcmTokenRegistrar`), so a wake finds it.
///
/// Until 2026-09-26 channel registrations and channel wakes used the raw
/// identity hash while LXMF and distro used this one: every channel wake
/// reached the bridge under a hash no token was registered for, and was
/// dropped there ("no APNs token registered"), since 1edc791 (2026-04-20).
pub fn notify_key(identity_hash: &[u8]) -> Vec<u8> {
    reticulum_rust::destination::Destination::hash(Some(identity_hash), "lxmf", &["delivery"])
}

// ── Relay hash validation ─────────────────────────────────────────────────────

/// Validate a push relay destination hash at registration time.
///
/// The hash must be a 32-char lowercase hexadecimal string (16-byte RNS
/// truncated destination hash).  No URI scheme prefix is accepted or
/// required.
pub fn validate_relay_hash(hash: &str) -> Result<(), String> {
    if hash.len() != 32 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("relay hash must be a 32-char lowercase hex destination hash".into());
    }
    Ok(())
}

// ── DeliveryHook ─────────────────────────────────────────────────────────────

/// Single interface implemented by all notify/bridge adapters.
///
/// `on_deliver` is called once per outer-envelope delivery attempt, after the
/// Reticulum packet has been queued.  Implementations MUST return quickly;
/// any blocking I/O should be dispatched on a background thread.
pub trait DeliveryHook: Send + Sync {
    /// Fire a wake-up ping toward `subscriber_pubkey`.
    ///
    /// `inner_blob` is available for metadata extraction but MUST NOT be
    /// forwarded as notify payload content (privacy-by-design requirement).
    fn on_deliver(&self, subscriber_pubkey: &[u8], inner_blob: &[u8]);
}

// ── Notify registration ───────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
pub struct NotifyRegistration {
    /// 16-byte truncated RNS destination hash of the subscriber.
    pub subscriber_hash: Vec<u8>,
    /// 16-byte channel hash this registration covers, or `None` for LXMF
    /// propagation notifications (global, not channel-specific).
    #[serde(default)]
    pub channel_hash: Option<Vec<u8>>,
    /// 32-char lowercase hex destination hash of the notify relay node.
    pub relay_hash: String,
    /// When the registration was last updated (Unix timestamp).
    pub registered: f64,
}

// ── NotifyRegistry ────────────────────────────────────────────────────────────

/// Per-node notify registration table.  Never synced between peers.
///
/// Persisted in `notify_registrations.sqlite3`, one row per registration
/// (crate::store_db); the channel of an LXMF registration (`None`) is stored
/// as an empty blob, so the triple stays unique.
pub struct NotifyRegistry {
    registrations: Vec<NotifyRegistration>,
    db: Option<rusqlite::Connection>,
}

const NOTIFY_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS notify_registrations (
        subscriber_hash BLOB NOT NULL,
        channel_hash    BLOB NOT NULL,
        relay_hash      TEXT NOT NULL,
        registered      REAL NOT NULL,
        UNIQUE (subscriber_hash, channel_hash, relay_hash)
    );";

/// Channel registrations stored before 2026-09-26 are keyed by the identity
/// hash; re-key them to [`notify_key`] once (PRAGMA user_version 0 -> 1), in
/// one transaction. LXMF rows already use the delivery hash and are left
/// alone. A row the new key already holds keeps the later timestamp.
fn rekey_channel_rows(conn: &rusqlite::Connection) -> rusqlite::Result<usize> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if version >= 1 {
        return Ok(0);
    }
    let tx = conn.unchecked_transaction()?;
    let rows: Vec<(i64, Vec<u8>, Vec<u8>, String, f64)> = {
        let mut stmt = tx.prepare(
            "SELECT rowid, subscriber_hash, channel_hash, relay_hash, registered
             FROM notify_registrations WHERE channel_hash != X''",
        )?;
        let mapped = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)))?;
        mapped.collect::<rusqlite::Result<_>>()?
    };
    for (rowid, subscriber, channel, relay, registered) in &rows {
        tx.execute(
            "INSERT INTO notify_registrations (subscriber_hash, channel_hash, relay_hash, registered)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (subscriber_hash, channel_hash, relay_hash)
             DO UPDATE SET registered = max(registered, excluded.registered)",
            rusqlite::params![notify_key(subscriber), channel, relay, registered],
        )?;
        tx.execute("DELETE FROM notify_registrations WHERE rowid = ?1", [rowid])?;
    }
    tx.execute_batch("PRAGMA user_version = 1")?;
    tx.commit()?;
    Ok(rows.len())
}

fn channel_key(channel_hash: Option<&[u8]>) -> &[u8] {
    channel_hash.unwrap_or(&[])
}

fn put_registration(conn: &rusqlite::Connection, r: &NotifyRegistration) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO notify_registrations (subscriber_hash, channel_hash, relay_hash, registered)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (subscriber_hash, channel_hash, relay_hash) DO UPDATE SET registered = excluded.registered",
        rusqlite::params![r.subscriber_hash, channel_key(r.channel_hash.as_deref()), r.relay_hash, r.registered],
    )
}

impl NotifyRegistry {
    /// Load the registrations kept beside `file_path` (the old msgpack file,
    /// imported once if present).
    pub fn load(file_path: PathBuf) -> Self {
        let db = crate::store_db::open(&file_path, NOTIFY_SCHEMA);
        let registrations = match &db {
            Some(conn) => {
                crate::store_db::import_legacy(conn, &file_path, "notify registrations", |tx, old: Vec<NotifyRegistration>| {
                    let mut n = 0;
                    for r in &old {
                        n += put_registration(tx, r)?;
                    }
                    Ok(n)
                });
                match rekey_channel_rows(conn) {
                    Ok(0) => {}
                    Ok(n) => log(
                        format!("[store] re-keyed {n} channel notify registration(s) to the lxmf.delivery hash"),
                        LOG_NOTICE,
                        false,
                        false,
                    ),
                    Err(e) => log(
                        format!("[store] channel notify registrations could not be re-keyed: {e}"),
                        reticulum_rust::LOG_ERROR,
                        false,
                        false,
                    ),
                }
                Self::read_all(conn).unwrap_or_else(|e| {
                    log(format!("[store] notify registrations could not be read: {e}"), reticulum_rust::LOG_ERROR, false, false);
                    Vec::new()
                })
            }
            // No database: the old file is read as-is, and its channel
            // rows were stored under the identity hash.
            None => crate::store_db::read_legacy::<Vec<NotifyRegistration>>(&file_path)
                .unwrap_or_default()
                .into_iter()
                .map(|mut r| {
                    if r.channel_hash.is_some() {
                        r.subscriber_hash = notify_key(&r.subscriber_hash);
                    }
                    r
                })
                .collect(),
        };
        NotifyRegistry { registrations, db }
    }

    fn read_all(conn: &rusqlite::Connection) -> rusqlite::Result<Vec<NotifyRegistration>> {
        let mut stmt = conn.prepare(
            "SELECT subscriber_hash, channel_hash, relay_hash, registered FROM notify_registrations ORDER BY rowid",
        )?;
        let rows = stmt.query_map([], |row| {
            let channel: Vec<u8> = row.get(1)?;
            Ok(NotifyRegistration {
                subscriber_hash: row.get(0)?,
                channel_hash: if channel.is_empty() { None } else { Some(channel) },
                relay_hash: row.get(2)?,
                registered: row.get(3)?,
            })
        })?;
        rows.collect()
    }

    /// Register or refresh a notify relay for `(subscriber_hash, channel_hash)`.
    ///
    /// `channel_hash` is `None` for LXMF propagation notifications and
    /// `Some(16-byte hash)` for a specific rfed.channel subscription.
    ///
    /// If the exact `(subscriber, channel, relay)` triple already exists the
    /// timestamp is refreshed.  Otherwise a new entry is appended.
    /// A subscriber may register multiple relay hashes for the same channel.
    pub fn register(&mut self, subscriber_hash: Vec<u8>, channel_hash: Option<Vec<u8>>, relay_hash: String) {
        let index = match self.registrations.iter().position(|r| {
            r.subscriber_hash == subscriber_hash
                && r.channel_hash == channel_hash
                && r.relay_hash == relay_hash
        }) {
            Some(i) => {
                self.registrations[i].registered = now();
                i
            }
            None => {
                self.registrations.push(NotifyRegistration {
                    subscriber_hash,
                    channel_hash,
                    relay_hash,
                    registered: now(),
                });
                self.registrations.len() - 1
            }
        };
        let r = &self.registrations[index];
        crate::store_db::write(self.db.as_ref(), "notify registration", |c| put_registration(c, r).map(|_| ()));
    }

    /// Remove a specific relay registration for `(subscriber_hash, channel_hash)`.
    pub fn unregister(&mut self, subscriber_hash: &[u8], channel_hash: Option<&[u8]>, relay_hash: &str) {
        let before = self.registrations.len();
        self.registrations.retain(|r| {
            !(r.subscriber_hash.as_slice() == subscriber_hash
              && r.channel_hash.as_deref() == channel_hash
              && r.relay_hash == relay_hash)
        });
        if self.registrations.len() != before {
            crate::store_db::write(self.db.as_ref(), "notify unregistration", |c| {
                c.execute(
                    "DELETE FROM notify_registrations WHERE subscriber_hash = ?1 AND channel_hash = ?2 AND relay_hash = ?3",
                    rusqlite::params![subscriber_hash, channel_key(channel_hash), relay_hash],
                )
                .map(|_| ())
            });
        }
    }

    /// Remove ALL relay registrations for a subscriber (all channels + LXMF).
    pub fn clear(&mut self, subscriber_hash: &[u8]) {
        let before = self.registrations.len();
        self.registrations.retain(|r| r.subscriber_hash.as_slice() != subscriber_hash);
        if self.registrations.len() != before {
            crate::store_db::write(self.db.as_ref(), "notify clear", |c| {
                c.execute("DELETE FROM notify_registrations WHERE subscriber_hash = ?1", [subscriber_hash])
                    .map(|_| ())
            });
        }
    }

    /// Lookup all registrations for `(subscriber_hash, channel_hash)`.
    ///
    /// Pass `channel_hash = None` to match LXMF propagation registrations.
    /// Pass `channel_hash = Some(hash)` to match a specific rfed.channel.
    pub fn get_for_channel<'a>(&'a self, subscriber_hash: &[u8], channel_hash: Option<&[u8]>) -> Vec<&'a NotifyRegistration> {
        self.registrations
            .iter()
            .filter(|r| {
                r.subscriber_hash.as_slice() == subscriber_hash
                    && r.channel_hash.as_deref() == channel_hash
            })
            .collect()
    }

    pub fn count(&self) -> usize {
        self.registrations.len()
    }
}

// ── HookRegistry ─────────────────────────────────────────────────────────────

/// Ordered registry of delivery hooks.
///
/// Hooks are registered at startup; the node itself has zero application-
/// specific logic.  Each hook is called for every delivery event in
/// registration order.
pub struct HookRegistry {
    hooks: Vec<Box<dyn DeliveryHook>>,
}

impl HookRegistry {
    pub fn new() -> Self {
        HookRegistry { hooks: Vec::new() }
    }

    /// Register a new delivery hook.
    pub fn register(&mut self, hook: Box<dyn DeliveryHook>) {
        self.hooks.push(hook);
    }

    /// Fire all registered hooks for a delivery event.
    pub fn on_deliver(&self, subscriber_pubkey: &[u8], inner_blob: &[u8]) {
        for hook in &self.hooks {
            hook.on_deliver(subscriber_pubkey, inner_blob);
        }
    }
}

impl Default for HookRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Notify dispatch ───────────────────────────────────────────────────────────

/// Send a notify wake-up for `reg` via the RNS adapter and report whether its
/// packet left.
///
/// Called by the LXMF propagation ingest path when a message arrives for a
/// notify-registered destination, and by the channel and distro fan-outs for
/// subscribers they deferred, and by main.rs for the backup tick's adopted
/// subscribers. It never waits on the network, but it is a packet send:
/// snapshot the registrations and release the registry and the FedNode mutex
/// first.
pub fn dispatch_notify(
    reg: &NotifyRegistration,
    sender: Option<&[u8]>,
    channel: Option<&[u8]>,
) -> rns::WakeOutcome {
    dispatch_notify_via(&rns::LiveStack, reg, sender, channel)
}

/// [`dispatch_notify`] on the given stack. The tests pass a fake one.
pub fn dispatch_notify_via(
    stack: &dyn rns::RelayStack,
    reg: &NotifyRegistration,
    sender: Option<&[u8]>,
    channel: Option<&[u8]>,
) -> rns::WakeOutcome {
    log(
        format!(
            "[notify] dispatch START relay={} subscriber={} sender={} channel={}",
            &reg.relay_hash,
            hexrep(&reg.subscriber_hash, false),
            sender.map(|s| hexrep(s, false)).unwrap_or_else(|| "(none)".to_string()),
            channel.map(|c| hexrep(c, false)).unwrap_or_else(|| "(none)".to_string()),
        ),
        LOG_DEBUG,
        false,
        false,
    );
    rns::dispatch(stack, reg, sender, channel)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("rfed_notify_{label}_{unique}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_notify_key_is_the_lxmf_delivery_hash() {
        let identity = reticulum_rust::identity::Identity::new(true);
        let hash = identity.hash.clone().unwrap();
        let delivery = reticulum_rust::destination::Destination::hash(Some(&hash), "lxmf", &["delivery"]);
        assert_eq!(notify_key(&hash), delivery);
    }

    /// A database from before 2026-09-26 holds channel rows under the
    /// identity hash. The first load re-keys them to the delivery hash, once;
    /// LXMF rows and rows stored the new way are left alone.
    #[test]
    fn channel_rows_stored_under_the_identity_hash_are_rekeyed_once() {
        let dir = temp_dir("rekey");
        let legacy = dir.join("notify_registrations.rmp");
        let identity_hash = vec![7u8; 16];
        let channel = vec![9u8; 16];
        let relay = "a".repeat(32);
        {
            let conn = crate::store_db::open(&legacy, NOTIFY_SCHEMA).unwrap();
            let old = |sub: Vec<u8>, ch: Option<Vec<u8>>, t: f64| NotifyRegistration {
                subscriber_hash: sub, channel_hash: ch, relay_hash: relay.clone(), registered: t,
            };
            put_registration(&conn, &old(identity_hash.clone(), Some(channel.clone()), 1.0)).unwrap();
            put_registration(&conn, &old(notify_key(&identity_hash), None, 2.0)).unwrap();
            // user_version stays 0: a database written before the re-key.
        }

        let mut registry = NotifyRegistry::load(legacy.clone());
        assert_eq!(registry.count(), 2);
        assert!(registry.get_for_channel(&identity_hash, Some(&channel)).is_empty());
        assert_eq!(registry.get_for_channel(&notify_key(&identity_hash), Some(&channel)).len(), 1);
        assert_eq!(registry.get_for_channel(&notify_key(&identity_hash), None).len(), 1, "LXMF row untouched");

        // Stored the new way after the re-key: a later load does not move it.
        let other = notify_key(&[8u8; 16]);
        registry.register(other.clone(), Some(channel.clone()), relay.clone());
        drop(registry);
        let mut registry = NotifyRegistry::load(legacy.clone());
        assert_eq!(registry.count(), 3);
        assert_eq!(registry.get_for_channel(&other, Some(&channel)).len(), 1, "not re-keyed twice");

        // A channel unregister (under the new key) reaches the re-keyed row.
        registry.unregister(&notify_key(&identity_hash), Some(&channel), &relay);
        drop(registry);
        assert_eq!(NotifyRegistry::load(legacy).count(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }
}

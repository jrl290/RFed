//! SQLite persistence for rfed's stores: notify registrations, channel
//! subscriptions, distro devices and announces, and the deferred queue.
//!
//! Each store keeps its data in memory as before and writes every change to
//! its own database beside its old msgpack file (`notify_registrations.rmp`
//! becomes `notify_registrations.sqlite3`): one statement, or one transaction,
//! per change, never the whole store. WAL with synchronous=NORMAL: a process
//! killed at any point leaves the database whole.
//!
//! Until 2026-09-26 every change rewrote the store's whole msgpack file in
//! place, and a file that did not decode loaded as empty (`unwrap_or_default`)
//! and was then overwritten by the next change: a stop mid-write could
//! silently lose every notify registration, queued message, distro device or
//! subscription. Reticulum-rust a7a5a3a fixed the same flaw in its known
//! destinations.
//!
//! The old file is imported once and renamed (`<file>.imported-<secs>`); one
//! that cannot be read is set aside (`<file>.unreadable-<secs>`) and logged,
//! never overwritten. A database that cannot be opened is set aside and a new
//! one made; if even that fails the store runs from memory and says so.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reticulum_rust::{log, LOG_ERROR, LOG_NOTICE};
use rusqlite::Connection;
use serde::de::DeserializeOwned;

/// The database for the store whose old file is `legacy_path`.
pub fn db_path(legacy_path: &Path) -> PathBuf {
    legacy_path.with_extension("sqlite3")
}

/// Open the store's database with `schema` applied. None only when neither
/// the database nor a fresh one in its place can be opened (logged).
pub fn open(legacy_path: &Path, schema: &str) -> Option<Connection> {
    let path = db_path(legacy_path);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    match open_at(&path, schema) {
        Ok(conn) => Some(conn),
        Err(first) => {
            let aside = set_aside(&path);
            log(
                format!(
                    "[store] {} could not be opened ({first}); set aside as {}, starting a new one",
                    path.display(),
                    aside.map(|p| p.display().to_string()).unwrap_or_else(|| "(not moved)".into()),
                ),
                LOG_ERROR,
                false,
                false,
            );
            match open_at(&path, schema) {
                Ok(conn) => Some(conn),
                Err(e) => {
                    log(
                        format!("[store] {} could not be created ({e}); this store runs from memory and nothing is saved", path.display()),
                        LOG_ERROR,
                        false,
                        false,
                    );
                    None
                }
            }
        }
    }
}

fn open_at(path: &Path, schema: &str) -> Result<Connection, String> {
    let conn = Connection::open(path).map_err(|e| e.to_string())?;
    conn.busy_timeout(Duration::from_secs(2)).map_err(|e| e.to_string())?;
    // A file that is not a database fails here.
    conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(())).map_err(|e| e.to_string())?;
    conn.execute_batch("PRAGMA synchronous=NORMAL;").map_err(|e| e.to_string())?;
    conn.execute_batch(schema).map_err(|e| e.to_string())?;
    Ok(conn)
}

/// Import the store's old msgpack file, once: `insert` writes its rows in one
/// transaction (rows the database already holds are the caller's to keep).
/// The file is then renamed; one that cannot be read is set aside. Both are
/// logged.
pub fn import_legacy<T: DeserializeOwned>(
    conn: &Connection,
    legacy_path: &Path,
    what: &str,
    insert: impl FnOnce(&Connection, T) -> rusqlite::Result<usize>,
) {
    if !legacy_path.is_file() {
        return;
    }
    match read_legacy::<T>(legacy_path) {
        Ok(value) => {
            let written = (|| {
                let tx = conn.unchecked_transaction()?;
                let n = insert(&tx, value)?;
                tx.commit()?;
                Ok::<usize, rusqlite::Error>(n)
            })();
            match written {
                Ok(n) => {
                    let kept = rename_with_stamp(legacy_path, "imported");
                    log(
                        format!(
                            "[store] imported {n} {what} from {} (kept as {})",
                            legacy_path.display(),
                            kept.map(|p| p.display().to_string()).unwrap_or_else(|| "(not moved)".into()),
                        ),
                        LOG_NOTICE,
                        false,
                        false,
                    );
                }
                // Left in place: the next start tries again.
                Err(e) => log(
                    format!("[store] could not import {what} from {}: {e}", legacy_path.display()),
                    LOG_ERROR,
                    false,
                    false,
                ),
            }
        }
        Err(e) => {
            let aside = rename_with_stamp(legacy_path, "unreadable");
            log(
                format!(
                    "[store] {} could not be read ({e}); set aside as {}, its {what} are not loaded",
                    legacy_path.display(),
                    aside.map(|p| p.display().to_string()).unwrap_or_else(|| "(not moved)".into()),
                ),
                LOG_ERROR,
                false,
                false,
            );
        }
    }
}

/// Decode the old msgpack file (for a store whose database could not be
/// opened: it still starts with what the file holds).
pub fn read_legacy<T: DeserializeOwned>(legacy_path: &Path) -> Result<T, String> {
    let bytes = fs::read(legacy_path).map_err(|e| e.to_string())?;
    rmp_serde::from_slice::<T>(&bytes).map_err(|e| e.to_string())
}

/// Apply one change to the store's database. A failure is logged, never
/// dropped; the in-memory state keeps the change either way.
pub fn write(conn: Option<&Connection>, what: &str, change: impl FnOnce(&Connection) -> rusqlite::Result<()>) {
    if let Some(conn) = conn {
        if let Err(e) = change(conn) {
            log(format!("[store] {what} not saved: {e}"), LOG_ERROR, false, false);
        }
    }
}

/// Apply several statements as one transaction (see [`write`]).
pub fn write_all(conn: Option<&Connection>, what: &str, change: impl FnOnce(&Connection) -> rusqlite::Result<()>) {
    write(conn, what, |conn| {
        let tx = conn.unchecked_transaction()?;
        change(&tx)?;
        tx.commit()
    })
}

fn unix_now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn rename_with_stamp(path: &Path, label: &str) -> Option<PathBuf> {
    let target = PathBuf::from(format!("{}.{label}-{}", path.display(), unix_now_secs()));
    fs::rename(path, &target).ok().map(|_| target)
}

fn set_aside(db: &Path) -> Option<PathBuf> {
    let moved = rename_with_stamp(db, "unreadable")?;
    for suffix in ["-wal", "-shm"] {
        let companion = PathBuf::from(format!("{}{suffix}", db.display()));
        if companion.exists() {
            let _ = fs::rename(&companion, format!("{}{suffix}", moved.display()));
        }
    }
    Some(moved)
}

/// Test helper: remove a store's old file, database and WAL files.
#[cfg(test)]
pub fn remove_store_files(legacy_path: &Path) {
    let db = db_path(legacy_path);
    let _ = fs::remove_file(legacy_path);
    let _ = fs::remove_file(&db);
    for suffix in ["-wal", "-shm"] {
        let _ = fs::remove_file(format!("{}{suffix}", db.display()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deferred_queue::DeferredQueue;
    use crate::distro::{DistroAnnounceStore, DistroTable};
    use crate::notify::{NotifyRegistration, NotifyRegistry};
    use crate::subscription::{SubscriptionEntry, SubscriptionTable};

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("rfed_store_db_{label}_{}_{unique}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn files_starting(dir: &Path, prefix: &str) -> Vec<PathBuf> {
        fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.file_name().unwrap().to_str().unwrap().starts_with(prefix))
            .collect()
    }

    fn registration(sub: u8, channel: Option<u8>, relay: char) -> NotifyRegistration {
        NotifyRegistration {
            subscriber_hash: vec![sub; 16],
            channel_hash: channel.map(|c| vec![c; 16]),
            relay_hash: relay.to_string().repeat(32),
            registered: 1.0,
        }
    }

    /// The upgrade: the old file's rows are kept, the file is renamed (not
    /// deleted) and imported once.
    #[test]
    fn a_legacy_file_is_imported_once_and_kept() {
        let dir = temp_dir("import");
        let legacy = dir.join("notify_registrations.rmp");
        let old = vec![registration(1, None, 'a'), registration(2, Some(9), 'b')];
        let bytes = rmp_serde::to_vec(&old).unwrap();
        fs::write(&legacy, &bytes).unwrap();

        let mut registry = NotifyRegistry::load(legacy.clone());
        assert_eq!(registry.count(), 2);
        assert!(!legacy.exists());
        let kept = files_starting(&dir, "notify_registrations.rmp.imported-");
        assert_eq!(kept.len(), 1);
        assert_eq!(fs::read(&kept[0]).unwrap(), bytes, "kept byte for byte");

        registry.register(vec![3; 16], None, "c".repeat(32));
        drop(registry);
        let registry = NotifyRegistry::load(legacy);
        assert_eq!(registry.count(), 3, "stored, and not imported twice");
        // An imported channel row was stored under the identity hash; the
        // one-time re-key moved it to the delivery hash.
        assert!(registry.get_for_channel(&[2; 16], Some(&[9; 16])).is_empty());
        assert_eq!(registry.get_for_channel(&crate::notify::notify_key(&[2; 16]), Some(&[9; 16])).len(), 1);
        fs::remove_dir_all(dir).ok();
    }

    /// The flaw this replaces: a file cut off mid-write loaded as empty and
    /// the next change overwrote it. Now it is set aside intact.
    #[test]
    fn a_truncated_legacy_file_is_set_aside_not_overwritten() {
        let dir = temp_dir("truncated");
        let legacy = dir.join("subscriptions.rmp");
        let old: Vec<SubscriptionEntry> = (0..20u8)
            .map(|i| SubscriptionEntry {
                subscriber_hash: vec![i; 16],
                channel_hash: vec![7; 16],
                added: 1.0,
                owner_node_hash: None,
                last_refreshed: 1.0,
            })
            .collect();
        let bytes = rmp_serde::to_vec(&old).unwrap();
        let truncated = &bytes[..bytes.len() / 2];
        fs::write(&legacy, truncated).unwrap();

        let mut table = SubscriptionTable::load(legacy.clone());
        assert!(table.is_empty());
        table.subscribe(vec![42; 16], vec![7; 16]);
        let aside = files_starting(&dir, "subscriptions.rmp.unreadable-");
        assert_eq!(aside.len(), 1);
        assert_eq!(fs::read(&aside[0]).unwrap(), truncated, "kept byte for byte");
        drop(table);
        assert!(SubscriptionTable::load(legacy).is_subscribed(&[42; 16], &[7; 16]));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_database_that_cannot_be_read_is_set_aside() {
        let dir = temp_dir("baddb");
        let legacy = dir.join("distro.rmp");
        fs::write(db_path(&legacy), b"not a database, and longer than a header check").unwrap();

        let mut table = DistroTable::load(legacy.clone());
        table.register(vec![1; 16], vec![2; 16], vec![3; 64]);
        assert_eq!(files_starting(&dir, "distro.sqlite3.unreadable-").len(), 1);
        drop(table);
        assert!(DistroTable::load(legacy).is_distro(&[1; 16]));
        fs::remove_dir_all(dir).ok();
    }

    /// An LXMF registration has no channel; it must still be one row, and
    /// unregister and clear must reach the database.
    #[test]
    fn notify_registrations_stay_unique_and_changes_persist() {
        let dir = temp_dir("notify");
        let legacy = dir.join("notify_registrations.rmp");
        let relay = "d".repeat(32);
        {
            let mut r = NotifyRegistry::load(legacy.clone());
            r.register(vec![1; 16], None, relay.clone());
            r.register(vec![1; 16], None, relay.clone());
            r.register(vec![1; 16], Some(vec![5; 16]), relay.clone());
            r.register(vec![2; 16], None, relay.clone());
            r.unregister(&[1; 16], Some(&[5; 16]), &relay);
            r.clear(&[2; 16]);
        }
        let r = NotifyRegistry::load(legacy);
        assert_eq!(r.count(), 1);
        assert_eq!(r.get_for_channel(&[1; 16], None).len(), 1);
        fs::remove_dir_all(dir).ok();
    }

    /// The deferred queue holds undelivered messages: order, per-subscriber
    /// eviction and drains must all be what a restart finds.
    #[test]
    fn the_deferred_queue_keeps_order_evictions_and_drains_across_a_reopen() {
        let dir = temp_dir("deferred");
        let legacy = dir.join("deferred_delivery.rmp");
        let (sub, chan_a, chan_b) = (vec![1u8; 16], vec![0xA; 16], vec![0xB; 16]);
        {
            let mut q = DeferredQueue::load(legacy.clone());
            for i in 0..5u8 {
                q.enqueue(sub.clone(), chan_a.clone(), vec![i], 3); // keeps the last 3
            }
            q.enqueue(sub.clone(), chan_b.clone(), vec![9], 10);
        }
        {
            let mut q = DeferredQueue::load(legacy.clone());
            assert_eq!(q.total_len(), 4);
            let page = q.drain_channel_batch(&sub, &chan_a, 1);
            assert_eq!(page.iter().map(|p| p.blob[0]).collect::<Vec<_>>(), vec![2], "oldest kept first");
        }
        let mut q = DeferredQueue::load(legacy);
        let rest = q.drain_batch(&sub, 10);
        assert_eq!(rest.iter().map(|p| p.blob[0]).collect::<Vec<_>>(), vec![3, 4, 9], "drained rows stay gone");
        drop(q);
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn backup_subscriptions_refresh_and_prune_across_a_reopen() {
        let dir = temp_dir("subs");
        let legacy = dir.join("subscriptions.rmp");
        {
            let mut t = SubscriptionTable::load(legacy.clone());
            t.subscribe(vec![1; 16], vec![7; 16]);
            t.subscribe_backup(vec![2; 16], vec![7; 16], vec![8; 16]);
            t.subscribe_backup(vec![2; 16], vec![7; 16], vec![8; 16]); // refresh, not a second row
            assert_eq!(t.len(), 2);
        }
        {
            let mut t = SubscriptionTable::load(legacy.clone());
            assert_eq!(t.len(), 2);
            assert_eq!(t.backup_entries_for_tick().len(), 1);
            assert_eq!(t.prune_stale_backups(-1.0), 1, "every backup is stale");
        }
        let t = SubscriptionTable::load(legacy);
        assert_eq!(t.len(), 1);
        assert!(t.is_subscribed(&[1; 16], &[7; 16]));
        fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn a_replaced_distro_announce_is_one_row() {
        let dir = temp_dir("announces");
        let legacy = dir.join("distro_announces.rmp");
        {
            let mut s = DistroAnnounceStore::load(legacy.clone());
            s.put(vec![1; 16], vec![1], false);
            s.put(vec![2; 16], vec![2], true);
            s.put(vec![1; 16], vec![3], true);
        }
        {
            let mut s = DistroAnnounceStore::load(legacy.clone());
            let order: Vec<u8> = s.snapshot().iter().map(|a| a.distro_lxmf_hash[0]).collect();
            assert_eq!(order, vec![2, 1], "a replaced announce moves to the end");
            assert_eq!(s.get(&[1; 16]).unwrap().announce_data, vec![3]);
            s.remove(&[2; 16]);
        }
        assert_eq!(DistroAnnounceStore::load(legacy).snapshot().len(), 1);
        fs::remove_dir_all(dir).ok();
    }
}

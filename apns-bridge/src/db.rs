//! SQLite-backed token registry: subscriber_hash (hex) → APNs device token.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct TokenDB {
    conn: Connection,
}

impl TokenDB {
    /// Open (or create) the SQLite database at `path`.
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tokens (
                subscriber_hash TEXT NOT NULL PRIMARY KEY,
                apns_token      TEXT NOT NULL,
                registered      INTEGER NOT NULL,
                updated         INTEGER NOT NULL
            );",
        )?;
        Ok(TokenDB { conn })
    }

    /// Insert or update a subscriber_hash → apns_token mapping.
    pub fn register(&self, subscriber_hash: &str, apns_token: &str) -> Result<(), rusqlite::Error> {
        let now = now_secs();
        self.conn.execute(
            "INSERT INTO tokens (subscriber_hash, apns_token, registered, updated)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(subscriber_hash) DO UPDATE SET
                 apns_token = excluded.apns_token,
                 updated    = excluded.updated",
            params![subscriber_hash, apns_token, now],
        )?;
        Ok(())
    }

    /// Look up an APNs token by subscriber_hash.
    pub fn get_token(&self, subscriber_hash: &str) -> Result<Option<String>, rusqlite::Error> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT apns_token FROM tokens WHERE subscriber_hash = ?1 LIMIT 1",
        )?;
        let mut rows = stmt.query(params![subscriber_hash])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    /// Remove a registration by subscriber_hash.  Returns true if a row was deleted.
    pub fn unregister(&self, subscriber_hash: &str) -> Result<bool, rusqlite::Error> {
        let n = self.conn.execute(
            "DELETE FROM tokens WHERE subscriber_hash = ?1",
            params![subscriber_hash],
        )?;
        Ok(n > 0)
    }

    /// Remove a registration by APNs token (called when APNs responds 410 / BadDeviceToken).
    pub fn invalidate_token(&self, apns_token: &str) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "DELETE FROM tokens WHERE apns_token = ?1",
            params![apns_token],
        )?;
        Ok(())
    }

    /// Total number of registered tokens.
    pub fn count(&self) -> Result<i64, rusqlite::Error> {
        self.conn
            .query_row("SELECT COUNT(*) FROM tokens", [], |row| row.get(0))
    }
}

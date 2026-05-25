//! SQLite-backed token registry: subscriber_hash (hex) → FCM registration token.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};

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
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS tokens (
                subscriber_hash TEXT NOT NULL PRIMARY KEY,
                fcm_token       TEXT NOT NULL,
                registered      INTEGER NOT NULL,
                updated         INTEGER NOT NULL
            );",
        )?;
        Ok(TokenDB { conn })
    }

    pub fn register(&self, subscriber_hash: &str, fcm_token: &str) -> Result<(), rusqlite::Error> {
        let now = now_secs();
        self.conn.execute(
            "INSERT INTO tokens (subscriber_hash, fcm_token, registered, updated)
             VALUES (?1, ?2, ?3, ?3)
             ON CONFLICT(subscriber_hash) DO UPDATE SET
                 fcm_token = excluded.fcm_token,
                 updated   = excluded.updated",
            params![subscriber_hash, fcm_token, now],
        )?;
        Ok(())
    }

    pub fn get_token(&self, subscriber_hash: &str) -> Result<Option<String>, rusqlite::Error> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT fcm_token FROM tokens WHERE subscriber_hash = ?1 LIMIT 1",
        )?;
        let mut rows = stmt.query(params![subscriber_hash])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn unregister(&self, subscriber_hash: &str) -> Result<bool, rusqlite::Error> {
        let n = self.conn.execute(
            "DELETE FROM tokens WHERE subscriber_hash = ?1",
            params![subscriber_hash],
        )?;
        Ok(n > 0)
    }

    pub fn invalidate_token(&self, fcm_token: &str) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "DELETE FROM tokens WHERE fcm_token = ?1",
            params![fcm_token],
        )?;
        Ok(())
    }

    pub fn count(&self) -> Result<i64, rusqlite::Error> {
        self.conn
            .query_row("SELECT COUNT(*) FROM tokens", [], |row| row.get(0))
    }
}
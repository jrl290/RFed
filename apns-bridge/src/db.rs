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

/// APNs environment a token was issued against.  Tokens are scoped to one
/// gateway (sandbox or production) and `BadDeviceToken` is returned when
/// pushing a sandbox token through prod (or vice versa), so the bridge has
/// to remember which gateway each token belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApnsEnv {
    Sandbox,
    Production,
}

impl ApnsEnv {
    pub fn as_db_str(self) -> &'static str {
        match self {
            ApnsEnv::Sandbox => "sandbox",
            ApnsEnv::Production => "production",
        }
    }

    pub fn parse(s: &str) -> Option<ApnsEnv> {
        match s.trim().to_lowercase().as_str() {
            "sandbox" | "development" | "dev" => Some(ApnsEnv::Sandbox),
            "production" | "prod" => Some(ApnsEnv::Production),
            _ => None,
        }
    }
}

pub struct TokenDB {
    conn: Connection,
}

impl TokenDB {
    /// Open (or create) the SQLite database at `path`.
    ///
    /// Schema migrations:
    ///   v1 → v2: add `env` column (default "production" for existing rows
    ///   so an existing prod-only deployment keeps working unchanged).
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

        // Add `env` column if it doesn't exist yet (migration from v1).
        let env_exists: bool = conn
            .prepare("PRAGMA table_info(tokens)")?
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(Result::ok)
            .any(|name| name == "env");
        if !env_exists {
            conn.execute_batch(
                "ALTER TABLE tokens ADD COLUMN env TEXT NOT NULL DEFAULT 'production';",
            )?;
        }

        Ok(TokenDB { conn })
    }

    /// Insert or update a subscriber_hash → (apns_token, env) mapping.
    pub fn register(
        &self,
        subscriber_hash: &str,
        apns_token: &str,
        env: ApnsEnv,
    ) -> Result<(), rusqlite::Error> {
        let now = now_secs();
        self.conn.execute(
            "INSERT INTO tokens (subscriber_hash, apns_token, env, registered, updated)
             VALUES (?1, ?2, ?3, ?4, ?4)
             ON CONFLICT(subscriber_hash) DO UPDATE SET
                 apns_token = excluded.apns_token,
                 env        = excluded.env,
                 updated    = excluded.updated",
            params![subscriber_hash, apns_token, env.as_db_str(), now],
        )?;
        Ok(())
    }

    /// Look up an APNs token + environment by subscriber_hash.
    pub fn get_token(
        &self,
        subscriber_hash: &str,
    ) -> Result<Option<(String, ApnsEnv)>, rusqlite::Error> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT apns_token, env FROM tokens WHERE subscriber_hash = ?1 LIMIT 1",
        )?;
        let mut rows = stmt.query(params![subscriber_hash])?;
        if let Some(row) = rows.next()? {
            let token: String = row.get(0)?;
            let env_str: String = row.get(1)?;
            let env = ApnsEnv::parse(&env_str).unwrap_or(ApnsEnv::Production);
            Ok(Some((token, env)))
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
    /// Scoped to a specific environment so an identical hex string registered
    /// against the other gateway (theoretically possible) is not collateral.
    pub fn invalidate_token(&self, apns_token: &str, env: ApnsEnv) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "DELETE FROM tokens WHERE apns_token = ?1 AND env = ?2",
            params![apns_token, env.as_db_str()],
        )?;
        Ok(())
    }

    /// Total number of registered tokens.
    pub fn count(&self) -> Result<i64, rusqlite::Error> {
        self.conn
            .query_row("SELECT COUNT(*) FROM tokens", [], |row| row.get(0))
    }
}

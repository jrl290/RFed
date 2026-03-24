<?php
/**
 * rfed → APNs Bridge — Token Registry (SQLite)
 *
 * Stores the mapping between an RNS subscriber destination hash (16 bytes,
 * stored as 32-char lowercase hex) and the APNs device token string
 * (64-char lowercase hex as returned by iOS).
 *
 * Schema
 * ──────
 * tokens
 *   id             INTEGER PRIMARY KEY AUTOINCREMENT
 *   subscriber_hash TEXT NOT NULL UNIQUE   — 32 hex chars (16-byte RNS hash)
 *   apns_token      TEXT NOT NULL          — 64 hex chars
 *   registered      INTEGER NOT NULL        — Unix timestamp (registration time)
 *   updated         INTEGER NOT NULL        — Unix timestamp (last refresh)
 */

class TokenDB
{
    private PDO $pdo;

    public function __construct(string $path)
    {
        $this->pdo = new PDO('sqlite:' . $path, null, null, [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);

        $this->pdo->exec('PRAGMA journal_mode=WAL');
        $this->pdo->exec('PRAGMA foreign_keys=ON');

        $this->migrate();
    }

    // ── Schema migration ──────────────────────────────────────────────────

    private function migrate(): void
    {
        $this->pdo->exec(<<<SQL
            CREATE TABLE IF NOT EXISTS tokens (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                subscriber_hash  TEXT    NOT NULL UNIQUE,
                apns_token       TEXT    NOT NULL,
                registered       INTEGER NOT NULL,
                updated          INTEGER NOT NULL
            )
        SQL);

        $this->pdo->exec(<<<SQL
            CREATE INDEX IF NOT EXISTS idx_tokens_apns
                ON tokens (apns_token)
        SQL);
    }

    // ── Token registration ────────────────────────────────────────────────

    /**
     * Register or refresh a device token for a subscriber.
     *
     * @param string $subscriberHash  32-char lowercase hex RNS hash
     * @param string $apnsToken       64-char lowercase hex APNs device token
     */
    public function register(string $subscriberHash, string $apnsToken): void
    {
        $now = time();
        $stmt = $this->pdo->prepare(<<<SQL
            INSERT INTO tokens (subscriber_hash, apns_token, registered, updated)
            VALUES (:hash, :token, :now, :now)
            ON CONFLICT(subscriber_hash) DO UPDATE SET
                apns_token = excluded.apns_token,
                updated    = excluded.updated
        SQL);
        $stmt->execute([':hash' => $subscriberHash, ':token' => $apnsToken, ':now' => $now]);
    }

    // ── Token lookup ──────────────────────────────────────────────────────

    /**
     * Look up the APNs token for a subscriber hash.
     *
     * @param string $subscriberHash  32-char lowercase hex
     * @return string|null            APNs device token, or null if not registered
     */
    public function getToken(string $subscriberHash): ?string
    {
        $stmt = $this->pdo->prepare(
            'SELECT apns_token FROM tokens WHERE subscriber_hash = :hash LIMIT 1'
        );
        $stmt->execute([':hash' => $subscriberHash]);
        $row = $stmt->fetch();
        return $row ? $row['apns_token'] : null;
    }

    // ── Unregister ────────────────────────────────────────────────────────

    /**
     * Remove the APNs token registration for a subscriber.
     *
     * @param string $subscriberHash  32-char lowercase hex
     * @return bool  true if a row was deleted
     */
    public function unregister(string $subscriberHash): bool
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM tokens WHERE subscriber_hash = :hash'
        );
        $stmt->execute([':hash' => $subscriberHash]);
        return $stmt->rowCount() > 0;
    }

    /**
     * Remove a registration by APNs token (called when APNs reports the
     * token as invalid/unregistered — apns-unregistered or BadDeviceToken).
     *
     * @param string $apnsToken  64-char lowercase hex
     */
    public function invalidateToken(string $apnsToken): void
    {
        $stmt = $this->pdo->prepare(
            'DELETE FROM tokens WHERE apns_token = :token'
        );
        $stmt->execute([':token' => $apnsToken]);
    }

    // ── Stats (for health check) ──────────────────────────────────────────

    public function count(): int
    {
        return (int) $this->pdo->query('SELECT COUNT(*) FROM tokens')->fetchColumn();
    }
}

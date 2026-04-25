# rfed.toml for backup-test BACKUP NODE
# This node acts as a failover backup for the primary.
# It has the primary as a static peer so sync fires immediately.
# PRIMARY_NODE_HASH is replaced by setup_backup_nodes.sh.

[node]
name                      = "rfed-backup-node"
announce_interval_minutes = 60
announce_at_start         = true

[storage]
limit_mb = 100

[peering]
static_peers     = ["PRIMARY_NODE_HASH"]  # sync from primary
from_static_only = false
backup_tick_secs = 8                      # fast backup delivery tick for tests
owner_offline_secs = 12.0                # how long silence = owner offline

[policy.default]
stamp_cost              = 0
stamp_flexibility       = 0
allow_notify_registration = true
allow_subscription      = true

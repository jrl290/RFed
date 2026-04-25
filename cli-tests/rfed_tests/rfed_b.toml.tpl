# rfed.toml for Node B (internode sync test)
# NODE_A_HASH is replaced by setup_node_b.sh with the actual hash.

[node]
name                      = "rfed-test-b"
announce_interval_minutes = 1
announce_at_start         = true

[storage]
limit_mb = 100

[peering]
static_peers     = ["NODE_A_HASH"]
from_static_only = false

[policy.default]
stamp_cost              = 0
stamp_flexibility       = 0
allow_notify_registration = true
allow_subscription      = true

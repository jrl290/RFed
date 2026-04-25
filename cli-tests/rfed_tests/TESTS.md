# rfed Integration Test Suite

All tests in this directory exercise the rfed federation node via Python RNS
clients and shell orchestration.

---

## Test Runner

```bash
./run_tests.sh [1|2|3|4|5|6|all]   # default: all
```

Starts a local rfed node, runs each scenario, and reports PASS/FAIL.

---

## Scenarios

| # | Name | Script(s) | What It Tests |
|---|------|-----------|---------------|
| 1 | **Live Fanout** | `rfed_subscriber.py`, `rfed_publisher.py` | Subscribe → publish → verify blob arrives via live fanout delivery |
| 2 | **Deferred Delivery** | `rfed_subscriber.py` (pull mode), `rfed_publisher.py` | Subscribe → subscriber goes offline → publish → subscriber comes online → deferred flush |
| 3 | **PULL** | `rfed_subscriber.py` (pull mode), `rfed_publisher.py` | Subscribe offline → publish → explicit PULL request → verify blobs returned |
| 4 | **Notify** | `rfed_notify_register.py`, `rfed_notify_relay.py`, `rfed_publisher.py` | Register notify relay → publish offline → relay receives wake packet with correct subscriber hash |
| 5 | **Inter-Node Sync** | `rfed_sync_subscriber.py`, `rfed_publisher.py`, `setup_node_b.sh` | Publish on Node A → subscribe on Node B → verify sync delivers blob via PULL |
| 6 | **Backup Failover** | `rfed_backup_subscriber.py`, `rfed_publisher.py`, `setup_backup_nodes.sh` | Subscribe on primary → publish blob → kill primary → pull from backup → verify delivery |
| 7 | **LXMF Propagation Notify** | `rfed_prop_receiver.py`, `rfed_prop_sender.py` | Receiver registers with rfed.notify → sender pushes LXMF propagation batch → rfed fires wake-up to receiver |
| 8 | **LXMF Propagation Store-and-Forward** | `lxmf_e2e_receiver.py`, `lxmf_e2e_sender.py` | Receiver announces identity → sender sends real encrypted LXMF message via PROPAGATED method → receiver syncs from rfed's `lxmf.propagation` node and decrypts message |

---

## Setup & Teardown

| File | Purpose |
|------|---------|
| `setup.sh` | Start rfed Node A (TCP server on `:4244`), export hashes to `rfed_data/hashes.env` |
| `teardown.sh` | Stop rfed Node A by PID |
| `setup_node_b.sh` | Start rfed Node B (`:4245`), peered with Node A for Scenario 5 |
| `teardown_node_b.sh` | Stop Node B |
| `setup_backup_nodes.sh` | Start primary (`:4246`) + backup (`:4247`) rfed pair for Scenario 6 |
| `teardown_backup_nodes.sh` | Stop backup-test nodes |

---

## LXMF Propagation Tests

| File | What It Tests |
|------|---------------|
| `test_lxmf_propagation.py` | E2E: send LXMF message → rfed's `lxmf.propagation` node → client sync via `/get`, peering check |
| `test_prop_notify.sh` | E2E: register relay → send LXMF propagation batch → relay receives wake packet |
| `lxmf_prop_sender.py` | Send a minimal LXMF propagation batch to rfed (used by `test_prop_notify.sh`) |
| `rfed_prop_receiver.py` | Scenario 7 receiver: registers with rfed.notify (subscriber=self, relay=self), waits for wake packet |
| `rfed_prop_sender.py` | Scenario 7 sender: reads subscriber hash from `rfed_data/prop_receiver_hash.txt`, sends LXMF batch |
| `test_reg.py` | Register a notify relay via rfed.notify Link request (against external rnsd) |
| `test_registration.sh` | Shell wrapper: start rfed → wait for announce → run `test_reg.py` → report PASS/FAIL |

---

## Shared Utilities

| File | Purpose |
|------|---------|
| `channel_hash.py` | `compute_channel_hash()`, `AnnounceHandler`, `load_hashes()` — shared by all rfed test clients |
| `relay_hash.py` | Compute rfed.notify destination hash from identity file (offline, no RNS needed) |

---

## Diagnostics

| File | Purpose |
|------|---------|
| `debug_announce.py` | Listen for rfed announces from Python RNS |
| `debug_path.py` | Request path to rfed node hash — quick connectivity check |
| `diag_announces.py` | Listen for all announces, tag rfed.NOTIFY/rfed.NODE |
| `diag_link.py` | Test link establishment to rfed.notify destination |
| `parse_peers.py` | Parse and dump msgpack `rfed_data/lxmf_propagation/peers` file |

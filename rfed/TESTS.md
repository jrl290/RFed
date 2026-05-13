# rfed Tests

---

## Automated Rust Tests

The automated Rust test suite lives in the main crate and runs with:

`cargo test -p rfed`

---

## Rust Manual Harnesses

These files are standalone verification tools, not `#[test]` integration tests.
They live under `examples/` so `cargo test` only reports real automated tests.

| File | What It Tests | How to Run |
|------|---------------|------------|
| `examples/notify_register.rs` | Register a notify relay with rfed: boots RNS, opens Link to `rfed.notify`, sends `/rfed/notify/register`, validates boolean response. Requires a running `rnsd`. | `cargo run --example notify_register --` |
| `examples/rfed_channel_e2e.rs` | End-to-end channel send/receive verification against a running rfed instance. It subscribes a receiver, sends a channel message, and verifies the decrypted payload. | `cargo run --example rfed_channel_e2e -- --rfed-port <port>` |

---

## rfed Integration Suite (Python/Shell)

The full Python/shell integration suite lives in `../../cli-tests/rfed_tests/`.
See [`cli-tests/rfed_tests/TESTS.md`](../../cli-tests/rfed_tests/TESTS.md) for
the complete suite documentation including all 6 scenarios, setup/teardown
scripts, and shared utilities.

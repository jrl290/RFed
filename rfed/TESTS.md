# rfed Tests

---

## Rust Integration Test

| File | What It Tests | How to Run |
|------|---------------|------------|
| `tests/notify_register.rs` | Register a notify relay with rfed: boots RNS, opens Link to `rfed.notify`, sends `/rfed/notify/register`, validates boolean response.  Requires a running `rnsd`. | `cargo test --test notify_register` or `cargo run --bin notify_register` |

---

## rfed Integration Suite (Python/Shell)

The full Python/shell integration suite lives in `../../cli-tests/rfed_tests/`.
See [`cli-tests/rfed_tests/TESTS.md`](../../cli-tests/rfed_tests/TESTS.md) for
the complete suite documentation including all 6 scenarios, setup/teardown
scripts, and shared utilities.

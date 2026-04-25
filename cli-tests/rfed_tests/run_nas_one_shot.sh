#!/usr/bin/env bash
set -euo pipefail

ROOT="/Users/james/Library/CloudStorage/SynologyDrive-Development/Rust/Reticulum"
RFED_NODE_HASH="8772cfeaee0489ba496c4b229e849472"
LXMF_PROP_HASH="0f75ac15961b7d2b1577a57bdb1fda3c"
RNS_CFG="cli-tests/rfed_tests/rns_client_rmap"

printf "=== NAS One-Shot Verification ===\n"
printf "root: %s\n" "$ROOT"
printf "rfed.node: %s\n" "$RFED_NODE_HASH"
printf "lxmf.propagation: %s\n\n" "$LXMF_PROP_HASH"

printf "[1/2] Path and identity discovery via rmap client...\n"
set +e
PATH_OUTPUT=$(cd "$ROOT" && PYTHONPATH=Reticulum-master python3 - <<'PY'
import sys,time,json
sys.path.insert(0,'Reticulum-master')
import RNS

targets = {
  'rfed_node': bytes.fromhex('8772cfeaee0489ba496c4b229e849472'),
  'lxmf_prop': bytes.fromhex('0f75ac15961b7d2b1577a57bdb1fda3c'),
}

RNS.Reticulum(configdir='cli-tests/rfed_tests/rns_client_rmap')
result = {}
for name, h in targets.items():
    RNS.Transport.request_path(h)
    deadline = time.time() + 90
    while time.time() < deadline and not RNS.Transport.has_path(h):
        time.sleep(0.4)
    has_path = RNS.Transport.has_path(h)
    ident = RNS.Identity.recall(h)
    hops = RNS.Transport.hops_to(h) if has_path else None
    next_hop = RNS.Transport.next_hop(h) if has_path else None
    result[name] = {
        'has_path': bool(has_path),
        'identity': bool(ident),
        'hops': hops,
        'next_hop': next_hop.hex() if next_hop else None,
    }

print(json.dumps(result, sort_keys=True))
ok = all(v['has_path'] and v['identity'] for v in result.values())
raise SystemExit(0 if ok else 1)
PY
)
PATH_STATUS=$?
set -e
printf "%s\n" "$PATH_OUTPUT"
if [[ $PATH_STATUS -eq 0 ]]; then
  printf "Path discovery: PASS\n\n"
else
  printf "Path discovery: FAIL\n\n"
fi

printf "[2/2] Rust link_request test against NAS rfed.node...\n"
set +e
TEST_OUTPUT=$(cd "$ROOT/Retichat-ios/rust/retichat-ffi" && RFED_NODE_HASH="$RFED_NODE_HASH" cargo test --release --test link_request 2>&1)
TEST_STATUS=$?
set -e
printf "%s\n" "$TEST_OUTPUT"
if [[ $TEST_STATUS -eq 0 ]]; then
  printf "link_request test: PASS\n"
else
  printf "link_request test: FAIL\n"
fi

if [[ $PATH_STATUS -eq 0 && $TEST_STATUS -eq 0 ]]; then
  printf "\nOVERALL: PASS\n"
  exit 0
else
  printf "\nOVERALL: FAIL\n"
  exit 1
fi

#!/usr/bin/env bash
# Detached orchestration: stop the running devnet, inject Sentinel as node 3's
# standalone watchtower, then restart the devnet (preserving chain + config).
# Run with: setsid bash scripts/restart-devnet-with-sentinel.sh &
set -uo pipefail

UP="/home/ken/Projects/fiber-watchtower/upstream"
export PATH="$HOME/.local/bin:$PATH"
export TEST_ENV=release   # note: NO REMOVE_OLD_STATE, so config edits persist

# 1. Stop devnet.
pkill -f "tests/nodes/start.sh" 2>/dev/null || true
sleep 2
pkill -f "target/release/fnn" 2>/dev/null || true
pkill -f "ckb run" 2>/dev/null || true
sleep 4

# 2. Inject standalone watchtower into node 3 config (idempotent).
python3 - "$UP/tests/nodes/3/config.yml" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
if "standalone_watchtower_rpc_url" not in s:
    inj = ("  disable_built_in_watchtower: true\n"
           "  standalone_watchtower_rpc_url: http://127.0.0.1:23456\n"
           "  standalone_watchtower_token: sentinel-devnet-token\n")
    s = re.sub(r"(^fiber:\n)", r"\1" + inj, s, count=1, flags=re.M)
    open(p, "w").write(s)
    print("injected standalone watchtower into node 3")
else:
    print("standalone watchtower already present in node 3")
PY

# 3. Restart devnet (chain + configs preserved).
cd "$UP" || exit 1
nohup ./tests/nodes/start.sh e2e/watchtower/revocation > /tmp/devnet2.log 2>&1 &
echo "devnet restarting (pid $!) — log: /tmp/devnet2.log"

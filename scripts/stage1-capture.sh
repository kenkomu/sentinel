#!/usr/bin/env bash
# Stage 1: reconfigure the victim node (node 3) to use Sentinel as its standalone
# watchtower, then drive a channel + payment so real create_watch_channel /
# update_revocation payloads land on Sentinel. Run AFTER the devnet is up.
set -euo pipefail

UP="/home/ken/Projects/fiber-watchtower/upstream"
SENTINEL="/home/ken/Projects/fiber-watchtower/sentinel"
NODE3_CFG="$UP/tests/nodes/3/config.yml"
TOWER_RPC="http://127.0.0.1:23456"
TOKEN="sentinel-devnet-token"

echo "== node 3 generated config (before) =="
grep -nE "watchtower|listening_addr" "$NODE3_CFG" || true

# Inject standalone watchtower settings into node 3's fiber config.
if ! grep -q "standalone_watchtower_rpc_url" "$NODE3_CFG"; then
  python3 - "$NODE3_CFG" "$TOWER_RPC" "$TOKEN" <<'PY'
import sys, re
path, url, token = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
# add under the `fiber:` block
inject = f"  disable_built_in_watchtower: true\n  standalone_watchtower_rpc_url: {url}\n  standalone_watchtower_token: {token}\n"
s = re.sub(r"(^fiber:\n)", r"\1" + inject, s, count=1, flags=re.M)
open(path, "w").write(s)
print("injected standalone watchtower config into node 3")
PY
fi

echo "== restart node 3 pointed at Sentinel =="
echo "   (kill node3 fnn, restart with same -d 3; Sentinel must be running on $TOWER_RPC)"
echo "   pkill -f 'fnn -d 3' ; then start_fnn -d 3"
echo
echo "Then drive the channel flow via bruno or curl and watch Sentinel's"
echo "sentinel::capture log for create_watch_channel + update_revocation."

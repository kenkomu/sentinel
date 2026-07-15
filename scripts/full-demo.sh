#!/usr/bin/env bash
# End-to-end Sentinel breach demo against a live Fiber devnet — the exact recipe
# that sweeps an attacker on-chain.
#
# Prereqs:
#   * DEBUG-built fnn (submit_commitment_transaction is #[cfg(debug_assertions)])
#   * ckb + ckb-cli on PATH
#   * Fiber devnet running with node 3 configured for Sentinel:
#         fiber:
#           disable_built_in_watchtower: true
#           standalone_watchtower_rpc_url: http://127.0.0.1:23456
#           standalone_watchtower_token: <token>
#   * Sentinel running in active-defence mode:
#         sentinel --config configs/devnet.toml --data-dir <dir> \
#                  --ckb-rpc-url http://127.0.0.1:8114
set -uo pipefail

N1=http://127.0.0.1:21714
N3=http://127.0.0.1:21716
CKB=http://127.0.0.1:8114
SENTINEL=http://127.0.0.1:8080
UP="${UPSTREAM:-/home/ken/Projects/fiber-watchtower/upstream}"
NODE1_ADDR="/ip4/127.0.0.1/tcp/8344/p2p/QmbvRjJHAQDmj3cgnUBGQ5zVnGxUKwb2qJygwNs2wk41h8"
NODE3_PUBKEY="03032b99943822e721a651c5a5b9621043017daa9dc3ec81d83215fd2e25121187"

j(){ curl -s -m10 -X POST "$1" -H 'Content-Type:application/json' -d "$2"; }
blocks(){ bash "$UP/tests/deploy/generate-blocks.sh" "${1:-6}" >/dev/null 2>&1; }

echo "== 1. open a channel node1 -> node3 =="
j $N3 "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"connect_peer\",\"params\":[{\"address\":\"$NODE1_ADDR\"}]}" >/dev/null
sleep 3
j $N1 "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"open_channel\",\"params\":[{\"pubkey\":\"$NODE3_PUBKEY\",\"funding_amount\":\"0xba43b7400\",\"public\":true}]}" >/dev/null
blocks 6; sleep 6; blocks 8; sleep 5

CH=$(j $N3 '{"id":1,"jsonrpc":"2.0","method":"list_channels","params":[{}]}' | python3 -c "import sys,json;chs=json.load(sys.stdin)['result']['channels'];r=[c for c in chs if c['state']['state_name']=='ChannelReady'];print(r[-1]['channel_id'] if r else 'NONE')")
echo "   channel: $CH"

echo "== 2. node3 invoices, node1 pays (creates revocations) =="
PRE="0x$(openssl rand -hex 32)"
INV=$(j $N3 "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"new_invoice\",\"params\":[{\"amount\":\"0x64\",\"currency\":\"Fibd\",\"description\":\"demo\",\"expiry\":\"0xe10\",\"final_expiry_delta\":\"0x927C00\",\"payment_preimage\":\"$PRE\"}]}")
ENC=$(echo "$INV" | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['invoice_address'])")
j $N1 "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"send_payment\",\"params\":[{\"invoice\":\"$ENC\"}]}" >/dev/null
sleep 5
echo "   Sentinel now holds: $(curl -s $SENTINEL/channels | python3 -c "import sys,json;c=json.load(sys.stdin)['channels'];print(list(c[0]['parts'].keys()) if c else 'none')")"

echo "== 3. THE BREACH: node1 broadcasts old commitment 0x1 =="
BTX=$(j $N1 "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"submit_commitment_transaction\",\"params\":[{\"channel_id\":\"$CH\",\"commitment_number\":\"0x1\"}]}" | python3 -c "import sys,json;print(json.load(sys.stdin).get('result',{}).get('tx_hash','?'))")
echo "   stale commitment tx: $BTX"
blocks 8; sleep 12

echo "== 4. Sentinel detects + broadcasts the penalty =="
curl -s $SENTINEL/breaches | python3 -m json.tool
blocks 4; sleep 4

echo "== 5. WIN: attacker's commitment cell swept? =="
curl -s -X POST $CKB -H 'Content-Type:application/json' \
  -d "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"get_live_cell\",\"params\":[{\"tx_hash\":\"$BTX\",\"index\":\"0x0\"},false]}" \
  | python3 -c "import sys,json;s=json.load(sys.stdin)['result']['status'];print('   commitment cell status:',s,'->','SWEPT ✔' if s!='live' else 'still live')"
echo
echo "Sentinel's log shows 'PENALTY BROADCAST — cheater swept' with the penalty tx hash."

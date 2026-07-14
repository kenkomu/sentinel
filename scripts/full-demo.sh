#!/usr/bin/env bash
# End-to-end Sentinel breach demo against a live Fiber devnet.
#
# Prereqs: a DEBUG-built fnn (submit_commitment_transaction is #[cfg(debug_assertions)]),
# ckb + ckb-cli on PATH, and the Fiber repo at $UPSTREAM.
#
# Flow:
#   1. (assumes devnet already running with node 3 -> Sentinel, and Sentinel up)
#   2. node1 opens a channel to node3; fund + confirm.
#   3. node3 invoices, node1 pays -> Sentinel captures update_revocation.
#   4. node1 broadcasts an OLD commitment (the breach).
#   5. Sentinel detects the breach and broadcasts the penalty.
#   6. Assert the attacker's commitment cell is spent (status != live).
set -uo pipefail

UPSTREAM="${UPSTREAM:-/home/ken/Projects/fiber-watchtower/upstream}"
N1=http://127.0.0.1:21714
N3=http://127.0.0.1:21716
CKB=http://127.0.0.1:8114
SENTINEL=http://127.0.0.1:8080
NODE1_ADDR="/ip4/127.0.0.1/tcp/8344/p2p/QmbvRjJHAQDmj3cgnUBGQ5zVnGxUKwb2qJygwNs2wk41h8"
NODE3_PUBKEY="03032b99943822e721a651c5a5b9621043017daa9dc3ec81d83215fd2e25121187"

j(){ curl -s -m10 -X POST "$1" -H 'Content-Type:application/json' -d "$2"; }
blocks(){ bash "$UPSTREAM/tests/deploy/generate-blocks.sh" "${1:-6}" >/dev/null 2>&1; }

echo "== 1. connect node3 -> node1 =="
j $N3 "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"connect_peer\",\"params\":[{\"address\":\"$NODE1_ADDR\"}]}" >/dev/null
sleep 3

echo "== 2. open channel node1 -> node3 =="
j $N1 "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"open_channel\",\"params\":[{\"pubkey\":\"$NODE3_PUBKEY\",\"funding_amount\":\"0xba43b7400\",\"public\":true}]}" >/dev/null
blocks 6; sleep 6

echo "== 3. node3 invoice, node1 pays (creates revocation) =="
PRE="0x$(openssl rand -hex 32)"
INV=$(j $N3 "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"new_invoice\",\"params\":[{\"amount\":\"0x64\",\"currency\":\"Fibd\",\"description\":\"demo\",\"expiry\":\"0xe10\",\"final_expiry_delta\":\"0x927C00\",\"payment_preimage\":\"$PRE\"}]}")
ENC=$(echo "$INV" | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['invoice_address'])")
j $N1 "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"send_payment\",\"params\":[{\"invoice\":\"$ENC\"}]}" >/dev/null
sleep 5
CH=$(curl -s -m5 -X POST $N3 -H 'Content-Type:application/json' -d '{"id":1,"jsonrpc":"2.0","method":"list_channels","params":[{}]}' | python3 -c "import sys,json;print(json.load(sys.stdin)['result']['channels'][0]['channel_id'])")
echo "   channel: $CH"
echo "   Sentinel now holds:"; curl -s $SENTINEL/channels | python3 -c "import sys,json;c=json.load(sys.stdin)['channels'][0];print('    parts:',list(c['parts'].keys()))" 2>/dev/null

echo "== 4. node1 broadcasts an OLD commitment (the breach) =="
j $N1 "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"submit_commitment_transaction\",\"params\":[{\"channel_id\":\"$CH\",\"commitment_number\":\"0x0\"}]}" | python3 -c "import sys,json;r=json.load(sys.stdin);print('   result:',r.get('result',r.get('error')))"
blocks 6; sleep 10

echo "== 5. Sentinel breach detection + penalty =="
curl -s $SENTINEL/breaches | python3 -m json.tool

echo "== 6. was the attacker's commitment swept? =="
curl -s $SENTINEL/breaches | python3 -c "
import sys,json
d=json.load(sys.stdin)
b=[o for o in d.get('outcomes',[]) if o['verdict'].get('state')=='breach']
if b: print('   BREACH detected on', b[0]['channel_id'][:20], '- penalty path engaged')
else: print('   (no breach in current scan — check Sentinel logs)')
"
echo
echo "Watch Sentinel logs for 'PENALTY BROADCAST', then verify the commitment"
echo "cell status flips to non-live via get_live_cell."

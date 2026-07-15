#!/usr/bin/env bash
# Deploy Sentinel to a VPS as the live, always-on hosted demo (public
# /attestation anyone can verify).
#
# Usage:
#   SSH_HOST=user@your-vps CKB_RPC_URL=https://testnet.ckb.dev/rpc \
#     bash scripts/deploy-vps.sh
#
# Requires: ssh access to the host, and Docker installed on the host.
# The tower runs in DETECTION/ALERTING-only mode by default (no penalty config),
# which is the safe choice for a public demo — it proves liveness + accountability
# without holding a funded penalty key. Point a Fiber node's
# standalone_watchtower_rpc_url at <host>:23456 to feed it real channels.
set -euo pipefail

: "${SSH_HOST:?set SSH_HOST=user@host}"
CKB_RPC_URL="${CKB_RPC_URL:-https://testnet.ckb.dev/rpc}"
IMAGE="sentinel:latest"

echo "== 1. build image locally =="
docker build -t "$IMAGE" .

echo "== 2. ship image to $SSH_HOST =="
docker save "$IMAGE" | gzip | ssh "$SSH_HOST" 'gunzip | docker load'

echo "== 3. (re)start the tower on the host =="
ssh "$SSH_HOST" bash -s <<EOF
set -e
docker rm -f sentinel 2>/dev/null || true
docker volume create sentinel-data >/dev/null 2>&1 || true
docker run -d --name sentinel --restart unless-stopped \
  -p 8080:8080 -p 23456:23456 \
  -v sentinel-data:/data \
  $IMAGE \
  --data-dir /data --http-port 8080 --rpc-port 23456 \
  --ckb-rpc-url "$CKB_RPC_URL" --attest-interval 10
echo "started; waiting for health..."
for i in \$(seq 1 20); do
  if curl -fsS http://localhost:8080/health >/dev/null 2>&1; then echo "healthy"; break; fi
  sleep 1
done
EOF

echo
echo "== done =="
HOSTNAME_ONLY="\${SSH_HOST#*@}"
echo "Console:      http://\${SSH_HOST#*@}:8080"
echo "Attestation:  http://\${SSH_HOST#*@}:8080/attestation  (public, verifiable)"
echo "Watchtower:   http://\${SSH_HOST#*@}:23456  (point a node's standalone_watchtower_rpc_url here)"
echo
echo "Verify liveness from anywhere:"
echo "  cargo run --bin verify -- --tower http://\${SSH_HOST#*@}:8080 --ckb $CKB_RPC_URL"

# Demo runbook — Stage 1 capture & Stage 3 breach

Derived from Fiber's own watchtower e2e test
(`upstream/tests/bruno/e2e/watchtower/revocation`), which exercises the built-in
watchtower. Sentinel is the *standalone* tower a node points at instead.

## Prerequisites (installed / verified)

- `ckb` v0.207.0 → `~/.local/bin/ckb` (on PATH)
- `ckb-cli` → `/usr/local/bin/ckb-cli`
- `fnn` → built from `upstream` (`TEST_ENV=release`)

## Devnet

```
cd upstream
REMOVE_OLD_STATE=y TEST_ENV=release ./tests/nodes/start.sh e2e/watchtower/revocation
```

Starts a CKB dev chain + 3 Fiber nodes. The `e2e/watchtower/revocation` testcase
is the breach scenario.

## Stage 1 — point a node at Sentinel and capture

To route a node's revocation stream to Sentinel instead of its built-in tower,
its fiber config needs:

```yaml
fiber:
  disable_built_in_watchtower: true
  standalone_watchtower_rpc_url: http://127.0.0.1:23456
  standalone_watchtower_token: <bearer token>   # becomes the tenant id
```

Run Sentinel, then drive the channel flow. Expect to capture, in order:
- `create_watch_channel` — on channel funding (RemoteTxComplete)
- `update_revocation` — on each RevokeAndAck (i.e. each payment)
- `update_local_settlement` / `update_pending_remote_settlement`
- `create_preimage` / `remove_preimage` for TLCs

Save the raw payloads (Sentinel logs them under `sentinel::capture`) to
`tests/fixtures/` and lock `rpc/types.rs` to their exact shape.

## Stage 3 — force the breach

The exact sequence from the e2e test:

1. `01-connect-peer` — node1 connects to node3
2. `02-open-channel` / `03-get-auto-accepted-channel` — channel opens
3. `04..05` — generate blocks, node3 makes an invoice
4. `06-node1-send-payment-with-invoice` — a payment; this advances the
   commitment number and produces a fresh revocation (the old state is now stale)
5. **`07-submit-old-version-commitment-tx`** — the breach:
   ```json
   { "method": "submit_commitment_transaction",
     "params": [{ "channel_id": "<id>", "commitment_number": "0x1" }] }
   ```
   Broadcasting commitment number `0x1` when the channel has moved past it is a
   stale-state broadcast — a theft attempt.
6. `08..09` — generate blocks so the tower sees it
7. **Win condition** (`10-check-commitment-tx`): the submitted commitment's
   output becomes `status: "unknown"` on CKB — i.e. Sentinel's penalty
   transaction spent it. The thief's commitment was revoked.

For Sentinel, the victim node uses the standalone tower, and Sentinel (not the
built-in tower) must be what publishes the penalty that flips that cell to
`unknown`.

## What proves success

`get_live_cell` on the attacker's commitment output returns `status: unknown`
after Sentinel acts. That single assertion is the whole demo: a stale-state
theft, caught and punished by the standalone tower while the victim was offline.

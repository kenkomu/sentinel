# What is real, what is mocked, what production needs

The hackathon asks submissions to be clear about this. Kept scrupulously honest.

## Fully working — proven live on a Fiber devnet, end to end

- **Node → tower ingestion.** A real devnet node, configured with
  `standalone_watchtower_rpc_url` → Sentinel + `disable_built_in_watchtower`,
  streams its full watchtower lifecycle over JSON-RPC (create_watch_channel,
  update_revocation, create/remove_preimage, local/pending settlements). Real
  payloads: `tests/fixtures/captured-devnet.log`.
- **Breach detection.** The scan derives each channel's funding lock (musig2),
  finds the commitment tx that spent it, reads the broadcast commitment number,
  and decides breach vs legitimate-close vs unactionable.
- **Penalty broadcast — the whole point.** On a real breach, Sentinel assembles
  the revocation (penalty) transaction and broadcasts it. **Proven:** the
  attacker's commitment cell was swept (`get_live_cell` → `unknown`) and the
  penalty transaction committed on-chain (`0x4a9bf510…`). The build matches
  Fiber's own built-in watchtower transaction byte-for-byte in structure.
- **Accountability.** Live CKB-tip-bound attestations; the `verify` tool proves
  liveness and catches a stale/sleeping tower; signed registration receipts.
- **Persistence & identity.** Multi-tenant sled store survives restart; tower
  identity key persists across restarts.
- **Operator surface.** Dashboard (with live red breach state), `/metrics`,
  `/health`, `/channels`, `/breaches`, `/receipts`.

## Verified by unit tests (17 passing)

Breach decision logic; revocation-witness byte layout; penalty-output molecule
deserialization; the commitment-lock message format (verified against the
built-in watchtower's accepted transaction); musig2 aggregation; positional-array
param parsing; identity persistence.

## Hard-won protocol details (undocumented; found by decoding the built-in tx)

- Punish commitment N with the revocation numbered **N+1** (Daric: the later
  revocation revokes the earlier state).
- Penalty cell deps: `[CommitmentLock, ckb-auth, secp256k1]` — funding lock not
  needed.
- `output_data "0x00000000"` is a molecule-packed **empty** `Bytes`, not four
  zero bytes; it must be unpacked or the length-prefixed message hash breaks.
- Commitment-lock message: `blake2b(output ‖ u32le(len(data)) ‖ data ‖
  args[0..28] ‖ version)`.

## Known limits / production gaps

- Network cell-dep out-points are config (devnet values shipped); testnet/mainnet
  need their own `config.toml`.
- Fee is a conservative flat value, not size-computed (negligible over-pay).
- RPC auth is the node's bearer token → tenant; no additional hardening yet.
- Single tower; no redundancy/failover.
- Not audited. Do not use on mainnet funds.

## Roadmap

TEE-attested penalty signing (PCR0-pinned enclave), P2P tower discovery +
multi-tower redundancy, size-based fee estimation, watchtower-client SDK. See
`SUBMISSION.md`.

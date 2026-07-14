# What is real, what is mocked, what production needs

The hackathon explicitly asks submissions to be clear about this. Kept honest and
current as the build progresses.

## Fully working — verified live against a Fiber devnet

- **Node → tower ingestion.** A real devnet node (node 3), configured with
  `standalone_watchtower_rpc_url` → Sentinel + `disable_built_in_watchtower`,
  streamed its full watchtower lifecycle over JSON-RPC: `create_watch_channel`,
  `update_revocation`, `create_preimage`, `remove_preimage`,
  `update_local_settlement`, `update_pending_remote_settlement`. Real payloads:
  `tests/fixtures/captured-devnet.log`.
- **Channel identity derivation.** musig2 funding-lock derivation matches the
  real funding cell exactly (found the live 599 CKB funding cell from just the
  funding pubkeys, via the `locate` tool).
- **Chain-state detection.** The scan loop correctly reports channel state
  against the live chain (ChannelOpen for a live funding cell).
- **Accountability.** Live attestations bound to the real CKB tip; the `verify`
  tool proves both PROVEN LIVE and catches a stale/sleeping tower; signed
  receipts on registration.
- **Persistence & identity.** Multi-tenant sled store survives restart; tower
  identity key persists across restarts.
- **Operator surface.** Dashboard, `/metrics`, `/health`, `/channels`,
  `/breaches`, `/receipts`.

## Fully working — verified by unit tests (14 passing)

- Breach decision logic (breach / legitimate-close / unactionable).
- Revocation-witness byte layout (vs real captured data).
- Penalty output deserialization as a molecule `CellOutput` (vs real data).
- Domain parsing (positional-array params), musig2 aggregation properties.

## Built, pending the final live run

- **Breach → penalty broadcast end-to-end.** Every component is built and wired:
  the detector raises a Breach, the executor assembles the sweep transaction
  (pre-computed penalty output + revocation witness for the commitment input),
  collects a fee cell, signs it with CKB secp256k1-blake160 sighash-all, and
  broadcasts. The live breach run needs a **debug** `fnn` because Fiber's breach
  trigger (`submit_commitment_transaction`) is `#[cfg(debug_assertions)]`;
  that build is the last step. Repro: `scripts/full-demo.sh`.
- **The one honest risk:** CKB sighash correctness is only fully confirmed by an
  accepted on-chain transaction. The implementation is reviewed against the spec
  and the witness/tx assembly is unit-tested, but the live broadcast is the
  final proof.

## Known limits / production gaps

- Fee is a conservative flat value, not size-computed (negligible over-pay).
- RPC auth is the node's bearer token → tenant; no additional hardening yet.
- Single tower; no redundancy/failover.
- Not audited. Do not use on mainnet funds.

## Roadmap

TEE-attested penalty signing (PCR0-pinned enclave), P2P tower discovery +
multi-tower redundancy, size-based fee estimation, wallet SDK for auto-register
+ periodic verify. See `SUBMISSION.md`.

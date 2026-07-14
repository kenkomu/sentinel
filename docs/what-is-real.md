# What is real, what is mocked, what production needs

The hackathon explicitly asks submissions to be clear about this. Kept honest and
current as the build progresses.

## Fully working (verified by running it)

- MIT Rust service that builds and runs; library + two binaries (`sentinel`,
  `verify`).
- **Watchtower RPC surface**: all seven methods accept and store what a Fiber
  node streams. Verified with simulated node calls.
- **Multi-tenancy**: bearer token → distinct tenant id; two nodes stay isolated;
  survives restart. Verified.
- **Accountability**:
  - live liveness attestations bound to the CKB tip, served at `/attestation`;
  - `verify` tool checks signature **and** freshness vs the live chain;
  - demonstrated both **PROVEN LIVE** (exit 0) and **caught a stale/sleeping
    tower** (exit 5);
  - signed **receipts** issued on registration, bound to block height, at
    `/receipts`.
- **Operator surface**: live dashboard at `/` (screenshot in `dashboard.png`),
  Prometheus `/metrics`, `/health`, `/channels`.
- **Packaging**: multi-stage Dockerfile + docker-compose.

## Proven against a live Fiber devnet (Stage 1 ✅)

- A **real Fiber node** (devnet node 3), reconfigured with
  `standalone_watchtower_rpc_url` → Sentinel and `disable_built_in_watchtower`,
  streamed its full watchtower lifecycle to Sentinel over JSON-RPC:
  `create_watch_channel`, `update_revocation` (×2), `create_preimage`,
  `remove_preimage`, `update_local_settlement`, `update_pending_remote_settlement`.
  Real captured payloads: `tests/fixtures/captured-devnet.log`.
- Sentinel's `/attestation` bound to the **real CKB devnet tip** (verified live).
- This capture also corrected the wire format: params arrive as a positional
  array `[{...}]`; the store keys correctly off the inner object now.

## Not yet wired (the remaining hard part)

- **Breach → penalty broadcast.** Sentinel now holds the real `update_revocation`
  data needed to build a penalty, and can detect the stale-commitment broadcast.
  Constructing and broadcasting the penalty transaction itself (using Fiber's
  cell/commitment primitives) is the remaining cryptographic integration —
  see `demo-runbook.md` for the exact breach trigger and win condition.

## Known limits / production gaps

- Tower identity key is ephemeral (regenerated per run) until persisted.
- RPC auth is the node's bearer token; no additional hardening yet.
- Single tower; no redundancy/failover.
- Not audited. Do not use on mainnet funds.

## Roadmap

See [`SUBMISSION.md`](SUBMISSION.md#future-roadmap). Headline items: live-devnet
penalty execution, persisted identity, TEE-attested penalty signing, P2P tower
discovery + redundancy.

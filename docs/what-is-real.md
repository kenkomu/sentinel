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

## Mocked / test-harnessed

- End-to-end runs so far drive the tower with a **mock CKB** endpoint and
  simulated node RPC calls. This exercises every code path but is not yet a live
  Fiber devnet.
- `rpc/types.rs` keeps opaque fields as raw JSON; they are locked to the exact
  wire bytes once captured from a real node (Stage 1).

## Not yet wired (final integration step)

- **Breach → penalty against a live devnet.** The chain-watcher interface and the
  breach flow are specified (`demo-runbook.md`, derived from Fiber's own
  `e2e/watchtower/revocation` test), and `ckb` + the Fiber node are being built
  to run it. Penalty *construction* uses Fiber's primitives via dependency, not
  vendored source.

## Known limits / production gaps

- Tower identity key is ephemeral (regenerated per run) until persisted.
- RPC auth is the node's bearer token; no additional hardening yet.
- Single tower; no redundancy/failover.
- Not audited. Do not use on mainnet funds.

## Roadmap

See [`SUBMISSION.md`](SUBMISSION.md#future-roadmap). Headline items: live-devnet
penalty execution, persisted identity, TEE-attested penalty signing, P2P tower
discovery + redundancy.

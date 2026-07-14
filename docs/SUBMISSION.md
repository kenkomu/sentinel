# Sentinel — Hackathon Submission

*Gone in 60ms: Fiber Network Infrastructure Hackathon · Category 2 (Node,
Routing, Cross-Chain & Diagnostics Infrastructure)*

## Project summary

Sentinel is a standalone, deployable **watchtower service** for Fiber Network,
and the first watchtower on any payment-channel network that can **prove it is
watching**. Fiber nodes point their `standalone_watchtower_rpc_url` at Sentinel
and can then go offline without risking a stale-state theft; Sentinel watches the
CKB chain and publishes the penalty transaction if a counterparty cheats. Its
distinguishing feature is an **accountability layer**: Sentinel continuously
signs the live CKB tip, so any client can verify — not merely trust — that the
tower is awake, and receives a signed receipt proving the tower accepted the job.

## The Fiber infrastructure gap addressed

Fiber's node config already exposes `standalone_watchtower_rpc_url` and
`disable_built_in_watchtower` — the hooks for an external watchtower — and the
seven watchtower RPC methods and penalty logic exist inside `fiber-lib`. What did
**not** exist:

1. **A deployable standalone tower service.** Today, protecting an offline node
   means running a second full Fiber node as its tower and trusting it blindly.
   There is no lightweight, operable watchtower distribution.
2. **Accountability.** No watchtower — on Fiber *or* Lightning — lets a client
   verify it is actually watching. You hand over revocation data and hope. This
   is a large part of why watchtower markets never matured (BOLT-13 stalled).
3. **Operational tooling.** No health, metrics, dashboard, or alerting for a
   tower operator.

Sentinel fills all three. This matters especially for Fiber because Fiber is
already shipping browser (`fiber-wasm`) and mobile (`fiber-android-demo`) nodes,
which are offline almost all the time — precisely the case that makes an external,
verifiable tower necessary.

## How it works

- **Watchtower RPC surface** (`--rpc-port`, default 23456): implements the seven
  methods a Fiber node streams — `create_watch_channel`, `remove_watch_channel`,
  `update_revocation`, `update_pending_remote_settlement`,
  `update_local_settlement`, `create_preimage`, `remove_preimage`.
- **Multi-tenant store** (sled): every record namespaced by the calling node's
  identity (derived from its bearer token), so one tower protects many nodes.
- **Chain watcher**: polls the CKB tip; on a stale-commitment broadcast, builds
  and broadcasts the penalty. *(Penalty execution: see "What is real" below.)*
- **Accountability**: a background loop signs `(ckb_tip_hash, height,
  channels_watched, timestamp)` every N seconds and serves it at `/attestation`;
  registration returns a signed `WatchReceipt`. The `verify` binary checks both
  the signature and the tip freshness against the live chain, so a sleeping tower
  is detectable.
- **Operator surface**: a live watch-console at `/`, Prometheus `/metrics`,
  `/health`, `/channels`, `/receipts`.

## Technical breakdown

- Language: Rust (server + `verify` client, shared library crate).
- RPC: `jsonrpsee` (same JSON-RPC 2.0 contract a Fiber node's watchtower client
  speaks). We re-declare the wire contract rather than copy Fiber's source (the
  upstream repo is unlicensed), keeping Sentinel cleanly MIT.
- Storage: `sled` embedded KV — single self-contained binary, no external DB.
- Crypto: `secp256k1` ECDSA over a SHA-256 digest for attestations and receipts.
- Packaging: multi-stage `Dockerfile` + `docker-compose.yml` for one-command
  deploy.

## Demonstrated, end-to-end

- Multi-tenancy: two nodes' tokens resolve to distinct tenants, each isolated;
  survives restart.
- Accountability, **both** directions:
  - Healthy tower → `verify` reports **PROVEN LIVE** (exit 0).
  - Tower stuck on an old block while the chain advances → `verify` reports
    **STALE — the tower is NOT watching** (exit 5).
- Signed receipts issued on registration, bound to the CKB height.
- Live dashboard rendered (see `docs/dashboard.png`).

## What is fully working / mocked / production gaps

See [`what-is-real.md`](what-is-real.md). In brief: the service, multi-tenancy,
accountability (attestations + verifier + receipts), dashboard, and metrics are
fully working. The breach-to-penalty execution against a live Fiber devnet is the
final integration step (runbook in [`demo-runbook.md`](demo-runbook.md)); penalty
construction uses Fiber's primitives via dependency, not vendored code.

## Future roadmap

- Penalty execution wired against the live devnet breach flow (Stage 3).
- Persisted, stable tower identity key.
- **TEE-attested penalty signing** (PCR0-pinned enclave) so the tower proves not
  only that it is awake but that it runs the exact published binary — closing the
  "is the operator honest?" gap the way modern enclave-based custody does.
- P2P tower discovery and multi-tower redundancy (defense in depth for a channel).
- Client SDK helpers for wallets to auto-register and periodically verify.

## Repository & license

MIT. Source: this repository. No pre-existing code reused; Fiber is referenced
over its RPC / as a dependency, never vendored.

## AI usage

AI was used as a development aide (research, scaffolding, docs) with human-driven
architecture, testing, and verification. Per hackathon guidance, all claims here
are backed by runnable code and observed behavior, and the "what is real" doc is
kept scrupulously honest about mocked vs. working parts.

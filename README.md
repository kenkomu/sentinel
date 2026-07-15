# Sentinel — an accountable watchtower for Fiber Network

> Category 2 · Node, Routing, Cross-Chain & Diagnostics Infrastructure
> Gone in 60ms: Fiber Network Infrastructure Hackathon

**Sentinel is a standalone, deployable watchtower service for Fiber Network — and
the first watchtower on any payment-channel network that can *prove* it is
watching.**

---

## The problem

A Fiber payment channel is only safe while someone is watching the chain. Old
channel states remain broadcastable forever; if your counterparty publishes a
stale state while your node is offline, they can take funds that are no longer
theirs. Your only defense is to catch it inside the dispute window and broadcast
a **penalty transaction** that sweeps the whole channel to you.

That defense requires being **online, always**. Phones sleep. Browsers close.
Power and connectivity are not guaranteed. This single liveness requirement is
the reason most mobile payment-channel wallets fall back to custody.

Fiber ships the *hook* for an external watchtower — every node config has a
`standalone_watchtower_rpc_url` field — but there is no standalone watchtower to
point it at, and no watchtower anywhere lets a client verify it is actually
awake. You hand a third party your revocation data and simply hope.

## What Sentinel does

- **Standalone service.** Point a Fiber node's `standalone_watchtower_rpc_url` at
  Sentinel and go offline safely. It implements the seven watchtower RPC methods
  a node streams to: channel registration, revocation updates, settlement data,
  and preimages.
- **Multi-tenant.** One Sentinel protects many nodes; every record is namespaced
  by the calling node's identity.
- **Breach defense.** It watches the CKB chain and, on a stale-commitment
  broadcast, publishes the penalty transaction.
- **Accountability (the novel part).** Every few seconds Sentinel signs the
  current CKB tip together with the number of channels under watch. A sleeping
  tower cannot produce this — it does not know the tip. Any client can verify
  the latest attestation against the public chain and know, continuously, that
  its guard is alive. Registration returns a signed receipt proving the tower
  took the job.

## Honest scope

This project is scrupulous about what is new versus what already exists upstream,
because the hackathon asks for exactly that.

- The watchtower **RPC contract** and the in-node **penalty logic** already exist
  inside Fiber's `fiber-lib`. Sentinel does **not** copy that source (the Fiber
  repo is currently unlicensed). It re-implements the wire contract and, for
  penalty execution, links `fiber-lib` as an external dependency / drives the
  node rather than vendoring code.
- **New in this project:** the deployable standalone service, multi-tenant
  storage, the signed **liveness-attestation** and **receipt** scheme, and the
  operator monitoring surface. None of these exist upstream or in any showcase
  project.

See [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md) for the staged build plan
and [`docs/what-is-real.md`](docs/what-is-real.md) for the working / mocked /
production-gap breakdown.

## Status

Proven **end-to-end on a live Fiber devnet**: a real node streams to Sentinel, an
attacker broadcasts a stale commitment, Sentinel detects it and **broadcasts the
penalty** — the attacker's commitment cell is swept and the penalty tx is
committed on-chain (`0x4a9bf510…`). See `docs/dashboard-breach.png`.

| Stage | What | State |
|------|------|-------|
| 1 | Capture real node→tower wire payloads | ✅ live |
| 2 | JSON-RPC watchtower server + multi-tenant store | ✅ live |
| 3 | Chain watcher + penalty broadcast (breach → sweep) | ✅ **live, on-chain** |
| 4 | Liveness attestations + receipts + verifier | ✅ verified |
| 5 | Dashboard, health, metrics, Docker | ✅ done (VPS deploy pending) |

## Quick start

```
cargo run                      # tower on :8080 (console) + :23456 (watchtower RPC)
cargo run --bin verify -- --tower http://localhost:8080 --ckb http://localhost:8114
```

Open `http://localhost:8080` for the watch console; `/attestation` is the public
liveness proof.

## License

MIT — see [`LICENSE`](LICENSE).

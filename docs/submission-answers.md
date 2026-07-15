# CKBoost submission — copy-paste answers

Direct answers to the hackathon quest prompts. Category: **2 — Node, Routing,
Cross-Chain & Diagnostics Infrastructure**.

---

## Project name

**Sentinel — an accountable watchtower for Fiber Network**

## One-line summary

A standalone, deployable watchtower service for Fiber that punishes stale-state
channel breaches on behalf of offline nodes — and the first watchtower on any
payment-channel network that can *prove* it is watching.

## What is your project? (project description)

Sentinel is a standalone watchtower service for Fiber Network. A Fiber node points
its `standalone_watchtower_rpc_url` at Sentinel and can then go offline safely:
Sentinel receives the node's channel-defense data, watches the CKB chain, and if a
counterparty broadcasts a revoked (stale) commitment to steal funds, Sentinel
builds and broadcasts the penalty transaction that sweeps the entire channel
balance to the honest party.

It adds an **accountability layer** that no watchtower — on Fiber or Lightning —
has shipped: every few seconds Sentinel signs the current CKB tip together with
the set of channels it guards. A tower that is asleep cannot produce this, so any
client can verify — not merely trust — that its guard is awake. Registration
returns a signed receipt binding the tower to "watching channel X since block N".

## What problem does it solve? Why does it matter?

A Fiber payment channel is only safe while someone is watching the chain. Old
channel states remain broadcastable forever; if your counterparty publishes a
stale state while your node is offline, they take funds that are no longer theirs,
and the only defense is to catch it within the dispute window and broadcast a
penalty. That requires being online 24/7. Phones sleep, browsers close, power and
connectivity are not guaranteed — and this single liveness requirement is the
reason most mobile payment-channel wallets fall back to custody.

Fiber already ships the *hook* for an external watchtower (`standalone_watchtower_
rpc_url` in every node config) but there was no standalone tower to point it at,
and no watchtower anywhere lets a client verify it is actually awake. This matters
especially for Fiber because Fiber is already shipping browser (`fiber-wasm`) and
mobile (`fiber-android-demo`) nodes — which are offline almost all the time.

## Who is it for?

Fiber node operators who cannot stay online (mobile, browser, intermittent power/
connectivity), and — more importantly — the wallet and service developers who come
after: nobody can ship a genuinely non-custodial mobile Fiber wallet until a
deployable, verifiable watchtower exists. Sentinel is that piece.

## How does it work? (technical)

- **Ingestion:** implements the seven watchtower JSON-RPC methods a Fiber node
  streams (channel registration, revocation updates, settlement data, preimages),
  multi-tenant — one tower protects many nodes.
- **Detection:** derives each channel's funding lock (musig2 aggregate of the
  funding pubkeys), finds via the CKB indexer the transaction that spent it (the
  commitment tx), reads the broadcast commitment number, and decides breach vs
  legitimate close.
- **Penalty:** assembles the revocation transaction (pre-computed penalty output +
  the revocation witness that unlocks the commitment; a separately-signed fee
  input) and broadcasts it. Proven live on a devnet: the attacker's commitment
  cell was swept and the penalty tx committed on-chain.
- **Accountability:** signs the live CKB tip on an interval, served at
  `/attestation`; a `verify` binary checks the signature and freshness against the
  chain and detects a stale/sleeping tower.
- **Operations:** dashboard, Prometheus `/metrics`, `/health`, `/channels`,
  `/breaches`, `/receipts`; one binary runs any network via TOML config; Docker
  packaging.

## Which Fiber infrastructure gap does it address?

The `standalone_watchtower_rpc_url` hook existed with nothing to plug into it;
running a tower meant running a second full node and trusting it blindly; and no
tower could prove its own liveness. Sentinel fills all three.

## Repository

<your GitHub URL> — MIT licensed, fully open source. No pre-existing code reused;
Fiber is referenced over its RPC / matched at the wire and molecule level, never
vendored.

## Demo

- `docs/dashboard-breach.png` / `docs/dashboard-resolved.png` — the live console.
- `scripts/full-demo.sh` — one-command end-to-end breach → sweep on a devnet.
- Video: <link>

## Roadmap

TEE-attested penalty signing (PCR0-pinned enclave, à la modern enclave custody) so
the tower proves not just that it is awake but that it runs the exact published
binary; P2P tower discovery + multi-tower redundancy; size-based fee estimation; a
watchtower-client SDK so wallets auto-register and periodically verify.

## AI usage

AI was used as a development aide (research, scaffolding, docs, and — critically —
decoding the built-in watchtower's transaction to reverse-engineer three
undocumented protocol details) with human-driven architecture, testing, and
verification. Every claim here is backed by runnable code and observed on-chain
behavior.

# Sentinel — Step-by-step implementation plan

Deadline: **15 July 23:59 UTC**. This plan is staged so that **every stage is an
independently shippable submission**. If you stop after any stage, you still have
a coherent, demoable project. Stages do not depend on later stages to be
presentable.

Time budget assumes a single developer working from now.

---

## Stage 0 — Foundation (done)

- [x] MIT-licensed Rust project (`sentinel`) that compiles and runs.
- [x] Module skeleton: `store`, `rpc`, `watch`, `attest`.
- [x] Multi-tenant `sled` store keyed by `node_id`.
- [x] Liveness-attestation signer with a passing verification test.
- [x] HTTP surface: `/health`, `/attestation`, `/channels`.

Ship-check: `cargo run` → `curl localhost:8080/health` returns ok, `/attestation`
returns a real signed statement. ✅

---

## Stage 1 — Devnet + capture the real wire protocol (go/no-go)

**Goal:** prove a real Fiber node will talk to an external tower, and capture the
exact JSON it sends so the `rpc/types.rs` structs are locked to reality, not
guessed.

1. Build the Fiber node from source:
   ```
   cd upstream && cargo build --release   # produces target/release/fnn
   ```
2. Bring up the bundled devnet (`upstream/tests/nodes/`): a CKB dev chain plus
   Fiber nodes 1, 2, 3.
3. Run Sentinel with the JSON-RPC surface replaced by a **capture stub** — a
   server that logs the raw method + params of every call and returns `null`.
4. In node 2's config set:
   ```yaml
   standalone_watchtower_rpc_url: http://127.0.0.1:23456
   disable_built_in_watchtower: true
   standalone_watchtower_token: <token>
   ```
5. Open a channel node1↔node2, push a payment.

**Ship-check (the go/no-go):** `create_watch_channel` and `update_revocation`
land on the stub with real payloads. Save them to `tests/fixtures/`.

- ✅ If they arrive → the premise holds. Lock `rpc/types.rs` to the captured
  bytes and continue.
- ❌ If nothing arrives → stop and reassess before sinking more time. (Fallback
  ideas are in the project notes.)

---

## Stage 2 — The watchtower server

**Goal:** a real tower that accepts and durably stores what a node streams.

1. Stand up a `jsonrpsee` server on `--rpc-port` exposing the seven methods.
2. Resolve the caller's `node_id` from the request (bearer token → context),
   matching how the node authenticates.
3. Wire each method to the `Store` (already written): `create_watch_channel`,
   `remove_watch_channel`, `update_revocation`,
   `update_pending_remote_settlement`, `update_local_settlement`,
   `create_preimage`, `remove_preimage`.
4. Persist and reload across restarts.

**Ship-check:** restart the tower, `curl /channels`, and the channel node 2
registered is still there with its latest revocation. **This alone is the first
standalone Fiber watchtower — a complete submission.**

---

## Stage 3 — Chain watcher + penalty (the breach demo)

**Goal:** detect a breach and punish it. This is the video.

1. Poll the CKB dev chain tip via CKB RPC (`get_tip_header`).
2. For each watched channel, detect when its funding cell is spent by a
   commitment transaction (watch the funding lock script).
3. Compare the broadcast commitment's state against the latest revocation held.
   Older than what we hold ⇒ **breach**.
4. Build + broadcast the penalty transaction. Penalty construction uses Fiber's
   primitives via `fiber-lib` as a linked dependency (not vendored) — nail the
   exact call boundary here.
5. Force a breach on demand with the node's dev RPC:
   `dev_submit_commitment_transaction(channel_id, <old commitment_number>)`.

**Ship-check:** node 2 offline → node 1 broadcasts a stale commitment → Sentinel
detects it and sweeps the channel. A live theft, defeated.

> Risk note: if extracting penalty construction from `fiber-lib` proves too
> coupled, fall back to running the tower as a stripped `fnn` with only the
> watchtower module enabled, and keep all novel work in Stages 4–5.

---

## Stage 4 — Accountability (the differentiator)

**Goal:** make the tower's honesty verifiable. (Signer already written.)

1. Background task: every N seconds, poll the CKB tip and publish a fresh
   `LivenessAttestation` at `/attestation` (real tip, not the `0x00`
   placeholder).
2. On `create_watch_channel`, return a signed `WatchReceipt`.
3. Ship a tiny **verifier** (CLI + TS) that fetches `/attestation`, checks the
   signature against the tower pubkey, and checks the height against a CKB node —
   flagging a stale (asleep) tower.

**Ship-check:** freeze the tower; the verifier reports the attestation height has
stopped advancing and declares the tower not-live. No other watchtower can do
this.

---

## Stage 5 — Operator surface (make it attractive)

1. Dashboard (served from `web/`): channels watched, tower heartbeat/attestation
   age, live breach alarm, per-node view.
2. `/metrics` Prometheus endpoint; structured logs.
3. `Dockerfile` + `docker-compose.yml` (tower + CKB + two Fiber nodes) for
   one-command demo.

**Ship-check:** `docker compose up` brings up the whole demo; dashboard goes red
on a breach.

---

## Stage 6 — Submission package

- README (done), `docs/what-is-real.md` (working / mocked / production gaps).
- 2–3 min video walking the breach demo and the liveness verifier.
- Hosted demo or one-command runnable instructions.
- Fill every deliverable on the CKBoost checklist (missing ones cost points).
- Future roadmap: TEE-attested penalty signing (PCR0-pinned enclave), P2P tower
  discovery, multi-tower redundancy.

---

## Build / run cheatsheet

```
cargo run -- --http-port 8080 --rpc-port 23456   # start the tower
curl localhost:8080/health
curl localhost:8080/attestation
cargo test                                        # attestation crypto test
```

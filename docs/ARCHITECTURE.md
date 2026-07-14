# Architecture

Sentinel is a standalone watchtower service for Fiber Network. It ingests
channel-defense data from nodes, watches CKB for stale-state breaches, and
(when configured to defend) broadcasts the penalty that sweeps a cheater.

## Data flow

```
 Fiber node ──JSON-RPC──▶ ingest ──▶ store (sled, multi-tenant)
 (standalone_watchtower_    │                    │
  rpc_url)                  │                    ▼
                            │            chain scan loop ──▶ detector ──▶ verdict
                            │                    │                          │
                            ▼                    ▼                     Breach│
                     attestation loop      CKB client                       ▼
                     (signs live tip)    (indexer + rpc)          penalty executor
                            │                                     (assemble→sign→send)
                            ▼                                              │
                    /attestation, dashboard ◀── HTTP surface ◀────────────┘
                    /channels /breaches /receipts /metrics /health
```

## Modules

| Module | Responsibility | Key property |
|--------|----------------|--------------|
| `rpc/` | Watchtower JSON-RPC surface (7 methods) a node streams to | multi-tenant via bearer-token→tenant; captures raw payloads |
| `store/` | Persistent, namespaced storage (sled) | one tower, many nodes; survives restart |
| `domain.rs` | Typed wire model | locked to real capture; positional-array params |
| `channel_id.rs` | musig2 funding-lock derivation | validated against live chain |
| `ckb.rs` | Resilient CKB RPC/indexer client | retry+backoff, timeouts, never panics |
| `detector.rs` | Pure breach-decision state machine | unit-testable without a chain |
| `watch/` | Periodic per-channel chain scan | indexed lookups, reorg-safety, fault-isolated |
| `penalty/` | Penalty tx assembly, signing, broadcast | behind a trait; idempotent; auto-discovers deps |
| `attest/` | Liveness attestations + receipts | the accountability layer |
| `metrics.rs` | Prometheus gauges | operator observability |
| `config.rs` | TOML config | one binary, any network |

## Design decisions

- **Penalty execution behind a trait.** `PenaltyExecutor` isolates the
  security-critical transaction assembly so it is swappable and testable; the
  service depends only on the trait. `MockExecutor` backs tests and
  detection-only towers; `CkbPenaltyExecutor` does the real work.
- **The commitment input needs no key.** Fiber hands the tower a pre-computed
  penalty output and an aggregated signature, so the tower unlocks the revoked
  commitment with a revocation witness and signs only a separate fee input
  (CKB secp256k1-blake160 sighash-all).
- **Two modes, one binary.** With a `[penalty]` config the tower actively
  defends; without it, it is a detection/alerting-only tower. Both share all
  detection code.
- **Scale.** Each scan does bounded, indexer-backed lookups per channel rather
  than replaying the chain; per-channel outcomes are independent so one bad
  channel never aborts the sweep.
- **Reliability.** No `unwrap()` in runtime paths; every CKB call retries;
  penalty submission is idempotent (skips if the commitment is already spent);
  graceful shutdown flushes the store; locks recover from poisoning.
- **MIT-clean.** Sentinel never vendors Fiber's (unlicensed) source — it
  re-declares the wire contract and reuses on-chain data. musig2/ckb-types
  versions are pinned to match Fiber so encodings are identical.

## Accountability (the differentiator)

Every N seconds the tower signs `(ckb_tip_hash, height, channels_watched,
timestamp)` and serves it at `/attestation`. A sleeping tower cannot produce
this — it does not know the tip. The `verify` binary checks the signature and
the freshness against the live chain, so a client can prove its tower is awake
rather than trust it. Registration returns a signed receipt binding the tower to
"watching channel X since block N".

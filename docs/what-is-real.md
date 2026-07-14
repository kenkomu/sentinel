# What is real, what is mocked, what production needs

The hackathon explicitly asks submissions to be clear about this. Kept honest and
current as the build progresses.

## Fully working

- MIT Rust service that builds and runs.
- Multi-tenant `sled` store, namespaced by `node_id`.
- Liveness-attestation signer (secp256k1) with a passing verification test.
- HTTP surface: `/health`, `/attestation`, `/channels`.

## Scaffolded, not yet wired

- The seven watchtower JSON-RPC methods (types declared; server wiring is Stage 2).
- Watch receipts (signer written; issued on registration in Stage 4).
- Chain watcher (interface only; real CKB polling + penalty is Stage 3).

## Mocked / placeholder

- `/attestation` currently signs a placeholder tip (`0x00`, height 0). Stage 3/4
  replaces this with a live CKB tip poll.
- `rpc/types.rs` opaque fields are `serde_json::Value` until Stage 1 captures the
  real wire bytes and locks the structs.

## Known limits / production gaps

- **Penalty construction** relies on Fiber's `fiber-lib` primitives. Because the
  upstream repo is unlicensed, this project links/drives rather than vendors that
  code; the exact boundary is finalized in Stage 3.
- Tower identity key is ephemeral (regenerated per run) until Stage 4 persists it.
- No auth hardening on the RPC surface beyond the node's bearer token yet.
- Single-tower only; no redundancy or failover (roadmap).
- Not audited. Do not use on mainnet funds.

## Roadmap (post-hackathon)

- TEE-attested penalty signing (PCR0-pinned enclave) so the tower can prove not
  just that it is awake but that it runs the exact published binary.
- P2P tower discovery and multi-tower redundancy.

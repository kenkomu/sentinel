//! Penalty execution — turning a detected breach into the transaction that
//! sweeps the cheater's channel balance.
//!
//! Design: execution sits behind the [`PenaltyExecutor`] trait so the
//! security-critical transaction assembly is one isolated, swappable, testable
//! component. The service depends only on the trait; a [`MockExecutor`] backs
//! tests and detection-only deployments, and [`ckb::CkbPenaltyExecutor`] builds
//! and broadcasts the real transaction.
//!
//! The commitment input is unlocked by the **revocation witness** — Fiber hands
//! the tower a pre-computed penalty `output` and an `aggregated_signature`, so
//! the tower needs no channel key to spend the revoked commitment. It only signs
//! a separate fee-provider input. The revocation witness layout (validated
//! against real captured data) is:
//!
//!   XUDT_COMPATIBLE_WITNESS (16) ‖ 0x00 (unlock=revocation)
//!     ‖ commitment_number BE (8) ‖ x_only_aggregated_pubkey (32)
//!     ‖ aggregated_signature (64)

pub mod witness;

use crate::domain::RevocationData;
use async_trait::async_trait;

/// Everything an executor needs to punish one breach.
#[derive(Debug, Clone)]
pub struct BreachContext {
    pub channel_id: String,
    /// The revoked commitment cell to spend.
    pub commitment_tx_hash: String,
    pub commitment_index: u32,
    /// The revocation data the node streamed (penalty output + signature).
    pub revocation: RevocationData,
    /// x-only musig2 aggregate of the funding pubkeys, in commitment order.
    pub x_only_aggregated_pubkey: [u8; 32],
}

/// The outcome of attempting to punish a breach.
#[derive(Debug, Clone)]
pub enum PenaltyOutcome {
    /// Penalty transaction broadcast; carries its hash.
    Broadcast(String),
    /// The commitment cell was already spent (someone punished first, or it was
    /// settled) — nothing to do. Idempotent, not an error.
    AlreadyResolved,
    /// Could not execute; carries a human reason.
    Failed(String),
}

#[async_trait]
pub trait PenaltyExecutor: Send + Sync {
    async fn punish(&self, ctx: &BreachContext) -> PenaltyOutcome;
}

/// No-op executor for detection-only towers and tests. Records calls so tests
/// can assert the detector handed it the right breach.
#[derive(Default, Clone)]
pub struct MockExecutor {
    pub calls: std::sync::Arc<std::sync::Mutex<Vec<BreachContext>>>,
}

#[async_trait]
impl PenaltyExecutor for MockExecutor {
    async fn punish(&self, ctx: &BreachContext) -> PenaltyOutcome {
        self.calls.lock().unwrap().push(ctx.clone());
        PenaltyOutcome::Broadcast(format!("mock-penalty-for-{}", ctx.channel_id))
    }
}

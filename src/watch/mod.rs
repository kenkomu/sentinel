//! Chain watcher — the periodic scan that drives breach detection across every
//! watched channel, and (when configured to defend) hands breaches to the
//! penalty executor.
//!
//! Design for scale and reliability:
//!   * Each scan iterates watched channels and does a bounded, indexed lookup
//!     (funding-lock → spending tx) rather than replaying the chain.
//!   * A per-channel outcome is independent: one channel's RPC error or odd
//!     state never aborts the sweep of the others.
//!   * The scan is idempotent — re-detecting an already-punished breach is
//!     harmless (the executor checks the commitment cell is still live first).

use crate::ckb::CkbClient;
use crate::channel_id::commitment_x_only_pubkey;
use crate::detector::{self, Verdict};
use crate::domain::parse_hex_bytes;
use crate::penalty::{BreachContext, PenaltyExecutor, PenaltyOutcome};
use crate::store::Store;
use std::sync::Arc;

/// Immutable inputs the scan needs about the network's deployed scripts.
#[derive(Clone)]
pub struct WatchParams {
    pub funding_lock_code_hash: String,
    pub funding_lock_hash_type: String,
    /// Confirmations to wait before treating a spend as final (reorg safety).
    pub reorg_safety_blocks: u64,
}

/// Result of scanning one channel — surfaced to metrics/alerting and, on a
/// breach, to the executor.
#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub channel_id: String,
    pub node_id: String,
    pub verdict: Verdict,
}

pub struct ChainWatcher {
    pub store: Store,
    pub ckb: CkbClient,
    pub params: WatchParams,
    /// When present, the watcher punishes breaches; otherwise it is a
    /// detection/alerting-only tower.
    pub executor: Option<Arc<dyn PenaltyExecutor>>,
}

impl ChainWatcher {
    pub fn new(store: Store, ckb: CkbClient, params: WatchParams) -> Self {
        Self { store, ckb, params, executor: None }
    }

    pub fn with_executor(mut self, executor: Arc<dyn PenaltyExecutor>) -> Self {
        self.executor = Some(executor);
        self
    }

    /// Scan every watched channel once, returning per-channel outcomes.
    pub async fn scan_once(&self, tip: u64) -> Vec<ScanOutcome> {
        let channels = match self.store.all_channels() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "scan: cannot read store");
                return Vec::new();
            }
        };

        let mut outcomes = Vec::new();
        for wc in channels {
            let outcome = self.scan_channel(&wc, tip).await;
            if let Some(o) = outcome {
                outcomes.push(o);
            }
        }
        outcomes
    }

    async fn scan_channel(
        &self,
        wc: &crate::store::WatchedChannel,
        tip: u64,
    ) -> Option<ScanOutcome> {
        let (create, revocation) = self.store.typed(wc)?;

        let lock = detector::funding_lock_script(
            &create,
            &self.params.funding_lock_code_hash,
            &self.params.funding_lock_hash_type,
        )?;

        // Is the funding cell still live? Then the channel is open — nothing to do.
        match self.ckb.find_live_cell(&lock).await {
            Ok(Some(_)) => {
                return Some(ScanOutcome {
                    channel_id: create.channel_id.clone(),
                    node_id: wc.node_id.clone(),
                    verdict: Verdict::ChannelOpen,
                });
            }
            Ok(None) => { /* fall through: maybe spent */ }
            Err(e) => {
                tracing::warn!(channel = %create.channel_id, error = %e, "scan: live-cell lookup failed");
                return None;
            }
        }

        // Funding cell not live — find the tx that spent it (the commitment tx).
        let spend = match self.ckb.find_spending_tx(&lock).await {
            Ok(Some(s)) => s,
            Ok(None) => return None,
            Err(e) => {
                tracing::warn!(channel = %create.channel_id, error = %e, "scan: spend lookup failed");
                return None;
            }
        };

        // Reorg safety: don't act until the spend is buried enough.
        if tip.saturating_sub(spend.block_number) < self.params.reorg_safety_blocks {
            tracing::debug!(channel = %create.channel_id, "spend not yet final; deferring");
            return None;
        }

        let tx_json = match self.ckb.get_transaction(&spend.tx_hash).await {
            Ok(Some(t)) => t,
            _ => return None,
        };
        let commitment_args = detector::commitment_lock_args_from_tx(&tx_json)?;

        let mut verdict = detector::decide(
            &create,
            revocation.as_ref(),
            &spend.tx_hash,
            0,
            &commitment_args,
        );

        // If this was a breach but the revoked commitment cell is no longer live,
        // it has already been swept (by our penalty) — report it resolved so the
        // alarm clears and the win is visible.
        if let Verdict::Breach { commitment_tx, commitment_index, .. } = &verdict {
            if let Ok(status) = self.ckb.live_cell_status(commitment_tx, *commitment_index).await {
                if status != "live" {
                    verdict = Verdict::BreachResolved { commitment_tx: commitment_tx.clone() };
                }
            }
        }

        if let Verdict::Breach { commitment_index, broadcast_commitment, .. } = &verdict {
            tracing::warn!(channel = %create.channel_id, node = %wc.node_id, "BREACH detected");
            // In Fiber's revocation semantics, the revocation with
            // commitment_number = N+1 revokes commitment cell N (the secret is
            // released when moving PAST that state). Daric lets the LATEST
            // revocation revoke any earlier commitment, so punish with the
            // highest-numbered revocation we hold that is strictly greater than
            // the broadcast — falling back to the stored latest.
            let punish_with = self
                .store
                .get_revocation_for(&wc.node_id, &create.channel_id, *broadcast_commitment + 1)
                .ok()
                .flatten()
                .or_else(|| revocation.clone());
            if let (Some(executor), Some(revocation)) = (self.executor.as_ref(), punish_with) {
                self.punish(&create, &revocation, &spend.tx_hash, *commitment_index, executor.as_ref())
                    .await;
            }
        }

        Some(ScanOutcome {
            channel_id: create.channel_id.clone(),
            node_id: wc.node_id.clone(),
            verdict,
        })
    }

    /// Assemble the breach context and hand it to the executor.
    async fn punish(
        &self,
        create: &crate::domain::CreateWatchChannel,
        revocation: &crate::domain::RevocationData,
        commitment_tx_hash: &str,
        commitment_index: u32,
        executor: &dyn PenaltyExecutor,
    ) {
        let (Some(local), Some(remote)) = (
            parse_hex_bytes(&create.local_funding_pubkey),
            parse_hex_bytes(&create.remote_funding_pubkey),
        ) else {
            tracing::error!(channel = %create.channel_id, "punish: unparseable funding pubkeys");
            return;
        };
        let Some(agg) = commitment_x_only_pubkey(&local, &remote) else {
            tracing::error!(channel = %create.channel_id, "punish: musig2 aggregation failed");
            return;
        };
        tracing::info!(
            channel = %create.channel_id,
            using_revocation_commitment = ?revocation.commitment_number_u64(),
            "punish: assembling penalty with this revocation"
        );
        let ctx = BreachContext {
            channel_id: create.channel_id.clone(),
            commitment_tx_hash: commitment_tx_hash.to_string(),
            commitment_index,
            revocation: revocation.clone(),
            x_only_aggregated_pubkey: agg,
        };
        match executor.punish(&ctx).await {
            PenaltyOutcome::Broadcast(h) => {
                tracing::warn!(channel = %create.channel_id, penalty_tx = %h, "PENALTY BROADCAST — cheater swept")
            }
            PenaltyOutcome::AlreadyResolved => {
                tracing::info!(channel = %create.channel_id, "penalty: commitment already resolved")
            }
            PenaltyOutcome::Failed(e) => {
                tracing::error!(channel = %create.channel_id, error = %e, "penalty FAILED")
            }
        }
    }
}

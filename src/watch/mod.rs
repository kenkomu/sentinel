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
use crate::config::PenaltyConfig;
use crate::detector::{self, Verdict};
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
    /// When present, the watcher will attempt to punish breaches.
    pub penalty: Option<Arc<PenaltyConfig>>,
}

impl ChainWatcher {
    pub fn new(store: Store, ckb: CkbClient, params: WatchParams) -> Self {
        Self { store, ckb, params, penalty: None }
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

        let verdict = detector::decide(
            &create,
            revocation.as_ref(),
            &spend.tx_hash,
            0,
            &commitment_args,
        );

        if let Verdict::Breach { .. } = &verdict {
            tracing::warn!(channel = %create.channel_id, node = %wc.node_id, "BREACH detected");
        }

        Some(ScanOutcome {
            channel_id: create.channel_id.clone(),
            node_id: wc.node_id.clone(),
            verdict,
        })
    }
}

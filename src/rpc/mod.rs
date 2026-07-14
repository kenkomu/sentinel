//! The watchtower JSON-RPC surface a Fiber node connects to.
pub mod server;
pub mod types;

use crate::attest::Attestor;
use crate::error::Result;
use crate::store::Store;
use serde_json::Value;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Shared handler state for the RPC methods. Wired into a `jsonrpsee` server
/// (see [`server`]) exposing the seven watchtower methods; each handler resolves
/// the caller's `node_id` and writes to the multi-tenant [`Store`].
#[derive(Clone)]
pub struct WatchtowerRpc {
    pub store: Store,
    pub attestor: Arc<Attestor>,
    /// Latest CKB tip height the tower has seen, updated by the attestation
    /// loop. Used to stamp registration receipts with "watching since block N".
    pub height: Arc<AtomicU64>,
}

/// Pull a string field out of a raw params object, tolerating both
/// `{"field": "x"}` and a positional `["x", ...]` shape until Stage 1 locks it.
fn field(raw: &Value, name: &str) -> Option<String> {
    raw.get(name)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

impl WatchtowerRpc {
    pub fn new(store: Store, attestor: Arc<Attestor>, height: Arc<AtomicU64>) -> Self {
        Self { store, attestor, height }
    }

    pub fn store_create(&self, node_id: &str, raw: Value) -> Result<()> {
        let channel_id = field(&raw, "channel_id").unwrap_or_else(|| "unknown".into());
        self.store.insert_raw(node_id, &channel_id, "create", raw)?;
        // Issue a signed receipt: proof the tower accepted responsibility for
        // this channel from the current block height. The client can later use
        // it to hold the tower to account.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let receipt = self.attestor.issue_receipt(
            node_id,
            &channel_id,
            self.height.load(Ordering::Relaxed),
            now,
        );
        self.store.insert_receipt(node_id, &channel_id, &receipt)
    }

    pub fn store_remove(&self, node_id: &str, raw: &Value) -> Result<()> {
        let channel_id = field(raw, "channel_id").unwrap_or_else(|| "unknown".into());
        self.store.remove_channel(node_id, &channel_id)
    }

    pub fn store_revocation(&self, node_id: &str, raw: Value) -> Result<()> {
        let channel_id = field(&raw, "channel_id").unwrap_or_else(|| "unknown".into());
        self.store.insert_raw(node_id, &channel_id, "revocation", raw)
    }

    pub fn store_pending_remote(&self, node_id: &str, raw: Value) -> Result<()> {
        let channel_id = field(&raw, "channel_id").unwrap_or_else(|| "unknown".into());
        self.store
            .insert_raw(node_id, &channel_id, "pending_remote_settlement", raw)
    }

    pub fn store_local_settlement(&self, node_id: &str, raw: Value) -> Result<()> {
        let channel_id = field(&raw, "channel_id").unwrap_or_else(|| "unknown".into());
        self.store
            .insert_raw(node_id, &channel_id, "local_settlement", raw)
    }

    pub fn store_preimage(&self, node_id: &str, raw: Value) -> Result<()> {
        let payment_hash = field(&raw, "payment_hash").unwrap_or_else(|| "unknown".into());
        let preimage = field(&raw, "preimage").unwrap_or_default();
        self.store.insert_preimage(node_id, &payment_hash, &preimage)
    }

    pub fn store_remove_preimage(&self, node_id: &str, raw: &Value) -> Result<()> {
        let payment_hash = field(raw, "payment_hash").unwrap_or_else(|| "unknown".into());
        self.store.remove_preimage(node_id, &payment_hash)
    }
}

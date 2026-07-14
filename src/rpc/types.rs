//! Wire types for the watchtower JSON-RPC surface.
//!
//! These mirror the JSON shape that a Fiber node sends to its configured
//! `standalone_watchtower_rpc_url`. We deliberately do NOT copy Fiber's Rust
//! source (the upstream repo is unlicensed); we re-declare the wire contract.
//!
//! The seven methods a node calls are:
//!   create_watch_channel, remove_watch_channel, update_revocation,
//!   update_pending_remote_settlement, update_local_settlement,
//!   create_preimage, remove_preimage
//!
//! During Stage 1 we capture the exact bytes a real node sends and lock these
//! structs to that wire format. Until then, opaque fields are kept as
//! `serde_json::Value` so nothing is guessed incorrectly.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The per-request context a Fiber node attaches, carrying the calling node's
/// identity (derived from its bearer token on the node side). This is what lets
/// one Sentinel protect many nodes — every record is keyed by `node_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcContext {
    pub node_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWatchChannelParams {
    pub channel_id: String,
    #[serde(default)]
    pub funding_udt_type_script: Option<Value>,
    pub local_settlement_key: Value,
    pub remote_settlement_key: Value,
    pub local_funding_pubkey: Value,
    pub remote_funding_pubkey: Value,
    pub settlement_data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveWatchChannelParams {
    pub channel_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRevocationParams {
    pub channel_id: String,
    pub revocation_data: Value,
    pub settlement_data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatePendingRemoteSettlementParams {
    pub channel_id: String,
    pub settlement_data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateLocalSettlementParams {
    pub channel_id: String,
    pub settlement_data: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreatePreimageParams {
    pub payment_hash: String,
    pub preimage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovePreimageParams {
    pub payment_hash: String,
}

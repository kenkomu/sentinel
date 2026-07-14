//! The watchtower JSON-RPC surface a Fiber node connects to.
pub mod types;

use crate::store::Store;
use crate::attest::Attestor;
use std::sync::Arc;

/// Shared handler state for the RPC methods. In Stage 2 this is wired into a
/// `jsonrpsee` server exposing the seven watchtower methods; each handler
/// resolves the caller's `node_id` from the request context and writes to the
/// multi-tenant `Store`.
#[derive(Clone)]
pub struct WatchtowerRpc {
    pub store: Store,
    pub attestor: Arc<Attestor>,
}

impl WatchtowerRpc {
    pub fn new(store: Store, attestor: Arc<Attestor>) -> Self {
        Self { store, attestor }
    }
}

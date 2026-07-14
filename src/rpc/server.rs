//! The JSON-RPC watchtower surface a Fiber node connects to via
//! `standalone_watchtower_rpc_url`.
//!
//! Built with a manual `jsonrpsee` `RpcModule` (rather than the typed macro) so
//! that during Stage 1 it accepts and logs the *raw* params a real node sends —
//! we lock typed structs only after observing the wire bytes. Every method both
//! records the payload (capture) and writes it to the multi-tenant store.
//!
//! Tenant identity: a Fiber node authenticates with a bearer token. We derive a
//! stable `node_id` from that token so one tower cleanly separates many nodes.
//! (Full biscuit parsing is a later refinement; the token → tenant mapping is
//! the load-bearing property and it holds today.)

use crate::rpc::WatchtowerRpc;
use jsonrpsee::server::{Server, ServerHandle};
use jsonrpsee::types::ErrorObjectOwned;
use jsonrpsee::{Extensions, RpcModule};
use serde_json::Value;
use std::net::SocketAddr;

/// A resolved tenant, injected into request extensions by the HTTP middleware.
#[derive(Clone, Debug)]
pub struct Tenant(pub String);

fn tenant_of(ext: &Extensions) -> String {
    ext.get::<Tenant>()
        .map(|t| t.0.clone())
        .unwrap_or_else(|| "anonymous".to_string())
}

/// Log a raw incoming call (Stage 1 capture) at info level.
fn log_call(method: &str, node_id: &str, raw: &Value) {
    tracing::info!(target: "sentinel::capture", %method, %node_id, payload = %raw, "node → tower");
}

/// Derive a stable tenant id from the node's bearer token. We hash the token so
/// the on-disk tenant key never contains the raw secret. (Full biscuit parsing
/// to the node's real public identity is a later refinement; the token→tenant
/// separation is what the multi-tenancy guarantee rests on, and it holds here.)
fn tenant_from_auth(header: Option<&str>) -> Tenant {
    match header {
        Some(h) => {
            use sha2::Digest;
            let token = h.strip_prefix("Bearer ").unwrap_or(h);
            let mut hasher = sha2::Sha256::new();
            hasher.update(token.as_bytes());
            let d = hasher.finalize();
            Tenant(format!("node-{}", hex::encode(&d[..8])))
        }
        None => Tenant("anonymous".to_string()),
    }
}

pub async fn serve(
    handler: WatchtowerRpc,
    addr: SocketAddr,
) -> anyhow::Result<(SocketAddr, ServerHandle)> {
    // HTTP middleware: read the Authorization header once per request and inject
    // the resolved Tenant into request extensions, which jsonrpsee forwards to
    // each method's `Extensions`.
    let http_mw = tower::ServiceBuilder::new().map_request(|mut req: jsonrpsee::server::HttpRequest<_>| {
        let auth = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        req.extensions_mut().insert(tenant_from_auth(auth.as_deref()));
        req
    });

    let server = Server::builder()
        .set_http_middleware(http_mw)
        .build(addr)
        .await?;
    let local_addr = server.local_addr()?;
    let module = build_module(handler)?;
    let handle = server.start(module);
    Ok((local_addr, handle))
}

fn build_module(handler: WatchtowerRpc) -> anyhow::Result<RpcModule<WatchtowerRpc>> {
    let mut module = RpcModule::new(handler);

    module.register_async_method(
        "create_watch_channel",
        |params, ctx, ext| async move {
            let raw: Value = params.parse().unwrap_or(Value::Null);
            let node_id = tenant_of(&ext);
            log_call("create_watch_channel", &node_id, &raw);
            ctx.store_create(&node_id, raw).map_err(to_rpc_err)?;
            Ok::<Value, ErrorObjectOwned>(Value::Null)
        },
    )?;

    module.register_async_method("remove_watch_channel", |params, ctx, ext| async move {
        let raw: Value = params.parse().unwrap_or(Value::Null);
        let node_id = tenant_of(&ext);
        log_call("remove_watch_channel", &node_id, &raw);
        ctx.store_remove(&node_id, &raw).map_err(to_rpc_err)?;
        Ok::<Value, ErrorObjectOwned>(Value::Null)
    })?;

    module.register_async_method("update_revocation", |params, ctx, ext| async move {
        let raw: Value = params.parse().unwrap_or(Value::Null);
        let node_id = tenant_of(&ext);
        log_call("update_revocation", &node_id, &raw);
        ctx.store_revocation(&node_id, raw).map_err(to_rpc_err)?;
        Ok::<Value, ErrorObjectOwned>(Value::Null)
    })?;

    module.register_async_method(
        "update_pending_remote_settlement",
        |params, ctx, ext| async move {
            let raw: Value = params.parse().unwrap_or(Value::Null);
            let node_id = tenant_of(&ext);
            log_call("update_pending_remote_settlement", &node_id, &raw);
            ctx.store_pending_remote(&node_id, raw).map_err(to_rpc_err)?;
            Ok::<Value, ErrorObjectOwned>(Value::Null)
        },
    )?;

    module.register_async_method("update_local_settlement", |params, ctx, ext| async move {
        let raw: Value = params.parse().unwrap_or(Value::Null);
        let node_id = tenant_of(&ext);
        log_call("update_local_settlement", &node_id, &raw);
        ctx.store_local_settlement(&node_id, raw).map_err(to_rpc_err)?;
        Ok::<Value, ErrorObjectOwned>(Value::Null)
    })?;

    module.register_async_method("create_preimage", |params, ctx, ext| async move {
        let raw: Value = params.parse().unwrap_or(Value::Null);
        let node_id = tenant_of(&ext);
        log_call("create_preimage", &node_id, &raw);
        ctx.store_preimage(&node_id, raw).map_err(to_rpc_err)?;
        Ok::<Value, ErrorObjectOwned>(Value::Null)
    })?;

    module.register_async_method("remove_preimage", |params, ctx, ext| async move {
        let raw: Value = params.parse().unwrap_or(Value::Null);
        let node_id = tenant_of(&ext);
        log_call("remove_preimage", &node_id, &raw);
        ctx.store_remove_preimage(&node_id, &raw).map_err(to_rpc_err)?;
        Ok::<Value, ErrorObjectOwned>(Value::Null)
    })?;

    Ok(module)
}

fn to_rpc_err(e: crate::error::SentinelError) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32000, e.to_string(), None::<()>)
}

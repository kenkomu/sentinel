//! Sentinel — an accountable watchtower service for Fiber Network.
//!
//! Library surface shared by the `sentinel` server binary and the `verify`
//! client binary.

pub mod attest;
pub mod ckb;
pub mod error;
pub mod metrics;
pub mod rpc;
pub mod store;
pub mod watch;

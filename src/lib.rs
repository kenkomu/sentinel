//! Sentinel — an accountable watchtower service for Fiber Network.
//!
//! Library surface shared by the `sentinel` server binary and the `verify`
//! client binary.

pub mod attest;
pub mod channel_id;
pub mod ckb;
pub mod config;
pub mod domain;
pub mod error;
pub mod metrics;
pub mod rpc;
pub mod store;
pub mod watch;

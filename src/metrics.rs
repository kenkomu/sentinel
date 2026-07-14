//! Prometheus metrics for operators. A watchtower is only useful if its operator
//! can tell at a glance that it is healthy — so the same signals the dashboard
//! shows are exported here for alerting.

use prometheus::{IntGauge, Registry, TextEncoder};

#[derive(Clone)]
pub struct Metrics {
    pub registry: Registry,
    pub channels_watched: IntGauge,
    pub tenants: IntGauge,
    /// Seconds since the last successful liveness attestation. The key alerting
    /// signal: if this climbs, the tower has stopped proving it is watching.
    pub attestation_age: IntGauge,
    pub ckb_tip_height: IntGauge,
    /// 1 while the tower can currently prove liveness, 0 otherwise.
    pub live: IntGauge,
    /// Channels currently in a detected-breach state (should normally be 0).
    pub breaches_detected: IntGauge,
}

impl Metrics {
    pub fn new() -> Self {
        let registry = Registry::new();
        let channels_watched =
            IntGauge::new("sentinel_channels_watched", "Channels currently under watch").unwrap();
        let tenants = IntGauge::new("sentinel_tenants", "Distinct nodes protected").unwrap();
        let attestation_age = IntGauge::new(
            "sentinel_attestation_age_seconds",
            "Seconds since the last liveness attestation",
        )
        .unwrap();
        let ckb_tip_height =
            IntGauge::new("sentinel_ckb_tip_height", "Attested CKB tip height").unwrap();
        let live = IntGauge::new(
            "sentinel_live",
            "1 if the tower can currently prove liveness, else 0",
        )
        .unwrap();
        let breaches_detected = IntGauge::new(
            "sentinel_breaches_detected",
            "Channels currently in a detected-breach state",
        )
        .unwrap();

        registry.register(Box::new(channels_watched.clone())).ok();
        registry.register(Box::new(tenants.clone())).ok();
        registry.register(Box::new(attestation_age.clone())).ok();
        registry.register(Box::new(ckb_tip_height.clone())).ok();
        registry.register(Box::new(live.clone())).ok();
        registry.register(Box::new(breaches_detected.clone())).ok();

        Self { registry, channels_watched, tenants, attestation_age, ckb_tip_height, live, breaches_detected }
    }

    pub fn encode(&self) -> String {
        let mut buf = String::new();
        let encoder = TextEncoder::new();
        let families = self.registry.gather();
        encoder.encode_utf8(&families, &mut buf).ok();
        buf
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

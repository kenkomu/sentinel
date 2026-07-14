//! Typed domain model for watchtower data.
//!
//! These structs are locked to the exact wire format a Fiber node sends, as
//! captured from a live devnet (see `tests/fixtures/captured-devnet.log`). Params
//! arrive as a positional array `[{...}]`; helpers here unwrap and validate that.
//!
//! Hex fields keep their `0x` string form as received and are decoded on demand,
//! so ingestion never rejects a record it could have stored — a watchtower must
//! be maximally willing to *accept* protective data.

use serde::{Deserialize, Serialize};

/// Registration payload — everything needed to recognise a channel's on-chain
/// commitment cell and (later) authorize its penalty.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateWatchChannel {
    pub channel_id: String,
    #[serde(default)]
    pub funding_udt_type_script: Option<serde_json::Value>,
    pub local_funding_pubkey: String,
    pub remote_funding_pubkey: String,
    pub local_settlement_key: String,
    pub remote_settlement_key: String,
    pub settlement_data: SettlementData,
}

/// The secret + pre-computed penalty output a node hands the tower on every new
/// commitment. `output`/`output_data` are molecule-serialized and passed through
/// into the penalty transaction verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationData {
    pub aggregated_signature: String,
    pub commitment_number: String,
    /// Molecule-serialized `CellOutput` — the penalty output, pre-built by the node.
    pub output: String,
    pub output_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRevocation {
    pub channel_id: String,
    pub revocation_data: RevocationData,
    pub settlement_data: SettlementData,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SettlementData {
    #[serde(default)]
    pub local_amount: String,
    #[serde(default)]
    pub remote_amount: String,
    #[serde(default)]
    pub tlcs: Vec<serde_json::Value>,
}

/// Decode a `0x`-prefixed hex integer (as CKB JSON-RPC encodes numbers).
pub fn parse_hex_u64(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

/// Decode a `0x`-prefixed hex byte string.
pub fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    hex::decode(s.trim_start_matches("0x")).ok()
}

impl RevocationData {
    pub fn commitment_number_u64(&self) -> Option<u64> {
        parse_hex_u64(&self.commitment_number)
    }
}

/// Unwrap the positional-array params a Fiber node sends and deserialize the
/// inner object into `T`.
pub fn from_positional<T: for<'de> Deserialize<'de>>(raw: &serde_json::Value) -> Option<T> {
    let obj = match raw {
        serde_json::Value::Array(items) => items.first()?,
        other => other,
    };
    serde_json::from_value(obj.clone()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exact shape captured from a live devnet node.
    const CREATE: &str = r#"[{"channel_id":"0x4b4c","funding_udt_type_script":null,
        "local_funding_pubkey":"0323","remote_funding_pubkey":"03bc",
        "local_settlement_key":"7c0d","remote_settlement_key":"02c5",
        "settlement_data":{"local_amount":"0x24e160300","remote_amount":"0xba43b7400","tlcs":[]}}]"#;

    const REVOKE: &str = r#"[{"channel_id":"0x4b4c",
        "revocation_data":{"aggregated_signature":"0x59c1","commitment_number":"0x1",
        "output":"0x6100","output_data":"0x00000000"},
        "settlement_data":{"local_amount":"0x24e160300","remote_amount":"0xba43b739c","tlcs":[]}}]"#;

    #[test]
    fn parses_positional_create() {
        let v: serde_json::Value = serde_json::from_str(CREATE).unwrap();
        let c: CreateWatchChannel = from_positional(&v).expect("parse create");
        assert_eq!(c.channel_id, "0x4b4c");
        assert_eq!(c.settlement_data.local_amount, "0x24e160300");
    }

    #[test]
    fn parses_positional_revocation_and_commitment_number() {
        let v: serde_json::Value = serde_json::from_str(REVOKE).unwrap();
        let r: UpdateRevocation = from_positional(&v).expect("parse revoke");
        assert_eq!(r.revocation_data.commitment_number_u64(), Some(1));
    }

    #[test]
    fn hex_helpers() {
        assert_eq!(parse_hex_u64("0x1"), Some(1));
        assert_eq!(parse_hex_u64("0x24e160300"), Some(9_900_000_000));
        assert_eq!(parse_hex_bytes("0x00000000"), Some(vec![0, 0, 0, 0]));
    }
}

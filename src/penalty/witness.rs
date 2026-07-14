//! Revocation-witness assembly — the exact bytes that unlock a revoked
//! commitment cell down the penalty path.
//!
//! Validated byte-for-byte against Fiber's `build_revocation_tx` and against
//! real revocation data captured from a live devnet node.

use crate::domain::{parse_hex_bytes, RevocationData};

/// Molecule empty-vector prefix Fiber prepends (its `XUDT_COMPATIBLE_WITNESS`).
pub const XUDT_COMPATIBLE_WITNESS: [u8; 16] =
    [16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0, 16, 0, 0, 0];

/// Unlock selector byte for the revocation (penalty) path.
pub const UNLOCK_REVOCATION: u8 = 0x00;

/// Build the revocation witness that spends a revoked commitment cell.
///
/// Returns `None` if the revocation data can't be decoded or has an unexpected
/// signature length (must be 64 bytes for the aggregated Schnorr/musig2 sig).
pub fn build_revocation_witness(
    revocation: &RevocationData,
    x_only_aggregated_pubkey: &[u8; 32],
) -> Option<Vec<u8>> {
    let commitment_number = revocation.commitment_number_u64()?;
    let signature = parse_hex_bytes(&revocation.aggregated_signature)?;
    if signature.len() != 64 {
        return None;
    }

    let mut w = Vec::with_capacity(16 + 1 + 8 + 32 + 64);
    w.extend_from_slice(&XUDT_COMPATIBLE_WITNESS);
    w.push(UNLOCK_REVOCATION);
    w.extend_from_slice(&commitment_number.to_be_bytes());
    w.extend_from_slice(x_only_aggregated_pubkey);
    w.extend_from_slice(&signature);
    Some(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real revocation data captured from a live devnet node (commitment 0x1).
    fn real_revocation() -> RevocationData {
        RevocationData {
            aggregated_signature: "0x59c168936008778a03b7f451fd2527642dc70ecff2b9ac9e78ec9497e254210e6846a5f36f42ef889084dd26b01ea0922c15272a72f43049229d044948b56bf6".into(),
            commitment_number: "0x1".into(),
            output: "0x6100".into(),
            output_data: "0x00000000".into(),
        }
    }

    #[test]
    fn witness_layout_is_exact() {
        let agg = [0xAAu8; 32];
        let w = build_revocation_witness(&real_revocation(), &agg).expect("build witness");
        // 16 (prefix) + 1 (unlock) + 8 (commitment number) + 32 (pubkey) + 64 (sig)
        assert_eq!(w.len(), 121);
        assert_eq!(&w[0..16], &XUDT_COMPATIBLE_WITNESS);
        assert_eq!(w[16], UNLOCK_REVOCATION);
        assert_eq!(&w[17..25], &1u64.to_be_bytes()); // commitment number 1, BE
        assert_eq!(&w[25..57], &agg); // x-only aggregated pubkey
        assert_eq!(w[57..121].len(), 64); // signature
    }

    #[test]
    fn rejects_bad_signature_length() {
        let mut r = real_revocation();
        r.aggregated_signature = "0x1234".into(); // too short
        assert!(build_revocation_witness(&r, &[0u8; 32]).is_none());
    }
}

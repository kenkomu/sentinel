//! Verify the EXACT signature from an assembled penalty tx against the message
//! the deployed commitment lock computes, using real values pulled from the tx
//! dump and the on-chain commitment cell (channel bf311faa).

#[cfg(test)]
mod tests {
    use ckb_hash::blake2b_256;
    use ckb_types::{bytes::Bytes, core::{Capacity, ScriptHashType}, packed::{CellOutput, Script}, prelude::*, H256};
    use secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};

    // From the assembled penalty tx dump + chain.
    const PUBKEY: &str = "ec0bb6fe4317206da5c1388f2b9ca9c6cf51c892ec8c81790a0276ec6a77afff";
    const SIG: &str = "0ce4fe02044926557f5433f37d5c561fbfdeb663981ab69ff3ee50919e1cc4d818c886de768c56bbb76ebd95a5f92dd0d2b668b13f608ac70ba8be19f06fefac";
    // penalty output[0] fields
    const OUT_CAP: u64 = 0xdf2517538;
    const OUT_CODE: &str = "9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8";
    const OUT_ARGS: &str = "639b4a957ef467ddf92a2dcb53e94b3aa61b2382";
    const ODATA: &str = "00000000";
    // commitment cell args (bf311faa commitment 1)
    const CELL_ARGS28: &str = "d8e5f3eac0207550cc3ad69e87636dbec79c7aab01000000000100a0";
    const VERSION: u64 = 1;

    #[test]
    fn assembled_penalty_signature_verifies() {
        let lock = Script::new_builder()
            .code_hash(H256(hex::decode(OUT_CODE).unwrap().try_into().unwrap()).pack())
            .hash_type(ckb_types::packed::Byte::new(ScriptHashType::Type as u8))
            .args(Bytes::from(hex::decode(OUT_ARGS).unwrap()).pack())
            .build();
        let output = CellOutput::new_builder()
            .capacity(Capacity::shannons(OUT_CAP).pack())
            .lock(lock)
            .build();

        let odata = hex::decode(ODATA).unwrap();
        let cell28 = hex::decode(CELL_ARGS28).unwrap();

        // Candidate C (deployed, no length prefix): output ‖ odata ‖ args28 ‖ version
        let mut c = Vec::new();
        c.extend_from_slice(output.as_slice());
        c.extend_from_slice(&odata);
        c.extend_from_slice(&cell28);
        c.extend_from_slice(&VERSION.to_be_bytes());

        // Candidate B (length prefix): output ‖ u32le(len) ‖ odata ‖ args28 ‖ version
        let mut b = Vec::new();
        b.extend_from_slice(output.as_slice());
        b.extend_from_slice(&(odata.len() as u32).to_le_bytes());
        b.extend_from_slice(&odata);
        b.extend_from_slice(&cell28);
        b.extend_from_slice(&VERSION.to_be_bytes());

        let secp = Secp256k1::verification_only();
        let xonly = XOnlyPublicKey::from_slice(&hex::decode(PUBKEY).unwrap()).unwrap();
        let sig = Signature::from_slice(&hex::decode(SIG).unwrap()).unwrap();
        let vc = secp.verify_schnorr(&sig, &Message::from_digest(blake2b_256(&c)), &xonly).is_ok();
        let vb = secp.verify_schnorr(&sig, &Message::from_digest(blake2b_256(&b)), &xonly).is_ok();
        println!("assembled-tx sig verifies: C(no-prefix)={vc} B(prefix)={vb}");
        println!("output molecule = 0x{}", hex::encode(output.as_slice()));
        assert!(vc || vb, "assembled tx signature does not verify against either message format");
    }
}

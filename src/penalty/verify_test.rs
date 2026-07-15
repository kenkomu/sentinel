//! Diagnostic: verify a real captured revocation signature against the message
//! the commitment-lock script actually computes, to validate our understanding
//! of the revocation-path signing before assembling the penalty transaction.
//!
//! Script message (fiber-scripts commitment-lock, revocation path):
//!   blake2b_256( output ‖ u32_le(len(output_data)) ‖ output_data
//!                ‖ cell_args[0..28] ‖ version_be(8) )
//! verified as Schnorr (x-only) against blake160 == cell_args[0..20].

#[cfg(test)]
mod tests {
    use crate::channel_id::{blake160, commitment_x_only_pubkey};
    use ckb_hash::blake2b_256;
    use secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};

    // Real devnet data (channel 0xb2fe56cd…, revocation for commitment 1).
    const SIG: &str = "b8ea014404ab35589ff0efb6069136bb077eabaf790209102110cb888c1503a48e37ef059ed4b82ac09a4f81dc230e00f57d58f5a2d6060fc4186865edc3c3be";
    const OUTPUT: &str = "61000000100000001800000061000000387551f20d000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000639b4a957ef467ddf92a2dcb53e94b3aa61b2382";
    const ODATA: &str = "00000000";
    // Commitment cell lock args from chain: pubkey_hash(20) ‖ delay(8) ‖ version(8) ‖ …
    const CELL_ARGS: &str = "7b022c90f11844a9ab305635895ffb4ebb6fb6ba01000000000100a00000000000000001db285e01dc8cc188c9f62a87ab1e7bdada24cd9900";
    const NODE3: &str = "0337c877adc2753a328728e570b5d47e71d263f65ad9c23b9cf4d80485a82605ea";
    const NODE1: &str = "03b5e19401890e2fb68331b2700f48f091842ea44b6d3680cf5f89f6c63482ddbf";
    const CNUM: u64 = 1;

    #[test]
    fn revocation_signature_verifies_against_script_message() {
        let output = hex::decode(OUTPUT).unwrap();
        let odata = hex::decode(ODATA).unwrap();
        let cell_args = hex::decode(CELL_ARGS).unwrap();

        // x-only aggregated pubkey (commitment order [local, remote] = [node3, node1]).
        let l = hex::decode(NODE3).unwrap();
        let r = hex::decode(NODE1).unwrap();
        let agg = commitment_x_only_pubkey(&l, &r).unwrap();
        // sanity: blake160(agg) must equal the cell's pubkey hash.
        assert_eq!(&blake160(&agg), &cell_args[0..20], "pubkey hash mismatch");

        let secp = Secp256k1::verification_only();
        let xonly = XOnlyPublicKey::from_slice(&agg).unwrap();
        let sig = Signature::from_slice(&hex::decode(SIG).unwrap()).unwrap();

        let verify = |buf: &[u8]| {
            let m = blake2b_256(buf);
            secp.verify_schnorr(&sig, &Message::from_digest(m), &xonly).is_ok()
        };

        // Candidate A — node format (channel.rs): output ‖ odata ‖ args[0..36]
        let mut a = Vec::new();
        a.extend_from_slice(&output);
        a.extend_from_slice(&odata);
        a.extend_from_slice(&cell_args[0..36]);

        // Candidate B — script format (fiber-scripts main): output ‖ u32le(len) ‖ odata ‖ args[0..28] ‖ version
        let mut b = Vec::new();
        b.extend_from_slice(&output);
        b.extend_from_slice(&(odata.len() as u32).to_le_bytes());
        b.extend_from_slice(&odata);
        b.extend_from_slice(&cell_args[0..28]);
        b.extend_from_slice(&CNUM.to_be_bytes());

        // Candidate C — node format without version in args (output ‖ odata ‖ args[0..28] ‖ version)
        let mut c = Vec::new();
        c.extend_from_slice(&output);
        c.extend_from_slice(&odata);
        c.extend_from_slice(&cell_args[0..28]);
        c.extend_from_slice(&CNUM.to_be_bytes());

        println!("A(node args36)={} B(script lenpfx)={} C(node args28+ver)={}", verify(&a), verify(&b), verify(&c));
        assert!(verify(&a) || verify(&b) || verify(&c), "no candidate message verified");

        // Does ckb-types re-serialize the penalty output identically? If not, the
        // executor's output[0].as_slice() differs from what was signed.
        use ckb_types::{packed::CellOutput, prelude::*};
        let co = CellOutput::from_slice(&output).unwrap();
        let reser = co.as_slice().to_vec();
        println!("output roundtrip identical = {}", reser == output);
        assert_eq!(reser, output, "CellOutput re-serialization differs from signed bytes");
    }
}

//! Regression test pinning the commitment-lock revocation message format.
//!
//! Uses Fiber's built-in watchtower's ACCEPTED penalty transaction (committed
//! on the devnet) as ground truth: its revocation signature must verify against
//!   blake2b(output ‖ u32le(len(output_data)) ‖ output_data ‖ args[0..28] ‖ version)
//! and NOT against the no-length-prefix variant. If Fiber changes this format,
//! this test fails loudly and the executor must be updated to match.

#[cfg(test)]
mod tests {
    use ckb_types::{packed::Transaction, prelude::*};

    const WORKING_TX: &str = "c30200000c000000e1010000d50100001c000000200000009300000097000000f3000000c10100000000000003000000cfcbbe3426fc724b308b2cdb1177c26dd242e6f871b099eec86478ef8825ebd80700000000cfcbbe3426fc724b308b2cdb1177c26dd242e6f871b099eec86478ef8825ebd80500000000a314e2bd08b067c07c9b98814c6362d7ee1f89d14ee3ebefd473a18724efbfc60000000001000000000200000000000000000000009219249ac532f02416f899861800db4b1b8fc1095978ca1a1b800a57d2035e1800000000000000000000000040ca76e8062e38eb0c711fe803e204254c10e661b83f119877809247b7919feb00000000ce0000000c0000006d00000061000000100000001800000061000000387551f20d000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000639b4a957ef467ddf92a2dcb53e94b3aa61b23826100000010000000180000006100000039fd895d78456301490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000639b4a957ef467ddf92a2dcb53e94b3aa61b2382140000000c000000100000000000000000000000e20000000c00000089000000790000001000000010000000100000001000000000000000000000000295c0d0223a6f1959e3162c603574b49f62830d529a31f088e6ac803db72db356580f6a3e1e229b4f8e950bc9af7f90034e6e7b6168e2fc3e943d5839c594de28c5764c282b63804bcf726e8b68c2341630b9864dccd7e46694d0da9b65cf8a645500000055000000100000005500000055000000410000000f61b694563c2b724385a85fa37902e826e46457c150d8bc64ff78f9f4af8f0c4ce76aa23971e9666898fe0dd10ded0b18935a83d8f49c861f5d75437d88a46500";

    #[test]
    fn commitment_lock_message_format_is_length_prefixed() {
        let bytes = hex::decode(WORKING_TX).unwrap();
        let tx = Transaction::from_slice(&bytes).unwrap();
        let raw = tx.raw();
        println!("--- cell_deps ---");
        for cd in raw.cell_deps().into_iter() {
            let op = cd.out_point();
            let dt: u8 = cd.dep_type().into();
            println!("  {}:{} dep_type={}", hex::encode(op.tx_hash().raw_data()), u32::from_le_bytes(op.index().raw_data()[..4].try_into().unwrap()), dt);
        }
        println!("--- inputs: {} ---", raw.inputs().len());
        for inp in raw.inputs().into_iter() {
            let op = inp.previous_output();
            println!("  {}:{}", hex::encode(op.tx_hash().raw_data()), u32::from_le_bytes(op.index().raw_data()[..4].try_into().unwrap()));
        }
        println!("--- outputs: {} ---", raw.outputs().len());
        for (i, o) in raw.outputs().into_iter().enumerate() {
            let cap: u64 = o.capacity().unpack();
            println!("  out[{i}] cap={cap} lock_code={}", hex::encode(&o.lock().code_hash().raw_data()[..6]));
        }
        println!("--- witnesses: {} ---", tx.witnesses().len());
        for (i, w) in tx.witnesses().into_iter().enumerate() {
            let wb = w.raw_data();
            println!("  wit[{i}] len={} {}", wb.len(), hex::encode(&wb));
        }

        // Verify the WORKING sig against message B (length prefix) vs C (none),
        // using output[0] from this tx and the real commitment cell args.
        use ckb_hash::blake2b_256;
        use secp256k1::{schnorr::Signature, Message, Secp256k1, XOnlyPublicKey};
        let out0 = raw.outputs().get(0).unwrap();
        let out0_bytes = out0.as_slice().to_vec();
        let odata0 = raw.outputs_data().get(0).unwrap().raw_data().to_vec();
        // commitment cell 9219 args (pubkey_hash20 ‖ delay8 ‖ version8 ‖ …)
        let cell_args = hex::decode("bb253dace71160563557bf9456d9936dc9da489101000000000100a00000000000000001119ff5672d2b6170ca620ef3af714bb2fdc3ad1b00").unwrap();
        let wit0 = tx.witnesses().get(0).unwrap().raw_data();
        let version = &wit0[17..25];
        let pubkey = &wit0[25..57];
        let sig = &wit0[57..121];

        let mut c = out0_bytes.clone();
        c.extend_from_slice(&odata0);
        c.extend_from_slice(&cell_args[0..28]);
        c.extend_from_slice(version);
        let mut b = out0_bytes.clone();
        b.extend_from_slice(&(odata0.len() as u32).to_le_bytes());
        b.extend_from_slice(&odata0);
        b.extend_from_slice(&cell_args[0..28]);
        b.extend_from_slice(version);

        let secp = Secp256k1::verification_only();
        let xo = XOnlyPublicKey::from_slice(pubkey).unwrap();
        let s = Signature::from_slice(sig).unwrap();
        let vc = secp.verify_schnorr(&s, &Message::from_digest(blake2b_256(&c)), &xo).is_ok();
        let vb = secp.verify_schnorr(&s, &Message::from_digest(blake2b_256(&b)), &xo).is_ok();
        assert!(vb, "built-in penalty sig must verify against the length-prefixed message (format B)");
        assert!(!vc, "no-length-prefix variant must NOT verify (guards against format drift)");
    }
}

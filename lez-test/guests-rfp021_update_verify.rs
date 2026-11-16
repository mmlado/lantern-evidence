/// RFP-021 spike: one sync-committee finality update. The plan verifies the aggregate signature
/// against a witnessed committee aggregate minus the absent members and records the finalised
/// header in `accounts = [instance]`; the apply would check the witnessed keys against the stored
/// committee, which this spike leaves out.
pub fn rfp021_update_verify() {
    use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
    use bls12_381::{G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt, multi_miller_loop};
    const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    type Instruction = (Vec<u8>, Vec<Vec<u8>>, Vec<u8>, [u8; 32], [u8; 32], u64);
    match read_program_call::<Instruction>() {
        ProgramCall::Plan(input, (aggregate, absent, signature, signing_root, header_root, slot)) => {
            let [instance] = input.accounts.as_slice() else {
                panic!("rfp021_update_verify requires [instance]");
            };
            let instance = instance.clone();
            let witnessed = |bytes: &[u8]| -> G1Affine {
                let raw: [u8; 96] = bytes.try_into().expect("96 bytes");
                let point = G1Affine::from_uncompressed_unchecked(&raw).expect("a point");
                assert!(bool::from(point.is_on_curve()), "key off the curve");
                point
            };
            let mut acc = G1Projective::from(witnessed(&aggregate));
            for key in &absent {
                acc -= G1Projective::from(witnessed(key));
            }
            let public_key = G1Affine::from(acc);
            let raw: [u8; 96] = signature.as_slice().try_into().expect("96 bytes");
            let signature = G2Affine::from_compressed(&raw).expect("a signature");
            let message: G2Affine =
                <G2Projective as HashToCurve<ExpandMsgXmd<sha2_09::Sha256>>>::hash_to_curve(&signing_root, DST).into();
            let paired = multi_miller_loop(&[
                (&public_key, &G2Prepared::from(message)),
                (&-G1Affine::generator(), &G2Prepared::from(signature)),
            ])
            .final_exponentiation();
            assert!(paired == Gt::identity(), "sync committee signature verifies");
            let mut plan = Plan::new(&input);
            plan.effect(&instance, &(slot, header_root));
            plan.write();
        }
        ProgramCall::Apply(input) => {
            let (slot, header_root): (u64, [u8; 32]) =
                borsh::from_slice(&input.effect_data).expect("own effect");
            let mut data = slot.to_le_bytes().to_vec();
            data.extend_from_slice(&header_root);
            apply_write(input, data.try_into().expect("fits the data limit"));
        }
    }
}

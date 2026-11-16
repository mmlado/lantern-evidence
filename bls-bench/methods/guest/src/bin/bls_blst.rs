#![no_main]
risc0_zkvm::guest::entry!(main);

use blst::{
    blst_core_verify_pk_in_g1, blst_final_exp, blst_fp12, blst_fp12_is_one, blst_fp12_mul, blst_hash_to_g2, blst_miller_loop, blst_miller_loop_n, blst_p1_affine_generator, blst_p2, blst_p2_to_affine, blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_affine_compress,
    blst_p1_affine_on_curve, blst_p1_cneg, blst_p1_deserialize, blst_p1_from_affine, blst_p1_to_affine,
    blst_p1_uncompress, blst_p2_affine, blst_p2_affine_in_g2, blst_p2_uncompress, BLST_ERROR,
};
use risc0_zkvm::guest::env;

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(serde::Deserialize)]
struct Input {
    op: u8,
    n: u32,
    pubkeys: Vec<Vec<u8>>,
    bits: Vec<u8>,
    signature: Vec<u8>,
    signing_root: Vec<u8>,
    agg_all: Vec<u8>,
    absent: Vec<Vec<u8>>,
    pubkeys_uncompressed: Vec<Vec<u8>>,
    signature_uncompressed: Vec<u8>,
    agg_all_uncompressed: Vec<u8>,
    absent_uncompressed: Vec<Vec<u8>>,
}

fn uncompress(compressed: &[u8]) -> blst_p1_affine {
    let mut aff = blst_p1_affine::default();
    unsafe { assert!(blst_p1_uncompress(&mut aff, compressed.as_ptr()) == BLST_ERROR::BLST_SUCCESS) };
    aff
}

// Uncompressed point checked against its compressed encoding; no square root involved.
fn witnessed(uncompressed: &[u8], compressed: &[u8]) -> blst_p1_affine {
    let mut aff = blst_p1_affine::default();
    unsafe {
        assert!(blst_p1_deserialize(&mut aff, uncompressed.as_ptr()) == BLST_ERROR::BLST_SUCCESS);
        assert!(blst_p1_affine_on_curve(&aff));
        let mut out = [0u8; 48];
        blst_p1_affine_compress(out.as_mut_ptr(), &aff);
        assert!(out.as_slice() == compressed);
    }
    aff
}

fn projective(aff: &blst_p1_affine) -> blst_p1 {
    let mut p = blst_p1::default();
    unsafe { blst_p1_from_affine(&mut p, aff) };
    p
}

fn subtract(acc: &mut blst_p1, aff: &blst_p1_affine) {
    let mut q = projective(aff);
    unsafe {
        blst_p1_cneg(&mut q, true);
        blst_p1_add_or_double(acc, acc, &q);
    }
}

fn add(acc: &mut blst_p1, aff: &blst_p1_affine) {
    let q = projective(aff);
    unsafe { blst_p1_add_or_double(acc, acc, &q) };
}

fn affine(p: &blst_p1) -> blst_p1_affine {
    let mut aff = blst_p1_affine::default();
    unsafe { blst_p1_to_affine(&mut aff, p) };
    aff
}

// Signature decode with its subgroup check, hash to G2 and the pairing check.
fn verify(pk: &blst_p1_affine, sig: &[u8], msg: &[u8]) -> bool {
    let mut sig_aff = blst_p2_affine::default();
    unsafe {
        if blst_p2_uncompress(&mut sig_aff, sig.as_ptr()) != BLST_ERROR::BLST_SUCCESS || !blst_p2_affine_in_g2(&sig_aff) {
            return false;
        }
        blst_core_verify_pk_in_g1(pk, &sig_aff, true, msg.as_ptr(), msg.len(), DST.as_ptr(), DST.len(), core::ptr::null(), 0)
            == BLST_ERROR::BLST_SUCCESS
    }
}

fn main() {
    let inp: Input = env::read();
    let out: u32 = match inp.op {
        20 => {
            let mut acc = projective(&uncompress(&inp.agg_all));
            for k in &inp.absent {
                subtract(&mut acc, &uncompress(k));
            }
            verify(&affine(&acc), &inp.signature, &inp.signing_root) as u32
        }
        21 => {
            let mut acc = projective(&witnessed(&inp.agg_all_uncompressed, &inp.agg_all));
            for (u, c) in inp.absent_uncompressed.iter().zip(inp.absent.iter()) {
                subtract(&mut acc, &witnessed(u, c));
            }
            verify(&affine(&acc), &inp.signature, &inp.signing_root) as u32
        }
        22 => verify(&uncompress(&inp.agg_all), &inp.signature, &inp.signing_root) as u32,
        23 => {
            let mut acc: Option<blst_p1> = None;
            let mut count = 0u32;
            for (i, (u, c)) in inp.pubkeys_uncompressed.iter().zip(inp.pubkeys.iter()).enumerate() {
                let aff = witnessed(u, c);
                if (inp.bits[i / 8] >> (i % 8)) & 1 == 1 {
                    match acc.as_mut() {
                        None => acc = Some(projective(&aff)),
                        Some(a) => add(a, &aff),
                    }
                    count += 1;
                }
            }
            let _ = acc.map(|p| affine(&p));
            count
        }
        24 => {
            let mut c = 0u32;
            for k in inp.pubkeys.iter().take(inp.n as usize) {
                let _ = uncompress(k);
                c += 1;
            }
            c
        }
        25 => {
            let aff = uncompress(&inp.agg_all);
            unsafe { blst_p1_affine_on_curve(&aff) as u32 }
        }
        26 => {
            let mut sig_aff = blst_p2_affine::default();
            unsafe {
                assert!(blst_p2_uncompress(&mut sig_aff, inp.signature.as_ptr()) == BLST_ERROR::BLST_SUCCESS);
                blst_p2_affine_in_g2(&sig_aff) as u32
            }
        }
        27 => {
            let mut p = blst_p2::default();
            unsafe { blst_hash_to_g2(&mut p, inp.signing_root.as_ptr(), inp.signing_root.len(), DST.as_ptr(), DST.len(), core::ptr::null(), 0) };
            core::hint::black_box(p);
            1
        }
        // Steps 2 and 3 of a split check: two Miller loops and their product, then the final exponentiation.
        28 | 29 => {
            let pk = uncompress(&inp.agg_all);
            let mut sig_aff = blst_p2_affine::default();
            let mut msg = blst_p2::default();
            let mut msg_aff = blst_p2_affine::default();
            let mut ml1 = blst_fp12::default();
            let mut ml2 = blst_fp12::default();
            let mut prod = blst_fp12::default();
            unsafe {
                assert!(blst_p2_uncompress(&mut sig_aff, inp.signature.as_ptr()) == BLST_ERROR::BLST_SUCCESS);
                blst_hash_to_g2(&mut msg, inp.signing_root.as_ptr(), inp.signing_root.len(), DST.as_ptr(), DST.len(), core::ptr::null(), 0);
                blst_p2_to_affine(&mut msg_aff, &msg);
                let mut neg_g1 = projective(&*blst_p1_affine_generator());
                blst_p1_cneg(&mut neg_g1, true);
                let neg_g1_aff = affine(&neg_g1);
                blst_miller_loop(&mut ml1, &msg_aff, &pk);
                blst_miller_loop(&mut ml2, &sig_aff, &neg_g1_aff);
                blst_fp12_mul(&mut prod, &ml1, &ml2);
                if inp.op == 28 {
                    core::hint::black_box(prod);
                    1
                } else {
                    let mut gt = blst_fp12::default();
                    blst_final_exp(&mut gt, &prod);
                    blst_fp12_is_one(&gt) as u32
                }
            }
        }
        // Op 30 is op 28's baseline, so op 28 minus op 30 isolates the Miller loops.
        30 | 32 => {
            let pk = uncompress(&inp.agg_all);
            let mut sig_aff = blst_p2_affine::default();
            let mut msg = blst_p2::default();
            let mut msg_aff = blst_p2_affine::default();
            unsafe {
                assert!(blst_p2_uncompress(&mut sig_aff, inp.signature.as_ptr()) == BLST_ERROR::BLST_SUCCESS);
                blst_hash_to_g2(&mut msg, inp.signing_root.as_ptr(), inp.signing_root.len(), DST.as_ptr(), DST.len(), core::ptr::null(), 0);
                blst_p2_to_affine(&mut msg_aff, &msg);
                let mut neg_g1 = projective(&*blst_p1_affine_generator());
                blst_p1_cneg(&mut neg_g1, true);
                let neg_g1_aff = affine(&neg_g1);
                if inp.op == 32 {
                    let mut prod = blst_fp12::default();
                    let qs: [*const blst_p2_affine; 2] = [&msg_aff, &sig_aff];
                    let ps: [*const blst_p1_affine; 2] = [&pk, &neg_g1_aff];
                    blst_miller_loop_n(&mut prod, qs.as_ptr(), ps.as_ptr(), 2);
                    core::hint::black_box(prod);
                } else {
                    core::hint::black_box((pk, sig_aff, msg_aff, neg_g1_aff));
                }
            }
            1
        }
        31 => {
            let mut sig_aff = blst_p2_affine::default();
            unsafe {
                assert!(blst_p2_uncompress(&mut sig_aff, inp.signature.as_ptr()) == BLST_ERROR::BLST_SUCCESS);
            }
            core::hint::black_box(sig_aff);
            1
        }
        // The whole check as the program runs it, with the combined Miller loop.
        33 => {
            let mut acc = projective(&uncompress(&inp.agg_all));
            for k in &inp.absent {
                subtract(&mut acc, &uncompress(k));
            }
            let pk = affine(&acc);
            let mut sig_aff = blst_p2_affine::default();
            let mut msg = blst_p2::default();
            let mut msg_aff = blst_p2_affine::default();
            let mut prod = blst_fp12::default();
            let mut gt = blst_fp12::default();
            unsafe {
                if blst_p2_uncompress(&mut sig_aff, inp.signature.as_ptr()) != BLST_ERROR::BLST_SUCCESS || !blst_p2_affine_in_g2(&sig_aff) {
                    0
                } else {
                    blst_hash_to_g2(&mut msg, inp.signing_root.as_ptr(), inp.signing_root.len(), DST.as_ptr(), DST.len(), core::ptr::null(), 0);
                    blst_p2_to_affine(&mut msg_aff, &msg);
                    let mut neg_g1 = projective(&*blst_p1_affine_generator());
                    blst_p1_cneg(&mut neg_g1, true);
                    let neg_g1_aff = affine(&neg_g1);
                    let qs: [*const blst_p2_affine; 2] = [&msg_aff, &sig_aff];
                    let ps: [*const blst_p1_affine; 2] = [&pk, &neg_g1_aff];
                    blst_miller_loop_n(&mut prod, qs.as_ptr(), ps.as_ptr(), 2);
                    blst_final_exp(&mut gt, &prod);
                    blst_fp12_is_one(&gt) as u32
                }
            }
        }
        _ => 99,
    };
    env::commit(&out);
}

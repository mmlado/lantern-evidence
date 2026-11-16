#![no_main]
risc0_zkvm::guest::entry!(main);

use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt};
use group::Group;
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

fn g1(b: &[u8]) -> G1Affine {
    let a: [u8; 48] = b.try_into().unwrap();
    G1Affine::from_compressed(&a).unwrap()
}

fn g2(b: &[u8]) -> G2Affine {
    let a: [u8; 96] = b.try_into().unwrap();
    G2Affine::from_compressed(&a).unwrap()
}

fn hash_to_g2(msg: &[u8]) -> G2Affine {
    <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(msg, DST).into()
}

fn g1_witnessed(uncompressed: &[u8], compressed: &[u8]) -> G1Affine {
    let a: [u8; 96] = uncompressed.try_into().unwrap();
    let p = G1Affine::from_uncompressed_unchecked(&a).unwrap();
    assert!(bool::from(p.is_on_curve()));
    assert!(p.to_compressed().as_slice() == compressed);
    p
}

fn g2_witnessed(uncompressed: &[u8], compressed: &[u8]) -> G2Affine {
    let a: [u8; 192] = uncompressed.try_into().unwrap();
    let p = G2Affine::from_uncompressed_unchecked(&a).unwrap();
    assert!(bool::from(p.is_on_curve()));
    assert!(p.to_compressed().as_slice() == compressed);
    p
}

fn sha256(a: &[u8], b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

// hash_tree_root of SyncCommittee { pubkeys: Vector[BLSPubkey, 512], aggregate_pubkey }.
fn committee_root(keys: &[Vec<u8>], aggregate: &[u8]) -> [u8; 32] {
    fn key_root(k: &[u8]) -> [u8; 32] {
        let mut padded = [0u8; 64];
        padded[..48].copy_from_slice(k);
        sha256(&padded[..32], &padded[32..])
    }
    let mut layer: Vec<[u8; 32]> = keys.iter().map(|k| key_root(k)).collect();
    while layer.len() > 1 {
        layer = layer.chunks(2).map(|c| sha256(&c[0], &c[1])).collect();
    }
    sha256(&layer[0], &key_root(aggregate))
}

fn participating(bits: &[u8], i: usize) -> bool {
    (bits[i / 8] >> (i % 8)) & 1 == 1
}

fn aggregate(keys: &[Vec<u8>], bits: &[u8]) -> (G1Affine, u32) {
    let mut acc = G1Projective::identity();
    let mut count = 0;
    for (i, k) in keys.iter().enumerate() {
        if participating(bits, i) {
            acc += G1Projective::from(g1(k));
            count += 1;
        }
    }
    (acc.into(), count)
}

fn verify(pk: &G1Affine, sig: &G2Affine, msg: &G2Affine) -> bool {
    let neg_g1 = -G1Affine::generator();
    let res = multi_miller_loop(&[(pk, &G2Prepared::from(*msg)), (&neg_g1, &G2Prepared::from(*sig))])
        .final_exponentiation();
    res == Gt::identity()
}

fn main() {
    let inp: Input = env::read();
    let out: u32 = match inp.op {
        0 => {
            let r = bls12_381::pairing(&G1Affine::generator(), &G2Affine::generator());
            (r != Gt::identity()) as u32
        }
        1 => {
            let mut c = 0u32;
            for k in inp.pubkeys.iter().take(inp.n as usize) {
                if !bool::from(g1(k).is_identity()) {
                    c += 1;
                }
            }
            c
        }
        2 => {
            let (agg, c) = aggregate(&inp.pubkeys, &inp.bits);
            if bool::from(agg.is_identity()) { 0 } else { c }
        }
        3 => (!bool::from(hash_to_g2(&inp.signing_root).is_identity())) as u32,
        4 => {
            let (agg, _) = aggregate(&inp.pubkeys, &inp.bits);
            let sig = g2(&inp.signature);
            let msg = hash_to_g2(&inp.signing_root);
            verify(&agg, &sig, &msg) as u32
        }
        5 => {
            let mut acc = G1Projective::from(g1(&inp.agg_all));
            for k in &inp.absent {
                acc -= G1Projective::from(g1(k));
            }
            let agg: G1Affine = acc.into();
            let sig = g2(&inp.signature);
            let msg = hash_to_g2(&inp.signing_root);
            verify(&agg, &sig, &msg) as u32
        }
        6 => (!bool::from(g2(&inp.signature).is_identity())) as u32,
        7 => {
            let pk = g1(&inp.agg_all);
            let sig = g2(&inp.signature);
            let msg = hash_to_g2(&inp.signing_root);
            let neg_g1 = -G1Affine::generator();
            let r = multi_miller_loop(&[(&pk, &G2Prepared::from(msg)), (&neg_g1, &G2Prepared::from(sig))]);
            (r.final_exponentiation() == Gt::identity()) as u32
        }
        8 => {
            let pk = g1(&inp.agg_all);
            let sig = g2(&inp.signature);
            let msg = hash_to_g2(&inp.signing_root);
            let neg_g1 = -G1Affine::generator();
            let r = multi_miller_loop(&[(&pk, &G2Prepared::from(msg)), (&neg_g1, &G2Prepared::from(sig))]);
            core::hint::black_box(r);
            1
        }
        10 => {
            let mut acc = G1Projective::identity();
            let mut count = 0u32;
            for (i, (u, c)) in inp.pubkeys_uncompressed.iter().zip(inp.pubkeys.iter()).enumerate() {
                let p = g1_witnessed(u, c);
                if participating(&inp.bits, i) {
                    acc += G1Projective::from(p);
                    count += 1;
                }
            }
            if bool::from(acc.is_identity()) { 0 } else { count }
        }
        11 => {
            let r = committee_root(&inp.pubkeys, &inp.agg_all);
            u32::from_le_bytes([r[0], r[1], r[2], r[3]])
        }
        12 => (!bool::from(g2_witnessed(&inp.signature_uncompressed, &inp.signature).is_identity())) as u32,
        13 => {
            let mut acc = G1Projective::from(g1_witnessed(&inp.agg_all_uncompressed, &inp.agg_all));
            for (u, c) in inp.absent_uncompressed.iter().zip(inp.absent.iter()) {
                acc -= G1Projective::from(g1_witnessed(u, c));
            }
            let agg = G1Affine::from(acc);
            let sig = g2(&inp.signature);
            let msg = hash_to_g2(&inp.signing_root);
            let neg_g1 = -G1Affine::generator();
            let r = multi_miller_loop(&[(&agg, &G2Prepared::from(msg)), (&neg_g1, &G2Prepared::from(sig))]).final_exponentiation();
            (r == Gt::identity()) as u32
        }
        9 => inp.pubkeys.len() as u32 + inp.pubkeys_uncompressed.len() as u32,
        _ => 99,
    };
    env::commit(&out);
}

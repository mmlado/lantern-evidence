use anyhow::{bail, Result};
use bls12_381::hash_to_curve::{ExpandMsgXmd, HashToCurve};
use bls12_381::{multi_miller_loop, G1Affine, G1Projective, G2Affine, G2Prepared, G2Projective, Gt};
use group::Group;
use bls_bench_methods::{BLS_BLST_ELF, BLS_COMPONENTS_ELF, MPT_INCLUSION_ELF};
use clap::{Parser, Subcommand};
use risc0_zkvm::{default_executor, ExecutorEnv};
use std::time::Instant;

const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Parser)]
struct Args {
    /// Session limit on the executor, like LEZ's gas_limit.
    #[arg(long)]
    budget: Option<u64>,
    #[arg(long)]
    out: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Sync-committee signature check by component, on a real update.
    Bls {
        #[arg(long)]
        data: String,
        #[arg(long, default_value = "0,1,2,3,4,5,6,7")]
        ops: String,
        /// Keys to decompress in op 1.
        #[arg(long, default_value_t = 512)]
        n: u32,
    },
    /// Write the borsh instruction for the LEZ guest: (aggregate uncompressed, absent uncompressed, signature compressed, signing root, header root, slot).
    Dump {
        #[arg(long)]
        data: String,
        #[arg(long)]
        file: String,
    },
    /// Account and storage inclusion proofs from eth_getProof.
    Mpt {
        #[arg(long)]
        proof: String,
        #[arg(long)]
        block: String,
    },
}

#[derive(serde::Serialize, Clone)]
struct BlsInput {
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

#[derive(serde::Serialize)]
struct MptInput {
    root: Vec<u8>,
    key: Vec<u8>,
    expected: Vec<u8>,
    proof: Vec<Vec<u8>>,
}

#[derive(serde::Serialize)]
struct Row {
    label: String,
    user_cycles: u64,
    segments: usize,
    exec_ms: f64,
    result: u32,
}

fn run<T: serde::Serialize>(label: &str, elf: &[u8], input: &T, budget: Option<u64>) -> Result<Row> {
    let mut b = ExecutorEnv::builder();
    if let Some(l) = budget {
        b.session_limit(Some(l));
    }
    b.write(input)?;
    let env = b.build()?;
    let started = Instant::now();
    let info = default_executor().execute(env, elf)?;
    let exec_ms = started.elapsed().as_secs_f64() * 1000.0;
    let result: u32 = info.journal.decode()?;
    let row = Row { label: label.to_string(), user_cycles: info.cycles(), segments: info.segments.len(), exec_ms, result };
    eprintln!(
        "{:<40} user_cycles={:>12} ({:5.1}% of 10M) segments={:>3} exec={:.0}ms result={}",
        row.label, row.user_cycles, row.user_cycles as f64 / 1e7 * 100.0, row.segments, row.exec_ms, row.result
    );
    Ok(row)
}

fn g1(b: &[u8]) -> G1Affine {
    let a: [u8; 48] = b.try_into().unwrap();
    G1Affine::from_compressed(&a).unwrap()
}

fn bls(data: &str, ops: &str, n: u32, budget: Option<u64>) -> Result<Vec<Row>> {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(data)?)?;
    let pubkeys: Vec<Vec<u8>> = v["pubkeys"].as_array().unwrap().iter().map(|k| hex::decode(k.as_str().unwrap()).unwrap()).collect();
    let bits = hex::decode(v["bits"].as_str().unwrap())?;
    let signature = hex::decode(v["signature"].as_str().unwrap())?;
    let signing_root = hex::decode(v["signing_root"].as_str().unwrap())?;
    let absent_idx: Vec<usize> = v["absent"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as usize).collect();

    // Native check first, so a wrong signing root is caught before any guest runs.
    let mut acc = G1Projective::identity();
    let mut all = G1Projective::identity();
    let mut count = 0;
    for (i, k) in pubkeys.iter().enumerate() {
        let p = G1Projective::from(g1(k));
        all += p;
        if (bits[i / 8] >> (i % 8)) & 1 == 1 {
            acc += p;
            count += 1;
        }
    }
    let agg: G1Affine = acc.into();
    let sig = {
        let a: [u8; 96] = signature.as_slice().try_into().unwrap();
        G2Affine::from_compressed(&a).unwrap()
    };
    let msg: G2Affine = <G2Projective as HashToCurve<ExpandMsgXmd<sha2::Sha256>>>::hash_to_curve(&signing_root, DST).into();
    let ok = multi_miller_loop(&[(&agg, &G2Prepared::from(msg)), (&-G1Affine::generator(), &G2Prepared::from(sig))]).final_exponentiation() == Gt::identity();
    eprintln!("native verify over {count} participants: {ok}");
    if !ok {
        bail!("native verification failed, inputs are wrong");
    }
    let agg_all = G1Affine::from(all).to_compressed().to_vec();
    let absent: Vec<Vec<u8>> = absent_idx.iter().map(|&i| pubkeys[i].clone()).collect();
    let pubkeys_uncompressed: Vec<Vec<u8>> = pubkeys.iter().map(|k| g1(k).to_uncompressed().to_vec()).collect();
    let signature_uncompressed = sig.to_uncompressed().to_vec();
    let agg_all_uncompressed = G1Affine::from(all).to_uncompressed().to_vec();
    let absent_uncompressed: Vec<Vec<u8>> = absent_idx.iter().map(|&i| pubkeys_uncompressed[i].clone()).collect();

    let base = BlsInput { op: 0, n, pubkeys, bits, signature, signing_root, agg_all, absent, pubkeys_uncompressed, signature_uncompressed, agg_all_uncompressed, absent_uncompressed };
    let labels = [
        "0 one pairing, generators",
        "1 decompress n G1 keys",
        "2 decompress + aggregate participants",
        "3 hash to G2",
        "4 full verify, compressed keys",
        "5 full verify, pre-aggregated, minus absent",
        "6 decompress G2 signature",
        "7 pairing check only, 1 G1 decompress",
        "8 as 7 without final exponentiation",
        "9 input decode only",
        "10 witnessed 512 keys: on-curve, encoding, aggregate",
        "11 SSZ committee root, 513 keys, sha256",
        "12 witnessed G2 signature: on-curve, encoding",
        "13 full verify, witnessed G1 aggregate, compressed G2",
        "14 unused", "15 unused", "16 unused", "17 unused", "18 unused", "19 unused",
        "20 blst: full verify, pre-aggregated, compressed aggregate and absent",
        "21 blst: full verify, witnessed aggregate and absent",
        "22 blst: signature check only, full-committee aggregate (expect 0)",
        "23 blst: witnessed 512 keys, on-curve, encoding, aggregate",
        "24 blst: decompress n keys",
        "25 blst: uncompress one G1 key",
        "26 blst: signature uncompress and subgroup check",
        "27 blst: hash to G2",
        "28 blst: decode, hash, two Miller loops and product, no final exponentiation",
        "29 blst: op 28 plus the final exponentiation (expect 0, full-committee aggregate)",
        "30 blst: op 28 without the Miller loops",
        "31 blst: signature uncompress, no subgroup check",
        "32 blst: op 30 plus one combined Miller loop over both pairs",
        "33 blst: full verify, pre-aggregated minus absent, combined Miller loop",
    ];
    let mut rows = Vec::new();
    for op in ops.split(',') {
        let op: u8 = op.trim().parse()?;
        let mut inp = base.clone();
        inp.op = op;
        if op == 1 {
            inp.pubkeys.truncate(n as usize);
        }
        if op == 9 && n == 0 {
            inp.pubkeys.clear();
        }
        // An op that never reads the committee keys must not pay to decode them.
        if (op >= 20 && op != 23 && op != 24) || matches!(op, 0 | 3 | 5 | 6 | 7 | 8) {
            inp.pubkeys.clear();
        }
        if op != 10 && op != 12 && op != 13 && op != 21 && op != 23 && !(op == 9 && n == 512) {
            inp.pubkeys_uncompressed.clear();
            inp.signature_uncompressed.clear();
        }
        let label = if op == 1 { format!("1 decompress {n} G1 keys") } else { labels[op as usize].to_string() };
        let elf = if op >= 20 { BLS_BLST_ELF } else { BLS_COMPONENTS_ELF };
        rows.push(run(&label, elf, &inp, budget)?);
    }
    Ok(rows)
}

#[derive(alloy_rlp::RlpEncodable)]
struct Account {
    nonce: u64,
    balance: alloy_primitives::U256,
    storage_root: alloy_primitives::B256,
    code_hash: alloy_primitives::B256,
}

fn mpt(proof: &str, block: &str, budget: Option<u64>) -> Result<Vec<Row>> {
    use alloy_primitives::{keccak256, Address, B256, U256};
    let p: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(proof)?)?;
    let b: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(block)?)?;
    let p = &p["result"];
    let b = &b["result"];
    let hx = |v: &serde_json::Value| hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap();
    let state_root = hx(&b["stateRoot"]);
    let address: Address = p["address"].as_str().unwrap().parse()?;
    let account = Account {
        nonce: u64::from_str_radix(p["nonce"].as_str().unwrap().trim_start_matches("0x"), 16)?,
        balance: U256::from_str_radix(p["balance"].as_str().unwrap().trim_start_matches("0x"), 16)?,
        storage_root: B256::from_slice(&hx(&p["storageHash"])),
        code_hash: B256::from_slice(&hx(&p["codeHash"])),
    };
    let account_rlp = alloy_rlp::encode(&account);
    let account_proof: Vec<Vec<u8>> = p["accountProof"].as_array().unwrap().iter().map(hx).collect();
    let sp = &p["storageProof"][0];
    let slot = U256::from_str_radix(sp["key"].as_str().unwrap().trim_start_matches("0x"), 16)?;
    let value = U256::from_str_radix(sp["value"].as_str().unwrap().trim_start_matches("0x"), 16)?;
    let storage_proof: Vec<Vec<u8>> = sp["proof"].as_array().unwrap().iter().map(hx).collect();

    let acct = MptInput { root: state_root.clone(), key: keccak256(address).to_vec(), expected: account_rlp.clone(), proof: account_proof.clone() };
    let stor = MptInput { root: account.storage_root.to_vec(), key: keccak256(B256::from(slot)).to_vec(), expected: alloy_rlp::encode(value), proof: storage_proof.clone() };

    // Native check first.
    for (name, i) in [("account", &acct), ("storage", &stor)] {
        let nodes: Vec<alloy_primitives::Bytes> = i.proof.iter().cloned().map(Into::into).collect();
        let r = alloy_trie::proof::verify_proof(B256::from_slice(&i.root), alloy_trie::Nibbles::unpack(&i.key), Some(i.expected.clone()), nodes.iter());
        eprintln!("native {name} proof, {} nodes, {} bytes: {:?}", i.proof.len(), i.proof.iter().map(|n| n.len()).sum::<usize>(), r.as_ref().map(|_| "ok"));
        if r.is_err() {
            bail!("native {name} proof failed");
        }
    }
    let mut rows = Vec::new();
    rows.push(run(&format!("account proof, {} nodes", acct.proof.len()), MPT_INCLUSION_ELF, &acct, budget)?);
    rows.push(run(&format!("storage proof, {} nodes", stor.proof.len()), MPT_INCLUSION_ELF, &stor, budget)?);
    Ok(rows)
}

fn dump(data: &str, file: &str) -> Result<()> {
    let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(data)?)?;
    let pubkeys: Vec<Vec<u8>> = v["pubkeys"].as_array().unwrap().iter().map(|k| hex::decode(k.as_str().unwrap()).unwrap()).collect();
    let absent_idx: Vec<usize> = v["absent"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as usize).collect();
    let mut all = G1Projective::identity();
    for k in &pubkeys {
        all += G1Projective::from(g1(k));
    }
    let aggregate = G1Affine::from(all).to_uncompressed().to_vec();
    let absent: Vec<Vec<u8>> = absent_idx.iter().map(|&i| g1(&pubkeys[i]).to_uncompressed().to_vec()).collect();
    let signature = hex::decode(v["signature"].as_str().unwrap())?;
    let signing_root: [u8; 32] = hex::decode(v["signing_root"].as_str().unwrap())?.try_into().unwrap();
    let header_root: [u8; 32] = hex::decode(v["header_root"].as_str().unwrap())?.try_into().unwrap();
    let slot = v["attested_slot"].as_u64().unwrap();
    let instruction = (aggregate, absent, signature, signing_root, header_root, slot);
    let bytes = borsh::to_vec(&instruction)?;
    std::fs::write(file, &bytes)?;
    eprintln!("wrote {file}, {} bytes, absent {}", bytes.len(), absent_idx.len());
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    if let Cmd::Dump { data, file } = &args.cmd {
        return dump(data, file);
    }
    let rows = match &args.cmd {
        Cmd::Bls { data, ops, n } => bls(data, ops, *n, args.budget)?,
        Cmd::Mpt { proof, block } => mpt(proof, block, args.budget)?,
        Cmd::Dump { .. } => unreachable!(),
    };
    if let Some(out) = args.out {
        std::fs::write(&out, serde_json::to_string_pretty(&rows)?)?;
        eprintln!("wrote {out}");
    }
    Ok(())
}

#![no_main]
risc0_zkvm::guest::entry!(main);

use alloy_primitives::{Bytes, B256};
use alloy_trie::{proof::verify_proof, Nibbles};
use risc0_zkvm::guest::env;

#[derive(serde::Deserialize)]
struct Input {
    root: Vec<u8>,
    key: Vec<u8>,
    expected: Vec<u8>,
    proof: Vec<Vec<u8>>,
}

fn main() {
    let inp: Input = env::read();
    let root = B256::from_slice(&inp.root);
    let nodes: Vec<Bytes> = inp.proof.into_iter().map(Bytes::from).collect();
    let ok = verify_proof(root, Nibbles::unpack(&inp.key), Some(inp.expected), nodes.iter()).is_ok();
    env::commit(&(ok as u32));
}

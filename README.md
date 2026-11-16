# RFP-021 spikes

Measurements for the Ethereum state attestation bid. Started 2026-10-16.

Data in `data/`, fetched 2026-10-16 from https://lodestar-mainnet.chainsafe.io (beacon) and https://ethereum-rpc.publicnode.com (execution):

- `updates_p1884_p1885.json`: light-client updates for sync-committee periods 1884 and 1885 (Fulu).
- `update_p1885_inputs.json`: built by `prep_update.py`. The period-1885 update's attested header signed by period 1884's next committee, 511 of 512 participants, signing root computed from the spec constants in `spec.json` and `genesis.json`.
- `proof_weth_latest.json`, `block_latest.json`: `eth_getProof` for WETH (0xC02a...) storage slot 0 at block 26203210, with the block header.

Data for the LEZ 0.4 runs:

- `bootstrap_p1885.json`, `bootstrap_root.txt`: the period-1885 light-client bootstrap and its block root, the checkpoint the runs start from.
- `updates_p1886.json`: the period-1886 update, fetched 2026-11-11, signed by the period-1886 committee and carrying the period-1887 committee.
- `fresh-2026-11-11/`: a recent bootstrap, the latest finality update and an `eth_getProof` for WETH slot 0 at its finalized block 26,389,914, fetched at 06:51 UTC by `lez04/fetch-fresh.sh`, with the local chain's account ids from the last setup.
- `cross-2026-11-11/`: period 1907's light-client update as the beacon API serves it, finalized at the period's first slot and carrying the 1908 committee, and the latest finality update, signed by the 1908 committee, fetched at 15:46 UTC by `lez04/fetch-cross.sh`.

`lez04/`: the program on LEZ v0.4.0-rc3, its runner and the private consumption scripts, measured as real transactions on a standalone sequencer. `lez04/README.md` gives the steps.

`bls-bench/`: RISC Zero 3.0.5 host and guests. `bls_components` measures the sync-committee signature check by component on real data. `mpt_inclusion` measures account and storage proof verification with alloy-trie and the accelerated keccak.

## Reproducing

```
cd bls-bench && cargo build --release
./target/release/bls-bench --out ../results/bls-p1885-zkcrypto.json bls --data ../data/update_p1885_inputs.json --ops 0,1,2,3,4,5,6,7,8,10,11,12,13
./target/release/bls-bench --out ../results/bls-p1885-blst.json bls --data ../data/update_p1885_inputs.json --ops 20,21,22,23,24,25,26,27,28,29,30,31,32,33
for n in 0 511 512; do ./target/release/bls-bench --out ../results/bls-p1885-decode-n$n.json bls --data ../data/update_p1885_inputs.json --ops 9 --n $n; done
./target/release/bls-bench --out ../results/mpt-weth.json mpt --proof ../data/proof_weth_latest.json --block ../data/block_latest.json
```

`lez-test/README.md` gives the steps for the private-transaction run. Findings and every figure are in `FINDINGS.md`.


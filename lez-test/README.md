# The update verified inside a LEZ private transaction

Five manual steps on top of the RFP-005 evidence checkout (`gemot-evidence/work/accel`: LEZ v0.3.0 with patches 01 to 04 applied, RISC Zero 3.0.5). They add one test guest and one state test to `lee`.

1. Workspace `Cargo.toml`, under `[patch.crates-io]`, add:
   ```
   bls12_381 = { git = "https://github.com/risc0/zkcrypto-bls12_381", tag = "bls12_381/v0.8.0-risczero.1" }
   sha2-v0-9-9 = { git = "https://github.com/risc0/RustCrypto-hashes", package = "sha2", tag = "sha2-v0.9.9-risczero.0" }
   ```
2. `test_guest_core/Cargo.toml`, under `[dependencies]`, add:
   ```
   bls12_381 = { version = "0.8.0", features = ["experimental"] }
   sha2_09 = { package = "sha2", version = "0.9" }
   ```
3. Append `guests-rfp021_update_verify.rs` to `test_guest_core/src/guests.rs`.
4. Copy `rfp021_update_verify.rs` to `lee/state_machine/test_methods/guest/src/bin/`, and in `lee/state_machine/src/lib.rs` add next to `rfp005_multisig_execute`:
   ```
   pub const fn rfp021_update_verify() -> Program {
       Program::new_unchecked(test_methods::RFP021_UPDATE_VERIFY_ID, Cow::Borrowed(test_methods::RFP021_UPDATE_VERIFY_ELF))
   }
   ```
5. Copy `rfp021_update_tx.rs` to `lee/state_machine/src/state/tests/` and add `mod rfp021_update_tx;` to `lee/state_machine/src/state/tests/mod.rs`.

Run, with the instruction file from `bls-bench dump`:

```
unset RISC0_DEV_MODE
RFP021_INSTRUCTION=/abs/path/data/rfp021_instruction_p1885.bin /usr/bin/time -v \
  cargo test --release -p lee --lib state::tests::rfp021_update_tx::rfp021_update_private_tx -- --exact --nocapture
```

Our run: `results/proof-update-private-tx.log`, 3,852.9 s, 9,627,316 KiB peak, proof 224,929 bytes, transaction 226,727 bytes, settled.

# RFP-021 spike findings

2026-10-16, revised the same day with the blst fork. Measurements on Ryzen 7 5700X3D (8 cores, 16 threads), 64 GB. RISC Zero host crate 3.0.5, guests compiled with RISC Zero's Rust 1.97.0 and cargo-risczero 3.0.6, r0vm 3.0.6. Cycle counts are user cycles from the executor with no proving, deterministic for a given guest toolchain. Every run is in `results/`.

## 0. The cap the design must fit

On LEZ v0.3.0 and v0.3.1 every user public transaction is fee-charged and runs at its declared `gas_limit`, which the fee market caps at `MAX_GAS_EXEC`, 10,000,000 cycles per transaction and per block (`lez/chain_state/src/classify.rs`, `lez/programs/fee/core/src/market.rs`, `lez/chain_state/src/apply.rs`). The 32M `DEFAULT_PUBLIC_CYCLE_BUDGET` applies only to paths without a transaction budget. Private transactions are exempt from fees and from metering. Their cost is proving time on the submitter's machine.

The RFP's central question, whether in-program BLS12-381 verification fits the public budget, is therefore a question against 10M. The answer, measured in section 1, is no for one transaction and yes for two with the right library.

**On LEZ 0.4.** On LEZ v0.4.0-rc1, the 0.4 actor model, the 10M cap per transaction and per block holds. A private transaction pays a flat 409,764 execution gas and 224,063 storage gas plus the cycles of its public part, which runs within the block's remaining 10M of execution gas. Its private transitions still run with no cycle bound. At dev commit 7e3f7f7, the tag's ancestor, private transactions were fee-exempt and their public part ran under a 32M default. A handler reads its input as one byte frame and decodes it with borsh, so the input-decoding lines below should shrink there. The guest cycles below carry to 0.4, which runs RISC Zero 3.0.5 with the same accelerated forks. Section 6 measures `blst` inside a LEZ program on v0.4.0-rc3, where the cap is the same.

## 1. The sync-committee signature check, by component, two libraries

Guest `bls_components` uses RISC Zero's accelerated zkcrypto `bls12_381` fork (`risc0/zkcrypto-bls12_381`, tag `bls12_381/v0.8.0-risczero.1`), the fork r0vm-helios builds on. Guest `bls_blst` uses RISC Zero's accelerated `blst` fork (`risc0/blst`, tag `v0.3.16-risczero.0`) through its C API. Real data: the period-1885 mainnet light-client update, attested slot 15441985, signed by 511 of the 512 members of the period-1885 committee. The host verifies the signature natively before any guest runs. Every figure below comes from one build of the harness, run on 2026-10-31.

Input decoding matters: the executor charges about 150 cycles per byte for data that arrives as separate vectors. Op 9 decodes the input and nothing else: 79,047 with no keys (the guest floor), 3,900,152 with the 512 compressed keys, 11,436,503 with the compressed and the uncompressed keys. Every op that does not read the keys runs without them. The tables give measured session totals, with the decoding noted where an op's input carried keys. The derived figures take the floor and the decoding out.

**zkcrypto fork** (`results/bls-p1885-zkcrypto.log`):

| Op | What | User cycles | Of 10M |
|---|---|---:|---:|
| 0 | One pairing of the generators | 16,768,489 | 1.7x |
| 8 | Both Miller loops in one `multi_miller_loop`, with one G1 and the G2 decompression and the hash | 14,296,034 | 1.4x |
| 7 | Op 8 plus the final exponentiation | 25,238,835 | 2.5x |
| 3 | Hash the signing root to G2 | 2,777,791 | 28% |
| 6 | Decompress the G2 signature | 1,490,741 | 15% |
| 12 | Witnessed G2 signature, on-curve and encoding checks, with 11.4M of decoding | 11,444,195 | 114% |
| 1 | Decompress 512 G1 committee keys | 540,672,769 | 54x |
| 2 | Decompress and aggregate the 511 participants | 545,216,987 | 55x |
| 10 | Witnessed 512 keys, on-curve, encoding, aggregate, with 11.4M of decoding | 18,719,490 | 1.9x |
| 11 | SSZ root of the committee, 513 keys, accelerated sha256, with 3.8M of decoding | 5,604,275 | 56% |
| 5 | Full check, pre-aggregated committee minus the absent member | 26,300,618 | 2.6x |
| 4 | Full check from compressed keys | 569,328,763 | 57x |
| 13 | Full check, witnessed aggregate, with 11.4M of decoding | 35,567,523 | 3.6x |

Derived: final exponentiation 10.9M (op 7 minus op 8), the combined Miller loop over both pairs, with its G2 line precomputation, about 9.1M (op 8 minus ops 6 and 3 and one G1 decompression, the floor added back once), so a pairing check of 20.0M. Hash to G2 2.7M and signature decompression 1.4M net of the floor. One G1 decompression 1.05M (op 1 less the key decoding, per key), one G1 addition about 9k, the witnessed key check about 14k per key, the SSZ root 1.7M, about 3.3k per key.

**blst fork** (`results/bls-p1885-blst.log`):

| Op | What | User cycles | Of 10M |
|---|---|---:|---:|
| 25 | Uncompress one G1 key | 178,239 | 1.8% |
| 31 | Uncompress the G2 signature, no subgroup check | 280,144 | 2.8% |
| 26 | Uncompress the G2 signature, with the subgroup check | 678,414 | 6.8% |
| 27 | Hash the signing root to G2 | 1,402,600 | 14% |
| 30 | Decode, hash, prepare both pairs, no Miller loop | 1,707,903 | 17% |
| 28 | Op 30 plus two Miller loops and their product | 6,546,987 | 65% |
| 32 | Op 30 plus one combined Miller loop over both pairs (`blst_miller_loop_n`) | 5,547,007 | 55% |
| 29 | Op 28 plus the final exponentiation | 10,823,662 | 108% |
| 33 | Full check, pre-aggregated committee minus the absent member, combined Miller loop | 10,329,868 | 103% |
| 22 | Signature check only through `blst_core_verify_pk_in_g1`, full-committee aggregate | 12,034,183 | 120% |
| 20 | Full check, pre-aggregated committee minus the absent member, through `blst_core_verify_pk_in_g1` | 12,141,928 | 121% |
| 21 | Full check, witnessed aggregate, with 7.6M of decoding | 19,493,582 | 1.9x |
| 23 | Witnessed 512 keys, on-curve, encoding, aggregate, with 11.4M of decoding | 17,734,507 | 1.8x |
| 24 | Decompress 512 G1 keys, with 3.8M of decoding | 54,248,021 | 5.4x |

Derived: one combined Miller loop over both pairs 3.8M (op 32 minus op 30), two separate Miller loops with their product 4.8M (op 28 minus op 30), final exponentiation 4.3M (op 29 minus op 28), so a pairing check of 8.1M with the combined loop and 9.1M with two loops. Hash to G2 1.3M and signature uncompression with its subgroup check 0.6M net of the floor, the subgroup check alone 0.4M (op 26 minus op 31). One G1 decompression 0.1M, the witnessed key check about 12k per key, the 512-key decompression about 50M. Op 33 verifies the real signature through the combined loop.

**What the two libraries say together.** The zkcrypto fork's final exponentiation alone, 10.9M, exceeds a 10M transaction, so no split rescues it. The blst fork's whole check is 10.3M through the combined Miller loop, just over one transaction, and it splits at the pairing's seams: about 2M of decoding, hashing and the subgroup check, the 3.8M combined Miller loop, and the 4.3M final exponentiation, so an update fits three public transactions with each under half the cap. Our first conclusion, written on the zkcrypto numbers alone, was "nothing fits the public path". It was right for that library and wrong as a statement about LEZ: the library decides. A bid filed on 2026-10-16 by another team (rfp#224) reached the same split with blst, at a pairing of 7.85M against our 8.1M, before we had measured blst.

**Reference points.** SP1's blog reports 49.4M cycles for its light-client program with a dedicated BLS12-381 precompile and 6.7B without. That total covers two sync-committee checks: an update at 30.0M and a finality update at 19.4M with the precompile, about 3.4B each without. Our accelerated 569M (zkcrypto) and 54M (blst) from compressed keys sit between, and the 10.3M pre-aggregated blst path is the one that matters.

## 2. What this means for the two paths

**Public path.** One signature check does not fit a 10M transaction with either library. With blst it fits three: the signature decoding, the subgroup check, the hash to G2 and the branches in one transaction (about 2.3M for a finality update once the SSZ branches and bookkeeping are added, an estimate), the combined Miller loop in a second (about 3.8M), and the final exponentiation with the state write in a third (about 4.3M). A committee handoff adds about 8M (the witnessed check of 512 keys as one blob and the SSZ root) and takes a step of its own. Section 6 measures the split as LEZ 0.4 transactions at 2.7M, 3.3M and 3.6M, and a handoff as two transactions of 2.3M and 2.8M. Intermediate state, an Fp12 of 576 bytes plus digests, lives in a job account between steps. A BLS12-381 precompile would collapse the steps into one transaction, and the measurement above is the delta the RFP asks for under P.8.

**Private path.** Unmetered and fee-exempt. The submitter proves the update on their own machine, the sequencer verifies the proof, and the deferred public apply writes the consensus state. In v0.3.1 the sequencer applies a private transaction's public effects itself, unmetered by the fee market, under the 32M `DEFAULT_PUBLIC_CYCLE_BUDGET` shared across the transaction's public actions (`lee/state_machine/src/validated_state_diff/mod.rs`, `from_privacy_preserving_transaction` and `apply_public_effects`). Section 3 measures it with the zkcrypto guest. It is the path for an operator with a prover and no LEZ gas, not the main path.

**Consumer path.** Inclusion and predicate evaluation are cheap on either path, section 4.

## 3. One finality update as a private transaction

Guest `rfp021_update_verify` in the LEZ v0.3.0 checkout with the accelerated forks (`gemot-evidence/work/accel`), the same harness as the RFP-005 spikes. The plan verifies the period-1885 aggregate signature against a witnessed committee aggregate minus the absent member and records the finalised header in one private account. Real proving, `RISC0_DEV_MODE` unset, 16 threads, `/usr/bin/time -v`. Log: `results/proof-update-private-tx.log`, driver `results/run-proof.sh`, instruction `data/rfp021_instruction_p1885.bin` (376 bytes: the committee aggregate and the one absent key uncompressed, the compressed signature, the signing root, the header root, the slot).

| | |
|---|---|
| Proving time | 3,852.9 s, 64.2 minutes |
| Peak memory | 9,627,316 KiB, 9.2 GiB |
| Proof | 224,929 bytes |
| Transaction | 226,727 bytes |
| Settlement | `transition_from_privacy_preserving_transaction` accepted it, the instance account holds the slot and header root |

Consistency check: the standalone 2.1M-cycle RFP-005 guest proved in 4.7 minutes and the minimal private transaction in 6.5 minutes on this machine, about 108 s per 1M-cycle segment plus the circuit. About 31 segments for this update plus the circuit lands at 64 minutes. Memory is set by the segment size, the same 9.2 GiB as every other private proof on this machine. A GPU prover is an order of magnitude faster, which the operator guide will state with a measured figure once we have one.

The dev-mode run of the same test (`RISC0_DEV_MODE=1`) takes 0.7 s, which is the executor cost without proving.

## 4. Inclusion proofs

Guest `mpt_inclusion` with `alloy-trie` 0.7.9 and RISC Zero's `tiny-keccak` fork, on `eth_getProof` for WETH (0xC02a...) at mainnet block 26203210, verified natively first.

| Proof | Nodes | Bytes | User cycles | Of 10M |
|---|---:|---:|---:|---:|
| Account, under the state root | 9 | 3,794 | 716,365 | 7.2% |
| Storage slot 0, under the account's storage root | 7 | 2,938 | 555,072 | 5.6% |

Both figures are session totals and include decoding the proof nodes from the input at about 150 cycles per byte, about 0.57M and 0.44M. The verification itself is about 0.15M and 0.12M. An account plus a storage slot is under 0.3M of verification, under 3 percent of a public transaction, and well inside one segment of proving on the private path. Our guest does not enable the risc0-zkvm `unstable` feature, so whether the keccak accelerator is engaged is unconfirmed. The figures are upper bounds.

## 5. Reuse

r0vm-helios runs `helios-consensus-core` (a16z) in a RISC Zero guest with the same `bls12_381` fork, `tiny-keccak` fork and `alloy-trie`. Its guest decompresses the committee keys on every update, which is the 540M path above. It can afford that because it proves off-chain with Boundless. For an in-LEZ private submission the light-client logic transfers and the key handling does not: the committee is stored uncompressed and pre-aggregated, and a handoff verifies the new keys through the witnessed check against the SSZ root.

## 6. On LEZ 0.4 as real transactions

2026-11-11, on LEZ v0.4.0-rc3 (commit `bafd07be`): a standalone sequencer with 15-second blocks and `RISC0_DEV_MODE` unset, on the machine above. The program, runner and scripts are in `lez04/`, the steps to reproduce in `lez04/README.md`, every log in `results/lez04/`. Each step is a real transaction, dry-run first for its metered cycles. An applied step's fee is its metered cycles plus its wire bytes, each at the minimum base fee of 8, in every log line.

**The program.** An instance holds its configuration, written once, its head and its current and next committee roots, 354 bytes, or 394 with a next committee. A committee lives in an actor of its own, 49,285 bytes, installed in two transactions that each check their half against the SSZ committee root, and any instance holding that root uses it. An update takes three transactions. Step one sends the update to the instance, which checks it and asks the committee actor for the participants' key, the checked signature and the hashed message, which go to an empty job actor. Step two runs the combined Miller loop on the job. Step three hands the loop's output to the instance, which checks that the update's committee still applies and that the update is still newer, and only then runs the final exponentiation and advances. The instance rotates to the next committee once its finalized head reaches that committee's period. Step three can also write the update's head once into a record actor, which is what private consumers read. An empty actor is written only by a transaction that its own account signs: the instance's initialisation, a committee's first half, the job's step one, the record's step three and a consumer's consumption.

**Run 6, periods 1885 and 1886** (`results/lez04/run6.log`):

| Transaction | Cycles | Of 10M |
|---|---:|---:|
| Initialise an instance | 82,477 | 0.8% |
| Committee, first half | 2,250,218 | 23% |
| Committee, second half | 2,757,080 | 28% |
| Step one, 511 signers | 2,662,923 | 27% |
| Step one, at the 342-signer floor | 3,748,072 | 37% |
| Step two, combined Miller loop | 3,278,748 | 33% |
| Step three, final exponentiation and the advance | 3,635,084 | 36% |
| Step three with the rotation, the next committee and a record | 3,651,430 | 37% |

Step one is largest at the floor, where 170 absent keys come off the stored aggregate, and it stays at 37 percent of the cap. Steps two and three do not depend on the number of signers. A whole update is 9.6M cycles with 511 signers, and 10.7M at the floor, where step one's 3.75M joins the successful steps two and three, so one update per epoch uses 15 to 17 percent of block capacity at 60-second blocks. A committee costs 5.0M once per period, the same at the bootstrap and at every handoff. Each figure in this table that run 4 also measured is within 0.2 percent of it.

**Two boundary crossings.** In run 6 the instance started at the first slot of period 1885. The period-1885 update supplied the 1886 committee root. The 1886 committee went into its own actor without touching the instance, its first half staged while the 1885 update ran. The period-1886 update, signed by that committee, moved the head into period 1886, rotated the instance and wrote a record, and the instance then held the 1887 root as next. The second crossing starts from a head later than its period's served update (`results/lez04/cross-run6.log`, data in `data/cross-2026-11-11/`). The instance `setup-private` left today stood 7,424 slots into period 1907. Period 1907's update, as the beacon API serves it, had finalized at the period's first slot, before that head. It taught the instance the 1908 committee and left the head where it was, as the spec does. Once the 1908 committee was installed, the latest finality update, signed by it, moved the head into period 1908 and rotated the instance. Its steps cost what run 6's main run did, to within 0.3 percent.

**Refusals**, from run 6:

| Refused transaction | Code | Charged |
|---|---:|---:|
| A forged first half naming the real 1886 root, with 1885 keys | 10 | 1,971,238 cycles |
| Step three of the floor update, whose signature does not verify | 11 | 3,628,342 cycles |
| Step one naming another instance as its job | 15 | 2,655,392 cycles |
| An unsigned initialisation of the empty job, or the empty record, that an honest update names | 17 | 24,907 cycles |
| Step one without its job's signature | 17 | 2,655,332 cycles |
| A valid consumption sent unsigned into a finished job, or into the record an honest update names (`cross-run6.log`) | 17 | 34,911 cycles |
| A duplicate of the 1885 update | 12 | 95,548 cycles |
| Step two on a finished job | 15 | 6,881 cycles |
| Step three of a second job for the 1886 update, after the first finished | 12 | 47,387 cycles |
| Step one on an instance whose 14-day weak-subjectivity window has passed | none | its declared 3,328,652 gas |
| Step three of a job prepared in time, after its instance's window closed | none | its declared 4,543,854 gas |

A refusal exits with a code, and rc3 charges it only the cycles used, those of the nested calls before it included. A panic is charged the whole gas limit: on rc1, before the program used exit codes, a duplicate update paid the full 10M (`results/lez04/rc1/run1.log`).

The windows are the exception. Steps one and three set a timestamp validity window on their transaction that ends the weak-subjectivity period after the instance's head, and step one's starts at the signature slot. rc3 checks a window at settlement, after execution, and charges a transaction outside it its whole declared gas. The rc3 wallet's simulation does not check windows. It reported both transactions as applying, and both left their actors unchanged. A third instance shows step three's window. Its weak-subjectivity period was set so that its window closed four minutes after its initialisation. Its update's steps one and two ran inside the window, and its step three ran after it and reverted, so a job prepared in time cannot refresh an instance whose window has since closed. rc3's clock program answers a `ReadTimestamp` message, which would let step one refuse with an exit code instead, at the price of parking the update in the instance until the clock replies.

The unsigned initialisations and consumptions stand for a third party that writes first to an actor an honest update names. Run 4 would have accepted such an initialisation at the 82k cycles of an Init, and the honest update's step one or step three would then have failed on the occupied actor. Run 6 refuses both kinds of write, and the honest update then used the same actors. rc3 lets a transaction name a fresh account only with its public key, so these steps stand for a third party who has seen the key in a pending transaction, or who names an account already on chain, such as a finished job. Since run 5 the record is no longer among step one's accounts, so its key first appears in step three. The two jobs for the 1886 update stand for two submitters racing. The loser's step three is refused before the final exponentiation, for 47,387 cycles, where run 4's order would have paid about 3.6M first. The loser still pays for its steps one and two, 5.9M cycles. A job that names a record can be finished only by the record's key holder, since the record signs step three.

**What the program checks, and what it leaves out.** This list comes from three independent reviews of runs 3, 4 and 5 against the consensus specs' light-client sync protocol, brought up to date with run 6's fixes. The program checks:

- at initialisation, that the header hashes to the configured checkpoint root, the current committee's branch at generalized index 86 under the header's state root, the execution payload's branch under the body root, and fork epochs in strictly ascending order
- at a committee install, each half against the SSZ committee root, every key decoded and on the curve, and the aggregate decoded
- for each update, the signature slot after the attested slot and the attested slot at or after the finalized one, at least 342 of the 512 signers, the finality branch at index 169, the finalized header's execution branch at index 25, and the next committee's branch at index 87, adopted only when the finalized and attested headers share a period
- for the signature, the committee of the signature's period, current or the known next, the fork version of the signature slot's epoch, the sync committee domain and signing root, the participants' key as the stored aggregate less the absent keys and never the identity, the signature in G2 and not at infinity, the hash to curve with Ethereum's tag, and the pairing
- for order and time, a duplicate refused, an update finalized at or before the head refused unless it brings the next committee the instance lacks, a conflicting next committee refused, the rotation when the finalized head enters the next period, and the windows above
- for the actors, state tagged by kind, the inner messages accepted only from the program's own actors, an empty actor written only with its own signature, and a job and record distinct from the instance and the committee

It leaves out, each for a milestone or by design:

- Gloas. The generalized indices and the execution header are Electra's and Fulu's. A Gloas header carries only the execution block hash, and the program neither handles nor measures it. The proposal puts Gloas in M2.
- A trusted configuration. Anyone can initialise an instance on any checkpoint, fork list or weak-subjectivity period, so a consumer has to check an instance's whole configuration, not only its checkpoint.
- An optimistic head. The head is the finalized header only, with no best valid update and no forced update, and a stalled instance is replaced rather than forced forward.
- The attested header's execution branch, since no attested execution field is used.
- A G1 subgroup check on committee keys. The root binds the keys to a beacon state whose deposits already validated each one.
- Exit codes for the windows, which are settlement reverts charged the declared gas. A submitting daemon has to check the times against its own clock before sending, since rc3's dry run reports such a transaction as applying.
- A public consumer. The consumption is a private probe of one WETH slot-0 proof that refuses with assertions, not exit codes. A public consumer and the recorded-statement path are M2 work.

**The wallet and the block.** The rc3 wallet declares a public transaction's gas as its simulated cycles plus 25 percent, capped at 10M, and refuses to send one whose simulation reverts unless told to. A block counts the cycles charged, not the gas declared, so the margin costs no block capacity. A private transaction's public part may use only what is left of the block's 10M, so a consumption in a nearly full block reverts and is charged.

**Private consumption** (`results/lez04/private/`). A private actor reads the record of a 2026-11-11 finality update, for block 26,389,914, and proves WETH's storage slot 0 under it with a 9-node account proof and a 7-node storage proof. Run 3's program, real proving, `/usr/bin/time -v`:

| | 16 threads | 8 threads |
|---|---:|---:|
| Proving and sending | 810 s, 13.5 min | 1,131 s, 18.9 min |
| Peak memory | 9.2 GiB | 9.2 GiB |
| Public part | 14,069 cycles | 14,069 cycles |
| Fee | 5,183,168 | 5,183,168 |

The fee is the flat 409,764 execution gas and 224,063 storage gas of a private transaction plus the public part's cycles, all at the base fee of 8. The 8-thread proof took 1.40 times as long. Shielding the fee balance into the fresh private account came first and took 7 minutes 16 seconds at 9.2 GiB. A browser, an editor and an idle second sequencer ran throughout, about half a core during the 16-thread proof and a sixth of a core during the 8-thread one (`private/load.log`, `private/machine.txt`). Run 6's program adds one authorization check to `Consume` and keeps run 3's `Read` and `RecordReply` handlers and every consumption message index unchanged. Its dry run of the same consumption, against the record its own `setup-private` wrote for the same block, reports 14,062 public cycles (`private/consume-dry-run6.log`).

**Earlier runs.** Runs 1 and 2 on v0.4.0-rc1 and run 3 on rc3 measured an earlier layout that kept the committee inside the instance. Its step three cost 4.58M because its advance read and rewrote the 49 KB instance. An independent review found that layout let a forged first half block an install for good, let a job overwrite any actor of the program, and switched committees at installation rather than at the period boundary. Run 4's layout removed all three (`results/lez04/run4.log`). A second review found four gaps in run 4. Anyone could write first to the empty job or record actor an honest update named. An update carrying the next committee was refused when it had finalized before the head, so an instance past its period's served update could not cross into the next period. A raced step three paid the whole final exponentiation before its refusal. A job prepared in time could still advance an instance after its window closed. Run 5 closed all four (`results/lez04/run5.log`, `cross-run5.log`). A third review found that run 5's `Consume` still wrote an empty actor without its signature, so a third party holding any valid consumption could occupy a job or record. Run 6 adds the check. The proofs above ran on run 3's program, `results/lez04/lantern_spike-run3.bin`.

## Reproducing

```
cd bls-bench && cargo build --release
./target/release/bls-bench bls --data ../data/update_p1885_inputs.json --ops 0,1,2,3,4,5,6,7,8,9,10,11,12,13
./target/release/bls-bench bls --data ../data/update_p1885_inputs.json --ops 20,21,22,23,24,25,26,27,28,29
./target/release/bls-bench mpt --proof ../data/proof_weth_latest.json --block ../data/block_latest.json
```

`data/prep_update.py` rebuilds the update inputs from the beacon API responses.

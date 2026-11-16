# Lantern on LEZ 0.4: the spike program

A Lantern-shaped program on LEZ v0.4.0-rc3 (commit `bafd07be`), the runner that drives it on a standalone sequencer with real mainnet data, and the scripts for the private consumption. Logs are in `../results/lez04/`. The figures and what they mean are in `../FINDINGS.md`, section 6.

## Layout

- `core/`: types and SSZ helpers shared by the program and the runner.
- `methods/guest/`: the program, one actor entry point.
- `runner/`: deploys the program and sends every step as a real transaction, each dry-run first for its metered cycles.
- `fetch-fresh.sh`: a recent bootstrap, the latest finality update and an `eth_getProof` for WETH slot 0 at its finalized block.
- `fetch-cross.sh`: one period's served light-client update and the latest finality update, for crossing into the next period.
- `run-private.sh`: shields a fee balance into a fresh private account, then proves the consumption at the given thread counts.

## Actors

| Actor | Holds | Size |
|---|---|---:|
| Instance | Configuration written once (checkpoint root, genesis validators root, genesis time, forks, weak-subjectivity period), the head, the current and the next committee root | 354 bytes, 394 with a next committee |
| Committee | 512 keys in blst's affine form and their aggregate, checked against the SSZ committee root. Any instance holding that root uses it | 49,285 bytes |
| Job | One update's prepared pairing between its transactions | under 1.4 KB |
| Record | One verified head, written once | 176 bytes |
| Consumer | A private actor's attested statement | |

Installing a committee never touches an instance. An instance learns a committee's root from a verified update and finds the keys in any committee actor that holds that root.

An empty actor is written only by a transaction its own account signs, so nobody can occupy the job or record actor that someone else's update names.

An update counts as newer when its finalized head is past the instance's head, or when it brings the next committee and the instance has none yet. The spec takes the next committee from any update of the period whose finalized and attested headers share that period, including one finalized before the head, and such an update leaves the head where it is.

## Transactions

| Transaction | Messages | Signed by |
|---|---|---|
| Initialise | `Init` to an empty actor | The instance account |
| Committee, first half | `InstallFirst` to an empty actor: 256 keys, checked against the root through the second half's subtree root and the aggregate | The committee account |
| Committee, second half | `InstallSecond` to the staged actor: the other 256 keys, checked against the staged subtree root | Anyone |
| Update, step one | `Prepare` to the instance, which sends `Aggregate` to the committee, which sends `Begin` to an empty job | The job account |
| Update, step two | `Miller` to the job | Anyone |
| Update, step three | `Finish` to the job, which sends `Advance` with the Miller loop's output to the instance and, if named, `Record` to an empty record. `Advance` checks the committee and that the update is still newer, then runs the final exponentiation | The record account, if one is named |
| Consumption, private | `Consume` to the consumer, which sends `Read` to a record, which replies with `RecordReply` | The private consumer |

The fee payer signs every transaction as well.

A refused message exits with a code, which LEZ charges only the cycles used, where a panic is charged the whole gas limit.

| Code | Refusal |
|---:|---|
| 10 | Committee keys do not match the root |
| 11 | The sync committee signature does not verify |
| 12 | Stale or duplicate update |
| 13 | No committee of the instance for the signature period |
| 14 | Fewer than 342 of 512 signers |
| 15 | Actor in the wrong state for the message |
| 16 | Malformed update or key data |
| 17 | Sender not allowed, or an empty actor written without its own signature |
| 18 | A different next committee for a period already known |
| 19 | The timestamp window is empty, possible only with a weak-subjectivity period under two committee periods |

`Prepare` also sets a timestamp window on its transaction: valid from the signature slot's start until the weak-subjectivity period after the instance's head. `Advance` sets the same upper bound on step three, so a job prepared in time cannot refresh an instance whose window has closed since. A transaction outside its window reverts at settlement and pays its whole declared gas. The rc3 wallet's simulation does not check windows, so it reports such a transaction as applying.

## Reproducing

LEZ, built from a checkout at the tag:

```sh
git worktree add --detach ../lez-rc3 v0.4.0-rc3
cd ../lez-rc3 && cargo build --release --features standalone -p sequencer_service -p wallet
```

A standalone sequencer with the local network config, 15-second blocks and `RISC0_DEV_MODE` unset:

```sh
target/release/sequencer_service setup <stack>/seq/home --config lez/sequencer/service/networks/local.json --funding-public-key <hex key> --create-channel
cd <stack>/seq && target/release/sequencer_service start $PWD/home --rpc-listen-address 127.0.0.1:3042
```

A wallet in `<stack>/wallet` whose `wallet_config.json` points `sequencer_addr` at that address and sets `gas_limit` to 10,000,000, with the two genesis-funded accounts of LEZ's local network imported through `wallet account import public`.

The program and the runner:

```sh
cd methods && cargo build --release && cd ..
cargo build --release -p lantern-spike-runner
BIN=methods/target/riscv-guest/lantern-spike-methods/lantern-spike-guest/riscv32im-risc0-zkvm-elf/release/lantern_spike.bin
export LEE_WALLET_HOME_DIR=<stack>/wallet LEE_WALLET_PASSWORD=<password>
target/release/lantern-spike-runner $BIN <payer> ../data
```

The private consumption, on a fresh checkpoint because a full node keeps state for about 128 blocks:

```sh
target/release/lantern-spike-runner setup-private $BIN <payer> ../data ../data/fresh-<date>
WALLET=../lez-rc3/target/release/wallet PAYER=<payer> ./run-private.sh ../data/fresh-<date> ../results/lez04/private 16 8
```

`run-private.sh` runs `fetch-fresh.sh` and `setup-private` itself when the fresh directory has no `ids.json`. `consume ... --dry-run` reports the consumption's public cycles without proving.

The crossing, from the mid-period instance `setup-private` leaves, once the next period has finalized blocks:

```sh
./fetch-cross.sh <the instance's period> ../data/cross-<date>
target/release/lantern-spike-runner cross <payer> ../data ../data/fresh-<date> ../data/cross-<date>
```

## Runs

| Run | LEZ | Program | Logs |
|---|---|---|---|
| 1 | v0.4.0-rc1 | First version: refusals panicked | `rc1/run1.log`, binary `rc1/lantern_spike-run1.bin` |
| 2 | v0.4.0-rc1 | Refusals exit with codes, the committee inside the instance | `rc1/run2.log`, `rc1/private/`, binary `rc1/lantern_spike-run2.bin` |
| 3 | v0.4.0-rc3 | Same program as run 2 | `run3.log`, `private/setup-private.log` |
| Proofs | v0.4.0-rc3 | Run 3's program | `private/shield.log`, `private/consume-t16.log`, `private/consume-t8.log`, `private/load.log`, `private/machine.txt`, binary `lantern_spike-run3.bin` |
| 4 | v0.4.0-rc3 | Committees in actors of their own, after an independent review | `run4.log`, `private/setup-private-run4.log`, `private/consume-dry-run4.log` |
| 5 | v0.4.0-rc3 | Empty actors written only with their own signature, except by `Consume`, the final exponentiation after the instance's checks, a window on step three, and next committees from updates finalized before the head, after a second review | `run5.log`, `cross-run5.log`, `private/setup-private-run5.log`, `private/consume-dry-run5.log`, binary hash `run5-binary.sha256` |
| 6 | v0.4.0-rc3 | This directory: `Consume` needs its consumer's signature too, after a third review. Every other figure matches run 5 to the cycle | `run6.log`, `cross-run6.log`, `private/setup-private-run6.log`, `private/consume-dry-run6.log`, binary hash `run6-binary.sha256` |

Run 6's program adds one authorization check to `Consume` and keeps run 3's `Read` and `RecordReply` handlers and every consumption message index unchanged, so the consumption the proofs measured differs only by that check.

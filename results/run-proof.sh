#!/usr/bin/env bash
cd "$HOME/projects/logos/gemot-evidence/work/accel" || exit 1
export CARGO_TARGET_DIR=$PWD/target
unset RISC0_DEV_MODE
OUT=$HOME/projects/logos/spel/.rfp021-spikes/results
date -u +"start %Y-%m-%dT%H:%M:%SZ" > "$OUT/proof-update-private-tx.log"
RFP021_INSTRUCTION=$HOME/projects/logos/spel/.rfp021-spikes/data/rfp021_instruction_p1885.bin /usr/bin/time -v cargo test --release -p lee --lib state::tests::rfp021_update_tx::rfp021_update_private_tx -- --exact --nocapture >> "$OUT/proof-update-private-tx.log" 2>&1
date -u +"end %Y-%m-%dT%H:%M:%SZ" >> "$OUT/proof-update-private-tx.log"

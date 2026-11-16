#!/usr/bin/env bash
# The private consumption: a fresh instance from today's checkpoint, a shielded fee balance, then
# one consumption proven at the given thread count. Wallet from LEE_WALLET_HOME_DIR.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
RUNNER=$HERE/target/release/lantern-spike-runner
BIN=$HERE/methods/target/riscv-guest/lantern-spike-methods/lantern-spike-guest/riscv32im-risc0-zkvm-elf/release/lantern_spike.bin
WALLET=${WALLET:?path to the rc1 wallet binary}
PAYER=${PAYER:?funded public account}
FRESH=${1:?usage: run-private.sh <fresh dir> <out dir> [threads...]}
OUT=${2:?usage: run-private.sh <fresh dir> <out dir> [threads...]}
shift 2
THREADS=("${@:-16}")
mkdir -p "$OUT"
unset RISC0_DEV_MODE

if [ ! -s "$FRESH/ids.json" ]; then
  "$HERE/fetch-fresh.sh" "$FRESH" | tee "$OUT/fetch.log"
  "$RUNNER" setup-private "$BIN" "$PAYER" "$HERE/../data" "$FRESH" 2>&1 \
    | grep -v '^Transaction data is' > "$OUT/setup-private.log"
fi

if [ ! -s "$FRESH/consumer.txt" ]; then
  consumer=$("$WALLET" account new private 2>&1 | grep -o 'Private/[1-9A-HJ-NP-Za-km-z]*' | head -1 | cut -d/ -f2)
  echo "$consumer" > "$FRESH/consumer.txt"
  /usr/bin/time -v "$WALLET" auth-transfer send --from "Public/$PAYER" --to "Private/$consumer" --amount 1000000000000 \
    > "$OUT/shield.log" 2>&1
fi
consumer=$(cat "$FRESH/consumer.txt")

for t in "${THREADS[@]}"; do
  date -u +"start %Y-%m-%dT%H:%M:%SZ" > "$OUT/consume-t$t.log"
  RAYON_NUM_THREADS=$t /usr/bin/time -v "$RUNNER" consume "$BIN" "$FRESH" "$consumer" 2>&1 \
    | grep -v '^Transaction data is' >> "$OUT/consume-t$t.log"
  date -u +"end %Y-%m-%dT%H:%M:%SZ" >> "$OUT/consume-t$t.log"
done

#!/usr/bin/env bash
# Fetches a recent finalized bootstrap, the latest finality update and an eth_getProof for WETH
# slot 0 at that update's finalized block. Run it right before the private run: a full node keeps
# state for about 128 blocks, so the proof must be fetched within minutes of finality.
set -euo pipefail
BEACON=${BEACON:-https://lodestar-mainnet.chainsafe.io}
EXEC=${EXEC:-https://ethereum-rpc.publicnode.com}
OUT=${1:?usage: fetch-fresh.sh <out dir>}
mkdir -p "$OUT"

curl -sf "$BEACON/eth/v1/beacon/light_client/finality_update" -o "$OUT/finality_update.json"
fin_slot=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['data']['finalized_header']['beacon']['slot'])" "$OUT/finality_update.json")
block=$(python3 -c "import json,sys; print(hex(int(json.load(open(sys.argv[1]))['data']['finalized_header']['execution']['block_number'])))" "$OUT/finality_update.json")

# A bootstrap a few epochs before the latest finalized checkpoint, so the update advances it.
for back in 3 4 5 6; do
  slot=$(( (fin_slot / 32 - back) * 32 ))
  root=$(curl -sf "$BEACON/eth/v1/beacon/blocks/$slot/root" | python3 -c "import json,sys; print(json.load(sys.stdin)['data']['root'])") || continue
  if curl -sf "$BEACON/eth/v1/beacon/light_client/bootstrap/$root" -o "$OUT/bootstrap.json"; then
    echo "$root" > "$OUT/bootstrap_root.txt"
    break
  fi
done
test -s "$OUT/bootstrap_root.txt"

curl -sf -X POST -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_getProof\",\"params\":[\"0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2\",[\"0x0000000000000000000000000000000000000000000000000000000000000000\"],\"$block\"]}" \
  "$EXEC" -o "$OUT/proof_weth.json"
python3 -c "import json,sys; r=json.load(open(sys.argv[1])); assert 'result' in r, r" "$OUT/proof_weth.json"
date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/fetched_at.txt"
echo "finalized slot $fin_slot, block $block, bootstrap slot $slot root $(cat "$OUT/bootstrap_root.txt")"

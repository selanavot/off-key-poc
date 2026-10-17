#!/bin/bash
# Two-container input-guessing selective failure attack against MP-SPDZ MASCOT.
#
# Proves the honest party runs a COMPLETELY UNMODIFIED MP-SPDZ binary.
#
# Container "honest": clean mpspdz:built image, zero patches, stock mascot-party.x.
# Container "attacker": same base image, patched at runtime.
# They communicate over a Docker network.
#
# Usage: ./run-attack.sh [guess] [secret]
#   Default: guess=7 secret=7 (should PASS — attacker learns y=7)
#   Try:     ./run-attack.sh 7 3  (should FAIL — y!=7)

set -eo pipefail

GUESS=${1:-7}
SECRET=${2:-7}

echo "=== Two-Container Selective Failure Attack ==="
echo "Attacker's guess: $GUESS"
echo "Honest party's secret: $SECRET"
echo ""

cd "$(dirname "$0")"

NETWORK=attack-net
PORT=14000

cleanup() {
  docker rm -f attacker honest 2>/dev/null || true
  docker network rm $NETWORK 2>/dev/null || true
}
trap cleanup EXIT
cleanup

# Create Docker network
docker network create $NETWORK >/dev/null

echo "--- Step 1: Start containers ---"
# Both containers use the SAME clean base image
docker run -d --name attacker --network $NETWORK mpspdz:built sleep infinity >/dev/null
docker run -d --name honest   --network $NETWORK mpspdz:built sleep infinity >/dev/null
echo "  Two containers on network '$NETWORK'"

echo "--- Step 2: Prepare honest party (completely unmodified) ---"
# Copy ONLY the .mpc program — no patches, no modifications
docker cp simple_threaded_mul.mpc honest:/usr/src/MP-SPDZ/Programs/Source/
docker exec honest bash -c "
  cd /usr/src/MP-SPDZ
  ./compile.py simple_threaded_mul 2>&1 | tail -1
  mkdir -p Player-Data
  echo $SECRET > Player-Data/Input-P1-0
"
echo "  Honest party ready (stock mascot-party.x, no patches)"

echo "--- Step 3: Prepare attacker (patched binary) ---"
# Copy .mpc + patch script
docker cp simple_threaded_mul.mpc attacker:/usr/src/MP-SPDZ/Programs/Source/
docker cp patch_guess.py attacker:/usr/src/MP-SPDZ/
docker exec attacker bash -c "
  cd /usr/src/MP-SPDZ
  python3 patch_guess.py
  rm -f Machines/SPDZ.o Machines/mascot-party.o
  make -j4 mascot-party.x 2>&1 | tail -1
  ./compile.py simple_threaded_mul 2>&1 | tail -1
  mkdir -p Player-Data
  echo 0 > Player-Data/Input-P0-0
"
echo "  Attacker ready (patched mascot-party.x)"

echo ""
echo "--- Step 4: Run protocol ---"
echo "  Party 0 (attacker container): x=0, guess=$GUESS"
echo "  Party 1 (honest container):   y=$SECRET (unmodified binary)"
echo ""

# Start attacker (party 0) — listens for connections
docker exec -d attacker bash -c "
  cd /usr/src/MP-SPDZ
  ATTACK_MAC_KEY=1 ATTACK_GUESS=$GUESS \
    ./mascot-party.x 0 simple_threaded_mul -pn $PORT -h attacker -N 2 \
    > /tmp/party0.log 2>&1
"

# Give party 0 a moment to start listening
sleep 1

# Start honest party (party 1) — connects to attacker
docker exec honest bash -c "
  cd /usr/src/MP-SPDZ
  ./mascot-party.x 1 simple_threaded_mul -pn $PORT -h attacker -N 2 \
    > /tmp/party1.log 2>&1
" || true

# Wait for attacker to finish
sleep 2

echo "--- Logs ---"
docker exec attacker cat /tmp/party0.log 2>/dev/null | sed 's/^/  [attacker] /'
docker exec honest   cat /tmp/party1.log 2>/dev/null | sed 's/^/  [honest]   /'

echo ""
if docker exec attacker grep -q "DONE" /tmp/party0.log 2>/dev/null; then
  echo "=== RESULT: Program succeeded ==="
  echo "=== Attacker learned: y = $GUESS ==="
else
  echo "=== RESULT: MAC Check Failure ==="
  echo "=== Attacker learned: y != $GUESS ==="
fi

echo ""
echo "Key point: honest party ran completely unmodified mascot-party.x"
echo "from a clean mpspdz:built image with zero patches."

# Cross-Run MAC-Key Inconsistency in SCALE-MAMBA (Full Threshold)

A proof-of-concept off-key attack on **SCALE-MAMBA**'s Full Threshold protocol. In
this attack, we show how a malicious party breaks the confidentiality of an honest
party's secret input.

**Off-key vector: cross-run restart.** SCALE-MAMBA re-reads each party's MAC-key
share from a plaintext file on disk at the start of every run, and authenticated
secrets carry from one run to the next unchanged. A malicious party therefore
supplies the normal key `α` on run 1 and `α + 1` on a restart: a secret stored
under `α` in run 1 is then checked under `α + 1` in run 2, so two inconsistent keys
meet in the same MAC check. The attack rides SCALE-MAMBA's documented
stop-and-restart workflow (`-memory old` checkpoint/resume, crash recovery, and
reactive program swap), each of which reloads authenticated state into a fresh
process that re-reads the key from disk.

## Threat model

Both parties run the same stock `Player.x`; no binary is patched. The honest party
(Player 0) supplies its real input and runs the same programs and `-memory` flags.
The sole adversarial action is Player 1 editing its own `Data/MKey-1.key` (and, for
the selective attack, its `Data/Memory-P1` MAC tag) between the two runs.

## Demonstrated attacks

The attack driver runs both an input-recovery attack and the more robust
selective-failure attack, against the multiplication and affine-transformation
circuits (see [the repository overview](../README.md) for how the two attacks and
two circuits relate).

## How to run

The image needs x86 AES-NI/PCLMULQDQ, so on Apple Silicon it runs under
linux/amd64 emulation (slow, but works via Docker Desktop). Build once:

```bash
docker build --platform linux/amd64 -t scale-mamba-attack .   # one-time, ~15-20 min
```

The attack driver takes the circuit and attack type as flags:

```
run-attack.sh --circuit mult|affine --attack selective|recovery --real-y N [--guess-of-y G] [--x X]
```

For example:

```bash
# Multiplication circuit f(x, y) = x*y (the attacker fixes x = 0):
./run-attack.sh --circuit mult --attack selective --guess-of-y 5 --real-y 5    # completes iff guess == y
./run-attack.sh --circuit mult --attack selective --guess-of-y 5 --real-y 4    # aborts, so y != 5
./run-attack.sh --circuit mult --attack recovery  --real-y 12345               # recovers y = 12345, no guessing

# Affine circuit f(x; (y, r)) = x*y + r, output masked by a uniform r:
./run-attack.sh --circuit affine --attack selective --guess-of-y 1 --real-y 1  # completes iff y == 1
./run-attack.sh --circuit affine --attack recovery  --real-y 987654 --x 3      # recovers y, output stays masked

# Prepend FAKE=1 for the fast trusted-dealer offline:
FAKE=1 ./run-attack.sh --circuit mult --attack selective --guess-of-y 5 --real-y 5
```

`run-attack.sh` runs the honest store (run 1) and the attacker's restart (run 2),
then reports the result. `--circuit` picks the functionality and `--attack` the
strength: `selective` needs `--guess-of-y` and leaks one bit (complete vs abort);
`recovery` reads `y` outright from the unmasked MAC check with no guessing. The
default offline is real FHE/BGV (minutes per run under emulation); `FAKE=1` swaps
in SCALE-MAMBA's trusted-dealer offline, which keeps the attack identical and only
bypasses the FHE path, so the real-FHE run is the canonical demonstration.

For the affine circuit the honest party holds `y` and a mask `r`, and the attacker
holds `x`. The output `x*y + r` is masked by `r`, so it reveals nothing about `y`;
unlike the multiplication circuit (whose `x = 0` output is trivially `0`), the leak
there is a genuine violation of malicious security. SCALE-MAMBA's clear input path
is 64-bit, so `r` is a uniform 64-bit mask; the attack is independent of `r`'s
distribution.

## Files

| File | What |
|---|---|
| `Dockerfile` | Pinned SCALE-MAMBA build (AVX patch, variant 18, attack programs) |
| `patches/avx_memcpy.h` | AVX path `#ifdef`-guarded for no-AVX emulation |
| `patches/offkey_recover.py` | Env-gated (`OFFKEY_RECOVER`) instrumentation of the unmasked MAC check, so the attacker inverts the opened check value to recover `y`. Attacker-only; no effect without the variable. |
| `Programs/attack_store/attack_store.mpc` | Run 1: P0 inputs `y`, store in `Ms[100]` |
| `Programs/attack_open/attack_open.mpc` | Run 2 (mult, selective): load `y`, reveal `z = x·y` with `x = 0` |
| `Programs/attack_recover/attack_recover.mpc` | Run 2 (mult, recovery): load `y`, open a single off-key value `d = y - b` |
| `Programs/attack_affine/attack_affine.mpc` | Run 2 (affine, selective): load `y`, enter `x` (P1) and 64-bit mask `r` (P0), reveal `z = x*y + r` |
| `Programs/attack_affine_recover/attack_affine_recover.mpc` | Run 2 (affine, recovery): the affine output plus a standalone off-key `d = y - b` opening |
| `patcher.py` | The two between-runs edits (Player 1): `MKey-1.key`, `Memory-P1` |
| `poc.sh` | In-container driver: `store` / `open` / `recover` / `affine` / `affine-recover` |
| `run-attack.sh` | The attack driver (circuit and attack type are flags; see above) |

## How it works

Full Threshold authenticates every share with a MAC under a global key `α = Σ α_i`
and aborts if any opened value fails its MAC check, which silently assumes every
value in the check was authenticated under the same `α`. The cross-run restart
breaks that: the attacker changes its key share between runs (`α → α + 1`) while
carrying a run-1 secret `y` (still MAC'd under `α`) into run 2. When `y`, via a
Beaver mask opening `d = y − b` with `b` fresh under `α + 1`, reaches the MAC check,
the key mismatch makes the check value a known function of `y`:

- **Selective abort:** the attacker also adds a guess `g` to `y`'s MAC, so the
  check passes iff `g = y`.
- **Full secret recovery:** SCALE-MAMBA uses the *unmasked* Damgard et al. (2013)
  MAC check, in which every party opens its own check share, so the attacker
  reconstructs the off-key opening's check value and reads `y` directly, with no
  guess. The check then aborts, but the value was already opened. SCALE-MAMBA
  batches a run's openings into one check, so the recovery program arranges `d` to
  be the only off-key opening in that batch (opened last); a single reconstructed
  value then yields `y`. The instrumentation (`patches/offkey_recover.py`) does the
  inversion, gated on `OFFKEY_RECOVER`, which only the attacker sets, and changes
  no message sent nor the accept/abort decision.

The attack is identical under both offline modes: `FAKE=1` (trusted dealer) and the
real FHE/BGV offline both recover `y`. See the accompanying paper for the full
derivation and security analysis.

## Why FHE does not save SCALE-MAMBA

One might expect the FHE/BGV preprocessing to prevent this, since the MAC key is
used in encrypted form throughout the offline phase. It does not: SCALE-MAMBA
regenerates the encrypted key at the start of every run from the party's mutable
on-disk plaintext share, with a ZKPoK that proves only intra-run well-formedness.
Nothing carries the encrypted key between runs or commits it at setup, so a party
that edits its share just gets a fresh, valid encryption of the new value, and the
offline phase MACs under it. That is why the real-FHE run recovers `y` just as the
trusted-dealer run does.

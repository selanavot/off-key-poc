# Cross-Run MAC-Key Inconsistency in FANNG-MPC (Full Threshold)

FANNG-MPC is a fork of SCALE-MAMBA and inherits the cross-run MAC-key
selective-failure attack unchanged. **For the full analysis see
[`../scale-mamba/README.md`](../scale-mamba/README.md).** This folder is just the
FANNG-specific proof of concept, with the run knobs FANNG needs.

> **What's bundled here.** FANNG-MPC's build harness ([`docker/`](docker/)) and
> the no-AVX emulation patch ([`patches/avx_memcpy.h`](patches/avx_memcpy.h)) are
> git-untracked upstream, so copies are included here. The complete, tested
> end-to-end procedure, including running the **real FHE/BGV** offline on a
> native x86 box (required; local Apple-Silicon emulation can do `FAKE=1` only,
> and the real-FHE peak exceeds the Docker VM cap), is in
> [`NATIVE-X86-RUNBOOK.md`](NATIVE-X86-RUNBOOK.md). Both the input-recovery and
> Example 2 affine attacks were verified on native x86 under real FHE.

## How to run

Clone the upstream [Crypto-TII/FANNG-MPC](https://github.com/Crypto-TII/FANNG-MPC)
source, drop in this folder's `docker/`, `patches/`, `poc.sh`/`patcher.py`, and
`Programs/attack_*`, then build with the harness (it needs x86 AES-NI/PCLMULQDQ
and stdin IO; `patches/avx_memcpy.h` guards the AVX path for emulation):

```bash
docker/run.sh build && docker/run.sh up && docker/run.sh progs
```

Then, from this folder:

```bash
# run-attack.sh --circuit mult|affine --attack selective|recovery --real-y N [--guess-of-y G] [--x X]

# Multiplication circuit f(x, y) = x*y (the attacker fixes x = 0):
./run-attack.sh --circuit mult --attack selective --guess-of-y 5 --real-y 5    # completes iff guess == y
./run-attack.sh --circuit mult --attack selective --guess-of-y 5 --real-y 4    # aborts, so y != 5
./run-attack.sh --circuit mult --attack recovery  --real-y 12345               # recovers y = 12345, no guessing

# Affine circuit f(x; (y, r)) = x*y + r, output masked by a uniform r:
./run-attack.sh --circuit affine --attack selective --guess-of-y 1 --real-y 1  # completes iff y == 1
./run-attack.sh --circuit affine --attack recovery  --real-y 987654 --x 3      # recovers y, output stays masked

# Prepend FAKE=1 for the fast, low-memory trusted-dealer offline, e.g.
FAKE=1 ./run-attack.sh --circuit mult --attack selective --guess-of-y 5 --real-y 5
```

`run-attack.sh` installs variant 18, syncs the attack programs and poc scripts
into the running `fanng` container, runs the honest store (run 1) and the
attacker's restart (run 2), and reports the result. `--circuit` picks the
functionality and `--attack` the strength: `selective` needs `--guess-of-y` and
leaks one bit (complete vs abort); `recovery` reads `y` outright from the unmasked
MAC check with no guessing (and, since that instruments the check, it applies
`patches/offkey_recover.py` and rebuilds the runtime once before running). The
default offline is the **real FHE/BGV** preprocessing, including the per-run
`ctx_macs = Enc(alpha_i)` regeneration the attack abuses; `FAKE=1` swaps in FANNG's
trusted-dealer offline, which keeps the attack identical (it still reads
`Data/MKey-<i>.key` and runs the same online MAC check) and only bypasses the FHE
path.

> **Memory warning.** The real FHE offline (the default) peaks at ~17 GiB
> resident on variant 18 and needs a native x86 machine with around 32 GB RAM. Use FAKE=1 to run in low-memory environments.

The driver also passes two FANNG-specific knobs: **`-dOT`** skips the binary
TinyOT/OT production (the attack is purely arithmetic, so the binary engine is
unused, and this trims the real-FHE peak), and **`SCALE_IO_SIMPLE=1`** gives
stdin/stdout IO so the guess can be fed on stdin.

## Stronger attack: full input recovery

`--attack recovery` upgrades the selective-failure oracle (one bit per run) to
**full input recovery in a single run, no guessing**, exactly as in
[`../scale-mamba/README.md`](../scale-mamba/README.md) ("The input-recovery
math"). FANNG inherits SCALE-MAMBA's **unmasked** SPDZ MAC check verbatim:
`Open_Protocol::RunOpenCheck` commits to and opens each party's own check share
`tau_i`, so the batched opened sum `t = sum_k r_k (M_k - alpha' v_k)` is visible.
The recovery program opens a single off-key value `d = y - b` on its own (a fresh
square-tuple mask `b` under `alpha+1`, carried `y` under `alpha`), so
`t = r*(g - y)` with a single attacker-known coefficient `r`, and the attacker
inverts it to `y = g - t/r`. The opened `d` is uniform and leaks nothing; the
secret leaks through the unmasked check value, before the abort. With `g = 0` the
only between-runs edit is `alpha_1 -> alpha_1 + 1`.

Unlike the selective attacks (which need no source change), the recovery attacks
instrument the check, so `run-attack.sh` applies `patches/offkey_recover.py` to
the mounted source and **rebuilds the runtime once** before running. The
instrumentation is gated on `OFFKEY_RECOVER` (set only
on the attacker, Player 1); an honest party running the same binary without the
variable is unaffected. Under real FHE the offline sacrifice phase also opens
values, but only in large correctly keyed batches, so the recovery line to read
is the unique `nopen=1` online opening (the driver filters on that).

## Files

| File | What |
|---|---|
| `run-attack.sh` | The attack driver (circuit and attack type are flags; see above) against the `fanng` container |
| `poc.sh` | In-container driver (`store`/`open`/`recover`/`affine`/`affine-recover`); real FHE by default; `-dOT` + Simple IO; `FAKE=1` for trusted-dealer |
| `patcher.py` | The two between-runs edits (Player 1): `MKey-1.key`, `Memory-P1` |
| `patches/offkey_recover.py` | Env-gated (`OFFKEY_RECOVER`) instrumentation of the unmasked MAC check for recovery; attacker-only, no effect without the variable |
| `Programs/attack_store/attack_store.mpc` | Run 1: P0 inputs `y`, store in `Ms[100]` |
| `Programs/attack_open/attack_open.mpc` | Run 2 (mult, selective): load `y`, reveal `z = x·y` with `x = 0` |
| `Programs/attack_recover/attack_recover.mpc` | Run 2 (mult, recovery): load `y`, open a single off-key value `d = y - b` |
| `Programs/attack_affine/attack_affine.mpc` | Run 2 (affine, selective): load `y`, enter `x` (P1) and 64-bit mask `r` (P0), reveal `z = x*y + r` |
| `Programs/attack_affine_recover/attack_affine_recover.mpc` | Run 2 (affine, recovery): the affine output plus a standalone off-key `d = y - b` opening |

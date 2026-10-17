# Cross-Run MAC-Key Inconsistency in FANNG-MPC (Full Threshold)

FANNG-MPC is a fork of SCALE-MAMBA and inherits the cross-run off-key attack
unchanged, in both the selective-failure and full-recovery variants and on both
circuits. The vector, threat model, and analysis are identical to SCALE-MAMBA, so
this folder is only the FANNG-specific proof of concept; see
[`../scale-mamba/README.md`](../scale-mamba/README.md) for how and why the attack
works.

What differs is the build harness and a couple of run knobs. FANNG's Docker harness
([`docker/`](docker/)) and the no-AVX patch ([`patches/avx_memcpy.h`](patches/avx_memcpy.h))
are git-untracked upstream, so copies live here.

## How to run

Clone the upstream [Crypto-TII/FANNG-MPC](https://github.com/Crypto-TII/FANNG-MPC)
source, drop in this folder's `docker/`, `patches/`, `poc.sh`/`patcher.py`, and
`Programs/attack_*`, and build the container:

```bash
docker/run.sh build && docker/run.sh up && docker/run.sh progs
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

# Prepend FAKE=1 for the fast, low-memory trusted-dealer offline:
FAKE=1 ./run-attack.sh --circuit mult --attack selective --guess-of-y 5 --real-y 5
```

`run-attack.sh` syncs the attack programs and poc scripts into the running `fanng`
container, runs the honest store (run 1) and the attacker's restart (run 2), and
reports the result. The recovery attacks additionally instrument the MAC check
(`patches/offkey_recover.py`, gated on `OFFKEY_RECOVER`, which only the attacker
sets) and rebuild the runtime once. The driver also passes two FANNG-specific
knobs automatically: `-dOT` skips the unused binary-OT preprocessing, and
`SCALE_IO_SIMPLE=1` feeds inputs on stdin.

> We recommend a native x86 Linux machine with ~32 GB RAM: the default real
> FHE/BGV offline peaks at ~17 GiB on variant 18. On Apple Silicon it runs under
> linux/amd64 emulation, which is slow and too memory-constrained for the real
> offline, so use `FAKE=1` there. The tested native end-to-end procedure is in
> [`NATIVE-X86-RUNBOOK.md`](NATIVE-X86-RUNBOOK.md).

## Files

| File | What |
|---|---|
| `run-attack.sh` | The attack driver (circuit and attack type are flags; see above) |
| `poc.sh` | In-container driver: `store` / `open` / `recover` / `affine` / `affine-recover` |
| `patcher.py` | The two between-runs edits (Player 1): `MKey-1.key`, `Memory-P1` |
| `patches/offkey_recover.py` | Env-gated (`OFFKEY_RECOVER`) instrumentation of the unmasked MAC check for recovery; attacker-only |
| `patches/avx_memcpy.h` | AVX path `#ifdef`-guarded for no-AVX emulation |
| `docker/` | FANNG build harness (git-untracked upstream; copied here) |
| `Programs/attack_*` | The run-1 store and run-2 attack programs (mult/affine, selective/recovery) |

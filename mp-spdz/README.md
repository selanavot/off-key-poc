# Cross-Thread MAC-Key Inconsistency in MP-SPDZ (MASCOT)

A proof-of-concept off-key attack on **MP-SPDZ**'s MASCOT protocol: a malicious
party breaks the confidentiality of an honest party's secret input, while the
opened output reveals nothing. The honest party runs an **unmodified**
`mascot-party.x` in a separate Docker container; only the attacker's binary is
patched. MASCOT runs over a 128-bit prime field (the MP-SPDZ default).

**Off-key vector: cross-thread.** In MP-SPDZ's multi-threaded execution each
thread generates its own preprocessing, so a malicious party can use a different
MAC-key share per thread. Shares from different threads then meet in the same MAC
check, with no cross-thread consistency check to catch it: the main thread uses
key `α` and the worker thread uses `α + 1`.

Both attack strengths run on both circuits, selected by flags to `run-attack.sh`
(`--attack selective|recovery`, `--circuit mult|affine`):

- **Selective abort** (`--attack selective`): the attacker guesses `y`, and the
  check passes only if the guess was right, leaking one bit per run.
- **Full secret recovery** (`--attack recovery`): the attacker reads `y` outright
  in a single run, with no guessing, from the value opened by the unmasked MAC check.
- **Example 2** (`--circuit affine`): the same two attacks on the affine
  functionality `f(x; (y, r)) = x·y + r`, whose output is masked by a uniform `r`.

> **Fixed upstream in MP-SPDZ [v0.4.3](https://github.com/data61/MP-SPDZ/commit/982e91e7a378) (July 2026); this PoC targets the earlier pinned commit [`58d2739`](https://github.com/data61/MP-SPDZ/commit/58d2739ac251262c0bd6034f7fc7d0666a6b1e2c).**

## Threat model

Both parties run the same unmodified `.mpc` program, and the honest party runs a
stock `mascot-party.x` with no patches. Only the attacker's own binary is patched,
in two places: the per-thread key increment in `Processor/Machine.hpp`, and the
guess added to the honest input's MAC before the multiplication gate in
`Processor/Processor.hpp`.

## How to run

Requires Docker. Run from this directory (`mp-spdz/`):

```bash
# Build unmodified MP-SPDZ at the pinned pre-fix commit (one-time, ~10 min)
docker build -t mpspdz:built .

# run-attack.sh --circuit mult|affine --attack selective|recovery --real-y N [--guess-of-y G] [--x X]

# Multiplication circuit f(x, y) = x*y (the attacker fixes x = 0):
./run-attack.sh --circuit mult --attack selective --guess-of-y 7 --real-y 7   # completes iff guess == y
./run-attack.sh --circuit mult --attack selective --guess-of-y 7 --real-y 3   # aborts, so y != 7
./run-attack.sh --circuit mult --attack recovery  --real-y 42                 # recovers y = 42, no guessing

# Affine circuit f(x; (y, r)) = x*y + r to P0, output masked by a uniform r:
./run-attack.sh --circuit affine --attack selective --guess-of-y 1 --real-y 1 # completes iff y == 1
./run-attack.sh --circuit affine --attack recovery  --real-y 42 --x 3         # recovers y = 42, output stays uniform
```

`run-attack.sh` starts two Docker containers on a private network: an `honest`
party running the stock `mascot-party.x`, and an `attacker` party whose binary is
patched at runtime. `--circuit` picks the functionality and `--attack` the
strength: `selective` needs `--guess-of-y` and leaks one bit (complete vs abort);
`recovery` reads `y` outright from the unmasked MAC check with no guessing. Both
parties run the same unmodified `.mpc` program; only the attacker's binary differs.

## Files

| File | What |
|---|---|
| `Dockerfile` | Builds unmodified MP-SPDZ at the pinned pre-fix commit |
| `simple_threaded_mul.mpc` | Multiplication circuit `x·y` (Example 1) |
| `affine_eval.mpc` | Affine circuit `x·y + r` (Example 2) |
| `patch_guess.py` | The attacker's binary patches, applied at runtime |
| `run-attack.sh` | The attack driver (circuit and attack type are flags; see above) |

## The circuits

Both circuits are standard multi-threaded MP-SPDZ programs: inputs are taken on
the main thread or the worker thread, and the worker does the arithmetic. Both
parties run the exact program unmodified.

**Example 1, multiplication** (`simple_threaded_mul.mpc`): `f(x, y) = x·y`.

```python
x = MemValue(sint.get_input_from(0))   # party 0's input
y = MemValue(sint.get_input_from(1))   # party 1's input
result = sint.Array(1)

def worker():
    result[regint(0)] = x.read() * y.read()

tape = program.new_tape(worker)
program.join_tape(program.run_tape(tape, 0))
print_ln('x * y = %s', result[0].reveal())
```

This is the standard MP-SPDZ pattern, shared by programs such as `vickrey.mpc`,
`idash_train.mpc`, and `bankers_bonus.mpc`, and by anything using
`@for_range_multithread`. The attacker inputs `x = 0`, so the opened output is
always `0` and reveals nothing about `y`.

**Example 2, affine** (`affine_eval.mpc`): `f(x; (y, r)) = x·y + r`, revealed only
to P0, with `r` a uniform input of the honest party.

```python
y = MemValue(sint.get_input_from(1))   # P1's y, main thread (key α)

def worker():
    x = sint.get_input_from(0)         # P0's x, worker thread (key α+1)
    r = sint.get_input_from(1)         # P1's r, worker thread (key α+1)
    out = x * y.read() + r             # Beaver multiply under α+1
    res = out.reveal_to(0)             # one-sided output, mask known only to P0
    print_ln_to(0, 'x*y+r = %s', res)  # only P0 sees this
```

Here `y` is taken on the main thread (key `α`) while `x`, `r`, and the triple are
on the worker thread (key `α+1`). Because `r` is uniform the output is uniform for
any `x`, so it reveals nothing about `y`, which makes the leak a genuine
malicious-security violation rather than a simulatable one. See
[How it works](#how-it-works) for why the key assignment is needed.

## How it works

Each worker thread does its own base OTs and generates its own Beaver triples, so
the MAC key is bound per thread. In `Processor/Machine.hpp`, `prepare()` creates
the threads in a loop, and each reads `*(tinfo->alphapi)`, a pointer to the shared
MAC key. The attacker lets thread 0 finish initializing, then increments
`*alphapi` before thread 1 is created:

```
Thread 0: reads α,   base OTs with key α
          ↓ attacker increments α to α+1
Thread 1: reads α+1, base OTs with key α+1
```

Both threads' triples still pass the offline sacrifice check (each batch is
verified in isolation against its own key, with no cross-thread consistency check).
At end-of-tape the worker thread runs its own MAC check, under `α + 1`, on the
values it opened, including the Beaver masks `ε = x − a` and `δ = y − b`. The
carried secret `y` was authenticated under `α`, so the opening `δ = y − b` mixes
keys, and that is what the attack exploits:

- **Selective abort:** the attacker adds a guess `g` to `y`'s MAC, so the check
  passes iff `g = y`. With `x = 0` the output is always `0`, so `y` leaks only
  through pass versus abort.
- **Full secret recovery:** MP-SPDZ's default check is the *unmasked* Damgard et
  al. (2013) check, in which every party opens its own check share. The attacker
  reconstructs the off-key opening's check value and reads `y` directly, with no
  guess; the check then aborts, but the value was already opened.
- **Example 2 (affine):** the output `x·y + r` is masked by the honest party's
  uniform `r`, so it reveals nothing about `y` for any `x`, which makes the leak a
  genuine malicious-security violation. Here `x ≠ 0`, so `x`, `r`, and the triple
  are input on the worker thread (key `α + 1`) while `y` stays on the main thread
  (key `α`); only `δ = y − b` mixes keys. `run-attack.sh` samples `r` as 256
  uniform bits reduced modulo the field prime.

See the accompanying paper for the full derivation and security analysis.

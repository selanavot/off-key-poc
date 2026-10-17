# Cross-Run MAC-Key Inconsistency in SCALE-MAMBA (Full Threshold)

A proof-of-concept attack on **SCALE-MAMBA**'s Full Threshold protocol: a
malicious party recovers another party's secret input from whether the
computation aborts, never from its output.

Two parties compute `x * y`, the attacker's `x` times the honest party's secret
`y`. The attacker sets `x = 0`, so the revealed result is always `0` and tells it
nothing. But the computation runs across a stop-and-restart, and during the
restart the attacker edits two of its own files. That turns the protocol's final
MAC check into a yes/no oracle: the second run completes **only if** `y` equals a
value the attacker guessed. The honest party runs a stock SCALE-MAMBA
binary throughout; only the attacker's own files change.

## How to run

```bash
docker build --platform linux/amd64 -t scale-mamba-attack .   # one-time, ~15-20 min

# Run the attack with real pre-processing, takes a few minutes
./run-attack.sh 5 5          # correct guess -> COMPLETE -> attacker learns y = 5
./run-attack.sh 5 4          # wrong guess   -> ABORT    -> attacker learns y != 5

# Same attack with mocked preprocessing for faster iteration
FAKE=1 ./run-attack.sh 5 5 

# STRONGER attack: recover the secret outright in ONE run (no guessing)
./run-recovery.sh 12345      # attacker prints y = 12345, no guessing
FAKE=1 ./run-recovery.sh 42  # same, fast trusted-dealer offline

# EXAMPLE 2: private affine evaluation f(x;(y,r)) = x*y+r, output masked by r
FAKE=1 ./run-affine.sh 1 1   # y == guess -> COMPLETE -> attacker learns y = 1
FAKE=1 ./run-affine.sh 1 4   # y != guess -> ABORT    -> attacker learns y != 1
```

`run-attack.sh [guess] [secret]` runs the honest store (run 1) and the attacker's
restart-and-open (run 2) and reports whether the guess was right. Default offline
is real FHE/BGV (minutes per run under x86 emulation); `FAKE=1` swaps in
SCALE-MAMBA's trusted-dealer offline, which keeps the attack identical and only
bypasses the FHE path, so the FHE run stays the canonical proof below.

`run-recovery.sh [secret]` is the stronger, single-run input-recovery variant:
it recovers `y` in full rather than testing one guess. It relies on
SCALE-MAMBA using the *unmasked* MAC check; see
[The input-recovery math](#the-input-recovery-math) below.

`run-affine.sh [guess] [secret] [x]` is the private affine evaluation
(**Example 2**): `f(x; (y, r)) = x*y + r`. The honest party holds `y` (run 1) and a
mask `r` (run 2); the attacker holds `x`. Privacy wants `r` uniform over the whole
field, but the attack is independent of `r`'s distribution, and
SCALE-MAMBA's clear input path is 64-bit, so `r` is a uniform 64-bit mask —
ample for the small `x` used here (a full-field uniform mask is the theoretical ideal).
The output `x*y+r` is masked by `r` and reveals nothing about `y` — yet
complete-vs-abort still tests whether `y` equals the guess. Unlike
Example 1 (`x = 0`, whose zero output an ideal-world adversary could also
produce), leaking `y` here is a genuine violation of malicious security. It uses
the same restart tampering as `run-attack.sh`; no recovery instrumentation.

> Needs x86 AES-NI/PCLMULQDQ, so it runs under linux/amd64 emulation (slow but
> works on Apple Silicon via Docker Desktop).

## Files

| File | What |
|---|---|
| `Dockerfile` | Pinned SCALE-MAMBA build (AVX patch, variant 18, attack programs) |
| `patches/avx_memcpy.h` | AVX path `#ifdef`-guarded for no-AVX emulation. Makes local dev on MAC easier. |
| `patches/offkey_recover.py` | Env-gated (`OFFKEY_RECOVER`) instrumentation of the unmasked MAC check, so the attacker inverts the opened check value to recover `y`. Attacker-only at runtime; no effect without the variable. |
| `Programs/attack_store/attack_store.mpc` | Run 1: P0 inputs `y`, store in `Ms[100]` |
| `Programs/attack_open/attack_open.mpc` | Run 2 (selective failure): load `y`, reveal `z = x·y` with `x = 0` |
| `Programs/attack_recover/attack_recover.mpc` | Run 2 (recovery): load `y`, open a single off-key value `d = y - b` |
| `Programs/attack_affine/attack_affine.mpc` | Run 2 (Example 2): load `y`, enter `x` (P1) and 64-bit mask `r` (P0), reveal `z = x*y + r` |
| `patcher.py` | The two between-runs edits (Player 1): `MKey-1.key`, `Memory-P1` |
| `poc.sh` | In-container driver: `store <y>` / `open <baseline\|mkeyonly\|guess:G>` / `recover [g]` / `affine <baseline\|mkeyonly\|guess:G>` |
| `run-attack.sh` | Selective-failure driver: `[guess] [secret]` |
| `run-recovery.sh` | Input-recovery driver: `[secret]` |
| `run-affine.sh` | Example 2 (private affine evaluation) driver: `[guess] [secret] [x]` |

## How it works

Full Threshold authenticates every share with a MAC under a global key `α = Σ α_i`
(each party holds an additive share `α_i`) and aborts if any opened value fails
its MAC check. But `α` is not bound across runs: each run re-reads the shares from
plaintext files on disk, and authenticated secrets carry from one run to the next
unchanged. So a corrupted party can (1) change its share `α_i` between runs (edit
`Data/MKey-<i>.key`) and (2) carry a run-1 secret into run 2. The secret was MAC'd
under the old `α` but is checked under the new `α'`; that mismatch makes the MAC
check an exact equality test of the attacker's guess (see the math below).

## Why the restart path is supported

The attack rides a documented workflow: the engine is built to be stopped and
restarted as a fresh process to continue a computation, in three forms that all
reload authenticated state into a new process:

- **Reactive systems / program swap**: a restart can "replace the underlying
  schedule file and tapes" for systems where "the precise program ... is not known
  until just before execution" (`Documentation/Restart.tex`; examples
  `Programs/restart_1`, `restart_2`).
- **Crash / failure recovery**: "an online program can crash, and then a new one
  can be restarted without loosing all the offline data"
  (`Documentation/IO.tex:212-222`).
- **Checkpoint / resume**: `-memory old` reloads the dumped secret memory
  `Data/Memory-P<i>` (`Documentation/Example.tex:99-101`); shares can also move
  between runs via `output_shares`/`input_shares` (`Documentation/IO.tex:159-175`,
  example `Programs/IO_demo`), which IO.tex says "need to be ... suitably MAC'd"
  not to "break the MPC security model", the assumption this breaks.

Each restart is a fresh process, which re-reads the MAC key from
`Data/MKey-<i>.key` (`src/Player.cpp:435-447`), the window the attack needs. The
in-process `restart()` bytecode reloads only the schedule and tapes, not the key
(`src/Processor/Instruction.cpp:2830-2835`), so it is not the vector; the attack
needs the engine relaunched, which is exactly the recovery path above.

## Threat model

Both parties run the same stock `Player.x`; no binary is patched for the attack. The honest party (Player 0) supplies its real input and runs the same
programs and `-memory` flags; the sole adversarial action is Player 1 editing its
own `Data/MKey-1.key` and `Data/Memory-P1` between the two runs.

## Why FHE does not save SCALE-MAMBA

One might expect the FHE/BGV preprocessing to prevent this, since the MAC key is
used in encrypted form throughout the offline phase. It does not: SCALE-MAMBA
regenerates that encrypted key at the start of every run from the party's mutable
on-disk plaintext share, with a ZKPoK that proves only intra-run well-formedness.
Nothing carries the encrypted key between runs, commits it at setup, or ties one
run's key to another's, so a party that edits its share just gets a fresh, valid
encryption of the new value and the offline phase MACs under it. An FHE offline
would resist this only if the encrypted key were fixed once (e.g. NIZK-bound at
key generation), persisted, and changed only via authenticated broadcast;
SCALE-MAMBA does none of these across runs.

## Evidence chain (file:line in the SCALE-MAMBA clone)

**1. MAC key share is bare plaintext on disk, re-read every run, never committed.**
- Written raw by Setup: `src/Setup.cpp:237-250` (`outk << aa`, no commitment).
- Read raw at the start of every run: `src/Player.cpp:435-447` (`inp >> MacK[i]`).
- A corrupted party edits `Data/MKey-<i>.key` between runs, one field element.

**2. The encrypted MAC key is regenerated from that file every run.**
- Offline triple MACs are computed homomorphically against the *encrypted* MAC key
  `industry.ct_mac(i)`: `src/Offline/offline_FHE.cpp:183`.
- `ct_mac(i)` returns `ctx_macs[i]` (`src/Offline/FHE_Factory.h:35-54`).
- `ctx_macs` is built **fresh each run** from the on-disk `MacK` via a ZKPoK
  (`src/Offline/FHE_Factory.cpp:449-486`) that proves only intra-run
  well-formedness (a valid encryption of a constant the prover knows) and binds
  nothing to any prior run.

**3. No cross-run commitment to `α_i`.** Setup publishes no commitment; the per-run
ZKPoK proves a fresh self-consistent encryption of whatever is on disk. Nothing
compares `α_i` across runs.

**4. Authenticated secrets transfer across runs, un-re-authenticated.**
- `Share::output` serializes the value share **and** the MAC share
  (`src/LSSS/Share.cpp:351-385`); `Share::input` reads both back with no MAC check
  and no key signature (`src/LSSS/Share.cpp:387-425`).
- These back `output_shares`/`input_shares`, and the same `Share`s are dumped/
  loaded as memory (`Memory-P<i>`) under `-memory old` (`src/Online/Machine.cpp`).
  The files carry no key-binding signature, so nothing on load detects that a
  share's MAC was made under a different key than the current run's.

**5. The online MAC check is then a selective-failure oracle.**
- The check uses the **current run's local key** `P.get_mac_key(j)` against the
  **loaded share's MAC**, opens `τ`, and aborts on `Σ τ ≠ 0`:
  `src/LSSS/Open_Protocol.cpp:226-260`.

## The selective-failure math

A secret `v` is created in run 1 under the global key `α = Σ α_i`, so the parties'
MAC shares satisfy `Σ m_i = α·v`. It is carried to run 2, where the corrupted
party (party 1 in the PoC) increments its key share `α_1 → α_1 + 1` (global key
becomes `α' = α + 1`) and adds a guess `g` to its loaded share of `v`'s MAC
(`m_1 → m_1 + g`). When `v` (or a value derived from it, e.g. a Beaver mask
opening `v − a`) is checked in run 2, the MAC residual is:

```
Σ_i ( m_i − α_i^current · v )
  = ( m_1 + g − (α_1 + 1)·v ) + Σ_{i≠1} ( m_i − α_i·v )
  = ( Σ m_i − α·v )  +  g − v
  = g − v
```

The check passes **iff `g = v`**: a direct equality test of the attacker's guess
against the honest secret.

## The input-recovery math

The selective-failure attack above learns only one bit (pass/abort). The stronger
attack learns `v` outright, because SCALE-MAMBA uses the *unmasked* SPDZ MAC check
(Damgard et al., 2013), not a masked one. In `RunOpenCheck`
(`src/LSSS/Open_Protocol.cpp`) each party commits to and then opens its own share

```
τ_i = γ_i − a·α_i^current,   with  a = Σ_k r_k·v_k,  γ_i = Σ_k r_k·m_{k,i}
```

for jointly random, public coefficients `r_k` over the openings `k` batched into
the check. The opened sum is therefore not hidden:

```
t = Σ_i τ_i = Σ_k r_k·( M_k − α'·v_k )
```

where `M_k = Σ_i m_{k,i}` is the reconstructed MAC of opening `k`. Every correctly
authenticated opening contributes `0`. The recovery program opens a **single**
off-key value `d = y − b` on its own (`b` a fresh square-tuple mask, so it is
authenticated under the current run's key `α' = α + 1`, while `y` was carried under
`α`). That one opening is the only nonzero term:

```
M_d − α'·d = ( α·y + g ) − α'·b − α'·(y − b) = g − y
```

so `t = r·(g − y)` with a single coefficient `r` the attacker itself drew. It
inverts this to

```
y = g − t / r
```

The attacker already holds every `τ_i` after the commit-and-open, so it reads `y`
in one run, even though the check then aborts (`t ≠ 0`) and the opened value
`d = y − b` is uniform and reveals nothing on its own. With `g = 0` the only
between-runs edit needed is `α_1 → α_1 + 1`; no MAC-tag edit and no guessing.

Under real FHE preprocessing the offline (sacrifice) phase also opens values, but
always in large, correctly keyed batches (tens of thousands at once, all with
residual 0). The online opening of `d` is a single-value check, so the recovery
line to read is the unique `nopen=1` opening; `poc.sh` filters on that. The
instrumentation skips the large offline batches for the same reason. The attack is
otherwise identical in both offline modes: `FAKE=1` (trusted dealer) and the real
FHE/BGV offline both recover `y`, confirming FHE does not bind the key across runs.

The instrumentation (`patches/offkey_recover.py`) performs exactly this inversion,
gated on `OFFKEY_RECOVER`, which only the malicious party sets. It reads state the
party already has and changes no message sent nor the accept/abort decision, so an
honest party running the same binary without the variable is unaffected. This is the distinction between the masked MAC check (which reduces the attack to selective failure) and the unmasked check (which leaks the input outright).
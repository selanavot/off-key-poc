# FANNG-MPC real-FHE attack on native x86 -- runbook

How to reproduce the **real-FHE** cross-run MAC-key attack on FANNG-MPC end to
end on a cheap native-x86 cloud box. Written 2026-06-21 after doing exactly this
on Hetzner. Covers: why it would not run on the Mac, how we solved it, the cloud
setup, and the exact commands. The findings themselves are summarized in the PoC READMEs; this is the operational "come back to it" guide.

Result it produces: the full selective-failure truth table on the unmodified
FANNG `PlayerBinary.x` under the real FHE offline -- COMPLETE iff the attacker's
guess equals the honest secret, output `z=0` throughout. Confirmed for secrets
y in {0, 5, 7, 5423}. Raw logs in `native-x86-evidence/`.

---

## 1. Why it would not run on the Mac

- This Mac is Apple Silicon (arm64). FANNG requires x86 AES-NI / PCLMULQDQ, so we
  ran it under Docker's `linux/amd64` emulation (Rosetta) in an Ubuntu 20.04
  container. See [FANNG-MPC/docker/](the FANNG-MPC docker/ harness).
- Docker Desktop on macOS runs everything inside a **Linux VM with a fixed RAM
  cap**. On the 24 GB Mac the usable cap topped out around **18 GiB** (we set
  `MemoryMiB` in Docker's `settings-store.json`; 20 GiB hung the engine).
- The **real FHE** store peaks at **~17-19 GiB resident** (both players together).
  That exceeds the ~18 GiB VM cap, so player 1 dies with a `bad_alloc` cascade in
  the FHE offline. The online phase would sometimes squeak through, but a full
  run could not finish.
- The trusted-dealer **FAKE** offline avoids the OOM (no FHE threads), and the
  full truth table reproduces under FAKE -- but FAKE bypasses the FHE `ctx_macs`
  regeneration, which is the actual vulnerable path. So FAKE alone "does not
  count" as proof that real FHE is broken.
- Two **wrong** Mac-era diagnoses (corrected after further analysis): it is NOT a
  binary-engine difference (both SCALE-MAMBA and FANNG use `Etype=HSS`), and it is
  NOT FANNG's `kdaBitsPerLoop=65536` (on native, 8192 vs 65536 changes the peak by
  ~0.1 GiB). The peak is just FANNG's concurrent FHE + binary-OT preprocessing,
  and it simply did not fit under the Mac's VM cap.

## 2. How we solved it

A **native x86 Linux box with >= 32 GB RAM**. On native Linux, Docker uses host
memory directly (no VM cap) and there is no Rosetta translation overhead, so the
~18 GiB peak fits with headroom and the real FHE offline runs to completion. We
still build/run inside an Ubuntu 20.04 container (FANNG needs OpenSSL 1.1 + the
right deps; the host is 22.04), but on a native amd64 host that container runs at
full speed.

## 3. Provision a cloud box (Hetzner)

Provider notes from the shopping-around:
- **DigitalOcean**: new accounts are capped (we could only get 4 GB). Skip.
- **Vultr**: requires a **non-refundable $10 prepaid deposit** for new accounts.
  Works, but you eat ~$9 of leftover credit.
- **Hetzner**: bills hourly, **no deposit**, cheapest. Used this. (Possible
  one-time ID verification at signup.)

Steps:
1. Sign up at **console.hetzner.cloud**, add a payment method, create a project.
2. **Security -> SSH Keys -> Add SSH Key**: paste your `~/.ssh/id_ed25519.pub`.
3. **Add Server**:
   - Location: a US region (Ashburn / Hillsboro) or whatever is closest.
   - Image: **Ubuntu 22.04**.
   - Type: **Shared vCPU -> CPX** tab (AMD/x86). **Not the CAX tab -- that is ARM.**
   - Size: anything with **>= 32 GB RAM**. `CPX51` (16 vCPU / 32 GB, ~EUR 0.10/hr)
     is plenty; we actually used an 8 vCPU / 32 GB dedicated (CCX) box at
     ~EUR 0.27/hr, which is overkill -- the bottleneck is RAM, not CPU.
   - Tick your SSH key. Leave volumes/firewall/backups off. **Create & Buy now.**
4. Grab the public IPv4. Sanity check: `ssh root@<IP> 'uname -m; nproc; free -h'`
   should show `x86_64`, 8 cores, ~30 GiB free.

Cost was ~EUR 0.27/hr; a full reproduction is ~1-2 hours of box time.
**Billing stops only when you DELETE the server** in the console (power-off does
not stop it).

## 4. Set up FANNG on the box (run these from the Mac)

Set `BOX` to the new IP (we used `<BOX_IP>`):

```bash
BOX=<BOX_IP>
```

**4a. Install Docker:**
```bash
ssh root@$BOX 'curl -fsSL https://get.docker.com | sh'
# smoke test: a native 20.04 container should run in ~1s, arch x86_64
ssh root@$BOX 'docker run --rm ubuntu:20.04 uname -m'
```

**4b. Ship the FANNG tree.** Do NOT `git clone` upstream -- the `docker/` harness
and the attack `poc/` are **git-untracked**, so they only exist in the local
working tree. Use `tar | ssh` (macOS ships an ancient rsync that rejects modern
flags). Exclude the 236 MB `.git`, the 479 MB Rust `target/`, and rebuildable
binaries:
```bash
cd <your FANNG-MPC checkout>
tar czf - --exclude='.git' --exclude='target' \
    --exclude='*.o' --exclude='*.x' --exclude='*.a' --exclude='.depend' . \
  | ssh root@$BOX 'mkdir -p /root/fanng && tar xzf - -C /root/fanng'
```
(The local tree must contain `docker/`, `poc/poc.sh`, `poc/patcher.py`,
`Programs/attack_store/` + `attack_open/` with their pre-compiled `*.bc`/`*.sch`,
and `Auto-Test-Data/18`. The pre-compiled bytecode means you never need the Rust
scasm compiler on the box.)

**4c. Build the image** (MPIR 3.0.0 + crypto++ 8.2.0 from source, ~few min native):
```bash
ssh root@$BOX 'cd /root/fanng && ./docker/run.sh build'
```

**4d. Build the C++ runtime with NATIVE flags.** The harness's `progs` target uses
reduced no-AVX flags meant for emulation; on a native box build with
`-march=native` instead (AVX2 used, the `avx_memcpy.h` guard becomes transparent):
```bash
ssh root@$BOX 'cd /root/fanng && ./docker/run.sh up && \
  ./docker/run.sh exec "make -C src ARCH=-march=native -j\$(nproc)"'
# produces /root/fanng/PlayerBinary.x (~25 MB) and SetupBinary.x
```

**4e. Install variant 18 data + certs:**
```bash
ssh root@$BOX 'cd /root/fanng && ./docker/run.sh variant 18'
```

**4f. Install python3 in the container** (the image only has python2; `patcher.py`
needs python3 -- see gotchas):
```bash
ssh root@$BOX 'docker exec fanng bash -c "apt-get update -qq && apt-get install -y -qq python3"'
```

## 5. Run the attack

The driver is `/fanng/poc/poc.sh` inside the container. Real FHE is the default
(`FAKE` unset; NetworkData fake-flags are `0 0`). One store (run 1) then one or
more opens (run 2):

```bash
# real FHE, full binary engine (no -dOT) -- the fully-stock config:
DEX() { ssh root@$BOX "docker exec -e POC_ROOT=/fanng -e QUIET=1 -e 'PLAYER_FLAGS= ' -i fanng bash -lc 'bash /fanng/poc/poc.sh $*'"; }

DEX store 5            # P0 stores secret y=5 under the real MAC
DEX open baseline     # -> COMPLETE  (no tamper)
DEX open mkeyonly     # -> ABORT     (alpha_1 += 1; COMPLETE only if y==0)
DEX open guess:5      # -> COMPLETE  (guess == y)
DEX open guess:4      # -> ABORT     (guess != y)
```

Knobs:
- `-e 'PLAYER_FLAGS= '` (a literal space) runs the **full binary engine**. Omit it
  to fall back to poc.sh's default `-dOT`, which skips the unused binary-OT
  subsystem and shaves ~2 GiB (16.9 vs 18.6 GiB). Both give the identical table;
  `-dOT` does not touch the FHE/MAC path. (A space is needed because poc.sh uses
  `${PLAYER_FLAGS:--dOT}`, which treats an empty string as unset.)
- For the **trusted-dealer** comparison run, add `-e FAKE=1` (fast, no FHE).
- Fully-stock `kdaBitsPerLoop`: the shipped local source has it at **8192** (the
  Mac value). For a faithful FANNG-stock run set it to **65536** and rebuild:
  `ssh root@$BOX "sed -i 's/kdaBitsPerLoop 8192/kdaBitsPerLoop 65536/' /root/fanng/src/config.h"`
  then redo step 4d (`make -C src clean` first). It still fits in 32 GB (peak 18.7 GiB).

## 6. Gotchas (the things that cost time)

- **`docker/` and `poc/` are git-untracked** -> ship the local tree (tar+ssh), do
  not clone upstream.
- **No python3 in the container** -> `patcher.py` silently fails and *every* open
  COMPLETEs (looks like the attack is broken / no selective failure). The tell is
  `python3: command not found` in the output. Install python3 (step 4f).
- **macOS rsync is too old** for `--info=progress2` etc. -> use `tar | ssh`.
- **Build flags**: use `-march=native`, not the harness's emulation no-AVX flags.
- **`SCALE_IO_SIMPLE`** (already patched into `src/Player.cpp`) is what lets the
  attacker feed the guess on stdin; poc.sh exports it. It is the only non-stock
  code that runs in the proof; it touches no crypto.
- **Memory peak ~18.7 GiB** -> need >= 32 GB. 16 GB is too tight.
- **Billing**: delete the server to stop it; power-off does not.

## 7. Results (what you should see)

| config (real FHE, variant 18) | resident peak | truth table |
|---|---|---|
| `-dOT`, kdaBitsPerLoop=8192 | 16.9 GiB | COMPLETE iff guess==y |
| full engine, kdaBitsPerLoop=8192 | 18.6 GiB | same |
| full engine, kdaBitsPerLoop=65536 (stock) | 18.7 GiB | same |

Multi-value (fully-stock): y in {0, 7, 5423}, each correct guess COMPLETE and each
wrong guess ABORT, `z=0` in all runs. Logs:
- `native-x86-evidence/real-fhe-native-runs.log`
- `native-x86-evidence/multi-value-secrets.log`

## 8. Teardown

Pull anything you need to the Mac first (the evidence logs above are already
pulled). Then in the Hetzner console: **Servers -> (your server) -> ... -> Delete**.
That is the only thing that stops billing.

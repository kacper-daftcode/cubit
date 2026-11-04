#!/usr/bin/env python3
"""GPU side of the SM120 stall-floor harness (see stallfloor_gen.py; runs inside R's night block).

    python3 stallfloor_run.py kernels_stall/ [--reps 20] [--out out/stall_floors.json]

For every kernel of index.json: launch 32 CTAs x 1024 threads `reps` times, compare each thread's
checksum with the reference of the path, count mismatching threads. The reference is the CPU model,
validated first against the path's `sf_<path>_ref` kernel (tested edge behind a scoreboard, every
other edge at S15): a mismatch there means the model (not the silicon) is wrong and the path is
reported MODEL_MISMATCH. `mufu` has no CPU model (MUFU.RCP is an approximation): its reference is the
`_ref` kernel's own output, and the path is the variable-latency control - it is expected to mismatch
at every stall. Output: per path and distance the minimum stall with zero mismatches over all
repetitions and all larger stalls, in the layout of the `stallfix` section (`floor_<path>_d<d>`),
plus the raw mismatch table.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from culaunch import Cuda  # noqa: E402

M32 = 0xffffffff
THREADS, CTAS = 1024, 32


def u32(x):
    return x & M32


def model(path, seed, gid, repeat):
    """CPU model of sf_<path>_* (stallfloor_gen.py v3): R4 = seed + gid, R5 = gid ^ 0x5bd1e995, R8 = 0,
    UR8 = 1, UR9 = 0, P0 = UP0 = false; per iteration producer, consumer, R10 += effect, then the rotation."""
    base = gid >> 5 if path == "r2ur" else gid  # v3: r2ur inputs are warp-uniform (R2UR broadcasts one lane)
    a = u32(seed + base)
    b = u32(base ^ 0x5bd1e995)  # LOP3 0x3c = a ^ b
    chk = 0
    r8 = 0
    ur8, ur9 = 1, 0
    for _ in range(repeat):
        if path == "rpath":
            r8 = u32(u32(a + b) + b)
        elif path == "pcarry":
            r8 = a if a < b else b
        elif path == "guard":
            if a < b:
                r8 = u32(a + b)
        elif path == "dmix":
            r6 = u32(a * b)  # low word of the 64-bit product; carry-out P0 = 0 (RZ addend)
            r8 = u32(r6 + b)
        elif path == "xchain":
            r6 = u32(a + b + 1)  # cin PT = 1, second cin !PT = 0
            carry = 1 if (a + b + 1) > M32 else 0
            r8 = u32(r6 + b + carry)
        elif path == "mufu":
            return None  # MUFU.RCP is an approximation: the reference is the sf_mufu_ref kernel
        elif path == "urpath":
            ur8 = u32(ur8 + 3); ur9 = u32(ur8 + 5)
        elif path == "xread":
            ur8 = u32(ur8 + 3); r8 = u32(a + ur8)
        elif path == "r2ur":
            ur9 = u32(a + b)
        elif path == "uguard":
            if ur8 < 0x80000000:
                ur9 = u32(ur9 + 5)
        eff = ur9 if path in ("urpath", "r2ur", "uguard") else r8
        chk = u32(chk + eff)
        a = u32(a + 0x9e3779b9); b = u32(b + 0x7f4a7c15)
        if path == "uguard":
            ur8 = u32(ur8 + 0x40000001)
    return chk


def run(cu, kdir, entry, seed):
    fn = cu.load_kernel(os.path.join(kdir, entry["cubin"]), entry["name"])
    n = THREADS * CTAS
    d_out = cu.alloc(n * 4)
    cu.memset32(d_out, 0, n)
    cu.launch(fn, grid=(CTAS, 1, 1), block=(THREADS, 1, 1), args=[d_out, ctypes.c_uint32(seed)])
    cu.synchronize()
    out = cu.from_device(d_out, n * 4, dtype=np.uint32)
    cu.free(d_out)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kdir")
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--out", default=os.path.join(HERE, "out", "stall_floors.json"))
    ap.add_argument("--device", type=int, default=0)
    args = ap.parse_args()
    index = json.load(open(os.path.join(args.kdir, "index.json")))
    cu = Cuda(args.device)
    seed = 0x12345
    results = {}
    expected = {}
    model_check = {}
    refs = {e["path"]: e for e in index if e.get("reference")}
    for path, ref in sorted(refs.items()):
        gpu_ref = run(cu, args.kdir, ref, seed).astype(np.int64)
        m = model(path, seed, 0, ref["repeat"])
        if m is None:
            expected[path] = gpu_ref
            model_check[path] = "GPU_REFERENCE"
            print(f"OBSERVED {ref['name']}: no CPU model, the scoreboarded kernel's output is the reference")
            continue
        cpu = np.array([model(path, seed, g, ref["repeat"]) for g in range(THREADS * CTAS)], dtype=np.int64)
        bad = int(np.count_nonzero(cpu != gpu_ref))
        expected[path] = cpu
        model_check[path] = bad
        print(("PASS" if bad == 0 else "FAIL") + f" model_{path}: {bad} threads differ between the CPU model and {ref['name']} (scoreboarded)")
    for e in sorted((e for e in index if not e.get("reference")), key=lambda e: (e["path"], e["distance"], -e["stall"])):
        key = (e["path"], e["distance"])
        exp = expected.get(e["path"])
        if exp is None:
            print(f"SKIP {e['name']}: no reference kernel for the path")
            continue
        mism = 0
        for _ in range(args.reps):
            out = run(cu, args.kdir, e, seed).astype(np.int64)
            mism += int(np.count_nonzero(out != exp))
        results.setdefault(f"{key[0]}_d{key[1]}", {})[e["stall"]] = mism
        print(f"OBSERVED {e['name']}: {mism} mismatching threads over {args.reps} runs")
    floors = {}
    for pd, by_stall in results.items():
        path = pd.rsplit("_d", 1)[0]
        smax = max(by_stall)
        if model_check.get(path) not in (0, "GPU_REFERENCE"):
            floors[pd] = "MODEL_MISMATCH"
            print(f"FAIL {pd}: the CPU model disagrees with the scoreboarded reference kernel, no floor derived")
            continue
        if by_stall[smax] != 0:
            floors[pd] = "NEEDS_SCOREBOARD"
            print(f"OBSERVED {pd}: {by_stall[smax]} mismatches at S{smax:02d} with a proven reference - no stall count closes this edge (variable latency, scoreboard required)")
            continue
        ok = sorted(s for s, m in by_stall.items() if m == 0)
        floor = min(s for s in ok if all(by_stall[t] == 0 for t in by_stall if t >= s))
        floors[pd] = floor
        print(f"PASS floor_{pd} = S{floor:02d} (mismatches per stall: {dict(sorted(by_stall.items()))})")
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump({"arch": "sm_120", "threads": THREADS, "ctas": CTAS, "reps": args.reps, "harness": "v2 (2026-11-03)",
               "model_check": model_check, "floors": floors, "mismatches": results}, open(args.out, "w"), indent=1)
    print(f"written {args.out}")
    cu.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

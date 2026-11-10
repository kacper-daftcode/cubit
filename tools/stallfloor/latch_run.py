#!/usr/bin/env python3
"""GPU side of the SM120 store-latch probe (see latch_gen.py): pairfloor_run.py (harness v5) with a per-kernel
geometry (`ctas`, `threads`, `out_scale` in index.json).

    python3 latch_run.py <kernel dir> [--reps 10] [--out latch.json] [--limit-s N]

Per pair: the reference kernel (producer at S15 in front of the consumer) is launched three times; its output must
be identical in all three (else the pair is INVALID: the oracle itself is not stable) and is the expected checksum.
Then every (distance, stall[, yield]) kernel: 32 CTAs x 1 024 threads x `reps` launches, mismatching threads counted.
Floor = the smallest stall with 0 mismatches such that every larger stall of the sweep is clean; `NONE` when the
largest stall of the sweep is still wrong. Lines: `FLOOR <pair> d<d> = Sxx | <mismatches per stall>`.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from culaunch import Cuda  # noqa: E402

THREADS, CTAS = 1024, 32


_TAB = {}


def run(cu, kdir, entry, seed):
    """Per-entry geometry: `ctas` CTAs x 1 024 threads; the output buffer holds `out_scale` words per thread (the
    kernel's checksum is the first; the store-latch kernels use the second half as the threads' private slot B)."""
    fn = cu.load_kernel(os.path.join(kdir, entry["cubin"]), entry["name"])
    ctas = int(entry.get("ctas", CTAS))
    threads = int(entry.get("threads", THREADS))      # block size; the buffer keeps 1 024 words per CTA (gid = ctaid * 1024 + tid)
    scale = int(entry.get("out_scale", 1))
    n = THREADS * ctas
    d_out = cu.alloc(n * 4 * scale)
    if scale > 1 and (d_out.value & 0xFFFFFFFF) + n * 4 * scale >= 2 ** 32:
        cu.free(d_out)        # a torn 64-bit address (new low word, old high word) must stay inside the buffer
        raise RuntimeError("output buffer straddles a 4-GiB boundary: kernel skipped")
    cu.memset32(d_out, 0, n * scale)
    cu.launch(fn, grid=(ctas, 1, 1), block=(threads, 1, 1), args=[d_out, ctypes.c_uint32(seed)])
    cu.synchronize()
    out = cu.from_device(d_out, n * 4, dtype=np.uint32)
    cu.free(d_out)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kdir")
    ap.add_argument("--reps", type=int, default=10)
    ap.add_argument("--out", default="floors.json")
    ap.add_argument("--device", type=int, default=0)
    ap.add_argument("--limit-s", type=float, default=1e9)
    args = ap.parse_args()
    t0 = time.time()
    index = json.load(open(os.path.join(args.kdir, "index.json")))
    cu = Cuda(args.device)
    seed = 0x12345
    refs = {e["pair"]: e for e in index if e.get("reference")}
    expected, ref_state = {}, {}
    for pair, ref in sorted(refs.items()):
        try:
            outs = [run(cu, args.kdir, ref, seed) for _ in range(3)]
        except Exception as e:  # a kernel that does not load / launch: name it, keep going
            ref_state[pair] = f"ERROR {str(e)[:120]}"
            print(f"FAIL ref {pair}: {ref_state[pair]}", flush=True)
            continue
        stable = all(np.array_equal(outs[0], o) for o in outs[1:])
        nz = int(np.count_nonzero(outs[0]))
        nthreads = int(outs[0].size)
        distinct = int(len(np.unique(outs[0])))
        if not stable:
            ref_state[pair] = "UNSTABLE"
            print(f"FAIL ref {pair}: the S15 reference kernel is not deterministic", flush=True)
            continue
        expected[pair] = outs[0].astype(np.int64)
        ref_state[pair] = f"ok ({distinct} distinct checksums, {nz} non-zero of {nthreads})"
        # the checksum is a function of the thread's index in its block: a block of T threads cannot show more than T
        # values (+ 0 for the words no thread owns)
        if distinct < min(64, int(ref.get("threads", THREADS))):
            ref_state[pair] += " WEAK"       # the checksum does not depend on the inputs enough to see a stale read
            print(f"FAIL ref {pair}: only {distinct} distinct checksums - the pair's effect does not reach the checksum", flush=True)
    results, skipped = {}, 0
    for e in sorted((e for e in index if not e.get("reference")), key=lambda e: (e["pair"], e["distance"], -e["stall"])):
        if time.time() - t0 > args.limit_s:
            skipped += 1
            continue
        exp = expected.get(e.get("ref_pair", e["pair"]))
        if exp is None:
            continue
        mism = 0
        try:
            for _ in range(args.reps):
                out = run(cu, args.kdir, e, seed).astype(np.int64)
                mism += int(np.count_nonzero(out != exp))
        except Exception as ex:
            mism = -1
            print(f"FAIL {e['name']}: {str(ex)[:120]}", flush=True)
        results.setdefault((e["pair"], e["distance"]), {})[e["stall"]] = mism
    floors = {}
    cells = []
    meta = {}
    for e in index:
        meta[e["pair"]] = e["cell"]
    for (pair, d), by in sorted(results.items()):
        smax = max(by)
        if any(v < 0 for v in by.values()):
            floor = "ERROR"
        elif by[smax] != 0:
            floor = "NONE"
        else:
            floor = min(s for s in by if by[s] == 0 and all(by[t] == 0 for t in by if t >= s))
        floors[f"{pair}_d{d}"] = floor
        tab = " ".join(f"S{s}:{by[s]}" for s in sorted(by))
        print(f"FLOOR {pair} d{d} = {('S%02d' % floor) if isinstance(floor, int) else floor} [{meta.get(pair, '')}] | {tab}", flush=True)
        if d == 0 and "+Y" not in pair and "/" not in pair and isinstance(floor, int) and not pair.startswith("arm_"):
            try:
                p, rest = meta[pair].split(" -> ")
                c, role = rest.rsplit(" ", 1)
                cells.append({"producer": p, "consumer": c, "role": role, "floor_d0": floor, "pair": pair})
            except ValueError:
                pass
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    json.dump({"arch": "sm_120", "threads": THREADS, "ctas": "per kernel (index.json)", "reps": args.reps, "harness": "v5 store-latch probe (2026-11-10)",
               "gpu": cu.device_name() if hasattr(cu, "device_name") else "", "references": ref_state, "floors": floors,
               "mismatches": {f"{p}_d{d}": by for (p, d), by in results.items()}, "cells": cells, "skipped": skipped},
              open(args.out, "w"), indent=1)
    print(f"written {args.out} ({len(floors)} floors, {skipped} kernels skipped by the time limit, {time.time() - t0:.0f} s)", flush=True)
    cu.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

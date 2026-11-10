#!/usr/bin/env python3
"""GPU side of the SM120 pair stall-floor harness v5e (kernels of pairfloor_gen_e.py; also runs the directories of
pairfloor_gen.py / _b / _c). pairfloor_run.py with one more kind of third kernel parameter:

  index entry `table`    4 096 random words, shared by all threads (read only)
  index entry `scratch`  N zeroed bytes per thread (a global store's address probe writes its own words there)

and a process per pair on request (`--isolate`): a probe that faults (CUDA error 700) ends its own process only.

    python3 pairfloor_run_e.py <kernel dir> [--reps 20] [--out floors.json] [--limit-s N] [--pairs a,b] [--isolate]

Per pair: the S15 reference kernel is launched three times; its output must be identical in all three and is the
expected checksum. Then every (distance, stall) kernel: 32 CTAs x 1 024 threads x `reps` launches, mismatching threads
counted. Floor = the smallest stall with 0 mismatches such that every larger stall of the sweep is clean. For the MMA
sweeps (`<pair>/pad<n>`: distance = S + 15 * n) the line `MMAFLOOR` gives the smallest clean distance over both pads.
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import subprocess
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

THREADS, CTAS = 1024, 32
_BUF = {}


def run(cu, kdir, entry, seed):
    fn = cu.load_kernel(os.path.join(kdir, entry["cubin"]), entry["name"])
    n = THREADS * CTAS
    d_out = cu.alloc(n * 4)
    cu.memset32(d_out, 0, n)
    largs = [d_out, ctypes.c_uint32(seed)]
    if entry.get("table"):
        if "tab" not in _BUF:
            _BUF["tab"] = cu.to_device(np.random.RandomState(7).randint(0, 2 ** 32, size=4096, dtype=np.uint64).astype(np.uint32))
        largs.append(_BUF["tab"])
    elif entry.get("scratch"):
        per = int(entry["scratch"])
        if ("scr", per) not in _BUF:
            _BUF[("scr", per)] = cu.alloc(n * per)
        cu.memset32(_BUF[("scr", per)], 0, n * per // 4)
        largs.append(_BUF[("scr", per)])
    cu.launch(fn, grid=(CTAS, 1, 1), block=(THREADS, 1, 1), args=largs)
    cu.synchronize()
    out = cu.from_device(d_out, n * 4, dtype=np.uint32)
    if hasattr(cu, "free"):
        cu.free(d_out)
    return out


def measure(args, index, pairs):
    from culaunch import Cuda
    cu = Cuda(args.device)
    t0 = time.time()
    seed = 0x12345
    refs = {e["pair"]: e for e in index if e.get("reference") and (not pairs or e["pair"] in pairs)}
    expected, ref_state = {}, {}
    for pair, ref in sorted(refs.items()):
        try:
            outs = [run(cu, args.kdir, ref, seed) for _ in range(3)]
        except Exception as e:  # noqa: BLE001
            ref_state[pair] = f"ERROR {str(e)[:120]}"
            print(f"FAIL ref {pair}: {ref_state[pair]}", flush=True)
            continue
        stable = all(np.array_equal(outs[0], o) for o in outs[1:])
        nz = int(np.count_nonzero(outs[0]))
        distinct = int(len(np.unique(outs[0])))
        if not stable:
            ref_state[pair] = "UNSTABLE"
            print(f"FAIL ref {pair}: the S15 reference kernel is not deterministic", flush=True)
            continue
        expected[pair] = outs[0].astype(np.int64)
        ref_state[pair] = f"ok ({distinct} distinct checksums, {nz} non-zero of {THREADS * CTAS})"
        if distinct < 64:
            ref_state[pair] += " WEAK"
            print(f"FAIL ref {pair}: only {distinct} distinct checksums - the pair's effect does not reach the checksum", flush=True)
    results, skipped = {}, 0
    todo = [e for e in index if not e.get("reference") and (not pairs or e.get("ref_pair", e["pair"]) in pairs)]
    for e in sorted(todo, key=lambda e: (e["pair"], e["distance"], -e["stall"])):
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
        except Exception as ex:  # noqa: BLE001
            mism = -1
            print(f"FAIL {e['name']}: {str(ex)[:120]}", flush=True)
        results.setdefault((e["pair"], e["distance"]), {})[e["stall"]] = mism
    return ref_state, results, skipped


def report(args, index, ref_state, results, skipped, t0):
    floors, cells, meta = {}, [], {}
    for e in index:
        meta[e["pair"]] = e["cell"]
    mma = {}
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
        if "/pad" in pair:
            base, npad = pair.split("/pad")
            for s, v in by.items():
                mma.setdefault(base, {})[s + 15 * int(npad)] = v
        if d == 0 and "+Y" not in pair and "/" not in pair and isinstance(floor, int) and not pair.startswith("arm_"):
            try:
                p, rest = meta[pair].split(" -> ")
                c, role = rest.rsplit(" ", 1)
                cells.append({"producer": p, "consumer": c, "role": role, "floor_d0": floor, "pair": pair})
            except ValueError:
                pass
    mma_floors = {}
    for base, by in sorted(mma.items()):
        dmax = max(by)
        if any(v < 0 for v in by.values()):
            fl = "ERROR"
        elif by[dmax] != 0:
            fl = "NONE"
        else:
            fl = min(d for d in by if by[d] == 0 and all(by[t] == 0 for t in by if t >= d))
        mma_floors[base] = fl
        wrong = [d for d in sorted(by) if by[d] != 0]
        print(f"MMAFLOOR {base} = {fl} [{meta.get(base + '/pad0', '').split(' (')[0]}] | wrong at distances {wrong if wrong else 'none'} of 1..{dmax}", flush=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    json.dump({"arch": "sm_120", "threads": THREADS, "ctas": CTAS, "reps": args.reps, "harness": "v5e pair floors (2026-11-10)",
               "references": ref_state, "floors": floors, "mma_floors": mma_floors,
               "mismatches": {f"{p}_d{d}": by for (p, d), by in results.items()}, "cells": cells, "skipped": skipped},
              open(args.out, "w"), indent=1)
    print(f"written {args.out} ({len(floors)} floors, {skipped} kernels skipped by the time limit, {time.time() - t0:.0f} s)", flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kdir")
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--out", default="floors.json")
    ap.add_argument("--device", type=int, default=0)
    ap.add_argument("--limit-s", type=float, default=1e9)
    ap.add_argument("--pairs", default="")
    ap.add_argument("--isolate", action="store_true", help="one process per pair")
    ap.add_argument("--worker", default="", help="internal: measure these pairs and dump the raw result")
    args = ap.parse_args()
    t0 = time.time()
    index = json.load(open(os.path.join(args.kdir, "index.json")))
    allp = sorted({e["pair"] for e in index if e.get("reference")})
    pairs = [p for p in args.pairs.split(",") if p] or allp
    if args.worker:
        ref_state, results, skipped = measure(args, index, set(pairs))
        json.dump({"refs": ref_state, "results": [[p, d, by] for (p, d), by in results.items()], "skipped": skipped}, open(args.worker, "w"))
        return 0
    if not args.isolate:
        ref_state, results, skipped = measure(args, index, set(pairs))
    else:
        ref_state, results, skipped = {}, {}, 0
        for p in pairs:
            left = args.limit_s - (time.time() - t0)
            if left <= 5:
                skipped += sum(1 for e in index if not e.get("reference") and e.get("ref_pair", e["pair"]) == p)
                continue
            tmp = f"{args.out}.{p}.part"
            cmd = [sys.executable, os.path.abspath(__file__), args.kdir, "--reps", str(args.reps), "--device", str(args.device),
                   "--limit-s", str(left), "--pairs", p, "--worker", tmp, "--out", args.out]
            r = subprocess.run(cmd, capture_output=True, text=True)
            for l in r.stdout.splitlines():
                if l.startswith("FAIL"):
                    print(l, flush=True)
            if r.returncode or not os.path.exists(tmp):
                ref_state[p] = f"ERROR worker rc={r.returncode} {r.stderr.strip()[-160:]}"
                print(f"FAIL pair {p}: {ref_state[p]}", flush=True)
                continue
            j = json.load(open(tmp)); os.remove(tmp)
            ref_state.update(j["refs"]); skipped += j["skipped"]
            for pp, d, by in j["results"]:
                results[(pp, d)] = {int(k): v for k, v in by.items()}
    report(args, index, ref_state, results, skipped, t0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

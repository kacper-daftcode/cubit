#!/usr/bin/env python3
"""GPU side of the SM120 stall-floor harness v6 (populations per table cell; see cellfloor_gen.py).

    python3 cellfloor_run.py <kernel dir> [--reps 3] [--out cells.json] [--limit-s N]

Per cell: the reference kernel (producer at S15) three times -> must be identical (else the cell is INVALID) and is the
expected checksum of every kernel of the cell. Then every kernel (random registers / yield / neighbours) at the cell's
latency L and at L - 1: 32 CTAs x 1 024 threads x 256 iterations x `reps` launches; a kernel FAILS when any thread of any
launch differs. Lines:
  CELL  <producer> -> <consumer> <role> L=<L>[*]: S(L-1) <fail>/<n> FAIL | S(L) <fail>/<n> FAIL   (* = a default, no cell)
  CLASS <producer class>: at L <n> kernels <fail> FAIL (must be 0) | at L-1 <n> kernels <fail> FAIL | cells clean at L-1: ...
  V6 <verdict line>
"""
from __future__ import annotations

import argparse
import collections
import ctypes
import json
import os
import sys
import time

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from culaunch import Cuda, CK  # noqa: E402

THREADS, CTAS = 1024, 32


class Module:
    def __init__(self, cu, path):
        self.cu = cu
        self.mod = ctypes.c_void_p()
        CK(cu.cu.cuModuleLoad(ctypes.byref(self.mod), str(path).encode()), f"cuModuleLoad {path}")

    def fn(self, name):
        f = ctypes.c_void_p()
        CK(self.cu.cu.cuModuleGetFunction(ctypes.byref(f), self.mod, name.encode()), f"cuModuleGetFunction {name}")
        return f

    def unload(self):
        self.cu.cu.cuModuleUnload(self.mod)


def launch(cu, fn, d_out, seed):
    n = THREADS * CTAS
    cu.memset32(d_out, 0, n)
    cu.launch(fn, grid=(CTAS, 1, 1), block=(THREADS, 1, 1), args=[d_out, ctypes.c_uint32(seed)])
    cu.synchronize()
    return cu.from_device(d_out, n * 4, dtype=np.uint32)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kdir")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out", default="cells.json")
    ap.add_argument("--device", type=int, default=0)
    ap.add_argument("--limit-s", type=float, default=1e9)
    args = ap.parse_args()
    t0 = time.time()
    index = json.load(open(os.path.join(args.kdir, "index.json")))
    cu = Cuda(args.device)
    d_out = cu.alloc(THREADS * CTAS * 4)
    seed = 0x12345
    by_cubin = collections.OrderedDict()
    for e in index:
        by_cubin.setdefault(e["cubin"], []).append(e)
    expected, ref_state = {}, {}
    for cubin, es in by_cubin.items():
        if not es[0].get("reference"):
            continue
        e = es[0]
        cell = e["cell"]
        try:
            m = Module(cu, os.path.join(args.kdir, cubin))
            f = m.fn(e["name"])
            outs = [launch(cu, f, d_out, seed) for _ in range(3)]
            m.unload()
        except Exception as ex:
            ref_state[cell] = f"ERROR {str(ex)[:120]}"
            print(f"FAIL ref {cell}: {ref_state[cell]}", flush=True)
            continue
        if not all(np.array_equal(outs[0], o) for o in outs[1:]):
            ref_state[cell] = "UNSTABLE"
            print(f"FAIL ref {cell}: the S15 reference kernel is not deterministic", flush=True)
            continue
        distinct = int(len(np.unique(outs[0])))
        expected[cell] = outs[0]
        ref_state[cell] = f"ok ({distinct} distinct checksums)"
        if distinct < 64:
            ref_state[cell] += " WEAK"
            print(f"FAIL ref {cell}: only {distinct} distinct checksums - a stale read may not reach the checksum", flush=True)
    res = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0, 0, []]))   # cell -> rel -> [n, fail, threads, failing names]
    meta = {}
    skipped = errors = 0
    nk = 0
    for cubin, es in by_cubin.items():
        if es[0].get("reference"):
            continue
        cell = es[0]["cell"]
        meta[cell] = (es[0]["cls"], es[0]["L"], es[0].get("defaulted", False))
        exp = expected.get(cell)
        if exp is None:
            continue
        if time.time() - t0 > args.limit_s:
            skipped += len(es)
            continue
        try:
            m = Module(cu, os.path.join(args.kdir, cubin))
        except Exception as ex:
            errors += len(es)
            print(f"FAIL load {cubin}: {str(ex)[:120]}", flush=True)
            continue
        for e in es:
            try:
                f = m.fn(e["name"])
                mism = 0
                for _ in range(args.reps):
                    mism += int(np.count_nonzero(launch(cu, f, d_out, seed) != exp))
            except Exception as ex:
                errors += 1
                print(f"FAIL {e['name']}: {str(ex)[:120]}", flush=True)
                continue
            r = res[cell][e["rel"]]
            r[0] += 1
            nk += 1
            if mism:
                r[1] += 1
                r[2] += mism
                if len(r[3]) < 6:
                    r[3].append(dict(name=e["name"], regs=e["regs"], y=e["y"], pre=e["pre"], threads=mism))
        m.unload()
    # report
    cls = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, 0]))
    clean_below = collections.defaultdict(list)
    bad_at_L = []
    out_cells = []
    for cell in sorted(res, key=lambda c: (meta[c][0], c)):
        c, L, dflt = meta[cell]
        parts = []
        for rel in sorted(res[cell]):
            n, f, th, names = res[cell][rel]
            cls[c][rel][0] += n
            cls[c][rel][1] += f
            parts.append(f"S(L{rel:+d})={L + rel:02d}: {f}/{n} FAIL" if rel else f"S(L)={L:02d}: {f}/{n} FAIL")
            if rel == 0 and f:
                bad_at_L.append((cell, f, n, names))
            if rel == -1 and f == 0:
                clean_below[c].append(cell)
            out_cells.append(dict(cell=cell, cls=c, L=L, defaulted=dflt, rel=rel, stall=L + rel, kernels=n, failing=f,
                                  mismatching_threads=th, examples=names))
        print(f"CELL  {cell} L={L}{'*' if dflt else ''}: " + " | ".join(parts) + f"   [{ref_state.get(cell, '')}]", flush=True)
    for c in sorted(cls):
        at = cls[c].get(0, [0, 0])
        below = cls[c].get(-1, [0, 0])
        cb = clean_below.get(c, [])
        print(f"CLASS {c}: at L {at[0]} kernels {at[1]} FAIL | at L-1 {below[0]} kernels {below[1]} FAIL"
              + (f" | clean at L-1 ({len(cb)}): " + "; ".join(x.split(' -> ', 1)[1] for x in cb[:12]) if cb else ""), flush=True)
    tot_at = sum(v.get(0, [0, 0])[0] for v in cls.values())
    tot_below = sum(v.get(-1, [0, 0])[0] for v in cls.values())
    fail_below = sum(v.get(-1, [0, 0])[1] for v in cls.values())
    print(f"V6 {len(res)} cells of {len(cls)} producer classes, {nk} kernels x {args.reps} launches: at L {tot_at} kernels, "
          f"{sum(f for _, f, _, _ in bad_at_L)} FAIL in {len(bad_at_L)} cells; at L-1 {tot_below} kernels, {fail_below} FAIL; "
          f"references not usable: {sum(1 for v in ref_state.values() if not v.startswith('ok') or 'WEAK' in v)}; errors {errors}; "
          f"skipped by the time limit {skipped}; {time.time() - t0:.0f} s", flush=True)
    for cell, f, n, names in bad_at_L[:20]:
        print(f"V6 FAIL at L: {cell}: {f}/{n} kernels, e.g. {names[:2]}", flush=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    json.dump({"arch": "sm_120", "harness": "v6 cell populations (2026-11-10)", "threads": THREADS, "ctas": CTAS, "reps": args.reps,
               "references": ref_state, "cells": out_cells, "errors": errors, "skipped": skipped}, open(args.out, "w"), indent=1)
    cu.free(d_out)
    cu.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

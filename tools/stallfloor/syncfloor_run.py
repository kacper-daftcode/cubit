#!/usr/bin/env python3
"""GPU side of the synchronisation-word floor probes (harness v7; see syncfloor_gen.py, sync_probes.cu).

    python3 syncfloor_run.py <kernel dir> [--probe p_mbar ...] [--reps 20] [--out floors.json] [--limit-s N]

Per probe kernel: the reference (ptxas's own schedule, byte-identical to nvcc's cubin) is launched three times; its
outputs must be identical (else the probe is INVALID) and are the expectation. Then every variant `reps` times; a thread
is wrong when its checksum (or, for the bulk probe, any word the CTA pushed to global memory) differs. Lines:
`VAR <variant> [<group>] = <wrong threads> of <threads x reps>` and, per sweep group, `FLOOR <group> = Sxx | S..:n ...`
(the smallest stall with no wrong thread such that every larger stall of the sweep is clean; NONE when the largest is
still wrong). A variant that faults is `ERROR`; the context is rebuilt and the run goes on.

`--isolate` (the form to use for words whose wrong schedule faults or hangs -- `UBLKCP`, `USETMAXREG`): the reference and
every variant run in a process of their own, each bounded by `--var-timeout` seconds; a launch fault is `FAULT`, a variant
that does not return is `HANG` (the process is killed, the next one gets a fresh context). Both count as wrong in a sweep.
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

ITERS = 64
GEOM = {"p_mbar": (32, 1024), "p_mbars": (32, 1024), "p_named": (32, 1024), "p_bulk": (32, 1024), "p_acqrel": (32, 32),
        "p_setmaxnreg": (376, 384), "p_coll": (32, 1024)}
SEED = 0x12345


class Probe:
    def __init__(self, cu, name):
        self.cu, self.name = cu, name
        self.grid, self.block = GEOM[name]
        self.n = self.grid * self.block
        self.d_out = cu.alloc(self.n * 4)
        rs = np.random.RandomState(7)
        self.extra = []
        if name == "p_bulk":
            self.words = self.grid * (ITERS // 4) * 1024
            self.d_src = cu.to_device(rs.randint(0, 2 ** 32, size=self.words, dtype=np.uint64).astype(np.uint32))
            self.d_dst = cu.alloc(self.words * 4)
        elif name == "p_acqrel":
            self.d_flag, self.d_ack, self.d_data = cu.alloc(self.grid * 4), cu.alloc(self.grid * 4), cu.alloc(self.grid * 32 * 4)
        elif name == "p_setmaxnreg":
            self.d_tab = cu.to_device(rs.randint(0, 2 ** 32, size=4096, dtype=np.uint64).astype(np.uint32))

    def run(self, kdir, entry):
        cu = self.cu
        fn = cu.load_kernel(os.path.join(kdir, entry["cubin"]), entry["name"])
        cu.memset32(self.d_out, 0, self.n)
        args = [self.d_out, ctypes.c_uint32(SEED)]
        if self.name == "p_bulk":
            cu.memset32(self.d_dst, 0, self.words)
            args += [self.d_src, self.d_dst]
        elif self.name == "p_acqrel":
            cu.memset32(self.d_flag, 0, self.grid)
            cu.memset32(self.d_ack, 0, self.grid)
            cu.memset32(self.d_data, 0, self.grid * 32)
            args += [self.d_flag, self.d_ack, self.d_data]
        elif self.name == "p_setmaxnreg":
            args += [self.d_tab]
        cu.launch(fn, grid=(self.grid, 1, 1), block=(self.block, 1, 1), args=args)
        cu.synchronize()
        out = cu.from_device(self.d_out, self.n * 4, dtype=np.uint32)
        if self.name == "p_bulk":
            dst = cu.from_device(self.d_dst, self.words * 4, dtype=np.uint32)
            # per thread: its checksum and the words it pushed (thread t of CTA c owns dst[c][it][t])
            pushed = dst.reshape(self.grid, ITERS // 4, 1024).transpose(0, 2, 1).reshape(self.n, ITERS // 4)
            return np.concatenate([out[:, None], pushed], axis=1)
        return out[:, None]


def child(a, index):
    """One entry in this process: the reference (3 launches, saved as the expectation) or one variant."""
    e = next(x for x in index if x["variant"] == a.child)
    cu = Cuda(a.device)
    pr = Probe(cu, e["probe"])
    if e["reference"]:
        outs = [pr.run(a.kdir, e) for _ in range(3)]
        if not all(np.array_equal(outs[0], o) for o in outs[1:]):
            print(f"FAIL ref {e['probe']}: the reference kernel is not deterministic", flush=True)
            return 2
        np.save(a.exp, outs[0])
        exp = outs[0]
        dead = int(np.count_nonzero((exp[:, 0] & 0xFFFF0000) == 0xDEAD0000))
        print(f"REF {e['probe']}: ok ({int(len(np.unique(exp[:, 0])))} distinct checksums of {pr.n} threads" + (f", {dead} threads gave up a poll" if dead else "") + ")", flush=True)
        return 0
    exp = np.load(a.exp)
    wrong = 0
    for _ in range(a.reps):
        wrong += int(np.count_nonzero((pr.run(a.kdir, e) != exp).any(axis=1)))
    print(f"VAR {e['variant']} [{e['group']}] = {wrong} of {pr.n * a.reps}", flush=True)
    cu.close()
    return 0


def isolated(a, index, probes):
    import re
    import subprocess
    import tempfile

    t0 = time.time()
    results, ref_state, floors, skipped = {}, {}, {}, 0
    tmp = tempfile.mkdtemp(prefix="syncfloor_")

    def run_one(variant, exp, tmo):
        cmd = [sys.executable, os.path.abspath(__file__), a.kdir, "--child", variant, "--exp", exp, "--reps", str(a.reps), "--device", str(a.device)]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=tmo)
            return r.returncode, (r.stdout + r.stderr)
        except subprocess.TimeoutExpired as ex:
            return -9, ((ex.stdout or b"").decode(errors="replace") if isinstance(ex.stdout, bytes) else (ex.stdout or ""))

    for pname in probes:
        ref = next(e for e in index if e["probe"] == pname and e["reference"])
        exp = os.path.join(tmp, pname + ".npy")
        rc, out = run_one(ref["variant"], exp, 40)
        line = next((l for l in out.splitlines() if l.startswith(("REF", "FAIL"))), None)
        if rc != 0 or line is None or not line.startswith("REF"):
            ref_state[pname] = "HANG" if rc == -9 else (line or f"ERROR rc={rc} {out.strip().splitlines()[-1][:120] if out.strip() else ''}")
            print(f"FAIL ref {pname}: {ref_state[pname]}", flush=True)
            continue
        ref_state[pname] = line.split(": ", 1)[1]
        print(f"{line} [{time.time() - t0:.0f} s]", flush=True)
        n = GEOM[pname][0] * GEOM[pname][1]
        for e in [e for e in index if e["probe"] == pname and not e["reference"]]:
            if time.time() - t0 > a.limit_s:
                skipped += 1
                continue
            rc, out = run_one(e["variant"], exp, a.var_timeout)
            m = re.search(r"^VAR \S+ \[.*\] = (\d+) of (\d+)", out, re.M)
            if m:
                wrong, state = int(m.group(1)), None
            elif rc == -9:
                wrong, state = -2, f"HANG (no return within {a.var_timeout:.0f} s; process killed)"
            else:
                last = out.strip().splitlines()[-1][:110] if out.strip() else ""
                wrong, state = -1, f"FAULT ({last})"
            results[e["variant"]] = dict(group=e["group"], x=e["x"], wrong=wrong, of=n * a.reps, identical_to_reference=e.get("bytes_changed", 1) == 0)
            if state:
                results[e["variant"]]["state"] = state
            print(f"VAR {e['variant']} [{e['group']}] = {state if state else str(wrong) + ' of ' + str(n * a.reps)}", flush=True)
    groups = {}
    for v, r in results.items():
        if r["x"] is not None:
            groups.setdefault(r["group"], {})[r["x"]] = r["wrong"]
    name = {-1: "FAULT", -2: "HANG"}
    for g, by in sorted(groups.items()):
        smax = max(by)
        if by[smax] != 0:
            floor = "NONE"
        else:
            floor = min(s for s in by if by[s] == 0 and all(by[t] == 0 for t in by if t >= s))
        floors[g] = floor
        print(f"FLOOR {g} = {('S%02d' % floor) if isinstance(floor, int) else floor} | " + " ".join(f"S{s}:{name.get(by[s], by[s])}" for s in sorted(by)), flush=True)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump({"arch": "sm_120", "harness": "v7 synchronisation words, one process per variant (2026-11-10)", "reps": a.reps, "geometry": {p: GEOM[p] for p in probes},
               "references": ref_state, "floors": floors, "variants": results, "skipped": skipped}, open(a.out, "w"), indent=1)
    print(f"written {a.out} ({len(results)} variants, {len(floors)} sweeps, {skipped} skipped by the time limit, {time.time() - t0:.0f} s)", flush=True)
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("kdir")
    ap.add_argument("--probe", nargs="*", default=None)
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--out", default="sync_floors.json")
    ap.add_argument("--device", type=int, default=0)
    ap.add_argument("--limit-s", type=float, default=1e9)
    ap.add_argument("--isolate", action="store_true", help="one process per variant (a fault or a hang costs one variant)")
    ap.add_argument("--var-timeout", type=float, default=12.0)
    ap.add_argument("--child", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--exp", default=None, help=argparse.SUPPRESS)
    a = ap.parse_args()
    t0 = time.time()
    index = json.load(open(os.path.join(a.kdir, "index.json")))
    probes = a.probe or sorted({e["probe"] for e in index})
    if a.child:
        return child(a, index)
    if a.isolate:
        return isolated(a, index, probes)
    cu = Cuda(a.device)
    results, ref_state, floors, skipped = {}, {}, {}, 0
    for pname in probes:
        ref = next(e for e in index if e["probe"] == pname and e["reference"])
        try:
            pr = Probe(cu, pname)
            outs = [pr.run(a.kdir, ref) for _ in range(3)]
        except Exception as ex:  # noqa: BLE001
            ref_state[pname] = f"ERROR {str(ex)[:120]}"
            print(f"FAIL ref {pname}: {ref_state[pname]}", flush=True)
            cu.close(); cu = Cuda(a.device)
            continue
        if not all(np.array_equal(outs[0], o) for o in outs[1:]):
            ref_state[pname] = "UNSTABLE"
            print(f"FAIL ref {pname}: the reference kernel is not deterministic "
                  f"({int(np.count_nonzero((outs[0] != outs[1]).any(axis=1)))} / {int(np.count_nonzero((outs[0] != outs[2]).any(axis=1)))} threads differ between launches)", flush=True)
            continue
        exp = outs[0]
        distinct = int(len(np.unique(exp[:, 0])))
        dead = int(np.count_nonzero((exp[:, 0] & 0xFFFF0000) == 0xDEAD0000))
        ref_state[pname] = f"ok ({distinct} distinct checksums of {pr.n} threads" + (f", {dead} threads gave up a poll" if dead else "") + ")"
        print(f"REF {pname}: {ref_state[pname]} [{time.time() - t0:.0f} s]", flush=True)
        for e in [e for e in index if e["probe"] == pname and not e["reference"]]:
            if time.time() - t0 > a.limit_s:
                skipped += 1
                continue
            wrong = 0
            try:
                for _ in range(a.reps):
                    wrong += int(np.count_nonzero((pr.run(a.kdir, e) != exp).any(axis=1)))
            except Exception as ex:  # noqa: BLE001
                wrong = -1
                print(f"VAR {e['variant']} [{e['group']}] = ERROR {str(ex)[:100]}", flush=True)
                cu.close(); cu = Cuda(a.device); pr = Probe(cu, pname)
            results[e["variant"]] = dict(group=e["group"], x=e["x"], wrong=wrong, of=pr.n * a.reps, identical_to_reference=e.get("bytes_changed", 1) == 0)
            if wrong >= 0:
                print(f"VAR {e['variant']} [{e['group']}] = {wrong} of {pr.n * a.reps}", flush=True)
    groups = {}
    for v, r in results.items():
        if r["x"] is not None:
            groups.setdefault(r["group"], {})[r["x"]] = r["wrong"]
    for g, by in sorted(groups.items()):
        smax = max(by)
        if any(v < 0 for v in by.values()):
            floor = "ERROR"
        elif by[smax] != 0:
            floor = "NONE"
        else:
            floor = min(s for s in by if by[s] == 0 and all(by[t] == 0 for t in by if t >= s))
        floors[g] = floor
        print(f"FLOOR {g} = {('S%02d' % floor) if isinstance(floor, int) else floor} | " + " ".join(f"S{s}:{by[s]}" for s in sorted(by)), flush=True)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    json.dump({"arch": "sm_120", "harness": "v7 synchronisation words (2026-11-10)", "reps": a.reps, "geometry": {p: GEOM[p] for p in probes},
               "references": ref_state, "floors": floors, "variants": results, "skipped": skipped}, open(a.out, "w"), indent=1)
    print(f"written {a.out} ({len(results)} variants, {len(floors)} sweeps, {skipped} skipped by the time limit, {time.time() - t0:.0f} s)", flush=True)
    cu.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

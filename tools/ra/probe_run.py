#!/usr/bin/env python3
"""GPU side of the register-grid probes (gen_align_probes.py).

    probe_run.py <kernel dir> [--out result.json] [--reps 3] [--limit-s N]      the driver: one child process per kernel
    probe_run.py --one <cubin> <kernel name> <reps>                             the child: prints one JSON line

One process per kernel because an illegal instruction (CUDA 715) kills the context. Per kernel: 1 CTA x 32 threads,
`reps` launches; verdict OK (the 8 output words per thread are the expected ones in every launch) / WRONG (launched,
other words) / FAULT <rc> (the launch or the synchronise returned a driver error) / HANG (no answer in 30 s).
`ctl` expectations (LDSM) take the control kernel's words as the oracle.
Lines: `PROBE <name> <on-grid|OFF-grid> <verdict> ...` and one `SHAPE <shape>: ...` summary per shape.
PROBE_MOCK=1: no CUDA at all (fabricated answers) -- a dry run of the driver on a machine whose GPUs must not be touched.
"""
import ctypes
import json
import os
import subprocess
import sys
import time

import numpy as np

THREADS = 32


class Cuda:
    """The CUDA driver API through ctypes, as much as a probe needs (no torch: a child starts in well under a second)."""

    def __init__(self, device=0):
        self.cu = ctypes.CDLL("libcuda.so.1")
        self.ck(self.cu.cuInit(0), "cuInit")
        dev = ctypes.c_int(device)
        self.ck(self.cu.cuDeviceGet(ctypes.byref(dev), device), "cuDeviceGet")
        self.ctx = ctypes.c_void_p()
        self.ck(self.cu.cuCtxCreate_v2(ctypes.byref(self.ctx), 0, dev), "cuCtxCreate")

    @staticmethod
    def ck(rc, what):
        if rc:
            raise RuntimeError(f"CUDA driver error {rc} in {what}")

    def load_kernel(self, cubin, kernel):
        mod = ctypes.c_void_p()
        self.ck(self.cu.cuModuleLoad(ctypes.byref(mod), str(cubin).encode()), "cuModuleLoad")
        fn = ctypes.c_void_p()
        self.ck(self.cu.cuModuleGetFunction(ctypes.byref(fn), mod, kernel.encode()), "cuModuleGetFunction")
        return fn

    def alloc(self, nbytes):
        d = ctypes.c_uint64()
        self.ck(self.cu.cuMemAlloc_v2(ctypes.byref(d), int(nbytes)), "cuMemAlloc")
        return d

    def to_device(self, arr):
        arr = np.ascontiguousarray(arr)
        d = self.alloc(arr.nbytes)
        self.ck(self.cu.cuMemcpyHtoD_v2(d, arr.ctypes.data_as(ctypes.c_void_p), arr.nbytes), "cuMemcpyHtoD")
        return d

    def from_device(self, d, nbytes, dtype):
        out = np.zeros(int(nbytes) // np.dtype(dtype).itemsize, dtype)
        self.ck(self.cu.cuMemcpyDtoH_v2(out.ctypes.data_as(ctypes.c_void_p), d, int(nbytes)), "cuMemcpyDtoH")
        return out

    def memset32(self, d, value, nwords):
        self.ck(self.cu.cuMemsetD32_v2(d, ctypes.c_uint32(value), int(nwords)), "cuMemsetD32")

    def launch(self, fn, grid, block, args, shared=0):
        vals = list(args)                      # alive until cuLaunchKernel has returned
        argv = (ctypes.c_void_p * len(vals))(*[ctypes.cast(ctypes.byref(v), ctypes.c_void_p) for v in vals])
        self.ck(self.cu.cuLaunchKernel(fn, grid[0], grid[1], grid[2], block[0], block[1], block[2], int(shared), None, argv, None), "cuLaunchKernel")

    def synchronize(self):
        self.ck(self.cu.cuCtxSynchronize(), "cuCtxSynchronize")


def mock_child(cubin, name, reps):
    """PROBE_MOCK=1: no CUDA at all -- fabricated answers to dry-run the driver's logic on a machine whose GPUs must
    not be touched (expected words for most kernels, a driver error for imadw_c_b9, a wrong word for ldg_addr_b9)."""
    index = {p["name"]: p for p in json.load(open(os.path.join(os.path.dirname(cubin), "index.json")))}
    p = index[name]
    inp = np.random.RandomState(1234).randint(1, 2 ** 32 - 1, size=THREADS * 4, dtype=np.uint64).astype(np.uint32).tolist()
    ptr = 0x7F0012340000
    if name == "imadw_c_b9":
        print("RESULT " + json.dumps(dict(name=name, ok=False, stage="sync 0", error="CUDA driver error 715 in cuCtxSynchronize (mock)")))
        return
    words = []
    for t in range(THREADS):
        e = [0x1000 + t, 0x2000 + t, 0x33333333] if p["expect"] == "ctl" else expected(p["expect"], inp, ptr, t)
        words += e + [0xDEADBEEF] * (8 - len(e))
    if name == "ldg_addr_b9":
        words[0] ^= 1
    print("RESULT " + json.dumps(dict(name=name, ok=True, stage="done", out=[words] * reps, inp=inp, inp_ptr=ptr)))


def child(cubin, name, reps):
    if os.environ.get("PROBE_MOCK") == "1":
        return mock_child(cubin, name, reps)
    res = dict(name=name, stage="init")
    try:
        cu = Cuda()
        res["stage"] = "load"
        fn = cu.load_kernel(cubin, name)
        inp = np.random.RandomState(1234).randint(1, 2 ** 32 - 1, size=THREADS * 4, dtype=np.uint64).astype(np.uint32)
        d_in = cu.to_device(inp)
        d_out = cu.alloc(THREADS * 32)
        outs = []
        for r in range(reps):
            cu.memset32(d_out, 0xDEADBEEF, THREADS * 8)
            res["stage"] = f"launch {r}"
            cu.launch(fn, grid=(1, 1, 1), block=(THREADS, 1, 1), args=[d_out, d_in], shared=4096)
            res["stage"] = f"sync {r}"
            cu.synchronize()
            outs.append(cu.from_device(d_out, THREADS * 32, dtype=np.uint32).tolist())
        res.update(stage="done", ok=True, out=outs, inp=inp.tolist(), inp_ptr=int(d_in.value))
    except Exception as e:  # noqa: BLE001
        res.update(ok=False, error=str(e)[:200])
    print("RESULT " + json.dumps(res), flush=True)


def expected(spec, inp, inp_ptr, t):
    w = inp[4 * t:4 * t + 4]
    mad = ((w[1] << 32) | w[0]) + t * 0x10000
    env = dict(w0=w[0], w1=w[1], w2=w[2], w3=w[3], inp_lo=inp_ptr & 0xFFFFFFFF, inp_hi=inp_ptr >> 32,
               mad_lo=mad & 0xFFFFFFFF, mad_hi=(mad >> 32) & 0xFFFFFFFF)
    return [env[s] if s in env else int(s, 0) for s in spec]


def main():
    if sys.argv[1] == "--one":
        return child(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("kdir")
    ap.add_argument("--out", default="probes.json")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--limit-s", type=float, default=1e9)
    a = ap.parse_args()
    t0 = time.time()
    index = json.load(open(os.path.join(a.kdir, "index.json")))
    # controls first: an OFF-grid kernel that hangs must not cost the controls
    index.sort(key=lambda p: (not p["on_grid"], p["shape"], p["base"]))
    results, ctl = {}, {}
    for p in index:
        if time.time() - t0 > a.limit_s:
            print(f"SKIP {p['name']}: time limit", flush=True)
            continue
        try:
            cp = subprocess.run([sys.executable, os.path.abspath(__file__), "--one", os.path.join(a.kdir, p["name"] + ".cubin"), p["name"], str(a.reps)],
                                capture_output=True, text=True, timeout=30)
            line = [l for l in cp.stdout.splitlines() if l.startswith("RESULT ")]
            r = json.loads(line[-1][7:]) if line else dict(ok=False, error=f"no result, rc {cp.returncode}: {cp.stderr[-200:]}", stage="?")
        except subprocess.TimeoutExpired:
            r = dict(ok=False, error="HANG (30 s)", stage="?")
        grid = "on-grid " if p["on_grid"] else "OFF-grid"
        if not r.get("ok"):
            verdict = "HANG" if "HANG" in r.get("error", "") else f"FAULT [{r.get('error')}] at {r.get('stage')}"
            words = None
        else:
            outs = r["out"]
            same = all(o == outs[0] for o in outs)
            words = outs[0]
            if p["expect"] == "ctl":
                if p["on_grid"]:
                    ctl[p["shape"]] = words
                    live = sum(1 for t in range(THREADS) for k in range(3) if words[8 * t + k] != 0xDEADBEEF)
                    verdict = f"OK (control = the oracle; deterministic {same}; thread 0 words {[hex(x) for x in words[:4]]})" if same and live else "WRONG (control not stable)"
                else:
                    c = ctl.get(p["shape"])
                    n = len([1 for k in range(THREADS * 8) if c is not None and words[k] != c[k]])
                    verdict = "OK (== the control's words)" if c is not None and n == 0 and same else f"WRONG ({n} words differ from the control; thread 0 {[hex(x) for x in words[:4]]})"
            else:
                bad = 0
                for t in range(THREADS):
                    e = expected(p["expect"], r["inp"], r["inp_ptr"], t)
                    bad += sum(1 for k, x in enumerate(e) if words[8 * t + k] != x)
                e0 = expected(p["expect"], r["inp"], r["inp_ptr"], 0)
                verdict = "OK" if bad == 0 and same else f"WRONG ({bad} words; thread 0 got {[hex(x) for x in words[:len(e0)]]} expected {[hex(x) for x in e0]}; deterministic {same})"
        results[p["name"]] = dict(shape=p["shape"], base=p["base"], on_grid=p["on_grid"], verdict=verdict, words_t0=None if words is None else words[:8])
        print(f"PROBE {p['name']:18s} {grid} {verdict}", flush=True)
    shapes = {}
    for n, r in results.items():
        shapes.setdefault(r["shape"], []).append(r)
    for s, rs in sorted(shapes.items()):
        on = [f"b{r['base']} {r['verdict'].split(' ')[0]}" for r in rs if r["on_grid"]]
        off = [f"b{r['base']} {r['verdict'].split(' (')[0][:60]}" for r in rs if not r["on_grid"]]
        print(f"SHAPE {s}: on the grid {', '.join(on)} | off the grid {', '.join(off)}", flush=True)
    json.dump(results, open(a.out, "w"), indent=1)
    print(f"[probe_run] {len(results)} kernels in {time.time() - t0:.1f}s", flush=True)


if __name__ == "__main__":
    main()

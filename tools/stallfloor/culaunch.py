#!/usr/bin/env python3
"""Shared ctypes CUDA-driver launch helpers for the cubit validators.

The recurring footguns this module removes (each one has cost silicon-debug
hours in this repo):
  * kernel-arg lifetimes — every ctypes object referenced by the argv array
    must stay alive until cuLaunchKernel RETURNS; `make_args` returns the argv
    together with a keepalive list for exactly that reason.
  * cuInit/ctx boilerplate and inconsistent error checking.

Typical use:

    from culaunch import Cuda

    cu = Cuda()                      # cuInit + primary device + context
    fn = cu.load_kernel("/tmp/x.cubin", "my_kernel")
    d_in = cu.to_device(np_array)    # cuMemAlloc + HtoD
    d_out = cu.alloc(nbytes)
    cu.launch(fn, grid=(nblk, 1, 1), block=(256, 1, 1),
              args=[d_in, d_out, ctypes.c_uint32(n)])
    cu.synchronize()
    host = cu.from_device(d_out, nbytes, dtype=np.uint32)
    cu.close()
"""

import ctypes

import numpy as np


def CK(rc, what=""):
    if rc:
        raise RuntimeError(f"CUDA driver error {rc} {what}")


def make_args(*vals):
    """Build a cuLaunchKernel argv from ctypes scalar objects.

    Returns (argv, keepalive). EVERYTHING in `vals` plus the argv itself must
    stay referenced until cuLaunchKernel returns — keep `keepalive` in scope.
    """
    vals = list(vals)
    argv = (ctypes.c_void_p * len(vals))(
        *[ctypes.cast(ctypes.byref(v), ctypes.c_void_p) for v in vals])
    return argv, vals


class Cuda:
    """Thin stateful wrapper over libcuda for one device/context."""

    def __init__(self, device: int = 0):
        self.cu = ctypes.CDLL("libcuda.so.1")
        CK(self.cu.cuInit(0), "cuInit")
        self.dev = ctypes.c_int(device)
        CK(self.cu.cuDeviceGet(ctypes.byref(self.dev), device), "cuDeviceGet")
        self.ctx = ctypes.c_void_p()
        CK(self.cu.cuCtxCreate_v2(ctypes.byref(self.ctx), 0, self.dev), "cuCtxCreate")
        self.modules = []

    # ── module / kernel ───────────────────────────────────────────────────────
    def load_kernel(self, cubin: str, kernel: str):
        mod = ctypes.c_void_p()
        CK(self.cu.cuModuleLoad(ctypes.byref(mod), str(cubin).encode()),
           f"cuModuleLoad {cubin}")
        self.modules.append(mod)
        fn = ctypes.c_void_p()
        CK(self.cu.cuModuleGetFunction(ctypes.byref(fn), mod, kernel.encode()),
           f"cuModuleGetFunction {kernel}")
        return fn

    # ── memory ───────────────────────────────────────────────────────────────
    def alloc(self, nbytes: int) -> ctypes.c_uint64:
        d = ctypes.c_uint64()
        CK(self.cu.cuMemAlloc_v2(ctypes.byref(d), max(int(nbytes), 4)), "cuMemAlloc")
        return d

    def to_device(self, arr) -> ctypes.c_uint64:
        arr = np.ascontiguousarray(arr)
        d = self.alloc(arr.nbytes)
        CK(self.cu.cuMemcpyHtoD_v2(d, arr.ctypes.data_as(ctypes.c_void_p),
                                   arr.nbytes), "cuMemcpyHtoD")
        return d

    def htod(self, d, arr):
        arr = np.ascontiguousarray(arr)
        CK(self.cu.cuMemcpyHtoD_v2(d, arr.ctypes.data_as(ctypes.c_void_p),
                                   arr.nbytes), "cuMemcpyHtoD")

    def from_device(self, d, nbytes: int, dtype=np.uint8) -> np.ndarray:
        out = np.zeros(int(nbytes) // np.dtype(dtype).itemsize, dtype)
        CK(self.cu.cuMemcpyDtoH_v2(out.ctypes.data_as(ctypes.c_void_p), d,
                                   int(nbytes)), "cuMemcpyDtoH")
        return out

    def memset32(self, d, value: int, nwords: int):
        CK(self.cu.cuMemsetD32_v2(d, ctypes.c_uint32(value), int(nwords)),
           "cuMemsetD32")

    def free(self, d):
        self.cu.cuMemFree_v2(d)

    # ── launch ───────────────────────────────────────────────────────────────
    def launch(self, fn, grid, block, args, shared: int = 0, stream=None,
               check: bool = True):
        """args: list of ctypes objects (device ptrs as c_uint64, scalars as
        c_uint32/c_uint64/...). Objects are kept alive through the call."""
        gx, gy, gz = (tuple(grid) + (1, 1))[:3] if isinstance(grid, (tuple, list)) else (grid, 1, 1)
        bx, by, bz = (tuple(block) + (1, 1))[:3] if isinstance(block, (tuple, list)) else (block, 1, 1)
        argv, keepalive = make_args(*args)
        rc = self.cu.cuLaunchKernel(fn, int(gx), int(gy), int(gz),
                                    int(bx), int(by), int(bz),
                                    int(shared), stream, argv, None)
        del keepalive  # alive until here, i.e. until cuLaunchKernel returned
        if check:
            CK(rc, "cuLaunchKernel")
        return rc

    def synchronize(self):
        CK(self.cu.cuCtxSynchronize(), "cuCtxSynchronize")

    # ── events / timing ──────────────────────────────────────────────────────
    def time_launches(self, fn, grid, block, args, iters: int = 100,
                      warmup: int = 20, shared: int = 0) -> float:
        """Average kernel wall time in ms over `iters` back-to-back launches."""
        for _ in range(warmup):
            self.launch(fn, grid, block, args, shared)
        self.synchronize()
        e0, e1 = ctypes.c_void_p(), ctypes.c_void_p()
        CK(self.cu.cuEventCreate(ctypes.byref(e0), 0))
        CK(self.cu.cuEventCreate(ctypes.byref(e1), 0))
        CK(self.cu.cuEventRecord(e0, None))
        for _ in range(iters):
            self.launch(fn, grid, block, args, shared)
        CK(self.cu.cuEventRecord(e1, None))
        self.synchronize()
        ms = ctypes.c_float()
        CK(self.cu.cuEventElapsedTime(ctypes.byref(ms), e0, e1))
        return ms.value / iters

    def close(self):
        if self.ctx:
            self.cu.cuCtxDestroy_v2(self.ctx)
            self.ctx = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

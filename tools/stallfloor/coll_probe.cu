// CS-1 (2026-11-10): the collective-region probe of cubit's sm_120 control classes (harness v7, syncfloor_gen.py).
// `__shfl_xor_sync` under divergent control flow: nvcc emits `BRA.DIV` + the fast-path `SHFL`, and out of line the
// fallback `WARPSYNC.COLLECTIVE R, L ; SHFL ; ENDCOLLECTIVE`. ptxas's shape of the fallback (1 808 of 1 808 regions of
// the served MoE cubin): S07 without yield on the instruction in front of the WARPSYNC, the shuffle with a write AND a
// read barrier at S02, ENDCOLLECTIVE waiting both at S05. The probe takes the branch around its two shuffles with
// 2..30 lanes of every warp in 15 of 16 iterations (the fallback runs) and with all 32 in the 16th (the fast path).
// Geometry: 32 CTAs x 1 024 threads; one checksum per thread.
#include <cuda_runtime.h>
#include <stdint.h>

#define ITERS 64

namespace {
__device__ __forceinline__ uint32_t lcg(uint32_t v) { return v * 1664525u + 1013904223u; }
__device__ __forceinline__ uint32_t work(uint32_t v, int n) {
#pragma unroll 1
  for (int d = 0; d < n; ++d) v = lcg(v);
  return v;
}
}  // namespace

extern "C" __global__ void p_coll(uint32_t* out, uint32_t seed) {
  const int tid = threadIdx.x, lane = tid & 31, warp = tid >> 5;
  uint32_t acc = seed ^ (blockIdx.x * 0x9E3779B9u + (uint32_t)tid * 0x85EBCA6Bu);
#pragma unroll 1
  for (int it = 0; it < ITERS; ++it) {
    const int n = 2 * (1 + ((it + warp) & 15));          // 2..32 lanes of the warp take the branch
    uint32_t v = work(acc, 3) ^ (uint32_t)it;
    const uint32_t o = __shfl_xor_sync(0xffffffffu, v, 1);
    acc = acc * 31u + o;
    if (lane < n) {
      // shuffles behind a branch the compiler does not reconverge: the next ones get `BRA.DIV` + the collective fallback.
      // Every shuffle pairs lane 2k with 2k+1 and n is even: both partners are on the same side of the branch.
      acc = work(acc, 2);
      const uint32_t q = __shfl_xor_sync(0xffffffffu, acc, 1);
      acc ^= q >> 3;
      if (acc & 1u) acc = lcg(acc);
      const uint32_t r = __shfl_xor_sync(0xffffffffu, acc, 1);
      acc += r;
    }
  }
  out[blockIdx.x * blockDim.x + tid] = acc;
}

// CS-1 (2026-11-10): the synchronisation-word floor probes of cubit's sm_120 control classes. Each kernel is compiled by
// nvcc / ptxas (the reference schedule = the oracle) and then re-assembled by `cubit asm -T` with ONE control field of the
// word under test changed (stall, write / read barrier, the consumer's wait): tools/stallfloor/syncfloor_gen.py.
// Geometry: 32 CTAs x 1 024 threads (warps 0-15 producers, 16-31 consumers) unless the kernel says otherwise; every kernel
// writes one checksum per thread into out[blockIdx.x * blockDim.x + threadIdx.x]; a variant is wrong when a checksum differs
// from the reference kernel's. No kernel can hang: every wait is a phase / poll that completes or is bounded.
#include <cuda_runtime.h>
#include <stdint.h>

#define ITERS 64

namespace {
__device__ __forceinline__ uint32_t smem_addr(const void* p) { return static_cast<uint32_t>(__cvta_generic_to_shared(p)); }
__device__ __forceinline__ void mbar_init(uint32_t bar, uint32_t count) {
  asm volatile("mbarrier.init.shared::cta.b64 [%0], %1;\n" ::"r"(bar), "r"(count) : "memory");
}
__device__ __forceinline__ void mbar_arrive(uint32_t bar) {
  asm volatile("{\n.reg .b64 st;\nmbarrier.arrive.shared::cta.b64 st, [%0];\n}\n" ::"r"(bar) : "memory");
}
__device__ __forceinline__ void mbar_arrive_expect_tx(uint32_t bar, uint32_t bytes) {
  asm volatile("{\n.reg .b64 st;\nmbarrier.arrive.expect_tx.shared::cta.b64 st, [%0], %1;\n}\n" ::"r"(bar), "r"(bytes) : "memory");
}
__device__ __forceinline__ void mbar_wait(uint32_t bar, uint32_t parity) {
  asm volatile("{\n.reg .pred p;\nWAIT_%=:\nmbarrier.try_wait.parity.shared::cta.b64 p, [%0], %1;\n@!p bra WAIT_%=;\n}\n" ::"r"(bar), "r"(parity) : "memory");
}
__device__ __forceinline__ void mbar_wait_sleep(uint32_t bar, uint32_t parity) {
  asm volatile("{\n.reg .pred p;\nWAIT_%=:\nmbarrier.try_wait.parity.shared::cta.b64 p, [%0], %1, %2;\n@!p bra WAIT_%=;\n}\n" ::"r"(bar), "r"(parity),
               "r"(0x989680u) : "memory");
}
__device__ __forceinline__ uint32_t lcg(uint32_t v) { return v * 1664525u + 1013904223u; }
__device__ __forceinline__ uint32_t work(uint32_t v, int n) {
#pragma unroll 1
  for (int d = 0; d < n; ++d) v = lcg(v);
  return v;
}

// mbarrier hand-off: 512 producer threads write a slot each and arrive, 512 consumer threads wait for the phase (the probe
// site: the try_wait predicate and its consumer) and read their producer's slot. A consumer that leaves its wait early
// reads the slot of the previous iteration.
template <bool SLEEP>
__device__ __forceinline__ void mbar_probe(uint32_t* out, uint32_t seed) {
  __shared__ __align__(8) uint64_t bar;
  __shared__ uint32_t slot[512];
  const int tid = threadIdx.x, warp = tid >> 5;
  const uint32_t b = smem_addr(&bar);
  if (tid == 0) mbar_init(b, 512);
  __syncthreads();
  uint32_t acc = seed ^ (blockIdx.x * 0x9E3779B9u + (uint32_t)tid * 0x85EBCA6Bu);
#pragma unroll 1
  for (int it = 0; it < ITERS; ++it) {
    if (warp < 16) {
      const uint32_t v = work(acc, 24);  // the consumers reach their wait first
      slot[tid] = v ^ (uint32_t)it;
      mbar_arrive(b);
      acc = v;
    } else {
      if (SLEEP) mbar_wait_sleep(b, it & 1);
      else mbar_wait(b, it & 1);
      acc = acc * 31u + slot[tid - 512];
    }
    __syncthreads();
  }
  out[blockIdx.x * blockDim.x + tid] = acc;
}
}  // namespace

extern "C" {

__global__ void p_mbar(uint32_t* out, uint32_t seed) { mbar_probe<false>(out, seed); }
__global__ void p_mbars(uint32_t* out, uint32_t seed) { mbar_probe<true>(out, seed); }

// named barriers with role counts: 512 producers write and `bar.arrive 1, 1024`, 512 consumers `bar.sync 1, 1024` and read.
__global__ void p_named(uint32_t* out, uint32_t seed) {
  __shared__ uint32_t slot[512];
  const int tid = threadIdx.x, warp = tid >> 5;
  uint32_t acc = seed ^ (blockIdx.x * 0x9E3779B9u + (uint32_t)tid * 0x85EBCA6Bu);
#pragma unroll 1
  for (int it = 0; it < ITERS; ++it) {
    if (warp < 16) {
      const uint32_t v = work(acc, 24);
      slot[tid] = v ^ (uint32_t)it;
      asm volatile("bar.arrive 1, 1024;\n" ::: "memory");
      acc = v;
    } else {
      asm volatile("bar.sync 1, 1024;\n" ::: "memory");
      acc = acc * 31u + slot[tid - 512];
    }
    __syncthreads();
  }
  out[blockIdx.x * blockDim.x + tid] = acc;
}

// bulk copies: thread 0 loads 4 096 B global -> shared on an mbarrier's transaction count, every thread reads its word; then
// every thread stores a word to shared memory and thread 0 pushes the buffer shared -> global behind the async-proxy fence
// (dst is compared by the host).
__global__ void p_bulk(uint32_t* out, uint32_t seed, const uint32_t* src, uint32_t* dst) {
  __shared__ __align__(128) uint32_t buf[1024];
  __shared__ __align__(8) uint64_t bar;
  const int tid = threadIdx.x;
  const uint32_t b = smem_addr(&bar), s = smem_addr(buf);
  if (tid == 0) mbar_init(b, 1);
  __syncthreads();
  uint32_t acc = seed ^ (blockIdx.x * 0x9E3779B9u + (uint32_t)tid * 0x85EBCA6Bu);
#pragma unroll 1
  for (int it = 0; it < ITERS / 4; ++it) {
    const size_t o = ((size_t)blockIdx.x * (ITERS / 4) + it) * 1024;
    if (tid == 0) {
      mbar_arrive_expect_tx(b, 4096);
      asm volatile("cp.async.bulk.shared::cluster.global.mbarrier::complete_tx::bytes [%0], [%1], %2, [%3];\n" ::"r"(s), "l"(src + o), "r"(4096u), "r"(b)
                   : "memory");
    }
    mbar_wait(b, it & 1);
    acc = acc * 31u + buf[tid];
    __syncthreads();
    buf[tid] = acc;
    __syncthreads();
    if (tid == 0) {
      asm volatile("fence.proxy.async.shared::cta;\n" ::: "memory");
      asm volatile("cp.async.bulk.global.shared::cta.bulk_group [%0], [%1], %2;\n" ::"l"(dst + o), "r"(s), "r"(4096u) : "memory");
      asm volatile("cp.async.bulk.commit_group;\n" ::: "memory");
      asm volatile("cp.async.bulk.wait_group 0;\n" ::: "memory");
    }
    __syncthreads();
  }
  out[blockIdx.x * blockDim.x + tid] = acc;
}

// acquire / release across CTAs (launch with 32 threads per CTA, an even number of CTAs): CTA 2k writes 32 words and releases
// flag[k]; CTA 2k + 1 has the words of the previous round in its L1, acquires flag[k], reads the words again and releases
// ack[k]. Every poll is bounded (a broken variant records 0xDEAD0000 | round instead of hanging).
__global__ void p_acqrel(uint32_t* out, uint32_t seed, uint32_t* flag, uint32_t* ack, uint32_t* data) {
  const int lane = threadIdx.x & 31, pair = blockIdx.x >> 1;
  const bool writer = (blockIdx.x & 1) == 0;
  uint32_t acc = seed ^ ((uint32_t)pair * 0x9E3779B9u + (uint32_t)lane * 0x85EBCA6Bu);
  uint32_t* d = data + (size_t)pair * 32 + lane;
#pragma unroll 1
  for (int it = 0; it < ITERS; ++it) {
    if (writer) {
      uint32_t a = 0xFFFFFFFFu;
#pragma unroll 1
      for (int n = 0; n < 4000000 && a != (uint32_t)it; ++n)
        asm volatile("ld.acquire.gpu.global.u32 %0, [%1];\n" : "=r"(a) : "l"(ack + pair) : "memory");
      if (a != (uint32_t)it) { acc = 0xDEAD0000u | (uint32_t)it; break; }
      acc = lcg(acc);
      *d = acc;
      __syncwarp();
      if (lane == 0) asm volatile("st.release.gpu.global.u32 [%0], %1;\n" ::"l"(flag + pair), "r"((uint32_t)it + 1u) : "memory");
    } else {
      const uint32_t stale = *d;  // the previous round's word, now in this SM's L1
      uint32_t f = 0;
#pragma unroll 1
      for (int n = 0; n < 4000000 && f != (uint32_t)it + 1u; ++n)
        asm volatile("ld.acquire.gpu.global.u32 %0, [%1];\n" : "=r"(f) : "l"(flag + pair) : "memory");
      if (f != (uint32_t)it + 1u) { acc = 0xDEAD0000u | (uint32_t)it; break; }
      acc = acc * 31u + *d + (stale & 0u);
      __syncwarp();
      if (lane == 0) asm volatile("st.release.gpu.global.u32 [%0], %1;\n" ::"l"(ack + pair), "r"((uint32_t)it + 1u) : "memory");
    }
  }
  out[blockIdx.x * blockDim.x + threadIdx.x] = acc;
}

// warpgroup register reallocation (launch with 384 threads per CTA): warps 8-11 give registers back, warps 0-7 take them and
// keep 88 values live at once (registers above the launch count of 80).
__global__ void __launch_bounds__(384, 2) p_setmaxnreg(uint32_t* out, uint32_t seed, const uint32_t* tab) {
  const int tid = threadIdx.x;
  if (tid >= 256) {
    asm volatile("setmaxnreg.dec.sync.aligned.u32 32;\n");
    out[blockIdx.x * blockDim.x + tid] = seed ^ (uint32_t)tid;
    return;
  }
  asm volatile("setmaxnreg.inc.sync.aligned.u32 104;\n");
  uint32_t v[88];
  const uint32_t base = (seed + blockIdx.x * 131u + (uint32_t)tid * 7u) & 2047u;
#pragma unroll
  for (int i = 0; i < 88; ++i) v[i] = tab[(base + i * 17u) & 4095u];
  uint32_t acc = seed;
#pragma unroll 1
  for (int it = 0; it < 16; ++it) {
#pragma unroll
    for (int i = 0; i < 88; ++i) v[i] = v[i] * 1664525u + v[(i + 1) % 88];
  }
#pragma unroll
  for (int i = 0; i < 88; ++i) acc = acc * 31u + v[i];
  out[blockIdx.x * blockDim.x + tid] = acc;
}
}

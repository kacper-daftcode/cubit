# SM120 (Blackwell/RTX 5090) undocumented-class instructions

Instructions that exist in hardware but nvcc doesn't generate.
Only accessible via hand-written SASS (cubit).

## Tier 1: Immediate Impact for LLM Inference

### F2FP.SATFINITE.E4M3.F32.PACK — Hardware FP8 Quantize
- **What**: Converts F32 → FP8 E4M3 with saturation and packing, in ONE instruction
- **Replaces**: 608-instruction `k_absmax_quantize` kernel (manual exp/mantissa extraction)
- **Impact**: Entire quantize kernel → ~10 instructions
- **Status**: encodable (in the ISA table); nvcc does not emit it on LLM-inference kernels.
- **Opcode**: F2FP family, 0x7c45-variant with SATFINITE.E4M3 modifier

### BMMA.168128 / BMMA.168256 — Giant Tensor Core Tiles
- **What**: MMA with K=128 or K=256 (vs QMMA K=32)
- **Replaces**: 4-8 QMMA iterations per BMMA
- **Impact**: Kt=128 becomes 4 BMMA.168128 or 2 BMMA.168256 (vs 128 QMMA)
- **Status**: sched_only listing — encoding not yet reverse engineered.
- **Risk**: Unknown operand layout, register requirements likely very high

### REDUX.SUM / REDUX.MAX — Hardware Warp Reduction
- **What**: Warp-level parallel reduce (sum/max/min/or) in 1 instruction
- **Replaces**: 5-step `__shfl_xor_sync` loop (5 SHFL + 5 FADD/FMAX)
- **Impact**: rmsnorm sum_sq, quantize absmax, softmax max/sum — all 10× fewer instructions
- **Status**: encodable; nvcc does not emit it on these kernels.

## Tier 2: Significant Optimization

### FSWZADD — Fused Swizzle + Add
- **What**: Cross-lane add with built-in data permutation
- **Replaces**: Tree reduction pattern (shared memory store → barrier → load → add)
- **Impact**: Block-level reduction without shared memory
- **Status**: sched_only listing — encoding not yet known.

### CREDUX — Cross-Warp Reduction
- **What**: Reduction across warps within a block
- **Replaces**: Shared memory tree reduction (STS → BAR → LDS → reduce loop)
- **Impact**: Combined with REDUX, entire rmsnorm reduction = 2 instructions
- **Status**: sched_only listing — encoding not yet known.

### MUFU.TANH — Hardware Tanh
- **What**: tanh(x) in 1 cycle via special function unit
- **Replaces**: SiLU(x) = x * sigmoid(x) = x * 0.5 * (1 + tanh(x * 0.7071))
- **Impact**: SiLU activation from ~10 instructions → 3 (FMUL + MUFU.TANH + FMUL)
- **Status**: encodable; nvcc reaches for an MUFU.EX2-based sigmoid instead.

### DECOMPRESS — Hardware Decompression
- **What**: Likely FP4/INT4 → FP8/INT8 unpacking in hardware
- **Replaces**: Software bit manipulation for GPTQ dequantization
- **Impact**: Could enable FP4 inference with zero dequant overhead
- **Status**: sched_only listing — purpose and encoding unknown.

## Tier 3: Patterns nvcc already uses

(usage counts observed in one production FP8 GEMV cubin)

### HADD2.F32 — FP16 Add with F32 Output
- observed ×34 in a production GEMV cubin
- Half-precision weight × float input in one instruction (rmsnorm multiply)

### FMNMX — Float Min/Max
- nvcc uses 8× — branchless min/max (vs FSETP + SEL = 2 instructions)

### VIMNMX.S32/U32 — Vector Integer Min/Max
- nvcc uses 15× — clamping in quantization

### LEA / ULEA — Load Effective Address
- nvcc uses 58× — fused shift+add for index computation (vs IMAD + IADD)

### LDS.128 / STS.128 — 128-bit Shared Memory Access
- nvcc uses 16× — 4× wider than LDS.32

### BRA.U — Uniform Branch
- nvcc uses 24× — skip divergence check when all threads take same path

### FFMA.RM/RP/RZ — Rounding Mode FMA
- nvcc uses 36× — Newton-Raphson reciprocal/rsqrt refinement


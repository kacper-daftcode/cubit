# nvcc QMMA GEMV K-loop Reference (SM120)

Exact disassembly of nvcc's K-loop for `qmma_gemv_fused` kernel (4096×4096 FP8).

## K-loop Structure

```
PHASE 1: Address setup + 40 LDG burst (0xA50-0xD60)
├── IADD.64 R26 (advance weight ptr by +0x800 per iter, use negative offsets)
├── IMAD.WIDE R30 (activation base = d_b + tile_counter * 4)
├── 8× LDG.E.GPU.STRONG (weight tiles 0-3, barriers W2-W5)
│   R20:R21(t0), R16:R17(t1), R8:R9(t2), R12:R13(t3), R22:R23(t0), R18:R19(t1), R10:R11(t2), R14:R15(t3)
├── 32× LDG.E (activation tiles 0-3, same barriers W2-W5)
│   t0: R64,R66,R62,R58,R60,R56,R54,R52
│   t1: R67,R69,R40,R42,R44,R46,R48,R50
│   t2: R51,R53,R55,R57,R59,R61,R63,R65
│   t3: R35,R37,R39,R41,R43,R45,R47,R49
└── Loop counter update: IADD3×3, ISETP

PHASE 2: Compute 4 tiles (0xDB0-0x10E0)
├── Tile 0: FMUL×8 + F2FP×4 → QMMA R20, R20, R30, R4
├── Tile 1: FMUL×8 + F2FP×4 → QMMA R16, R16, R4, R20  (cascaded from t0)
├── Tile 2: FMUL×8 + F2FP×4 → QMMA R8, R8, R4, R16   (cascaded from t1)
└── Tile 3: FMUL×8 + F2FP×4 → QMMA R4, R12, R4, R8   (cascaded from t2)

@P0 BRA k_loop
```

## Barrier Map

| Barrier | Phase 1 (LDG) | Phase 2 (wait) |
|---------|---------------|----------------|
| W2 | weight t0 + act t0 (10 LDGs) | Tile 0 first FMUL: B--2--- |
| W3 | weight t1 + act t1 (10 LDGs) | Tile 0 second FMUL: B---3-- |
| W4 | weight t2 + act t2 (10 LDGs) | Tile 0 third FMUL: B----4- |
| W5 | weight t3 + act t3 (10 LDGs) | Tile 0 fourth FMUL: B-----5 |

First 4 FMULs of tile 0 each wait for one barrier = drain ALL 40 LDGs across 4 cycles.

## FMUL/F2FP Interleaving Detail (Tile 0)

```
cycle  instruction                          stall  notes
T+0    FMUL R64, R64, R0                   S01    wait B2 (drain t0 loads)
T+1    FMUL R66, R66, R0                   S01    wait B3 (drain t1 loads)
T+2    FMUL R62, R62, R0                   S01    wait B4 (drain t2 loads)
T+3    FMUL R58, R58, R0                   S03    wait B5 + padding for F2FP
T+6    F2FP R64, R66, R64, RZ              S01    R64@T+0=6cy✓ R66@T+1=5cy✓
T+7    FMUL R60, R60, R0                   S01
T+8    F2FP R58, R58, R62, RZ              S01    R62@T+2=6cy✓ R58@T+3=5cy✓
T+9    FMUL R56, R56, R0                   S01
T+10   FMUL R54, R54, R0                   S01
T+11   FMUL R52, R52, R0                   S03    padding for MERGE_C
T+14   F2FP R30, R56, R60, R64            S02    MERGE R64 from T+6=8cy✓
T+16   F2FP R31, R52, R54, R58            S07    MERGE R58 from T+8=8cy✓
T+23   QMMA R20, R20, R30, R4             S01    weight R20 from LDG, B from R30:R31
```

**Total tile 0 compute: 23 cycles. 4 tiles × 23 = 92 cycles per iteration.**

## Register Allocation

| Registers | Usage | Notes |
|-----------|-------|-------|
| R0 | scale | Persistent, loaded before K-loop |
| R4-R7 | QMMA B-fragment + temp | Reused per tile |
| R8-R23 | Weight data (4 tiles) | Also QMMA cascade accumulators |
| R24-R27 | A pointer, B pointer | Address computation |
| R30-R34 | B-fragment, scale, loop | Mixed usage |
| R35-R69 | Activation data (4 tiles) | 32 registers, non-sequential |

**Key insight**: nvcc uses non-sequential register allocation for activation to optimize
the FMUL→F2FP distance. Register pairs (R64,R66) are separated by 2 register indices
so that consecutive FMUL writes to R64, then R66 — creating 1 cycle gap before F2FP
reads both.

## Performance Characteristics

- 107 K-loop instructions, avg stall 2.9
- 312 total cycles per iteration × 32 iterations = 9984 cycles ≈ 5µs compute
- 14.4µs total → 9.4µs memory latency overhead
- 40 LDGs per iteration → ~10 concurrent memory requests per barrier
- L1 bypass for weights (LDG.E.GPU.STRONG), L2 cache for activations (LDG.E)

## Key nvcc Optimization Patterns

### 1. Pre-advanced pointer with negative offsets
```
IADD.64 R26, R24, 0x608    // advance ptr once
LDG R20, desc[UR6][R26.64+-0x608]  // tile 0 (=original ptr)
LDG R16, desc[UR6][R26.64+-0x408]  // tile 1 (+0x200)
LDG R8,  desc[UR6][R26.64+-0x208]  // tile 2 (+0x400)
LDG R12, desc[UR6][R26.64+-0x8]    // tile 3 (+0x600)
LDG R14, desc[UR6][R26.64]         // tile 3 (+0x608)
```
Fires ALL weight LDGs without intermediate IADD.64 between tiles.

### 2. B-ptr reload from constant bank each iteration
```
LDC.64 R30, c[0x0][0x390]           // reload d_b ptr from cbank
IMAD.WIDE.U32 R30, R34, 0x4, R30   // compute B-base
```
Frees R18:R19 for activation data. LDC is fast (constant cache hit).

### 3. FMUL/F2FP immediate interleaving
```
FMUL R64  S01    // first pair starts
FMUL R66  S01
FMUL R62  S01
FMUL R58  S03    // gap before F2FP
F2FP(R66,R64) S01  // pack IMMEDIATELY after 4th FMUL
FMUL R60  S01    // continue FMULs
F2FP(R58,R62) S01  // second pack interleaved
```

### 4. Non-sequential activation register allocation
Registers are ordered to maximize FMUL→F2FP def-use distance:
- t0: R64,R66,R62,R58 (not R40,R41,R42,R43)
- The F2FP reads R64 which was FMULed 4 instructions ago = 4+ cycles ✓

### 5. Loop control hidden in LDG tail
Last weight LDG fires, then 5 control instructions execute during
LDG memory latency. Zero overhead for loop control.

### 6. Cascaded QMMA accumulation
```
QMMA R20, R20, R30, R4   // t0: Rd=weight=R20, overwrites weight!
QMMA R16, R16, R4, R20   // t1: reads R20 as acc (fresh from t0)
QMMA R8,  R8,  R4, R16   // t2
QMMA R4,  R12, R4, R8    // t3: back to R4
```
Each QMMA's Rd=Ra (writes into weight location), acc cascades through.

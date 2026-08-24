# SM120 SASS Kernel Tuning Guide

Hard-won knowledge from hand-scheduling QMMA GEMV kernels on RTX 5090 (SM120).

## Critical Hardware Facts

### Stall Behavior
- SM120 `wait_mask` is **bounded, NOT a hard block**. The barrier wait provides ~170 cycles max wait, then proceeds regardless.
- Stall count provides **additional safety margin** on top of barrier wait.
- **Minimum useful ALU stall = S02** (SM120 pipeline forwarding). S01 works for throughput but not latency.
- FMA pipeline latency = 5 cycles. With interleaving, S01 stall on independent FMULs is safe.
- **F2FP MERGE_C chain** (reads own output): needs S04 minimum between dependent F2FPs. Independent F2FPs can use S01.
- QMMA: always S11 (accumulation pipeline). Cannot encode wait_mask — use **UIADD3 URZ drain** instruction before QMMA.
- **NOP stall is IGNORED**: NOP has CtrlClass::Nop → encoder uses static upper32 (stall=0). Use `MOV R_unused, RZ` with `[S15]` if you need real stall padding.

### Barrier Scoreboard
- 6 barriers (B0-B5). Each tracks ALL instructions assigned to it (counter-based).
- **Batch consecutive loads** under one barrier (nvcc style): 8-16 LDGs on one barrier, single wait drains all.
- Barrier is "consumed" when an instruction waits for it (counter reaches 0).
- After consumption, barrier can be reused for new loads.
- `UIADD3 URZ, UPT, UPT, URZ, URZ, URZ` = noop drain instruction that CAN encode wait_mask (unlike QMMA).
- **WAW hazard on LDC.64/LDG.E.64**: `LDC.64 R2` writes R2:R3 (long-latency). If a subsequent ALU writes R3 before LDC completes, LDC's late writeback overwrites the ALU result. cubit scheduler must track R+1 defs for 64-bit loads and add WAW waits.

### Register Limits
- EIATTR regcount=72 → usable R0-R69 (2 hardware-reserved). R70+ causes ILLEGAL_INSTRUCTION.
- SM120 rounds to 32-granularity internally but enforces EIATTR limit.
- With `-T template` mode, EIATTR comes from template cubin.

### QMMA Cooperative Writeback (CRITICAL)

SM120 QMMA uses warp-cooperative execution. The writeback of accumulator registers has special rules:

1. **ALU instructions CANNOT read QMMA output** without explicit sync. `FMUL R5, R7, R64` after QMMA reads STALE register values (pre-QMMA state), even with 150+ cycles of stall delay.
2. **STG CAN read QMMA output** — memory pipeline has implicit sync with QMMA writeback.
3. **Sync pattern**: `@!UPT UIADD3 URZ, UPT, UPT, URZ, URZ, URZ` (2x, stall=1 then stall=6). The `@!UPT` guard (bit 15 = 1) is the hardware-recognized QMMA writeback barrier.
4. **Drains must be IMMEDIATELY after QMMA** — even 1 instruction (IADD) between QMMA and drain breaks sync.
5. **Drains INSIDE a QMMA accumulation loop RESET accumulation** (all zeros). Only safe after the LAST QMMA.
6. **cubit auto-inserts** `@!UPT` drains for standalone (non-looped) QMMA. For QMMA in loops, the kernel MUST be unrolled so the last QMMA can have drains immediately after it.

**Encoding**: `@!UPT UIADD3 URZ` = `lo=0x000000fffffff290` (bit 15 set vs regular UIADD3 `lo=0x000000ffffff7290`).

**nvcc approach**: 16× unroll hides QMMA writeback latency entirely — hundreds of instructions between QMMA and first ALU read of accumulators, plus cascaded accumulation (each QMMA's output feeds the next as input).

## nvcc's K-loop Pattern (the gold standard)

nvcc achieves **1170 GB/s** (65% peak BW) with this structure:

### 1. ALL LDGs fire upfront (40 loads in one burst)
```
// 8 weight LDGs (4 tiles × LDG.E.GPU.STRONG ×2)
LDG.E.GPU.STRONG R20, desc[UR6][R26.64+-0x608]  // tile 0 weight
...8 total weight LDGs...

// 32 activation LDGs (4 tiles × 8 LDG.E)
LDG.E R64, desc[UR6][R30.64+0x8]  // tile 0 act
...32 total activation LDGs...
```
**160 cycles of natural LDG→FMUL distance.** Memory bus saturated.

### 2. FMUL/F2FP deeply interleaved (per tile)
```
FMUL R64 S01  // barrier wait B2
FMUL R66 S01  // barrier wait B3
FMUL R62 S01  // barrier wait B4
FMUL R58 S03  // extra stall before F2FP
F2FP(R66,R64) S01  // reads R64 (4cy ago), R66 (3cy ago) ✓
FMUL R60 S01
F2FP(R58,R62) S01  // reads R62 (4cy ago via S03), R58 (6cy ago) ✓
FMUL R56 S01
FMUL R54 S01
FMUL R52 S03       // extra stall for MERGE_C
F2FP(R56,R60,R64_merged) S02
F2FP(R52,R54,R58_merged) S07  // MERGE_C needs S07
QMMA S01
```
**Key**: S03 on every 4th FMUL creates enough latency gap for F2FP to read results.

### 3. Stall distribution
| Stall | Count | Usage |
|-------|-------|-------|
| S01 | 42 | Independent FMULs, F2FPs, address compute |
| S02 | 7 | F2FP before MERGE_C |
| S03 | 9 | FMUL before F2FP (data readiness buffer) |
| S04 | 38 | LDG issue rate |
| S06 | 4 | IMAD.WIDE, address computation |
| S07 | 5 | F2FP MERGE_C chain |
| **Avg** | **2.9** | 312 cycles / 107 instructions |

### 4. Barrier plan (K-loop)
- W0: unused in K-loop (used by setup)
- W1: amax LDGs  
- W2-W5: one per activation tile group (rotated)
- Weight LDGs share barrier with activation (same group)

### 5. Other tricks
- **LDG.E.GPU.STRONG** for weights (L1 bypass, streaming access)
- **LDG.E** for activations (L2 cached, reused across blocks)
- **Cascaded QMMA accumulation**: R4→R20→R16→R8→R4 (each tile's output feeds next)
- **Yield flag** on most instructions (warp switching for latency hiding)
- **Negative offsets**: `desc[UR6][R26.64+-0x608]` — precompute advanced pointer, load backwards

## Optimization Progression (our results)

| Version | µs | GB/s | Key Change |
|---------|-----|------|-----------|
| 2-tile serialized | 52.0 | 323 | Baseline |
| 4-tile + barrier batching | 36.5 | 459 | +42%: batch LDGs under shared barriers |
| Interleaved act groups | 32.7 | 513 | +12%: dual-buffer R40-R47 + R44-R47 |
| **2-phase bulk LDG** | **24.2** | **693** | **+26%: fire 24 LDGs before compute** |
| + FMUL S06→S02 | 22.5 | 745 | +7%: safe with 96+ cycle LDG distance |
| nvcc roundtrip | 14.4 | 1164 | Target (byte-identical roundtrip) |

## Control Code Format

cubit supports inline scheduling annotations:
```
[B------:R-:W-:-:S05] FMUL R40, R40, R30 ;
│          │  │ │ │
│          │  │ │ └─ Stall cycles (01-15)
│          │  │ └─── Yield (Y/-) 
│          │  └───── Write barrier (0-5/-)
│          └──────── Read barrier (0-5/-)
└─────────────────── Wait mask: B012345 (digit=wait, -=skip)
```

When CC is specified, cubit's auto-scheduler skips that instruction (but still tracks register defs for downstream deps). UIADD3 drain instructions must be manually added before QMMA.

## Checklist: Writing a Fast SASS Kernel

1. **Fire ALL LDGs upfront** — maximum burst before any compute
2. **L1 bypass** for streaming data (weights): `LDG.E.GPU.STRONG`
3. **L2 cache** for reused data (activations): `LDG.E`
4. **Batch barriers**: consecutive LDGs share one `W` barrier
5. **Interleave FMUL/F2FP**: process pairs as they become ready, don't wait for all FMULs
6. **Variable stalls**: S01 independent, S03 before F2FP reads, S07 MERGE_C chain
7. **UIADD3 drain** before every QMMA with barrier wait bits
8. **Double-buffer registers**: set A (R40-R47) + set B (R52-R59) for 2-phase pipelines
9. **Yield flag** on loads and tensor ops
10. **Keep under R69** — EIATTR=72 enforces hard limit

## Common Pitfalls

- **Stall too low on barrier-dependent FMUL** → non-deterministic results (race condition)
- **Missing UIADD3 drain before QMMA** → QMMA reads stale data (can't encode wait_mask)
- **F2FP MERGE_C at S01** → half the result missing (reads own output before ready)
- **LDG into register > R69** → ILLEGAL_INSTRUCTION
- **All LDGs on one barrier with counter overflow** → partial data (limit ~8 per barrier)
- **BRA without backward-drain** → previous iteration's barriers leak into next
- **FMUL/FADD on QMMA output without @!UPT drain** → reads stale pre-QMMA register values (c0=c2 pattern, garbage, or zeros). STG works fine but ALU does not.
- **@!UPT drain inside QMMA loop** → resets accumulation to zero. Drain ONLY after loop exit.
- **Instructions between QMMA and @!UPT drain** → sync broken. Must be immediately adjacent.
- **IMAD.WIDE.U32 dest_regs**: IMAD.WIDE writes Rd:Rd+1 (64-bit) but opcode doesn't contain ".64" — scheduler must track R+1 for WIDE ops too.
- **User control codes on UIADD3+URZ**: IADD3+RZ forces hi[7:0]=0xFF — scheduler may override user wait_mask. Use drain pass instead of manual `[B123456]` annotations.

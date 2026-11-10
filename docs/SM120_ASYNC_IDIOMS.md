# SM120 memory-ordering and async-proxy idioms, as ptxas schedules them

How nvcc 13.0 (`-arch=sm_120a`) lowers the PTX primitives a persistent, device-scheduled kernel is built from, and the
control codes ptxas puts on them. Source: the primitive probe of vLLM-Moet's megakernel programme (nine kernels, 472
words: bulk copies, mbarriers, fences at every scope, `setmaxnreg`, the acquire / release idioms, cluster barriers)
compiled on 2026-11-08, disassembled with nvdisasm 13.4 and frozen by `cubit disassemble --frozen` — the control codes
below are ptxas's, quoted as `[B<wait>:R<rd>:W<wr>:Y:S<stall>]`. The encodings are measured rows of `sm120.json`
(`tools/probes/re_sm120_{ublkcp_dir,fence_view_async,vote,usetmaxreg}.py`, 2026-11-08); the words are exact suite pins
(`tests/corpus_pins.rs::megakernel_corpus_sm120_strict`). Scheduling facts marked *law* were measured with nvdisasm;
the rest is what ptxas emits — a reference for hand-written SASS. Since 2026-11-10 cubit's scheduler has a control
class for every word of this page behind the opt-in switch `CUBIT_SYNC_CLASSES=1` (`src/sync_class.rs`; the section
"What the scheduler does with them" below), with floors measured on sm_120 silicon; without the switch nothing of it
runs.

## Release and acquire

| PTX | SASS (ptxas control code) |
|---|---|
| `st.release.gpu` / `red.release.gpu` | `MEMBAR.ALL.GPU` `[S06,Y]` → `ERRBAR` `[S00]` → `CGAERRBAR` `[S06–S08,Y]` → `STG.E.STRONG.GPU` / `REDG.E.ADD.STRONG.GPU` waiting the data's barrier `[B3,S01]` / `[B2,S04]` |
| `st.release.sys` / `red.release.sys` | the same chain with `MEMBAR.ALL.SYS` and `.STRONG.SYS` |
| `ld.acquire.gpu` / `.sys` | `LDG.E.STRONG.GPU` / `.SYS` with a write barrier `[W3,S04]` / `[W2,S04]` → `CCTL.IVALL` waiting it `[B3,S01]` (the L1 invalidate is the acquire) |
| `atom.acq_rel.gpu` (returning) | the release chain → `ATOMG.E.ADD.STRONG.GPU` `[W3,S04]` → `CCTL.IVALL` `[B3,S01]` |
| `__threadfence()` / `fence.acq_rel.gpu` | `MEMBAR.ALL.GPU; ERRBAR; CGAERRBAR; CCTL.IVALL` (`[B012345]` on the invalidate when it closes a kernel section) |
| `__threadfence_system()` / `fence.sc.sys` | `MEMBAR.SC.SYS` `[S06,Y]` → `ERRBAR` `[S00]` → `CGAERRBAR` `[S06,Y]` → `CCTL.IVALL` `[S01–S04,Y]` |
| `fence.acq_rel.cta` | `MEMBAR.ALL.CTA` `[S06,Y]` |

Measured cost on 4× RTX PRO 6000 (PCIe P2P, the megakernel programme's stage-3 model): an acquire at `.sys` scope —
`LDG.E.STRONG.SYS` + `CCTL.IVALL`, or a relaxed poll followed by `MEMBAR.ALL.SYS` — costs ≈ 2.5 µs per use; four of
them per 88-µs compute tile were 10 % of a persistent kernel's SM time. A relaxed poll (`LDG.E.STRONG` + `NANOSLEEP`)
is free. Hoist the fence out of the per-tile path: one `MEMBAR.*.SYS` per task group a CTA enters, relaxed polls
inside.

## The async proxy

| PTX | SASS |
|---|---|
| `fence.proxy.async.shared::cta` | `MEMBAR.ALL.CTA` `[S06,Y]` → `FENCE.VIEW.ASYNC.S` `[W1,S01]` |
| `fence.proxy.async` (generic) | `MEMBAR.ALL.GPU` → `FENCE.VIEW.ASYNC.S` `[W1–W2,S09–S10]` — the barrier is waited by the next `SYNCS` / `UBLKCP` |
| `fence.proxy.async.global` | `FENCE.VIEW.ASYNC.G` (scope bit 72; no row before 2026-11-08) |

*Law*: a `FENCE` word with a read barrier (`[115:113]` other than 7) is illegal — the fence carries a write barrier at
most. `FENCE.VIEW.ASYNC.T` (bit 73) is the tensor-memory scope of sm_100 / sm_103 and is illegal on SM120 / SM121.

## mbarriers

| PTX | SASS |
|---|---|
| `mbarrier.init` | `SYNCS.EXCH.64 URZ, [UR], UR` `[R1,W3,S02]` — a read barrier on the UR source, a write barrier the next arrive waits (`[B3]`) |
| `mbarrier.arrive.expect_tx` | `SYNCS.ARRIVE.TRANS64 RZ, [R+URZ], R` `[B3,R1,S01–S03]` |
| `mbarrier.arrive` (no tx) | `SYNCS.ARRIVE.TRANS64.A1T0 RZ, [UR], RZ` `[S01]` |
| `mbarrier.try_wait.parity` | `SYNCS.PHASECHK.TRANS64.TRYWAIT P0, [R+URZ], R` `[W1–W2,S02–S03]` → `@!P0 BRA` (or `@!P0 NANOSLEEP.SYNCS 0x3e8` → `@!P0 SYNCS.PHASECHK.TRANS64 P0, …`): the predicate is a variable-latency result behind a write barrier |
| `cp.async.mbarrier.arrive.noinc` | `ARRIVES.LDGSTSBAR.64.ARVCNT [UR]` `[S01]` after `LDGSTS.E.BYPASS.128 … [R0,S01]` |

## Bulk copies (TMA) and their completion

| PTX | SASS |
|---|---|
| `cp.async.bulk.shared::cta.global … .mbarrier::complete_tx::bytes` | `UBLKCP.S.G [URdst], [URsrc], URsize` `[R3,S12]` (the load: direction code [74:73] = 1) |
| `cp.async.bulk.global.shared::cta.bulk_group` | `UBLKCP.G.S [URdst], [URsrc], URsize` (the store: code 2; the text minted the load until 2026-11-08) |
| `cp.async.bulk.tensor.2d.shared::cluster.global` | `UTMALDG.2D [UR], [UR]` `[R2,S12]` |
| `cp.async.bulk.commit_group` | `UTMACMDFLUSH` `[R0,S01]` — the group completes on **scoreboard SB0** |
| `cp.async.bulk.wait_group[.read] N` | `DEPBAR.LE SB0, N` `[S04]` (the same word for both; followed by `CCTL.IVALL` `[S01]` for the non-`.read` form) |
| `cp.async.commit_group` / `wait_group N` | `LDGDEPBAR` / `DEPBAR.LE SB0, N` |

The bulk group's completion uses SB0, which cubit's barrier allocator also hands to loads: a cubit-scheduled kernel
that mixes bulk copies with `LDG` / `LDGSTS` must keep SB0 for the group (open item 4 below). `UBLKCP` and `UTMALDG`
are issued with a stall of 12 by ptxas.

## Warpgroup register reallocation and votes

| PTX | SASS |
|---|---|
| `setmaxnreg.dec.sync.aligned.u32 N` | `USETMAXREG.DEALLOC.CTAPOOL 0xNN` `[S00]` (a hardware interlock; no stall) |
| `setmaxnreg.inc.sync.aligned.u32 N` | `USETMAXREG.TRY_ALLOC.CTAPOOL UP0, 0xNN` `[W0]` → `@!UP0 BRA` back to it until it succeeds |
| `vote.sync.all/any/uni.pred` (uniform result) | `VOTEU.ALL/ANY/EQ URd, UPd, Ps` (measured 2026-11-08; `.ALL` and a non-PT source did not assemble before) |

*Law*: the reuse bits (122–124) are illegal on `USETMAXREG`. The count field is ten bits and holds the register count
itself (0x18 = 24, 0xe0 = 224); ptxas emits multiples of 8 in 24..256 and only ever two distinct sizes per CTA — whether
the pool accepts a third distinct allocation, and the stall floor between `TRY_ALLOC` and the first use of a register
above the launch count, are silicon questions still open. A resident 32-thread × 32-register CTA (1 024 registers) is the
budget that co-resides with the layer's CUTLASS / DeepGEMM kernels on an SM (measured 2026-11-08, vLLM-Moet MK-4).

## What the scheduler does with them (`CUBIT_SYNC_CLASSES=1`, opt-in)

`src/sync_class.rs` gives every word above a control class; `src/cfg_flow.rs` is the control-flow graph of a kernel as
nvcc lays it out (slow paths behind the last `EXIT` returning with a backward `BRA`, `BRA.DIV` falling through, `BRX`
dispatching through a table) on which the barrier allocator and the latency legaliser then run. Nothing is inserted: a
branch carries its wait itself, so a kernel of nvcc keeps its instruction count and `cubit asm -T` over ptxas's cubin
accepts it without `--allow-stale-metadata`.

| word | write barrier | read barrier | stall | waits |
|---|---|---|---|---|
| `SYNCS.PHASECHK.TRANS64[.TRYWAIT] P, [a], R` | on the predicate | `a`, `R` when overwritten behind it | 2 | the fence / init token (`TRYWAIT`; the re-check never waits) |
| `USETMAXREG.TRY_ALLOC.CTAPOOL UP, n` | on the uniform predicate | – | 2 | – |
| `SYNCS.EXCH.64 URZ, [a], UR` | a token (the next mbarrier word / `BAR` waits it) | `a`, `UR` | 2 | the fence token |
| `SYNCS.ARRIVE.TRANS64[.A1T0] RZ, [a], R` | – | `a`, `R` | 1 | never (the wait goes on the instruction in front) |
| `SYNCS.CCTL.IVALL` | a token | – | 2 | the fence token |
| `ARRIVES.LDGSTSBAR.64.ARVCNT [a]` | – | – | 1 (8 in front of a branch) | – |
| `FENCE.VIEW.ASYNC.{S,G}` | a token (the next mbarrier / bulk word waits it) | – | 2 | never |
| `UBLKCP.S.G`, `UTMALDG` | – | every operand | 12, no yield | the fence token |
| `UBLKCP.G.S`, `UTMASTG` | – | every operand | 1 | the fence token |
| `UTMACMDFLUSH` / `LDGDEPBAR` | scoreboard 0 as read / write barrier | | 1 | – |
| `DEPBAR.LE SB0, n` | – | – | 4, no yield | – |
| `MEMBAR.*` / `ERRBAR` / `CGAERRBAR` | – | – | 6 (0 on a `MEMBAR` in front of another) / 0 / 6 | – |
| `CCTL.IVALL` | – | – | 1 (4 in front of a memory instruction) | the barrier of the `.STRONG` load / atomic in front of it |
| `CCTL.E.RML2 [a]`, `CCTL.E.PF2 [a+n]` (one cache line) | – | `a` (both halves) when overwritten behind it | 1 (4 in front of a memory instruction or another line control) | – |
| `BAR.ARV` | – | – | 8 | – |
| `NANOSLEEP[.SYNCS]`, `YIELD`, `WARPSYNC.*`, `ENDCOLLECTIVE` | – | – | 5 | their guard's producer |
| `LDGSTS` | – | its address registers | the memory spacing | never (0 of 1 163 in ptxas's code) |

Scoreboard 0 belongs to the copy group in a kernel that commits one (`LDGDEPBAR`, `UTMACMDFLUSH`). A collective region
— the fallback nvcc emits behind the `BRA.DIV` of a `shfl.sync` whose warp may be split,
`WARPSYNC.COLLECTIVE R, L ; SHFL P, ... ; ENDCOLLECTIVE` — keeps ptxas's shape (1 808 of 1 808 regions of the served MoE
cubin): stall 7 without yield on the instruction in front of the `WARPSYNC`, a write AND a read barrier on the shuffle
at stall 2, `ENDCOLLECTIVE` waiting both at stall 5.

### Silicon floors (test host, RTX PRO 6000 Server Edition, 2026-11-10; `tools/stallfloor/`, harness v7)

Probe kernels compiled by nvcc 13.0 (`sync_probes.cu`); the reference is ptxas's own schedule, a variant is the same
kernel with one control field changed, 20 launches, a thread is wrong when its checksum differs.

| word | result |
|---|---|
| `SYNCS.PHASECHK.TRANS64.TRYWAIT`, spin and suspend form | **without its write barrier wrong at every stall 1 … 15** (327 680 of 327 680 consumer threads at S01, still wrong at S15): the predicate is a scoreboard result, no stall replaces the barrier. With the barrier: S01 with yield wrong on every consumer thread, S01 without yield, S02, S03 clean — the arming distance of every scoreboard setter (2) |
| `USETMAXREG.TRY_ALLOC.CTAPOOL` | with its barrier at S01 the kernel hangs; **without the barrier it hangs at S01, S02, S04, S08, S13**; the retry branch at S01 / S02, `DEALLOC` without its barrier, the `WARPSYNC` in front at S01: clean |
| `UBLKCP.S.G` | **stall 1, 2, 4, 8: launch failure (CUDA_ERROR_LAUNCH_FAILED); 12: clean** — the 12 is an issue law of the word, not a latency. Dropping its read barrier, the barrier of the arrive, of `UBLKCP.G.S`, of `UTMACMDFLUSH`, the fence's write barrier: no wrong word in 655 360 thread-launches each (not observable with this probe — ptxas's practice is kept) |
| `DEPBAR.LE SB0, 0` | S01, S02, S04 clean |
| `MEMBAR.ALL.CTA` (in front of the fence) / `MEMBAR.ALL.GPU` / `CGAERRBAR` | S01, S03 clean (the release chain's stalls are ptxas's practice, not a measured floor) |
| `CCTL.IVALL` behind `LDG.E.STRONG` | dropped: every reader thread wrong (the invalidate IS the acquire); issued before the load's barrier is waited: clean |
| `BAR.ARV` | the stall behind it 1 … 8 clean; control `BAR.SYNC` → `LDS`: wrong at 1 … 5, clean at 6 (BUG-479 reproduced) |
| the collective region (`coll_probe.cu`, 24 one-field variants) | the instruction in front of `WARPSYNC.COLLECTIVE` at **S01 / S02: fault (CUDA error 715, illegal instruction)**, clean from S03 (ptxas: 7); the region's `SHFL` at S01 with its barriers: 248 754 of 655 360 thread-launches wrong, S02 clean (the arming distance); `ENDCOLLECTIVE` without its waits: 205 284 wrong — the reader behind the region waiting instead: clean; the stalls of `WARPSYNC.COLLECTIVE` / `ENDCOLLECTIVE` 1 … 5: clean |

### What a kernel of nvcc needs beyond the classes

The first kernels of nvcc that cubit scheduled — the served MoE `fc1_kernel_wg<4,1>` / `fc2_kernel_ws<4,1>` (3 048 /
2 576 instructions: mbarrier pipelines with `QMMA` consumers) — faulted on silicon although every scoreboard dependency
was covered. Each cause was isolated the same way: ptxas's OWN schedule of the kernel with ONE distance changed (the
stall in front of an instruction moved behind it, every other field the vendor's), assembled over ptxas's cubin and run
in the served module against a recorded dump — 10 calls, ptxas's cubin through the same route as the control
(identical in 13 of 13 processes in every block). **Law** = that single change gives wrong bits or a fault.
**Practice** = ptxas never does otherwise in the census, but the single change gives identical bits. The census is
ptxas's schedules of the served MoE cubin (36 kernels, 128 528 instructions) and of 166 production cubins (752 kernels,
1 811 600 instructions); a distance is the sum of the stalls on the straight-line text.

| | what | ptxas (census) | silicon, the distance alone | under the switch |
|---|---|---|---|---|
| **law** | the high half of a 64-bit address base is a use: `LEA R4, … ; LEA.HI.X R5, … ; LDG … [R4.64]` reads `R5` (and the descriptor `UR8:UR9`) | never below 5: 34 581 sites | `LEA.HI.X` → `LDG` at 1: **CUDA_ERROR_ILLEGAL_ADDRESS** (at six store sites of `fc2`: identical — the register held the same upper word) | `wide_address_uses` |
| law (census) | the high half of a 64-bit register operand is a use: `IADD.64 R28, R28, UR4` reads `R29` and `UR5`; `ISETP.*64`, `MOV.64`, `SEL.64`; the target of `BRX` / `RET` | never below 5: 15 681 sites (4 when one 64-bit instruction wrote both halves; 4 for a transfer's target) | no control of its own; the `BRX` target at 1 (5 sites): identical — a sign extension that does not change | `wide_operand_uses` |
| **law** | a predicate destination is a result: `LOP3.LUT Pd, Rd, …` defines `Pd` AND `Rd` (also `UISETP`'s uniform predicate, `R2P` / `P2R`, the second register of `LDCU.64`) | 13 to a guard: 59 084 sites, none below; `Rd` to its reader 4 | the eight `LOP3` → guard distances of `fc1` at 1: **wrong bits** in 10 of 10 calls | `certified_xfer`, `predicate_register_xfer` |
| **law** | `F2F` (the float-format conversion, `F2F.BF16.F32`) is a scoreboard result — it was in no variable-latency list of the scheduler (they were learned from kernels without one) and was priced with the table's default 6 | every one of 104 results is read behind a scoreboard wait: 52 `F2F` carry a write barrier, the first reader of each of the other 52 waits the barrier of a later `F2F` it reads as well | the four barriered `F2F` of `fc2` without their barrier, the `PRMT` behind them without its wait and 2, 6, 9, 12, 15 cycles behind: **wrong bits** at every one — no distance replaces the barrier | `unlisted_scoreboard_result` (with `BREV`: 48 of 48 with a write barrier in the census, no silicon run) |
| **law** | an MMA holds its source registers against a fixed-latency overwriter (a load may follow at once: its result lands late) | 8: 56 723 sites, 16 524 at exactly 8, 28 below in two classes; never a read barrier on an MMA (0 of 39 624) | the overwriter at 2 and at 4 cycles behind a `QMMA`: **wrong bits**; at 6: identical. (cubit's own schedule of that loop tail had the overwriter at 2 behind a read barrier on the MMA, waited by the overwriter: wrong bits — the barrier does not replace the distance) | `hold_need`, `hold_operands` |
| **law** | a uniform-datapath reader (`ULEA`, `UIADD3`, `UIMAD`, `UISETP`, `ULOP3`, `USHF`, …) holds its uniform operands against a `UMOV` (a per-thread reader of the uniform register is followed at 1) | 3: 2 246 sites, 683 at exactly 3, none below | `ULEA UR4, UR5, UR4 ; UMOV UR5` at 1 and at 2: **CUDA_ERROR_ILLEGAL_ADDRESS** — 3 is the floor | `hold_need`, `hold_operands` |
| practice | a result has landed before a word that changes the warp's thread set: a register / a predicate / an MMA 7 / 13 / 29 cycles in front of `BSYNC`, `CALL`, `WARPSYNC.COLLECTIVE`, `NANOSLEEP.SYNCS` (`EXIT` 6 / 13 / 29), an MMA 14 in front of a conditional `BRA` | no site below on 22 698 per-thread sites; MMA → `BRA` 1 298 sites | 11 controls — a register 1 / 4 in front of `BSYNC.RECONVERGENT` (also in `fc2`'s chain of per-thread branches, where the warp really splits), 6 / 2 in front of `BSYNC`, a `QMMA` 8 / 2 / 6 – 7 in front of a guarded `BRA`, 19 in front of `BSYNC`: identical. Not run alone: the predicate rows, `CALL`, `NANOSLEEP.SYNCS`, `EXIT` | `settle_need` |
| practice | a control transfer is issued at stall 5 or more, with yield (`BRX` 58 of 58 at `[Y:S05]`; cubit's control-flow list had no `BRX` / `JMX`: under `CUBIT_SCHED2` the dispatch got an ALU stall of 1) | | every `BRX` at S01; all 209 control-flow words without yield: identical | `is_unlisted_transfer` |
| practice | a reuse flag (`R6.reuse`) stands only on a word with yield and a stall of 1 or 2 (nvdisasm does not print `.reuse` without the yield bit) | 10 155 of 10 155: 7 476 at S01, 2 679 at S02 | ten flags at S03 / S05 / without yield: identical | `settle_reuse` (the flag is dropped where the stall changed) |
| practice | `LDGSTS`, `SYNCS.ARRIVE`, the re-check `SYNCS.PHASECHK`, `FENCE`, the never-executed pads carry no wait mask | 0 of 1 163 / 168 / 200 / 27 / 875 | a wait on every `LDGSTS` (27) / arrive (4) / re-check (5): identical | `never_waits` (`CUBIT_SYNC_WAIT_ALL=1` lets them wait) |
| practice | a cache control on one line carries a read barrier | 52 of 52 | the eight of `fc2` dropped from ptxas's schedule: identical | the class "cache-line control" |

The last two laws are write-after-read distances — the latency table prices read-after-write only, and no barrier
covers them: `tools/stallfloor/war_census.py` builds the vendor's write-after-read rows from a frozen corpus and, with
`--against`, lists what a schedule has below them (`tools/ccdev.py` does the same for control codes ptxas never puts on
an opcode, `examples/opgaps.rs` for the definitions and uses the scheduler's operand convention misses). The limits of
all of it: one card type (Server Edition, ≤ 2 430 MHz), 10 calls per control, the sites of these two kernels.

### Where the served kernels stand (2026-11-10)

Scheduled by cubit from the plain instruction text — no control code of ptxas kept — with
`CUBIT_SYNC_CLASSES=1 CUBIT_SCHED2=1 CUBIT_SCHED2_LAT=sm120 CUBIT_MMA_PTXAS=1`, assembled over ptxas's cubin (`asm -T`,
no `--allow-stale-metadata`), run in the served module on the test host (RTX PRO 6000 Server Edition) against two
recorded dumps, 4 096 and 256 rows, three timed rounds with ptxas's cubin first and last in every round:

| kernel | bits | kernel time against ptxas's schedule, 4 096 / 256 rows |
|---|---|---|
| `fc1_kernel_wg<4,1>` | **identical: 7 of 7 processes, 190 calls** | **+16.7 %** (1 043.1 against 893.4 µs) / +1.3 % |
| `fc2_kernel_ws<4,1>` | **identical: 7 of 7 processes, 190 calls** | **+12.7 %** (642.9 against 570.1 µs) / +0.6 % |
| both in one module | identical: 7 of 7 processes, 190 calls | `fc1` +16.8 %, `fc2` +9.5 % / +1.3 %, +0.6 % |
| `fc1`, only the hand-off loops by cubit | identical, 190 calls | −0.1 % / 0.0 % |
| `fc1` with `CUBIT_SB_SHARE=1 CUBIT_RB_EARLY=32` | identical: 7 of 7 processes, 190 calls | **+6.3 %** / +0.3 % |
| `fc2` with `CUBIT_SB_SHARE=1 CUBIT_RB_EARLY=32` | CUDA_ERROR_LAUNCH_FAILED in the first process (Xid 43, no SM exception) | – |

The bits are right; the time is the barrier allocator's, not the stall model's. Crossed schedules of `fc1`: ptxas's
barriers with cubit's stalls **+1.2 %** (identical bits), cubit's barriers with ptxas's stalls **+17.8 %** (identical
bits). ptxas spreads its 369 write barriers over the six scoreboards (119 on scoreboard 0) and 438 instructions wait;
cubit puts 294 of 384 on scoreboard 0 and 964 instructions wait — a wait on a crowded scoreboard waits for every
producer on it. With the scoreboards shared as counters (`CUBIT_SB_SHARE`, the policy of the attention kernel) 153 of
`fc1`'s 384 write barriers stay on scoreboard 0, 786 instructions wait, and the cost falls to +6.3 %.

## Open items

1. **A launch failure without an SM exception (Xid 43) on `fc2`**, seen in three builds and in none of the others: with
   `CUBIT_SB_SHARE=1` (the first process), and with one region of the kernel kept as ptxas scheduled it inside cubit's
   schedule (once after 70 clean calls, once at the first call) — while the kernel scheduled whole by cubit without
   sharing is clean in 380 calls. Not understood; `tools/sbcheck.py` passes all three.
2. **The allocator's cost** on a kernel of this size: +16.7 % on `fc1`, +12.7 % on `fc2` (`fc2`: 268 of 347 write
   barriers on scoreboard 0 against ptxas's 87 of 325; 837 waiting instructions against 356). Shared scoreboards take
   `fc1` to +6.3 %; ptxas's own allocation is the bound (+1.2 % with cubit's stalls).
3. Write-after-read by distance is implemented for the two classes with a silicon run (MMA, uniform datapath against
   `UMOV`). The census has more classes whose minimum is above 1 on dense counts (`IADD3` → `IADD3` 2 on 14 693
   sites, `LOP3` → `LOP3` 2 on 20 825, `PRMT` → `PRMT` 2 on 15 325, `IADD.64` → `IADD3` 3) while others are followed
   at 1 (`FMUL` → `FMUL` 6 553 times); cubit's `fc1` has 23 such sites below ptxas and gives identical bits. Not
   modelled, not measured.
4. The MMA hold is ptxas's 8; the silicon floor on this card is 5 or 6 (4 wrong, 6 identical).
5. The scheduler's variable-latency lists were learned from corpora, and a corpus without an instruction teaches
   nothing about it. `tools/stallfloor/scoreboard_class_census.py` lists the opcodes whose results ptxas never reads
   without a scoreboard in the two corpora: `LDG`, `LDCU`, `LDC`, `LD`, `S2R`, `S2UR`, `F2I`, `FLO`, `POPC`, `ATOM`,
   `ATOMG`, the `SYNCS` results, `F2F` and `BREV`. The last two were in no list; under the switch both are scoreboard
   results — `F2F` with its silicon run, `BREV` by the census alone (48 of 48 with a write barrier; no kernel of ours
   has one). An instruction that neither corpus contains is still unknown.
6. Whether `LDGSTS` / `SYNCS.ARRIVE` / the re-check need to be free of a wait mask is not a law (a wait gives identical
   bits); the scheduler follows ptxas.
7. `UTMALDG` / `UTMASTG` (the tensor-map forms) and `FENCE.VIEW.ASYNC.G` take the class of their bulk / fence sibling;
   no probe kernel uses them.
8. The sleep form of an mbarrier wait: ptxas chains a read barrier from one `TRYWAIT` to the next
   (`[B0-----:R0:W1] SYNCS.PHASECHK.TRANS64.TRYWAIT` at the head of the suspend loop, 5 of 5 in the served `fc1`); the
   scheduler sets a read barrier only where an operand is overwritten.
9. A partly frozen kernel (some lines with a `[B:R:W:Y:S]` prefix, some without) is safe only where the path-aware check
   (`tools/sbcheck.py`) is clean: an unfrozen producer does not take the scoreboard its frozen reader waits — and
   item 1 says that a clean check is not the whole story.
10. The stall behind `BAR.ARV` is 8 (ptxas's value in the megakernel probe); the measured floor is 1.

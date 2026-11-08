# SM120 memory-ordering and async-proxy idioms, as ptxas schedules them

How nvcc 13.0 (`-arch=sm_120a`) lowers the PTX primitives a persistent, device-scheduled kernel is built from, and the
control codes ptxas puts on them. Source: the primitive probe of vLLM-Moet's megakernel programme (nine kernels, 472
words: bulk copies, mbarriers, fences at every scope, `setmaxnreg`, the acquire / release idioms, cluster barriers)
compiled on 2026-11-08, disassembled with nvdisasm 13.4 and frozen by `cubit disassemble --frozen` — the control codes
below are ptxas's, quoted as `[B<wait>:R<rd>:W<wr>:Y:S<stall>]`. The encodings are measured rows of `sm120.json`
(`tools/probes/re_sm120_{ublkcp_dir,fence_view_async,vote,usetmaxreg}.py`, 2026-11-08); the words are exact suite pins
(`tests/corpus_pins.rs::megakernel_corpus_sm120_strict`). Scheduling facts marked *law* were measured with nvdisasm;
the rest is what ptxas emits — a reference for hand-written SASS, not a model cubit's scheduler implements yet (the
open items are listed at the end).

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

## Open items for cubit's scheduler (not modelled today)

1. `FENCE` has no `ctrl_class`: ptxas gives it a write barrier its consumers wait on (the static `barrier` class would
   drop it).
2. The mbarrier words (`SYNCS.*`) have no `ctrl_class`: `TRYWAIT`'s predicate is a variable-latency result (scoreboard),
   `EXCH` / `ARRIVE` carry read barriers on their sources.
3. `BAR.ARV`'s stall floor and the arrive / sync pairing are unmeasured (ptxas: S08 after `BAR.ARV`).
4. SB0 must be reserved for the bulk group when `UBLKCP` / `UTMA*` / `LDGDEPBAR` are present, and the S12 issue floor
   after `UBLKCP` / `UTMALDG` belongs in `stallfix`.

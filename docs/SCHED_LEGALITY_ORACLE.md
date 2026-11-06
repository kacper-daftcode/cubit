# Static scheduling-legality oracle (regression corpus for the scheduler)

Why: the scheduler's 2-CTA/SM WAR bug (a missing store-address read barrier, fixed in `ebbd1dc`,
2026-06) was found on silicon after weeks of kernel work. It would have been found on the CPU by
comparing cubit's schedule of a kernel with the schedule nvcc gave the same instruction stream:
every dependency nvcc protects with a scoreboard or a stall, cubit must protect too. This document
specifies that check as a static oracle over the frozen census kernels; it is the specification for
`tests/sched_legality_corpus.rs` (status 2026-11-06: **implemented** — as `tools/sched_oracle.py`,
the corpus driver, plus `tests/sched_legality_oracle.rs`, the 6 in-tree pins of P1/P2a/P2b, the
probe's no-false-positive property and two publish-corpus fixtures. The core insight beyond this
spec: the verifier alone is blind to a schedule that never SET the read barrier — the 2026-06
shape itself — so the tool's rb-coverage probe injects a free barrier index into every bare
late-latching mem-op, batched by disjoint register sets, and re-verifies; R255/RZ findings are
non-events. See KNOWN_ISSUES A4).

## Corpus

Frozen nvcc schedules are what `cubit disassemble --frozen` emits: every instruction with its
`[B:R:W:Y:S]` control code. The corpus is a set of small kernels from the production cubins (one per
instruction family the project's kernels use: QMMA K-loop, LDGSTS pipeline, LDS/STS epilogue, LDG/STG
streams, barrier/arrive patterns, uniform-datapath address arithmetic) stored under
`tests/fixtures/sched/<kernel>.frozen.sass` (a few hundred instructions each, ≤ 1 MB total).

## Invariants (checked against the frozen original, instruction by instruction)

1. **RAW through a variable-latency producer** (LDG, LDS, LDC/LDCU, S2R, MUFU, QMMA/HMMA, SHFL,
   ATOM*, LDSM): the consumer of a register written by such a producer must wait on the barrier the
   producer sets (`W` of the producer ∈ `B` of the consumer, or an intervening instruction's wait
   covers it), or sit after a drain the frozen schedule also has.
2. **WAR on a source of a variable-latency reader** (the `ebbd1dc` class): an instruction that
   overwrites a register a pending LDGSTS/STG/STS/ATOM reads must wait on that reader's read barrier
   (`R` of the reader ∈ `B` of the writer). Store *addresses* count as sources.
3. **WAW**: a second write to a register with a pending scoreboard write must wait on it.
4. **Back edges**: at every backward branch the wait set of the loop header must cover every barrier
   still armed at the branch (drain before the back edge), as in the frozen schedule.
5. **QMMA constraints** (SM120): no wait mask on a QMMA whose accumulator chain continues; the
   `@!UPT UIADD3 URZ` drain pattern after the last QMMA of a chain; accumulator registers of a
   cooperative chain not touched between its QMMAs (see `docs/sasstuning.md`).
6. **Fixed-latency stalls**: for an ALU → ALU dependency at distance d, cubit's stall ≥ the frozen
   stall of the same pair (the frozen schedule is the lower bound ptxas chose; after the SM120
   stall-floor measurement, ≥ `floor_global` instead).

## Procedure of the test

For each corpus kernel: strip the control codes (`[B------:R-:W-:-:S01]` on everything) → run
`cubit sched --mode list` (or the automatic scheduler of `asm`) → read back the resulting controls
→ evaluate invariants 1–6 against the frozen original. The test fails on the first violated
invariant and prints the two schedules side by side at the offending instruction. A second mode
checks the frozen original *itself* against the invariants (the oracle must accept nvcc's schedule;
a disagreement is a bug in the oracle, not in nvcc).

## What this does not do

It cannot prove that cubit's schedule runs correctly (the hardware may tolerate more or less than
the invariants); it proves cubit never protects *less* than nvcc did on the same stream — which is
exactly the class of the 2026-06 defect. Measured floors (`SM120_STALLFIX_PLAN.md`) later tighten
invariant 6 from "not less than nvcc" to "not less than silicon".

## The path-aware walk — design note (NEEDS_OWNER 39, 2026-11-06; not implemented)

**What the verifier does today.** `run_verify` (`src/scheduling_pass.rs`) simulates one warp's
scoreboard over the instruction *text in order* (`SbState`: pending write barriers per register,
recycled barriers, late-latched operands per read barrier), then re-walks every statically resolved
loop body once from its end-of-iteration snapshot (the BUG-347 wrap pass), and counts
register-indirect / unresolvable edges as `UNRESOLVED-EDGE` (fail-loud). For cubit's own kernels —
straight-line code with a few loops, every branch target a label — this is exact. On nvcc's
structured code it over-reports in two ways the oracle (`tools/sched_oracle.py`) filters after the
fact with its own control-flow graph (census of 752 frozen sm_120 kernels, 2026-11-06):
`nonlinear-path` — 124 902 events whose two instructions are connected in the text only across an
unconditional `BRA` / `EXIT` / `RET` (the linear walk carries a fall-through state no path has, and
misses the waits on the real paths); `unreachable` — 121 504 events whose writer is not reachable
from the mem-op at all (subroutine bodies placed after the kernel's `EXIT`, `BSSY` / `BSYNC`
regions). Both are limitations of the walk, not races: with the filter every census verdict is
ACCEPT or a named, measured divergence (KNOWN_ISSUES A4).

**The design.** Replace the single linear state with one state per basic block, joined at labels:

1. *Blocks.* Split the text at every branch target (label / resolved address) and after every
   terminator (`BRA`, `BRX*`, `JMP*`, `EXIT`, `RET`, `BSYNC` with a `BSSY` partner, `CALL`); the
   instruction set already resolves targets (`branch_target`, `resolved_back_edges`,
   `unresolved_edge_class`). Guarded branches (`@P BRA`) fall through *and* jump; `EXIT` ends a
   path; register-indirect targets (`BRX`, `JMX`, `RET.REL.NODEC` to a register) stay what they
   are today — an unresolved edge, reported — but no longer poison the fall-through state.
2. *State and join.* `SbState` is already a value type (cloned for the wrap snapshots). The join
   of two predecessor states at a label is the *union* of their pending / lost / late-latched maps
   — a register is pending on a barrier if it is on **any** incoming path (the conservative
   direction: an extra entry can only add a finding, never hide one) — with the producer index of
   the entry kept per path (a finding names one path's producer). A wait mask releases the
   barrier's entries on the path it is on exactly as today.
3. *Walk.* Worklist over blocks in reverse post-order from the entry; a block is re-walked when
   its input state changes (monotone: the join only grows, each map is bounded by registers ×
   barriers, so the fixpoint is reached in ≤ (loop depth + 1) visits of each block in practice; put
   a hard cap — e.g. 8 visits — and report `UNRESOLVED-EDGE`-style if it is hit). The wrap pass
   becomes a consequence of the fixpoint (a back edge feeds the header's input state), so the
   BUG-347 re-walk and its snapshots are subsumed — keep them for one release as a cross-check
   (`CUBIT_VERIFY_LINEAR=1` runs the old walk; the two must agree on every cubit kernel of the suite
   and differ on the census only by the two filtered classes).
4. *Distances.* `stall_gap` (the issue distance for the late-latch windows) is per path too: the
   sum of stalls along the block path from the mem-op to the writer; at a join take the *minimum*
   over incoming paths (again the conservative direction). Blocks carry their stall sum so the
   minimum is a per-block scalar, not a per-instruction walk.
5. *Reporting.* Every finding names the path (`insn[a] … insn[b] via block L_12 → L_15`); the
   oracle's `nonlinear-path` / `unreachable` classes disappear from the tool because the walk no
   longer produces them (`classify_verifier_events` keeps the other classes).

**Size estimate.** ~400 lines in `scheduling_pass.rs` (block splitting over the existing target
resolution: 80; the join and the worklist: 120; per-path distances: 60; reporting: 40; the
`CUBIT_VERIFY_LINEAR` cross-check and plumbing: 100), ~150 lines of tests (a diamond, a loop with
a guarded exit, a subroutine behind `EXIT`, a `BSSY`/`BSYNC` region, the BUG-347 and BUG-486
fixtures re-pinned to the same verdicts), and one census re-run of the oracle to show the two
classes at zero with every other verdict unchanged. One session of work (a day with the gate),
not the four hours the T-12 brief allowed — so **not started by T-12**. Acceptance: (a) every
test of the suite that pins verifier output passes unchanged; (b) on the 752 census kernels the
new walk reports no `nonlinear-path` / `unreachable` event (the oracle's filter has nothing to
filter) and the same core counts (0 REJECT, the measured divergence classes) as `T/t9/oracle/`;
(c) the verifier's run time on the census stays within 2× of today's.

**What it buys and what it does not.** It makes the verifier a grader of nvcc kernels without the
tool's CFG filter (the oracle's divergence classes would then be the verifier's own output) and
removes the linear-walk caveat from KNOWN_ISSUES A4. It does not change any production schedule:
the allocator (`reallocate_barriers`) does not use the verifier's state, and the 99 production
sources have no subroutine or `BSSY` region that the linear walk mis-handles (all ACCEPT today).
Nothing shipped depends on it — the owner's call whether a session goes to it.

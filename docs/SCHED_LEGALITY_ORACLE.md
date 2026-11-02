# Static scheduling-legality oracle (regression corpus for the scheduler)

Why: the scheduler's 2-CTA/SM WAR bug (a missing store-address read barrier, fixed in `ebbd1dc`,
2026-06) was found on silicon after weeks of kernel work. It would have been found on the CPU by
comparing cubit's schedule of a kernel with the schedule nvcc gave the same instruction stream:
every dependency nvcc protects with a scoreboard or a stall, cubit must protect too. This document
specifies that check as a static oracle over the frozen census kernels; it is the specification for
`tests/sched_legality_corpus.rs` (status 2026-11-02: specified, not yet implemented —
`docs/KNOWN_ISSUES.md` A4).

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

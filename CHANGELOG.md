# cubit changelog

User-visible changes, newest first. Table syncs name the blackwell-isa revision they vendor
(`tables/SOURCE.json` pins it byte for byte). Numbered `BUG-NNN` entries are the encoder /
decoder findings whose executable specification is `tests/bugNNN_*.rs` (index: `docs/TESTS.md`).

## Unreleased — 2026-11-10 (session SCH-2: two prices of the sm_120 dependency table that were one cycle short — opt-in path only)

- **`CUBIT_SCHED2_LAT=sm120`: the upper register of an `IMAD.WIDE` result is priced apart, and `CS2R → IMAD` is 6**
  (`tables/dep_latency_sm120.json`: section `result_high`, one pair cell; `src/dep_stall.rs`; `tools/stallfloor/README.md`).
  A second session's probe (`stall_floors_sm120_20261110_em_blk3.json`: 392 kernels, three geometries, 20 launches) found the first
  kernels that the table called safe and silicon did not: a reader of the HIGH register of a 64-bit product one cycle too close
  (`IMAD.WIDE → LOP3` / `→ LEA` at the cell's 4: wrong; clean from 5), and `CS2R Rn, SRZ → IMAD` at the cell's 5 (clean from 6). The
  two registers of a wide product are not ready together: low from 1–3 issue cycles, high from 3–5. ptxas knows — the census split
  by result register (`result_register_census.py`, 63 701 pairs) has the low register read from 3 and the high one never closer than
  5, or 4 into the multiplier — but the cells were mined from the merged pairs. Now a reader of the upper register takes the larger of
  the pair's cell and its own (`result_high.cells`: 7, by the dense-cell rule of the table), and without one the pair's cell lifted to
  the largest measured floor (5). `CS2R → IMAD` takes the measured 6 (its 24 census pairs are the 32-bit form). **Nothing else moves:**
  532 of the 533 pair cells are byte for byte, the generator without the two new options still writes the previous table, a table
  without the section loads and prices as before, and no production kernel has either form — the attention cubins (`v41s1`, `v42`,
  `v43`, `v43b`, `v41s1b`) and the MoE schedule set rebuild to their digests. Tests: three in `src/dep_stall.rs` (every floor of the
  probe at or below what that register's reader is charged) and `the_upper_register_of_a_wide_product_is_read_later` in
  `tests/sched2_dep_latency.rs` with the schedule the parent built pinned next to it (three stalls 4 → 5); all four are red on the
  previous table. The default path does not read the table.

## Unreleased — 2026-11-10 (session T-27: `CUBIT_VERIFY` checks the read barriers of stores on every path — three unprotected store → overwriter pairs of a production kernel had passed as "0 broken WAR"; batch 6 of the B300 lane's candidate forms on sm103a / sm100a — `QMUL4` and `QADD4` with their operand selectors (55 refs taken); a test of the suite that failed at random)

- **`CUBIT_VERIFY` checks the read barriers of stores on every path of the flow graph** (`src/store_paths.rs`; lines `STORE PATH: …` and
  `CUBIT_VERIFY_PATHS: N …`, `VerifyReport.store_paths`; read-only). A store reads its address and data registers when the memory pipe
  serves it, so whoever rewrites one of them must first wait on the store's read barrier (KNOWN_ISSUES A27). The scoreboard simulation
  behind "N broken WAR" could not check that in a kernel with control flow: it does not track shared stores at all, and its loop pass
  re-walks the TEXT of the loop body, so a wait that sits in a block the last iteration branches around counted as protection. **Found
  on a production kernel** (the sm_120 scheduler session, with a path walk of the frozen listing written independently in Python): in
  `sparse_mla_prefill_v43` / `v43b` three `STS.128` of the in-loop dequant have their data quads rewritten by the next chunk's
  `LDSM.16.M88.4` 58 / 67 issue cycles later with nobody having waited on their read barriers (4 pairs in `v42`; the shipped kernel and
  the `v41s1` schedules: none) — and `CUBIT_VERIFY` said "0 broken WAR". The new check walks from every store that holds a read barrier
  along every path — both outcomes of a guarded branch, loops included, a predicate known from the last branch on it until something
  writes it — to the first writer of each register the store reads; a path with no wait on the store's barrier is a finding, reported
  with the smallest issue distance. **It reproduces the independent walk row for row** (store, overwriter, register, barrier, distance)
  on the six attention listings (0 / 0 / 0 / 4 / 3 / 3) and on the 116 committed production cubins it was run on (112 × 0; 4, 3, 3,
  and 12 on an old build of the state kernel — here 8 + the 4 of the class counted apart, below). **The vendor's own schedules are clean under it:** in the 166 listings of the sm_120 census, 0 pairs on a data
  register of any store and 0 on the address pair of a global store; 97 pairs (two copies of each) sit on the ADDRESS register of a
  shared store, 8 to 24 issue cycles behind it — ptxas does not wait there — so that class is printed as a second count (`+ N …`) and
  is not in `N`. The three old counters and their line are unchanged ("broken WAR" keeps its meaning; the new line says what it could
  not see); a write is taken from the scheduler's operand model and from the register allocator's sm_120 footprints (`LDSM.….4` writes
  four registers). `tests/store_paths_verify.rs` (the frozen listing of `v43b` as the fixture: the three pairs, the unchanged bytes,
  the report's counts) + 4 unit tests. **Not fixed here: the allocator itself** — `war_overwriter` looks for the next iteration's
  overwriter along the same text, which is why the wait was placed where only the non-final iterations pass (KNOWN_ISSUES A30).
- **Tables vendored from blackwell-isa `1fb517a`: batch 6 of the B300 measurement lane's candidates — `QMUL4` and `QADD4`** (two more of the
  review refs `hidden-b300/*`, `qmul4` and `qadd4`; 55 of the 68 refs are taken; sm103a 545 → 549 forms, 37 524 → 37 530 rows; sm100a
  544 → 548, 37 518 → 37 524; the rows of sm120 / sm121a unchanged; rows without `_src` unchanged, 336). Forms added (6 rows per table):
  **`QMUL4.E4M3x4.E2M1x4.E4M3x4[.SATFINITE] Rd, Ra.<sel>, Rb.<sel>`** (opcode 0x27c — the packed FP4 × FP8 multiply of the vendor's
  production code, three production witnesses; a selector is mandatory on each source: `.B3210`, `.B3` … `.B0`, `.N7654`, `.N3210`,
  `.N6420` — three bits at [76:74] and [61:59] —, sign and abs on both) and **`QADD4.E4M3x4.E2M1x4[.SATFINITE] Rd, Ra.<sel>, Rc.<sel>`**
  (0x27d — a controlled vendor-text form, the lane has no production witness of it: the same eight selectors on `Ra`; `.B3210` / `.B3` …
  `.B0` on `Rc` at [87:85], whose values 5 – 7 nvdisasm prints as `.INVALID5` … `.INVALID7` and the rows refuse). Each form also
  assembles from the spelling with the modifier in the mnemonic (an encode-only twin key `<op>.SATFINITE_R_R_R`). Vendor text and CPU
  round trips of complete words, no execution claim. **Engine — the candidates' own changes, applied as written behind the lines of the
  scaled F2FP unpack** (their bases are 46 / 48 commits old; ten "both added a line here" conflicts): three extractions `qmul4_sel`,
  `qadd4_ra_sel`, `qadd4_rc_sel` (loader, encoder, decoder, printer, `tools/sync_table.py`), each read only on its own opcode, and
  `QADD4` among the decoder's opcodes without a sign-tolerant fallback. **The gatekeeper's checks.** The engine differential:
  1 688 900 words — every row of the four tables (its constant word, each field at all ones, random fillings) and the sign-window
  combinations of the new keys — through the engine and tables before the batch and after it: 1 657 942 decode, print and re-assemble
  identically, 26 430 are refused by both, **4 528 differ, every one a word of the two new keys on sm103a / sm100a that had no row
  before; no word of sm120 / sm121a and no word of an existing row changes.** nvdisasm 13.1 on all 4 528: the 1 497 without a reuse flag
  print the vendor's text and re-assemble to themselves; the 3 031 with a reuse flag in the list's otherwise empty control word are
  refused by nvdisasm as control words, and with the production control word of the lane's first witness in its place every one prints
  the vendor's text and round-trips (3 011 distinct words). The two fixtures named again with nvdisasm 13.1 on `-b SM103` and
  `-b SM100` (the lane measured with 13.3 on SM103; the rows are on both tables): 3 170 word / target pairs, 2 624 texts identical,
  546 without text on both, none different. **Pins moved to `main`'s table layout, none of them of the measurement:** a source's
  `rows` counts every row that resolves to its tag — 3, the twin key included (the lane declared 2); a field's own `_src` reads
  "absent or equal"; the twin key's row is compared with its key-level note resolved. Ten refs are pending (the five packed-FP32
  immediate forms, where the compiler sets a bit the candidates' rows leave clear; `vimnmx3` and the four `VIADDMNMX` refs, which
  change rows measured since their bases), `movm` is returned to the lane.
- **`tests/kand058_ufadd_imm_neg.rs` no longer races on its own scratch table.** The test wrote its two-row table to a temporary file
  named by the process id and the Debug text of `Instant::now()`; two of its test threads that read the clock at the same reading shared
  the path, and one thread's rewrite emptied the file the other was parsing (`floatimm_negative`: "failed to parse table JSON — EOF while
  parsing a value at line 1 column 0"). Measured on the test binary alone: 259 failing runs of 10 000 at three test threads and 8 of
  10 000 at two (the suite's setting — one push gate went red on it); with a counter of the process in the name 0 of 20 000 and 0 of
  10 000 (0 of 10 000 at sixteen threads). The file is removed once the table is loaded (every run used to leave four in the temporary
  directory). No other test names a file by the clock; the encoder is not touched.

## Unreleased — 2026-11-10 (session SD-1: the sm_120 dependency table checked against the other hand-written production kernels — evidence only, no behaviour change)

- **The pair-latency table beyond the attention kernel: `QMMA.SF` and `IADD.64` in the census, 31 more pair floors on two card types**
  (`tools/stallfloor/README_v5e.md`, `tests/dep_latency_corpus.rs`). The 92 auto-scheduled production sources of vLLM-Moet (89 MoE GEMM
  kernels on 2-bit / FP4 / quintal planes, the state-prefill kernel, the two attention kernels) assemble with
  `CUBIT_SCHED2=1 CUBIT_SCHED2_LAT=sm120 CUBIT_MMA_PTXAS=1` — the same instruction words, both verifiers clean, the MoE set's stall cycles
  per warp 704 309 → 325 130 — and bind on pairs the table's census could not see: the register-liveness model has no def / use rule for
  the 7-operand `QMMA.SF` form nor for `IADD.64` (`depdump`: `known: false`), so `census_pairs_sm120.json` holds no row through either.
  `slot_census.py` and `qmma_census.py` mine them through the operand slots (142 rows, 146 962 pairs): ptxas's practice for QMMA is exactly
  the MMA rows (a reader 28, the accumulate operand 29, issue spacing 16, an ALU result into a fragment 7) and no default is below ptxas's
  dense practice. Silicon (harness v5e, 874 probe kernels; RTX PRO 6000 Blackwell Server Edition at ≤ 2 370 MHz and Workstation Edition at
  ≤ 2 820 MHz — the same floors and the same verdict of every kernel in every run): `QMMA → FFMA` 20, the QMMA chain and spacing
  interlocked by the tensor pipe, `R2UR → UIADD3` 8, everything else 1 … 5. **No price is below a floor; four are exactly the floor —
  `ISETP →` the guard of `BRA` / `EXIT` (13), `LOP3 → PRMT` (4), `UIADD3 → UISETP` (4).** No cell, default or source line changes.
- **The MMA reader row is the floor of a QMMA's upper result registers, as it is for HMMA**
  (`tools/stallfloor/mma_result_registers_sm120_20261110_qmma.json`, the layout of the HMMA file). `QMMA.SF` result register k → `FFMA`,
  nothing waited, distance 1 … 45, two runs on each of the two card types with the same verdict of all 165 kernels: registers 0 / 1 are
  wrong at every distance up to 19 and clean from 20; **registers 2 / 3 are wrong up to 27 — on every thread to 24, on a quarter of them
  at 27 — and clean from 28, the `to_data` row exactly.** The first measurement of the row (20) had read register 0. ptxas never reads a
  QMMA result earlier than 28 (13 204 `FFMA` readers); the 89 MoE GEMM sources under the three switches read registers 0 / 1 / 2 / 3 at
  28 / 29 / 36 / 37 cycles at the earliest. `pairfloor_gen_e.py` gains the three pairs (`qmma_data_r1..3`, 138 kernels; its other 874
  kernels are byte for byte what they were); `tests/dep_latency_corpus.rs` pins the four floors against the row. No cell moves.

## Unreleased — 2026-11-10 (session RA-1: `cubit ra` on a production sm_120 kernel — the register allocator certified on the sparse-MLA prefill attention kernel; two fixes of the pass, `--target sm120` and `--no-share` opt-in, the default allocation unchanged)

- **`cubit ra` reads the attention kernel.** Every mode refused it (`unknown predicate-role op(s): VIMNMX.S32, FMNMX.FTZ`, then
  `FSETP`). The Strict predicate families now know the min/max selector (`FMNMX` / `VIMNMX` / `HMNMX2` with one predicate, in
  the last slot: a use) and `FSETP` (ISETP's shape); Compat keeps the reference's list. Identity on the kernel: zero changed
  numerals.
- **The renderer keeps register operand selectors; its proof compares them** (`cubit render`, `ra --mode full`, `ra --mode apply`).
  `.H1` / `.H0_H0` / `.H1_H1` / `.B0`…`.B3` and the operand modifier flags live in the source text, where the encoder reads
  them; the renderer printed operands from the structured form and dropped them, and `structural_eq` compared two parses that
  both lack them. On the kernel's v41 text 608 selectors went and the output still assembled — into another kernel, with a
  clean scoreboard verifier. A bare register token that carries a suffix chain besides `.reuse` is now re-printed from its
  source token with only the register name replaced, and the proof fails on a chain that is dropped, moved or changed. Text
  without selectors renders byte for byte as before.
- **`cubit ra --mode full|apply --target sm120`** (`src/ra_target.rs`) — the allocation made for the silicon: 64-bit pairs on even
  registers and quads on multiples of four; the footprints the role table does not carry (the address pair and the descriptor
  pair of `desc[UR][R.64]`, the pair `CS2R` writes, the two registers of `LDSM.2`); liveness in which a guarded write does not
  end the life of the value it may overwrite; three group orders, the plan with the lowest watermark kept; the plan audited
  against the footprints (also a plan given with `--mode apply`); a register read before it is written is an error; `.reg`
  rewritten to the registers the plan uses; `target`, `regcount`, `peak_live_r` in the report. Without `--target` the pass is
  what it was — and its plan for this kernel is not sm_120 code (pairs on odd registers; KNOWN_ISSUES A28).
- **`cubit ra --mode full --no-share`**: every numeral keeps a register of its own — an injective renaming, so the result has the
  register dependencies of the source and assembles to the same schedule. By default two values that are never alive together
  may share a register, which saves registers and can add a wait (the second value's write behind a load address or store data
  the memory pipe has not latched yet).
- **Measured** (the kernel's two source texts, 2 535 and 1 449 instructions, R0–R125 by hand): re-numbered from zero on
  R0–R124 (register count 128 as by hand; 126 registers with `--no-share`); `CUBIT_VERIFY` 0 / 0, `CUBIT_DEP_VERIFY` 0, strict
  round trip complete; every control word equal to the hand-numbered build's; on silicon (RTX PRO 6000 Server and Workstation
  Edition) output and lse identical on 8 synthetic cases and 8 real-prefill dumps in 30 warm launches and 30 fresh processes,
  times within ±0.3 % at every shape, as for two further numberings.
- **The register grid of sm_120 is silicon law** (`tools/ra/`): 38 probe kernels, every multi-register operand off its grid
  faults the launch (CUDA 715) — 23 of 23, 15 shapes; ptxas is never off it in 1 811 600 census instructions.
- **BUG-008: the wide IMAD's pairs are checked in every form — addend, destination, uniform addend.** The guard saw only
  the 4-operand spelling: `IMAD.WIDE.U32 R10, PT, R4, R5, R7` assembled silently to the word that faults (and the message
  recommended that spelling). Measured on silicon (two probe sets, `tools/ra/`): a pair on an odd register ends the launch
  with CUDA 715 whatever the form — the odd addend in the `PT` spelling, an odd destination, both again with a real
  carry-out predicate (`IMAD.WIDE.U32 R12, P0, …`) and in the carry-in form (`.X`), an odd destination with a uniform
  addend, and an odd uniform addend pair (`IMAD.WIDE.U32 R12, R6, R7, UR7`). All are hard errors now
  (`CUBIT_DISABLE_ERRATA=1` assembles them for RE). The measured rows of the table re-assemble such field words: the 32
  that are refused now carry the `silicon_bits` mark in `tests/fixtures/sm120_rows_intalu_nvdisasm.jsonl` (the mark the
  row probe gives a field word the encoder refuses on a silicon law; written by that rule, 784 field words of the 16
  `IMAD.WIDE` rows re-assembled). The predicate behind `Rd` is the carry of the 64-bit sum (four more kernels,
  `tools/ra/gen_carry_probes.py --set3`), and a guard six issue cycles behind the IMAD — where the default schedule
  puts one — still reads its earlier value: KNOWN_ISSUES A2. The other 21 off-grid shapes still assemble:
  KNOWN_ISSUES A28 (1).
- `docs/RA_SYMBOLIC_REGISTERS.md`: how to write a generator with symbolic registers and what the pass guarantees. With the measured
  tables of the attention kernel: v41 / v42 (125 registers for 126 numerals, 0 control words differ) and v43 (127 for 130;
  4 of 1 489 control words differ with sharing, 0 with `--no-share`; bits and times the hand-numbered kernel's in both).
  `tools/ra/ra_equiv.py`: an independent check of a renaming (its own footprints, liveness and control flow).
  Tests: `tests/ra_sm120_attention.rs`, `ra_sm120_target.rs`, `ra_sm120_target_cli.rs`.

## Unreleased — 2026-11-10 (session SCH-1: the automatic scheduler on sm_120 — the `CUBIT_SCHED2` failures root-caused and fixed, a pair-latency table measured on sm_120 silicon, ptxas's MMA discipline; every switch opt-in, the default schedule unchanged)

- **`CUBIT_SCHED2`: the scoreboard arming rule — the fix for both silicon failures of the opt-in stall model** (`49f8340`). RULE 2 put the yield flag
  on a scoreboard producer whose waiter is the very next instruction, one cycle behind it (`MUFU.EX2 [W:Y:S01]` / `FSEL [B]`,
  `MUFU.LG2 [W:Y:S01]` / `FADD [B]`); the waiter passes its wait before the barrier is armed and reads the stale register. Isolated on
  sm_120 silicon (32 CTAs × 1 024 threads × 256 iterations × 20 launches): `MUFU`, `SHFL`, `LDC` and `LDS` setters alike — every thread
  wrong with yield at S01, clean without the yield, at S02, or with one instruction between; ptxas never schedules it (0 of ~70 000
  setter → first-waiter pairs of the sm_120 census closer than 2). Under `CUBIT_SCHED2` a waiter is now never closer than 2 issue cycles
  behind the instruction that set its barrier; `CUBIT_SCHED2_NOARM=1` keeps the old schedule for A/B runs. The default scheduler emits the
  same adjacency without the yield flag and is correct — it is not touched (KNOWN_ISSUES A26).
- **`CUBIT_SCHED2_LAT=sm120|<file>` (with `CUBIT_SCHED2`): a dependency latency is a property of the pair, enforced on every control-flow
  path.** `tables/dep_latency_sm120.json` prices a fixed-latency dependency by (producer class, consumer class, operand role): same unit 4,
  cross unit 5, predicate into a guard 13 but into a select 5, into an MMA fragment 7, the low half of an `IMAD.WIDE` addend 5 where its
  high half, read later, needs 4. `src/dep_stall.rs` computes, on the final instruction list and the final barriers, the minimum issue
  distance from every producer to every reader over the control-flow graph (fall-through, taken branches, joins, back edges) and raises
  stalls until every requirement holds — it never lowers a stall and never touches a hand-scheduled line. The issue spacing of the shared
  pipes (memory 4, `LDC` 8, multiplier 2 / 4, `BAR` → memory 6, MMA 16) and the arming rule run through the same machinery. A requirement
  stalls cannot reach fails the assembly; a table of another architecture is refused (latencies are measured per architecture: no sm_103a
  number is in the sm_120 table).
- **`CUBIT_MMA_PTXAS=1` (with the table): the warp-cooperative MMA as ptxas schedules it** — no `@!UPT UIADD3` writeback drain behind the
  MMA; two MMAs never closer than 16 issue cycles, the accumulate operand of the next MMA 29 behind the previous one, any other reader 28
  (the table's `mma` rows; 39 624 HMMA / QMMA of the census); one `NOP` where two text-adjacent MMAs need the 16 cycles. Default: the
  drain scheme, unchanged.
- **`CUBIT_SB_LONG_KEEP=1` (opt-in, with `CUBIT_SB_SHARE=1`): a prefetch keeps its scoreboard to itself.** Scoreboards are counters, so a
  wait on a scoreboard waits for everything counted on it. Under the sharing policy three kinds of use ended up on the scoreboard of a long
  prefetch and drained it early: a short use coloured before the long ones, a short use that overflowed onto "the busiest" scoreboard, and
  the read barrier of a store whose data registers are next written far away (a long use itself). In the production attention kernel the
  fifth `LDSM` of the QK chain waited for all 16 gather loads (`[B-1---5]`); one more load in the loop moved the gather to scoreboard 4,
  where the first instruction of QK waited. Under the switch the colouring takes long uses first, puts long loads on the top scoreboard and
  long store latches on the one below, and never lets a short use share either; waits move between scoreboards, none is dropped
  (`CUBIT_VERIFY` 0 / 0, `CUBIT_DEP_VERIFY` clean on the kernel). RTX PRO 6000, the kernel's own text: −1.4…−2.0 % where the gather misses the
  cache (random indices), ±0 on real prefill inputs; what it buys is that the prefetch survives changes of the kernel's text. Default off:
  every existing build is byte-identical (`tests/sb_long_keep.rs`: the drain pinned without the switch, absent with it; the same with the gather's scoreboard pinned by control codes - a pin
  alone does not keep the prefetch; opt-in; KNOWN_ISSUES A13). Minimal kernels (session RA-1; `tests/fixtures/sb_long_keep/edit_*.sass`,
  generated by `gen_edits.py` there): a four-load prefetch read ~300 instructions later over 32 rounds of four shared loads — without the
  switch the prefetch is split over scoreboards 4 and 5 and any one-line edit of the compute (a fifth load in a round, a load through its
  own address register, a temp renumbered onto it, no quiet stretch behind the prefetch) puts a waiter on it 33–214 instructions behind
  its last load; with the switch it sits alone on 5 and nothing waits before its first reader (two more tests, six in all).
- **`CUBIT_SCHED2` / `CUBIT_SCHED2_LAT` outside `cubit asm`: the library path no longer emits an illegal schedule when the switches are in
  the environment.** `cubit asm` runs `schedule()`, `reallocate_barriers()` and then the legaliser `dep_stall::apply`; `cubit::assemble` and
  the Python module's verifier ran the first two only, while `schedule()` read the switches from the environment. With `CUBIT_SCHED2_LAT`
  set it left every fixed-latency dependency to a legaliser that never came (`ISETP` → its guard at S01, measured floor 13; an `IMAD.WIDE`
  producer at S01); under plain `CUBIT_SCHED2` the arming rule was missing (`MUFU [W:Y:S01]` one cycle in front of its waiter — the
  schedule that reads a stale register on sm_120 silicon). Found by running cubit's own suite with the switches set (14 tests that call the
  passes directly failed on missing stalls). Now `schedule()` leaves the fixed latencies to the legaliser only for a caller that declared
  one (`scheduling_pass::DEP_LEGALISER_FOLLOWS`; `cubit asm` sets it), and `assemble` / the Python verifier run the arming rule
  (`dep_stall::apply_library_path`). The table stays a `cubit asm` feature — on the library path `CUBIT_SCHED2_LAT` gives plain
  `CUBIT_SCHED2`'s stream. `cubit asm` output is unchanged under every switch, the default path everywhere
  (`tests/sched2_library_path.rs`; KNOWN_ISSUES A26).
- **`CUBIT_SCHED2`: the instructions the dependency model does not see are named, and `CUBIT_SCHED2_STRICT=1` refuses a kernel that has
  one.** The switch charges a stall where a consumer needs it, so a producer without a definition in the scheduler's operand model, or a
  read missing from it, gets none — and neither the table's legaliser nor `CUBIT_DEP_VERIFY` can know. Every whole-kernel `CUBIT_SCHED2`
  build of the ptxas-compiled MoE kernels of the serving stack faulted on sm_120 silicon on such forms: the predicate-result
  `LOP3.LUT Pn, Rd, …`, definitions of uniform predicates (`UISETP`, `VOTEU`), `BRA.DIV` / `BRA.CONV` / `BRX`, 64-bit operands whose
  halves have different producers. `dep_stall::blind_spots` lists them; `cubit asm` prints the list under `CUBIT_SCHED2` and under
  `CUBIT_DEP_VERIFY` (only when it is not empty), and with `CUBIT_SCHED2_STRICT=1` writes no kernel. No stall of any kernel changes; the
  attention kernel has no such form and builds byte for byte with and without the strict switch (`tests/sched2_blind_spots.rs`, which also
  pins the minimal case of the hole; KNOWN_ISSUES A26). The operand model itself is not extended here — the default scheduler shares it.
- **The table's MMA → reader row is a measured floor, not ptxas's caution: result registers 2 and 3 of an `HMMA` need 28 issue cycles.**
  The session's own probe read the first result register only and reported "floor 20"; a second session's per-register probes
  (`tools/stallfloor/mma_result_registers_sm120_20261110_em.json`, 60 kernels × 20 launches) show registers 0 / 1 clean from 20 and
  registers 2 / 3 wrong up to 27, clean from 28. The row stays 28 (no cell or row changes; `tables/dep_latency_sm120.json` changes in the
  `mma` note and in `provenance` only and regenerates byte for byte with the README command, which gains `--mma-registers`); the unit test
  `the_mma_data_row_holds_every_result_register` fails if the row is ever lowered below a register's floor. The attention kernel reads the
  four registers at 28 / 29 / 30 / 31, as ptxas does (KNOWN_ISSUES A26).
- **The scaled BF16 unpack under the table (`F2FP.BF16.<E4M3|E2M1>.UNPACK_B Rd, Rs[.sel], Rscale.B0`, the row of `89564ac`): measured,
  no cell moved.** It is of the class `F2FP.UNPACK` (source r1, scale register r2). Harness v5 on sm_120 silicon
  (`tools/stallfloor/pairfloor_gen_d.py`, 175 kernels; `stall_floors_sm120_20261110_pairs_d.json`): `MOV` → its scale register 5, `SEL` →
  its source 5, `SHF` → its source 4, its result → `HMUL2` 5 (either operand), → `STS` data 3, → the last register of `STS.128` 1 — the
  floors of the plain forms of the class, all at or below the cells and the default 6 that price them (`dep_stall`'s
  `no_cell_is_below_a_silicon_measurement` now reads the file; `the_scaled_unpack_is_priced_as_f2fp_unpack`). A dequant written with it
  — eight unpacks behind their loads' barriers, two `STS.128`; the unit scale code, the byte selectors, `HMUL2` by a block scale —
  schedules at S01 per unpack under `CUBIT_SCHED2_LAT=sm120` (`tests/sched2_dep_latency.rs`
  `the_scaled_unpack_dequant_holds_the_table`, fixture `dequant_unpackb.sass`); the table file changes in its `provenance` only.
- **Small switches of the same family**: `CUBIT_SCHED2_YIELD=loads` (the default scheduler's yield policy under SCHED2's stalls),
  `CUBIT_DEP_VERIFY=1` (read-only: every fixed-latency dependency below its table latency on some path, waits inside the arming distance,
  spacings — also on frozen kernels), `CUBIT_DEP_CELLS=<file>` (one JSON line per requirement a schedule rests on, for weighing the
  table's cells by execution count).
- **The table is measured, not copied** (test host, 4× RTX PRO 6000 Server Edition, GPU 0; `tools/stallfloor/`, harness v5 / v6 with an
  S15 reference kernel per pair as the oracle). 533 cells = the minimum distance ptxas ever schedules, dense cells only (166 cubins,
  1 811 600 instructions; `examples/depdump.rs` + `dep_latency_census.py`). Silicon: 45 pair floors, every one at or below its cell;
  populations of 20 624 kernels over 200 cells (random registers, yield flag, neighbours) at the cell's latency and one cycle below —
  8 958 of 10 312 fail one cycle below, 99 failed AT the latency, all in three cells whose role had merged the two halves of an
  `IMAD.WIDE` addend (split into `r3` / `r3h`, re-measured clean; `dep_stall::tests::no_cell_is_below_a_silicon_measurement` pins the
  table against the result files). MMA: result → ALU reader floor 20 (row 28); the accumulate operand and two MMAs back to back are
  clean at every distance 1…30 — the tensor pipe interlocks them, the rows keep ptxas's spacing. Producer → store data floor 3 (cells
  5). The table regenerates byte for byte from the files in `tools/stallfloor/` (`gen_dep_latency.py`).
- **The cells the attention kernel binds on that were census-only, measured** (harness v5c, `pairfloor_gen_c.py`; two identical
  runs + a store-address run): `IADD3` / `IMAD` → `LDS` address 4, → `STS` address and `IMAD.WIDE` → `LDG` address clean from S01 (a
  memory instruction reads its address when the pipe serves it), `FADD` / `FMNMX` → `SHFL` 3, `F2FP.PACK` / `FSEL` → `STG` data 3 (cells
  5); `ISETP` → the guard of a store / a load 13 / 11 / 9 at d0 / d1 / d2 (cell 13); the high half of an `IMAD.WIDE` addend clean from
  S01 (cell 4). No latency of the table moved: twelve more cells carry a `silicon` note (213 of 533), the pinning unit test reads the
  two new result files. Every binding requirement of that kernel now rests on a silicon run at or below its cell.
- **`dep_stall`: the accumulate operand of an MMA is all four of its registers** — after the `r3` / `r3h` split of multi-register
  third operands the lookup priced only the first register of an MMA's accumulate operand with the `mma.to_mma_accumulate` row and
  the upper three with `mma.to_data`. With the shipped rows (29 / 28) the binding value is the same 29 and no schedule moves; a table
  whose accumulate row is below its reader row was priced wrong. `dep_stall::tests::bundled_table_parses_and_names_the_measured_pairs`
  asserts the row on each of the four registers.
- **The store latch (NEEDS_OWNER 38 (ii)) measured** (`latch_gen.py` / `latch_run.py`): a bare `STS` / `STG` whose data register is
  overwritten d issue cycles later stores the NEW value under load — at 32 warps per SM `STS` is wrong on every thread for d ≤ 19, on
  96 % of the threads at 20, 63–77 % at 21–30, last mismatch at 48 (`STG`: 56); with one warp per SM it is clean from d = 1; without the
  overwriter, or with a read barrier on the store and the overwriter waiting on it, clean at every distance. A store's operand latch is
  the memory pipe's service time, not a count of issue cycles: cubit's rule (a read barrier, never a distance) stays (KNOWN_ISSUES A27).
  The load series (one CTA per SM, 1 … 32 warps storing in lockstep): `STS` clean from d = 1 up to 8 warps per SM, last mismatch at 12
  with 16 warps and at 48 with 32; `STG` clean up to 4 warps, 6 with 8, 38 with 16.
- **On the kernel the model was written for** (the sparse-MLA prefill attention `sparse_mla_prefill_v41` of vLLM-Moet, 2 535
  instructions; its own harness, µs per launch at four shapes, the shipped schedule in the same rounds): stall cycles per token-warp
  67 807 → 44 165 (`CUBIT_SCHED2`) → 41 979 (+ the table) → 35 555 (+ `CUBIT_MMA_PTXAS`); time 1 058 / 1 153 / 2 503 / 1 025 →
  933 / 1 021 / 2 240 / 903 → 922 / 1 011 / 2 222 / 892 → **898 / 986 / 2 162 / 864 (−15.1 / −14.5 / −13.6 / −15.7 %)**; output and lse
  bit-identical on 8 synthetic cases and 8 real-prefill dumps, 30 warm launches and 30 fresh processes each. Stall cycles −48 % buy
  −15 % of time: ncu on the last schedule shows the fixed-stall `wait` at 2.78 of 9.4 warp-cycles per issued instruction (5.34 of 10.0
  before) and the tensor-pipe throttle, the scoreboards and the barrier taking up what the stalls released.
- **Default path**: the 99 production sources re-assemble with identical `.text` and control words, the attention build with the
  switches off equals its pinned reference; `tests/sched2_dep_latency.rs` (11 tests, 9 red before the change) and 6 unit tests.

## Unreleased — 2026-11-10 (session T-26: the review queue — the B300 latency model of pull request 3; `USETMAXREG` measured and the SM120 async idioms document from the megakernel branch; the sm_120 scheduler session's opt-in switches; the first five batches (53 refs) of the B300 lane's candidate forms on sm103a / sm100a; the scaled F2FP unpack on the four tables; the CI's clippy)

- **`cubit asm` on sm_120, opt-in: `CUBIT_SCHED2` with the scoreboard arming rule, a pair-latency table enforced on every control-flow path
  (`CUBIT_SCHED2_LAT=sm120`), ptxas's MMA discipline (`CUBIT_MMA_PTXAS=1`)** (`49f8340`, the sm_120 scheduler session's commit). `CUBIT_SCHED2=1`
  built the production attention kernel wrong on silicon: its yield rule put the yield flag on a scoreboard producer one cycle in front of
  its waiter (`MUFU.EX2 [W:Y:S01]` / `FSEL [B]`), and the waiter read the stale register — measured in isolation on MUFU / SHFL / LDC / LDS
  setters (655 360 of 655 360 thread-runs wrong; clean without the yield, at S02, or with one instruction between); a waiter is now never
  closer than two issue cycles behind the instruction that set its barrier (`CUBIT_SCHED2_NOARM=1` = the old schedule). With
  `CUBIT_SCHED2_LAT` the fixed-latency dependencies are priced per (producer class, consumer class, operand role) pair from
  `tables/dep_latency_sm120.json` (533 cells: ptxas's practice in the sm_120 census, checked on sm_120 silicon; arch-locked — refused against
  another architecture's ISA table) by a forward min-distance dataflow on the final instruction list (`src/dep_stall.rs`), so a consumer at a
  branch target or behind a join can no longer sit below its latency; a requirement stalls cannot reach fails the assembly.
  `CUBIT_DEP_VERIFY=1` / `CUBIT_DEP_CELLS=<file>` are the read-only forms. **Without a switch nothing changes**: the 99 production sources
  assemble byte-identically and the attention build is the pinned one (the push gate's checks). `tests/sched2_dep_latency.rs` (11) + 5 unit
  tests; the scheduler session's own text is the section above (KNOWN_ISSUES A26 / A27; the stall-floor harness and its result files:
  `tools/stallfloor/README.md`).
- **A report of 2026-09-18 pinned as a test** (`979365c`, `tests/sm120_omma_uri_split.rs`; reported by ComradePenguin-1917 in pull request 2
  and blackwell-isa pull request 1): the SM120 OMMA block-scale operand `URi` is an eight-bit register number split across `ureg` [62:60] +
  `ureg_shr3` [77:73] (255 = `URZ`); in September the table declared one four-bit field and the printer assigned each slice instead of
  merging them. Both were fixed in October from measurement (blackwell-isa `fcb8132` / `59561b2`, cubit `94489ed`); the test holds the
  report's cases — every OMMA key × `UR0`..`UR63`, `URZ` (1 040 texts, each word named the same by nvdisasm 13.1), the `.reuse` at bit 51,
  the `CS2R` / `CS2UR` system-register reads.
- **`sched`: per-class dependency latency (cost-model schema 2; pull request 3, `94e7dae`).** A cost file may carry `dep_latency_cy` — rows
  (producer class, consumer kind) → cycles — and `dep_latency_default_cy`; a RAW edge is then priced from the producer's *start*
  (`avail(consumer) = start(producer) + L`, the semantics of the stall-floor measurement), ordering edges (WAR / WAW / memory chain) carry no
  latency, and an edge whose class the table does not name takes the default and is counted in the report's new `dep_class_defaulted`
  (`dep_latency_model` says `legacy` or `per_class`). A file without the table — the vendored sm_103a `cost_model` section, every existing
  plan — keeps the single `dep_link_latency_slots` after the producer's end, byte for byte (`tests/sched_m3_dep_latency.rs`).
- **`stallfix`: the producer classes of the B300 stall-floor measurement of 2026-11-07 (pull request 3, `26a1681`).** New optional rule keys,
  each defaulting to "no rule" so that the vendored sm_103a (v2) and SM120 (v4) sections behave as before: `floor_imad_d0` / `_d1` (IMAD /
  IMAD.WIDE data result → consumer, measured 5 / 3), `floor_fma_d0` / `_d1` (FFMA / FMUL / HFMA2 / FMUL2, 4 / 3), `floor_f2fp_d0` (F2FP pack /
  unpack, 4), `floor_umov_d0` (0), the R2UR boundary split into `floor_r2ur_in_d0` (4) and `floor_r2ur_out_d1` / `_d2` (6 / 4), and
  `mufu_scoreboard_only` (a MUFU result read within three slots without a write barrier on the MUFU is a violation: no stall count up to S15
  makes it right). The rule values are data of the rule file, scope-locked by `arch`; no shipped section carries them yet
  (`tests/stallfix_v3data.rs`).
- **The IMAD display aliases are members of the measured IMAD class** — `IMAD.MOV`, `IMAD.IADD`, `IMAD.SHL` and the `.U32` / `.HI` forms have
  the stall floors of the arithmetic IMAD on sm_103a silicon (5 / 3 / 0 at d0 / d1 / d2 in front of an IADD3 consumer; MOV / IADD3 / LOP3 4 / 0 /
  0 in the same run; B300, 2026-11-09, 588 kernels × 655 360 thread-runs — the table is in the review of pull request 3), and ptxas never
  schedules an alias → ALU-consumer pair with a producer stall below 5 (240 sm_103a cubins of one image; the 328 cubins of the B300 publish
  corpus). The pull request's third commit (a separate alias class priced with the 4-cycle default and exempt from `floor_imad_d0`) had no
  measurement behind it and is not taken; `t_m3_imad_display_aliases_take_the_measured_imad_class` and
  `imad_display_aliases_take_the_measured_imad_floor` pin the measured membership instead. Not measured: the constant load
  `IMAD.MOV.U32 R, RZ, RZ, imm` (kept in the class, the conservative side) and the edges into an IMAD, carry, guard or cross-domain consumer.

- **`USETMAXREG` measured** (`tools/probes/re_sm120_usetmaxreg.py`, 73 form + 148 lattice words; measured 2026-11-08 on the branch `r0b-mk-items`; tables vendored from blackwell-isa
  `5043aee` = that branch's `940fb83` on today's tip: sm120 only, rows unchanged at 38 848): the uniform guard, the ten-bit register count [41:32] (the count itself, in hex — ptxas emits multiples of 8 in 24..256,
  the field admits 0..1023), the operation [73:72] (1 DEALLOC, 2 TRY_ALLOC), the pool bit 74 (clear = the unclaimed vendor glyph `.???0`),
  UPd [83:81] on TRY_ALLOC (text-inert on DEALLOC, baked at 7); the reuse bits are illegal on the opcode (nvdisasm refuses the opex-table
  value) — a control-word law the scheduler respects. The DEALLOC row had no guard field and neither row was measured per field
  (KNOWN_ISSUES T1 exception 9, closed); USETMAXREG joins the decoder's fail-closed bases — none of BUG-225's four exposed bases is on the
  sign-bit fallback any more (`tests/sm120_usetmaxreg.rs`). `nvprobe.nvdisasm_text` accepts nvdisasm's second rejection spelling
  (`undefined value … for table 'TABLES_opex_0'`) as an illegal word.

- **Tables vendored from blackwell-isa `5629154`: batch 4 of the B300 measurement lane's candidates** (seven more of the review refs
  `hidden-b300/*` — the ones of the lane's first days, 7–8 November, that change no engine code; 42 of the 68 refs are taken; sm103a
  533 → 534 forms, 37 366 → 37 418 rows; sm100a 532 → 533, 37 360 → 37 412; sm120 / sm121a unchanged). **Rows without `_src`: sm103a /
  sm100a 339 → 338** (`USETMAXREG.TRY_ALLOC.CTAPOOL UPd, count` re-measured: guard, UPd [83:81], the ten-bit count — after the constant
  bits under its fields were cleared the row is, field for field, the row SM120 carries from its own measurement of 2026-11-08).
  Forms added: **the compressed-matrix loads `LDSM.U4x16P64TO8` / `LDSM.U6x16P32TO8 Rd, [addr]`** on the three address forms — the `M816`
  shape ×1 / ×2 / ×4 on both datatypes, `MT1616` on U4 and, with a uniform-only address, on U6 (22 rows from two refs; four rows the
  second ref measured again are kept once, under the first ref's tag); **`F2FP.<E2M1|E3M2|S2_6>.F32.PACK_AB_MERGE_C Rd, Ra, Rb, Rc`**
  with `SATFINITE` / `RELU` / `RS` (24 rows; the two E2M1 forms SM120 has measured since 2026-10-22 carry the same bits);
  **`STSM.8.MT168 [addr], Rs`** ×1 / ×2 / ×4 on the register and the register + uniform address forms. Each with its complete-word
  fixture and test (`tests/hidden_b300_<name>.rs`); text and CPU round trips, no execution claim. **Brought to the measured-row form by
  the gatekeeper (blackwell-isa `5629154`, no change of the measurement):** the 24 pack-merge rows carried the whole control code [127:105]
  in their mask next to the fields — the mask is the fields now (decoding unchanged: the control code is stripped before a word is
  matched); the `USETMAXREG` row's constant bits cleared under its fields. **Known and left:** each pack-merge form sits under two group
  names with identical bits — the sorted one and the vendor's modifier order — because on these two tables the decoder and encoder go
  through the vendor-order name (as for the harvest E4M3 / E5M2 pairs already there; SM120 has the sorted name alone); one pass over the key
  removes the fourteen pairs. **Not taken: `hidden-b300/movm`** — its six rows leave the bits outside their fields open in the mask and
  its fixture adopts 534 text-inert words whose text assembles to a different word; a measured row fails closed on those bits. Returned to
  the lane. **Pins moved to the batch:** the three pack-merge tests each required the other two types to stay unclaimed and
  unassemblable (now: a sibling's measured word prints the vendor text through the sibling's row, never through a group of the candidate
  under test; 4 / 8 / 8 such words); the second LDSM ref's tag counts its fourteen own rows; a field's own `_src` reads "absent or equal"
  (the canonical layout writes a tag once per level); the legacy censuses of the LDSM groups (`bug426`, `bug429`) carry the lane's
  compressed-matrix groups on sm103a / sm100a (22 / 22 / 23 groups) next to the original fifteen. **Gatekeeper check:** the ten fixtures
  named again with nvdisasm 13.1 on a second host, every word on `-b SM103` and `-b SM100` — 35 100 word / target pairs: 30 808 texts
  identical, 4 290 without text on both, and one word that 13.1 names `F2FP.SATFINITE.E0M3.F32.PACK_AB_MERGE_C` where the lane's 13.3
  prints no line (unclaimed either way); on the 53 rows taken per table the mask is the fields' bits, the constant bits are clear under
  it and carry no control bit.
- **Tables vendored from blackwell-isa `018a927`: batch 5 of the B300 measurement lane's candidates** (eleven more of the review refs
  `hidden-b300/*` — the ones whose cubit side changes a line or two of the engine; 53 of the 68 refs are taken; sm103a 534 → 545 forms,
  37 418 → 37 524 rows; sm100a 533 → 544, 37 412 → 37 518; the rows of sm120 / sm121a unchanged). **Rows without `_src`: sm103a / sm100a
  338 → 336** (the plain `STAS [Ra.64+imm], Rs` and `VIMNMX.S16x2 Rd, Pd, Pe, Ra, Rb, Pc` re-measured). Forms added (106 rows per table):
  **`FHFMA.BF16[.RM|.RP|.RZ][.SAT] Rd, Ra, Rb, Rc`** (the mixed bf16 / f32 fused multiply-add; `.H1` on the two bf16 sources);
  **`HMNMX2[.BF16_V2][.FTZ][.NAN][.XORSIGN]`** in the register form `Rd, Ra, Rb, Pc` and with two f16 / bf16 immediates;
  **`STAS`, `STAS.64`, `STAS.128`** on `[Ra.64+imm]` and `[Ra.64+URb+imm]`; **the `SYNCS.ARRIVE.TRANS64.RED[.OPTOUT]` selectors `.A0T1` /
  `.A0TR` / `.A0TX` / `.ART0`**; **`FMNMX[.FTZ][.NAN][.XORSIGN].IS_A Rd, Pd, Ra, {Rb | URb | fimm}, Pc`** (the float min / max with its
  predicate output); **`LDGMC.E.{ADD.F32 | .F32x2 | .F32x4 | HPADD.F16x2 | .F16x8 | .BF16x2 | .BF16x4 | .BF16x8}.RN.STRONG.SYS Rd,
  [Ra.64+URb+imm]`**; **`VIMNMX.{S16x2 | U16x2}[.RELU]`** with a register or a uniform second source; **`USGXT URd, URa, imm`**,
  **`SGXT.U32 Rd, Ra, URb`**; **`VHMNMX[.BF16_V2][.NAN]`** with `.H0_H0` / `.H1_H1` on each source; **`UP2UR.B3 URd, UPR, URs, imm`**
  and **`UR2UP UPR, URs.B3`**. Each with its complete-word fixture and test (`tests/hidden_b300_<name>.rs`); text and CPU round trips,
  no execution claim. **Engine — the candidates' own changes, applied as written:** the printer ranks `FHFMA`'s modifiers as `FHADD`'s
  (type, rounding, `SAT`), `VHMNMX`'s as `HMNMX2`'s, knows `F32x2` / `BF16x4` among `LDGMC`'s types, prints `SYNCS`'s `.OPTOUT` and then
  the A-selector last (`A0T1`, `A0TX`, `ART0` are new), prints a uniform-indexed `STAS` address as `[Ra.64+URb]` (and `UR63` by its name
  there), `USGXT`'s immediate unsigned, and the bank token `UPR` for `UP2UR`'s second and `UR2UP`'s first operand (the harvest row of
  `UP2UR` printed `0x0` there); the encoder accepts `UPR` on `UR2UP`; the parser reads `HMNMX2`'s integral immediates as floats (they
  did not assemble); on sm103a / sm100a `VIMNMX` has no sign-tolerant fallback. **One change widened by the gatekeeper:** the candidate
  printed `UP2UR.B3`'s immediate unsigned; nvdisasm 13.1 prints `0xffffffff` for the plain, `.B1`, `.B2` and `.B3` words on all four
  targets, so every group of the key prints unsigned (`tests/sm103a_up2ur_imm_unsigned.rs`). **Two changes not taken, shown
  unnecessary:** fmnmx-is-a-schedule's rank for `IS_A` (the generic rank already prints it last; its three tests pass without) and
  sgxt-u32-production's second look at `claim_forbid` entries at or above bit 96 (the candidate filter evaluates every exclusion on the
  complete word since BUG-512 / 518; its two tests pass without). **Brought to the measured-row form by the gatekeeper (blackwell-isa
  `3a30f62`; what the rows claim gets narrower):** the `FHFMA` and `HMNMX2` rows carried every text-inert bit of their lattice as a
  one-bit field without an extraction (34 / 37 / 17 bits per row), so a word with such a bit set decoded to the text of the word without
  it — the fields are gone, the rows fail closed on those bits (472 + 180 fixture words per table are refused now; none of the 389 + 629
  production witnesses has such a bit set, and every other adopted word, the production ones included, re-assembles to itself: 1 418 and
  3 604 words over the two tables, where the candidates asserted the exact round trip for a part); the `USGXT` row's constant bits
  cleared under its guard field. **The gatekeeper's engine differential (new with this batch):** every row of the four tables — its
  constant word, each field at all ones, random fillings; 3 143 050 words — decoded, printed and re-assembled by the engine before and
  after the `src/` changes on the same tables: 2 250 words differ, all on sm103a / sm100a and all in keys this batch adds or
  re-measures; of the 630 sent to nvdisasm 13.1 the new text is the vendor's in 500, the word re-assembles now where it did not in 74,
  48 are synthetic control words nvdisasm refuses and both engines decode, 6 are `.INVALID1` spellings neither re-assembles, and 2 were
  the plain `UP2UR` immediate (fixed by the widening above); none where the old engine was right and the new one wrong; **no word of
  sm120 / sm121a changes.** For the decoder arm, 14 960 words around the `VIMNMX` rows with every combination of the six sign-window bits:
  1 476 differ, all on sm103a / sm100a, all refusals of words the fallback had absorbed — 1 069 printed a text nvdisasm does not print
  for the word, 221 nvdisasm refuses, 186 were text-inert neighbours that did not re-assemble to themselves. The twenty fixtures named
  again with nvdisasm 13.1 on a second host: 121 498 word / target pairs, 118 244 texts identical, 3 254 without text on both, none
  different. **Superseded, not taken separately:** `hidden-b300/fmnmx-is-a` (the same 24 rows with `claim_forbid` lists on the
  scheduler's bits, which rejected real scheduled words — the lane's own repair is the ref taken). **Pins moved to the batch:** a field's
  own `_src` reads "absent or equal"; the `USGXT` test pins the cleared `and_base`; the per-row pass's exception on
  `VIMNMX_R_P_P_R_R_P` `S16x2` (sm103a / sm100a `rows_intalu`) reads "re-measured since: <the lane's tag>"; `sm103a_sm100a_fp32_alu`
  lets the `FMNMX.IS_A` neighbours decode through the new keys (the lane's own edit); the SGXT row model the lane kept at the repository
  root is `tests/fixtures/sgxt_u32_table_model.json`.
- **The vendor's degenerate glyphs and the frozen path (KNOWN_ISSUES A23; the owner's decision of 2026-11-10 to let the frozen path
  carry them): already carried — pinned.** A word nvdisasm prints as `LDG.E.LTC128B R4, [???255.64+UR6+0x10]` is printed that way by
  `disassemble`, and that text cannot be assembled; `disassemble --frozen` has re-assembled every non-branch line before writing it since
  2026-07-31 and writes such a word as `__raw__0x<128 bits>`, so `asm -T` of the frozen listing reproduces the cubin.
  `tests/a23_degenerate_glyph_frozen.rs` builds a cubin with the four glyph words of T-11's audit and takes it through plain listing,
  frozen listing and `asm -T`: byte-identical. No engine change; A23 is closed.
- **`FHADD` has operand roles** (blackwell-isa `018a927`: `operand_roles.base_ops.FHADD`, class `alu` — dest first, two register
  sources). The measured row of `FHADD[.BF16] Rd, Ra[.H1], Rb` (ptxas's mixed bf16 → f32 accumulate) had no role entry, so
  `cubit sched --mode list`, `ra`, `stallfix` and the register liveness stopped on it ("unknown operand roles"); reported by session
  BQ-1 from the production Triton top-k-sum kernel of the MoE (20 of its 176 instructions). `tests/reg_liveness.rs`
  `fhadd_is_a_dest_first_alu`.
- **The scaled F2FP unpack on the four tables — `F2FP.BF16.<E2M1|E2M3|E3M2|E4M3|E5M2>[.RELU][.SATFINITE].UNPACK_B Rd, Rs, Rscale.<sel>`
  (opcode 0x63e; tables vendored from blackwell-isa `05068b6`: batch 3 of the B300 lane's candidates + the same rows measured for SM120 /
  SM121A).** The unpack of a low-precision pair to bf16 with an E8M0 block scale taken from a register: the scale selector [26:24] is
  printed on the scale register (`.H0`, `.H1`, `.B0`..`.B3` — mandatory, selector 0 is `.H0`; 6 / 7 are the vendor's `INVALID6` /
  `INVALID7` and unclaimed), the source half [88] as `Rs.H1`, for E2M1 the source byte (bits 88 / 72) as `Rs.B1` / `.B2` / `.B3`; RELU bit
  75, SATFINITE bit 77. No table had a row at 0x63e (`no instruction matches opcode 0x063e`). **sm103a / sm100a:** the lane's refs
  `hidden-b300/f2fp-unpackb` (20 rows per table: five source types × plain / RELU / SATFINITE / both; 2 396 complete words per target) and
  `hidden-b300/f2fp-e4m3-source-h1` (the plain E4M3 row measured a second time to the same fields — the table keeps the row once, under
  the first tag; its 23-word fixture is a second witness) — 35 of the 68 refs are taken; rows 37 346 → 37 366 / 37 340 → 37 360, rows
  without `_src` unchanged (339). **sm120 / sm121a: the same 20 rows, measured, not copied** — the 2 406 distinct words of the lane's two
  lattices named again with nvdisasm 13.1 on `-b SM120` and `-b SM121`, one word per call: identical on the two targets and identical to
  `-b SM103` / `-b SM100` (328 named — 212 of them the rows' words —, 914 printed with a vendor glyph, 1 164 rejected; against the lane's
  nvdisasm 13.3 records every text and rejection agrees except 128 glyph words on which 13.3 exits 0 without an instruction line); the rows
  carry tags of their own, sm120 38 848 → 38 868 rows, sm121a 49 824 → 49 844. **Why sm120:** the scheduler session executed
  `F2FP.BF16.E4M3.UNPACK_B Rd, Rs, Rscale.B0` / `.H0` and the E2M1 twin on sm_120 silicon — equal to the five-instruction dequantisation on
  all 65 536 byte pairs × 256 scale bytes, both halves — and the production attention kernel's two-instruction dequant needs the word as
  text; the other types and selectors are text-measured only, nothing was executed on GB10. **Engine (the lane's change, reviewed and taken
  as written):** two extractions — `f2fp_scale_sel` (the mandatory selector suffix; refused on any opcode but F2FP) and `f2fp_ra_b1` /
  `f2fp_ra_b2` (the E2M1 source byte, one bit each) — in the table loader, encoder, decoder and printer; `tools/sync_table.py` knows the
  three names and gains `--stage-only` (vendor without the built-in `cargo test`). `tests/hidden_b300_f2fp_unpackb.rs`,
  `tests/hidden_b300_f2fp_e4m3_source_h1.rs` (two pins of the second ref that describe it alone moved to the batch: the tag on the row, and
  three of its "unclaimed" neighbours that are words of measured sibling rows and must print the vendor text through them) and
  **`tests/sm120_f2fp_unpackb_scaled.rs`** (sm120 / sm121a: the 212 words decode to nvdisasm's text and re-encode, the other 2 162
  instruction words of the lattice fail closed — text-inert neighbours, the unclaimed types E0M3 / S2_6, the immediate-scale form at
  0xe3e —, `F2FP.BF16.E4M3.UNPACK_B R11, R2, R5.B0` assembles from text to the compiler's word, the rows equal sm103a's field for field).
  The immediate-scale form `… Rd, Rs, FIMM.<sel>` (0xe3e) has no row yet on any table.
- **Tables vendored from blackwell-isa `c3b2d5e`: batch 2 of the B300 measurement lane's candidates** (23 more of the review refs
  `hidden-b300/*` — the ones without engine changes on the bases of 8–9.11; sm103a 517 → 533 forms, 35 894 → 37 346 rows; sm100a 516 → 532,
  35 888 → 37 340; sm120 / sm121a unchanged). **Rows without `_src`: sm103a / sm100a 357 → 339** — eighteen harvest rows per table are
  re-measured by the lane (`F2F.F16.F32` plain / `.RM` / `.RP`, `FCHK P, R, UR`, twelve `HSETP2` groups incl. two dual-immediate ones,
  `SYNCS.ARRIVE.TRANS64.RED.A0TR`, `UFLO.U32`): exactly the rows whose defects session T-23 had named as exceptions (a sign / abs /
  half-selector bit outside the fields moving an operand, a 9-bit uniform field, a predicate field at the wrong position).
  Forms added: `BMSK Rd, Ra, Rb|URb`, `BMSK.W`, `UBMSK` (UR / immediate), `UBREV`, `UFLO` (the four `SH` / `U32` groups);
  `F2F.BF16.F16` / `F2F.F16.BF16`; `F2F.F16.F32` with the sign fields, the three rounding modes and the four `FTZ` rows; the `FSET.BF`
  comparison family on the three operand forms `R, R, R` / `R, R, FIMM` / `R, R, UR` (96 groups each); **`HSETP2` complete on the register,
  uniform and dual-immediate forms** (384 groups each; the register and uniform rows are, group for group, the rows SM120 carries from its
  own measurement of 2026-11-06 — the only difference is the lane's fail-closed list on the unused reuse bits); `FMNMX3.NAN`; plain
  `VHMNMX`; `I2I.S8.S32.SAT`, `I2IP.S8.S32.SAT`, `I2FP.F32.U32.RZ`; `R2UR.OR P, UR, R`; `SHF R, R, R, UR` (left / right). Each with its
  complete-word fixture and test (`tests/hidden_b300_<name>.rs`); text and CPU round trips, no execution claim.
  **A change of meaning on sm103a / sm100a to know about: a bare `HSETP2` register operand and `.H0_H0` are different words** —
  `HSETP2.GEU.AND P1, PT, R9, R24, PT` (selector 0) and `… R9.H0_H0, R24.H0_H0 …` (selector 2) are both named by nvdisasm (13.1 and 13.3,
  `-b SM103` / `SM100` / `SM120`) exactly as written; until now the two spellings encoded to the same word (the harvest rows baked selector
  2, the printer added `.H0_H0` as a default notation). Compiler output always carries the suffix, so the B300 corpus is unchanged;
  hand-written text that relied on the bare spelling meaning `.H0_H0` must say `.H0_H0` (`tests/bug272_enopsuffix.rs`, re-pinned to the
  five measured words; `tests/b9_ptx_lower.rs`: `HSETP2.GTU` assembles now, the PTX lowering of the f16 / bf16 `setp` forms stays refused).
  **How the batch was taken:** as batch 1 (row deltas, pins re-derived); three pins of the lane's tests that describe one candidate alone
  moved to the batch (`F2F_R_R` has ten groups when the four F2F refs meet; the plain `BMSK` word next to `BMSK.W` decodes through the
  sibling's row; the plain `R2UR` group next to `R2UR.OR` is `main`'s measured row); the six `sm103a` / `sm100a` `rows_{half,misc,uniform}`
  tests of 2026-11-08 keep their fixtures, and the 18 exceptions per table the lane closed say `re-measured since: <tag>` in their reason
  (`tests/sm120_rows_common.inc` then requires exactly that tag on the row). **Gatekeeper check:** all 65 676 fixture words (46 files)
  named again with nvdisasm 13.1 on a second host — 64 426 texts identical, 1 250 without text on both, none different.
- **Tables vendored from blackwell-isa `0f20ae6`: batch 1 of the B300 measurement lane's candidates** (the review refs `hidden-b300/*`,
  ten one-commit pairs measuring production forms of sm_103a / sm_100a with nvdisasm 13.3 on the B300 host; sm103a 514 → 517 forms,
  35 875 → 35 894 rows; sm100a 513 → 516, 35 869 → 35 888; sm120 / sm121a unchanged; rows without `_src` unchanged at 357 / 357 — every
  row added is measured). New forms, each with its fixture of complete probe records and a test (`tests/hidden_b300_<name>.rs`:
  every positive word decodes to the row, prints nvdisasm's text and re-encodes; the negatives fail closed):
  `ATOMS.MAX Rd, [Ra+URb+imm], Rc` (new key `ATOMS_R_ARURI_R`) and `ATOMS.MIN Rd, [URa+imm], Rb` (`ATOMS_R_AURI_R`); `UMEMSETS.64
  [URa+imm], URZ, URb` (new key `UMEMSETS_AURI_UR_UR`); `F2F.BF16.F32 Rd, URs` (the source also as `-URs`, `|URs|`, `-|URs|`) with the four rounding modes × FTZ (eight groups
  of `F2F_R_UR`); `F2FP.BF16.E8.UNPACK_B Rd, Rs` (`F2FP_R_R`); `UBLKRED.G.S.ADD.{F16,BF16,F32,F64}.RN [URa], [URb], URc` (new key
  `UBLKRED_AURI_AURI_UR`); `STL.U16` / `STL.U8 [Ra+imm], Rb` (`STL_ARI_R`); `LDG.E.S16 Rd, desc[URa][Rb.64+imm]` (`LDG_R_dARI`).
  The lane's evidence is nvdisasm text and CPU round trips — no execution claim is made for any of the forms.
  **How the candidates were taken:** each blackwell-isa candidate re-applied as its row delta (not a textual cherry-pick: the count and
  revision pins of ~55 legacy tests are re-derived, not merged); `F2F.BF16.F32 R, UR` was proposed twice from the same base — the
  later row (with the fail-closed list over the text-inert bits) is the table's, the earlier candidate's production fixture reads it
  through the later tag; the masks of the new rows carry the `0x` prefix. **Gatekeeper check:** all 49 098 fixture words named again
  with nvdisasm 13.1 on a second host — every text identical, every negative without text on both. **Fixtures of this lane are
  vendored gzip-compressed** (`tests/fixtures/<name>.jsonl.gz`, read through `tests/hb300_fixture.inc`; digests of the decompressed
  bytes in `tests/fixtures/hidden_b300.sha256`): the 22 files are 45 MB of complete nvdisasm records, 3.3 MB compressed.

## Unreleased — 2026-11-09 (sessions T-23 / T-24 / T-25: the sm121a / sm103a / sm100a long tails verified row by row — T1 2 654 → 811 and 893 → 357 / 357 —, the decoder's fail-closed zone around a measured row, the 2026-08/09 battery re-pinned to the measured-row doctrine)

- **Tables vendored from blackwell-isa `04bcb53`** (sm121a 50 444 → 49 824 rows, 2 150 → 1 624 forms, 21 750 → 22 227 aliases; sm103a 35 876 →
  35 875 / 516 → 514; sm100a 35 870 → 35 869 / 515 → 513; sm120 unchanged). Rows without `_src` (`tools/audit_table.py --summary`): sm121a
  **2 654 → 811**, sm103a / sm100a **893 → 357**, sm120 7. What the revision carries:
  - **T-23's per-row passes** (`6428595` / `ddac54d` / `21fc69a`): `tools/probes/re_sm120_rows.py --arch SM121 / SM103 / SM100` — the canonical
    word + every single-bit flip named by nvdisasm 13.1, cubit's decode / print / re-encode of every word, the GB10 census (sm121a) and the
    B300 publish corpus (sm103a / sm100a) as witnesses — over the eight families (memory, atomic, tensor, half, intalu, uniform, misc, control):
    sm121a 1 185 rows measured, 511 shadowed harvest keys retired as `_meta.key_aliases` clones, 52 unreachable rows deleted; sm103a / sm100a
    529 rows measured each, 3 keys aliased, 1 dead row deleted. The 24 new tests `tests/{sm121a,sm103a,sm100a}_rows_<family>.rs` (+ fixtures)
    pin every record: measured rows (fields, fail-closed mask), the aliases, the deleted keys, the named harvest leftovers and the `modelled`
    retention rows (the note resolved row → key → tag, `tools/tablefmt.py`'s three levels).
  - **T-24's correction** (`ad7804a`): two T-23 alias retirements whose targets could not decode the retired keys' words reverted
    (`HFMA2_R_R_II_II_R` — the II immediates had fallen to a field-less dotted row printing `0x0, 0x0` for `1, 1` —, `F2FP.BF16.F32.PACK_AB_P_R_R_R`).
  - **T-25's table fixes** (`64db08b` / `daac080` / `04bcb53`, each with its nvdisasm measurement in the commit): the sm121a junk keys that printed
    vendor-nonexistent text for the measured rows' text-inert neighbours deleted (`LDS.128_R_AR` — `LDS.128 R91, ?AR` for `LDS.U8 R91, [R10]` —,
    `UIADD3_UR_UP_UP_UR_UR_R_II_P`, `HADD2_R_R_II_II_II_II_?`, `MOV_P0_R_II` (a UMOV word), `QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R` (a MOVM word),
    `HFMA2_R_R_FI_FI_R` (31 rows at an illegal opcode claiming the LEA lattice's illegal words)); the sm121a **LEA family rebuilt from
    measurement** (`re_sm120_lea.py --arch SM121`: 824 / 824 words identical to the SM120 law; 24 keys / 36 rows for 23 harvest keys / 58 rows,
    `tests/sm120_lea.rs` on the four tables); `LDG_P_R_ARI_P` / `LDG_R_ARI_P` `.64` rows measured with the `_P_R_` claim exclusion; on sm103a /
    sm100a the plain `LDG_R_ARURI` row's **UR field widened 6 → 8 bits** (cubit printed `UR0` for `UR64`; the word decoded through the `E,LTC128B`
    sibling), the `LDG_P_R_dARI` rows re-measured, **`IMAD_R_R_R_R` `U32` added** (the plain `IMAD.U32 Rd, Ra, Rb, Rc` had no row — the encoder
    minted a word its own decoder rejected, BUG-303, b9_ptx_lower's `mad.lo.cc.u32`; on the pushed tables the `.U32` was silently dropped), the
    `REDG_P_dARI_R` retention key restored as 13 `modelled` rows (BUG-128). T-23's sm121a / sm103a / sm100a row notes say `-b SM120; session G
    run 5` where the measurement was `-b SM121` / `SM103` / `SM100` by T-23 — a wording defect of the probe's note writer, fixed for the rows
    T-25 wrote (`note_for(…, arch, session)`); the earlier notes are corrected with the next per-row pass.
- **Decoder: a measured row's fail-closed zone (T-24 + T-25, `src/decoder.rs`).** A harvest sibling may take a word through the broad address
  fallback (priority 2) only where no measured row of the opcode agrees with the word on every fixed bit outside the four standard operand slots
  up to one more bit; on the sign-tolerant path (priority 3) a harvest sibling loses the match when it fixes a bit on which the word departs from
  the near measured row to another value, or bakes a window bit ([75:72] / [63:62]) the word has clear. Why: T-23's passes measured the plain
  rows but left their harvest siblings, and the sibling then absorbed the measured row's text-inert neighbour with a modifier the vendor does
  not print — `LDG.E` + an inert bit → `LDG.E.LTC128B`, `LDS.U8` → `LDS.128 ?AR`, `IMAD.WIDE` + bit 78 → `IMAD.WIDE.U32`, `IADD3` → `IADD3.X … P0, P1`,
  `CREDUX.MIN.S32` → `CREDUX.MIN.F32` (`T/t25/inert_check.py`: 339 / 176 / 176 such words on sm121a / sm103a / sm100a, 0 on sm120, nvdisasm 13.1
  the truth) — the measured row fails closed on the bit and the sibling must not reopen it; the legitimate priority-3 words (`HFMA2.SAT R2, R3,
  |UR4|, R5`, `HFMA2.BF16_V2 R0, -R0, 1, 1, R0`) stay. Production identity: **0 differences on the 249 929-word production census**, GB10
  **91 927 / 91 927** decode (91 926 re-encode, the BUG-037 refusal), B300 **85 721 / 85 792** words (296 / 328 cubins strict-exact), the sm120
  table byte-identical. Wrong-text words left in the 8 550 bug-wave test words: **0** on the three tables; inert-neighbour wrong texts
  (`inert_check.py`) 17 / 17 on sm103a / sm100a and 113 on sm121a, all pre-existing (`docs/KNOWN_ISSUES.md` T1).
- **Encoder:** the IMAD high-half rule (`native_hi`, the NEEDS 53 refusal) applies on sm120 and on every measured IMAD row (`row_probe`), not on
  the harvest rows of the other tables.
- **The 2026-08/09 battery re-pinned to the measured-row doctrine (84 binaries; the T-18 convention):** a word a measured row fails closed on is a
  HOLE, read through its clean word — `tests/t25_fail_closed.inc` (`t25_closed_as`: the witness with its junk bits cleared, of the nearest row of
  its opcode whose clean word renders the vendor text) —, structural pins switch on `row_probe` (a measured row's mask is its fields; the harvest
  reference stands in where the donor is measured: bug381's SAT rows, bug429's `16,MT88`), the census pins moved to the vendored state
  (forms 1 624 / 514 / 513, loader keys 23 849, claim_forbid 23 482 / 10 977 / 10 978), the 42 canonical-revision pins to `04bcb53`. Four words
  are pinned as holes because their form is not a row of the measured table (`STG.E.U8 [R.64+UR]` on sm100a / sm103a / sm121a, bug442 / 443; the
  predicated `.U32` ARURI loads `LDG.E P3, R7, [R69.U32+UR67+0x5bda4], !P0` / `LDG.E.LTC256B …, !P4` on sm121a, bug469) — the next rows to measure
  (`docs/KNOWN_ISSUES.md` T1). Suite 547 / 547 binaries green.

## Unreleased — 2026-11-08 (the bulk store `UBLKCP.G.S`, the async-proxy fence `FENCE.VIEW.ASYNC.G` and the warp votes: forms a persistent / TMA kernel needs, measured; a silent wrong-direction encode closed)

- **Tables vendored from blackwell-isa `c374bad`** (sm120 38 838 → 38 848 rows, 979 → 983 forms; sm103a / sm100a / sm121a unchanged).
- **`VOTE` / `VOTEU` measured — `.ALL` / `.ANY` / `.EQ` on the four keys.** Both opcodes (0x806 / 0x886) share one layout: guard, ballot
  destination [23:16] (255 = RZ / URZ, elided by nvdisasm — the two-operand keys `VOTE_P_P` / `VOTEU_UP_P`), mode [73:72] (3 = INVALID3,
  unclaimed), predicate destination [83:81], source predicate [89:87] with its negation bit 90 (`tools/probes/re_sm120_vote.py`, 516 form +
  154 lattice words). The harvest rows (`bug226d`, `audit-fix-2026-11-06-t10`) carried `.ANY` only on `VOTEU_UR_UP_P` / `VOTE_R_P_P` with a
  predicate baked at PT — `VOTEU.ALL UR4, UPT, PT` (a comm warp's "every lane ready") and `VOTEU.ANY UR4, UPT, P1` did not assemble — and
  no `.EQ` anywhere; 6 → 12 rows. VOTE / VOTEU join the decoder's fail-closed bases (`tests/sm120_vote.rs`).
- **`UBLKCP.G.S` had no row and its text minted the load.** The bulk copy's direction is the code [74:73] — 0 `.G.G`, 1 `.S.G` (the load,
  global → shared), 2 `.G.S` (the store, shared → global: PTX `cp.async.bulk.global.shared::cta.bulk_group`), 3 `.S.S` — measured with
  nvdisasm 13.1 (`tools/probes/re_sm120_ublkcp_dir.py`, 167 form + 48 lattice words). The table carried the codes 0 and 1 as the plain
  key's groups `G,G` / `G,S`; a mod-group name is the *sorted* modifier set, so nvcc 13.0's store word decoded as an unknown word and the
  text `UBLKCP.G.S [UR4], [UR36], UR6` assembled to the load word `UBLKCP.S.G` — a kernel built from that text would have copied in the
  wrong direction. Like the conversions (`F2F.BF16.F32_R_R` next to `F2F.F32.F64_R_R`) the ordered pair lives on dotted keys now
  (`UBLKCP.G.S_AURI_AURI_UR[_II]`, `UBLKCP.S.S_AURI_AURI_UR[_II]`), and the encoder serves a `.G.S` / `.S.S` text from those keys only — a
  table without the row refuses the text instead of minting the other direction (`tests/sm120_ublkcp_dir.rs`). The modifier bits 75
  `.MULTICAST`, 81 `.LTC64B`, 82 `.LTC128B`, 83 `.SEQUENCED`, 84 `.DST_G_BYTE_MASK` are recorded as unclaimed lattice.
- **`FENCE.VIEW.ASYNC.G` measured; the donor `.T` row retired on SM120.** The async-proxy fence (0x3c6) carried two donor rows of the
  2026-08 census (`bug226e`): `ASYNC,S,VIEW` and `ASYNC,T,VIEW`, no fields. nvdisasm 13.1 (`tools/probes/re_sm120_fence_view_async.py`):
  bit 72 is the scope — clear `.S` (`fence.proxy.async.shared::cta`, also nvcc's lowering of the generic `fence.proxy.async` behind
  `MEMBAR.ALL.GPU`), set `.G` (`fence.proxy.async.global`; its word decoded as `.S` with a reserved-bit residue through the sign-bit
  fallback and did not assemble) — the predicate guard [15:12] is live, bit 73 (`.T`, the tensor-memory scope of sm_100 / sm_103, legal
  on `-b SM100` / `-b SM103`) is illegal on SM120 and SM121, every other bit text-inert. `FENCE` joins the decoder's fail-closed bases
  (BUG-225 list). Control law recorded with the rows: a read barrier on the word ([115:113] ≠ 7) is illegal — the fence carries a write
  barrier at most (nvcc: wrtbar + stall 4); `ctrl_class` stays unset (the static `barrier` class would drop the write barrier nvcc's
  consumers wait on — a scheduler item). Both scopes assemble; `.T` is refused (`tests/sm120_fence_view_async.rs`; bug225 / bug226e pins
  moved to the measured state). The `.G` rows on sm103a / sm100a / sm121a (where `FENCE` is absent) are open.
- **The megakernel corpus as a suite pin** (`tests/corpus_pins.rs::megakernel_corpus_sm120_strict`,
  `tests/fixtures/corpus_megakernel_sm120.jsonl.gz`): the 32 963 distinct words nvcc 13.0 emits for the persistent-kernel programme's
  kernels — the primitive probe (bulk copies, mbarriers, fences, `USETMAXREG`, timers, acquire / release idioms), the fused persistent MoE
  kernels (427 120 words over four cubins) and the hybrid's device-side collective kernel (`LDGSTS.E.BYPASS.128`, `LDGDEPBAR`, `DEPBAR.LE
  SB0`, `F2F.BF16.F32`, `ATOMG.E.EXCH.STRONG.GPU`, the `MEMBAR.SC.SYS; ERRBAR; CGAERRBAR; CCTL.IVALL` fence). None of these kernels is in the
  census corpora; every word decodes and re-encodes bit for bit (on the previous table two did not: `UBLKCP.G.S`, `FENCE.VIEW.ASYNC.G`).
- Suite 2 916 → 2 929 passed / 0 failed / 9 ignored; the form / variant pins of 13 tests moved (979 → 983, 38 838 → 38 848, 15 897 →
  15 901 loader keys); census strict 1 811 600 / 1 811 600, `asm -T` 157 / 157, the 99 production sources byte-identical, and the
  megakernel probe cubins (472 + 80 words of nvcc 13.0's persistent-kernel primitives) round-trip strictly for the first time.

## Unreleased — 2026-11-08 (session T-23: the canonical tables in the compact one-row-per-line layout with the provenance written once per level — NEEDS 61 (a) + (b); `tools/tablefmt.py`)

- **Tables vendored from blackwell-isa `4f72245`** — the same 38 838 / 35 876 / 35 870 / 50 444 rows (sm120 / sm103a / sm100a / sm121a; rows
  without `_src` unchanged at 7 / 893 / 893 / 2 654), rewritten: `sm121a.json` **87.0 → 32.8 MiB**, `sm120.json` 73.6 → 28.0, `sm103a.json` /
  `sm100a.json` 67.8 → 23.7 / 23.6 (the vendored `.gz` 1.08 → 0.69 MB on sm121a). Why: GitHub refuses files over 100 MiB and the next sm121a
  lattices would not have fit (`T/NEEDS_OWNER.md` 61; R's decision 12:40Z). What moved: a lattice family's measurement note is written once
  — in `_meta.provenance.sources[<tag>].note` when every row of the tag shares it, on `instructions.<key>._note` when every row of the key
  shares it, on the row only where the row's own differs (24.0 MiB of repeated prose on sm121a); `instructions.<key>._src` is set on every
  key whose rows all carry one tag (the rows keep their `_src`); a field carries `_src` only when measured by another tag than its row
  (6.6 MiB); the layout is compact JSON with one encoding row per line (24 MiB of `indent=1` whitespace), `_meta` indented. For every row
  the encoding record and the resolved provenance (tag, note, per-field tag) are identical before and after (`T/t23/probe/fmt/equiv_check.py`,
  0 differences, idempotent); whole-census parity, the two corpus pins and every suite count are unchanged.
- **`tools/tablefmt.py`** (new) is the canonical reader / writer: `load_table` refuses any other layout, `save_table` hoists and writes,
  `row_src()` / `row_note()` resolve a row's provenance (row → key → tag), `--check` / `--rewrite` / `--stats`. `tools/probes/nvprobe.py`
  and the twelve probes with their own writers go through it (`nvprobe.row()` may keep producing verbose rows — the hoisting happens on
  save); `tools/sync_table.py --validate-only` refuses a canonical table in any other layout or with un-hoisted provenance, and documents
  key-level `_src` tags like row tags; `tools/audit_table.py` and the loader (`IsaTable::load`: the `rows-` arm) read a row's tag as its
  own or its key's. Tests re-pinned to the convention: a field's tag is its own or its row's (`sm120_{prmt_ur,arrives_ldgstsbar,mufu_ur,
  hmul2_imm,ldsm_fp4,ldl_aruri,utmastg_dims}`, bug175 / 202 / 371), the `sm120_ldsm8_mt1616` snapshot projected by the same rule; the
  42 canonical-revision pins moved once.
- **CI (NEEDS 62):** `cargo test` in CI ran the 520 integration-test binaries one after another in the debug profile, each parsing its
  tables cold — 1 h 50 to 3 h 35 per run on the hosted runner (six runs of 2026-11-08 still in progress at 13:00Z) against the 6-hour job
  limit. The workflow now runs the push gate's runner, `tools/test_suite.py --release -j $(nproc) -t 2` (the same binaries built with
  `cargo test --release --no-run`, run in parallel longest first, exit 1 on any failure), plus `cargo test --release --doc`, with
  `Swatinem/rust-cache` for the dependency builds; `--validate-only` also checks the canonical layout.

## Unreleased — 2026-11-08 (session T-22, batch 9: the UIADD3 `.64` groups on sm103a / sm100a / sm121a — the B300 corpus' last `UIADD3.64` holes, the GB10 16-word residue)

- **Tables vendored from blackwell-isa `fddd1b3` + `3fb3b82`** (sm103a 516 forms / 35 876 variants, rows without `_src` 898 → 893; sm100a 515 /
  35 870, 898 → 893; sm121a 2 150 / 50 444, 2 663 → 2 654). sm120's measured UIADD3 `.64` rows (the UR form 0x297, the immediate form
  0x897) placed as the `64` groups of the plain keys of the three tables and re-measured there with `tools/probes/re_sm120_rows.py
  --family uniform --arch SM103` / `SM100` / `SM121` (the corpus words as witnesses: sm103a 6 + 3, sm100a 3, sm121a 19 + 16; the plain
  `""` rows of the two keys measured on the way); sm121a's three dotted `UIADD3.64_*` harvest keys are aliases. Test
  `tests/sm121a_sm103a_sm100a_uiadd3_64.rs`. **The `.X` rows measured too** (`3fb3b82`): once the plain rows failed closed on their dead
  bits [90:77], the harvest `UIADD3_…_UP_UP` rows were found claiming those words (`UP15, !UPT` / `!UPT, !UP6` for the vendor's plain
  6-token text — bug459a's 2026-09 "x3 standing" overprint); sm120's field lists measured on the three targets, bug459a's EXACT /
  X3STANDING cells re-pinned to the sm120 hole-parity doctrine.
- Corpus pins (`tests/corpus_pins.rs`): **B300 85 707 → 85 721 / 85 792 words, 288 → 296 / 328 cubins strict-exact** (sm103a 3 959 /
  3 962 decoded — the 3 `MOV` probe-cubin words with text-inert bits are the last holes —, sm100a every word decodes); **GB10 91 926 /
  91 927 re-encode** (the one left is BUG-037's alignment refusal of a cuBLASLt `HMMA.1688.F32` word).
- Found on the way by the lattice sweep (counted by the test, the uniform family's next items on these tables): the sm121a junk
  key `UIADD3_UR_UP_UP_UR_UR_R_II_P` (it claims the UR form's words with bits in the unused immediate window), sm103a / sm100a's
  harvest `ULOP3 LUT` row (a 6-bit `pred`, a 9-bit LUT, no `.PAND`: the ULOP3 immediate word renders vendor-false).

## Unreleased — 2026-11-08 (session T-22, batch 8: sm121a ATOM / ATOMG in the plain uniform-indexed form measured on `-b SM121`)

- **Tables vendored from blackwell-isa `ce51005`** (sm121a 2 153 forms / 50 447 variants, rows without `_src` 9 575 → **2 663**). New
  probe `tools/probes/re_sm120_atom_aruri.py` (modelled on `re_sm120_redg.py` and T-6's `re_sm120_atomg_el_aruri.py`): `probe --arch
  SM121 --witnesses <corpus>` — 18 398 form words print the law's text, 55 lattice words are illegal / `INVALIDn` / inert twins / other
  forms' words (`-b SM120` / `SM103` / `SM100` print the same text for the canonical words); `apply` creates `ATOM_P_R_ARURI_R` /
  `ATOMG_P_R_ARURI_R` (8 640 + 9 600 groups: 2 (`.E`) × 9 / 10 ops × 5 types incl. `.128` × 6 cache × 16 scope; SAFEADD is ATOMG's op 9,
  `INVALID9` on ATOM) and retires the 6 912 dotted one-group keys as aliases. The 15 ATOMG words of the GB10 corpus are the descriptor
  form: 0 witnesses in this form, the census unchanged. Test `tests/sm121a_atom_aruri.rs`.
- Printer: the atomics' `_P_R_ARURI_R` keys print `[Ra.U32+URb(+off)]` with RZ printed and the width taken from the key — on ATOM /
  ATOMG bit 90 is the top bit of the 4-bit op field, so the generic width rule (`[91:90] == 3` → `.64`) printed a false `.64` on every
  EXCH / SAFEADD word, and sm121a's dotted `ATOM.E.*` keys printed `desc[UR][R.64]` for a `[R.U32+UR]` word (0 GB10 witnesses);
  `SAFEADD` joins the atomics' op slot of the modifier order. Whole-census parity 0 on the 249 929 production words.
- **The table-size wall** (`T/NEEDS_OWNER.md` 61): `sm121a.json` is 87 MiB after this batch — GitHub refuses files over 100 MiB. The
  ATOM rows carry a one-line `_note` (the family's law once, in `_meta.provenance.sources[tag].note`) and no per-field `_src`; the
  next sm121a lattice waits for the owner's schema decision.
- Census pins: sm121a forms 9 063 → 2 153, variants 39 119 → 50 447, aliases 14 835 → 21 747, claim_forbid 5 253 → 23 493.

## Unreleased — 2026-11-08 (sessions T-21 / T-22, batch 7 + NEEDS 59: the conversions and the FP32 ALU on sm121a / sm103a / sm100a; VIMNMX3 measured on sm103a / sm100a; sm121a's MUFU_R_L retired)

- **Tables vendored from blackwell-isa `15435a0`** (sm121a 9 063 forms / 39 119 variants, rows without `_src` 10 000 → 9 575; sm103a
  516 / 35 875, 1 280 → 898; sm100a 515 / 35 869, 1 280 → 898). `tools/probes/re_sm120_conv.py` and `re_sm120_fp32_alu.py` (G's
  batch 6 / 8 probes) run with `--arch SM121` / `SM103` / `SM100`: every word obeys the sm120 law on the three targets (conv 2 494 form
  + 18 glyph + 547 lattice words, FP32 ALU 1 636 + 30 + 492 + 16 neighbour, per target); the conv `apply` keeps measured rows outside
  its lattice (T-14's sm103a MUFU packed-half lanes) and aliases the mis-tokenised keys by their `and_base`'s form. Tests
  `tests/sm121a_conv.rs`, `tests/sm121a_fp32_alu.rs`, `tests/sm103a_sm100a_conv.rs`, `tests/sm103a_sm100a_fp32_alu.rs`.
- **NEEDS 59** (two harvest rows the new lattice tests exposed): the sm103a / sm100a `VIMNMX3_R_R_R_R_P` / `VIMNMX3_R_R_UR_R_P` rows
  declared the fifth operand's predicate as a 4-bit field at shift 1 — inside the opcode nibble — and claimed FMNMX words
  (`FMNMX R4, R2, R3, PT` decoded as `VIMNMX3 R4, R2, R3, R1, P4`); the form is real (nvdisasm names it, harvest count 1 139 / 944),
  so the three rows were measured, not deleted (`re_sm120_rows.py --family intalu --arch SM103` / `SM100`: the predicate at [89:87]
  with its sign at 90, the `.U32` / `.S16x2` / `.RELU` bits other groups' words; `tests/sm103a_sm100a_vimnmx3.rs`). sm121a's
  label-typed junk key `MUFU_R_L` (a whole-key twin of the measured `MUFU_R_R`; it claimed `MUFU.INVALID6.F16`) is an alias.
  `re_sm120_rows.py`: VIMNMX3 in the `intalu` family with its measured field lists, `apply --arch / --test` for the other tables.
- Corpus pins: B300 sm103a 3 950 / 3 962 decoded, 3 933 bit-exact (the `I2F.U16[.RZ]` ×2 and `FMUL.RZ` ×1 holes closed; the strict
  round trip 85 704 → **85 707 / 85 792**); GB10 strict residue **40 → 17** (the 23 `FFMA_R_R_R_II` words re-encode — the measured
  `FFMA_R_R_R_FI` row carries the `.reuse` field of the second register; left: the harvest `UIADD3` `64` group ×16, one BUG-037 refusal).
- Re-pins of the 2026-08/09 F2I / MUFU / FADD / FMNMX wave suites on their sm121a / sm103a / sm100a legs (15 binaries, 31 tests): G's
  sm120 arms extended to the measured legs by a documented `conv_measured(leg)` where the arm is the inert-bit convention (the F2I
  alias bits 73 / 74 fail closed on every table; bug339 / 341 / 361 / 362 / 363 / 379_380 / 390 / 403 / 265 / 270); bug125 (the sm103a
  F2I forms carry 512 measured groups each, the immediate typed by the source lane); bug159 / bug178 (the sm103a `MUFU_R_FI` /
  `FMUL_R_R_FI` immediates are f32 fields, not the harvest's baked corpus constant — the vendor's `-QNAN` glyph is the display print,
  the lossless `0xffc00000F` literal re-encodes (A8), a symbol on the typed field is refused, nothing is fabricated); bug247
  (`.XORSIGN` / `.FTZ.NAN` measured FMNMX groups on the four legs); bug261 (the measured and_base is clear in the guard field); the
  census pins (sm121a forms 9 064 → 9 063 after the alias).

## Unreleased — 2026-11-08 (session T-21, batch 6: ISETP / UISETP on sm121a / sm103a / sm100a, FSETP / DSETP on sm103a / sm100a, PLOP3 / P2R / R2P on the three)

- **Tables vendored from blackwell-isa `0525e95`** (sm121a 9 334 forms / 36 884 variants, rows without `_src` 11 160 → 10 000;
  sm103a 651 / 33 532, 1 584 → 1 280; sm100a 650 / 33 526, 1 584 → 1 280). `tools/probes/re_sm120_isetp.py` gains `--arch SM121`
  (the 64-bit compare renders there as on SM120) and `--witnesses`, and an `apply` for the other tables (subsets, retired
  out-of-lattice groups, dotted keys → aliases; on SM103 / SM100 two types and bit 80 fail-closed — NEEDS 46, the four phantom
  `.S64` / `.U64` groups retired). Measurement: SM121 1 944 form + 192 lattice + **3 155 GB10 witness words** (579 64-bit compares)
  obey the SM120 law; SM103 / SM100 967 form + 1 169 lattice words (the 977 bit-80 words print the 32-bit text).
  `re_sm120_fsetp_dsetp.py --arch SM103` / `SM100` (NEEDS 58): the sm120 law holds word for word; the donors' `.OR` reading of bit 75
  and the baked `|Rb|` of `DSETP LTU,OR` are gone. `re_sm120_plop3_p2r_r2p.py --arch SM103` / `SM100` / `SM121`: the law holds; the
  sm103a / sm100a harvest `PLOP3_P_P_P_P_P_II_II` row with a "pred" field inside the opcode nibble (it claimed the bit-80 ISETP
  words and encoded PLOP3 texts as R2P words) retired. Tests `tests/sm121a_isetp.rs`, `tests/sm103a_sm100a_isetp.rs`,
  `tests/sm103a_sm100a_fsetp_dsetp.rs`, `tests/sm121a_plop3_p2r_r2p.rs`, `tests/sm103a_sm100a_plop3_p2r_r2p.rs`.
- Decoder: the DSETP sign-law arm (the boolean `INVALID3` fails closed instead of printing `.XOR`) covers every table now that the
  family is measured on all four.
- Re-pins: bug254 (the donors decode the boolean like sm120; no injected `|R116|`), bug139 / bug140 (the 2026-08 "byte-exact"
  PLOP3 words were `R2P PR, R0.B3, 0x0` for nvdisasm — the measured words are the vendor's PLOP3), the census pins.
- Gates: GB10 91 927 / 91 927 (287 ISETP words moved to the plain keys, texts unchanged); B300 85 704 / 85 792, 0 words with a
  changed text or key.

## Unreleased — 2026-11-08 (session T-21, batch 5: sm121a LDG.256 (three address forms) + STG.256 + REDG uniform-indexed forms measured on `-b SM121`; the GB10 and B300 corpora as suite pins)

- **Tables vendored from blackwell-isa `f254702`** (sm121a 9 488 forms / 37 077 variants from 23 754 / 26 595; rows without
  `_src` 25 427 → 11 160). G's batch 10–14 probes gain `--arch SM121` and `--witnesses <corpus.jsonl>` (the form's words of a
  census corpus as `witness` fixture rows with their own control codes): `tools/probes/re_sm120_ldg256.py --form dARI /
  ARURI64 / ARURI`, `re_sm120_stg256.py`, `re_sm120_redg.py` — all five runs passed on `-b SM121` (every form word prints the
  SM120 text; the 99 LDG.256 + 68 STG.256 words of the GB10 census corpus obey the law). `LDG_R_R_{dARI,ARURI64,ARURI}[_II][_P]`,
  `STG_{dARI,ARURI,ARURI64}_R_R[_II]` and `REDG_ARURI_R` / `REDG_ARURI64_R` created with the measured rows; the 14 286 dotted
  2026-08/09 keys retired as `_meta.key_aliases` (167 corpus words moved to the plain keys, texts unchanged). Tests
  `tests/sm121a_{ldg256_dari,ldg256_aruri64,ldg256_aruri,stg256,redg_aruri}.rs` (G's sm120 checks over this table + the GB10
  witness words).
- Re-pins of the sm121a legs of the 2026-09 EFL2.256 wave suites to the measured doctrine (the text-inert bits fail closed;
  the vendor-named words the 2026-09 HOLEs stood on decode — bug476's "sm121a coverage gap" and bug475's "121a HOLE-keep"
  closed; the R3b anomaly and 469 graft keys are aliases), the sm121a key / variant / `claim_forbid` census pins, arch_vendoring's
  pred_inv4 probe on the measured `LDG_R_R_dARI_P` row.
- **`tests/corpus_pins.rs` (NEEDS 56):** the GB10 census (`tests/fixtures/corpus_gb10_sm121a.jsonl.gz`, 91 927 words with
  nvdisasm 13.0 texts) and the B300 publish corpus (`corpus_b300_sm103a.jsonl` / `corpus_b300_sm100a.jsonl`, the 3 962 + 1 116
  distinct instruction words of the 328 cubins) are suite tests: every word decoded, printed losslessly, re-parsed and
  re-encoded, the counts exact and the residues named (GB10: 91 927 / 91 927 decode, 40 re-encode residues of three keys;
  sm103a: 15 holes by opcode — `UIADD3.64`, `I2F.U16`, `FMUL.RZ`, three `MOV` words with text-inert bits —, 9 BUG-080
  refusals, 8 isolated-word artefacts; sm100a: 3 `UIADD3.64` holes, 3 artefacts). A regression of the 2026-11-06..08 class
  (564 GB10 words without a decode for two days) fails `cargo test` now, not the field.

## Unreleased — 2026-11-08 (sessions T-20 / T-21, batch 4: sm103a / sm100a LDG.256 (three address forms) + STG.256 measured on `-b SM103` / `SM100`)

- **Tables vendored from blackwell-isa `39d0372`** (sm103a 650 forms / 32 916 variants from 8 784 / 25 517, sm100a 649 / 32 910
  from 8 783 / 25 511; rows without `_src` 9 714 → 1 584 on both). G's batch 10–13 probes `tools/probes/re_sm120_ldg256.py
  --form dARI / ARURI64 / ARURI` and `re_sm120_stg256.py` run with `--arch SM103` / `SM100` (nvdisasm 13.1): all eight runs
  passed — every form word prints the SM120 text on both targets (the L2 = 3 plane is `INVALID3` there, a lattice plane on
  every target); fixtures `tests/fixtures/sm103a_{ldg256_dari,ldg256_aruri64,ldg256_aruri,stg256}_nvdisasm.jsonl` and
  `sm100a_…`. `LDG_R_R_{dARI,ARURI64,ARURI}[_II][_P]` and `STG_{dARI,ARURI,ARURI64}_R_R[_II]` created with 13 824 + 1 728
  measured rows per table, the 7 782 + 1 164 dotted 2026-09 keys of each retired as `_meta.key_aliases`. Tests
  `tests/sm103a_sm100a_{ldg256_dari,ldg256_aruri64,ldg256_aruri,stg256}.rs` (G's sm120 checks over the two tables; on sm103a
  the encoder's silicon laws BUG-060 — an EFL2.256 load with an even base is refused — and BUG-077 — the descriptor form's
  true-pair classes need an even base — are accepted exactly where they fire, the byte mapping proven under
  `CUBIT_DISABLE_ERRATA`).
- Re-pins of the 2026-09 EFL2.256 wave suites on their sm103a / sm100a legs (18 binaries; the sm120 arms G added per batch
  extended to the measured legs, the measurement cited in each file): the text-inert bits of the 256-bit load (83, [95:92]) and
  store ([74:72], 83, 87, [95:92]) fail closed on the measured rows; words nvdisasm names that the 2026-09 HOLEs stood on decode
  through the plain keys (the EU / NA cache-code drills, the LTC × ENL2 crosses); the bare `[URb]` spelling mints the `.64`
  word (BUG-464's rule); the NA.EFL2 descriptor spellings of LDG / STG are legal words the vendor names on SM103 / SM100 /
  SM120 and mint (bug076 / bug077 — the "era desc spelling must be dead" pins of 2026-09 stood on the harvest's silence;
  BUG-060 / BUG-076 keep their arms); the sm103a table-shape anchors of bug123 / bug147 (`LDG_R_R_dARI[_II]` 1 152 measured
  groups each, `STG_dARI_R_R` present with 288, the 475-lattice keys aliases); the `_src463` / `_src465` / 468-graft key
  censuses → 0 on the measured legs; the key / variant / `claim_forbid` counts of sm103a / sm100a and the canonical revision
  in 58 files.
- Gates for the batch: the B300 publish corpus strict round trip unchanged at 85 704 / 85 792 words and 288 / 328 cubins
  strict-exact (0 cubins with a changed count); the GB10 census and the sm120 census untouched; the full suite green.

## Unreleased — 2026-11-08 (session T-20, batch 3: sm103a / sm100a REDG uniform-indexed forms measured on `-b SM103` / `SM100` — the first batch of the B300 line)

- **Tables vendored from blackwell-isa `6a468a2`** (sm103a 8 784 forms / 25 517 variants from 14 926 / 22 445, sm100a 8 783 /
  25 511 from 14 925 / 22 439; rows without `_src` 15 858 → 9 714 on both). `tools/probes/re_sm120_redg.py --arch SM103` /
  `SM100`: G's batch-14 sweep (9 334 form + 58 lattice words) prints the same text on both targets word for word;
  `REDG_ARURI_R` / `REDG_ARURI64_R` created with the 9 216 measured rows per table, the 6 144 dotted harvest keys of each
  retired as `_meta.key_aliases`. Test `tests/sm103a_sm100a_redg_aruri.rs` (the five sm120 checks over the two tables; on
  sm103a a guard-predicated non-EL REDG is refused by BUG-080 — the silicon law — and the test accepts exactly that).
- Re-pins: bug452 / bug461 (the measured plain key on the two legs; the 2026-09 fuzz words with a text-inert bit fail closed
  on the measured rows as on sm120 since batch 14), bug176 / bug381 / bug463 / bug467 and the data of bug450 / 453 / 459a /
  468 / 469 / 474 / 475 / 476 (the sm103a / sm100a key / variant census).
- Gate: the B300 publish corpus strict round trip unchanged at 85 704 / 85 792 words, 288 / 328 cubins strict-exact.

## Unreleased — 2026-11-08 (session T-20, batch 2: sm121a FSETP / DSETP measured on `-b SM121` — the first batch of the GB10 line; a GB10 census regression closed)

- **Tables vendored from blackwell-isa `75e9d20`** (sm121a 23 754 forms / 26 595 variants, from 23 860 / 26 421; rows without `_src`
  25 685 → 25 427; the other tables unchanged). `tools/probes/re_sm120_fsetp_dsetp.py --arch SM121`: the sm120 law of 2026-11-06
  holds word for word on SM121 (1 022 form + 12 glyph + 223 lattice words) and on all 2 688 FSETP / DSETP words of the GB10 census
  corpus (`--witnesses`, their own control codes); 432 measured rows on the six plain keys (`FSETP_P_P_R_UR_P` created, 312 groups
  added), 105 dotted harvest keys + the 7 junk keys of the sm120 batch retired as `_meta.key_aliases`. `apply` generalised for a
  table whose plain keys hold a subset of the lattice (byte-identical on sm120). Test `tests/sm121a_fsetp_dsetp.rs` (6 pins).
- **Decoder:** DSETP off the priority-3 sign-tolerant match on sm121a as on sm120 (its boolean sits in the sign window).
- **GB10 census regression closed (KNOWN_ISSUES V3):** since G's batch 3 (2026-11-06) the FSETP decoder arm applied to every table
  while the sm121a harvest rows had no sign fields — **564 signed FSETP words of the 91 927-word GB10 corpus had no decode** at the
  2026-11-06..08 tips (found by running the census locally, `T/t20/gb10_census.py`); with the measured rows 91 927 / 91 927 decode,
  1 text mismatch (`LEPC`), strict re-encode 91 887 / 91 927 (40 words outside the family, as before). The GB10 census joins the
  gate of every change that touches the decoder or `sm121a.json`.
- **Inventories of the three remaining tables** (KNOWN_ISSUES T1): sm121a 25 427 of 26 595 rows without `_src`, sm103a 15 858 of
  22 445, sm100a 15 858 of 22 439 — the LDG / REDG / STG (/ ATOM / ATOMG on sm121a) lattices are 85–91 % of them.
- Pins: the sm121a key / variant census in the bug439 / 441 / 442 / 450 / 453 / 459a / 462 / 463 / 468 / 469 / 474 / 475 / 476 data.

## Unreleased — 2026-11-08 (session T-20: the IMAD `-Ra` reading of bit 72 retired — NEEDS 53 measured compute-inert on silicon)

- **Tables vendored from blackwell-isa `27b1272`** (sm120 979 forms / 38 838 variants, unchanged counts; 7 rows without `_src`,
  unchanged). The 24 measured non-HI IMAD rows lose the `neg@72` field they carried as cubit's own law (BUG-296: `-Ra` at
  bit 72, re-affirmed by T-3 on 2026-11-04 with the U32 twins; the T-19 fixture's class `cubit_law`). **Silicon (session T-19,
  test host GPU 0, `pt-needs53`, 2026-11-08): plain `IMAD` and the same word with bit 72 set both compute a·b+c; the `-Rc`
  control (bit 75) computes a·b−c; `IMAD.U32` agrees** — and nvdisasm 13.1 prints nothing for the bit on any IMAD form on the
  four targets (62 / 63 text-inert too; 73 = `.U32`, 74 = `.X`, 75 = `-Rc`). Bit 72 is a text-inert bit like any other: the
  rows fail closed on it. Whole production census (249 929 words): decoded and re-encoded bit-exact before and after, 0 text /
  key / group changes (0 census words carry bit 72 on IMAD).
- **Encoder (SM120):** the whole IMAD base is off the generic ALU sign emit (until now the `.HI` groups only), and a `-` / `|`
  glyph on an IMAD register operand without a field of the row is refused with the measurement named (`NEEDS 53: IMAD has no
  encoding for the signed / absolute operand …`) — `IMAD R5, -R4, R3, R2` used to assemble to the plain a·b+c word plus bit 72
  (silent wrong code), `|R4|` was dropped silently, `-R3` minted the text-inert bit 63. `-Rc` (bit 75) and `-URc` (bit 63 on
  the UR-addend form) stay as the measured fields. Other tables unchanged (their IMAD rows are harvest rows).
- **Decoder (SM120):** the whole IMAD base is off the priority-3 sign-tolerant match and the ghost-sign post-pass: the bit-62 /
  63 / 72 words fail closed (`no instruction matches`) — on the T-19 tree the bit-63 neighbour of `IMAD R32, R48, R80, R24`
  decoded through the T-3 `U32` twin as `IMAD.U32 R32, |R48|, -R80, R24`; 73 / 74 / 75 decode as `.U32` / `.X` / `-Rc`.
- **`tools/probes/re_sm120_rows.py`:** `MANUAL_FIELDS` emptied (its one entry was this law) and the inverse `RETIRED_FIELDS`
  added — a declared field dropped before the sweep so the bit takes its measured class; the intalu family re-probed on the
  applied table (183 / 183 rows measured, pass 2 structurally identical to pass 1). Tests: `bug296_i2ip_sign`'s IMAD control
  re-pinned on the sm120 leg (`-Ra` / `|Ra|` refused, `-Rc` = bit 75 round-trips, the bit-72 word fails closed; the sm121a leg
  keeps the harvest behaviour until that table's measurement), the 24 records of
  `tests/fixtures/sm120_rows_intalu_nvdisasm.jsonl` updated, 58 revision / SHA pins moved to `27b1272`.

## Unreleased — 2026-11-08 (session T-19: the last 111 harvest rows of sm120 closed — 7 documented rows left)

- **Tables vendored from blackwell-isa `89dc967`** (sm120 979 forms / 38 838 variants, from 1 015 / 38 866 at `7f12b68`).
  KNOWN_ISSUES T1: **38 838 rows, 38 831 with `_src` — 7 harvest rows left, every one a documented owner item** (111 at
  `7f12b68`): the alias-able groups of the four mixed keys `F2FP_R_R` / `FLO_R_UR` / `WARPSYNC` / `WARPSYNC_R` (a group-level
  alias is a schema item) and `WARPSYNC.COLLECTIVE_R_II`'s 50-bit immediate (NEEDS_OWNER 55c). The decisions of NEEDS 55 (R,
  2026-11-08 03:05Z) measured with `tools/probes/re_sm120_rows.py`: 71 rows measured with their field lists corrected from the
  sweep (`MANUAL_ROW_FIELDS`: the destination-predicate windows narrowed to 3 bits, the STS / STL `sub_ur` 9 → 8 bits, IADD3's
  second carry-out predicate [86:84], BSSY's `imm_shr2` target at [63:34], the `.H1` merge selector `opmod:H1` on the F2FP /
  F2IP / UF2FP merge forms, …), 15 HADD2 / HFMA2 immediate-pair rows (bit 85 `BF16_V2` re-types both packed-half immediates —
  a modifier bit, `PAIRED_TYPE_BITS`), the four PT-elided `IMAD.HI` / `R2UR.FILL` plain groups, 17 mis-named keys renamed to
  the vendor's spelling (`RENAMED_FROM`), 12 keys retired as `_meta.key_aliases` (the five `CALL.REL.NOINC_*` spellings →
  `CALL_II`, the five F2FP `*PACK_AB_P_R_R_R` phantom-predicate keys, `IADD.X_R_P_R_R_R`, the dotted
  `ULOP3.LUT_UP_UR_UR_II_UR_II_UP`), 4 dead rows and 12 junk keys deleted (`DELETE`: every canonical word nvdisasm rejects, or
  another form's words), 6 design rows marked `_src: "modelled"` (`MODELLED`: the IADD3.X encode / decode pair of bug089 /
  bug012, `HFMA2_R_R_R_II_FI`'s plain group, `UBLKPF.L2_AUR_UR`, the `encode_only` retention rows of bug193 / bug092). Whole
  production census (249 929 words): 249 929 decoded, 249 929 re-encoded bit-exact, 0 text changes; the only key / group
  moves are the two deliberate renames (`F2FP_R_R_R_R`'s sorted group name, 2 759 words; `UIADD3_UR_UP_UP_UR_II_UR` `64`,
  160 words).
- **Printer:** branch targets print as full signed values — `decode_branch_target` returns the 64-bit target and
  `fmt_branch_target` spells a backward target of an isolated word `-0x…` as nvdisasm does (the old print wrapped BSSY /
  CALL targets to 32 bits: `0xe9696978` for `-0x16969688`); BSSY reads its target from the measured `imm_shr2` field at
  [63:34]. `UF2FP` prints `SATFINITE` / `RELU` before the types like F2FP; `UBLKRED` prints the two address spaces, then the
  operation, then the element type (`UBLKRED.G.S.ADD.S32`). HSET2 joins the packed-half compares' `INVALID1` half-selector
  law (`r_hsel_invalid1_slot`). No production word changes text (whole-census parity).
- **Encoder:** BUG-048 kept on the measured rows — on the IADD3 / IADD `.X` carry forms a `-Rn` lands on the register's
  `inv` bit (nvdisasm 13.1 prints `~Rn` for every one of them; the harvest had `neg` and `inv` stacked on bit 63).
- **Tests:** the six `tests/sm120_rows_*.rs` regenerated from the T-19 fixtures; `tests/sm120_rows_common.inc` knows the
  `deleted` (a key gone whole) and `modelled` (`_src: "modelled"`, the pinning test named in the note) statuses; 30 bug-wave
  tests re-pinned to the measured doctrine with the measurement cited in each (bug399 / 412413 / 413ii / 425 / 425b / 433 /
  438 / 443: the bit-72 and bit-91 carriers of the STS grids fail closed on the measured rows; bug419: HADD2 / HFMA2 cells with
  text-inert modifier bits; bug165 / 172: the measured LDC donors' masks are their fields; bug048: `~R92` on IADD3.X's bit 75;
  bug289: the `HFMA2_R_R_R_UR` reuse drill with a live control word, bit 124 is nvdisasm-rejected; bug308: the F2IP text's
  fourth operand is a register; sm120_era_keys: the `MOV_P0_R_II` UMOV words carry the inert bits [75:72]; the census /
  claim_forbid / alias counts). `tests/sm120_rows_common.inc` is shared by all seven family tests.
- **Probe tool `tools/probes/re_sm120_rows.py`:** `MANUAL_ROW_FIELDS` (per-row corrected field lists), `MANUAL_SPELLING_OK`,
  `PAIRED_TYPE_BITS`, `MODELLED`, `DELETE`, `RENAMED_FROM`; an applied row's cubit-law field (IMAD's `neg@72`) re-probes as
  `cubit_law`, not as a text-inert defect; a flip whose text is an existing row's spelling is a modifier bit (F2FP's bit 78
  `PACK_AB` ↔ `MERGE_C`).

## Unreleased — 2026-11-08 (session T-18 batch 2: the exceptions phase — 32 whole-key twins retired as aliases)

- **Tables vendored from blackwell-isa `7f12b68`** (sm120 1 015 forms / 38 866 variants, from 1 047 / 38 898 at `fd736a7`).
  KNOWN_ISSUES T1: **38 866 rows, 38 755 with `_src` — 111 harvest rows left** (143 at `fd736a7`). The key-naming decisions
  of G's NEEDS 10–12, decided by the table's existing convention "aliases for twins": 32 harvest keys whose name does not
  spell the vendor text of their own canonical word, each a whole-key twin — the single group's canonical word decodes
  through an existing family key with the vendor's exact text and re-encodes bit for bit, 0 census witnesses — retired as
  `_meta.key_aliases` forwarding to the real key (ATOMG.E.{MAX.S32,MIN}.STRONG.GPU_P_R_dARI_UR → ATOMG_P_R_dARI_R; the
  BSSY / BMOV / BREAK / CCTL.IVALL / PREEXIT / CS2R / S2UR control & sysreg mis-keys; the five IADD3 immediate mis-keys;
  the five LOP3.LUT_*_II_II → LOP3_*_II_P; VIMNMX.S32 / VIMNMX.U32_R_R_II_II; the UIADD3 / ULOP3.LUT / UPRMT / USEL /
  UVIMNMX uniform mis-keys). Kept as named exceptions (owner decision, the project models them deliberately with
  dedicated tests): IADD.X_R_P_R_R_R (bug089/012), IADD3.X_R_P_P_R_II_R_P_P (bug089), UBLKPF.L2_AUR_UR (sm120_ublkpf_l2);
  and the four mixed keys F2FP_R_R / FLO_R_UR / WARPSYNC / WARPSYNC_R (a live or non-aliasable group among theirs).
  The five family tests regenerated (the 32 move from EXCEPTIONS to ALIAS_KEYS); era-keys alias count 14 874 → 14 906;
  the claim_forbid census pins of bug459a / 461 / 462 / 463 / 476 re-pinned 11 001 → 10 999. Whole-census parity batch 1
  → batch 2 (249 929 words): 0 text / re-encode / key moves. Suite 496 binaries 2 799 / 0 / 9.

## Unreleased — 2026-11-08 (session T-18: the 192 wave-pinned rows take their measured status; the 2026-08/09 bug-wave suites re-pinned to the measured doctrine)

- **Tables vendored from blackwell-isa `fd736a7`** (sm120 1 047 forms / 38 898 variants, from 1 083 / 38 966 at `37d030f`; sm103a /
  sm100a / sm121a unchanged at `b214b0e`). KNOWN_ISSUES T1: **38 898 rows, 38 755 with `_src` — 143 harvest rows left** (304 at `37d030f`).
  Session G run 5 had verified 192 of the 304 remaining rows field by field but left them harvest because 46 test binaries (67 tests) of the
  2026-08/09 bug waves pinned their harvest structure or the tolerant decode of a text-inert bit (`EXCEPTION_PREFIXES` in
  `tools/probes/re_sm120_rows.py`; G's NEEDS 10–12). T-18 lifts the pin and re-pins those suites to the measured doctrine (a measured row's
  mask is its fields, fail closed on the text-inert bits — T-10's convention, every batch since). Of the 192: **93 measured** (`rows-half`
  43 → 51, `rows-intalu` 164 → 167, `rows-memory` 199 → 270, `rows-atomic` 57 → 68), **65 aliased** (the HFMA2 integer-immediate spellings
  `*_R_R_II_II_R*` → `*_R_R_FI_FI_R*`, the HADD2.F32 dotted twins, `F2F.F64.F32_R_R_R` → `F2F.F64.F32_R_R`, the LDC[.64]_R_cAI_II junk,
  `ATOMS_R_ARI` → `ATOMS_R_ARURI`), **3 deleted** (unreachable; `F2IP.U8.F32.NTZ_P_R_R_R_R` is an HMMA.1688.F16 word under a conversion
  key — no alias across mnemonics), **31 stay harvest** (their probe finds a real problem that folds into the named classes: the HADD2 /
  HFMA2 bit-85 immediate-pair rows, the STS / STL over-wide `sub_ur`, F2FP's `.H1`). Whole-census parity (249 929 production words, old
  engine + `655a2f1` vs new): **0 text / re-encode / key-group changes** — the measurement only narrows masks on words with no census
  witness. The 143 left = those 31 + the 112 named exceptions.
- **Re-pins of the 2026-08/09 bug-wave suites to the measured doctrine** (the measurement cited in each): the half / I2IP / MOVM cluster
  (`bug265 / 271 / 272 / 274 / 275 / 276 / 279 / 282 / 283 / 284 / 285 / 286 / 288 / 296 / 330 / 419 / 226e / 340` — the widened windows and
  the MOVM sub-op band and the HFMA2.F32 FTZ/SAT absorb window are text-inert and fail closed; the integer-immediate spellings and the
  dotted twins are aliases; two unreachable rows are dead), LDC (`bug145 / 163 / 167 / 172` — the measured rows carry the guard field, mask =
  fields), LDGSTS / LDS / STS / LDL / STL (`bug148 / 164 / 188 / 204 / 311 / 359 / 360 / 413ii / 415 / 420 / 425 / 425b / 427 / 433 / 438` —
  the synthetic bit-32 / bit-72 / scale / era-band words fail closed instead of folding or tolerating; the and_base lattice deltas are
  compared outside the measured fields; the STS_AURI b95 "era-band relax" is gone on the measured rows), and `sm120_audit_20261103` (one
  deleted-row word now decodes to a hole). `re_sm120_rows.py`: `EXCEPTION_PREFIXES` emptied, the IMAD HI-group exclusion for the neg@72
  law baked in, `apply` idempotent on tagged rows. The four `tests/sm120_rows_{half,intalu,memory,atomic}.rs` regenerated; era-keys alias
  count 14 839 → 14 874. Suite 496 binaries 2 799 / 0 / 9.

## Unreleased — 2026-11-07 (session T-17, gate 1: the T1 production line's run 5 — the long tail verified row by row by session G, batch 16)

- **Tables vendored from blackwell-isa `37d030f`** (sm120 1 083 forms / 38 966 variants, from 1 231 / 39 125; sm103a / sm100a /
  sm121a unchanged at `b214b0e`). KNOWN_ISSUES T1: **38 966 rows, 38 662 with `_src` — 304 harvest rows left** (1 034 at `3dde6e1`;
  18 841 of 26 598 on 2026-11-06): 192 of them verify field by field (their records are in the fixtures) but stay harvest until the
  2026-08/09 bug-wave suites that pin the tolerant decode of their text-inert bits (46 binaries, 67 tests) are re-pinned to the measured
  doctrine — the next T batch; the other 112 are the long tail's named remainder (the `EXCEPTIONS` of `tests/sm120_rows_<family>.rs`,
  G's NEEDS 10–12). Session G's run-5 batch 16, re-measured by T-17 (`T/t17/review/b16`, `b16b`): all 101 393 distinct words of the six
  fixtures (the canonical word and the single-bit flips of every row with their recorded texts or rejections, the 512 census witnesses)
  re-rendered with nvdisasm 13.1 on SM120; the whole production census (249 929 distinct words) decodes to the same display text,
  lossless text and re-encode verdict before and after — the one key move is the 272 census words of the retired integer-spelling twin
  `S2R_R_II`, now on their alias target `S2R_R_L` with identical text; the six tests are red on the previous table and green on this one.
  - **The long tail verified row by row — half-precision, integer ALU, uniform datapath, control, memory, atomics** (G's `2f56ae5`,
    taken as `37d030f` by G's own `tools/probes/re_sm120_rows.py apply --family {half,intalu,uniform,control,memory,atomic}` run on
    T's table — the six runs reproduce G's commit byte for byte on G's base, and T's result is exactly T's base + G's delta;
    `tests/fixtures/sm120_rows_{half,intalu,uniform,control,memory,atomic}_nvdisasm.jsonl`, `tests/sm120_rows_<family>.rs` on the
    shared body `tests/sm120_rows_common.inc`): the method of batch 15 over the 1 034 remaining harvest rows of 85 mnemonics —
    **571 rows measured** (`rows-half-2026-11-07` 43, `rows-intalu-…` 164, `rows-uniform-…` 95, `rows-control-…` 13, `rows-memory-…`
    199, `rows-atomic-…` 57; 237 fields added or retyped from the sweep: undeclared guard / `-X` / `~X` / `|X|` / `!P` / `.reuse` bits,
    f16 / bf16 immediates the harvest spelled as integers, 4-bit predicate windows split into predicate + negation; `variable_mask` =
    exactly the field bits, fail closed on the text-inert ones), **148 shadowed twin keys retired as `_meta.key_aliases`** (dotted
    twins, integer spellings of float-immediate forms, `?` / phantom-token junk, byte-identical rows — every one decoded through its
    target with the vendor text; 0 census witnesses but the 272 `S2R_R_II` words above, which the target prints identically), **11
    unreachable rows deleted** (dead rows of staying keys — the six `F2FP_R_R_R_R` junk groups, three `IADD3_R_P_P_R_*_R_P_P`
    spellings, `IMAD_R_P_R_II_R_P` `B90,U32,WIDE,X`, `WARPSYNC_R_II` — cubit decodes their words elsewhere; 0 census witnesses).
    **The 304 rows left:** 192 verified field by field but left harvest because the 2026-08/09 bug-wave suites pin the tolerant decode
    of their text-inert bits (field counts, `variable_mask` equal to a donor's, inert-bit "polygons") — G hands their re-pin to T; the
    other 112 are named exceptions (G's NEEDS 10–12): 82 keys whose name does not spell the vendor text of their own word (renames or
    deletions — a key-naming decision), 17 over-wide harvest fields, 15 HADD2 / HFMA2 immediate-pair rows whose bit 85 re-types both
    immediates, 12 undeclared operand bits, 8 keys whose every canonical word nvdisasm rejects, the PT-elided `IMAD.HI` / `R2UR.FILL`
    spellings, `WARPSYNC.COLLECTIVE`'s 50-bit immediate. Engine: a row tagged `rows-<family>-…` (`ModGroupEntry::row_probe`) stays on
    the strict / relaxed decode paths — off the broad match of memory keys and off the priority-3 sign-tolerant fallback (it has a
    field on every live slot; the batch-14 REDG guard by tag, next to the by-name one, which stays for the `redg-aruri-family` rows);
    LDGMC / STSM on the fallback's fail-closed list. Printer: `FHADD[.BF16][.RM|.RP|.RZ][.SAT]`, `I2FP.<dst>.<src>[.RZ]`,
    `LDGMC.E.<op>.<type>[.RN].<strength>.<scope>`. Re-pinned on sm120: era-keys 14 691 → 14 839, the 55 revision / count pins, the
    `bug400` LDG inert-bit words to the `_P` sibling (the measured plain row fails closed on bits 70 / 71), the claim_forbid census of
    bug459a / bug461 / bug462 / bug476 11 013 → 11 001 (12 claim_forbid-bearing junk rows gone with the aliases and deletions);
    `LEFT_TO_OTHER_BATCHES` of the memory / atomic tests 0 on this base (batches 12–14 are here). Of the three F2F harvest rows
    `F2F.F64.F32_R_R_R` is an alias now and the two typed keys `F2F.BF16.F32_R_R` / `F2F.F16.F32_R_R` verify field by field (pinned by
    `bug226e`, left for the re-pin batch) — the typed-key convention (D2) is the one the table already carries for F2F; the full
    type-pair × rounding × FTZ lattice stays a coverage item, not a T1 one.
- **T-17's re-pins for batch 16 on the sm120 leg, and one correction of the batch** (the gate's five red binaries): `bug463`'s
  claim_forbid census 11 013 → 11 001; `bug442`'s `???0` glyph cell and 97 of `bug443`'s 210 heal cells are holes on sm120 (the
  measured ordinary-store rows fail closed on their text-inert bits and on the `.64` uniform-indexed form `[R4.64+UR4]`, which has no
  row of its own — a `STG_ARURI64_R` probe is the fix; the other three legs keep the heal); the `sm120_ldsm8_mt1616` snapshot carries
  the three measured LDSM rows' form; and **the row probe's manual IMAD `-Ra` law at bit 72 (BUG-296) is withdrawn from the 12 IMAD HI
  rows** (blackwell-isa `37d030f`): the HI packet's bit 72 is not a negation — cubit's `native_hi` law and `tests/sm120_oracle_semantics.rs`
  (NVIDIA-confirmed inert) — so `IMAD.HI.U32.X R31, -R45, …` is refused again; the rows stay measured.
- **Docs hygiene after the week (T-17):** README's `sm120.json` row carries the live T1 count and the audit's end state (0 rows;
  the former `IMMA.SF` hypothesis is the measured `QMMA.SF` MXINT8 variant, T5) instead of the 2026-11-06 figures; KNOWN_ISSUES T1
  carries batch 16 and the 304-row inventory.

## Unreleased — 2026-11-07 (session T-16, gate 2: the T1 production line's run 5 — the tensor-core long tail verified row by row by session G)

- **Tables vendored from blackwell-isa `3dde6e1`** (sm120 1 231 forms / 39 125 variants, from 1 309 / 39 203; sm103a / sm100a /
  sm121a unchanged). KNOWN_ISSUES T1: **39 125 rows, 38 091 with `_src` — 1 034 harvest rows left** (1 376 at `3a94df3`).
  Session G's run-5 batch 15, re-measured by T-16 (`T/t16/review/b15`): all 28 288 distinct words of the fixture (the canonical word
  and the 109 single-bit flips of every row, their recorded texts or rejections, the 21 census witnesses) re-rendered identical with
  nvdisasm 13.1 on SM120 (on `-b SM103` / `SM100` the tensor words differ, as the five mnemonics do there); the whole production
  census (249 929 distinct words, among them 6 249 on the seven census-bearing tensor keys whose rows were rewritten) decodes to the
  same key, display text, lossless text and re-encode verdict before and after, 0 text differences vs nvdisasm on those 6 249; the
  batch's test fails 3 / 4 on the previous table and passes 4 / 4 on its own.
  - **The tensor-core long tail — QMMA / HMMA / OMMA / DMMA / IMMA — verified row by row** (G's `b1b332b`, taken as `1886972` by G's own
    `tools/probes/re_sm120_rows.py apply --family tensor` run on T's table — the tool reproduces G's commit byte for byte on G's base,
    and T's result is exactly T's base + G's delta; `tests/fixtures/sm120_rows_tensor_nvdisasm.jsonl`, `tests/sm120_rows_tensor.rs`,
    the shared body `tests/sm120_rows_common.inc`, `examples/text_keys.rs`): **a new method for the long tail** — per harvest row the
    canonical word and every single-bit flip of bits 0..104 / 122..125 are rendered by nvdisasm and diffed token by token against the
    canonical text; the row is measured (`rows-tensor-2026-11-07`, 264 rows) when every declared field bit moves exactly its own operand
    token, no undeclared bit moves an operand of the same form, cubit decodes the canonical word to the row with the vendor text and
    re-encodes it, and every census witness does too; `variable_mask` becomes exactly the field bits (fail closed on the text-inert
    bits); 149 undeclared fields the vendor names were added (`.reuse` on the B operand at bit 123 on 137 rows, the guard on 4 HMMA
    rows, `-Ra` 72 / `-Rb` 63 on 4 HMMA rows each); **78 shadowed twin keys are `_meta.key_aliases`** (73 byte-identical `_P_` twins of
    the plain `QMMA.SP` / `HMMA.SP` / `HMMA` / `DMMA` keys, the `_UP_II_?` / `_R_R_R_R_?` junk spellings, the dotted
    `HMMA.1684.F32.TF32_R_R_R_R` twin of `HMMA_R_R_R_R`'s group; 0 deletions, 0 census witnesses). Laws recorded: QMMA shape 75 /
    accumulator 77 / A type [79:78] + 83 / B type 79 + 85, `.SP` 80, the `UP` gate [89:87] printed inverted (`UP0` = 7) with `!` at 90,
    `.reuse` only on the B operand (122 / 124 are nvdisasm's "undefined opex value"); HMMA shape 75 (+ 78 = `INVALID3`), accumulator 76,
    BF16 82 / TF32 83, `.SP` 73; DMMA rounding [79:78], `|Ra|` 73 / `|Rb|` 62 / `|Rc|` 74 / `-Rc` 75; IMMA's `ROW` / `COL` glyph planes
    at 73 / 74. cubit: HMMA / DMMA / OMMA join IMMA / IDP off the priority-3 sign-tolerant decode fallback (HMMA's shape bit sits in the
    sign window — the `HMMA.INVALID3.F16.BF16` word decoded as the 1684 row); 30 rows have field flips the encoder refuses on the
    BUG-037 alignment law (text checked, refusal accepted on exactly those words). The 25 `INVALIDn`-keyed rows are verified as faithful
    glyph keys (keep or fail closed = the owner's, G's NEEDS 9 / T's NEEDS 41). Re-pinned on sm120: bug276 / bug280 / bug283 (the measured
    `QMMA.16816.F16.E4M3.E4M3` row fails closed on its text-inert bit 74; the BUG-280 reclaim stands on sm121a), era-keys 14 613 → 14 691.
  - **15 stale provenance legends re-counted** (blackwell-isa `3dde6e1`, found by T-16's merge check): the `_meta.provenance.sources`
    row counts of fifteen pre-2026-11 tags lagged the table since their rows were rewritten or retired (`dsv41-sm120-2026-10-22` 529 →
    516, `bug226d` 36 → 28, `bug226e` 17 → 4, `bug339` 9 → 0, …); the entries with 0 live rows stay as history. No row changes.
  - **The same hygiene on the other three tables** (blackwell-isa `b214b0e`, vendored as `124299b`): `sm103a.json` two LEA legends and
    `rows_total` 22 439 → 22 445 (the six MUFU packed-half rows of `8aa5f34` never updated it), `sm100a.json` the two LEA legends,
    `sm121a.json` `bug226d` 1 → 0; the revision pins `3dde6e1 → b214b0e`, no count changes.

## Unreleased — 2026-11-07 (session T-16: the T1 production line's run 4 — the 256-bit global load's U32 uniform-indexed form, the 256-bit global store and the global reduction's uniform-indexed forms measured whole by session G)

- **Tables vendored from blackwell-isa `3a94df3`** (sm120 1 309 forms / 39 203 variants, from 11 725 / 34 079; sm103a / sm100a /
  sm121a unchanged). KNOWN_ISSUES T1: **39 203 rows, 37 827 with `_src` — 1 376 harvest rows left** (11 789 at `5cb10e5`).
  Session G's run-4 batches 12–14, re-measured word by word by T-16 (`T/t16/review/b12` … `b14`: 4 969 + 2 233 + 9 392 fixture
  words identical on SM120, the same text on `-b SM103` / `SM100` except the five L2 = 3 lattice words of batch 12) with the census
  text-parity check widened to **the whole production census** — all 249 929 distinct words of the production cubins and our
  kernels decoded with each batch's engine and table before and after it: the same key, display text, lossless text and
  re-encode verdict for every word (0 changes per batch; the memory family — `LDG_R_dARI`, `STG_dARI_R`, `LD_R_dARI`, `REDG_dARI_R`,
  `LDS_R_ARURI`, `LDSM_R_ARURI`, `LDGSTS_ARI_dARI[_P]`, `STS_ARURI_R`, `ATOMS_*`, `ATOMG_P_R_dARI_R`, `SYNCS_*_ARURI_R`, … — 19 387 words on 18
  keys, 0 text differences vs nvdisasm 13.1); the census carries no word of the 10 428 retired keys or the 12 added ones. Each
  batch's test fails 5 / 5 on the previous table and passes 5 / 5 on its own (T's runs).
  - **LDG.256 ARURI measured whole** (G's `020ab68`, taken as `10b1a6a`; `tools/probes/re_sm120_ldg256.py --form ARURI`, 4 952
    form + 17 lattice words; `tests/fixtures/sm120_ldg256_aruri_nvdisasm.jsonl`, `tests/sm120_ldg256_aruri.rs`): the 256-bit global
    load (opcode 0x97e, frame bit 91) in its 32-bit uniform-indexed form `[Ra.U32+URb(+off)]` (bits 75 / 76 clear) — the four new
    plain keys `LDG_R_R_ARURI[_II][_P]` with 1 152 measured groups each (6 cache × 3 L2 × 4 LTC × the 16-value strength / scope /
    PRIVATE enum), provenance `ldg256-family-2026-11-07` (the legend 9 216 → 13 824: **the whole 0x97e opcode is measured on its
    twelve plain keys**); **the 3 120 dotted one-group harvest keys of the form are `_meta.key_aliases`** of the plain key of their
    signature (11 of their rows carried `wave11-integration-2026-11-05` — reproduced, that legend 36 → 25; 5 carried a `claim_forbid`,
    10 833 → 10 828: RZ is a legal elided base). Law = batches 10–11's with bits 75 / 76 clear; RZ elides to `[URb(+off)]` — the
    `.64` twin's text, so the lossless print spells `[RZ.U32+URb(+off)]` (re-encodes the U32 word) and the bare spelling mints the
    `.64` word (BUG-464 / 474). Printer only: the plain keys on the BUG-474 `plain_u32` arm. Re-pinned on sm120: bug474 (8 heal words
    with bit 92 fail closed; **5 `b86-zone` anchor drills — `LDG.E.EU.EFL2.256`, `LDG.E.NA.EFL2.256` bare / `0x99` / `LTC128B`,
    `LDG.E.NA.ELL2.256` on `[R28.U32+UR38]` — are legal words the vendor names on the three targets, HOLE lifted**), bug468 graft
    census 16 → 0, claim_forbid census in bug459a / 461 / 462 / 463 / 476, era-keys 4 185 → 7 305.
  - **STG.256 measured whole** (G's `722e69e`, taken as `3216477`; `tools/probes/re_sm120_stg256.py`, 2 140 form + 93 lattice
    words — **the same text on the three targets for every word**; `tests/fixtures/sm120_stg256_nvdisasm.jsonl`,
    `tests/sm120_stg256.rs`): the 256-bit global store (opcode 0x97f, frame bit 91) in its three address forms — the six new plain
    keys `STG_{dARI,ARURI,ARURI64}_R_R[_II]` with 288 measured groups each (6 cache × 3 L2 × the store's 16-value enum), provenance
    `stg256-family-2026-11-07` (1 728 rows); **the 1 164 dotted one-group harvest keys of the opcode are `_meta.key_aliases`** (4
    wave11 rows reproduced, that legend 25 → 21). Law: Rs1 [23:16], Ra [31:24] (RZ illegal on the descriptor form → `claim_forbid`,
    elided on the uniform-indexed forms), Rs0 [39:32], **a signed 19-bit 32-byte-unit offset [58:40]** (the load's is 17 bits),
    **the trailing byte split [63:59] + [90:88]** (elided at 0xff; `imm@59:5` + `imm_shr5@88:3` on the `_II` keys), URb [71:64],
    75 / 76 the address form, **the store's own enum [80:77] — STRONG.SM.PRIVATE at 4, SYS.ORDERED / STRONG.SYS.ORDERED /
    MMIO.SYS.ORDERED at 13–15** (the load has CONSTANT / CONSTANT.VC / .VC.PRIVATE / .GPU there), L2 [82:81], cache [86:84]; no LTC
    width and no trailing predicate — [74:72], 83, 87, [95:92] text-inert, fail closed. Printer only: the plain store keys on the
    ARURI64 / U32 arms, **`ORDERED` in the LDG / STG modifier rank after the scope** (the generic rank printed
    `STG.E.NA.EFL2.ORDERED.256.MMIO.SYS`). Re-pinned on sm120 (the STG half of the 2026-09 EFL2.256 waves): the inert-bit cells 72 /
    73 / 74 / 87 / 94 fail closed (bug446 / 447 / 453 / 463 / 464 / 466 / 474 / 475 / 476), bug448 (the bare `[UR38]` store spelling
    mints `.64`), bug452 inventory 1 → 0, bug465 (the STG half of the graft on the plain keys; `_src465` 382 → 0), **bug466
    `STG.E.NA.ELL2.256.STRONG.GPU desc[UR4][R5.64], R8, R12` is legal — the store's refusal lifted like the load's**, **bug474's
    three store `b86-zone` drills legal, HOLE lifted**, bug475 (`STG_dARI_R_R` is the measured plain key), claim_forbid 10 828 →
    11 013 (+576 measured descriptor rows with the RZ exclusion, −391 retired), era-keys 7 305 → 8 469.
  - **REDG uniform-indexed forms measured whole** (G's `13ff289`, taken as `3a94df3`; `tools/probes/re_sm120_redg.py`, 9 334 form +
    58 lattice words — the same text on the three targets for every word; `tests/fixtures/sm120_redg_aruri_nvdisasm.jsonl`,
    `tests/sm120_redg_aruri.rs`): the global reduction (opcode 0x98e, bit 91 = the uniform-indexed form, bit 90 = the base width) —
    the two new plain keys `REDG_ARURI_R` (6 144 groups = 2 `.E` × 8 ops × 4 types × 6 cache × 16 scope; **the no-`.E` plane of the
    U32 form is legal, 3 072 groups the harvest never saw**) and `REDG_ARURI64_R` (3 072 groups — **the `.64` base needs `.E`; without
    it the vendor prints the `REDG.???0.<op>` glyph plane**), provenance `redg-aruri-family-2026-11-07` (9 216 rows); **the 6 144
    dotted one-group harvest keys are `_meta.key_aliases`** (0 census witnesses; the census REDG words are the descriptor form's,
    `REDG_dARI_R`, untouched). Law: [23:16] text-inert (the atomic's destination slot), Ra [31:24] (RZ prints `[RZ.U32+URb]` on U32
    and the `???255` glyph on `.64` — printed, never minted, BUG-461), Rb [39:32], a signed 24-bit byte offset [63:40], URb [71:64],
    `.E` 72, type [75:73], the load's enum [80:77], cache [86:84], op [89:87]; 76, 82, 83, [95:92] inert, fail closed. cubit: the
    printer arms for the two keys and **two key-scoped engine guards** — the decoder's broad match (which frees the standard register
    slots for memory keys with narrow harvest masks) is off for exactly `REDG_ARURI_R` / `REDG_ARURI64_R` (their only slot without a
    field is the inert [23:16]; measured rows fail closed on it), and the encoder refuses a `.64` uniform-indexed text whose
    mnemonic has a measured plain `_ARURI64` key (LDG.256, STG.256, REDG — the only ones) but no row for the text's modifier group,
    instead of minting the U32 twin (`REDG.ADD.EL.STRONG.GPU [R2.64+UR4], R6` minted the U32 word before); the ordinary `LDG.E.64 …
    [R.64+UR]` chain and the ATOMG `.EL` pair are untouched. Verified by T-16: the 99 production sources byte-identical in `.text`,
    the frozen census 157 / 157, the strict census 1 811 600 / 1 811 600, every census word's key / text / re-encode unchanged.
    Re-pinned on sm120: bug452 / bug461 (the 3 072 dotted `.64` keys → the one plain key), era-keys 8 469 → 14 613.
  - Base shifts handled by T-16 as the exact three-way merge: G's three commits cherry-picked (`-x`) onto the NEEDS 48 tip, every
    revision pin re-pointed to T's blackwell-isa commit and T-14's sm103a pins kept (`T/t16/reapply.py`; T's tables == G's bytes
    at every step, the engine == G's `ab2900e`).
- **BUG-487 — `_meta.key_aliases` deep-copied their target's whole group map; the alias now shares it** (`cubit::table::ModGroups`,
  an `Arc` behind `InsKeyEntry::mod_groups`; `tests/bug487_alias_shared_groups.rs`). Found by T-16's gate on the batch-14 table: with
  14 613 aliases whose targets carry up to 6 144 groups the loader materialised **36 804 246 cloned rows for 39 203 real ones** —
  `cubit decode` of one word took **21 GB and 8.5 s** (3.9 GB / 1.9 s at `5cb10e5`; the growth since the first aliases of 2026-11-04),
  every test binary 40–55 GB, and `tools/test_suite.py -j 16` drove the build host out of memory (the production worker was
  OOM-killed at 18:59Z — T-16's incident, logged). Fixed: the same `cubit decode` is **0.56 GB / 0.7 s** on the batch-14 table
  (0.54 GB on `5cb10e5`'s), the heaviest test binary 2.0 GB; the alias contract is unchanged (present in `entries`, `encode_only`,
  the target's rows by name and value; copy-on-write through `ModGroups::make_mut` for the tests that poison rows) and
  `num_groups()` counts each shared map once (it summed the alias copies before). The push gate measures `cubit decode`'s peak RSS
  and caps every test process (`ulimit -v`) before any parallel run.

## Unreleased — 2026-11-07 (session T-15: the T1 production line's run 3 / 4 — the 256-bit global load's 64-bit uniform-indexed address form measured whole by session G)

- **Tables vendored from blackwell-isa `5cb10e5`** (sm120 11 725 forms / 34 079 variants, from 14 805 / 32 555; sm103a / sm100a /
  sm121a unchanged). KNOWN_ISSUES T1: **34 079 rows, 22 290 with `_src` — 11 789 harvest rows left** (14 865 at `8aa5f34`).
  Session G's run-3 batch 11 (measured by G run 3, committed and announced by G run 4), re-measured word by word by T-15
  (`T/t15/review/b11`) with the full census text-parity check: the whole production LDG / STG / LD / `ARURI` witness set — 13
  keys, **18 346 / 18 346 words** (`LDS_R_ARURI` 5 857, `LDG_R_dARI` 4 372, `STG_dARI_R` 3 381, `LDSM_R_ARURI` 1 648, …) — prints
  nvdisasm 13.1's text with the new table and G's printer, 0 undecoded, 0 re-encode failures; the census carries no word of the
  touched keys themselves (0 witnesses on all 3 088).
  - **LDG.256 ARURI64 measured whole** (G's `af3329f`, taken as `5cb10e5`; `tools/probes/re_sm120_ldg256.py --form ARURI64`, 4 952
    form + 17 lattice words — the same text on `-b SM103` / `SM100` for every form word, the L2 = 3 lattice plane `INVALID3` there
    as in batch 10; `tests/fixtures/sm120_ldg256_aruri64_nvdisasm.jsonl`, `tests/sm120_ldg256_aruri64.rs`): the 256-bit global
    load (opcode 0x97e, frame bit 91) in its 64-bit uniform-indexed address form `[Ra.64+URb(+off)]` (bit 75 = `.64`, bit 76
    clear) — the four new plain keys `LDG_R_R_ARURI64[_II][_P]` carry 1 152 measured groups each (6 cache × 3 L2 × 4 LTC × the
    16-value strength / scope / PRIVATE enum), provenance `ldg256-family-2026-11-07` (the legend 4 608 → 9 216); **the 3 084
    dotted one-group harvest keys of the form are `_meta.key_aliases` of the plain key of their operand signature** (every one
    names a group of its target; 8 of their rows carried coldface's `wave11-integration-2026-11-05` tag — reproduced by the
    measured rows, that legend 44 → 36; 0 census witnesses). Law = batch 10's with bit 76 clear: guard [15:12], Rd1 [23:16], Ra
    [31:24] — **RZ legal and elided (`[URb(+off)]`, the U32 twin's text)**, URb [39:32] (255 = `URZ`, printed), the signed 17-bit
    offset in 32-byte units [56:40], the trailing byte [63:57] + 72 elided at 0xff (the `_II` keys), Rd0 [71:64], LTC [74:73],
    the strength / scope / PRIVATE enum [80:77], L2 [82:81], cache [86:84], the trailing predicate [90:87] (`pred_inv4`, the `_P`
    keys); bit 83 and [95:92] text-inert, fail-closed; no `claim_forbid` (every base is legal). Printer only (2 hunks): the plain
    keys print the `[Ra.64+URb(+off)]` arm; **BUG-464's rule widened to the whole 256-bit family — the bare `[URm(+off)]`
    spelling of the NA family mints the `.64` word** now that every group has a measured `.64` twin (the lossless print keeps
    `[RZ.U32+URm(+off)]` for the U32 word, so it re-encodes bit-exact; the census round trip is unchanged). Re-pinned on sm120:
    bug448 (the new mint), bug461 / 463 heal words with bits 83 / 92–95 fail closed, **bug464 `.C3.ldg_b86` (`LDG.E.NA.EFL2.256
    …, 0x99`) is a legal word the vendor names — HOLE lifted**, bug465 (the LDG half of the graft lives on the plain keys' groups;
    the STG half stays until STG.256), bug468 graft census 2 320 → 16, claim_forbid rows 10 837 → 10 833, era-keys 1 101 → 4 185.

## Unreleased — 2026-11-07 (session T-14, gated and pushed by T-15: the T1 production line's run 3 — the 256-bit global load's descriptor form measured whole by session G; the sm103a MUFU packed-half lanes measured by T on the B300; NEEDS 46 measured)

- **Tables vendored from blackwell-isa `8aa5f34`** (sm120 14 805 forms / 32 555 variants, from 15 583 / 28 729; sm103a
  14 926 forms / 22 445 variants, from 14 925 / 22 439; sm100a / sm121a unchanged). KNOWN_ISSUES T1: **32 555 rows, 17 690 with
  `_src` — 14 865 harvest rows left** (15 647 at `94ff281`). Session G's run-3 batch 10, re-measured word by word by T
  (`T/t14/review/b10`) with, new for this run, the **full census text-parity check**: every one of the 249 929 distinct
  words of the production census + our kernels is decoded with the old and the new table, and every word of a touched key
  (all of them, not a sample) is compared with nvdisasm 13.1's text — the whole production LDG / STG / LD witness
  set, 8 020 / 8 020 words print the vendor's text with the new table and the new printer rank.
  - **LDG.256 dARI measured whole** (G's `348535f`; `tools/probes/re_sm120_ldg256.py --form dari`, 4 888 form + 81 lattice
    words — the same text on `-b SM103` / `SM100` for every form word, the L2 = 3 plane prints `INVALID3` there against
    SM120's `RML2.???` glyphs (lattice either way); `tests/fixtures/sm120_ldg256_dari_nvdisasm.jsonl`, `tests/sm120_ldg256_dari.rs`):
    the 256-bit global load (opcode 0x97e, frame bit 91) in its descriptor address form `desc[URb][Ra.64(+off)]` — the four
    plain keys `LDG_R_R_dARI[_II][_P]` carry 1 152 measured groups each (6 cache × 3 L2 × 4 LTC × the 16-value strength /
    scope / PRIVATE enum; 4 607 groups added), provenance `ldg256-family-2026-11-07`; **the 781 dotted one-group harvest
    keys of the form are `_meta.key_aliases` of the plain key of their operand signature** (every one names a group of its
    target; 0 census witnesses). Law: guard [15:12], Rd1 [23:16], Ra [31:24] (RZ illegal → `claim_forbid`), URb [39:32], the
    signed 17-bit offset in 32-byte units [56:40], the trailing byte [63:57] + 72 elided at 0xff (the `_II` keys), Rd0
    [71:64], LTC [74:73], bits 75 / 76 = base width + descriptor, the strength / scope / PRIVATE enum [80:77], L2 [82:81],
    cache [86:84] (EF / none / EL / LU / EU / NA), the trailing predicate [90:87] (`pred_inv4`, PT elided: the `_P` keys);
    bit 83 and [95:92] text-inert, fail-closed. Printer: the LDG / STG modifier rank gains the LTC widths (after the L2 hint,
    before the size), MMIO (the STRONG / CONSTANT slot), VC (a scope) and LU (the cache slot) — 2 590 of the 4 888 words
    printed out of order before. Re-pinned on sm120: the claim_forbid census 7 011 → 10 837, bug466's "legacy desc-form"
    refusal lifted for `LDG.E.NA.ELL2.256.STRONG.GPU desc[..]` (a legal word the vendor names), the heal words of
    bug453 / 463 / 475 with the text-inert bits 92–95 fail closed, era-keys 320 → 1 101.
- **The sm103a MUFU packed-half lanes measured** (blackwell-isa `8aa5f34`; `tools/probes/re_sm103_mufu_x2.py`, run on the
  B300 host with **nvdisasm 13.3.73** on `-b SM103` — 13.0.85 and 13.1 print the same text for every one of the 384 lattice +
  674 single-bit sweep + 281 fixture words; `tests/fixtures/sm103a_mufu_x2_nvdisasm.jsonl` (108 form + 173 lattice words),
  `tests/sm103a_mufu_x2.rs`): `MUFU.EX2.BF16x2` / `MUFU.EX2.F16x2 Rd, [-|]Ra[|] | [-|]URa[|] | imm_hi, imm_lo` — `.BF16x2` =
  bit 80 with the half code 0, `.F16x2` = the half code 3 ([73:72]); **EX2 is the only function the packed lanes admit** (the
  other 15 values print `INVALIDn`, unclaimed); the immediate form carries two halves, hi [63:48] printed first and lo
  [47:32], as bf16 / f16 literals; bit 60 (`.H1` of the scalar half lanes) is text-inert in the lanes; bit 80 with a half
  code and half 3 with bit 80 are illegal. On `-b SM120` / `SM100` bit 80 is text-inert and half 3 illegal, so the rows live
  on sm103a only: the groups `BF16x2,EX2` / `EX2,F16x2` on `MUFU_R_R` and `MUFU_R_UR` and the new key `MUFU_R_FI_FI` (the
  HMUL2 / HADD2 packed-immediate convention), provenance `mufu-x2-sm103a-2026-11-07` (6 rows). No code change: every form
  word decodes to its measured row (which wins the decoder's unexplained-variance tiebreak over the harvest `EX2` row whose
  mask lets bit 80 float), prints the vendor's text — the lossless print spells a NaN half's payload as a hex literal
  (A8) — and re-encodes bit for bit; sm120 / sm100a decode none of the lane words. The scalar sm103a MUFU harvest rows are
  the family proper (`re_sm120_conv.py --arch SM103`), a later batch. Silicon not measured (the B300 was busy); no compiler
  word of the B300 corpora (2 145 cubins, 149 934 sm_100 / sm_103 MUFU words) uses either lane. The sm103a census pins
  re-pinned (`bug381` pins the two sparse legs separately now).
- **NEEDS 46 measured, not decided** (T-14 on the B300, nvdisasm 13.3.73 + 13.0.85; `T/NEEDS_OWNER.md` 46): the 64-bit ISETP
  compare (bit 80, `.S64` / `.U64`) is SM120-only in every nvdisasm 13.x build — on `-b SM103` / `SM100` bit 80 is text-inert
  (0 of the 2 136 ISETP sweep words carry the suffix there). The four sm103a / sm100a harvest `S64` / `U64` groups
  (`ISETP_P_P_R_UR_P`: AND,GE,U64 / AND,GT,U64 / AND,NE,S64 / NE,OR,S64, identical on both tables) are text phantoms —
  their canonical words print `.U32` compares or are illegal on every target — and no ISETP word of 2 145 corpus cubins
  (1 347 282 sm_100 + 688 446 sm_103 + 43 886 sm_120 ISETP words) sets bit 80. Whether sm_103a silicon compares 64 bits
  with the bit is a 2-second probe when the B300 is idle; the groups stay until the owner / G run 3 decide.

## Unreleased — 2026-11-07 (session T-13: the T1 production line's batches 5–9 — UFSETP, the FP32 ALU, its uniform twin, the conversions and FSET / FSEL / FCHK measured whole by session G; NEEDS 44 closed on silicon — the QMMA.SF opcode-bit-2 variant is MXINT8 × MXINT8; R1 at zero lints; R2's Polish headers gone)

- **Tables vendored from blackwell-isa `94ff281`** (sm120 15 583 forms / 28 729 variants, from 15 807 / 26 581; sm103a /
  sm100a / sm121a unchanged). KNOWN_ISSUES T1: **28 729 rows, 13 082 with `_src` — 15 647 harvest rows left** (16 156 at
  `dac48ad`). Session G's batches 7, 8 and 9, re-measured word by word by T and re-applied on T's table (G's commits were
  stacked on batch 6; each probe's `apply` on T's table is byte-identical to G's table plus the NEEDS 44 rename):
  - **Uniform FP32 ALU measured whole — UFADD / UFMUL / UFFMA / UFSEL** (`tools/probes/re_sm120_ufp32_alu.py`, 1 025 form +
    30 glyph + 278 lattice + 4 neighbour words; `tests/fixtures/sm120_ufp32_alu_nvdisasm.jsonl`, `tests/sm120_ufp32_alu.rs`):
    444 rows on the 9 plain keys `UFADD_UR_UR_{UR,FI}` (0x254 / 0x454 + 91; **URb in the C slot [71:64]**), `UFMUL_UR_UR_{UR,FI}`
    (0x256 / 0x856 + 91), `UFFMA_UR_UR_UR_UR` / `_UR_FI` / `_FI_UR` (0x255 / 0x455 / 0x855 + 91), `UFSEL_UR_UR_{UR,FI}_UP`
    (0x251 / 0x851 + 91) — 441 with `ufp32-alu-family-2026-11-07`, 3 dsv41 rows reproduced field for field and kept with their
    tag; 143 harvest rows rewritten (T-10's `UFMUL_UR_UR_UR` row lacked the sign fields — its legend count follows, 25 → 24)
    and **298 missing groups added** (`UFMUL_UR_UR_UR` had 1 of 168, `UFADD_UR_UR_UR` 1 of 16, `UFFMA_UR_UR_UR_UR` 1 of 24);
    9 junk keys retired as aliases (the `_II` / `_L` / `_?` spellings → the f32 key; the hexadecimal f32 literal still
    assembles through them). **The family is SM120-only: every one of the 1 337 sweep words is illegal on `-b SM103` /
    `SM100`** (like UFSETP; the sm103a / sm100a tables carry none of the four mnemonics). Law = the FP32 ALU law in the uniform
    datapath (guard `@[!]UPn`; URa `-` 72 / `|` 73; B [39:32] `|` 62 / `-` 63 or f32 [63:32]; the C slot `|` 74 / `-` 75; the
    FADD / FMUL / FFMA modifiers as on the vector family; UFSEL `[.FTZ]` + UPc [89:87] / `!` 90 with `UPT` spelled); no
    `.reuse`; bit 81 on the register forms of UFADD / UFFMA = `UFHADD` / `UFHFMA` (neighbours, no key anywhere). Decoder: the
    four mnemonics on the priority-3 fail-closed list; printer: the FP32 order arm covers the uniform twins
    (`UFMUL.FTZ.D2.RM.SAT`; 442 words printed `.SAT` first before).
  - **Conversions measured whole — F2I / I2F / FRND / MUFU** (`tools/probes/re_sm120_conv.py`, 2 494 form + 18 glyph + 547
    lattice words; `-b SM100` identical, `-b SM103` differs on 6 MUFU words — the B300 packed-half lanes `.F16x2` / `.BF16x2`,
    text-inert / illegal on SM120 and SM100; `tests/fixtures/sm120_conv_nvdisasm.jsonl`, `tests/sm120_conv.rs`): 2 030 rows on
    the 12 plain keys `F2I_R_{R,UR,FI}` (0x305 / 0x311), `I2F_R_{R,UR,II}` (0x306 / 0x312), `FRND_R_{R,UR,FI}` (0x307 / 0x313),
    `MUFU_R_{R,UR,FI}` (0x308) — 2 020 with `conv-family-2026-11-07`, 10 of T-4's `MUFU_R_UR` rows kept with their tag (the 16
    `.F16` / `.BF16` rows gain the `.H1` selector); 130 harvest rows rewritten and **1 890 missing groups added** (the F2I
    lattice is 512 per form; four keys are new: `F2I_R_FI`, `I2F_R_II`, `FRND_R_UR`, `FRND_R_FI`); **213 junk keys retired as
    aliases — the 207 dotted F2I keys** (`F2I.FTZ.U32.TRUNC.NTZ_R_R` had 190 census words; they decode on `F2I_R_R` and print
    the vendor's text), `I2F.RP_R_R`, four dotted FRND keys, `MUFU_R_II` → `_FI`; the 2026-09 bug-wave legends (bug380 / 390 /
    403) follow their live count 0. Law: two opcodes per conversion × R / UR (+0xc00, bit 91) / imm (+0x800); F2I dst width
    [76:75] + signed 72, src [86:84], NTZ 77, rounding [79:78], FTZ 80 → `F2I[.FTZ][.dst][.src][.rnd][.NTZ]`; I2F dst [77:75],
    src width [85:84] + signed 74, `.B1..B3` [61:60] / `.H1` 60 on the 8- / 16-bit sources, the immediate signed for S-types;
    FRND type [77:75] = [86:84] → `FRND[.FTZ][.type][.rnd]`; MUFU fn [77:74], half [73:72]; **the F16 / BF16 sources of F2I /
    FRND / MUFU take `.H1` at bit 60 too, composed inside the sign pipes (`-|R2.H1|`)**; no `.reuse` (text-inert); the `???n` /
    `INVALIDn` states fail closed. **F2F excluded** (its type pair is order-significant — `G/NEEDS_OWNER.md` 3). Doctrine, as
    on every measured family: the 2026-09 F2I pins (bug339 / 341 / 361 / 362 / 363 / 379-380 / 390 / 403) expected the
    text-inert bits 73 / 74 to decode as aliases; the measured sm120 rows fail closed on them (0 census words carry the bits;
    the other three legs unchanged) — those tests are re-pinned on the sm120 leg, bug308 / bug341's signed F2I mints are legal
    now, bug226d's `-QNAN` is the lossless hex. Decoder: I2F / FRND on the priority-3 fail-closed list; printer: the FRND
    `[.FTZ][.type][.rnd]` order, the BUG-125 key-scoped `F2I_R_FI` arm folded into the BUG-361 mnemonic law, `.B<n>` / `.H1`
    rendered on UR operands, `.H1` inside the sign pipes, the I2F immediate signed / unsigned by type; parser: FRND's float
    immediate; encoder: the suffix scrape accepts `|R2.H1|`.
  - **FSET / FSEL / FCHK measured whole** (`tools/probes/re_sm120_fset_fsel_fchk.py`, 885 form + 15 glyph + 375 lattice
    words, the same text on the three targets; `tests/fixtures/sm120_fset_fsel_fchk_nvdisasm.jsonl`,
    `tests/sm120_fset_fsel_fchk.rs`): 297 rows with `fset-fsel-fchk-family-2026-11-07` on the 9 plain keys `FSET_R_R_{R,FI,UR}_P`
    (0x20a / 0x80a / 0xc0a + 91; `_FI_P` / `_UR_P` are new keys), `FSEL_R_R_{R,FI,UR}_P` (0x208 / 0x808 / 0xc08 + 91), `FCHK_P_R_{R,FI,UR}`
    (0x302 / 0x902 / 0xd02 + 91) — 102 rows rewritten in place (the 2026-10-22 FSET mode grid, the FSEL / FCHK harvest rows,
    three of the four bug249 FSEL rows with the same fields; that legend 4 → 1) and **195 groups added**; 8 junk keys retired as
    aliases (`FSET.BF.F.AND_R_R_R_P`, six FSEL tokenisations, `FCHK_P_R_II` → `_FI`); **`FSEL_R_R_II_P` kept** — the BUG-178 /
    BUG-249 canonical `+QNAN` lane, measured by that wave. Law: FSET = the FSETP law with a register destination (bool
    [75:74], cmp [79:76], FTZ 80, Pc [89:87] / `!` 90; **`.BF` on every word** → `FSET.BF.<cmp>[.FTZ].<bool>`), FSEL `[.FTZ]` + Pc
    (PT spelled), FCHK Pd [83:81] with no modifier and no `.reuse` (text-inert); `-Ra` 72 / `|Ra|` 73 / reuse 122, `|B|` 62 /
    `-B` 63 / Rb reuse 123 or f32 [63:32]. Decoder: the three mnemonics on the priority-3 fail-closed list; printer: the
    `FSET.BF.<cmp>[.FTZ].<bool>` order (115 words printed `FSET.NEU.FTZ.BF.XOR` before); parser: FCHK's immediate is a float
    (`FCHK P0, R2, 1` encoded the integer 1 before). Re-pinned by G: bug249 / bug265, the `claim_forbid` census 7 012 → 7 011 in
    bug459a / 461 / 462 / 463 / 476 (the junk `FCHK_P_R_UR` row carried a `claim_forbid` on the opcode nibble; the measured
    row pins the whole opcode).
- **Tables vendored from blackwell-isa `dac48ad`** (sm120 15 807 forms / 26 581 variants, from 15 834 / 26 341; sm103a /
  sm100a / sm121a unchanged). KNOWN_ISSUES T1: **26 581 rows, 10 425 with `_src` — 16 156 harvest rows left** (16 612 at
  `63e5040`). Session G's batch 6 and T-13's NEEDS 44 closure:
  - **FP32 ALU measured whole — FADD / FMUL / FFMA / FMNMX** (G's `dad8393`; `tools/probes/re_sm120_fp32_alu.py`, 1 636 form
    + 30 glyph + 492 lattice + 16 neighbour words, the same text on `-b SM120` / `SM103` / `SM100`;
    `tests/fixtures/sm120_fp32_alu_nvdisasm.jsonl`, `tests/sm120_fp32_alu.rs`; re-measured word by word by T): 696 rows
    with `fp32-alu-family-2026-11-07` on the 14 plain keys `FADD_R_R_{R,FI,UR}`, `FMUL_R_R_{R,FI,UR}`, `FFMA_R_R_R_R` /
    `_R_R_R_FI` / `_R_R_FI_R` / `_R_R_UR_R` / `_R_R_R_UR`, `FMNMX_R_R_{R,FI,UR}_P` — 355 harvest rows rewritten in place
    (`FADD_R_R_R` baked a sample's guard and claimed the unused reuse bit 123; the `|Rb|` 62 field was missing) and **341
    missing groups added** (`FMUL_R_R_FI` / `_UR` had 3 of 168 groups, `FADD_R_R_R` 5 of 16); 27 junk keys retired as
    `_meta.key_aliases` (the `_?` / `_L` / `_R_R_R_R` mis-tokenised harvest keys, the dotted twins with the modifier in
    the key — `FADD.RZ_R_R_R`'s row decoded the `.RM` word as `.RZ` —, the integer-spelling `*_II*` twins of the f32
    forms: the 185 census words of `FMUL_R_R_II` decode on `FMUL_R_R_FI` now and still print nvdisasm's text — checked
    by T on 733 sampled census words of the 14 keys). Law: Ra [31:24] (`-` 72, `|` 73, `.reuse` 122); B [39:32] (Rb /
    URb, `|` 62, `-` 63) or f32 [63:32]; the C slot [71:64] (FFMA Rc with `|` 74 / `-` 75; text-inert on the
    three-operand forms); FADD `[.FTZ][.RM|.RP|.RZ][.SAT]` (80 / [79:78] / 77); FMUL `[.FTZ|.FMZ][.D8…M8][.RND][.SAT]`
    (scale [86:84]: 4 = unspelled, 0 = `INVALID0`, FTZ + FMZ = `INVALID3`); FFMA the same without the scale; FMNMX
    `[.FTZ][.NAN][.XORSIGN]` + Pc [89:87] / `!` 90; `.reuse` per form (FADD Rb = 124; FFMA by slot). Measured and left
    unclaimed: bit 81 on the register / UR forms of FADD / FFMA = `FHADD` / `FHFMA`, bit 65 on FMNMX = `FMNMX.IS_A Rd, Pd,
    Ra, Rb, Pc`. Decoder: the four mnemonics off the priority-3 sign-tolerant fallback (it absorbed the text-inert C-slot
    sign bit 74); printer: `FMUL.FTZ.D2.RM.SAT` / `FFMA.RM.SAT` / `FADD.FTZ.RP.SAT` order (751 of the form words printed
    `FMUL.SAT.D2` before). bug132 / bug226c re-pinned to the measured grid.
  - **NEEDS 44 closed on silicon: the QMMA.SF opcode-bit-2 variant (0x47e) is the block-scaled MMA over MXINT8 × MXINT8**
    (T-13's `dac48ad`; test host GPU 0, RTX PRO 6000 Blackwell SE, kernel `needs44_types` with the five documented
    diagonal type pairs and the 0x47e word on identical fragments): byte-value sweeps of A and of B against three
    references give 32 · (int8(a)/64) · (int8(b)/64) exactly for all 6 × 256 cases — OCP MX INT8 elements
    (two's-complement int8 with six fractional bits, range [−2, 1.984375], under the E8M0 block scale), fp32 output; one-hot
    bytes light one D row (A) / one D column (B) exactly as `E4M3.E4M3` does (the m16n8k32 8-bit fragment layout); a byte
    is one element; D · 2^(s−127) for every scale with NaN at 0xff. The row is
    `QMMA.SF.16832.F32.MXINT8.MXINT8.E8_R_R_R_R_R_R_UR`, the hypothesis key and the interim `UNIDENTIFIED` key its aliases,
    provenance `qmma-sf-mxint8-silicon-2026-11-07`; `tests/fixtures/sm120_qmma_sf_mxint8_silicon.jsonl` (the measured
    sweeps) and `tests/needs44_qmma_sf_bit2.rs` (6 pins incl. the MXINT8 law on the 1 536 measured values). Side result
    from the same run: the documented `E2M1` type code computes exactly the E2M3 map on bits [5:0] of the container for
    every byte value (PTX puts `.e2m1` in bits [5:2]; the silicon does not mask bits [1:0]) — the rows are correctly
    named; R's 2026-11-06 `E2M1.E2M1` results were unpadded inputs. Not measured: the type-field lattice under bit 2.
- **R1 closed — `cargo clippy --release --all-targets` at 0 warnings**: the 84 hand lints left after T-11's mechanical
  pass (21 `get(k).is_some()` → `contains_key`, 13 hex-literal regroupings, 9 unused test helpers deleted, 10 documentary
  constants kept under an explicit `#[allow(dead_code)]`, the generated witness tables under
  `#[allow(clippy::type_complexity)]`, seven `TABLES` index loops as `enumerate`, bug444's two identical heal arms
  merged, a handful of one-offs) and the printer's `#[cfg(test)]` module moved to the end of the file (a pure reorder).
- **R2**: the nine remaining Polish `//!` headers translated (bug168, bug169, bug170, bug194, bug459a, bug464, bug465,
  bug467, bug476; doc comments only). A wider census afterwards: 11 files still carry two or more Polish lines inside
  otherwise English headers (listed in KNOWN_ISSUES R2).
- **Tables vendored from blackwell-isa `63e5040`** (sm120 15 834 forms / 26 341 variants, from 15 840 / 26 442; sm103a /
  sm100a / sm121a unchanged). KNOWN_ISSUES T1: **26 341 rows, 9 729 with `_src` — 16 612 harvest rows left** (16 905 at
  `e1e8598`). Session G's batch 5, re-measured word by word by T before the take:
  - **UFSETP measured whole** (`tools/probes/re_sm120_ufsetp.py`, 394 form + 6 glyph + 66 lattice words;
    `tests/fixtures/sm120_ufsetp_nvdisasm.jsonl`, `tests/sm120_ufsetp.rs`): the 96 + 96 "mode grid" rows of
    `UFSETP_UP_UP_UR_UR_UP` (0x253 + 91) / `UFSETP_UP_UP_UR_FI_UP` (0x853 + 91) of 2026-10-22 were field-correct and are
    re-emitted from the measurement with provenance `ufsetp-family-2026-11-06`. **The family is SM120-only: nvdisasm 13.1
    rejects every one of the 466 sweep words on `-b SM103` / `SM100`** (the sm103a / sm100a tables have no UFSETP key).
    Six keys retired as `_meta.key_aliases` (0 census witnesses): the encode-only integer-spelling twin
    `UFSETP_UP_UP_UR_II_UP` → `_FI_UP` (the hexadecimal f32 literal still assembles through the alias) and five dotted
    harvest samples with a baked guard and predicates (`UFSETP.GT.AND_UP_UP_UR_UR_UP`, `UFSETP.NEU.{AND,OR}_UP_UP_UR_UR_UP`,
    `UFSETP.NEU.AND_UP_UP_UR_{FI,II}_UP`). Law = FSETP in the uniform datapath: guard [15:12] (`@[!]UPn`); URa [31:24],
    `-URa` 72, `|URa|` 73; URb [39:32] with `|URb|` 62, `-URb` 63, or the f32 immediate at [63:32]; the boolean [75:74]
    (3 = `INVALID3`); the comparison [79:76]; `.FTZ` 80; UPd0 [83:81]; UPd1 [86:84]; UPc [89:87] + `!` 90; bit 91 set
    (clear = illegal); no `.reuse` (nvdisasm rejects the reuse bits on the uniform opclass); [23:16], the unused part of
    [71:40] and [95:92] text-inert (fail-closed). Decoder: UFSETP joins FSETP off the priority-3 sign-tolerant fallback
    (`UFSETP.GT.INVALID3` used to print as `.XOR`); printer: `UFSETP.F.FTZ.AND` / `UFSETP.T.FTZ.OR` order (the constant
    comparisons precede FTZ, as on FSETP).

## Unreleased — 2026-11-06/07 (session T-12: the T1 production line's first two batches — HSETP2 and ISETP / UISETP measured whole by session G; the suite in 2 minutes (R3); the template rebuild checks its positional metadata (A5); EiFmt named after cuobjdump (A7); NaN payloads on every immediate lane (A8))

- **Tables vendored from blackwell-isa `6dff9c7`** (sm120 15 961 forms / 26 662 variants, from 15 964 / 26 598; sm103a /
  sm100a / sm121a unchanged). KNOWN_ISSUES T1: **26 662 rows, 9 101 with `_src` — 17 561 harvest rows left** (18 841 at
  `78285f5`). Both batches are session G's (the T1 production line: G measures, T reviews, gates and pushes); each word of
  their fixtures was re-measured by T with nvdisasm 13.1 on `-b SM120` / `SM103` / `SM100` before the take.
  - **HSETP2 measured whole** (`tools/probes/re_sm120_hsetp2.py`, 1 002 form + 88 lattice words, the same text on the three
    targets; `tests/fixtures/sm120_hsetp2_nvdisasm.jsonl`, `tests/sm120_hsetp2.rs`): the 384 + 384 "mode grid" rows of
    `HSETP2_P_P_R_R_P` / `HSETP2_P_P_R_UR_P` (2026-10-22, no `_src`) were field-correct and are re-emitted from the
    measurement with provenance `hsetp2-family-2026-11-06`; three dotted harvest keys (`HSETP2.GEU.AND_P_P_R_R_P` encode-only
    twin, `HSETP2.GEU.AND_P_P_R_R_R` / `_P_P_R_UR_UR` — a `R2.H0_H0, R3.H0_H0` sample mis-tokenised as a third register) are
    `_meta.key_aliases` of the plain keys (0 census witnesses). Law: opcode 0x234 (register) / 0xe34 + bit 91 (uniform);
    Ra [31:24] with `-Ra` 72, `|Ra|` 73, selector [75:74]; Rb / URb [39:32] with selector [61:60], `|Rb|` 62, `-Rb` 63; the
    type [65:64] (fp16 / `.BF16_V2`; 1, 3 = `INVALID1` / `INVALID3`), the boolean [70:69] (AND / OR / XOR; 3 = `INVALID3`),
    `.H_AND` 71, the comparison [79:76], `.FTZ` 80, Pd0 [83:81], Pd1 [86:84], Pc [89:87] + `!` 90; [23:16], [59:40], 66–68,
    [95:92] text-inert (fail-closed). `nvprobe.probe_words(jobs=N)` runs nvdisasm in parallel on per-worker scratch files.
  - **ISETP / UISETP measured whole** (`tools/probes/re_sm120_isetp.py`, 1 944 form + 192 lattice words;
    `tests/fixtures/sm120_isetp_nvdisasm.jsonl`, `tests/sm120_isetp.rs`): 960 groups on the ten keys
    `ISETP_P_P_R_{R,UR,II}_P`, `UISETP_UP_UP_UR_{UR,II}_UP` and their `.EX` twins — 576 rows with `isetp-family-2026-11-06`
    (509 harvest rows rebuilt: they baked PT guards and a sample's predicates and their masks excluded their own fields; 67
    missing immediate-form groups added) + the 384 dsv41 rows of 2026-10-22 reproduced field for field and kept. Law: the
    `.EX` carry-in `[!]Pn` at [71:68] is read only with bit 72 (`.EX`); without it the window is text-inert and nvcc writes
    PT (7 414 / 7 414 census words), so the non-EX rows bake `[70:68] = 7` and fail closed elsewhere; 73 signed, [75:74] the
    boolean (3 = `INVALID3`), [78:76] the comparison, **80 = the 64-bit compare (`.S64` / `.U64`) — SM120-only: text-inert on
    `-b SM103` / `SM100`** (977 of the 2 136 sweep words differ by that suffix alone; the sm103a / sm100a harvest `S64` / `U64`
    groups are a question for the B300 lane). Decoder: ISETP / UISETP off the priority-3 sign-tolerant fallback
    (`ISETP.GE.INVALID3` used to print as `.XOR`). Census strict 1 811 600 / 1 811 600 with 7 414 ISETP / UISETP words.
  - A vendor rendering rule met in both reviews, for the record: nvdisasm prints `.reuse` only when the control word's yield
    bit (109) is set — a fixture's `.reuse` texts are reproducible only under the probe's control code (`0x000fe200`).
- **R3 closed — the test suite runs in 2 minutes** (was 32 min in `--release` on 16 cores at the T-11 gate, ~90 in debug):
  `IsaTable::load` caches a parsed table per process from its second load on (keyed by path, size and mtime; the CLI, which
  loads once, keeps no copy; `CUBIT_TABLE_CACHE=0` disables it) — `cargo test --release` alone drops to 12.5 min; and
  **`tools/test_suite.py`** runs the test binaries in parallel, longest first, with the `cargo test` totals (`--release -j 16
  -t 2`: 2.0 min, the same 2 68x passed / 0 failed / 9 ignored as `cargo test`). The push gate uses it from T-12 on; plain
  `cargo test` stays the reference.
- **A5 — the template rebuild (`asm -T` / `--eiattr-from`) checks the positional `.nv.info.<kernel>` records it copies.**
  Measured on the 759 kernels of the sm_120 census: four records are lists of byte offsets into the code — EXIT_INSTR_OFFSETS
  (exactly the EXIT words, 759 / 759), COOP_GROUP_INSTR_OFFSETS (661), INT_WARP_WIDE_INSTR_OFFSETS (208),
  MBARRIER_INSTR_OFFSETS (522, 16-byte entries); only the EXIT list has a code-only law, the other three are compiler analysis
  (translatable along an edit, not regenerable); no census record points elsewhere into the code, no census cubin relocates
  into `.text`. The frozen path (A20) keeps every instruction in place, so verbatim copying stays exact there; an edit that
  moves a listed instruction is refused with the record, the offset and both opcodes named (`--allow-stale-metadata` writes
  the cubin with the template's records as they are). A `KernelEntry` built from code bytes without `exit_offsets` had its
  EXIT list written as a single `0x0`; it is the code's EXIT words now (`tests/a5_positional_metadata.rs`).
- **A7 — `EiFmt` variants are cuobjdump's names** (`NVal` 0x01, `BVal` 0x02, `HVal` 0x03, `SVal` 0x04; the historical `Byte`
  / `Half` / `BValAlt` / `Sized` contradicted their bytes and `from_u8` was not the inverse of `to_u8`); the pre-2026-08
  record set `KernelMeta::to_kernel_records` and friends removed. No byte changes.
- **A8 — NaN immediates keep their payload through the lossless print on every lane.** Measured (nvdisasm 13.1, SM120 =
  SM103): every payload of the f64 high dword (DFMA, MUFU.RCP64H) and of the fp16 / bf16 halves of HFMA2 prints the same
  `+/-QNAN` / `+/-SNAN` glyph — the vendor's text cannot carry it. The lossless print spells a NaN f64 immediate as
  `0x<8 hex>D` (the high dword, which is all the word holds; the parser reads it back) and the half lanes under `II`-typed
  tokens as the half's f32 literal; every case re-encodes bit for bit (`tests/a8_nan_payload_lanes.rs`). The display print
  is the vendor's, unchanged.
- **Tables vendored from blackwell-isa `e1e8598`** (sm120 15 840 forms / 26 442 variants, from 15 961 / 26 662;
  **rows without `_src` 17 561 → 16 905**) — session G's batches 3 and 4, each re-measured word by word by T:
  - **FSETP / DSETP measured whole** (`tools/probes/re_sm120_fsetp_dsetp.py`, 1 022 form + 12 glyph + 223 lattice
    words, the same text on the three targets; `tests/fixtures/sm120_fsetp_dsetp_nvdisasm.jsonl`,
    `tests/sm120_fsetp_dsetp.rs`): the 432 "mode grid" rows of the six keys `FSETP_P_P_R_{R,UR,FI}_P` (0x20b / 0xc0b +
    91 / 0x80b) and `DSETP_P_P_R_{R,UR,FI}_P` (0x22a / 0xe2a + 91 / 0x42a) confirmed field by field and re-emitted with
    provenance `fsetp-dsetp-family-2026-11-06` (DSETP's `reuse` fields dropped: text-inert there). 112 junk keys gone:
    100 dotted encode-only twins `FSETP.<cmp>[.FTZ].<bool>_P_P_R_{R,UR,FI,II}_P` (byte-identical copies of the plain
    keys' groups, decoder-invisible, 0 witnesses — deleted, the SHF / HADD2 precedent; the spellings still assemble
    through the plain keys), `FSETP_P_P_L_L_P` (five vendor-rejected "label" rows — deleted), 11 aliases
    (`FSETP.{GE,NAN}.FTZ.AND_P_P_R_R_R`, `FSETP.{GEU,NEU}.AND_P_P_R_UR_UR`, `FSETP.NEU.OR_P_P_R_UR_UR`,
    `FSETP.NE.FTZ.AND_P_P_R_R_?`, `FSETP.NEU.{AND,OR}_P_P_R_R_P_?`, `FSETP_P_P_II_II_P`, `FSETP_P_P_II_R_P` → the plain
    key of their opcode; `FSETP_P_P_R_II_P` → `FSETP_P_P_R_FI_P` — the hexadecimal-f32 spelling `0x3f800000` still
    encodes through the alias). Law: Ra [31:24] with `-Ra` 72, `|Ra|` 73; Rb / URb [39:32] with `|Rb|` 62, `-Rb` 63, or
    the immediate at [63:32] (f32 / the f64 high half); the boolean [75:74] (3 = `INVALID3`); the comparison [79:76]
    (**DSETP names 0 / 15 `MIN` / `MAX`**); 80 `.FTZ` on FSETP, text-inert on DSETP; Pd0 [83:81], Pd1 [86:84], Pc
    [89:87] + `!` 90. Decoder: FSETP off the priority-3 sign-tolerant fallback (`FSETP.GT.INVALID3` printed as `.XOR` —
    the bug226 "226-forward" item); printer: `FSETP.F.FTZ.AND` / `DSETP.MIN.AND` order, the f64 `-0.0 ` token pad
    mid-line.
  - **PLOP3 / P2R / R2P measured whole** (`tools/probes/re_sm120_plop3_p2r_r2p.py`, 202 form + 158 lattice words;
    `tests/sm120_plop3_p2r_r2p.rs`): 8 rows with `plop3-p2r-r2p-family-2026-11-06` — the two PLOP3 harvest rows rebuilt
    (LUT = [66:64] + [76:72]; bit 67 = the third source predicate is uniform, the `_UP_` key; Pc [70:68] + `!` 71, Pb
    [79:77] + `!` 80, Pd0 / Pd1 / Pa as the SETP family), the four P2R dsv41 rows with **the mask widened to 32 bits**
    (`P2R R17, PR, RZ, 0x80000040`; the 2026-10-22 rows had swept 0..255 and carried an 8-bit field, so masks above 0xff
    did not decode; `.B1` / `.B2` / `.B3` at [77:76]), the R2P dsv41 row reproduced (`R20.reuse.B2`; the mask prints
    unsigned) and the new encode-only `R2P_II_R` — the vendor's bare spelling `R2P PR, R0` = the mask 0xff baked, which
    cubit's printer now elides like the vendor (the explicit `, 0xff` stays a bitwise alias). 10 junk keys retired as
    aliases (`PLOP3.LUT_P_P_P_P_P_II_II` and its era alias, seven P2R shapes with `PR` read as a register / label and
    6–7-bit masks, `R2P_?_R_II`, `R2P_L_R_II`).
- **Tables vendored from blackwell-isa `39bafbb` — NEEDS 44: the `IMMA.SF.16832.U8.U8_R_R_R_R_R_R_UR` hypothesis row
  (opcode 0x47e, 2026-03-26, no numerical oracle) is the measured `QMMA.SF.16832.F32.UNIDENTIFIED.E8_R_R_R_R_R_R_UR`.**
  Session R measured the word on sm_120 silicon (2026-11-06, test host GPU 0; cubit-assembled probes next to the documented
  QMMA.SF E4M3.E4M3 / E2M1.E2M1 forms on identical fragments): it executes, writes fp32, honours the E8M0 block scales
  (scale 0xff → NaN, scale ×2 → result ×2) and matches neither documented input type (64.0 / 0.0 / 28.0 on A = 0x38,
  B = 0x40) — an undocumented QMMA.SF-family variant selected by opcode bit 2, input element types unidentified, not an
  integer MMA. The row carries the family's fields (the hypothesis read R6 at [55:48] and had no UR field — R's first probe
  on that model scattered garbage), provenance `qmma-sf-opcode-bit2-silicon-2026-11-06` (`nvdisasm_sm120: "no text"`), the
  old key as an alias (`tests/needs44_qmma_sf_bit2.rs`; the IMMA / U8 claims withdrawn). **The SM120 dynamic audit's
  replay at this table (`T/audit/dyn23`, 85 873 words): 0 rows with a finding** — the last named exception is gone, and
  the `nan_glyph` class is empty (A8). KNOWN_ISSUES T1 17 560, T5 closed as measured.
- **NEEDS 39** — `docs/SCHED_LEGALITY_ORACLE.md` carries the design note for the path-aware verifier walk (blocks, joined
  states, a worklist fixpoint; ~400 lines, a session's work; acceptance criteria) — not implemented, the owner's call.

## Unreleased — 2026-11-06 (session T-11: coldface's D2 reviewed and the IDP family measured whole; A16 closed; the SM120 audit's 14 named exceptions → 1; NEEDS 37 measured as `CUBIT_GUARDED_READER_SETTLES=1`)

- **Tables vendored from blackwell-isa `c896e8f`** (sm120 15 964 forms / 26 598 variants, from 15 953 / 26 580;
  sm103a / sm100a 14 925 / 22 439, from 14 913 / 22 420; sm121a 23 860 / 26 421, from 23 850 / 26 406):
  - **The `IDP` family measured whole on the four tables** (`tools/probes/re_sm120_idp.py`, nvdisasm 13.1: 128 form +
    480 lattice words per table, the same text on `-b SM120` / `SM103` / `SM100` / `SM121` for every word; fixtures
    `tests/fixtures/{sm120,sm103a,sm100a,sm121a}_idp_nvdisasm.jsonl`, test `tests/sm120_idp.rs`). Law: guard [15:12],
    Rd [23:16], Ra [31:24], Rb [39:32] (0x7226) / URb [39:32] (opcode byte 0xc26 + bit 91), Rc [71:64]; [77:76] the
    mode (`4A` / `2A.LO` / `2A.HI`, 10 illegal), 73 / 74 the signedness of the two types, 75 `-Rc`; 72, 78, 79,
    [63:40], [95:80] text-inert. Twelve legal forms per operand shape; the mixed-type forms carry typed keys
    (NEEDS 36 = the owner's D2 of 2026-11-06 — coldface's `IDP.4A.{S8.U8,U8.S8}_R_R_R_R` rows, blackwell-isa `42192f0`,
    are the first of them and were taken as they are; his test `tests/wave11_idp_type_law.rs` fails on the pre-D2
    tables and passes here), the symmetric forms stay mod-group rows of `IDP_R_R_R_R` / `IDP_R_R_UR_R`; sm121a keeps
    typed keys for every register form. **What the measurement closed:** the uniform-register rows (the 2026-08
    harvest donor and D2's three copies of it) had no `-Rc` field and failed closed on the inert bit 72, so
    `IDP.4A.U8.U8 R15, R15, UR6, -R7` printed as the `S8.S8` row through the sign-tolerant fallback; the 2A half of
    the family had no rows (the mixed `LO` types, every `HI` form — 6 register + 8 uniform forms) and a `2A.LO.U16.U8`
    word with bit 72 set printed as `2A.LO.S16.S8`; the sm121a register rows lacked `-Rc` and baked `Rc = RZ`, its
    two `_?` twins of the S8.S8 row are retired (aliases). The decoder's sign-tolerant fallback is off for IDP; the
    printer orders `IDP.2A.HI.U16.U8` as nvdisasm does.
  - **The SM120 dynamic audit's named exceptions: 14 → 1** (the replay of the complete audit word set at this table,
    `T/audit/dyn22`, 85 886 words: text differences 0, re-encode mismatches 0; the row left is the documented
    `IMMA.SF.16832.U8.U8` hypothesis — every probe word vendor-rejected, kept by the owner's rule until a numerical
    oracle on silicon). Each re-measured with nvdisasm 13.1 on the four targets (`tests/sm120_audit_t11.rs`):
    `DEPBAR.LE`'s scoreboard field names SB0..SB5 (6 / 7 are `INVALID6` / `INVALID7` — claim-forbidden now, the
    encoder refuses `SB7`); `FADD.SAT_R_R_R` was a SAT-less harvest row (no bit 77, `Ra = RZ` baked; retired, alias
    `FADD_R_R_R`); ULEA's bit 72 is `-URa` (a field on the 4-operand row) and its UP operand prints `UP0..UP6` and is
    elided at 7 (the printer elides a `UPT` operand; the explicit spelling stays a bitwise alias as BUG-045 does for
    ULOP3); ULOP3's dest-less row baked the source predicate as `!UPT` ([89:87] + 90 are fields now — the
    UPT-destination words print the vendor's six operands and `UPT` / `!UPn` sources round-trip); `BMOV.64`'s first
    operand is the special register `ATEXIT_PC` (printed and parsed as the literal; the old `0x0` stays accepted);
    USETMAXREG is off the sign-tolerant fallback (72 = DEALLOC, 73 = TRY_ALLOC, 74 = CTAPOOL, 63 text-inert — the
    bit-63 DEALLOC word used to print as `TRY_ALLOC … UPT, 0x0`, it fails closed now); the plain 64-bit-base
    `LDG` / `STG` / `ST` forms with base 255 print the vendor's degenerate glyph `[???255.64+UR6+0x10]` (the U32 width
    prints `[RZ.U32+UR6+0x10]` normally) — the BUG-461 doctrine of the REDG / ATOMG `.EL` twins applied consistently:
    decode text-faithful, the encoder refuses to mint the glyph (and the old cubit-only `[RZ.64+UR..]` spelling);
    `tools/audit_dynamic.py` names the class (`vendor_glyph`) instead of counting it.
- **A16 closed — the encoder refuses a guard whose predicate bank disagrees with the instruction's family**
  (`tests/a16_guard_class.rs`): `@!P2 SYNCS.EXCH.64 URZ, [UR8], UR6` used to assemble silently as the word nvdisasm
  names `@!UP2 SYNCS.EXCH.64 …` (the guard bits carry only predicate + negation; the bank follows the family — U*,
  LDCU, SYNCS_UR*, S2UR, CS2UR, LDTM, STTM); only the strict code-only path checked it, after the fact. Every encode
  refuses now with both classes named ("predicate bank mismatch (A16) — … Write the @UPn guard, or guard a branch
  around the instruction"); `@PT` / `@UPT` stay interchangeable; decode and print are unchanged. `bug171` t171_3 pinned
  the silence as "a print-level distinction" — it pins the refusal now.
- **NEEDS 37 measured, not decided — `CUBIT_GUARDED_READER_SETTLES=1`** (`tests/needs37_guarded_reader.rs`; default =
  today's rule): the first reader of a load settles its write barrier guarded or not (the ptxas evidence: a predicated
  instruction's wait is honoured whether or not its guard is true, 50 / 50 census sites); today's rule makes the
  reader behind a guarded first reader wait too. On the production set the switch changes nothing in the 89 MoE
  sources (byte-identical) and removes 6 waits from V's `sparse_mla_prefill_v41` prologue; on silicon (test host, V's
  harness) bits identical 8 / 8 cases and time within the run-to-run band (1 054 / 1 152 / 2 445 / 1 055 µs vs
  1 055 / 1 154 / 2 445 / 1 054). The default stays — the owner's (KNOWN_ISSUES A24).

## Unreleased — 2026-11-06 (session T-10: the SM120 dynamic audit to its end state — 14 named exceptions; BRA on sm103a / sm100a; the BRX / BRXU / RET and dense IMMA families; NEEDS 38 measured as `CUBIT_MMA_SRC_RB=0`; the public-face review)

- **Tables vendored from blackwell-isa `c258f8a`** (sm120 15 953 forms / 26 580 variants, from 16 045 / 26 646;
  sm103a / sm100a 14 913 / 22 420, from 14 912 / 22 363; sm121a unchanged):
  - **`BRA` on sm103a / sm100a is the measured SM120 family** (`tools/probes/re_sm120_bra.py probe --arch SM103` /
    `SM100`: the 551 words of the SM120 sweep print the same text on the three nvdisasm targets, the uniform-predicate
    form 0x547 included — T-9's "sm_120-only" note was wrong; fixtures `tests/fixtures/{sm103a,sm100a}_bra_nvdisasm.jsonl`,
    test `tests/sm103a_sm100a_bra.rs`): 6 keys / 66 rows per table replace the 5 harvest keys / 9 rows (`BRA_P_UR_II`
    with `imm@18:6` + `imm@34:5` junk target fields, `BRA_UP_II [ANY,U]` with a `pred@24:4` field over the UP operand).
    The sm_103a encoder routed `BRA.DIV` / `BRA.CONV` through the REL16 arm (a 21-bit `rq`, [81:64] untouched) — a
    sub-case of the 56-bit law for 16-byte-aligned targets within 2^24 bytes, wrong beyond it; BRA takes the dword-split
    path on every table now (CALL / RET / WARPSYNC keep the REL16 law). `b4fill3` re-pinned: the rt98 gold `BRA 0x170`
    words carry the mode bits [33:32] and are `BRA.U` / `BRA.CONV` for nvdisasm on `-b SM103` as on SM120.
  - **The `BRX` / `BRXU` / `RET` family measured** (`tools/probes/re_sm120_brx_ret.py`, nvdisasm 13.1 `-b SM120`,
    506 form + 29 lattice words, every form text predicted by the layout; `tests/sm120_brx_ret.rs`): register [31:24],
    a signed 56-bit dword offset at [23:16] + [81:34] (the BRA split) printed as `Rn off*4` by BRX / BRXU (0 elided) and
    RET.ABS, `Rn PC+16+off*4` by RET.REL; predicate operand [89:87] + `!` 90 before the register; BRX / BRXU 85 `.INC`,
    86 `.DEC`, BRXU mode [33:32] `.U` / `.DIV` / `.CONV`; RET 85 `.ABS` (else `.REL`), 86 `.NODEC`, bit 91 = the
    uniform-register form (`RET.REL URZ 0x110`). Eight keys `{BRX,BRXU,RET}[_P]_{R,UR}_II` / 46 rows replace 13 harvest
    keys / 16 rows (`BRX_II` with `imm@18:20` + `reg@25:8`, `BRXU_II` printing `BRXU 0xfffe0220` for the vendor's
    `BRXU UR20 -0x1fdf0`, `RET.REL.NODEC_II` without a register, `RET.ABS.NODEC_?` without fields; aliases
    `RET.REL.NODEC_R_II` / `RET.REL.NODEC_R` → `RET_R_II`). **What changes for users:** the printer spells the family as
    nvdisasm does — register and target as one operand, no comma (`BRX R8 -0x3f00`, `RET.REL.NODEC R2 0x0`,
    `BRXU.INC.U !P4, UR8 0x100`); both spellings assemble; `BRX R8` (a zero offset) assembles; the encoder writes the
    56-bit offset without touching BRXU's mode bits (the old 32-bit write cleared `.U` / `.DIV` / `.CONV`) and without
    the wrong sign fill of [81:64] below −2^40. `strict_brxu_offsets` re-pinned to the vendor print.
  - **The dense `IMMA` family measured** (`tools/probes/re_sm120_imma.py`, nvdisasm 13.1 `-b SM120`, 240 form + 16 lattice
    words, fixture `tests/fixtures/sm120_imma_nvdisasm.jsonl`, test `tests/sm120_imma.rs`; measured by the session's second
    instance, reviewed and applied by T-10): opcode 0x237, Rd [23:16], Ra [31:24] `.ROW`, Rb [39:32] `.COL`, Rc [71:64];
    bit 86 the dense frame, 75 the shape (`16816` / `16832`), 76 A = `S8` (else `U8`), 78 B = `S8`, 82 `.SAT`; bits 73 /
    74 the only legal layouts (`???1` / `???0` otherwise — baked, fail-closed); the fifth operand `[!]UPn` = the 4-bit
    `pred_inv4` window [90:87]; bit 72 the sparse form. Typed keys `IMMA.<shape>.<A>.<B>[.SAT]_R_R_R_R[_UP]` (the type
    pair is order-sensitive, a sorted mod-group name cannot tell `S8.U8` from `U8.S8`): 32 keys × 1 row replace the 14
    dense harvest keys (2-bit-shifted register fields that printed `R4, R6.ROW, R8.COL, R10` for the vendor's `R16,
    R24.ROW, R8.COL, R40`, `neg` junk on the layout bits whose canonical words rendered `R8.???0`, the `_P_` / `_?`
    twins → aliases). The decoder's sign-tolerant fallback is off for IMMA (bits 72–79 carry the family's law).
  - **The dynamic audit of the SM120 harvest rows is at its end state: 215 → 14 rows, every one a named exception**
    (`T/audit/dyn21`; KNOWN_ISSUES T1 lists the 14 with what closes each: the T5 `IMMA.SF` hypothesis, the seven RZ-base
    64-bit descriptor words the decoder tolerates and the encoder refuses (BUG-461), the `UPT`-destination elision of
    ULEA / ULOP3, `BMOV.64 ATEXIT_PC`, `DEPBAR SB7`, `FADD.SAT` bit 62, `USETMAXREG` bit 63; the eight IMMA.16816/16832
    harvest rows of the 22 at `dyn20` left with the IMMA family).
    Closed by T-10 (`blackwell-isa-internal tools/audit_fix_20261106_t10.py` + `_t10b.py`, every repair asserted against
    nvdisasm 13.1 before the write, retirements checked against the 249 929 distinct words of the production census +
    our kernels; `tests/sm120_audit_t10.rs`): 15 harvest-row field repairs — ATOMG CAS Pd = [83:81] (the harvest's
    `pred@7` sat on the opcode bits and let the row claim illegal words), STS.64 opcode bit 9 baked (the 0x188 words
    are illegal) and the text-inert [71:64] fail-closed, the MOV / WARPSYNC / VOTE / VOTEU junk fields, IMAD.X Ra = RZ
    baked, UFMUL's three 8-bit URs, UTMAREDG's operand slots, USETMAXREG's 10-bit count, the LDCU index field (the size
    groups could not mint `c[0x0][URn]`), BAR.RED.{AND,OR} count-less twins (the vendor elides a zero thread count),
    HADD2 fp16 immediates, the SYNCS RED.A1T0 destination [23:16], the F2I.NTZ UR-form fields — and 105 junk keys / 5
    groups retired (the `_?` partial keys, the shifted-field `_P_R_R_R_R` HMMA ×5 / QMMA ×51 twins, SULD (nvdisasm:
    `SULD.P.1D.EF.INVALID0.IGN`), the FSETP / FSEL / IADD / IADD3 / UIADD3 junk shapes, the LDGSTS `[64,E,LTC128B]`
    harvest twin, …); three batch-1 retirements that cubit's pins refuted were undone with the measurement (`_t10c.py` /
    `_t10d.py`: `LD_R_ARURI [E]` with measured fields, `IADD3_R_P_P_R_II_R [X]`, the LDGSTS `[128,E,LTC128B]` rows + a
    PT-baked twin for the vendor's elided PT operand) and `STS_ARI_R [64]` keeps the BUG-425 / 425b tolerance bits with
    opcode bit 9 baked (`_t10e.py`). Printer: a zero f64 immediate prints `0` / `-0.0` as nvdisasm does (DFMA / DADD / DMUL / MUFU.RCP64H —
    the old arm printed `1` and re-encoded 1.0), the SYNCS `[R+UR+-0x..]` glyph, `[URZ+0x10]` / `[URZ]` for an RZ base on
    the SYNCS / ATOMS baked-sink rows, no `+URZ` splice when a register operand lives in the UR window
    (`ATOMS.CAST.SPIN PT, [R7+0x10], R8, RZ`), UCLEA / UBMSK immediates unsigned, no IMAD `.MOV` alias with a UR b
    operand (`IMAD R4, RZ, UR7, R10`); parser: MUFU is a float-immediate opcode (`MUFU.RCP64H R4, 0`). The audit tool
    names six measured non-defect classes instead of counting them (`reuse_rejected`, `inert_failclosed`, `inert_bits`,
    `vendor_invalid`, `nan_glyph`, `silicon_illegal` — a text both oracles print that the encoder refuses under a
    silicon-measured law, BUG-037's MMA operand alignment; `tools/audit_dynamic.py`). Census 1 811 600 / 1 811 600 and the 99 production sources
    byte-identical throughout (gate below).
- **NEEDS 38 (i) measured, not decided — `CUBIT_MMA_SRC_RB=0`** (default = today's rule; `tests/needs38_mma_src_rb.rs`):
  the MMA-source read-barrier rule as an opt-in relaxation. Test host GPU 0, K's K1 harness (`pt2-needs38-moe`, 25 reps,
  E = 64 / 8) and V's harness (`pt2-needs38-v41`): the switch removes every MMA read barrier of the 90 production
  kernels (2 696; 6 133 control words), bits identical everywhere (84 / 84 MoE kernels B = C, 81 / 81 = shipped,
  deterministic; V's kernel output and lse identical), time-neutral (C/B median 1.000 at E = 64, 79 / 84 within ±1 %;
  V 1 055 → 1 054 µs). KNOWN_ISSUES A22; the owner's decision (NEEDS_OWNER 38).

## Unreleased — 2026-11-06 (session T-9: coldface's B300 s3 commits C10 / C11 / C13 reviewed and taken, BUG-486, the legality oracle verified against the census, A19 measured with `CUBIT_RB_CHAIN`, the BRA family, the reproduction contract)

- **Tables vendored from blackwell-isa `b75cc20`** (sm120 16 045 forms / 26 646 variants; the other three
  tables unchanged): **the `BRA` family rebuilt from measurement** (`tools/probes/re_sm120_bra.py`, nvdisasm
  13.1 `-b SM120`, 519 form words every text predicted by the layout + 32 lattice words, fixture
  `tests/fixtures/sm120_bra_nvdisasm.jsonl`, test `tests/sm120_bra.rs`): target = PC + 16 + a signed 56-bit dword
  offset ([23:16] + [81:34]), guard [15:12], predicate operand [89:87] + `!` 90 (PT elided), mode [33:32] plain /
  `.U` / `.DIV` / `.CONV`, 85 `.INC`, 86 `.DEC`, 84 `.ANY` and 83 `.NOT_TID0` with `.U`, the UR operand [31:24] +
  `~` 82 behind the frame bit 91 (`.DIV` / `.CONV` only), `[!]UPn` [26:24] + 27 on the 0x547 form. Six keys
  `BRA[_P][_UR|_UP]_II` × one group per legal modifier set = 66 rows replace 15 harvest keys / 31 rows
  (`BRA_II_II_II_?` and the other `_?` junk keys, the triplicated `CONV` / `DIV` groups with `guard@29` /
  `imm_shr3@28` junk fields, `BRA_UP_II [""]` / `BRA_UR_II [""]`, `BRA_UP_II [U]` that claimed `BRA.INVALID1` words,
  `BRA_P_UR_II [CONV]` that printed `PT, UR6` for the vendor's `~UR6`; the dotted keys `BRA.U_UP_II`, `BRA.DIV_UR_II`,
  `BRA.U_?_II` are `_meta.key_aliases`). What changes for users: the printer prints the family in the vendor's
  order and glyphs (`BRA.INC.U.ANY.NOT_TID0`, `BRA.CONV ~URZ, 0x20`, `BRA.U.ANY !UP3, -0x40`, `BRA.DIV !P2, UR6,
  0x110`) and **a negative target as nvdisasm prints it** (`BRA -0x14a0` for an isolated backward word; before: the
  32-bit wrap `BRA 0xffffeb60`); text-inert bits (92-95, the UR field without the frame bit, 83 / 84 without `.U`)
  fail closed like in every measured family. Census 1 811 600 / 1 811 600 unchanged; `b4fill2` re-pinned (`~URZ`,
  the rt98 gold text was an era rendering). Dynamic audit at these tables: **230 → 215 rows** (`T/audit/dyn15`;
  the six BRA rows left are 29 harvest-junk words with inert bits set, `decode_miss` by the fail-closed
  convention). Census pins re-pinned (keys 16 054 → 16 045, variants 26 611 → 26 646, `claim_forbid` 7 013 → 7 011).
- **BUG-486 — register-indirect control flow is not a static branch target; three verifier model gaps**
  (found reviewing the A4 oracle against the sm_120 census). `branch_target` resolved the `0x0` of
  `RET.REL.NODEC R2, 0x0` to instruction 0, so every in-kernel subroutine return was a back-edge over the whole
  kernel for `resolved_back_edges` (the loop-aware verifier re-walked the kernel as a loop body and reported the
  prologue's `S2R` / `MOV` / `LEA` as loop-carried overwriters of a bare store — 16 of the oracle's 16 REJECTs on
  the B300 corpus; `load_result_loop_carried` and the allocator's loop logic saw the same phantom loop; no
  production source has a RET). RET/PRET, BRX/BRXU, JMX/JMXU, `CALL.ABS` and any control-flow op carrying a
  non-RZ GPR have no static target. The verifier: a waited WRITE barrier releases a mem-op's late-latched
  operands too (the result landed, the address was consumed — ptxas's `LDS R3, [R2]` W0 → `… R3` B0 → `MOV R2`
  shape); `DEPBAR.<m> SBb, imm` drains scoreboard b (the allocator's audit did since rt98); `src_regs` no longer
  counts `Rd` of `SHFL.* Pd, Rd, …` as a source. `tests/bug486_ret_not_a_back_edge.rs` (5 pins, 2 red before);
  the 99 production sources re-assemble byte-identical. `tests/bug347_verify_wrap.rs::t347_4` re-pinned (its
  dropped wrap wait is caught with the load's write barrier removed — with it, the inner loop's data wait makes
  the drop physically harmless under the new rule).
- **The scheduling-legality oracle (KNOWN_ISSUES A4) verified against the production census** — coldface's C11
  (`tools/sched_oracle.py`, `tests/sched_legality_oracle.rs`, two publish-corpus fixtures) taken with its
  authorship and two corrections: the read-barrier coverage probe is a **verifier mode**
  (`verify_scoreboard_rb_probe` / `CUBIT_VERIFY_RBPROBE=1`: every bare late-latching mem-op tracked under a
  virtual barrier nothing waits — the first design injected a free barrier index into the R slot and nvcc uses
  all six on most real kernels, so it ran on none of them), and findings are routed into **measured classes**
  before the verdict: `mma-source-rb` (ptxas sets a read barrier on 0 of the census's 39 624 HMMA/QMMA, 717 720
  overwriter sites — cubit protects MMA sources against an overwriting load), `store-latch-distance` (ptxas
  overwrites a store's registers without its rb from 20 issue cycles on the shortest control-flow path; cubit
  never covers a store by distance), `lds-address-latch`, `load-address-latch`, `recycle` (counter semantics),
  `guard-complement` (`@P1 LDG R19` … `@!P1 PRMT R19`), `nonlinear-path` (two instructions connected only through
  a jump — the linear walk's limitation), `unreachable` (listed, not counted). Over the 752 frozen nvcc kernels of
  the census every verdict is ACCEPT or a named divergence; **no REJECT** — the bar the review set. The two
  places where cubit's allocator pays for the stricter model in production (MMA-source read barriers, the store
  latch) are named in KNOWN_ISSUES A4 for an A/B.
- **A19: `CUBIT_RB_CHAIN=1` (default off)** — the shipped `5912400` read-barrier chain on the sub-word global
  loads (byte load k → the next global load waits its rb; `tests/a19_rb_chain.rs`) as an opt-in switch, measured on
  the test host with K's method (bits identical in every arm): `mc4_k4096_a32` shipped 340.6 µs — default 1.379×,
  chain 1.156×, `CUBIT_SB_SHARE=1` 1.177×, **both 1.012×**; `mc4_k6144_a32` shipped 533.1 — 1.608× / 1.569× /
  1.588× / **0.962×**. Over the whole MoE set (K's K1 harness, 84 kernels, bits S = B = C identical 84 / 84) both
  switches close the five MC4 K ≥ 4096 prefill kernels and cost 3–30 % on 57 of the other 79 — a per-kernel
  opt-in, not a default (the flip is the owner's decision, NEEDS_OWNER 31). KNOWN_ISSUES A19 carries the table.
- **Reproduction contract (KNOWN_ISSUES A20):** a shipped cubin is reproduced byte for byte from its frozen text
  (`disassemble --frozen` → `asm -T`, the path the gate holds at 157 / 157) with any cubit since 0.2.0;
  re-assembling the `.sass` source is a *regeneration* whose control codes follow the current allocator
  (BUG-485 added two waits to `sparse_mla_prefill_v41`) and needs its validation pass before it ships. No
  `--at <rev>` mode.
- **C14 (IDP mixed types): D2 — typed keys** (R's rule; the case in `T/NEEDS_OWNER.md` 36): the mod-group model
  canonicalises by sorting and cannot express `S8.U8` vs `U8.S8`; the schema already uses typed keys for this
  collision (`IMMA.16816.{S8.U8,U8.S8}_…` on sm120, `IDP.4A.{S8.U8,U8.S8}_R_R_R_R` on sm121a). Rows + fixture +
  test are coldface's next step; nvdisasm 13.1 confirms his eight fixture words on the three sm_120-family targets.
- **CI green again**: the `cargo doc --no-deps` step (`RUSTDOCFLAGS=-D warnings`) had failed since `1d8c450`
  (2026-11-06 03:22Z, `52767f9`'s run) on four rustdoc intra-doc links in the `--driver-abi 12` comment of
  `src/elf.rs` (`[15:8]`, `[7:0]`, `[23:16]`, `[11:8]` read as links); the test and clippy steps were green.
  The bit ranges are code spans now. `f064bed`'s and `bc8c2bd`'s runs fail the same way at their end.
- **KNOWN_ISSUES A14 closed** (coldface's C10 verified from the artefacts: the native `--driver-abi 12` cubin equals
  the `cubin12.py` rewrite byte for byte and executes on `rtx` / driver 575.51.02; the default identity still
  crashes that loader — the README's "driver ≥ 580 or `--driver-abi 12`" stands); **R1's seven tautological
  assertions are real pins** (coldface's C13, taken as is).

### Coldface's own notes for the three commits (B300 s3, kept for the record)

- **KNOWN_ISSUES A14: fixed, measured (C10)**: silicon re-verification of the native `--driver-abi 12`
  emitter on rtx (GB202, driver 575.51.02 / CUDA 12.9): the freshly assembled 12-identity cubin
  loads and executes (bug008_even stores `0x2222222411151113`, the A2 even-pair law, equal to the
  580-host value); its header is byte-identical to the `cubin12.py` rewrite (`EI_OSABI 0x33` /
  `EI_ABIVERSION 7` / `e_flags 0x00780578`) and the a12/a13 cubins differ in the three identity
  fields only; the default-13 cubin still SIGSEGVs `cuModuleLoad` (subprocess, rc -11) while a
  garbage file returns `CUDA_ERROR_INVALID_IMAGE` 200 cleanly. Artifacts:
  `pubwave/wave11/b300/c10_a14_silicon/` (B300 host).
- **KNOWN_ISSUES A4 implemented (C11)**: the static scheduling-legality oracle of
  `docs/SCHED_LEGALITY_ORACLE.md` as `tools/sched_oracle.py` (corpus driver over
  `disassemble --frozen` + `CUBIT_VERIFY=1 asm` -- cubit's own scoreboard verifier does all
  operand extraction) plus the **rb-coverage probe** for the `ebbd1dc` shape the verifier cannot
  see by construction: a schedule that never SET a store's read barrier is invisible to it, so the
  probe injects a free barrier index into every bare late-latching mem-op (batched by disjoint
  register sets; R255/RZ findings are non-events) and re-verifies. `tests/sched_legality_oracle.rs`
  pins P1 (clean frozen schedule accepted), P2a (wait-stripped variant -> BROKEN WAR),
  P2b (rb-missing variant -> the probe), the probe's no-false-positive property and two
  publish-corpus fixtures. `--stats` emits the per-kernel rb/wb/wait/stall accounting (A19 data:
  where extra read barriers come from), `--resched` oracles cubit's own emitted schedule of the
  same stream, `--stallfix` reports stall-floor raises (invariant 6, report-only).
## Unreleased — 2026-11-06 (session T-8: the LEA family, the allocator's WAW rule, the audit oracle corrected)

- **Tables vendored from blackwell-isa `7094efc`** (sm120 16 054 forms / 26 611 variants, sm103a / sm100a
  14 912 / 22 363, sm121a unchanged): the **`LEA` family rebuilt from measurement on the three tables**
  (`tools/probes/re_sm120_lea.py`, nvdisasm 13.1 `-b SM120`, `-b SM103` / `-b SM100` text-identical for
  all 824 probe words per target; fixtures `tests/fixtures/{sm120,sm103a,sm100a}_lea_nvdisasm.jsonl`, test
  `tests/sm120_lea.rs`): `LEA[.HI][.X][.SX32] Rd, [Pd,] Ra, <b>, [Rc,] imm5 [, Pcin]` × register / imm32 /
  UR forms × {a `Pd` token, `PT` baked} = 36 rows on 24 keys replace 56 / 18 / 18 harvest keys (NEEDS_OWNER
  30, the audit's largest family). What changes for users: the plain `LEA R4, R8, R10, 0x1` word no longer
  decodes as `LEA.HI.X … RZ, 0x1, PT`, the `.X` forms print their carry-in (`, PT` / `, !P2`) and nvdisasm's
  bitwise-inverse glyph (`LEA.HI.X R9, ~R12, UR14, RZ, 0x2, PT` — before: `-R12`), 26 372 production LEA
  words and the census round-trip unchanged (1 811 600 / 1 811 600). The decoder's sign-tolerant fallback
  is off for `LEA` (every legal combination is a measured row; text-inert bits fail closed), and the
  **encoder refuses a sign glyph the row has no field for** instead of dropping it: `LEA.HI.X R4, -R8, …`
  (an `.X` form wants `~`) and `LEA R4, ~R8, …` are errors naming the law — before, `LEA.HI.X R4, ~R8,
  UR10, R6, 0x1, PT` minted the word WITHOUT bit 72 through the sm103a B300-4 row (`neg` field, `~` text).
  Also: the two `F2FP.*.F32.PACK_AB_R_R_R_?` junk twins and the duplicate `F2FP_R_R` TF32 group retired
  (their words decode through the measured rows unchanged); the printer prints the `UNPACK_B_MERGE_C`
  conversions in the vendor's order — source type first, `F2FP.SATFINITE.RELU.E4M3.BF16.UNPACK_B_MERGE_C`
  (96 audit words were `BF16.E4M3`). Census pins re-pinned (`tests/bug*_data.inc`, `bug176`, `bug289`,
  `bug381`, `bug459a`, `bug476`); `bug229` / `bug230` / `b3004` re-pinned to the measured family (the
  `.X` pivot word of `bug229` now prints the vendor's 6-token text that the 2026-08 pin had parked as a
  known gap).
- **`ATOMS_R_ARURI_R` measured over its whole operation × type lattice** (`tools/probes/re_sm120_atoms_aruri_ops.py`,
  nvdisasm 13.1 `-b SM120`, 720 form + 27 lattice words; `tests/sm120_atoms_aruri_ops.rs`; blackwell-isa
  `0a0f539`): `ATOMS.<op>[.S32|.64|.128] Rd, [Ra+URb(+imm)], Rb` (0x98c + frame bit 91) — operation [90:87]
  ADD / MIN / MAX / INC / DEC / AND / OR / XOR / EXCH (9+ `INVALIDn`), type [75:73] plain / S32 / 64 / 128
  (others `INVALIDn`), 36 groups replace the one measured (`MAX,S32`, 2026-10-29) and six harvest groups that
  read the UR byte as a fourth register (`ATOMS.AND R4, [R7+UR4], R8` printed `ATOMS.AND R4, [R7], R8, R4` and
  did not re-encode); the four 0x98c junk groups of `ATOMS_R_ARI_R_R` and the mis-keyed `ATOMS_R_AURI_R`
  [EXCH] (it absorbed `ATOMS.INVALID10` words as `EXCH`) retired. `bug211` re-pinned: the `.64` word of the
  RZ-base AND form now prints the vendor text on sm120 (`@P0 ATOMS.AND.64 RZ, [UR8+0x14], R3`), the sm103a /
  sm100a tables keep the hole.
- **Nine harvest keys whose every probe word nvdisasm rejects retired** (`DADD_R_II_R`, `DMUL_R_R_R_II_?`,
  `DMUL_R_R_R_II_II_II_?`, `DMUL_R_R_R_R`, `MOV_R_UR_II_?`, `MOV_R_UR_II_II_?`, `MOV.64_R_UR_II_?`,
  `MOV.64_R_UR_II_II_?`, `MOV.64_R_UR_UR`; blackwell-isa `5222c58`): re-measured after the oracle correction,
  no witness among the 237 844 distinct words of the production census (every word decoded once per row for
  the count), no alias target, a measured sibling carries the real form. The audit's "every probe word
  illegal" class is 17 rows after the oracle correction (168 on 2026-11-05 — the race's artefact); the eight
  left are the documented `IMMA.SF.16832.U8.U8` hypothesis and rows whose canonical word decodes through
  another row with one illegal reuse-bit variant. **Audit at the pushed tables: 230 rows** (`T/audit/dyn14`;
  LEA, ATOMS and F2FP closed; nvdisasm-rejects-cubit-decodes 59 words).
- **BUG-485 — the barrier allocator has a WAW rule** (KNOWN_ISSUES A17's open remainder, NEEDS_OWNER 34).
  `raw_consumers` collected only the READERS of a variable-latency producer's destinations as waiters; an
  instruction that overwrote a still-live destination merely dropped it from the live set, so a dead load
  (never read before the register is rewritten by an ALU op, a load of another class or a load of another
  address stream) got no write barrier and the overwriter no wait — its asynchronous writeback could land
  after the new value. Now the overwriter is a waiter like a reader (ptxas waits the barrier there too);
  an unguarded one ends the scan on its path. `tests/bug485_waw_dead_load.rs` (5 pins; 3 red on the old
  allocator). Effect on the production sources (`T/t8/moe/cmp_prod_485b.log`): 97 of 99 byte-identical in
  `.text`; `sparse_mla_prefill_v41` (2 control words: the guarded `@P0 VIMNMX.S32 R18/R19, R2, RZ, !PT`
  overwriters of `LDC R18/R19` wait their barrier) and `mla_prefill_state2` (the same pattern + a
  recolouring) carry additional waits — the shipped cubins stay pinned; a regeneration of either carries
  the extra waits. Evidence recorded on the way (50 / 50 sites of the sm_120 census): a wait on a
  PREDICATED instruction is honoured whether or not the guard is true — ptxas puts no wait on the next
  unguarded reader behind `@P0 SHF … R10` of an `LDC R10` — so cubit's "a guarded first reader may be
  skipped" rule is conservative, not a hazard (left as is; relaxing it removes waits, needs an A/B).
- **`tools/audit_dynamic.py`: the nvdisasm scratch-file race fixed.** Two rows probing the same word in
  parallel shared `<word>.bin`; one unlinked the file the other was about to pass to nvdisasm, and the
  tool recorded the failure as "rejected". The 2026-11-04 record set had 386 such legal words (LDG 163,
  IMMA 32, SHF 28, LEA 18, …, F2FP 13); re-measured 2026-11-06 (`T/audit/dyn/words_in_fixed.jsonl`), the
  scratch name is unique per call and a failure that is not nvdisasm's own verdict raises. With the
  corrected oracle and this entry's rows the audit stands at **255 rows** with at least one defect
  (418 on the T-7 tables: 43 LEA rows gone, 120 of the rest are the "nvdisasm rejects, cubit decodes"
  class that the race had inflated to 474).

## Unreleased — 2026-11-05 (session B300 / coldface, reviewed and taken by T-7 2026-11-06) — `asm --driver-abi 12`: the CUDA-12 ELF identity for the 12.9 driver

- **KNOWN_ISSUES A14 fixed (pending silicon — measured 2026-11-06, see the T-9 entry: closed)**: `asm` writes the CUDA-13 ELF identity
  (`EI_OSABI 0x41`, `EI_ABIVERSION 8`, `e_flags 0x06_00_SS_fX`), which SIGSEGVs `cuModuleLoad` on
  the CUDA-12.9 driver (measured 2026-11-05 on rtx, driver 575.51.02; a garbage file fails cleanly
  with `CUDA_ERROR_INVALID_IMAGE`). `--driver-abi 12` rewrites the three header fields to the
  CUDA-12 convention (`EI_OSABI 0x33`, `EI_ABIVERSION 7`, `e_flags 0x00_SS_0A_SS` -- SM in [7:0] and
  [23:16], `0x5 | ('a' ? 0x8 : 0)` in [11:8]); the same bytes then load and run on 12.9 (specification
  `T/gpu/cubin12.py`). Default stays 13 -- today's cubins are byte-identical (frozen `asm -T` tests
  green). Applies to all three `asm` paths (template rebuild, standalone ELF build, directive format);
  `src/elf.rs::rewrite_driver_abi_12` carries the unit test. The 580.x drivers load both identities.
  Silicon re-verification of the emitted 12-identity on rtx: T/K (the measurement that motivated the
  feature used the Python rewrite, not this emitter).

## Unreleased — 2026-11-06 (session T-7: the scheduler's atomics, the shared footprint)

- **BUG-482 — the scheduler tracks the atomics' operands** (KNOWN_ISSUES A17, found 2026-11-05 by the
  NEEDS 28 silicon probe). `dest_regs` took operand 0 as every instruction's destination; on nvcc's shape
  `ATOMG.E.ADD.STRONG.GPU PT, R6, desc[UR4][R2.64], R7` — and every `ATOM* Pd, Rd, …` form — that is the
  predicate, so `Rd` had no producer, the write barrier the long-latency class requests was dropped as
  waiter-less, and a consumer of `Rd` read it before the atomic returned (test host, RTX PRO 6000 Server
  Edition: old values `0xac0799b5` / `0x9d0c99b5` / `0x8d059935` instead of `0x100`; correct with a
  hand-written `W2` / `B--2---`). `Rd` was also a false *source*, the address of `RED`/`REDG` (operand 0)
  was not a source at all, `.64` data operands were single registers, and the family's data registers
  had no WAR protection (ptxas tags every `ATOMS.MAX.S32 RZ, [R157+UR7+0x15100], R58` of the sparse-MLA
  kernels with a read barrier — 1 248 sites in the census). Now: on `ATOM`/`ATOMG`/`ATOMS` the first
  REGISTER operand is the destination (operand 1 behind a `Pd`; `RZ` = no result), spanning the access
  width (`.64`/`.S64`/`.U64`/`.F64`/`.F32x2`/`.F16x4` a pair, `.128`/`.F32x4`/`.F16x8` a quad), a real
  `Pn` destination is a result too, sources start after `Rd`, `RED`/`REDG` sources start at the address,
  data operands span the access width and are late-latched like a store's (read barrier, waited by the
  overwriter). Mirrors the "atom" role class of `reg_liveness.rs`. `tests/bug482_atom_pd_rd_dest.rs`
  (7 pins; 6 fail on the previous scheduler). Exposure: the 97 production SASS sources that assemble carry
  no atomics and re-assemble byte-identical in `.text`; frozen (`[CC]`-prefixed) kernels keep their control
  codes.
- **BUG-483 — `.nv.shared.<K>` is the declared footprint, not footprint + 0x400** (session K's finding of
  2026-11-05, `K/REPORT.md` §1.2). Since `a0e5438` (2026-08-24, b10 F-2) the ELF builder sized every
  kernel's shared section `.shared smem[N]` + 0x400, reading ptxas's output as a driver law. It is ptxas's
  LAYOUT: user shared data starts at window offset 0x400 behind a 1 KB system head, so `sh_size = user +
  0x400` follows (all 668 nvcc sm_120 census kernels have `sh_size >= 0x400`, exactly 0x400 without
  statics). The section size is the whole per-CTA static allocation — the driver adds nothing on top (K,
  test host GPU 0: 4 CTAs × 8 192 B fit the 32 KB carveout step, 4 × 9 216 B need the next one → smaller L1
  → the re-assembled L1-bound MC4/AFRAG MoE prefill kernels ran 1.4–2.0× slower than the shipped 2026-06
  cubins, `mc4_k4096_a32` 337 → 670 µs; with the section patched back to 8 192 the shipped time returns,
  `K/k1/smem_probe2.py`). The b10 PTX kernels had faulted in 2026-08 because the PTX path lays their data
  out at 0x400+ (`ptx_parse` shared layout) but declared only the user bytes — the fix landed one layer too
  low and every hand-written kernel, which addresses the window from 0, paid 1 KB per CTA. Now `.shared
  smem[N]` is the section size verbatim (as `disassemble --frozen` already reads it and `asm -T` already
  reproduces it), PT_LOAD RW memsz = footprint + 0x40, and the PTX path declares its 0x400-based footprint
  (`PtxKernel::shared_footprint` = head + aligned statics; the head alone for extern-only kernels, which
  previously declared nothing although their lowered addresses start at 0x400) — the b10 cubins are
  byte-identical to before. The 97 production sources re-assemble with `.nv.shared` = the shipped cubins'
  (8 192 / 7 168 / 4 096 / 3 072 / 1 024 / 32 768 / 40 960 / 45 376), `.text` unchanged.
  `tests/bug483_nv_shared_footprint.rs`; `b10_harness_fixes` F-2 and `merc_companions` re-pinned to the
  declared size.

- **BUG-484 — `HADD2.H1H1A Rd, Ra, Rb` assembles again, as the vendor's `HADD2 Rd, Ra.H1_H1, Rb`; the
  SM120 `HADD2` register form rebuilt from measurement** (session K's finding of 2026-11-05: the production
  kernels `exl3-wave-m8/k1_m8{,g}.sass` — 256 sites, built by cubit `5912400` — did not assemble on `main`).
  `H1H1A` was cubit's own 2026-08-08 mnemonic-suffix row (blackwell-isa `8f773da`, "Ra = H1_H1 baked into
  the mnemonic", added because the plain row then dropped the selector), retired at the O2 cut without an
  alias. nvdisasm 13.1 names the words `HADD2 Rn, Rn.H1_H1, Rn`; the spelling is now an INPUT alias in the
  parser (rewritten before encoding, never printed; `HADD2.H1H1A` with a non-register Ra is refused). Both
  kernels re-assemble to the shipped `.text` (`k1_m8` 923 / 923 words identical; `k1_m8g` 934 / 935 — the
  one difference is `ISETP … R24, RZ` written as the register form the source spells, where the 2026-06
  encoder minted the equivalent immediate `0x0` form). Measuring the form showed the plain row itself
  incomplete (`tools/probes/re_sm120_hadd2_sel.py`, 181 form + 36 lattice words): **blackwell-isa
  `ac04a77`** rebuilds `HADD2_R_R_R` with 12 measured groups — Ra selector [75:74], Rb [61:60] (0 natural,
  2 `.H0_H0`, 3 `.H1_H1`, 1 = `INVALID1` outside the rows), `-Ra` 72, `|Ra|` 73 (text-inert under `.F32`),
  `-Rb` 63, `|Rb|` 62, `.SAT` 77, `.F32` 78, `.FTZ` 80, `.BF16_V2` 85 — and retires the dotted twins
  `HADD2.F32_R_R_R` / `HADD2.BF16_V2_R_R_R` and five register-opcode junk rows (`HADD2_R_R_R_R`,
  `HADD2_R_R_R_II_?`, `HADD2_R_R_R_II_II_?`, `HADD2_R_R_II`, `HADD2_R_R_II_II_II_II_?`): before, a word
  with `|R5|` printed `HADD2 R9, R2, 0x7000, 0x5, 0, 0, UR0`, the `F32` group was a harvest sample with
  `-Ra`, `Rd = RZ`, `Rb.H0_H0` baked into `and_base`, and `BF16_V2` had no sign fields. The decoder's
  `.F32` bit-73 arm (`hadd2_f32_abs_inert`) now covers the register form. Keys 16 103 → 16 096, variants
  26 656 → 26 658; the BUG-261/265/266/274/276 pins that asserted the junk "keeper" row on sm120 are
  re-pinned (its witness decodes through `HFMA2_R_R_R_R` since the September HFMA2 closures; sm121a keeps
  the era row). `tests/bug484_hadd2_h1h1a_spelling.rs`, fixture `sm120_hadd2_sel_nvdisasm.jsonl`.

- **KNOWN_ISSUES A13 closed as documented: `CUBIT_SB_SHARE=1` stays opt-in.** Session K measured the policy
  on the production MoE set (2026-11-05, test host GPU 0): 84 / 84 kernels bit-identical to the shipped
  cubins and to the default re-assembly, deterministic; time-neutral (median +0.3 % at E=64, 0.0 % at E=8,
  range −6.9…+4.2 % on small kernels). The gain is for scoreboard-starved kernels (session V's sparse-MLA
  attention, 1.6×); flipping the default would re-schedule every cubit-assembled production kernel for no
  measured gain there. The README names the switch. **New A19:** with the BUG-483 size restored, the
  default scheduler is still +34…37 % (`mc4_k4096_a32`) / +58 % (`mc4_k6144_a32`) slower than the 2026-06
  `5912400` schedule on the MC4 MoE prefill kernels (34 read barriers where the shipped schedule set 75 —
  the fragment-register WAR protection; AFRAG and k2048 at or below the shipped time); the shipped cubins
  stay pinned, the frozen shipped schedules are the safe regeneration path and the oracle for the allocator.

- **Tables: the 64-bit-base twin of the plain `.EL` atomic** (blackwell-isa `582dfd8`, provenance
  `atomg-el-aruri64-2026-11-06`; `tools/probes/re_sm120_atomg_el_aruri64.py`, nvdisasm 13.1, 74 form + 8 lattice
  words, text-identical on `-b SM120` / `SM103` / `SM100`): `ATOMG.E.{ADD,OR}.EL.STRONG.GPU Pd, Rd,
  [Ra.64+URb(+off)], Rb` — the fields of the 2026-11-05 U32 rows with the width bit 63 set, bit 76 (the
  descriptor form) excluded; base 255 prints the degenerate `???255.64` glyph like the REDG twin (BUG-461,
  decode only). The U32 rows exclude bit 63 since 2026-11-05, so these words failed closed — the four
  `[R8.64+UR7(+-0x1)]` decode misses of the dynamic audit (`T/audit/dyn10`) decode and round-trip now
  (`tests/sm120_atomg_el_aruri64.rs`). Keys +2 per table (sm120 16 098, sm103a / sm100a 14 904), the
  claim_forbid census +2 per table (the BUG-461 REDG census now counts REDG keys only).

## Unreleased — 2026-11-05 (session T-6: BUG-041 doctrine lifted by the owner)

- **`ATOMG.E.<op>.EL.STRONG.GPU Pd, Rd, desc[URm][Rn.64], Rb` assembles** — the `.EL` descriptor-pair form
  (bits 76 + 63). It was a hard error since 2026-03 because the text silently minted the plain U32 word
  (`[Rn.U32+URm]`, bit 76 clear; `CUDA_ERROR_ILLEGAL_ADDRESS` on silicon) through a mis-keyed row; the
  wave-11 tables carry the real pair row, nvdisasm 13.0 / 13.3 / 13.4 render the word as written on the
  four models (coldface, `HANDOVER_TO_T6.md` §3: word `000fc200082ef10480000028053a79a8` →
  `ATOMG.E.ADD.EL.STRONG.GPU PT, R58, desc[UR4][R5.64], R40`), and the silicon probe of 2026-11-05 17:27Z
  (test host, RTX PRO 6000 Server Edition, driver 580; `atomg_el_pair` vs the nvcc pair `atomg_desc_ctl` and
  the plain `.EL` form `atomg_el_plain`, one thread each, `out` above 4 GiB) shows the pair form **executes
  through the 64-bit descriptor-pair address and returns the old value**, identical to the other two. Owner's
  decision 21:59 CET: the doctrine is lifted. The explicit guard `check_atom_el_desc64_bug041` (`44c9a4d`) is
  removed; the hazard stays pinned positively — `tests/bug041_atomg_el_desc.rs` asserts the minted word carries
  bits 63 + 76, is never the U32 word, and decodes back to the same text (also through the CLI); on sm_103a the
  pair rides the BUG-078 odd-base rule (`bug078` t3b). REDG has no `.EL` pair row on sm120 and stays a hard
  error. KNOWN_ISSUES A15 closed.

## Unreleased — 2026-11-05 (session T-6, item 2: session T-5's gate-2 measurement landed on the wave-11 tables)

Session T-5 measured these on `bb11659` and died before gating them; re-applied with the same probes on
blackwell-isa `377b507` (on top of the wave-11 tables), gated and pushed by T-6.

- **Tables: tcgen05 `LDTM`/`STTM` rebuilt from measurement on sm100a and sm103a** (blackwell-isa, provenance
  `ldtm-sttm-sm100-2026-11-05`; `tools/probes/re_sm100_ldtm_sttm.py`, nvdisasm 13.1 `-b SM100` / `-b SM103`,
  576 form + 80 lattice words, text-identical on both targets): `LDTM_R_II` and `STTM_II_R` carry 96 measured
  groups each (shape enum bits {87, 82, 81}, count `x2^n` at [85:83], `PACK16BIT` / `EXPAND16BIT` bit 80,
  8-bit register and UR fields with 255 = RZ / URZ, the 24-bit tmem offset at [63:40], bit 91 = frame). This
  closes KNOWN_ISSUES V5 (a): the five tcgen05 words of the 2026-11-03 B300 strict round trip — the
  `16dp32bit_t16_t31` x2 / x8 / x32 harvest rows had no UR field (`tmem[URZ+0x20]` re-encoded as
  `tmem[UR192+0x20]`) — now round-trip (`tests/sm100a_ldtm_sttm.rs`). Printer: the LDTM/STTM guard is
  **uniform** (`@UP0 LDTM …`, nvdisasm prints all 16 guard codes as `@UPn`), and `PACK16BIT` /
  `EXPAND16BIT` print after the count (`LDTM.16dp32bit_t16_t31.x8.PACK16BIT`). V5 (b)/(c) — a reuse bit
  on an immediate-source `UMOV`, the mode bit of `I2F.S16` — stay text-inert bits the strict path cannot
  carry (the frozen `!rsd` path does); documented, not fixed.
- **Tables: the SM120 `SHF` family rebuilt from measurement** (dynamic-audit batch 3, blackwell-isa
  provenance `shf-sm120-2026-11-05`; `tools/probes/re_sm120_shf.py`, 380 form + 78 lattice words): the 40
  dotted harvest keys (`SHF.L.U32_R_R_II_R`, `SHF.R.S32.HI_R_R_II_R_II_II_?`, …) are gone and the five forms
  — 0x219 `Rd, Ra, Rb, Rc`, 0x419 `Rd, Ra, Rc, imm32`, 0x819 `Rd, Ra, imm32, Rc`, 0xc19 `Rd, Ra, URb, Rc`,
  0xe19 `Rd, Ra, Rc, URb` — carry 32 measured modifier groups each (bit 73 unsigned, 74 32-bit, 75 `.W`,
  76 `.R`, 80 `.HI`). The decoder's prio-3 sign-window fallback no longer absorbs SHF words (bit 72 is
  text-inert; the b72 neighbour of `SHF.R.U32` printed as `SHF.R.W.U32 R2, -R4, …`). `tests/sm120_shf.rs`.
  Keys 16 143 → 16 103, variants 26 612 → 26 656 (on the wave-11 tables; T-5 measured the family on
  `bb11659`, the rows are re-applied unchanged). Audit replay of the complete 2026-11-04 word set at this
  tree (`T/audit/dyn10`): **463 → 423 rows** with at least one defect (444 after wave 11 alone; SHF 13 → 1 —
  the one left is a reuse-bit variant nvdisasm refuses on the UR form); the production census is unchanged
  (session report part 6).
- **`stallfix` v4 for SM120** (blackwell-isa `377b507`): `guard_d0_forbid` false, `floor_guard_d0` 13,
  `cap_stall` 15, `legacy_stall_risk_from` 15. Harness v4 (T-5, 2026-11-05, `rtx` = 2× RTX 5090 / GB202, 98
  kernels; the `guard` path swept to S15 and a new `guardbra` path `ISETP → @P BRA`): S12 still wrong
  (618 880 / 655 360 threads), S13 / S14 / S15 clean, on the data consumer and on the guarded branch alike.
  The v3 sweep had ended at S11 and called the site a violation, which refused session V's silicon-validated
  kernel (S14 at its 7 guard-d0 sites) and cubit's own `schedule()` output (S14 before `@P BRA`).
  `tests/stallfix_sm120.rs`: `guard_d0_is_raised_to_13_on_sm120`. The RTX PRO 6000 confirmation of the
  S13 point is still owed (NEEDS_OWNER 24); every other floor agreed on both SKUs field by field.
- `docs/SM120_STALLFIX_PLAN.md` §4 carries the v4 reading; `tools/probes/README.md` lists the two probes.

## Unreleased — 2026-11-05 (session T-6: wave 11 merged onto main, the suite green again)

Another agent ("coldface", B300 host) moved both public `main`s on 2026-11-05: blackwell-isa `e99598a`
(wave 11, the "lane October stack": +1 285 310 / −63 555 table lines, see its CHANGELOG) and cubit
`f452227` + `9ff63c8` (the lane's engine arms BUG-479b / 495 / 496 / 458b / 458c / 505b / 512 / 518 / 493 /
051, tables re-vendored from `e99598a`, tests `wave11_fmnmx3_f32_imm.rs`, `wave11_idp_type_law.rs`), gated
by the lane's census (sm120 238 848 / 238 848, deep_gemm 56 248 / 56 248) but **not by `cargo test`**.
`1312d44` merges that `main` with session T-5's `ed4d316` (no conflicts; T's commits touch only
`src/scheduling_pass.rs`). On the merged tree the suite was red; this entry is the triage.

- **Wave 11 arms, as merged (from the lane's commit messages; measured on nvdisasm 13.3 / silicon by the
  lane):** `claim_forbid` evaluated on the full 128-bit word (BUG-512/518: exclusions above bit 96 were
  inert under `code_clean`); IDP excluded from the decoder's ghost-sign synthesis (b72 printed a ghost
  `-R15`); F2FP ghost-sign suppression per bit, `UNPACK_B` 4-operand junk collapsed to the vendor 2-operand
  form, `MERGE_C` `.H1` selector (b72), the five `PACK_AB_P_R_R_R` keys' `PT` destination elided (BUG-458b/c);
  VIADD `|R|` ghost suppressed (BUG-505b); `ENDCOLLECTIVE` trailing `PT` elided (BUG-495); the sm120/sm121
  `WARPSYNC.COLLECTIVE [P,] Rn, <target>` 8-bit target law (target = addr + 0x10 + (byte2 << 2), BUG-496)
  with the `ALL.COLLECTIVE` form kept on the dword-split layout (`9ff63c8`); `FMNMX3` immediates parsed as
  f32 (the harvest key baked 0x3f800000 and routed the text into a 6-bit field).
- **ATOMG `.EL` plain form — "our pin was wrong" (`tests/b4fill2_rows.rs`, `bug041`, `bug078` t3,
  `bug080` t4):** the sm103a / sm100a era keys `ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_dARI_R` keyed the plain
  `[Ra.U32+URb(+off)]` word (bit 76 clear) as a 64-bit descriptor form, so cubit printed
  `desc[UR6][RZ.64]` for a word nvdisasm 13.1 reads as `[RZ.U32+UR6]` on SM103 / SM120 / SM100 alike, and
  the era text `desc[URm][Rn.64]` + `.EL` minted the plain word — the BUG-041 downcast kept alive on
  sm103a as "era fixed points". Wave 11 carries the real `.EL` descriptor rows (`ATOMG_P_R_dARI_R`, bits
  76 + 63 set), so the era text now mints the faithful pair word and the mis-keyed text re-encoded to a
  different word. Measured (`tools/probes/re_sm120_atomg_el_aruri.py`, 98 form + 25 lattice words on each
  of `-b SM120` / `SM103` / `SM100`, text-identical): the rows are rebuilt as `…_P_R_ARURI_R` on the three
  tables (blackwell-isa, provenance `atomg-el-aruri-2026-11-05`): Pd [83:81], Rd, Ra, Rb, 8-bit URb
  [71:64], **signed 23-bit offset [62:40]** (the sm120 rows had a 24-bit field that swallowed the width
  bit 63 — `+-0x10` minted the `.64` word — a 6-bit UR field and no Pd field); bit 63 (address width) and
  bit 76 (descriptor) are `claim_forbid` so the decoder's broad operand-window match cannot claim the
  `[Ra.64+URb]` word. Printer: the 23-bit window at [62:40] prints the vendor's `+-0x…` glyph. Tests:
  `tests/sm120_atomg_el_aruri.rs` (the fixture replayed on the three tables, lattice fail-closed); the
  pins of `b4fill2`, `bug078` t3 and `bug080` t4 re-spelled with the vendor's text for the same words.
  **BUG-041 doctrine unchanged** (owner decision pending at the time, NEEDS_OWNER 28 — lifted 2026-11-05, see the T-7 entry): `.EL` + `desc[URm][Rn.64]` stays
  a hard error. The wave-11 rows would mint the real pair word (bits 63 + 76, rendered by nvdisasm as
  written, never executed), so the refusal no longer falls out of the tables — it is an explicit encoder
  guard now (`check_atom_el_desc64_bug041`, `CUBIT_DISABLE_ERRATA=1` lifts it for RE; `bug041` unchanged,
  `bug078` t3b). **BUG-078:** the `.EL` text exemption is gone (it assumed the text could only mint the
  plain word); the plain `.EL` form (`[Rn.U32+URm]`, an Addr operand) was never subject to the rule. REDG
  keeps the BUG-454 era-glyph fallback (`PT, desc[..]` → plain word).
- **The other agent's own fixes of the same red suite, reviewed and taken:** coldface fixed 47 of its 49
  red tests on its branch `wave-11/integration` (six commits after `9ff63c8`, cherry-picked here with their
  authorship: `165b986b` behavioural pins, `40a91c13` / `c646cad5` / `eca1fe84` census counters, variant
  snapshots and table digests, `b12b226e` / `3eab74e2` printer arm + the t195_4 / t199_3 / t199_7 pins).
  Independent check (T-6, nvdisasm 13.1): the t195_4 / t199_3 / t199_7 / t373_1 / t476 verdicts agree
  with ours; the counter re-pins are taken with the values of the final tree (two more `claim_forbid`
  rows per table from the ATOMG rows, canonical `2eed3ac`, sm120 digest `d756d8c7…`); their `bug078` t3 /
  `bug080` t4 re-pins (the `.EL` descriptor text → pair word) are replaced by the vendor-text pins above
  (they contradict the BUG-041 doctrine and left the sm103a decode text wrong); their ATOM printer arm
  (CONSTANT < scope < PRIVATE) is superseded by the family arm measured on the whole lattice (it left
  `.64.EF`, `.EF.MMIO.S32`, `.CONSTANT.EF.VC` out of order). Per-test comparison: session report part 6.

## Unreleased — 2026-11-05 (session T-5: session V's scheduler fixes integrated)

Session V (the sparse-MLA prefill SASS kernel, 2026-11-04) found three defects in the auto-scheduler
that every cubit kernel with if/else arms, a barrier followed by a shared-memory access, or registers
above R127 was exposed to; earlier kernels were protected by accidental overflow drains. V's two commits
(`b17895d`, `1f1a998` on `53e9ed8`) are cherry-picked verbatim, then renumbered: V reported them as
"BUG-421/422", numbers that `tests/bug421422_ldsm_enum_s16.rs` already owns.

- **BUG-478 — the barrier allocator follows forward control flow** (`reallocate_barriers`):
  `raw_consumers` / `war_overwriter` scanned program order linearly, so after an unconditional
  `BRA join` closing an if/else arm the scan walked into the other (dead) arm and took its first
  match as the waiter, and a guarded forward branch did not fork the scan (the taken arm's first
  consumer never waited). Silicon symptom (sm_120, 1 CTA/SM): the fp8 dequant arm's last
  `STS.128 …, R8` was "waited" by an instruction of the fp4 arm; the join's `IADD3 R11` clobbered the
  store data → nondeterministic wrong KV rows in ~1 % of the tokens. Now: path-following scans
  (`FlowInfo`: unconditional forward branch = continue at the target, guarded forward branch = fork,
  first consumer / overwriter on every path, `seen` sets bound the walk on diamonds and joins) with
  V's refinements — predicate knowledge along a path (`@!P5 BRA a` … `@!P5 BRA b` is one path, not
  four), a load's address latch is released by its own unguarded RAW waiter, loop-carried
  consumers / overwriters only when a path reaches an enclosing back-edge with the operand pending.
  Maintainer refinement (T-5): a path that leaves a loop through a guarded forward jump resumes at
  the jump target, not at the loop-exit fall-through (pre-fix a consumer at the target never waited
  when the fall-through exit code read the register first; `t478_6`). Tests
  `tests/bug478_fwd_branch_join_barriers.rs` (6), `bug342` / `bug347` fixtures made consumer-guarded so
  their wrap-WAR pins stay real hazards. `CUBIT_BUG478_LEGACY=<bits>` restores the pre-refinement
  behaviours for bisection.
- **BUG-479 — `BAR.SYNC` stall floor 6**: `BAR.SYNC` / `BAR.RED` block deferred; a shared-memory
  access issued within 5 cycles of the barrier slips past it (silicon: the softmax cross-warp
  reduction `STS; BAR.SYNC; LDS ×8` wrong in ~40 % of the tokens at S01..S05, exact at S06; ptxas
  never goes below 6). `schedule()` had no floor for `BAR` (the `main.rs` re-injection comment promised
  "BAR=6" without anything computing it) → S01 in every cubit kernel; `LATENCY_BAR_SYNC = 6` now
  reaches the bytes through the static-control re-injection. Frozen (`[CC]`-prefixed) barriers are
  untouched, so the census / frozen round trips are unchanged by construction. Tests
  `tests/bug479_bar_sync_stall_floor.rs`.
- **`CUBIT_SB_SHARE=1` — scoreboard-sharing colouring policy (opt-in)**: scoreboards are counters;
  ptxas puts several in-flight loads on one and waits once. Under the knob a use that finds no free
  scoreboard shares the busiest one instead of draining its setter (the drain serialised a 16-load
  register prefetch), long uses (span > `CUBIT_SB_LONG`, default 256) are confined to the top two
  scoreboards, far WAR uses are released early (`CUBIT_RB_EARLY`, default 64 walked instructions).
  Effect on V's kernel: 1.09–1.13× → 0.66–0.72× of the ptxas reference, bits unchanged. **Stays
  opt-in** (see `docs/KNOWN_ISSUES.md` A13 for the measurement on the production kernels and what a
  default change needs).
- **BUG-480 — the scheduler now tracks R128–R254** (V's "BUG gpr128"): registers were keyed as
  `(uniform, u8)` with vector predicates at `128 + n`, so every GPR ≥ R128 was taken for a
  predicate — a load into R128+ got no scoreboard, a store with data in R128+ no read barrier, and a
  write to R128..R134 "redefined" P0..P6 for the predicate-latency model (V kept its kernel in R0–R125
  because of it). Predicates now live at `PRED_KEY + n` in a `u16` key space; the R128+ kernel and its
  R<128 twin schedule identically (`tests/bug480_sched_gpr128.rs`).
- V's kernel build (`vllm-moet tools/dsv41_sm120/sparse_mla_sass/build_sparse_mla_sass.sh`) reproduces
  the validated cubin **byte for byte** from this tree (2 663 words; checked 2026-11-05).
## Unreleased — 2026-11-04 (session T-4)

- **SM121a text parity to 100 %** (blackwell-isa `bb11659`, owner decision NEEDS_OWNER 17):
  the 60 remaining GB10-census text differences (`docs/KNOWN_ISSUES.md` V3) are closed. Table side
  (`blackwell-isa-internal/tools/t4_sm121a_parity.py`, SM121a is delta-driven vs SM120): the measured
  SM120 rows adopted for `R2P`, `IMNMX`, `SEL.64` (its 33-bit immediate → `-0x1`), `REDUX` (the
  duplicate op=0 `.AND` group gone), `BAR` (the era rows that baked a spurious second immediate
  replaced by SM120's per-form keys), `DEPBAR` (the `SBn` token restored); the one SM121a-only harvest
  row `UIMNMX.U64` immediate form rebuilt from the SM120 register-form layout. Printer side (shared
  with SM120): `ATOMS`/`ARRIVES` `[Rm+URn(+off)]` glyph now fires for the whole sm_120 encoding family
  (`table::is_sm120_encoding_family`, which includes sm_121a — it was gated on sm_120 only, so SM121a
  rendered the descriptor form `desc[UR][R.64]`); the `F2IP` modifier order (`.U8.F32.TRUNC.NTZ`, same
  law as F2I); the `IMMA` `.ROW`/`.COL` matrix-layout print on the A/B operands (the layout bits are
  baked ROW/COL in `and_base`, so the parser already re-encodes the identical word). Parity on the 373
  recorded mismatch words: **372 / 373** — the residue is `LEPC` (a PC-relative target the isolated-word
  census renders at address 0; byte-identical to the vendor in a full disassembly). Confirmed by the
  full GB10 census re-run at this revision (`gx4`, 2026-11-05: 91 927 / 91 927 decode, 1 text
  mismatch = `LEPC`; the sm_120 half 0 text mismatches). Test
  `tests/sm121a_parity_20261104.rs` + fixture; SM121a 23 823 → 23 825 forms / 26 380 → 26 381 variants
  (the census tests re-pinned to blackwell-isa `bb11659`).
- **SM120 `stallfix` r2ur floor measured** (silicon v3, 2026-11-04, 4× RTX PRO 6000 Server Edition):
  `floor_r2ur_d0` 11 → **4** (== `floor_global`). Harness v3 r2ur kernels with warp-uniform inputs:
  `model_r2ur` PASS, 26 floors PASS on every path (R2UR broadcasts one lane; the v2 model that summed
  per-thread values was wrong). `tests/stallfix_sm120.rs` re-pinned; `docs/KNOWN_ISSUES.md` A3 closed
  in full. The register-shadow law (A1) was re-confirmed on the same run (regcount 64 and 128 → 715),
  the LDC-bound loop passed 4/4 (A10); the LDSM FP4 fragment was executed (A3/T6, layout recorded).
- **The four blackwell-isa HTML references** regenerated with the merged `export_html.py` (origin
  lineage + the ported measured control-word layout / per-variant provenance / date·revision·SHA header;
  NEEDS_OWNER 14). `blackwell-isa-internal` merged onto origin (`1c7c4c2`, no force push).

## Unreleased — 2026-11-04

- **Tables vendored as gzip**: `tables/<arch>.json.gz` (0.5–0.9 MB each) replace the 38–59 MB
  plain files in git; `tables/SOURCE.json` still pins the SHA-256 of the decompressed JSON. The
  loader (`cubit::table::read_table_bytes` / `read_table_text`) serves `tables/sm120.json` from
  the plain file when one exists and from the `.gz` twin otherwise (30 ms), the CLI, the Python
  bindings, the tests (54 files that opened the JSON directly now go through it) and the Python
  tools (`tools/tablefile.py`) all use it; the bundled SM120 table is `include_bytes!` of the gz
  (binary 54 → 8 MB). `tools/sync_table.py` writes the gz (deterministic, mtime 0), `--check`
  decompresses and compares and rejects a stale unpacked copy, `--unpack` writes the plain JSON
  (git-ignored) for people who want it. New dependency `flate2`.
- **Silicon results of 2026-11-03** (4x NVIDIA RTX PRO 6000 Server Edition, cubit-assembled probes;
  README "SM120 laws measured on silicon"): **BUG-008** — even c reads the pair c:c+1, the PT form
  is the same, RZ zero-extends, an odd c faults (715): the encoder refuses an odd c with the
  measurement in the message (an odd destination stays a warning; `CUBIT_DISABLE_ERRATA` for RE).
  **BUG-040/075** confirmed at 64 and 128 with both controls. **BUG-362a** — `F2I` with reuse bits
  executes with the plain result; the decoder's ~130-row fail-closed arm is removed, the words
  decode (the source slot's bit prints `.reuse` and re-encodes), the fixture records the silicon
  verdict per word. **HMUL2** packed immediates 4/4. **`stallfix` for SM120**: 23 measured floors →
  rules v3 in `tables/sm120.json` (`floor_pcarry_d0/d1`, `guard_d0_forbid`, `floor_guard_d1`,
  `floor_urpath_d1`, `floor_xread_d1/d2`, `floor_uguard_d2` are new keys, all defaulting to "no
  rule" so the sm_103a v2 section is unchanged; a predicate producer directly followed by its `@P`
  guard consumer is a violation on SM120; R2UR boundaries raise to the cap until the corrected
  `r2ur` kernel runs); the harness lives in `tools/stallfloor/`; `tests/stallfix_sm120.rs`;
  `docs/SM120_STALLFIX_PLAN.md` §4. `SEL`/`FSEL`/`DSEL` read their trailing predicate in the
  Strict predicate-transfer mode.
- **Tables: era keys retired** (blackwell-isa 2026-11-04): the 20 SM120 keys with a glued predicate
  token in the mnemonic (`QMMA.16816.F16.E4M3.E4M3_P0_R_R_R_R`, `F2IP.U8.F32_P2_…`, `DMMA.8x8x4_P5_…`,
  `S2R_P0_R_L`, `MOV_P0_R_II`, …; 10 of them in sm121a) are `_meta.key_aliases` of the plain keys —
  the loader resolves an alias as an encoder-visible, decoder-invisible copy, so `bug280`/`bug340`
  and old text keep working while the decoder never prints a glued mnemonic. The DMMA.8x8x4 and
  F2FP.F16.F32.PACK_AB plain rows gained their guard field (and PACK_AB the text-inert [71:64])
  by probe; `MOV_P0`/`PLOP3.LUT_P1` had claimed UMOV/UPLOP3 words. Test
  `tests/sm120_era_keys_20261104.rs` + fixture.
- **Tables: undocumented forms stay and are marked** (owner's decision): the E3M4 block-scaled MMA
  rows (22; 11 dense combinations executed on RTX PRO 6000), the tcgen05 kinds the SM120 silicon
  runs (UTCHMMA/UTCIMMA/UTCQMMA.1CTA on RTX 5090, UTCATOMSWS) and FFMA2 carry a `_src` whose
  provenance says `nvdisasm_sm120: "no text"`; `tools/audit_dynamic.py` classifies their words as
  `vendor_unknown` (never a defect). Audit state replayed against this tree: 483 → **463 rows**
  (`docs/KNOWN_ISSUES.md` T1).
- **Printer / decoder**: `F2FP.SATFINITE…` modifier order; F2FP excluded from the sign-window
  fallback (bits 73/74/82/83 are rejected by nvdisasm, 79–81 are `???n`); the F2FP PACK_AB lattice
  recorded in the era-keys fixture.
- **Validation claims**: SM121a re-run on the GB10 host `gx4` (2026-11-04): 91 927 / 91 927 words
  decode, text parity 99.59 % (373 differences in 17 keys — the 2026-09 "0 differences" does not
  reproduce for text parity; KNOWN_ISSUES V3); the same corpus's sm_120 half revealed 97 `LDL.64
  [R+UR+imm]` decode holes and a `MUFU` UR-form function field — fixed below.
- **Tables: GB10-census follow-up** (blackwell-isa `15caf70`): `LDL_R_ARURI` (`LDL[.size][.LU] Rd,
  [Ra+URb+imm]`, 14 groups, 351 probe words; the printer prints the plain `[R+UR+imm]` sum for LDL/STL
  like LDS/STS instead of a fabricated `desc[UR][R.64+off]`), `MUFU_R_UR` rebuilt (10 functions × the
  half types they take, abs/neg on the UR operand, 494 words; four harvest rows had decoded EX2 as
  LG2 and RSQ as RCP / RCP64H; `MUFU.<fn>.F16` order; MUFU excluded from the sign-window fallback),
  `F2F.F64.F32_R_R` / `F2F.F32.F64_R_R` rebuilt on SM120 and SM121a (the sm121a rows had their
  register fields one bit off and the `F2F_R_R` harvest group swallowed 217 census words with the
  wrong type order; on SM120 that group assembled `F2F.F32.F64 R8, |R15|` without the abs), and
  **nvdisasm's `IMAD.MOV` / `.IADD` / `.SHL` display law** measured on 144 words (`.MOV` when a = RZ,
  b = RZ, b = 0, or b = 1 with c = RZ; `.IADD` when b = 1 and c is a register; `.SHL` when b is a
  power of two in 2..2^30 and c = RZ; never with a UR c): the printer derives the name, the encoder
  accepts an alias only in that shape, the seven alias-named harvest groups (which had put the Ra
  token on the Rb field: `IMAD.MOV.U32 R4, RZ, R14, 0x10` printed as `R4, R14, R14, 0x10`) are gone
  and every four-operand form has a `U32` twin. Probes `tools/probes/re_sm120_{ldl_aruri,mufu_ur,
  imad_alias}.py`, tests `sm120_ldl_aruri`, `sm120_mufu_ur`, `sm120_f2f_pair_20261104`,
  `sm120_imad_alias`. SM120: 16 107 forms / 20 894 variants.
- NaN immediates: the display print keeps the lossless payload (decision recorded in KNOWN_ISSUES A8).

## 2026-11-03 (`6392786`, after `v0.2.0`)

- **Tables: hygiene pass** (blackwell-isa `64eaa21`): the control-code bits [127:105] every harvest
  template still baked (880 SM120 / 1 670 SM103a / 1 674 SM100a / 546 SM121a variants) are cleared
  and the 43 + 17 + 17 + 52 entries without `base_op` / `operand_sig` carry them. No decode or
  encode change: census 1 811 600 / 1 811 600 identical per cubin (166 cubins), 157 / 157 cubins
  byte-identical through `disassemble --frozen → asm -T`. `tools/sync_table.py`'s baked-control
  ratchet is zero for every table now.
- **Tables: dynamic-audit batch 1** (blackwell-isa `6619782`, SM120): LDGSTS shared-address base
  field 9 → 8 bits (70 rows; `[R5+0x10]` printed as `[R261+0x10]`), the text-inert `reuse` field
  removed from 13 LDC/LDCU rows, 22 harvest rows removed whose words nvdisasm names as other
  instructions (FSETP → P2R.B3, F2FP ↔ HMMA, LOP3.LUT → SEL, QMMA → MOVM, the HMMA `_P0_`
  mnemonics); 16 126 forms / 20 883 variants; census identical. Fixture
  `tests/fixtures/sm120_audit_20261103_nvdisasm.jsonl`, test `tests/sm120_audit_20261103.rs`.
  Audit state: 1 977 flagged rows (2026-11-02) → 483 (`docs/KNOWN_ISSUES.md` T1 lists the
  remaining families); `tools/audit_dynamic.py --replay` re-scores an earlier run's words and
  nvdisasm texts against the current table, and compares the display print with the vendor while
  re-encoding the lossless print.
- **Printer**: the lossless print spells the U32 twin of a UR-indexed global address with an RZ
  base as `[RZ.U32+URm(+off)]` (the display print keeps the vendor's `[URm(+off)]`, which the
  assembler mints as the .64 twin); `BRA.U.ANY` (was `BRA.ANY.U`).
- **ELF: `a`-variant e_flags were parsed as sm_10** (`0x0600_640a`: the low byte 0x0a failed the
  `< 10` flag-byte test). Every cubin assembled with `sm100a.json` carried `.note.nv.cuinfo` SM byte
  0x0a, the legacy `.nv.compat` blob and the non-sm_100 Mercury variant, and the table could not be
  used on real sm_100 cubins without `--allow-arch-mismatch`. Fixed (`parse_sm_version`: any low
  byte below 0x10 is a flag byte); `tests/encoding.rs::ef_flags_arch_detection` pins the variants.
  Found re-verifying the SM100a corpus on cold-face-bounces-fin-02 (KNOWN_ISSUES A11).
- **BUG-040/075 WARN** is suppressed for kernels that reconfigure their register budget
  (`USETMAXREG`); the law itself is confirmed on sm_120 silicon (KNOWN_ISSUES A1).
- **BUG-362a, two text oracles**: the 30 reuse-armed F2I TRUNC lattice words are refused by
  nvdisasm 13.1 and 13.3 alike (`TABLES_opex_0` undefined value = the reuse/yield byte);
  fixture `tests/fixtures/sm120_f2i_reuse_362a_nvdisasm.jsonl`, test
  `tests/sm120_f2i_reuse_362a.rs`; the decoder stays fail-closed until the silicon probe
  (`T/gpu/kernels/f2i_reuse_362a_b{122,123,124}`) answers (KNOWN_ISSUES A12).
- **Validation claims re-run on the B300 host** (cold-face-bounces-fin-02, 2026-11-03): SM103a
  publish corpus 177 / 177 and SM100a 151 / 151 cubins byte-identical through `--frozen → asm -T`,
  strict 85 646 / 85 792 words; SM100a archive 99.924 % exact-minus-schedule over 20 024 512
  instructions (gate 99.90 PASS). The GB10 corpus is not on that host (README, KNOWN_ISSUES V1–V3).

## 0.2.0 — 2026-11-03 (tag `v0.2.0`)

**History rewritten on 2026-11-03 — clones made before that date must be re-cloned.** The committed
Cargo build directory `tests/target-suite/` (458 files, 195 MB, commit `07b331b` of 2026-09-05) was
removed from the whole history with `git filter-repo --path tests/target-suite --invert-paths
--preserve-commit-hashes`; 461 commits stay 461, every commit message, author and date is unchanged,
the tree at `main` is identical, 18 commits from `07b331b` onwards have new ids (`fd11931` → `cd88768`,
`0d51705` → `02c1b30`, `c2d83a5` → `d7413e6`, `accd984` → `fc18522`; the ids quoted in older entries
below and in commit messages are the pre-rewrite ids). Pack size 56.5 MB → 12.6 MB. `main` was
force-pushed once, with the owner's sanction; no other branch exists on the public remote.

GPU results of the 2026-11-02 night window (RTX 5090, cubit-assembled probe kernels): the packed
HMUL2 immediates behave as the register form (4/4 PASS: identity, negation, `.H1_H1` broadcast), a loop
with an LDC-loaded bound iterates exactly n times (4/4), standalone cubins launch; a kernel declared
at regcount 64 touching R62/R63 and one at regcount 128 touching R126/R127 both fault with
`CUDA_ERROR_ILLEGAL_INSTRUCTION` (715) while R60/R61 at 64 work — **the BUG-040/075 shadow law is
confirmed at 64 and 128**. The "nvcc contradicts it" note of 2026-11-02 was wrong: FlashInfer's
`sparse_mla_streaming_dsv4_nvfp4` kernels use `USETMAXREG.TRY_ALLOC.CTAPOOL 0xd8` (register
reconfiguration, `EIATTR_REG_RECONFIG`), so their text legitimately uses registers above the launch
regcount 128 (up to R213). The BUG-008 probe (one kernel with four IMAD.WIDE variants incl. an odd
pair base R7) also faulted with 715 — consistent with "an odd pair base is illegal", but the four
variants are split into separate kernels for the next window before that is recorded as measured.


Quality session over the whole public face (cubit + blackwell-isa); every change below was gated by
`tools/sync_table.py` (vendoring + the full suite), `cargo clippy --release -- -D warnings` on the
host (1.95.0) and CI (1.99.1) toolchains, the strict census over the production kernel set and the
strict round trip of the project's own kernels.

### ISA table: SM120 census at 100 %
- Vendored blackwell-isa `77a3dfa`: `HMUL2_R_R_FI_FI` (packed-immediate multiply, 12 664 census
  words), `LDSM_R_ARI` FP4/FP6 unpacking loads (`U4x16P64TO8` / `U6x16P32TO8`, 576 words),
  `PRMT_R_R_UR_R` (uniform selector, 544), `ARRIVES_ARURI` (`ARRIVES.LDGSTSBAR.64[.ARVCNT]`, 297),
  `UTMASTG` 1D/2D/4D/5D (36). Each measured with nvdisasm 13.1 (`tools/probes/re_sm120_*.py`,
  fixtures `tests/fixtures/sm120_*_nvdisasm.jsonl`, tests `tests/sm120_*.rs`). The strict census of
  the 169 production cubins (1 811 600 instructions: FlashInfer sparse-MLA, CAKE DSV4.1, MXFP8
  GEMM, b12x MoE, DeepGEMM) is now **1 811 600 / 1 811 600** (was 1 797 483).
- Printer: `LDSM.U4x16P64TO8.M816.2` / `ARRIVES.LDGSTSBAR.64.ARVCNT` modifier order; ARRIVES
  prints the `[URn(+off)]` / `[Rm+URn(+off)]` address like ATOMS. Decoder: ARRIVES and PRMT are
  excluded from the sign-window fallback (a PRMT neighbour with bit 63 set used to decode as an
  arbitrary `.RC16` mode).
- Table metadata: `_meta.provenance` (legend, every `_src` tag documented with tool/test, the former
  loose `_meta.bugNNN` notes under `history`); `tools/sync_table.py --validate-only` enforces it and
  rejects undocumented top-level records.

### Table audit (static + nvdisasm cross-check)
- `tools/audit_table.py` over `sm120.json` (20 905 variants, 1 565 with `_src`): 6 410 operand bytes
  baked into `and_base` without a field (4 316 in the immediate window), 1 223 fields addressing an
  operand token the key does not have, 994 `reg`/`ureg` fields off the standard slots, 257
  immediate-bearing keys without an immediate field, 1 462 masks narrower than their fields,
  14 634 same-opcode row pairs separated only by the decoder's tiebreak (10 438 on opcode 0x97e).
  Output: `static_findings.jsonl` (session `T/audit/`).
- `tools/audit_dynamic.py` + `examples/audit_words.rs`: 88 388 probe words over the 6 000 flagged
  rows (canonical word + each field at its boundary values), nvdisasm 13.1 vs cubit decode + print
  + re-encode: 51 526 identical and bit-exact, 27 855 decoded through a sibling row with the same
  text, 437 rejected by both; **1 977 rows with at least one defect**: 6 288 text mismatches (3 584
  HSETP2 / 144 ISETP / 247 F2FP modifier order — fixed in the printer below; 906 LDGSTS words whose
  9-bit base field prints `R261`; LEA.HI.X rows dropping the trailing predicate; `F2FP_R_R
  BF16,F32,PACK_AB` missing its UR operand; `BRA.DIV URZ`/`BRA.CONV` glyphs; ATOMG `.64` address
  width), 1 403 re-encode mismatches (1 129 `LDG … ELL2.256` rows with an RZ base), 671 words of 194
  rows that nvdisasm rejects but cubit decodes (`LDG … CONSTANT.SM.PRIVATE`, `MOV.64_R_UR_II_?`,
  ATOMG CAS with a real output predicate, IMMA/UTC* field values), 208 words of 27 rows whose own
  canonical word cubit cannot decode (FSETP rows whose word nvdisasm names FSEL/P2R; F2I with reuse
  bits — accepted by nvdisasm 13.1, rejected by cubit per the 13.3.73 measurement of BUG-362a).
  None of these rows is reached by the production census; the list is `docs/KNOWN_ISSUES.md` T1 and
  the per-row data is in the session's `T/audit/dyn/`.
- Printer: `HSETP2.<cmp>.H_AND.FTZ.<bool>`, `ISETP.T.<width>.<bool>`, `F2FP.RELU.<types>` now follow
  nvdisasm's order (3 975 of the mismatching probe words).

### Assembler path for whole-cubin reassembly (`disassemble --frozen` → `asm -T`)
- `.param` declarations reproduce `EIATTR_KPARAM_INFO` exactly: new type `b8[N]` for by-value
  aggregates, per-parameter `offset=` / `space=` / `logalign=` attributes, `CBANK_PARAM_SIZE` as the
  unrounded end of the last parameter (768 census kernels measured). `--frozen` writes them;
  `asm -T` / `--eiattr-from` compare every parameter with the reference and print the declared vs
  recorded layout and the declarations to use (previously: an 8-byte `.param u64` for a 112-byte
  struct and a one-line refusal).
- New directive `.regcount N`: the exact `EIATTR_REGCOUNT` (ptxas records the highest register
  touched + 3, unrounded; cubit's `.reg`-derived count rounds to 8). `--frozen` writes it; on a
  template rebuild whose instruction payload changed, the register-count floor is the `.entry`'s
  own count (never the byte-lane guess), the rebuild **refuses** a count that moves the kernel to
  another allocation class (units of 8 registers per thread; e.g. 128 → 136 = 16 → 15 resident
  warps per SM) unless `--allow-regcount-change`, and the effective `EIATTR_REGCOUNT in cubin` is
  printed after the write.
- EIATTR: identifiers corrected against `cuobjdump` (0x05 MAX_THREADS, 0x0a PARAM_CBANK, 0x12
  MIN_STACK_SIZE, 0x17 KPARAM_INFO, 0x1e CRS_STACK_SIZE, 0x36 SW_WAR, 0x4a VRC_CTA_INIT_COUNT, 0x4c
  NUM_BARRIERS, …); fmt byte 3 is a 16-bit value (`CBANK_PARAM_SIZE` 0x300 of the DeepGEMM MQA
  kernels was read and written as 0); the global `.nv.info` REGCOUNT / FRAME_SIZE records are now
  attributed to the kernel by symbol index (a multi-kernel cubin handed every kernel the last
  record's value).
- New `tools/asm_roundtrip.py`: frozen → `asm -T` → byte comparison with a per-section explanation
  (`.text` words, EIATTR records, Mercury, string tables), `__raw__` words counted. Result at this
  revision: **157 / 157** code-bearing census cubins and the project's own kernels (`v5_final`,
  `v6_retile`, spec B) byte-identical.
- BUG-008 (`IMAD.WIDE` with a register c): the even-register pair idiom nvcc emits (`Rd:Rd+1 =
  Ra*Rb + Rc:Rc+1`, 190 sites in the MoE kernels) no longer warns; an **odd** base register of c or
  d warns, naming the register and the pair; `CUBIT_NOTE_IDIOMS=1` prints an informational note for
  the idiom. The silicon re-check of the pair semantics is a listed GPU item (`docs/KNOWN_ISSUES.md`).
- BUG-040/075 shadow-register warning stays a warning under `.regcount`: nvcc's own
  `sparse_mla_streaming_dsv4_nvfp4` kernel touches R126/R127 at `EIATTR_REGCOUNT` 128
  (`docs/KNOWN_ISSUES.md`).

### Repository
- `cargo clippy --release -- -D warnings` clean on 1.95.0 and 1.99.1 (10 library + 3 binary lints
  fixed, the `-A clippy::if_same_then_else` CI exception dropped); `cargo doc --no-deps` free of
  rustdoc warnings (184 fixed); CI runs both.
- `tests/target-suite/` — a Cargo build directory of 458 files (195 MB) committed in `07b331b` —
  removed from the tree and ignored (history unchanged).
- The twelve `tools/re_sm120_*.py` probes moved to `tools/probes/` with a README that names what
  each measured and which rows and tests cite it; `tools/audit_table.py` (static table audit),
  `tools/audit_dynamic.py` + `examples/audit_words.rs` (nvdisasm cross-check), `tools/gen_tests_index.py`
  → `docs/TESTS.md` (index of the 425 test files).
- CLI help texts without internal codenames; `cubit --help` describes the tool.
- `docs/KNOWN_ISSUES.md`: every known shortcoming with status, evidence and what it needs;
  `docs/SM120_STALLFIX_PLAN.md`, `docs/SCHED_LEGALITY_ORACLE.md`.
- README rewritten; `Cargo.toml` version 0.1.0 → 0.2.0.

## 2026-11-02 (`accd984`) — SM120 ATOMS `[R+UR+imm]`, STSM.8.MT168, UBLKPF.L2
Vendored blackwell-isa `137cd34`. The last three forms of FlashInfer 0.7.2's sparse-MLA prefill
cubin: `ATOMS_R_ARURI_R / MAX,S32` re-measured (the harvest row read the UR byte as a fourth
register), `STSM_ARI_R` 8-bit MT168 groups, `UBLKPF.L2` with and without `desc[UR]`. Printer:
the 8-bit datatype prints before the shape (`STSM.8.MT168.4`, `LDSM.8.MT1616.2`). Both sparse-MLA
census cubins round-trip completely (544 064 / 544 064 and 544 200 / 544 200). Suite 2 496 tests.

## 2026-10-29 (`4737391`) — SM120 F2FP.BF16.E8.UNPACK_B
Vendored blackwell-isa `f1e02b3`: the UE8M0 → BF16x2 unpack (48 words of the DSV4.1 BF16 prefill
kernel). Suite 2 483 tests.

## 2026-10-26 (`f8605f6`) — SM120 CCTL `.E` register-address forms
Vendored blackwell-isa `8d26508`: the seven missing `CCTL.E` operations (PF1, WB, IV, RS, PML2,
DML2, RML2). Found by the image gate on `moe_l2_discard`; every extension cubin of vLLM-Moet image
r21 (11 cubins, 504 128 instructions) round-trips.

## 2026-10-23 (`e4aed20`) — SM120 CS2UR
Measured uniform guard, URd and system-register fields (blackwell-isa `59561b2`); the junk
`CS2UR_UR_II` row is gone.

## 2026-10-22 — control-code legality, byte-exact semantic round trips, LDSM.8
- `80d7495`: the encoder rejects the reserved SM120 yield/stall combinations (yield with stall 0 or
  12–15; `docs/SM120_CONTROL_OPEX.md`, fixture of all 32 combinations on six anchors).
- `73455d8`: `roundtrip-strict` compares complete 128-bit words (scheduling included), forbids
  `__raw__` words and `!rsd` residue overlays, and writes a report with SHA-256 pins.
- `845e43e`: scheduling claims of the `IMMA.SF.16832.U8.U8` row qualified as unvalidated.
- `5122015`: `LDSM.8.MT1616` x1/x2 (blackwell-isa `afa885f`).

## 2026-08-28 … 09-19 — fleet waves 1–10 (BUG-207 … BUG-476)
Ten batches of encoder/decoder findings with their table grafts (blackwell-isa canonical cuts
`b3efa8f` … `96372cb`): vendor-parity of sign windows, LDG/STG `ELL2.256` and `dARI` lattices,
LDGSTS descriptor forms, F2I/F2FP/HFMA2/HADD2 lattices, SHFL windows, LDS/STS/LDSM/STSM address
scales and enums. Each finding is a `tests/bugNNN_*.rs` file (`docs/TESTS.md`).

## 2026-08-25 … 08-27 — O2 layout and the wave-2/3 landings (BUG-127 … BUG-206)
- `9e2d9cd` / `711f20c`: one canonical table per architecture under `tables/` with a single
  `tables/SOURCE.json` manifest pinned to a blackwell-isa revision; `1e1a5b2`: all four tables
  (sm120, sm103a, sm100a, sm121a) vendored.
- `7d53405` BUG-127: deterministic multi-kernel emission order in `cubit asm`.
- LDC/LDCU constant-address windows (BUG-162…175), ATOM/REDG/ATOMS descriptor forms (BUG-142…161),
  SYNCS render parity (BUG-157), nvdisasm numeric glyph laws for immediates (BUG-146, BUG-177).

## 2026-07-31 — SM103a
ISA table derivation and architecture guard for sm_103a (B300), the `!rsd[..]` residue
annotations for the legacy round trip, the SM103a regression battery.

## 2026-06-25 — initial public release (0.1.0)
SM120 assembler/disassembler, `asm` with `.entry` directive format and template (`-T`) rebuilds,
`disassemble`, `roundtrip`, `patch`, `encode` / `decode`, Mercury (`.nv.capmerc`) emission,
automatic scheduling, Python bindings.

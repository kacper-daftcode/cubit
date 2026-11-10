# Harness v5e and the slot census (2026-11-10): the dependency-latency table beyond the kernel it was built for

`tables/dep_latency_sm120.json` (`CUBIT_SCHED2_LAT=sm120`, KNOWN_ISSUES A26) was mined and measured for the pairs the
sparse-MLA attention kernel binds on. The other hand-written kernels that are assembled with the automatic scheduler —
the MoE GEMM kernels on 2-bit / FP4 / quintal weight planes (`QMMA.SF`, a `PRMT` LUT decode, 64-bit address arithmetic)
and the state-prefill kernel — bind on other pairs. The v5e files of this directory are the evidence for those: 92
auto-scheduled production sources, 53 954 binding register requirements per warp under the three switches
(`CUBIT_SCHED2=1 CUBIT_SCHED2_LAT=sm120 CUBIT_MMA_PTXAS=1`), every one of them now on a silicon run or an MMA row, none
above what the table charges. Nothing here changes the table or the scheduler; `tests/dep_latency_corpus.rs` pins what
the files say against the table.

| file | role |
|---|---|
| `slot_census.py` | the ptxas pair census of `dep_latency_census.py` for the two instruction forms the register-liveness model does not know — the 7-operand `QMMA.SF` form and `IADD.64` (`depdump` prints `known: false`, no defs, no uses), so `census_pairs_sm120.json` has no row with either as producer or consumer. Their operands are taken from the operand slots; walk, classes and roles are the original's |
| `census_pairs_slots_sm120.json` | its rows over the 166 frozen sm_120 listings (12 448 QMMA): 142 (producer, consumer, role) rows with QMMA or IADD.64 on either side, 146 962 pairs |
| `qmma_census.py` | the same listings around QMMA only, including what is not a register pair: the issue spacing between two MMAs |
| `pairfloor_gen_e.py` | CPU side, the harness v5 skeleton and oracle (one S15 reference kernel per pair): the LUT decode (`IMAD → PRMT`, `PRMT → LOP3`, `LOP3 → PRMT`), 64-bit address arithmetic (`SHF → IMAD.WIDE` multiplier, producers → either operand of `IADD.64`, `IADD.64 → IADD.64`), `IADD.64` → the address of a global store / load, store data, guards of `BRA` / `EXIT`, the QMMA rows (result → `FFMA` on each of the four result registers, → the accumulate operand of the next QMMA, two QMMAs back to back; distance = S + 15 × pad), producers → QMMA / HMMA operands, uniform loop counters (`UIADD3 → UISETP`, `UMOV` / `R2UR → UIADD3`) |
| `pairfloor_run_e.py` | GPU side: `pairfloor_run.py` plus a per-thread scratch buffer as third kernel parameter (a global store's address probe writes its own words there), a shared read-only table for the load probe, and one process per pair (`--isolate`) |
| `stall_floors_sm120_20261110_pairs_e.json` | the result: 31 pairs, 874 probe kernels, two card types (`run`, `run_rtx`, `run_new_pairs` say what was launched where) — identical floors and an identical clean / dirty verdict of every kernel in every run |
| `mma_result_registers_sm120_20261110_qmma.json` | the reader of a QMMA result by result register (`qmma_data`, `qmma_data_r1..3`: 165 kernels, distance 1 … 45), in the layout of `mma_result_registers_sm120_20261110_em.json` (what `gen_dep_latency.py --mma-registers` reads): registers 0 / 1 clean from 20, **registers 2 / 3 from 28** — the HMMA picture |

```bash
python3 tools/stallfloor/slot_census.py <dir with *.dep.jsonl> census_pairs_slots_sm120.json tables/dep_latency_sm120.json
python3 tools/stallfloor/qmma_census.py <dir with *.dep.jsonl> qmma_census.json
python3 tools/stallfloor/pairfloor_gen_e.py --cubit target/release/cubit --table tables/sm120.json.gz --out kernels_pair_e/
python3 tools/stallfloor/pairfloor_run_e.py kernels_pair_e/ --reps 20 --isolate --out floors_e.json      # on the GPU host
```

## What the census says (ptxas's practice through QMMA and IADD.64)

| pair | pairs | minimum | at the minimum | the table charges |
|---|---|---|---|---|
| QMMA → FFMA (a reader of the result) | 13 204 | 28 | 1 092 | 28 (MMA row) |
| QMMA → FMUL (a reader of the result) | 758 | 28 | 28 | 28 (MMA row) |
| QMMA → FADD (a reader of the result) | 320 | 28 | 52 | 28 (MMA row) |
| QMMA → MOV (a reader of the result) | 504 | 28 | 28 | 28 (MMA row) |
| QMMA → the accumulate operand of the next QMMA | 8 222 | 29 | 3 228 | 29 (MMA row) |
| QMMA → the next QMMA, issue spacing | 11 764 | 16 | 5 095 | 16 (MMA spacing) |
| PRMT → QMMA B fragment | 11 856 | 7 | 1 110 | 7 (fragment default) |
| LOP3 → QMMA B fragment | 1 232 | 7 | 336 | 7 (fragment default) |
| LOP3 → QMMA scale register, A side | 4 376 | 7 | 126 | 7 (fragment default) |
| LOP3 → QMMA scale register, B side | 928 | 7 | 42 | 7 (fragment default) |
| MOV → QMMA A fragment | 1 778 | 7 | 70 | 7 (fragment default) |
| MOV → QMMA accumulate operand | 414 | 7 | 28 | 7 (fragment default) |
| IMAD → QMMA B fragment | 1 528 | 7 | 69 | 7 (fragment default) |
| IADD.64 → LDG address | 4 592 | 6 | 867 | 6 (default) |
| IADD.64 → STG address | 2 596 | 6 | 145 | 6 (default) |
| IADD.64 → LDGSTS address | 2 523 | 6 | 102 | 6 (default) |
| IADD.64 → IADD.64 (first operand) | 3 420 | 4 | 1 568 | 6 (default) |
| IMAD → IADD.64 (first / second operand) | 1 880 / 805 | 5 / 5 | 20 / 104 | 6 (default) |
| IMAD.WIDE → IADD.64 (first / second operand) | 3 738 / 1 596 | 5 / 5 | 714 / 255 | 6 (default) |
| MOV → IADD.64 (first / second operand) | 1 850 / 1 893 | 5 / 5 | 102 / 1 267 | 6 (default) |
| SHF → IADD.64 (first / second operand) | 416 / 373 | 5 / 5 | 63 / 64 | 6 (default) |
| LOP3 → IADD.64 (first / second operand) | 1 298 / 2 752 | 5 / 5 | 49 / 737 | 6 (default) |
| IADD3 → IADD.64 (first / second operand) | 178 / 886 | 6 / 5 | 2 / 13 | 6 (default) |

The MMA rows are ptxas's numbers for QMMA exactly, and no default is below ptxas's dense practice on these classes. Rows
whose minimum is a sharp peak above the price exist — `IADD.64 → LEA` r3 9 × 875, `LOP3 → QMMA` r2 9 × 308, `LEA → IADD.64` r1 9 × 126 —
the "minimum ≤ 7 or default" rule of the table generator does not see them. None of these pairs occurs in the production
sources; they are candidates for cells when a kernel that uses them is scheduled from the table.

## What the silicon says

32 CTAs × 1 024 threads × 256 iterations × 20 launches per kernel; floors at distance 0 / 1 / 2 (fillers between producer
and consumer). Two card types: RTX PRO 6000 Blackwell Server Edition (core clock ≤ 2 370 MHz, two runs) and Workstation
Edition (core clock up to 2 820 MHz, two runs of the first 20 pairs, three of the last 11, two of the QMMA result
registers). **Every floor and the clean / dirty verdict of every one of the 978 swept kernels is the same in every run
on both cards** — down to the fraction of wrong threads one cycle below a floor: a floor here is a count of issue
cycles, not a setup time.

| pair (role) | floor d0 / d1 / d2 | the table charges |
|---|---|---|
| QMMA result registers 0 / 1 → FFMA | **20** (wrong at every distance 1 … 19) | 28 (MMA row) |
| QMMA result registers 2 / 3 → FFMA | **28** (wrong on every thread to 24, on a quarter of them at 27) | **28 (MMA row) — at the floor** |
| QMMA → the accumulate operand of the next QMMA; two QMMAs back to back | clean at every distance 1 … 30 (the tensor pipe interlocks them) | 29 / 16 |
| ISETP → BRA (gc) | 13 / 11 / 9 | **13 (cell) — at the floor** |
| ISETP → EXIT (gc) | 13 / 11 / 9 | **13 (cell) — at the floor** |
| SHF → HADD2.F32 (r2) | 5 / 4 / 1 | 6 (default) |
| F2FP.PACK → HMMA (r2h) | 2 / 1 / 1 | 7 (cell) |
| IADD.64 → IADD.64 (r1) | 4 / 1 / 1 | 6 (default) |
| IMAD → IADD.64 (r1) | 4 / 3 / 1 | 6 (default) |
| SHF → IADD.64 (r2) | 5 / 3 / 1 | 6 (default) |
| SHF → IMAD.WIDE (r2) | 4 / 3 / 1 | 7 (cell) |
| IADD.64 → LDG (a1) | clean from S01 | 6 (default) |
| PRMT → LOP3 (r2) | 4 / 1 / 1 | 6 (default) |
| IMAD → PRMT (r2) | 5 / 3 / 1 | 6 (default) |
| LOP3 → PRMT (r2) | 4 / 1 / 1 | **4 (cell) — at the floor** |
| LOP3 → QMMA (r5) | 4 / 3 / 1 | 7 (fragment default) |
| MOV → QMMA (r3) | clean from S01 | 7 (fragment default) |
| MOV → QMMA (r3h) | clean from S01 | 7 (fragment default) |
| PRMT → QMMA (r2) | 2 / 1 / 1 | 7 (fragment default) |
| IADD.64 → STG (a0) | clean from S01 | 6 (default) |
| LOP3 → HMMA (r2h) | 2 / 1 / 1 | 7 (fragment default) |
| IADD3 → IADD.64 (r2) | 5 / 3 / 1 | 6 (default) |
| IMAD → IADD.64 (r2) | 4 / 3 / 1 | 6 (default) |
| IMAD.WIDE → IADD.64 (r1) | 4 / 3 / 1 | 6 (default) |
| MOV → IADD.64 (r2) | 5 / 3 / 1 | 6 (default) |
| FFMA → STG (r1h) | clean from S01 | 6 (default) |
| FMUL → STG (r1) | 3 / 1 / 1 | 6 (default) |
| SHF → STS (r1) | 3 / 1 / 1 — a weak probe (its reference checksum takes two values; a quarter of the threads discriminate) | 6 (default) |
| R2UR → UIADD3 (u1) | 8 / 6 / 4 | 13 (uniform default) |
| UMOV → UIADD3 (u1) | clean from S01 | 4 (cell) |
| UIADD3 → UISETP (u0) | 4 / 1 / 1 | **4 (cell) — at the floor** |

QMMA behaves as HMMA does, register for register: a reader of result registers 0 / 1 needs 20 issue cycles, of
registers 2 / 3 28 — the `to_data` row exactly, as `mma_result_registers_sm120_20261110_em.json` shows for HMMA — and the
accumulate chain and the issue spacing are enforced by the tensor pipe itself. In the 89 MoE sources under the three
switches the first reader of result register 0 / 1 / 2 / 3 is 28 / 29 / 36 / 37 cycles behind its QMMA at the earliest. An address is read when the memory pipe serves the instruction (`IADD.64 → STG` /
`LDG` clean from S01), as `stall_floors_sm120_20261110_store_addr.json` shows for `STS`. A uniform register written through `R2UR` is the slowest path measured
on sm_120 so far: 8 issue cycles (the uniform default is 13). **Five prices are exactly the floor** —
the MMA reader row (28) for result registers 2 / 3, and `ISETP → BRA` gc, `ISETP → EXIT` gc, `LOP3 → PRMT` r2, `UIADD3 → UISETP` u0 — they must not be lowered; everything else has at least one cycle of margin. The additive
model (the sum of the stalls from producer to consumer ≥ the pair's latency) holds on every d1 / d2 floor.

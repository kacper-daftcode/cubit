# SM120 stall-floor harness

The measurement behind the `stallfix` section of `tables/sm120.json` (rules v3; the pass is
`cubit stallfix`, the plan and the reading of every floor is [docs/SM120_STALLFIX_PLAN.md](../../docs/SM120_STALLFIX_PLAN.md)).

| file | role |
|---|---|
| `stallfloor_gen.py` | CPU side: one cubit-assembled kernel per (dependency path, distance d ∈ {0,1,2}, producer stall S ∈ {0..11}) plus one scoreboarded reference kernel per path — 370 cubins, every control code frozen, `index.json` |
| `stallfloor_run.py` | GPU side (CUDA driver API through `culaunch.py`): 32 CTAs × 1 024 threads × 20 repetitions per kernel, per-thread checksums against the CPU model, the model proven against the reference kernel first; writes `stall_floors.json` in the layout of the rule keys |
| `culaunch.py` | ctypes driver-API helper (shared with the other probe kernels) |
| `stall_floors_sm120_20261103.json` | the run of 2026-11-03 18:05Z on 4x NVIDIA RTX PRO 6000 Server Edition (harness v2): 23 floors, `r2ur` model mismatch, `mufu`/`guard d0` need the scoreboard |

```bash
python3 tools/stallfloor/stallfloor_gen.py --cubit target/release/cubit --table tables/sm120.json --out kernels_stall/
python3 tools/stallfloor/stallfloor_run.py kernels_stall/ --reps 20 --out stall_floors.json     # on the GPU host
```

Reading a floor: the smallest producer stall with zero mismatching threads over all repetitions such
that every larger stall is clean too. S00 is clean on every path at every distance (including MUFU):
on sm_120 a stall count of 0 behaves as a hardware interlock, not as "no stall", and is never used as
a floor. v3 (2026-11-04) fixes the `r2ur` path: `R2UR UR, R` broadcasts one lane's register, so its
inputs are warp-uniform now (regenerate with `--paths r2ur`); its floor is the one measurement still
owed, and until it exists the rules carry `floor_r2ur_d0 = cap_stall`.

## Harness v5 / v6 (2026-11-10): pair floors, populations per cell, the dependency-latency table

The measurement behind `tables/dep_latency_sm120.json` (`CUBIT_SCHED2_LAT=sm120`, `src/dep_stall.rs`; KNOWN_ISSUES A26).
The oracle of every probe is the GPU's own safe schedule — a reference kernel with the tested producer at S15 — so no CPU
model of an instruction is needed and any producer / consumer pair cubit can assemble can be measured.

| file | role |
|---|---|
| `pairfloor_gen.py`, `pairfloor_gen_b.py`, `pairfloor_gen_c.py` | v5, CPU side: one kernel per (pair, distance 0..2, producer stall, yield) + the S15 reference per pair. `_b`: scoreboard arming (setter with / without yield, waiter 1..3 behind), MMA rows (distance = S + 15 × pad), memory operands. `_c`: address operands of loads and stores, → `SHFL`, `STG` data, guards of memory instructions, the high half of an `IMAD.WIDE` addend — with what `_b`'s memory probes got wrong fixed (a stale address is still a valid address; no bare store is rewritten behind; a store's slot is read back position-weighted) |
| `memdata_gen.py` | v5: producer → store data (`STS`, the last register of `STS.128`) |
| `pairfloor_gen_d.py` | v5: the scaled BF16 unpack (`F2FP.BF16.<E4M3\|E2M1>.UNPACK_B Rd, Rs, Rscale.B0`, opcode 0x63e; class `F2FP.UNPACK`) as a producer (→ `STS` data, → the last register of `STS.128`, → `HMUL2` either operand) and as a consumer (`SEL` / `SHF` → its source, `MOV` → its scale register) — the pairs of a dequant written with it |
| `pairfloor_run.py` | v5, GPU side: 32 CTAs × 1 024 threads × 256 iterations × `--reps` launches per kernel; `FLOOR <pair> d<d> = Sxx` = the smallest clean stall with every larger one clean |
| `cellfloor_gen.py`, `cellfloor_run.py` | v6: populations per table cell — N kernels at the cell's latency L (must all pass) and at L − 1 … (the sensitivity side), each a random draw of registers, yield flag and 0–3 unrelated neighbours in front of the producer |
| `latch_gen.py`, `latch_run.py`, `latch_summary.py` | the store-latch probe: a bare `STS` / `STG` whose data / address register is overwritten d issue cycles behind it; controls without the overwriter and with a read barrier; geometries 32 × 1 024, 376 × 1 024, 188 × 32 (one warp per SM), and the load series 188 × 64 … 1 024 (2 … 32 warps on every SM) |
| `dep_latency_census.py` | ptxas's practice: the minimum issue distance per (producer class, consumer class, operand role) over frozen listings (`cargo run --release --example depdump -- k.frozen.sass > k.dep.jsonl` per cubin) |
| `gen_dep_latency.py` | builds the table from the census pairs and the result files; a measured floor above a cell raises it, a floor below it is recorded only |
| `census_pairs_sm120.json` | the pair matrix of the sm_120 census (166 nvcc / ptxas cubins, 1 811 600 instructions): 1 109 (producer, consumer, role) rows with their distance histograms |

```bash
# the table, byte for byte, from the files of this directory
python3 tools/stallfloor/gen_dep_latency.py tools/stallfloor/census_pairs_sm120.json tables/dep_latency_sm120.json \
    --floors tools/stallfloor/stall_floors_sm120_20261110_{pairs,pairs_b,store_data,pairs_c,store_addr,pairs_d}.json \
    --v6 tools/stallfloor/stall_floors_sm120_20261110_{cells,cells_b}.json
# a run (CPU: kernels; GPU host: launches)
python3 tools/stallfloor/pairfloor_gen.py --cubit target/release/cubit --table tables/sm120.json.gz --out kernels_pair/
python3 tools/stallfloor/pairfloor_run.py kernels_pair/ --reps 20 --out floors.json
```

Result files (test host, 4× NVIDIA RTX PRO 6000 Server Edition, GPU 0, 400 W, core clock ≤ 2 430 MHz; each file's `run` key
says what was launched):

| file | what it holds |
|---|---|
| `stall_floors_sm120_20261110_pairs.json` | 45 pair floors (ALU, fp16 / fp32, predicate → select / guard), d0–d2. Every floor ≤ its cell; same unit 4, cross unit 5, predicate → select 5, → guard 13 (d1 11, d2 9). The yield flag on the producer does not move a floor (five pairs; the guard pair with yield stops at S11 — yield with S12–S15 is reserved on sm_120 — and is wrong at every stall to 11, as without it) |
| `stall_floors_sm120_20261110_pairs_b.json` | scoreboard arming: a `MUFU` / `SHFL` / `LDC` / `LDS` setter with yield at S01 and its waiter next — 655 360 of 655 360 threads wrong; without yield, at S02, or one instruction between — 0. `LOP3` → HMMA fragment 2, `HMUL2` → `STS` data 3. The `IMAD.WIDE` → `LDG` address pair is clean at S04–S08 and faults at S03 (the stale address); the run ended there. The two shared-memory address pairs have no result: their references were not deterministic (the probes carry bare stores whose registers are rewritten behind them — the store-latch race below) |
| `stall_floors_sm120_20261110_cells.json` | v6: 200 cells of 19 producer classes, 20 624 kernels × 3 launches. At L − 1: 8 958 of 10 312 fail. At L: 99 fail, all `IADD3` / `MOV` / `SHF` → the addend of `IMAD.WIDE` at 4 — the role merged the addend's two registers; the table now has `r3` (low half: 5 / 5 / 6, ptxas's minimum for that register) and `r3h` (high half: ptxas from 3, priced 4) |
| `stall_floors_sm120_20261110_cells_b.json` | v6, 13 cells × stalls L − 3 … L + 1 × 64 kernels × 10 launches: the corrected `IMAD.WIDE` addend cells (fail one below, clean at L) and seven pairs the attention kernel prices with the default 6 (floors 4–5) |
| `stall_floors_sm120_20261110_mma.json` | HMMA result → `FMUL`: wrong at every distance ≤ 19, clean from 20 (table 28). HMMA → the accumulate operand of the next HMMA, and two HMMAs back to back: clean at every distance 1…30 — the tensor pipe interlocks them; the rows 29 / 16 are ptxas's spacing, not a silicon floor |
| `stall_floors_sm120_20261110_store_data.json` | `F2FP.PACK` / `FADD` / `FSEL` / `IADD3` → `STS` data: 3 (cells 5); the last register of `STS.128`: clean from S01 (read late) |
| `stall_floors_sm120_20261110_pairs_c.json` | the cells the attention kernel binds on that were census-only (two identical runs): `F2FP.PACK` / `FSEL` → `STG` data 3, `FADD` / `FMNMX` → `SHFL` 3, `IADD3` / `IMAD` → `LDS` address 4 (cells 5); `ISETP` → the guard of a store / a load 13 / 11 / 9 at d0 / d1 / d2 (cell 13); `SHF` → `IADD3` second addend 4 (default 6); the high half of an `IMAD.WIDE` addend and the `IMAD.WIDE` → `LDG` address low half clean from S01 |
| `stall_floors_sm120_20261110_store_addr.json` | `IADD3` / `IMAD` → the address of `STS`, position-weighted read-back: clean from S01 at d0–d2 (cells 5) — a store reads its address when the memory pipe serves it |
| `stall_floors_sm120_20261110_pairs_d.json` | the scaled BF16 unpack: `MOV` → its scale register 5, `SEL` → its source 5, `SHF` → its source 4; its result → `HMUL2` 5 (either operand), → `STS` data 3, → the last register of `STS.128` 1 — the numbers of the plain forms of its class (`F2FP.UNPACK` → `HMUL2` 5, `F2FP.PACK` → `STS` 3 / 1, `SEL` / `SHF` → `F2FP.UNPACK` 5 / 4): no cell and no default is below one of them, none was added |
| `store_latch_sm120_20261110.json` | bare `STS` / `STG`, data or address register overwritten 1…45 cycles later, 32 warps per SM: wrong on every thread to 19, 62–98 % of threads at 20–30, still 1–9 % at 45. The references at 64 warps per SM and of `STS.128` (overwriter at 60) were not deterministic |
| `store_latch_sm120_20261110_controls.json` | the same to 75 cycles (reference at 105) with controls: 32 warps per SM — last mismatch at 48 (`STS`) / 56 (`STG`); one warp per SM — clean from 1; no overwriter — clean; read barrier + waiting overwriter — clean. A bare store reads its operands when the memory pipe serves it (KNOWN_ISSUES A27) |
| `store_latch_sm120_20261110_series.json` | the load series: one CTA per SM on 188 SMs with 1 / 2 / 4 / 8 / 16 / 32 warps storing in lockstep, the data register overwritten 1…60 cycles behind the bare store. Last distance with a wrong thread — `STS`: none up to 8 warps, 12 at 16, 48 at 32; `STG`: none up to 4 warps, 6 at 8, 38 at 16 (reference not deterministic at 32). The distance a bare store needs grows with the number of warps that have stores in flight |

Reading the numbers. A pair floor is a count of issue cycles of a synchronous pipeline, measured at the test host's core
clock; a kernel scheduled from the table is to be bit-checked at the production clock before it ships. The additive model
(the sum of the stalls from producer to consumer on every control-flow path ≥ the pair's latency) holds on every d1 / d2
floor measured here and on the 26 floors of 2026-11-03.

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
| `mma_result_registers_sm120_20261110_em.json` | `HMMA` result register k → `FMUL` / `FADD` with nothing waited, per register and distance (23…32; 60 kernels × 20 launches, 32 CTAs × 1 024 threads × 256 iterations; measured by a second session with its own probe kernels, family `mr2`): registers 0 / 1 clean over the range (their floor is 20), **registers 2 / 3 wrong up to 27 and clean from 28** — the table's MMA → reader row is their floor exactly; `gen_dep_latency.py --mma-registers` checks the row against it and writes the note |
| `census_pairs_sm120.json` | the pair matrix of the sm_120 census (166 nvcc / ptxas cubins, 1 811 600 instructions): 1 109 (producer, consumer, role) rows with their distance histograms |
| `result_register_census.py`, `census_pairs_result_sm120.json` | the same census for the fixed-latency producers that write more than one register (`IMAD.WIDE`, `MOV.64`, `SEL`), split by which register of the result the consumer reads: 80 rows, 63 701 pairs. ptxas reads the LOW register of an `IMAD.WIDE` result from 3 issue cycles (`→ LOP3` 3 × 36, `→ IADD3` second addend 3 × 8) and the HIGH one never closer than 5 (`→ IADD3` 5 × 2 100, `→ SHFL` 5 × 758), or 4 into the multiplier (`→ IMAD` 4 × 403 / 4 × 808, the high half of the next `IMAD.WIDE`'s addend 4 × 354) |
| `stall_floors_sm120_20261110_em_blk3.json` | a second session's probe by result register (392 kernels × 3 geometries — 32 × 1 024, 188 × 256, 188 × 32 threads — × 20 launches; families `wh`, `cs` are the table's): `IMAD.WIDE` low / high register → `IADD3` 3 / 5, `LEA` 3 / 5, `LOP3` 3 / 5, `SHF` 3 / 5, `MOV` 2 / 5, `SEL` 2 / 5, `ISETP` 2 / 4, `IMAD` 1 / 4, `STS` data 1 / 3; either register of the pair form `CS2R Rn, SRZ` → `IMAD` / `IADD3` 6. `gen_dep_latency.py --result-census … --result-floors …` writes the table's section `result_high` from the two files (7 cells for the readers of the upper register, the floor 5 for a reader without one) and raises `CS2R → IMAD` from 5 to 6; the other families of the file (the accumulate operand of an MMA, a taken branch, the MMA result registers again) are on record |

```bash
# the table, byte for byte, from the files of this directory
python3 tools/stallfloor/gen_dep_latency.py tools/stallfloor/census_pairs_sm120.json tables/dep_latency_sm120.json \
    --floors tools/stallfloor/stall_floors_sm120_20261110_{pairs,pairs_b,store_data,pairs_c,store_addr,pairs_d}.json \
    --v6 tools/stallfloor/stall_floors_sm120_20261110_{cells,cells_b}.json \
    --mma-registers tools/stallfloor/mma_result_registers_sm120_20261110_em.json \
    --result-census tools/stallfloor/census_pairs_result_sm120.json \
    --result-floors tools/stallfloor/stall_floors_sm120_20261110_em_blk3.json
# (without the last two options: the table as it was before the split by result register, byte for byte)
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

## Harness v7 (2026-11-10): the synchronisation words

The words a warp-specialised kernel talks through — mbarriers, bulk copies, the async-proxy fence, the release / acquire
chains, named barriers, `setmaxnreg`, the collective region of a diverged `shfl.sync` — cannot be written as a one-pair
probe: their oracle is ptxas itself. `sync_probes.cu` (six kernels) and `coll_probe.cu` (one) are compiled by nvcc 13.0
for sm_120a; the frozen listing of the cubin is the reference schedule; a variant is the same kernel with ONE control
field of the word under test changed (its stall, its write / read barrier, the wait of its reader) or one instruction
replaced by a `NOP` (the positive controls), re-assembled over the nvcc cubin with `cubit asm -T`. Every kernel writes
one checksum per thread; a thread is wrong when its checksum differs from the reference kernel's. The references are
re-assembled the same way and must reproduce nvcc's cubin byte for byte.

```
nvcc -O3 -std=c++20 -gencode arch=compute_120a,code=sm_120a -cubin -o sync_probes.cubin tools/stallfloor/sync_probes.cu
python3 tools/stallfloor/syncfloor_gen.py --cubit target/release/cubit --table tables/sm120.json.gz \
    --cubin sync_probes.cubin --out kernels_sync/              # 81 kernels: 6 references + 75 variants, index.json
python3 tools/stallfloor/syncfloor_run.py kernels_sync/ --probe p_mbar --reps 20 --out floors.json
python3 tools/stallfloor/syncfloor_run.py kernels_sync/ --probe p_bulk --isolate --out floors.json
```

`--isolate` runs the reference and every variant in a process of its own with a timeout: a wrong schedule of `UBLKCP`
faults the context (CUDA_ERROR_LAUNCH_FAILED) and a wrong schedule of `USETMAXREG.TRY_ALLOC` never returns — without it
the first such variant takes the rest of the sweep with it.

| file | what it holds |
|---|---|
| `sync_floors_sm120_20261110_mbar.json`, `..._mbars.json` | `SYNCS.PHASECHK.TRANS64.TRYWAIT` → its branch (spin form) / → `NANOSLEEP.SYNCS` (suspend form), 512 producer and 512 consumer threads per CTA: **without the write barrier 327 680 of 327 680 consumer thread-launches wrong at every stall 1, 2, 3, 4, 5, 6, 8, 10, 12, 15**; with it wrong at S01 with yield, clean at S01 without yield, S02, S03 |
| `sync_floors_sm120_20261110_setmaxnreg.json` | `USETMAXREG.TRY_ALLOC.CTAPOOL` → `BRA.U !UP0`: **hangs at S01 with its barrier and at S01, S02, S04, S08, S13 without it**; the retry branch at S01 / S02, `DEALLOC` without its write barrier, `WARPSYNC.ALL` at S01: clean |
| `sync_floors_sm120_20261110_bulk.json` | `UBLKCP.S.G`: **launch failure at stall 1, 2, 4, 8, clean at 12**; the read barriers of the copy / the arrive / the store form / `UTMACMDFLUSH`, the fence's write barrier, `MEMBAR.ALL.CTA` at S01 / S03, `DEPBAR.LE` at S01 / S02 / S04: no wrong word (the probe copies 4 KiB per CTA and iteration; a dropped barrier is not observable with it) |
| `sync_floors_sm120_20261110_acqrel.json` | a writer CTA releases (`MEMBAR.ALL.GPU ; ERRBAR ; CGAERRBAR ; STG.E.STRONG.GPU`), a reader CTA polls and acquires (`LDG.E.STRONG.GPU ; CCTL.IVALL`): the invalidate dropped — every reader thread wrong; issued before the load's barrier is waited — clean; the chain's stalls at 1 / 3 and the `MEMBAR` dropped — clean (not observable: one writer per flag) |
| `sync_floors_sm120_20261110_named.json` | the stall behind `BAR.ARV` 1 … 8: clean; control `BAR.SYNC` → `LDS`: wrong at 1 … 5, clean at 6 (the `bar` resource of the table, BUG-479) |
| `sync_floors_sm120_20261110_coll.json` | the collective region of a diverged `shfl.sync` (`coll_probe.cu`, 24 one-field variants): the instruction in front of `WARPSYNC.COLLECTIVE` at **S01 / S02: fault (CUDA error 715)**, clean from S03; the region's `SHFL` at S01: 248 754 of 655 360 thread-launches wrong, S02 clean; `ENDCOLLECTIVE` without its waits: 205 284 wrong (the reader behind the region waiting instead: clean); the stalls of `WARPSYNC.COLLECTIVE` / `ENDCOLLECTIVE` 1 … 5: clean |

The classes these files stand behind are `src/sync_class.rs` (`CUBIT_SYNC_CLASSES=1`); the table of
`docs/SM120_ASYNC_IDIOMS.md` says for every word which number is a measured law and which is ptxas's practice.

`war_census.py` is the census of the other direction — write-after-read: how soon behind a reader of a register a
schedule lets another instruction overwrite it. Built from `depdump` files like `dep_latency_census.py`; with
`--against corpus.json … -- schedule.dep.jsonl` it lists the sites of a schedule below the corpus's minimum of their
(reader class, overwriter class). Two of its rows are laws with a silicon run (`docs/SM120_ASYNC_IDIOMS.md`): ptxas keeps
a fixed-latency overwriter 8 cycles behind an MMA that reads the register (56 723 sites of 1.9 M instructions, 16 524 at
exactly 8) and a `UMOV` 3 cycles behind a uniform-datapath reader (2 246 sites, none below). The metric is the stall sum
on the straight-line text and looks only at the overwriter's own wait mask: a pair coupled through a scoreboard (a wait
on the instruction in front of the overwriter) is listed although it is covered.

`scoreboard_class_census.py` asks a corpus which instruction classes its assembler synchronises with a scoreboard: per
opcode the results with a write barrier, and for the others whether their first reader waits. An opcode whose results
are never read without a scoreboard is a scoreboard class whatever a variable-latency list says — ptxas's schedules
give `LDG`, `LDCU`, `LDC`, `LD`, `S2R`, `S2UR`, `F2I`, `FLO`, `POPC`, `ATOM`, `ATOMG`, the `SYNCS` results, and two
that were in no list of cubit: `F2F` (silicon: wrong bits at every distance up to 15 without its barrier) and `BREV`.


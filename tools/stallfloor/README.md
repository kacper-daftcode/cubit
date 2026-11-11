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

## Harness v8 (2026-11-10): the probe service — one request, one isolated kernel family, an absolute oracle

`probe.py` turns the method of the earlier harnesses into one tool with one difference: **no reference kernel is the
judge.** A request names two forms and what is swept; `gen` builds one frozen kernel per point (every control code is in
the text, nothing is scheduled) and computes on the host, from the kernel's own instruction list, the checksum every
thread must end with — for "everything right" and for each failure hypothesis; `run` launches each kernel 20 times and
puts every thread of every launch into one class. The earlier harnesses compared with a reference kernel (the producer
at S15, or an overwriter 105 cycles behind a store); for the store latch that reference was itself affected and the
comparison under-reported (KNOWN_ISSUES A27).

| kind | question | forms |
|---|---|---|
| `raw` | from which issue distance does a consumer see a producer's result | producers `IADD3` (also `-R + imm`), `IMAD`, `IMAD.SHL`, `IMAD.WIDE`, `IADD.64`, `LOP3`, `MOV`, `SHF`, `SEL`, `PRMT`, `CS2R` (pair form), `FADD`, `FMUL`, `F2FP.SATFINITE.BF16.F32.PACK_AB`, uniform `UMOV` / `UIADD3`; consumers `STS` data / address, the first / last register of `STS.128`, `STG` data, `LDS` address, `IADD3` r1 / r2, `IMAD` r1 / r3, `IMAD.SHL`, `IADD.64` low / high word, `SHF.L.U32`, `SHF.L.U64.HI`, `LOP3`, `MOV`, `SEL`, `PRMT`, `I2FP`, `LEA`, the low / high word of the `IMAD.WIDE` addend, uniform `UIADD3` / `MOV R, UR`; `LEA` also as a producer |
| `war` | from which distance may an instruction rewrite a register a BARE store reads | stores `STS` / `STS.128` / `STG` data, `STS` / `STG` address; overwriters `LOP3`, `IADD3` (adds a constant: the number of late iterations per thread is read from the checksum), `MOV`, `LDS`, `LDS.128`, `LDSM`, `LDG`; controls without the overwriter and with a read barrier + wait |
| `ord` | is an OLDER load without a write barrier landed when a YOUNGER load's barrier clears (the reader waits only on the younger one's) | `LDS`–`LDS`, `LDS`–`LDSM`, `LDS.128`–`LDS`, `LDS`–`LDS.128`, `LDS`–`LDG`, `LDG`–`LDS`, `LDG`–`LDG`; `"far": true` puts the younger shared load on another line of shared memory 1 KB away (otherwise both loads read the thread's own line); control: the older load carries its own barrier |
| `ord`, N loads | N = 2 … 8 shared loads of one thread in flight behind ONE wait of the reader (`"nload"`) | on one line, through two base registers, or ≥ 1 KB apart in a second region of the CTA's shared memory (`"place"`: `near` / `base2` / `far`); the older loads bare or all N on ONE write barrier (`"barrier"`: `last` / `all`), or no barrier and no wait — the positive control (`none`: it must be wrong). The reader takes all N registers within N / 2 issue cycles of its wake-up (version 13; version 12 read the oldest at once and each further one 15 cycles later) |
| `ord`, more shapes | the same question in further forms | two loads on ONE write barrier (`"older_barrier": "same"`: does a scoreboard count its producers?); the younger load on the same base register 0x200 bytes away (`"far": "off"`); a guarded younger load (`"younger_guard": "true"` / `"false"`); `LDS.64` on either side, `LDS.U16` as the older load (version 14) |
| `mma` | two tensor instructions of one warp d cycles apart (another accumulator, the same, under guards; the vendor's `NOP` shape); ONE tensor instruction and a rewrite of a fragment register d cycles behind it (the operand hold: an A register, the upper or the lower B register; optionally K tensor instructions issued in front, `front: mmaxK@S`), with its positive control (`sens_*`: the same rewrite IN FRONT of the instruction must change the result — a hold result without it says nothing) | `QMMA.SF.16832.F32.E4M3.E2M1.E8`, `HMMA.16816.F32`, `HMMA.16816.F32.BF16` |

Swept: the distance (one stall 1…15 on the tested instruction + fillers of 15; `"via": "fill"` = stall 1 + fillers of
1), the occupancy (`w1` … `w32` = 1 … 32 warps on every SM of a 188-SM card; `g32` = 32 CTAs × 32 warps, the geometry of
v5; `w12` = one CTA of 12 warps per SM; `c2w9` = 376 CTAs of 9 warps — ONE CTA resident per SM, two waves: every kernel declares
65 536 B of shared memory and an SM has 102 400 B; described as "2 CTAs of 9 warps per SM" until 2026-11-11, KNOWN_ISSUES A31; `w9` = one CTA of 9 warps per SM;
`c2w9s` = 2 CTAs of 9 warps per SM and `c4w8` = 4 CTAs of 8 warps per SM — their kernels declare 49 152 B / 24 576 B so
that two / four CTAs fit an SM; whether they are co-resident shows in the launch time, which the runner records per
kernel from version 12),
the memory traffic in front (K stores of a
constant at stall S, shared or global). A request may carry `wanted` — the distance a schedule move asks for — and the
verdict then says whether the floor covers it.

How the oracle stays honest: the vectorised host model is checked against an independent scalar interpreter at
generation; a series has a result only when its own control (no overwriter / the largest distance) is right in 100 % of
the threads — otherwise `oracle: FAILED` (the runner then keeps the control's raw output and, per kernel, the count of
threads equal to it, so the relative reading survives and the model can be repaired on the CPU). The tensor family
needs no knowledge of the fragment layout: every A element is the same code (1.0 on even iterations, 2.0 on odd), every
B element the same code (1.0 in the first fragment, 2.0 in the second), unit block scales, accumulators = integer-valued
floats 2^23 + k per thread and register — each result is its accumulator + K·a·b, an integer add on the bit pattern.
Every address a kernel can form — right or stale — is the thread's own 64 bytes of shared memory or its own two words
of the output buffer; kernels use R0–R31 with `.regcount 40`.

```bash
python3 tools/stallfloor/probe.py list                                   # the catalogue
python3 tools/stallfloor/probe.py gen requests.json --out batch/         # CPU: kernels, family.json, model.npz per request
python3 tools/stallfloor/probe.py run batch/ [--reps 20] [--limit-s 600] # GPU host: result.json per request, floors.json
python3 tools/stallfloor/probe.py floor batch/                           # one line per request: `floor: <pair> = N (conditions)`
python3 tools/stallfloor/probe.py adapt <emu120.gate json | dir> --out requests.json   # a search loop's gate requests -> requests
python3 tools/stallfloor/probe.py selftest                               # the model against the scalar interpreter (CPU)
PROBE_FAKE=1 python3 tools/stallfloor/probe.py run batch/                # the runner's logic without a card
```

Cost: 0.6 CPU-seconds per kernel to assemble; on the card 2.9 s per request of ≈ 270 kernels (27 requests, 7 392
kernels × 20 launches: 78 s) + ≈ 10 s per block; with one process per request 43 requests / 4 482 kernels took 68 s.
The tool's version is in every result file: `probe.py 8` = one process per request (a kernel that traps costs its own
request) and the register-alignment check in `gen`; `probe.py 9` = tensor traffic in front of a hold request, the lower
B register, the controls; `probe.py 10` = the `IMAD.WIDE` addend consumers and the producer `LEA`; `probe.py 11` = the `ord`
shapes `far` and `LDS`–`LDS.128`; `probe.py 12` = the shared memory a kernel declares is per grid (`c2w9s`, `c4w8`,
`w9`), the N-load shapes, the launch → synchronize time per kernel (`launch_us_median_by_distance`), and **`run` refuses
outside a container** — it opens a CUDA context on device 0, which on a shared machine is somebody else's card
(`PROBE_FAKE=1 | 2` rehearses on a CPU; `PROBE_ALLOW_HOST=1` is for a machine whose device 0 is yours); `probe.py 13` =
the N-load reader that takes every register at once, its positive control, two loads on one write barrier;
`probe.py 14` = pairs with `LDS.64` / `LDS.U16`, the guarded younger load, the same base register 0x200 away, and `gen`
refuses a 64-bit DATA pair on an odd register. The runner did not change from 8 to 11 and not from 12 to 14: a batch
of a later version runs under an earlier runner of its group (it reads the kernel index and the host model only).

Result files (2026-11-10 / 11, RTX PRO 6000 Blackwell Server Edition, GPU 0 of the test host, 400 W, core clock 2 356 – 2 377
MHz while busy; one file per batch: every request with its floor per condition, the distances at which every thread
was right and the classes at the others, the table cell it was compared with, conditions and provenance):

| file | what it holds |
|---|---|
| `probe_sm120_20261110_b1.json` | **the store cells against the absolute oracle** (27 requests, 7 392 kernels). Producer → store operand / load address, the same floor at 1 / 8 / 32 warps per SM and at 32 warps on 32 SMs: `LOP3` / `IADD3` / `FADD` / `FMUL` → `STS` data 3, `IADD3` → the first register of `STS.128` 3, `MOV` / `IADD3` → its last register 1, `IADD3` / `MOV` / `FADD` → `STG` data 3, `IADD3` / `IMAD` / `LOP3` → `STS` address 1, → `LDS` address 4 — the numbers of the v5 files, no cell moves; with 15 stores issued in front every one of them is 1 (a store or load reads its operands when the memory pipe serves it). **A register of a bare store rewritten behind it by an ALU instruction — first distance at which every thread is right: one warp per SM 1 (the last register of `STS.128`: 4); one warp with 15 of its own stores in front 150 (wrong in every thread up to 105); 8 warps per SM, nothing in front 105 (`STG` address 75); 8 warps with 15 stores in front, and 32 warps: none up to 300 for a shared store** (one cell of the five differs: `STS` data at 32 warps on 32 SMs without traffic, 300; a global store at 32 warps without traffic: 90 on 32 SMs, 300 (data) / 225 (address) on 188; with 15 global stores in front 225 on 32 SMs, none up to 300 on 188 and at 8 warps; one warp with 15 global stores in front: 13). Controls: no overwriter, and read barrier + wait — 0 wrong of 4.7 × 10^8 thread-launches each. **A LOAD as the overwriter never reached the store**: `STS` ← `LDS`, `STS.128` ← `LDS.128` / `LDSM`, `STG` ← `LDG`, and across the pipes `STG` ← `LDS`, `STS` ← `LDG` — 0 of 4.02 × 10^8 thread-launches per pair (1.03 × 10^11 store → overwrite events), distances 1 … 75 and 105, four occupancies, with and without 15 stores in front: a measured exemption (the memory pipe serves a warp's instructions in issue order — inferred), not a rule for the scheduler |
| `probe_sm120_20261110_b4.json`, `_b5.json` | **two `QMMA.SF.16832.F32.E4M3.E2M1.E8` of one warp: right at every distance 1 … 16 (to 60)** — another accumulator with the same A fragment and another B fragment, the same accumulator, both under guards on two predicates, the second under a false guard; the distance as the first MMA's stall and as `QMMA [S(d−1)] ; NOP [S01] ; QMMA`; 1 / 8 / 16 / 32 warps per SM, one CTA of 12 warps per SM, one CTA of 9 warps per SM (the 376-CTA grid `c2w9`: NOT two CTAs per SM, A31); 1.49 × 10^9 thread-launches, 0 wrong. The resource row `mma` (16) is the vendor's spacing, not a silicon floor — as the v5e file says for `…E4M3.E4M3` against a reference kernel. **The operand hold (`_b5.json`): a `MOV` / `IADD3` that rewrites a register of the A fragment d cycles behind the MMA changes the result up to 4 and never from 5** (1 / 8 / 9 / 12 / 32 warps per SM, one CTA each); the vendor keeps 8 |
| `probe_sm120_20261110_b6.json` | the same for `HMMA.16816.F32` and `HMMA.16816.F32.BF16`: two back to back right from 1; A-fragment hold 5 |
| `probe_sm120_20261111_b8.json`, `_b9.json` | **the operand hold of an MMA with positive controls and with tensor traffic in front.** Controls: the rewrite of a fragment register 45 cycles IN FRONT of the instruction changed the result in 100 % of the thread-launches — the upper B register by `SHF.R.U32.HI` and by `MOV`, the lower B register, an A register; `HMMA.16816.F32`, `.BF16`, `QMMA.SF.16832.F32.E4M3.E2M1.E8`; 1 / 8 / 16 / 32 warps per SM. Behind the instruction: **a B register (upper or lower) rewritten 1 … 90 cycles behind it never changed the result** (0 of 1.1 × 10^8 thread-launches per overwriter without traffic, 0 of 7.9 × 10^7 per traffic shape); **an A register changes it up to 4 cycles behind and never from 5** — the same with one tensor instruction 7 / 8 cycles in front, with eight back to back and with eight 7 apart (`front: mmaxK@S`). So the instruction takes its B fragment at issue and its A fragment up to four cycles later (the mechanism is inferred, the counts are not); the vendor keeps 8 behind both |
| `probe_sm120_20261111_b11.json` | **the upper register of the 64-bit addend of `IMAD.WIDE` (role `r3h`): floor 3** — `IADD3`, `SHF.R.U32.HI`, `LEA` writing it 1 or 2 cycles in front are wrong in every thread, right from 3; `MOV` right from 1 at one warp per SM, from 3 at 8 and 32. The cell 4 holds; the vendor's 3 is the floor. The LOWER register (`r3`) in the same batch as the validation of the consumer form: 5 (`IADD3` wrong in every thread at 4), the v6 floor and the cell |
| `probe_sm120_20261111_b12.json`, `_b10.json` | **load order with two loads in flight — at ONE CTA per SM (the grid `c2w9` was described as two CTAs per SM until 2026-11-11; it holds one, A31).** `_b12`: an older shared load WITHOUT a write barrier was landed whenever the reader woke on the barrier of a younger shared load that reads another line 1 KB away (`LDS`, `LDS.128`, `LDSM`) or is 16 bytes wide on the same line — 0 of 2.9 × 10^8 thread-launches in each of four shapes; one CTA of 9 warps per SM (`c2w9`), one CTA of 12 warps, 8 and 32 warps per SM; distances 1 … 30; with and without 15 stores queued. `_b10`: the pairs of `_b1` / `_b7` on the grid `c2w9` (one CTA of 9 warps per SM) and the 12-warp CTA, loads on the thread's own line — in-pipe pairs 0 of 1.2 × 10^8 each, across the two pipes wrong in 99.8 % / 48 %, a load that rewrites a register of a bare store 0 of 2.6 × 10^8 in each of seven pairs. Two loads in flight in every kernel: the allocator's recorded counter-example (eight `LDS` 1 KB apart on one barrier at 2 CTAs per SM) is neither reproduced nor refuted — no kernel of these files ran at two CTAs per SM —, and the batching key is not changed by these files |
| `probe_sm120_20261111_b7.json` | 43 requests, one process each. **Pairs a vendor schedule holds below the table's default — every one at or above its floor:** `IADD.64` → `IADD.64` 4 (both registers), `MOV` → `MOV` 5, `IADD3` (−R + imm) → `I2FP` / `SHF` 4, `SEL` → `PRMT` 5, `PRMT` / `SHF` / `F2FP.SATFINITE…PACK_AB` → `SEL` 5, `SEL` → `MOV` 5, `LOP3` / `MOV` → `IADD.64` 5, `IADD.64` → `LEA` 5, `IMAD.WIDE` → `IADD.64` high register 4 (its low register and `IMAD.WIDE` → `IMAD`: right behind a stall of 1 at three occupancies — not a cell until a second card and the `fill` shape agree), `PRMT` → `STG` data 3; store cells `PRMT` / `F2FP…PACK_AB` / `IMAD.SHL` → `STS` data 3, `PRMT` / `SEL` → the last register of `STS.128` 1; `CS2R Rn, SRZ` → `IADD.64` 6 (low register; the default, no margin) / 5 (high), → `STS` data 3. **An older load WITHOUT a write barrier, read when the reader wakes on a younger load's barrier: across the two memory pipes there is no order** — older `LDS` / younger `LDG` wrong in 91 % of the thread-launches, older `LDG` / younger `LDS` in 49 % (right only where the shared pipe is the slower one). Inside one pipe the family measures two loads of ONE thread from ONE line at ONE CTA per SM — `LDS`–`LDS`, `LDS`–`LDSM`, `LDS.128`–`LDS`, `LDG`–`LDG`: 0 of 1.9 × 10^8 thread-launches each, distances 1 … 30, four occupancies, with and without stores queued; that is the ground of the allocator's batching key (same opcode, width and address stream) and no reason to widen it — loads of different lines at 2 CTAs per SM, where the allocator's comment records stale reads, are not in these files. **Write-after-read to 900 cycles with the number of late iterations** (the overwriter adds a constant): a shared store's data is right from 450 – 600 cycles under load (105 at 8 warps with an idle pipe, where every wrong thread has exactly one late iteration of 256), a global store's with 32 warps and 15 stores in front not at 900 (32 of 3.9 × 10^6 thread-launches, one iteration each); `STS` address ← `LDS`: 0 of 4.0 × 10^8 |
| `probe_sm120_20261110_b3.json`, `_b2.json` | pairs the served MoE kernels' vendor schedule holds below the table: `F2FP.SATFINITE.BF16.F32.PACK_AB` → `IMAD.SHL.U32` 5 (default 6; the vendor 5), `IADD.64` → `SHF.L.U64.HI` 5 (default 6; the vendor 5), `IMAD.WIDE` → `SHF.L.U64.HI` 5, `UMOV` → `UIADD3` 1 (cell 4; the vendor 2), `UMOV` → `MOV R, UR` 1 (uniform default 13; the vendor 2), `UIADD3` → `UIADD3` 4 and → `MOV R, UR` 6 (the cells exactly), `CS2R Rn, SRZ` → `IMAD` / `IADD3` / `LOP3` 6 (cell / default 6 exactly) |
| `probe_sm120_20261111_b13.json` | **the floor and floor + 1 with ≥ 10^8 thread-launches each** (240 launches; 1 / 8 / 32 warps per SM, 32 warps on 32 SMs, 12 warps and 9 warps in one CTA): two `QMMA.SF` of one warp at 1 and at 2 (another accumulator, the chain, guards, the `NOP` shape), the A-fragment hold at 5 and at 6 (`QMMA.SF` by `MOV` / `IADD3`, `HMMA.16816.F32` and `.BF16` by `MOV`, with and without tensor traffic), the B fragment at 1 and at 2: 0 not right of 110 376 960 per request and traffic; 8 positive controls changed in 100 % |
| `probe_sm120_20261111_b14.json` | **grids that really hold 2 and 4 CTAs per SM** (`c2w9s`, `c4w8`). Co-residency by launch time (request `t_time_war`, a kernel of ≈ 100 µs): 188 CTAs × 9 warps 128.5 µs, 376 CTAs with 65 536 B each 246.7 µs (two waves), with 49 152 B each 129.0 µs, 752 CTAs × 8 warps with 24 576 B 138.2 µs against 128.0 µs for 188. On them: the in-pipe load pairs and the covers of `_b10` / `_b12` 0 of 3.7 × 10^7 / 6.5 × 10^7 thread-launches each, a load that rewrites a register of a bare store 0 in seven pairs, across the two pipes no order; **a bare store ← `IADD3` 300 cycles behind it: 0 not right with one CTA of 9 warps, 77 312 of 4 331 520 at 2 × 9, 1 001 184 of 7 700 480 at 4 × 8** (right at 900); P1 right from 1, the A-fragment hold 5 (wrong at 1 – 4), the B fragment 1 on the served grid 2 × 9 |
| `probe_sm120_20261111_b16.json` | **N shared loads of one thread in flight behind ONE wait: 0 not right of 2 144 102 400** (N = 2 / 4 / 8; one line, two base registers, ≥ 1 KB apart; the older loads bare or all on ONE write barrier; spacing 1 … 15; 2 × 9 and 4 × 8 warps per SM, 9 / 8 / 32 warps in one CTA; with and without 15 stores queued), every register read within N / 2 cycles of the wake-up; **the positive control (no barrier, no wait) not right in 127 779 840 of 127 779 840.** The allocator's recorded shape — eight `LDS` 1 KB apart on one barrier, one wait, 2 CTAs per SM — 0 of 21 657 600. **Two loads of different pipes on ONE write barrier: 0 not right of 241 361 920 per pair in either order, while the same pair with the older load bare is not right in 97.5 – 100 % (idle shared pipe): a write barrier counts its producers.** `_b15.json` is the same N-load family with version 12's reader (only the oldest register read at the wake-up) — kept for the record, superseded |
| `probe_sm120_20261111_b17.json` | the MMA operand hold and the spacing of two `QMMA.SF` swept on `g32` (32 warps on each of 32 SMs; also 1 / 8 / 32 warps per SM): the A-fragment register wrong in 93 – 100 % at 1 – 4 and right from 5, the B fragment right from 1, two MMAs right from 1; five positive controls 100 % |
| `probe_sm120_20261111_b18.json` | **a bare shared load behind the wait on a younger load's barrier, in the shapes a vendor-compiled serving kernel uses** (two loads; 2 × 9 warps per SM for real, 12, 8 and 32 warps; distances 1 … 30; with and without 15 stores queued): `LDS` ← `LDS.64` on another base register and line, and on the same line; `LDS.64` ← `LDS.64` on the same base register 0x200 away, and on another base; `LDS.64` ← `LDS`; `LDS.U16` ← `LDS`; `LDS` ← a guarded `LDS.128` with its guard true — 0 not right of 286 361 600 each; **with the guard FALSE (the younger load does not happen) 0 of 859 084 800: the wait on its barrier still found the older load landed.** N = 3 / 5 loads and the 12-warp CTA: 0 of 360 960 000 |
| `probe_sm120_20261111_b<n>_ws_<card>_alone.json`, `…_capped.json`, `…_alone_2.json` | **the same batches on two cards of the Workstation Edition** (`conditions.card` = the first 12 hex digits of the sha256 of the card's UUID; `state`, `state_name`, `power_median_w`, the clock percentiles): each card alone (busy clock mean 2 708 – 2 864 MHz of a 3 090 MHz maximum; `fast` only where the mean is ≥ 2 800) and at its 400-W limit beside a sustained load in a second process (power median 399.9 – 400.2 W, 2 286 – 2 449 MHz). `_b8` / `_b9` / `_b4` / `_b5` / `_b13`: **two `QMMA.SF` of a warp right from 1, the A-fragment hold 5, the B fragment 1 — the Server card's numbers on both cards in both states**, 0 not right of 110 376 960 at the floor and at floor + 1 per request. `_b14` / `_b17` / `_b16` / `_b18` on the same two cards in the same two states: **the MMA rows on the grid that really holds 2 CTAs of 9 warps per SM and on `g32` as on the Server card** (per run on `c2w9s`: the A-fragment register not right in 60 – 100 % of the thread-launches at 1 – 4 and in 0 of 311 869 440 from 5 up, 103 956 480 of them at 6; two MMAs 0 of 77 967 360 at floor + 1; the B fragment 0 of 155 934 720 at 2), **and the load family with the Server card's zeros in every run** (N loads behind one wait 0 of 2 144 102 400 with the positive control at 100 %, two loads of different pipes on one write barrier 0 of 1 448 171 520, the vendor's cover shapes 0 of 3 019 069 440, in-pipe pairs, covers and load overwriters on 2 and 4 CTAs per SM 0 of 3 826 176 000). Under the load the card alternates between the two processes, so `launch_us_median_by_distance` of a capped file is not a co-residency measurement; alone, the three launch times of `_b14` repeat on both cards (105 – 109 µs, 202 – 207 µs, 106 – 109 µs). Two things these files are NOT: the fast state (mean ≥ 2 800 MHz) was reached on one of the two cards only — by its 12-second `_b17` batch only in a second run behind a longer batch, the two `_alone_2` files —, and none of them is the evidence of an edition entry (`tools/stallfloor/silicon/README.md`) |

The files without `_ws_` in their name are ONE card model (Server Edition, 2 356 – 2 389 MHz); the `_ws_` files are two
cards of the other model, each in two clock states. A floor here is a measurement with its conditions. The table changes only by a commit with the result
file beside the cell; none is proposed with these files.

Two things the first day taught, both now in the tool: **a 64-bit register pair must sit on an even register** — cubit
assembles `IADD.64 R13, R6, 0x4`, the card answers "Misaligned Register" (Xid 13) at the first launch; `gen` refuses such
a text (and a 128-bit or tensor operand off a multiple of four). And the runner runs **one process per request**: a
kernel that traps ends its own request, not the batch.

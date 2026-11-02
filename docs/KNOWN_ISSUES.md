# Known issues

Everything this project knows to be imperfect, in one place, with its status, the evidence and
what closing it needs. Rule: nothing knowingly imperfect stays unlisted. Updated 2026-11-02
(cubit 0.2.0, blackwell-isa `77a3dfa`). The ISA-side counterpart is the "Known issues" section
of the blackwell-isa README.

Status words: **open** (needs work that can be done on a build host), **needs silicon** (a GPU
run; the prepared probes are under the project's GPU items), **needs corpus/host** (data that is
not on the build host), **decision** (the owner has to choose), **documented** (a limitation that
is stated, not a defect to fix), **closed** (kept for the record; closed in the named commit).

## ISA table (SM120)

| # | item | status | evidence / what it needs |
|---|---|---|---|
| T1 | 19 340 of 20 905 SM120 encoding variants are **harvest rows** (learned from compiler output 2026-06..08, no per-field measurement). Static audit `tools/audit_table.py`: 6 410 operand bytes baked into `and_base` without a field (4 316 of them in the immediate window), 1 223 fields addressing an operand token the key signature does not have, 994 `reg`/`ureg` fields off the standard slots, 257 immediate-bearing keys without an immediate field, 1 462 masks narrower than their fields, 14 634 pairs of same-opcode rows the decoder separates only by tiebreak. | open | The census proves these rows on the words real kernels use (1 811 600 / 1 811 600 strict), not on every value of every field. Dynamic nvdisasm cross-check (`tools/audit_dynamic.py`, 2026-11-02, 88 388 probe words over the 6 000 flagged rows): **1 977 rows** with at least one defect — 685 rows print a different text than nvdisasm (after this session's three printer-order fixes the largest remaining families are LDGSTS `[R261+…]` from a 9-bit base field, LEA.HI.X dropping its trailing predicate, `F2FP_R_R BF16,F32,PACK_AB` missing the UR operand, BRA.DIV/BRA.CONV glyphs, ATOMG `.64` address width), 1 255 rows whose text re-encodes to a different word (1 129 `LDG … ELL2.256` rows with an RZ base), 194 rows that decode words nvdisasm rejects, 27 rows (FSETP/F2I/FMNMX) that cannot decode their own canonical variants. Fix path = `tools/probes/` pattern per family (fixture + test + canonical row). |
| T2 | 43 SM120 entries (17 SM103a, 17 SM100a, 52 SM121a) have no `base_op` / `operand_sig`; some `base_op` values include modifiers (`LDG.E.EL.ELL2.256.STRONG.GPU`). cubit derives both from the key, so nothing breaks; the HTML export derives them too. | open (cosmetic) | Normalise in the canonical table (`base_op` = mnemonic, `operand_sig` = key suffix) in one pinned sync. |
| T3 | 880 of 1 145 SM120 variants (SM103a 1 670 / 1 681, SM100a 1 674 / 1 685, SM121a 546 / 546) bake control-code bits [127:105] into `and_base` (the compiler sample's stall / barriers / reuse). Decoders strip the control code before matching and the encoder overwrites it, so they are a provenance artefact; `tools/sync_table.py` ratchets their number. | documented | Explained in the blackwell-isa README ("Baked control bits") and the HTML control-word section. Cleaning them (`and_base &= ~(bits 105..127)`) is a mechanical table pass that changes no decode; left for a dedicated sync because it changes every pinned SHA. |
| T4 | Keys with `?` are partial: valid encodings whose full operand syntax is not determined. | documented | blackwell-isa README "Limitations". |
| T5 | `IMMA.SF.16832.U8.U8_R_R_R_R_R_R_UR` is an unvalidated historical hypothesis (no numerical oracle). | documented | blackwell-isa README / CHANGELOG 2026-10-22. |
| T6 | The 2026-11-02 rows are **encoding** evidence only: `ARRIVES_ARURI` carries `ctrl_class alu_simple` cloned from UBLKPF (the 297 shipped words all have the plain stall-1/yield control word), the FP4/FP6 `LDSM` unpack semantics, the `HMUL2` immediate semantics and the `UTMASTG` dimensions were not executed. | needs silicon | GPU item `T/gpu/forms_semantics.sh` (ARRIVES arrive count observed through `SYNCS.PHASECHK`, LDSM.U4x16P64TO8 fragment layout, HMUL2 imm vs register result). |
| T7 | Scheduling metadata outside `hw_measured` rows is synthetic or a ptxas weight; `sched_only` entries have no encoding. | documented | README of blackwell-isa; `latency_source` per row. |

## Assembler / encoder

| # | item | status | evidence / what it needs |
|---|---|---|---|
| A1 | **BUG-075 / BUG-040 shadow law** ("a declared register count N leaves R0..R(N-3) usable; R(N-2), R(N-1) are ILLEGAL", measured on i115 at rc = 64) is contradicted by nvcc: FlashInfer's `sparse_mla_streaming_dsv4_nvfp4_kernel` touches R126 and R127 under `EIATTR_REGCOUNT` 128. cubit keeps the WARN (not an error) and `.regcount` pins the compiler's value. | needs silicon | GPU item `T/gpu/regcount_shadow.sh`: a probe kernel at regcount 64 / 128 touching R(N-1); decides whether the law holds, holds only for some counts, or was an artefact. |
| A2 | **BUG-008** `IMAD.WIDE` 4-operand with a register c: the pair reading (`Rd:Rd+1 = Ra*Rb + Rc:Rc+1`) is what nvcc assumes in 190 sites of the MoE kernels; the warning now fires only for odd base registers. The hardware behaviour of an odd pair base is not measured. | needs silicon | GPU item `T/gpu/bug008_imad_wide_pair.sh` (even pair: result must include c_hi; odd c: observe). |
| A3 | `stallfix` has measured rules for sm_103a only; SM120 has none. | needs silicon | Plan and CPU-side harness: `docs/SM120_STALLFIX_PLAN.md`, GPU item `T/gpu/sm120_stall_floors.sh`. |
| A4 | The scheduler's 2-CTA/SM WAR bug (fixed `ebbd1dc`, 2026-06) has no regression corpus; the static legality oracle over frozen nvcc schedules is specified but not yet a test. | open | `docs/SCHED_LEGALITY_ORACLE.md`; implement `tests/sched_legality_corpus.rs` over `tests/fixtures/` frozen kernels. |
| A5 | Metadata that a template rebuild (`asm -T`) copies verbatim rather than regenerates: `.nv.info` records other than REGCOUNT / KPARAM / CBANK_PARAM_SIZE, `.nv.constant0`, relocations, Mercury companions of the template. A standalone build (`asm` without `-T`) regenerates them by the nvcc 13.3 laws of `docs/MERC13_COMPANIONS.md`; the differences that remain against nvcc output are listed there. | documented | `docs/MERC13_COMPANIONS.md` "What is not reproduced". |
| A6 | `cubit validate` needs `tables/records.jsonl` (the harvest record stream), which is not shipped; the command is only useful with a private harvest. | documented | Help text says so; `tools/sync_table.py --validate-only` is the public table validator. |
| A7 | Legacy code kept for compatibility: `KernelMeta::to_kernel_records` (pre-2026-08 record set with historical attribute ids; used by its unit test only), the historical `EiFmt` variant names (`Byte` is the 16-bit fmt 3, `Half` the 8-bit fmt 2 — documented on the enum), the `__raw__` / `!rsd` legacy round trip. | open (cleanup) | Remove `to_kernel_records` and rename the variants in a dedicated commit. |
| A8 | QNAN immediates re-encode only from the exact hexadecimal literal: nvdisasm's `+QNAN` glyph drops the payload (bimodal lanes per instruction). The strict round trip prints the hex form; decode-side render parity holds. | documented | `src/parser.rs` comment, `tests/sm120_hmul2_imm.rs`. |
| A9 | Standalone cubins and `--eiattr-from` renames: the 2026-03 notes (`BUG_STANDALONE_CUBIN_LAUNCH`, `BUG_CONSERVATIVE_SCHEDULING`, `BUG_EIATTR_FROM_KERNEL_NAME`, `NEXT_AGENT_CUBIN_FIX`) describe launch failures of early standalone builds on driver 570 / CUDA 12.8. The ELF builder, EIATTR record set and Mercury emitter were rebuilt in 2026-06..08 (standalone cubit kernels ran in production in 2026-06; `tests/bug039_*`, `bug127`, the mk/mercury suite). | closed (not re-verified on the 2026-03 driver) | A standalone launch smoke test is part of `T/gpu/forms_semantics.sh`. |
| A10 | SM120 loop scheduling (2026-03 `TASK_LOOP_SCHEDULING`: a loop with an LDC-loaded bound exited after one iteration under automatic scheduling). The scheduler changed substantially since (`ebbd1dc`, drains, back-edge settles); the June kernels loop correctly. | closed (not re-verified as a unit case) | A minimal loop probe is in `T/gpu/forms_semantics.sh`. |

## Repository and tests

| # | item | status | evidence / what it needs |
|---|---|---|---|
| R1 | `cargo clippy --all-targets` reports ~730 lints in 173 of 425 test files (doc indentation, needless borrows, dead helpers) including nine **tautological assertions** (`assert!(x \|\| true)`, `if … && false` in `bug274`, `bug324`, `b9_ptx_lower`, `reg_liveness`, `bug303`, `bug069`) that guard nothing. CI lints the library and binary only. | open | Fix per file; promote CI to `--all-targets` afterwards. |
| R2 | Doc comments of many `tests/bug*.rs` files and some source comments are in Polish (the fix waves were written that way); `docs/TESTS.md` carries them verbatim. | open | Translate when a file is touched; the index is regenerated by `tools/gen_tests_index.py`. |
| R3 | `cargo test` runs 425 test binaries that each load the 46 MB SM120 table; a full run takes ~90 minutes on 16 cores (measured 2026-11-02). | documented | Shared table loading (a process-wide cache) or fixture-scoped table subsets would cut it. |
| R4 | `tests/target-suite/` (a committed Cargo build directory, 458 files / 195 MB) was removed from the tree on 2026-11-02; the pack history still carries it (~54 MB packed). | decision | Only a history rewrite removes it from clones; not done (no force pushes). |
| R5 | The Python bindings (`pip install -e .`, maturin) are verified on Python 3.12 only (2026-11-02). | documented | README states it. |

## Validation claims that cannot be re-run from the build host

| # | claim | status |
|---|---|---|
| V1 | SM103a byte-exact round trip on 323 / 323 cubins (2026-09-18) | needs corpus/host (B300 corpus) |
| V2 | SM100a 99.92 % EXACT-minus-sched over 20 M instructions (2026-08-26) | needs corpus/host (archived sm_100 corpus) |
| V3 | SM121a 0 decode differences over 648 992 raw instructions, 92 098-word census (2026-09-18) | needs corpus/host (GB10 corpus) |
| V4 | SM120 hardware validation of selected fields (RTX 5090 / RTX PRO 6000, 2026-02..03) | historical; the current silicon evidence is the production run of cubit-assembled kernels (2026-06..10) |

# cubit changelog

User-visible changes, newest first. Table syncs name the blackwell-isa revision they vendor
(`tables/SOURCE.json` pins it byte for byte). Numbered `BUG-NNN` entries are the encoder /
decoder findings whose executable specification is `tests/bugNNN_*.rs` (index: `docs/TESTS.md`).

## 0.2.0 — 2026-11-02

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

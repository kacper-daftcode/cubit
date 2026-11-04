# cubit changelog

User-visible changes, newest first. Table syncs name the blackwell-isa revision they vendor
(`tables/SOURCE.json` pins it byte for byte). Numbered `BUG-NNN` entries are the encoder /
decoder findings whose executable specification is `tests/bugNNN_*.rs` (index: `docs/TESTS.md`).

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

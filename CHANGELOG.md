# cubit changelog

User-visible changes, newest first. Table syncs name the blackwell-isa revision they vendor
(`tables/SOURCE.json` pins it byte for byte). Numbered `BUG-NNN` entries are the encoder /
decoder findings whose executable specification is `tests/bugNNN_*.rs` (index: `docs/TESTS.md`).

## Unreleased — 2026-11-06 (session T-8: the LEA family, the allocator's WAW rule, the audit oracle corrected)

- **Tables vendored from blackwell-isa `09a7141`** (sm120 16 063 forms / 26 596 variants, sm103a / sm100a
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

- **KNOWN_ISSUES A14 fixed (pending silicon)**: `asm` writes the CUDA-13 ELF identity
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
  **BUG-041 doctrine unchanged** (owner decision pending, NEEDS_OWNER 28): `.EL` + `desc[URm][Rn.64]` stays
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

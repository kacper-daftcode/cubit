# ISA probes — the provenance of the measured SM120 table rows

Every script here measures one instruction form (or one field family) of SM120 against
NVIDIA's own tools and turns the measurement into canonical table rows. They are kept in
the repository because they *are* the evidence behind the rows of
[blackwell-isa](https://github.com/kacper-daftcode/blackwell-isa)`/sm120.json` that carry a
`_src` tag, and because the tests under `tests/` replay their fixtures.

The method (2026-10 onwards, `nvprobe.py` helpers):

1. `probe --nvdisasm <path>` feeds nvdisasm 13.1 one 128-bit word per call (nvdisasm aborts a
   whole file on one illegal word): a bounded sweep over every register / uniform-register /
   immediate field, the guard, the modifier lattice, and the neighbouring bits. The result is a
   fixture `tests/fixtures/sm120_<form>_nvdisasm.jsonl` (`word`, `nvidia_sass`, nvdisasm version
   and SHA-256; `"lattice": true` marks words that must stay *outside* the row — illegal,
   `INVALIDn`, text-inert).
2. `apply <sm120.json>` writes the measured row(s) into the canonical table: `and_base` = the
   form's constant bits, `variable_mask` = exactly the measured fields (fail-closed), `count null`,
   `_src` = the probe's provenance tag, `_note` = the measurement in one paragraph.
3. A test `tests/sm120_<form>.rs` replays the fixture: every form word decodes to the row, prints
   NVIDIA's text in NVIDIA's modifier order and re-encodes bit for bit; every lattice word either
   fails to decode or prints exactly NVIDIA's text; the encoder refuses the `INVALIDn` spellings.
4. `python3 tools/sync_table.py` vendors the new canonical revision and runs the suite.

Older scripts (2026-10-22/23) follow the same idea with their own helpers; the table rows they
produced are listed with their tags.

| script | measured | `_src` tag (rows in `sm120.json`) | test |
|---|---|---|---|
| `re_sm120_hmul2_imm.py` | `HMUL2[.BF16_V2][.FMZ][.SAT][.FTZ] Rd, Ra, imm, imm` (0x832): packed f16/bf16 immediates, `-Ra`, `\|Ra\|`, `.H0_H0`/`.H1_H1`; the 12 664-word gap of the FlashInfer CAKE DSV4.1 kernels | `hmul2-imm-sm120-2026-11-02` (12) | `sm120_hmul2_imm.rs` |
| `re_sm120_ldl_aruri.py` | `LDL[.size][.LU] Rd, [Ra+URb+imm]` (0x983 with the bit-91 frame): the three-term local address the GB10-host census found missing (95 cuBLASLt words) | `ldl-aruri-sm120-2026-11-04` (14) | `sm120_ldl_aruri.rs` |
| `re_sm120_mufu_ur.py` | `MUFU.<fn>[.F16/.BF16] Rd, URb` (0xd08): the 10 functions × the half types they take, abs/neg on the UR operand; rebuilt four harvest rows that decoded EX2 as LG2 | `mufu-ur-sm120-2026-11-04` (26) | `sm120_mufu_ur.rs` |
| `re_sm120_imad_alias.py` | nvdisasm's `IMAD.MOV` / `.IADD` / `.SHL` display law over the four-operand forms (144 words); removed 7 alias-named harvest groups, added the U32 twins | `imad-alias-sm120-2026-11-04` (4) | `sm120_imad_alias.rs` |
| `re_sm120_ldsm_fp4.py` | `LDSM.U4x16P64TO8` / `LDSM.U6x16P32TO8` `[R+imm]` (0x83b): FP4/FP6 matrix loads, all shapes and counts; DeepGEMM grouped FP8×FP4 GEMMs | `ldsm-fp4-fp6-sm120-2026-11-02` (30) | `sm120_ldsm_fp4.rs` |
| `re_sm120_prmt_ur.py` | `PRMT[.mode] Rd, Ra, URsel, Rc` (0xc16): the uniform-selector permute, 7 modes | `prmt-ur-sm120-2026-11-02` (7) | `sm120_prmt_ur.rs` |
| `re_sm120_arrives_ldgstsbar.py` | `ARRIVES.LDGSTSBAR.64[.ARVCNT] [R+UR+imm]` (0x9b0): mbarrier arrive with the cp.async count | `arrives-ldgstsbar-sm120-2026-11-02` (2) | `sm120_arrives_ldgstsbar.rs` |
| `re_sm120_utmastg_dims.py` | `UTMASTG.1D/2D/4D/5D [UR], [UR]` (0x3b5): the bulk tensor store dimensions next to the harvest-era 3D row | `utmastg-dims-sm120-2026-11-02` (4) | `sm120_utmastg_dims.rs` |
| `re_sm120_atoms_aruri.py` | `ATOMS.MAX.S32 RZ, [R+UR+imm], R` (0x98c): replaced the harvest row that read the UR byte as a fourth register | `atoms-aruri-sm120-2026-10-29` (1) | `bug477_atoms_aruri_print.rs` |
| `re_sm120_stsm8_mt168.py` | `STSM.8.MT168[.2/.4] [R+imm], R` (0x844): 8-bit transposed matrix store | `stsm8-mt168-sm120-2026-10-29` (3) | `sm120_stsm8_mt168.rs` |
| `re_sm120_ublkpf.py` | `UBLKPF.L2 [UR], UR[, desc[UR]]` (0x3bc): bulk L2 prefetch | `ublkpf-l2-sm120-2026-10-29` (2) | `sm120_ublkpf_l2.rs` |
| `re_sm120_f2fp_e8.py` | `F2FP.BF16.E8.UNPACK_B` (UE8M0 → BF16×2) | `f2fp-e8-sm120-2026-10-28` (1) | `sm120_f2fp_e8_unpack.rs` |
| `re_sm120_cctl.py` | the seven `CCTL.E` register-address operations (PF1, WB, IV, RS, PML2, DML2, RML2) | `cctl-sm120-2026-10-25` (7) | `sm120_cctl_register_forms.rs` |
| `re_sm120_cs2ur.py` | `CS2UR URd, SR_*`: uniform guard, URd and system-register fields | `cs2ur-sm120-2026-10-23` (2) | `sm120_cs2ur_sysreg.rs` |
| `re_sm120_dsv41.py` | the DeepSeek-V4.1 field probes (memory, float, tensor, control forms of the served kernels) | `dsv41-sm120-2026-10-22` (541) | `dsv41_re_fields.rs` |
| `re_sm120_capture_control_fields.py` | control / copy fields recovered from native DSV4.1 CUPTI captures | `sm120-native-capture-control-2026-10-22` (22) | (captured rows; checked by the census) |
| `re_sm120_memory_fields.py` | memory-row recovery from decoded production witnesses (retired the `ATOMS_R_ARI_R_R` fourth-register defect) | rows carry the per-row `_src` of the 2026-10-22 capture | `bug477_atoms_aruri_print.rs` |
| `re_sm120_float_fields.py` | native float packets rebuilt from independently probed fields | 2026-10-22 capture rows | `dsv41_float_re.rs` |
| `re_sm120_tensor_fields.py` | semantic tensor, election and scalar/vector ALU field repairs | 2026-10-22 capture rows | `bug202_dsetp_tok2_explicit.rs` |
| `re_sm120_branch_fields.py` | `BRA.DIV`'s REL16 layout repair | 2026-10-22 capture rows | (census) |
| `re_sm120_atomg_el_aruri.py` | the plain uniform-indexed `.EL` atomic `ATOMG.E.{ADD,OR}.EL.STRONG.GPU Pd, Rd, [Ra.U32+URb(+off)], Rb` (0x9a8): Pd / 8-bit UR / signed 23-bit offset fields, width bit 63 and descriptor bit 76 excluded; measured on `-b SM120`, `-b SM103`, `-b SM100` (text-identical) and applied to the three tables (the sm103a / sm100a `_P_R_dARI_R` era keys replaced) | `atomg-el-aruri-2026-11-05` (2 rows per table) | `sm120_atomg_el_aruri.rs` |

Provenance tags of the form `bugNNN-<date>` (113 rows `bug324-2026-09-01`, …) come from the
2026-08/09 encoder bug-fix waves (`tests/bugNNN_*.rs` hold the pinned words); rows with no `_src`
are the 2026-06..08 harvest (rows learned from compiler output). `docs/KNOWN_ISSUES.md` lists the
audit state of the harvest rows.

Ground truth used by every probe: `nvdisasm` 13.1 (`-b SM120 -hex` on a 16-byte raw file). The
probes do not execute anything on a GPU; where the *semantics* of a form had to be assumed, the
assumption is listed in `docs/KNOWN_ISSUES.md`.

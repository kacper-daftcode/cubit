//! SM120 memory long tail (the plain LDG / STG / LD / ST / LDGMC keys, LDSM / CCTL / UTMA / UBLK …; LDGSTS / LDS / STS / LDL / STL / MOVM stay for the wave re-pins) (session G run 5, 2026-11-07; KNOWN_ISSUES T1): the remaining harvest rows of
//! LDG, STG, LD, ST, LDS, STS, LDL, STL, LDGSTS, LDGMC, LDSM, STSM, MOVM, CCTL, QSPC, LDGDEPBAR, UTMALDG, UTMASTG, UTMACCTL, UTMACMDFLUSH, UBLKCP, UBLKRED, UBLKPF verified row by row with nvdisasm 13.1 over the whole
//! 128-bit word by `tools/probes/re_sm120_rows.py --family memory` -- 270 rows measured (13833 canonical +
//! field words, 159 census witnesses), 4 shadowed keys (4 rows) retired as aliases, 0 unreachable
//! rows of staying keys deleted, 20 named exceptions. Fixture `tests/fixtures/sm120_rows_memory_nvdisasm.jsonl`; the test body is `tests/sm120_rows_common.inc`.
//! Session T-18 (2026-11-08): batch 1 lifted the 2026-08/09 bug-wave pin (the verified rows take their measured status);
//! batch 2 retired the whole-key twins of the long-tail named exceptions as `_meta.key_aliases` (aliases for twins -- the
//! alias key's canonical word decodes through the target family key vendor-true, 0 census witnesses).

const FAMILY: &str = "memory";
const SOURCE: &str = "rows-memory-2026-11-07";
const MNEMONICS: &[&str] = &["LDG", "STG", "LD", "ST", "LDS", "STS", "LDL", "STL", "LDGSTS", "LDGMC", "LDSM", "STSM", "MOVM", "CCTL", "QSPC", "LDGDEPBAR", "UTMALDG", "UTMASTG", "UTMACCTL", "UTMACMDFLUSH", "UBLKCP", "UBLKRED", "UBLKPF"];
const FIXTURE: &str = include_str!("fixtures/sm120_rows_memory_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 270;
const ALIAS_ROWS: usize = 4;
const DEAD_ROWS: usize = 0;
const FORM_WORDS: usize = 13833;
const WITNESS_WORDS: usize = 159;
/// Harvest rows of the family's mnemonics that batches 12-14 measure or retire on their own branches (LDG.256 /
/// STG.256 / REDG lattices): harvest on this base, not this family's; 0 once those batches are on `main`.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
    ("CCTL.IVALL_?_?", "CCTL"),
    ("CCTL.IVALL_P", "CCTL"),
    ("LDG.E.STRONG.GPU_R_ARURI", "LDG_R_ARURI"),
    ("LDS_P_R_A", "LDS_R_ARI"),
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- `G/NEEDS_OWNER.md`.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("CCTL.E.PF1_AR", "", "the key does not spell the vendor text: 'CCTL.PF1 [R48+0x5a5a5a5a]' -> CCTL.PF1_ARI / 'PF1'"),
    ("CCTL.E.PF2_AR", "", "the key does not spell the vendor text: 'CCTL.PF1 [R48+0x5a5a5a5a]' -> CCTL.PF1_ARI / 'PF1'"),
    ("CCTL.E.PML2_AR", "", "the key does not spell the vendor text: 'CCTL.PF2 [R48+0x5a5a5a5a]' -> CCTL.PF2_ARI / 'PF2'"),
    ("LD_R_dARI", "E,STRONG,SYS", "bit 40 outside the fields moves operand 2 of the same form: 'LD.E.STRONG.SYS R16, desc[UR48][R32.64+0x1]'"),
    ("STL_AURI_R", "", "field bit 72 (sub_ur0 tok 1) is text-inert"),
    ("STL_AURI_R", "128", "field bit 72 (sub_ur0 tok 1) is text-inert"),
    ("STL_AURI_R", "64", "field bit 72 (sub_ur0 tok 1) is text-inert"),
    ("STL_P_ARI_R", "", "the key does not spell the vendor text: 'STL.EF.U8 [R48+0x5a5a5a], R64' -> STL.EF.U8_ARI_R / 'EF,U8'"),
    ("STSM.8.MT168.2_AR_R", "", "the key does not spell the vendor text: 'STSM.8.MT168.2 [R32], R0' -> STSM.8.MT168.2_ARI_R / '2,8,MT168'"),
    ("STS_ARURI_R", "", "field bit 72 (sub_ur1 tok 1) is text-inert"),
    ("STS_ARURI_R", "128", "field bit 72 (sub_ur1 tok 1) is text-inert"),
    ("STS_ARURI_R", "64", "field bit 72 (sub_ur1 tok 1) is text-inert"),
    ("STS_ARURI_R", "S16", "field bit 72 (sub_ur1 tok 1) is text-inert"),
    ("STS_ARURI_R", "S8", "field bit 72 (sub_ur1 tok 1) is text-inert"),
    ("STS_ARURI_R", "U16", "field bit 72 (sub_ur1 tok 1) is text-inert"),
    ("STS_ARURI_R", "U8", "field bit 72 (sub_ur1 tok 1) is text-inert"),
    ("UBLKCP.S.G_AUR_AUR_UR", "", "the key does not spell the vendor text: 'UBLKCP.G.G [UR32], [UR48], UR64' -> UBLKCP.G.G_AURI_AURI_UR / 'G,G'"),
    ("UBLKPF.L2_AUR_UR", "", "the key does not spell the vendor text: 'UBLKPF.L2 [UR32], UR48' -> UBLKPF.L2_AURI_UR / 'L2'"),
    ("UBLKRED.G.S.ADD.S32_AUR_AUR_UR", "", "the key does not spell the vendor text: 'UBLKRED.G.INVALID0.ADD [UR32], [UR48], UR64' -> UBLKRED.G.INVALID0.ADD_AURI_AURI_UR / 'ADD,G,INVALID0'"),
    ("UBLKRED.G.S.ADD_AUR_AUR_UR", "", "the key does not spell the vendor text: 'UBLKRED.G.INVALID0.ADD [UR32], [UR48], UR64' -> UBLKRED.G.INVALID0.ADD_AURI_AURI_UR / 'ADD,G,INVALID0'"),
];

include!("sm120_rows_common.inc");

//! SM120 integer ALU long tail (VIMNMX / IADD / IMAD / IADD3 / IMNMX / PRMT / LOP3 / SEL / MOV / FLO / LDC / S2R / FHADD / DMUL / DADD …) (session G run 5, 2026-11-07; KNOWN_ISSUES T1): the remaining harvest rows of
//! VIMNMX, IADD, IMAD, IADD3, IMNMX, IABS, VIADD, SGXT, BMSK, PRMT, LOP3, SEL, MOV, FLO, POPC, BREV, R2UR, LDC, S2R, CS2R, MOV64IUR, LDCU, S2UR, FHADD, DMUL, DADD verified row by row with nvdisasm 13.1 over the whole
//! 128-bit word by `tools/probes/re_sm120_rows.py --family intalu` -- 183 rows measured (7746 canonical +
//! field words, 195 census witnesses), 1 shadowed keys (1 rows) retired as aliases, 10 unreachable
//! rows of staying keys deleted, 1 named exceptions. Fixture `tests/fixtures/sm120_rows_intalu_nvdisasm.jsonl`; the test body is `tests/sm120_rows_common.inc`.
//! Session T-18 (2026-11-08): batch 1 lifted the 2026-08/09 bug-wave pin (the verified rows take their measured status);
//! batch 2 retired the whole-key twins of the long-tail named exceptions as `_meta.key_aliases` (aliases for twins -- the
//! alias key's canonical word decodes through the target family key vendor-true, 0 census witnesses).
//! Session T-19 (2026-11-08, T/NEEDS_OWNER.md 55 -- R's decisions): the field-narrowing pass over the last harvest rows
//! (`MANUAL_ROW_FIELDS` of the probe: over-wide predicate windows, the 9-bit `sub_ur`, the undeclared IADD3 carry-out,
//! the BSSY target, the `.H1` selector, the paired `BF16_V2` immediate type), the renames of mis-named keys to the vendor's
//! spelling (`RENAMED_FROM`), the hand-retired twins (`MANUAL_ALIAS` / `MANUAL_DEAD`), 9 junk keys deleted whole
//! (`DELETE`: every canonical word illegal, or another form's words) and 2 design rows marked `_src: "modelled"` (`MODELLED`, the
//! pinning test in each note). The rows left without `_src` are the documented owner items of KNOWN_ISSUES T1.

const FAMILY: &str = "intalu";
const SOURCE: &str = "rows-intalu-2026-11-07";
const MNEMONICS: &[&str] = &["VIMNMX", "IADD", "IMAD", "IADD3", "IMNMX", "IABS", "VIADD", "SGXT", "BMSK", "PRMT", "LOP3", "SEL", "MOV", "FLO", "POPC", "BREV", "R2UR", "LDC", "S2R", "CS2R", "MOV64IUR", "LDCU", "S2UR", "FHADD", "DMUL", "DADD"];
const FIXTURE: &str = include_str!("fixtures/sm120_rows_intalu_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 183;
const ALIAS_ROWS: usize = 1;
const DEAD_ROWS: usize = 10;
const FORM_WORDS: usize = 7746;
const WITNESS_WORDS: usize = 195;
/// Harvest rows of the family's mnemonics that batches 12-14 measure or retire on their own branches (LDG.256 /
/// STG.256 / REDG lattices): harvest on this base, not this family's; 0 once those batches are on `main`.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
    ("IADD.X_R_P_R_R_R", "IADD_R_P_R_R_P"),
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- `G/NEEDS_OWNER.md`.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("FLO_R_UR", "SH,U32", "the key does not spell the vendor text: 'FLO.U32.SH R16, R32' -> FLO.U32.SH_R_R / 'SH,U32'"),
];

include!("sm120_rows_common.inc");

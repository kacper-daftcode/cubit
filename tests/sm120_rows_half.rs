//! SM120 half-precision long tail (HFMA2 / HMNMX2 / HADD2 / HSET2 / F2FP / I2FP / F2IP / I2IP / UF2FP / UI2FP / F2F / UF2I / UI2F) (session G run 5, 2026-11-07; KNOWN_ISSUES T1): the remaining harvest rows of
//! HFMA2, HMNMX2, HADD2, HSET2, F2FP, I2FP, F2IP, I2IP, UF2FP, UI2FP, F2F, UF2I, UI2F verified row by row with nvdisasm 13.1 over the whole
//! 128-bit word by `tools/probes/re_sm120_rows.py --family half` -- 76 rows measured (3270 canonical +
//! field words, 9 census witnesses), 5 shadowed keys (5 rows) retired as aliases, 0 unreachable
//! rows of staying keys deleted, 2 named exceptions. Fixture `tests/fixtures/sm120_rows_half_nvdisasm.jsonl`; the test body is `tests/sm120_rows_common.inc`.
//! Session T-18 (2026-11-08): batch 1 lifted the 2026-08/09 bug-wave pin (the verified rows take their measured status);
//! batch 2 retired the whole-key twins of the long-tail named exceptions as `_meta.key_aliases` (aliases for twins -- the
//! alias key's canonical word decodes through the target family key vendor-true, 0 census witnesses).
//! Session T-19 (2026-11-08, T/NEEDS_OWNER.md 55 -- R's decisions): the field-narrowing pass over the last harvest rows
//! (`MANUAL_ROW_FIELDS` of the probe: over-wide predicate windows, the 9-bit `sub_ur`, the undeclared IADD3 carry-out,
//! the BSSY target, the `.H1` selector, the paired `BF16_V2` immediate type), the renames of mis-named keys to the vendor's
//! spelling (`RENAMED_FROM`), the hand-retired twins (`MANUAL_ALIAS` / `MANUAL_DEAD`), 0 junk keys deleted whole
//! (`DELETE`: every canonical word illegal, or another form's words) and 1 design rows marked `_src: "modelled"` (`MODELLED`, the
//! pinning test in each note). The rows left without `_src` are the documented owner items of KNOWN_ISSUES T1.

const TABLE: &str = "tables/sm120.json";
const FAMILY: &str = "half";
const SOURCE: &str = "rows-half-2026-11-07";
const MNEMONICS: &[&str] = &["HFMA2", "HMNMX2", "HADD2", "HSET2", "F2FP", "I2FP", "F2IP", "I2IP", "UF2FP", "UI2FP", "F2F", "UF2I", "UI2F"];
const FIXTURE: &str = include_str!("fixtures/sm120_rows_half_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 76;
const ALIAS_ROWS: usize = 5;
const DEAD_ROWS: usize = 0;
const FORM_WORDS: usize = 3270;
const WITNESS_WORDS: usize = 9;
/// Harvest rows of the family's mnemonics that batches 12-14 measure or retire on their own branches (LDG.256 /
/// STG.256 / REDG lattices): harvest on this base, not this family's; 0 once those batches are on `main`.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
    ("F2FP.BF16.F32.PACK_AB_P_R_R_R", "F2FP_R_R_R"),
    ("F2FP.RELU.BF16.F32.PACK_AB_P_R_R_R", "F2FP.RELU.BF16.F32.PACK_AB_R_R_R"),
    ("F2FP.SATFINITE.BF16.F32.PACK_AB_P_R_R_R", "F2FP.SATFINITE.BF16.F32.PACK_AB_R_R_R"),
    ("F2FP.SATFINITE.F16.F32.PACK_AB_P_R_R_R", "F2FP.SATFINITE.F16.F32.PACK_AB_R_R_R"),
    ("F2FP.SATFINITE.RELU.F16.F32.PACK_AB_P_R_R_R", "F2FP.SATFINITE.RELU.F16.F32.PACK_AB_R_R_R"),
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- `G/NEEDS_OWNER.md`.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("F2FP_R_R", "BF16,F32,PACK_AB", "the key does not spell the vendor text: 'F2FP.BF16.F32.PACK_AB R16, RZ, UR4' -> F2FP.BF16.F32.PACK_AB_R_R_UR / 'BF16,F32,PACK_AB'"),
    ("F2FP_R_R", "F16,F32,PACK_AB", "the key does not spell the vendor text: 'F2FP.F16.F32.PACK_AB R16, RZ, R32' -> F2FP.F16.F32.PACK_AB_R_R_R / 'F16,F32,PACK_AB'"),
];

include!("sm120_rows_common.inc");

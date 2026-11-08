//! SM120 atomics long tail (ATOMG / ATOM / REDG per-key remainders; ATOMS stays for the wave re-pins) (session G run 5, 2026-11-07; KNOWN_ISSUES T1): the remaining harvest rows of
//! ATOMG, ATOM, ATOMS, REDG verified row by row with nvdisasm 13.1 over the whole
//! 128-bit word by `tools/probes/re_sm120_rows.py --family atomic` -- 68 rows measured (4015 canonical +
//! field words, 11 census witnesses), 6 shadowed keys (6 rows) retired as aliases, 0 unreachable
//! rows of staying keys deleted, 1 named exceptions. Fixture `tests/fixtures/sm120_rows_atomic_nvdisasm.jsonl`; the test body is `tests/sm120_rows_common.inc`.
//! Session T-18 (2026-11-08): batch 1 lifted the 2026-08/09 bug-wave pin (the verified rows take their measured status);
//! batch 2 retired the whole-key twins of the long-tail named exceptions as `_meta.key_aliases` (aliases for twins -- the
//! alias key's canonical word decodes through the target family key vendor-true, 0 census witnesses).

const FAMILY: &str = "atomic";
const SOURCE: &str = "rows-atomic-2026-11-07";
const MNEMONICS: &[&str] = &["ATOMG", "ATOM", "ATOMS", "REDG"];
const FIXTURE: &str = include_str!("fixtures/sm120_rows_atomic_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 68;
const ALIAS_ROWS: usize = 6;
const DEAD_ROWS: usize = 0;
const FORM_WORDS: usize = 4015;
const WITNESS_WORDS: usize = 11;
/// Harvest rows of the family's mnemonics that batches 12-14 measure or retire on their own branches (LDG.256 /
/// STG.256 / REDG lattices): harvest on this base, not this family's; 0 once those batches are on `main`.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
    ("ATOMG.E.ADD.STRONG.GPU_P_R_dARI_R", "ATOMG_P_R_dARI_R"),
    ("ATOMG.E.MAX.S32.STRONG.GPU_P_R_dARI_UR", "ATOMG_P_R_dARI_R"),
    ("ATOMG.E.MIN.STRONG.GPU_P_R_dARI_UR", "ATOMG_P_R_dARI_R"),
    ("ATOMS_R_ARI", "ATOMS_R_ARURI"),
    ("REDG.E.MAX.S32.STRONG.GPU_dARI_R", "REDG_dARI_R"),
    ("REDG.E.MIN.STRONG.GPU_dARI_R", "REDG_dARI_R"),
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- `G/NEEDS_OWNER.md`.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("ATOMG.E.ADD.F64.RN.STRONG.GPU_P_R_AR_R", "", "the key does not spell the vendor text: '@P0 ATOMG.ADD.EF.F16x2.RN P0, R0, [R0], R0' -> ATOMG.ADD.EF.F16x2.RN_P_R_ARI_R / 'ADD,EF,F16x2,RN'"),
];

include!("sm120_rows_common.inc");

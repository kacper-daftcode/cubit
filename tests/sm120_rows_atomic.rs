//! SM120 atomics long tail (ATOMG / ATOM / REDG per-key remainders; ATOMS stays for the wave re-pins) (session G run 5, 2026-11-07; KNOWN_ISSUES T1): the remaining harvest rows of
//! ATOMG, ATOM, ATOMS, REDG verified row by row with nvdisasm 13.1 over the whole
//! 128-bit word by `tools/probes/re_sm120_rows.py --family atomic` -- 68 rows measured (4015 canonical +
//! field words, 11 census witnesses), 4 shadowed keys (4 rows) retired as aliases, 0 unreachable
//! rows of staying keys deleted, 3 named exceptions. Fixture `tests/fixtures/sm120_rows_atomic_nvdisasm.jsonl`; the test body is `tests/sm120_rows_common.inc`.
//! Session T-18 (2026-11-08): the rows run 5 verified but held back while the 2026-08/09 bug-wave tests pinned their harvest
//! structure (`EXCEPTION_PREFIXES`, G/NEEDS_OWNER.md 12) take their measured status -- those suites are re-pinned to the
//! measured doctrine in the same commit (blackwell-isa fd736a7).

const FAMILY: &str = "atomic";
const SOURCE: &str = "rows-atomic-2026-11-07";
const MNEMONICS: &[&str] = &["ATOMG", "ATOM", "ATOMS", "REDG"];
const FIXTURE: &str = include_str!("fixtures/sm120_rows_atomic_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 68;
const ALIAS_ROWS: usize = 4;
const DEAD_ROWS: usize = 0;
const FORM_WORDS: usize = 4015;
const WITNESS_WORDS: usize = 11;
/// Harvest rows of the family's mnemonics that batches 12-14 measure or retire on their own branches (LDG.256 /
/// STG.256 / REDG lattices): harvest on this base, not this family's; 0 once those batches are on `main`.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
    ("ATOMG.E.ADD.STRONG.GPU_P_R_dARI_R", "ATOMG_P_R_dARI_R"),
    ("ATOMS_R_ARI", "ATOMS_R_ARURI"),
    ("REDG.E.MAX.S32.STRONG.GPU_dARI_R", "REDG_dARI_R"),
    ("REDG.E.MIN.STRONG.GPU_dARI_R", "REDG_dARI_R"),
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- `G/NEEDS_OWNER.md`.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("ATOMG.E.ADD.F64.RN.STRONG.GPU_P_R_AR_R", "", "the key does not spell the vendor text: '@P0 ATOMG.ADD.EF.F16x2.RN P0, R0, [R0], R0' -> ATOMG.ADD.EF.F16x2.RN_P_R_ARI_R / 'ADD,EF,F16x2,RN'"),
    ("ATOMG.E.MAX.S32.STRONG.GPU_P_R_dARI_UR", "", "the key does not spell the vendor text: 'ATOMG.E.MAX.S32.STRONG.GPU PT, R32, desc[UR48][R64.64+-0x25a5a6], R96' -> ATOMG.E.MAX.S32.STRONG.GPU_P_R_dARI_R / 'E,GPU,MAX,S32,STRONG'"),
    ("ATOMG.E.MIN.STRONG.GPU_P_R_dARI_UR", "", "the key does not spell the vendor text: 'ATOMG.E.MIN.STRONG.GPU PT, R32, desc[UR48][R64.64+-0x25a5a6], R96' -> ATOMG.E.MIN.STRONG.GPU_P_R_dARI_R / 'E,GPU,MIN,STRONG'"),
];

include!("sm120_rows_common.inc");

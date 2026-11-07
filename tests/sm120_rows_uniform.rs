//! SM120 uniform-datapath long tail (USHF / ULEA / ULOP3 / UFLO / UMOV / UIADD3 / UIMAD / USEL / UIMNMX / UBMSK / REDUX …) (session G run 5, 2026-11-07; KNOWN_ISSUES T1): the remaining harvest rows of
//! USHF, ULEA, ULOP3, UFLO, UMOV, UIADD3, UIMAD, USEL, UIMNMX, UBMSK, UVIMNMX, UPRMT, UCLEA, UBREV, UPOPC, UISETP, REDUX, ELECT verified row by row with nvdisasm 13.1 over the whole
//! 128-bit word by `tools/probes/re_sm120_rows.py --family uniform` -- 95 rows measured (3628 canonical +
//! field words, 67 census witnesses), 22 shadowed keys (22 rows) retired as aliases, 0 unreachable
//! rows of staying keys deleted, 17 named exceptions. Fixture `tests/fixtures/sm120_rows_uniform_nvdisasm.jsonl`; the test body is `tests/sm120_rows_common.inc`.

const FAMILY: &str = "uniform";
const SOURCE: &str = "rows-uniform-2026-11-07";
const MNEMONICS: &[&str] = &["USHF", "ULEA", "ULOP3", "UFLO", "UMOV", "UIADD3", "UIMAD", "USEL", "UIMNMX", "UBMSK", "UVIMNMX", "UPRMT", "UCLEA", "UBREV", "UPOPC", "UISETP", "REDUX", "ELECT"];
const FIXTURE: &str = include_str!("fixtures/sm120_rows_uniform_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 95;
const ALIAS_ROWS: usize = 22;
const DEAD_ROWS: usize = 0;
const FORM_WORDS: usize = 3628;
const WITNESS_WORDS: usize = 67;
/// Harvest rows of the family's mnemonics that batches 12-14 measure or retire on their own branches (LDG.256 /
/// STG.256 / REDG lattices): harvest on this base, not this family's; 0 once those batches are on `main`.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
    ("UBMSK.W_UR_UR_II", "UBMSK_UR_UR_II"),
    ("UBMSK.W_UR_UR_UR", "UBMSK_UR_UR_UR"),
    ("UFLO.U32.SH_UR_UR", "UFLO_UR_UR"),
    ("UFLO.U32_UR_UR", "UFLO_UR_UR"),
    ("UIADD3.X_UR_UP_UP_?_?_UR_UP_UP", "UIADD3_UR_UP_UP_UR_UR_UR_UP_UP"),
    ("UIADD3.X_UR_UP_UP_?_UR_UR_UP_UP", "UIADD3_UR_UP_UP_UR_UR_UR_UP_UP"),
    ("UIADD3_UP0_UR_UP_UP_UR_II_UR", "UIADD3_UR_UP_UP_UR_II_UR"),
    ("UIMNMX.S64_UP_UP_UR_UR_UR_UP_?", "UIMNMX_UP_UP_UR_UR_UR_UP_UP"),
    ("UIMNMX.S64_UP_UP_UR_UR_UR_UP_UP", "UIMNMX_UP_UP_UR_UR_UR_UP_UP"),
    ("UIMNMX.U64_UP_UP_UR_UR_UR_UP_UP", "UIMNMX_UP_UP_UR_UR_UR_UP_UP"),
    ("ULOP3.LUT_UR_UR_II_UR_II_?", "ULOP3_UR_UR_II_UR_II_UP"),
    ("ULOP3.LUT_UR_UR_UR_UR_II_?", "ULOP3_UR_UR_UR_UR_II_UP"),
    ("ULOP3_UP_UR_UR_II_UR_II_P", "ULOP3_UR_UR_II_UR_II_UP"),
    ("UMOV.64_UR_II", "UMOV_UR_II"),
    ("UMOV_UR_?_II_II_II_?", "UMOV_UR_UR"),
    ("UMOV_UR_II_II", "UMOV_UR_II"),
    ("UMOV_UR_II_II_?", "UMOV_UR_II"),
    ("UMOV_UR_UR_II_II_?", "UMOV_UR_UR"),
    ("USEL.64_UR_UR_II_UP", "USEL_UR_UR_II_UP"),
    ("USEL_UR_UR_II_?", "USEL_UR_UR_II_UP"),
    ("UVIMNMX.S32_UR_UR_II_?", "UVIMNMX_UR_UR_II_UP"),
    ("UVIMNMX.U32_UR_UR_II_?", "UVIMNMX_UR_UR_II_UP"),
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- `G/NEEDS_OWNER.md`.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("REDUX_UR_R", "AND", "the key does not spell the vendor text: 'REDUX UR32, R48' -> REDUX_UR_R / ''"),
    ("UIADD3.64_UR_UP_UP_UR_II_UR", "", "bit 64 outside the fields moves operand 6 of the same form: 'UIADD3.64 UR16, UPT, UPT, UR32, 0x5a5a5a5a, UR254'"),
    ("UIADD3_UR_UP_UP_UR_II_II", "", "the key does not spell the vendor text: 'UIADD3 UR32, UPT, UPT, UR96, 0x5a5a5a5a, URZ' -> UIADD3_UR_UP_UP_UR_II_UR / ''"),
    ("UIMNMX_P_P_UR_UR_UR_P_P", "S64", "the key does not spell the vendor text: 'UIMNMX.U32 UPT, UPT, UR64, UR80, UR96, UPT, UPT' -> UIMNMX.U32_UP_UP_UR_UR_UR_UP_UP / 'U32'"),
    ("UISETP_UP_UP_UR_UR_UP", "", "the key does not spell the vendor text: '@UP0 UISETP.LT.U32.AND UPT, UPT, UR16, UR24, UPT' -> UISETP.LT.U32.AND_UP_UP_UR_UR_UP / 'AND,LT,U32'"),
    ("ULEA_UR_UP_UR_II_II", "", "field bit 84 (pred tok 2) is text-inert"),
    ("ULEA_UR_UP_UR_UR_II", "", "field bit 84 (pred tok 2) is text-inert"),
    ("ULEA_UR_UP_UR_UR_UR_II", "HI", "field bit 84 (pred tok 2) is text-inert"),
    ("ULOP3.LUT_UR_UR_II_II_II_II", "", "the key does not spell the vendor text: 'ULOP3.LUT UR1, UR1, 0xb4b4b4b4, URZ, 0xe8, !UPT' -> ULOP3.LUT_UR_UR_II_UR_II_UP / 'LUT'"),
    ("ULOP3.LUT_UR_UR_UR_UR_II_II", "", "the key does not spell the vendor text: 'ULOP3.LUT UR1, UR1, UR1, URZ, 0x5a, !UPT' -> ULOP3.LUT_UR_UR_UR_UR_II_UP / 'LUT'"),
    ("ULOP3_UP_UR_UR_II_UR_II_UP", "LUT", "bit 64 outside the fields moves operand 5 of the same form: 'ULOP3.LUT UP3, UR16, UR32, 0x5a5a5a5a, UR254, 0xc0, !UPT'"),
    ("ULOP3_UR_UR_UR_UR_II_UP", "LUT", "bit 87 outside the fields moves operand 6 of the same form: 'ULOP3.LUT UR16, UR32, UR48, UR64, 0x5a, !UP6'"),
    ("UPRMT_UR_UR_II_II", "", "the key does not spell the vendor text: 'UPRMT UR1, UR1, 0x7771, URZ' -> UPRMT_UR_UR_II_UR / ''"),
    ("USEL.64_UR_UR_UR_UR", "", "the key does not spell the vendor text: 'USEL.64 UR2, UR2, UR2, !UP0' -> USEL.64_UR_UR_UR_UP / '64'"),
    ("USEL_UR_UR_II_II", "", "the key does not spell the vendor text: 'USEL UR1, UR1, 0x5a5a5a5a, !UP0' -> USEL_UR_UR_II_UP / ''"),
    ("UVIMNMX_UR_UR_II_P", "S32", "the key does not spell the vendor text: 'UVIMNMX.U32 UR32, UR48, 0x5a5a5a5a, UPT' -> UVIMNMX.U32_UR_UR_II_UP / 'U32'"),
    ("UVIMNMX_UR_UR_UR_P", "S32", "the key does not spell the vendor text: 'UVIMNMX.U32 UR32, UR48, UR64, UPT' -> UVIMNMX.U32_UR_UR_UR_UP / 'U32'"),
];

include!("sm120_rows_common.inc");

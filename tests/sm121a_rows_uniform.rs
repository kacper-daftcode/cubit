//! SM121a uniform-datapath long tail (session T-23, 2026-11-08; KNOWN_ISSUES T1, the GB10 line): the remaining harvest rows of USHF / ULEA / ULOP3 / UFLO / UMOV / UIADD3 / UIMAD / USEL / UIMNMX / UBMSK / UVIMNMX / UPRMT / UCLEA / UBREV / UPOPC / UISETP / REDUX / ELECT on sm121a.json verified row by row with nvdisasm 13.1 (-b SM121) over the whole 128-bit word by `tools/probes/re_sm120_rows.py --family uniform --arch SM121` (T-22's UIADD3 pass extended to the whole family; the junk key UIADD3_UR_UP_UP_UR_UR_R_II_P it had named), the GB10 census words as witnesses; the shadowed dotted keys retired as aliases; the rows left are named.
//! Fixture `tests/fixtures/sm121a_rows_uniform_full_nvdisasm.jsonl` (`tools/probes/re_sm120_rows.py probe --family uniform --arch SM121`,
//! nvdisasm 13.1, the table's own corpus words as witnesses); the test body is `tests/sm120_rows_common.inc` (session T-23, 2026-11-08).

const TABLE: &str = "tables/sm121a.json";
const FAMILY: &str = "uniform";
const SOURCE: &str = "rows-uniform-2026-11-07";
const MNEMONICS: &[&str] = &["USHF", "ULEA", "ULOP3", "UFLO", "UMOV", "UIADD3", "UIMAD", "USEL", "UIMNMX", "UBMSK", "UVIMNMX", "UPRMT", "UCLEA", "UBREV", "UPOPC", "UISETP", "REDUX", "ELECT"];
const FIXTURE: &str = include_str!("fixtures/sm121a_rows_uniform_full_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 129;
const ALIAS_ROWS: usize = 32;
const DEAD_ROWS: usize = 3;
const FORM_WORDS: usize = 6381;
const WITNESS_WORDS: usize = 59;
/// Rows of the family's mnemonics another batch measures on its own branch: none on this table.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
    ("UFLO.U32.SH_UR_UR", "UFLO_UR_UR"),
    ("UFLO.U32_UR_UR", "UFLO_UR_UR"),
    ("UIADD3.X_UR_UP_UP_?_?_UR_UP_UP", "UIADD3_UR_UP_UP_UR_UR_UR_UP_UP"),
    ("UIADD3.X_UR_UP_UP_?_UR_UR_UP_UP", "UIADD3_UR_UP_UP_UR_UR_UR_UP_UP"),
    ("UIADD3_UP0_UR_UP_UP_UR_II_UR", "UIADD3_UR_UP_UP_UR_II_UR"),
    ("ULEA.HI.X_UR_UR_UR_UR_II_UP", "ULEA_UR_UR_UR_UR_II_UP"),
    ("ULEA.HI_UR_UR_UR_UR_II", "ULEA_UR_UR_UR_UR_II"),
    ("ULEA_UR_UR_UR_II_?", "ULEA_UR_UR_UR_II"),
    ("ULOP3.LUT_UR_UR_II_UR_II_?", "ULOP3_UR_UR_II_UR_II_UP"),
    ("ULOP3.LUT_UR_UR_UR_UR_II_?", "ULOP3_UR_UR_UR_UR_II_UP"),
    ("ULOP3_UP_UR_UR_II_UR_II_P", "ULOP3_UR_UR_II_UR_II_UP"),
    ("ULOP3_UP_UR_UR_II_UR_II_UP", "ULOP3.LUT_UP_UR_UR_II_UR_II_UP"),
    ("UMOV.64_UR_II", "UMOV_UR_II"),
    ("UMOV_UR_?_II_II_II_?", "UMOV_UR_UR"),
    ("UMOV_UR_II_II", "UMOV_UR_II"),
    ("UMOV_UR_II_II_?", "UMOV_UR_II"),
    ("UMOV_UR_UR_II_II_?", "UMOV_UR_UR"),
    ("USHF.L.U32_P_UR_UR_II_?", "USHF_UR_UR_II_UR"),
    ("USHF.L.U32_UP0_UR_UR_II_UR", "USHF_UR_UR_II_UR"),
    ("USHF.L.U32_UR_UR_II_UR", "USHF_UR_UR_II_UR"),
    ("USHF.L.U64.HI_UR_UR_II_UR", "USHF_UR_UR_II_UR"),
    ("USHF.L.U64.HI_UR_UR_UR_II", "USHF_UR_UR_UR_II"),
    ("USHF.L.W.U32.HI_UR_UR_II_UR", "USHF_UR_UR_II_UR"),
    ("USHF.R.S32.HI_UR_UR_II_UR", "USHF_UR_UR_II_UR"),
    ("USHF.R.S32.HI_UR_UR_II_UR_II_?", "USHF_UR_UR_II_UR"),
    ("USHF.R.S32.HI_UR_UR_II_UR_II_II_?", "USHF_UR_UR_II_UR"),
    ("USHF.R.S32.HI_UR_UR_II_UR_UR", "USHF_UR_UR_II_UR"),
    ("USHF.R.S64_UR_UR_II_UR", "USHF_UR_UR_II_UR"),
    ("USHF.R.U32.HI_UR_UR_II_UR", "USHF_UR_UR_II_UR"),
    ("USHF.R.U64_UR_UR_II_UR", "USHF_UR_UR_II_UR"),
    ("USHF.R.W.U32_UR_UR_UR_II", "USHF_UR_UR_UR_II"),
    ("UVIMNMX.S32_UR_UR_II_?", "UVIMNMX.S32_UR_UR_II_UP"),
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- the probe's verdict names each.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("UFLO_UR_UR", "U32", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'UFLO.U32 UR16, -UR32' re-encode mismatch:000fe200080e010000000020001072bd for 'UFLO.U32 UR16, ~UR32'"),
    ("UIADD3_UR_P_P_UR_UR_UR_UP_UP", "X", "the key does not spell the vendor text: 'UIADD3 UR32, UPT, UPT, URZ, URZ, UR40' -> UIADD3_UR_UP_UP_UR_UR_UR / ''"),
    ("UIADD3_UR_UP_UP_UR_II_II", "", "the key does not spell the vendor text: 'UIADD3 UR32, UPT, UPT, UR96, 0x5a5a5a5a, URZ' -> UIADD3_UR_UP_UP_UR_II_UR / ''"),
    ("UIMAD_UR_UP_UR_II_UR", "U32,WIDE", "field bit 84 (pred tok 2) is text-inert"),
    ("UIMAD_UR_UP_UR_UR_UR", "U32,WIDE", "field bit 84 (pred tok 2) is text-inert"),
    ("UIMAD_UR_UR_II_UR", "U32", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'UIMAD UR32, UR48, 0x5a5a5a5a, -UR64' re-encode mismatch:000fe2000f8e0a405a5a5a5a302078a4 for 'UIMAD.U32 UR32, UR48, 0x5a5a5a5a, -UR64'"),
    ("UIMAD_UR_UR_II_UR", "U32,WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'UIMAD.WIDE.U32 UR32, UR48, 0x5a5a5a5a, UR80' re-encode mismatch:000fe2000f8e00505a5a5a5a302078a5 for 'UIMAD.WIDE.U32 UR32, UR48, 0x5a5a5a5a, -UR80'"),
    ("UIMAD_UR_UR_II_UR_UP", "U32,WIDE,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'UIMAD.WIDE.U32.X UR16, UR32, 0x5a5a5a5a, UR64, UPT' re-encode mismatch:000fe2000b8e04405a5a5a5a201078a5 for 'UIMAD.WIDE.U32.X UR16, UR32, 0x5a5a5a5a, ~UR64, UPT'"),
    ("UIMAD_UR_UR_UR_UR", "U32,WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'UIMAD.WIDE.U32 UR32, UR48, UR64, UR80' re-encode mismatch:000fe2000f8e005000000040302072a5 for 'UIMAD.WIDE.U32 UR32, UR48, UR64, -UR80'"),
    ("UIMAD_UR_UR_UR_UR", "WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'UIMAD.WIDE UR16, UR32, UR48, UR64' re-encode mismatch:000fe2000f8e024000000030201072a5 for 'UIMAD.WIDE UR16, UR32, UR48, -UR64'"),
    ("UIMAD_UR_UR_UR_UR_UP", "U32,WIDE,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'UIMAD.WIDE.U32.X UR32, UR48, UR64, UR80, UPT' re-encode mismatch:000fe2000b8e045000000040302072a5 for 'UIMAD.WIDE.U32.X UR32, UR48, UR64, ~UR80, UPT'"),
    ("UIMNMX.S64_UP_UP_UR_UR_UR_UP_?", "", "the key does not spell the vendor text: 'UIMNMX.S64 UPT, UPT, UR2, UR2, UR2, UPT, !UPT' -> UIMNMX.S64_UP_UP_UR_UR_UR_UP_UP / 'S64'"),
    ("UIMNMX_P_P_UR_UR_UR_P_P", "S64", "the key does not spell the vendor text: 'UIMNMX.U32 UPT, UPT, UR64, UR80, UR96, UPT, UPT' -> UIMNMX.U32_UP_UP_UR_UR_UR_UP_UP / 'U32'"),
    ("UIMNMX_UP_UP_UR_UR_UR_UP_UP", "S64", "bit 16 outside the fields moves operand 3 of the same form: 'UIMNMX.S64 UPT, UPT, UR1, UR0, UR2, UPT, !UPT'"),
    ("ULEA.HI.SX32_UR_UR_II_II", "", "bit 16 outside the fields moves operand 1 of the same form: 'ULEA.HI.SX32 UR13, UR6, 0xfffffffd, 0x1c'"),
    ("ULEA.HI_UR_UR_II_UR_II", "", "bit 21 outside the fields moves operand 1 of the same form: 'ULEA.HI UR33, UR1, 0xffffffe1, URZ, 0x1a'"),
    ("ULEA_UR_UP_UR_II_II", "", "cubit mishandles the row's words (not tagged; T-23): field word bit 83: cubit 'ULEA UR32, UR64, 0x5a5a5a5a, 0x1a' re-encode error:no operand-compatible table entry; attempted keys: [(ULEA_UR_UR_II_II, \"\") REJECTED: operand 3 (imm 0x5a5a5a5a) has no field able to encode it;"),
    ("ULEA_UR_UP_UR_UR_II", "", "cubit mishandles the row's words (not tagged; T-23): cubit does not decode the canonical word: no instruction matches code 0x000000000f86d0ff0000006040207291 at opcode 0x0291 (+3 more)"),
    ("ULEA_UR_UR_II_II", "", "bit 21 outside the fields moves operand 1 of the same form: 'ULEA UR33, UR1, 0x1, 0x5'"),
    ("ULEA_UR_UR_II_II", "HI", "the key does not spell the vendor text: 'ULEA.HI UR1, UR1, 0x1, URZ, 0x1f' -> ULEA.HI_UR_UR_II_UR_II / 'HI'"),
    ("ULEA_UR_UR_II_II", "HI,X", "the key does not spell the vendor text: 'ULEA.HI.X UR1, UR1, 0xffffffff, UR1, 0xa, UP1' -> ULEA.HI.X_UR_UR_II_UR_II_UP / 'HI,X'"),
    ("ULEA_UR_UR_II_UR_II", "", "the key does not spell the vendor text: 'ULEA UR1, UP0, UR1, 0xfffff000, 0xa' -> ULEA_UR_UP_UR_II_II / ''"),
    ("ULEA_UR_UR_II_UR_II", "HI", "bit 20 outside the fields moves operand 1 of the same form: 'ULEA.HI UR17, UR1, 0x1, URZ, 0x1f'"),
    ("ULEA_UR_UR_II_UR_II", "HI,X", "the key does not spell the vendor text: 'ULEA.HI.X UR1, UR1, 0xffffffff, UR1, 0xa, UP0' -> ULEA.HI.X_UR_UR_II_UR_II_UP / 'HI,X'"),
    ("ULEA_UR_UR_II_UR_II_UP", "HI", "the key does not spell the vendor text: 'ULEA.HI UR1, UR1, 0xb4b4b4b5, URZ, 0x1f' -> ULEA.HI_UR_UR_II_UR_II / 'HI'"),
    ("ULEA_UR_UR_II_UR_II_UP", "HI,X", "bit 21 outside the fields moves operand 1 of the same form: 'ULEA.HI.X UR33, UR26, 0xffffffff, UR1, 0xa, UP0'"),
    ("ULEA_UR_UR_UR_II", "HI", "the key does not spell the vendor text: 'ULEA.HI UR1, UR1, 0x1, URZ, 0x1f' -> ULEA.HI_UR_UR_II_UR_II / 'HI'"),
    ("ULEA_UR_UR_UR_II", "HI,X", "the key does not spell the vendor text: 'ULEA.HI.X UR1, UR26, 0x7fffffff, UR1, 0xa, UP0' -> ULEA.HI.X_UR_UR_II_UR_II_UP / 'HI,X'"),
    ("ULEA_UR_UR_UR_UR_II", "", "the key does not spell the vendor text: 'ULEA.HI UR32, UR48, UR64, UR80, 0x1a' -> ULEA.HI_UR_UR_UR_UR_II / 'HI'"),
    ("ULEA_UR_UR_UR_UR_II", "HI,X", "the key does not spell the vendor text: 'ULEA.HI.X UR1, UR26, 0xffffffff, UR1, 0xa, UP0' -> ULEA.HI.X_UR_UR_II_UR_II_UP / 'HI,X'"),
    ("ULEA_UR_UR_UR_UR_II_UP", "HI", "the key does not spell the vendor text: 'ULEA.HI UR1, UR1, 0x1, URZ, 0x19' -> ULEA.HI_UR_UR_II_UR_II / 'HI'"),
    ("ULEA_UR_UR_UR_UR_II_UP", "HI,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'ULEA.HI.X UR32, UR48, -UR64, UR80, 0x1a, UPT' re-encode ok for 'ULEA.HI.X UR32, UR48, ~UR64, UR80, 0x1a, UPT' (+2 more)"),
    ("ULOP3.LUT_UR_UR_II_II_II_II", "", "the key does not spell the vendor text: 'ULOP3.LUT UR1, UR1, 0xb4b4b4b4, URZ, 0xe8, !UPT' -> ULOP3.LUT_UR_UR_II_UR_II_UP / 'LUT'"),
    ("ULOP3.LUT_UR_UR_UR_UR_II_II", "", "the key does not spell the vendor text: 'ULOP3.LUT UR1, UR1, UR1, URZ, 0x5a, !UPT' -> ULOP3.LUT_UR_UR_UR_UR_II_UP / 'LUT'"),
    ("ULOP3_UP_UR_UR_UR_UR_II_UP", "LUT", "bit 16 outside the fields moves operand 2 of the same form: 'ULOP3.LUT UP3, UR254, UR32, UR1, URZ, 0x5a, UP3'"),
    ("ULOP3_UR_UR_UR_UR_II_UP", "LUT", "cubit mishandles the row's words (not tagged; T-23): cubit does not decode the canonical word: no instruction matches code 0x000000000b8e5a500000004030207292 at opcode 0x0292 (+3 more)"),
    ("UPOPC_UR_UR", "", "field bit 32 (ureg tok 0) moves operand 2: 'UPOPC UR16, UR33'"),
    ("UPRMT_UR_UR_II_II", "", "the key does not spell the vendor text: 'UPRMT UR1, UR1, 0x7771, URZ' -> UPRMT_UR_UR_II_UR / ''"),
    ("USEL.64_UR_UR_II_UP", "", "bit 16 outside the fields moves operand 1 of the same form: 'USEL.64 UR3, UR2, 0x1, !UP1'"),
    ("USEL.64_UR_UR_UR_UP", "", "bit 16 outside the fields moves operand 1 of the same form: 'USEL.64 UR9, UR8, UR12, UP0'"),
    ("USEL.64_UR_UR_UR_UR", "", "the key does not spell the vendor text: 'USEL.64 UR2, UR2, UR2, !UP0' -> USEL.64_UR_UR_UR_UP / '64'"),
    ("USEL_UR_UR_II_?", "", "the key does not spell the vendor text: 'USEL UR3, URZ, 0x1, !UP0' -> USEL_UR_UR_II_UP / ''"),
    ("USEL_UR_UR_II_II", "", "the key does not spell the vendor text: 'USEL UR1, UR1, 0x5a5a5a5a, !UP0' -> USEL_UR_UR_II_UP / ''"),
    ("USEL_UR_UR_II_UP", "", "cubit mishandles the row's words (not tagged; T-23): field word bit 90: cubit 'no instruction matches code 0x000000000f8000005a5a5a5a201078' re-encode None for 'USEL UR16, UR32, 0x5a5a5a5a, !UPT'"),
    ("USHF.L.U32_UR_UR_II_II", "", "the key does not spell the vendor text: 'USHF.L.S64 UR32, UR48, 0x5a5a5a5a, URZ' -> USHF.L.S64_UR_UR_II_UR / 'L,S64'"),
    ("UVIMNMX.S32_UR_UR_II_UP", "", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'UVIMNMX.S32 UR16, UR32, 0xda5a5a5a, UPT' re-encode ok for 'UVIMNMX.S32 UR16, UR32, -0x25a5a5a6, UPT'"),
    ("UVIMNMX.S32_UR_UR_UR_UP", "", "bit 21 outside the fields moves operand 1 of the same form: 'UVIMNMX.S32 UR33, UR1, UR1, UPT'"),
    ("UVIMNMX.U32_UR_UR_II_?", "", "the key does not spell the vendor text: 'UVIMNMX.U32 UR5, UR63, 0x1, !UPT' -> UVIMNMX.U32_UR_UR_II_UP / 'U32'"),
    ("UVIMNMX.U32_UR_UR_II_UP", "", "bit 20 outside the fields moves operand 1 of the same form: 'UVIMNMX.U32 UR17, UR6, 0x2, UPT'"),
    ("UVIMNMX.U32_UR_UR_UR_UP", "", "bit 87 outside the fields moves operand 4 of the same form: 'UVIMNMX.U32 UR32, UR48, UR64, UP6'"),
    ("UVIMNMX_UR_UR_II_P", "S32", "the key does not spell the vendor text: 'UVIMNMX.U32 UR32, UR48, 0x5a5a5a5a, UPT' -> UVIMNMX.U32_UR_UR_II_UP / 'U32'"),
    ("UVIMNMX_UR_UR_II_UP", "S32", "the key does not spell the vendor text: 'UVIMNMX.S32 UR1, UR0, UR0, !UPT' -> UVIMNMX.S32_UR_UR_UR_UP / 'S32'"),
    ("UVIMNMX_UR_UR_II_UP", "U32", "bit 87 outside the fields moves operand 4 of the same form: 'UVIMNMX.U32 UR16, UR32, 0x5a5a5a5a, UP6'"),
    ("UVIMNMX_UR_UR_UR_P", "S32", "the key does not spell the vendor text: 'UVIMNMX.U32 UR32, UR48, UR64, UPT' -> UVIMNMX.U32_UR_UR_UR_UP / 'U32'"),
    ("UVIMNMX_UR_UR_UR_UP", "S32", "bit 21 outside the fields moves operand 1 of the same form: 'UVIMNMX.S32 UR33, UR0, UR0, !UPT'"),
    ("UVIMNMX_UR_UR_UR_UP", "U32", "field bit 2 (ureg tok 0) moves complex None: 'UI2I.U8.S32.SAT UR24, UR0'"),
];

include!("sm120_rows_common.inc");

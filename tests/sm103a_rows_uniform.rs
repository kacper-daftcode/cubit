//! SM103a uniform-datapath long tail (session T-23, 2026-11-08; KNOWN_ISSUES T1, the B300 line): the remaining harvest rows of USHF / ULEA / ULOP3 / UFLO / UMOV / UIADD3 / UIMAD / USEL / UIMNMX / UBMSK / UVIMNMX / UPRMT / UCLEA / UBREV / UPOPC / UISETP / REDUX / ELECT on sm103a.json verified row by row with nvdisasm 13.1 (-b SM103) over the whole 128-bit word by `tools/probes/re_sm120_rows.py --family uniform --arch SM103` (T-22's UIADD3 pass extended to the whole family -- the harvest ULOP3 LUT row it had named), the B300 publish corpus words as witnesses; the rows left are named.
//! Fixture `tests/fixtures/sm103a_rows_uniform_full_nvdisasm.jsonl` (`tools/probes/re_sm120_rows.py probe --family uniform --arch SM103`,
//! nvdisasm 13.1, the table's own corpus words as witnesses); the test body is `tests/sm120_rows_common.inc` (session T-23, 2026-11-08).

const TABLE: &str = "tables/sm103a.json";
const FAMILY: &str = "uniform";
const SOURCE: &str = "rows-uniform-2026-11-07";
const MNEMONICS: &[&str] = &["USHF", "ULEA", "ULOP3", "UFLO", "UMOV", "UIADD3", "UIMAD", "USEL", "UIMNMX", "UBMSK", "UVIMNMX", "UPRMT", "UCLEA", "UBREV", "UPOPC", "UISETP", "REDUX", "ELECT"];
const FIXTURE: &str = include_str!("fixtures/sm103a_rows_uniform_full_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 61;
const ALIAS_ROWS: usize = 0;
const DEAD_ROWS: usize = 0;
const FORM_WORDS: usize = 3311;
const WITNESS_WORDS: usize = 61;
/// Rows of the family's mnemonics another batch measures on its own branch: none on this table.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- the probe's verdict names each.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("ELECT_P_UR_P", "", "field bit 1 (pred tok 3) moves complex None: 'PREEXIT'"),
    ("UFLO_UR_UR", "U32", "re-measured since: rows-uflo-production-2026-11-08 (a candidate form of the B300 measurement lane, taken on 2026-11-10 -- complete-word fixture tests/hidden_b300_*.rs); this pass had found: cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'UFLO.U32 UR16, UR32' re-encode mismatch:000fe200080e000000000020001072bd for 'UFLO.U32 UR16, ~UR32'"),
    ("UIMAD_UR_UP_UR_II_UR", "U32,WIDE", "field bit 84 (pred tok 2) is text-inert"),
    ("UIMAD_UR_UP_UR_UR_UR", "U32,WIDE", "field bit 84 (pred tok 2) is text-inert"),
    ("UIMAD_UR_UR_II_UR", "U32", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'UIMAD UR32, UR48, 0x5a5a5a5a, -UR64' re-encode mismatch:000fe2000f8e0a405a5a5a5a302078a4 for 'UIMAD.U32 UR32, UR48, 0x5a5a5a5a, -UR64'"),
    ("UIMAD_UR_UR_II_UR", "U32,WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'UIMAD.WIDE.U32 UR32, UR48, 0x5a5a5a5a, UR80' re-encode mismatch:000fe2000f8e00505a5a5a5a302078a5 for 'UIMAD.WIDE.U32 UR32, UR48, 0x5a5a5a5a, -UR80'"),
    ("UIMAD_UR_UR_II_UR_UP", "U32,WIDE,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'UIMAD.WIDE.U32.X UR16, UR32, 0x5a5a5a5a, UR64, UPT' re-encode mismatch:000fe2000b8e04405a5a5a5a201078a5 for 'UIMAD.WIDE.U32.X UR16, UR32, 0x5a5a5a5a, ~UR64, UPT' (+1 more)"),
    ("UIMAD_UR_UR_UR_UR", "U32,WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'UIMAD.WIDE.U32 UR32, UR48, UR64, UR80' re-encode mismatch:000fe2000f8e005000000040302072a5 for 'UIMAD.WIDE.U32 UR32, UR48, UR64, -UR80'"),
    ("UIMAD_UR_UR_UR_UR", "WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'UIMAD.WIDE UR16, UR32, UR48, UR64' re-encode mismatch:000fe2000f8e024000000030201072a5 for 'UIMAD.WIDE UR16, UR32, UR48, -UR64'"),
    ("UIMAD_UR_UR_UR_UR_UP", "U32,WIDE,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'UIMAD.WIDE.U32.X UR32, UR48, UR64, UR80, UPT' re-encode mismatch:000fe2000b8e045000000040302072a5 for 'UIMAD.WIDE.U32.X UR32, UR48, UR64, ~UR80, UPT' (+1 more)"),
    ("ULEA_UR_UP_UR_II_II", "", "cubit mishandles the row's words (not tagged; T-23): field word bit 72: cubit 'ULEA UR32, UP3, UR64, 0x5a5a5a5a, 0x1a' re-encode mismatch:000fe2000f86d0ff5a5a5a5a40207891 for 'ULEA UR32, UP3, -UR64, 0x5a5a5a5a, 0x1a'"),
    ("ULEA_UR_UP_UR_UR_II", "", "re-measured since: rows-ulea-urb-neg-production-2026-11-11 (a candidate form of the B300 measurement lane, taken on 2026-11-13 -- complete-word fixture tests/hidden_b300_ulea_urb_neg.rs); this pass had found: cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'ULEA UR32, UP3, -UR64, UR96, 0x1a' re-encode mismatch:000fe2000f86d1ff0000006040207291 for 'ULEA UR32, UP3, UR64, -UR96, 0x1a'"),
    ("ULEA_UR_UP_UR_UR_UR_II", "HI", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'ULEA.HI UR32, UP3, -UR64, UR96, UR40, 0x1a' re-encode ok for 'ULEA.HI UR32, UP3, UR64, -UR96, UR40, 0x1a' (+1 more)"),
    ("ULEA_UR_UR_II_II_UP", "HI,SX32,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 72: cubit 'ULEA.HI.X.SX32 UR16, -UR32, 0x5a5a5a5a, 0x1a, UPT' re-encode ok for 'ULEA.HI.X.SX32 UR16, ~UR32, 0x5a5a5a5a, 0x1a, UPT' (+1 more)"),
    ("ULEA_UR_UR_II_UR_II_UP", "HI,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 72: cubit 'ULEA.HI.X UR16, -UR32, 0x5a5a5a5a, UR64, 0x1a, UPT' re-encode ok for 'ULEA.HI.X UR16, ~UR32, 0x5a5a5a5a, UR64, 0x1a, UPT' (+1 more)"),
    ("ULEA_UR_UR_UR_II_UP", "HI,SX32,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 72: cubit 'ULEA.HI.X.SX32 UR16, -UR32, UR48, 0x1a, UPT' re-encode ok for 'ULEA.HI.X.SX32 UR16, ~UR32, UR48, 0x1a, UPT' (+1 more)"),
    ("ULEA_UR_UR_UR_UR_II_UP", "HI,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'ULEA.HI.X UR32, UR48, -UR64, UR80, 0x1a, UPT' re-encode ok for 'ULEA.HI.X UR32, UR48, ~UR64, UR80, 0x1a, UPT' (+2 more)"),
    ("ULOP3_UP_UR_UR_II_UR_II_UP", "LUT", "cubit mishandles the row's words (not tagged; T-23): cubit prints 'ULOP3.LUT UP3, UR48, UR64, 0x5a5a5a5a, UR96, 0x5a, UP4' for 'ULOP3.LUT UP3, UR48, UR64, 0x5a5a5a5a, UR96, 0x5a, UP3' (+3 more)"),
    ("ULOP3_UP_UR_UR_UR_UR_II_UP", "LUT", "bit 16 outside the fields moves operand 2 of the same form: 'ULOP3.LUT UP5, UR254, UR16, UR160, UR56, 0x5a, UPT'"),
    ("ULOP3_UR_UR_UR_UR_II_UP", "LUT", "cubit mishandles the row's words (not tagged; T-23): cubit does not decode the canonical word: no instruction matches code 0x000000000b8e5a500000004030207292 at opcode 0x0292 (+3 more)"),
    ("UPOPC_UR_UR", "", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'UPOPC UR16, UR32' re-encode mismatch:000fe2000800000000000020001072bf for 'UPOPC UR16, ~UR32'"),
];

include!("sm120_rows_common.inc");

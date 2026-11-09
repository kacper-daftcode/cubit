//! SM103a control long tail (session T-23, 2026-11-08; KNOWN_ISSUES T1, the B300 line): the remaining harvest rows of WARPSYNC / CALL / BSSY / BSYNC / EXIT / BREAK / BAR / MEMBAR / NOP / YIELD / PREEXIT / ERRBAR / CGAERRBAR / ACQBULK / ACQSHMINIT / NANOSLEEP / BMOV / UCGABAR on sm103a.json verified row by row with nvdisasm 13.1 (-b SM103) over the whole 128-bit word by `tools/probes/re_sm120_rows.py --family control --arch SM103`, the B300 publish corpus words as witnesses; the rows left are named.
//! Fixture `tests/fixtures/sm103a_rows_control_nvdisasm.jsonl` (`tools/probes/re_sm120_rows.py probe --family control --arch SM103`,
//! nvdisasm 13.1, the table's own corpus words as witnesses); the test body is `tests/sm120_rows_common.inc` (session T-23, 2026-11-08).

const TABLE: &str = "tables/sm103a.json";
const FAMILY: &str = "control";
const SOURCE: &str = "rows-control-2026-11-07";
const MNEMONICS: &[&str] = &["WARPSYNC", "CALL", "BSSY", "BSYNC", "EXIT", "BREAK", "BAR", "MEMBAR", "NOP", "YIELD", "PREEXIT", "ERRBAR", "CGAERRBAR", "ACQBULK", "ACQSHMINIT", "NANOSLEEP", "BMOV", "UCGABAR"];
const FIXTURE: &str = include_str!("fixtures/sm103a_rows_control_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 31;
const ALIAS_ROWS: usize = 0;
const DEAD_ROWS: usize = 0;
const FORM_WORDS: usize = 385;
const WITNESS_WORDS: usize = 22;
/// Rows of the family's mnemonics another batch measures on its own branch: none on this table.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- the probe's verdict names each.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("BAR_II", "DEFER_BLOCKING,SYNC", "field bit 16 (imm tok 1) is text-inert"),
    ("BAR_II_II", "ARV", "field bit 58 (imm tok 1) is text-inert"),
    ("BAR_II_II", "DEFER_BLOCKING,SYNC", "field bit 58 (imm tok 1) is text-inert"),
    ("BAR_II_P", "AND,DEFER_BLOCKING,RED", "field bit 15 (imm tok 1) moves guard 0: '@!PT BAR.RED.AND.DEFER_BLOCKING 0x0, PT'"),
    ("BAR_II_P", "DEFER_BLOCKING,OR,RED", "field bit 15 (imm tok 1) moves guard 0: '@!PT BAR.RED.OR.DEFER_BLOCKING 0x0, PT'"),
    ("BAR_R_II", "ARV", "field bit 54 (imm tok 2) is text-inert"),
    ("BAR_R_II", "DEFER_BLOCKING,SYNC", "field bit 54 (imm tok 2) is text-inert"),
    ("BAR_R_R", "ARV", "field bit 32 (reg tok 2) moves complex None: 'BAR.ARV R49, R49'"),
    ("BAR_R_R", "DEFER_BLOCKING,SYNC", "field bit 32 (reg tok 2) moves complex None: 'BAR.SYNC.DEFER_BLOCKING R49, R49'"),
    ("BMOV_R_B", "32,CLEAR", "cubit mishandles the row's words (not tagged; T-23): cubit prints 'BMOV.CLEAR.32 R16, B1' for 'BMOV.32.CLEAR R16, B1' (+3 more)"),
    ("BREAK_P_B", "RELIABLE", "the key does not spell the vendor text: '@!P0 LEPC R1, 0x1000000000010' -> LEPC_R_II / ''"),
    ("CALL_II", "NOINC,REL", "bit 16 outside the fields moves operand 1 of the same form: 'CALL.REL.NOINC 0x254'"),
    ("EXIT_P", "", "cubit mishandles the row's words (not tagged; T-23): field word bit 90: cubit 'EXIT' re-encode mismatch:000fe20003800000000000000000794d for 'EXIT !P3'"),
    ("WARPSYNC_II", "ALL,COLLECTIVE", "bit 16 outside the fields moves operand 1 of the same form: 'WARPSYNC.COLLECTIVE.ALL 0x1b4'"),
    ("WARPSYNC_R_II", "COLLECTIVE", "bit 16 outside the fields moves operand 2 of the same form: 'WARPSYNC.COLLECTIVE R16, 0x1b4'"),
];

include!("sm120_rows_common.inc");

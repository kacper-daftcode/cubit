//! SM121a control long tail (session T-23, 2026-11-08; KNOWN_ISSUES T1, the GB10 line): the remaining harvest rows of WARPSYNC / CALL / BSSY / BSYNC / EXIT / BREAK / BAR / MEMBAR / NOP / YIELD / PREEXIT / ERRBAR / CGAERRBAR / ACQBULK / ACQSHMINIT / NANOSLEEP / BMOV / UCGABAR on sm121a.json verified row by row with nvdisasm 13.1 (-b SM121) over the whole 128-bit word by `tools/probes/re_sm120_rows.py --family control --arch SM121`, the GB10 census words as witnesses; the shadowed dotted keys retired as aliases, the junk keys whose every canonical word nvdisasm rejects deleted; the rows left are named (WARPSYNC.COLLECTIVE's 50-bit immediate = the owner item NEEDS 55c, as on sm120).
//! Fixture `tests/fixtures/sm121a_rows_control_nvdisasm.jsonl` (`tools/probes/re_sm120_rows.py probe --family control --arch SM121`,
//! nvdisasm 13.1, the table's own corpus words as witnesses); the test body is `tests/sm120_rows_common.inc` (session T-23, 2026-11-08).
//! Fixture `tests/fixtures/sm121a_rows_control_nvdisasm.jsonl` (`tools/probes/re_sm120_rows.py probe --family control --arch SM121`,
//! nvdisasm 13.1, the table's own corpus words as witnesses); the test body is `tests/sm120_rows_common.inc` (session T-23, 2026-11-08).

const TABLE: &str = "tables/sm121a.json";
const FAMILY: &str = "control";
const SOURCE: &str = "rows-control-2026-11-07";
const MNEMONICS: &[&str] = &["WARPSYNC", "CALL", "BSSY", "BSYNC", "EXIT", "BREAK", "BAR", "MEMBAR", "NOP", "YIELD", "PREEXIT", "ERRBAR", "CGAERRBAR", "ACQBULK", "ACQSHMINIT", "NANOSLEEP", "BMOV", "UCGABAR"];
const FIXTURE: &str = include_str!("fixtures/sm121a_rows_control_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 31;
const ALIAS_ROWS: usize = 20;
const DEAD_ROWS: usize = 2;
const FORM_WORDS: usize = 377;
const WITNESS_WORDS: usize = 36;
/// Rows of the family's mnemonics another batch measures on its own branch: none on this table.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
    ("BSYNC_B_B", "BSYNC_B"),
    ("BSYNC_B_II_?", "BSYNC_B"),
    ("CALL.ABS.NOINC_II", "CALL_II"),
    ("CALL.ABS.NOINC_II_?", "CALL_II"),
    ("CALL.REL.NOINC_II", "CALL_II"),
    ("CALL.REL.NOINC_II_II", "CALL_II"),
    ("CALL.REL.NOINC_II_II_?", "CALL_II"),
    ("CALL.REL.NOINC_II_II_II_?", "CALL_II"),
    ("CALL.REL.NOINC_II_II_II_II_?", "CALL_II"),
    ("CGAERRBAR_?", "CGAERRBAR"),
    ("EXIT_P_?", "EXIT"),
    ("EXIT_P_II_?", "EXIT"),
    ("EXIT_P_II_II_?", "EXIT"),
    ("EXIT_P_II_II_II_?", "EXIT"),
    ("MEMBAR.ALL.GPU_?", "MEMBAR.ALL.GPU"),
    ("MEMBAR.SC.GPU", "MEMBAR.SC.CTA"),
    ("MEMBAR.SC.GPU_?", "MEMBAR"),
    ("NOP_?", "NOP"),
    ("WARPSYNC.ALL_?", "WARPSYNC"),
    ("YIELD_?", "YIELD"),
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- the probe's verdict names each.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("BAR.RED.AND.DEFER_BLOCKING_II_P", "", "bit 54 outside the fields moves operand 1 of the same form: 'BAR.RED.AND.DEFER_BLOCKING 0x1, P1'"),
    ("BAR.RED.OR.DEFER_BLOCKING_II_P", "", "bit 54 outside the fields moves operand 1 of the same form: 'BAR.RED.OR.DEFER_BLOCKING 0x1, !P1'"),
    ("BAR.RED.POPC.DEFER_BLOCKING_II_P", "", "nvdisasm rejects every canonical word of the row"),
    ("BMOV.32_R_II", "32", "the key does not spell the vendor text: 'BMOV.32 R32, B0' -> BMOV.32_R_B / '32'"),
    ("BREAK.RELIABLE_II", "", "the key does not spell the vendor text: '@!P0 BREAK.RELIABLE B1' -> BREAK.RELIABLE_B / 'RELIABLE'"),
    ("BREAK.RELIABLE_P_B", "", "bit 16 outside the fields moves operand 2 of the same form: '@!P0 BREAK.RELIABLE P1, B0'"),
    ("BREAK_P_B", "RELIABLE", "field bit 0 (imm tok 0) moves complex None: 'CALL.ABS P3, 0x100000000000c'"),
    ("BSSY.RECONVERGENT_II_II", "", "the key does not spell the vendor text: 'BSSY.RECONVERGENT B1, 0x1a5b0' -> BSSY.RECONVERGENT_B_II / 'RECONVERGENT'"),
    ("BSSY.RELIABLE_II_II", "", "the key does not spell the vendor text: 'BSSY.RELIABLE B0, 0x25b0' -> BSSY.RELIABLE_B_II / 'RELIABLE'"),
    ("BSSY_II_II", "", "the key does not spell the vendor text: 'BSSY B1, 0x1a5b0' -> BSSY_B_II / ''"),
    ("CALL_II", "ABS,NOINC", "field bit 16 ( tok 0) moves operand 1: 'CALL.ABS.NOINC 0x4'"),
    ("CALL_II", "NOINC,REL", "field bit 16 ( tok 0) moves operand 1: 'CALL.REL.NOINC 0x14'"),
    ("EXIT_P", "", "bit 87 outside the fields moves operand 1 of the same form: '@!P0 EXIT P0'"),
    ("PREEXIT_P", "", "the key does not spell the vendor text: 'PREEXIT' -> PREEXIT / ''"),
    ("WARPSYNC.COLLECTIVE_R_II", "", "the immediate is a 50-bit field the vendor prints whole (0x169696969696978 for the probe's pattern); cubit's row reads 20 bits of it -- the collective mask / target law needs its own probe (G/NEEDS_OWNER.md 10)"),
    ("WARPSYNC.COLLECTIVE.ALL_II", "", "bit 16 outside the fields moves operand 1 of the same form: 'WARPSYNC.COLLECTIVE.ALL 0x1b4'"),
];

include!("sm120_rows_common.inc");

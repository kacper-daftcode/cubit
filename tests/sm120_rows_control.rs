//! SM120 control long tail (WARPSYNC / CALL / BSSY / BSYNC / EXIT / BREAK / BAR / MEMBAR / NOP / YIELD …) (session G run 5, 2026-11-07; KNOWN_ISSUES T1): the remaining harvest rows of
//! WARPSYNC, CALL, BSSY, BSYNC, EXIT, BREAK, BAR, MEMBAR, NOP, YIELD, PREEXIT, ERRBAR, CGAERRBAR, ACQBULK, ACQSHMINIT, NANOSLEEP, BMOV, UCGABAR verified row by row with nvdisasm 13.1 over the whole
//! 128-bit word by `tools/probes/re_sm120_rows.py --family control` -- 13 rows measured (121 canonical +
//! field words, 31 census witnesses), 21 shadowed keys (21 rows) retired as aliases, 1 unreachable
//! rows of staying keys deleted, 18 named exceptions. Fixture `tests/fixtures/sm120_rows_control_nvdisasm.jsonl`; the test body is `tests/sm120_rows_common.inc`.
//! Session T-18 (2026-11-08): batch 1 lifted the 2026-08/09 bug-wave pin (the verified rows take their measured status);
//! batch 2 retired the whole-key twins of the long-tail named exceptions as `_meta.key_aliases` (aliases for twins -- the
//! alias key's canonical word decodes through the target family key vendor-true, 0 census witnesses).

const FAMILY: &str = "control";
const SOURCE: &str = "rows-control-2026-11-07";
const MNEMONICS: &[&str] = &["WARPSYNC", "CALL", "BSSY", "BSYNC", "EXIT", "BREAK", "BAR", "MEMBAR", "NOP", "YIELD", "PREEXIT", "ERRBAR", "CGAERRBAR", "ACQBULK", "ACQSHMINIT", "NANOSLEEP", "BMOV", "UCGABAR"];
const FIXTURE: &str = include_str!("fixtures/sm120_rows_control_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 13;
const ALIAS_ROWS: usize = 21;
const DEAD_ROWS: usize = 1;
const FORM_WORDS: usize = 121;
const WITNESS_WORDS: usize = 31;
/// Harvest rows of the family's mnemonics that batches 12-14 measure or retire on their own branches (LDG.256 /
/// STG.256 / REDG lattices): harvest on this base, not this family's; 0 once those batches are on `main`.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
    ("BMOV.32_R_II", "BMOV_R_B"),
    ("BREAK.RELIABLE_II", "BREAK_B"),
    ("BREAK.RELIABLE_P_B", "BREAK_P_B"),
    ("BSSY.RECONVERGENT_II_II", "BSSY_B_II"),
    ("BSSY.RELIABLE_II_II", "BSSY_B_II"),
    ("BSSY_II_II", "BSSY_B_II"),
    ("BSYNC_B_B", "BSYNC_B"),
    ("BSYNC_B_II_?", "BSYNC_B"),
    ("CALL.ABS.NOINC_II", "CALL_II"),
    ("CALL.ABS.NOINC_II_?", "CALL_II"),
    ("CGAERRBAR_?", "CGAERRBAR"),
    ("EXIT_P_?", "EXIT"),
    ("EXIT_P_II_?", "EXIT"),
    ("EXIT_P_II_II_?", "EXIT"),
    ("EXIT_P_II_II_II_?", "EXIT"),
    ("MEMBAR.ALL.GPU_?", "MEMBAR"),
    ("MEMBAR.SC.GPU_?", "MEMBAR"),
    ("NOP_?", "NOP"),
    ("PREEXIT_P", "PREEXIT"),
    ("WARPSYNC.ALL_?", "WARPSYNC"),
    ("YIELD_?", "YIELD"),
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- `G/NEEDS_OWNER.md`.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("BAR.RED.POPC.DEFER_BLOCKING_II_II_P", "_BLOCKING", "nvdisasm rejects every canonical word of the row"),
    ("BAR.SYNC.DEFER_BLOCKING_P_II", "", "the key does not spell the vendor text: 'BAR.SYNC R0, R0' -> BAR.SYNC_R_R / 'SYNC'"),
    ("BSSY_B_II", "", "field bit 34 ( tok 0) moves operand 2: 'BSSY B1, 0x14'"),
    ("BSSY_B_II", "RECONVERGENT", "field bit 34 ( tok 0) moves operand 2: 'BSSY.RECONVERGENT B1, 0x14'"),
    ("BSSY_B_II", "RELIABLE", "field bit 34 ( tok 0) moves operand 2: 'BSSY.RELIABLE B1, 0x14'"),
    ("CALL.REL.NOINC_II", "", "bit 16 outside the fields moves operand 1 of the same form: 'CALL.REL.NOINC 0x169b4'"),
    ("CALL.REL.NOINC_II_II", "", "the key does not spell the vendor text: 'CALL.REL.NOINC 0x69b0' -> CALL.REL.NOINC_II / 'NOINC,REL'"),
    ("CALL.REL.NOINC_II_II_?", "", "the key does not spell the vendor text: 'CALL.REL.NOINC 0x69b0' -> CALL.REL.NOINC_II / 'NOINC,REL'"),
    ("CALL.REL.NOINC_II_II_II_?", "", "the key does not spell the vendor text: 'CALL.REL.NOINC 0x169b0' -> CALL.REL.NOINC_II / 'NOINC,REL'"),
    ("CALL.REL.NOINC_II_II_II_II_?", "", "the key does not spell the vendor text: 'CALL.REL.NOINC 0x69b0' -> CALL.REL.NOINC_II / 'NOINC,REL'"),
    ("UCGABAR_ARV", "_ARV", "the key does not spell the vendor text: 'UCGABAR_ARV' -> UCGABAR_ARV / ''"),
    ("UCGABAR_WAIT", "_WAIT", "the key does not spell the vendor text: 'UCGABAR_WAIT' -> UCGABAR_WAIT / ''"),
    ("WARPSYNC", "", "the key does not spell the vendor text: 'WARPSYNC R16' -> WARPSYNC_R / ''"),
    ("WARPSYNC", "ALL", "field bit 24 (reg tok 1) is text-inert"),
    ("WARPSYNC", "COLLECTIVE", "the key does not spell the vendor text: 'WARPSYNC.COLLECTIVE R16, 0x30' -> WARPSYNC.COLLECTIVE_R_II / 'COLLECTIVE'"),
    ("WARPSYNC.COLLECTIVE_R_II", "", "the immediate is a 50-bit field the vendor prints whole (0x169696969696978 for the probe's pattern); cubit's row reads 20 bits of it -- the collective mask / target law needs its own probe (G/NEEDS_OWNER.md 10)"),
    ("WARPSYNC_R", "ALL", "the key does not spell the vendor text: 'WARPSYNC.ALL' -> WARPSYNC.ALL / 'ALL'"),
    ("WARPSYNC_R", "COLLECTIVE", "the key does not spell the vendor text: 'WARPSYNC.COLLECTIVE R16, 0x30' -> WARPSYNC.COLLECTIVE_R_II / 'COLLECTIVE'"),
];

include!("sm120_rows_common.inc");

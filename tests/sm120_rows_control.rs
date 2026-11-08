//! SM120 control long tail (WARPSYNC / CALL / BSSY / BSYNC / EXIT / BREAK / BAR / MEMBAR / NOP / YIELD …) (session G run 5, 2026-11-07; KNOWN_ISSUES T1): the remaining harvest rows of
//! WARPSYNC, CALL, BSSY, BSYNC, EXIT, BREAK, BAR, MEMBAR, NOP, YIELD, PREEXIT, ERRBAR, CGAERRBAR, ACQBULK, ACQSHMINIT, NANOSLEEP, BMOV, UCGABAR verified row by row with nvdisasm 13.1 over the whole
//! 128-bit word by `tools/probes/re_sm120_rows.py --family control` -- 19 rows measured (253 canonical +
//! field words, 43 census witnesses), 5 shadowed keys (5 rows) retired as aliases, 3 unreachable
//! rows of staying keys deleted, 4 named exceptions. Fixture `tests/fixtures/sm120_rows_control_nvdisasm.jsonl`; the test body is `tests/sm120_rows_common.inc`.
//! Session T-18 (2026-11-08): batch 1 lifted the 2026-08/09 bug-wave pin (the verified rows take their measured status);
//! batch 2 retired the whole-key twins of the long-tail named exceptions as `_meta.key_aliases` (aliases for twins -- the
//! alias key's canonical word decodes through the target family key vendor-true, 0 census witnesses).
//! Session T-19 (2026-11-08, T/NEEDS_OWNER.md 55 -- R's decisions): the field-narrowing pass over the last harvest rows
//! (`MANUAL_ROW_FIELDS` of the probe: over-wide predicate windows, the 9-bit `sub_ur`, the undeclared IADD3 carry-out,
//! the BSSY target, the `.H1` selector, the paired `BF16_V2` immediate type), the renames of mis-named keys to the vendor's
//! spelling (`RENAMED_FROM`), the hand-retired twins (`MANUAL_ALIAS` / `MANUAL_DEAD`), 2 junk keys deleted whole
//! (`DELETE`: every canonical word illegal, or another form's words) and 0 design rows marked `_src: "modelled"` (`MODELLED`, the
//! pinning test in each note). The rows left without `_src` are the documented owner items of KNOWN_ISSUES T1.

const FAMILY: &str = "control";
const SOURCE: &str = "rows-control-2026-11-07";
const MNEMONICS: &[&str] = &["WARPSYNC", "CALL", "BSSY", "BSYNC", "EXIT", "BREAK", "BAR", "MEMBAR", "NOP", "YIELD", "PREEXIT", "ERRBAR", "CGAERRBAR", "ACQBULK", "ACQSHMINIT", "NANOSLEEP", "BMOV", "UCGABAR"];
const FIXTURE: &str = include_str!("fixtures/sm120_rows_control_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 19;
const ALIAS_ROWS: usize = 5;
const DEAD_ROWS: usize = 3;
const FORM_WORDS: usize = 253;
const WITNESS_WORDS: usize = 43;
/// Harvest rows of the family's mnemonics that batches 12-14 measure or retire on their own branches (LDG.256 /
/// STG.256 / REDG lattices): harvest on this base, not this family's; 0 once those batches are on `main`.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
    ("CALL.REL.NOINC_II", "CALL_II"),
    ("CALL.REL.NOINC_II_II", "CALL_II"),
    ("CALL.REL.NOINC_II_II_?", "CALL_II"),
    ("CALL.REL.NOINC_II_II_II_?", "CALL_II"),
    ("CALL.REL.NOINC_II_II_II_II_?", "CALL_II"),
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- `G/NEEDS_OWNER.md`.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("WARPSYNC", "", "the key does not spell the vendor text: 'WARPSYNC R16' -> WARPSYNC_R / ''"),
    ("WARPSYNC", "COLLECTIVE", "the key does not spell the vendor text: 'WARPSYNC.COLLECTIVE R16, 0x30' -> WARPSYNC.COLLECTIVE_R_II / 'COLLECTIVE'"),
    ("WARPSYNC.COLLECTIVE_R_II", "", "the immediate is a 50-bit field the vendor prints whole (0x169696969696978 for the probe's pattern); cubit's row reads 20 bits of it -- the collective mask / target law needs its own probe (G/NEEDS_OWNER.md 10)"),
    ("WARPSYNC_R", "COLLECTIVE", "the key does not spell the vendor text: 'WARPSYNC.COLLECTIVE R16, 0x30' -> WARPSYNC.COLLECTIVE_R_II / 'COLLECTIVE'"),
];

include!("sm120_rows_common.inc");

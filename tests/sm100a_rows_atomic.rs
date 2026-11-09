//! SM100a atomics long tail (session T-23, 2026-11-08; KNOWN_ISSUES T1, the B200 line (the B300 publish corpus holds 151 sm_100a cubins)): the remaining harvest rows of ATOMG / ATOM / ATOMS / REDG on sm100a.json verified row by row with nvdisasm 13.1 (-b SM100) over the whole 128-bit word by `tools/probes/re_sm120_rows.py --family atomic --arch SM100`, the B300 publish corpus words as witnesses; the words the encoder refuses on the sm_100a silicon laws (BUG-080: a guarded non-EL atomic is silently broken on the B300 -- the probe's canonical words carry a guard, so every such row is decode- and print-checked and its text refused by design; BUG-077 / 078: the odd 64-bit base) are silicon / silicon_bits; the shadowed dotted keys retired as aliases; the rows left are named.
//! Fixture `tests/fixtures/sm100a_rows_atomic_nvdisasm.jsonl` (`tools/probes/re_sm120_rows.py probe --family atomic --arch SM100`,
//! nvdisasm 13.1, the table's own corpus words as witnesses); the test body is `tests/sm120_rows_common.inc` (session T-23, 2026-11-08).

const TABLE: &str = "tables/sm100a.json";
const FAMILY: &str = "atomic";
const SOURCE: &str = "rows-atomic-2026-11-07";
const MNEMONICS: &[&str] = &["ATOMG", "ATOM", "ATOMS", "REDG"];
const FIXTURE: &str = include_str!("fixtures/sm100a_rows_atomic_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 71;
const ALIAS_ROWS: usize = 1;
const DEAD_ROWS: usize = 0;
const FORM_WORDS: usize = 4172;
const WITNESS_WORDS: usize = 12;
/// Rows of the family's mnemonics another batch measures on its own branch: none on this table.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
    ("ATOMS_R_ARI", "ATOMS_R_ARURI"),
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- the probe's verdict names each.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("ATOMG_P_R_dARI_R", "E,EXCH,GPU,STRONG", "bit 40 outside the fields moves operand 3 of the same form: 'ATOMG.E.EXCH.STRONG.GPU PT, R64, desc[UR80][R16.64+0x1], R32'"),
    ("ATOMG_P_R_dARI_R", "E,EXCH,SM,STRONG", "bit 40 outside the fields moves operand 3 of the same form: 'ATOMG.E.EXCH.STRONG.SM PT, R64, desc[UR80][R16.64+0x1], R32'"),
    ("ATOMG_P_R_dARI_R", "E,EXCH,STRONG,SYS", "bit 40 outside the fields moves operand 3 of the same form: 'ATOMG.E.EXCH.STRONG.SYS PT, R64, desc[UR80][R16.64+0x1], R32'"),
    ("ATOMS_P_ARI_R_R", "64,CAST,SPIN", "field bit 84 (pred tok 1) is text-inert"),
    ("ATOMS_P_ARI_R_R", "CAST,SPIN", "field bit 84 (pred tok 1) is text-inert"),
    ("ATOMS_R_AURI", "32,INC,POPC", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through ATOMS_R_ARURI / '32,INC,POPC' (shadowed) (+4 more)"),
];

include!("sm120_rows_common.inc");

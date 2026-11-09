//! SM100a tensor-core long tail (session T-23, 2026-11-08; KNOWN_ISSUES T1, the B200 line (the B300 publish corpus holds 151 sm_100a cubins)): the remaining harvest rows of QMMA / HMMA / OMMA / DMMA / IMMA on sm100a.json verified row by row with nvdisasm 13.1 (-b SM100) over the whole 128-bit word by `tools/probes/re_sm120_rows.py --family tensor --arch SM100`, the B300 publish corpus words as witnesses; the rows left are named.
//! Fixture `tests/fixtures/sm103a_rows_tensor_nvdisasm.jsonl` (`tools/probes/re_sm120_rows.py probe --family tensor --arch SM100`,
//! nvdisasm 13.1, the table's own corpus words as witnesses); the test body is `tests/sm120_rows_common.inc` (session T-23, 2026-11-08).
//! Fixture `tests/fixtures/sm100a_rows_tensor_nvdisasm.jsonl` (`tools/probes/re_sm120_rows.py probe --family tensor --arch SM100`,
//! nvdisasm 13.1, the table's own corpus words as witnesses); the test body is `tests/sm120_rows_common.inc` (session T-23, 2026-11-08).

const TABLE: &str = "tables/sm100a.json";
const FAMILY: &str = "tensor";
const SOURCE: &str = "rows-tensor-2026-11-07";
const MNEMONICS: &[&str] = &["QMMA", "HMMA", "OMMA", "DMMA", "IMMA"];
const FIXTURE: &str = include_str!("fixtures/sm100a_rows_tensor_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 1;
const ALIAS_ROWS: usize = 0;
const DEAD_ROWS: usize = 0;
const FORM_WORDS: usize = 39;
const WITNESS_WORDS: usize = 0;
/// Rows of the family's mnemonics another batch measures on its own branch: none on this table.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- the probe's verdict names each.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("DMMA_R_R_R_R", "8x8x4", "cubit mishandles the row's words (not tagged; T-23): field word bit 62: cubit 'no instruction matches code 0x000000000000002840000050201072' re-encode None for 'DMMA.8x8x4 R16, R32, |R80|, R40' (+2 more)"),
    ("HMMA_R_R_R_R", "16816,BF16,F32", "cubit mishandles the row's words (not tagged; T-23): cubit prints 'HMMA.16816.BF16.F32 R16, R32, R64, R96' for 'HMMA.16816.F32.BF16 R16, R32, R64, R96' (+3 more)"),
    ("HMMA_R_R_R_R", "16816,F16", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'no instruction matches code 0x000000000000086080000040201072' re-encode None for 'HMMA.16816.F16 R16, R32, -R64, R96' (+1 more)"),
    ("HMMA_R_R_R_R", "16816,F32", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'no instruction matches code 0x000000000000186080000040201072' re-encode None for 'HMMA.16816.F32 R16, R32, -R64, R96' (+1 more)"),
    ("HMMA_R_R_R_R", "1688,F32,TF32", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'no instruction matches code 0x000000000008106080000040201072' re-encode None for 'HMMA.1688.F32.TF32 R16, R32, -R64, R96' (+1 more)"),
    ("IMMA_R_R_R_R", "16816,S8,S8,SAT", "bit 123 outside the fields moves operand 3 of the same form: 'IMMA.16816.S8.S8.SAT R16, R32.ROW, R48.reuse.COL, R64'"),
    ("IMMA_R_R_R_R", "16832,S8,S8,SAT", "cubit mishandles the row's words (not tagged; T-23): cubit prints 'IMMA.SAT.16832.S8.S8 R16, R32.ROW, R64.COL, R96' for 'IMMA.16832.S8.S8.SAT R16, R32.ROW, R64.COL, R96' (+3 more)"),
];

include!("sm120_rows_common.inc");

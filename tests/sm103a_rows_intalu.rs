//! SM103a integer / scalar ALU long tail (session T-23, 2026-11-08; KNOWN_ISSUES T1, the B300 line): the remaining harvest rows of VIMNMX / IADD / IMAD / IADD3 / IMNMX / IABS / VIADD / SGXT / BMSK / PRMT / LOP3 / SEL / MOV / FLO / POPC / BREV / R2UR / LDC / S2R / CS2R / LDCU / S2UR / FHADD / DMUL / DADD on sm103a.json verified row by row with nvdisasm 13.1 (-b SM103) over the whole 128-bit word by `tools/probes/re_sm120_rows.py --family intalu --arch SM103`, the B300 publish corpus words as witnesses (the LDC.64 odd-destination law of BUG-088 as silicon_bits); the rows left are named.
//! Fixture `tests/fixtures/sm103a_rows_intalu_full_nvdisasm.jsonl` (`tools/probes/re_sm120_rows.py probe --family intalu --arch SM103`,
//! nvdisasm 13.1, the table's own corpus words as witnesses); the test body is `tests/sm120_rows_common.inc` (session T-23, 2026-11-08).

const TABLE: &str = "tables/sm103a.json";
const FAMILY: &str = "intalu";
const SOURCE: &str = "rows-intalu-2026-11-07";
const MNEMONICS: &[&str] = &["VIMNMX", "VIMNMX3", "IADD", "IMAD", "IADD3", "IMNMX", "IABS", "VIADD", "SGXT", "BMSK", "PRMT", "LOP3", "SEL", "MOV", "FLO", "POPC", "BREV", "R2UR", "LDC", "S2R", "CS2R", "MOV64IUR", "LDCU", "S2UR", "FHADD", "DMUL", "DADD"];
const FIXTURE: &str = include_str!("fixtures/sm103a_rows_intalu_full_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 54;
const ALIAS_ROWS: usize = 0;
const DEAD_ROWS: usize = 0;
const FORM_WORDS: usize = 2111;
const WITNESS_WORDS: usize = 46;
/// Rows of the family's mnemonics another batch measures on its own branch: none on this table.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- the probe's verdict names each.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("CS2R_R_II", "", "the key does not spell the vendor text: 'CS2R R32, SRZ' -> CS2R_R_L / ''"),
    ("FLO_R_R", "SH,U32", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'FLO.U32.SH R16, R32' re-encode mismatch:000fe200000e04000000002000107300 for 'FLO.U32.SH R16, ~R32'"),
    ("FLO_R_R", "U32", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'FLO.U32.SH R16, R32' re-encode mismatch:000fe200000e04000000002000107300 for 'FLO.U32 R16, ~R32'"),
    ("FLO_R_UR", "U32", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'FLO.U32 R16, UR32' re-encode mismatch:000fe200080e00000000002000107d00 for 'FLO.U32 R16, ~UR32'"),
    ("IADD3_R_P_P_R_R_R_P_P", "X", "cubit mishandles the row's words (not tagged; T-23): field word bit 90: cubit 'IADD3.X R32, PT, PT, R80, R40, R16, PT, PT' re-encode mismatch:000fe20003fee4100000002850207210 for 'IADD3.X R32, PT, PT, R80, R40, R16, !PT, PT'"),
    ("IMAD.U32_R_R_R_R", "U32", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through IMAD_R_R_R_R / '' (shadowed) (+5 more)"),
    ("IMAD_R_P_R_II_R", "U32,WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.WIDE.U32 R32, P3, R64, 0x5a5a5a5a, R24' re-encode mismatch:000fe200078600185a5a5a5a40207825 for 'IMAD.WIDE.U32 R32, P3, R64, 0x5a5a5a5a, -R24'"),
    ("IMAD_R_P_R_II_R_P", "B90,U32,WIDE,X", "T-23, not deleted: dead row kept: without it the canonical word 00000000078e04185a5a5a5a40207825 = `IMAD.WIDE.U32.X R32, R64, 0x5a5a5a5a, R24, !PT` prints 'IMAD.WIDE.U32.X R32, R64, 0x5a5a5a5a, R24, P15' on this table (the target 'IMAD_R_P_R_II_R_P' has no such group here)"),
    ("IMAD_R_P_R_II_R_P", "U32,WIDE,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.WIDE.U32.X R32, P3, R64, 0x5a5a5a5a, R24, P3' re-encode mismatch:000fe200018604185a5a5a5a40207825 for 'IMAD.WIDE.U32.X R32, P3, R64, 0x5a5a5a5a, ~R24, P3' (+1 more)"),
    ("IMAD_R_P_R_R_R", "HI,U32", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.HI.U32 R32, P3, R64, R96, R40' re-encode mismatch:000fe200078600280000006040207227 for 'IMAD.HI.U32 R32, P3, R64, R96, -R40'"),
    ("IMAD_R_P_R_R_R", "U32,WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.WIDE.U32 R32, P3, R64, R96, R40' re-encode mismatch:000fe200078600280000006040207225 for 'IMAD.WIDE.U32 R32, P3, R64, R96, -R40'"),
    ("IMAD_R_P_R_R_R_P", "U32,WIDE,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.WIDE.U32.X R32, P3, R64, R96, R40, P3' re-encode mismatch:000fe200018604280000006040207225 for 'IMAD.WIDE.U32.X R32, P3, R64, R96, ~R40, P3'"),
    ("IMAD_R_P_R_UR_R", "HI,U32", "bit 16 outside the fields moves operand 1 of the same form: 'IMAD.HI.U32 R9, P3, R48, UR16, R80'"),
    ("IMAD_R_P_R_UR_R", "U32,WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.WIDE.U32 R16, P3, R32, UR48, R64' re-encode mismatch:000fe2000f8600400000003020107c25 for 'IMAD.WIDE.U32 R16, P3, R32, UR48, -R64'"),
    ("IMAD_R_R_II_R", "HI", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.HI R16, R32, 0x5a5a5a5a, R64' re-encode mismatch:000fe200078e02405a5a5a5a20107827 for 'IMAD.HI R16, R32, 0x5a5a5a5a, -R64'"),
    ("IMAD_R_R_II_R", "HI,U32", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.HI R16, R32, 0x5a5a5a5a, R80' re-encode mismatch:000fe200078e02505a5a5a5a20107827 for 'IMAD.HI.U32 R16, R32, 0x5a5a5a5a, -R80'"),
    ("IMAD_R_R_II_R", "IADD", "the key does not spell the vendor text: 'IMAD R32, R48, 0x5a5a5a5a, R80' -> IMAD_R_R_II_R / ''"),
    ("IMAD_R_R_II_R", "IADD,U32", "the key does not spell the vendor text: 'IMAD.U32 R32, R48, 0x5a5a5a5a, R80' -> IMAD.U32_R_R_II_R / 'U32'"),
    ("IMAD_R_R_II_R", "SHL,U32", "the key does not spell the vendor text: 'IMAD.U32 R32, R48, 0x5a5a5a5a, R96' -> IMAD.U32_R_R_II_R / 'U32'"),
    ("IMAD_R_R_II_R", "U32", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.U32 R32, R48, 0x5a5a5a5a, R96' re-encode mismatch:000fe200078e00605a5a5a5a30207824 for 'IMAD.U32 R32, R48, 0x5a5a5a5a, -R96' (+2 more)"),
    ("IMAD_R_R_II_R", "U32,WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.WIDE.U32 R48, R64, 0x5a5a5a5a, R24' re-encode mismatch:000fe200078e00185a5a5a5a40307825 for 'IMAD.WIDE.U32 R48, R64, 0x5a5a5a5a, -R24'"),
    ("IMAD_R_R_II_R_P", "U32,WIDE,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.WIDE.U32.X R16, R32, 0x5a5a5a5a, R64, PT' re-encode mismatch:000fe200038e04405a5a5a5a20107825 for 'IMAD.WIDE.U32.X R16, R32, 0x5a5a5a5a, ~R64, PT' (+1 more)"),
    ("IMAD_R_R_II_R_P", "X", "cubit mishandles the row's words (not tagged; T-23): field word bit 90: cubit 'IMAD R32, R48, 0x5a5a5a5a, R80' re-encode mismatch:000fe200078e02505a5a5a5a30207824 for 'IMAD.X R32, R48, 0x5a5a5a5a, R80, !PT'"),
    ("IMAD_R_R_R_II", "MOV", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through IMAD_R_R_R_II / '' (shadowed) (+1 more)"),
    ("IMAD_R_R_R_II", "MOV,U32", "bit 24 outside the fields moves several tokens of the same form: 'IMAD.U32 R32, R254, R80, 0x5a5a5a5a'"),
    ("IMAD_R_R_R_II_P", "X", "bit 24 outside the fields moves operand 2 of the same form: 'IMAD.X R16, R254, R80, 0x5a5a5a5a, PT'"),
    ("IMAD_R_R_R_R", "HI,U32", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.HI.U32 R32, R48, R80, R24' re-encode mismatch:000fe200078e00180000005030207227 for 'IMAD.HI.U32 R32, R48, R80, -R24'"),
    ("IMAD_R_R_R_R", "MOV", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through IMAD_R_R_R_R / '' (shadowed) (+1 more)"),
    ("IMAD_R_R_R_R", "MOV,U32", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through IMAD_R_R_R_R / 'U32' (shadowed) (+1 more)"),
    ("IMAD_R_R_R_R", "U32,WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.WIDE.U32 R32, R48, R80, R24' re-encode mismatch:000fe200078e00180000005030207225 for 'IMAD.WIDE.U32 R32, R48, R80, -R24'"),
    ("IMAD_R_R_R_R", "WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.WIDE R32, R48, R80, R24' re-encode mismatch:000fe200078e02180000005030207225 for 'IMAD.WIDE R32, R48, R80, -R24'"),
    ("IMAD_R_R_R_R_P", "U32,WIDE,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.WIDE.U32.X R32, R48, R80, R24, PT' re-encode mismatch:000fe200038e04180000005030207225 for 'IMAD.WIDE.U32.X R32, R48, R80, ~R24, PT' (+1 more)"),
    ("IMAD_R_R_R_R_P", "X", "cubit mishandles the row's words (not tagged; T-23): field word bit 90: cubit 'IMAD R32, R48, R64, R80' re-encode mismatch:000fe200078e02500000004030207224 for 'IMAD.X R32, R48, R64, R80, !PT'"),
    ("IMAD_R_R_R_UR", "HI,U32", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'IMAD.HI.U32 R16, R32, -R48, UR64' re-encode ok for 'IMAD.HI.U32 R16, R32, R48, -UR64' (+1 more)"),
    ("IMAD_R_R_R_UR", "U32", "bit 24 outside the fields moves operand 2 of the same form: 'IMAD.U32 R32, R254, R80, UR48'"),
    ("IMAD_R_R_R_UR", "U32,WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'IMAD.WIDE.U32 R32, R48, -R80, UR24' re-encode ok for 'IMAD.WIDE.U32 R32, R48, R80, -UR24'"),
    ("IMAD_R_R_R_UR", "WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'IMAD.WIDE R32, R48, -R80, UR24' re-encode ok for 'IMAD.WIDE R32, R48, R80, -UR24'"),
    ("IMAD_R_R_R_UR_P", "X", "bit 24 outside the fields moves operand 2 of the same form: 'IMAD.X R32, R254, R120, UR48, PT'"),
    ("IMAD_R_R_UR_R", "HI,U32", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.HI.U32 R32, R48, UR80, R96' re-encode mismatch:000fe2000f8e00600000005030207c27 for 'IMAD.HI.U32 R32, R48, UR80, -R96'"),
    ("IMAD_R_R_UR_R", "U32,WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.WIDE.U32 R32, R48, UR80, R96' re-encode mismatch:000fe2000f8e00600000005030207c25 for 'IMAD.WIDE.U32 R32, R48, UR80, -R96'"),
    ("IMAD_R_R_UR_R", "WIDE", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.WIDE R32, R48, UR80, R96' re-encode mismatch:000fe2000f8e02600000005030207c25 for 'IMAD.WIDE R32, R48, UR80, -R96'"),
    ("IMAD_R_R_UR_R_P", "U32,WIDE,X", "cubit mishandles the row's words (not tagged; T-23): field word bit 75: cubit 'IMAD.WIDE.U32.X R16, R32, UR48, R64, PT' re-encode mismatch:000fe2000b8e04400000003020107c25 for 'IMAD.WIDE.U32.X R16, R32, UR48, ~R64, PT' (+1 more)"),
    ("LDCU_UR_cAI", "", "the key does not spell the vendor text: 'LDCU UR32, c[0xd][UR48+0x5a5a]' -> LDCU_UR_cAURI / ''"),
    ("LOP3_P_R_R_II_R_II_P", "LUT,PAND", "cubit mishandles the row's words (not tagged; T-23): field word bit 83: cubit 'LOP3.LUT.PAND PT, R48, R64, 0x5a5a5a5a, R96, 0x5a, P3' re-encode ok for 'LOP3.LUT.PAND R48, R64, 0x5a5a5a5a, R96, 0x5a, P3'"),
    ("POPC_R_R", "", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'POPC R32, R48' re-encode mismatch:000fe200000000000000003000207309 for 'POPC R32, ~R48'"),
    ("POPC_R_UR", "", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'POPC R16, UR32' re-encode mismatch:000fe200080000000000002000107d09 for 'POPC R16, ~UR32'"),
    ("PRMT_R_R_R_II", "", "cubit mishandles the row's words (not tagged; T-23): field word bit 123: cubit 'PRMT R16, R32, R48, 0x5a5a5a5a' re-encode mismatch:000fe200000000305a5a5a5a20107416 for 'PRMT R16, R32, R48.reuse, 0x5a5a5a5a'"),
    ("PRMT_R_R_R_R", "", "cubit mishandles the row's words (not tagged; T-23): cubit prints 'PRMT R16, R32, R80.reuse, R40' for 'PRMT R16, R32, R80, R40' (+4 more)"),
    ("PRMT_R_R_R_UR", "", "cubit mishandles the row's words (not tagged; T-23): field word bit 123: cubit 'PRMT R16, R32, R48, UR64' re-encode mismatch:000fe200080000300000004020107e16 for 'PRMT R16, R32, R48.reuse, UR64'"),
    ("S2R_R_L", "", "field bit 80 (sysreg tok 2) is text-inert"),
    ("S2UR_UR_L", "", "field bit 80 (sysreg tok 2) is text-inert"),
    ("VIMNMX_R_P_P_R_II_P", "", "bit 81 outside the fields moves operand 2 of the same form: 'VIMNMX R32, P6, PT, R48, 0x5a5a5a5a, PT'"),
    ("VIMNMX_R_P_P_R_II_P", "U32", "bit 87 outside the fields moves operand 6 of the same form: 'VIMNMX.U32 R16, PT, PT, R32, 0x5a5a5a5a, P6'"),
    ("VIMNMX_R_P_P_R_R_P", "", "bit 81 outside the fields moves operand 2 of the same form: 'VIMNMX R32, P6, PT, R48, R80, PT'"),
    ("VIMNMX_R_P_P_R_R_P", "S16x2", "bit 81 outside the fields moves operand 2 of the same form: 'VIMNMX.S16x2 R32, P6, PT, R48, R64, PT'"),
    ("VIMNMX_R_P_P_R_R_P", "U32", "bit 81 outside the fields moves operand 2 of the same form: 'VIMNMX.U32 R32, P6, PT, R48, R80, PT'"),
    ("VIMNMX_R_P_P_R_UR_P", "", "bit 81 outside the fields moves operand 2 of the same form: 'VIMNMX R32, P6, PT, R48, UR80, PT'"),
    ("VIMNMX_R_P_P_R_UR_P", "U32", "bit 87 outside the fields moves operand 6 of the same form: 'VIMNMX.U32 R16, PT, PT, R32, UR64, P6'"),
];

include!("sm120_rows_common.inc");

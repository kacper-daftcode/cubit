//! SM100a half-precision / conversion long tail (session T-23, 2026-11-08; KNOWN_ISSUES T1, the B200 line (the B300 publish corpus holds 151 sm_100a cubins)): the remaining harvest rows of HFMA2 / HMNMX2 / HADD2 / HSET2 / F2FP / I2FP / F2IP / I2IP / UF2FP / UI2FP / F2F / UF2I / UI2F on sm100a.json verified row by row with nvdisasm 13.1 (-b SM100) over the whole 128-bit word by `tools/probes/re_sm120_rows.py --family half --arch SM100`, the B300 publish corpus words as witnesses; the rows left are named.
//! Fixture `tests/fixtures/sm103a_rows_half_nvdisasm.jsonl` (`tools/probes/re_sm120_rows.py probe --family half --arch SM100`,
//! nvdisasm 13.1, the table's own corpus words as witnesses); the test body is `tests/sm120_rows_common.inc` (session T-23, 2026-11-08).
//! Fixture `tests/fixtures/sm100a_rows_half_nvdisasm.jsonl` (`tools/probes/re_sm120_rows.py probe --family half --arch SM100`,
//! nvdisasm 13.1, the table's own corpus words as witnesses); the test body is `tests/sm120_rows_common.inc` (session T-23, 2026-11-08).

const TABLE: &str = "tables/sm100a.json";
const FAMILY: &str = "half";
const SOURCE: &str = "rows-half-2026-11-07";
const MNEMONICS: &[&str] = &["HFMA2", "HMNMX2", "HADD2", "HSET2", "F2FP", "I2FP", "F2IP", "I2IP", "UF2FP", "UI2FP", "F2F", "UF2I", "UI2F"];
const FIXTURE: &str = include_str!("fixtures/sm100a_rows_half_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 46;
const ALIAS_ROWS: usize = 0;
const DEAD_ROWS: usize = 0;
const FORM_WORDS: usize = 2702;
const WITNESS_WORDS: usize = 0;
/// Rows of the family's mnemonics another batch measures on its own branch: none on this table.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- the probe's verdict names each.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("F2FP_R_R", "E4M3,F16,UNPACK_B", "bit 88 outside the fields moves operand 2 of the same form: 'F2FP.F16.E4M3.UNPACK_B R32, R48.H1'"),
    ("F2FP_R_R", "E5M2,F16,UNPACK_B", "bit 88 outside the fields moves operand 2 of the same form: 'F2FP.F16.E5M2.UNPACK_B R16, R32.H1'"),
    ("F2FP_R_R", "F32,PACK_B,TF32", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through F2FP_R_R / 'TF32,F32,PACK_B' (shadowed)"),
    ("F2FP_R_R", "F16,E4M3,UNPACK_B", "the key does not spell the vendor text: 'F2FP.F16.E4M3.UNPACK_B R32, R48' -> F2FP.F16.E4M3.UNPACK_B_R_R / 'E4M3,F16,UNPACK_B'"),
    ("F2FP_R_R", "F16,E5M2,UNPACK_B", "the key does not spell the vendor text: 'F2FP.F16.E5M2.UNPACK_B R16, R32' -> F2FP.F16.E5M2.UNPACK_B_R_R / 'E5M2,F16,UNPACK_B'"),
    ("F2FP_R_R", "TF32,F32,PACK_B", "the key does not spell the vendor text: 'F2FP.TF32.F32.PACK_B R16, R32' -> F2FP.TF32.F32.PACK_B_R_R / 'F32,PACK_B,TF32'"),
    ("F2FP_R_R_R", "BF16,F32,PACK_AB", "bit 78 outside the fields moves several tokens of the same form: 'F2FP.BF16.F32.MERGE_C R32, R64, RZ'"),
    ("F2FP_R_R_R", "F16,F32,PACK_AB", "bit 78 outside the fields moves several tokens of the same form: 'F2FP.F16.F32.MERGE_C R32, R64, RZ'"),
    ("F2FP_R_R_R", "F16,F32,PACK_AB,RZ", "bit 78 outside the fields moves several tokens of the same form: 'F2FP.F16.F32.MERGE_C.RZ R32, R48, RZ'"),
    ("F2FP_R_R_R_R", "E4M3,F32,PACK_AB_MERGE_C,SATFINITE", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through F2FP_R_R_R_R / 'SATFINITE,E4M3,F32,PACK_AB_MERGE_C' (shadowed) (+1 more)"),
    ("F2FP_R_R_R_R", "E5M2,F32,PACK_AB_MERGE_C,SATFINITE", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through F2FP_R_R_R_R / 'SATFINITE,E5M2,F32,PACK_AB_MERGE_C' (shadowed) (+1 more)"),
    ("F2FP_R_R_R_R", "SATFINITE,E4M3,F32,PACK_AB_MERGE_C", "the key does not spell the vendor text: 'F2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C R32, R48, R80, R24' -> F2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C_R_R_R_R / 'E4M3,F32,PACK_AB_MERGE_C,SATFINITE'"),
    ("F2FP_R_R_R_R", "SATFINITE,E5M2,F32,PACK_AB_MERGE_C", "the key does not spell the vendor text: 'F2FP.SATFINITE.E5M2.F32.PACK_AB_MERGE_C R32, R48, R80, R24' -> F2FP.SATFINITE.E5M2.F32.PACK_AB_MERGE_C_R_R_R_R / 'E5M2,F32,PACK_AB_MERGE_C,SATFINITE'"),
    ("F2F_R_R", "F16,F32", "cubit mishandles the row's words (not tagged; T-23): field word bit 63: cubit 'F2F.F16.F32 R16, R32' re-encode mismatch:000fe200002008000000002000107304 for 'F2F.F16.F32 R16, -R32'"),
    ("F2F_R_R", "F16,F32,RM", "cubit mishandles the row's words (not tagged; T-23): field word bit 62: cubit 'F2F.F16.F32.RM R32, R48' re-encode mismatch:000fe200002048000000003000207304 for 'F2F.F16.F32.RM R32, |R48|' (+1 more)"),
    ("F2F_R_R", "F16,F32,RP", "cubit mishandles the row's words (not tagged; T-23): field word bit 62: cubit 'F2F.F16.F32.RP R32, R48' re-encode mismatch:000fe200002088000000003000207304 for 'F2F.F16.F32.RP R32, |R48|' (+1 more)"),
    ("F2F_R_UR", "F32,F64", "cubit mishandles the row's words (not tagged; T-23): field word bit 62: cubit 'F2F.F32.F64 R16, UR32' re-encode mismatch:000fe200083010000000002000107d10 for 'F2F.F32.F64 R16, |UR32|' (+1 more)"),
    ("F2IP_R_R_R_R", "F32,NTZ,S8", "bit 72 outside the fields moves operand 4 of the same form: 'F2IP.S8.F32.NTZ R16, R32, R48, R64.H1'"),
    ("HADD2_R_R_FI_FI", "", "field bit 64 (f16_d tok 3) is text-inert"),
    ("HADD2_R_R_FI_FI", "SAT", "field bit 64 (f16_d tok 3) is text-inert"),
    ("HADD2_R_R_FI_FI", "FTZ", "field bit 64 (f16_d tok 3) is text-inert"),
    ("HADD2_R_R_FI_FI", "BF16_V2", "field bit 64 (bf16 tok 3) is text-inert"),
    ("HADD2_R_R_FI_FI", "FTZ,SAT", "field bit 64 (f16_d tok 3) is text-inert"),
    ("HADD2_R_R_FI_FI", "BF16_V2,SAT", "field bit 64 (bf16 tok 3) is text-inert"),
    ("HADD2_R_R_FI_FI", "BF16_V2,FTZ", "field bit 64 (bf16 tok 3) is text-inert"),
    ("HADD2_R_R_FI_FI", "BF16_V2,FTZ,SAT", "field bit 64 (bf16 tok 3) is text-inert"),
    ("HADD2_R_R_R", "BF16_V2", "cubit mishandles the row's words (not tagged; T-23): field word bit 124: cubit 'HADD2.BF16_V2 R32, R48, R96' re-encode mismatch:000fe200002000000000006030207230 for 'HADD2.BF16_V2 R32, R48, R96.reuse'"),
    ("HFMA2_R_R_FI_FI_R", "RELU", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through HFMA2.RELU_R_R_FI_FI_R_P / '' (shadowed)"),
    ("HFMA2_R_R_FI_FI_R", "FMZ,RELU", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through HFMA2.FMZ.RELU_R_R_FI_FI_R_P / '' (shadowed)"),
    ("HFMA2_R_R_FI_FI_R", "FTZ,RELU", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through HFMA2.FTZ.RELU_R_R_FI_FI_R_P / '' (shadowed)"),
    ("HFMA2_R_R_FI_FI_R", "OOB,RELU", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through HFMA2.OOB.RELU_R_R_FI_FI_R_P / '' (shadowed)"),
    ("HFMA2_R_R_FI_FI_R", "F32,RELU", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through HFMA2.F32.RELU_R_R_FI_FI_R_P / '' (shadowed)"),
    ("HFMA2_R_R_FI_FI_R", "F32,FTZ,RELU", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through HFMA2.F32.FTZ.RELU_R_R_FI_FI_R_P / '' (shadowed)"),
    ("HFMA2_R_R_FI_FI_R", "BF16_V2,RELU", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through HFMA2.BF16_V2.RELU_R_R_FI_FI_R_P / '' (shadowed)"),
    ("HFMA2_R_R_FI_FI_R", "BF16_V2,FMZ,RELU", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through HFMA2.BF16_V2.FMZ.RELU_R_R_FI_FI_R_P / '' (shadowed)"),
    ("HFMA2_R_R_FI_FI_R", "BF16_V2,FTZ,RELU", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through HFMA2.BF16_V2.FTZ.RELU_R_R_FI_FI_R_P / '' (shadowed)"),
    ("HFMA2_R_R_FI_FI_R", "BF16_V2,OOB,RELU", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through HFMA2.BF16_V2.OOB.RELU_R_R_FI_FI_R_P / '' (shadowed)"),
    ("HFMA2_R_R_R_FI_FI", "", "cubit mishandles the row's words (not tagged; T-23): field word bit 123: cubit 'HFMA2 R16, R64, R80, 203.25, 203.25' re-encode mismatch:000fe200000000505a5a5a5a40107431 for 'HFMA2 R16, R64, R80.reuse, 203.25, 203.25'"),
    ("HSET2_R_R_FI_FI_P", "AND,BF,BF16_V2,EQ", "field bit 12 (pred tok 5) moves guard 0: '@P6 HSET2.BF16_V2.BF.EQ.AND R16, R96, -2.4233807008389482662e-25, -0.0030975341796875, PT'"),
    ("HSET2_R_R_FI_FI_P", "AND,EQ", "cubit mishandles the row's words (not tagged; T-23): cubit prints 'HSET2.EQ.AND R32, R48, 1.2964953521779640022e-40, 0.003101348876953125, PT' for 'HSET2.EQ.AND R32, R48, 203.25, 203.25, PT' (+3 more)"),
    ("HSET2_R_R_R_P", "AND,BF,BF16_V2,EQ", "bit 60 outside the fields moves operand 3 of the same form: 'HSET2.BF16_V2.BF.EQ.AND R32, R48, R64.H1_H1, PT'"),
    ("HSET2_R_R_R_P", "AND,EQ", "bit 60 outside the fields moves operand 3 of the same form: 'HSET2.EQ.AND R32, R48, R64.H1_H1, PT'"),
];

include!("sm120_rows_common.inc");

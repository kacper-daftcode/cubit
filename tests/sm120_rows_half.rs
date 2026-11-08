//! SM120 half-precision long tail (HFMA2 / HMNMX2 / HADD2 / HSET2 / F2FP / I2FP / F2IP / I2IP / UF2FP / UI2FP / F2F / UF2I / UI2F) (session G run 5, 2026-11-07; KNOWN_ISSUES T1): the remaining harvest rows of
//! HFMA2, HMNMX2, HADD2, HSET2, F2FP, I2FP, F2IP, I2IP, UF2FP, UI2FP, F2F, UF2I, UI2F verified row by row with nvdisasm 13.1 over the whole
//! 128-bit word by `tools/probes/re_sm120_rows.py --family half` -- 51 rows measured (1903 canonical +
//! field words, 6 census witnesses), 34 shadowed keys (64 rows) retired as aliases, 9 unreachable
//! rows of staying keys deleted, 37 named exceptions. Fixture `tests/fixtures/sm120_rows_half_nvdisasm.jsonl`; the test body is `tests/sm120_rows_common.inc`.
//! Session T-18 (2026-11-08): the rows run 5 verified but held back while the 2026-08/09 bug-wave tests pinned their harvest
//! structure (`EXCEPTION_PREFIXES`, G/NEEDS_OWNER.md 12) take their measured status -- those suites are re-pinned to the
//! measured doctrine in the same commit (blackwell-isa 7f12b68).

const FAMILY: &str = "half";
const SOURCE: &str = "rows-half-2026-11-07";
const MNEMONICS: &[&str] = &["HFMA2", "HMNMX2", "HADD2", "HSET2", "F2FP", "I2FP", "F2IP", "I2IP", "UF2FP", "UI2FP", "F2F", "UF2I", "UI2F"];
const FIXTURE: &str = include_str!("fixtures/sm120_rows_half_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 51;
const ALIAS_ROWS: usize = 64;
const DEAD_ROWS: usize = 9;
const FORM_WORDS: usize = 1903;
const WITNESS_WORDS: usize = 6;
/// Harvest rows of the family's mnemonics that batches 12-14 measure or retire on their own branches (LDG.256 /
/// STG.256 / REDG lattices): harvest on this base, not this family's; 0 once those batches are on `main`.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
    ("F2F.F64.F32_R_R_R", "F2F.F64.F32_R_R"),
    ("F2FP.BF16.F32.PACK_AB_R_R_R", "F2FP_R_R_R"),
    ("F2FP.F16.F32.MERGE_C_P_R_R_R", "F2FP.F16.F32.MERGE_C_R_R_R"),
    ("F2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C_R_R_R", "F2FP_R_R_R_R"),
    ("F2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C_R_R_R_?", "F2FP_R_R_R_R"),
    ("F2FP.SATFINITE.E5M2.F32.PACK_AB_MERGE_C_R_R_R_?", "F2FP_R_R_R_R"),
    ("HADD2.F32_R_?_?_II_?", "HADD2_R_R_R"),
    ("HADD2.F32_R_R_R_II_?", "HADD2_R_R_R"),
    ("HADD2.F32_R_R_R_R", "HADD2_R_R_R"),
    ("HADD2_R_R_II_II", "HADD2_R_R_R"),
    ("HFMA2.BF16_V2.FMZ.RELU_R_R_II_II_R_P", "HFMA2.BF16_V2.FMZ.RELU_R_R_FI_FI_R_P"),
    ("HFMA2.BF16_V2.FTZ.RELU_R_R_II_II_R_P", "HFMA2.BF16_V2.FTZ.RELU_R_R_FI_FI_R_P"),
    ("HFMA2.BF16_V2.OOB.RELU_R_R_II_II_R_P", "HFMA2.BF16_V2.OOB.RELU_R_R_FI_FI_R_P"),
    ("HFMA2.BF16_V2.RELU_R_R_II_II_R_P", "HFMA2.BF16_V2.RELU_R_R_FI_FI_R_P"),
    ("HFMA2.BF16_V2_R_R_II_II_R", "HFMA2_R_R_FI_FI_R"),
    ("HFMA2.BF16_V2_R_R_UR_R", "HFMA2_R_R_UR_R"),
    ("HFMA2.F32.FTZ.RELU_R_R_II_II_R_P", "HFMA2.F32.FTZ.RELU_R_R_FI_FI_R_P"),
    ("HFMA2.F32.RELU_R_R_II_II_R_P", "HFMA2.F32.RELU_R_R_FI_FI_R_P"),
    ("HFMA2.FMZ.RELU_R_R_II_II_R_P", "HFMA2.FMZ.RELU_R_R_FI_FI_R_P"),
    ("HFMA2.FTZ.RELU_R_R_II_II_R_P", "HFMA2.FTZ.RELU_R_R_FI_FI_R_P"),
    ("HFMA2.OOB.RELU_R_R_II_II_R_P", "HFMA2.OOB.RELU_R_R_FI_FI_R_P"),
    ("HFMA2.RELU_R_R_II_II_R_P", "HFMA2.RELU_R_R_FI_FI_R_P"),
    ("HFMA2_R_R_II_II_R", "HFMA2_R_R_FI_FI_R"),
    ("HFMA2_R_R_R_?_?_?", "HFMA2_R_R_R_FI_FI"),
    ("HFMA2_R_R_R_?_?_II_?", "HFMA2_R_R_R_FI_FI"),
    ("HFMA2_R_R_R_FI_II", "HFMA2_R_R_R_FI_FI"),
    ("HFMA2_R_R_R_II_?_II_II_?", "HFMA2_R_R_R_FI_FI"),
    ("HFMA2_R_R_R_II_II_II", "HFMA2_R_R_R_FI_FI"),
    ("HFMA2_R_R_R_II_II_II_?", "HFMA2_R_R_R_FI_FI"),
    ("I2FP.F32.S32_R_R", "I2FP_R_R"),
    ("I2FP.F32.S32_R_UR", "I2FP_R_UR"),
    ("UI2F.U32.RP_UR_UR", "UI2F_UR_UR"),
    ("UI2FP.F32.S32_UR_UR_?", "UI2FP.F32.S32_UR_UR"),
    ("UI2FP_UR_UR", "UI2FP.F32.S32_UR_UR"),
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- `G/NEEDS_OWNER.md`.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("F2FP.BF16.F32.PACK_AB_P_R_R_R", "", "the key does not spell the vendor text: 'F2FP.BF16.F32.PACK_AB R32, R48, R64' -> F2FP.BF16.F32.PACK_AB_R_R_R / 'BF16,F32,PACK_AB'"),
    ("F2FP.F16.F32.MERGE_C_R_R_R", "", "bit 72 outside the fields moves operand 3 of the same form: 'F2FP.F16.F32.MERGE_C R16, R32, R48.H1'"),
    ("F2FP.RELU.BF16.F32.PACK_AB_P_R_R_R", "", "the key does not spell the vendor text: 'F2FP.RELU.BF16.F32.PACK_AB R32, R48, R64' -> F2FP.RELU.BF16.F32.PACK_AB_R_R_R / 'BF16,F32,PACK_AB,RELU'"),
    ("F2FP.SATFINITE.BF16.F32.PACK_AB_P_R_R_R", "", "the key does not spell the vendor text: 'F2FP.SATFINITE.BF16.F32.PACK_AB R32, R48, R64' -> F2FP.SATFINITE.BF16.F32.PACK_AB_R_R_R / 'BF16,F32,PACK_AB,SATFINITE'"),
    ("F2FP.SATFINITE.F16.F32.PACK_AB_P_R_R_R", "", "the key does not spell the vendor text: 'F2FP.SATFINITE.F16.F32.PACK_AB R32, R48, R64' -> F2FP.SATFINITE.F16.F32.PACK_AB_R_R_R / 'F16,F32,PACK_AB,SATFINITE'"),
    ("F2FP.SATFINITE.RELU.F16.F32.PACK_AB_P_R_R_R", "", "the key does not spell the vendor text: 'F2FP.SATFINITE.RELU.F16.F32.PACK_AB R32, R48, R64' -> F2FP.SATFINITE.RELU.F16.F32.PACK_AB_R_R_R / 'F16,F32,PACK_AB,RELU,SATFINITE'"),
    ("F2FP_R_R", "BF16,F32,PACK_AB", "the key does not spell the vendor text: 'F2FP.BF16.F32.PACK_AB R16, RZ, UR4' -> F2FP.BF16.F32.PACK_AB_R_R_UR / 'BF16,F32,PACK_AB'"),
    ("F2FP_R_R", "F16,F32,PACK_AB", "the key does not spell the vendor text: 'F2FP.F16.F32.PACK_AB R16, RZ, R32' -> F2FP.F16.F32.PACK_AB_R_R_R / 'F16,F32,PACK_AB'"),
    ("F2FP_R_R_R_R", "E4M3,F32,MERGE_C,PACK_AB,SATFINITE", "the key does not spell the vendor text: 'F2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C R32, R48, R64, R80' -> F2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C_R_R_R_R / 'E4M3,F32,PACK_AB_MERGE_C,SATFINITE'"),
    ("F2FP_R_R_R_R", "E4M3,F32,PACK_AB_MERGE_C,SATFINITE", "bit 72 outside the fields moves operand 4 of the same form: 'F2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C R32, R48, R64, R80.H1'"),
    ("F2FP_R_R_R_R", "E5M2,F32,MERGE_C,PACK_AB,SATFINITE", "the key does not spell the vendor text: 'F2FP.SATFINITE.E5M2.F32.PACK_AB_MERGE_C R32, R48, R64, R80' -> F2FP.SATFINITE.E5M2.F32.PACK_AB_MERGE_C_R_R_R_R / 'E5M2,F32,PACK_AB_MERGE_C,SATFINITE'"),
    ("F2FP_R_R_R_R", "E5M2,F32,PACK_AB_MERGE_C,SATFINITE", "bit 72 outside the fields moves operand 4 of the same form: 'F2FP.SATFINITE.E5M2.F32.PACK_AB_MERGE_C R32, R48, R64, R80.H1'"),
    ("F2FP_R_R_R_R", "SATFINITE,E4M3,F32,PACK_AB_MERGE_C", "the key does not spell the vendor text: 'F2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C R32, R48, R64, R80' -> F2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C_R_R_R_R / 'E4M3,F32,PACK_AB_MERGE_C,SATFINITE'"),
    ("F2FP_R_R_R_R", "SATFINITE,E5M2,F32,PACK_AB_MERGE_C", "the key does not spell the vendor text: 'F2FP.SATFINITE.E5M2.F32.PACK_AB_MERGE_C R32, R48, R64, R80' -> F2FP.SATFINITE.E5M2.F32.PACK_AB_MERGE_C_R_R_R_R / 'E5M2,F32,PACK_AB_MERGE_C,SATFINITE'"),
    ("F2IP.S8.F32.NTZ_R_R_R_II", "", "the key does not spell the vendor text: 'F2IP.S8.F32.NTZ R32, R48, R64, R90' -> F2IP.S8.F32.NTZ_R_R_R_R / 'F32,NTZ,S8'"),
    ("HADD2_R_R_FI_FI", "BF16_V2", "bit 85 outside the fields moves several tokens of the same form: 'HADD2 R32, R64, 203.25, 203.25'"),
    ("HADD2_R_R_FI_FI", "BF16_V2,FTZ", "bit 85 outside the fields moves several tokens of the same form: 'HADD2.FTZ R32, R64, 203.25, 203.25'"),
    ("HADD2_R_R_FI_FI", "BF16_V2,FTZ,SAT", "bit 85 outside the fields moves several tokens of the same form: 'HADD2.FTZ.SAT R32, R64, 203.25, 203.25'"),
    ("HADD2_R_R_FI_FI", "BF16_V2,SAT", "bit 85 outside the fields moves several tokens of the same form: 'HADD2.SAT R32, R64, 203.25, 203.25'"),
    ("HADD2_R_R_FI_FI", "FTZ", "bit 85 outside the fields moves several tokens of the same form: 'HADD2.BF16_V2.FTZ R32, R64, 1.53403862307307520000e+16, 1.53403862307307520000e+16'"),
    ("HADD2_R_R_FI_FI", "FTZ,SAT", "bit 85 outside the fields moves several tokens of the same form: 'HADD2.BF16_V2.FTZ.SAT R32, R64, 1.53403862307307520000e+16, 1.53403862307307520000e+16'"),
    ("HADD2_R_R_FI_FI", "SAT", "bit 85 outside the fields moves several tokens of the same form: 'HADD2.BF16_V2.SAT R32, R64, 1.53403862307307520000e+16, 1.53403862307307520000e+16'"),
    ("HFMA2.BF16_V2.FMZ.RELU_R_R_FI_FI_R_P", "", "bit 85 outside the fields moves several tokens of the same form: 'HFMA2.FMZ.RELU R32, R48, 203.25, 203.25, R80, P3'"),
    ("HFMA2.BF16_V2.FTZ.RELU_R_R_FI_FI_R_P", "", "bit 85 outside the fields moves several tokens of the same form: 'HFMA2.FTZ.RELU R32, R48, 203.25, 203.25, R80, P3'"),
    ("HFMA2.BF16_V2.OOB.RELU_R_R_FI_FI_R_P", "", "bit 85 outside the fields moves several tokens of the same form: 'HFMA2.OOB.RELU R32, R48, 203.25, 203.25, R80, P3'"),
    ("HFMA2.BF16_V2.RELU_R_R_FI_FI_R_P", "", "bit 85 outside the fields moves several tokens of the same form: 'HFMA2.RELU R32, R48, 203.25, 203.25, R80, P3'"),
    ("HFMA2.FMZ.RELU_R_R_FI_FI_R_P", "", "bit 85 outside the fields moves several tokens of the same form: 'HFMA2.BF16_V2.FMZ.RELU R32, R48, 1.53403862307307520000e+16, 1.53403862307307520000e+16, R80, P3'"),
    ("HFMA2.FTZ.RELU_R_R_FI_FI_R_P", "", "bit 85 outside the fields moves several tokens of the same form: 'HFMA2.BF16_V2.FTZ.RELU R32, R48, 1.53403862307307520000e+16, 1.53403862307307520000e+16, R80, P3'"),
    ("HFMA2.OOB.RELU_R_R_FI_FI_R_P", "", "bit 85 outside the fields moves several tokens of the same form: 'HFMA2.BF16_V2.OOB.RELU R32, R48, 1.53403862307307520000e+16, 1.53403862307307520000e+16, R80, P3'"),
    ("HFMA2.RELU_R_R_FI_FI_R_P", "", "bit 85 outside the fields moves several tokens of the same form: 'HFMA2.BF16_V2.RELU R32, R48, 1.53403862307307520000e+16, 1.53403862307307520000e+16, R80, P3'"),
    ("HFMA2_R_R_R_II_FI", "", "the key does not spell the vendor text: 'HFMA2 R32, R48, R64, 203.25, 203.25' -> HFMA2_R_R_R_FI_FI / ''"),
    ("HFMA2_R_R_R_UR", "", "field bit 123 (reuse tok 4) moves operand 3: 'HFMA2 R32, R80, R40.reuse, UR56'"),
    ("HSET2_R_R_II_II_P", "AND,EQ", "the key does not spell the vendor text: 'HSET2.EQ.AND R32, R48, 203.25, 203.25, PT' -> HSET2.EQ.AND_R_R_FI_FI_P / 'AND,EQ'"),
    ("UF2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C_UR_?_?_?", "", "the key does not spell the vendor text: 'UF2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C UR8, URZ, URZ, URZ' -> UF2FP.SATFINITE.E4M3.F32.PACK_AB_MERGE_C_UR_UR_UR_UR / 'E4M3,F32,PACK_AB_MERGE_C,SATFINITE'"),
    ("UF2FP.SATFINITE.E5M2.F32.PACK_AB_MERGE_C_UR_?_?_?", "", "the key does not spell the vendor text: 'UF2FP.SATFINITE.E5M2.F32.PACK_AB_MERGE_C UR8, URZ, URZ, URZ' -> UF2FP.SATFINITE.E5M2.F32.PACK_AB_MERGE_C_UR_UR_UR_UR / 'E5M2,F32,PACK_AB_MERGE_C,SATFINITE'"),
    ("UI2F.RP_UR_UR", "", "bit 20 outside the fields moves operand 1 of the same form: 'UI2F.RP UR17, UR1'"),
    ("UI2FP.F32.S32_UR_UR", "", "bit 20 outside the fields moves operand 1 of the same form: 'UI2FP.F32.S32 UR17, UR1'"),
];

include!("sm120_rows_common.inc");

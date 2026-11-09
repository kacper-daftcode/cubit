//! SM100a memory long tail (session T-23, 2026-11-08; KNOWN_ISSUES T1, the B200 line (the B300 publish corpus holds 151 sm_100a cubins)): the remaining harvest rows of the plain LDG / STG / LD / ST / LDS / STS / LDL / STL / LDGSTS / LDSM / STSM / CCTL / UTMA* / UBLK* keys of sm100a.json verified row by row with nvdisasm 13.1 (-b SM100) over the whole 128-bit word by `tools/probes/re_sm120_rows.py --family memory --arch SM100`, the B300 publish corpus words as witnesses; the field flips the encoder refuses on the sm_100a silicon laws (the odd 64-bit base of a descriptor pair, BUG-077; the LDS / STS .64 / .128 register alignment, BUG-088) are silicon_bits -- nvdisasm names those words, cubit refuses to mint them; the rows left are named.
//! Fixture `tests/fixtures/sm100a_rows_memory_nvdisasm.jsonl` (`tools/probes/re_sm120_rows.py probe --family memory --arch SM100`,
//! nvdisasm 13.1, the table's own corpus words as witnesses); the test body is `tests/sm120_rows_common.inc` (session T-23, 2026-11-08).

const TABLE: &str = "tables/sm100a.json";
const FAMILY: &str = "memory";
const SOURCE: &str = "rows-memory-2026-11-07";
const MNEMONICS: &[&str] = &["LDG", "STG", "LD", "ST", "LDS", "STS", "LDL", "STL", "LDGSTS", "LDGMC", "LDSM", "STSM", "MOVM", "CCTL", "QSPC", "LDGDEPBAR", "UTMALDG", "UTMASTG", "UTMACCTL", "UTMACMDFLUSH", "UBLKCP", "UBLKRED", "UBLKPF"];
const FIXTURE: &str = include_str!("fixtures/sm100a_rows_memory_nvdisasm.jsonl");
const MEASURED_ROWS: usize = 207;
const ALIAS_ROWS: usize = 0;
const DEAD_ROWS: usize = 0;
const FORM_WORDS: usize = 10552;
const WITNESS_WORDS: usize = 11;
/// Rows of the family's mnemonics another batch measures on its own branch: none on this table.
const LEFT_TO_OTHER_BATCHES: usize = 0;
const ALIAS_KEYS: &[(&str, &str)] = &[
];
/// Rows of the family's mnemonics that stay without `_src` (key, group, reason) -- the probe's verdict names each.
const EXCEPTIONS: &[(&str, &str, &str)] = &[
    ("CCTL_ARI", "E,RML2", "bit 32 outside the fields moves operand 1 of the same form: 'CCTL.E.RML2 [R32+0x1]'"),
    ("LDG.E.128_R_ARURI", "128,E", "bit 38 outside the fields moves operand 2 of the same form: 'LDG.E.128 R32, [R48.U32+UR64+0x5a5a5a]'"),
    ("LDG.E.64_R_ARURI", "64,E", "bit 38 outside the fields moves operand 2 of the same form: 'LDG.E.64 R32, [R48.U32+UR64+0x5a5a5a]'"),
    ("LDG.E.EL.STRONG.GPU_R_ARURI", "E,EL,GPU,STRONG", "bit 38 outside the fields moves operand 2 of the same form: 'LDG.E.EL.STRONG.GPU R32, [R48.U32+UR64+0x5a5a5a]'"),
    ("LDG.E.LTC128B.128_R_dARI", "128,E,LTC128B", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through LDG_R_dARI_P / '128,E,LTC128B' (shadowed)"),
    ("LDG.E.NA.STRONG.SM_R_ARURI", "E,NA,SM,STRONG", "bit 38 outside the fields moves operand 2 of the same form: 'LDG.E.NA.STRONG.SM R32, [R48.U32+UR64+0x5a5a5a]'"),
    ("LDG.E_R_ARURI", "E", "bit 38 outside the fields moves operand 2 of the same form: 'LDG.E R32, [R48.U32+UR64+0x5a5a5a]'"),
    ("LDGSTS_ARI_ARI", "128,BYPASS,E,LTC128B", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through LDGSTS_ARI_ARURI / '128,BYPASS,E,LTC128B' (shadowed) (+1 more)"),
    ("LDGSTS_ARI_ARI", "64,E,LTC128B", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through LDGSTS_ARI_ARURI / '64,E,LTC128B' (shadowed) (+1 more)"),
    ("LDGSTS_ARI_ARI_P", "128,BYPASS,E,LTC128B", "cubit mishandles the row's words (not tagged; T-23): field word bit 90: cubit 'LDGSTS.E.BYPASS.LTC128B.128 [R16+-0x5a5a6], [R32.64+-0x5a6],' re-encode error:invalid predicate literal `P11` in \"LDGSTS.E.BYPASS.LTC128B.128 [R16+-0x5a5a6], [R32.64+-0x5a6], P11 ;\": predicate s"),
    ("LDGSTS_ARI_ARI_P", "128,E,LTC128B", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through LDGSTS_ARI_ARURI_P / '64,E,LTC128B' (shadowed) (+5 more)"),
    ("LDGSTS_ARI_ARI_P", "64,E,LTC128B", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through LDGSTS_ARI_ARURI_P / '64,E,LTC128B' (shadowed) (+1 more)"),
    ("LDGSTS_ARI_ARURI", "128,BYPASS,E,LTC128B", "field bit 72 (sub_ur1 tok 2) moves modifier None: 'LDGSTS.E.BYPASS.LTC256B.128 [R32+-0x5a5a6], [R48.64+UR64+-0x5a6]'"),
    ("LDGSTS_ARI_ARURI", "128,E,LTC128B", "field bit 72 (sub_ur1 tok 2) moves modifier None: 'LDGSTS.E.LTC256B.128 [R32+-0x5a5a6], [R48.64+UR96+-0x5a6]'"),
    ("LDGSTS_ARI_ARURI", "64,E,LTC128B", "field bit 72 (sub_ur1 tok 2) moves modifier None: 'LDGSTS.E.LTC256B.64 [R32+-0x5a5a6], [R48.64+UR64+-0x5a6]'"),
    ("LDGSTS_ARI_ARURI", "E,LTC128B", "bit 32 outside the fields moves operand 2 of the same form: '@P3 LDGSTS.E.LTC128B [R16+-0x5a5a6], [R32.64+UR64+0x1]'"),
    ("LDGSTS_ARI_ARURI_P", "128,E,LTC128B", "field bit 72 (sub_ur1 tok 2) moves modifier None: 'LDGSTS.E.LTC256B.128 [R16+-0x5a5a6], [R32.64+UR80+-0x5a6], P3'"),
    ("LDGSTS_ARI_ARURI_P", "64,E,LTC128B", "field bit 72 (sub_ur1 tok 2) moves modifier None: 'LDGSTS.E.LTC256B.64 [R16+-0x5a5a6], [R48.64+UR64+-0x5a6], P3'"),
    ("LDGSTS_ARI_ARURI_P", "E,LTC128B", "field bit 72 (sub_ur1 tok 2) moves modifier None: 'LDGSTS.E.LTC256B [R16+-0x5a5a6], [R48.64+UR64+-0x5a6], P3'"),
    ("LDGSTS_ARI_dARI", "128,BYPASS,E", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E.BYPASS.128 [R288+-0x5a5a6], desc[UR96][R49.64+-0x5a' re-encode error:unencodable memory address \"[R288+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate)"),
    ("LDGSTS_ARI_dARI", "128,BYPASS,E,LTC128B", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E.BYPASS.LTC128B.128 [R288+-0x5a5a6], desc[UR96][R49.' re-encode error:unencodable memory address \"[R288+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate)"),
    ("LDGSTS_ARI_dARI", "64,E", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E.64 [R288+-0x5a5a6], desc[UR96][R49.64+-0x5a6]' re-encode error:unencodable memory address \"[R288+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate); imme"),
    ("LDGSTS_ARI_dARI", "64,E,LTC128B", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E.LTC128B.64 [R288+-0x5a5a6], desc[UR96][R49.64+-0x5a' re-encode error:unencodable memory address \"[R288+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate)"),
    ("LDGSTS_ARI_dARI", "64,E,LTC256B", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E.LTC256B.64 [R288+-0x5a5a6], desc[UR96][R49.64+-0x5a' re-encode error:unencodable memory address \"[R288+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate)"),
    ("LDGSTS_ARI_dARI", "E", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E [R288+-0x5a5a6], desc[UR96][R49.64+-0x5a6]' re-encode error:unencodable memory address \"[R288+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate); immedia"),
    ("LDGSTS_ARI_dARI", "E,LTC128B", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E.LTC128B [R288+-0x5a5a6], desc[UR96][R49.64+-0x5a6]' re-encode error:unencodable memory address \"[R288+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate);"),
    ("LDGSTS_ARI_dARI_P", "128,BYPASS,E,LTC128B", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E.BYPASS.LTC128B.128 [R272+-0x5a5a6], desc[UR80][R33.' re-encode error:unencodable memory address \"[R272+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate)"),
    ("LDGSTS_ARI_dARI_P", "128,BYPASS,E,LTC128B,ZFILL", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E.BYPASS.LTC128B.128.ZFILL [R272+-0x5a5a6], desc[UR80' re-encode error:unencodable memory address \"[R272+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate)"),
    ("LDGSTS_ARI_dARI_P", "128,BYPASS,E,ZFILL", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E.BYPASS.128.ZFILL [R272+-0x5a5a6], desc[UR80][R33.64' re-encode error:unencodable memory address \"[R272+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate)"),
    ("LDGSTS_ARI_dARI_P", "64,E", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E.64 [R272+-0x5a5a6], desc[UR48][R65.64+-0x5a6], P3' re-encode error:unencodable memory address \"[R272+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate);  (+1 more)"),
    ("LDGSTS_ARI_dARI_P", "64,E,LTC128B", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E.LTC128B.64 [R272+-0x5a5a6], desc[UR80][R33.64+-0x5a' re-encode error:unencodable memory address \"[R272+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate)"),
    ("LDGSTS_ARI_dARI_P", "E", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E [R272+-0x5a5a6], desc[UR48][R65.64+-0x5a6], P3' re-encode error:unencodable memory address \"[R272+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate); imm (+1 more)"),
    ("LDGSTS_ARI_dARI_P", "E,LTC128B", "cubit mishandles the row's words (not tagged; T-23): field word bit 24: cubit 'LDGSTS.E.LTC128B [R272+-0x5a5a6], desc[UR80][R33.64+-0x5a6],' re-encode error:unencodable memory address \"[R272+-0x5a5a6]\": every bracket component must classify once (base reg / UR / immediate)"),
    ("LDGSTS_ARURI_ARI", "128,BYPASS,E,LTC128B", "field bit 72 (sub_ur1 tok 1) moves modifier None: 'LDGSTS.E.BYPASS.LTC256B.128 [R32+UR96+-0x5a5a6], [R48.64+-0x5a6]'"),
    ("LDGSTS_ARURI_ARI", "128,E,LTC128B", "field bit 72 (sub_ur1 tok 1) moves modifier None: 'LDGSTS.E.LTC256B.128 [R32+UR96+-0x5a5a6], [R48.64+-0x5a6]'"),
    ("LDGSTS_ARURI_ARI", "64,E,LTC128B", "field bit 72 (sub_ur1 tok 1) moves modifier None: 'LDGSTS.E.LTC256B.64 [R32+UR96+-0x5a5a6], [R48.64+-0x5a6]'"),
    ("LDGSTS_ARURI_ARI", "E,LTC128B", "field bit 72 (sub_ur1 tok 1) moves modifier None: 'LDGSTS.E.LTC256B [R32+UR96+-0x5a5a6], [R48.64+-0x5a6]'"),
    ("LDGSTS_ARURI_ARI_P", "64,E,LTC128B", "field bit 72 (sub_ur1 tok 1) moves modifier None: 'LDGSTS.E.LTC256B.64 [R16+UR32+-0x5a5a6], [R64.64+-0x5a6], P3'"),
    ("LDGSTS_ARURI_ARI_P", "E,LTC128B", "cubit mishandles the row's words (not tagged; T-23): field word bit 90: cubit 'LDGSTS.E.LTC128B [R16+UR80+-0x5a5a6], [R32.64+-0x5a6], P11' re-encode error:invalid predicate literal `P11` in \"LDGSTS.E.LTC128B [R16+UR80+-0x5a5a6], [R32.64+-0x5a6], P11 ;\": predicate space is "),
    ("LDS_R_AURI", "", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through LDS_R_ARURI / '' (shadowed)"),
    ("LDS_R_AURI", "128", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through LDS_R_ARURI / '128' (shadowed)"),
    ("LDS_R_AURI", "64", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through LDS_R_ARURI / '64' (shadowed)"),
    ("LDS_R_AURI", "U16", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through LDS_R_ARURI / 'U16' (shadowed)"),
    ("LDS_R_AURI", "U8", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through LDS_R_ARURI / 'U8' (shadowed)"),
    ("LD_R_ARURI", "E", "field bit 15 (reg tok 1) moves guard 0: '@!PT LD.E R8, [R32.U32+UR48]'"),
    ("LD_R_dARI", "E,STRONG,SYS", "cubit mishandles the row's words (not tagged; T-23): cubit prints 'LD.E.STRONG.SYS R32, desc[UR64][R48.64]' for 'LD.E.STRONG.SYS R32, desc[UR64][R48.64+0x5a5a5a]' (+4 more)"),
    ("QSPC_P_R_ARI", "D,E", "field bit 84 (pred tok 1) is text-inert"),
    ("STG.E.128_ARURI_R", "128,E", "bit 70 outside the fields moves operand 1 of the same form: 'STG.E.128 [R32.U32+UR112+0x5a5a5a], R80'"),
    ("STG.E.64_ARURI_R", "64,E", "bit 70 outside the fields moves operand 1 of the same form: 'STG.E.64 [R32.U32+UR112+0x5a5a5a], R80'"),
    ("STG.E.EL.STRONG.GPU_ARURI_R", "E,EL,GPU,STRONG", "bit 70 outside the fields moves operand 1 of the same form: 'STG.E.EL.STRONG.GPU [R32.U32+UR112+0x5a5a5a], R80'"),
    ("STG.E.NA.128.STRONG.GPU_ARURI_R", "128,E,GPU,NA,STRONG", "bit 70 outside the fields moves operand 1 of the same form: 'STG.E.NA.128.STRONG.GPU [R32.U32+UR112+0x5a5a5a], R80'"),
    ("STG.E.NA.U16.STRONG.GPU_ARURI_R", "E,GPU,NA,STRONG,U16", "bit 70 outside the fields moves operand 1 of the same form: 'STG.E.NA.U16.STRONG.GPU [R32.U32+UR112+0x5a5a5a], R80'"),
    ("STS_ARI_R", "64", "nvdisasm rejects every canonical word of the row"),
    ("STS_AURI_R", "", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through STS_ARURI_R / '' (shadowed)"),
    ("STS_AURI_R", "128", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through STS_ARURI_R / '128' (shadowed)"),
    ("STS_AURI_R", "64", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through STS_ARURI_R / '64' (shadowed)"),
    ("STS_AURI_R", "U16", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through STS_ARURI_R / 'U16' (shadowed)"),
    ("STS_AURI_R", "U8", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through STS_ARURI_R / 'U8' (shadowed)"),
    ("STS_AURI_R", "S8", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through STS_ARURI_R / 'S8' (shadowed)"),
    ("STS_AURI_R", "S16", "cubit mishandles the row's words (not tagged; T-23): cubit decodes the canonical word through STS_ARURI_R / 'S16' (shadowed)"),
    ("UBLKCP_AURI_AURI_UR", "G,S", "field bit 40 (sub_imm1 tok 1) is text-inert"),
];

include!("sm120_rows_common.inc");

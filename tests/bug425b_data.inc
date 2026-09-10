// MACHINE-BUILT by work/bug425b/gen425bpins.py (rc=2 self-checks; no hand hex).
// BUG-425b witnesses: arb425b_law (60 combos x4 carrier x4 model AGREE EVERY/DIVERGENT=0) +
// arb425c_law (era-retention) + fuzz425 26-rec taxonomy machine-verified post-fix +
// measure425b_wt grid 520 cells 511-claims-preserved BAD 0 (== post-425 reference).
pub const CANON425B: &str = "d560e9953d42117859b75b8895c0ec34f30f6c8f"; // BUG-425b graft F2-iter238B; rides 3f6ca6f = BUG-425
#[rustfmt::skip]
pub const REFUSE425B: &[(u128, &str)] = &[
    (0x000fc20000000800000000040a007188, "ari.pl.b9=0,b11=0"),
    (0x000fc20000000800000000040a007988, "ari.pl.b9=0,b11=1"),
    (0x000fc20000000800000000040a007b88, "ari.pl.b9=1,b11=1"),
    (0x000fc20000000a00000000040a007988, "ari.64.b9=0,b11=1"),
    (0x000fc20000000a00000000040a007b88, "ari.64.b9=1,b11=1"),
    (0x000fc20008000804000055040a007188, "aruri.pl.b9=0,b11=0"),
    (0x000fc20008000804000055040a007388, "aruri.pl.b9=1,b11=0"),
    (0x000fc20008000804000055040a007b88, "aruri.pl.b9=1,b11=1"),
    (0x000fc20008000a04000055040a007b88, "aruri.64.b9=1,b11=1"),
    (0x000fc2000800080400005504ff007188, "auri.pl.b9=0,b11=0"),
    (0x000fc2000800080400005504ff007388, "auri.pl.b9=1,b11=0"),
    (0x000fc2000800080400005504ff007b88, "auri.pl.b9=1,b11=1"),
    (0x000fc20008000a0400005504ff007b88, "auri.64.b9=1,b11=1"),
    (0x000fc20000000c00000000040a007188, "ari.128.b9=0,b11=0"),
    (0x000fc20000000c00000000040a007988, "ari.128.b9=0,b11=1"),
    (0x000fc20000000c00000000040a007b88, "ari.128.b9=1,b11=1"),
    (0x000fc20000000000000000040a007188, "ari.U8.b9=0,b11=0"),
    (0x000fc20000000000000000040a007988, "ari.U8.b9=0,b11=1"),
    (0x000fc20000000000000000040a007b88, "ari.U8.b9=1,b11=1"),
    (0x000fc20000000400000000040a007188, "ari.U16.b9=0,b11=0"),
    (0x000fc20000000400000000040a007988, "ari.U16.b9=0,b11=1"),
    (0x000fc20000000400000000040a007b88, "ari.U16.b9=1,b11=1"),
    (0x000fc20008000c04000055040a007188, "aruri.128.b9=0,b11=0"),
    (0x000fc20008000c04000055040a007388, "aruri.128.b9=1,b11=0"),
    (0x000fc20008000c04000055040a007b88, "aruri.128.b9=1,b11=1"),
    (0x000fc20008000004000055040a007188, "aruri.U8.b9=0,b11=0"),
    (0x000fc20008000004000055040a007388, "aruri.U8.b9=1,b11=0"),
    (0x000fc20008000004000055040a007b88, "aruri.U8.b9=1,b11=1"),
    (0x000fc20008000404000055040a007188, "aruri.U16.b9=0,b11=0"),
    (0x000fc20008000404000055040a007388, "aruri.U16.b9=1,b11=0"),
    (0x000fc20008000404000055040a007b88, "aruri.U16.b9=1,b11=1"),
    (0x000fc20008000c0400005504ff007188, "auri.128.b9=0,b11=0"),
    (0x000fc20008000c0400005504ff007388, "auri.128.b9=1,b11=0"),
    (0x000fc20008000c0400005504ff007b88, "auri.128.b9=1,b11=1"),
    (0x000fc2000800000400005504ff007188, "auri.U8.b9=0,b11=0"),
    (0x000fc2000800000400005504ff007388, "auri.U8.b9=1,b11=0"),
    (0x000fc2000800000400005504ff007b88, "auri.U8.b9=1,b11=1"),
    (0x000fc2000800040400005504ff007188, "auri.U16.b9=0,b11=0"),
    (0x000fc2000800040400005504ff007388, "auri.U16.b9=1,b11=0"),
    (0x000fc2000800040400005504ff007b88, "auri.U16.b9=1,b11=1"),
];
#[rustfmt::skip]
pub const FUZZ425B_DECODE: &[(u128, u32, &str, [Option<&str>; 4], [Option<&str>; 4])] = &[
    (0x000fc2000800052e7fffff040a007988, 18, "B", [Some("STS.U16 [R10+UR46+0x7fffff], R4"), Some("STS.U16 [R10+UR46+0x7fffff], R4"), Some("STS.U16 [R10+UR46+0x7fffff], R4"), Some("STS.U16 [R10+UR46+0x7fffff], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc200080005ba7fffff040a007988, 40, "B", [Some("STS.U16 [R10+UR186+0x7fffff], R4"), Some("STS.U16 [R10+UR186+0x7fffff], R4"), Some("STS.U16 [R10+UR186+0x7fffff], R4"), Some("STS.U16 [R10+UR186+0x7fffff], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc200080047322e5ada04ff007988, 83, "A", [None, None, None, None], [None, None, None, None]),
    (0x000fc2000800055263eb67040a007988, 95, "B", [Some("STS.U16 [R10+UR82+0x63eb67], R4"), Some("STS.U16 [R10+UR82+0x63eb67], R4"), Some("STS.U16 [R10+UR82+0x63eb67], R4"), Some("STS.U16 [R10+UR82+0x63eb67], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc200080005af800001040a007988, 96, "B", [Some("STS.U16 [R10+UR175+-0x7fffff], R4"), Some("STS.U16 [R10+UR175+-0x7fffff], R4"), Some("STS.U16 [R10+UR175+-0x7fffff], R4"), Some("STS.U16 [R10+UR175+-0x7fffff], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc200080055257ffffe040a001988, 144, "B", [Some("@P1 STS.U16 [R10.X4+UR37+0x7ffffe], R4"), Some("@P1 STS.U16 [R10.X4+UR37+0x7ffffe], R4"), Some("@P1 STS.U16 [R10.X4+UR37+0x7ffffe], R4"), Some("@P1 STS.U16 [R10.X4+UR37+0x7ffffe], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc20008002e937fffff04ff003988, 231, "A-hole", [None, None, None, None], [None, None, None, None]),
    (0x000fc2000800828b00015504ff007988, 257, "A", [None, None, None, None], [None, None, None, None]),
    (0x000fc20008002484800000040a007988, 274, "X", [Some("STS.U16 [R10+UR132+-0x800000], R4"), Some("STS.U16 [R10+UR132+-0x800000], R4"), Some("STS.U16 [R10+UR132+-0x800000], R4"), Some("STS.U16 [R10+UR132+-0x800000], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc2000800144e800001040a00e988, 303, "B", [Some("@!P6 STS.U16 [R10+UR78+-0x7fffff], R4"), Some("@!P6 STS.U16 [R10+UR78+-0x7fffff], R4"), Some("@!P6 STS.U16 [R10+UR78+-0x7fffff], R4"), Some("@!P6 STS.U16 [R10+UR78+-0x7fffff], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc2000800847fffffff040a007988, 307, "B", [Some("STS.U16 [R10.X8+UR127+-0x1], R4"), Some("STS.U16 [R10.X8+UR127+-0x1], R4"), Some("STS.U16 [R10.X8+UR127+-0x1], R4"), Some("STS.U16 [R10.X8+UR127+-0x1], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc2000800027e00015504ff007988, 309, "D", [None, None, None, None], [None, None, None, None]),
    (0x000fc20008010461ffffff040a007988, 333, "X", [Some("STS.U16 [R10+UR97+-0x1], R4"), Some("STS.U16 [R10+UR97+-0x1], R4"), Some("STS.U16 [R10+UR97+-0x1], R4"), Some("STS.U16 [R10+UR97+-0x1], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc2000000022400000104f8000844, 348, "D-stsm", [Some("@P0 STSM.16.M88.4 [R248+0x1], R4"), Some("@P0 STSM.16.M88.4 [R248+0x1], R4"), None, Some("@P0 STSM.16.M88.4 [R248+0x1], R4")], [Some("STSM_ARI_R|16,4,M88"), Some("STSM_ARI_R|16,4,M88"), None, Some("STSM_ARI_R|16,4,M88")]),
    (0x000fc2000800444b800000040a007988, 350, "X", [Some("STS.U16 [R10.X4+UR75+-0x800000], R4"), Some("STS.U16 [R10.X4+UR75+-0x800000], R4"), Some("STS.U16 [R10.X4+UR75+-0x800000], R4"), Some("STS.U16 [R10.X4+UR75+-0x800000], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc20000000b2a800000040a007988, 362, "C", [None, None, None, None], [None, None, None, None]),
    (0x000fc200080104ff7ffffe040a007988, 376, "X", [Some("STS.U16 [R10+URZ+0x7ffffe], R4"), Some("STS.U16 [R10+URZ+0x7ffffe], R4"), Some("STS.U16 [R10+URZ+0x7ffffe], R4"), Some("STS.U16 [R10+URZ+0x7ffffe], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc20008002fcb80000104ff007988, 389, "A", [None, None, None, None], [None, None, None, None]),
    (0x000fc200000000047ffffe046c000844, 426, "D-stsm", [None, None, None, Some("@P0 STSM.16.M88 [R108+0x7ffffe], R4")], [None, None, None, Some("STSM_ARI_R|16,M88")]),
    (0x000fc200080004547fffff040a007988, 530, "B", [Some("STS.U16 [R10+UR84+0x7fffff], R4"), Some("STS.U16 [R10+UR84+0x7fffff], R4"), Some("STS.U16 [R10+UR84+0x7fffff], R4"), Some("STS.U16 [R10+UR84+0x7fffff], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc2000800039580000004ff007988, 542, "D", [None, None, None, None], [None, None, None, None]),
    (0x000fc2000800033500000004ff009988, 568, "D", [None, None, None, None], [None, None, None, None]),
    (0x000fc2000800456c7ffffe040a006988, 570, "B", [Some("@P6 STS.U16 [R10.X4+UR108+0x7ffffe], R4"), Some("@P6 STS.U16 [R10.X4+UR108+0x7ffffe], R4"), Some("@P6 STS.U16 [R10.X4+UR108+0x7ffffe], R4"), Some("@P6 STS.U16 [R10.X4+UR108+0x7ffffe], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc20008000424ccc152040a007988, 587, "B", [Some("STS.U16 [R10+UR36+-0x333eae], R4"), Some("STS.U16 [R10+UR36+-0x333eae], R4"), Some("STS.U16 [R10+UR36+-0x333eae], R4"), Some("STS.U16 [R10+UR36+-0x333eae], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc200880005e0ffffff04ff00e988, 690, "E", [None, None, None, Some("@!P6 STS.U16 [UR224+-0x1], R4")], [None, None, None, Some("STS_AURI_R|U16")]),
    (0x000fc200080015c63b9218040a007988, 764, "B", [Some("STS.U16 [R10+UR198+0x3b9218], R4"), Some("STS.U16 [R10+UR198+0x3b9218], R4"), Some("STS.U16 [R10+UR198+0x3b9218], R4"), Some("STS.U16 [R10+UR198+0x3b9218], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
];
#[rustfmt::skip]
pub const ERA425B: &[(u128, &str, [Option<&str>; 4])] = &[
    (0x0001c00000000a000000100005000188, "sts64-oldera", [Some("@P0 STS.64 [R5+0x10], R0"), Some("@P0 STS.64 [R5+0x10], R0"), Some("@P0 STS.64 [R5+0x10], R0"), None]),
    (0x0001c0000000080000001000ff000388, "stspl-oldera", [Some("@P0 STS [0x10], R0"), Some("@P0 STS [0x10], R0"), Some("@P0 STS [0x10], R0"), Some("@P0 STS [0x10], R0")]),
];
#[rustfmt::skip]
pub const LEGAL425B: &[(u128, &str, [Option<&str>; 4])] = &[
    (0x000fc20000000800000000040a007388, "ari.pl.b9=1,b11=0", [Some("STS [R10], R4"), Some("STS [R10], R4"), Some("STS [R10], R4"), Some("STS [R10], R4")]),
    (0x000fc20000000a00000000040a007388, "ari.64.b9=1,b11=0", [Some("STS.64 [R10], R4"), Some("STS.64 [R10], R4"), Some("STS.64 [R10], R4"), Some("STS.64 [R10], R4")]),
    (0x000fc20008000804000055040a007988, "aruri.pl.b9=0,b11=1", [Some("STS [R10+UR4+0x55], R4"), Some("STS [R10+UR4+0x55], R4"), Some("STS [R10+UR4+0x55], R4"), Some("STS [R10+UR4+0x55], R4")]),
    (0x000fc20008000a04000055040a007988, "aruri.64.b9=0,b11=1", [Some("STS.64 [R10+UR4+0x55], R4"), Some("STS.64 [R10+UR4+0x55], R4"), Some("STS.64 [R10+UR4+0x55], R4"), Some("STS.64 [R10+UR4+0x55], R4")]),
    (0x000fc2000800080400005504ff007988, "auri.pl.b9=0,b11=1", [Some("STS [UR4+0x55], R4"), Some("STS [UR4+0x55], R4"), Some("STS [UR4+0x55], R4"), Some("STS [UR4+0x55], R4")]),
    (0x000fc20008000a0400005504ff007988, "auri.64.b9=0,b11=1", [Some("STS.64 [UR4+0x55], R4"), Some("STS.64 [UR4+0x55], R4"), Some("STS.64 [UR4+0x55], R4"), Some("STS.64 [UR4+0x55], R4")]),
    (0x000fc20000000c00000000040a007388, "ari.128.b9=1,b11=0", [Some("STS.128 [R10], R4"), Some("STS.128 [R10], R4"), Some("STS.128 [R10], R4"), Some("STS.128 [R10], R4")]),
    (0x000fc20000000000000000040a007388, "ari.U8.b9=1,b11=0", [Some("STS.U8 [R10], R4"), Some("STS.U8 [R10], R4"), Some("STS.U8 [R10], R4"), Some("STS.U8 [R10], R4")]),
    (0x000fc20000000400000000040a007388, "ari.U16.b9=1,b11=0", [Some("STS.U16 [R10], R4"), Some("STS.U16 [R10], R4"), Some("STS.U16 [R10], R4"), Some("STS.U16 [R10], R4")]),
    (0x000fc20008000c04000055040a007988, "aruri.128.b9=0,b11=1", [Some("STS.128 [R10+UR4+0x55], R4"), Some("STS.128 [R10+UR4+0x55], R4"), Some("STS.128 [R10+UR4+0x55], R4"), Some("STS.128 [R10+UR4+0x55], R4")]),
    (0x000fc20008000004000055040a007988, "aruri.U8.b9=0,b11=1", [Some("STS.U8 [R10+UR4+0x55], R4"), Some("STS.U8 [R10+UR4+0x55], R4"), Some("STS.U8 [R10+UR4+0x55], R4"), Some("STS.U8 [R10+UR4+0x55], R4")]),
    (0x000fc20008000404000055040a007988, "aruri.U16.b9=0,b11=1", [Some("STS.U16 [R10+UR4+0x55], R4"), Some("STS.U16 [R10+UR4+0x55], R4"), Some("STS.U16 [R10+UR4+0x55], R4"), Some("STS.U16 [R10+UR4+0x55], R4")]),
    (0x000fc20008000c0400005504ff007988, "auri.128.b9=0,b11=1", [Some("STS.128 [UR4+0x55], R4"), Some("STS.128 [UR4+0x55], R4"), Some("STS.128 [UR4+0x55], R4"), Some("STS.128 [UR4+0x55], R4")]),
    (0x000fc2000800000400005504ff007988, "auri.U8.b9=0,b11=1", [Some("STS.U8 [UR4+0x55], R4"), Some("STS.U8 [UR4+0x55], R4"), Some("STS.U8 [UR4+0x55], R4"), Some("STS.U8 [UR4+0x55], R4")]),
    (0x000fc2000800040400005504ff007988, "auri.U16.b9=0,b11=1", [Some("STS.U16 [UR4+0x55], R4"), Some("STS.U16 [UR4+0x55], R4"), Some("STS.U16 [UR4+0x55], R4"), Some("STS.U16 [UR4+0x55], R4")]),
];
#[rustfmt::skip]
pub const TOLER425B: &[(u128, &str, [Option<&str>; 4])] = &[
    (0x000fc20000000a00000000040a007188, "ari.64.b9=0,b11=0", [Some("STS.64 [R10], R4"), Some("STS.64 [R10], R4"), Some("STS.64 [R10], R4"), None]),
    (0x000fc20008000a04000055040a007188, "aruri.64.b9=0,b11=0", [Some("STS.64 [R10+0x55], R4"), Some("STS.64 [R10+0x55], R4"), Some("STS.64 [R10+0x55], R4"), None]),
    (0x000fc20008000a04000055040a007388, "aruri.64.b9=1,b11=0", [Some("STS.64 [R10+0x55], R4"), Some("STS.64 [R10+0x55], R4"), Some("STS.64 [R10+0x55], R4"), None]),
    (0x000fc20008000a0400005504ff007188, "auri.64.b9=0,b11=0", [Some("STS.64 [0x55], R4"), Some("STS.64 [0x55], R4"), Some("STS.64 [0x55], R4"), None]),
    (0x000fc20008000a0400005504ff007388, "auri.64.b9=1,b11=0", [Some("STS.64 [0x55], R4"), Some("STS.64 [0x55], R4"), Some("STS.64 [0x55], R4"), None]),
];
pub const CLAIMCOUNT425B: usize = 511; // 520-grid claims-preserved == post-425 reference

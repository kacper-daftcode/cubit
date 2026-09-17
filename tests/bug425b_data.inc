// MACHINE-BUILT by work/bug425b/gen425bpins.py (rc=2 self-checks; no hand hex).
// BUG-425b witnesses: arb425b_law (60 combos x4 carrier x4 model AGREE EVERY/DIVERGENT=0) +
// arb425c_law (era-retention) + fuzz425 26-rec taxonomy machine-verified post-fix +
// measure425b_wt grid 520 cells 511-claims-preserved BAD 0 (== post-425 reference).
pub const CANON425B: &str = "bd2e25464208f9be6abc1e3c7475ca34914ad095" /* ride F2-iter275 (BUG-466 ELL2.256 dARI-era rekanon plain-geo): 67b54f4405b7f6d2d748d8221deb6a9a59cd3c2f canonical, was 23976eb44550254b12f8862ebc088d2c5d49dd72; */ /* ride F2-iter272 (BUG-465 modsub plain E*L2.256 lattice): 23976eb44550254b12f8862ebc088d2c5d49dd72 canonical, was 49681135da169cdd27585a3eea52b61c585fa589; old:  ride F2-iter270 (BUG-464 plain ARURI64 lattice): 49681135da169cdd27585a3eea52b61c585fa589 canonical, was 50780675cd8e43ddd496d5a130752178b7163686; old:  ride F2-iter268 (BUG-432R donor-128E): 50780675cd8e43ddd496d5a130752178b7163686 canonical, was a6e3c9ea9ad9ad95d14687580eec2c8f82646baf = BUG-432 ari-cavity F2-iter267; old:  ride F2-iter267 (BUG-432 ari-cavity): a6e3c9ea9ad9ad95d14687580eec2c8f82646baf canonical, was a64b82bff6706350b82018609016f624188b99a5 = BUG-463 ltc F2-iter266 */ /* ride F2-iter266 (BUG-463 ltc-widths): a64b82bff6706350b82018609016f624188b99a5 canonical, was f58ed1683bded052bcb100a0762c16e7e91248c4 = BUG-461 glyph F2-iter265 */ /* ride F2-iter265 (BUG-461 glyph): f58ed1683bded052bcb100a0762c16e7e91248c4 canonical, was f37655889e6da3ddd25b73a926c21ec3b58fa768 = BUG-462 narrow F2-iter264 */ /* ride F2-iter264 (BUG-462 narrow): f37655889e6da3ddd25b73a926c21ec3b58fa768 canonical, was 700524e698304dcbf1a3884f72f05abff609b8aa = BUG-453 graft F2-iter263 */ /* ride F2-iter263 (BUG-453 graft): 700524e698304dcbf1a3884f72f05abff609b8aa canonical, was 700524e698304dcbf1a3884f72f05abff609b8aa = BUG-452 narrow F2-iter260 */ /* ride F2-iter260 (BUG-452 narrow): 700524e698304dcbf1a3884f72f05abff609b8aa canonical, was 4ee843162216e75d037135b5907c819759471296 = BUG-454 F2-iter258 */ /* ride F2-iter258 (BUG-454 graft): 4ee843162216e75d037135b5907c819759471296 canonical, was 589be874 = BUG-450 F2-iter255 */ /* ride F2-iter255 (BUG-450 graft): 589be874bfcab4513e5f70b43c832d73f1bea3c1 canonical, was 099faa0 = BUG-447 F2-iter252 */; // BUG-425b graft F2-iter238B; rides 3f6ca6f = BUG-425
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
    (0x000fc200080047322e5ada04ff007988, 83, "B", [Some("STS.S16 [RZ.X4+UR50+0x2e5ada], R4"), Some("STS.S16 [RZ.X4+UR50+0x2e5ada], R4"), Some("STS.S16 [RZ.X4+UR50+0x2e5ada], R4"), Some("STS.S16 [RZ.X4+UR50+0x2e5ada], R4")], [Some("STS_ARURI_R|S16"), Some("STS_ARURI_R|S16"), Some("STS_ARURI_R|S16"), Some("STS_ARURI_R|S16")]), // healed 443 (S2 width-map; vendor re-probe x4 work/bug443/arb443ride83_law.json),
    (0x000fc2000800055263eb67040a007988, 95, "B", [Some("STS.U16 [R10+UR82+0x63eb67], R4"), Some("STS.U16 [R10+UR82+0x63eb67], R4"), Some("STS.U16 [R10+UR82+0x63eb67], R4"), Some("STS.U16 [R10+UR82+0x63eb67], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc200080005af800001040a007988, 96, "B", [Some("STS.U16 [R10+UR175+-0x7fffff], R4"), Some("STS.U16 [R10+UR175+-0x7fffff], R4"), Some("STS.U16 [R10+UR175+-0x7fffff], R4"), Some("STS.U16 [R10+UR175+-0x7fffff], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc200080055257ffffe040a001988, 144, "B", [Some("@P1 STS.U16 [R10.X4+UR37+0x7ffffe], R4"), Some("@P1 STS.U16 [R10.X4+UR37+0x7ffffe], R4"), Some("@P1 STS.U16 [R10.X4+UR37+0x7ffffe], R4"), Some("@P1 STS.U16 [R10.X4+UR37+0x7ffffe], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc20008002e937fffff04ff003988, 231, "A-hole", [None, None, None, None], [None, None, None, None]),
    (0x000fc2000800828b00015504ff007988, 257, "B", [Some("STS.S8 [RZ.X8+UR139+0x155], R4"), Some("STS.S8 [RZ.X8+UR139+0x155], R4"), Some("STS.S8 [RZ.X8+UR139+0x155], R4"), Some("STS.S8 [RZ.X8+UR139+0x155], R4")], [Some("STS_ARURI_R|S8"), Some("STS_ARURI_R|S8"), Some("STS_ARURI_R|S8"), Some("STS_ARURI_R|S8")]), // healed 443 (S1/S2 width map; vendor re-probe x4 work/bug443/arb443ride83_law.json + ride257.bin; class A->B),
    (0x000fc20008002484800000040a007988, 274, "X", [Some("STS.U16 [R10+UR132+-0x800000], R4"), Some("STS.U16 [R10+UR132+-0x800000], R4"), Some("STS.U16 [R10+UR132+-0x800000], R4"), Some("STS.U16 [R10+UR132+-0x800000], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc2000800144e800001040a00e988, 303, "B", [Some("@!P6 STS.U16 [R10+UR78+-0x7fffff], R4"), Some("@!P6 STS.U16 [R10+UR78+-0x7fffff], R4"), Some("@!P6 STS.U16 [R10+UR78+-0x7fffff], R4"), Some("@!P6 STS.U16 [R10+UR78+-0x7fffff], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc2000800847fffffff040a007988, 307, "B", [Some("STS.U16 [R10.X8+UR127+-0x1], R4"), Some("STS.U16 [R10.X8+UR127+-0x1], R4"), Some("STS.U16 [R10.X8+UR127+-0x1], R4"), Some("STS.U16 [R10.X8+UR127+-0x1], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc2000800027e00015504ff007988, 309, "B", [Some("STS.S8 [UR126+0x155], R4"), Some("STS.S8 [UR126+0x155], R4"), Some("STS.S8 [UR126+0x155], R4"), Some("STS.S8 [UR126+0x155], R4")], [Some("STS_AURI_R|S8"), Some("STS_AURI_R|S8"), Some("STS_AURI_R|S8"), Some("STS_AURI_R|S8")]), // healed 443 (S1/S2 width map; vendor re-probe x4 work/bug443/arb443ride83_law.json + ride309.bin; class D->B),
    (0x000fc20008010461ffffff040a007988, 333, "X", [Some("STS.U16 [R10+UR97+-0x1], R4"), Some("STS.U16 [R10+UR97+-0x1], R4"), Some("STS.U16 [R10+UR97+-0x1], R4"), Some("STS.U16 [R10+UR97+-0x1], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc2000000022400000104f8000844, 348, "D-stsm", [Some("@P0 STSM.16.M88.4 [R248+0x1], R4"), Some("@P0 STSM.16.M88.4 [R248+0x1], R4"), Some("@P0 STSM.16.M88.4 [R248+0x1], R4"), Some("@P0 STSM.16.M88.4 [R248+0x1], R4")], [Some("STSM_ARI_R|16,4,M88"), Some("STSM_ARI_R|16,4,M88"), Some("STSM_ARI_R|16,4,M88"), Some("STSM_ARI_R|16,4,M88")]),
    (0x000fc2000800444b800000040a007988, 350, "X", [Some("STS.U16 [R10.X4+UR75+-0x800000], R4"), Some("STS.U16 [R10.X4+UR75+-0x800000], R4"), Some("STS.U16 [R10.X4+UR75+-0x800000], R4"), Some("STS.U16 [R10.X4+UR75+-0x800000], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc20000000b2a800000040a007988, 362, "C", [None, None, None, None], [None, None, None, None]),
    (0x000fc200080104ff7ffffe040a007988, 376, "X", [Some("STS.U16 [R10+URZ+0x7ffffe], R4"), Some("STS.U16 [R10+URZ+0x7ffffe], R4"), Some("STS.U16 [R10+URZ+0x7ffffe], R4"), Some("STS.U16 [R10+URZ+0x7ffffe], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc20008002fcb80000104ff007988, 389, "A", [None, None, None, None], [None, None, None, None]),
    (0x000fc200000000047ffffe046c000844, 426, "D-stsm", [Some("@P0 STSM.16.M88 [R108+0x7ffffe], R4"), Some("@P0 STSM.16.M88 [R108+0x7ffffe], R4"), Some("@P0 STSM.16.M88 [R108+0x7ffffe], R4"), Some("@P0 STSM.16.M88 [R108+0x7ffffe], R4")], [Some("STSM_ARI_R|16,M88"), Some("STSM_ARI_R|16,M88"), Some("STSM_ARI_R|16,M88"), Some("STSM_ARI_R|16,M88")]),
    (0x000fc200080004547fffff040a007988, 530, "B", [Some("STS.U16 [R10+UR84+0x7fffff], R4"), Some("STS.U16 [R10+UR84+0x7fffff], R4"), Some("STS.U16 [R10+UR84+0x7fffff], R4"), Some("STS.U16 [R10+UR84+0x7fffff], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc2000800039580000004ff007988, 542, "B", [Some("STS.S8 [UR149+-0x800000], R4"), Some("STS.S8 [UR149+-0x800000], R4"), Some("STS.S8 [UR149+-0x800000], R4"), Some("STS.S8 [UR149+-0x800000], R4")], [Some("STS_AURI_R|S8"), Some("STS_AURI_R|S8"), Some("STS_AURI_R|S8"), Some("STS_AURI_R|S8")]), // healed 443 (S1/S2 width map; vendor re-probe x4 work/bug443/arb443ride83_law.json + ride542.bin; class D->B),
    (0x000fc2000800033500000004ff009988, 568, "B", [Some("@!P1 STS.S8 [UR53], R4"), Some("@!P1 STS.S8 [UR53], R4"), Some("@!P1 STS.S8 [UR53], R4"), Some("@!P1 STS.S8 [UR53], R4")], [Some("STS_AURI_R|S8"), Some("STS_AURI_R|S8"), Some("STS_AURI_R|S8"), Some("STS_AURI_R|S8")]), // healed 443 (S1/S2 width map; vendor re-probe x4 work/bug443/arb443ride83_law.json + ride568.bin; class D->B),
    (0x000fc2000800456c7ffffe040a006988, 570, "B", [Some("@P6 STS.U16 [R10.X4+UR108+0x7ffffe], R4"), Some("@P6 STS.U16 [R10.X4+UR108+0x7ffffe], R4"), Some("@P6 STS.U16 [R10.X4+UR108+0x7ffffe], R4"), Some("@P6 STS.U16 [R10.X4+UR108+0x7ffffe], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc20008000424ccc152040a007988, 587, "B", [Some("STS.U16 [R10+UR36+-0x333eae], R4"), Some("STS.U16 [R10+UR36+-0x333eae], R4"), Some("STS.U16 [R10+UR36+-0x333eae], R4"), Some("STS.U16 [R10+UR36+-0x333eae], R4")], [Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16"), Some("STS_ARURI_R|U16")]),
    (0x000fc200880005e0ffffff04ff00e988, 690, "E", [Some("@!P6 STS.U16 [UR224+-0x1], R4"), Some("@!P6 STS.U16 [UR224+-0x1], R4"), Some("@!P6 STS.U16 [UR224+-0x1], R4"), Some("@!P6 STS.U16 [UR224+-0x1], R4")], [Some("STS_AURI_R|U16"), Some("STS_AURI_R|U16"), Some("STS_AURI_R|U16"), Some("STS_AURI_R|U16")]),
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

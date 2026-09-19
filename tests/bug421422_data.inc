// MACHINE-BUILT by work/bug427/gen421422_427.py (rc=2 self-checks; no hand hex).
// FLIP (BUG-427 F2-iter236, canonical a5e6d0a): S16 addr-scale + ARI/ARURI-frame S16 closure --
// MINT421 11 -> 16 (healed circles: RZ-scale x3 + ARI-frame x2), REFUSE421 11 -> 6 (same five shed),
// the S16 addr_scale cordon assert LIFTED (421422 pinned refuse when unmeasured; arb427 measured x4).
// Law sections re-proven against the 421422 evidence files and freshly executed live on the f2-236
// tables (work-427 engine); 428 bare-bracket posture re-asserted identical; LDSM lattice (426) intact.
pub const CANON421422: &str = "cc2f62c379c3e190ef373ab9e8f76af0aeef326c" /* ride F2-iter275 (BUG-466 ELL2.256 dARI-era rekanon plain-geo): 67b54f4405b7f6d2d748d8221deb6a9a59cd3c2f canonical, was 23976eb44550254b12f8862ebc088d2c5d49dd72; */ /* ride F2-iter272 (BUG-465 modsub plain E*L2.256 lattice): 23976eb44550254b12f8862ebc088d2c5d49dd72 canonical, was 49681135da169cdd27585a3eea52b61c585fa589; old:  ride F2-iter270 (BUG-464 plain ARURI64 lattice): 49681135da169cdd27585a3eea52b61c585fa589 canonical, was 50780675cd8e43ddd496d5a130752178b7163686; old:  ride F2-iter268 (BUG-432R donor-128E): 50780675cd8e43ddd496d5a130752178b7163686 canonical, was a6e3c9ea9ad9ad95d14687580eec2c8f82646baf = BUG-432 ari-cavity F2-iter267; old:  ride F2-iter267 (BUG-432 ari-cavity): a6e3c9ea9ad9ad95d14687580eec2c8f82646baf canonical, was a64b82bff6706350b82018609016f624188b99a5 = BUG-463 ltc F2-iter266 */ /* ride F2-iter266 (BUG-463 ltc-widths): a64b82bff6706350b82018609016f624188b99a5 canonical, was f58ed1683bded052bcb100a0762c16e7e91248c4 = BUG-461 glyph F2-iter265 */ /* ride F2-iter265 (BUG-461 glyph): f58ed1683bded052bcb100a0762c16e7e91248c4 canonical, was f37655889e6da3ddd25b73a926c21ec3b58fa768 = BUG-462 narrow F2-iter264 */ /* ride F2-iter264 (BUG-462 narrow): f37655889e6da3ddd25b73a926c21ec3b58fa768 canonical, was 700524e698304dcbf1a3884f72f05abff609b8aa = BUG-453 graft F2-iter263 */ /* ride F2-iter263 (BUG-453 graft): 700524e698304dcbf1a3884f72f05abff609b8aa canonical, was 700524e698304dcbf1a3884f72f05abff609b8aa = BUG-452 narrow F2-iter260 */ /* ride F2-iter260 (BUG-452 narrow): 700524e698304dcbf1a3884f72f05abff609b8aa canonical, was 4ee843162216e75d037135b5907c819759471296 = BUG-454 F2-iter258 */ /* ride F2-iter258 (BUG-454 graft): 4ee843162216e75d037135b5907c819759471296 canonical, was 589be874 = BUG-450 F2-iter255 */ /* ride F2-iter255 (BUG-450 graft): 589be874bfcab4513e5f70b43c832d73f1bea3c1 canonical, was 099faa0 = BUG-447 F2-iter252 */; // ride-after flip F2-iter252 (BUG-447 graft): 099faa0 canonical, was e8d1af3 = BUG-443 F2-iter250, 57e7ecd = BUG-442 F2-iter246, ffa3244 = BUG-441 F2-iter245, bb1ba6c = BUG-438 F2-iter244, 54c5b02 = BUG-439 F2-iter243, 3032686 = BUG-423 F2-iter242, 61858fb = BUG-433 F2-iter241, 0a6b178 = BUG-435+434+435b F2-iter240, 1810912 = 435+434 hop, 70eb0fe = BUG-416 F2-iter239, 52cb73c = BUG-425+425b F2-iter238, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424, 13e13b6 = BUG-421+422, 0eddad5 = BUG-420
#[rustfmt::skip]
pub const LAW421_DECODE: &[(u128, &str, [Option<&str>; 4])] = &[
    (0x000000000800800000000004ff10783b, "ldsmenum.e2", [Some("LDSM.16.M816 R16, [UR4]"), Some("LDSM.16.M816 R16, [UR4]"), Some("LDSM.16.M816 R16, [UR4]"), Some("LDSM.16.M816 R16, [UR4]")]),
    (0x000000000800810000000004ff10783b, "ldsmenum.e2.n2", [Some("LDSM.16.M816.2 R16, [UR4]"), Some("LDSM.16.M816.2 R16, [UR4]"), Some("LDSM.16.M816.2 R16, [UR4]"), Some("LDSM.16.M816.2 R16, [UR4]")]),
    (0x000000000800820000000004ff10783b, "ldsmenum.e2.n4", [Some("LDSM.16.M816.4 R16, [UR4]"), Some("LDSM.16.M816.4 R16, [UR4]"), Some("LDSM.16.M816.4 R16, [UR4]"), Some("LDSM.16.M816.4 R16, [UR4]")]),
    (0x000000000800c00000000004ff10783b, "ldsmenum.e3", [Some("LDSM.16.M832 R16, [UR4]"), Some("LDSM.16.M832 R16, [UR4]"), Some("LDSM.16.M832 R16, [UR4]"), Some("LDSM.16.M832 R16, [UR4]")]),
    (0x000000000801000000000004ff10783b, "ldsmenum.e4", [Some("LDSM.16.MT1616 R16, [UR4]"), Some("LDSM.16.MT1616 R16, [UR4]"), Some("LDSM.16.MT1616 R16, [UR4]"), Some("LDSM.16.MT1616 R16, [UR4]")]),
    (0x000000000801010000000004ff10783b, "ldsmenum.e4.n2", [Some("LDSM.16.MT1616.2 R16, [UR4]"), Some("LDSM.16.MT1616.2 R16, [UR4]"), Some("LDSM.16.MT1616.2 R16, [UR4]"), Some("LDSM.16.MT1616.2 R16, [UR4]")]),
    (0x000000000801020000000004ff10783b, "ldsmenum.e4.n4", [Some("LDSM.16.MT1616.4 R16, [UR4]"), Some("LDSM.16.MT1616.4 R16, [UR4]"), Some("LDSM.16.MT1616.4 R16, [UR4]"), Some("LDSM.16.MT1616.4 R16, [UR4]")]),
    (0x000000000800800000000004ff10783b, "single.ldsm.b79", [Some("LDSM.16.M816 R16, [UR4]"), Some("LDSM.16.M816 R16, [UR4]"), Some("LDSM.16.M816 R16, [UR4]"), Some("LDSM.16.M816 R16, [UR4]")]),
    (0x000000000801000000000004ff10783b, "single.ldsm.b80", [Some("LDSM.16.MT1616 R16, [UR4]"), Some("LDSM.16.MT1616 R16, [UR4]"), Some("LDSM.16.MT1616 R16, [UR4]"), Some("LDSM.16.MT1616 R16, [UR4]")]),
    (0x000000000800000000000004ff10783b, "ldsmenum.e0", [Some("LDSM.16.M88 R16, [UR4]"), Some("LDSM.16.M88 R16, [UR4]"), Some("LDSM.16.M88 R16, [UR4]"), Some("LDSM.16.M88 R16, [UR4]")]),
    (0x000000000800400000000004ff10783b, "ldsmenum.e1", [Some("LDSM.16.MT88 R16, [UR4]"), Some("LDSM.16.MT88 R16, [UR4]"), Some("LDSM.16.MT88 R16, [UR4]"), Some("LDSM.16.MT88 R16, [UR4]")]),
    (0x000000000800410000000004ff10783b, "ldsmenum.e1.n2", [Some("LDSM.16.MT88.2 R16, [UR4]"), Some("LDSM.16.MT88.2 R16, [UR4]"), Some("LDSM.16.MT88.2 R16, [UR4]"), Some("LDSM.16.MT88.2 R16, [UR4]")]),
    (0x000000000800420000000004ff10783b, "ldsmenum.e1.n4", [Some("LDSM.16.MT88.4 R16, [UR4]"), Some("LDSM.16.MT88.4 R16, [UR4]"), Some("LDSM.16.MT88.4 R16, [UR4]"), Some("LDSM.16.MT88.4 R16, [UR4]")]),
];
pub const LAW422_DECODE: &[(u128, &str, [Option<&str>; 4])] = &[
    (0x000fe2000800060000000004ff5d7984, "single.s8.b74", [Some("LDS.S16 R93, [UR4]"), Some("LDS.S16 R93, [UR4]"), Some("LDS.S16 R93, [UR4]"), Some("LDS.S16 R93, [UR4]")]),
    (0x000fe2000800060000000004ff5d7984, "s8width.w3", [Some("LDS.S16 R93, [UR4]"), Some("LDS.S16 R93, [UR4]"), Some("LDS.S16 R93, [UR4]"), Some("LDS.S16 R93, [UR4]")]),
    (0x000fe2000800020000000004ff5d7984, "base.s8.z0", [Some("LDS.S8 R93, [UR4]"), Some("LDS.S8 R93, [UR4]"), Some("LDS.S8 R93, [UR4]"), Some("LDS.S8 R93, [UR4]")]),
    (0x000fe2000800000000000004ff5d7984, "single.s8.b73", [Some("LDS.U8 R93, [UR4]"), Some("LDS.U8 R93, [UR4]"), Some("LDS.U8 R93, [UR4]"), Some("LDS.U8 R93, [UR4]")]),
    (0x000fe20008000a0000000004ff5d7984, "single.s8.b75", [Some("LDS.64 R93, [UR4]"), Some("LDS.64 R93, [UR4]"), Some("LDS.64 R93, [UR4]"), Some("LDS.64 R93, [UR4]")]),
];
pub const HOLE421: &[(u128, &str)] = &[
    (0x000000000800430000000004ff10783b, "ldsmenum.e1.n6"),
    (0x000000000800830000000004ff10783b, "ldsmenum.e2.n6"),
    (0x000000000801030000000004ff10783b, "ldsmenum.e4.n6"),
    (0x000000000801400000000004ff10783b, "ldsmenum.e5"),
    (0x000000000801800000000004ff10783b, "ldsmenum.e6"),
    (0x000000000801c00000000004ff10783b, "ldsmenum.e7"),
    (0x000000000800030000000004ff10783b, "ldsmcombo.b72b73"),
    (0x000000000800430000000004ff10783b, "ldsmcombo.b72b73b78"),
];
pub const MINT421: &[(&str, u128, &str)] = &[
    ("LDSM.16.M816 R16, [UR4] ;", 0x000fc2000800800000000004ff10783b, "LDSM.16.M816 R16, [UR4]"),
    ("LDSM.16.M816.2 R16, [UR4] ;", 0x000fc2000800810000000004ff10783b, "LDSM.16.M816.2 R16, [UR4]"),
    ("LDSM.16.M816.4 R16, [UR4] ;", 0x000fc2000800820000000004ff10783b, "LDSM.16.M816.4 R16, [UR4]"),
    ("LDSM.16.M832 R16, [UR4] ;", 0x000fc2000800c00000000004ff10783b, "LDSM.16.M832 R16, [UR4]"),
    ("LDSM.16.MT1616 R16, [UR4] ;", 0x000fc2000801000000000004ff10783b, "LDSM.16.MT1616 R16, [UR4]"),
    ("LDSM.16.MT1616.2 R16, [UR4] ;", 0x000fc2000801010000000004ff10783b, "LDSM.16.MT1616.2 R16, [UR4]"),
    ("LDSM.16.MT1616.4 R16, [UR4] ;", 0x000fc2000801020000000004ff10783b, "LDSM.16.MT1616.4 R16, [UR4]"),
    ("LDS.S16 R93, [UR4] ;", 0x000fc2000800060000000004ff5d7984, "LDS.S16 R93, [UR4]"),
    ("LDS.S16 R93, [UR4+0x1] ;", 0x000fc2000800060000000104ff5d7984, "LDS.S16 R93, [UR4+0x1]"),
    ("LDSM.16.M832.2 R16, [UR4] ;", 0x000fc2000800c10000000004ff10783b, "LDSM.16.M832.2 R16, [UR4]"),
    ("LDSM.16.M832.4 R16, [UR4] ;", 0x000fc2000800c20000000004ff10783b, "LDSM.16.M832.4 R16, [UR4]"),
    ("LDS.S16 R93, [RZ.X4+UR4] ;", 0x000fc2000800460000000004ff5d7984, "LDS.S16 R93, [RZ.X4+UR4]"),
    ("LDS.S16 R93, [RZ.X8+UR4] ;", 0x000fc2000800860000000004ff5d7984, "LDS.S16 R93, [RZ.X8+UR4]"),
    ("LDS.S16 R93, [RZ.X16+UR4] ;", 0x000fc2000800c60000000004ff5d7984, "LDS.S16 R93, [RZ.X16+UR4]"),
    ("LDS.S16 R93, [R10.X4+0x155] ;", 0x000fc20000004600000155000a5d7984, "LDS.S16 R93, [R10.X4+0x155]"),
    ("LDS.S16 R93, [R10+0x155] ;", 0x000fc20000000600000155000a5d7984, "LDS.S16 R93, [R10+0x155]"),
];
pub const REFUSE421: &[&str] = &[
    "LDSM.16.INVALID5 R16, [UR4] ;",
    "LDSM.16.INVALID6 R16, [UR4] ;",
    "LDSM.16.INVALID7 R16, [UR4] ;",
    "LDSM.16.M88.INVALID3 R16, [UR4] ;",
    "LDSM.16.M816.INVALID3 R16, [UR4] ;",
    "LDSM.16.MT1616.INVALID3 R16, [UR4] ;",
];
pub const POSTURE428_WORD: u128 = 0x000fc2000800060000000004ff5d7984;
pub const CENSUS_SM100A_ARURI: &[&str] = &["16,2,M816", "16,2,M832", "16,2,M88", "16,2,MT1616", "16,2,MT88", "16,4,M816", "16,4,M832", "16,4,M88", "16,4,MT1616", "16,4,MT88", "16,M816", "16,M832", "16,M88", "16,MT1616", "16,MT88"];
pub const CENSUS_SM100A_AURI: &[&str] = &["16,2,M816", "16,2,M832", "16,2,M88", "16,2,MT1616", "16,2,MT88", "16,4,M816", "16,4,M832", "16,4,M88", "16,4,MT1616", "16,4,MT88", "16,M816", "16,M832", "16,M88", "16,MT1616", "16,MT88"];
pub const CENSUS_SM100A_LDS_AURI: &[&str] = &["", "128", "64", "S16", "S8", "U16", "U8"];
pub const CENSUS_SM103A_ARURI: &[&str] = &["16,2,M816", "16,2,M832", "16,2,M88", "16,2,MT1616", "16,2,MT88", "16,4,M816", "16,4,M832", "16,4,M88", "16,4,MT1616", "16,4,MT88", "16,M816", "16,M832", "16,M88", "16,MT1616", "16,MT88"];
pub const CENSUS_SM103A_AURI: &[&str] = &["16,2,M816", "16,2,M832", "16,2,M88", "16,2,MT1616", "16,2,MT88", "16,4,M816", "16,4,M832", "16,4,M88", "16,4,MT1616", "16,4,MT88", "16,M816", "16,M832", "16,M88", "16,MT1616", "16,MT88"];
pub const CENSUS_SM103A_LDS_AURI: &[&str] = &["", "128", "64", "S16", "S8", "U16", "U8"];
pub const CENSUS_SM120_ARURI: &[&str] = &["16,2,M816", "16,2,M832", "16,2,M88", "16,2,MT1616", "16,2,MT88", "16,4,M816", "16,4,M832", "16,4,M88", "16,4,MT1616", "16,4,MT88", "16,M816", "16,M832", "16,M88", "16,MT1616", "16,MT88"];
pub const CENSUS_SM120_AURI: &[&str] = &["16,2,M816", "16,2,M832", "16,2,M88", "16,2,MT1616", "16,2,MT88", "16,4,M816", "16,4,M832", "16,4,M88", "16,4,MT1616", "16,4,MT88", "16,M816", "16,M832", "16,M88", "16,MT1616", "16,MT88"];
pub const CENSUS_SM120_LDS_AURI: &[&str] = &["", "128", "64", "S16", "S8", "U16", "U8"];
pub const CENSUS_SM121A_ARURI: &[&str] = &["16,2,M816", "16,2,M832", "16,2,M88", "16,2,MT1616", "16,2,MT88", "16,4,M816", "16,4,M832", "16,4,M88", "16,4,MT1616", "16,4,MT88", "16,M816", "16,M832", "16,M88", "16,MT1616", "16,MT88"];
pub const CENSUS_SM121A_AURI: &[&str] = &["16,2,M816", "16,2,M832", "16,2,M88", "16,2,MT1616", "16,2,MT88", "16,4,M816", "16,4,M832", "16,4,M88", "16,4,MT1616", "16,4,MT88", "16,M816", "16,M832", "16,M88", "16,MT1616", "16,MT88"];
pub const CENSUS_SM121A_LDS_AURI: &[&str] = &["", "128", "64", "S16", "S8", "U16", "U8"];

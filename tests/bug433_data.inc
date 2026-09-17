// MACHINE-BUILT by work/bug433/gen433pins.py (rc=2 self-checks; no hand hex).
// BUG-433 witnesses: arb433 (69 probes) + arb433b (20), nvdisasm 13.3.73 raw -b
// x4 AGREE EVERY/DIVERGENT=0 + measure433_pre (publish db252b1e neg-ctl) +
// measure433_post (work .so) + canonical 5956274 = BUG-433 graft F2-iter241.
pub const CANON433: &str = "bd2e25464208f9be6abc1e3c7475ca34914ad095" /* ride F2-iter275 (BUG-466 ELL2.256 dARI-era rekanon plain-geo): 67b54f4405b7f6d2d748d8221deb6a9a59cd3c2f canonical, was 23976eb44550254b12f8862ebc088d2c5d49dd72; */ /* ride F2-iter272 (BUG-465 modsub plain E*L2.256 lattice): 23976eb44550254b12f8862ebc088d2c5d49dd72 canonical, was 49681135da169cdd27585a3eea52b61c585fa589; old:  ride F2-iter270 (BUG-464 plain ARURI64 lattice): 49681135da169cdd27585a3eea52b61c585fa589 canonical, was 50780675cd8e43ddd496d5a130752178b7163686; old:  ride F2-iter268 (BUG-432R donor-128E): 50780675cd8e43ddd496d5a130752178b7163686 canonical, was a6e3c9ea9ad9ad95d14687580eec2c8f82646baf = BUG-432 ari-cavity F2-iter267; old:  ride F2-iter267 (BUG-432 ari-cavity): a6e3c9ea9ad9ad95d14687580eec2c8f82646baf canonical, was a64b82bff6706350b82018609016f624188b99a5 = BUG-463 ltc F2-iter266 */ /* ride F2-iter266 (BUG-463 ltc-widths): a64b82bff6706350b82018609016f624188b99a5 canonical, was f58ed1683bded052bcb100a0762c16e7e91248c4 = BUG-461 glyph F2-iter265 */ /* ride F2-iter265 (BUG-461 glyph): f58ed1683bded052bcb100a0762c16e7e91248c4 canonical, was f37655889e6da3ddd25b73a926c21ec3b58fa768 = BUG-462 narrow F2-iter264 */ /* ride F2-iter264 (BUG-462 narrow): f37655889e6da3ddd25b73a926c21ec3b58fa768 canonical, was 700524e698304dcbf1a3884f72f05abff609b8aa = BUG-453 graft F2-iter263 */ /* ride F2-iter263 (BUG-453 graft): 700524e698304dcbf1a3884f72f05abff609b8aa canonical, was 700524e698304dcbf1a3884f72f05abff609b8aa = BUG-452 narrow F2-iter260 */ /* ride F2-iter260 (BUG-452 narrow): 700524e698304dcbf1a3884f72f05abff609b8aa canonical, was 4ee843162216e75d037135b5907c819759471296 = BUG-454 F2-iter258 */ /* ride F2-iter258 (BUG-454 graft): 4ee843162216e75d037135b5907c819759471296 canonical, was 589be874 = BUG-450 F2-iter255 */ /* ride F2-iter255 (BUG-450 graft): 589be874bfcab4513e5f70b43c832d73f1bea3c1 canonical, was 099faa0 = BUG-447 F2-iter252 */; // BUG-447 graft F2-iter252; rides e8d1af3 = BUG-443 F2-iter250, 57e7ecd = BUG-442 F2-iter246, ffa3244 = BUG-441 F2-iter245, bb1ba6c = BUG-438 F2-iter244, 54c5b02 = BUG-439 F2-iter243, 3032686 = BUG-423 F2-iter242, 61858fb = BUG-433 F2-iter241; older: 0a6b178 = BUG-435+434+435b, 1810912 hop, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b
#[rustfmt::skip]
pub const LAW433_STSM: &[(u128, &str)] = &[
    (0x000fc2000000000000000104f8000844, "@P0 STSM.16.M88 [R248+0x1], R4"), // B.e0 x4
    (0x000fc2000000010000000104f8000844, "@P0 STSM.16.M88.2 [R248+0x1], R4"), // B.e0.n2 x4
    (0x000fc2000000020000000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // B.e0.n4 x4
    (0x000fc20000000000000155100a007844, "STSM.16.M88 [R10+0x155], R16"), // Bv.e0 x4
    (0x000fc20000000100000155100a007844, "STSM.16.M88.2 [R10+0x155], R16"), // Bv.e0.n2 x4
    (0x000fc20000000200000155100a007844, "STSM.16.M88.4 [R10+0x155], R16"), // Bv.e0.n4 x4
    (0x000fc2000000000000000104f8000844, "@P0 STSM.16.M88 [R248+0x1], R4"), // C.e0 x4
    (0x000fc2000000020000000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // C.e0.n4 x4
    (0x000fc2000000000000000004f8000844, "@P0 STSM.16.M88 [R248], R4"), // D.i000000 x4
    (0x000fc2000000020000000004f8000844, "@P0 STSM.16.M88.4 [R248], R4"), // D.i000000.n4 x4
    (0x000fc2000000000000000104f8000844, "@P0 STSM.16.M88 [R248+0x1], R4"), // D.i000001 x4
    (0x000fc2000000020000000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // D.i000001.n4 x4
    (0x000fc2000000000001000004f8000844, "@P0 STSM.16.M88 [R248+0x10000], R4"), // D.i010000 x4
    (0x000fc2000000020001000004f8000844, "@P0 STSM.16.M88.4 [R248+0x10000], R4"), // D.i010000.n4 x4
    (0x000fc200000000007ffffe04f8000844, "@P0 STSM.16.M88 [R248+0x7ffffe], R4"), // D.i7ffffe x4
    (0x000fc200000002007ffffe04f8000844, "@P0 STSM.16.M88.4 [R248+0x7ffffe], R4"), // D.i7ffffe.n4 x4
    (0x000fc200000000007fffff04f8000844, "@P0 STSM.16.M88 [R248+0x7fffff], R4"), // D.i7fffff x4
    (0x000fc200000002007fffff04f8000844, "@P0 STSM.16.M88.4 [R248+0x7fffff], R4"), // D.i7fffff.n4 x4
    (0x000fc2000000000080000004f8000844, "@P0 STSM.16.M88 [R248+-0x800000], R4"), // D.i800000 x4
    (0x000fc2000000020080000004f8000844, "@P0 STSM.16.M88.4 [R248+-0x800000], R4"), // D.i800000.n4 x4
    (0x000fc20000000000ffffff04f8000844, "@P0 STSM.16.M88 [R248+-0x1], R4"), // D.iffffff x4
    (0x000fc20000000200ffffff04f8000844, "@P0 STSM.16.M88.4 [R248+-0x1], R4"), // D.iffffff.n4 x4
    (0x000fc2000000000000001004ff000844, "@P0 STSM.16.M88 [0x10], R4"), // E.rbRZ x4
    (0x000fc2000000020000001004ff000844, "@P0 STSM.16.M88.4 [0x10], R4"), // E.rbRZ.n4 x4
    (0x000fc2000000000000000100f8000844, "@P0 STSM.16.M88 [R248+0x1], R0"), // E.src0 x4
    (0x000fc20000000000000001fff8000844, "@P0 STSM.16.M88 [R248+0x1], RZ"), // E.src255 x4
    (0x000fc2000000000000000104f8001844, "@P1 STSM.16.M88 [R248+0x1], R4"), // F.g1 x4
    (0x000fc2000000000000000104f800d844, "@!P5 STSM.16.M88 [R248+0x1], R4"), // F.g13 x4
    (0x000fc2000000000000000104f800e844, "@!P6 STSM.16.M88 [R248+0x1], R4"), // F.g14 x4
    (0x000fc2000000000000000104f800f844, "@!PT STSM.16.M88 [R248+0x1], R4"), // F.g15 x4
    (0x000fc2000000000000000104f8002844, "@P2 STSM.16.M88 [R248+0x1], R4"), // F.g2 x4
    (0x000fc2000000000000000104f8006844, "@P6 STSM.16.M88 [R248+0x1], R4"), // F.g6 x4
    (0x000fc2000000022400000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // wit348 x4
    (0x000fc200000000047ffffe046c000844, "@P0 STSM.16.M88 [R108+0x7ffffe], R4"), // wit426 x4
    (0x0001c0000000020000000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // G.era0001c000 x4
    (0x000fc2000000020000000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // G.era000fc200 x4
    (0x000fca000000020000000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // G.flip107 x4
    (0x000dc2000000020000000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // G.flip113 x4
    (0x001fc2000000020000000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // G.flip116 x4
    (0x008fc2000000020000000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // G.flip119 x4
    (0x040fc2000000020000000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // G.flip122 x4
    (0x200fc2000000020000000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // G.flip125 x4
];
#[rustfmt::skip]
pub const LAW433_U16: &[(u128, &str)] = &[
    (0x000fc200880005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // wit690 x4
    (0x000fc200880005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // K000 x4
    (0x000fc200080005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // K001 x4
    (0x000fe200880005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // K010 x4
    (0x000fe200080005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // K011 x4
    (0x0007c200880005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // K100 x4
    (0x0007c200080005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // K101 x4
    (0x0007e200880005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // K110 x4
    (0x0007e200080005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // K111 x4
];
#[rustfmt::skip]
pub const MINT433: &[(u128, &str)] = &[
    (0x000fc2000000020000000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // B.e0.n4 x4 mint+circle
    (0x000fc2000000022400000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // wit348 x4 mint+circle
    (0x000fc200000000047ffffe046c000844, "@P0 STSM.16.M88 [R108+0x7ffffe], R4"), // wit426 x4 mint+circle
    (0x000fc2000000010000000104f8000844, "@P0 STSM.16.M88.2 [R248+0x1], R4"), // B.e0.n2 x4 mint+circle
    (0x000fc2000000000000000104f8000844, "@P0 STSM.16.M88 [R248+0x1], R4"), // B.e0 x4 mint+circle
    (0x000fc20000000000000155100a007844, "STSM.16.M88 [R10+0x155], R16"), // Bv.e0 x4 mint+circle
    (0x000fc2000000000000001004ff000844, "@P0 STSM.16.M88 [0x10], R4"), // E.rbRZ x4 mint+circle
    (0x000fc2000000000000000104f800e844, "@!P6 STSM.16.M88 [R248+0x1], R4"), // F.g14 x4 mint+circle
    (0x000fc2000000020000000104f8000844, "@P0 STSM.16.M88.4 [R248+0x1], R4"), // C.e0.n4 x4 mint+circle
    (0x000fc200000000007fffff04f8000844, "@P0 STSM.16.M88 [R248+0x7fffff], R4"), // D.i7fffff x4 mint+circle
];
#[rustfmt::skip]
pub const REFUSE433: &[&str] = &[
    "@P0 STSM.16.M88.INVALID3 [R248+0x1], R4",
    "STSM.16.M88.INVALID3 [R10+0x155], R16",
    "@P0 STSM.16.INVALID3 [R248+0x1], R4",
    "@P0 STSM.16.INVALID3.4 [R248+0x1], R4",
    "@P0 STSM.16.MT88.INVALID3 [R248+0x1], R4",
];
#[rustfmt::skip]
pub const CIRCLE433: &[(u128, &str)] = &[
    (0x000fc200880005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // wit690 x4 text-circle (word contacts/era non-mintable)
    (0x000fc200880005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // K000 x4 text-circle (word contacts/era non-mintable)
    (0x000fe200880005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // K010 x4 text-circle (word contacts/era non-mintable)
    (0x0007c200880005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // K100 x4 text-circle (word contacts/era non-mintable)
    (0x0007e200080005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // K111 x4 text-circle (word contacts/era non-mintable)
    (0x000fc200080005e0ffffff04ff00e988, "@!P6 STS.U16 [UR224+-0x1], R4"), // S.clr95 x4 text-circle (word contacts/era non-mintable)
];
#[rustfmt::skip]
pub const POSTURE433: &[(u128, &str, &str)] = &[
    (0x000fc20088000fe0ffffff04ff00e988, "W.inv7.witbits.sm100a", "HOLE"), // W-family 438-kand standing
    (0x000fc20088000fe0ffffff04ff00e988, "W.inv7.witbits.sm103a", "HOLE"), // W-family 438-kand standing
    (0x000fc20088000fe0ffffff04ff00e988, "W.inv7.witbits.sm120", "HOLE"), // W-family 438-kand standing
    (0x000fc20088000fe0ffffff04ff00e988, "W.inv7.witbits.sm121a", "HOLE"), // W-family 438-kand standing
    (0x000fc200880009e0ffffff04ff00e988, "W.plain.witbits.sm100a", "@!P6 STS [UR224+-0x1], R4"), // heal-attribution: BUG-438 bb1ba6c (flip438.py 438heal; was standing-HOLE) // W-family 438-kand standing
    (0x000fc200880009e0ffffff04ff00e988, "W.plain.witbits.sm103a", "@!P6 STS [UR224+-0x1], R4"), // heal-attribution: BUG-438 bb1ba6c (flip438.py 438heal; was standing-HOLE) // W-family 438-kand standing
    (0x000fc200880009e0ffffff04ff00e988, "W.plain.witbits.sm120", "@!P6 STS [UR224+-0x1], R4"), // heal-attribution: BUG-438 bb1ba6c (flip438.py 438heal; was standing-HOLE) // W-family 438-kand standing
    (0x000fc200880009e0ffffff04ff00e988, "W.plain.witbits.sm121a", "@!P6 STS [UR224+-0x1], R4"), // W-family 438-kand standing
    (0x000fc200880007e0ffffff04ff00e988, "W.s16.witbits.sm100a", "@!P6 STS.S16 [UR224+-0x1], R4"), // healed 443 (S1/S2; prev note: 438-kand standing), // W-family 438-kand standing
    (0x000fc200880007e0ffffff04ff00e988, "W.s16.witbits.sm103a", "@!P6 STS.S16 [UR224+-0x1], R4"), // healed 443 (S1/S2; prev note: 438-kand standing), // W-family 438-kand standing
    (0x000fc200880007e0ffffff04ff00e988, "W.s16.witbits.sm120", "@!P6 STS.S16 [UR224+-0x1], R4"), // healed 443 (S1/S2; prev note: 438-kand standing), // W-family 438-kand standing
    (0x000fc200880007e0ffffff04ff00e988, "W.s16.witbits.sm121a", "@!P6 STS.S16 [UR224+-0x1], R4"), // healed 443 (S1/S2; prev note: 438-kand standing), // W-family 438-kand standing
    (0x000fc200880001e0ffffff04ff00e988, "W.u8.witbits.sm100a", "@!P6 STS.U8 [UR224+-0x1], R4"), // heal-attribution: BUG-438 bb1ba6c (flip438.py 438heal; was standing-HOLE) // W-family 438-kand standing
    (0x000fc200880001e0ffffff04ff00e988, "W.u8.witbits.sm103a", "@!P6 STS.U8 [UR224+-0x1], R4"), // heal-attribution: BUG-438 bb1ba6c (flip438.py 438heal; was standing-HOLE) // W-family 438-kand standing
    (0x000fc200880001e0ffffff04ff00e988, "W.u8.witbits.sm120", "@!P6 STS.U8 [UR224+-0x1], R4"), // heal-attribution: BUG-438 bb1ba6c (flip438.py 438heal; was standing-HOLE) // W-family 438-kand standing
    (0x000fc200880001e0ffffff04ff00e988, "W.u8.witbits.sm121a", "@!P6 STS.U8 [UR224+-0x1], R4"), // W-family 438-kand standing
    (0x000fc20088000de0ffffff04ff00e988, "W.w128.witbits.sm100a", "@!P6 STS.128 [UR224+-0x1], R4"), // heal-attribution: BUG-438 bb1ba6c (flip438.py 438heal; was standing-HOLE) // W-family 438-kand standing
    (0x000fc20088000de0ffffff04ff00e988, "W.w128.witbits.sm103a", "@!P6 STS.128 [UR224+-0x1], R4"), // heal-attribution: BUG-438 bb1ba6c (flip438.py 438heal; was standing-HOLE) // W-family 438-kand standing
    (0x000fc20088000de0ffffff04ff00e988, "W.w128.witbits.sm120", "@!P6 STS.128 [UR224+-0x1], R4"), // heal-attribution: BUG-438 bb1ba6c (flip438.py 438heal; was standing-HOLE) // W-family 438-kand standing
    (0x000fc20088000de0ffffff04ff00e988, "W.w128.witbits.sm121a", "@!P6 STS.128 [UR224+-0x1], R4"), // W-family 438-kand standing
    (0x000fc20088000be0ffffff04ff00e988, "W.w64.witbits.sm100a", "@!P6 STS.64 [UR224+-0x1], R4"), // heal-attribution: BUG-438 bb1ba6c (flip438.py 438heal; was standing-HOLE) // W-family 438-kand standing
    (0x000fc20088000be0ffffff04ff00e988, "W.w64.witbits.sm103a", "@!P6 STS.64 [UR224+-0x1], R4"), // heal-attribution: BUG-438 bb1ba6c (flip438.py 438heal; was standing-HOLE) // W-family 438-kand standing
    (0x000fc20088000be0ffffff04ff00e988, "W.w64.witbits.sm120", "@!P6 STS.64 [UR224+-0x1], R4"), // heal-attribution: BUG-438 bb1ba6c (flip438.py 438heal; was standing-HOLE) // W-family 438-kand standing
    (0x000fc20088000be0ffffff04ff00e988, "W.w64.witbits.sm121a", "@!P6 STS.64 [UR224+-0x1], R4"), // W-family 438-kand standing
    (0x000fc2000000030000000104f8000844, "B.e0.n6.sm100a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000030000000104f8000844, "B.e0.n6.sm103a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000030000000104f8000844, "B.e0.n6.sm120", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000030000000104f8000844, "B.e0.n6.sm121a", "HOLE"), // INVALID3/construct standing
    (0x000fc20000000300000155100a007844, "Bv.e0.n6.sm100a", "HOLE"), // INVALID3/construct standing
    (0x000fc20000000300000155100a007844, "Bv.e0.n6.sm103a", "HOLE"), // INVALID3/construct standing
    (0x000fc20000000300000155100a007844, "Bv.e0.n6.sm120", "HOLE"), // INVALID3/construct standing
    (0x000fc20000000300000155100a007844, "Bv.e0.n6.sm121a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000c00000000104f8000844, "C.e3.sm100a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000c00000000104f8000844, "C.e3.sm103a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000c00000000104f8000844, "C.e3.sm120", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000c00000000104f8000844, "C.e3.sm121a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000c20000000104f8000844, "C.e3.n4.sm100a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000c20000000104f8000844, "C.e3.n4.sm103a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000c20000000104f8000844, "C.e3.n4.sm120", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000c20000000104f8000844, "C.e3.n4.sm121a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000001c00000000104f8000844, "C.e7.sm100a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000001c00000000104f8000844, "C.e7.sm103a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000001c00000000104f8000844, "C.e7.sm120", "HOLE"), // INVALID3/construct standing
    (0x000fc2000001c00000000104f8000844, "C.e7.sm121a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000001c20000000104f8000844, "C.e7.n4.sm100a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000001c20000000104f8000844, "C.e7.n4.sm103a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000001c20000000104f8000844, "C.e7.n4.sm120", "HOLE"), // INVALID3/construct standing
    (0x000fc2000001c20000000104f8000844, "C.e7.n4.sm121a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000430000000104f8000844, "H.e1.n6.sm100a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000430000000104f8000844, "H.e1.n6.sm103a", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000430000000104f8000844, "H.e1.n6.sm120", "HOLE"), // INVALID3/construct standing
    (0x000fc2000000430000000104f8000844, "H.e1.n6.sm121a", "HOLE"), // INVALID3/construct standing
];
#[rustfmt::skip]
pub const ERATOL433: &[(u128, &str, &str)] = &[
    (0x000000000000020000000104f8000844, "G.era00000000.sm100a", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance
    (0x000000000000020000000104f8000844, "G.era00000000.sm103a", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance
    (0x000000000000020000000104f8000844, "G.era00000000.sm120", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance; sm120 acquires x3 parity with the new key
    (0x000040000000020000000104f8000844, "G.era00004000.sm100a", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance
    (0x000040000000020000000104f8000844, "G.era00004000.sm103a", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance
    (0x000040000000020000000104f8000844, "G.era00004000.sm120", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance; sm120 acquires x3 parity with the new key
    (0x000080000000020000000104f8000844, "G.era00008000.sm100a", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance
    (0x000080000000020000000104f8000844, "G.era00008000.sm103a", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance
    (0x000080000000020000000104f8000844, "G.era00008000.sm120", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance; sm120 acquires x3 parity with the new key
    (0x000100000000020000000104f8000844, "G.era00010000.sm100a", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance
    (0x000100000000020000000104f8000844, "G.era00010000.sm103a", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance
    (0x000100000000020000000104f8000844, "G.era00010000.sm120", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance; sm120 acquires x3 parity with the new key
    (0x000f82000000020000000104f8000844, "G.flip110.sm100a", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance
    (0x000f82000000020000000104f8000844, "G.flip110.sm103a", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance
    (0x000f82000000020000000104f8000844, "G.flip110.sm120", "@P0 STSM.16.M88.4 [R248+0x1], R4"), // era-band cut at [95:0] -- documented tolerance; sm120 acquires x3 parity with the new key
];

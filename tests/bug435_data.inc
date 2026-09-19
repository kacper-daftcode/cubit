// MACHINE-BUILT by work/bug435/gen435pins.py (rc=2 self-checks; no hand hex).
// BUG-435+434 witnesses: arb416/arb416c/arb416d/arb400c/arb435/arb435b law
// (nvdisasm 13.3.73 raw -b x4 AGREE EVERY/DIVERGENT=0) + verify435 post grid
// (x4 legs) + measure435_pre (publish cace1da4 neg-ctl) + canonical e8d1af3 (ride; data-set unchanged, CANON435 const above).
pub const CANON435: &str = "cc2f62c379c3e190ef373ab9e8f76af0aeef326c" /* ride F2-iter275 (BUG-466 ELL2.256 dARI-era rekanon plain-geo): 67b54f4405b7f6d2d748d8221deb6a9a59cd3c2f canonical, was 23976eb44550254b12f8862ebc088d2c5d49dd72; */ /* ride F2-iter272 (BUG-465 modsub plain E*L2.256 lattice): 23976eb44550254b12f8862ebc088d2c5d49dd72 canonical, was 49681135da169cdd27585a3eea52b61c585fa589; old:  ride F2-iter270 (BUG-464 plain ARURI64 lattice): 49681135da169cdd27585a3eea52b61c585fa589 canonical, was 50780675cd8e43ddd496d5a130752178b7163686; old:  ride F2-iter268 (BUG-432R donor-128E): 50780675cd8e43ddd496d5a130752178b7163686 canonical, was a6e3c9ea9ad9ad95d14687580eec2c8f82646baf = BUG-432 ari-cavity F2-iter267; old:  ride F2-iter267 (BUG-432 ari-cavity): a6e3c9ea9ad9ad95d14687580eec2c8f82646baf canonical, was a64b82bff6706350b82018609016f624188b99a5 = BUG-463 ltc F2-iter266 */ /* ride F2-iter266 (BUG-463 ltc-widths): a64b82bff6706350b82018609016f624188b99a5 canonical, was f58ed1683bded052bcb100a0762c16e7e91248c4 = BUG-461 glyph F2-iter265 */ /* ride F2-iter265 (BUG-461 glyph): f58ed1683bded052bcb100a0762c16e7e91248c4 canonical, was f37655889e6da3ddd25b73a926c21ec3b58fa768 = BUG-462 narrow F2-iter264 */ /* ride F2-iter264 (BUG-462 narrow): f37655889e6da3ddd25b73a926c21ec3b58fa768 canonical, was 700524e698304dcbf1a3884f72f05abff609b8aa = BUG-453 graft F2-iter263 */ /* ride F2-iter263 (BUG-453 graft): 700524e698304dcbf1a3884f72f05abff609b8aa canonical, was 700524e698304dcbf1a3884f72f05abff609b8aa = BUG-452 narrow F2-iter260 */ /* ride F2-iter260 (BUG-452 narrow): 700524e698304dcbf1a3884f72f05abff609b8aa canonical, was 4ee843162216e75d037135b5907c819759471296 = BUG-454 F2-iter258 */ /* ride F2-iter258 (BUG-454 graft): 4ee843162216e75d037135b5907c819759471296 canonical, was 589be874 = BUG-450 F2-iter255 */ /* ride F2-iter255 (BUG-450 graft): 589be874bfcab4513e5f70b43c832d73f1bea3c1 canonical, was 099faa0 = BUG-447 F2-iter252 */; // BUG-447 graft F2-iter252; rides e8d1af3 = BUG-443 F2-iter250, 57e7ecd = BUG-442 F2-iter246, ffa3244 = BUG-441 F2-iter245, bb1ba6c = BUG-438 F2-iter244, 54c5b02 = BUG-439 F2-iter243, 3032686 = BUG-423 F2-iter242, 61858fb = BUG-433 F2-iter241; older: 0a6b178 = BUG-435+434+435b (1810912-hop squashed), 70eb0fe = BUG-416
#[rustfmt::skip]
pub const LAW435_LDG: &[(u128, &str)] = &[
    (0x000000000c1e1d200000000c0c217981, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64]"), // B.true.ltc2pv0 x4
    (0x000000000c1e1d210000000c0c217981, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64], P6"), // B.true.ltc2pv1 x4
    (0x000000000c1e1d280000000c0c217981, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64], !PT"), // B.true.ltc2pv8 x4
    (0x000000000c1e1d500000000c0c217981, "LDG.E.LTC64B.128 R33, desc[UR12][R12.64]"), // syn121a.b70pv0ltc1 x4
    (0x000000000c1e1d700000000c0c217981, "LDG.E.LTC256B.128 R33, desc[UR12][R12.64]"), // syn121a.b70pv0ltc3 x4
    (0x000000000c1e1d510000000c0c217981, "LDG.E.LTC64B.128 R33, desc[UR12][R12.64], P6"), // syn121a.b70pv1ltc1 x4
    (0x000000000c1e1d710000000c0c217981, "LDG.E.LTC256B.128 R33, desc[UR12][R12.64], P6"), // syn121a.b70pv1ltc3 x4
    (0x000000000c1e1d580000000c0c217981, "LDG.E.LTC64B.128 R33, desc[UR12][R12.64], !PT"), // syn121a.b70pv8ltc1 x4
    (0x000000000c1e1d780000000c0c217981, "LDG.E.LTC256B.128 R33, desc[UR12][R12.64], !PT"), // syn121a.b70pv8ltc3 x4
    (0x000000000c1e1d900000000c0c217981, "LDG.E.LTC64B.128 R33, desc[UR12][R12.64]"), // syn121a.b71pv0ltc1 x4
    (0x000000000c1e1db00000000c0c217981, "LDG.E.LTC256B.128 R33, desc[UR12][R12.64]"), // syn121a.b71pv0ltc3 x4
    (0x000000000c1e1d910000000c0c217981, "LDG.E.LTC64B.128 R33, desc[UR12][R12.64], P6"), // syn121a.b71pv1ltc1 x4
    (0x000000000c1e1db10000000c0c217981, "LDG.E.LTC256B.128 R33, desc[UR12][R12.64], P6"), // syn121a.b71pv1ltc3 x4
    (0x000000000c1e1d980000000c0c217981, "LDG.E.LTC64B.128 R33, desc[UR12][R12.64], !PT"), // syn121a.b71pv8ltc1 x4
    (0x000000000c1e1db80000000c0c217981, "LDG.E.LTC256B.128 R33, desc[UR12][R12.64], !PT"), // syn121a.b71pv8ltc3 x4
    (0x000000000c1e1dd00000000c0c217981, "LDG.E.LTC64B.128 R33, desc[UR12][R12.64]"), // syn121a.ballpv0ltc1 x4
    (0x000000000c1e1df00000000c0c217981, "LDG.E.LTC256B.128 R33, desc[UR12][R12.64]"), // syn121a.ballpv0ltc3 x4
    (0x000000000c1e1dd10000000c0c217981, "LDG.E.LTC64B.128 R33, desc[UR12][R12.64], P6"), // syn121a.ballpv1ltc1 x4
    (0x000000000c1e1df10000000c0c217981, "LDG.E.LTC256B.128 R33, desc[UR12][R12.64], P6"), // syn121a.ballpv1ltc3 x4
    (0x000000000c1e1dd80000000c0c217981, "LDG.E.LTC64B.128 R33, desc[UR12][R12.64], !PT"), // syn121a.ballpv8ltc1 x4
    (0x000000000c1e1df80000000c0c217981, "LDG.E.LTC256B.128 R33, desc[UR12][R12.64], !PT"), // syn121a.ballpv8ltc3 x4
];
#[rustfmt::skip]
pub const LAW435_LD: &[(u128, &str)] = &[
    (0x000000000c1019000000000c0c210980, "@P0 LD.E R33, desc[UR12][R12.64]"), // P.ltc0pv0 x4
    (0x000000000c1019010000000c0c210980, "@P0 LD.E R33, desc[UR12][R12.64], P6"), // P.ltc0pv1 x4
    (0x000000000c1019080000000c0c210980, "@P0 LD.E R33, desc[UR12][R12.64], !PT"), // P.ltc0pv8 x4
    (0x000000000c1019100000000c0c210980, "@P0 LD.E.LTC64B R33, desc[UR12][R12.64]"), // P.ltc1pv0 x4
    (0x000000000c1019110000000c0c210980, "@P0 LD.E.LTC64B R33, desc[UR12][R12.64], P6"), // P.ltc1pv1 x4
    (0x000000000c1019180000000c0c210980, "@P0 LD.E.LTC64B R33, desc[UR12][R12.64], !PT"), // P.ltc1pv8 x4
    (0x000000000c1019200000000c0c210980, "@P0 LD.E.LTC128B R33, desc[UR12][R12.64]"), // P.ltc2pv0 x4
    (0x000000000c1019210000000c0c210980, "@P0 LD.E.LTC128B R33, desc[UR12][R12.64], P6"), // P.ltc2pv1 x4
    (0x000000000c1019280000000c0c210980, "@P0 LD.E.LTC128B R33, desc[UR12][R12.64], !PT"), // P.ltc2pv8 x4
    (0x000000000c1019300000000c0c210980, "@P0 LD.E.LTC256B R33, desc[UR12][R12.64]"), // P.ltc3pv0 x4
    (0x000000000c1019310000000c0c210980, "@P0 LD.E.LTC256B R33, desc[UR12][R12.64], P6"), // P.ltc3pv1 x4
    (0x000000000c1019380000000c0c210980, "@P0 LD.E.LTC256B R33, desc[UR12][R12.64], !PT"), // P.ltc3pv8 x4
    (0x000000000c1019400000000c0c210980, "@P0 LD.E R33, desc[UR12][R12.64]"), // Q.b70pv0 x4
    (0x000000000c1019410000000c0c210980, "@P0 LD.E R33, desc[UR12][R12.64], P6"), // Q.b70pv1 x4
    (0x000000000c1019800000000c0c210980, "@P0 LD.E R33, desc[UR12][R12.64]"), // Q.b71pv0 x4
    (0x000000000c1019810000000c0c210980, "@P0 LD.E R33, desc[UR12][R12.64], P6"), // Q.b71pv1 x4
    (0x000000000c1019c00000000c0c210980, "@P0 LD.E R33, desc[UR12][R12.64]"), // Q.ballpv0 x4
    (0x000000000c1019c10000000c0c210980, "@P0 LD.E R33, desc[UR12][R12.64], P6"), // Q.ballpv1 x4
];
#[rustfmt::skip]
pub const LAW435_MIGRATE: &[(u128, &str)] = &[
    (0x000000000c1019000000000c0c217980, "LD.E R33, desc[UR12][R12.64]"), // A.junk.b0_0ltc0pv0 x4
    (0x000000000c1019010000000c0c217980, "LD.E R33, desc[UR12][R12.64], P6"), // A.junk.b0_0ltc0pv1 x4
    (0x000000000c1019080000000c0c217980, "LD.E R33, desc[UR12][R12.64], !PT"), // A.junk.b0_0ltc0pv8 x4
    (0x000000000c1019100000000c0c217980, "LD.E.LTC64B R33, desc[UR12][R12.64]"), // A.junk.b0_0ltc1pv0 x4
    (0x000000000c1019110000000c0c217980, "LD.E.LTC64B R33, desc[UR12][R12.64], P6"), // A.junk.b0_0ltc1pv1 x4
    (0x000000000c1019180000000c0c217980, "LD.E.LTC64B R33, desc[UR12][R12.64], !PT"), // A.junk.b0_0ltc1pv8 x4
    (0x000000000c1019200000000c0c217980, "LD.E.LTC128B R33, desc[UR12][R12.64]"), // A.junk.b0_0ltc2pv0 x4
    (0x000000000c1019210000000c0c217980, "LD.E.LTC128B R33, desc[UR12][R12.64], P6"), // A.junk.b0_0ltc2pv1 x4
    (0x000000000c1019280000000c0c217980, "LD.E.LTC128B R33, desc[UR12][R12.64], !PT"), // A.junk.b0_0ltc2pv8 x4
    (0x000000000c1019300000000c0c217980, "LD.E.LTC256B R33, desc[UR12][R12.64]"), // A.junk.b0_0ltc3pv0 x4
    (0x000000000c1019310000000c0c217980, "LD.E.LTC256B R33, desc[UR12][R12.64], P6"), // A.junk.b0_0ltc3pv1 x4
    (0x000000000c1019380000000c0c217980, "LD.E.LTC256B R33, desc[UR12][R12.64], !PT"), // A.junk.b0_0ltc3pv8 x4
];
#[rustfmt::skip]
pub const LAW435_POUT: &[(u128, &str)] = &[
    (0x000000000c1019000000000c0c217981, "LDG.E P0, R33, desc[UR12][R12.64]"), // A.junk.b0_1ltc0pv0 x4
    (0x000000000c1019010000000c0c217981, "LDG.E P0, R33, desc[UR12][R12.64], P6"), // A.junk.b0_1ltc0pv1 x4
    (0x000000000c1019080000000c0c217981, "LDG.E P0, R33, desc[UR12][R12.64], !PT"), // A.junk.b0_1ltc0pv8 x4
    (0x000000000c1019100000000c0c217981, "LDG.E.LTC64B P0, R33, desc[UR12][R12.64]"), // A.junk.b0_1ltc1pv0 x4
    (0x000000000c1019110000000c0c217981, "LDG.E.LTC64B P0, R33, desc[UR12][R12.64], P6"), // A.junk.b0_1ltc1pv1 x4
    (0x000000000c1019180000000c0c217981, "LDG.E.LTC64B P0, R33, desc[UR12][R12.64], !PT"), // A.junk.b0_1ltc1pv8 x4
    (0x000000000c1019200000000c0c217981, "LDG.E.LTC128B P0, R33, desc[UR12][R12.64]"), // A.junk.b0_1ltc2pv0 x4
    (0x000000000c1019210000000c0c217981, "LDG.E.LTC128B P0, R33, desc[UR12][R12.64], P6"), // A.junk.b0_1ltc2pv1 x4
    (0x000000000c1019280000000c0c217981, "LDG.E.LTC128B P0, R33, desc[UR12][R12.64], !PT"), // A.junk.b0_1ltc2pv8 x4
    (0x000000000c1019300000000c0c217981, "LDG.E.LTC256B P0, R33, desc[UR12][R12.64]"), // A.junk.b0_1ltc3pv0 x4
    (0x000000000c1019310000000c0c217981, "LDG.E.LTC256B P0, R33, desc[UR12][R12.64], P6"), // A.junk.b0_1ltc3pv1 x4
    (0x000000000c1019380000000c0c217981, "LDG.E.LTC256B P0, R33, desc[UR12][R12.64], !PT"), // A.junk.b0_1ltc3pv8 x4
];
#[rustfmt::skip]
pub const LAW435_LD128: &[(u128, &str)] = &[
    (0x000000000c101d010000000c0c217980, "LD.E.128 R33, desc[UR12][R12.64], P6"), // P128d.ltc0pv1 x4
    (0x000000000c101d080000000c0c217980, "LD.E.128 R33, desc[UR12][R12.64], !PT"), // P128d.ltc0pv8 x4
    (0x000000000c101d210000000c0c217980, "LD.E.LTC128B.128 R33, desc[UR12][R12.64], P6"), // P128d.ltc2pv1 x4
    (0x000000000c101d280000000c0c217980, "LD.E.LTC128B.128 R33, desc[UR12][R12.64], !PT"), // P128d.ltc2pv8 x4
    (0x000000000c101d000000000c0c217980, "LD.E.128 R33, desc[UR12][R12.64]"), // C.hi.ltc0pv0.0c101d x4
    (0x000000000c101d200000000c0c217980, "LD.E.LTC128B.128 R33, desc[UR12][R12.64]"), // C.hi.ltc2pv0.0c101d x4
];
#[rustfmt::skip]
pub const LAW435_DOLD: &[(u128, &str)] = &[
    (0x000000000c1e19100000000c0c210981, "@P0 LDG.E.LTC64B R33, desc[UR12][R12.64]"), // D.old.ltc1pv0 x4
    (0x000000000c1e19200000000c0c210981, "@P0 LDG.E.LTC128B R33, desc[UR12][R12.64]"), // D.old.ltc2pv0 x4
    (0x000000000c1e19300000000c0c210981, "@P0 LDG.E.LTC256B R33, desc[UR12][R12.64]"), // D.old.ltc3pv0 x4
    (0x000000000c1e19000000000c0c210981, "@P0 LDG.E R33, desc[UR12][R12.64]"), // D.old.pv0 x4
    (0x000000000c1e19010000000c0c210981, "@P0 LDG.E R33, desc[UR12][R12.64], P6"), // D.old.pv1 x4
    (0x000000000c1e19080000000c0c210981, "@P0 LDG.E R33, desc[UR12][R12.64], !PT"), // D.old.pv8 x4
];
#[rustfmt::skip]
pub const POSTURE435: &[(u128, &str, &str)] = &[
    (0x000000000c1e1d000000000c0c217980, "C.lane.ltc0pv0.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d000000000c0c217980, "C.lane.ltc0pv0.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d000000000c0c217980, "C.lane.ltc0pv0.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d000000000c0c217980, "C.lane.ltc0pv0.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d010000000c0c217980, "C.lane.ltc0pv1.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d010000000c0c217980, "C.lane.ltc0pv1.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d010000000c0c217980, "C.lane.ltc0pv1.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d010000000c0c217980, "C.lane.ltc0pv1.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d080000000c0c217980, "C.lane.ltc0pv8.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d080000000c0c217980, "C.lane.ltc0pv8.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d080000000c0c217980, "C.lane.ltc0pv8.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d080000000c0c217980, "C.lane.ltc0pv8.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d100000000c0c217980, "C.lane.ltc1pv0.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d100000000c0c217980, "C.lane.ltc1pv0.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d100000000c0c217980, "C.lane.ltc1pv0.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d100000000c0c217980, "C.lane.ltc1pv0.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d110000000c0c217980, "C.lane.ltc1pv1.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d110000000c0c217980, "C.lane.ltc1pv1.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d110000000c0c217980, "C.lane.ltc1pv1.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d110000000c0c217980, "C.lane.ltc1pv1.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d180000000c0c217980, "C.lane.ltc1pv8.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d180000000c0c217980, "C.lane.ltc1pv8.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d180000000c0c217980, "C.lane.ltc1pv8.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d180000000c0c217980, "C.lane.ltc1pv8.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.lane.ltc2pv0.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.lane.ltc2pv0.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.lane.ltc2pv0.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.lane.ltc2pv0.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c210980, "C.lane.ltc2pv0lo0980.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c210980, "C.lane.ltc2pv0lo0980.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c210980, "C.lane.ltc2pv0lo0980.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c210980, "C.lane.ltc2pv0lo0980.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d210000000c0c217980, "C.lane.ltc2pv1.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d210000000c0c217980, "C.lane.ltc2pv1.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d210000000c0c217980, "C.lane.ltc2pv1.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d210000000c0c217980, "C.lane.ltc2pv1.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d280000000c0c217980, "C.lane.ltc2pv8.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d280000000c0c217980, "C.lane.ltc2pv8.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d280000000c0c217980, "C.lane.ltc2pv8.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d280000000c0c217980, "C.lane.ltc2pv8.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d300000000c0c217980, "C.lane.ltc3pv0.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d300000000c0c217980, "C.lane.ltc3pv0.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d300000000c0c217980, "C.lane.ltc3pv0.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d300000000c0c217980, "C.lane.ltc3pv0.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d310000000c0c217980, "C.lane.ltc3pv1.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d310000000c0c217980, "C.lane.ltc3pv1.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d310000000c0c217980, "C.lane.ltc3pv1.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d310000000c0c217980, "C.lane.ltc3pv1.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d380000000c0c217980, "C.lane.ltc3pv8.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d380000000c0c217980, "C.lane.ltc3pv8.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d380000000c0c217980, "C.lane.ltc3pv8.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d380000000c0c217980, "C.lane.ltc3pv8.sm121a", "HOLE"), // pre==post
    (0x000000000c1e19200000000c0c217980, "C.w.ltc2pv0.w19.sm100a", "HOLE"), // pre==post
    (0x000000000c1e19200000000c0c217980, "C.w.ltc2pv0.w19.sm103a", "HOLE"), // pre==post
    (0x000000000c1e19200000000c0c217980, "C.w.ltc2pv0.w19.sm120", "HOLE"), // pre==post
    (0x000000000c1e19200000000c0c217980, "C.w.ltc2pv0.w19.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1b200000000c0c217980, "C.w.ltc2pv0.w1b.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1b200000000c0c217980, "C.w.ltc2pv0.w1b.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1b200000000c0c217980, "C.w.ltc2pv0.w1b.sm120", "HOLE"), // pre==post
    (0x000000000c1e1b200000000c0c217980, "C.w.ltc2pv0.w1b.sm121a", "HOLE"), // pre==post
    (0x000000000c1219000000000c0c217980, "D.pout1.ltc0pv0.sm100a", "HOLE"), // pre==post
    (0x000000000c1219000000000c0c217980, "D.pout1.ltc0pv0.sm103a", "HOLE"), // pre==post
    (0x000000000c1219000000000c0c217980, "D.pout1.ltc0pv0.sm120", "HOLE"), // pre==post
    (0x000000000c1219000000000c0c217980, "D.pout1.ltc0pv0.sm121a", "HOLE"), // pre==post
    (0x000000000c1419000000000c0c217980, "D.pout2.ltc0pv0.sm100a", "HOLE"), // pre==post
    (0x000000000c1419000000000c0c217980, "D.pout2.ltc0pv0.sm103a", "HOLE"), // pre==post
    (0x000000000c1419000000000c0c217980, "D.pout2.ltc0pv0.sm120", "HOLE"), // pre==post
    (0x000000000c1419000000000c0c217980, "D.pout2.ltc0pv0.sm121a", "HOLE"), // pre==post
    (0x000000000c1e19000000000c0c217980, "D.pout7.ltc0pv0.sm100a", "HOLE"), // pre==post
    (0x000000000c1e19000000000c0c217980, "D.pout7.ltc0pv0.sm103a", "HOLE"), // pre==post
    (0x000000000c1e19000000000c0c217980, "D.pout7.ltc0pv0.sm120", "HOLE"), // pre==post
    (0x000000000c1e19000000000c0c217980, "D.pout7.ltc0pv0.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d010000000c0c217980, "P7lane.ltc0pv1.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d010000000c0c217980, "P7lane.ltc0pv1.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d010000000c0c217980, "P7lane.ltc0pv1.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d010000000c0c217980, "P7lane.ltc0pv1.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d080000000c0c217980, "P7lane.ltc0pv8.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d080000000c0c217980, "P7lane.ltc0pv8.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d080000000c0c217980, "P7lane.ltc0pv8.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d080000000c0c217980, "P7lane.ltc0pv8.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d110000000c0c217980, "P7lane.ltc1pv1.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d110000000c0c217980, "P7lane.ltc1pv1.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d110000000c0c217980, "P7lane.ltc1pv1.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d110000000c0c217980, "P7lane.ltc1pv1.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d180000000c0c217980, "P7lane.ltc1pv8.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d180000000c0c217980, "P7lane.ltc1pv8.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d180000000c0c217980, "P7lane.ltc1pv8.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d180000000c0c217980, "P7lane.ltc1pv8.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d210000000c0c217980, "P7lane.ltc2pv1.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d210000000c0c217980, "P7lane.ltc2pv1.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d210000000c0c217980, "P7lane.ltc2pv1.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d210000000c0c217980, "P7lane.ltc2pv1.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d280000000c0c217980, "P7lane.ltc2pv8.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d280000000c0c217980, "P7lane.ltc2pv8.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d280000000c0c217980, "P7lane.ltc2pv8.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d280000000c0c217980, "P7lane.ltc2pv8.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d310000000c0c217980, "P7lane.ltc3pv1.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d310000000c0c217980, "P7lane.ltc3pv1.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d310000000c0c217980, "P7lane.ltc3pv1.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d310000000c0c217980, "P7lane.ltc3pv1.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d380000000c0c217980, "P7lane.ltc3pv8.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d380000000c0c217980, "P7lane.ltc3pv8.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d380000000c0c217980, "P7lane.ltc3pv8.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d380000000c0c217980, "P7lane.ltc3pv8.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk0_base.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk0_base.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk0_base.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk0_base.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk1_0.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk1_0.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk1_0.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk1_0.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk2_0_74.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk2_0_74.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk2_0_74.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk2_0_74.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk3_0_74_81.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk3_0_74_81.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk3_0_74_81.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk3_0_74_81.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk4_0_74_81_82.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk4_0_74_81_82.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk4_0_74_81_82.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk4_0_74_81_82.sm121a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk5_0_74_81_82_83.sm100a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk5_0_74_81_82_83.sm103a", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk5_0_74_81_82_83.sm120", "HOLE"), // pre==post
    (0x000000000c1e1d200000000c0c217980, "C.walk5_0_74_81_82_83.sm121a", "HOLE"), // pre==post
    (0x080000000c1019000000000c0c217980, "H.reuse.sm100a", "LD.E R33, desc[UR12][R12.64]"), // pre==post
    (0x080000000c1019000000000c0c217980, "H.reuse.sm103a", "LD.E R33, desc[UR12][R12.64]"), // pre==post
    (0x080000000c1019000000000c0c217980, "H.reuse.sm120", "LD.E R33, desc[UR12][R12.64]"), // pre==post
    (0x080000000c1019000000000c0c217980, "H.reuse.sm121a", "LD.E R33, desc[UR12][R12.64]"), // pre==post
];
#[rustfmt::skip]
pub const MINT435: &[(u128, &str)] = &[
    (0x000fc2000c1e1d200000000c0c217981, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64]"), // m1 sm100a
    (0x000fc2000c1e1d200000000c0c217981, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64]"), // m1 sm103a
    (0x000fc2000c1e1d200000000c0c217981, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64]"), // m1 sm121a
    (0x000fc2000c1e1d280000000c0c217981, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64], !PT"), // m2 sm100a
    (0x000fc2000c1e1d280000000c0c217981, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64], !PT"), // m2 sm103a
    (0x000fc2000c1e1d280000000c0c217981, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64], !PT"), // m2 sm120
    (0x000fc2000c1e1d280000000c0c217981, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64], !PT"), // m2 sm121a
    (0x000fc2000c1019110000000c0c217980, "LD.E.LTC64B R33, desc[UR12][R12.64], P6"), // m3 sm100a
    (0x000fc2000c1019110000000c0c217980, "LD.E.LTC64B R33, desc[UR12][R12.64], P6"), // m3 sm103a
    (0x000fc2000c1019110000000c0c217980, "LD.E.LTC64B R33, desc[UR12][R12.64], P6"), // m3 sm120
    (0x000fc2000c1019110000000c0c217980, "LD.E.LTC64B R33, desc[UR12][R12.64], P6"), // m3 sm121a
    (0x000fc2000c1019200000000c0c217981, "LDG.E.LTC128B P0, R33, desc[UR12][R12.64]"), // m4 sm100a
    (0x000fc2000c1019200000000c0c217981, "LDG.E.LTC128B P0, R33, desc[UR12][R12.64]"), // m4 sm103a
    (0x000fc2000c1019200000000c0c217981, "LDG.E.LTC128B P0, R33, desc[UR12][R12.64]"), // m4 sm120
    (0x000fc2000c1019200000000c0c217981, "LDG.E.LTC128B P0, R33, desc[UR12][R12.64]"), // m4 sm121a
    (0x000fc2000c1019010000000c0c217981, "LDG.E P0, R33, desc[UR12][R12.64], P6"), // m5 sm100a
    (0x000fc2000c1019010000000c0c217981, "LDG.E P0, R33, desc[UR12][R12.64], P6"), // m5 sm103a
    (0x000fc2000c1019010000000c0c217981, "LDG.E P0, R33, desc[UR12][R12.64], P6"), // m5 sm120
    (0x000fc2000c1019010000000c0c217981, "LDG.E P0, R33, desc[UR12][R12.64], P6"), // m5 sm121a
    (0x000fc2000c1019210000000c0c210980, "@P0 LD.E.LTC128B R33, desc[UR12][R12.64], P6"), // m6 sm100a
    (0x000fc2000c1019210000000c0c210980, "@P0 LD.E.LTC128B R33, desc[UR12][R12.64], P6"), // m6 sm103a
    (0x000fc2000c1019210000000c0c210980, "@P0 LD.E.LTC128B R33, desc[UR12][R12.64], P6"), // m6 sm120
    (0x000fc2000c1019210000000c0c210980, "@P0 LD.E.LTC128B R33, desc[UR12][R12.64], P6"), // m6 sm121a
    (0x000fc2000c101d010000000c0c217980, "LD.E.128 R33, desc[UR12][R12.64], P6"), // m7 sm100a
    (0x000fc2000c101d010000000c0c217980, "LD.E.128 R33, desc[UR12][R12.64], P6"), // m7 sm103a
    (0x000fc2000c101d010000000c0c217980, "LD.E.128 R33, desc[UR12][R12.64], P6"), // m7 sm120
    (0x000fc2000c101d010000000c0c217980, "LD.E.128 R33, desc[UR12][R12.64], P6"), // m7 sm121a
    (0x000fc2000c101d280000000c0c217980, "LD.E.LTC128B.128 R33, desc[UR12][R12.64], !PT"), // m8 sm100a
    (0x000fc2000c101d280000000c0c217980, "LD.E.LTC128B.128 R33, desc[UR12][R12.64], !PT"), // m8 sm103a
    (0x000fc2000c101d280000000c0c217980, "LD.E.LTC128B.128 R33, desc[UR12][R12.64], !PT"), // m8 sm120
    (0x000fc2000c101d280000000c0c217980, "LD.E.LTC128B.128 R33, desc[UR12][R12.64], !PT"), // m8 sm121a
    (0x000fc2000c101d200000000c0c217980, "LD.E.LTC128B.128 R33, desc[UR12][R12.64]"), // m9 sm100a
    (0x000fc2000c101d200000000c0c217980, "LD.E.LTC128B.128 R33, desc[UR12][R12.64]"), // m9 sm103a
    (0x000fc2000c101d200000000c0c217980, "LD.E.LTC128B.128 R33, desc[UR12][R12.64]"), // m9 sm120
    (0x000fc2000c101d200000000c0c217980, "LD.E.LTC128B.128 R33, desc[UR12][R12.64]"), // m9 sm121a
    (0x000fc2000c101d000000000c0c217980, "LD.E.128 R33, desc[UR12][R12.64]"), // m10 sm100a
    (0x000fc2000c101d000000000c0c217980, "LD.E.128 R33, desc[UR12][R12.64]"), // m10 sm103a
    (0x000fc2000c101d000000000c0c217980, "LD.E.128 R33, desc[UR12][R12.64]"), // m10 sm120
    (0x000fc2000c101d000000000c0c217980, "LD.E.128 R33, desc[UR12][R12.64]"), // m10 sm121a
    (0x000fc2000c1019380000000c0c217980, "LD.E.LTC256B R33, desc[UR12][R12.64], !PT"), // m11 sm100a
    (0x000fc2000c1019380000000c0c217980, "LD.E.LTC256B R33, desc[UR12][R12.64], !PT"), // m11 sm103a
    (0x000fc2000c1019380000000c0c217980, "LD.E.LTC256B R33, desc[UR12][R12.64], !PT"), // m11 sm120
    (0x000fc2000c1019380000000c0c217980, "LD.E.LTC256B R33, desc[UR12][R12.64], !PT"), // m11 sm121a
    (0x000fc2000c1019300000000c0c217981, "LDG.E.LTC256B P0, R33, desc[UR12][R12.64]"), // m12 sm100a
    (0x000fc2000c1019300000000c0c217981, "LDG.E.LTC256B P0, R33, desc[UR12][R12.64]"), // m12 sm103a
    (0x000fc2000c1019300000000c0c217981, "LDG.E.LTC256B P0, R33, desc[UR12][R12.64]"), // m12 sm120
    (0x000fc2000c1019300000000c0c217981, "LDG.E.LTC256B P0, R33, desc[UR12][R12.64]"), // m12 sm121a
];
#[rustfmt::skip]
pub const SM120_090_SHADOW435: &[(u128, &str)] = &[
    (0x000fc2000c1019000000000c0c217980, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64]"), // m1 sm120 090-era junk-route mint (contract)
];
#[rustfmt::skip]
pub const REFUSE435: &[&str] = &[
    "LDG.E.LTC64B.256 R33, desc[UR12][R12.64]",
    "LDG.E.LTC64B P0, R33, desc[UR12][R12.64], P9",
    "LD.E.LTC128B.256 R33, desc[UR12][R12.64]",
    "LDG.E.LTC128B.128 R33, desc[UR12][R12.64], P9",
    "LD.E.LTC64B.64 R33, desc[UR12][R12.64]",
];

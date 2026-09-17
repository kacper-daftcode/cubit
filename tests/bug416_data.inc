// MACHINE-BUILT by work/bug416/gen416pins.py (rc=2 self-checks; no hand hex).
// BUG-416 witnesses: arb416/arb416d/arb416c/arb400c law (x4 nvdisasm AGREE
// EVERY/DIVERGENT=0) + measure416_post (cells BAD 0 sm121a) + measure416_pre
// (publish c3d618a9 neg-ctl) + canonical 70eb0fe.
pub const CANON416: &str = "bd2e25464208f9be6abc1e3c7475ca34914ad095" /* ride F2-iter275 (BUG-466 ELL2.256 dARI-era rekanon plain-geo): 67b54f4405b7f6d2d748d8221deb6a9a59cd3c2f canonical, was 23976eb44550254b12f8862ebc088d2c5d49dd72; */ /* ride F2-iter272 (BUG-465 modsub plain E*L2.256 lattice): 23976eb44550254b12f8862ebc088d2c5d49dd72 canonical, was 49681135da169cdd27585a3eea52b61c585fa589; old:  ride F2-iter270 (BUG-464 plain ARURI64 lattice): 49681135da169cdd27585a3eea52b61c585fa589 canonical, was 50780675cd8e43ddd496d5a130752178b7163686; old:  ride F2-iter268 (BUG-432R donor-128E): 50780675cd8e43ddd496d5a130752178b7163686 canonical, was a6e3c9ea9ad9ad95d14687580eec2c8f82646baf = BUG-432 ari-cavity F2-iter267; old:  ride F2-iter267 (BUG-432 ari-cavity): a6e3c9ea9ad9ad95d14687580eec2c8f82646baf canonical, was a64b82bff6706350b82018609016f624188b99a5 = BUG-463 ltc F2-iter266 */ /* ride F2-iter266 (BUG-463 ltc-widths): a64b82bff6706350b82018609016f624188b99a5 canonical, was f58ed1683bded052bcb100a0762c16e7e91248c4 = BUG-461 glyph F2-iter265 */ /* ride F2-iter265 (BUG-461 glyph): f58ed1683bded052bcb100a0762c16e7e91248c4 canonical, was f37655889e6da3ddd25b73a926c21ec3b58fa768 = BUG-462 narrow F2-iter264 */ /* ride F2-iter264 (BUG-462 narrow): f37655889e6da3ddd25b73a926c21ec3b58fa768 canonical, was 700524e698304dcbf1a3884f72f05abff609b8aa = BUG-453 graft F2-iter263 */ /* ride F2-iter263 (BUG-453 graft): 700524e698304dcbf1a3884f72f05abff609b8aa canonical, was 700524e698304dcbf1a3884f72f05abff609b8aa = BUG-452 narrow F2-iter260 */ /* ride F2-iter260 (BUG-452 narrow): 700524e698304dcbf1a3884f72f05abff609b8aa canonical, was 4ee843162216e75d037135b5907c819759471296 = BUG-454 F2-iter258 */ /* ride F2-iter258 (BUG-454 graft): 4ee843162216e75d037135b5907c819759471296 canonical, was 589be874 = BUG-450 F2-iter255 */ /* ride F2-iter255 (BUG-450 graft): 589be874bfcab4513e5f70b43c832d73f1bea3c1 canonical, was 099faa0 = BUG-447 F2-iter252 */; // BUG-447 graft F2-iter252; rides e8d1af3 = BUG-443 F2-iter250, 57e7ecd = BUG-442 F2-iter246, ffa3244 = BUG-441 F2-iter245, bb1ba6c = BUG-438 F2-iter244, 54c5b02 = BUG-439 F2-iter243, 3032686 = BUG-423 F2-iter242, 61858fb = BUG-433 F2-iter241; older: 0a6b178 = BUG-435+434+435b, 1810912 hop, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b
#[rustfmt::skip]
pub const LAW416_LDG: &[(u128, &str, &str, &str)] = &[
    (0x000000000c1e1d200000000c0c217981, "B.true.ltc2pv0", "LDG.E.LTC128B.128 R33, desc[UR12][R12.64]", "LDG_R_dARI_P|128,E,LTC128B"), // pre: LDG.E.128 R33, desc[UR12][R12.64] [LDG_R_dARI|128,E]
    (0x000000000c1e1d210000000c0c217981, "B.true.ltc2pv1", "LDG.E.LTC128B.128 R33, desc[UR12][R12.64], P6", "LDG_R_dARI_P|128,E,LTC128B"), // pre: LDG.E.128 R33, desc[UR12][R12.64] [LDG_R_dARI|128,E]
    (0x000000000c1e1d280000000c0c217981, "B.true.ltc2pv8", "LDG.E.LTC128B.128 R33, desc[UR12][R12.64], !PT", "LDG_R_dARI_P|128,E,LTC128B"), // pre: LDG.E.128 R33, desc[UR12][R12.64] [LDG_R_dARI|128,E]
    (0x000000000c1e1d500000000c0c217981, "syn121a.b70pv0ltc1", "LDG.E.LTC64B.128 R33, desc[UR12][R12.64]", "LDG_R_dARI|128,E,LTC64B"), // pre: LDG.E.128 PT, R33, desc[UR12][R12.64] [LDG_P_R_dARI|128,E]
    (0x000000000c1e1d510000000c0c217981, "syn121a.b70pv1ltc1", "LDG.E.LTC64B.128 R33, desc[UR12][R12.64], P6", "LDG_R_dARI_P|128,E,LTC64B"), // pre: LDG.E.128 PT, R33, desc[UR12][R12.64] [LDG_P_R_dARI|128,E]
    (0x000000000c1e1d580000000c0c217981, "syn121a.b70pv8ltc1", "LDG.E.LTC64B.128 R33, desc[UR12][R12.64], !PT", "LDG_R_dARI_P|128,E,LTC64B"), // pre: LDG.E.128 PT, R33, desc[UR12][R12.64] [LDG_P_R_dARI|128,E]
    (0x000000000c1e1d700000000c0c217981, "syn121a.b70pv0ltc3", "LDG.E.LTC256B.128 R33, desc[UR12][R12.64]", "LDG_R_dARI|128,E,LTC256B"), // pre: LDG.E.128 PT, R33, desc[UR12][R12.64] [LDG_P_R_dARI|128,E]
    (0x000000000c1e1d710000000c0c217981, "syn121a.b70pv1ltc3", "LDG.E.LTC256B.128 R33, desc[UR12][R12.64], P6", "LDG_R_dARI_P|128,E,LTC256B"), // pre: LDG.E.128 PT, R33, desc[UR12][R12.64] [LDG_P_R_dARI|128,E]
    (0x000000000c1e1d780000000c0c217981, "syn121a.b70pv8ltc3", "LDG.E.LTC256B.128 R33, desc[UR12][R12.64], !PT", "LDG_R_dARI_P|128,E,LTC256B"), // pre: LDG.E.128 PT, R33, desc[UR12][R12.64] [LDG_P_R_dARI|128,E]
    (0x000000000c1e1d900000000c0c217981, "syn121a.b71pv0ltc1", "LDG.E.LTC64B.128 R33, desc[UR12][R12.64]", "LDG_R_dARI|128,E,LTC64B"), // pre: LDG.E.128 PT, R33, desc[UR12][R12.64] [LDG_P_R_dARI|128,E]
    (0x000000000c1e1db80000000c0c217981, "syn121a.b71pv8ltc3", "LDG.E.LTC256B.128 R33, desc[UR12][R12.64], !PT", "LDG_R_dARI_P|128,E,LTC256B"), // pre: LDG.E.128 PT, R33, desc[UR12][R12.64] [LDG_P_R_dARI|128,E]
    (0x000000000c1e1dd00000000c0c217981, "syn121a.ballpv0ltc1", "LDG.E.LTC64B.128 R33, desc[UR12][R12.64]", "LDG_R_dARI|128,E,LTC64B"), // pre: LDG.E.128 PT, R33, desc[UR12][R12.64] [LDG_P_R_dARI|128,E]
    (0x000000000c1e1db00000000c0c217981, "syn121a.b71pv0ltc3", "LDG.E.LTC256B.128 R33, desc[UR12][R12.64]", "LDG_R_dARI|128,E,LTC256B"), // pre: LDG.E.128 PT, R33, desc[UR12][R12.64] [LDG_P_R_dARI|128,E]
];

#[rustfmt::skip]
pub const LAW416_LD: &[(u128, &str, &str, &str)] = &[
    (0x000000000c1019000000000c0c210980, "P.ltc0pv0", "@P0 LD.E R33, desc[UR12][R12.64]", "LD_R_dARI|E"), // pre: @P0 LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019010000000c0c210980, "P.ltc0pv1", "@P0 LD.E R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E"), // pre: @P0 LDG.E.LTC128B.128 R33, desc[UR12][R12.64], P6 [LDG_R_dARI_P|128,E,LTC128B]
    (0x000000000c1019080000000c0c210980, "P.ltc0pv8", "@P0 LD.E R33, desc[UR12][R12.64], !PT", "LD_R_dARI_P|E"), // pre: @P0 LDG.E.LTC128B.128 R33, desc[UR12][R12.64], !PT [LDG_R_dARI_P|128,E,LTC128B]
    (0x000000000c1019100000000c0c210980, "P.ltc1pv0", "@P0 LD.E.LTC64B R33, desc[UR12][R12.64]", "LD_R_dARI|E,LTC64B"), // pre: @P0 LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019110000000c0c210980, "P.ltc1pv1", "@P0 LD.E.LTC64B R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E,LTC64B"), // pre: @P0 LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019180000000c0c210980, "P.ltc1pv8", "@P0 LD.E.LTC64B R33, desc[UR12][R12.64], !PT", "LD_R_dARI_P|E,LTC64B"), // pre: @P0 LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019200000000c0c210980, "P.ltc2pv0", "@P0 LD.E.LTC128B R33, desc[UR12][R12.64]", "LD_R_dARI|E,LTC128B"), // pre: @P0 LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019210000000c0c210980, "P.ltc2pv1", "@P0 LD.E.LTC128B R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E,LTC128B"), // pre: @P0 LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019280000000c0c210980, "P.ltc2pv8", "@P0 LD.E.LTC128B R33, desc[UR12][R12.64], !PT", "LD_R_dARI_P|E,LTC128B"), // pre: @P0 LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019300000000c0c210980, "P.ltc3pv0", "@P0 LD.E.LTC256B R33, desc[UR12][R12.64]", "LD_R_dARI|E,LTC256B"), // pre: @P0 LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019310000000c0c210980, "P.ltc3pv1", "@P0 LD.E.LTC256B R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E,LTC256B"), // pre: @P0 LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019380000000c0c210980, "P.ltc3pv8", "@P0 LD.E.LTC256B R33, desc[UR12][R12.64], !PT", "LD_R_dARI_P|E,LTC256B"), // pre: @P0 LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
];

#[rustfmt::skip]
pub const LAW416_INERT: &[(u128, &str, &str, &str)] = &[
    (0x000000000c1019400000000c0c217980, "G.b70pv0", "LD.E R33, desc[UR12][R12.64]", "LD_R_dARI|E"), // pre: LD.E R33, desc[UR12][R12.64]
    (0x000000000c1019410000000c0c217980, "G.b70pv1", "LD.E R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E"), // pre: LD.E R33, desc[UR12][R12.64]
    (0x000000000c1019800000000c0c217980, "G.b71pv0", "LD.E R33, desc[UR12][R12.64]", "LD_R_dARI|E"), // pre: LD.E R33, desc[UR12][R12.64]
    (0x000000000c1019810000000c0c217980, "G.b71pv1", "LD.E R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E"), // pre: LD.E R33, desc[UR12][R12.64]
    (0x000000000c1019c00000000c0c217980, "G.ballpv0", "LD.E R33, desc[UR12][R12.64]", "LD_R_dARI|E"), // pre: LD.E R33, desc[UR12][R12.64]
    (0x000000000c1019c10000000c0c217980, "G.ballpv1", "LD.E R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E"), // pre: LD.E R33, desc[UR12][R12.64]
    (0x000000000c1019400000000c0c210980, "Q.b70pv0", "@P0 LD.E R33, desc[UR12][R12.64]", "LD_R_dARI|E"), // pre: @P0 LD.E R33, desc[UR12][R12.64]
    (0x000000000c1019410000000c0c210980, "Q.b70pv1", "@P0 LD.E R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E"), // pre: @P0 LD.E R33, desc[UR12][R12.64]
    (0x000000000c1019800000000c0c210980, "Q.b71pv0", "@P0 LD.E R33, desc[UR12][R12.64]", "LD_R_dARI|E"), // pre: @P0 LD.E R33, desc[UR12][R12.64]
    (0x000000000c1019810000000c0c210980, "Q.b71pv1", "@P0 LD.E R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E"), // pre: @P0 LD.E R33, desc[UR12][R12.64]
    (0x000000000c1019c00000000c0c210980, "Q.ballpv0", "@P0 LD.E R33, desc[UR12][R12.64]", "LD_R_dARI|E"), // pre: @P0 LD.E R33, desc[UR12][R12.64]
    (0x000000000c1019c10000000c0c210980, "Q.ballpv1", "@P0 LD.E R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E"), // pre: @P0 LD.E R33, desc[UR12][R12.64]
    (0x000000000c1019000000000c0c212980, "R.guardP2", "@P2 LD.E R33, desc[UR12][R12.64]", "LD_R_dARI|E"), // pre: @P2 LD.E R33, desc[UR12][R12.64]
    (0x000000000c1019000001550c0c210980, "R.imm", "@P0 LD.E R33, desc[UR12][R12.64+0x155]", "LD_R_dARI|E"), // pre: @P0 LD.E R33, desc[UR12][R12.64+0x155]
];

#[rustfmt::skip]
pub const LAW416_FABRIC: &[(u128, &str, &str, &str)] = &[
    (0x000000000c1019000000000c0c217980, "A.junk.b0_0ltc0pv0", "LD.E R33, desc[UR12][R12.64]", "LD_R_dARI|E"), // pre: LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019010000000c0c217980, "A.junk.b0_0ltc0pv1", "LD.E R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E"), // pre: LDG.E.LTC128B.128 R33, desc[UR12][R12.64], P6 [LDG_R_dARI_P|128,E,LTC128B]
    (0x000000000c1019080000000c0c217980, "A.junk.b0_0ltc0pv8", "LD.E R33, desc[UR12][R12.64], !PT", "LD_R_dARI_P|E"), // pre: LDG.E.LTC128B.128 R33, desc[UR12][R12.64], !PT [LDG_R_dARI_P|128,E,LTC128B]
    (0x000000000c1019100000000c0c217980, "A.junk.b0_0ltc1pv0", "LD.E.LTC64B R33, desc[UR12][R12.64]", "LD_R_dARI|E,LTC64B"), // pre: LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019110000000c0c217980, "A.junk.b0_0ltc1pv1", "LD.E.LTC64B R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E,LTC64B"), // pre: LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019180000000c0c217980, "A.junk.b0_0ltc1pv8", "LD.E.LTC64B R33, desc[UR12][R12.64], !PT", "LD_R_dARI_P|E,LTC64B"), // pre: LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019200000000c0c217980, "A.junk.b0_0ltc2pv0", "LD.E.LTC128B R33, desc[UR12][R12.64]", "LD_R_dARI|E,LTC128B"), // pre: LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019210000000c0c217980, "A.junk.b0_0ltc2pv1", "LD.E.LTC128B R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E,LTC128B"), // pre: LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019280000000c0c217980, "A.junk.b0_0ltc2pv8", "LD.E.LTC128B R33, desc[UR12][R12.64], !PT", "LD_R_dARI_P|E,LTC128B"), // pre: LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019300000000c0c217980, "A.junk.b0_0ltc3pv0", "LD.E.LTC256B R33, desc[UR12][R12.64]", "LD_R_dARI|E,LTC256B"), // pre: LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019310000000c0c217980, "A.junk.b0_0ltc3pv1", "LD.E.LTC256B R33, desc[UR12][R12.64], P6", "LD_R_dARI_P|E,LTC256B"), // pre: LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
    (0x000000000c1019380000000c0c217980, "A.junk.b0_0ltc3pv8", "LD.E.LTC256B R33, desc[UR12][R12.64], !PT", "LD_R_dARI_P|E,LTC256B"), // pre: LD.E R33, desc[UR12][R12.64] [LD_R_dARI|E]
];

#[rustfmt::skip]
pub const POSTURE416: &[(u128, &str, &str)] = &[
    (0x000000000c1019000000000c0c217981, "A.junk.b0_1ltc0pv0", "LDG.E P0, R33, desc[UR12][R12.64]"), // FLIP-435: healed by 434 (LDG_P LTC lattice); pre==post era ends
    (0x000000000c1019010000000c0c217981, "A.junk.b0_1ltc0pv1", "LDG.E P0, R33, desc[UR12][R12.64], P6"), // FLIP-435: healed by 434 (LDG_P LTC lattice); pre==post era ends
    (0x000000000c1019080000000c0c217981, "A.junk.b0_1ltc0pv8", "LDG.E P0, R33, desc[UR12][R12.64], !PT"), // FLIP-435: healed by 434 (LDG_P LTC lattice); pre==post era ends
    (0x000000000c1019100000000c0c217981, "A.junk.b0_1ltc1pv0", "LDG.E.LTC64B P0, R33, desc[UR12][R12.64]"), // FLIP-435: healed by 434 (LDG_P LTC lattice); pre==post era ends
    (0x000000000c1019110000000c0c217981, "A.junk.b0_1ltc1pv1", "LDG.E.LTC64B P0, R33, desc[UR12][R12.64], P6"), // FLIP-435: healed by 434 (LDG_P LTC lattice); pre==post era ends
    (0x000000000c1019180000000c0c217981, "A.junk.b0_1ltc1pv8", "LDG.E.LTC64B P0, R33, desc[UR12][R12.64], !PT"), // FLIP-435: healed by 434 (LDG_P LTC lattice); pre==post era ends
    (0x000000000c1019200000000c0c217981, "A.junk.b0_1ltc2pv0", "LDG.E.LTC128B P0, R33, desc[UR12][R12.64]"), // FLIP-435: healed by 434 (LDG_P LTC lattice); pre==post era ends
    (0x000000000c1019210000000c0c217981, "A.junk.b0_1ltc2pv1", "LDG.E.LTC128B P0, R33, desc[UR12][R12.64], P6"), // FLIP-435: healed by 434 (LDG_P LTC lattice); pre==post era ends
    (0x000000000c1019280000000c0c217981, "A.junk.b0_1ltc2pv8", "LDG.E.LTC128B P0, R33, desc[UR12][R12.64], !PT"), // FLIP-435: healed by 434 (LDG_P LTC lattice); pre==post era ends
    (0x000000000c1019300000000c0c217981, "A.junk.b0_1ltc3pv0", "LDG.E.LTC256B P0, R33, desc[UR12][R12.64]"), // FLIP-435: healed by 434 (LDG_P LTC lattice); pre==post era ends
    (0x000000000c1019310000000c0c217981, "A.junk.b0_1ltc3pv1", "LDG.E.LTC256B P0, R33, desc[UR12][R12.64], P6"), // FLIP-435: healed by 434 (LDG_P LTC lattice); pre==post era ends
    (0x000000000c1019380000000c0c217981, "A.junk.b0_1ltc3pv8", "LDG.E.LTC256B P0, R33, desc[UR12][R12.64], !PT"), // FLIP-435: healed by 434 (LDG_P LTC lattice); pre==post era ends
];

#[rustfmt::skip]
pub const POSTURE416_JUNK: &[(u128, &str, &str)] = &[
    (0x040000000c1019000000000c0c210980, "arb416d.R.reuse122", "@P0 LD.E R33, desc[UR12][R12.64]"),
    (0x080000000c1019000000000c0c210980, "arb416d.R.reuse123", "@P0 LD.E R33, desc[UR12][R12.64]"),
    (0x000000000c1e1d200000000c0c217980, "arb416.C.walk0_base", "HOLE"),
    (0x000000000c1e1d200000000c0c217980, "arb416.C.walk1_0", "HOLE"),
    (0x000000000c1e1d200000000c0c217980, "arb416.C.walk2_0_74", "HOLE"),
    (0x000000000c1e1d200000000c0c217980, "arb416.C.walk3_0_74_81", "HOLE"),
    (0x000000000c1e1d200000000c0c217980, "arb416.C.walk4_0_74_81_82", "HOLE"),
    (0x000000000c1e1d200000000c0c217980, "arb416.C.walk5_0_74_81_82_83", "HOLE"),
];

#[rustfmt::skip]
pub const MINT416: &[(u128, &str)] = &[
    (0x000fc2000c1e1d210000000c0c217981, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64], P6"), // m1
    (0x000fc2000c1e1d200000000c0c217981, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64]"), // m10
    (0x000fc2000c1e1d280000000c0c217981, "LDG.E.LTC128B.128 R33, desc[UR12][R12.64], !PT"), // m2
    (0x000fc2000c1e1d110000000c0c217981, "LDG.E.LTC64B.128 R33, desc[UR12][R12.64], P6"), // m3
    (0x000fc2000c1e1d300000000c0c217981, "LDG.E.LTC256B.128 R33, desc[UR12][R12.64]"), // m4
    (0x000fc2000c1019010000000c0c217980, "LD.E R33, desc[UR12][R12.64], P6"), // m5
    (0x000fc2000c1019080000000c0c217980, "LD.E R33, desc[UR12][R12.64], !PT"), // m6
    (0x000fc2000c1019100000000c0c217980, "LD.E.LTC64B R33, desc[UR12][R12.64]"), // m7
    (0x000fc2000c1019210002f00c0c217980, "LD.E.LTC128B R33, desc[UR12][R12.64+0x2f0], P6"), // m8
    (0x000fc2000c1019308000000c0c217980, "LD.E.LTC256B R33, desc[UR12][R12.64+-0x800000]"), // m9
];

#[rustfmt::skip]
pub const REFUSE416: &[(&str, &str)] = &[
    ("r1", "LD.E.LTC64B.128 R33, desc[UR12][R12.64]"),
    ("r2", "LDG.E.LTC64B R33, desc[UR12][R12.64]"),
    ("r3", "LDG.E.LTC128B.128 R33, desc[UR12][R12.64], P7"),
    ("r4", "LD.E.LTC128B R33, desc[UR12][R12.64+0x1000000]"),
    ("r5", "LDG.E.LTC128B.128 R33, desc[UR12][R12.64+0x1000000]"),
];


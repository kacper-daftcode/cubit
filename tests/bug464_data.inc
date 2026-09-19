// BUG-464 machine-built pin data (gen464pins.py rc=2; no hand hex).
pub const CANON464: &str = "cc2f62c379c3e190ef373ab9e8f76af0aeef326c" /* ride F2-iter275 (BUG-466 ELL2.256 dARI-era rekanon plain-geo): 67b54f4405b7f6d2d748d8221deb6a9a59cd3c2f canonical, was 23976eb44550254b12f8862ebc088d2c5d49dd72; */; // ride F2-iter272 (BUG-465 modsub plain E*L2.256 lattice); was 4968113; old:  ride F2-iter270 (BUG-464 plain ARURI64 lattice);(graft +6 kluczy/noga)
                                                                       // RIDE465-STAND: 15 wpisow STAND464 przeszly z HOLE na tekst vendora (modsub lattice 465; cross z arb464*-law era-unanim; fail-closed).
pub const LAW464_HEAL: &[(u128, &str, &str)] = &[
    (
        0x010fe4000810082650d13a2c1c30197fu128,
        "arb464_.Cg.stg439",
        "@P1 STG.E.EFL2.256 [R28.64+UR38+0x1a2740], R44, R48, 0xa",
    ),
    (
        0x000be4000810082cbc0400261c30197eu128,
        "arb464_.Cg.ldg458",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38+0x8000], 0x5e",
    ),
    (
        0x000be4000f100826837bfe2c1c10197fu128,
        "arb464_.Cg.stg500",
        "@P1 STG.E.EFL2.256 [R28.64+UR38+0x6f7fc0], R44, R16, 0xf0",
    ),
    (
        0x000be4004f10082613b13c2c1c30197fu128,
        "arb464_.Cg.stg685",
        "@P1 STG.E.EFL2.256 [R28.64+UR38+0x762780], R44, R48, 0xe2",
    ),
    (
        0x000be4000810082c000000261c30197eu128,
        "arb464_.L.pol00",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x0",
    ),
    (
        0x000be4000810082c020000261c30197eu128,
        "arb464_.L.pol01",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x1",
    ),
    (
        0x000be4000810082c800000261c30197eu128,
        "arb464_.L.pol40",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x40",
    ),
    (
        0x000be4000810082cfc0000261c30197eu128,
        "arb464_.L.pol7e",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x7e",
    ),
    (
        0x000be4000810082cfe0000261c30197eu128,
        "arb464_.L.pol7f",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x7f",
    ),
    (
        0x000be4000810092c000000261c30197eu128,
        "arb464_.L.pol80",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x80",
    ),
    (
        0x000be4000810092c320000261c30197eu128,
        "arb464_.L.pol99",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be4000810092c7e0000261c30197eu128,
        "arb464_.L.polbf",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0xbf",
    ),
    (
        0x000be4000810092cfc0000261c30197eu128,
        "arb464_.L.polfe",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0xfe",
    ),
    (
        0x000be4000810092c320001261c30197eu128,
        "arb464_.L.pol99_imm00001",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38+0x20], 0x99",
    ),
    (
        0x000be4000810092c320100261c30197eu128,
        "arb464_.L.pol99_imm00100",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38+0x2000], 0x99",
    ),
    (
        0x000be4000810092c33ffff261c30197eu128,
        "arb464_.L.pol99_imm1ffff",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38+-0x20], 0x99",
    ),
    (
        0x000be4000810092c330000261c30197eu128,
        "arb464_.L.pol99_imm10000",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38+-0x200000], 0x99",
    ),
    (
        0x000be4000810092c332345261c30197eu128,
        "arb464_.L.pol99_imm12345",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38+-0x1b9760], 0x99",
    ),
    (
        0x000be4000810092c320000261c30197eu128,
        "arb464_.L.pol99_noimm",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be40008100900320000261c30197eu128,
        "arb464_.L.pol99_dst0",
        "@P1 LDG.E.EFL2.256 R0, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be400081009ff320000261c30197eu128,
        "arb464_.L.pol99_dst255",
        "@P1 LDG.E.EFL2.256 RZ, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be4000810092c320000261c00197eu128,
        "arb464_.L.pol99_r20",
        "@P1 LDG.E.EFL2.256 R44, R0, [R28.64+UR38], 0x99",
    ),
    (
        0x000be4000810092c320000261cff197eu128,
        "arb464_.L.pol99_r2255",
        "@P1 LDG.E.EFL2.256 R44, RZ, [R28.64+UR38], 0x99",
    ),
    (
        0x000be4000810092c320000260030197eu128,
        "arb464_.L.pol99_ra0",
        "@P1 LDG.E.EFL2.256 R44, R48, [R0.64+UR38], 0x99",
    ),
    (
        0x000be4000810092c320000001c30197eu128,
        "arb464_.L.pol99_ur0",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR0], 0x99",
    ),
    (
        0x000be4000810092c320000ff1c30197eu128,
        "arb464_.L.pol99_ur255",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+URZ], 0x99",
    ),
    (
        0x000be4000810092c320000261c30097eu128,
        "arb464_.L.pol99_guard0",
        "@P0 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be4000810092c320000261c30897eu128,
        "arb464_.L.pol99_guard8",
        "@!P0 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x004be4000810092c320000261c30197eu128,
        "arb464_.L.pol99_era118",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be4000890092c320000261c30197eu128,
        "arb464_.L.pol99_pred1",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99, P6",
    ),
    (
        0x000be4000b90092c320000261c30197eu128,
        "arb464_.L.pol99_pred7",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99, P0",
    ),
    (
        0x000be4000c10092c320000261c30197eu128,
        "arb464_.L.pol99_pred8",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99, !PT",
    ),
    (
        0x000be4000f10092c320000261c30197eu128,
        "arb464_.L.pol99_pred14",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99, !P1",
    ),
    (
        0x000be4000f90092c320000261c30197eu128,
        "arb464_.L.pol99_pred15",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99, !P0",
    ),
    (
        0x000be4000810082c060000261c30197eu128,
        "arb464_.L.sweep03",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x3",
    ),
    (
        0x000be4000810082c360000261c30197eu128,
        "arb464_.L.sweep1b",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x1b",
    ),
    (
        0x000be4000810082c760000261c30197eu128,
        "arb464_.L.sweep3b",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x3b",
    ),
    (
        0x000be4000810082cf60000261c30197eu128,
        "arb464_.L.sweep7b",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x7b",
    ),
    (
        0x000be4000810092cf60000261c30197eu128,
        "arb464_.L.sweepfb",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0xfb",
    ),
    (
        0x000be4001810092c320000261c30197eu128,
        "arb464_.L.pol99_b92",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be4002810092c320000261c30197eu128,
        "arb464_.L.pol99_b93",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be4004810092c320000261c30197eu128,
        "arb464_.L.pol99_b94",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be4008810092c320000261c30197eu128,
        "arb464_.L.pol99_b95",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be400081008260000002c1c30197fu128,
        "arb464_.S.pol00",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0x0",
    ),
    (
        0x000be400081008260800002c1c30197fu128,
        "arb464_.S.pol01",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0x1",
    ),
    (
        0x000be40008100826f800002c1c30197fu128,
        "arb464_.S.pol1f",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0x1f",
    ),
    (
        0x000be400091008260000002c1c30197fu128,
        "arb464_.S.pol20",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0x20",
    ),
    (
        0x000be4000c100826f800002c1c30197fu128,
        "arb464_.S.pol9f",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0x9f",
    ),
    (
        0x000be4000d1008260000002c1c30197fu128,
        "arb464_.S.pola0",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xa0",
    ),
    (
        0x000be4000f1008262000002c1c30197fu128,
        "arb464_.S.pole4",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xe4",
    ),
    (
        0x000be4000f100826f000002c1c30197fu128,
        "arb464_.S.polfe",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xfe",
    ),
    (
        0x000be4000d1008260000012c1c30197fu128,
        "arb464_.S.pola0_imm00001",
        "@P1 STG.E.EFL2.256 [R28.64+UR38+0x20], R44, R48, 0xa0",
    ),
    (
        0x000be4000d10082607ffff2c1c30197fu128,
        "arb464_.S.pola0_imm7ffff",
        "@P1 STG.E.EFL2.256 [R28.64+UR38+-0x20], R44, R48, 0xa0",
    ),
    (
        0x000be4000d1008260000002c0030197fu128,
        "arb464_.S.pola0_ra0",
        "@P1 STG.E.EFL2.256 [R0.64+UR38], R44, R48, 0xa0",
    ),
    (
        0x000be4000d1008000000002c1c30197fu128,
        "arb464_.S.pola0_ur0",
        "@P1 STG.E.EFL2.256 [R28.64+UR0], R44, R48, 0xa0",
    ),
    (
        0x000be4000d1008ff0000002c1c30197fu128,
        "arb464_.S.pola0_ur255",
        "@P1 STG.E.EFL2.256 [R28.64+URZ], R44, R48, 0xa0",
    ),
    (
        0x000be4000d100826000000001c30197fu128,
        "arb464_.S.pola0_rd00",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R0, R48, 0xa0",
    ),
    (
        0x000be4000d100826000000ff1c30197fu128,
        "arb464_.S.pola0_rd0255",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], RZ, R48, 0xa0",
    ),
    (
        0x000be4000d1008260000002c1c00197fu128,
        "arb464_.S.pola0_rd10",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R0, 0xa0",
    ),
    (
        0x000be4000d1008260000002c1c30097fu128,
        "arb464_.S.pola0_guard0",
        "@P0 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xa0",
    ),
    (
        0x004be4000d1008260000002c1c30197fu128,
        "arb464_.S.pola0_era118",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xa0",
    ),
    (
        0x000be400081008260800002c1c30197fu128,
        "arb464_.S.sweep01",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0x1",
    ),
    (
        0x000be400081008263800002c1c30197fu128,
        "arb464_.S.sweep07",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0x7",
    ),
    (
        0x000be40008100826f800002c1c30197fu128,
        "arb464_.S.sweep1f",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0x1f",
    ),
    (
        0x000be400091008260800002c1c30197fu128,
        "arb464_.S.sweep21",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0x21",
    ),
    (
        0x000be40009100826f800002c1c30197fu128,
        "arb464_.S.sweep3f",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0x3f",
    ),
    (
        0x000be4000810092c320000261c30197fu128,
        "arb464_.U.pol99_b0",
        "@P1 STG.E.EFL2.256 [R28.64+UR44+0x400000], R38, R48, 0x6",
    ),
    (
        0x000be4000810082c060000261c30197eu128,
        "arb464b_era_.LP.lo03_h0",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x3",
    ),
    (
        0x000be4000810082cf60000261c30197eu128,
        "arb464b_era_.LP.lo7b_h0",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x7b",
    ),
    (
        0x000be4000810092c260000261c30197eu128,
        "arb464b_era_.LP.lo13_h1",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x93",
    ),
    (
        0x000be4000810092caa0000261c30197eu128,
        "arb464b_era_.LP.lo55_h1",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0xd5",
    ),
    (
        0x000be4000810082c00000026ff30197eu128,
        "arb464c_.C1.ra255_pol00",
        "@P1 LDG.E.EFL2.256 R44, R48, [UR38], 0x0",
    ),
    (
        0x000be4000810092c32200126ff30197eu128,
        "arb464c_.C1.ra255_imm_pol99",
        "@P1 LDG.E.EFL2.256 R44, R48, [UR38+0x40020], 0x99",
    ),
    (
        0x000be4000810092c320000ffff30197eu128,
        "arb464c_.C1.ra255_ur255_pol99",
        "@P1 LDG.E.EFL2.256 R44, R48, [URZ], 0x99",
    ),
    (
        0x000be4000d1008260000002cff30197fu128,
        "arb464c_.C1.stg_ra255_pola0",
        "@P1 STG.E.EFL2.256 [UR38], R44, R48, 0xa0",
    ),
    (
        0x000be4000d1008ff0000002cff30197fu128,
        "arb464c_.C1.stg_ra255_ur255_pola0",
        "@P1 STG.E.EFL2.256 [URZ], R44, R48, 0xa0",
    ),
    (
        0x000be4000d10082600d13a2cff30197fu128,
        "arb464c_.C1.stg_ra255_imm_pola0",
        "@P1 STG.E.EFL2.256 [UR38+0x1a2740], R44, R48, 0xa0",
    ),
    (
        0x000be4001890092c320000261c30197eu128,
        "arb464c_.C6.b92_pred1",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99, P6",
    ),
    (
        0x010ba2000810092c320000261c30197eu128,
        "arb464b_era_.E.ldg99_nof",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be4000810082cfe0000261c30197eu128,
        "arb464_.L.elide_ff_b72_0",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x7f",
    ),
    (
        0x000be4000d1009260000002c1c30197fu128,
        "arb464_.S.pola0_b72",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xa0",
    ),
    (
        0x000be4000d100a260000002c1c30197fu128,
        "arb464_.S.pola0_b73",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xa0",
    ),
    (
        0x000be4000d100c260000002c1c30197fu128,
        "arb464_.S.pola0_b74",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xa0",
    ),
    (
        0x000be4000d9008260000002c1c30197fu128,
        "arb464_.S.pola0_b87",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xa0",
    ),
    (
        0x000be4000d100a260000002c1c30197fu128,
        "arb464c_.C4.stg_ltc1",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xa0",
    ),
    (
        0x000be4000d100c260000002c1c30197fu128,
        "arb464c_.C4.stg_ltc2",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xa0",
    ),
    (
        0x000be4000d100e260000002c1c30197fu128,
        "arb464c_.C4.stg_ltc3",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xa0",
    ),
];
pub const LAW464_ELIDE: &[(u128, &str, &str)] = &[
    (
        0x000be4000810092cfe0000261c30197eu128,
        "arb464_.L.polff",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38]",
    ),
    (
        0x000be4000f100826f800002c1c30197fu128,
        "arb464_.S.polff",
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48",
    ),
    (
        0x000be4000810092cfe000026ff30197eu128,
        "arb464c_.C1.ra255_polff",
        "@P1 LDG.E.EFL2.256 R44, R48, [UR38]",
    ),
    (
        0x000be4000810092cfe0000ffff30197eu128,
        "arb464c_.C1.ra255_ur255_polff",
        "@P1 LDG.E.EFL2.256 R44, R48, [URZ]",
    ),
    (
        0x000be4000f100826f800002cff30197fu128,
        "arb464c_.C1.stg_ra255_polff",
        "@P1 STG.E.EFL2.256 [UR38], R44, R48",
    ),
    (
        0x000be4000890092cfe0000261c30197eu128,
        "arb464c_.C2.elide_pred1",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], P6",
    ),
    (
        0x000be4000b90092cfe0000261c30197eu128,
        "arb464c_.C2.elide_pred7",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], P0",
    ),
    (
        0x000be4000c10092cfe0000261c30197eu128,
        "arb464c_.C2.elide_pred8",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], !PT",
    ),
    (
        0x000be4000f90092cfe0000261c30197eu128,
        "arb464c_.C2.elide_pred15",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], !P0",
    ),
    (
        0x000be4000890092cfe0040261c30197eu128,
        "arb464c_.C2.elide_pred1_imm",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38+0x800], P6",
    ),
    (
        0x000be4000810092cffffff261c30197eu128,
        "arb464c_.C7.elide_neg",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38+-0x20]",
    ),
    (
        0x000be4000810092cff2345261c30197eu128,
        "arb464c_.C7.elide_upper",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38+-0x1b9760]",
    ),
];
// RIDE468-STAND (F2-iter282, naprawa pin-driftu wykryta gates468 release 2309/1):
// 8 wpisow STAND464 (x4 nogi = 32 asercji) przeszlo z HOLE na tekst vendora
// przez graft 468 (LTC-sel [74:73] lattice; .EFL2.LTC{64,128,256}B.256 pol=0x99
// sel{1,2,3} + aliasy b73/b74 + C4.ldg_ltc*); vendor-x4 potwierdzony nvdisasm
// 13.3.73 raw -b (work/bug469/stand464_drifts.json).
// RIDE474-STAND (F2-iter286, drift wykryty battery474): 6 wpisow C5 STAND464 (x4 nogi = 24 asercje) przeszlo z HOLE na tekst vendora przez graft 474 (U32-sibling b75=0 -- to DOSLOWNIE sondy rejestrujace 474; pol99 elizja 0xff/imm/pred1/ra255/stg). Vendor-x4 AGREE EVERY nvdisasm 13.3.73 raw -b (work/bug474/arb474_snaps_fix.json).
pub const STAND464: &[(u128, &str, &str)] = &[
    (
        0x000be40008100b2c320000261c30197eu128,
        "arb464_.L.pol99_sel1",
        "@P1 LDG.E.EFL2.LTC64B.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be40008100d2c320000261c30197eu128,
        "arb464_.L.pol99_sel2",
        "@P1 LDG.E.EFL2.LTC128B.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be40008100f2c320000261c30197eu128,
        "arb464_.L.pol99_sel3",
        "@P1 LDG.E.EFL2.LTC256B.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be40008100b2c320000261c30197eu128,
        "arb464_.L.pol99_b73",
        "@P1 LDG.E.EFL2.LTC64B.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be40008100d2c320000261c30197eu128,
        "arb464_.L.pol99_b74",
        "@P1 LDG.E.EFL2.LTC128B.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be4000811092c320000261c30197eu128,
        "arb464_.L.pol99_b80",
        "@P1 LDG.E.EFL2.256.MMIO.GPU R44, R48, [R28.64+UR38], 0x99", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000810292c320000261c30197eu128,
        "arb464_.L.pol99_b77",
        "@P1 LDG.E.EFL2.256.CONSTANT.PRIVATE R44, R48, [R28.64+UR38], 0x99", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000800092c320000261c30197eu128,
        "arb464_.L.pol99_b84_0",
        "@P1 LDG.E.EF.EFL2.256 R44, R48, [R28.64+UR38], 0x99", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000810192c320000261c30197eu128,
        "arb464_.L.pol99_b76",
        "@P1 LDG.E.EFL2.256 R44, R48, desc[UR38][R28.64], 0x99",
    ),
    (
        0x000be4000d1108260000002c1c30197fu128,
        "arb464_.S.pola0_b80",
        "@P1 STG.E.EFL2.256.MMIO.GPU [R28.64+UR38], R44, R48, 0xa0", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000d1018260000002c1c30197fu128,
        "arb464c_.C3.stg_b76",
        "@P1 STG.E.EFL2.256 desc[UR38][R28.64], R44, R48, 0xa0",
    ),
    (
        0x000be4000d1028260000002c1c30197fu128,
        "arb464c_.C3.stg_b77",
        "@P1 STG.E.EFL2.256.CONSTANT.PRIVATE [R28.64+UR38], R44, R48, 0xa0", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000d1088260000002c1c30197fu128,
        "arb464c_.C3.stg_b79",
        "@P1 STG.E.EFL2.256.STRONG.SM.PRIVATE [R28.64+UR38], R44, R48, 0xa0", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000810892c320000261c30197eu128,
        "arb464c_.C3.ldg_b79",
        "@P1 LDG.E.EFL2.256.CONSTANT R44, R48, [R28.64+UR38], 0x99", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000810492c320000261c30197eu128,
        "arb464c_.C3.ldg_b78",
        "@P1 LDG.E.EFL2.256.CONSTANT.CTA R44, R48, [R28.64+UR38], 0x99", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000850092c320000261c30197eu128,
        "arb464c_.C3.ldg_b86",
        "HOLE",
    ),
    (
        0x000be40008100b2c320000261c30197eu128,
        "arb464c_.C4.ldg_ltc1",
        "@P1 LDG.E.EFL2.LTC64B.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be40008100d2c320000261c30197eu128,
        "arb464c_.C4.ldg_ltc2",
        "@P1 LDG.E.EFL2.LTC128B.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be40008100f2c320000261c30197eu128,
        "arb464c_.C4.ldg_ltc3",
        "@P1 LDG.E.EFL2.LTC256B.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000be4000810012c320000261c30197eu128,
        "arb464c_.C5.u32_pol99",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.U32+UR38], 0x99", // 474-ride: heal U32 twin (vendor-x4)
    ),
    (
        0x000be4000810012cfe0000261c30197eu128,
        "arb464c_.C5.u32_polff",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.U32+UR38]", // 474-ride: heal U32 twin (vendor-x4)
    ),
    (
        0x000be4000810012c322001261c30197eu128,
        "arb464c_.C5.u32_imm",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.U32+UR38+0x40020], 0x99", // 474-ride: heal U32 twin (vendor-x4)
    ),
    (
        0x000be4000890012c320000261c30197eu128,
        "arb464c_.C5.u32_pred1",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.U32+UR38], 0x99, P6", // 474-ride: heal U32 twin (vendor-x4)
    ),
    (
        0x000be4000810012c32000026ff30197eu128,
        "arb464c_.C5.u32_ra255",
        "@P1 LDG.E.EFL2.256 R44, R48, [UR38], 0x99", // 474-ride: heal U32 twin (vendor-x4)
    ),
    (
        0x000be4000d1000260000002c1c30197fu128,
        "arb464c_.C5.stg_u32_pola0",
        "@P1 STG.E.EFL2.256 [R28.U32+UR38], R44, R48, 0xa0", // 474-ride: heal U32 twin (vendor-x4)
    ),
    (
        0x000be4000812092c320000261c30197eu128,
        "arb464d_.D.ldg_b81",
        "@P1 LDG.E.ENL2.256 R44, R48, [R28.64+UR38], 0x99", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000d1208260000002c1c30197fu128,
        "arb464d_.D.stg_b81",
        "@P1 STG.E.ENL2.256 [R28.64+UR38], R44, R48, 0xa0", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000814092c320000261c30197eu128,
        "arb464d_.D.ldg_b82",
        "@P1 LDG.E.ELL2.256 R44, R48, [R28.64+UR38], 0x99", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000d1408260000002c1c30197fu128,
        "arb464d_.D.stg_b82",
        "@P1 STG.E.ELL2.256 [R28.64+UR38], R44, R48, 0xa0", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000830092c320000261c30197eu128,
        "arb464d_.D.ldg_b85",
        "@P1 LDG.E.LU.EFL2.256 R44, R48, [R28.64+UR38], 0x99", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000d3008260000002c1c30197fu128,
        "arb464d_.D.stg_b85",
        "@P1 STG.E.LU.EFL2.256 [R28.64+UR38], R44, R48, 0xa0", // 465-ride: klasa modsub,
    ),
    (
        0x000be4000d1808260000002c1c30197fu128,
        "arb464d_.D.stg_b83",
        "HOLE",
    ),
    (
        0x000be4000818092c320000261c30197eu128,
        "arb464d_.D.ldg_b83",
        "HOLE",
    ),
    (
        0x000be4000830092c320000261c30197eu128,
        "arb464d_.D.ldg_m85_84",
        "@P1 LDG.E.LU.EFL2.256 R44, R48, [R28.64+UR38], 0x99", // 465-ride: klasa modsub,
    ),
];
pub const KILL464: &[(u128, &str)] = &[
    (
        0x000be4000010092c320000261c30197eu128,
        "arb464_.L.pol99_b91_0",
    ),
    (
        0x000be400051008260000002c1c30197fu128,
        "arb464_.S.pola0_b91_0",
    ),
];
pub const REUSE464: &[(u128, &str, &str, &str)] = &[
    (
        0x100be4000810092c320000261c30197eu128,
        "arb464_.L.pol99_erahi",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99",
        "@P1 LDG.E.EFL2.256 R44.reuse, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x100be4000810092c322001261c30197eu128,
        "arb464_.Cg.ldg37",
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38+0x40020], 0x99",
        "@P1 LDG.E.EFL2.256 R44.reuse, R48, [R28.64+UR38+0x40020], 0x99",
    ),
];
pub const SHADOW464: &[(u128, &str, &str)] = &[(
    0x010ba2000d1008260000002c1c30197fu128,
    "arb464b_era_.E.stga0_nof",
    "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xa0",
)];
pub const MINT464: &[(u128, &str)] = &[
    (
        0x000fc2000810092c322001261c30197eu128,
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38+0x40020], 0x99",
    ),
    (
        0x000fc2000810082650d13a2c1c30197fu128,
        "@P1 STG.E.EFL2.256 [R28.64+UR38+0x1a2740], R44, R48, 0xa",
    ),
    (
        0x000fc2000810092c320000261c30197eu128,
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99",
    ),
    (
        0x000fc2000810082c000000261c30197eu128,
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x0",
    ),
    (
        0x000fc2000c10092c320000261c30197eu128,
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], 0x99, !PT",
    ),
    (
        0x000fc2000810092c330000261c30197eu128,
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38+-0x200000], 0x99",
    ),
    (
        0x000fc2000810092cfe0000261c30197eu128,
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38]",
    ),
    (
        0x000fc2000d1008260000002c1c30197fu128,
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48, 0xa0",
    ),
    (
        0x000fc2000f100826f800002c1c30197fu128,
        "@P1 STG.E.EFL2.256 [R28.64+UR38], R44, R48",
    ),
    (
        0x000fc2000c10092cfe0000261c30197eu128,
        "@P1 LDG.E.EFL2.256 R44, R48, [R28.64+UR38], !PT",
    ),
];
pub const MINT464_ELIDE: &[(u128, &str)] = &[
    (
        0x000fc2000810092c32000026ff30197eu128,
        "@P1 LDG.E.EFL2.256 R44, R48, [UR38], 0x99",
    ),
    (
        0x000fc2000810092cfe000026ff30197eu128,
        "@P1 LDG.E.EFL2.256 R44, R48, [UR38]",
    ),
    (
        0x000fc2000810092c320000ffff30197eu128,
        "@P1 LDG.E.EFL2.256 R44, R48, [URZ], 0x99",
    ),
    (
        0x000fc2000d1008260000002cff30197fu128,
        "@P1 STG.E.EFL2.256 [UR38], R44, R48, 0xa0",
    ),
    (
        0x000fc2000f100826f800002cff30197fu128,
        "@P1 STG.E.EFL2.256 [UR38], R44, R48",
    ),
];

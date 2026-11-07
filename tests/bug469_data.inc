pub const CANON469: &str = "9c0e4cec355119065444f59d0710de372b9d0577";
/// HEAL 203 / ANCH 34 / KILL 11 / MINT 11 (ENC-noentry standing 1) -- gen469pins.py rc=2; werdykty z law/corpus vendor.
pub static HEAL469: &[(u128, &str, &str)] = &[
    (
        0x00000000081e09000000800408047981u128,
        "sm121a",
        "LDG.E R4, [R8.U32+UR4+0x80]",
    ),
    (
        0x000000001c1e09000000800408047981u128,
        "sm121a",
        "LDG.E R4, [R8.64+UR4+0x80]",
    ),
    (
        0x000000000c1e09000000000408047981u128,
        "sm121a",
        "LDG.E R4, [R8.64+UR4]",
    ),
    (
        0x000000000c1e0900ffffff0408047981u128,
        "sm121a",
        "LDG.E R4, [R8.64+UR4+-0x1]",
    ),
    (
        0x000000000c1e09008000000408047981u128,
        "sm121a",
        "LDG.E R4, [R8.64+UR4+-0x800000]",
    ),
    (
        0x000000000c1e09000000800408047981u128,
        "sm121a",
        "LDG.E R4, [R8.64+UR4+0x80]",
    ),
    (
        0x000000000c1e09100000800408047981u128,
        "sm121a",
        "LDG.E.LTC64B R4, [R8.64+UR4+0x80]",
    ),
    (
        0x000000000c1e09200000800408047981u128,
        "sm121a",
        "LDG.E.LTC128B R4, [R8.64+UR4+0x80]",
    ),
    (
        0x000000000c1e09300000800408047981u128,
        "sm121a",
        "LDG.E.LTC256B R4, [R8.64+UR4+0x80]",
    ),
    (
        0x000000000c1e09000000800408ff7981u128,
        "sm121a",
        "LDG.E RZ, [R8.64+UR4+0x80]",
    ),
    (
        0x000000000c1e09000000806408047981u128,
        "sm121a",
        "LDG.E R4, [R8.64+UR100+0x80]",
    ),
    (
        0x000000000c1e0900000080bf08047981u128,
        "sm121a",
        "LDG.E R4, [R8.64+UR191+0x80]",
    ),
    (
        0x000000000c1e0900000080ff08047981u128,
        "sm121a",
        "LDG.E R4, [R8.64+URZ+0x80]",
    ),
    (
        0x000000000c1e09000000803f08047981u128,
        "sm121a",
        "LDG.E R4, [R8.64+UR63+0x80]",
    ),
    (
        0x000000000c1e09000000804008047981u128,
        "sm121a",
        "LDG.E R4, [R8.64+UR64+0x80]",
    ),
    (
        0x00000000081e092000000008028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R2.U32+UR8]",
    ),
    (
        0x000000001c1e092000000008028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R2.64+UR8]",
    ),
    (
        0x000000000c1e092000000008028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R2.64+UR8]",
    ),
    (
        0x000000000c1e0920ffffff08028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R2.64+UR8+-0x1]",
    ),
    (
        0x000000000c1e092080000008028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R2.64+UR8+-0x800000]",
    ),
    (
        0x000000000c1e090000000008028e0981u128,
        "sm121a",
        "@P0 LDG.E R142, [R2.64+UR8]",
    ),
    (
        0x000000000c1e091000000008028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC64B R142, [R2.64+UR8]",
    ),
    (
        0x000000000c1e093000000008028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC256B R142, [R2.64+UR8]",
    ),
    (
        0x000000000c1e092700000008028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R2.64+UR8], P0",
    ),
    (
        0x000000000c1e092800000008028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R2.64+UR8], !PT",
    ),
    (
        0x000000000c06092000000008028e0981u128,
        "sm121a",
        "@P0 LDG.E.EF.LTC128B P3, R142, [R2.64+UR8]",
    ),
    (
        0x000000000c1e09200000000802ff0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B RZ, [R2.64+UR8]",
    ),
    (
        0x000000000c1e092000000064028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R2.64+UR100]",
    ),
    (
        0x000000000c1e0920000000bf028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R2.64+UR191]",
    ),
    (
        0x000000000c1e0920000000ff028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R2.64+URZ]",
    ),
    (
        0x000000000c1e09200000003f028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R2.64+UR63]",
    ),
    (
        0x000000000c1e092000000040028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R2.64+UR64]",
    ),
    (
        0x000000000824e110fe112014410c097eu128,
        "sm121a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R16, R12, [R65.U32+UR20+0x22400]",
    ),
    (
        0x000000000824e110fe112014410cf97eu128,
        "sm121a",
        "@!PT LDG.E.EL.ELL2.256.STRONG.GPU R16, R12, [R65.U32+UR20+0x22400]",
    ),
    (
        0x000000000824e110fe000014410c197eu128,
        "sm121a",
        "@P1 LDG.E.EL.ELL2.256.STRONG.GPU R16, R12, [R65.U32+UR20]",
    ),
    (
        0x000000000824e100fe112014410c197eu128,
        "sm121a",
        "@P1 LDG.E.EL.ELL2.256.STRONG.GPU R0, R12, [R65.U32+UR20+0x22400]",
    ),
    (
        0x000000000824e110fe112014410c197eu128,
        "sm121a",
        "@P1 LDG.E.EL.ELL2.256.STRONG.GPU R16, R12, [R65.U32+UR20+0x22400]",
    ),
    (
        0x000000000824e120fe112014410c197eu128,
        "sm121a",
        "@P1 LDG.E.EL.ELL2.256.STRONG.GPU R32, R12, [R65.U32+UR20+0x22400]",
    ),
    (
        0x000000000824e130fe112014410c197eu128,
        "sm121a",
        "@P1 LDG.E.EL.ELL2.256.STRONG.GPU R48, R12, [R65.U32+UR20+0x22400]",
    ),
    (
        0x000000000824e110fe112014ff0c197eu128,
        "sm121a",
        "@P1 LDG.E.EL.ELL2.256.STRONG.GPU R16, R12, [UR20+0x22400]",
    ),
    (
        0x000000000824e1fffe112014410c197eu128,
        "sm121a",
        "@P1 LDG.E.EL.ELL2.256.STRONG.GPU RZ, R12, [R65.U32+UR20+0x22400]",
    ),
    (
        0x000000000824e110fe1120ff410c197eu128,
        "sm121a",
        "@P1 LDG.E.EL.ELL2.256.STRONG.GPU R16, R12, [R65.U32+URZ+0x22400]",
    ),
    (
        0x000000000824e110fe11203f410c197eu128,
        "sm121a",
        "@P1 LDG.E.EL.ELL2.256.STRONG.GPU R16, R12, [R65.U32+UR63+0x22400]",
    ),
    (
        0x000000000824e110fe112040410c197eu128,
        "sm121a",
        "@P1 LDG.E.EL.ELL2.256.STRONG.GPU R16, R12, [R65.U32+UR64+0x22400]",
    ),
    (
        0x000000000854e114fe0000080a10797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR8]",
    ),
    (
        0x000000000854e114fe0000080a10097eu128,
        "sm121a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR8]",
    ),
    (
        0x000000000854e114fe0000080a10f97eu128,
        "sm121a",
        "@!PT LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR8]",
    ),
    (
        0x000000000854e104fe0000080a10797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R4, R16, [R10.U32+UR8]",
    ),
    (
        0x000000000854e124fe0000080a10797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R36, R16, [R10.U32+UR8]",
    ),
    (
        0x000000000854e134fe0000080a10797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R52, R16, [R10.U32+UR8]",
    ),
    (
        0x000000000854e114fe000008ff10797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [UR8]",
    ),
    (
        0x000000000854e100fe0000080a10797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R0, R16, [R10.U32+UR8]",
    ),
    (
        0x000000000854e1fffe0000080a10797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU RZ, R16, [R10.U32+UR8]",
    ),
    (
        0x000000000854e114fe0000ff0a10797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+URZ]",
    ),
    (
        0x000000000854e114fe00003f0a10797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR63]",
    ),
    (
        0x000000000854e114fe0000400a10797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR64]",
    ),
    (
        0x00000000081609cf05bda44345077981u128,
        "sm121a",
        "LDG.E P3, R7, [R69.U32+UR67+0x5bda4], !P0",
    ),
    (
        0x000000001c1609cf05bda44345077981u128,
        "sm121a",
        "LDG.E P3, R7, [R69.64+UR67+0x5bda4], !P0",
    ),
    (
        0x000000000c1609cf05bda44345077981u128,
        "sm121a",
        "LDG.E P3, R7, [R69.64+UR67+0x5bda4], !P0",
    ),
    (
        0x000000000c1609df05bda44345077981u128,
        "sm121a",
        "LDG.E.LTC64B P3, R7, [R69.64+UR67+0x5bda4], !P0",
    ),
    (
        0x000000000c1609ef05bda44345077981u128,
        "sm121a",
        "LDG.E.LTC128B P3, R7, [R69.64+UR67+0x5bda4], !P0",
    ),
    (
        0x000000000c1609ff05bda44345077981u128,
        "sm121a",
        "LDG.E.LTC256B P3, R7, [R69.64+UR67+0x5bda4], !P0",
    ),
    (
        0x000000000c1609c005bda44345077981u128,
        "sm121a",
        "LDG.E P3, R7, [R69.64+UR67+0x5bda4]",
    ),
    (
        0x000000000c1609c105bda44345077981u128,
        "sm121a",
        "LDG.E P3, R7, [R69.64+UR67+0x5bda4], P6",
    ),
    (
        0x000000000c1609cb05bda44345077981u128,
        "sm121a",
        "LDG.E P3, R7, [R69.64+UR67+0x5bda4], !P4",
    ),
    (
        0x000000000c1609c705bda44345077981u128,
        "sm121a",
        "LDG.E P3, R7, [R69.64+UR67+0x5bda4], P0",
    ),
    (
        0x000000000c1609c805bda44345077981u128,
        "sm121a",
        "LDG.E P3, R7, [R69.64+UR67+0x5bda4], !PT",
    ),
    (
        0x000000000c0009cf05bda44345077981u128,
        "sm121a",
        "LDG.E.EF P0, R7, [R69.64+UR67+0x5bda4], !P0",
    ),
    (
        0x000000000c0009ef05bda44345077981u128,
        "sm121a",
        "LDG.E.EF.LTC128B P0, R7, [R69.64+UR67+0x5bda4], !P0",
    ),
    (
        0x000000000c0009ff05bda44345077981u128,
        "sm121a",
        "LDG.E.EF.LTC256B P0, R7, [R69.64+UR67+0x5bda4], !P0",
    ),
    (
        0x000000000c0209cf05bda44345077981u128,
        "sm121a",
        "LDG.E.EF P1, R7, [R69.64+UR67+0x5bda4], !P0",
    ),
    (
        0x000000000c0209df05bda44345077981u128,
        "sm121a",
        "LDG.E.EF.LTC64B P1, R7, [R69.64+UR67+0x5bda4], !P0",
    ),
    (
        0x000000000c0c09cf05bda44345077981u128,
        "sm121a",
        "LDG.E.EF P6, R7, [R69.64+UR67+0x5bda4], !P0",
    ),
    (
        0x000000000c1e09800887b20668e3f981u128,
        "sm121a",
        "@!PT LDG.E R227, [R104.64+UR6+0x887b2]",
    ),
    (
        0x000000000c1e098f0887b20668e3f981u128,
        "sm121a",
        "@!PT LDG.E R227, [R104.64+UR6+0x887b2], !P0",
    ),
    (
        0x000000000c1e09870887b20668e3f981u128,
        "sm121a",
        "@!PT LDG.E R227, [R104.64+UR6+0x887b2], P0",
    ),
    (
        0x000000000c1e09880887b20668e3f981u128,
        "sm121a",
        "@!PT LDG.E R227, [R104.64+UR6+0x887b2], !PT",
    ),
    (
        0x000000000c0009870887b20668e3f981u128,
        "sm121a",
        "@!PT LDG.E.EF P0, R227, [R104.64+UR6+0x887b2], P0",
    ),
    (
        0x000000000c0609870887b20668e3f981u128,
        "sm121a",
        "@!PT LDG.E.EF P3, R227, [R104.64+UR6+0x887b2], P0",
    ),
    (
        0x00000000081e09fb0b3940e277fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC256B R251, [R119.U32+UR226+0xb3940], !P4",
    ),
    (
        0x000000001c1e09fb0b3940e277fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC256B R251, [R119.64+UR226+0xb3940], !P4",
    ),
    (
        0x000000000c1e09fb000000e277fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC256B R251, [R119.64+UR226], !P4",
    ),
    (
        0x000000000c1e09fbffffffe277fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC256B R251, [R119.64+UR226+-0x1], !P4",
    ),
    (
        0x000000000c1e09fb800000e277fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC256B R251, [R119.64+UR226+-0x800000], !P4",
    ),
    (
        0x000000000c1e09cb0b3940e277fb8981u128,
        "sm121a",
        "@!P0 LDG.E R251, [R119.64+UR226+0xb3940], !P4",
    ),
    (
        0x000000000c1e09db0b3940e277fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC64B R251, [R119.64+UR226+0xb3940], !P4",
    ),
    (
        0x000000000c1e09eb0b3940e277fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC128B R251, [R119.64+UR226+0xb3940], !P4",
    ),
    (
        0x000000000c1e09fb0b3940e277fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC256B R251, [R119.64+UR226+0xb3940], !P4",
    ),
    (
        0x000000000c1e09fb0b3940e277ff8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC256B RZ, [R119.64+UR226+0xb3940], !P4",
    ),
    (
        0x000000000c1e09fb0b39406477fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC256B R251, [R119.64+UR100+0xb3940], !P4",
    ),
    (
        0x000000000c1e09fb0b3940bf77fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC256B R251, [R119.64+UR191+0xb3940], !P4",
    ),
    (
        0x000000000c1e09fb0b3940ff77fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC256B R251, [R119.64+URZ+0xb3940], !P4",
    ),
    (
        0x000000000c1e09fb0b39403f77fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC256B R251, [R119.64+UR63+0xb3940], !P4",
    ),
    (
        0x000000000c1e09fb0b39404077fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC256B R251, [R119.64+UR64+0xb3940], !P4",
    ),
    (
        0x00000000081e090000000004ff007981u128,
        "sm121a",
        "LDG.E R0, [RZ.U32+UR4]",
    ),
    (
        0x00000000081e0900ffffff04ff007981u128,
        "sm121a",
        "LDG.E R0, [RZ.U32+UR4+-0x1]",
    ),
    (
        0x00000000081e090080000004ff007981u128,
        "sm121a",
        "LDG.E R0, [RZ.U32+UR4+-0x800000]",
    ),
    (
        0x00000000081e091000000004ff007981u128,
        "sm121a",
        "LDG.E.LTC64B R0, [RZ.U32+UR4]",
    ),
    (
        0x00000000081e092000000004ff007981u128,
        "sm121a",
        "LDG.E.LTC128B R0, [RZ.U32+UR4]",
    ),
    (
        0x00000000081e093000000004ff007981u128,
        "sm121a",
        "LDG.E.LTC256B R0, [RZ.U32+UR4]",
    ),
    (
        0x00000000081e090000000004ffff7981u128,
        "sm121a",
        "LDG.E RZ, [RZ.U32+UR4]",
    ),
    (
        0x00000000081e090000000064ff007981u128,
        "sm121a",
        "LDG.E R0, [RZ.U32+UR100]",
    ),
    (
        0x00000000081e0900000000bfff007981u128,
        "sm121a",
        "LDG.E R0, [RZ.U32+UR191]",
    ),
    (
        0x00000000081e0900000000ffff007981u128,
        "sm121a",
        "LDG.E R0, [RZ.U32+URZ]",
    ),
    (
        0x00000000081e09000000003fff007981u128,
        "sm121a",
        "LDG.E R0, [RZ.U32+UR63]",
    ),
    (
        0x00000000081e090000000040ff007981u128,
        "sm121a",
        "LDG.E R0, [RZ.U32+UR64]",
    ),
    (
        0x000000000824e114fe0000041824797eu128,
        "sm121a",
        "LDG.E.EL.ELL2.256.STRONG.GPU R20, R36, [R24.U32+UR4]",
    ),
    (
        0x000000000824e124fe0000041828797eu128,
        "sm121a",
        "LDG.E.EL.ELL2.256.STRONG.GPU R36, R40, [R24.U32+UR4]",
    ),
    (
        0x000000000824e128fe0000041824797eu128,
        "sm121a",
        "LDG.E.EL.ELL2.256.STRONG.GPU R40, R36, [R24.U32+UR4]",
    ),
    (
        0x000000000824e128fe000004182c797eu128,
        "sm121a",
        "LDG.E.EL.ELL2.256.STRONG.GPU R40, R44, [R24.U32+UR4]",
    ),
    (
        0x000000000824e128fe0000061824797eu128,
        "sm121a",
        "LDG.E.EL.ELL2.256.STRONG.GPU R40, R36, [R24.U32+UR6]",
    ),
    (
        0x000000000824e12afe0000041828797eu128,
        "sm121a",
        "LDG.E.EL.ELL2.256.STRONG.GPU R42, R40, [R24.U32+UR4]",
    ),
    (
        0x000000000824e130fe000004182c697eu128,
        "sm121a",
        "@P6 LDG.E.EL.ELL2.256.STRONG.GPU R48, R44, [R24.U32+UR4]",
    ),
    (
        0x000000000824e130fe0000061a34797eu128,
        "sm121a",
        "LDG.E.EL.ELL2.256.STRONG.GPU R48, R52, [R26.U32+UR6]",
    ),
    (
        0x000000000824e150fe000004184c397eu128,
        "sm121a",
        "@P3 LDG.E.EL.ELL2.256.STRONG.GPU R80, R76, [R24.U32+UR4]",
    ),
    (
        0x000000000824e150fe000004184c497eu128,
        "sm121a",
        "@P4 LDG.E.EL.ELL2.256.STRONG.GPU R80, R76, [R24.U32+UR4]",
    ),
    (
        0x000000000824e150fe000004184c697eu128,
        "sm121a",
        "@P6 LDG.E.EL.ELL2.256.STRONG.GPU R80, R76, [R24.U32+UR4]",
    ),
    (
        0x000000000824e150fe000004184ce97eu128,
        "sm121a",
        "@!P6 LDG.E.EL.ELL2.256.STRONG.GPU R80, R76, [R24.U32+UR4]",
    ),
    (
        0x000000000824e178fe0000041a74297eu128,
        "sm121a",
        "@P2 LDG.E.EL.ELL2.256.STRONG.GPU R120, R116, [R26.U32+UR4]",
    ),
    (
        0x000000000824e178fe0000041a74797eu128,
        "sm121a",
        "LDG.E.EL.ELL2.256.STRONG.GPU R120, R116, [R26.U32+UR4]",
    ),
    (
        0x000000000824e188fe1120141a84797eu128,
        "sm121a",
        "LDG.E.EL.ELL2.256.STRONG.GPU R136, R132, [R26.U32+UR20+0x22400]",
    ),
    (
        0x000000000824e190fe1121141a8c797eu128,
        "sm121a",
        "LDG.E.EL.ELL2.256.STRONG.GPU R144, R140, [R26.U32+UR20+0x22420]",
    ),
    (
        0x000000000824e198fe1122141a94797eu128,
        "sm121a",
        "LDG.E.EL.ELL2.256.STRONG.GPU R152, R148, [R26.U32+UR20+0x22440]",
    ),
    (
        0x000000000824e1a0fe1123141a9c797eu128,
        "sm121a",
        "LDG.E.EL.ELL2.256.STRONG.GPU R160, R156, [R26.U32+UR20+0x22460]",
    ),
    (
        0x000000000824e1f8fe00000419f4797eu128,
        "sm121a",
        "LDG.E.EL.ELL2.256.STRONG.GPU R248, R244, [R25.U32+UR4]",
    ),
    (
        0x000000000854e11cfe0000080a18797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R28, R24, [R10.U32+UR8]",
    ),
    (
        0x000000000854e128fe000006182c797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R40, R44, [R24.U32+UR6]",
    ),
    (
        0x000000000854e12cfe0000080a28097eu128,
        "sm121a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R44, R40, [R10.U32+UR8]",
    ),
    (
        0x000000000854e12cfe0000080a28797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R44, R40, [R10.U32+UR8]",
    ),
    (
        0x000000000854e134fe0000080a30097eu128,
        "sm121a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R52, R48, [R10.U32+UR8]",
    ),
    (
        0x000000000854e134fe0000080a30797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R52, R48, [R10.U32+UR8]",
    ),
    (
        0x000000000854e198fe0000041894797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R152, R148, [R24.U32+UR4]",
    ),
    (
        0x000000000854e1a0fe000004189c797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R160, R156, [R24.U32+UR4]",
    ),
    (
        0x000000000854e1a8fe00000418a4797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R168, R164, [R24.U32+UR4]",
    ),
    (
        0x000000000854e1b0fe00000418ac797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R176, R172, [R24.U32+UR4]",
    ),
    (
        0x000000000854e1b8fe00000418b4797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R184, R180, [R24.U32+UR4]",
    ),
    (
        0x000000000854e1c0fe00000418bc797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R192, R188, [R24.U32+UR4]",
    ),
    (
        0x000000000854e1c8fe00000418c4797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R200, R196, [R24.U32+UR4]",
    ),
    (
        0x000000000854e1d0fe00000418cc797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R208, R204, [R24.U32+UR4]",
    ),
    (
        0x000000000854e1d8fe00000418d4797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R216, R212, [R24.U32+UR4]",
    ),
    (
        0x000000000854e1e0fe00000418dc797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R224, R220, [R24.U32+UR4]",
    ),
    (
        0x000000000854e1e8fe00000418e4797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R232, R228, [R24.U32+UR4]",
    ),
    (
        0x000000000854e1f0fe00000418ec797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R240, R236, [R24.U32+UR4]",
    ),
    (
        0x000000000c1e0900000080040a067981u128,
        "sm121a",
        "LDG.E R6, [R10.64+UR4+0x80]",
    ),
    (
        0x000000000c1e09000000800608057981u128,
        "sm121a",
        "LDG.E R5, [R8.64+UR6+0x80]",
    ),
    (
        0x000000000c1e0900000080060a047981u128,
        "sm121a",
        "LDG.E R4, [R10.64+UR6+0x80]",
    ),
    (
        0x000000000c1e0900000080060c087981u128,
        "sm121a",
        "LDG.E R8, [R12.64+UR6+0x80]",
    ),
    (
        0x000000000c1e0900000080060c0a7981u128,
        "sm121a",
        "LDG.E R10, [R12.64+UR6+0x80]",
    ),
    (
        0x000000000c1e0900000080060e057981u128,
        "sm121a",
        "LDG.E R5, [R14.64+UR6+0x80]",
    ),
    (
        0x000000000c1e0900000080060e077981u128,
        "sm121a",
        "LDG.E R7, [R14.64+UR6+0x80]",
    ),
    (
        0x000000000c1e09000000800808077981u128,
        "sm121a",
        "LDG.E R7, [R8.64+UR8+0x80]",
    ),
    (
        0x000000000c1e0900000080080a087981u128,
        "sm121a",
        "LDG.E R8, [R10.64+UR8+0x80]",
    ),
    (
        0x000000000c1e0900000080080e097981u128,
        "sm121a",
        "LDG.E R9, [R14.64+UR8+0x80]",
    ),
    (
        0x000000000c1e09000000800a0c057981u128,
        "sm121a",
        "LDG.E R5, [R12.64+UR10+0x80]",
    ),
    (
        0x000000000c1e09000000800a0c077981u128,
        "sm121a",
        "LDG.E R7, [R12.64+UR10+0x80]",
    ),
    (
        0x000000000c1e09000000800c0c097981u128,
        "sm121a",
        "LDG.E R9, [R12.64+UR12+0x80]",
    ),
    (
        0x000000000c1e09000000800c0c0a7981u128,
        "sm121a",
        "LDG.E R10, [R12.64+UR12+0x80]",
    ),
    (
        0x000000000c1e09200000000802920981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R146, [R2.64+UR8]",
    ),
    (
        0x000000000c1e092000000008048e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R4.64+UR8]",
    ),
    (
        0x000000000c1e092000000008048f0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R143, [R4.64+UR8]",
    ),
    (
        0x000000000c1e09200000000804920981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R146, [R4.64+UR8]",
    ),
    (
        0x000000000c1e09200000000804930981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R147, [R4.64+UR8]",
    ),
    (
        0x000000000c1e092000000008068e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R6.64+UR8]",
    ),
    (
        0x000000000c1e092000000008068f0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R143, [R6.64+UR8]",
    ),
    (
        0x000000000c1e09200000000808920981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R146, [R8.64+UR8]",
    ),
    (
        0x000000000c1e09200000000808930981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R147, [R8.64+UR8]",
    ),
    (
        0x000000000c1e0920000000080a920981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R146, [R10.64+UR8]",
    ),
    (
        0x000000000c1e0920000000080a930981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R147, [R10.64+UR8]",
    ),
    (
        0x000000000c1e092000008008028d0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R141, [R2.64+UR8+0x80]",
    ),
    (
        0x000000000c1e09200000800802910981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R145, [R2.64+UR8+0x80]",
    ),
    (
        0x000000000c1e092000008008048d0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R141, [R4.64+UR8+0x80]",
    ),
    (
        0x000000000c1e092000008008048e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R4.64+UR8+0x80]",
    ),
    (
        0x000000000c1e092000008008048e1981u128,
        "sm121a",
        "@P1 LDG.E.LTC128B R142, [R4.64+UR8+0x80]",
    ),
    (
        0x000000000c1e09200000800804910981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R145, [R4.64+UR8+0x80]",
    ),
    (
        0x000000000c1e09200000800804920981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R146, [R4.64+UR8+0x80]",
    ),
    (
        0x000000000c1e092000008008068d0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R141, [R6.64+UR8+0x80]",
    ),
    (
        0x000000000c1e092000008008068e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, [R6.64+UR8+0x80]",
    ),
    (
        0x000000000c1e09200000800808910981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R145, [R8.64+UR8+0x80]",
    ),
    (
        0x000000000c1e09200000800808920981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R146, [R8.64+UR8+0x80]",
    ),
    (
        0x000000000c1e0920000080080a910981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R145, [R10.64+UR8+0x80]",
    ),
    (
        0x000000000c1e0920000080080a920981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R146, [R10.64+UR8+0x80]",
    ),
    (
        0x000000000c1e09200001000802870981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R135, [R2.64+UR8+0x100]",
    ),
    (
        0x000000000c1e09200001000802900981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R144, [R2.64+UR8+0x100]",
    ),
    (
        0x000000000c1e09200001000804870981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R135, [R4.64+UR8+0x100]",
    ),
    (
        0x000000000c1e092000010008048d0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R141, [R4.64+UR8+0x100]",
    ),
    (
        0x000000000c1e09200001000804900981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R144, [R4.64+UR8+0x100]",
    ),
    (
        0x000000000c1e09200001000804910981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R145, [R4.64+UR8+0x100]",
    ),
    (
        0x000000000c1e09200001000806870981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R135, [R6.64+UR8+0x100]",
    ),
    (
        0x000000000c1e092000010008068d0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R141, [R6.64+UR8+0x100]",
    ),
    (
        0x000000000c1e09200001000808900981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R144, [R8.64+UR8+0x100]",
    ),
    (
        0x000000000c1e09200001000808910981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R145, [R8.64+UR8+0x100]",
    ),
    (
        0x000000000c1e0920000100080a900981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R144, [R10.64+UR8+0x100]",
    ),
    (
        0x000000000c1e0920000100080a910981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R145, [R10.64+UR8+0x100]",
    ),
    (
        0x000000000c1e09200001800802810981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R129, [R2.64+UR8+0x180]",
    ),
    (
        0x000000000c1e092000018008028f0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R143, [R2.64+UR8+0x180]",
    ),
    (
        0x000000000c1e09200001800804810981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R129, [R4.64+UR8+0x180]",
    ),
    (
        0x000000000c1e092000018008048f0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R143, [R4.64+UR8+0x180]",
    ),
    (
        0x000000000c1e09200001800804900981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R144, [R4.64+UR8+0x180]",
    ),
    (
        0x000000000c1e09200001800806810981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R129, [R6.64+UR8+0x180]",
    ),
    (
        0x000000000c1e092000018008088f0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R143, [R8.64+UR8+0x180]",
    ),
    (
        0x000000000c1e09200001800808900981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R144, [R8.64+UR8+0x180]",
    ),
    (
        0x000000000c1e0920000180080a8f0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R143, [R10.64+UR8+0x180]",
    ),
    (
        0x000000000c1e0920000180080a900981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R144, [R10.64+UR8+0x180]",
    ),
];
/// (word, leg, cold_tekst; "" = cold HOLE -- pre==post pinned przez gen na poziomie cold)
// RIDE474-ANCH (F2-iter286): 2 wpisy ANCH469 (121a, cold-HOLE z e7d4a91f) przeszly na tekst vendora przez graft 474 (LDG.E.EL.ELL2.256.STRONG.GPU U32; era-mutanty 0x0c24/0x1824 = klasa 449-era-nosnik; vendor-x4 AGREE EVERY work/bug474/arb474_snaps_fix.json).
pub static ANCH469: &[(u128, &str, &str)] = &[
    (0x000000000c1e090000008004ff047981u128, "sm121a", ""),
    (0x000000000c1e0d000000800408047981u128, "sm121a", ""),
    (
        0x000000000c1e19000000800408047981u128,
        "sm121a",
        "LDG.E R4, desc[UR4][R8.64+0x80]",
    ),
    (0x000000000c1e092000000008ff8e0981u128, "sm121a", ""),
    (0x000000000c1e0d2000000008028e0981u128, "sm121a", ""),
    (
        0x000000000c1e192000000008028e0981u128,
        "sm121a",
        "@P0 LDG.E.LTC128B R142, desc[UR8][R2.64]",
    ),
    (
        0x000000001824e110fe112014410c197eu128,
        "sm121a",
        "@P1 LDG.E.EL.ELL2.256.STRONG.GPU R16, R12, [R65.U32+UR20+0x22400]", // 474-ride: heal 121a U32 (vendor-x4)
    ),
    (
        0x000000000824e910fe112014410c197eu128,
        "sm121a",
        "@P1 LDG.E.EL.ELL2.256.STRONG.GPU R16, R12, [R65.64+UR20+0x22400]",
    ),
    (
        0x000000000c24e110fe112014410c197eu128,
        "sm121a",
        "@P1 LDG.E.EL.ELL2.256.STRONG.GPU R16, R12, [R65.U32+UR20+0x22400], !PT", // 474-ride: heal 121a U32 (vendor-x4)
    ),
    (
        0x000000000854e914ff2345080a10797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.64+UR8+-0x1b9760]",
    ), // 476-ride-B (F2-iter299): heal 476a po grafte (vendor x4 AGREE EVERY, nvdisasm 13.3.73; work/bug476/arb476_ride.json),),
    (
        0x000000000854e914fe0000080a10797eu128,
        "sm121a",
        "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.64+UR8]",
    ), // 476-ride-B (F2-iter299): heal 476a po grafte (vendor x4 AGREE EVERY, nvdisasm 13.3.73; work/bug476/arb476_ride.json),),
    (0x000000000c54e914fe0000080a10797eu128, "sm121a", "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.64+UR8], !PT"),
    (0x000000000874e114fe0000080a10797eu128, "sm121a", ""),
    (0x0000000008d4e114fe0000080a10797eu128, "sm121a", "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR8], P6"),
    (0x000000000954e114fe0000080a10797eu128, "sm121a", "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR8], P5"),
    (0x000000000a54e114fe0000080a10797eu128, "sm121a", "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR8], P3"),
    (0x000000000c54e114fe0000080a10797eu128, "sm121a", "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR8], !PT"),
    (0x000000001854e114fe0000080a10797eu128, "sm121a", "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR8]"),
    (0x0000000009d4e114fe0000080a10797eu128, "sm121a", "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR8], P4"),
    (0x000000000b54e114fe0000080a10797eu128, "sm121a", "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR8], P1"),
    (0x000000000d54e114fe0000080a10797eu128, "sm121a", "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR8], !P5"),
    (0x000000000e54e114fe0000080a10797eu128, "sm121a", "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR8], !P3"),
    (0x000000000f54e114fe0000080a10797eu128, "sm121a", "LDG.E.NA.ELL2.256.STRONG.GPU R20, R16, [R10.U32+UR8], !P1"),
    (0x000000000840e114fe0000080a10797eu128, "sm121a", ""),
    (0x00000000be4000c1000000887b202981u128, "sm121a", ""),
    (0x00000000be4000c1e0987088ff202981u128, "sm121a", ""),
    (0x00000000be4000c1e09870887bff2981u128, "sm121a", ""),
    (0x00000000be4000c1e09870ff7b202981u128, "sm121a", ""),
    (0x000000000c1e09fb0b3940e2fffb8981u128, "sm121a", ""),
    (0x000000000c1e0dfb0b3940e277fb8981u128, "sm121a", ""),
    (
        0x000000000c1e19fb0b3940e277fb8981u128,
        "sm121a",
        "@!P0 LDG.E.LTC256B R251, desc[UR226][R119.64+0xb3940]",
    ),
    (0x000000000c1e090000000004ff007981u128, "sm121a", ""),
    (0x00000000081e0d0000000004ff007981u128, "sm121a", ""),
    (
        0x00000000181e090000000004ff007981u128,
        "sm121a",
        "LDG.E R0, [RZ.U32+UR4]",
    ),
];
pub static KILL469: &[(u128, &str)] = &[
    (0x00000000041e09000000800408047981u128, "sm121a"),
    (0x00000000041e092000000008028e0981u128, "sm121a"),
    (0x000000000024e110fe112014410c197eu128, "sm121a"),
    (0x000000000824f110fe112014410c197eu128, "sm121a"),
    (0x000000000054e114fe0000080a10797eu128, "sm121a"),
    (0x000000000854f114fe0000080a10797eu128, "sm121a"),
    (0x00000000041609cf05bda44345077981u128, "sm121a"),
    (0x000000000c0e09cf05bda44345077981u128, "sm121a"),
    (0x00000000041e09fb0b3940e277fb8981u128, "sm121a"),
    (0x00000000001e090000000004ff007981u128, "sm121a"),
    (0x00000000081e190000000004ff007981u128, "sm121a"),
];
pub static MINT469: &[(&str, &str)] = &[
    ("LDG.E R44, [R29.64+UR38+0x80]", "sm121a"),
    ("LDG.E.LTC128B R44, [R29.64+UR8]", "sm121a"),
    ("LDG.E.LTC256B R44, [R29.64+UR226]", "sm121a"),
    ("LDG.E R0, [RZ.U32+UR4]", "sm121a"),
    ("LDG.E R44, [R29.64+UR38+0x80], P1", "sm121a"),
    ("LDG.E.LTC256B R44, [R29.64+UR226+0xb3940], !P4", "sm121a"),
    ("LDG.E P3, R44, [R29.64+UR38+0x5bda4], !P0", "sm121a"),
    ("LDG.E.EF P3, R44, [R29.64+UR6+0x887b2], P0", "sm121a"),
    ("LDG.E.EF.LTC128B P3, R44, [R29.64+UR8], P0", "sm121a"),
    (
        "LDG.E.EL.ELL2.256.STRONG.GPU R44, R48, [R29.U32+UR38+0x22400]",
        "sm121a",
    ),
    (
        "LDG.E.NA.ELL2.256.STRONG.GPU R44, R48, [R29.U32+UR8]",
        "sm121a",
    ),
];
pub static ENCTAIL469: &[(&str, &str)] = &[("LDG.E.LTC64B R4, [R29.U32+UR8+0x100]", "sm121a")];
pub static CENSUS469: &[(&str, usize)] = &[
    ("sm100a", 14925), // 2026-11-06 T-11 (canonical 8aa5f34): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-06 T-10 (canonical 315bffa): BRA sm103a/sm100a 14912 -> 14913 forms, 22363 -> 22420 variants; sm120 BRX/BRXU/RET + the audit batches 16045 -> 15935 forms, 26646 -> 26562 variants // 2026-11-06 T-8 (LEA family rebuilt from measurement, tools/probes/re_sm120_lea.py: sm120 56 keys / 100 rows -> 24 keys / 36 rows, sm103a / sm100a 18 keys / 21 rows -> 24 / 36): sm120 16097 -> 16065 forms, 26663 -> 26599 variants; sm103a / sm100a 14906 -> 14912, 22348 -> 22363 // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // RIDE476 (F2-iter299, canonical c88778e): +11 -> 14879 // RIDE475R3 (F2-iter289, INC-289e): +3/+3/+2/+2 -> 14868/14868/16005/23825 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: ("sm100a", 13721) RIDE474-pre (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468)
    ("sm103a", 14926), // 2026-11-07 T-14 (canonical 8aa5f34: the sm103a MUFU packed-half lanes measured, MUFU_R_FI_FI new): sm103a forms 14925 -> 14926, variants 22439 -> 22445 // 2026-11-06 T-11 (canonical 8aa5f34): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-06 T-10 (canonical 315bffa): BRA sm103a/sm100a 14912 -> 14913 forms, 22363 -> 22420 variants; sm120 BRX/BRXU/RET + the audit batches 16045 -> 15935 forms, 26646 -> 26562 variants // 2026-11-06 T-8 (LEA family rebuilt from measurement, tools/probes/re_sm120_lea.py: sm120 56 keys / 100 rows -> 24 keys / 36 rows, sm103a / sm100a 18 keys / 21 rows -> 24 / 36): sm120 16097 -> 16065 forms, 26663 -> 26599 variants; sm103a / sm100a 14906 -> 14912, 22348 -> 22363 // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // RIDE476 (F2-iter299, canonical c88778e): +11 -> 14879 // RIDE475R3 (F2-iter289, INC-289e): +3/+3/+2/+2 -> 14868/14868/16005/23825 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: ("sm103a", 13721) RIDE474-pre (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468)
    ("sm120", 14805), // re-pinned 2026-11-07 (G batch 10: LDG.256 dARI measured whole) // G batch 9 FSET / FSEL / FCHK 2026-11-07 // G batch 8 conversions 2026-11-07 // G batch 7 uniform FP32 ALU 2026-11-07 // G batch 6 FP32 ALU 2026-11-07 // 2026-11-06 G (canonical 8aa5f34): UFSETP measured, 6 junk keys retired as aliases: sm120 15840 -> 15834 forms, 26442 -> 26341 variants // 2026-11-06 G (canonical 8aa5f34): PLOP3 / P2R / R2P measured, 10 junk keys retired as aliases, R2P_II_R added: sm120 15849 -> 15840 forms, 26451 -> 26442 variants // 2026-11-06 G (canonical 8aa5f34): FSETP / DSETP measured, 112 keys retired (11 aliases): sm120 15961 -> 15849 forms, 26662 -> 26451 variants // 2026-11-06 G (canonical 8aa5f34): HSETP2 measured, 3 dotted keys retired: sm120 15964 -> 15961 forms, 26598 -> 26595 variants // 2026-11-06 T-11 (canonical 8aa5f34): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-06 T-10 IMMA family (canonical c258f8a): sm120 15935 -> 15953 forms, 26562 -> 26580 variants // 2026-11-06 T-10 (canonical 315bffa): BRA sm103a/sm100a 14912 -> 14913 forms, 22363 -> 22420 variants; sm120 BRX/BRXU/RET + the audit batches 16045 -> 15935 forms, 26646 -> 26562 variants // 2026-11-06 T-9 (BRA family rebuilt from measurement, tools/probes/re_sm120_bra.py: sm120 15 keys / 31 rows -> 6 keys / 66 rows, canonical b75cc20): sm120 keys 16054 -> 16045, variants 26611 -> 26646, loader 16074 -> 16068 (+3 key aliases) // 2026-11-06 T-8 ATOMS_R_ARURI_R rebuilt (36 groups) + 9 junk keys retired (canonical 5222c58): sm120 keys 16063 -> 16054, variants 26596 -> 26612 // 2026-11-06 T-8 F2FP twins retired (canonical 09a7141): sm120 keys 16065 -> 16063, variants 26599 -> 26596, claim_forbid rows 7016 -> 7013 // 2026-11-06 T-8 (LEA family rebuilt from measurement, tools/probes/re_sm120_lea.py: sm120 56 keys / 100 rows -> 24 keys / 36 rows, sm103a / sm100a 18 keys / 21 rows -> 24 / 36): sm120 16097 -> 16065 forms, 26663 -> 26599 variants; sm103a / sm100a 14906 -> 14912, 22348 -> 22363 // 2026-11-06 T-7 (coldface's B300-1/2/3/4 rows taken + the UTMALDG plain dims + the IADD3.X carry repair, provenance re-stamp, canonical 135068e): sm120 keys 16098 -> 16097 (-2 UTMALDG dotted era keys), variants 26660 -> 26663, loader 16117; sm103a / sm100a keys 14904 -> 14906 (+IADD.XOR, +LEA.HI.X), variants 22342 -> 22348 // 2026-11-06 T-7 (ATOMG .EL 64-bit-base rows ATOMG.E.{ADD,OR}.EL.STRONG.GPU_P_R_ARURI64_R on sm120 / sm103a / sm100a, canonical 582dfd8): sm120 keys 16096 -> 16098, variants 26658 -> 26660, loader 16118; sm103a / sm100a keys 14902 -> 14904, variants 22340 -> 22342 // 2026-11-06 T-7 (HADD2 register form rebuilt from measurement, canonical ac04a77): sm120 keys 16103 -> 16096 (-7: HADD2.F32_R_R_R, HADD2.BF16_V2_R_R_R and 5 register-opcode junk rows), variants 26656 -> 26658; loader sm120 16116 // 2026-11-05 T-6 item 2 (T-5's SHF + LDTM/STTM rows on the wave-11 tables, canonical 377b507): sm120 keys 16143 -> 16103 (-40 dotted SHF), variants 26612 -> 26656; sm100a/sm103a variants 22199 -> 22340; loader sm120 16123 // 2026-11-04 (canonical 6f11f6b): -20 / -10 era keys -> _meta.key_aliases, +LDL_R_ARURI (sm120) // 2026-11-03 dynamic-audit batch 1 (canonical 6619782): -12 sm120 keys / -22 variants (FSETP_P_P_L_FI_P, FSETP_P_P_L_L_P, F2FP.F16.F32.PACK_AB_P_R_R_R, HMMA *_P0_* rows, LOP3.LUT_P_R_R_R_R_II_P, QMMA.16816.F16.E4M3.E4M3_P_R_R_R_R: their words are other instructions for nvdisasm) = 16126 forms, 20883 variants; LDGSTS base field 8 bits, LDC/LDCU reuse field removed; hygiene pass (canonical 64eaa21) cleared the baked control bits, counts unchanged. // 2026-11-02 HMUL2 imm / LDSM FP4-FP6 / PRMT UR / ARRIVES.LDGSTSBAR / UTMASTG dims (canonical 77a3dfa): +3 sm120 keys (HMUL2_R_R_FI_FI, PRMT_R_R_UR_R, ARRIVES_ARURI), +30 LDSM_R_ARI and +4 UTMASTG groups (variants 20850 -> 20905) = 16138. // 2026-10-29 ATOMS [R+UR+imm] / STSM.8.MT168 / UBLKPF.L2 (canonical 137cd34): +2 sm120 keys (UBLKPF_AURI_UR, UBLKPF_AURI_UR_II), +3 STSM_ARI_R groups, ATOMS_R_ARURI_R MAX,S32 re-measured (variants 20845 -> 20850) = 16135. // 2026-10-28 F2FP.BF16.E8.UNPACK_B_R_R (canonical f1e02b3): +1 sm120 key (UE8M0 -> BF16x2 unpack) = 16133 // 2026-10-23 CS2UR (canonical 59561b2): -1 sm120 key (junk CS2UR_UR_II removed; CS2UR_UR_L gains the plain group) = 16132 // RIDE459a (F2-iter301, canonical 96372cb): -1 sm120 key (459a junk-mg "" / 64 DELETE -> key-del UR_II_..._UP_UP) -> forms 16015, variants -4=17631; sm121a variants -4=26385; cf stoi // RIDE476 (F2-iter299, canonical c88778e): +11 -> 16016 // RIDE475R3 (F2-iter289, INC-289e): +3/+3/+2/+2 -> 14868/14868/16005/23825 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: ("sm120", 14859) RIDE474-pre (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468)
    ("sm121a", 23860), // 2026-11-06 T-11 (canonical 8aa5f34): the IDP family measured whole (sm120 15953 -> 15964 forms, 26580 -> 26598 variants; sm103a / sm100a 14913 -> 14925, 22420 -> 22439; sm121a 23850 -> 23860, 26406 -> 26421) + the audit exceptions (FADD.SAT_R_R_R retired, DEPBAR claim_forbid) // 2026-11-04 (canonical 6f11f6b): -20 / -10 era keys -> _meta.key_aliases, +LDL_R_ARURI (sm120) // RIDE476 (F2-iter299, canonical c88778e): +8 -> 23833 // RIDE475R3 (F2-iter289, INC-289e): +3/+3/+2/+2 -> 14868/14868/16005/23825 // RIDE475 (F2-iter288 BUG-475, canonical PENDING-475): +1146 graft x4 nogi (dARI modsub lattice E*L2.256 frame b76=1: klon 6 donorow *_dARI EFL2.256/noga, fields/vm PARITY) + rekanon 462-mgs ENL2 [489-absorb: DELETE 13/13/7 mgs + 2 anomalie 121a; REPLACE 9 heritage _src462] -> raw 14865/14865/16003/23823; loader 121a 23821 (offset -2 _errata stoi); cf 1166/1166/1164/1181 // was: ("sm121a", 22688) RIDE474-pre (F2-iter285 BUG-474, canonical PENDING-474): +3454/+3454/+3454/+3455 twins _ARURI U32 (b75=0 sib calej rodziny plain ARURI64 464/465/468)
];

// BUG-466 machine-built pin data (gen466pins.py rc=2; no hand hex).
pub const CANON466: &str = "bd2e25464208f9be6abc1e3c7475ca34914ad095"; // ride F2-iter275 (BUG-466 x3 ELL2.256 dARI-era rekanon -> plain vendor geometry)
pub const LAW466_ROUTE: &[(u128, &str, &str)] = &[
    (
        0x000be4000824e100fe0000000000097eu128,
        "arb466.LDG_.EL.base0.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R0.U32+UR0]",
    ),
    (
        0x000be4000824e100fe000000fe00097eu128,
        "arb466.LDG_.EL.base254.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R254.U32+UR0]",
    ),
    (
        0x000be4000824e100fe0000002800097eu128,
        "arb466.LDG_.EL.base40.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR0]",
    ),
    (
        0x000be4000824e100fe0010042800097eu128,
        "arb466.LDG_.EL.imm0x10.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR4+0x200]",
    ),
    (
        0x000be4000824e100fe0020042800097eu128,
        "arb466.LDG_.EL.imm0x20.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR4+0x400]",
    ),
    (
        0x000be4000824e100fe0000042800097eu128,
        "arb466.LDG_.EL.imm_hi1.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR4]",
    ),
    (
        0x000be4000824e1ffff0000042800097eu128,
        "arb466.LDG_.EL.imm_neg1.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU RZ, R0, [R40.U32+UR4+-0x200000]",
    ),
    (
        0x000be4000824e100fe00007f2800097eu128,
        "arb466.LDG_.EL.ur127.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR127]",
    ),
    (
        0x000be4000824e100fe00000d2800097eu128,
        "arb466.LDG_.EL.ur13.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR13]",
    ),
    (
        0x000be4000824e100fe0000ff2800097eu128,
        "arb466.LDG_.EL.ur255.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R40.U32+URZ]",
    ),
    (
        0x000be4000824e100fe0000202800097eu128,
        "arb466.LDG_.EL.ur32.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR32]",
    ),
    (
        0x000be4000824e100fe00003f2800097eu128,
        "arb466.LDG_.EL.ur63.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR63]",
    ),
    (
        0x000be4000824e100fe0000402800097eu128,
        "arb466.LDG_.EL.ur64.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR64]",
    ),
    (
        0x000be4000854e100fe0000000000097eu128,
        "arb466.LDG_.NA.base0.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R0.U32+UR0]",
    ),
    (
        0x000be4000854e100fe000000fe00097eu128,
        "arb466.LDG_.NA.base254.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R254.U32+UR0]",
    ),
    (
        0x000be4000854e100fe0000002800097eu128,
        "arb466.LDG_.NA.base40.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR0]",
    ),
    (
        0x000be4000854e100fe0010042800097eu128,
        "arb466.LDG_.NA.imm0x10.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR4+0x200]",
    ),
    (
        0x000be4000854e100fe0020042800097eu128,
        "arb466.LDG_.NA.imm0x20.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR4+0x400]",
    ),
    (
        0x000be4000854e100fe0000042800097eu128,
        "arb466.LDG_.NA.imm_hi1.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR4]",
    ),
    (
        0x000be4000854e1ffff0000042800097eu128,
        "arb466.LDG_.NA.imm_neg1.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU RZ, R0, [R40.U32+UR4+-0x200000]",
    ),
    (
        0x000be4000854e100fe00007f2800097eu128,
        "arb466.LDG_.NA.ur127.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR127]",
    ),
    (
        0x000be4000854e100fe00000d2800097eu128,
        "arb466.LDG_.NA.ur13.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR13]",
    ),
    (
        0x000be4000854e100fe0000ff2800097eu128,
        "arb466.LDG_.NA.ur255.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R40.U32+URZ]",
    ),
    (
        0x000be4000854e100fe0000202800097eu128,
        "arb466.LDG_.NA.ur32.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR32]",
    ),
    (
        0x000be4000854e100fe00003f2800097eu128,
        "arb466.LDG_.NA.ur63.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR63]",
    ),
    (
        0x000be4000854e100fe0000402800097eu128,
        "arb466.LDG_.NA.ur64.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR64]",
    ),
    (
        0x000be4000f24e000f80000000000097fu128,
        "arb466.STG_.EL.base0.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R0.U32+UR0], R0, R0",
    ),
    (
        0x000be4000f24e000f8000000fe00097fu128,
        "arb466.STG_.EL.base254.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R254.U32+UR0], R0, R0",
    ),
    (
        0x000be4000f24e000f80000002800097fu128,
        "arb466.STG_.EL.base40.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R40.U32+UR0], R0, R0",
    ),
    (
        0x000be4000f24e000f80010042800097fu128,
        "arb466.STG_.EL.imm0x10.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R40.U32+UR0+0x200], R4, R0",
    ),
    (
        0x000be4000f24e000f80020042800097fu128,
        "arb466.STG_.EL.imm0x20.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R40.U32+UR0+0x400], R4, R0",
    ),
    (
        0x000be4000f24e000f80000042800097fu128,
        "arb466.STG_.EL.imm_hi1.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R40.U32+UR0], R4, R0",
    ),
    (
        0x000be4000f24e0ffff0000042800097fu128,
        "arb466.STG_.EL.imm_neg1.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R40.U32+URZ+-0x200000], R4, R0",
    ),
    (
        0x000be4000f24e000f800007f2800097fu128,
        "arb466.STG_.EL.ur127.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R40.U32+UR0], R127, R0",
    ),
    (
        0x000be4000f24e000f800000d2800097fu128,
        "arb466.STG_.EL.ur13.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R40.U32+UR0], R13, R0",
    ),
    (
        0x000be4000f24e000f80000ff2800097fu128,
        "arb466.STG_.EL.ur255.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R40.U32+UR0], RZ, R0",
    ),
    (
        0x000be4000f24e000f80000202800097fu128,
        "arb466.STG_.EL.ur32.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R40.U32+UR0], R32, R0",
    ),
    (
        0x000be4000f24e000f800003f2800097fu128,
        "arb466.STG_.EL.ur63.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R40.U32+UR0], R63, R0",
    ),
    (
        0x000be4000f24e000f80000402800097fu128,
        "arb466.STG_.EL.ur64.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R40.U32+UR0], R64, R0",
    ),
    (
        0x000be4000f54e000f80000000000097fu128,
        "arb466.STG_.NA.base0.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R0.U32+UR0], R0, R0",
    ),
    (
        0x000be4000f54e000f8000000fe00097fu128,
        "arb466.STG_.NA.base254.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R254.U32+UR0], R0, R0",
    ),
    (
        0x000be4000f54e000f80000002800097fu128,
        "arb466.STG_.NA.base40.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R40.U32+UR0], R0, R0",
    ),
    (
        0x000be4000f54e000f80010042800097fu128,
        "arb466.STG_.NA.imm0x10.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R40.U32+UR0+0x200], R4, R0",
    ),
    (
        0x000be4000f54e000f80020042800097fu128,
        "arb466.STG_.NA.imm0x20.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R40.U32+UR0+0x400], R4, R0",
    ),
    (
        0x000be4000f54e000f80000042800097fu128,
        "arb466.STG_.NA.imm_hi1.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R40.U32+UR0], R4, R0",
    ),
    (
        0x000be4000f54e0ffff0000042800097fu128,
        "arb466.STG_.NA.imm_neg1.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R40.U32+URZ+-0x200000], R4, R0",
    ),
    (
        0x000be4000f54e000f800007f2800097fu128,
        "arb466.STG_.NA.ur127.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R40.U32+UR0], R127, R0",
    ),
    (
        0x000be4000f54e000f800000d2800097fu128,
        "arb466.STG_.NA.ur13.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R40.U32+UR0], R13, R0",
    ),
    (
        0x000be4000f54e000f80000ff2800097fu128,
        "arb466.STG_.NA.ur255.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R40.U32+UR0], RZ, R0",
    ),
    (
        0x000be4000f54e000f80000202800097fu128,
        "arb466.STG_.NA.ur32.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R40.U32+UR0], R32, R0",
    ),
    (
        0x000be4000f54e000f800003f2800097fu128,
        "arb466.STG_.NA.ur63.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R40.U32+UR0], R63, R0",
    ),
    (
        0x000be4000f54e000f80000402800097fu128,
        "arb466.STG_.NA.ur64.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R40.U32+UR0], R64, R0",
    ),
    (
        0x000be4000824e100fe0020041c00097eu128,
        "arb466b.EL.anchor",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR4+0x400]",
    ),
    (
        0x000be4000f24e004f80020001c00097fu128,
        "arb466b.EN.anchor",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R28.U32+UR4+0x400], R0, R0",
    ),
    (
        0x000be4000854e100fe0000041c00097eu128,
        "arb466b.L.b57_63_57",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR4]",
    ),
    (
        0x000be4000854e100fe0001041c00097eu128,
        "arb466b.L.imm1",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR4+0x20]",
    ),
    (
        0x000be4000854e100fe0080041c00097eu128,
        "arb466b.L.imm80",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR4+0x1000]",
    ),
    (
        0x000be4000854e100feffff041c00097eu128,
        "arb466b.L.immF",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR4+0x1fffe0]",
    ),
    (
        0x000be4000854e100ff0000041c00097eu128,
        "arb466b.L.immS",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR4+-0x200000]",
    ),
    (
        0x000be4000854e100fe7fff041c00097eu128,
        "arb466b.L.immmax",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR4+0xfffe0]",
    ),
    (
        0x000be4000854e1fffe0000041c00097eu128,
        "arb466b.L.tok1_255",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU RZ, R0, [R28.U32+UR4]",
    ),
    (
        0x000be4000854e104fe0000041c00097eu128,
        "arb466b.L.tok1_4",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R4, R0, [R28.U32+UR4]",
    ),
    (
        0x000be4000854e100fe0000041cff097eu128,
        "arb466b.L.tok2_255",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, RZ, [R28.U32+UR4]",
    ),
    (
        0x000be4000854e100fe0000041c05097eu128,
        "arb466b.L.tok2_5",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R5, [R28.U32+UR4]",
    ),
    (
        0x000be4000854e100fe0000001c00097eu128,
        "arb466b.L.ur_0",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR0]",
    ),
    (
        0x000be4000854e100fe0000011c00097eu128,
        "arb466b.L.ur_1",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR1]",
    ),
    (
        0x000be4000854e100fe0000fe1c00097eu128,
        "arb466b.L.ur_254",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR254]",
    ),
    (
        0x000be4000854e100fe0000ff1c00097eu128,
        "arb466b.L.ur_255",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+URZ]",
    ),
    (
        0x000be4000854e100fe00003f1c00097eu128,
        "arb466b.L.ur_63",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR63]",
    ),
    (
        0x000be4000854e100fe0000401c00097eu128,
        "arb466b.L.ur_64",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR64]",
    ),
    (
        0x000be4000f54e004f80000001c00097fu128,
        "arb466b.S.b59",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR4], R0, R0",
    ),
    (
        0x000be4000f54e004f80001001c00097fu128,
        "arb466b.S.imm1",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR4+0x20], R0, R0",
    ),
    (
        0x000be4000f54e004f80080001c00097fu128,
        "arb466b.S.imm80",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR4+0x1000], R0, R0",
    ),
    (
        0x000be4000f54e004f8ffff001c00097fu128,
        "arb466b.S.immF",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR4+0x1fffe0], R0, R0",
    ),
    (
        0x000be4000f54e004fc0000001c00097fu128,
        "arb466b.S.immS",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR4+-0x800000], R0, R0",
    ),
    (
        0x000be4000f54e004f80000ff1c00097fu128,
        "arb466b.S.tok2_255",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR4], RZ, R0",
    ),
    (
        0x000be4000f54e004f80000051c00097fu128,
        "arb466b.S.tok2_4",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR4], R5, R0",
    ),
    (
        0x000be4000f54e004f80000001cff097fu128,
        "arb466b.S.tok3_255",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR4], R0, RZ",
    ),
    (
        0x000be4000f54e004f80000001c05097fu128,
        "arb466b.S.tok3_5",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR4], R0, R5",
    ),
    (
        0x000be4000f54e000f80000001c00097fu128,
        "arb466b.S.ur_0",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR0], R0, R0",
    ),
    (
        0x000be4000f54e001f80000001c00097fu128,
        "arb466b.S.ur_1",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR1], R0, R0",
    ),
    (
        0x000be4000f54e0fef80000001c00097fu128,
        "arb466b.S.ur_254",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR254], R0, R0",
    ),
    (
        0x000be4000f54e0fff80000001c00097fu128,
        "arb466b.S.ur_255",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+URZ], R0, R0",
    ),
    (
        0x000be4000f54e03ff80000001c00097fu128,
        "arb466b.S.ur_63",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR63], R0, R0",
    ),
    (
        0x000be4000f54e040f80000001c00097fu128,
        "arb466b.S.ur_64",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR64], R0, R0",
    ),
    (
        0x004be4000854e100fe0000041c00097eu128,
        "arb466b.L.e118",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR4]",
    ),
    (
        0x010be4000854e100fe0000041c00097eu128,
        "arb466b.L.e120",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR4]",
    ),
    (
        0x080be4000854e100fe0000041c00097eu128,
        "arb466b.L.e123",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR4]",
    ),
    (
        0x200be4000854e100fe0000041c00097eu128,
        "arb466b.L.e125",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR4]",
    ),
    (
        0x000be4000f54e104f80000001c00097fu128,
        "arb466b.S.b72",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR4], R0, R0",
    ),
];
pub const LAW466_ELIDE: &[(u128, &str, &str)] = &[
    (
        0x000be4000824e100fe000000ff00097eu128,
        "arb466.LDG_.EL.base255.sm100a",
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [UR0]",
    ),
    (
        0x000be4000854e100fe000000ff00097eu128,
        "arb466.LDG_.NA.base255.sm100a",
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [UR0]",
    ),
    (
        0x000be4000f24e000f8000000ff00097fu128,
        "arb466.STG_.EL.base255.sm100a",
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [UR0], R0, R0",
    ),
    (
        0x000be4000f54e000f8000000ff00097fu128,
        "arb466.STG_.NA.base255.sm100a",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [UR0], R0, R0",
    ),
    (
        0x000be4000f54e004f8000000ff00097fu128,
        "arb466b.S.base255",
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [UR4], R0, R0",
    ),
];
pub const STAND466: &[(u128, &str, &str)] = &[
    (
        0x000be4000854e300fe0000041c00097eu128,
        "arb466b.L.b73",
        "HOLE",
    ),
    (
        0x000be4000854e500fe0000041c00097eu128,
        "arb466b.L.b74",
        "HOLE",
    ),
    (
        0x000be4000854e900fe0000041c00097eu128,
        "arb466b.L.b75",
        "HOLE",
    ),
    (
        0x000be4000855e100fe0000041c00097eu128,
        "arb466b.L.b80",
        "HOLE",
    ),
    (
        0x000be4000856e100fe0000041c00097eu128,
        "arb466b.L.b81",
        "HOLE",
    ),
    (
        0x000be400085ce100fe0000041c00097eu128,
        "arb466b.L.b83",
        "HOLE",
    ),
    (
        0x000be4000874e100fe0000041c00097eu128,
        "arb466b.L.b85",
        "HOLE",
    ),
    (
        0x000be40008d4e100fe0000041c00097eu128,
        "arb466b.L.b87",
        "HOLE",
    ),
    (
        0x000be4000954e100fe0000041c00097eu128,
        "arb466b.L.b88",
        "HOLE",
    ),
    (
        0x000be4000a54e100fe0000041c00097eu128,
        "arb466b.L.b89",
        "HOLE",
    ),
    (
        0x000be4000f54e204f80000001c00097fu128,
        "arb466b.S.b73",
        "HOLE",
    ),
    (
        0x000be4000f54e404f80000001c00097fu128,
        "arb466b.S.b74",
        "HOLE",
    ),
    (
        0x000be4000f54e804f80000001c00097fu128,
        "arb466b.S.b75",
        "HOLE",
    ),
    (
        0x000be4000f55e004f80000001c00097fu128,
        "arb466b.S.b80",
        "HOLE",
    ),
    (
        0x000be4000f56e004f80000001c00097fu128,
        "arb466b.S.b81",
        "HOLE",
    ),
    (
        0x000be4000f5ce004f80000001c00097fu128,
        "arb466b.S.b83",
        "HOLE",
    ),
    (
        0x000be4000f74e004f80000001c00097fu128,
        "arb466b.S.b85",
        "HOLE",
    ),
    (
        0x000be4000fd4e004f80000001c00097fu128,
        "arb466b.S.b87",
        "HOLE",
    ),
];
pub const KILL466: &[(u128, &str)] = &[
    (0x000be4000854f100fe0000041c00097eu128, "arb466b.L.b76"),
    (0x000be4000f54f004f80000001c00097fu128, "arb466b.S.b76"),
];
pub const CTRL466: &[(u128, &str, &str)] = &[
    (
        0x000be40008141900fe0000002800097eu128,
        "C121a.L40",
        "@P0 LDG.E.ELL2.256 R0, R0, desc[UR0][R40.64]",
    ),
    (
        0x000be40008141900fe0001042800097eu128,
        "C121a.L4imm",
        "@P0 LDG.E.ELL2.256 R0, R0, desc[UR4][R40.64+0x20]",
    ),
    (
        0x000be4000f141800f80000282800097fu128,
        "C121a.S40",
        "@P0 STG.E.ELL2.256 desc[UR0][R40.64], R40, R0",
    ),
    (
        0x000be4000f141804f80000002800097fu128,
        "C121a.S_ur",
        "@P0 STG.E.ELL2.256 desc[UR4][R40.64], R0, R0",
    ),
];
pub const MINT466: &[(u128, &str)] = &[
    (
        0x000fc2000854e100fe0000002800097eu128,
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR0]",
    ),
    (
        0x000fc2000824e100fe00000d2800097eu128,
        "@P0 LDG.E.EL.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR13]",
    ),
    (
        0x000fc2000854e100fe0020042800097eu128,
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R40.U32+UR4+0x400]",
    ),
    (
        0x000fc2000f54e000f80000002800097fu128,
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R40.U32+UR0], R0, R0",
    ),
    (
        0x000fc2000f24e000f80020042800097fu128,
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [R40.U32+UR0+0x400], R4, R0",
    ),
    (
        0x000fc2000854e100fe0001041c00097eu128,
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR4+0x20]",
    ),
    (
        0x000fc2000f54e004f80001001c00097fu128,
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR4+0x20], R0, R0",
    ),
    (
        0x000fc2000f54e004f80000051c00097fu128,
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR4], R5, R0",
    ),
    (
        0x000fc2000854e100fe0000fe1c00097eu128,
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [R28.U32+UR254]",
    ),
    (
        0x000fc2000f54e000f80000001c00097fu128,
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [R28.U32+UR0], R0, R0",
    ),
];
pub const MINT466_ELIDE: &[(u128, &str)] = &[
    (
        0x000fc2000854e100fe000000ff00097eu128,
        "@P0 LDG.E.NA.ELL2.256.STRONG.GPU R0, R0, [UR0]",
    ),
    (
        0x000fc2000f54e000f8000000ff00097fu128,
        "@P0 STG.E.NA.ELL2.256.STRONG.GPU [UR0], R0, R0",
    ),
    (
        0x000fc2000f24e000f8000000ff00097fu128,
        "@P0 STG.E.EL.ELL2.256.STRONG.GPU [UR0], R0, R0",
    ),
];

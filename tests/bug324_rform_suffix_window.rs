//! BUG-324 (F2-iter173, loop5/blind front2, 2026-09-01): suffix-window-
//! carrier closure on pure-reg/clustered R-forms, legs sm120+sm121a
//! (canonical bug324 cut a0dbda7, ride-after cf1d6f1/BUG-342). Registered
//! 324-kand LOW at F2-iter161 (289 report sec.6; arb289 H-set in hand).
//! Measurement-first: arb324 = 404 probes, nvdisasm 13.3.73 raw -b, x4
//! models SM100a/103a/120/121a agree on EVERY probe (zero DIVERGENT).
//!
//! LAW (x4 agree):
//! HFMA2 kraty 0xe31 (HFMA2_R_R_R_UR) / 0xc31 (HFMA2_R_R_UR_R): full
//! donor-II_II window legal: [77:76]=FMZ/SAT, b78=F32, b80+b76=OOB
//! alias, b79=RELU (+P-dest: pred 3b@[89:87], inv@90; pv=7+inv0 elides
//! the whole trailing token; pv=7+inv1 prints !PT), b85=BF16_V2;
//! SAT x RELU any combo = vendor rc=1 (KILL) x4 => stays HOLE;
//! F32 x BF16_V2 presence = .INVALID3 print (285 doctrine) => HOLE.
//! HMUL2 kraty 0x232 (HMUL2_R_R_R) / 0xc32 (HMUL2_R_R_UR): legal =
//! FMZ, SAT, FMZ.SAT, FTZ, FTZ.SAT + BF16_V2 crosses. NO OOB alias
//! (b80+b76 = .INVALID3 print = HOLE); b78 = .INVALID1 print = HOLE;
//! b79 = vendor TEXT-INERT (single + all combos drop) => variable_mask
//! relaxed (316/320 doctrine); no RELU lanes (HMUL2 has no P-dest).
//! b91: kill-bit on 0x232 vs required-bake on 0xc31/0xc32/0xe31 (row
//! identity, untouched). Stray [90:87] singles text-inert everywhere
//! (289-documented status quo: stay care => HOLE). band [55:40] inert
//! x4 all kraty; the only corpus band word (t10.cubin@0x410 b0_32 =
//! 0x405d080000342c28087232 = w324) is INVALID1-class => stays HOLE
//! => band NOT relaxed (no effect).
//!
//! FIX = pure table graft (patch324.py, replayable+idempotent; engine
//! ZERO change), mirroring the donor II_II family structure: 15 direct
//! mg lanes + 8 BF16_V2 crosses + 12 base-key RELU mg (with the pv=7
//! elision bake 0x7<<87 in and_base, donor delta law) + 12 RELU _P
//! dotted keys with pred/inv fields @87/@90 tok5 (HFMA2 forms); HMUL2:
//! 5 direct + 6 BF16_V2-cross lanes as plain-row clones, vm|=b79 on
//! every row. DONORS sm100a/sm103a byte-pinned (BUG-315 owner scope).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t)
        .map(|d| to_sass(&d))
        .ok()
        .map(|s| s.trim_end().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).map_err(|e| format!("parse: {e}"))?;
    encode_instruction(&insn, t).map_err(|e| format!("encode: {e}"))
}

const LEGAL_CASES: &[(&str, u128, &str)] = &[
    (
        "A_232_b76",
        0x1c003000000c030a1232,
        "@P1 HMUL2.FMZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "A_232_b77",
        0x2c003000000c030a1232,
        "@P1 HMUL2.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "A_232_b79",
        0x8c003000000c030a1232,
        "@P1 HMUL2 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "A_232_b80",
        0x10c003000000c030a1232,
        "@P1 HMUL2.FTZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "A_232_b85",
        0x200c003000000c030a1232,
        "@P1 HMUL2.BF16_V2 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "A_c31_b76",
        0x816180b200000080c097c31,
        "HFMA2.FMZ R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "A_c31_b77",
        0x816280b200000080c097c31,
        "HFMA2.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "A_c31_b78",
        0x816480b200000080c097c31,
        "HFMA2.F32 R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "A_c31_b79",
        0x816880b200000080c097c31,
        "HFMA2.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "A_c31_b80",
        0x817080b200000080c097c31,
        "HFMA2.FTZ R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "A_c31_b85",
        0x836080b200000080c097c31,
        "HFMA2.BF16_V2 R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "A_c32_b76",
        0x8001000300000080c0b7c32,
        "HMUL2.FMZ R11, R12, UR8.H1_H1",
    ),
    (
        "A_c32_b77",
        0x8002000300000080c0b7c32,
        "HMUL2.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "A_c32_b79",
        0x8008000300000080c0b7c32,
        "HMUL2 R11, R12, UR8.H1_H1",
    ),
    (
        "A_c32_b80",
        0x8010000300000080c0b7c32,
        "HMUL2.FTZ R11, R12, UR8.H1_H1",
    ),
    (
        "A_c32_b85",
        0x8200000300000080c0b7c32,
        "HMUL2.BF16_V2 R11, R12, UR8.H1_H1",
    ),
    (
        "A_e31_b76",
        0x80010030000000402017e31,
        "HFMA2.FMZ R1, R2, R3, UR4",
    ),
    (
        "A_e31_b77",
        0x80020030000000402017e31,
        "HFMA2.SAT R1, R2, R3, UR4",
    ),
    (
        "A_e31_b78",
        0x80040030000000402017e31,
        "HFMA2.F32 R1, R2, R3, UR4",
    ),
    (
        "A_e31_b79",
        0x80080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "A_e31_b80",
        0x80100030000000402017e31,
        "HFMA2.FTZ R1, R2, R3, UR4",
    ),
    (
        "A_e31_b85",
        0x82000030000000402017e31,
        "HFMA2.BF16_V2 R1, R2, R3, UR4",
    ),
    (
        "D_c31_p0",
        0x816880b200000080c097c31,
        "HFMA2.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "D_c31_p6",
        0xb16880b200000080c097c31,
        "HFMA2.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P6",
    ),
    (
        "D_c31_p7",
        0xb96880b200000080c097c31,
        "HFMA2.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "D_e31_ip0",
        0xc0080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, !P0",
    ),
    (
        "D_e31_ip1",
        0xc8080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, !P1",
    ),
    (
        "D_e31_ip2",
        0xd0080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, !P2",
    ),
    (
        "D_e31_ip3",
        0xd8080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, !P3",
    ),
    (
        "D_e31_ip4",
        0xe0080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, !P4",
    ),
    (
        "D_e31_ip5",
        0xe8080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, !P5",
    ),
    (
        "D_e31_ip6",
        0xf0080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, !P6",
    ),
    (
        "D_e31_ip7",
        0xf8080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, !PT",
    ),
    (
        "D_e31_p0",
        0x80080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "D_e31_p1",
        0x88080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, P1",
    ),
    (
        "D_e31_p2",
        0x90080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, P2",
    ),
    (
        "D_e31_p3",
        0x98080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, P3",
    ),
    (
        "D_e31_p4",
        0xa0080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, P4",
    ),
    (
        "D_e31_p5",
        0xa8080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, P5",
    ),
    (
        "D_e31_p6",
        0xb0080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, P6",
    ),
    (
        "D_e31_p7",
        0xb8080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4",
    ),
    (
        "F_232_neg2_sat",
        0x2d003000000c030a1232,
        "@P1 HMUL2.SAT R10, -R3.H1_H1, R12.H1_H1",
    ),
    (
        "F_232_neg4_ftz",
        0x110c003000000c030a1232,
        "@P1 HMUL2.FTZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "F_c31_allmod",
        0x816690b200000080c097c31,
        "HFMA2.F32.SAT R9, -R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "F_c31_hs3_f32",
        0x816480b200000080c097c31,
        "HFMA2.F32 R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "F_c31_neg2_sat",
        0x816290b200000080c097c31,
        "HFMA2.SAT R9, -R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "F_c31_neg4_ftz",
        0x817080b200000080c097c31,
        "HFMA2.FTZ R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "F_c32_neg2_sat",
        0x8002100300000080c0b7c32,
        "HMUL2.SAT R11, -R12, UR8.H1_H1",
    ),
    (
        "F_c32_neg4_ftz",
        0x8110000300000080c0b7c32,
        "HMUL2.FTZ R11, R12, UR8.H1_H1",
    ),
    (
        "F_e31_allmod",
        0x80461030000000402017e31,
        "HFMA2.F32.SAT R1, -R2, R3.H0_H0, UR4",
    ),
    (
        "F_e31_hs3_f32",
        0x80440030000000402017e31,
        "HFMA2.F32 R1, R2, R3.H0_H0, UR4",
    ),
    (
        "F_e31_neg2_sat",
        0x80021030000000402017e31,
        "HFMA2.SAT R1, -R2, R3, UR4",
    ),
    (
        "F_e31_neg4_ftz",
        0x81100030000000402017e31,
        "HFMA2.FTZ R1, R2, -R3, UR4",
    ),
    (
        "B_232_00",
        0xc003000000c030a1232,
        "@P1 HMUL2 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_01",
        0x1c003000000c030a1232,
        "@P1 HMUL2.FMZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_02",
        0x2c003000000c030a1232,
        "@P1 HMUL2.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_03",
        0x3c003000000c030a1232,
        "@P1 HMUL2.FMZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_08",
        0x8c003000000c030a1232,
        "@P1 HMUL2 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_09",
        0x9c003000000c030a1232,
        "@P1 HMUL2.FMZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_0a",
        0xac003000000c030a1232,
        "@P1 HMUL2.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_0b",
        0xbc003000000c030a1232,
        "@P1 HMUL2.FMZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_10",
        0x10c003000000c030a1232,
        "@P1 HMUL2.FTZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_12",
        0x12c003000000c030a1232,
        "@P1 HMUL2.FTZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_18",
        0x18c003000000c030a1232,
        "@P1 HMUL2.FTZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_1a",
        0x1ac003000000c030a1232,
        "@P1 HMUL2.FTZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_c31_00",
        0x816080b200000080c097c31,
        "HFMA2 R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_01",
        0x816180b200000080c097c31,
        "HFMA2.FMZ R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_02",
        0x816280b200000080c097c31,
        "HFMA2.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_03",
        0x816380b200000080c097c31,
        "HFMA2.FMZ.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_04",
        0x816480b200000080c097c31,
        "HFMA2.F32 R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_05",
        0x816580b200000080c097c31,
        "HFMA2.F32.FMZ R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_06",
        0x816680b200000080c097c31,
        "HFMA2.F32.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_07",
        0x816780b200000080c097c31,
        "HFMA2.F32.FMZ.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_08",
        0x816880b200000080c097c31,
        "HFMA2.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "B_c31_09",
        0x816980b200000080c097c31,
        "HFMA2.FMZ.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "B_c31_0c",
        0x816c80b200000080c097c31,
        "HFMA2.F32.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "B_c31_0d",
        0x816d80b200000080c097c31,
        "HFMA2.F32.FMZ.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "B_c31_10",
        0x817080b200000080c097c31,
        "HFMA2.FTZ R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_11",
        0x817180b200000080c097c31,
        "HFMA2.OOB R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_12",
        0x817280b200000080c097c31,
        "HFMA2.FTZ.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_13",
        0x817380b200000080c097c31,
        "HFMA2.OOB.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_14",
        0x817480b200000080c097c31,
        "HFMA2.F32.FTZ R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_15",
        0x817580b200000080c097c31,
        "HFMA2.F32.OOB R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_16",
        0x817680b200000080c097c31,
        "HFMA2.F32.FTZ.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_17",
        0x817780b200000080c097c31,
        "HFMA2.F32.OOB.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "B_c31_18",
        0x817880b200000080c097c31,
        "HFMA2.FTZ.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "B_c31_19",
        0x817980b200000080c097c31,
        "HFMA2.OOB.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "B_c31_1c",
        0x817c80b200000080c097c31,
        "HFMA2.F32.FTZ.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "B_c31_1d",
        0x817d80b200000080c097c31,
        "HFMA2.F32.OOB.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "B_c32_00",
        0x8000000300000080c0b7c32,
        "HMUL2 R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_01",
        0x8001000300000080c0b7c32,
        "HMUL2.FMZ R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_02",
        0x8002000300000080c0b7c32,
        "HMUL2.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_03",
        0x8003000300000080c0b7c32,
        "HMUL2.FMZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_08",
        0x8008000300000080c0b7c32,
        "HMUL2 R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_09",
        0x8009000300000080c0b7c32,
        "HMUL2.FMZ R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_0a",
        0x800a000300000080c0b7c32,
        "HMUL2.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_0b",
        0x800b000300000080c0b7c32,
        "HMUL2.FMZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_10",
        0x8010000300000080c0b7c32,
        "HMUL2.FTZ R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_12",
        0x8012000300000080c0b7c32,
        "HMUL2.FTZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_18",
        0x8018000300000080c0b7c32,
        "HMUL2.FTZ R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_1a",
        0x801a000300000080c0b7c32,
        "HMUL2.FTZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_e31_00",
        0x80000030000000402017e31,
        "HFMA2 R1, R2, R3, UR4",
    ),
    (
        "B_e31_01",
        0x80010030000000402017e31,
        "HFMA2.FMZ R1, R2, R3, UR4",
    ),
    (
        "B_e31_02",
        0x80020030000000402017e31,
        "HFMA2.SAT R1, R2, R3, UR4",
    ),
    (
        "B_e31_03",
        0x80030030000000402017e31,
        "HFMA2.FMZ.SAT R1, R2, R3, UR4",
    ),
    (
        "B_e31_04",
        0x80040030000000402017e31,
        "HFMA2.F32 R1, R2, R3, UR4",
    ),
    (
        "B_e31_05",
        0x80050030000000402017e31,
        "HFMA2.F32.FMZ R1, R2, R3, UR4",
    ),
    (
        "B_e31_06",
        0x80060030000000402017e31,
        "HFMA2.F32.SAT R1, R2, R3, UR4",
    ),
    (
        "B_e31_07",
        0x80070030000000402017e31,
        "HFMA2.F32.FMZ.SAT R1, R2, R3, UR4",
    ),
    (
        "B_e31_08",
        0x80080030000000402017e31,
        "HFMA2.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "B_e31_09",
        0x80090030000000402017e31,
        "HFMA2.FMZ.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "B_e31_0c",
        0x800c0030000000402017e31,
        "HFMA2.F32.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "B_e31_0d",
        0x800d0030000000402017e31,
        "HFMA2.F32.FMZ.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "B_e31_10",
        0x80100030000000402017e31,
        "HFMA2.FTZ R1, R2, R3, UR4",
    ),
    (
        "B_e31_11",
        0x80110030000000402017e31,
        "HFMA2.OOB R1, R2, R3, UR4",
    ),
    (
        "B_e31_12",
        0x80120030000000402017e31,
        "HFMA2.FTZ.SAT R1, R2, R3, UR4",
    ),
    (
        "B_e31_13",
        0x80130030000000402017e31,
        "HFMA2.OOB.SAT R1, R2, R3, UR4",
    ),
    (
        "B_e31_14",
        0x80140030000000402017e31,
        "HFMA2.F32.FTZ R1, R2, R3, UR4",
    ),
    (
        "B_e31_15",
        0x80150030000000402017e31,
        "HFMA2.F32.OOB R1, R2, R3, UR4",
    ),
    (
        "B_e31_16",
        0x80160030000000402017e31,
        "HFMA2.F32.FTZ.SAT R1, R2, R3, UR4",
    ),
    (
        "B_e31_17",
        0x80170030000000402017e31,
        "HFMA2.F32.OOB.SAT R1, R2, R3, UR4",
    ),
    (
        "B_e31_18",
        0x80180030000000402017e31,
        "HFMA2.FTZ.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "B_e31_19",
        0x80190030000000402017e31,
        "HFMA2.OOB.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "B_e31_1c",
        0x801c0030000000402017e31,
        "HFMA2.F32.FTZ.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "B_e31_1d",
        0x801d0030000000402017e31,
        "HFMA2.F32.OOB.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "C_232_00",
        0x200c003000000c030a1232,
        "@P1 HMUL2.BF16_V2 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_01",
        0x201c003000000c030a1232,
        "@P1 HMUL2.BF16_V2.FMZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_02",
        0x202c003000000c030a1232,
        "@P1 HMUL2.BF16_V2.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_03",
        0x203c003000000c030a1232,
        "@P1 HMUL2.BF16_V2.FMZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_08",
        0x208c003000000c030a1232,
        "@P1 HMUL2.BF16_V2 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_09",
        0x209c003000000c030a1232,
        "@P1 HMUL2.BF16_V2.FMZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_0a",
        0x20ac003000000c030a1232,
        "@P1 HMUL2.BF16_V2.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_0b",
        0x20bc003000000c030a1232,
        "@P1 HMUL2.BF16_V2.FMZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_10",
        0x210c003000000c030a1232,
        "@P1 HMUL2.BF16_V2.FTZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_12",
        0x212c003000000c030a1232,
        "@P1 HMUL2.BF16_V2.FTZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_18",
        0x218c003000000c030a1232,
        "@P1 HMUL2.BF16_V2.FTZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_1a",
        0x21ac003000000c030a1232,
        "@P1 HMUL2.BF16_V2.FTZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_c31_00",
        0x836080b200000080c097c31,
        "HFMA2.BF16_V2 R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_01",
        0x836180b200000080c097c31,
        "HFMA2.BF16_V2.FMZ R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_02",
        0x836280b200000080c097c31,
        "HFMA2.BF16_V2.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_03",
        0x836380b200000080c097c31,
        "HFMA2.BF16_V2.FMZ.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_08",
        0x836880b200000080c097c31,
        "HFMA2.BF16_V2.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "C_c31_09",
        0x836980b200000080c097c31,
        "HFMA2.BF16_V2.FMZ.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "C_c31_10",
        0x837080b200000080c097c31,
        "HFMA2.BF16_V2.FTZ R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_11",
        0x837180b200000080c097c31,
        "HFMA2.BF16_V2.OOB R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_12",
        0x837280b200000080c097c31,
        "HFMA2.BF16_V2.FTZ.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_13",
        0x837380b200000080c097c31,
        "HFMA2.BF16_V2.OOB.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_18",
        0x837880b200000080c097c31,
        "HFMA2.BF16_V2.FTZ.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "C_c31_19",
        0x837980b200000080c097c31,
        "HFMA2.BF16_V2.OOB.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "C_c32_00",
        0x8200000300000080c0b7c32,
        "HMUL2.BF16_V2 R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_01",
        0x8201000300000080c0b7c32,
        "HMUL2.BF16_V2.FMZ R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_02",
        0x8202000300000080c0b7c32,
        "HMUL2.BF16_V2.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_03",
        0x8203000300000080c0b7c32,
        "HMUL2.BF16_V2.FMZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_08",
        0x8208000300000080c0b7c32,
        "HMUL2.BF16_V2 R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_09",
        0x8209000300000080c0b7c32,
        "HMUL2.BF16_V2.FMZ R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_0a",
        0x820a000300000080c0b7c32,
        "HMUL2.BF16_V2.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_0b",
        0x820b000300000080c0b7c32,
        "HMUL2.BF16_V2.FMZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_10",
        0x8210000300000080c0b7c32,
        "HMUL2.BF16_V2.FTZ R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_12",
        0x8212000300000080c0b7c32,
        "HMUL2.BF16_V2.FTZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_18",
        0x8218000300000080c0b7c32,
        "HMUL2.BF16_V2.FTZ R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_1a",
        0x821a000300000080c0b7c32,
        "HMUL2.BF16_V2.FTZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_e31_00",
        0x82000030000000402017e31,
        "HFMA2.BF16_V2 R1, R2, R3, UR4",
    ),
    (
        "C_e31_01",
        0x82010030000000402017e31,
        "HFMA2.BF16_V2.FMZ R1, R2, R3, UR4",
    ),
    (
        "C_e31_02",
        0x82020030000000402017e31,
        "HFMA2.BF16_V2.SAT R1, R2, R3, UR4",
    ),
    (
        "C_e31_03",
        0x82030030000000402017e31,
        "HFMA2.BF16_V2.FMZ.SAT R1, R2, R3, UR4",
    ),
    (
        "C_e31_08",
        0x82080030000000402017e31,
        "HFMA2.BF16_V2.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "C_e31_09",
        0x82090030000000402017e31,
        "HFMA2.BF16_V2.FMZ.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "C_e31_10",
        0x82100030000000402017e31,
        "HFMA2.BF16_V2.FTZ R1, R2, R3, UR4",
    ),
    (
        "C_e31_11",
        0x82110030000000402017e31,
        "HFMA2.BF16_V2.OOB R1, R2, R3, UR4",
    ),
    (
        "C_e31_12",
        0x82120030000000402017e31,
        "HFMA2.BF16_V2.FTZ.SAT R1, R2, R3, UR4",
    ),
    (
        "C_e31_13",
        0x82130030000000402017e31,
        "HFMA2.BF16_V2.OOB.SAT R1, R2, R3, UR4",
    ),
    (
        "C_e31_18",
        0x82180030000000402017e31,
        "HFMA2.BF16_V2.FTZ.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "C_e31_19",
        0x82190030000000402017e31,
        "HFMA2.BF16_V2.OOB.RELU R1, R2, R3, UR4, P0",
    ),
];
const HOLE_CASES: &[(&str, u128, &str)] = &[
    (
        "A_232_b78",
        0x4c003000000c030a1232,
        "@P1 HMUL2.INVALID1 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "A_c32_b78",
        0x8004000300000080c0b7c32,
        "HMUL2.INVALID1 R11, R12, UR8.H1_H1",
    ),
    (
        "B_232_04",
        0x4c003000000c030a1232,
        "@P1 HMUL2.INVALID1 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_05",
        0x5c003000000c030a1232,
        "@P1 HMUL2.INVALID1.FMZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_06",
        0x6c003000000c030a1232,
        "@P1 HMUL2.INVALID1.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_07",
        0x7c003000000c030a1232,
        "@P1 HMUL2.INVALID1.FMZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_0c",
        0xcc003000000c030a1232,
        "@P1 HMUL2.INVALID1 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_0d",
        0xdc003000000c030a1232,
        "@P1 HMUL2.INVALID1.FMZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_0e",
        0xec003000000c030a1232,
        "@P1 HMUL2.INVALID1.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_0f",
        0xfc003000000c030a1232,
        "@P1 HMUL2.INVALID1.FMZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_11",
        0x11c003000000c030a1232,
        "@P1 HMUL2.INVALID3 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_13",
        0x13c003000000c030a1232,
        "@P1 HMUL2.INVALID3.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_14",
        0x14c003000000c030a1232,
        "@P1 HMUL2.INVALID1.FTZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_15",
        0x15c003000000c030a1232,
        "@P1 HMUL2.INVALID1.INVALID3 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_16",
        0x16c003000000c030a1232,
        "@P1 HMUL2.INVALID1.FTZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_17",
        0x17c003000000c030a1232,
        "@P1 HMUL2.INVALID1.INVALID3.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_19",
        0x19c003000000c030a1232,
        "@P1 HMUL2.INVALID3 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_1b",
        0x1bc003000000c030a1232,
        "@P1 HMUL2.INVALID3.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_1c",
        0x1cc003000000c030a1232,
        "@P1 HMUL2.INVALID1.FTZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_1d",
        0x1dc003000000c030a1232,
        "@P1 HMUL2.INVALID1.INVALID3 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_1e",
        0x1ec003000000c030a1232,
        "@P1 HMUL2.INVALID1.FTZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "B_232_1f",
        0x1fc003000000c030a1232,
        "@P1 HMUL2.INVALID1.INVALID3.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    ("B_c31_0a", 0x816a80b200000080c097c31, "<rc=1>"),
    ("B_c31_0b", 0x816b80b200000080c097c31, "<rc=1>"),
    ("B_c31_0e", 0x816e80b200000080c097c31, "<rc=1>"),
    ("B_c31_0f", 0x816f80b200000080c097c31, "<rc=1>"),
    ("B_c31_1a", 0x817a80b200000080c097c31, "<rc=1>"),
    ("B_c31_1b", 0x817b80b200000080c097c31, "<rc=1>"),
    ("B_c31_1e", 0x817e80b200000080c097c31, "<rc=1>"),
    ("B_c31_1f", 0x817f80b200000080c097c31, "<rc=1>"),
    (
        "B_c32_04",
        0x8004000300000080c0b7c32,
        "HMUL2.INVALID1 R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_05",
        0x8005000300000080c0b7c32,
        "HMUL2.INVALID1.FMZ R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_06",
        0x8006000300000080c0b7c32,
        "HMUL2.INVALID1.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_07",
        0x8007000300000080c0b7c32,
        "HMUL2.INVALID1.FMZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_0c",
        0x800c000300000080c0b7c32,
        "HMUL2.INVALID1 R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_0d",
        0x800d000300000080c0b7c32,
        "HMUL2.INVALID1.FMZ R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_0e",
        0x800e000300000080c0b7c32,
        "HMUL2.INVALID1.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_0f",
        0x800f000300000080c0b7c32,
        "HMUL2.INVALID1.FMZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_11",
        0x8011000300000080c0b7c32,
        "HMUL2.INVALID3 R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_13",
        0x8013000300000080c0b7c32,
        "HMUL2.INVALID3.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_14",
        0x8014000300000080c0b7c32,
        "HMUL2.INVALID1.FTZ R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_15",
        0x8015000300000080c0b7c32,
        "HMUL2.INVALID1.INVALID3 R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_16",
        0x8016000300000080c0b7c32,
        "HMUL2.INVALID1.FTZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_17",
        0x8017000300000080c0b7c32,
        "HMUL2.INVALID1.INVALID3.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_19",
        0x8019000300000080c0b7c32,
        "HMUL2.INVALID3 R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_1b",
        0x801b000300000080c0b7c32,
        "HMUL2.INVALID3.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_1c",
        0x801c000300000080c0b7c32,
        "HMUL2.INVALID1.FTZ R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_1d",
        0x801d000300000080c0b7c32,
        "HMUL2.INVALID1.INVALID3 R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_1e",
        0x801e000300000080c0b7c32,
        "HMUL2.INVALID1.FTZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "B_c32_1f",
        0x801f000300000080c0b7c32,
        "HMUL2.INVALID1.INVALID3.SAT R11, R12, UR8.H1_H1",
    ),
    ("B_e31_0a", 0x800a0030000000402017e31, "<rc=1>"),
    ("B_e31_0b", 0x800b0030000000402017e31, "<rc=1>"),
    ("B_e31_0e", 0x800e0030000000402017e31, "<rc=1>"),
    ("B_e31_0f", 0x800f0030000000402017e31, "<rc=1>"),
    ("B_e31_1a", 0x801a0030000000402017e31, "<rc=1>"),
    ("B_e31_1b", 0x801b0030000000402017e31, "<rc=1>"),
    ("B_e31_1e", 0x801e0030000000402017e31, "<rc=1>"),
    ("B_e31_1f", 0x801f0030000000402017e31, "<rc=1>"),
    (
        "C_232_04",
        0x204c003000000c030a1232,
        "@P1 HMUL2.INVALID3 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_05",
        0x205c003000000c030a1232,
        "@P1 HMUL2.INVALID3.FMZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_06",
        0x206c003000000c030a1232,
        "@P1 HMUL2.INVALID3.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_07",
        0x207c003000000c030a1232,
        "@P1 HMUL2.INVALID3.FMZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_0c",
        0x20cc003000000c030a1232,
        "@P1 HMUL2.INVALID3 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_0d",
        0x20dc003000000c030a1232,
        "@P1 HMUL2.INVALID3.FMZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_0e",
        0x20ec003000000c030a1232,
        "@P1 HMUL2.INVALID3.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_0f",
        0x20fc003000000c030a1232,
        "@P1 HMUL2.INVALID3.FMZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_11",
        0x211c003000000c030a1232,
        "@P1 HMUL2.BF16_V2.INVALID3 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_13",
        0x213c003000000c030a1232,
        "@P1 HMUL2.BF16_V2.INVALID3.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_14",
        0x214c003000000c030a1232,
        "@P1 HMUL2.INVALID3.FTZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_15",
        0x215c003000000c030a1232,
        "@P1 HMUL2.INVALID3.INVALID3 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_16",
        0x216c003000000c030a1232,
        "@P1 HMUL2.INVALID3.FTZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_17",
        0x217c003000000c030a1232,
        "@P1 HMUL2.INVALID3.INVALID3.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_19",
        0x219c003000000c030a1232,
        "@P1 HMUL2.BF16_V2.INVALID3 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_1b",
        0x21bc003000000c030a1232,
        "@P1 HMUL2.BF16_V2.INVALID3.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_1c",
        0x21cc003000000c030a1232,
        "@P1 HMUL2.INVALID3.FTZ R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_1d",
        0x21dc003000000c030a1232,
        "@P1 HMUL2.INVALID3.INVALID3 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_1e",
        0x21ec003000000c030a1232,
        "@P1 HMUL2.INVALID3.FTZ.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_232_1f",
        0x21fc003000000c030a1232,
        "@P1 HMUL2.INVALID3.INVALID3.SAT R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "C_c31_04",
        0x836480b200000080c097c31,
        "HFMA2.INVALID3 R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_05",
        0x836580b200000080c097c31,
        "HFMA2.INVALID3.FMZ R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_06",
        0x836680b200000080c097c31,
        "HFMA2.INVALID3.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_07",
        0x836780b200000080c097c31,
        "HFMA2.INVALID3.FMZ.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    ("C_c31_0a", 0x836a80b200000080c097c31, "<rc=1>"),
    ("C_c31_0b", 0x836b80b200000080c097c31, "<rc=1>"),
    (
        "C_c31_0c",
        0x836c80b200000080c097c31,
        "HFMA2.INVALID3.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "C_c31_0d",
        0x836d80b200000080c097c31,
        "HFMA2.INVALID3.FMZ.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    ("C_c31_0e", 0x836e80b200000080c097c31, "<rc=1>"),
    ("C_c31_0f", 0x836f80b200000080c097c31, "<rc=1>"),
    (
        "C_c31_14",
        0x837480b200000080c097c31,
        "HFMA2.INVALID3.FTZ R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_15",
        0x837580b200000080c097c31,
        "HFMA2.INVALID3.OOB R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_16",
        0x837680b200000080c097c31,
        "HFMA2.INVALID3.FTZ.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    (
        "C_c31_17",
        0x837780b200000080c097c31,
        "HFMA2.INVALID3.OOB.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
    ),
    ("C_c31_1a", 0x837a80b200000080c097c31, "<rc=1>"),
    ("C_c31_1b", 0x837b80b200000080c097c31, "<rc=1>"),
    (
        "C_c31_1c",
        0x837c80b200000080c097c31,
        "HFMA2.INVALID3.FTZ.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    (
        "C_c31_1d",
        0x837d80b200000080c097c31,
        "HFMA2.INVALID3.OOB.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P0",
    ),
    ("C_c31_1e", 0x837e80b200000080c097c31, "<rc=1>"),
    ("C_c31_1f", 0x837f80b200000080c097c31, "<rc=1>"),
    (
        "C_c32_04",
        0x8204000300000080c0b7c32,
        "HMUL2.INVALID3 R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_05",
        0x8205000300000080c0b7c32,
        "HMUL2.INVALID3.FMZ R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_06",
        0x8206000300000080c0b7c32,
        "HMUL2.INVALID3.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_07",
        0x8207000300000080c0b7c32,
        "HMUL2.INVALID3.FMZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_0c",
        0x820c000300000080c0b7c32,
        "HMUL2.INVALID3 R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_0d",
        0x820d000300000080c0b7c32,
        "HMUL2.INVALID3.FMZ R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_0e",
        0x820e000300000080c0b7c32,
        "HMUL2.INVALID3.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_0f",
        0x820f000300000080c0b7c32,
        "HMUL2.INVALID3.FMZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_11",
        0x8211000300000080c0b7c32,
        "HMUL2.BF16_V2.INVALID3 R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_13",
        0x8213000300000080c0b7c32,
        "HMUL2.BF16_V2.INVALID3.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_14",
        0x8214000300000080c0b7c32,
        "HMUL2.INVALID3.FTZ R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_15",
        0x8215000300000080c0b7c32,
        "HMUL2.INVALID3.INVALID3 R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_16",
        0x8216000300000080c0b7c32,
        "HMUL2.INVALID3.FTZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_17",
        0x8217000300000080c0b7c32,
        "HMUL2.INVALID3.INVALID3.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_19",
        0x8219000300000080c0b7c32,
        "HMUL2.BF16_V2.INVALID3 R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_1b",
        0x821b000300000080c0b7c32,
        "HMUL2.BF16_V2.INVALID3.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_1c",
        0x821c000300000080c0b7c32,
        "HMUL2.INVALID3.FTZ R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_1d",
        0x821d000300000080c0b7c32,
        "HMUL2.INVALID3.INVALID3 R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_1e",
        0x821e000300000080c0b7c32,
        "HMUL2.INVALID3.FTZ.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_c32_1f",
        0x821f000300000080c0b7c32,
        "HMUL2.INVALID3.INVALID3.SAT R11, R12, UR8.H1_H1",
    ),
    (
        "C_e31_04",
        0x82040030000000402017e31,
        "HFMA2.INVALID3 R1, R2, R3, UR4",
    ),
    (
        "C_e31_05",
        0x82050030000000402017e31,
        "HFMA2.INVALID3.FMZ R1, R2, R3, UR4",
    ),
    (
        "C_e31_06",
        0x82060030000000402017e31,
        "HFMA2.INVALID3.SAT R1, R2, R3, UR4",
    ),
    (
        "C_e31_07",
        0x82070030000000402017e31,
        "HFMA2.INVALID3.FMZ.SAT R1, R2, R3, UR4",
    ),
    ("C_e31_0a", 0x820a0030000000402017e31, "<rc=1>"),
    ("C_e31_0b", 0x820b0030000000402017e31, "<rc=1>"),
    (
        "C_e31_0c",
        0x820c0030000000402017e31,
        "HFMA2.INVALID3.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "C_e31_0d",
        0x820d0030000000402017e31,
        "HFMA2.INVALID3.FMZ.RELU R1, R2, R3, UR4, P0",
    ),
    ("C_e31_0e", 0x820e0030000000402017e31, "<rc=1>"),
    ("C_e31_0f", 0x820f0030000000402017e31, "<rc=1>"),
    (
        "C_e31_14",
        0x82140030000000402017e31,
        "HFMA2.INVALID3.FTZ R1, R2, R3, UR4",
    ),
    (
        "C_e31_15",
        0x82150030000000402017e31,
        "HFMA2.INVALID3.OOB R1, R2, R3, UR4",
    ),
    (
        "C_e31_16",
        0x82160030000000402017e31,
        "HFMA2.INVALID3.FTZ.SAT R1, R2, R3, UR4",
    ),
    (
        "C_e31_17",
        0x82170030000000402017e31,
        "HFMA2.INVALID3.OOB.SAT R1, R2, R3, UR4",
    ),
    ("C_e31_1a", 0x821a0030000000402017e31, "<rc=1>"),
    ("C_e31_1b", 0x821b0030000000402017e31, "<rc=1>"),
    (
        "C_e31_1c",
        0x821c0030000000402017e31,
        "HFMA2.INVALID3.FTZ.RELU R1, R2, R3, UR4, P0",
    ),
    (
        "C_e31_1d",
        0x821d0030000000402017e31,
        "HFMA2.INVALID3.OOB.RELU R1, R2, R3, UR4, P0",
    ),
    ("C_e31_1e", 0x821e0030000000402017e31, "<rc=1>"),
    ("C_e31_1f", 0x821f0030000000402017e31, "<rc=1>"),
    (
        "F_232_allmod",
        0x46d003000000c030a1232,
        "@P1 HMUL2.INVALID1.SAT R10, -R3.H1_H1, R12.H1_H1",
    ),
    (
        "F_232_hs3_f32",
        0x44c003000000c030a1232,
        "@P1 HMUL2.INVALID1 R10, R3.H1_H1, R12.H1_H1",
    ),
    (
        "F_c32_allmod",
        0x8046100300000080c0b7c32,
        "HMUL2.INVALID1.SAT R11, -R12, UR8.H1_H1",
    ),
    (
        "F_c32_hs3_f32",
        0x8044000300000080c0b7c32,
        "HMUL2.INVALID1 R11, R12, UR8.H1_H1",
    ),
];
#[test]
fn t324_1_structure_graft_and_donors() {
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        // HFMA2 forms: full mod-lane closure under each base key
        for key in ["HFMA2_R_R_R_UR", "HFMA2_R_R_UR_R"] {
            let e = t
                .entries
                .get(key)
                .unwrap_or_else(|| panic!("{leg}: {key} missing"));
            let expect: [&str; 36] = [
                "",
                "FMZ",
                "SAT",
                "F32",
                "FMZ,SAT",
                "F32,FMZ",
                "F32,SAT",
                "F32,FMZ,SAT",
                "FTZ",
                "OOB",
                "FTZ,SAT",
                "OOB,SAT",
                "F32,FTZ",
                "F32,OOB",
                "F32,FTZ,SAT",
                "F32,OOB,SAT",
                "BF16_V2",
                "BF16_V2,FMZ",
                "BF16_V2,SAT",
                "BF16_V2,FMZ,SAT",
                "BF16_V2,FTZ",
                "BF16_V2,OOB",
                "BF16_V2,FTZ,SAT",
                "BF16_V2,OOB,SAT",
                "RELU",
                "F32,RELU",
                "FMZ,RELU",
                "F32,FMZ,RELU",
                "FTZ,RELU",
                "OOB,RELU",
                "F32,FTZ,RELU",
                "F32,OOB,RELU",
                "BF16_V2,RELU",
                "BF16_V2,FMZ,RELU",
                "BF16_V2,FTZ,RELU",
                "BF16_V2,OOB,RELU",
            ];
            for mgn in expect {
                let mg = e
                    .mod_groups
                    .get(mgn)
                    .unwrap_or_else(|| panic!("{leg}: {key}[{mgn}] missing"));
                // base-key RELU mg rows carry the pv=7 elision bake (donor law)
                let ab = mg.and_base;
                if mgn.contains("RELU") {
                    assert_eq!((ab >> 87) & 0x7, 0x7, "{leg} {key}[{mgn}] pv7 bake");
                    assert_eq!((ab >> 90) & 1, 0, "{leg} {key}[{mgn}] inv bake");
                }
                // never armed: SAT x RELU in one mg, F32 x BF16 in one mg
                let has = |m: &str| mgn.split(',').any(|x| x == m);
                assert!(
                    !(has("SAT") && has("RELU")),
                    "{leg} {key}[{mgn}] SATxRELU kill"
                );
                assert!(
                    !(has("F32") && has("BF16_V2")),
                    "{leg} {key}[{mgn}] F32xBF16 INV3"
                );
                let _ = ab;
            }
        }
        // RELU _P dotted keys (12 per parent) with pred/inv fields at tok5
        let mut hits = 0;
        for mods in [
            "RELU",
            "F32.RELU",
            "FMZ.RELU",
            "F32.FMZ.RELU",
            "FTZ.RELU",
            "OOB.RELU",
            "F32.FTZ.RELU",
            "F32.OOB.RELU",
            "BF16_V2.RELU",
            "BF16_V2.FMZ.RELU",
            "BF16_V2.FTZ.RELU",
            "BF16_V2.OOB.RELU",
        ] {
            for par in ["R_R_R_UR", "R_R_UR_R"] {
                let k = format!("HFMA2.{mods}_{par}_P");
                let e = t
                    .entries
                    .get(&k)
                    .unwrap_or_else(|| panic!("{leg}: {k} missing"));
                hits += 1;
                let mg = &e.mod_groups[""];
                let npred = mg
                    .fields
                    .iter()
                    .filter(|f| {
                        matches!(f.extraction, cubit::table::Extraction::Pred)
                            && f.shift == 87
                            && f.token_idx == 5
                    })
                    .count();
                let ninv = mg
                    .fields
                    .iter()
                    .filter(|f| {
                        matches!(f.extraction, cubit::table::Extraction::Inv)
                            && f.shift == 90
                            && f.token_idx == 5
                    })
                    .count();
                assert_eq!((npred, ninv), (1, 1), "{leg} {k} pred/inv fields");
            }
        }
        assert_eq!(hits, 24, "{leg}: dotted RELU _P key count");
        // HMUL2 forms: legal lanes only, b79 relaxed on every row.
        // SCOPE (348-kand): sm121a HMUL2_R_R_R is a dead era row measured
        // pre-existing (no tok2 field, junk ''@25, missing tok hsel fields;
        // 4,942 plain + 707 BF16 corpus words HOLE/era-wrong-claim) and stays
        // UNTOUCHED here -- the full sm121a rebuild is a separate ticket.
        for key in ["HMUL2_R_R_R", "HMUL2_R_R_UR"] {
            if leg == "sm121a" && key == "HMUL2_R_R_R" {
                let e = &t.entries[key];
                assert_eq!(
                    e.mod_groups.len(),
                    1,
                    "{leg} {key}: era row must stay untouched (348-kand)"
                );
                continue;
            }
            let e = &t.entries[key];
            for (mgn, mg) in &e.mod_groups {
                let mgn: &String = mgn;
                assert_ne!(
                    *mgn, "OOB",
                    "{leg} {key}[OOB] must NOT arm (INVALID3 print)"
                );
                assert!(
                    !mgn.contains("RELU"),
                    "{leg} {key}[{mgn}] HMUL2 RELU illegal"
                );
                assert!(
                    !mgn.contains("F32"),
                    "{leg} {key}[{mgn}] HMUL2 F32 = INVALID1"
                );
                assert_ne!(
                    mg.variable_mask & (1u128 << 79),
                    0,
                    "{leg} {key}[{mgn}] b79 text-inert relax"
                );
            }
            for mgn in [
                "FMZ",
                "SAT",
                "FMZ,SAT",
                "FTZ",
                "FTZ,SAT",
                "BF16_V2",
                "BF16_V2,FMZ",
                "BF16_V2,SAT",
                "BF16_V2,FMZ,SAT",
                "BF16_V2,FTZ",
                "BF16_V2,FTZ,SAT",
            ] {
                assert!(
                    e.mod_groups.contains_key(mgn),
                    "{leg}: {key}[{mgn}] missing"
                );
            }
        }
    }
    // donors byte-pinned: no 324 lanes on sm100a/sm103a
    for leg in ["sm100a", "sm103a"] {
        let t = tab(leg);
        assert!(
            t.entries.get("HFMA2_R_R_R_UR").is_none(),
            "{leg}: donor got e31"
        );
        for k in t.entries.keys() {
            assert!(
                !(k.starts_with("HFMA2.") && k.contains("RELU_R_R_R_UR_P")),
                "{leg}: donor dotted 324 key: {k}"
            );
            if k == "HMUL2_R_R_R" || k == "HMUL2_R_R_UR" || k == "HFMA2_R_R_UR_R" {
                for (mgn, _mg) in &t.entries[k].mod_groups {
                    let mgn: &String = mgn;
                    assert!(!mgn.contains("RELU"), "{leg} {k}[{mgn}] donor RELU lane");
                }
            }
        }
    }
}

#[test]
fn t324_2_decode_vendor_exact_x2() {
    let t120 = tab("sm120");
    let t121 = tab("sm121a");
    for (tag, w, text) in LEGAL_CASES {
        // HMUL2 forms have no tok4 slot: F_*_neg4 probes park b84 on a
        // vendor-inert stray bit (289-era status quo: stays care => HOLE).
        if matches!(*tag, "F_232_neg4_ftz" | "F_c32_neg4_ftz") {
            continue;
        }
        assert_eq!(dec(&t120, *w).as_deref(), Some(*text), "sm120 decode {tag}");
        if tag.contains("_232_") {
            // 348-kand residuum: sm121a HMUL2_R_R_R era row is dead
            // (bits missing: guard field split, tok hsel fields absent,
            // and_base era-bakes tok junk) -- every 0x232 host word is HOLE
            // on sm121a pre-existing (5,650 corpus words today); the 324
            // lane clones inherit the era care. Pin the unchanged era state
            // as a tripwire until the row rebuild (separate item).
            assert_eq!(dec(&t121, *w), None, "sm121a era-HOLE {tag}");
        } else {
            assert_eq!(
                dec(&t121, *w).as_deref(),
                Some(*text),
                "sm121a decode {tag}"
            );
        }
    }
}

#[test]
fn t324_3_encode_mint_roundtrip_and_relu_pred() {
    const CASES: &[(&str, &str)] = &[
        ("HFMA2.SAT R1, R2, R3, UR4", "HFMA2.SAT R1, R2, R3, UR4"),
        (
            "HFMA2.F32.FMZ.SAT R1, R2, R3, UR4",
            "HFMA2.F32.FMZ.SAT R1, R2, R3, UR4",
        ),
        (
            "HFMA2.BF16_V2.OOB R1, R2, R3, UR4",
            "HFMA2.BF16_V2.OOB R1, R2, R3, UR4",
        ),
        (
            "HFMA2.RELU R1, R2, R3, UR4, P2",
            "HFMA2.RELU R1, R2, R3, UR4, P2",
        ),
        ("HFMA2.RELU R1, R2, R3, UR4", "HFMA2.RELU R1, R2, R3, UR4"),
        (
            "HFMA2.RELU R1, R2, R3, UR4, !PT",
            "HFMA2.RELU R1, R2, R3, UR4, !PT",
        ),
        (
            "HFMA2.F32.RELU R1, R2, R3, UR4, P5",
            "HFMA2.F32.RELU R1, R2, R3, UR4, P5",
        ),
        (
            "HFMA2.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
            "HFMA2.SAT R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
        ),
        (
            "HFMA2.BF16_V2.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P1",
            "HFMA2.BF16_V2.RELU R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1, P1",
        ),
        (
            "HMUL2.SAT R10, R3.H1_H1, R12.H1_H1",
            "HMUL2.SAT R10, R3.H1_H1, R12.H1_H1",
        ),
        (
            "HMUL2.BF16_V2.FTZ.SAT R11, R12, UR8.H1_H1",
            "HMUL2.BF16_V2.FTZ.SAT R11, R12, UR8.H1_H1",
        ),
    ];
    for leg in ["sm120", "sm121a"] {
        let t = tab(leg);
        for (authored, expect) in CASES {
            // sm121a HMUL2_R_R_R era row lacks tok2/3 fields entirely (dead
            // pre-existing row, 348-kand): mint must stay loud-fail there.
            if leg == "sm121a" && (authored.starts_with("HMUL2.SAT R10,")) {
                assert!(
                    enc(&t, authored).is_err(),
                    "sm121a era fail-closed [{authored}] (348-kand)"
                );
                continue;
            }
            let w = enc(&t, authored).unwrap_or_else(|e| panic!("{leg} mint [{authored}]: {e}"));
            let rt = dec(&t, w).unwrap_or_else(|| panic!("{leg} redecode [{authored}]"));
            assert_eq!(&rt, expect, "{leg} roundtrip [{authored}]");
            // RELU pred law: elided form bakes pv=7/inv=0; explicit pred mints pv
            if *authored == "HFMA2.RELU R1, R2, R3, UR4" {
                assert_eq!((w >> 87) & 0x7, 0x7, "{leg} RELU elide bake");
            }
            if authored.contains(", P2") {
                assert_eq!((w >> 87) & 0x7, 0x2, "{leg} RELU pv2 mint");
            }
            if authored.contains("!PT") {
                assert_eq!((w >> 87) & 0x7, 0x7, "{leg} RELU !PT pv");
                assert_eq!((w >> 90) & 1, 1, "{leg} RELU !PT inv");
            }
        }
    }
}

#[test]
fn t324_4_doctrine_holes_and_failclosed_encode() {
    let t120 = tab("sm120");
    let t121 = tab("sm121a");
    // stray pair (b84 has no tok4 slot on HMUL2; vendor text-inert):
    for tag in ["F_232_neg4_ftz", "F_c32_neg4_ftz"] {
        let (_, w, text) = LEGAL_CASES.iter().find(|(t, _, _)| *t == tag).unwrap();
        assert!(!text.contains('<') && !text.contains("INVALID"));
        assert_eq!(dec(&t120, *w), None, "sm120 stray stays closed {tag}");
        assert_eq!(dec(&t121, *w), None, "sm121a stray stays closed {tag}");
    }
    for (tag, w, print) in HOLE_CASES {
        assert_eq!(dec(&t120, *w), None, "sm120 doctrine {tag} [{print}]");
        assert_eq!(dec(&t121, *w), None, "sm121a doctrine {tag} [{print}]");
    }
    // w324: lone corpus INVALID1-class witness (t10.cubin@0x410, HMUL2 b78)
    const W324: u128 = 0x405d080000342c28087232;
    assert_eq!(dec(&t120, W324), None, "w324 INVALID1 must stay HOLE");
    assert_eq!(
        dec(&t121, W324),
        None,
        "w324 INVALID1 must stay HOLE (121a)"
    );
    // encode fail-closed: kill/doctrine classes
    for authored in [
        "HFMA2.SAT.RELU R1, R2, R3, UR4",
        "HFMA2.BF16_V2.F32 R1, R2, R3, UR4",
        "HMUL2.F32 R10, R3.H1_H1, R12.H1_H1",
        "HMUL2.OOB R10, R3.H1_H1, R12.H1_H1",
        "HMUL2.RELU R11, R12, UR8.H1_H1, P2",
        "HFMA2.RELU R1, R2, R3, UR4, P8",
    ] {
        assert!(
            enc(&t120, authored).is_err(),
            "sm120 mint must fail: {authored}"
        );
        assert!(
            enc(&t121, authored).is_err(),
            "sm121a mint must fail: {authored}"
        );
    }
}

#[test]
fn t324_5_corpus_anchors_unchanged() {
    let t120 = tab("sm120");
    let t121 = tab("sm121a");
    // corpus witnesses on the touched kraty decode EXACTLY as before (plain rows)
    const WIT: &[(u128, &str)] = &[
        (
            0x816080b200000080c097c31,
            "HFMA2 R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
        ),
        (
            0x836080b200000080c097c31,
            "HFMA2.BF16_V2 R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1",
        ),
        (0xc003000000c030a1232, "@P1 HMUL2 R10, R3.H1_H1, R12.H1_H1"),
        (
            0x200c003000000c030a1232,
            "@P1 HMUL2.BF16_V2 R10, R3.H1_H1, R12.H1_H1",
        ),
        (0x8000000300000080c0b7c32, "HMUL2 R11, R12, UR8.H1_H1"),
        (
            0x8200000300000080c0b7c32,
            "HMUL2.BF16_V2 R11, R12, UR8.H1_H1",
        ),
        // BUG-321 sibling anchor on the 0x231 R_R_R_R lattice (320 fix)
        (
            0x405d080000342c28087231,
            "HFMA2.F32.FMZ R8, -R40.H1_H1, R44.H0_NH1, R8",
        ),
    ];
    for (w, text) in WIT {
        assert_eq!(
            dec(&t120, *w).as_deref(),
            Some(*text),
            "sm120 anchor {w:#x}"
        );
        if (*w & 0xfff) == 0x232 {
            // 348-kand: sm121a HMUL2_R_R_R era row = dead, HOLE pre/post
            assert_eq!(dec(&t121, *w), None, "sm121a era-HOLE {w:#x}");
        } else {
            assert_eq!(
                dec(&t121, *w).as_deref(),
                Some(*text),
                "sm121a anchor {w:#x}"
            );
        }
    }
}

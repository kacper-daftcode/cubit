// mk68: (1) a UISETP imm+imm pair -> additionally 42103e06 on the EX-tail lane;
// (2) F2FP fp8 SATFINITE -> 4212ec26, F2FP fp8->f16 UNPACK_B -> 4112720a;
// (3) ULOP3.LUT 0606: class (A) UP-write with tok1=URn, class (B) 0xb8/0x80000000,
//     the negative classes (UP with tok1=URZ, plain 6-tok) are recordless.
use cubit::ir::{ControlCode, Guard, Instruction};
use cubit::sass_file::{merc_mini2_scan, merc_usetp_scan};

fn mk_ins(lane: u32, opf: &str, text: &str, guard: Option<Guard>) -> Instruction {
    Instruction {
        addr: lane * 16,
        opcode: opf.split('.').next().unwrap_or(opf).to_string(),
        opcode_full: opf.to_string(),
        key: String::new(),
        guard,
        operands: Vec::new(),
        modifiers: Vec::new(),
        ctrl: ControlCode::default(),
        hand_sched: false,
        rsd: None,
        raw_text: text.to_string(),
    }
}

fn pair_immimm() -> Vec<Instruction> {
    vec![
        mk_ins(9, "UISETP", "UISETP.GT.U32.AND UP2, UPT, UR8, 0x7f, UPT ;", None),
        mk_ins(10, "UISETP.GT.AND.EX", "UISETP.GT.AND.EX UP2, UPT, UR9, -0x1, UPT, UP2 ;", None),
    ]
}

#[test]
fn mk68_para_immimm_daje_3e06_na_tail() {
    let (m, _u) = merc_usetp_scan(&pair_immimm());
    assert!(m.contains(&(9, 1)), "klasa 3406 na head: {:?}", m);
    assert!(m.contains(&(10, 3)), "3e06 na tail: {:?}", m);
    assert!(!m.contains(&(10, 2)), "4014 wygaszony gdy tail ma imm: {:?}", m);
}

#[test]
fn mk68_f2fp_fp8_minis() {
    let ins = vec![
        mk_ins(3, "F2FP.E4M3.F32.PACK_AB_MERGE_C.SATFINITE", "F2FP.E4M3.F32.PACK_AB_MERGE_C.SATFINITE R8, R44, R32, R5 ;", None),
        mk_ins(4, "F2FP.E5M2.F32.PACK_AB_MERGE_C.SATFINITE", "F2FP.E5M2.F32.PACK_AB_MERGE_C.SATFINITE R10, R46, R34, R7 ;", None),
        mk_ins(5, "F2FP.E4M3.F16.UNPACK_B", "F2FP.E4M3.F16.UNPACK_B R6, R50 ;", None),
        mk_ins(6, "F2FP.E5M2.F16.UNPACK_B", "F2FP.E5M2.F16.UNPACK_B R7, R51 ;", None),
        // counterexamples: TF32 and plain PACK_AB without an mk68 mini
        mk_ins(7, "F2FP.F16.F32.PACK_AB", "F2FP.F16.F32.PACK_AB R0, RZ, R0 ;", None),
        mk_ins(8, "F2FP.BF16.F32.PACK_AB", "F2FP.BF16.F32.PACK_AB R1, RZ, R1 ;", None),
    ];
    let v = merc_mini2_scan("kern_plain", &ins);
    assert!(v.contains(&(3, 0x26ec1242)), "{:?}", v); // 42 12 ec 26
    assert!(v.contains(&(4, 0x26ec1242)), "{:?}", v);
    assert!(v.contains(&(5, 0x0a721241)), "{:?}", v); // 41 12 72 0a
    assert!(v.contains(&(6, 0x0a721241)), "{:?}", v);
    assert!(!v.iter().any(|&(l, _)| l == 7 || l == 8), "{:?}", v);
}

#[test]
fn mk68_ulop3_0606() {
    let ins = vec![
        // (A) UP-write z tok1 = URn: TAK
        mk_ins(11, "ULOP3", "ULOP3.LUT UP0, UR7, UR7, 0x3, URZ, 0xc0, !UPT ;", None),
        // neg: UP-write z tok1 = URZ: NIE
        mk_ins(12, "ULOP3", "ULOP3.LUT UP0, URZ, UR5, 0x10, URZ, 0xc0, !UPT ;", None),
        // (B) sign-mask idiom: TAK
        mk_ins(13, "ULOP3", "ULOP3.LUT UR4, URZ, 0x80000000, UR9, 0xb8, !UPT ;", None),
        // neg: zwykly ULOP3 UR-dst 6-tok: NIE
        mk_ins(14, "ULOP3", "ULOP3.LUT UR4, UR4, 0x1ffffffe, URZ, 0xc0, !UPT ;", None),
        // neg: ULOP3 with lut 0xc0 without UP and without the 0xb8 idiom: NO (critical: contains
        // 0xc0 but neither 0xb8 nor 0x80000000)
        mk_ins(15, "ULOP3", "ULOP3.LUT UR7, UR5, 0xf, URZ, 0xc0, !UPT ;", None),
    ];
    let v = merc_mini2_scan("kern_plain", &ins);
    assert!(v.contains(&(11, 0x06062a42)), "{:?}", v); // 42 2a 06 06
    assert!(v.contains(&(13, 0x06062a42)), "{:?}", v);
    assert!(!v.iter().any(|&(l, _)| l == 12 || l == 14 || l == 15), "{:?}", v);
}

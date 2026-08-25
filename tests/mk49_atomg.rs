//! mk49: rekordy 024e*32 (32B) — rodzina ATOM.E/ATOMG/ATOMS (domkniecie
//! frontu mk48: 024e2032/024e3032/024e6832/024e8a32/024e8232 orig-only +
//! mistaken mk14-tuple classes for 024e5232-b6/b7, 024e2432-b7, 024e8432).
//!
//! sm_100 corpus (676 files): full byte agreement 11898/11898 records,
//! 2929/2929 kerneli, porzadek strumienia == lane-asc. CAST.SPIN /
//! ATOM.E.CAS.* are recordless (c8: once skipped, pairing is 1:1).
//! Tabela klas (b2): 20=ATOM.E desc float (b6: F16x2 00 / BF16x2 18 /
//! F32 48 / F64 78), 68=ATOM.E desc int (ADD 00 / ADD.64 60 / MAX.S32 42 /
//! MAX.S64 a2), 30=ATOMG float [Rn] (b6=80, b7: F32 44 / F64 47),
//! 24=ATOMG CAS (b7: GPU 68 / SYS 88 / .64 SYS 89), 52=ATOMG int
//! (b6: ADD 00 / MIN 10 / MAX 20 / INC 30 / EXCH 80; b7=40|04.S32),
//! 82=ATOMS [Rn(+imm)] ADD, 84=ATOMS [URn(+imm)] (MIN 14 / MAX 24 /
//! AND 54 / OR 64), 8a=ATOMS.POPC.INC [Rn+URZ(+imm)].
//! b8=01 instead of 03 for 82/8a from libcusparse.so.782 = parked (sub-driver).
//! The vectors below = appended (text -> record) pairs from the corpus (c10).
use cubit::mercury::{merc_atomg2_record, merc_atomg2_recordless};

trait Hex {
    fn hexify(&self) -> String;
}
impl Hex for [u8; 32] {
    fn hexify(&self) -> String {
        self.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[test]
fn atom_desc_float_forms() {
    // F64 (cusparse.110 csrmv_v3)
    assert_eq!(
        merc_atomg2_record("ATOM.E.ADD.F64.RN.STRONG.GPU P0, RZ, desc[UR6][R10.64], R14 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024e2032f8007834000000000100c1ff0082020a008201820300000000000000"
    );
    // F32.FTZ (cusparse.110)
    assert_eq!(
        merc_atomg2_record(
            "ATOM.E.ADD.F32.FTZ.RN.STRONG.GPU P1, RZ, desc[UR6][R2.64], R9 ;",
            0xf8
        )
        .unwrap()
        .hexify(),
        "024e2032f8004834000000000108c1ff0082000a008201400200000000000000"
    );
    // F16 x2 (cusparse.158 coomm)
    assert_eq!(
        merc_atomg2_record(
            "ATOM.E.ADD.F16 x2.RN.STRONG.GPU P4, RZ, desc[UR16][R4.64], R7 ;",
            0xf8
        )
        .unwrap()
        .hexify(),
        "024e2032f8000034000000000120c1ff0002010a000204c00100000000000000"
    );
    // BF16 x2 (cusparse.158 coomm)
    assert_eq!(
        merc_atomg2_record(
            "ATOM.E.ADD.BF16 x2.RN.STRONG.GPU P4, RZ, desc[UR16][R4.64], R7 ;",
            0xf8
        )
        .unwrap()
        .hexify(),
        "024e2032f8001834000000000120c1ff0002010a000204c00100000000000000"
    );
}

#[test]
fn atom_desc_int_forms() {
    // ADD domyslny (cusolver.213)
    assert_eq!(
        merc_atomg2_record(
            "ATOM.E.ADD.STRONG.GPU PT, RZ, desc[UR4][R16.64+0x4], R15 ;",
            0xf8
        )
        .unwrap()
        .hexify(),
        "024e6832f80000340000000001f8c1ff0002040a000201c00300000004000000"
    );
    // ADD.64 with a non-RZ dst (|3 on dest) (cusparse.318)
    assert_eq!(
        merc_atomg2_record(
            "ATOM.E.ADD.64.STRONG.GPU P1, R8, desc[UR8][R10.64+0x8], R8 ;",
            0xf8
        )
        .unwrap()
        .hexify(),
        "024e6832f800603400000000010803020082020a000202020200000008000000"
    );
    // MAX.S32 (cusparse.318)
    assert_eq!(
        merc_atomg2_record(
            "ATOM.E.MAX.S32.STRONG.GPU PT, RZ, desc[UR4][R2.64+0x4], R7 ;",
            0xf8
        )
        .unwrap()
        .hexify(),
        "024e6832f80042340000000001f8c1ff0082000a000201c00100000004000000"
    );
    // MAX.S64 (cusparse.318)
    assert_eq!(
        merc_atomg2_record(
            "ATOM.E.MAX.S64.STRONG.GPU P0, RZ, desc[UR4][R10.64+0x8], R8 ;",
            0xf8
        )
        .unwrap()
        .hexify(),
        "024e6832f800a234000000000100c1ff0082020a000201020200000008000000"
    );
}

#[test]
fn atomg_forms() {
    // F64 non-desc (cublasLt.548 cutlass_80 imma-emu)
    assert_eq!(
        merc_atomg2_record("ATOMG.E.ADD.F64.RN.STRONG.GPU PT, RZ, [R132], R4 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024e3032f80080470300000001f8c1ff0002210a000201000000000000000000"
    );
    // CAS.64 SYS (cusolver.510 csrIlu0)
    assert_eq!(
        merc_atomg2_record("ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R20], R8, R10 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024e2432f80000890000000001f883020002050a000202820200000000000000"
    );
    // int desc z guardem @P0 (cublas.219 trsv): b4=00, [21:23)=descUR
    assert_eq!(
        merc_atomg2_record(
            "@P0 ATOMG.E.ADD.STRONG.GPU PT, R5, desc[UR8][R4.64], R7 ;",
            0x00
        )
        .unwrap()
        .hexify(),
        "024e5232000000400300000001f841010002010a000202c00100000000000000"
    );
    // MIN desc (cublasLt.191 splitKreduce)
    assert_eq!(
        merc_atomg2_record(
            "@P0 ATOMG.E.MIN.STRONG.GPU PT, RZ, desc[UR6][R4.64], R3 ;",
            0x00
        )
        .unwrap()
        .hexify(),
        "024e5232000010400300000001f8c1ff0002010a008201c00000000000000000"
    );
    // MAX.S32 desc: b7 40|04
    assert_eq!(
        merc_atomg2_record(
            "@P0 ATOMG.E.MAX.S32.STRONG.GPU PT, RZ, desc[UR6][R4.64], R3 ;",
            0x00
        )
        .unwrap()
        .hexify(),
        "024e5232000020440300000001f8c1ff0002010a008201c00000000000000000"
    );
    // EXCH (cusolver.1002 sytrd4)
    assert_eq!(
        merc_atomg2_record("ATOMG.E.EXCH.STRONG.GPU PT, RZ, desc[UR8][R6.64], R3 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024e5232f80080400300000001f8c1ff0082010a000202c00000000000000000"
    );
}

#[test]
fn atoms_forms() {
    // 82: [Rn] without imm (cusparse.838 cub DeviceRadixSort)
    assert_eq!(
        merc_atomg2_record("ATOMS.ADD R58, [R57], R54 ;", 0xf8).unwrap().hexify(),
        "024e8232f800046003000000810e400e000a00800d0000000000000000000000"
    );
    // 84: MIN.S32 [UR4] z @P0 (cusolver.1528 gebal)
    assert_eq!(
        merc_atomg2_record("@P0 ATOMS.MIN.S32 RZ, [UR4], R0 ;", 0x00)
            .unwrap()
            .hexify(),
        "024e84320000146403000000c1ffc0ff0000010a000000000000000000000000"
    );
    // 84: MAX.S32 [UR5] (cublasLt.507)
    assert_eq!(
        merc_atomg2_record("@P0 ATOMS.MAX.S32 RZ, [UR5], R0 ;", 0x00)
            .unwrap()
            .hexify(),
        "024e84320000246403000000c1ffc0ff0040010a000000000000000000000000"
    );
    // 84: OR [UR4] (cusolver.771 irs_check) — plain, no-imm only
    assert_eq!(
        merc_atomg2_record("@P0 ATOMS.OR RZ, [UR4], R2 ;", 0x00)
            .unwrap()
            .hexify(),
        "024e84320000646003000000c1ffc0ff0000010a008000000000000000000000"
    );
    // 8a: POPC.INC [R0+URZ+0x3c] (cusolver.1020 laed2)
    assert_eq!(
        merc_atomg2_record("ATOMS.POPC.INC.32 RZ, [R0+URZ+0x3c] ;", 0xf8)
            .unwrap()
            .hexify(),
        "024e8a32f800b46203000000c1ff000000c0ff0a00000000000000003c000000"
    );
}

#[test]
fn recordless_forms() {
    // F64 CAS-emulation spin loop (cusparse) — recordless
    assert!(merc_atomg2_record(
        "ATOMS.CAST.SPIN.64 P0, [R3], R4, R6 ;",
        0xf8
    )
    .is_none());
    assert!(merc_atomg2_record(
        "ATOM.E.CAST.SPIN.64 PT, R6, [R10], R4, R6 ;",
        0xf8
    )
    .is_none());
    assert!(merc_atomg2_record("ATOM.E.CAS.STRONG.GPU P0, R4, [R2], R6, R8 ;", 0xf8).is_none());
    assert!(merc_atomg2_recordless("ATOMS.CAST.SPIN P0, [R0], R4, R5 ;"));
    assert!(merc_atomg2_recordless("ATOM.E.CAST.SPIN.64 PT, R6, [R10], R4, R6 ;"));
    assert!(merc_atomg2_recordless("ATOM.E.CAS.STRONG.GPU P0, R4, [R2], R6, R8 ;"));
    // inne klasy nietkniete
    assert!(!merc_atomg2_recordless("REDG.E.ADD.F64.RN.STRONG.GPU desc[UR12][R10.64], R28 ;"));
    assert!(!merc_atomg2_recordless("ATOMG.E.ADD.STRONG.GPU PT, R5, desc[UR8][R4.64], R7 ;"));
}

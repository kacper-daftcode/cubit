//! BUG-241 (F2-iter121, front2/blind, 2026-08-28): spelled-form encode HOLE
//! closure + decode twins (canonical 50d9e7b; patch241{a,b,c,d,e}.py
//! replayable+idempotent).
//!
//! Pre-fix state (probe240 ENC-ERR set + gold241 pre-census, 2,406-file
//! battery x 4 table legs vs vendor nvdisasm 13.3.73 at-address):
//!   encode HOLEs (fail-closed): HADD2.F32 R-form, SHF.L.U32,
//!   SHF.R.{S32,U32}.HI, LOP3.LUT dual-pred _II_P, UI2F.U32.RP_UR_UR,
//!   IMNMX.U64 _II_;
//!   decode twins: sm120 HADD2.F32 316,207 DIFF + HADD2 24,501 + BF16_V2
//!   5,956 (era rows dropped fields / 4-token monster), LOP3.LUT 7,196 DIFF
//!   + 2,524 HOLE (P-form swallowed leading pred / R-row leaked the leading
//!   value into the tail print), SHF.L.U32 630, SHF.L.U64.HI 10,350,
//!   SHF.R.U64 14 HOLE; donors: HADD2.F32 316,207 (tok2 neg drop),
//!   LOP3.LUT 15,303 (same P-law).
//!
//! Arb laws (arb241.json, transplant probes, vendor prints):
//!   HADD2 'F32': tok2 neg@72 + hsel 2b@74, tok3 abs@62 (also grafted on
//!     donors; 316k-line defect cured both sides).
//!   LOP3 II_P: leading pred 3b@81 (7/PT = absent -> R-form), tail pred
//!     3b@87 + neg@90; b80 = .PAND; R-form leading slot == PT on
//!     495,789/495,789 R-form lines (lop3law.json, 602,411 total).
//!   IMNMX II cells (b73,b74): (1,1)=S64 (0,1)=U64 (1,0)=bare (0,0)=U32
//!     (arb flips on the imnmx2 vendor II word @0x80).
//!   UI2F.U32.RP URd,URs: dst ureg 8b@16, src ureg 8b@32; b62/63/73/80/90
//!     inert, b109 ILLEGAL; zero corpus exposure (stays arb-anchored).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96G: u128 = (1u128 << 96) - 1; // guard kept, sched/ctrl zone masked
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> String {
    let idx = DecodeIndex::build(t);
    let d = idx.decode(w, 0, t).expect("decode");
    to_sass(&d)
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}
fn enc_err(t: &IsaTable, text: &str) -> String {
    let insn = parse_sass(text, 0).unwrap();
    format!("{}", encode_instruction(&insn, t).unwrap_err())
}

#[test]
fn t241_1_structure_law() {
    let t120 = tab("sm120");
    let h = &t120.entries["HADD2_R_R_R"].mod_groups;
    for mg in ["", "BF16_V2", "F32"] {
        assert!(h.contains_key(mg), "sm120 HADD2_R_R_R missing mg {mg:?}");
    }
    let f32 = &h["F32"];
    fn rustext(e: &str) -> &'static str {
        match e {
            "neg" => "Neg",
            "hsel" => "HalfSel",
            "abs" => "Abs",
            "pred" => "Pred",
            "imm" => "Imm",
            "ureg" => "UReg",
            "reg" => "Reg",
            _ => "?",
        }
    }
    let has = |r: &cubit::table::ModGroupEntry, e: &str, bits: u32, shift: u32, tok: i32| {
        let want = rustext(e);
        r.fields.iter().any(|f| {
            format!("{:?}", f.extraction) == want
                && f.bits == bits
                && f.shift == shift
                && f.token_idx == tok
        })
    };
    assert!(has(f32, "neg", 1, 72, 2), "F32 tok2 neg@72 (arb241 b72)");
    assert!(
        has(f32, "hsel", 2, 74, 2),
        "F32 tok2 hsel@74 (arb241 b74/75)"
    );
    assert!(has(f32, "abs", 1, 62, 3), "F32 tok3 abs@62 (arb241 b62)");
    // donor parity on the grafted row (239-law)
    let d100 = tab("sm100a");
    let d103 = tab("sm103a");
    let fa = &d100.entries["HADD2_R_R_R"].mod_groups["F32"];
    let fb = &d103.entries["HADD2_R_R_R"].mod_groups["F32"];
    assert_eq!(
        fa.fields.len(),
        fb.fields.len(),
        "donor F32 field-count parity"
    );
    // LOP3 law: P-rows carry leading pred 3b@81 + tail pred 3b@87 + neg@90
    for arch in ["sm120", "sm100a", "sm103a"] {
        let t = tab(arch);
        let p = &t.entries["LOP3_P_R_R_R_R_II_P"].mod_groups["LUT"];
        assert!(has(p, "pred", 3, 81, 1), "{arch} P-row tok1 pred 3b@81");
        assert!(has(p, "pred", 3, 87, 7), "{arch} P-row tok7 pred 3b@87");
        assert!(has(p, "neg", 1, 90, 7), "{arch} P-row tok7 neg@90");
        assert!(has(p, "imm", 8, 72, 6), "{arch} P-row imm 8b@72 (b80=PAND)");
        assert!(
            t.entries["LOP3_P_R_R_R_R_II_P"]
                .mod_groups
                .contains_key("LUT,PAND"),
            "{arch} PAND mg present"
        );
        // R-rows: bake PT(7) in the leading-pred 4b window, tail @87/90
        let r = &t.entries["LOP3_R_R_UR_R_II_P"].mod_groups["LUT"];
        let ab = r.and_base;
        assert_eq!((ab >> 81) & 0xF, 0x7, "{arch} R-row bakes PT leading slot");
        // IMNMX II cell set
        let bk = &t.entries["IMNMX_P_P_R_R_II_P_P"].mod_groups;
        for (mg, cell) in [
            ("S64", 0x3u128 << 73),
            ("U64", 0x1 << 74),
            ("", 0x1 << 73),
            ("U32", 0),
        ] {
            let row = bk
                .get(mg)
                .unwrap_or_else(|| panic!("{arch} IMNMX-II mg {mg:?}"));
            assert_eq!(
                row.and_base & (0x3 << 73),
                cell,
                "{arch} IMNMX-II {mg:?} cell"
            );
        }
    }
    // sm120: typed-II dead '' row removed (240 alias covers the route)
    assert!(!t120.entries["IMNMX.S64_P_P_R_R_II_P_P"]
        .mod_groups
        .contains_key(""));
    // SHF donor-only mg graft
    assert!(t120.entries["SHF_R_R_II_R"]
        .mod_groups
        .contains_key("HI,L,U64"));
    // UI2F src graft
    let u = &t120.entries["UI2F_UR_UR"].mod_groups["RP,U32"];
    assert!(has(u, "ureg", 8, 32, 2), "UI2F_UR_UR src ureg@32");
}

#[test]
fn t241_2_decode_anchors_vendor_true() {
    let t120 = tab("sm120");
    let t100 = tab("sm100a");
    let t103 = tab("sm103a");
    // HADD2 family (vendor corpus words; gold241_pre samples)
    let cases: &[(u128, &str)] = &[
        (
            0x004fca000000410020000016ff167230,
            "HADD2.F32 R22, -RZ, R22.H0_H0",
        ),
        (
            0x002fe40000000800200000ff09097230,
            "HADD2 R9, R9.H0_H0, RZ.H0_H0",
        ),
        (
            0x002fca0000200800200000ff1e047230,
            "HADD2.BF16_V2 R4, R30.H0_H0, RZ.H0_H0",
        ),
    ];
    for (w, g) in cases {
        assert_eq!(dec(&t120, *w), *g, "sm120 HADD2");
        assert_eq!(dec(&t100, *w), *g, "sm100a HADD2");
        assert_eq!(dec(&t103, *w), *g, "sm103a HADD2");
    }
    // LOP3 P-form law (anchors incl. reuse + non-PT tail + crafted PAND)
    let pcases: &[(u128, &str)] = &[
        (
            0x000fda000f80fcff0000000408ff7c12,
            "LOP3.LUT P0, RZ, R8, UR4, RZ, 0xfc, !PT",
        ),
        (
            0x000fda000082fcff000000071bff7212,
            "LOP3.LUT P1, RZ, R27, R7, RZ, 0xfc, P1",
        ),
        (
            0x040fe2000780a009000000ff0c087212,
            "LOP3.LUT P0, R8, R12.reuse, RZ, R9, 0xa0, !PT",
        ),
        (
            0x000fda000f80fcff0000000408ff7c12 | (1 << 80),
            "LOP3.LUT.PAND P0, RZ, R8, UR4, RZ, 0xfc, !PT",
        ),
        (
            0x000fc800078ec0fffffffff80c0c7812,
            "LOP3.LUT R12, R12, 0xfffffff8, RZ, 0xc0, !PT",
        ), // R-form regression
    ];
    for (w, g) in pcases {
        assert_eq!(dec(&t120, *w), *g, "sm120 LOP3");
        assert_eq!(dec(&t100, *w), *g, "sm100a LOP3");
    }
    // SHF anchors (UR lane / II / L.U64.HI reuse, no neg ghosts)
    let scases: &[(u128, &str)] = &[
        (
            0x004fe200080006ff0000000403037c19,
            "SHF.L.U32 R3, R3, UR4, RZ",
        ),
        (
            0x140fe200000102070000000406197819,
            "SHF.L.U64.HI R25, R6.reuse, 0x4, R7.reuse",
        ),
        (
            0x000fc80000001200369cf25805007419,
            "SHF.R.U64 R0, R5, R0, 0x369cf258",
        ),
    ];
    for (w, g) in scases {
        assert_eq!(dec(&t120, *w), *g, "sm120 SHF {g}");
    }
    // IMNMX II cell law x4 (arb planes on the imnmx2 sm_120a vendor word)
    let im = 0x008fcc0003ffe6000007ffff02047817u128;
    for t in [&t120, &t100, &t103] {
        assert_eq!(dec(t, im), "IMNMX.S64 PT, PT, R4, R2, 0x7ffff, PT, !PT");
        assert_eq!(
            dec(t, im ^ (1 << 73)),
            "IMNMX.U64 PT, PT, R4, R2, 0x7ffff, PT, !PT"
        );
        assert_eq!(
            dec(t, im ^ (1 << 74)),
            "IMNMX PT, PT, R4, R2, 0x7ffff, PT, !PT"
        );
        assert_eq!(
            dec(t, im ^ (3 << 73)),
            "IMNMX.U32 PT, PT, R4, R2, 0x7ffff, PT, !PT"
        );
    }
    // b4fill2/bug059-era word: vendor truth is bare IMNMX, no abs ghost
    for t in [&t120, &t100, &t103] {
        assert_eq!(
            dec(t, 0x020fec00038002000003ffffdada7817),
            "IMNMX P0, P0, R218, R218, 0x3ffff, PT, P0"
        );
    }
    // UI2F crafted (arb law; zero corpus exposure)
    let ut = &t120.entries["UI2F_UR_UR"].mod_groups["RP,U32"];
    let w = (ut.and_base & !(0xff << 16) & !(0xff << 32)) | (8 << 16) | (4 << 32);
    assert_eq!(dec(&t120, w), "UI2F.U32.RP UR8, UR4");
}

#[test]
fn t241_3_encode_anchors() {
    let t120 = tab("sm120");
    let t103 = tab("sm103a");
    // Text -> exact vendor word (masked: sched/ctrl zone [127:96) dropped)
    let mask = M96G;
    let pairs: &[(&str, u128)] = &[
        (
            "HADD2.F32 R22, -RZ, R22.H0_H0 ;",
            0x004fca000000410020000016ff167230,
        ),
        (
            "HADD2 R9, R9.H0_H0, RZ.H0_H0 ;",
            0x002fe40000000800200000ff09097230,
        ),
        (
            "HADD2.BF16_V2 R4, R30.H0_H0, RZ.H0_H0 ;",
            0x002fca0000200800200000ff1e047230,
        ),
        (
            "LOP3.LUT P1, RZ, R27, R7, RZ, 0xfc, P1 ;",
            0x000fda000082fcff000000071bff7212,
        ),
        (
            "SHF.L.U32 R3, R3, UR4, RZ ;",
            0x004fe200080006ff0000000403037c19,
        ),
        (
            "SHF.R.U64 R0, R5, R0, 0x369cf258 ;",
            0x000fc80000001200369cf25805007419,
        ),
    ];
    for (text, want) in pairs {
        for t in [&t120, &t103] {
            let w = enc(t, text);
            assert_eq!(w & mask, want & mask, "encode {text}");
            assert_eq!(&dec(t, w), text.trim_end_matches(" ;"), "roundtrip {text}");
        }
    }
    // probe240 HOLE list now encodes everywhere reachable (sm120 lead)
    for text in [
        "HADD2.F32 R1, R2, R3 ;",
        "SHF.L.U32 R1, R2, 0x0, R3 ;",
        "SHF.L.U32 R1, R2, R3, R4 ;",
        "SHF.R.S32.HI R1, R2, 0x0, R3 ;",
        "SHF.R.U32.HI R1, R2, 0x0, R3 ;",
        "SHF.R.U32.HI R1, R2, R3, R4 ;",
        "LOP3.LUT P1, R1, R2, R3, R4, 0x0, P2 ;",
        "UI2F.U32.RP UR1, UR2 ;",
        "IMNMX.U64 P1, P2, R1, R2, 0x7ffff, P3, !PT ;",
    ] {
        let w = enc(&t120, text);
        assert_eq!(
            &dec(&t120, w),
            text.trim_end_matches(" ;"),
            "encode+rt {text}"
        );
    }
    // IMNMX II cells on encode: spelled ty selects the cell bits
    for (text, cell) in [
        ("IMNMX.S64 P1, P2, R1, R2, 0x0, P3, !PT ;", 0x3u128 << 73),
        ("IMNMX.U64 P1, P2, R1, R2, 0x0, P3, !PT ;", 0x1 << 74),
        ("IMNMX.U32 P1, P2, R1, R2, 0x0, P3, !PT ;", 0),
    ] {
        let w = enc(&t120, text);
        assert_eq!(w & (0x3 << 73), cell, "IMNMX cell for {text}");
    }
}

#[test]
fn t241_4_fail_closed_kept() {
    let t120 = tab("sm120");
    // by-design HOLE register: 32-bit bare IMNMX lowers to VIMNMX (240)
    assert!(!enc_err(&t120, "IMNMX P0, P0, R1, R2, R3, PT, !PT ;").is_empty());
    assert!(!enc_err(&t120, "IMNMX.U32 P0, P0, R1, R2, R3, PT, !PT ;").is_empty());
    assert!(!enc_err(&t120, "IMNMX.S32 P0, P0, R1, R2, R3, PT, !PT ;").is_empty());
    // arity/class guards stay fail-closed
    assert!(!enc_err(&t120, "HADD2.F32 R1, R2 ;").is_empty());
    assert!(!enc_err(&t120, "UI2F.U32.RP UR1, R2 ;").is_empty());
    assert!(!enc_err(&t120, "LOP3.LUT P1, R1, R2, R3, R4, PT ;").is_empty());
}

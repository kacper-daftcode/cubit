//! BUG-240 (F2-iter119, front2/blind, 2026-08-28): sm120 encode wrong-route
//! closure via alias-mg grafts on typed keys (canonical 8c2ceaf;
//! patch240.py replayable+idempotent).
//!
//! Root: the encode candidate chain probes (base_key, sorted-mods) buckets
//! BEFORE the typed key's "" row. Buckets keyed base+sorted-mods cannot
//! express dst<->src type order, so spelled typed text collapsed onto the
//! wrong cell whenever the bucket was direction/shape specific:
//!
//! * `F2F.F64.F32 R1, R2` rode bucket F2F_R_R["F32,F64"] (F32-dst cell
//!   d2=0x301000) -- nvdisasm prints the word as F2F.F32.F64; vendor's
//!   F64-dst cell is d2=0x201800 (probe240.{sm_120a,sm_121a} cubins;
//!   `cubit roundtrip` pre-fix 4/96 mismatch == exactly the F64.F32 words
//!   of probe240.sm_120a.cubin).
//! * `F2F.F64.F32 R1, UR6` rode donor bucket F2F_R_UR["F32,F64"] (F32
//!   cell); cures via NEW typed key carrying the arb226e_c graft row.
//! * `IMNMX.S64` / `IMNMX.U64` spelled forms: the typed "" rows carry no
//!   64-bit cell bits {73,74}; the words fell off-cell and nvdisasm prints
//!   IMNMX/bare or .U32. Vendor law (imnmx*.cu ptxas probes + arb240
//!   x{100a,103a,120a} print-ident): (b73,b74): (1,1)=S64, (0,1)=U64,
//!   b80=tok7 inv(!PT), b81=tok1 pred LSB; 32-bit lowers to VIMNMX.
//!
//! Fix = ADDITIVE alias-mg grafts (typed key gains the row under its
//! spelled sorted-mod name so candidate (fk,mg) reaches it):
//! F2F.F64.F32_R_R += "F32,F64", F2F.F64.F32_R_UR (new key) += {"", "F32,F64"},
//! IMNMX.S64_P_P_R_R_{R,II}_P_P += "S64" (cell graft 3<<73; II alias fields
//! cloned from the bucket II row -- the typed-II "" row is an era reg@32
//! mis-harvest), IMNMX.U64_P_P_R_R_R_P_P += "U64" (cell graft 1<<74); plus
//! era-row repair F2F.F32.F64_R_R[""] tok2 src 8b@33 -> 8b@32 (vendor
//! probe240 F32.F64 R4,R4 = d1 0x00000004; bucket row agrees;
//! decode-shadowed so decode unchanged).
//! forms 1460->1461, variants 2620->2626, baked 823->825.
//!
//! 241-kand (NOT this fix): spelled-form encode HOLEs (all candidates
//! reject): HADD2.F32 R-form, SHF.L.U32 / SHF.R.{S32,U32}.HI, LOP3.LUT
//! _II_P, UI2F.U32.RP_UR_UR, IMNMX.U64 _II_, plus the dead reg@32 typed-II
//! -- pre-existing fail-closed, kept as-is here (pin below documents the
//! HADD2 sentinel so a future fix flips it consciously).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const T120: &str = "tables/sm120.json";
const M96: u128 = (1u128 << 96) - 1;
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new(T120)).unwrap()
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

#[test]
fn t240_1_structure() {
    let t = t120();
    let f64 = t.get("F2F.F64.F32_R_R", "F32,F64").unwrap_or_else(|| {
        panic!("alias mg F32,F64 missing under F2F.F64.F32_R_R");
    });
    let canon = t.get("F2F.F64.F32_R_R", "").unwrap();
    assert_eq!(
        format!("{:?}", f64.fields),
        format!("{:?}", canon.fields),
        "alias row drifts from canonical row"
    );
    assert_eq!(f64.and_base, canon.and_base);
    for mg in ["", "F32,F64"] {
        let r = t.get("F2F.F64.F32_R_UR", mg).unwrap_or_else(|| {
            panic!("F2F.F64.F32_R_UR[{mg:?}] missing");
        });
        assert!(r
            .fields
            .iter()
            .any(|f| f.shift == 16 && f.bits == 8 && f.token_idx == 1));
        assert!(r
            .fields
            .iter()
            .any(|f| f.shift == 32 && f.bits == 8 && f.token_idx == 2));
    }
    for (k, mg) in [
        ("IMNMX.S64_P_P_R_R_R_P_P", "S64"),
        ("IMNMX.S64_P_P_R_R_II_P_P", "S64"),
        ("IMNMX.U64_P_P_R_R_R_P_P", "U64"),
    ] {
        t.get(k, mg)
            .unwrap_or_else(|| panic!("alias mg {mg} missing under {k}"));
    }
    let f32 = t.get("F2F.F32.F64_R_R", "").unwrap();
    let src = f32
        .fields
        .iter()
        .find(|f| f.token_idx == 2 && format!("{:?}", f.extraction) == "Reg")
        .expect("src reg field");
    assert_eq!(src.shift, 32, "F32.F64 tok2 src must be 8b@32 (vendor law)");
}

#[test]
fn t240_2_encode_anchors() {
    let t = t120();
    // F64-dst spelled form now lands on the vendor F64 cell (0x201800):
    // anchor == the pop226e corpus word (cured decode anchor of 226e).
    assert_eq!(
        enc(&t, "F2F.F64.F32 R40, R10 ;") & M96,
        0x002018000000000a00287310u128,
        "F64-dst cell word"
    );
    assert_eq!(
        enc(&t, "F2F.F64.F32 R6, |R0| ;") & M96,
        0x002018004000000000067310u128,
        "abs tok2 rides the typed row fields"
    );
    // F32-dst spelled form keeps the bucket lane (status quo, byte-stable):
    assert_eq!(
        enc(&t, "F2F.F32.F64 R40, R10 ;") & M96,
        0x003010000000000a00287310u128,
        "F32-dst cell word (bucket lane, junk bits masked)"
    );
    // UR-src F64-dst form: NEW typed key (arb226e_c graft row clone).
    assert_eq!(
        enc(&t, "F2F.F64.F32 R2, UR6 ;") & M96,
        0x082018000000000600027d10u128,
        "UR-src F64-dst cell word (pop226e corpus anchor)"
    );
}

#[test]
fn t240_3_roundtrip_and_cell_law() {
    let t = t120();
    for text in [
        "F2F.F64.F32 R40, R10 ;",
        "F2F.F64.F32 R6, |R0| ;",
        "F2F.F32.F64 R40, R10 ;",
        "F2F.F64.F32 R2, UR6 ;",
        "F2F.F32.F64 R0, UR4 ;",
        "IMNMX.S64 P1, P2, R1, R2, R3, P3, P4 ;",
        "IMNMX.S64 P1, P2, R1, R2, 0x0, P3, P4 ;",
        "IMNMX.U64 P1, P2, R1, R2, R3, P3, P4 ;",
    ] {
        let w = enc(&t, text);
        let back = dec(&t, w);
        assert_eq!(back, text.trim_end_matches([' ', ';']), "roundtrip {text}");
    }
    // cell law: F64-dst word carries the 0x201800 cell; IMNMX.S64 words
    // carry the S64 cell bits (73/74 per typed and_base).
    assert_eq!(
        (enc(&t, "F2F.F64.F32 R40, R10 ;") >> 64) as u32 & 0x003f_f800,
        0x00201800
    );
    assert_eq!(
        (enc(&t, "F2F.F32.F64 R40, R10 ;") >> 64) as u32 & 0x003f_f800,
        0x00301000
    );
    // 64-bit cell law (arb240 x3 arch): (1,1)=S64, (0,1)=U64.
    let imnmx = enc(&t, "IMNMX.S64 P1, P2, R1, R2, R3, P3, P4 ;");
    assert_eq!(
        (imnmx >> 73) & 0x3,
        0x3,
        "spelled S64 must carry cell (1,1)"
    );
    let imnmx_i = enc(&t, "IMNMX.S64 P1, P2, R1, R2, 0x0, P3, P4 ;");
    assert_eq!(
        (imnmx_i >> 73) & 0x3,
        0x3,
        "spelled S64-II must carry cell (1,1)"
    );
    let umnmx = enc(&t, "IMNMX.U64 P1, P2, R1, R2, R3, P3, P4 ;");
    // (w>>73)&3 = b73 + 2*b74: (0,1) == 2
    assert_eq!(
        (umnmx >> 73) & 0x3,
        0x2,
        "spelled U64 must carry cell (b73,b74)=(0,1)"
    );
    assert_eq!(
        dec(&t, imnmx).split_whitespace().next().unwrap(),
        "IMNMX.S64",
        "spelled S64 must decode back S64 (bucket decoded U32 pre-fix)"
    );

    // part-2 anchors (arb240b/arb240c): phantom-neg ectomy -- reuse-set
    // vendor words print WITHOUT '-' ghosts (pre-240 rows printed
    // `-R2.reuse`; ctl26/27 are pure reuse).
    let idx = DecodeIndex::build(&t);
    let ctl: u128 = 0x0c4fe400;
    let word = 0x03ffe6000000000402067217u128 | (ctl << 96);
    let d = idx.decode(word, 0, &t).expect("decode S64-reuse");
    assert_eq!(
        to_sass(&d),
        "IMNMX.S64 PT, PT, R6, R2.reuse, R4.reuse, PT, !PT"
    );
    let wordu = 0x03ffe4000000000402067217u128 | (ctl << 96);
    let d = idx.decode(wordu, 0, &t).expect("decode U64-reuse");
    assert_eq!(
        to_sass(&d),
        "IMNMX.U64 PT, PT, R6, R2.reuse, R4.reuse, PT, !PT"
    );
}

#[test]
fn t240_4_controls() {
    let t = t120();
    // 3-operand typed lane: pre-existing fail-closed HOLE (typed
    // F2F.F64.F32_R_R_R carries no field for tok3; no bucket competitor,
    // untouched by this fix) -- parked with 241-kand.
    let insn3 = parse_sass("F2F.F64.F32 R2, R0, R4 ;", 0).unwrap();
    assert!(
        encode_instruction(&insn3, &t).is_err(),
        "F2F.F64.F32_R_R_R tok3 hole is parked 241-side (pre-existing)"
    );
    // Two-operand lanes are the fixed ones (asserted in t240_2/3).
    // BUG-241 landed (F2-iter121, canonical 8eaea28): HADD2.F32 R-form
    // encodes via the donor-law HADD2_R_R_R["F32"] rebuild. Flipped per
    // the 240-era contract: encode must now SUCCEED, and the word must
    // decode back to the same glyph (full text round-trip).
    let insn = parse_sass("HADD2.F32 R1, R2, R3 ;", 0).unwrap();
    let w = encode_instruction(&insn, &t)
        .expect("HADD2.F32 R-form encodes since BUG-241 (donor-law rebuild)");
    let rt = dec(&t, w);
    assert_eq!(rt, "HADD2.F32 R1, R2, R3", "HADD2.F32 self-roundtrip");
    // new keep-HOLE sentinel (by design per 240 register): 32-bit bare
    // IMNMX lowers to VIMNMX on sm120 -- stays fail-closed.
    let insn2 = parse_sass("IMNMX P0, P0, R1, R2, R3, PT, !PT ;", 0).unwrap();
    assert!(
        encode_instruction(&insn2, &t).is_err(),
        "32-bit bare IMNMX R-form stays fail-closed (VIMNMX lane, 240 register)"
    );
    // The ambiguous bucket rows survive for decode (additive fix): F32-dst
    // vendor word still decodes to the F32 form.
    assert_eq!(
        dec(&t, 0x003010000000000400047310 | (0x000e2200u128 << 96)),
        "F2F.F32.F64 R4, R4"
    );
}

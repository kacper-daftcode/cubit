//! BUG-199 (iter96, loop5/blind front MAIN) — ATOM-lane composite closure.
//! (A) defective harvest-era desc-UR windows: ATOM_P E,GPU,MAX,S64/S32
//!     (41,8)/(40,8) -> (64,8) on sm103a+sm100a; sm120 REDG 64,ADD (24,8)
//!     -> (64,8). Live corpus renders coincided with vendor (imm 4/8 reading
//!     UR4 through the broken windows), so the pin uses OOD probes with UR
//!     != imm-derived value (vendor glyphs nvdisasm-verified, arb199).
//! (B) missing ATOM-generic row ATOM_P E,MAX,S64,SM,STRONG on sm100a
//!     (graft197a silicon witness; geometry bit-walked in arb199).
//! (C) width prio-absorb closure: vm |= 3<<73 on width-incomplete ATOM-lane
//!     families (71/45/71 rows) + decoder is_memlike arm for ATOMG/REDG
//!     (kills the prio-3 sign-window re-absorption). Legal-but-uncovered
//!     width words are fail-closed HOLE (coverage = later witnessed
//!     campaigns); vendor-INVALID flips likewise.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn tab(p: &str) -> IsaTable { IsaTable::load(std::path::Path::new(p)).unwrap() }
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).ok()
}
fn word(lo: u64, hi: u64) -> u128 { ((hi as u128) << 64) | lo as u128 }
fn flip_w(lo: u64, hi: u64, wv: u64) -> u128 {
    let w = word(lo, hi) & !(3u128 << 73) | (wv as u128) << 73;
    w
}

/// t199_1 (A): OOD probes — UR is NOT derivable from imm; broken windows
/// printed UR0 (imm=0). Post-fix glyphs must be the nvdisasm-measured ones.
#[test]
fn t199_1_descur_windows_ood() {
    let t103 = tab("tables/sm103a.json"); let i103 = DecodeIndex::build(&t103);
    let t100 = tab("tables/sm100a.json"); let i100 = DecodeIndex::build(&t100);
    for (t, idx) in [(&t103, &i103), (&t100, &i100)] {
        let g32 = dec(t, idx, word(0x8000000702ff798a, 0x000fe200091ef30c))
            .expect("S32 OOD must decode (row exists)");
        assert_eq!(g32, "ATOM.E.MAX.S32.STRONG.GPU PT, RZ, desc[UR12][R2.64], R7");
        let g64 = dec(t, idx, word(0x800000080aff798a, 0x0001e4000910f714))
            .expect("S64 OOD must decode (row exists)");
        assert_eq!(g64, "ATOM.E.MAX.S64.STRONG.GPU P0, RZ, desc[UR20][R10.64], R8");
    }
    // sm120 REDG 64,ADD (24,8) defect: canonical anchor decodes vendor-exact
    let t120 = tab("tables/sm120.json"); let i120 = DecodeIndex::build(&t120);
    let g = dec(&t120, &i120, word(0x000008080600798e, 0x000fe2000c12e506))
        .expect("REDG 64,ADD must decode");
    assert_eq!(g, "REDG.E.ADD.64.STRONG.GPU desc[UR6][R6.64+0x8], R8");
}

/// t199_2 (B): graft197a silicon witness decodes on sm100a to the vendor
/// glyph, and encode reproduces the word bit-exact.
#[test]
fn t199_2_atom_generic_s64_sm_row() {
    let t = tab("tables/sm100a.json"); let idx = DecodeIndex::build(&t);
    let w = word(0x800000060202798a, 0x001eac00091eb704);
    let g = dec(&t, &idx, w).expect("ATOM MAX.S64.SM decodes on sm100a");
    assert_eq!(g, "ATOM.E.MAX.S64.STRONG.SM PT, R2, desc[UR4][R2.64], R6");
    let ins = parse_sass("ATOM.E.MAX.S64.STRONG.SM PT, R2, desc[UR4][R2.64], R6 ;", 0).unwrap();
    let enc = encode_instruction(&ins, &t).expect("encode SM row");
    assert_eq!(enc & !(0xFFFF_FFFFu128 << 96), w & !(0xFFFF_FFFFu128 << 96));
}

/// t199_3 (C): width flips on width-incomplete families are fail-closed
/// across all three tables (legal-but-uncovered AND vendor-INVALID alike).
#[test]
fn t199_3_width_flips_fail_closed() {
    let inc = (0x80000002040579a8u64, 0x001eec00099ef108u64); // ATOMG.E.INC U32 GPU
    let cas_sm = (0x00000006040573a9u64, 0x002ea200001ea107u64); // W probe CAS.SM
    let f32 = (0x8010007c86ff79a3u64, 0x000368000c1ef33eu64); // ATOMG ADD.F32.FTZ anchor
    for p in ["tables/sm103a.json", "tables/sm120.json", "tables/sm100a.json"] {
        let t = tab(p); let idx = DecodeIndex::build(&t);
        for wv in [1u64, 2, 3] {
            assert!(dec(&t, &idx, flip_w(inc.0, inc.1, wv)).is_none(),
                "{p}: INC width {wv} must be HOLE");
        }
        assert!(dec(&t, &idx, flip_w(cas_sm.0, cas_sm.1, 3)).is_none(),
            "{p}: CAS width 3 (vendor INVALID3) must be HOLE");
        assert!(dec(&t, &idx, flip_w(f32.0, f32.1, 0)).is_none(),
            "{p}: F32-FTZ width 0 (vendor INVALID8) must be HOLE");
    }
}

/// t199_4: canonical retention — unbeaten words decode vendor-exact.
#[test]
fn t199_4_canonical_retention() {
    let t = tab("tables/sm103a.json"); let idx = DecodeIndex::build(&t);
    let g = dec(&t, &idx, word(0x80000002040579a8, 0x001eec00099ef108))
        .expect("INC canon decodes");
    assert_eq!(g, "ATOMG.E.INC.STRONG.GPU PT, R5, desc[UR8][R4.64], R2");
    let g = dec(&t, &idx, word(0x8010007c86ff79a3, 0x000368000c1ef33e)).expect("F32 canon");
    assert_eq!(g, "ATOMG.E.FTZ.ADD.F32.RN.STRONG.GPU PT, RZ, desc[UR62][R134.64+0x1000], R124");
}

/// t199_5: encode/decode round-trip byte-exact (sched-matched) on canonicals.
#[test]
fn t199_5_roundtrip_canonical() {
    let t = tab("tables/sm103a.json"); let idx = DecodeIndex::build(&t);
    for (text, lo, hi) in [
        ("ATOMG.E.INC.STRONG.GPU PT, R5, desc[UR8][R4.64], R2 ;", 0x80000002040579a8u64, 0x001eec00099ef108u64),
        ("ATOMG.E.CAS.STRONG.SM PT, R5, [R4], R6, R7 ;", 0x00000006040573a9, 0x002ea200001ea107),
    ] {
        let ins = parse_sass(text, 0).unwrap();
        let w = encode_instruction(&ins, &t).expect("encode");
        let w2 = word(lo, hi);
        assert_eq!(w & !(0xFFFF_FFFFu128 << 96), w2 & !(0xFFFF_FFFFu128 << 96), "encode {text}");
        let g = dec(&t, &idx, w2).unwrap();
        assert_eq!(g, text.strip_suffix(" ;").unwrap_or(text), "decode {text}");
    }
}

/// t199_6: width-complete families keep correct sibling routing post-glue
/// (flips landing on a row that OWNS that width still decode vendor-exact).
#[test]
fn t199_6_complete_family_sibling_routing() {
    let t = tab("tables/sm103a.json"); let idx = DecodeIndex::build(&t);
    let s64 = (0x80000006020279a8u64, 0x001eac00091ef704u64); // ATOMG MAX.S64 GPU
    let g = dec(&t, &idx, flip_w(s64.0, s64.1, 0)).expect("w00 sibling row");
    assert_eq!(g, "ATOMG.E.MAX.STRONG.GPU PT, R2, desc[UR4][R2.64], R6");
    let g = dec(&t, &idx, flip_w(s64.0, s64.1, 2)).expect("64 sibling row");
    assert_eq!(g, "ATOMG.E.MAX.64.STRONG.GPU PT, R2, desc[UR4][R2.64], R6");
    let g = dec(&t, &idx, flip_w(s64.0, s64.1, 1)).expect("S32 sibling row");
    assert_eq!(g, "ATOMG.E.MAX.S32.STRONG.GPU PT, R2, desc[UR4][R2.64], R6");
}

/// t199_7: residuum posture — sm103a keeps the ATOM MAX.S64.SM HOLE
/// (arch-local-witness doctrine, 197); only sm100a gained the row (t199_2).
#[test]
fn t199_7_sm103a_atom_s64_sm_stays_hole() {
    let t = tab("tables/sm103a.json"); let idx = DecodeIndex::build(&t);
    let w = word(0x800000060202798a, 0x001eac00091eb704);
    assert!(dec(&t, &idx, w).is_none(), "sm103a ATOM MAX.S64.SM stays HOLE");
}

//! BUG-249 (F2-iter127, front2/blind, 2026-08-28): FSEL sign-window /
//! UR-shell vendor-parity closure, donors + sm120/sm121a (canonical 755183c;
//! patch249.py replayable+idempotent).
//!
//! Defects (dec249 uniq-word parity over law249 census = 168,104 unique FSEL
//! words / 468,158 occurrences, 2,406-cubin battery, vendor nvdisasm 13.3.73;
//! pre-fix: donors 0 bad, sm120 4,662 DIFF + 199 HOLE, sm121a 5,667 DIFF +
//! 199 HOLE; gold247_post text-level: s120 17,634 DIFF + 449 HOLE, s121a
//! 20,848 + 449):
//!   D1 sm120 FSEL_R_R_R_P['']: era tok2 'neg' 2b@72 absorbs the abs bit ->
//!      vendor '|R4|' printed '-R4' (+ !rsd[73:1] at disassemble level).
//!   D2 sm121a FSEL_R_R_R_P/FSEL_R_R_FI_P ['']: era tok2 'neg_abs' 2b@72 --
//!      decoder.rs extraction_name() has no NegAbs arm (catch-all "negabs")
//!      so the printer DROPS the sign entirely ('|R4|'/'-R6' -> 'R4'/'R6');
//!      1,005-uniq tok2-neg class + 140-uniq imm-form neg included.
//!   D3 sm120/sm121a FSEL_R_R_UR_P['']: 2-field era placeholder -> UR-form
//!      HOLE 199 uniq + 29-uniq junk steals ('FSEL R46, R10, UR6, P0' ->
//!      'UR0, PT').
//!   D4 donor FSEL_R_R_UR_P[''] (sm100a/sm103a): era sign windows SWAPPED
//!      (tok2 abs@62 / tok3 abs@73) -- correct only on the both-abs corpus
//!      class by coincidence; guard PT baked (0x7c08), no guard field.
//!   D5 chart-B: era sm121a FSEL_R_R_II_P junk row (f32 32b@33, neg@3) was
//!      out-scored pre-fix by the PT-baked era FI row; grafting the donor FI
//!      row (PT-unbaked) flipped 10,163 uniq plain-imm words into a hijack
//!      ('FSEL R2, R2, 1, !P0' -> '-8.13e-20, P8') -- fixed by donor-cloning
//!      II_P on sm120/sm121a (baked +QNAN-canonical row).
//! Laws (law249 census + arb249/arb249b transplant walks, nvdisasm 13.3.73;
//! hosts A = R-form 'FSEL R9, |R4|, |R5|, P0', C = UR-form
//! 'FSEL R5, |R3|.reuse, |UR11|, !P2'):
//!   L1 tok2 sign = neg@72 / abs@73 -- identical on R and UR forms.
//!   L2 tok3 sign = neg@63 / abs@62 for R AND UR cells; b74/b75/b84/b85
//!      text-inert.
//!   L3 reuse: tok2 reuse@122; tok3(R) reuse@123 (arb A b123 -> '|R5|.reuse');
//!      UR cell has NO tok3 reuse (arb C b123 vendor-ILLEGAL; b124 ILLEGAL on
//!      both forms).
//!   L4 guard 4b@12 full 16-value spectrum on R AND UR forms; UR index
//!      window = full 8b@32 (arb C urhi walk prints UR27/UR43/UR75/UR139).
//!   L5 tail pred dest = idx 3b@[87:90) + neg b90 (arb A tail walk; PT dest
//!      legal; corpus always concrete Pn).
//! Post-fix dec249: 168,104/168,104 MATCH on ALL four legs (0 DIFF 0 HOLE).
//! QNAN park: '+QNAN '/'-QNAN ' glyphs are bit-ambiguous (0x7FC00000 2,961 /
//! 0x7FF80000 1,171 / 0xFFF00000 408 / 0xFFFFFFFF 4 occ) -- parser.rs quirk
//! stands, !rsd overlay carries byte fidelity (t249_5 pins determinism).

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
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

// Vendor witnesses (full 128-bit; engine matches 96-bit payload).
const W_R_ABSABS: u128 = 0x000fe400000002004000000504097208; // FSEL R9, |R4|, |R5|, P0 (arb host A)
const W_UR_PLAIN: u128 = 0xfe4000c80000000000008ff027c08; //   FSEL R2, RZ, UR8, !P1
const W_UR_BOTHABS: u128 = 0x44fe2000d0002004000000b03057c08; // FSEL R5, |R3|.reuse, |UR11|, !P2 (arb host C)
const W_R_TOK2NEG: u128 = 0xfca0004000100000000ff00057208; //  FSEL R5, -R0, RZ, !P0
const W_R_NEGNEG: u128 = 0xfe20000000100800000ff130a7208; //  FSEL R10, -R19, -RZ, P0
const W_IMM1: u128 = 0x4fc400040000003f80000002027808; //      FSEL R2, R2, 1, !P0
const W_G_IMM: u128 = 0x20fe400000000003f80000029291808; //   @P1 FSEL R41, R41, 1, P0
const W_IMM_NEG: u128 = 0x1fe400050001003ff0000006077808; // FSEL R7, -R6, 1.875, !P2
const W_REUSE3: u128 = 0x80fe200040000000000006109137208; //  FSEL R19, R9, R97.reuse, !P0
const W_QNAN_CANON: u128 = 0xfc800008000007fc00000ff007808; // FSEL R0, RZ, +QNAN , P1 (canonical 0x7FC00000)
const W_QNAN_7FF8: u128 = 0xfe200008000007ff80000ff057808; //  FSEL R5, RZ, +QNAN , P1 (parked bimodal peer)
const W_NEGQNAN: u128 = 0xfce0000000000fff00000031f7808; //   FSEL R31, R3, -QNAN , P0 (0xFFF00000, parked)

#[test]
fn t249_1_structure() {
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let ur = t.entries.get("FSEL_R_R_UR_P").expect("UR key");
        let g = &ur.mod_groups[""];
        assert!(
            g.fields
                .iter()
                .any(|f| f.extraction == cubit::table::Extraction::Guard && f.shift == 12),
            "{arch} UR[''] missing guard field"
        );
        assert_eq!(g.and_base & 0xF000, 0, "{arch} UR[''] guard still baked");
        let tok2: Vec<_> = g.fields.iter().filter(|f| f.token_idx == 2).collect();
        assert!(
            tok2.iter()
                .any(|f| f.extraction == cubit::table::Extraction::Neg
                    && f.shift == 72
                    && f.bits == 1),
            "{arch} UR[''] tok2 missing neg@72"
        );
        assert!(
            tok2.iter()
                .any(|f| f.extraction == cubit::table::Extraction::Abs
                    && f.shift == 73
                    && f.bits == 1),
            "{arch} UR[''] tok2 missing abs@73 (era swap?)"
        );
        let tok3: Vec<_> = g.fields.iter().filter(|f| f.token_idx == 3).collect();
        assert!(
            tok3.iter()
                .any(|f| f.extraction == cubit::table::Extraction::UReg
                    && f.shift == 32
                    && f.bits == 8),
            "{arch} UR[''] tok3 missing ureg 8b@32"
        );
        assert!(
            tok3.iter()
                .any(|f| f.extraction == cubit::table::Extraction::Neg
                    && f.shift == 63
                    && f.bits == 1),
            "{arch} UR[''] tok3 missing neg@63"
        );
        assert!(
            tok3.iter()
                .any(|f| f.extraction == cubit::table::Extraction::Abs
                    && f.shift == 62
                    && f.bits == 1),
            "{arch} UR[''] tok3 missing abs@62 (era swap?)"
        );
        assert!(
            !tok3
                .iter()
                .any(|f| f.extraction == cubit::table::Extraction::Reuse),
            "{arch} UR[''] tok3 reuse must NOT exist (vendor-ILLEGAL, L3)"
        );
        // no 2-bit sign fields anywhere in the FSEL family post-fix
        for (k, row) in &t.entries {
            if !k.starts_with("FSEL") {
                continue;
            }
            for (mgn, mg) in &row.mod_groups {
                for f in &mg.fields {
                    assert!(
                        !(matches!(
                            f.extraction,
                            cubit::table::Extraction::Neg | cubit::table::Extraction::NegAbs
                        ) && f.bits == 2
                            && f.shift == 72),
                        "{arch} {k}[{mgn:?}] era 2-bit sign field @72 remains"
                    );
                }
            }
        }
        // II_P donor-shape (baked +QNAN canonical row with guard field)
        let ii = &t.entries.get("FSEL_R_R_II_P").expect("II key").mod_groups[""];
        assert!(
            ii.fields
                .iter()
                .any(|f| f.extraction == cubit::table::Extraction::Guard && f.shift == 12),
            "{arch} II[''] missing guard field (era junk shape?)"
        );
        assert!(
            !ii.fields
                .iter()
                .any(|f| matches!(f.extraction, cubit::table::Extraction::F32)),
            "{arch} II[''] must be f32-field-free (baked canonical row)"
        );
    }
    // donor semantic parity, and sm120/sm121a == donor mgs genetically on the
    // 4 grafted keys (fields+bases), modulo traceability annotations.
    let a = tab("sm100a");
    let b = tab("sm103a");
    for key in [
        "FSEL_R_R_R_P",
        "FSEL_R_R_FI_P",
        "FSEL_R_R_UR_P",
        "FSEL_R_R_II_P",
    ] {
        let ga = &a.entries[key].mod_groups[""];
        let gb = &b.entries[key].mod_groups[""];
        assert_eq!(ga.and_base, gb.and_base, "donor parity {key}");
        assert_eq!(ga.variable_mask, gb.variable_mask, "donor parity {key}");
        assert_eq!(ga.fields.len(), gb.fields.len(), "donor parity {key}");
        for leg in ["sm120", "sm121a"] {
            let gc = &tab(leg).entries[key].mod_groups[""];
            assert_eq!(gc.and_base, gb.and_base, "{leg} != donor on {key}");
            assert_eq!(
                gc.variable_mask, gb.variable_mask,
                "{leg} != donor on {key}"
            );
            assert_eq!(gc.fields.len(), gb.fields.len(), "{leg} != donor on {key}");
        }
    }
}

#[test]
fn t249_2_decode_vendor_true() {
    let cases: &[(u128, &str)] = &[
        (W_R_ABSABS, "FSEL R9, |R4|, |R5|, P0"),
        (W_UR_PLAIN, "FSEL R2, RZ, UR8, !P1"),
        (W_UR_BOTHABS, "FSEL R5, |R3|.reuse, |UR11|, !P2"),
        (W_R_TOK2NEG, "FSEL R5, -R0, RZ, !P0"),
        (W_R_NEGNEG, "FSEL R10, -R19, -RZ, P0"),
        (W_IMM1, "FSEL R2, R2, 1, !P0"),
        (W_G_IMM, "@P1 FSEL R41, R41, 1, P0"),
        (W_IMM_NEG, "FSEL R7, -R6, 1.875, !P2"),
        (W_REUSE3, "FSEL R19, R9, R97.reuse, !P0"),
        (W_QNAN_CANON, "FSEL R0, RZ, +QNAN , P1"),
        (W_QNAN_7FF8, "FSEL R5, RZ, +QNAN , P1"),
        (W_NEGQNAN, "FSEL R31, R3, -QNAN , P0"),
    ];
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (i, (w, want)) in cases.iter().enumerate() {
            let got = dec(&t, *w).unwrap_or_else(|| panic!("{arch} case{i} HOLE"));
            assert_eq!(&got, want, "{arch} case{i} mismatch");
        }
    }
}

#[test]
fn t249_3_encode_witness() {
    let cases: &[(u128, &str)] = &[
        (W_R_ABSABS, "FSEL R9, |R4|, |R5|, P0"),
        (W_UR_PLAIN, "FSEL R2, RZ, UR8, !P1"),
        (W_UR_BOTHABS, "FSEL R5, |R3|.reuse, |UR11|, !P2"),
        (W_R_TOK2NEG, "FSEL R5, -R0, RZ, !P0"),
        (W_R_NEGNEG, "FSEL R10, -R19, -RZ, P0"),
        (W_IMM1, "FSEL R2, R2, 1, !P0"),
        (W_G_IMM, "@P1 FSEL R41, R41, 1, P0"),
        (W_IMM_NEG, "FSEL R7, -R6, 1.875, !P2"),
        (W_REUSE3, "FSEL R19, R9, R97.reuse, !P0"),
        // QNAN park: text encodes to the CANONICAL 0x7FC00000 payload on all
        // legs (deterministic; the 0x7FF80000 peer of t249_2 is bimodal).
        (W_QNAN_CANON, "FSEL R0, RZ, +QNAN , P1"),
    ];
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (i, (w, text)) in cases.iter().enumerate() {
            let got = enc(&t, text);
            assert_eq!(got & M96, w & M96, "{arch} enc case{i} payload drift");
        }
    }
}

#[test]
fn t249_4_roundtrip_fidelity() {
    let words: &[u128] = &[
        W_R_ABSABS,
        W_UR_PLAIN,
        W_UR_BOTHABS,
        W_R_TOK2NEG,
        W_R_NEGNEG,
        W_IMM1,
        W_G_IMM,
        W_IMM_NEG,
        W_REUSE3,
        W_QNAN_CANON,
    ];
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (i, w) in words.iter().enumerate() {
            let txt = dec(&t, *w).unwrap_or_else(|| panic!("{arch} w{i} HOLE"));
            let back = enc(&t, &txt);
            assert_eq!(back & M96, w & M96, "{arch} w{i} roundtrip drift: {txt}");
        }
    }
}

#[test]
fn t249_5_law_spots_and_qnan_park() {
    // L4/L5 vertices on the grafted UR/R rows (arb249b-proven):
    let t = tab("sm103a");
    let idx = DecodeIndex::build(&t);
    let g = |w: u128| idx.decode(w, 0, &t).map(|d| to_sass(&d)).unwrap();
    // guard rides 4b@12 on the UR form (post-graft decodeable)
    assert_eq!(
        g((W_UR_PLAIN & !(0xF << 12)) | (0xE << 12)),
        "@!P6 FSEL R2, RZ, UR8, !P1"
    );
    // tail PT dest legal
    assert_eq!(
        g((W_UR_PLAIN & !(0xF << 87)) | (7 << 87)),
        "FSEL R2, RZ, UR8, PT"
    );
    // L1/L2 sign walks on the R-form: b72 toggles '-', b73 '|..|', b63 tok3 neg
    let base = W_R_ABSABS & !(1 << 72) & !(1 << 73) & !(1 << 62) & !(1 << 63);
    assert_eq!(g(base | (1 << 72)), "FSEL R9, -R4, R5, P0");
    assert_eq!(g(base | (1 << 73)), "FSEL R9, |R4|, R5, P0");
    assert_eq!(g(base | (1 << 63)), "FSEL R9, R4, -R5, P0");
    assert_eq!(g(base | (1 << 62) | (1 << 63)), "FSEL R9, R4, -|R5|, P0");
    // same law on the UR host (arb C): tok2 neg = b72, tok3(UR) neg = b63
    let ub = W_UR_BOTHABS & !(1 << 72) & !(1 << 73) & !(1 << 62) & !(1 << 63);
    assert_eq!(g(ub | (1 << 72)), "FSEL R5, -R3.reuse, UR11, !P2");
    assert_eq!(g(ub | (1 << 63)), "FSEL R5, R3.reuse, -UR11, !P2");
    // QNAN park determinism: the bimodal peer decodes to the same glyph as
    // canonical (render parity) but text encodes to the canonical payload —
    // the 0x7FF80000 payload stays !rsd-overlay territory (disassemble level).
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let idx = DecodeIndex::build(&t);
        let g7 = idx.decode(W_QNAN_7FF8, 0, &t).map(|d| to_sass(&d)).unwrap();
        assert_eq!(g7, "FSEL R5, RZ, +QNAN , P1", "{arch} QNAN render parity");
        let back = enc(&t, &g7);
        assert_eq!(
            back & M96,
            W_QNAN_CANON & M96 | (5 << 16),
            "{arch} QNAN park: text must encode canonical payload"
        );
        assert_ne!(
            back & M96,
            W_QNAN_7FF8 & M96,
            "{arch} QNAN park: bimodal payload must NOT be fabricated silently"
        );
    }
}

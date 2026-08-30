//! BUG-247 (F2-iter126, front2/blind, 2026-08-28): FMNMX tail-pred /
//! pred-ghost vendor-parity closure, donors + sm120/sm121a (canonical
//! b00b4eb; patch247.py replayable+idempotent).
//!
//! Defects (pre-fix dec247 uniq-word parity over law247 census = 11,666
//! unique FMNMX words / 32,433 occurrences, 2,406-cubin battery, vendor
//! nvdisasm 13.3.73):
//!   D1 donors FMNMX_R_R_UR_P[''/'NAN']: tail pred mapped onto GUARD bits
//!      (pred 4b@12, guard PT-baked in and_base) -> real tail (@87..90)
//!      invisible: plain-UR '!PT' printed as 'PT' (donor 678 DIFF uniq),
//!      real guards lost for the UR cell; sm120/s121a UR shell HOLE 1,421.
//!   D2 donors FMNMX_R_R_R_P['FTZ'/'NAN']: tok4 = pred 4b@88 swallowed the
//!      neg window -> FTZ/NAN printed without '!'.
//!   D3 sm120/s121a era shells: R_R_R_P tok4 = inv 1b@90 only, R_R_UR_P
//!      2-field placeholder, phantom FMNMX_R_R_R_R / FMNMX.NAN_R_R_UR_UR
//!      keys stealing corpus words (s120 8,880 DIFF + 1,421 HOLE uniq;
//!      s121a 8,062 DIFF + 1,421 HOLE uniq).
//!
//! Laws (law247 census + arb247 transplant walks A..G, nvdisasm 13.3.73):
//!   L1 tail pred = idx 3b@[87:90) + neg b90, uniform on R/UR/FTZ/NAN/FI
//!      forms (arb A/C/E/G idx-walks P0..P6/PT, x +/-); guard 4b@12 full
//!      16-value spectrum on R and UR forms (arb A/C guard-walk).
//!   L2 b80=.FTZ, b81=.NAN, b82=.XORSIGN (composable, e.g. arb E b81 ->
//!      FMNMX.FTZ.NAN); b83..b86 text-inert; b91=1 vendor-ILLEGAL.
//!   L3 tok2 neg@72 abs@73; tok3(R) abs@62; UR cell neg@63/abs@62
//!      vendor-printable but corpus-ZERO (registered 250-kand, NOT
//!      grafted); b74/b75 inert on the R cell.
//!   L4 corpus tail inventory = PT/!PT only; tok4 always predicate ->
//!      era sm120 R4 / UR_UR phantoms uncorroborated (left dormant;
//!      post-graft scoring never routes corpus words to them).
//!
//! Fix: donor R_R_UR_P[''/'NAN'] rebuilt (guard4@12, true tail), donor
//! R_R_R_P['FTZ'/'NAN'] tok4 := neg@90+pred3@87; sm120/sm121a mod_groups
//! of R_R_R_P {'',FTZ,NAN} + R_R_UR_P {'',NAN} := byte-copies of the fixed
//! donor rows (top-level key records stay native). Post-fix dec247:
//! 11,666/11,666 MATCH on ALL four legs (0 DIFF 0 HOLE).

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
const W_R_NOT_ABS: u128 = 0xfc800078002000000000209027209; // FMNMX R2, |R9|, R2, !PT
const W_R_PT: u128 = 0xfc800038000000000000a08037209; //      FMNMX R3, R8, R10, PT
const W_UR_NOT: u128 = 0xfe2000f8000000000000c0b1b7c09; //     FMNMX R27, R11, UR12, !PT
const W_UR_PT_SGL: u128 = 0xfe2000f8000000000000c0b1b7c09 ^ (1 << 90); // FMNMX R27, R11, UR12, PT (arb vertex)
const W_NAN_UR_NOT: u128 = 0xfe2000f8200000000000c19e57c09; // FMNMX.NAN R229, R25, UR12, !PT
const W_NAN_UR_PT: u128 = 0xfe4000b8200000000000d19187c09; //  FMNMX.NAN R24, R25, UR13, PT
const W_FTZ_NOT: u128 = 0xfc800078100000000000285857209; //   FMNMX.FTZ R133, R133, R2, !PT
const W_IMM_PT: u128 = 0xfc80003800000437f00003e3e7809; //    FMNMX R62, R62, 255, PT
const W_G_IMMPT: u128 = 0xfc80003800000437f00000000e809; //  @!P6 FMNMX R0, R0, 255, PT
const W_G_FTZ: u128 = 0xfe200078100000000008583a7e209; //    @!P6 FMNMX.FTZ R167, R131, R133, !PT
const W_REUSE2: u128 = 0x40fe200078000000000000609067209; // FMNMX R6, R9.reuse, R6, !PT
const W_REUSE3: u128 = 0x80fe400078000000000004619267209; // FMNMX R38, R25, R70.reuse, !PT

#[test]
fn t247_1_structure() {
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let ur = t.entries.get("FMNMX_R_R_UR_P").expect("UR key");
        for mg in ["", "NAN"] {
            let g = ur
                .mod_groups
                .get(mg)
                .unwrap_or_else(|| panic!("{arch} UR mg {mg:?}"));
            let has_guard = g
                .fields
                .iter()
                .any(|f| f.extraction == cubit::table::Extraction::Guard && f.shift == 12);
            assert!(has_guard, "{arch} UR[{mg:?}] missing guard field");
            let tail: Vec<_> = g.fields.iter().filter(|f| f.token_idx == 4).collect();
            let has_neg90 = tail.iter().any(|f| {
                f.extraction == cubit::table::Extraction::Neg && f.shift == 90 && f.bits == 1
            });
            let has_p87 = tail.iter().any(|f| {
                f.extraction == cubit::table::Extraction::Pred && f.shift == 87 && f.bits == 3
            });
            assert!(
                has_neg90 && has_p87,
                "{arch} UR[{mg:?}] tail != neg@90+pred3@87: {tail:?}"
            );
            assert!(
                !tail.iter().any(|f| f.shift == 12),
                "{arch} UR[{mg:?}] still maps tail onto guard bits"
            );
            assert_eq!(
                g.and_base & 0xF000,
                0,
                "{arch} UR[{mg:?}] guard still baked"
            );
        }
        let rp = t.entries.get("FMNMX_R_R_R_P").expect("R_P key");
        for mg in ["", "FTZ", "NAN"] {
            let g = rp
                .mod_groups
                .get(mg)
                .unwrap_or_else(|| panic!("{arch} R_P mg {mg:?}"));
            let tail: Vec<_> = g.fields.iter().filter(|f| f.token_idx == 4).collect();
            assert!(
                tail.iter()
                    .any(|f| f.extraction == cubit::table::Extraction::Neg && f.shift == 90),
                "{arch} R_P[{mg:?}] no neg@90"
            );
            assert!(
                tail.iter()
                    .any(|f| f.extraction == cubit::table::Extraction::Pred
                        && f.shift == 87
                        && f.bits == 3),
                "{arch} R_P[{mg:?}] no pred3@87"
            );
            assert!(
                !tail.iter().any(|f| f.shift == 88 && f.bits == 4),
                "{arch} R_P[{mg:?}] era 4b@88 remains"
            );
        }
    }
    // donor semantic parity (decoder-visible core), and sm120/sm121a == donor
    // rows genetically (fields+bases), modulo traceability annotations.
    let a = tab("sm100a");
    let b = tab("sm103a");
    for key in ["FMNMX_R_R_R_P", "FMNMX_R_R_UR_P"] {
        for (mg, ga) in &a.entries[key].mod_groups {
            let gb = &b.entries[key].mod_groups[mg];
            assert_eq!(ga.and_base, gb.and_base);
            assert_eq!(ga.variable_mask, gb.variable_mask);
            assert_eq!(ga.fields.len(), gb.fields.len());
        }
    }
}

#[test]
fn t247_2_decode_vendor_true() {
    let cases: &[(u128, &str)] = &[
        (W_R_NOT_ABS, "FMNMX R2, |R9|, R2, !PT"),
        (W_R_PT, "FMNMX R3, R8, R10, PT"),
        (W_UR_NOT, "FMNMX R27, R11, UR12, !PT"),
        (W_UR_PT_SGL, "FMNMX R27, R11, UR12, PT"),
        (W_NAN_UR_NOT, "FMNMX.NAN R229, R25, UR12, !PT"),
        (W_NAN_UR_PT, "FMNMX.NAN R24, R25, UR13, PT"),
        (W_FTZ_NOT, "FMNMX.FTZ R133, R133, R2, !PT"),
        (W_IMM_PT, "FMNMX R62, R62, 255, PT"),
        (W_G_IMMPT, "@!P6 FMNMX R0, R0, 255, PT"),
        (W_G_FTZ, "@!P6 FMNMX.FTZ R167, R131, R133, !PT"),
        (W_REUSE2, "FMNMX R6, R9.reuse, R6, !PT"),
        (W_REUSE3, "FMNMX R38, R25, R70.reuse, !PT"),
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
fn t247_3_encode_witness() {
    let cases: &[(u128, &str)] = &[
        (W_UR_NOT, "FMNMX R27, R11, UR12, !PT"),
        (W_NAN_UR_NOT, "FMNMX.NAN R229, R25, UR12, !PT"),
        (W_NAN_UR_PT, "FMNMX.NAN R24, R25, UR13, PT"),
        (W_FTZ_NOT, "FMNMX.FTZ R133, R133, R2, !PT"),
        (W_R_NOT_ABS, "FMNMX R2, |R9|, R2, !PT"),
        (W_R_PT, "FMNMX R3, R8, R10, PT"),
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
fn t247_4_roundtrip_fidelity() {
    let words: &[u128] = &[
        W_R_NOT_ABS,
        W_R_PT,
        W_UR_NOT,
        W_NAN_UR_NOT,
        W_NAN_UR_PT,
        W_FTZ_NOT,
        W_IMM_PT,
        W_G_IMMPT,
        W_G_FTZ,
        W_REUSE2,
        W_REUSE3,
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
fn t247_5_zero_corpus_sentinels() {
    // Registrations (arb vertices, corpus exposure measured ZERO):
    //  - b82 = .XORSIGN (vendor prints FMNMX.XORSIGN -> no table rows)
    //  - FTZ+NAN combo (arb E: FMNMX.FTZ.NAN vendor-legal -> no row)
    // Both fail closed on all legs post-247. If grafts ever land (250-class
    // decisions), these flip to positive asserts.
    let w_xorsign = W_R_NOT_ABS ^ (1u128 << 82);
    let w_ftznan = W_FTZ_NOT ^ (1u128 << 81);
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let idx = DecodeIndex::build(&t);
        assert!(
            idx.decode(w_xorsign, 0, &t).is_err(),
            "{arch}: XORSIGN row unexpectedly present"
        );
        assert!(
            idx.decode(w_ftznan, 0, &t).is_err(),
            "{arch}: FTZ.NAN row unexpectedly present"
        );
    }
    // L1 neg/idx spot law: flip b90 toggles '!', flip b88 walks pred idx.
    let t = tab("sm103a");
    let idx = DecodeIndex::build(&t);
    let g = |w: u128| idx.decode(w, 0, &t).map(|d| to_sass(&d)).unwrap();
    assert_eq!(g(W_R_NOT_ABS ^ (1 << 90)), "FMNMX R2, |R9|, R2, PT");
    assert_eq!(
        g((W_R_PT & !(0x7 << 87)) | (4 << 87) | (1 << 90)),
        "FMNMX R3, R8, R10, !P4"
    );
    assert_eq!(
        g((W_UR_NOT & !(0x7 << 87)) | (2 << 87)),
        "FMNMX R27, R11, UR12, !P2"
    );
    // guard rides the 4b@12 field, independent of the tail pred.
    let guarded = (W_UR_NOT & !(0xF << 12)) | (0xE << 12);
    assert_eq!(
        idx.decode(guarded, 0, &t).map(|d| to_sass(&d)).unwrap(),
        "@!P6 FMNMX R27, R11, UR12, !PT"
    );
}

//! BUG-264 (F2-iter136, loop5/blind front2, 2026-08-29): sm121a era 4-bit
//! 'neg'@60 tok3-UR on HMUL2_R_R_UR / HFMA2_R_R_UR_R BF16_V2 (canonical
//! 29c17c3). routex264 FULL 2,406-cubin battery: 16 + 35 injured words
//! (hsel values 3 / 2); b62/b63/b86 corpus-zero.
//!
//! arb264 (nvdisasm 13.3.73 raw -b, probes x4 models SM100a/103a/120/121a
//! all agree): the harvest window [63:60] is a merge of THREE vendor laws:
//!   b60..b61 = hsel pair: v0 '', v2 '.H0_H0', v3 '.H1_H1'
//!              (v1 vendor = '.INVALID1' HMUL2 / '.F32' HFMA2; engine/donor
//!              spelling '.H0_H1' kept = owner-scope note from BUG-261);
//!   b62 = abs ('|UR8|'), b63 = neg ('-UR8'), combo '-|UR8|' vendor-equal;
//!   sign+hsel composition order (vendor '|UR8.H0_H0|' vs engine
//!   '|UR8|.H0_H0', pre-existing on donors too) = 273-kand, corpus-zero;
//!   HFMA2 b86 = third bit of a 3-bit window (b86,b61,b60): v4 '.H0_NH1',
//!   v1/5/6/7 '.INVALIDn' -- needs its own extraction = 271-kand; the era
//!   neg@86 mislabel (also the shadow that killed the 4b ghost) deleted.
//! Graft (patch264.py, replayable+idempotent): delete neg 4b@60 both rows +
//! neg@86 (HFMA2); graft hsel 2b@60 + abs 1b@62 + neg 1b@63 per row.
//! and_base/variable_mask byte-unchanged; donors sm100a/sm103a/sm120
//! byte-untouched. Closes 267-kand (HFMA2 tok3-UR hsel suffix gap).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

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

// routex264 / bug261 corpus witnesses (ctl mask = harness convention).
const W_HML261: u128 = 0x10fc80008000000300000080c0b7c32; // HMUL2 v3 '-UR8' ghost
const W_HML_RX: u128 = 0x4fe20008000000300000080c037c32; // HMUL2 v3 (routex, file sm_103)
const W_HFA_RX2: u128 = 0x4fca00080408052000000602057c31; // HFMA2 v2 suffix drop (file sm_100)
const W_HMA: u128 = 0x2fca00080408052000000402057c31; // HFMA2 v2 (261 wit A)
const W_HMB: u128 = 0x140fe4000816080b200000080c097c31; // HFMA2 v2 + neg@84 (261 wit B)

#[test]
fn t264_1_structure() {
    let t = tab("sm121a");
    for (key, has86) in [("HMUL2_R_R_UR", false), ("HFMA2_R_R_UR_R", true)] {
        let g = &t.entries[key].mod_groups["BF16_V2"];
        let mut got: Vec<(u32, u32, Extraction)> = g
            .fields
            .iter()
            .filter(|f| f.token_idx == 3)
            .map(|f| (f.shift, f.bits, f.extraction.clone()))
            .collect();
        got.sort_by_key(|f| (f.0, f.1));
        let mut want: Vec<(u32, u32, Extraction)> = vec![
            (32, 8, Extraction::UReg),
            (60, 2, Extraction::HalfSel),
            (62, 1, Extraction::Abs),
            (63, 1, Extraction::Neg),
        ];
        // BUG-328 (F2-iter166 flip): the klone-era (123, Reuse) field on the
        // UR token was stripped -- b123 is vendor display-inert on the UR
        // slot of these forms x4 = silent-drop mint (arb328b); R-window
        // reuse (b122/b124) stays.
        // BUG-271 (F2-iter143 flip): HFMA2 host gains the h0nh1 b86 field;
        // HMUL2 b86 is vendor TEXT-INERT (arb271 D) => vm-reclaim, NO field
        if has86 {
            want.push((86, 1, Extraction::H0NH1));
        }
        want.sort_by_key(|f| (f.0, f.1));
        assert_eq!(got, want, "{key} tok3 field set");
        // no era wide-neg anywhere, no neg@86 remnant (b86 window = 271).
        for f in &g.fields {
            assert!(
                !(f.extraction == Extraction::Neg && f.bits >= 3),
                "{key}: wide neg left"
            );
            assert!(
                !(f.shift == 86 && f.extraction != Extraction::H0NH1),
                "{key}: shift-86 non-271 field left"
            );
        }
        // vmask keeps the full harvested window (payload-gap registrations).
        let vm = u128::from(g.variable_mask);
        assert_eq!((vm >> 60) & 0xF, 0xF, "{key} vmask window");
        assert_eq!(
            u128::from(g.and_base) >> 60 & 0xF,
            0,
            "{key} and_base window"
        );
        // F2-iter143 (BUG-271): b86 variable on BOTH hosts — HFMA2 via the
        // era window (now field-armed), HMUL2 via the text-inert reclaim.
        assert_eq!((vm >> 86) & 1, 1, "{key} vmask b86 (271)");
    }
    // donors byte-untouched: hsel-only shape, no sign fields at [63:62].
    for leg in ["sm100a", "sm103a", "sm120"] {
        for key in ["HMUL2_R_R_UR", "HFMA2_R_R_UR_R"] {
            let d = tab(leg);
            let g = &d.entries[key].mod_groups["BF16_V2"];
            let has = |ex: Extraction, sh: u32| {
                g.fields
                    .iter()
                    .any(|f| f.token_idx == 3 && f.extraction == ex && f.shift == sh)
            };
            assert!(has(Extraction::HalfSel, 60), "{leg} {key} donor hsel drift");
            assert!(
                !has(Extraction::Abs, 62) && !has(Extraction::Neg, 63),
                "{leg} {key} donor touched"
            );
        }
    }
}

#[test]
fn t264_2_witness_laws_vendor_equal() {
    let t = tab("sm121a");
    // ghost '-UR8' gone; vendor 'UR8.H1_H1' (arb264 A-set, x4 models).
    // Mnemonic-mod FLIPPED 2026-08-31 (BUG-307 landed): arb307c proved x4
    // models that ALL the pinned witnesses carry NO discriminant bit
    // (b85=0, both families) => vendor prints them PLAIN. The era
    // '.BF16_V2' claims below were a bf16-kernel-lattice inference, closed
    // by the discriminant-pinning graft + plain '' rows (patch307.py).
    assert_eq!(
        dec(&t, W_HML261 & M96).as_deref(),
        Some("HMUL2 R11, R12, UR8.H1_H1")
    );
    assert_eq!(
        dec(&t, W_HML_RX & M96).as_deref(),
        Some("HMUL2 R3, R12, UR8.H1_H1")
    );
    // 267-kand closed: tok3-UR hsel suffix restored (vendor 'UR6.H0_H0').
    assert_eq!(
        dec(&t, W_HFA_RX2 & M96).as_deref(),
        Some("HFMA2 R5, R2.H0_H0, UR6.H0_H0, R5.H0_H0")
    );
    assert_eq!(
        dec(&t, W_HMA & M96).as_deref(),
        Some("HFMA2 R5, R2.H0_H0, UR4.H0_H0, R5.H0_H0")
    );
    // 261 witness B keeps the (266-restored) true neg@84 AND gains the suffix.
    assert_eq!(
        dec(&t, W_HMB & M96).as_deref(),
        Some("HFMA2 R9, R12.H0_H0, UR8.H0_H0, -R11.H1_H1")
    );
}

#[test]
fn t264_3_encode_inverse() {
    let t = tab("sm121a");
    // Byte-exact payload reproduction of the corpus witnesses (hsel bits
    // set). FLIPPED 2026-08-31 (BUG-307): the witness payloads are vendor
    // PLAIN words (b85=0, arb307c x4) and reproduce through the new
    // '' rows; the '.BF16_V2' texts mint the SAME payload | discriminant
    // (law() below; arb307 A-set: bit85 is a free orthogonal suffix).
    for (wit, txt) in [
        (W_HML_RX, "HMUL2 R3, R12, UR8.H1_H1"),
        (W_HFA_RX2, "HFMA2 R5, R2.H0_H0, UR6.H0_H0, R5.H0_H0"),
        (W_HMA, "HFMA2 R5, R2.H0_H0, UR4.H0_H0, R5.H0_H0"),
    ] {
        let w = enc(&t, txt) & M96;
        assert_eq!(w, wit & M96, "encode payload drift on {txt}");
        assert_eq!(
            dec(&t, w).as_deref(),
            Some(txt),
            "decode-back drift on {txt}"
        );
    }
    // bit-level laws for the grafted sign fields (arb264 B/E sets).
    let base = W_HML_RX & M96 & !(0xFu128 << 60);
    let law = |txt: &str, bits: u128| {
        let w = enc(&t, txt) & M96;
        assert_eq!(w, base | bits, "encode bits on {txt}");
        assert_eq!(dec(&t, w).as_deref(), Some(txt), "decode-back on {txt}");
    };
    law("HMUL2 R3, R12, UR8", 0);
    law("HMUL2 R3, R12, |UR8|", 1 << 62);
    law("HMUL2 R3, R12, -UR8", 1 << 63);
    law("HMUL2 R3, R12, -|UR8|", 3 << 62);
    // BUG-307: the BF16_V2 forms mint base|bit85 (+window bits).
    law("HMUL2.BF16_V2 R3, R12, UR8", 1 << 85);
    law(
        "HMUL2.BF16_V2 R3, R12, |UR8.H0_H0|",
        (1 << 85) | (2 << 60) | (1 << 62),
    );
}

#[test]
fn t264_4_decode_window_laws() {
    let t = tab("sm121a");
    let base = W_HML_RX & M96 & !(0xFu128 << 60);
    // FLIPPED 2026-08-31 (BUG-307): `base` carries b85=0 = vendor PLAIN
    // lattice; the BF16_V2 prints below pre-fix were era claims without the
    // discriminant. Window laws (arb264/271/297) are discriminant-
    // orthogonal (arb307 A-set), only the prefix flips; arb307 A: the
    // b85-set siblings of every case print the BF16_V2 text (x4 models).
    // FLIPPED F2-iter151 (BUG-297 landed): v1 on the HMUL2 UR slot now
    // prints the vendor '.INVALID1' (arb273 C1..C4 + arb297b Hc set x4
    // models; routex297 confirms zero corpus exposure on the 2,406
    // battery). The HFMA2_R_R_UR_R sibling law (v1 = vendor '.F32') stays
    // on the old generic print = 305-kand, NOT armed here.
    assert_eq!(
        dec(&t, base | (1 << 60)).as_deref(),
        Some("HMUL2 R3, R12, UR8.INVALID1")
    );
    assert_eq!(
        dec(&t, base | (2 << 60)).as_deref(),
        Some("HMUL2 R3, R12, UR8.H0_H0")
    );
    // FLIPPED F2-iter143 (BUG-271 landed): HFMA2 BF16 host b86 = '.H0_NH1'
    // on the window (b86,b61,b60), armed as the h0nh1 field (arb271 C x4);
    // v5..7 (b86 with nonzero hsel) = vendor INVALID{5,6,7} = decode hole.
    let hfa = W_HFA_RX2 & M96 & !(0xFu128 << 60);
    // BUG-307: hfa carries b85=0 (plain); the h0nh1 window law is legal
    // under plain identically (arb307d x4) -- prints drop only the prefix.
    assert_eq!(
        dec(&t, hfa | (1 << 86)).as_deref(),
        Some("HFMA2 R5, R2.H0_H0, UR6.H0_NH1, R5.H0_H0")
    );
    assert!(dec(&t, hfa | (1 << 86) | (1 << 60)).is_none(), "INVALID5");
    assert!(dec(&t, hfa | (1 << 86) | (2 << 60)).is_none(), "INVALID6");
    assert!(dec(&t, hfa | (1 << 86) | (3 << 60)).is_none(), "INVALID7");
    // HMUL2 host: b86 vendor TEXT-INERT (arb271 D + arb307d plain) =
    // reclaim w/o field
    assert_eq!(
        dec(&t, base | (1 << 86)).as_deref(),
        Some("HMUL2 R3, R12, UR8")
    );
    assert_eq!(
        dec(&t, base | (1 << 86) | (2 << 60)).as_deref(),
        Some("HMUL2 R3, R12, UR8.H0_H0")
    );
    // BUG-307 discriminant spot-law: the same window words with b85 set
    // print the BF16_V2 mnemonic (arb307 A x4).
    assert_eq!(
        dec(&t, base | (1 << 85) | (2 << 60)).as_deref(),
        Some("HMUL2.BF16_V2 R3, R12, UR8.H0_H0")
    );
    assert_eq!(
        dec(&t, hfa | (1 << 85) | (1 << 86)).as_deref(),
        Some("HFMA2.BF16_V2 R5, R2.H0_H0, UR6.H0_NH1, R5.H0_H0")
    );
}

#[test]
fn t264_5_registration_sentinels() {
    // BUG-270 flip (F2-iter137, arb270 A: corpus witness HFMA2 R3,-RZ,RZ,0,0
    // + B/G/G2 hosts, x4 models agree): the II_FI era 8b@72 'neg' is RETYPED
    // to neg@72 + abs@73 + hsel 2b@74; op-suffix bits 76..79 payload-gap
    // (274-kand). sm121a mb-sign inventory 17 -> 5 (SKIP-registered rows).
    let t = tab("sm121a");
    let g = &t.entries["HFMA2_R_R_R_II_FI"].mod_groups[""];
    assert!(!g.fields.iter().any(|f| f.token_idx == 2
        && f.extraction == Extraction::Neg
        && f.bits == 8
        && f.shift == 72));
    for (sh, b, ex) in [
        (72u32, 1u32, Extraction::Neg),
        (73, 1, Extraction::Abs),
        (74, 2, Extraction::HalfSel),
    ] {
        assert!(g
            .fields
            .iter()
            .any(|f| f.token_idx == 2 && f.shift == sh && f.bits == b && f.extraction == ex));
    }
    let mb = t
        .entries
        .values()
        .flat_map(|e| e.mod_groups.values())
        .flat_map(|g| g.fields.iter())
        .filter(|f| {
            matches!(
                f.extraction,
                Extraction::Neg | Extraction::Abs | Extraction::NegAbs | Extraction::NegShl1
            ) && f.bits >= 3
        })
        .count();
    // FLIPPED 2026-08-29 (BUG-265): the residuum 5 lived exactly on the
    // 270-registered junk set (HFMA2_R_R_R_R_?, FI_FI|BF16_V2, IIII|BF16_V2)
    // which is now DELETED -> inventory 0 (class closed by removal).
    assert_eq!(
        mb, 0,
        "sm121a multi-bit sign inventory drift (post-265 zero)"
    );
    // 265-kand anchor: phantom head row KEPT (265 measured: only mask for
    // 112 vendor-decodable 'HFMA2 4R+reuse' words; removal=hole-ification;
    // synthesis = 278-kand, owner scope).
    assert!(t.entries.contains_key("HADD2_R_R_II_II_II_II_?"));
    // 270 witness byte-stable (corpus value=1 = pure b72 neg).
    assert_eq!(
        dec(&t, 0xfc600000001ff00000000ff037431 & M96).as_deref(),
        Some("HFMA2 R3, -RZ, RZ, 0, 0")
    );
}

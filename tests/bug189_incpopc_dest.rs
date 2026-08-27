//! BUG-189 (iter89, loop5/blind front MAIN): dest register window of the
//! two-operand ATOMS.POPC.INC.32 cluster (ATOMS_R_{ARI,AURI,ARURI}
//! "32,INC,POPC" in tables sm120/sm103a/sm100a) moved from reg@7 to
//! [16:24) (data-only, patch189.py).
//!
//! Evidence (work/i89):
//!   * arb189.json — nvdisasm-13.3.73 sm_120a in-place patch of the ptx3_120
//!     gold anchor A_popc: dest walk v in {0,1,42,127,128,254} renders `Rv`
//!     from bits [16:24); 0xff renders RZ. Same law on ARI/[R+URZ] and
//!     ARURI forms (F_ari_r4_d2a, AR_d2a/AR_d00). Bits [7:15) != 0xff are
//!     uC-INVALID (S_r7_*/S_both/F_*_r7*/AR_r7z) — [7:15) is a required
//!     sink, not a register window. Corroborated by arb188 A_bit16 and by
//!     ptxas-13.3.73 family anchors (ATOMS.INC R5, [UR4+0xc], R5 word
//!     0x00000c05ff05798c, byte-identical on sm_120a and sm_103a targets).
//!   * census189: zero dest!=0xff words in every measured population
//!     (1,876,934 sm120 words, 32,210,952 sm103-corpus words, 9,130
//!     atoms_all, 11,280 era) — production dest exposure is LATENT; the row
//!     itself is LIVE on sm103/sm100 (478 anchors, all dest=RZ).
//! Pre-fix main 2bd2a82 renders every dest!=0xff probe as `RZ,` (winner189:
//! 9/9 diverge) and cicho emits uC-INVALID words on encode of `Rv>0` texts
//! (writes the register into the [7:15) sink instead of failing).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn tab(p: &str) -> IsaTable { IsaTable::load(std::path::Path::new(p)).unwrap() }
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text} ;"), 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t).ok().map(|d| cubit::printer::to_sass(&d))
}

/// sm_120a arbitration vector: (word, vendor text). arb189.json.
const V120: &[(u128, &str)] = &[
    (0x000fe8000d800004_00000c00ffff7f8c, "ATOMS.POPC.INC.32 RZ, [UR4+0xc]"),
    (0x000fe8000d800004_00000c00ff007f8c, "ATOMS.POPC.INC.32 R0, [UR4+0xc]"),
    (0x000fe8000d800004_00000c00ff017f8c, "ATOMS.POPC.INC.32 R1, [UR4+0xc]"),
    (0x000fe8000d800004_00000c00ff2a7f8c, "ATOMS.POPC.INC.32 R42, [UR4+0xc]"),
    (0x000fe8000d800004_00000c00ff7f7f8c, "ATOMS.POPC.INC.32 R127, [UR4+0xc]"),
    (0x000fe8000d800004_00000c00ff807f8c, "ATOMS.POPC.INC.32 R128, [UR4+0xc]"),
    (0x000fe8000d800004_00000c00fffe7f8c, "ATOMS.POPC.INC.32 R254, [UR4+0xc]"),
    (0x000fe8000d800004_00000c0000ff7f8c, "ATOMS.POPC.INC.32 RZ, [R0+UR4+0xc]"),
    (0x000fe8000d800004_00000c00002a7f8c, "ATOMS.POPC.INC.32 R42, [R0+UR4+0xc]"),
    (0x000fe8000d800004_00000c0000007f8c, "ATOMS.POPC.INC.32 R0, [R0+UR4+0xc]"),
    (0x000fe8000d8000ff_00000c0004ff7f8c, "ATOMS.POPC.INC.32 RZ, [R4+URZ+0xc]"),
    (0x000fe8000d8000ff_00000c00042a7f8c, "ATOMS.POPC.INC.32 R42, [R4+URZ+0xc]"),
];

/// Vendor says uC-INVALID when the [7:15) sink is nonzero (arb189 S_* rows).
const SINK_VIOLATORS: &[u128] = &[
    0x000fe8000d800004_00000c00ffff000c,
    0x000fe8000d800004_00000c00ffff150c,
    0x000fe8000d800004_00000c00ff2a058c,
    0x000fe8000d8000ff_00000c0004ff000c,
    0x000fe8000d800004_00000c0000ff000c,
];

#[test]
fn t189_1_decode_vendor_parity_sm120() {
    let t = tab("tables/sm120.json");
    let idx = DecodeIndex::build(&t);
    for (w, want) in V120 {
        let got = dec(&t, &idx, *w).expect("decode");
        assert_eq!(got.trim_end_matches(" ;"), *want, "vendor parity {w:#034x}");
    }
}

#[test]
fn t189_2_encode_payload_exact_sm120() {
    let t = tab("tables/sm120.json");
    for (w, text) in V120 {
        assert_eq!(enc(&t, text), w & !SCHED, "encode payload {text}");
    }
}

#[test]
fn t189_3_sink_window_not_a_register_fabrication() {
    let t = tab("tables/sm120.json");
    let idx = DecodeIndex::build(&t);
    for w in SINK_VIOLATORS {
        match dec(&t, &idx, *w) {
            Some(s) => assert!(!s.contains("POPC.INC"),
                "sink-window fabrication {w:#034x} -> {s}"),
            None => {}
        }
    }
}

/// Live production anchors (atoms_all.tsv): 478-strong class, all dest=RZ.
const A103: &[(u128, &str)] = &[
    (0x0001e4000d8000ff_00003c0000ff7f8c, "ATOMS.POPC.INC.32 RZ, [R0+URZ+0x3c]"),
    (0x0001e4000d8000ff_0004840000ff7f8c, "ATOMS.POPC.INC.32 RZ, [R0+URZ+0x484]"),
    (0x0005e4000d8000ff_001a3c0002ff7f8c, "ATOMS.POPC.INC.32 RZ, [R2+URZ+0x1a3c]"),
    (0x0001e2000d8000ff_0000000008ff7f8c, "ATOMS.POPC.INC.32 RZ, [R8+URZ]"),
];

#[test]
fn t189_4_sm103a_anchor_decode_unchanged_and_encode_roundtrip() {
    let t = tab("tables/sm103a.json");
    let idx = DecodeIndex::build(&t);
    for (w, want) in A103 {
        let got = dec(&t, &idx, *w).expect("decode sm103a");
        let got = got.trim_end_matches(" ;").to_string();
        assert_eq!(got, *want, "sm103a anchor render regressed {w:#034x}");
        assert_eq!(enc(&t, want), w & !SCHED, "sm103a anchor encode payload {want}");
    }
}

#[test]
fn t189_5_sm100a_anchor_decode_unchanged() {
    let t = tab("tables/sm100a.json");
    let idx = DecodeIndex::build(&t);
    let (w, want) = A103[0];
    let got = dec(&t, &idx, w).expect("decode sm100a");
    assert_eq!(got.trim_end_matches(" ;"), want);
}

#[test]
fn t189_6_family_law_dest_window_on_sm103a_row() {
    // Vendor arbitration is sm_120a-only (no sm_103a plain-form anchors exist);
    // the ptxas ATOMS-family anchors are byte-identical on both archs and the
    // [16:24) window is the family dest law. Pin guards the fix's semantics.
    let t = tab("tables/sm103a.json");
    let idx = DecodeIndex::build(&t);
    let w = 0x0001e4000d8000ff_00003c00002a7f8c; // 478-shape with dest=[16:24)=0x2a
    let got = dec(&t, &idx, w).expect("decode sm103a dest-walk");
    assert!(got.starts_with("ATOMS.POPC.INC.32 R42, [R0+URZ+0x3c]"),
        "family-law dest window lost: {got}");
}

//! BUG-083 (F2Q, 2026-08-22): IMAD key-cluster re-canonicalization.
//!
//! sm120.json carried legacy-harvest IMAD rows (75 keys) with systematic
//! corruption: missing `MOV,U32`/`MOV` rows (.U32 dropped or mis-routed to
//! IMAD.WIDE), halved/garbled operand windows for UR forms, phantom
//! `IMAD.SHL.U32`+`|abs|` from a prio3 decoder heuristic, missing IADD/X/HI
//! mod variants. Both tables shared three code-level faults:
//!   (a) decoder select_best_candidate "SHL disambiguation" hijacked plain
//!       `IMAD Rd, Rs, imm, RZ` (bit73=1 = signed marker, Rc=RZ) into SHL —
//!       removed; the distinction is mask-exact now (SHL,U32: bit73=0,
//!       plain: bit73=1 baked);
//!   (b) printer MOV alias fired for UR-domain src3 — vendor prints
//!       `IMAD R9, RZ, RZ, -UR4` plain (896 corpus samples, 0 MOV-UR);
//!   (c) encoder BUG-012 MOV strip left mg="U32" for `MOV,U32` text and the
//!       "" fallback silently encoded bit73=1 (signed) — 16,866 corpus words
//!       re-encoded bit-flipped before this fix.
//! Pins below are word-anchored to the 2049-cubin vendor census
//! (1,071,461 IMAD records / 228,186 uniq words; parity post-fix:
//! 228,185/228,185 both tables; sole residual = F2Q-090 alt-geometry
//! IADD.U32 singleton, decode FAILs loud today).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
const M96: u128 = (1u128 << 96) - 1;

/// (word low96, vendor canonical text)
const GOLD: &[(u128, &str)] = &[
    (0x78e00ff00000002ff067424, "IMAD.MOV.U32 R6, RZ, RZ, 0x2"),
    (0x78e0007000000ffff057224, "IMAD.MOV.U32 R5, RZ, RZ, R7"),
    (0x78e00ff000000ffff037224, "IMAD.MOV.U32 R3, RZ, RZ, RZ"),
    (0xf8e00ff00000005ff027e24, "IMAD.U32 R2, RZ, RZ, UR5"),
    (0x78e0a0c000000ffff037224, "IMAD.MOV R3, RZ, RZ, -R12"),
    (0x78e0a02000000ffff027224, "IMAD.MOV R2, RZ, RZ, -R2"),
    (0xf8e02ff80000004ff097e24, "IMAD R9, RZ, RZ, -UR4"),
    (0xf8e02040000000611117e24, "IMAD R17, R17, R4, UR6"),
    (0x78e02050000000100007824, "IMAD.IADD R0, R0, 0x1, R5"),
    (0x78e0a040000000105057824, "IMAD.IADD R5, R5, 0x1, -R4"),
    (0x78e02ff0000000300057824, "IMAD R5, R0, 0x3, RZ"),
    (0x78e0a080000000807087824, "IMAD R8, R7, 0x8, -R8"),
    (0x78e00ff0000000402027824, "IMAD.SHL.U32 R2, R2, 0x4, RZ"),
    (0x78e00ff0200000000077824, "IMAD.SHL.U32 R7, R0, 0x2000000, RZ"),
    (0xe06050000000103097824, "IMAD.X R9, R3, 0x1, R5, P0"),
    (0x88e06ff00000005ff037e24, "IMAD.X R3, RZ, RZ, UR5, P1"),
    (0xe0e07000000ffff007224, "IMAD.X R0, RZ, RZ, ~R7, P0"),
    (0xf8e029c000000049c0a7c25, "IMAD.WIDE R10, R156, UR4, R156"),
    (0xf8e0006000000041a1a7e25, "IMAD.WIDE.U32 R26, R26, R6, UR4"),
    (0x78e00ff0000003b08057227, "IMAD.HI.U32 R5, R8, R59, RZ"),
    (0xf8e00080000000409087e27, "IMAD.HI.U32 R8, R9, R8, UR4"),
    (0x78400080000000b07087227, "IMAD.HI.U32 R8, P2, R7, R11, R8"),
    (0x78e00070000000100145824, "@P5 IMAD.IADD.U32 R20, R0, 0x1, R7"),
    (0x78e0a020000001014027825, "IMAD.WIDE R2, R20, 0x10, -R2"),
    (0xf8e02070000000c06068e25, "@!P0 IMAD.WIDE R6, R6, R7, UR12"),
    (0x78e00ff40140000ff0b7424, "IMAD.MOV.U32 R11, RZ, RZ, 0x40140000"),
];

#[test]
fn bug083_decode_vendor_exact_both_tables() {
    for t in [t103(), t120()] {
        let idx = DecodeIndex::build(&t);
        for &(w, golden) in GOLD {
            let d = idx.decode(w, 0, &t).unwrap();
            let text = cubit::printer::to_sass(&d);
            assert_eq!(text, golden, "word {w:024x}");
        }
    }
}

#[test]
fn bug083_roundtrip_word_exact() {
    // encode(decode(w)) == w on low96 for every anchor word
    for t in [t103(), t120()] {
        let idx = DecodeIndex::build(&t);
        for &(w, golden) in GOLD {
            // IMAD.HI.U32 text is decode-only on sm120 (BUG-002 policy)
            if golden.contains("IMAD.HI") && t.target_sm() == 120 { continue; }
            let d = idx.decode(w, 0, &t).unwrap();
            let text = cubit::printer::to_sass(&d);
            let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
            let w2 = encode_instruction(&insn, &t).unwrap();
            assert_eq!(w2 & M96, w & M96, "loop {golden}");
        }
    }
}

#[test]
fn bug083_encode_mov_u32_signed_bit_clear() {
    // The BUG-083 encoder regression: `IMAD.MOV.U32` re-encoded with bit73=1
    // (signed marker) via the "" fallback. Vendor truth: bit73 = 0.
    let t = t120();
    let insn = parse_sass("IMAD.MOV.U32 R10, RZ, RZ, 0x0 ;", 0).unwrap();
    let w = encode_instruction(&insn, &t).unwrap();
    assert_eq!((w >> 73) & 1, 0, "MOV.U32 must keep bit73=0");
    // plain (signed) IMAD keeps bit73=1
    let insn2 = parse_sass("IMAD R5, R0, 0x3, RZ ;", 0).unwrap();
    let w2 = encode_instruction(&insn2, &t).unwrap();
    assert_eq!((w2 >> 73) & 1, 1, "plain IMAD must keep bit73=1");
}

#[test]
fn bug083_mov_alias_ur_domain_stays_plain() {
    // vendor convention: MOV alias only in the R domain (U src3 prints plain)
    let t = t103();
    let idx = DecodeIndex::build(&t);
    let w = 0xf8e02ff80000004ff097e24u128; // IMAD R9, RZ, RZ, -UR4
    let d = idx.decode(w, 0, &t).unwrap();
    assert_eq!(cubit::printer::to_sass(&d), "IMAD R9, RZ, RZ, -UR4");
    // and R-domain stays aliased (BUG-012 preserved)
    let w2 = 0x78e0a02000000ffff027224u128; // IMAD.MOV R2, RZ, RZ, -R2
    let d2 = idx.decode(w2, 0, &t).unwrap();
    assert_eq!(cubit::printer::to_sass(&d2), "IMAD.MOV R2, RZ, RZ, -R2");
}

#[test]
fn bug083_shl_not_hijacked_by_plain() {
    // decoder heuristic regression: plain IMAD with Rc=RZ and bit73=1 must
    // stay plain (no SHL, no phantom |abs|)
    let t = t103();
    let idx = DecodeIndex::build(&t);
    let w = 0x78e02ff9e3779b100007824u128; // IMAD R0, R0, -0x61c8864f, RZ
    let d = idx.decode(w, 0, &t).unwrap();
    assert_eq!(d.mod_group, "");
    assert_eq!(cubit::printer::to_sass(&d), "IMAD R0, R0, -0x61c8864f, RZ");
    // genuine SHL still routes to SHL,U32
    let w2 = 0x78e00ff0000002000007824u128;
    let d2 = idx.decode(w2, 0, &t).unwrap();
    assert_eq!(d2.mod_group, "SHL,U32");
}

#[test]
fn bug083_imad_hi_decode_only_sm120() {
    // BUG-002 policy stays: IMAD.HI.U32 text decodes but is not encodable on sm120
    let t120 = t120();
    let insn = parse_sass("IMAD.HI.U32 R5, R8, R59, RZ ;", 0).unwrap();
    assert!(encode_instruction(&insn, &t120).is_err());
    // sm103a encodes it (era path)
    let t103 = t103();
    let w = encode_instruction(&insn, &t103).unwrap();
    assert_eq!(w & M96, 0x78e00ff0000003b08057227u128 & M96);
}

#[test]
fn bug083_x_cin_neg_pt_encodes_and_renders_b90() {
    // vendor corpus words for cin-PT on .X II forms: rendered by nvdisasm as
    // `!PT`; cubit keeps the era `.B90` marker render (production text pins)
    // but accepts BOTH text forms for encode, to the same word (bit90=1).
    let t = t103();
    let idx = DecodeIndex::build(&t);
    let w = 0x7840466000003d167567825u128;
    let d = idx.decode(w, 0, &t).unwrap();
    assert_eq!(cubit::printer::to_sass(&d),
               "IMAD.WIDE.U32.X.B90 R86, P2, R103, 0x3d1, R102, PT");
    let a = parse_sass("IMAD.WIDE.U32.X R86, P2, R103, 0x3d1, R102, !PT ;", 0).unwrap();
    let wa = encode_instruction(&a, &t).unwrap() & M96;
    let b = parse_sass("IMAD.WIDE.U32.X.B90 R86, P2, R103, 0x3d1, R102, PT ;", 0).unwrap();
    let wb = encode_instruction(&b, &t).unwrap() & M96;
    assert_eq!(wa, w);
    assert_eq!(wb, w);
    // plain cin real-pred text must NOT set bit90
    let p = parse_sass("IMAD.WIDE.U32.X R194, P2, R203, 0x3d1, R202, P2 ;", 0).unwrap();
    let wp = encode_instruction(&p, &t).unwrap();
    assert_eq!((wp >> 90) & 1, 0);
}

#[test]
fn bug083_no_dotted_imad_keys_left_sm120() {
    // table hygiene: the re-canon removed all legacy dotted/junk IMAD keys
    let t = t120();
    for k in t.entries.keys() {
        assert!(!k.starts_with("IMAD."), "legacy dotted key survived: {k}");
        if k.starts_with("IMAD") {
            assert!(t1023_keys().contains(&k.as_str()), "unexpected IMAD key on sm120: {k}");
        }
    }
}

fn t1023_keys() -> &'static [&'static str] {
    &[
        "IMAD_R_P_R_II_R", "IMAD_R_P_R_II_R_P", "IMAD_R_P_R_R_R",
        "IMAD_R_P_R_R_R_P", "IMAD_R_P_R_UR_R", "IMAD_R_R_II_R",
        "IMAD_R_R_II_R_P", "IMAD_R_R_R_II", "IMAD_R_R_R_II_P",
        "IMAD_R_R_R_R", "IMAD_R_R_R_R_P", "IMAD_R_R_R_UR",
        "IMAD_R_R_R_UR_P", "IMAD_R_R_UR_R", "IMAD_R_R_UR_R_P",
    ]
}

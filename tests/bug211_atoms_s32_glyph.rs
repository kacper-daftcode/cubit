//! BUG-211 (iter98, 2026-08-27): ATOMS AND/OR/XOR .S32 glyph-space closure.
//! Law (arb211.json, in-place graft on real vendor containers, nvdisasm
//! 13.3.73): b73 = .S32 glyph toggle for ARI-form AND/OR/XOR (probe204a
//! cubins, payload arch-eq x3) and AURI-form AND/OR/XOR (sm_103a corpus,
//! cutlass fp16/fp8 GEMM + FMHA + cusolver). b74 = .64 (212-kand, stays
//! fail-closed). probe211a NEGATIVE x3 arch: ptxas never emits b73 for
//! logic ops even on int operands — .S32 lives in nvdisasm glyph space only.
//! Pre-fix: prio-3 ALU sign-window absorbed b73 silently (ATOMS missing
//! from is_memlike — BUG-199 FIX C arm covered ATOMG/REDG but not ATOMS);
//! sm120 additionally had prio-0 phantom hijack (4-operand ARI_R_R rows,
//! mk296/143-E1 class). Fix: patch211.py donor-clones x3 tabs +
//! is_memlike += "ATOMS" (src arm).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const T103: &str = "tables/sm103a.json";
const T120: &str = "tables/sm120.json";
const T100: &str = "tables/sm100a.json";
const TABS: &[&str] = &[T120, T103, T100];
fn tab(p: &str) -> IsaTable { IsaTable::load(std::path::Path::new(p)).unwrap() }
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t).ok().map(|d| cubit::printer::to_sass(&d))
}
fn word(lo: u64, hi: u64) -> u128 { ((hi as u128) << 64) | lo as u128 }
const M96: u128 = (1u128 << 96) - 1;
const B73: u64 = 1u64 << 9; // bit73 in the hi qword
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let insn = parse_sass(&format!("{text} ;"), 0).expect("parse");
    encode_instruction(&insn, t).ok()
}

/// Witness pairs: bare vendor word (probe204a / corpus) -> b73-set == .S32.
const WIT: &[(&str, u64, u64)] = &[
    ("ATOMS.AND R7, [R0+0x80], R3",     0x000080030007738c, 0x004e280002800000),
    ("ATOMS.AND R9, [R0+0x20], R5",     0x000020050009738c, 0x008e280002800000),
    ("ATOMS.OR R7, [R0+0x40], R3",      0x000040030007738c, 0x004e280003000000),
    ("ATOMS.XOR R7, [R0+0x100], R3",    0x000100030007738c, 0x004e280003800000),
    ("@P0 ATOMS.AND RZ, [UR8+0x14], R3",0x00001403ffff098c, 0x0007e8000a800008),
    ("@P0 ATOMS.OR RZ, [UR4], R2",      0x00000002ffff098c, 0x0001e4000b000004),
    ("ATOMS.OR RZ, [UR9+0x18], R0",     0x00001800ffff798c, 0x0003e8000b000009),
    ("ATOMS.XOR RZ, [UR5+0x10], R4",    0x00001004ffff798c, 0x0005e4000b800005),
    ("ATOMS.XOR RZ, [UR54+0x10], R4",   0x00001004ffff798c, 0x0005e4000b800036),
];
fn s32_glyph(g: &str) -> String {
    // "ATOMS.AND ..."/"@P0 ATOMS.OR ..." -> insert ".S32" after the op
    g.replacen("ATOMS.AND", "ATOMS.AND.S32", 1)
        .replacen("ATOMS.OR", "ATOMS.OR.S32", 1)
        .replacen("ATOMS.XOR", "ATOMS.XOR.S32", 1)
}

#[test]
fn t211_1_s32_witnesses_decode_vendor_exact_x3() {
    for p in TABS {
        let t = tab(p); let idx = DecodeIndex::build(&t);
        for (glyph, lo, hi) in WIT {
            let got = dec(&t, &idx, word(*lo, hi | B73)).unwrap_or_else(|| panic!("{p} HOLE: {glyph}.S32"));
            assert_eq!(got, s32_glyph(glyph), "{p} .S32 decode != vendor: {glyph}");
        }
    }
}

#[test]
fn t211_2_bare_retention_x3() {
    // Retention: bare words unchanged by the fix (green on ctl too).
    for p in TABS {
        let t = tab(p); let idx = DecodeIndex::build(&t);
        for (glyph, lo, hi) in WIT {
            let got = dec(&t, &idx, word(*lo, *hi)).unwrap_or_else(|| panic!("{p} bare HOLE: {glyph}"));
            assert_eq!(&got, glyph, "{p} bare decode drift");
        }
    }
}

#[test]
fn t211_3_encode_s32_byte_exact_payload96() {
    // Unguarded encode (BUG-080: sm103a refuses guarded ATOMS encode — pinned
    // in t204_6; here only unguarded glyphs are encoded, on all 3 tables).
    for p in TABS {
        let t = tab(p);
        for (glyph, lo, hi) in WIT {
            if glyph.starts_with('@') { continue; }
            let g = s32_glyph(glyph);
            let w = enc(&t, &g).unwrap_or_else(|| panic!("{p} encode HOLE: {g}"));
            assert_eq!(w & M96, word(*lo, hi | B73) & M96, "{p} encode != witness+b73: {g}");
        }
    }
}

#[test]
fn t211_4_prio3_arm_fail_closed_unwitnessed_widths() {
    // src arm: ATOMS joins is_memlike — prio-3 sign-window no longer absorbs
    // width flips. .64 (b74, no row yet — 212-kand) and width=3 must HOLE.
    // NOTE: 212-kand landing re-pins the b74 arm here (like t143_6).
    for p in TABS {
        let t = tab(p); let idx = DecodeIndex::build(&t);
        let w64 = word(0x000020050009738c, 0x008e280002800000 | (1u64 << 10)); // AND b74
        assert!(dec(&t, &idx, w64).is_none(), "{p}: b74 (.64) must fail closed");
        let w3 = word(0x000020050009738c, 0x008e280002800000 | B73 | (1u64 << 10));
        assert!(dec(&t, &idx, w3).is_none(), "{p}: width=3 must fail closed");
        // same on the AURI form
        let w64a = word(0x00001403ffff098c, 0x0007e8000a800008 | (1u64 << 10));
        assert!(dec(&t, &idx, w64a).is_none(), "{p}: AURI b74 must fail closed");
    }
}

#[test]
fn t211_5_no_phantom_hijack_sm120() {
    // mk296/143-E1 class guard: the b73-set AURI word on sm120 must NOT be
    // claimed by the 4-operand ARI_R_R/ARURI_R phantom rows.
    let t = tab(T120); let idx = DecodeIndex::build(&t);
    let got = dec(&t, &idx, word(0x00000002ffff098c, 0x0001e4000b000004 | B73)).expect("hole");
    assert_eq!(got, "@P0 ATOMS.OR.S32 RZ, [UR4], R2");
    let got2 = dec(&t, &idx, word(0x00001403ffff098c, 0x0007e8000a800008 | B73)).expect("hole");
    assert_eq!(got2, "@P0 ATOMS.AND.S32 RZ, [UR8+0x14], R3");
}

#[test]
fn t211_6_roundtrip_enc_dec_identity() {
    for p in TABS {
        let t = tab(p); let idx = DecodeIndex::build(&t);
        for (glyph, _lo, _hi) in WIT {
            if glyph.starts_with('@') { continue; }
            let g = s32_glyph(glyph);
            let w = enc(&t, &g).unwrap_or_else(|| panic!("{p} encode HOLE: {g}"));
            let back = dec(&t, &idx, w).expect("decode of own encode");
            assert_eq!(back, g, "{p} roundtrip drift");
        }
    }
}

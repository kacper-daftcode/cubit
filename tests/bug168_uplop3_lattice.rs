//! BUG-168 (front-main iter78, loop5/blind; queue item "UPLOP3.LUT 2-bit
//! lattice imm render (64 linie, 7 uniq)" z raportu 153 sec.5 / noszony
//! iter72..77): encoder check_uplop3_lut_lattice mrozil prawo ery BUG-030
//! ({0,0x40,0x80,0xc0} x {0,0x4,0x8,0xc}) => 64 linie korpusu (8/44 uniq
//! tekstow hexdb) fail-closed: pary (0xf8,0x8f) i (0x2,0x20).
//! Prawo vendora (nvdisasm 13.3.73, matryca na szkielecie korpusowym
//! (0x40,0x4), work/i78/arb166.json + up_arb*; 107/107 uniq slow == vendor
//! pre i post na sm103a):
//!   tok5 (v1) = shr1@[65:67)<<1 | shr2@[71:77)<<2  => v1 in [0,0xfe] EVEN
//!   tok6 (v2) = [16:24) 8-bit, niezalezny od v1 ((0x40,0x14)/(0x40,0x44)/
//!          (0x40,0x9) legalne; korpusowe v2==rot4(v1) = relacja SEMANTYCZNA,
//!          nie struktura enkodowania).
//! Fix: (1) tables/sm103a.json UPLOP3_UP_UP_UP_UP_UP_II_II 'LUT': usuniecie
//! redundantnego overlap-pola imm_shr4@[16:20) tok6 (fabrykowal v1 gdy bit
//! [16:20) niespojny z shr2: pre-fix sonda v1_78 drukowala 0xf8 vs vendor
//! 0x78, sonda v2=0x09 drukowala 0xd0 vs vendor 0x40) + tok7 imm [16:48) ->
//! [16:24) (vendor ignoruje [24:.), dowod sondy v2=0x104 -> "0x4"); bity
//! [24:32) staja sie matched-0, census 107/107 slow ma tam 0 (bezstratne).
//! (2) src/encoder.rs: lattice-check = UP-forma (4 operandy UPred): v1 in
//! [0,0xfe] parzysty (bit0 bez magazynu), v2 in [0,0xff], bez relacji;
//! legacy P-forma zostaje na starej regule (fail-closed).
//! sm120: SWIADOMIE poza zakresem (kandydat 169): pelny wiersz UP przegrywa
//! tiebreak dekodera (score na enum Extraction::Pred, upred==pred) z junk-
//! -ekosystemem PLOP3.LUT_P1 (score +16); pre-fix fabrykuje 17/107 uniq
//! (dowody work/i78/up168_fixverify*.json).
//! Piny: t168_1 decode==tekst korpusowy 44 uniq; t168_2 arb-matrix decode
//! == vendor (9 form, w tym 3 pre-fabrykowane); t168_3 encode 44 teksty
//! payload[0:96)==corpus word; t168_4 fail-closed: v1 odd / >0xfe / v2>0xff;
//! t168_5 strict-hole: slowo z [24]!=0 fail-closed (vendor-inert); t168_6
//! fixed-point decode->encode->same-word + legacy rule nienaruszona.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    let d = idx.decode(w, 0, t).expect("decode");
    let s = cubit::printer::to_sass(&d);
    let s = s.split("/* @sched").next().unwrap().trim().to_string();
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// 44 uniq korpusowych UPLOP3.LUT (hexdb 32.2M; maszynowo: up_corpus_words.json): (lo, hi, tekst nvdisasma).
const CORPUS: &[((u64, u64), &str)] = &[
    ((0x000000000008789cu64, 0x000fc40003f0f070u64), "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    ((0x000000000004789cu64, 0x000fe20003f0e870u64), "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    ((0x00000000008f789cu64, 0x000fc80000f21f70u64), "UPLOP3.LUT UP1, UPT, UP1, UP0, UPT, 0xf8, 0x8f"),
    ((0x000000000008a89cu64, 0x000fe40003f0f030u64), "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UP3, 0x80, 0x8"),
    ((0x000000000008a89cu64, 0x000fe20003f2f040u64), "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP4, 0x80, 0x8"),
    ((0x00000000008f789cu64, 0x000fe20000703f70u64), "UPLOP3.LUT UP0, UPT, UP0, UP1, UPT, 0xf8, 0x8f"),
    ((0x00000000008f789cu64, 0x000fc80000705f70u64), "UPLOP3.LUT UP0, UPT, UP0, UP2, UPT, 0xf8, 0x8f"),
    ((0x000000000004789cu64, 0x000fc80003f0e800u64), "UPLOP3.LUT UP0, UPT, UPT, UPT, UP0, 0x40, 0x4"),
    ((0x000000000008789cu64, 0x000fe40003f4f070u64), "UPLOP3.LUT UP2, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    ((0x000000000008789cu64, 0x000fee0003f2f070u64), "UPLOP3.LUT UP1, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    ((0x000000000004789cu64, 0x000fe40003f2e870u64), "UPLOP3.LUT UP1, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    ((0x000000000004789cu64, 0x000fe20003f4e870u64), "UPLOP3.LUT UP2, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    ((0x000000000008789cu64, 0x000fe40003f8f070u64), "UPLOP3.LUT UP4, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    ((0x00000000008f789cu64, 0x000fe40000723f70u64), "UPLOP3.LUT UP1, UPT, UP0, UP1, UPT, 0xf8, 0x8f"),
    ((0x00000000008f789cu64, 0x000fc60000f25f70u64), "UPLOP3.LUT UP1, UPT, UP1, UP2, UPT, 0xf8, 0x8f"),
    ((0x000000000008789cu64, 0x000fe40003f6f070u64), "UPLOP3.LUT UP3, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    ((0x00000000008f589cu64, 0x000fc80000705f70u64), "@UP5 UPLOP3.LUT UP0, UPT, UP0, UP2, UPT, 0xf8, 0x8f"),
    ((0x000000000004589cu64, 0x000fc60003f6e800u64), "@UP5 UPLOP3.LUT UP3, UPT, UPT, UPT, UP0, 0x40, 0x4"),
    ((0x000000000004789cu64, 0x000fe40003f8e870u64), "UPLOP3.LUT UP4, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    ((0x00000000008f789cu64, 0x000fe40000743f70u64), "UPLOP3.LUT UP2, UPT, UP0, UP1, UPT, 0xf8, 0x8f"),
    ((0x000000000004089cu64, 0x000fec0003f2e820u64), "@UP0 UPLOP3.LUT UP1, UPT, UPT, UPT, UP2, 0x40, 0x4"),
    ((0x000000000008789cu64, 0x000fe40003fcf070u64), "UPLOP3.LUT UP6, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    ((0x000000000004789cu64, 0x000fe40003fae870u64), "UPLOP3.LUT UP5, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    ((0x000000000008889cu64, 0x000fe40003fcf070u64), "@!UP0 UPLOP3.LUT UP6, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    ((0x000000000004889cu64, 0x000fe40003fae870u64), "@!UP0 UPLOP3.LUT UP5, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    ((0x000000000008889cu64, 0x000fe40003f8f070u64), "@!UP0 UPLOP3.LUT UP4, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    ((0x000000000008889cu64, 0x000fe20003f6f070u64), "@!UP0 UPLOP3.LUT UP3, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    ((0x000000000004789cu64, 0x000fe20003f6e870u64), "UPLOP3.LUT UP3, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    ((0x000000000004789cu64, 0x000fe40003fce870u64), "UPLOP3.LUT UP6, UPT, UPT, UPT, UPT, 0x40, 0x4"),
    ((0x000000000008789cu64, 0x000fe40003faf070u64), "UPLOP3.LUT UP5, UPT, UPT, UPT, UPT, 0x80, 0x8"),
    ((0x000000000008789cu64, 0x000fe40003f2f000u64), "UPLOP3.LUT UP1, UPT, UPT, UPT, UP0, 0x80, 0x8"),
    ((0x000000000008789cu64, 0x000fc60003f4f010u64), "UPLOP3.LUT UP2, UPT, UPT, UPT, UP1, 0x80, 0x8"),
    ((0x000000000008989cu64, 0x000fe20003f0f020u64), "@!UP1 UPLOP3.LUT UP0, UPT, UPT, UPT, UP2, 0x80, 0x8"),
    ((0x000000000008a89cu64, 0x000fde0003f2f030u64), "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP3, 0x80, 0x8"),
    ((0x000000000008a89cu64, 0x000fe20003f0f040u64), "@!UP2 UPLOP3.LUT UP0, UPT, UPT, UPT, UP4, 0x80, 0x8"),
    ((0x000000000020789cu64, 0x000fe40000f40072u64), "UPLOP3.LUT UP2, UPT, UP1, UP0, UPT, 0x2, 0x20"),
    ((0x000000000004389cu64, 0x000fd60003f4e840u64), "@UP3 UPLOP3.LUT UP2, UPT, UPT, UPT, UP4, 0x40, 0x4"),
    ((0x000000000008789cu64, 0x000fe20003f8f050u64), "UPLOP3.LUT UP4, UPT, UPT, UPT, UP5, 0x80, 0x8"),
    ((0x000000000008989cu64, 0x000fe20003f6f000u64), "@!UP1 UPLOP3.LUT UP3, UPT, UPT, UPT, UP0, 0x80, 0x8"),
    ((0x000000000004889cu64, 0x000fe20003f6e840u64), "@!UP0 UPLOP3.LUT UP3, UPT, UPT, UPT, UP4, 0x40, 0x4"),
    ((0x000000000008089cu64, 0x000ff60003f6f010u64), "@UP0 UPLOP3.LUT UP3, UPT, UPT, UPT, UP1, 0x80, 0x8"),
    ((0x000000000008a89cu64, 0x000fe20003f2f000u64), "@!UP2 UPLOP3.LUT UP1, UPT, UPT, UPT, UP0, 0x80, 0x8"),
    ((0x000000000004789cu64, 0x000fe20003f2e840u64), "UPLOP3.LUT UP1, UPT, UPT, UPT, UP4, 0x40, 0x4"),
    ((0x000000000008089cu64, 0x000ff60003f2f020u64), "@UP0 UPLOP3.LUT UP1, UPT, UPT, UPT, UP2, 0x80, 0x8"),
];

#[test]
fn t168_1_decode_pary_corpus() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for ((lo, hi), text) in CORPUS {
        let w = (*lo as u128) | ((*hi as u128) << 64);
        let want = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(dec(&idx, w, &t), want, "decode parity for {text}");
    }
}

/// Matryca arbitrazu (syntetyki na szkielecie korpusowym; teksty == nvdisasm
/// 13.3.73, work/i78/arb166.json). W tym 3 formy pre-fabrykowane przez
/// overlap imm_shr4 (v1_78, mismatch) albo za szerokie okno v2.
const ARB: &[((u64, u64), &str)] = &[
    ((0x00000000008f789cu64, 0x000fe20003f0ff70u64), "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0xf8, 0x8f"),
    ((0x00000000000f789cu64, 0x000fe20003f0ff70u64), "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0xf8, 0xf"),
    ((0x000000000004789cu64, 0x000fe20003f0e872u64), "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x42, 0x4"),
    ((0x000000000004789cu64, 0x000fe20003f0e874u64), "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x44, 0x4"),
    ((0x000000000008789cu64, 0x000fe20003f0ef70u64), "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x78, 0x8"),
    ((0x000000000014789cu64, 0x000fe20003f0e870u64), "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x14"),
    ((0x000000000044789cu64, 0x000fe20003f0e870u64), "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x44"),
    ((0x000000000009789cu64, 0x000fe20003f0e870u64), "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x9"),
    ((0x000000000000789cu64, 0x000fe20003f0e070u64), "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x0, 0x0"),
];

#[test]
fn t168_2_decode_pary_arb() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for ((lo, hi), text) in ARB {
        let w = (*lo as u128) | ((*hi as u128) << 64);
        assert_eq!(dec(&idx, w, &t), *text);
    }
}

#[test]
fn t168_3_encode_payload_byte_exact() {
    let t = t103a();
    for ((lo, hi), text) in CORPUS {
        let got = enc(&t, text);
        let want = ((*lo as u128) | ((*hi as u128) << 64)) & !SCHED;
        assert_eq!(got, want, "payload for {text}");
    }
}

#[test]
fn t168_4_fail_closed_outside_lattice() {
    let t = t103a();
    for bad in [
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x41, 0x4",  // v1 odd (bit0 bez magazynu)
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x100, 0x4", // v1 > 0xfe
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, 0x40, 0x100", // v2 > 0xff
        "UPLOP3.LUT UP0, UPT, UPT, UPT, UPT, -0x8, 0x4",  // ujemny
    ] {
        let insn = parse_sass(bad, 0).expect("parse");
        assert!(encode_instruction(&insn, &t).is_err(), "must fail-closed: {bad}");
    }
}

#[test]
fn t168_5_strict_hole_bit24plus() {
    // slowo z [24:.) != 0 (vendor inert, drukuje bez nich) = strict-hole
    // (zamrozone tightening; zero kotwic w korpusie).
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let w: u128 = 0x000fe20003f0e870u128 << 64 | 0x000000000104789cu128;
    assert!(idx.decode(w, 0, &t).is_err());
}

#[test]
fn t168_6_fixed_point_and_legacy_rule() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for ((lo, hi), text) in CORPUS {
        let w = (*lo as u128) | ((*hi as u128) << 64);
        let re = enc(&t, &dec(&idx, w, &t));
        assert_eq!(re, w & !SCHED, "fixed-point for {text}");
    }
    // legacy P-forma zostaje na regule 030 (fail-closed dla nowych wartosci):
    let insn = parse_sass("UPLOP3.LUT UP0, PT, P0, P1, PT, 0xf8, 0x8f", 0).expect("parse");
    assert!(encode_instruction(&insn, &t).is_err());
}

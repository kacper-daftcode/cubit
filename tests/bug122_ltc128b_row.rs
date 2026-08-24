//! BUG-122 (F2-Q, depozyt loop5 iter52 / DESCCAMP-D1, severity A): encode_only
//! retention row `LDG.E.LTC128B.128_R_dARI`::"128,E,LTC128B" w sm103a.json
//! (zachowana przez BUG-094 era-text retention) emitowala slowo z ZEROWYM
//! hi-payload (bajty 8..11): enkoder wypelnia wylacznie bity < 64 (pola
//! koncza sie na [63:40], and_base mial tylko 0x980), wiersz niesie zero
//! vendor/wymaganych-krzemiowo bitow w hi-KLUCZU klasy. Krzem B300: slowo
//! takie = SYNC:ILLEGAL_ADDRESS (DESCCAMP-D1 p_txt_ltc13), podczas gdy slowo
//! vendor 13.3 z tymi samymi operandami (desc[UR4][R2.64]) = OK
//! (p_raw_ltc13/_pol). b12 "default-desc gate" = TEN BUG, nie krzem.
//!
//! Prawo krzemiowe (results/b12/DESCCAMP-D1.md + matrix.json, clear-1-bit
//! sweep ze slowa vendor, 12b x2 repliki): wymagane {72,90,91}; obojetne
//! pojedynczo {0,69,74,75,76,81,82,83,84}; kandydaci zweryfikowani krzemiowo:
//! s_ltc_minlaw (tylko {72,90,91} + lo-payload, bit0=0) OK, s_ltc_fullaw
//! (pelny hi-payload vendor 0x0c1e1d20) OK.
//!
//! Fix (data-level, wylacznie tables/sm103a.json; wiersz encode_only => decode
//! nieosiagalny, zero decode-delta): and_base |= hi-payload vendor
//! {69,72,74,75,76,81,82,83,84,90,91} (= 0x0c1e1d20<<64 — paritet z siostra
//! "128,E" ktora trzyma swoj hi-pattern 0x0c1e1d00 w and_base i reprodukuje
//! vendor bajtowo) + bit0=1 (vendor/era zawsze [2:0]=001-pche; sweep:
//! bit0 obojetny, ale None-field [2:0] czyszcil bit0 przy encode — pole
//! usuniete, region [2:0] dalej decode-luzny przez variable_mask).
//! variable_mask |= {76,90}: era slowa rt98 (249 slotow, hi {72,73,75,81..84,
//! 91,92}) maja te bity = 0 (patrz !rsd[76:0,90:0] w frozen rt98_v2.sass);
//! gdyby wiersz kiedys opuszczen retention, strict-match era dalej dziala
//! (zweryfikowane arytmetycznie w nocie raportu 122.md).
//!
//! Piny t122_1/2/5 FAIL przed fixem (kontrola), t122_3/4/6 = kotwice PASS.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

/// Slowo vendor ptxas-13.3.73, LDG.E.LTC128B.128 R4, desc[UR4][R2.64],
/// krzemiowo OK na B300 (DESCCAMP-D1 p_raw_ltc13/p_raw_ltc13_pol).
const VENDOR: u128 = 0x001e_a800_0c1e_1d20u128 << 64 | 0x0000_0004_0204_7981u128;
/// Era slowo rt98_pub (DESCCAMP-D1 p_raw_ltc_era; era-shape = gated IA na
/// B300, pre-fix render-anchor через "64,E").
const ERA: u128 = 0x0000_240e_0018_1e0bu128 << 64 | 0x0000_0008_0608_7981;
/// Maska zdejmujaca ctrl/sched (bity >= 96) — jak w bug116.
const NOSCHED: u128 = !(0xFFFF_FFFFu128 << 96);
/// Bity wymagane krzemiowo wg sweepu D1.
const SILICON_REQUIRED: u128 = (1u128 << 72) | (1u128 << 90) | (1u128 << 91);
/// Hi-payload vendor (bity [95:64]) — oczekiwana wartosc po fixie.
const PAYLOAD_HI: u64 = 0x0c1e_1d20;

fn enc103(text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &t103()).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}

fn dec103(word: u128) -> String {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    let d = idx.decode(word, 0, &t).expect("decode failed");
    to_sass(&d)
}

/// t122_1: encode dokladnej reprodukcji D1 daje hi-payload == vendor
/// (bajty 8..11 = 0x20 1d 1e 0c) + bit0=1 + bity krzemiowo wymagane.
#[test]
fn t122_1_encode_vendor_parity() {
    let w = enc103("LDG.E.LTC128B.128 R4, desc[UR4][R2.64]");
    assert_eq!(w & NOSCHED, VENDOR & NOSCHED,
               "payload encode musi byc bajt-w-bajt vendorem (maska ctrl>=96): got {w:#034x}");
    assert_eq!(w & SILICON_REQUIRED, SILICON_REQUIRED,
               "bity wymagane krzemiowo {{72,90,91}} musza byc ustawione: {w:#034x}");
}

/// t122_2: druga kombinacja operandow (ksztalt era-linii rt98) — ten sam
/// staly hi-payload, pola operandow na swoich miejscach (Rd@16, r1@24,
/// ur0@32, imm-okno [63:40] zerowe dla braku offsetu).
#[test]
fn t122_2_encode_era_shape_operands() {
    let w = enc103("LDG.E.LTC128B.128 R8, desc[UR8][R6.64]");
    assert_eq!(((w >> 64) & 0xFFFF_FFFF) as u64, PAYLOAD_HI,
               "hi-payload musi byc operand-niezalezny: {w:#034x}");
    assert_eq!((w >> 16) & 0xFF, 8, "Rd R8 @ [23:16]: {w:#034x}");
    assert_eq!((w >> 24) & 0xFF, 6, "baza R6 @ [31:24]: {w:#034x}");
    assert_eq!((w >> 32) & 0xFF, 8, "UR deskryptora UR8 @ [39:32]: {w:#034x}");
    assert_eq!((w >> 40) & 0xFF_FFFF, 0, "imm-okno [63:40] = 0: {w:#034x}");
    assert_eq!(w & SILICON_REQUIRED, SILICON_REQUIRED);
}

/// t122_3 (kotwica): wiersz pozostaje decode-niewidoczny — slowo vendor i
/// slowo NOWO-zakodowane renderuja sie przez siostrzany wiersz "128,E"
/// (LDG.E.128), zero hijack decode.
#[test]
fn t122_3_decode_invisible_sister_claims() {
    let s_vendor = dec103(VENDOR);
    assert!(s_vendor.starts_with("LDG.E.128 R4, desc[UR4][R2.64]"),
            "vendor word: render przez siostre 128,E (encode_only retention): {s_vendor}");
    let w_new = enc103("LDG.E.LTC128B.128 R4, desc[UR4][R2.64]");
    let s_new = dec103(w_new);
    assert!(s_new.starts_with("LDG.E.128 R4, desc[UR4][R2.64]"),
            "nowo-zakodowane slowo: render przez siostre, bez hijack: {s_new}");
}

/// t122_4 (kotwica): era slowo rt98 decode-side bez zmian (delta-anchor:
/// zakres fixu = encode-only; decode-side klasyfikacji era-shape = b4/b11).
#[test]
fn t122_4_era_decode_anchor() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    assert!(idx.decode(ERA, 0, &t).is_err(), "era slowo zostaje __raw__ (gated era-shape): anchor");
    // parse+encode era-linii dalej dziala (retention), teraz z krzemiowo
    // legalnym payloadem
    let w = enc103("LDG.E.LTC128B.128 R8, desc[UR8][R6.64]");
    assert_eq!(((w >> 64) & 0xFFFF_FFFF) as u64, PAYLOAD_HI, "era-shape encode payload: {w:#034x}");
}

/// t122_5: klasa-census law — kazda era-linia LDG.E.LTC128B.128 z frozen
/// rt98_v2.sass enkoduje sie z bitami wymaganymi {72,90,91} i stalym
/// hi-payload. Gated: CUBIT_LTC_CENSUS=<path rt98_v2.sass>; bez env dwie
/// linie inline.
#[test]
fn t122_5_class_census_silicon_law() {
    let mut lines: Vec<String> = Vec::new();
    if let Ok(p) = std::env::var("CUBIT_LTC_CENSUS") {
        let txt = std::fs::read_to_string(p).expect("census file");
        for l in txt.lines() {
            if l.contains("LDG.E.LTC128B.128") {
                let cut = l.split('!').next().unwrap();
                let cut = cut.split(';').next().unwrap();
                // zdejmij prefiks kontrolny [B..:..]
                let stmt = match cut.find("LDG.E.LTC128B.128") {
                    Some(i) => cut[i..].trim().to_string(),
                    None => continue,
                };
                lines.push(stmt);
            }
        }
    } else {
        lines.push("LDG.E.LTC128B.128 R8, desc[UR8][R6.64]".into());
        lines.push("LDG.E.LTC128B.128 R28, desc[UR8][R6.64+0x5000]".into());
    }
    assert!(!lines.is_empty());
    let mut imm_empty = 0usize;
    for (i, l) in lines.iter().enumerate() {
        let w = enc103(l);
        assert_eq!(w & SILICON_REQUIRED, SILICON_REQUIRED,
                   "linia {i} {l:?}: brak bitow wymaganych krzemiowo: {w:#034x}");
        assert_eq!(((w >> 64) & 0xFFFF_FFFF) as u64, PAYLOAD_HI,
                   "linia {i} {l:?}: hi-payload rozny od vendor 0x0c1e1d20: {w:#034x}");
        if (w >> 40) & 0xFF_FFFF == 0 { imm_empty += 1; }
    }
    // sanity: co najmniej jedna linia bez offsetu (imm 0)
    assert!(imm_empty >= 1);
    eprintln!("t122_5: {} linii klasy — silicon-law + payload OK", lines.len());
}

/// t122_6 (kotwica): wiersz-retencja istnieje i geometria pol nietknieta
/// (reg@16/sub_r1@24/sub_ur0@32/sub_imm2@40/guard@12), encode_only = true.
#[test]
fn t122_6_retention_geometry_anchor() {
    let t = t103();
    let e = t.entries.get("LDG.E.LTC128B.128_R_dARI").expect("retention row");
    assert!(e.encode_only, "wiersz ma zostac encode_only (retention)");
    let mg = e.mod_groups.get("128,E,LTC128B").expect("mod group");
    let want = [(12u8, 4u8), (16, 8), (24, 8), (32, 8), (40, 24)];
    // (post-fix: fantomowe pole [2:0] None usuniete)
    let got: Vec<(u8, u8)> = mg.fields.iter().map(|f| (f.shift as u8, f.bits as u8)).collect();
    assert_eq!(got, want, "geometria pol ma byc nietknieta: {got:?}");
}

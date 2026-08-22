//! BUG-069 (F2Q-069-kand z 067 findings; zamkniete F2 2026-08-22):
//! vendor 5-token form `ULEA.HI UR6, UR6, 0x1, URZ, 0x1b` (libcusparse.so.663
//! @3536, sm_103 gold) renderowala sie blednie w OBU tabelach (render-parity,
//! dekoder tracil operand albo fuzowal imm).
//!
//! Mechanika (empiria CUBIT_DEBUG_DECODE + inspekcja wierszy):
//! - sm103a: prawidlowy wiersz ULEA_UR_UR_II_UR_II mg "HI" istnial z DOBRA
//!   geometria (8-bit ureg/imm32/imm5), ale przegrywal wyscig kandydatow z
//!   szerszym wierszem ULEA_UR_UR_II_II mg "": jego pole imm@75/6b pochlanialo
//!   bit80 = DYSKRYMINATOR MODU HI (match_mask = ~variable_mask & ~field_mask
//!   nigdy nie testuje bitow pol imm). Fix dane: imm zawezone 6b->5b (okno
//!   [79:75], jak w rodzenstwie HI,SX32) + vm bit79 dolaczony (0x7800->0xf800)
//!   => bit80 wchodzi do matcha i forma plain przestaje rosciic slowa HI.
//!   Bezpieczenstwo: 211 slow plain w korpusie vendor (records) mialo
//!   max imm2 = 11 < 32 => zawezenie NIESTRATNE.
//! - sm120: wiersz dedykowany ULEA.HI_UR_UR_II_UR_II mial singleton-geometry
//!   (and_base wymagal ~1<<37 bitow w oknie imm => martwy dla dekodera);
//!   rodzine serwil zlefitowany singleton ULEA_UR_UR_II_II mg "HI" (imm
//!   3-bit "pred"@75, src3 gubiony, URZ->RZ) oraz ULEA_UR_UR_II_UR_II mg "HI"
//!   o tej samej zlefitowanej geometrii. Fix dane: wiersz dedykowany i
//!   II_UR_II(HI) przebudowane do geometrii rodziny (kotwice: 122 slow
//!   vendor libcusparse + gold 663), fantomy (ULEA_UR_UR_II_II,"HI") i
//!   (ULEA_UR_UR_UR_II,"HI") usuniete (0 kotwic vendor, render stratny).
//!
//! Stale slow = payload zlotych rekordow (records/*.jsonl), ctrl = domyslny
//! wzorzec enkodera 0x000fc200.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn dec(t: &IsaTable, word: u128) -> String {
    let idx = DecodeIndex::build(t);
    let d = idx.decode(word, 0, t).expect("decode failed");
    format!("{d}").trim_end_matches([' ', ';']).to_string()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
    encode_instruction(&insn, t).expect("encode failed")
}

// payload zlotego slowa 663 (ctrl zamieniony na stala enkodera)
const GOLD663_TEXT: &str = "ULEA.HI UR6, UR6, 0x1, URZ, 0x1b";
const GOLD663_WORD: u128 = 0x000fc2000f8fd8ff0000000106067891u128;

// t1: decode daje DOKLADNIE tekst vendora na obu tabelach (kotwice gold).
#[test]
fn t1_decode_vendor_exact_both_tables() {
    for t in [t103a(), t120()] {
        let s = dec(&t, 0x000fc8000f8fd8ff0000000106067891);
        assert_eq!(s, GOLD663_TEXT, "render-parity vs libcusparse.663");
        let s = dec(&t, 0x000fe4000f8fc8ffffffffff1a1a7891);
        assert_eq!(s, "ULEA.HI UR26, UR26, 0xffffffff, URZ, 0x19");
        let s = dec(&t, 0x000fe2000f8fc8ffffffffff050a7891);
        assert_eq!(s, "ULEA.HI UR10, UR5, 0xffffffff, URZ, 0x19");
    }
}

// t2: encode tekstu vendora = slowo zlote (payload-exact, ctrl-default).
#[test]
fn t2_encode_fixed_point_both_tables() {
    assert_eq!(enc(&t103a(), GOLD663_TEXT), GOLD663_WORD);
    assert_eq!(enc(&t120(), GOLD663_TEXT), GOLD663_WORD);
    assert_eq!(
        enc(&t120(), "ULEA.HI UR26, UR26, 0xffffffff, URZ, 0x19"),
        0x000fc2000f8fc8ffffffffff1a1a7891u128
    );
}

// t3: roundtrip dekodera na obu tabelach dla rodziny II_UR_II HI.
#[test]
fn t3_roundtrip_family() {
    for t in [t103a(), t120()] {
        for w in [
            0x000fc8000f8fd8ff0000000106067891u128,
            0x000fe4000f8fc8ffffffffff24247891u128,
            0x000fe4000f8fc8ffffffffff1b1b7891u128,
        ] {
            let s = dec(&t, w);
            let w2 = enc(&t, &s);
            assert_eq!((w2 >> 96) as u32 & 0, 0); // noop guard
            // payload [95:0] musi sie zgadzac (ctrl = default enkodera)
            assert_eq!(w2 & ((1u128 << 96) - 1), w & ((1u128 << 96) - 1), "roundtrip {s}");
        }
    }
}

// t4: forma plain II_II pozostaje EXACT (zawezenie niestratne; imm2<=11 w
// korpusie vendor) + sx32-rodzenstwo nietkniete.
#[test]
fn t4_plain_and_sx32_unaffected_sm103a() {
    let t = t103a();
    assert_eq!(dec(&t, 0x000fe4000f8e38ff000000800b137891), "ULEA UR19, UR11, 0x80, 0x7");
    assert_eq!(dec(&t, 0x000fe4000f8e38ff000001000b137891), "ULEA UR19, UR11, 0x100, 0x7");
    assert_eq!(dec(&t, 0x000fe4000f8ffaff0000001704047291), "ULEA.HI.SX32 UR4, UR4, UR23, 0x1f");
    assert_eq!(dec(&t, 0x001fcc000f8ec0ff0000000406047291), "ULEA UR4, UR6, UR4, 0x18");
}

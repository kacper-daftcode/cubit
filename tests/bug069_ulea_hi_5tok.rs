//! BUG-069 (F2Q-069-kand z 067 findings; zamkniete F2 2026-08-22):
//! vendor 5-token form `ULEA.HI UR6, UR6, 0x1, URZ, 0x1b` (libcusparse.so.663
//! @3536, sm_103 gold) renderowala sie blednie w OBU tabelach (render-parity,
//! dekoder tracil operand albo fuzowal imm).
//!
//! Mechanika (empiria CUBIT_DEBUG_DECODE + inspekcja wierszy):
//! - sm103a: prawidlowy wiersz ULEA_UR_UR_II_UR_II mg "HI" istnial z DOBRA
//!   geometry (8-bit ureg/imm32/imm5), but it lost the candidate race to
//!   the wider ULEA_UR_UR_II_II mg "" row: its imm/6b field swallowed
//!   bit80 = the HI MOD DISCRIMINATOR (match_mask = ~variable_mask & ~field_mask
//!   never tests field bits). Data fix: imm narrowed 6b->5b (the
//!   [79:75] window, as in the HI,SX32 siblings) + bit79 joined into vm (0x7800->0xf800)
//!   => bit80 enters the match and the plain form stops claiming HI words.
//!   Safety: 211 plain words in the vendor corpus (records) had
//!   max imm2 = 11 < 32 => the narrowing is LOSSLESS.
//! - sm120: the dedicated ULEA.HI_UR_UR_II_UR_II row had singleton geometry
//!   (and_base required ~1<<37 bits in the imm window => dead to the decoder);
//!   the family was served by the misfitted singleton ULEA_UR_UR_II_II mg "HI" (imm
//!   3-bit "pred", src3 dropped, URZ->RZ) and ULEA_UR_UR_II_UR_II mg "HI"
//!   with the same misfit geometry. Data fix: the dedicated row and
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

// t3: decoder round-trip on both tables for the II_UR_II HI family.
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
            // the [95:0] payload must match (ctrl = encoder default)
            assert_eq!(w2 & ((1u128 << 96) - 1), w & ((1u128 << 96) - 1), "roundtrip {s}");
        }
    }
}

// t4: forma plain II_II pozostaje EXACT (zawezenie niestratne; imm2<=11 w
// t4: the plain II_II form stays EXACT (lossless narrowing; imm2<=11 in
// the vendor corpus) + the sx32 sibling untouched.
#[test]
fn t4_plain_and_sx32_unaffected_sm103a() {
    let t = t103a();
    assert_eq!(dec(&t, 0x000fe4000f8e38ff000000800b137891), "ULEA UR19, UR11, 0x80, 0x7");
    assert_eq!(dec(&t, 0x000fe4000f8e38ff000001000b137891), "ULEA UR19, UR11, 0x100, 0x7");
    assert_eq!(dec(&t, 0x000fe4000f8ffaff0000001704047291), "ULEA.HI.SX32 UR4, UR4, UR23, 0x1f");
    assert_eq!(dec(&t, 0x001fcc000f8ec0ff0000000406047291), "ULEA UR4, UR6, UR4, 0x18");
}

//! BUG-032 (rejestr sm120: 032 / iter92 + i93 census): operand GATE MMA
//! (trailing UP rodzin QMMA/HMMA, sel 3b@87 + inv@90) ma konwencje nazw
//! ODWROCONA wzgledem nvdisasm: nvdisasm UPn <=> sel 7-n, UPT <=> sel 0,
//! a cubit drukowal/kodowal sel=n, UPT=7. Wewnetrzny roundtrip kubita dzialal
//! (inwersja symetryczna obu stron), ale tekst nvdisasm -> cubit asm dawal
//! INNA wartosc sel niz kanon (bit-exact re-emisja cudzych kerneli zlamana).
//!
//! Zakres (werdykt i93, 206775 rekordow UP, 2113 cubin): inwersja WYLACZNIE
//! na gate-operandzie MMA; WSZYSTKIE pozostale pola upred (@81 dest, @87 src
//! UISETP/USEL, @68 PLOP3/UPLOP3, BRA @24, ...) sa STRAIGHT — fix nie moze
//! byc globalny. Totez nowa ekstrakcja `upred_gate`, uzyta TYLKO przez pole
//! gate w wierszach zlozonych na zlocie.
//!
//! Bonus-naprawa wykryta zlota-censusem: wiersze `QMMA.16832.F32.*_R_R_R_R_UP`
//! mialy zharvestowane pola POZA oknami operandow (render "R1, R195, R11" za
//! "R4, R24, R22" — 5800/5800 slow zlotych deko. bledne) i 1-bit gate (sel
//! scinany); fantom `_UP_UP` łapał pozostale wartosci gate. Wiersze przepisane
//! na fit zloty (reg@16/24/32/64, gate 3b@87 + inv@90), fantomy usuniete.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn enc(text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &t120()).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}

fn dec(word: u128) -> String {
    let idx = DecodeIndex::build(&t120());
    let d = idx.decode(word, 0, &t120()).expect("decode failed");
    format!("{d}").trim_end_matches([' ', ';']).to_string()
}

fn gate(word: u128) -> (u64, bool) {
    (((word >> 87) & 7) as u64, (word >> 90) & 1 != 0)
}

/// Zlote slowa i zgodne z nvdisasm teksty (i93 harvest, cublasLt sm_120).
const GOLD: &[(u128, &str)] = &[
    (0x00cfe20003802c04000000161804727a, "QMMA.16832.F32.E4M3.E4M3 R4, R24, R22, R4, UP0"),
    (0x00cfe20003002c04000000868804727a, "QMMA.16832.F32.E4M3.E4M3 R4, R136, R134, R4, UP1"),
    (0x00cfe2000380ac04000000161804727a, "QMMA.16832.F32.E4M3.E5M2 R4, R24, R22, R4, UP0"),
    (0x004fe20003006c04000000464804727a, "QMMA.16832.F32.E5M2.E4M3 R4, R72, R70, R4, UP1"),
];

#[test]
fn bug032_gold_decode_and_reencode_byte_exact() {
    for (word, text) in GOLD {
        assert_eq!(&dec(*word), text, "render differs for {word:#034x}");
        assert_eq!(enc(text) & !SCHED, word & !SCHED, "re-encode differs for {text:?}");
    }
}

#[test]
fn bug032_gate_name_inversion_encode() {
    // repro z karty: encodecubit "UP6" pisal sel=6; nvdisasm-canon = sel 1.
    let w = enc("QMMA.16832.F32.E4M3.E4M3 R8, R40, R44, R8, UP6");
    assert_eq!(gate(w), (1, false), "UP6 must land at sel=1 (nvdisasm canon)");
    assert_eq!(gate(enc("QMMA.16832.F32.E4M3.E4M3 R8, R40, R44, R8, UP0")).0, 7);
    assert_eq!(gate(enc("QMMA.16832.F32.E4M3.E4M3 R8, R40, R44, R8, UPT")).0, 0);
    assert_eq!(gate(enc("QMMA.16832.F32.E4M3.E4M3 R8, R40, R44, R8, !UP5")), (2, true));
    assert_eq!(gate(enc("QMMA.16832.F32.E4M3.E4M3 R8, R40, R44, R8, !UPT")), (0, true));
}

#[test]
fn bug032_gate_name_inversion_decode() {
    // tabela z karty: (sel,inv) -> nvdisasm render
    let base: u128 = 0x00cfe20003802c04000000161804727a; // E4M3.E4M3 UP0 (sel=7,inv=0)
    let mut w = base;
    w &= !(0b111u128 << 87); // sel=0,inv=0 -> nvdisasm POMIJA operand (kanon)
    assert_eq!(dec(w), "QMMA.16832.F32.E4M3.E4M3 R4, R24, R22, R4");
    // ...a 4-tokenowy tekst re-enkoduje sie do tych samych bitow (sel=0)
    assert_eq!(enc("QMMA.16832.F32.E4M3.E4M3 R4, R24, R22, R4") & !SCHED, w & !SCHED,
        "omitted-UPT render must re-encode to the sel=0 word");
    w |= 1u128 << 90; // sel=0,inv=1 -> !UPT jawny (inv NIGDY pomijany)
    assert_eq!(dec(w), "QMMA.16832.F32.E4M3.E4M3 R4, R24, R22, R4, !UPT");
    w = (base & !(0b111u128 << 87)) | (1u128 << 87); // sel=1 -> UP6
    assert_eq!(dec(w), "QMMA.16832.F32.E4M3.E4M3 R4, R24, R22, R4, UP6");
    w = (base & !(0b111u128 << 87)) | (2u128 << 87) | (1u128 << 90); // (2,1) -> !UP5
    assert_eq!(dec(w), "QMMA.16832.F32.E4M3.E4M3 R4, R24, R22, R4, !UP5");
}

#[test]
fn bug032_self_roundtrip_all_gate_values() {
    for n in 0..=7 {
        for inv in [false, true] {
            let name = if n == 7 { "UPT".to_string() } else { format!("UP{n}") };
            let name = if inv { format!("!{name}") } else { name };
            let text = format!("QMMA.16832.F32.E4M3.E4M3 R8, R40, R44, R8, {name}");
            let w = enc(&text);
            // kanon nvdisasm: sel=0=UPT jest POMIJANY w renderze (bez inv)
            let canon = if name == "UPT" {
                "QMMA.16832.F32.E4M3.E4M3 R8, R40, R44, R8".to_string()
            } else { text.clone() };
            assert_eq!(dec(w), canon, "roundtrip broke for gate {name}");
            // i re-encode kanonicznego tekstu = te same bity
            assert_eq!(enc(&canon) & !SCHED, w & !SCHED, "canon re-encode broke for {name}");
        }
    }
}

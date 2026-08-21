//! BUG-053 (rejestr sm120: 053_omma_sf_field_extraction.md, SPARK q3 gx4):
//! wpisy OMMA.SF.16864 (E2M1.E2M1.{E8, UE4M3.4X}) niosly pola `reg_shr3`
//! (3-bit @18/26/34/42/50/66, _source: compute_120f extraction) — forma byla
//! w tabeli, ale zupelnie niekodowalna ("operand 7 (UR6) has no field able
//! to encode it"). Prawdziwa geometria (nvdisasm + warianty bitowe na gx4):
//! reg 8b @16/24/32/40/52 + Rc@64 w hi-word, UR6 @[63:60], bajt@[87:80] to
//! discriminator wariantu (E8=0x08, UE4M3.4X=0x04). Krzem GB10 wykonuje.
//! Fix: geometria klonowana z rodziny QMMA.SF + czysty and_base (usuniety
//! okaleczaly bit68, ktory nalezy do pola Rc).
use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
const SCHED: u128 = 0x1_FFFFu128 << 105;
fn enc_clean(t: &IsaTable, s: &str) -> u128 {
    let insn = cubit::parse_cuasm_line(s, 0).unwrap_or_else(|e| panic!("parse {s:?}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {s:?}: {e}"))
}
fn dec(t: &IsaTable, word: u128) -> String {
    let idx = DecodeIndex::build(t);
    format!("{}", idx.decode(word, 0, t).expect("decode"))
        .trim_end_matches([' ', ';']).trim().to_string()
}

/// Golden _discovery (lo/hi z erratum; nvdisasm SM120 i SM121a -> ten sam tekst).
const E8_TEXT: &str = "OMMA.SF.16864.F32.E2M1.E2M1.E8 R8, R8, R12, R16, R0, R0, UR6";
const E8_GOLD: u128 = 0x008f_f600_0008_0010_6000_000c_0808_747f;
const UE4M3_TEXT: &str = "OMMA.SF.16864.F32.E2M1.E2M1.UE4M3.4X R8, R8, R12, R16, R0, R0, UR6";

#[test]
fn bug053_e8_encode_matches_golden() {
    let t = t120();
    assert_eq!(enc_clean(&t, E8_TEXT) & !SCHED, E8_GOLD & !SCHED);
}

#[test]
fn bug053_e8_golden_decodes_to_text() {
    let t = t120();
    assert_eq!(dec(&t, E8_GOLD), E8_TEXT);
}

#[test]
fn bug053_ue4m3_variant_forms_and_discriminator() {
    let t = t120();
    // UE4M3.4X: pre-fix = ENCFAIL (brak pol); teraz koduje i rozni sie od E8
    // wylacznie discriminatorem @[87:80] (0x04 vs 0x08) oraz bitem sched-side.
    let w4x = enc_clean(&t, UE4M3_TEXT);
    assert_eq!((w4x >> 80) & 0xFF, 0x04, "discriminator UE4M3.4X @[87:80]");
    assert_eq!((E8_GOLD >> 80) & 0xFF, 0x08, "discriminator E8 @[87:80]");
    // poza sched i discriminatore slowo tozsame (operand-layout z QMMA.SF)
    let mask = !(SCHED | (0xFFu128 << 80));
    assert_eq!(w4x & mask, E8_GOLD & mask, "pola operandow identyczne E8 vs 4X");
    // roundtrip wariantu 4X przez nasz dekoder
    assert_eq!(dec(&t, w4x), UE4M3_TEXT);
}

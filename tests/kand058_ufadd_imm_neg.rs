//! KANDYDAT-058 (SPARK sm_121a iter7, errata-landing): UFADD z ujemnym
//! immediatem — luka semantyki enkodera. HW (gold nvcc sm_121a):
//!  * `UFADD UR7, UR6, -0.12400979548692703247` -> pattern f32 @32..63
//!    PLUS bit2=1 (mirror znaku); cubit dawal bit2=0 (op_neg tylko Reg/UReg).
//!  * `UFADD UR7, UR6, -12583039` (token "int") -> gold @32..63 =
//!    f32(-12583039.0) = 0xcb40007f (ieee-cast WARTOSCI) + bit2=1; cubit
//!    pisal surowa wartosc int.
//! Fix: nowe ekstrakcje `neg_f32` (znak FloatImm/Imm32) i `f32cast`
//! (Imm32 -> f32 WARTOSCI, bo nvdisasm drukuje calkowite patterny f32
//! jak inty). Czysto addytywne: zaden istniejacy wiersz repo ich nie uzywa
//! (neg+f32 na jednym tokenie ma tylko DFMA_R_R_FI_R tok3 -> `neg`/`f32`,
//! bez zmian). Adopcja = lokalna tabela sm121a po stronie SPARKA.

use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn table_ufadd() -> IsaTable {
    // encoder tokens are 1-based over operands (token 0 = guard slot):
    // 1 = UR dst, 2 = UR src, 3 = immediate. FI = FloatImm key, II = int key.
    let fields = r#"[
        {"shift": 16, "bits": 8, "token_idx": 1, "extraction": "ureg"},
        {"shift": 24, "bits": 8, "token_idx": 2, "extraction": "ureg"},
        {"shift": 32, "bits": 32, "token_idx": 3, "extraction": "f32cast"},
        {"shift": 2, "bits": 1, "token_idx": 3, "extraction": "neg_f32"}
      ]"#;
    let json = format!(
        r#"{{"UFADD_UR_UR_FI": {{"mod_groups": {{"": {{"and_base": "0x0", "fields": {fields} }}}}}},
        "UFADD_UR_UR_II": {{"mod_groups": {{"": {{"and_base": "0x0", "fields": {fields} }}}}}}}}"#
    );
    let p = std::env::temp_dir().join(format!(
        "kand058_ufadd_{}_{:?}.json",
        std::process::id(),
        std::time::Instant::now()
    ));
    std::fs::write(&p, json).unwrap();
    IsaTable::load(&p).unwrap()
}

fn enc(text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, &table_ufadd()).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}

#[test]
fn int_looking_negative_imm_is_f32_value_cast() {
    let w = enc("UFADD UR7, UR6, -12583039");
    assert_eq!((w >> 32) & 0xffff_ffff, 0xcb40007f, "f32(-12583039.0)");
    assert_eq!((w >> 2) & 1, 1, "neg mirror bit2");
    assert_eq!((w >> 16) & 0xff, 7, "dst UR7");
    assert_eq!((w >> 24) & 0xff, 6, "src UR6");
}

#[test]
fn floatimm_negative() {
    let w = enc("UFADD UR7, UR6, -0.5");
    assert_eq!((w >> 32) & 0xffff_ffff, 0xbf00_0000, "f32(-0.5)");
    assert_eq!((w >> 2) & 1, 1);
}

#[test]
fn positive_imm_no_neg_mirror() {
    let w = enc("UFADD UR1, UR2, 1.5");
    assert_eq!((w >> 32) & 0xffff_ffff, 0x3fc0_0000, "f32(1.5)");
    assert_eq!((w >> 2) & 1, 0, "bit2 must stay 0 for non-negative");
    let w2 = enc("UFADD UR1, UR2, 134217728");
    assert_eq!((w2 >> 32) & 0xffff_ffff, 0x4d00_0000, "f32(134217728) exact");
    assert_eq!((w2 >> 2) & 1, 0);
}

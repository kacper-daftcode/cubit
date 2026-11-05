//! wave 11: FMNMX3 immediate form carries an f32 at bits [63:32].
//!
//! Canonical row `FMNMX3_R_R_FI_R_P` mod_group `''` (sm_100a / sm_103a; the
//! BUG-508 lane fields of 2026-09-22, re-keyed from the harvest key
//! `FMNMX3_R_R_II_R_P` in wave 11) models the third operand as a real `f32`
//! field. The pre-wave-11 II row baked 0x3f800000 (1.0) into and_base and
//! routed the text immediate into a 6-bit field at [95:90]:
//! `FMNMX3 R2, R8, 2, R28, !PT` assembled to 0x...0b80001c3f800000...
//! (garbage bits at [95:90], value 1.0). With the real field the parser must
//! treat FMNMX3 as float context (FI key), otherwise the textual `1` is
//! Imm32(1) and encodes 0x00000001 (the BUG-034 / BUG-125 trap class) -- the
//! strict corpus round trip of cusolver `gebal_singleton_kernel` (4 words per
//! leg) caught exactly that.
//!
//! Oracle: nvdisasm-13.3 on the corpus word with the [63:32] slot rewritten
//! (0x3f800000 -> `1`, 0x40000000 -> `2`, 0x3fc00000 -> `1.5`,
//! 0x00000002 -> `2.8025969286496341418e-45`).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const NOSCHED: u128 = !(0xFFFF_FFFFu128 << 96);
/// corpus word: libcusolver.so.1529.sm_103 gebal_singleton_kernel @+0x4a40
const CORPUS: u128 = 0x041fe2000780001c3f80000008027876;

fn table(name: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(name)).unwrap()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).unwrap_or_else(|e| panic!("parse {text:?}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text:?}: {e}"))
}
fn dec(t: &IsaTable, word: u128) -> String {
    let idx = DecodeIndex::build(t);
    to_sass(&idx.decode(word, 0, t).unwrap_or_else(|e| panic!("decode {word:032x}: {e}")))
}

/// corpus word with the f32 slot rewritten and the `.reuse` bit (122) cleared
fn with_imm(bits: u32) -> u128 {
    (CORPUS & !(0xFFFF_FFFFu128 << 32) & !(1u128 << 122)) | ((bits as u128) << 32)
}

#[test]
fn wave11_fmnmx3_imm_is_f32_on_both_legs() {
    for name in ["tables/sm103a.json", "tables/sm100a.json"] {
        let t = table(name);
        // corpus fixed point: decode text == nvdisasm, re-encode == word (payload)
        let text = dec(&t, CORPUS);
        assert_eq!(text.trim_end_matches([' ', ';']), "FMNMX3 R2, R8.reuse, 1, R28, !PT", "{name}");
        assert_eq!(enc(&t, &text) & NOSCHED, CORPUS & NOSCHED, "{name}: corpus round trip");
        // the slot is a float: textual integers are f32 values, not raw bits
        for (imm, lit) in [(0x3f80_0000u32, "1"), (0x4000_0000, "2"), (0x3fc0_0000, "1.5"), (0x4180_0000, "16")] {
            let w = enc(&t, &format!("FMNMX3 R2, R8, {lit}, R28, !PT"));
            assert_eq!(w & NOSCHED, with_imm(imm) & NOSCHED, "{name}: FMNMX3 imm {lit}");
            assert_eq!(dec(&t, with_imm(imm)).trim_end_matches([' ', ';']), format!("FMNMX3 R2, R8, {lit}, R28, !PT"), "{name}: print {lit}");
        }
        // raw-bits spelling stays available: `0x<8 hex>F` is the parser's f32 bit-pattern literal
        assert_eq!(enc(&t, "FMNMX3 R2, R8, 0x3f800000F, R28, !PT") & NOSCHED, CORPUS & NOSCHED, "{name}: hex bits");
    }
}

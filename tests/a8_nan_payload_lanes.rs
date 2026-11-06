//! A8 (KNOWN_ISSUES, closed 2026-11-06): NaN immediates keep their payload through the lossless
//! print on every immediate lane. nvdisasm's `+QNAN` / `-QNAN` / `+SNAN` / `-SNAN` carry the sign
//! and the quiet bit only — measured 2026-11-06 with nvdisasm 13.1 on `-b SM120` (= `SM103`):
//! every payload of the f64 high dword (DFMA, MUFU.RCP64H) and of the fp16 / bf16 halves of
//! HFMA2 prints the same glyph (`T/t12/a8/a8_sweep.json`) — so the vendor's text cannot carry
//! the payload and the display print follows it. The lossless print (the strict round trip,
//! `disassemble --frozen`) spells the f32 lane as `0x<8 hex>F` since 2026-11-04, and now the f64
//! lane as `0x<8 hex>D` (the high dword, which is all the word carries) and the fp16 / bf16
//! halves under `II`-typed tokens as the f32 literal of the half (the half <-> f32 <-> f64
//! conversions are payload-preserving shifts); each re-encodes bit for bit.
use cubit::decoder::DecodeIndex;
use cubit::table::IsaTable;
use std::sync::OnceLock;

fn table() -> &'static (IsaTable, DecodeIndex) {
    static T: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    T.get_or_init(|| {
        let path = std::env::var_os("CUBIT_TABLE").map(std::path::PathBuf::from)
            .unwrap_or_else(|| "tables/sm120.json".into());
        let t = IsaTable::load(&path).unwrap();
        let idx = DecodeIndex::build(&t);
        (t, idx)
    })
}

const SCHEDULE: u128 = ((1u128 << 23) - 1) << 105;

fn reencode(text: &str) -> Result<u128, String> {
    let (t, _) = table();
    let body = text.trim().trim_end_matches(';').trim();
    let parsed = cubit::parser::parse_sass(&format!(" {body} ;"), 0).map_err(|e| e.to_string())?;
    cubit::encoder::encode_instruction(&parsed, t).map_err(|e| e.to_string())
}

/// (word, nvdisasm 13.1 text, the lossless spelling)
const CASES: &[(u128, &str, &str)] = &[
    // f64 high dword: DFMA R4, R6, R8, imm — payloads 0xffffffff / 0xfff81234 (QNAN), 0x7ff40001 (SNAN)
    (0x000fe20000000008ffffffff0604742b, "DFMA R4, R6, R8, -QNAN", "DFMA R4, R6, R8, 0xffffffffD"),
    (0x000fe20000000008fff812340604742b, "DFMA R4, R6, R8, -QNAN", "DFMA R4, R6, R8, 0xfff81234D"),
    (0x000fe200000000087ff400010604742b, "DFMA R4, R6, R8, +SNAN", "DFMA R4, R6, R8, 0x7ff40001D"),
    (0x000fe20000001800ffffffff00047908, "MUFU.RCP64H R4, -QNAN", "MUFU.RCP64H R4, 0xffffffffD"),
    // f32 (the 2026-11-04 literal, unchanged)
    (0x000fe20000000008ffc00001060b7423, "FFMA R11, R6, R8, -QNAN", "FFMA R11, R6, R8, 0xffc00001F"),
    // fp16 halves of HFMA2 (hi half [63:48] under the key's II-typed token, lo half [47:32])
    (0x000fe20000000008ffff001006047431, "HFMA2 R4, R6, R8, -QNAN , 9.5367431640625e-07",
     "HFMA2 R4, R6, R8, 0xffffe000F, 9.5367431640625e-07"),
    (0x000fe200000000087e01fe0006047431, "HFMA2 R4, R6, R8, +QNAN , -QNAN",
     "HFMA2 R4, R6, R8, 0x7fc02000F, 0xffc00000F"),
    (0x000fe20000000008fe017c0106047431, "HFMA2 R4, R6, R8, -QNAN , +SNAN",
     "HFMA2 R4, R6, R8, 0xffc02000F, 0x7f802000F"),
    // bf16 halves
    (0x000fe20003a08008ffff001006047431, "HFMA2.BF16_V2.RELU R4, R6, R8, -QNAN , 1.469367938527859385e-39",
     "HFMA2.BF16_V2.RELU R4, R6, R8, 0xffff0000F, 1.469367938527859385e-39"),
    (0x000fe20003a080083f80ffc106047431, "HFMA2.BF16_V2.RELU R4, R6, R8, 1, -QNAN",
     "HFMA2.BF16_V2.RELU R4, R6, R8, 1, 0xffc10000F"),
];

#[test]
fn a8_1_display_print_is_the_vendor_glyph_and_the_lossless_print_carries_the_payload() {
    let (t, idx) = table();
    for (word, vendor, lossless) in CASES {
        let d = idx.decode(*word, 0, t).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        let disp = cubit::printer::to_sass(&d);
        let loss = cubit::printer::to_sass_lossless(&d);
        assert_eq!(disp.trim().trim_end_matches(';').trim(), *vendor, "{word:032x} display");
        assert_eq!(loss.trim().trim_end_matches(';').trim(), *lossless, "{word:032x} lossless");
    }
}

#[test]
fn a8_2_every_lossless_spelling_re_encodes_bit_for_bit() {
    for (word, _, lossless) in CASES {
        let enc = reencode(lossless).unwrap_or_else(|e| panic!("{lossless}: {e}"));
        assert_eq!(enc & !SCHEDULE, *word & !SCHEDULE, "{lossless} -> {enc:032x}, expected {word:032x}");
    }
}

#[test]
fn a8_3_the_f64_high_word_literal_parses_exactly_and_hex_integers_are_untouched() {
    use cubit::ir::Operand;
    let imm = |s: &str| {
        let p = cubit::parser::parse_sass(&format!(" DFMA R4, R6, R8, {s} ;"), 0).unwrap();
        p.operands.last().unwrap().clone()
    };
    assert_eq!(imm("0xfff81234D"), Operand::FloatImm(0xfff8_1234_0000_0000));
    assert_eq!(imm("-0x7ff81234D"), Operand::FloatImm(0xfff8_1234_0000_0000));
    assert_eq!(imm("0x7ff00000D"), Operand::FloatImm(f64::INFINITY.to_bits()));
    // seven or nine hex digits before the D are hex integers, as before
    assert!(matches!(imm("0x1234abD"), Operand::Imm32(0x1234abd)));
    assert!(matches!(imm("0x123456789D"), Operand::Imm32(0x123456789d)));
}

#[test]
fn a8_4_the_vendor_glyph_itself_still_does_not_re_encode() {
    // the display print is the vendor's, payload-less by construction; the audits normalise the
    // glyph and the lossless print is the editable spelling — unchanged by A8
    for (_, vendor, _) in CASES {
        assert!(reencode(vendor).is_err(), "{vendor} should not re-encode: the glyph has no payload");
    }
}

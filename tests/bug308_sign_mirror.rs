//! BUG-308 (F2-iter169, loop5/blind front2, 2026-09-01): F2I/F2IP/USHF
//! sign mirror -- encoder generic sign emit closed, decoder prio-3 F2IP
//! arm + ghost post-pass exclusion, field-carried era lanes preserved.
//!
//! PRE (publish pyo3-9436f8c, measure308/measure308b shape census: every
//! (leg, row, operand-position, sign) probe; registration 308 from iter153
//! asked exactly for this wide census):
//!   D1 vm-gated NOOP author-drop: 'F2I.F64.FLOOR R4, -R6' mints the plain
//!      word b-identical (sign parsed, silently ignored) [x432 per leg pair].
//!   D2 vm-surviving cross-mint onto sibling law bits: USHF op1 sign ->
//!      shift-imm b63/b62 ('0x80000006'); USHF '|'-dest -> S32->U32 flip b73;
//!      USHF '-UR7' -> .W/b75 or width b74; F2I F64-rows '-R6' -> dst-type
//!      U32 drop via b72; F2IP '-R6' -> hsel .H1 b72; F2IP '-R10' -> .RELU
//!      b75; F2IP b62/b63/b73 vendor-inert (ghost printed by our decoder).
//!   D3 healthy mirror (PRESERVED): sm120/sm121a era F2I.*_R_R rows carry
//!      field neg@63/abs@62 tok2 -- 'F2I.S16.NTZ R4, -R6' vendor-agrees.
//!
//! VENDOR LAW (arb308: nvdisasm 13.3.73 raw -b, 2,357 probes, ALL FOUR
//! models SM100a/SM103a/SM120/SM121a agree on EVERY probe): on these bases
//! the sign window {62,63,72,73,74,75} carries NO operand sign except the
//! D3 field lanes; b62/b63 are the USHF shift-imm window and inert on F2IP,
//! b72 = F2I dst-type S-sel / F2IP hsel-H1, b73 = USHF S32/U32 sel / F2IP
//! inert, b74 = USHF 64-32 / F2IP .NTZ, b75 = USHF .W / F2IP .RELU.
//! CORPUS EXPOSURE ZERO (census308: 2,406-cubin battery x4 legs): no
//! authored-sign glyph ever survives the printer on a real corpus word for
//! these bases; claimed nz-delta words are imm-window/subtype artifacts
//! with vendor-identical text (rt-IDENT).
//!
//! POST arms: encoder generic sign emit excludes F2I/F2IP/USHF + a
//! fail-closed bail fires on any signed Reg/UReg operand UNLESS the matched
//! entry is an F2I row carrying Neg/NegShl1/Abs at shift 62/63 for that
//! token (the verified era mirror); decoder prio-3 gains F2IP and the
//! ghost post-pass excludes F2I/F2IP/USHF.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w & M96, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(&format!("{text};"), 0).unwrap();
    encode_instruction(&insn, t).map_err(|e| format!("{e}"))
}
fn enc_err(t: &IsaTable, text: &str) -> String {
    match enc(t, text) {
        Ok(w) => panic!("expected BUG-308 refuse, minted 0x{w:024x} for {text}"),
        Err(e) => e,
    }
}

#[test]
fn t308_1_sm120_era_sign_lanes_preserved_byte_exact() {
    let t = tab("sm120");
    // field-carried neg@63/abs@62 tok2 (era row F2I.S16.NTZ_R_R); vendor
    // prints '-R6'/'|R6|' on these bits (arb308 A-leg, x4 agreement).
    let neg = enc(&t, "@P0 F2I.S16.NTZ R4, -R6").unwrap() & M96;
    assert_eq!(neg, 0x002000008000000600040305u128);
    let abs = enc(&t, "@P0 F2I.S16.NTZ R4, |R6|").unwrap() & M96;
    assert_eq!(abs, 0x002000004000000600040305u128);
    let plain = enc(&t, "@P0 F2I.S16.NTZ R4, R6").unwrap() & M96;
    assert_eq!(plain, 0x002000000000000600040305u128);
    assert_eq!(neg ^ plain, 1u128 << 63);
    assert_eq!(abs ^ plain, 1u128 << 62);
    assert_eq!(&dec(&t, neg).unwrap(), "@P0 F2I.S16.NTZ R4, -R6");
    assert_eq!(&dec(&t, abs).unwrap(), "@P0 F2I.S16.NTZ R4, |R6|");
    assert_eq!(&dec(&t, plain).unwrap(), "@P0 F2I.S16.NTZ R4, R6");
}

#[test]
fn t308_2_sm121a_era_sign_lanes_preserved_byte_exact() {
    let t = tab("sm121a");
    let neg = enc(&t, "@P0 F2I.S8.TRUNC.NTZ R4, -R6").unwrap() & M96;
    assert_eq!(neg, 0x0020e1008000000600040305u128);
    let abs = enc(&t, "@P0 F2I.S8.NTZ R4, |R6|").unwrap() & M96;
    assert_eq!(abs, 0x002021004000000600040305u128);
    assert_eq!(&dec(&t, neg).unwrap(), "@P0 F2I.S8.TRUNC.NTZ R4, -R6");
    assert_eq!(&dec(&t, abs).unwrap(), "@P0 F2I.S8.NTZ R4, |R6|");
    assert_eq!(
        &dec(&t, enc(&t, "@P0 F2I.S8.NTZ R4, R6").unwrap()).unwrap(),
        "@P0 F2I.S8.NTZ R4, R6"
    );
}

#[test]
fn t308_3_signed_operands_fail_closed_with_attribution() {
    let cases: &[(&str, &str)] = &[
        // D1-class: pre-fix silently dropped the sign (word == plain mint)
        ("sm103a", "F2I.F64.FLOOR R4, -R6"),
        ("sm103a", "@P0 F2I -R4, 1.5"),
        // D2-class: pre-fix cross-mint onto law bits
        ("sm103a", "F2I.F64.TRUNC.U32 R4, -R6"), // b72 dst-type drop
        ("sm103a", "USHF.L.U32.HI UR3, -UR5, 0x6, UR9"), // b63 -> shift-imm
        ("sm103a", "USHF.L.U32.HI UR3, |UR5|, 0x6, UR9"), // b62 -> shift-imm
        ("sm103a", "USHF.L.S32.HI |UR3|, UR5, 0x6, UR9"), // b73 -> S32->U32
        ("sm103a", "F2IP.F32.NTZ.S8 R4, -R6, R8, R10"), // b72 -> hsel .H1
        ("sm103a", "F2IP.F32.NTZ.S8 R4, R6, R8, -R10"), // b75 -> .RELU
        ("sm103a", "F2IP.F32.NTZ.S8 R4, R6, |R8|, R10"), // b62 vendor-inert
        ("sm120", "@!P1 F2I.NTZ.TRUNC.U32 R4, -R6"),
        ("sm120", "@P0 F2IP.U8.F32 R4, -R6, R8, R10"),
        ("sm120", "F2IP.S8.F32.NTZ R6, R8, |R10|, 0x6"),
        ("sm120", "@UP0 USHF.L.U32 UR3, |UR5|, 0x6, UR9"),
        ("sm121a", "@UP0 USHF.L.S32 UR3, UR5, -UR7, 0x6"), // b75 -> .W
        ("sm121a", "@UP0 USHF.L.S64 UR3, UR5, |UR7|, 0x6"), // b74 -> width
        ("sm121a", "@P0 F2IP.F32.INVALID1.NTZ.S8 R4, R6, 1.5, -R8"),
        (
            "sm121a",
            "@P0 F2IP.F32.INVALID1.NTZ.RELU.S8 R4, |R6|, 1.5, R8",
        ),
        ("sm120", "F2I.NTZ.U32 R1, -R15"), // era-adjacent non-field lane
    ];
    for (arch, text) in cases {
        let text = text.strip_suffix(';').unwrap_or(text);
        let e = enc_err(&tab(arch), text);
        assert!(e.contains("BUG-308"), "{arch} {text}: unexpected error {e}");
    }
}

#[test]
fn t308_4_decoder_no_ghost_and_prio3_f2ip_fail_closed() {
    let t103 = tab("sm103a");
    // ghost-hsel word (pre-fix decoder printed '-R6'; vendor reads 'R10.H1')
    assert!(dec(&t103, 0x0000150a0000000806047243u128).is_none());
    // ghost-relu word (pre-fix printed plain w/ silent .RELU on vendor side)
    assert!(dec(&t103, 0x00001c0a0000000806047243u128).is_none());
    // USHF imm-window law must survive verbatim (no sign glyph)
    assert_eq!(
        dec(&t103, 0x080106098000000605037899u128).unwrap(),
        "USHF.L.U32.HI UR3, UR5, 0x80000006, UR9"
    );
    // F2I dst-type b72 law word decodes vendor-parity ('F2I.F64.TRUNC R4, R6')
    assert_eq!(
        dec(&t103, 0x0030d1000000000600047311u128).unwrap(),
        "F2I.F64.TRUNC R4, R6"
    );
    // era-adjacent word: field-carried abs prints, ghost neg gone
    for arch in ["sm120", "sm121a"] {
        assert_eq!(
            dec(&tab(arch), 0x002031004000000f00017305u128).unwrap(),
            "F2I.FLOOR.NTZ R1, |R15|"
        );
    }
}

#[test]
fn t308_5_unsigned_surface_byte_stable() {
    // Publish pyo3-9436f8c OLD mints (old_words308.json; 3,009-probe A/B:
    // 666 STABLE-MINT incl. all plain texts, 2,343 ARMED, 0 NEW-OPEN, 0
    // NEW-CHANGE) -- pin a representative cross-leg set.
    let plain: &[(&str, &str, u128)] = &[
        (
            "sm103a",
            "F2IP.F32.NTZ.S8 R4, R6, R8, R10",
            0x0000140a0000000806047243,
        ),
        (
            "sm103a",
            "USHF.L.U32.HI UR3, UR5, 0x6, UR9",
            0x080106090000000605037899,
        ),
        ("sm103a", "F2I.F64.FLOOR R4, R6", 0x003051000000000600047311),
        ("sm103a", "@P0 F2I R4, 1.5", 0x002011003fc0000000040905),
        (
            "sm120",
            "@P0 F2I.S16.NTZ R4, R6",
            0x002000000000000600040305,
        ),
        (
            "sm121a",
            "@P0 F2I.S8.NTZ R4, R6",
            0x002021000000000600040305,
        ),
    ];
    for (arch, text, want) in plain {
        let t = tab(arch);
        assert_eq!(enc(&t, text).unwrap() & M96, *want & M96, "{arch} {text}");
        let again = dec(&t, *want & M96).unwrap();
        assert_eq!(
            enc(&t, &again).unwrap() & M96,
            *want & M96,
            "roundtrip {text}"
        );
    }
}

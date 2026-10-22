//! BUG-160 (F2-iter77, front2/blind; candidate from note 158 sec.5,
//! re-queued 161 sec.5(b) F2/b11): the URZ/UR63 law in the desc[URn][...]
//! descriptor text layer was INVERTED on the decode side.
//!
//! Vendor law (nvdisasm 13.3.73 arbitration, work/bug160/probe160.sass on
//! sm_103a + p158raw probes on sm_120a; bug158 report sec.2): the descriptor
//! UR window is 8-bit at [64:72) -- value 255 renders `desc[URZ]` (the zero
//! uniform register), value 63 renders the REAL register `desc[UR63]`, and
//! the corpus even carries literal desc[UR64..UR76] (hexdb sm_103a STG.E
//! anchors). Pre-fix decode/printer (format_aruri): 63 -> "URZ"
//! (fabrication), 255 -> "UR255" (junk render that no parser accepts back).
//!
//! Census-first (bug142 hexdb all.tsv, 3 corpora / 1.9M desc-lines): the UR
//! window byte is always 0..76, ZERO occurrences of 63/255 and ZERO vendor
//! desc[URZ]/desc[UR63] texts => the inverted law is corpus-latent; the flip
//! changes no corpus decode (A/B gate 0-diff expected).
//!
//! FIXED (decode side, src/printer.rs format_aruri): standard ur_wide law --
//! field >= 8 bits: 255 = URZ, 63 = UR63; narrow windows cap at all-ones =
//! URZ there; field-less rows keep the historical URZ default. Mirrors
//! format_utc_desc / format_auri_uronly / format_sts_lds_addr.
//!
//! Encode and IR rendering now use the same law. The historical residue
//! fixture explicitly spells its numeric UR63 payload; it cannot redefine
//! URZ for normal semantic assembly. Residue-bearing input remains outside
//! the strict semantic audit.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::ir::Operand;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

/// Vendor-arbitrated decode law on the STG.E dARI skeleton (sm_103a corpus
/// anchors + byte-flips of the UR window; work/bug160/probe160.cubin renders
/// identically under nvdisasm 13.3.73). Pre-fix: 63->"URZ", 255->"UR255".
#[test]
fn t160_1_decode_law() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let a1: u128 = 0x001fe2000c101906_000000ff02007986u128; // STG.E desc[UR6][R2.64], RZ
    let base = a1 & !(0xFFu128 << 64);
    let cases: &[(u128, &str)] = &[
        (a1,                          "STG.E desc[UR6][R2.64], RZ"),
        (base | (0x3fu128 << 64),     "STG.E desc[UR63][R2.64], RZ"),
        (base | (0xFFu128 << 64),     "STG.E desc[URZ][R2.64], RZ"),
        (base,                        "STG.E desc[UR0][R2.64], RZ"),
        (0x0009e2000c10194c_0002705044007986u128, "STG.E desc[UR76][R68.64+0x270], R80"),
        (0x0009e2000c101940_0002882d44007986u128, "STG.E desc[UR64][R68.64+0x288], R45"),
    ];
    for (w, want) in cases {
        assert_eq!(dec(&idx, *w, &t), *want, "decode {w:032x}");
    }
}

/// Re-encode of canonical renders preserves both URZ and real UR63.
#[test]
fn t160_2_render_reencode_all_values() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let a1: u128 = 0x001fe2000c101906_000000ff02007986u128;
    let base = a1 & !(0xFFu128 << 64);
    let cases: &[(u128, &str, u64)] = &[
        (a1,                                     "STG.E desc[UR6][R2.64], RZ",  0x06),
        (base | (0x3fu128 << 64),                "STG.E desc[UR63][R2.64], RZ", 0x3F),
        (base | (0xffu128 << 64),                "STG.E desc[URZ][R2.64], RZ", 0xFF),
        (base,                                   "STG.E desc[UR0][R2.64], RZ",  0x00),
        (0x0009e2000c10194c_0002705044007986u128, "STG.E desc[UR76][R68.64+0x270], R80", 0x4C),
    ];
    for (w, want_text, want_byte) in cases {
        let text = dec(&idx, *w, &t);
        assert_eq!(text, *want_text, "decode {w:032x}");
        let insn = parse_sass(&format!("{text} ;"), 0).expect("rendered text must parse");
        let enc = encode_instruction(&insn, &t).expect("rendered text must encode");
        assert_eq!(((enc >> 64) & 0xFF) as u64, *want_byte,
            "window byte must survive decode->encode for {text}");
    }
}

/// Original residue source stays explicit unsupported evidence; the real
/// native STG identity must encode without residue.
#[test]
fn t160_3_legacy_residue_fixture_is_strict_negative() {
    const PIN: &str = "@P5 LDG.E.LTC128B.128 R0, desc[UR63][R60.64+0x2400] !rsd[1:1,2:1,66:1,68:1,76:0,77:1,78:1,79:1,84:0,85:1,90:0]";
    const WORD: u128 = 0x0009e4000820e914_0024003f3c005986u128;
    assert!(cubit::roundtrip_audit::check_semantic_source(PIN).is_err());
    let t = IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
    let text = "@P5 STG.E.EL.STRONG.GPU [R60.U32+UR20+0x2400], R63";
    let insn = parse_sass(text, 0).unwrap();
    assert_eq!(encode_instruction(&insn, &t).unwrap() & M96, WORD & M96);
}

/// The structured IR must preserve the distinction the vendor prints.
#[test]
fn t160_4_parser_preserves_zero_and_real_register() {
    let d = parse_sass("STG.E desc[URZ][R2.64], RZ ;", 0).unwrap();
    assert!(matches!(d.operands[0], Operand::Desc { ur_idx: 255, .. }),
        "desc[URZ] encode-side value = 255: {:?}", d.operands[0]);
    let d = parse_sass("STG.E desc[UR63][R2.64], RZ ;", 0).unwrap();
    assert!(matches!(d.operands[0], Operand::Desc { ur_idx: 63, .. }),
        "desc[UR63] stays 63: {:?}", d.operands[0]);
}

#[test]
fn t160_6_ir_renderer_keeps_zero_and_real_uniform_register_distinct() {
    for (spelling, expected) in [("URZ", 255), ("UR63", 63)] {
        let source = format!(".entry k\nSTG.E desc[{spelling}][R2.64], RZ ;\n.endentry\n");
        let file = cubit::sass_file::parse_sass_file_str_strict(&source).unwrap();
        let rendered = cubit::render::render_file(&file).unwrap();
        assert!(rendered.contains(&format!("desc[{spelling}]")), "{rendered}");
        let reparsed = cubit::sass_file::parse_sass_file_str_strict(&rendered).unwrap();
        assert!(matches!(reparsed.kernels[0].instructions[0].operands[0], Operand::Desc { ur_idx, .. } if ur_idx == expected));
    }
}

/// URZ-window decode now emits the parseable canonical spelling (pre-fix
/// "UR255" fell through to no parser form and broke render->parse).
#[test]
fn t160_5_urz_window_render_parses() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let w: u128 = 0x001fe2000c1019ff_000000ff02007986u128;
    let text = dec(&idx, w, &t);
    assert_eq!(text, "STG.E desc[URZ][R2.64], RZ");
    parse_sass(&format!("{text} ;"), 0).expect("URZ render must re-parse");
}

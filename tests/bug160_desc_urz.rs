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
//! PARKED (encode side = parser RE_DESC URZ -> 255): the ONE frozen
//! publish-era line `LDG.E.LTC128B.128 R0, desc[URZ][R60.64+0x2400]
//! !rsd[...]` (front-M artifact, results/cubitfix/049/rt98_v2.sass) encodes
//! through canonical LDG_R_dARI['128,E,LTC128B'] (sub_ur0@[32:40)/8) whose
//! silicon-proven published byte there is 0x3f -- produced under the old
//! inverted law. Re-spelling the frozen glyph (URZ->UR63) or its bytes is a
//! front-M/owner decision (text md5 gates + publish contract). t160_3/t160_4
//! pin the parked contract so the chain stays byte-exact. See 160.md sec.5.

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

/// Re-encode of the new canonical renders reproduces the window byte for
/// every NON-URZ value (UR63 round-trips now; pre-fix it collapsed to URZ /
///  "UR255" unparseable junk). URZ-word re-encode is the parked half.
#[test]
fn t160_2_render_reencode_nonz() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let a1: u128 = 0x001fe2000c101906_000000ff02007986u128;
    let base = a1 & !(0xFFu128 << 64);
    let cases: &[(u128, &str, u64)] = &[
        (a1,                                     "STG.E desc[UR6][R2.64], RZ",  0x06),
        (base | (0x3fu128 << 64),                "STG.E desc[UR63][R2.64], RZ", 0x3F),
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

/// Parked-contract pin: the ONE frozen publish-era line keeps its
/// silicon-proven bytes under BOTH tables in play (sm120 publish table and
/// the tb_i82p3 chain table). The glyph stays `desc[URZ]`; bytes stay 0x3f
/// in the [32:40) window (legacy inverted law) until the owner re-cuts the
/// era text. If this pin breaks, the publish chain changed bytes.
#[test]
fn t160_3_era_contract_frozen() {
    const PIN: &str = "@P5 LDG.E.LTC128B.128 R0, desc[URZ][R60.64+0x2400] !rsd[1:1,2:1,66:1,68:1,76:0,77:1,78:1,79:1,84:0,85:1,90:0]";
    const WORD: u128 = 0x0009e4000820e914_0024003f3c005986u128;
    for path in ["tables/sm120.json"] {
        let t = IsaTable::load(std::path::Path::new(path)).unwrap();
        let insn = parse_sass(&format!("{PIN} ;"), 0).unwrap();
        let enc = encode_instruction(&insn, &t).expect("era line must encode");
        assert_eq!(enc & M96, WORD & M96, "era publish line byte-exact ({path})");
    }
}

/// Documented parked parser state: URZ currently stores 63 encode-side
/// (inverted legacy, see header). UR63 stores 63 too. A future owner-side
/// flip must migrate the era artifact first (t160_3 will catch drift).
#[test]
fn t160_4_parser_parked_state() {
    let d = parse_sass("STG.E desc[URZ][R2.64], RZ ;", 0).unwrap();
    assert!(matches!(d.operands[0], Operand::Desc { ur_idx: 63, .. }),
        "parked: desc[URZ] encode-side value = 63: {:?}", d.operands[0]);
    let d = parse_sass("STG.E desc[UR63][R2.64], RZ ;", 0).unwrap();
    assert!(matches!(d.operands[0], Operand::Desc { ur_idx: 63, .. }),
        "desc[UR63] stays 63: {:?}", d.operands[0]);
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

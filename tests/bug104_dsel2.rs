//! BUG-104-kand (sm103a mercury lane deposit, encode-side dsel2(10,2)):
//! the tcgen05 UTC*MMA families drove payload bits [11:10] wrong when
//! re-encoding vendor text. Machine-check on 2028 corpus anchors
//! (mk296/mk297/mk299/mk300, both arches) gave the family law:
//!   * 7-op enable-UR forms (`..._UR_UP`): [11:10] = kind tag of tok1
//!     (gdesc=1 x ~496 anchors, tmem=2 x2 anchors) -- UTCHMMA row carried
//!     and_base b10=0 (siblings prove 1) and no dsel2 field at all;
//!   * WS variants: same kind-tag law (UTCHMMA.WS 6 anchors, UTCQMMA.WS 2);
//!   * 7-op tmem-tok6 forms (`..._II_II_UP`): [11:10] = CONSTANT per base op
//!     (UTCQMMA=3 x 22 anchors incl. 2CTA, UTCOMMA=1 x 14 anchors 4X);
//!     the mk299 groups shipped a kind-tag field that actively broke encode
//!     (2CTA Mis 17/17);
//!   * process catch: op_lbl_scrape's parse_body read URZ body "Z" as 0
//!     (kind-fixed paths already map URZ -> 0xFF in 8-bit desc slots);
//!   * process catch: UTCQMMA_WS tok2 field pointed at @24 (tok2 overlay);
//!     sibling geometry (UTCHMMA_WS, all 6-op/7-op rows) puts tok2 at @32.
//! After the fix: 2028/2028 anchors payload-clean (residual deltas are the
//! separate 103-kand ctrl_hi dispatch class, bits [127:96], parked).
//!
//! Pins compare payload bits [95:0]; bits [127:96] carry the scheduler
//! default word (0x0fc200 -- vs vendor 0x11d800/0x1f200/... = 103-kand).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(text: &str, t: &IsaTable) -> anyhow::Result<u128> {
    let insn = parse_sass(&format!("{text} ;"), 0).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    encode_instruction(&insn, t)
}

const PAY: u128 = (1u128 << 96) - 1;

fn assert_payload(text: &str, vendor: u128) {
    let t = t103();
    let got = enc(text, &t).unwrap_or_else(|e| panic!("encode failed for {text:?}: {e}"));
    assert_eq!(
        got & PAY,
        vendor & PAY,
        "payload mismatch for {text:?}\n got {got:032x}\n exp {vendor:032x}\n xor {:032x}",
        (got ^ vendor) & PAY
    );
}

fn dec_render(word: u128, t: &IsaTable) -> String {
    let idx = DecodeIndex::build(t);
    let d = idx.decode(word, 0, t).expect("decode");
    cubit::printer::to_sass(&d).trim_end_matches([';', ' ']).to_string()
}

/// 7-op enable-UR UTCHMMA: kind-tag gdesc=1 (b10), unguarded PT guard=7.
#[test]
fn bug104_utchmma_ur_up_gdesc_unguarded() {
    assert_payload(
        "UTCHMMA gdesc[URZ], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], UR8, !UPT",
        0x11d8000f800006000804ffff0075ea,
    );
}

/// Same family guarded @!UP1: guard field (15:12)=9 AND b10=1 both from text.
#[test]
fn bug104_utchmma_ur_up_gdesc_guarded() {
    assert_payload(
        "@!UP1 UTCHMMA gdesc[URZ], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], UR8, !UPT",
        0x0001f2000f800006000804ffff0095ea,
    );
}

/// tmem at tok1 of the enable-UR family: kind tag = 2 AND URZ body maps to
/// 0xFF in the tok2 slot (parse_body URZ alias).
#[test]
fn bug104_utchmma_ur_up_tmem_tok1() {
    assert_payload(
        "@!UP1 UTCHMMA tmem[UR7], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], UR8, !UPT",
        0x1f2000f800006000804ff070099ea,
    );
}

/// UTCQMMA guarded enable-UR (sibling row already carried b10=1; kept true).
#[test]
fn bug104_utcqmma_ur_up_guarded() {
    assert_payload(
        "@!UP1 UTCQMMA gdesc[URZ], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], UR8, !UPT",
        0x1f2000f800306000804ffff0095ea,
    );
}

/// WS variants: kind-tag law (gdesc=1) via added dsel2 field.
#[test]
fn bug104_ws_kind_tag() {
    assert_payload(
        "@!UP1 UTCHMMA.WS gdesc[URZ], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], !UPT",
        0x11d8000f88000600ff04ffff0095ea,
    );
    assert_payload(
        "@!UP1 UTCQMMA.WS gdesc[URZ], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], !UPT",
        0x11d8000f88030600ff04ffff0095ea,
    );
}

/// 7-op tmem-tok6 UTCQMMA: [11:10] = constant 3 (NOT tok1 kind tag 1).
#[test]
fn bug104_utcqmma6iup_family_const() {
    assert_payload(
        "UTCQMMA gdesc[UR6], gdesc[UR8], tmem[UR11], tmem[UR4], idesc[UR5], tmem[UR12], UPT",
        0x11d8000b80030b000c040806007dea,
    );
}

/// CUTLASS anchors: UTCQMMA.2CTA (const 3) and UTCOMMA.4X (const 1).
#[test]
fn bug104_cutlass_2cta_4x() {
    assert_payload(
        "UTCQMMA.2CTA gdesc[UR16], gdesc[UR14], tmem[UR12], tmem[UR64], idesc[UR65], tmem[UR6], UP0",
        0x0005e2000820030c0006400e10007dea,
    );
    assert_payload(
        "UTCOMMA.4X gdesc[UR30], gdesc[UR32], tmem[UR15], tmem[UR28], idesc[UR29], tmem[UR6], UPT",
        0x0003e2000b80000f80061c201e0075ea,
    );
}

/// Decode renders stay vendor-true on the touched rows (anchors above pass
/// through the same rows on the decode path: round-trip text equality).
#[test]
fn bug104_decode_text() {
    let t = t103();
    for (word, text) in [
        (0x11d8000f800006000804ffff0075ea_u128,
         "UTCHMMA gdesc[URZ], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], UR8, !UPT"),
        (0x1f2000f800006000804ff070099ea_u128,
         "@!UP1 UTCHMMA tmem[UR7], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], UR8, !UPT"),
        (0x11d8000f88030600ff04ffff0095ea_u128,
         "@!UP1 UTCQMMA.WS gdesc[URZ], gdesc[URZ], tmem[UR6], tmem[UR4], idesc[UR5], !UPT"),
        (0x0005e2000820030c0006400e10007dea_u128,
         "UTCQMMA.2CTA gdesc[UR16], gdesc[UR14], tmem[UR12], tmem[UR64], idesc[UR65], tmem[UR6], UP0"),
    ] {
        let rt = dec_render(word, &t);
        assert_eq!(rt, text, "decode render drift for {word:032x}");
        // round-trip: encode(render(word)) payload == word payload
        let t2 = t103();
        let got = enc(text, &t2).unwrap();
        assert_eq!(got & PAY, word & PAY, "roundtrip payload drift for {text:?}");
    }
}

/// WS tok2-geometry pin (process catch): tok2 lives at [39:32], not the
/// tok1 shadow @24. No divergent corpus anchors exist (all carry 0xFF in
/// both slots), so pin the geometry decode+re-encode on a synthetic word.
#[test]
fn bug104_ws_tok2_slot() {
    let t = t103();
    let vendor = 0x11d8000f88030600ff04ffff0095ea_u128;
    // @24 <- 0x05 (tok1 UR5), @32 <- 0x09 (tok2 UR9)
    let w = (vendor & !((0xFFu128 << 24) | (0xFFu128 << 32)))
        | (0x05u128 << 24)
        | (0x09u128 << 32);
    let rt = dec_render(w, &t);
    assert!(
        rt.contains("gdesc[UR5], gdesc[UR9]"),
        "tok2 slot not honored in render: {rt}"
    );
    let t2 = t103();
    let got = enc(&rt, &t2).unwrap();
    assert_eq!(got & PAY, w & PAY, "tok2 slot not honored in encode");
}

/// URZ elision (vendor spelling): an enable-UR slot of 0xFF prints the short
/// 6-operand form (cuobjdump-verified on harvest-2049 bi8_hop class, 164
/// words); the elided text re-encodes byte-identically via the 6II row
/// (AND-base carries 0xFF in that slot). Explicit URn!=URZ keeps the token.
#[test]
fn bug104_urz_elision_render() {
    let t = t103();
    // harvest-2049 bi8_hop /*09e0*/ vendor word, cuobjdump-checked
    let w = 0x000fca000f80000400ff100e080075ea_u128;
    let rt = dec_render(w, &t);
    assert_eq!(
        rt,
        "UTCHMMA gdesc[UR8], gdesc[UR14], tmem[UR4], tmem[UR16], idesc[UR17], !UPT"
    );
    let t2 = t103();
    let got = enc(&rt, &t2).unwrap();
    assert_eq!(got & PAY, w & PAY, "elided-form roundtrip drift");
    // explicit slot stays printed
    let w2 = 0x11d8000f800006000804ffff0075ea_u128;
    let t3 = t103();
    let rt2 = dec_render(w2, &t3);
    assert!(rt2.contains("UR8"), "explicit enable-UR dropped: {rt2}");
}

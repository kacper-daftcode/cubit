//! BUG-162 (iter76, loop5/blind front-main; queue item "LDC_R_cAI @38/49/50 +
//! LDCU_UR_cAI @37 window audit" from reports 156.md sec5 / 161.md sec5):
//! const-address carrier windows of the LDC/LDCU/cARI families landed off the
//! vendor geometry. nvdisasm-13.3.73 (V13.3.73) bit-walk arbitration on
//! corpus anchors (work/i76/arb162*.json, census162*.json) proves on sm_103a:
//!   LDC*  (R_cAI + R_cARI, all mod groups): off = s16 @[38:54), bank = u5
//!         @[54:59); bit37 inert; bits [59:64) inert.
//!   LDCU* (UR_cAI, all mod groups incl. UR-indexed form): off = s17 @[37:54),
//!         bank = u5 @[54:59); UR index @[24:32), URZ=255 elided.
//!   Index field @[24:32) with RZ/URZ=0xff sentinel exists HW-side on the
//!   plain cAI rows too (clr24 on a plain anchor renders R254); those words
//!   decode through the cARI rows instead -- rows pin [24:32)=0xff via
//!   and_base, match discipline unchanged.
//! Vendor sign render: plain `c[0x0][-0x10]`, indexed `c[0x0][R3+-0x7d84]`
//! (literal "+-"), UR `c[0x0][UR11+-0xfd60]`.
//! Pre-fix sm103a claims were all LATENT (census: 929,046 cAI + 3,086
//! cARI.64 + 122 cARI anchors, bit-population: off bits <= 49 (LDC) / <= 48
//! (LDCU plain), banks: .64-rows bank4 only, sign bit53 never set; decode
//! parity 929,046/929,046 OK on the old windows because format_const_addr
//! fell back to the single cm16 window whenever no sub_imm(k>=1) existed):
//!   - LDC ''/U8: cm16_off@38/24 + sub_imm0@50/24 -> ENCODE double-write:
//!     bank nibble landed on off bits [50:53] (silently wrong word for any
//!     bank!=0 text; demo work/i76/verify3: `LDC R4, c[0x1][0x20]` encoded
//!     as c[0x0][0x1020]-shape pre-fix)
//!   - LDC U16/S8: cm16_off@38/11 (offset truncated below [38:54)) +
//!     sub_imm0@49/24
//!   - LDCU ''/128: cm16_off@37/12 (12-bit carrier for a 17-bit field ->
//!     encode silently truncated off>=0x1000, bank written at @49 instead of
//!     54) + sub_imm0@49/24
//!   - LDCU U16/S8: cm16_off@37/11 + sub_imm0@48/24
//!   - LDCU.64: sub_imm1@37/24 (17th/sign bit dropped by &0xffff)
//!   - LDC_R_cARI '': sub_imm0@54/2 (2-bit bank window: banks 4..31
//!     misdecode)
//!   - LDC_R_cARI '64': sub_imm2@32/22 (offset at the wrong absolute
//!     position; corpus offsets all 0 => 2929/2929 "ok" vacuously; a real
//!     c[0x4][R16+0x400] word rendered with the offset DROPPED)
//! Fix = data-only window moves (13 rows, tables/sm103a.json via
//! work/i76/patch162.py) to the canonical single carriers
//! cm16_off@38/21 (LDC*) / cm17_off@37/22 (LDCU*) -- donor geometry of the
//! canonical sm120 rows -- plus printer sign-print for the cm-composed
//! offset path (src/printer.rs format_const_addr; off_field/sub_imm-carrier
//! paths untouched). sub_ur1/sub_r1 indices are NOT touched here: parked
//! patch151 (sub_ur1 9->8) and parked patch147 (sub_r1 narrowing) stay
//! replay-disjoint with patch162 (field-surgical edits, machine-checked).
//! Byte-neutrality on the corpus: every corpus word has bank==0 (or bank4
//! covered by @[54:59) on .64 rows), off bits <= 49, sign bit53 == 0; both
//! window sets emit/read identical bits for that shape (battery162 A/B/C
//! + corpus A/B machine-checks).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    let d = idx.decode(w, 0, t).expect("decode");
    let s = cubit::printer::to_sass(&d);
    s.split("/* @sched").next().unwrap().trim().to_string()
}

fn w(hex: &str) -> u128 {
    u128::from_str_radix(hex, 16).unwrap()
}

/// t162_1 (invariant): the 13 patched rows carry the canonical window
/// geometry and nothing else hangs off token 2's address space.
#[test]
fn t162_1_window_polygon() {
    let j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm103a.json").unwrap()).unwrap();
    let mut seen = 0;
    for (key, mg, ext, shift, bits) in [
        ("LDC_R_cAI", "", "cm16_off", 38u64, 21u64),
        ("LDC_R_cAI", "64", "cm16_off", 38, 21),
        ("LDC_R_cAI", "U8", "cm16_off", 38, 21),
        ("LDC_R_cAI", "U16", "cm16_off", 38, 21),
        ("LDC_R_cAI", "S8", "cm16_off", 38, 21),
        ("LDCU_UR_cAI", "", "cm17_off", 37, 22),
        ("LDCU_UR_cAI", "64", "cm17_off", 37, 22),
        ("LDCU_UR_cAI", "128", "cm17_off", 37, 22),
        ("LDCU_UR_cAI", "U8", "cm17_off", 37, 22),
        ("LDCU_UR_cAI", "U16", "cm17_off", 37, 22),
        ("LDCU_UR_cAI", "S8", "cm17_off", 37, 22),
        ("LDC_R_cARI", "", "cm16_off", 38, 21),
        ("LDC_R_cARI", "64", "cm16_off", 38, 21),
    ] {
        seen += 1;
        let row = j
            .pointer(&format!("/instructions/{key}/mod_groups/{mg}"))
            .unwrap_or_else(|| panic!("{key}[{mg}] missing"));
        let fields = row["fields"].as_array().unwrap();
        let car: Vec<_> = fields
            .iter()
            .filter(|f| f["extraction"] == ext)
            .collect();
        assert_eq!(car.len(), 1, "{key}[{mg}] exactly one {ext} carrier");
        assert_eq!(car[0]["shift"].as_u64().unwrap(), shift, "{key}[{mg}] shift");
        assert_eq!(car[0]["bits"].as_u64().unwrap(), bits, "{key}[{mg}] bits");
        assert_eq!(car[0]["token_idx"].as_u64().unwrap(), 2, "{key}[{mg}] tok");
        // no leftover bank-copy field on token 2
        for f in fields {
            let e = f["extraction"].as_str().unwrap();
            if f["token_idx"].as_u64().unwrap() != 2 {
                continue;
            }
            assert_ne!(e, "sub_imm0", "{key}[{mg}] stale bank copy {f:?}");
            assert!(
                !e.starts_with("sub_imm") || e.starts_with("sub_r") || e.starts_with("sub_ur"),
                "{key}[{mg}] unexpected sub-field {f:?}"
            );
        }
    }
    assert_eq!(seen, 13);
    // index fields of the cARI/UR rows survive untouched (151/147 compose)
    let cari = j.pointer("/instructions/LDC_R_cARI/mod_groups//fields").unwrap();
    assert!(cari.as_array().unwrap().iter().any(|f| f["extraction"] == "sub_r1"));
    let ur = j.pointer("/instructions/LDCU_UR_cAI/mod_groups//fields").unwrap();
    let urf: Vec<_> = ur
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["extraction"] == "sub_ur1")
        .collect();
    assert_eq!(urf.len(), 1, "sub_ur1 present exactly once");
    assert_eq!(urf[0]["shift"].as_u64().unwrap(), 24);
    assert!(matches!(urf[0]["bits"].as_u64().unwrap(), 8 | 9),
            "sub_ur1 width untouched by patch162 (8 or 9 both legal here)");
}

/// t162_2: vendor-law probes decode vendor-exact (nvdisasm 13.3.73 render
/// pairs captured in work/i76/verify162.json + verify4/5; every render here
/// was byte-compared against nvdisasm on the same word).
#[test]
fn t162_2_decode_vendor_law() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let ldc = w("000e1800000008000000e600ff147b82"); // LDC R20, c[0x0][0x398]
    let ldcu = w("000e18000800080000006c00ff0477ac"); // LDCU UR4, c[0x0][0x360]
    let cases: &[(u128, &str)] = &[
        (ldc | (1 << 54), "LDC R20, c[0x1][0x398]"),
        (ldc | (0x1f << 54), "LDC R20, c[0x1f][0x398]"),
        (ldc | (1 << 50), "LDC R20, c[0x0][0x1398]"),
        (ldc | (7 << 50), "LDC R20, c[0x0][0x7398]"),
        ((ldc & !(((1u128 << 16) - 1) << 38)) | (0xfff0u128 << 38), "LDC R20, c[0x0][-0x10]"),
        ((ldc & !(((1u128 << 16) - 1) << 38)) | (0xffffu128 << 38), "LDC R20, c[0x0][-0x1]"),
        (ldcu | (1 << 54), "LDCU UR4, c[0x1][0x360]"),
        (ldcu | (1 << 49), "LDCU UR4, c[0x0][0x1360]"),
        ((ldcu & !(((1u128 << 12) - 1) << 37)) | (0x10000u128 << 37), "LDCU UR4, c[0x0][-0x10000]"),
        ((ldcu & !(((1u128 << 12) - 1) << 37)) | (0x1fff0u128 << 37), "LDCU UR4, c[0x0][-0x10]"),
        // LDC_R_cARI::64 -- the class whose offset the old table dropped
        (w("0002a20000000a000100000010027b82") | (0x400u128 << 38), "LDC.64 R2, c[0x4][R16+0x400]"),
        (w("0002a20000000a000100000010027b82") & !(0x1fu128 << 54) | (0x7u128 << 54), "LDC.64 R2, c[0x7][R16]"),
        (w("0002a20000000a000100000010027b82") | (0x1fff0u128 << 38), "LDC.64 R2, c[0x5][R16+-0x10]"),
        // LDC_R_cARI::'' sign form
        (w("000e22000000080000009f0003037b82") | (1u128 << 53), "LDC R3, c[0x0][R3+-0x7d84]"),
    ];
    for (word, expect) in cases {
        let got = dec(&idx, word & !SCHED, &t);
        assert_eq!(&got, expect, "vendor law for {word:032x}");
        assert!(!got.contains("!rsd"), "no residue junk: {got}");
    }
}

/// t162_3: authored encodes hit the vendor windows exactly (bank u5 @[54:59),
/// off s16 @[38:54) / s17 @[37:54)); the pre-fix silent-junk encodes of
/// bank!=0 / off>=0x1000 texts are pinned dead. All expectations byte-checked
/// against nvdisasm renders of the produced words (work/i76/verify2/3).
#[test]
fn t162_3_encode_authored() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let w1 = enc(&t, "LDC R4, c[0x1][0x20]");
    assert_eq!((w1 >> 54) & 0x1f, 1, "bank lands @[54:59)");
    assert_eq!((w1 >> 50) & 0xf, 0, "no junk bank copy on off bits [50:53]");
    assert_eq!((w1 >> 38) & 0xffff, 0x20);
    let w2 = enc(&t, "LDC R4, c[0x1f][0x13ff]");
    assert_eq!((w2 >> 54) & 0x1f, 0x1f);
    assert_eq!((w2 >> 38) & 0xffff, 0x13ff);
    let u1 = enc(&t, "LDCU UR4, c[0x1][0x20]");
    assert_eq!((u1 >> 54) & 0x1f, 1, "LDCU bank @[54:59) via cm17");
    assert_eq!((u1 >> 37) & 0x1ffff, 0x20);
    assert_eq!((u1 >> 49) & 0x1f, 0, "no @49 junk copy");
    let u2 = enc(&t, "LDCU UR4, c[0x0][0x1360]");
    assert_eq!((u2 >> 37) & 0x1ffff, 0x1360, "off>=0x1000 not truncated");
    let n1 = enc(&t, "LDC R3, c[0x0][-0x10]");
    assert_eq!((n1 >> 38) & 0xffff, 0xfff0, "s16 negative offset");
    let n2 = enc(&t, "LDCU.64 UR4, c[0x1][-0x8]");
    assert_eq!((n2 >> 37) & 0x1ffff, 0x1fff8, "s17 negative offset");
    assert_eq!((n2 >> 54) & 0x1f, 1);
    // decode->re-encode fixed points incl. "+-" spelling
    for text in [
        "LDC R4, c[0x1][0x20]",
        "LDC R4, c[0x1f][0x13ff]",
        "LDCU UR4, c[0x0][-0x10]",
        "LDC R3, c[0x0][-0x10]",
        "LDC.64 R2, c[0x4][R16+-0x8000]",
        "LDC R3, c[0x0][R3+-0x7d84]",
    ] {
        let wv = enc(&t, text);
        let d = dec(&idx, wv, &t);
        let re = enc(&t, &d);
        assert_eq!(re, wv, "{text}: fixed point");
    }
}

/// t162_4: real corpus anchors (bug142 hexdb, sm_103a-class words) decode to
/// the canonical renders and re-encode byte-exact in the low 96 bits.
/// These words are the pre==post invariant points of the corpus.
#[test]
fn t162_4_corpus_anchors_fixedpoint() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let anchors: &[(u128, &str)] = &[
        (w("000e1800000008000000e600ff147b82"), "LDC R20, c[0x0][0x398]"),
        (w("000e6c00080008000000ae00ff0477ac"), "LDCU UR4, c[0x0][0x570]"),
        (w("000e180000000a000000e000ff100b82"), "@P0 LDC.64 R16, c[0x0][0x380]"),
        (w("0002a20000000a000100000010027b82"), "LDC.64 R2, c[0x4][R16]"),
        (w("000e22000000080000009f0003037b82"), "LDC R3, c[0x0][R3+0x27c]"),
    ];
    for (word, expect) in anchors {
        let d = dec(&idx, word & !SCHED, &t);
        assert_eq!(&d, expect, "corpus anchor render");
        let re = enc(&t, &d);
        assert_eq!(re, word & !SCHED, "anchor re-encode byte-exact: {expect}");
    }
}

/// t162_5: bit37 is print-inert for LDC rows at the vendor (nvdisasm
/// renders a bit37-set LDC word identically -- arbitration set37 effect
/// lists) but stays a match-fixed-0 position in our tables, pre==post
/// (decode of a bit37-set word fails closed, loudly, instead of silently
/// guessing). LDCU rows read bit37 as offset bit0 instead -- the 37-vs-38
/// shift difference between the families is real.
#[test]
fn t162_5_bit37_semantics() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let ldc = w("000e1800000008000000e600ff147b82");
    assert!(
        idx.decode((ldc | (1u128 << 37)) & !SCHED, 0, &t).is_err(),
        "bit37-set LDC word must remain fail-closed (strict match, pre==post)"
    );
    let without = dec(&idx, ldc & !SCHED, &t);
    assert_eq!(without, "LDC R20, c[0x0][0x398]");
    let ldcu = w("000e18000800080000006c00ff0477ac");
    let u37 = dec(&idx, (ldcu | (1u128 << 37)) & !SCHED, &t);
    assert_eq!(u37, "LDCU UR4, c[0x0][0x361]", "LDCU bit37 = offset bit0");
}

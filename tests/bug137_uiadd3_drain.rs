//! BUG-137 pins (era-table repair tb_i82p3 mod-group `""` of
//! `UIADD3_UR_UP_UP_UR_UR_UR`; the fix itself lives in the era table
//! artifact, this suite pins the same encoding on the shipped repo tables):
//!
//! The synthesized backward-branch drain (asm ctrl-fixup pass; the
//! instruction never appears in authored text) is
//! `UIADD3 URZ, UPT, UPT, URZ, URZ, URZ` — a verbatim vendor idiom ptxas
//! emits at loop back-edges to carry a barrier wait mask. The era table
//! could not encode it: the harvested `""` row saw only all-URZ
//! observations, so the suffix windows were baked into `and_base` with no
//! field for operand 6, and the BUG-071 zero-payload-junk guard (sibling
//! proven by the `X` row) rejected the whole key — `asm` refused to write
//! the cubin (1 of 5666 failed).
//!
//! Evidence anchors:
//!   * Vendor word (payload bits <105) from the 2014-cubin corpus
//!     (cusparse/libcusparse.so.899.sm_103.cubin slot 0x68d0; nvdisasm 13.3
//!     renders `@!UPT UIADD3 URZ, UPT, UPT, URZ, URZ, URZ`).
//!   * nvdisasm 13.3 arbitration graft: cubit-assembled cubin of the
//!     authored probes below renders byte-exact the authored text
//!     (operand fields incl. UP-dest selects, tok6 ureg, neg).

use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text} ;"), 0)
        .map_err(|e| anyhow::anyhow!("parse: {e}"))
        .unwrap();
    encode_instruction(&insn, t).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> String {
    t.decode_index()
        .decode(w, 0, t)
        .map(|d| cubit::printer::to_sass(&d))
        .expect("decode")
}

/// Scheduling/control is embedded by the asm pipeline at hi[41..58) (abs
/// [105..122)); the encoder API returns its own default there. Pins compare
/// payload + proven constant zone only.
const W_VENDOR: u128 = 0x000fe4000fffe0ff000000fffffff290; // @!UPT drain idiom
const KEEP: u128 = (1u128 << 105) - 1;

#[test]
fn t137_1_drain_idiom_byte_exact_vendor() {
    for t in [t103a(), t120()] {
        let w = enc(&t, "@!UPT UIADD3 URZ, UPT, UPT, URZ, URZ, URZ");
        assert_eq!(w & KEEP, W_VENDOR & KEEP, "drain idiom != vendor word");
        // decode of the all-URZ vendor word is a known decode-priority
        // artefact on the shipped tables (an _R_II_P row wins the match);
        // tracked as a follow-up candidate, out of BUG-137's scope.
    }
}

#[test]
fn t137_2_drain_plain_guard_stable() {
    // asm's synthesized drain carries guard:None -> PT encoding (0x7);
    // the vendor corpus rides the @!UPT (predicated-off) form.
    for t in [t103a(), t120()] {
        let w = enc(&t, "UIADD3 URZ, UPT, UPT, URZ, URZ, URZ");
        assert_eq!(
            w & KEEP,
            ((W_VENDOR & !(0xfu128 << 12)) | (0x7u128 << 12)) & KEEP,
            "plain drain guard encoding drifted"
        );
    }
}

#[test]
fn t137_3_authored_suffix_fields_roundtrip() {
    // Non-URZ suffix operands must ride real fields: tok2/tok3 UP-dest
    // selects, tok6 ureg + neg. (nvdisasm-arbitrated on a cubit-assembled
    // cubin; the decode side of the URZ-suffix variant is a known
    // decode-priority artefact, out of this bug's scope.)
    // sm120.json has no tok6 ureg field (33-record harvest): UR7 in the
    // suffix fails closed there — only sm103a covers the full pin set.
    let t103 = t103a();
    for c in [
        "UIADD3 UR4, UPT, UPT, UR5, UR6, UR7",
        "UIADD3 URZ, UPT, UPT, URZ, -URZ, URZ",
        "@UP2 UIADD3 UR10, UP0, UP1, -UR11, UR12, UR13",
    ] {
        let w = enc(&t103, c);
        let s = dec(&t103, w);
        assert_eq!(s.split(" /*").next().unwrap(), c, "roundtrip mismatch");
    }
}

/// sm120.json (33-record harvest) has no tok6 ureg field: authored forms
/// with a non-URZ suffix fail closed instead of silently baking URZ bits.
#[test]
fn t137_5_sm120_nonsuffix_field_absent_fails_closed() {
    let t = t120();
    let insn = parse_sass("UIADD3 UR4, UPT, UPT, UR5, UR6, UR7 ;", 0).unwrap();
    let e = encode_instruction(&insn, &t)
        .expect_err("sm120 has no field for a non-URZ operand 6 — must fail closed");
    assert!(format!("{e}").contains("UR7"), "error names the operand: {e}");
}

#[test]
fn t137_4_guard_and_neg_select_bits() {
    let t = t103a();
    let w = enc(&t, "@UP0 UIADD3 URZ, UPT, UPT, URZ, URZ, URZ");
    assert_eq!((w >> 12) & 0xf, 0x0, "guard @UP0");
    let w = enc(&t, "@!UP3 UIADD3 URZ, UPT, UPT, URZ, URZ, URZ");
    assert_eq!((w >> 12) & 0xf, 0xb, "guard @!UP3");
    let w = enc(&t, "UIADD3 UR4, UPT, UPT, UR5, UR6, -UR7");
    assert_ne!(w & (1u128 << 75), 0, "tok6 neg bit");
    assert!(dec(&t, w).contains("-UR7"));
}

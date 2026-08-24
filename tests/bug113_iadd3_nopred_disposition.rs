//! BUG-113 DISPOSITION: NOT-A-BUG (triage of PLAN_S0 / S0a i227 question:
//! "brak klucza IADD3 bez-predykatowego — swiadomy model krzemu czy dziura
//! tabeli?").
//!
//! Answer, data-anchored: IADD3 architecturally ALWAYS carries the two
//! carry-predicate operand columns (Rd, Pout, Pin, a, b, c). Vendor
//! nvdisasm 13.3 (sm_103 cubin ts2_s2cw6a) renders 0 plain 4-operand forms;
//! the silicon-certified rt98_v2 corpus has 296x IADD3 with 6 operand
//! tokens and 1x IADD3.X 9-token — zero plain forms. Cubit HEAD behaviour
//! on the plain form is loud fail-closed: rc=1, no output file, per-slot
//! attempted-keys diagnostics (BUG-043/e758f17 doctrine). So: vendor text
//! parity + fail-closed = no table hole, no tooling trap. Pins below fence
//! both halves.

use cubit::encoder::encode_instruction;
use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule};
use cubit::table::IsaTable;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn pipeline_words(src: &str, tab: &IsaTable) -> Vec<(String, u128)> {
    let f = parse_sass_file_str_strict(src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    schedule(&mut insns, Some(tab));
    reallocate_barriers(&mut insns, Some(tab));
    insns
        .iter()
        .map(|x| {
            let w = encode_instruction(x, tab)
                .unwrap_or_else(|e| panic!("encode failed for {}: {:?}", x.opcode_full, e));
            (x.opcode_full.clone(), w)
        })
        .collect()
}

/// t113_1: plain 4-operand IADD3 (no carry-predicate columns) must stay
/// fail-closed at the library level: encode_instruction returns Err with a
/// "no operand-compatible table entry" diagnostic on BOTH tables (imm and
/// reg addend variants, plus a malformed .X width).
#[test]
fn t113_1_plain_iadd3_rejected_fail_closed() {
    for src in [
        ".entry t\n    .param u64 io\n    IADD3 R8, R0, 0x5a5a, RZ ;\n    EXIT ;\n",
        ".entry t\n    .param u64 io\n    IADD3 R8, R0, R9, RZ ;\n    EXIT ;\n",
        ".entry t\n    .param u64 io\n    IADD3.X R8, R0, 0x5a5a, RZ, P0, PT ;\n    EXIT ;\n",
    ] {
        for tab in [t103(), t120()] {
            let f = parse_sass_file_str_strict(src).unwrap();
            let mut insns = f.kernels[0].instructions.clone();
            schedule(&mut insns, Some(&tab));
            reallocate_barriers(&mut insns, Some(&tab));
            let err = encode_instruction(&insns[0], &tab)
                .expect_err("plain IADD3 must be rejected, not silently encoded");
            let msg = format!("{:?}", err);
            assert!(
                msg.contains("no operand-compatible table entry"),
                "expected attempted-keys diagnostic, got: {msg}"
            );
        }
    }
}

/// t113_2: vendor-canonical 2-predicate form encodes to the nvdisasm-
/// roundtripped anchor word on sm103a (vendor nvdisasm 13.3 renders the
/// encoded cubin verbatim: `IADD3 R8, PT, PT, R0, 0x5a5a, RZ`).
#[test]
fn t113_2_two_pred_vendor_anchor_word_sm103a() {
    let src =
        ".entry t\n    .param u64 io\n    IADD3 R8, PT, PT, R0, 0x5a5a, RZ ;\n    EXIT ;\n";
    let w = pipeline_words(src, &t103());
    assert_eq!(w[0].0, "IADD3");
    assert_eq!(
        w[0].1,
        0x000fca0007ffe0ff_00005a5a00087810u128,
        "vendor-anchored IADD3 PT,PT word regressed"
    );
}

/// t113_3: same canonical forms encode on the sm120 table (cross-arch text
/// parity; the claim originated on the sm120 side pinned to stale bin
/// 5b2a7474 where the plain form was attempted).
#[test]
fn t113_3_two_pred_encodes_sm120() {
    let src = ".entry t\n    .param u64 io\n    IADD3 R8, PT, PT, R0, 0x5a5a, RZ ;\n    IADD3 R49, P6, PT, RZ, RZ, RZ ;\n    EXIT ;\n";
    for tab in [t103(), t120()] {
        let w = pipeline_words(src, &tab);
        assert_eq!(w.len(), 3);
        assert_eq!(w[0].0, "IADD3");
        assert_eq!(w[1].0, "IADD3");
    }
}

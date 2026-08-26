//! BUG-145 (F2 lane, follow-up of note-143 "tb/sm120 POPC.URZ render"):
//! POPC.32 URZ-tied ATOMS forms on tables/sm120.json (repo-side half; the
//! tb_i82p3 half is a results artifact proven script-level, work/bug145).
//!
//! Pre-fix state (all machine-observed on c9ef102 + epoch142 tb):
//!   * sm120: no POPC rows at all -> fail-closed __raw__ on decode of all
//!     128 unique vendor anchor words, fail-closed on encode of the 10
//!     vendor spellings (encode battery sm120: POPC 10/10 in fails_final).
//!   * tb_i82p3: zombie key ATOMS_R_dARI whose masks are byte-identical to
//!     ATOMS_R_ARURI's claimed every POPC.URZ word via the desc-slot
//!     consistency bonus and rendered `desc[UR255][Rn.64]` where nvdisasm
//!     prints `[Rn+URZ]` (127 anchors) / `[RZ+UR4+off]` (1 anchor).
//!
//! Fix:
//!   * sm120: add ATOMS_R_ARURI + ATOMS_R_AURI keys ('32,INC,POPC') built
//!     from the sm_120a anchor 0x000fe8000d800004'00000c00ffff7f8c with
//!     sm120 sibling geometry (dest@[16,24), UR slot [64,72)); the whole
//!     128-word POPC.32 family shares identical [0,96) constants outside
//!     field windows (machine-verified), so one strict row serves all.
//!   * printer: the shared-atom bracket arm (verbatim port of the BUG-143
//!     hook a6049c1 -> ATOMS+ARURI prints [R+UR+off], 0xFF = URZ sink).
//! Modifier spelling: nvdisasm prints "ATOMS.POPC.INC.32", cubit sorts mod
//! tokens ("ATOMS.INC.POPC.32") - documented print dialect, same class as
//! BUG-143 t143_2 (compare modifier sets when crossing to vendor text).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn enc_err(t: &IsaTable, text: &str) -> bool {
    let insn = match parse_sass(text, 0) { Ok(x) => x, Err(_) => return true };
    encode_instruction(&insn, t).is_err()
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

fn w(lo: u64, hi: u64) -> u128 { lo as u128 | ((hi as u128) << 64) }

#[test]
fn t145_1_sm120_auri_anchor_decode() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    // lone sm_120a anchor (nvdisasm: "ATOMS.POPC.INC.32 RZ, [UR4+0xc]")
    let word = w(0x00000c00ffff7f8c, 0x000fe8000d800004);
    let d = dec(&t, &idx, word);
    assert!(d.contains("+UR4+0xc"), "UR must survive decode, got: {d}");
    assert!(!d.contains("!rsd"), "residual-marker junk render is gone, got: {d}");
    assert!(!d.contains("desc["), "no descriptor-world spelling for shared atoms, got: {d}");
}

#[test]
fn t145_2_sm120_urz_bracket_decodes_vendor_shape() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    // 3 of the 127 URZ-sentinel anchors (0xFF@[64:72)); [0,96) constants
    // outside field windows are identical across the whole family.
    let cases = [
        ("ATOMS.INC.POPC.32 RZ, [R11+URZ]",
         w(0x000000000bff7f8c, 0x0003e2000d8000ff)),
        ("ATOMS.INC.POPC.32 RZ, [R0+URZ+0x121c]",
         w(0x00121c0000ff7f8c, 0x0001e4000d8000ff)),
        ("ATOMS.INC.POPC.32 RZ, [R2+URZ+0x1a3c]",
         w(0x001a3c0002ff7f8c, 0x0005e4000d8000ff)),
    ];
    for (text, word) in cases {
        let d = dec(&t, &idx, word);
        assert_eq!(d, text, "URZ-sentinel render must be vendor-shaped");
        assert!(!d.contains("desc["), "no desc[UR255] junk, got: {d}");
    }
}

#[test]
fn t145_3_sm120_encode_byte_exact_vs_vendor() {
    let t = t120();
    let cases = [
        ("ATOMS.POPC.INC.32 RZ, [R2+URZ]",
         w(0x0000000002ff7f8c, 0x0003e2000d8000ff)),
        ("ATOMS.POPC.INC.32 RZ, [R0+URZ+0x121c]",
         w(0x00121c0000ff7f8c, 0x0001e4000d8000ff)),
        ("ATOMS.POPC.INC.32 RZ, [UR4+0xc]",
         w(0x00000c00ffff7f8c, 0x000fe8000d800004)),
    ];
    for (text, word) in cases {
        assert_eq!(enc(&t, text), word & !SCHED, "encode payload must equal vendor word");
    }
    // short spelling (absent UR) carries the same 0xFF URZ sentinel
    let full = enc(&t, "ATOMS.POPC.INC.32 RZ, [R0+URZ+0x44]");
    let short = enc(&t, "ATOMS.POPC.INC.32 RZ, [R0+0x44]");
    assert_eq!(full, short, "both spellings carry 0xFF in the UR window");
    // roundtrip stability of the renderer
    let idx = DecodeIndex::build(&t);
    let back = dec(&t, &idx, full);
    assert!(back.contains("+URZ+"), "render must carry the URZ token, got: {back}");
}

#[test]
fn t145_4_sm120_graft_negatives_fail_closed() {
    let t = t120();
    // nonsense register window must not squeeze through vm=0 rows
    assert!(enc_err(&t, "ATOMS.POPC.INC.32 RZ, [R900+URZ]"), "graft must fail-closed");
    // the vendor corpus has no descriptor-form POPC on shared atomics;
    // keep it refused (documented dialect, no silent re-target)
    assert!(enc_err(&t, "ATOMS.INC.POPC.32 RZ, desc[UR255][R2.64]"),
            "desc-form POPC must stay fail-closed on sm120");
}

#[test]
fn t145_5_sm120_coverage_boundary_stable() {
    // the new strict 2-token POPC rows must not leak into neighbors:
    // (a) 3-token dataR shared ATOMS (no sm120 row by design, vendor-observed
    //     fail-closed in the battery on both sides) stays refused;
    let t = t120();
    assert!(enc_err(&t, "ATOMS.XOR RZ, [UR5+0x10], R6"),
            "3-token ATOMS must stay fail-closed on sm120");
    // (b) a mod-zone graft one nibble off the POPC constant must not claim
    //     (vm=0 strict row, matcher-checked over the whole hexdb).
    let idx = DecodeIndex::build(&t);
    let graft = w(0x00121c0000ff7f8c, 0x0001e4000d8c00ff);
    assert!(idx.decode(graft, 0, &t).is_err(), "mod-zone graft must not claim");
}

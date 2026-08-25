//! BUG-138 pins (drain addr_map remap now reaches single-token absolute
//! `BRXU 0xT` / `BRX 0xT` immediates, not just `Operand::BranchTarget`).
//!
//! The asm post-scheduling pass inserts a drain (`UIADD3 URZ, UPT, UPT,
//! URZ, URZ, URZ`) before a backward branch whose wait_mask is non-zero
//! and then remaps branch targets through addr_map. Before BUG-138 the
//! remap rewrote `BranchTarget` (label-resolved) operands and `BRA/BSSY`
//! immediates only. A single-token numeric `BRXU 0xT` parses to `Imm32`
//! at opcode `BRXU` and was skipped: after a +16B drain shift the branch
//! kept pointing one slot too low (observed on the certified R0b mulmod
//! window: two `BRXU 0xc850` emitted targets for slot -0x10, mid-sequence;
//! silicon would jump into the previous instruction's shadow).
//!
//! Fix signature mirrors the encoder's BUG-027 path: `operands.len()==1`
//! at opcode BRX/BRXU means the immediate is an absolute code address; the
//! two-operand dispatch-table form `BRXU.U URn, imm` carries a raw byte
//! offset that is NOT an address and must stay untouched.
//!
//! Pins below assemble tiny .entry kernels with an authored
//! `[B0-----:...]` control word on a backward BRA (wait_mask bit 0 forces
//! the drain) and assert the rendered branch targets after disassembly.

use std::process::Command;

fn run(table: &str, sass: &str, tag: &str) -> (String, bool) {
    let dir = std::env::temp_dir().join(format!("bug138_{tag}_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("k.sass");
    let out = dir.join("k.cubin");
    let _ = std::fs::remove_file(&out);
    std::fs::write(&src, sass).unwrap();
    let asm = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["asm", "-t", table, src.to_str().unwrap(), "-o", out.to_str().unwrap()])
        .env("CUBIT_MERC13", "0")
        .output().unwrap();
    assert!(asm.status.success(), "asm failed: {}{}",
            String::from_utf8_lossy(&asm.stdout),
            String::from_utf8_lossy(&asm.stderr));
    let dis = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args(["disassemble", "-t", table, out.to_str().unwrap()])
        .env("CUBIT_MERC13", "0")
        .output().unwrap();
    (String::from_utf8_lossy(&dis.stdout).into_owned(), dis.status.success())
}

/// Rendered branch targets of a given opcode, in program order.
fn targets<'a>(dis: &'a str, op: &str) -> Vec<&'a str> {
    dis.lines()
        .filter(|l| l.contains(op))
        .filter_map(|l| {
            let before_comment = l.split(';').next()?;
            let parts: Vec<&str> = before_comment.split_whitespace().collect();
            let pos = parts.iter().position(|p| *p == op)?;
            parts.get(pos + 1).map(|s| s.trim_end_matches(','))
        })
        .collect()
}

const T103A: &str = "tables/sm103a.json";

/// Single drain, label vs numeric single-token BRXU to the same
/// instruction past the shift. Layout (old -> new after +16B at 0x10):
///   0x00 IMAD top            -> 0x00
///   0x10 [W0] BRA top        -> drain@0x10, BRA@0x20
///   0x20 IMAD tgt            -> 0x30
///   0x30 BRXU tgt (label)    -> 0x40
///   0x40 BRXU 0x20 (numeric) -> 0x50
///   0x50 EXIT                -> 0x60
const S_LABEL_PARITY: &str = "\
.entry k
    .reg R0-R9
    .param u64 pp
top:
    IMAD.MOV.U32 R0, RZ, RZ, 0x1 ;
    [B0-----:R-:W-:-:S01] BRA top ;
tgt:
    IMAD.MOV.U32 R1, RZ, RZ, 0x2 ;
    BRXU tgt ;
    BRXU 0x20 ;
    EXIT ;
.endentry
";

/// Two backward branches with wait masks -> two drains (+0x20 cumulative
/// shift beyond the second). Layout (old -> new):
///   0x10 [W0] BRA top   -> drain@0x10, BRA@0x20 (target 0x0, identity)
///   0x40 [W0] BRA 0x20  -> drain@0x50, BRA@0x60 (target remap 0x20->0x30)
///   0x50 IMAD           -> 0x70
///   0x60 BRXU 0x50      -> 0x80 (target remap 0x50->0x70)
const S_TWO_DRAINS: &str = "\
.entry k
    .reg R0-R9
    .param u64 pp
top:
    IMAD.MOV.U32 R0, RZ, RZ, 0x1 ;
    [B0-----:R-:W-:-:S01] BRA top ;
    IMAD.MOV.U32 R1, RZ, RZ, 0x2 ;
    IMAD.MOV.U32 R2, RZ, RZ, 0x3 ;
    [B0-----:R-:W-:-:S01] BRA 0x20 ;
    IMAD.MOV.U32 R3, RZ, RZ, 0x4 ;
    BRXU 0x50 ;
    EXIT ;
.endentry
";

/// Backward target (before the drain slot) must stay put; unmapped /
/// unaligned literals pass through unchanged.
const S_MISC: &str = "\
.entry k
    .reg R0-R9
    .param u64 pp
top:
    IMAD.MOV.U32 R0, RZ, RZ, 0x1 ;
    [B0-----:R-:W-:-:S01] BRA top ;
    IMAD.MOV.U32 R1, RZ, RZ, 0x2 ;
    BRXU 0x0 ;
    BRXU 0x24 ;
    EXIT ;
.endentry
";

/// No wait mask on the backward branch -> no drain, no addr_map: every
/// target stays at its authored address.
const S_NO_DRAIN: &str = "\
.entry k
    .reg R0-R9
    .param u64 pp
top:
    IMAD.MOV.U32 R0, RZ, RZ, 0x1 ;
    [B------:R-:W-:-:S01] BRA top ;
    IMAD.MOV.U32 R1, RZ, RZ, 0x2 ;
    BRXU 0x20 ;
    EXIT ;
.endentry
";

#[test]
fn t138_1_abs_imm_follows_drain_shift() {
    let (dis, ok) = run(T103A, S_LABEL_PARITY, "t1");
    assert!(ok);
    // The numeric single-token form used to keep 0x20 (pre-fix bug: that
    // slot is the backward BRA itself after the drain swap-in).
    assert_eq!(targets(&dis, "BRXU"), vec!["0x30", "0x30"], "{dis}");
}

#[test]
fn t138_2_label_and_numeric_forms_agree() {
    // Same kernel as t138_1, asserted semantically: label-resolve
    // (BranchTarget remap, pre-existing) and numeric (Imm32 remap, BUG-138)
    // must land on the SAME final address, which is the shifted IMAD after
    // the drain, not the BRA.
    let (dis, ok) = run(T103A, S_LABEL_PARITY, "t2");
    assert!(ok);
    let ts = targets(&dis, "BRXU");
    assert!(ts.len() == 2 && ts[0] == ts[1], "label/numeric divergence: {dis}");
    assert!(dis.contains("BRA 0x0"), "loop head must stay put: {dis}");
    assert!(dis.contains("UIADD3 URZ, UPT, UPT, URZ, URZ, URZ"),
            "drain idiom must be present: {dis}");
}

#[test]
fn t138_3_two_drains_cumulative_shift() {
    let (dis, ok) = run(T103A, S_TWO_DRAINS, "t3");
    assert!(ok);
    assert_eq!(targets(&dis, "BRXU"), vec!["0x70"], "{dis}");
    // Second branch carried a numeric BRA immediate that must also track
    // the first drain (pre-existing BRA path, asserted so the two classes
    // cannot drift apart again).
    assert_eq!(targets(&dis, "BRA"), vec!["0x0", "0x30"], "{dis}");
    assert_eq!(dis.matches("UIADD3 URZ, UPT, UPT, URZ, URZ, URZ").count(), 2,
               "expected two drains: {dis}");
}

#[test]
fn t138_4_backward_and_unmapped_targets_passthrough() {
    let (dis, ok) = run(T103A, S_MISC, "t4");
    assert!(ok);
    // 0x0 predates the drain slot (identity in addr_map); 0x24 is not an
    // instruction start (not a key) and must pass through verbatim.
    assert_eq!(targets(&dis, "BRXU"), vec!["0x0", "0x24"], "{dis}");
}

#[test]
fn t138_5_no_drain_no_remap() {
    let (dis, ok) = run(T103A, S_NO_DRAIN, "t5");
    assert!(ok);
    assert!(!dis.contains("UIADD3 URZ, UPT, UPT, URZ, URZ, URZ"), "{dis}");
    assert_eq!(targets(&dis, "BRXU"), vec!["0x20"], "{dis}");
    assert!(dis.contains("BRA 0x0"), "{dis}");
}

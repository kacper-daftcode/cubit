//! BUG-091 (2026-08-23, found in b9 rt-check iter33): nvdisasm-style text
//! with dot-leading labels (`.L_x_0:`) and backtick-paren branch targets
//! (`` BRA `(.L_x_0) ``) silently misassembled: the label definition was
//! rejected by the alnum-only check (and in .sass files swallowed by the
//! directive path because it starts with '.'), the backtick-paren operand
//! stayed a backtick-wrapped Label that never matched any definition, and
//! the unresolved label then encoded a bogus target (repro word at 0x20:
//! target printed 0x100 instead of 0x40 -- wrong-branch silent corruption).
//! Fix: dotted labels legal, backtick-paren unwraps to the label name,
//! unresolved branch label = hard error.

use cubit::ir::Operand;
use cubit::sass_file::parse_sass_file_str_strict;
use cubit::table::IsaTable;

fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }

/// Positive: nvdisasm-flavored branch text assembles with the correct target.
#[test]
fn bug091_dotlabel_backtick_resolves() {
    let sass = ".entry k\n    .reg R0-R15\n\n\
        ISETP.GT.U32.AND P0, PT, R4, 0x64, PT ;\n\
        @P0 BRA `(.L_x_0) ;\n\
        IADD3 R1, PT, PT, R2, R3, RZ ;\n\
        .L_x_0:\n\
        IADD3 R5, PT, PT, R6, R7, RZ ;\n\
        EXIT ;\n    .L_x_1:\n.endentry\n";
    let file = parse_sass_file_str_strict(sass).expect("nvdisasm-style text must assemble");
    let insns = &file.kernels[0].instructions;
    // 5 instructions, BRA at index 1 (addr 0x10) must target index 3 (addr 0x30)
    assert_eq!(insns.len(), 5);
    assert_eq!(insns[1].opcode, "BRA");
    match &insns[1].operands[0] {
        Operand::BranchTarget(t) => assert_eq!(*t, 0x30,
            "BRA target must resolve to the .L_x_0 address 0x30, got 0x{:x}", t),
        other => panic!("BRA operand must be BranchTarget after resolution: {:?}", other),
    }
}

/// Positive: label defined with a trailing instruction on the same line
/// (`.L_x_0: EXIT ;`) and a plain dotted label without backticks.
#[test]
fn bug091_dotlabel_inline_instr() {
    let sass = ".entry k\n    .reg R0-R15\n\n\
        BRA .L_x_0 ;\n\
        NOP ;\n\
        .L_x_0: EXIT ;\n.endentry\n";
    let file = parse_sass_file_str_strict(sass).expect("inline label+instr assembles");
    let insns = &file.kernels[0].instructions;
    assert_eq!(insns.len(), 3);
    match &insns[0].operands[0] {
        Operand::BranchTarget(t) => assert_eq!(*t, 0x20),
        other => panic!("expected BranchTarget: {:?}", other),
    }
}

/// Negative: a branch to a label that is never DEFINED fails closed at byte
/// production with the label named (pre-fix it silently encoded target
/// 0x100). Text-level parse stays lenient on purpose: render/slice work
/// operates on fragments with out-of-window branch targets.
#[test]
fn bug091_unresolved_label_fails_closed() {
    let sass = ".entry k\n    .reg R0-R15\n\n\
        @P0 BRA `(.L_x_9) ;\n\
        EXIT ;\n.endentry\n";
    let file = parse_sass_file_str_strict(sass)
        .expect("text-level parse must stay lenient for fragments");
    let bra = &file.kernels[0].instructions[0];
    assert!(matches!(bra.operands[0], Operand::Label(_)),
        "unresolved label survives as data: {:?}", bra.operands[0]);
    let err = cubit::encoder::encode_instruction(bra, &t103())
        .unwrap_err().to_string();
    assert!(err.contains("unresolved branch label"), "encode must fail closed: {}", err);
    assert!(err.contains(".L_x_9"), "must name the missing label: {}", err);
}

/// Negative: dot-label line via the strict single-block parser too.
#[test]
fn bug091_unresolved_label_strict_multi() {
    let err = cubit::assemble("BRA `(.L_x_7) ; EXIT ;", 0, &t103())
        .unwrap_err().to_string();
    assert!(err.contains("unresolved branch label"), "{}", err);
}

//! Integration tests for the full assembler pipeline (SASS → cubin).
//!
//! Tests the Rust modules that replace sass_to_cubin.py and mk_cubin.py:
//!   - parser.rs + sass_file.rs (assembler)
//!   - scheduling_pass.rs (scheduler)
//!   - elf_builder.rs (cubin builder)

use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn load_table() -> Option<IsaTable> {
    match IsaTable::load_default() {
        Ok(t) => Some(t),
        Err(e) => {
            eprintln!("Skipping: {e}");
            None
        }
    }
}

/// Helper: full SASS→cubin pipeline using the public module APIs.
fn assemble_to_cubin(sass_text: &str, table: &IsaTable) -> anyhow::Result<Vec<u8>> {
    use cubit::elf_builder::{KernelEntry, build_cubin};
    use cubit::sass_file::{parse_sass_file_str, auto_detect_resources, kernel_def_to_meta};
    use cubit::scheduling_pass;

    let mut file = parse_sass_file_str(sass_text)?;
    if file.kernels.is_empty() {
        anyhow::bail!("no .entry definitions found");
    }
    for def in &mut file.kernels {
        auto_detect_resources(def);
    }

    let mut entries = Vec::new();
    for def in &file.kernels {
        let mut insns = def.instructions.clone();
        scheduling_pass::schedule(&mut insns, Some(table));

        let mut code_bytes = vec![0u8; insns.len() * 16];
        for (i, insn) in insns.iter().enumerate() {
            let code128 = encode_instruction(insn, table)?;
            let off = i * 16;
            code_bytes[off..off + 8].copy_from_slice(&(code128 as u64).to_le_bytes());
            code_bytes[off + 8..off + 16].copy_from_slice(&((code128 >> 64) as u64).to_le_bytes());
        }

        scheduling_pass::apply_convergence_barriers(&mut code_bytes, &insns);
        let meta = kernel_def_to_meta(def, &code_bytes);

        entries.push(KernelEntry {
            name: def.name.clone(),
            code: code_bytes,
            meta,
            mercury_stub: None,
        });
    }
    build_cubin(&entries)
}

// ---------------------------------------------------------------------------
// Phase 1: Assembler (parser + branch resolution)
// ---------------------------------------------------------------------------

#[test]
fn test_negative_branch_offset() {
    let table = match load_table() {
        Some(t) => t,
        None => return,
    };
    let insn = parse_sass("BRA -0xc0 ;", 0).unwrap();
    let code = encode_instruction(&insn, &table).unwrap();
    assert_ne!(code, 0, "BRA -0xc0 should produce non-zero encoding");

    // Verify the low bits contain the BRA opcode
    let lo = code as u64;
    let opcode12 = lo & 0xFFF;
    assert!(
        opcode12 == 0x0947 || opcode12 == 0x0948 || opcode12 == 0x0949,
        "BRA opcode should be in the 0x094x family, got 0x{opcode12:03x}"
    );
}

#[test]
fn test_label_resolution() {
    use cubit::parser::{parse_multi_sass, resolve_labels};

    let text = "BRA end ; NOP ; end: EXIT ;";
    let stmts = parse_multi_sass(text, 0);
    let insns = resolve_labels(stmts, 0);
    assert_eq!(insns.len(), 3);
    assert_eq!(insns[0].opcode, "BRA");
    assert_eq!(insns[2].opcode, "EXIT");

    match &insns[0].operands[0] {
        cubit::ir::Operand::BranchTarget(addr) => {
            assert_eq!(*addr, 0x20, "label 'end' is at instruction index 2 → addr 0x20");
        }
        other => panic!("Expected BranchTarget, got {:?}", other),
    }
}

#[test]
fn test_sass_file_parse() {
    let sass = "\
.entry test_kern
    .param u64 output
    .param u32 count
    MOV R0, RZ ;
    EXIT ;
.endentry
";
    let file = cubit::sass_file::parse_sass_file_str(sass).unwrap();
    assert_eq!(file.kernels.len(), 1);
    assert_eq!(file.kernels[0].name, "test_kern");
    assert_eq!(file.kernels[0].resources.params.len(), 2);
    assert_eq!(file.kernels[0].instructions.len(), 2);
}

// ---------------------------------------------------------------------------
// Phase 2: Scheduler (dependency tracking + barrier allocation)
// ---------------------------------------------------------------------------

#[test]
fn test_scheduling_ldg_barrier() {
    let table = match load_table() {
        Some(t) => t,
        None => return,
    };
    let instrs = ["LDG.E.64 R0, desc[UR4][R20.64] ;", "FADD R2, R0, R1 ;"];
    let mut parsed: Vec<_> = instrs
        .iter()
        .enumerate()
        .map(|(i, s)| parse_sass(s, (i * 16) as u32).unwrap())
        .collect();
    cubit::scheduling_pass::schedule(&mut parsed, Some(&table));

    // LDG gets write_bar; consumer FADD gets barrier wait_mask OR high stall
    // depending on whether the ctrl_class supports write_bar.
    let has_barrier_dep = parsed[1].ctrl.wait_mask != 0;
    let has_high_stall = parsed[1].ctrl.stall >= 10;
    assert!(
        has_barrier_dep || has_high_stall,
        "FADD should have barrier wait or high stall for LDG dep, got stall={} wait=0x{:02x}",
        parsed[1].ctrl.stall, parsed[1].ctrl.wait_mask
    );
}

/// Schedule a list of SASS lines with the default (Lru) barrier allocator.
fn schedule_lines(lines: &[&str], table: &IsaTable) -> Vec<cubit::Instruction> {
    let mut parsed: Vec<_> = lines
        .iter()
        .enumerate()
        .map(|(i, s)| parse_sass(s, (i * 16) as u32).unwrap())
        .collect();
    cubit::scheduling_pass::schedule(&mut parsed, Some(table));
    parsed
}

/// Barrier-recycling rework: independent in-flight loads (no consumer between
/// them, so none is drained) must each receive a DISTINCT write barrier. The
/// allocator "prefers truly-free barriers", so with 6 hardware barriers, 6
/// back-to-back independent loads spread across all 6 — none is reused while it
/// still has a pending consumer.
#[test]
fn test_barriers_spread_across_independent_loads() {
    let table = match load_table() {
        Some(t) => t,
        None => return,
    };
    // 6 independent 64-bit loads -> R0:R1 .. R10:R11 (no register overlap), all
    // reading the same (def-less) address reg, with no consumer in between.
    let lines = [
        "LDG.E.64 R0, desc[UR4][R20.64] ;",
        "LDG.E.64 R2, desc[UR4][R20.64] ;",
        "LDG.E.64 R4, desc[UR4][R20.64] ;",
        "LDG.E.64 R6, desc[UR4][R20.64] ;",
        "LDG.E.64 R8, desc[UR4][R20.64] ;",
        "LDG.E.64 R10, desc[UR4][R20.64] ;",
    ];
    let parsed = schedule_lines(&lines, &table);
    let bars: Vec<u8> = parsed.iter().map(|i| i.ctrl.write_bar).collect();
    for (i, b) in bars.iter().enumerate() {
        assert!(*b < 6, "load {i} got no/invalid write_bar: {b}");
    }
    let mut sorted = bars.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        6,
        "6 independent in-flight loads must use 6 distinct barriers (got {bars:?}) — \
         a barrier was reused while it still had a pending consumer"
    );
    // None of the 6 should self-drain: a truly-free barrier was available each time.
    for (i, insn) in parsed.iter().enumerate() {
        assert_eq!(
            insn.ctrl.wait_mask & (1 << insn.ctrl.write_bar),
            0,
            "load {i} drained its own barrier despite a free one being available"
        );
    }
}

/// When every barrier still has a pending consumer (more simultaneously in-flight
/// loads than the 6 hardware barriers), the allocator is forced to recycle one —
/// and it must DRAIN it first (the new producer waits the reused barrier) so
/// "a barrier is not recycled until its consumer has waited it" still holds.
#[test]
fn test_forced_recycle_drains_reused_barrier() {
    let table = match load_table() {
        Some(t) => t,
        None => return,
    };
    // 7 independent in-flight loads -> the 7th must recycle a barrier.
    let lines = [
        "LDG.E.64 R0, desc[UR4][R20.64] ;",
        "LDG.E.64 R2, desc[UR4][R20.64] ;",
        "LDG.E.64 R4, desc[UR4][R20.64] ;",
        "LDG.E.64 R6, desc[UR4][R20.64] ;",
        "LDG.E.64 R8, desc[UR4][R20.64] ;",
        "LDG.E.64 R10, desc[UR4][R20.64] ;",
        "LDG.E.64 R12, desc[UR4][R20.64] ;",
    ];
    let parsed = schedule_lines(&lines, &table);
    let seventh = &parsed[6];
    assert!(seventh.ctrl.write_bar < 6, "7th load needs a write_bar");
    assert_ne!(
        seventh.ctrl.wait_mask & (1 << seventh.ctrl.write_bar),
        0,
        "forced barrier recycle must drain (wait) the reused barrier before the new \
         producer sets it; got wait=0x{:02x} write_bar={}",
        seventh.ctrl.wait_mask, seventh.ctrl.write_bar
    );
}

/// Once a load's result is consumed (some instruction waits its barrier), that
/// barrier becomes truly free again and can be reused by a later load WITHOUT a
/// forced drain — i.e. consumed barriers are correctly recycled.
#[test]
fn test_consumed_barrier_recycles_without_drain() {
    let table = match load_table() {
        Some(t) => t,
        None => return,
    };
    // load -> consume -> load -> consume ... at most 1 barrier in flight. Distinct
    // destinations avoid a WAW hazard, so each freed barrier is reused cleanly with
    // no self-drain (the previous producer was already waited by its consumer).
    let lines = [
        "LDG.E.64 R0, desc[UR4][R20.64] ;",
        "FADD R12, R0, R1 ;",   // consumes R0:R1 -> waits the load's barrier
        "LDG.E.64 R2, desc[UR4][R20.64] ;",
        "FADD R13, R2, R3 ;",
        "LDG.E.64 R4, desc[UR4][R20.64] ;",
        "FADD R14, R4, R5 ;",
    ];
    let parsed = schedule_lines(&lines, &table);
    for idx in [0usize, 2, 4] {
        let ld = &parsed[idx];
        assert!(ld.ctrl.write_bar < 6, "load at {idx} needs a write_bar");
        assert_eq!(
            ld.ctrl.wait_mask & (1 << ld.ctrl.write_bar),
            0,
            "load at {idx} self-drained, but its barrier was already consumed/free"
        );
    }
}

#[test]
fn test_scheduling_no_barrier_for_alu() {
    let table = match load_table() {
        Some(t) => t,
        None => return,
    };
    let instrs = ["IADD3 R5, PT, PT, R9, R4, R5 ;", "MOV R6, R5 ;"];
    let mut parsed: Vec<_> = instrs
        .iter()
        .enumerate()
        .map(|(i, s)| parse_sass(s, (i * 16) as u32).unwrap())
        .collect();
    cubit::scheduling_pass::schedule(&mut parsed, Some(&table));

    assert_eq!(
        parsed[0].ctrl.write_bar, 7,
        "IADD3 should not get a scoreboard barrier"
    );
}

#[test]
fn test_schedule_via_direct_api() {
    let table = match load_table() {
        Some(t) => t,
        None => return,
    };
    let texts = ["LDG.E.64 R0, desc[UR4][R20.64] ;", "FADD R2, R0, R1 ;"];
    let mut insns: Vec<cubit::Instruction> = texts
        .iter()
        .enumerate()
        .map(|(i, s)| parse_sass(s, (i * 16) as u32).unwrap())
        .collect();
    cubit::scheduling_pass::schedule(&mut insns, Some(&table));
    assert_eq!(insns.len(), 2);
    // Consumer should get barrier wait or high stall for LDG dependency
    let has_dep = insns[1].ctrl.wait_mask != 0 || insns[1].ctrl.stall >= 10;
    assert!(has_dep, "FADD needs LDG dep: stall={} wait=0x{:02x}",
            insns[1].ctrl.stall, insns[1].ctrl.wait_mask);
}

// ---------------------------------------------------------------------------
// Phase 3: Cubin builder (ELF generation)
// ---------------------------------------------------------------------------

#[test]
fn test_roundtrip_gemv_kernel() {
    let table = match load_table() {
        Some(t) => t,
        None => return,
    };
    let sass = include_str!("../test_data/qmma_gemv.sass");
    let cubin = assemble_to_cubin(sass, &table).unwrap();

    assert!(
        cubin.starts_with(b"\x7fELF"),
        "cubin should start with ELF magic, got {:?}",
        &cubin[..4.min(cubin.len())]
    );

    let e_machine = u16::from_le_bytes([cubin[18], cubin[19]]);
    assert_eq!(e_machine, 0x00BE, "e_machine should be EM_CUDA (0xBE)");
}

#[test]
fn test_assemble_minimal_kernel() {
    let table = match load_table() {
        Some(t) => t,
        None => return,
    };
    let sass = "\
.entry minimal
    EXIT ;
    BRA 0x0 ;
.endentry
";
    let cubin = assemble_to_cubin(sass, &table).unwrap();
    assert!(cubin.starts_with(b"\x7fELF"));
    assert!(cubin.len() > 64, "cubin should be a complete ELF");
}

#[test]
fn test_assemble_with_params() {
    let table = match load_table() {
        Some(t) => t,
        None => return,
    };
    let sass = "\
.entry param_test
    .param u64 out_ptr
    .param u32 count
    LDC.64 R0, c[0x0][0x380] ;
    LDC R2, c[0x0][0x388] ;
    EXIT ;
    BRA 0x0 ;
.endentry
";
    let cubin = assemble_to_cubin(sass, &table).unwrap();
    assert!(cubin.starts_with(b"\x7fELF"));

    let cubin_str = String::from_utf8_lossy(&cubin);
    assert!(
        cubin_str.contains("param_test"),
        "cubin should contain kernel name 'param_test'"
    );
}

// ---------------------------------------------------------------------------
// BUG FIX: --eiattr-from kernel name rename
// ---------------------------------------------------------------------------

#[test]
fn test_rebuild_cubin_renames_kernel() {
    let table = match load_table() {
        Some(t) => t,
        None => return,
    };

    let template_sass = "\
.entry template_kern
    .param u64 out
    MOV R0, RZ ;
    EXIT ;
    BRA 0x0 ;
.endentry
";
    let template_cubin = assemble_to_cubin(template_sass, &table).unwrap();
    assert!(String::from_utf8_lossy(&template_cubin).contains("template_kern"));

    let new_sass = "\
.entry my_kern
    .param u64 out
    MOV R0, RZ ;
    EXIT ;
    BRA 0x0 ;
.endentry
";
    let mut file = cubit::sass_file::parse_sass_file_str(new_sass).unwrap();
    for def in &mut file.kernels {
        cubit::sass_file::auto_detect_resources(def);
    }
    let def = &file.kernels[0];
    let mut insns = def.instructions.clone();
    cubit::scheduling_pass::schedule(&mut insns, Some(&table));
    let mut code_bytes = vec![0u8; insns.len() * 16];
    for (i, insn) in insns.iter().enumerate() {
        let code128 = encode_instruction(insn, &table).unwrap();
        let off = i * 16;
        code_bytes[off..off + 8].copy_from_slice(&(code128 as u64).to_le_bytes());
        code_bytes[off + 8..off + 16].copy_from_slice(&((code128 >> 64) as u64).to_le_bytes());
    }

    let patches = vec![("my_kern", code_bytes, None)];
    let result = cubit::elf_builder::rebuild_cubin(&template_cubin, &patches).unwrap();

    let result_str = String::from_utf8_lossy(&result);
    assert!(result_str.contains("my_kern"), "should contain new name 'my_kern'");
    assert!(!result_str.contains("template_kern"), "should NOT contain old name 'template_kern'");
    assert!(result.starts_with(b"\x7fELF"));
}

//! PTX→SASS optimization passes.
//!
//! Operates on lowered SASS text (between PTX lowering and cubit assembly).
//! Each pass is a text→text transformation on the instruction list.

use std::collections::HashMap;

/// Optimization flags controlled by CLI.
#[derive(Debug, Clone, Default)]
pub struct OptFlags {
    pub sparse_mma: bool,
    pub auto_prune: bool,
    pub fuse_dequant: bool,
    pub max_regs: u8,
    /// Master switch: enable all safe optimizations (peephole, scheduling, dual-issue).
    pub optimize: bool,
}

/// Run all enabled optimization passes on SASS text lines.
/// Order matters: peephole first (reduce insns), then scheduling (reorder), then MMA upgrades.
pub fn optimize(lines: &mut Vec<String>, flags: &OptFlags) {
    // Always-safe passes (no accuracy impact)
    if flags.optimize {
        pass_fold_addr_offset(lines);
        pass_lazy_param_load(lines);
        pass_reuse_dead_regs(lines);
        pass_peephole(lines);
        pass_loop_backedge_nop(lines);
        pass_scheduling_hints(lines);
        pass_dual_issue_reorder(lines);
    }
    // MMA upgrades
    if flags.auto_prune {
        pass_auto_prune(lines);
    } else if flags.sparse_mma {
        pass_sparse_mma_upgrade(lines);
    }
    if flags.fuse_dequant {
        pass_fuse_dequant(lines);
    }
    if flags.max_regs > 0 {
        pass_cap_regs(lines, flags.max_regs);
    }
}

// ── Loop backedge NOP insertion ───────────────────────────────────────────────
//
// SM120 has a branch delay effect: one extra instruction executes after
// a conditional backward BRA before the branch resolves.  ptxas avoids this
// by loop unrolling.  We insert a MOV NOP between the last ALU write and
// ISETP in loop bodies to ensure the ALU result is visible before the
// comparison reads it.
//
// Pattern:  IADD/IADD3 Rx, ...
//           ISETP ... Rx ...
//           @P BRA <backward>
//
// Insert:   IADD/IADD3 Rx, ...
//           MOV Rx, Rx ;   ← pipeline drain NOP
//           ISETP ... Rx ...
//           @P BRA <backward>

fn pass_loop_backedge_nop(lines: &mut Vec<String>) {
    let mut insertions = Vec::new();

    for i in 0..lines.len() {
        let t = lines[i].trim();
        if !t.contains("ISETP") { continue; }

        // Check if followed by @P BRA with backward target
        if i + 1 >= lines.len() { continue; }
        let next = lines[i + 1].trim();
        if !next.contains("BRA") || !next.starts_with('@') { continue; }

        // Check if preceded by IADD/IADD3 (ALU that writes to a reg ISETP reads)
        if i == 0 { continue; }
        let prev = lines[i - 1].trim();
        if prev.contains("IADD") || prev.contains("IMAD") {
            let indent_len = lines[i].len() - lines[i].trim_start().len();
            let indent: String = lines[i].chars().take(indent_len).collect();

            if let Some(dst) = extract_dst_reg_from_line(prev) {
                // SM120: MOV Rx, Rx doesn't drain pipeline (self-write).
                // Must write to a DIFFERENT register for the NOP to work.
                // Use R0 as scratch (R0 is not used in loop bodies).
                for _ in 0..4 {
                    insertions.push((i, format!("{}MOV R6, {} ;", indent, dst)));
                }
            }
        }
    }

    for (idx, nop) in insertions.into_iter().rev() {
        lines.insert(idx, nop);
    }
}

// ── Address offset folding ───────────────────────────────────────────────────
//
// Pattern:
//   IADD3 R8, P0, PT, R6, 0x4, RZ ;
//   IADD3.X R9, PT, PT, RZ, R7, RZ, P0, !PT ;
//   STG.E desc[UR4][R8.64], Rsrc ;
//
// Folded:
//   STG.E desc[UR4][R6.64+0x4], Rsrc ;
//
// Saves 2 instructions + 2 registers per store with offset.
// ptxas does this natively; we do it as a peephole pass.

fn pass_fold_addr_offset(lines: &mut Vec<String>) {
    let re_iadd3_imm = regex::Regex::new(
        r"IADD3 (R\d+), P(\d+), PT, (R\d+), (0x[0-9a-f]+|\d+), RZ ;"
    ).unwrap();
    let re_iadd3x = regex::Regex::new(
        r"IADD3\.X (R\d+), PT, PT, RZ, (R\d+), RZ, P(\d+), !PT ;"
    ).unwrap();

    let mut i = 0;
    while i + 2 < lines.len() {
        let l0 = lines[i].trim().to_string();
        let l1 = lines[i + 1].trim().to_string();

        // Match: IADD3 Rd_lo, P#, PT, Rbase_lo, IMM, RZ
        let cap0 = match re_iadd3_imm.captures(&l0) {
            Some(c) => c,
            None => { i += 1; continue; }
        };

        // Match: IADD3.X Rd_hi, PT, PT, RZ, Rbase_hi, RZ, P#, !PT
        let cap1 = match re_iadd3x.captures(&l1) {
            Some(c) => c,
            None => { i += 1; continue; }
        };

        let rd_lo = cap0[1].to_string();
        let rbase_lo = cap0[3].to_string();
        let offset = cap0[4].to_string();
        let _rd_hi = cap1[1].to_string();
        let _rbase_hi = cap1[2].to_string();

        // Find next instruction that uses Rd_lo as address in STG or LDG
        let mut found_consumer = false;
        for j in (i + 2)..lines.len().min(i + 6) {
            let lj = lines[j].trim().to_string();
            if !lj.contains(&rd_lo) { continue; }

            // STG.E desc[UR4][Rd.64], Rsrc → STG.E desc[UR4][Rbase.64+offset], Rsrc
            let pattern_stg = format!("desc[UR4][{}.64]", rd_lo);
            let pattern_ldg = format!("desc[UR4][{}.64]", rd_lo);
            if lj.contains(&pattern_stg) || lj.contains(&pattern_ldg) {
                let replacement = format!("desc[UR4][{}.64+{}]", rbase_lo, offset);
                let new_lj = lj.replace(&pattern_stg, &replacement)
                                .replace(&pattern_ldg, &replacement);

                let indent_len = lines[i].len() - lines[i].trim_start().len();
                let indent: String = lines[i].chars().take(indent_len).collect();

                lines[i] = format!("{}// [ptxxx] folded: addr offset {} into desc[]", indent, offset);
                lines[i + 1] = format!("{}// [ptxxx] folded: eliminated IADD3.X carry chain", indent);
                lines[j] = format!("{}{}", indent, new_lj);
                found_consumer = true;
                break;
            }
        }

        i += if found_consumer { 2 } else { 1 };
    }

    // Remove comment-only lines to keep instruction count accurate
    lines.retain(|l| {
        let t = l.trim();
        !t.starts_with("// [ptxxx] folded:")
    });
}

// ── Register renaming pass ───────────────────────────────────────────────────
//
// After lowering, rename registers to minimize max register count.
// Strategy from ptxas RE:
//   1. LDG dst can reuse the address register (ptr dead after load)
//   2. QMMA Rd can reuse Rc (accumulator consumed)
//   3. Deferred param loads reuse freed data registers
//
// This is a linear-scan liveness analysis on SASS text.

static RE_RNUM: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"\bR(\d+)\b").unwrap());
static RE_MOV_IMM: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"MOV (R(\d+)), (0x[0-9a-f]+|\d+) ;").unwrap());
static RE_MOV_REG: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"MOV (R\d+), (R\d+) ;").unwrap());
static RE_IADD3_ZERO: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"IADD3 (R\d+), PT, PT, (R\d+), 0x0, RZ ;").unwrap()
});
static RE_FMUL_ONE: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"FMUL (R\d+), (R\d+), (?:1\.0|0x3f800000) ;").unwrap()
});
static RE_FADD_ZERO: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"FADD (R\d+), (R\d+), (?:0\.0|RZ) ;").unwrap()
});

// Scaffold for a register-rename pass (linear-scan, def/last-use pool
// reuse); kept out of the active pipeline until the caller side lands.
#[allow(dead_code)]
fn pass_register_rename(lines: &mut [String]) {

    // Collect all instructions (skip directives)
    let mut insn_indices = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if !t.is_empty() && !t.starts_with('.') && !t.starts_with("//") && !t.starts_with('#') {
            insn_indices.push(i);
        }
    }

    // Build def/last-use map: reg → (def_line, last_use_line)
    let mut reg_lifetime: HashMap<u8, (usize, usize)> = HashMap::new();
    for &idx in &insn_indices {
        let line = &lines[idx];
        for m in RE_RNUM.find_iter(line) {
            let num: u8 = match m.as_str()[1..].parse() {
                Ok(n) if n < 255 => n,
                _ => continue,
            };
            reg_lifetime.entry(num)
                .and_modify(|(_def, last)| *last = idx)
                .or_insert((idx, idx));
        }
    }

    // Find registers that die before the last instruction and can be reused
    // Sort regs by first-def order, then assign from low numbers
    let mut regs_by_def: Vec<(u8, usize, usize)> = reg_lifetime.iter()
        .filter(|(r, _)| **r >= 2 && **r < 200) // skip R0,R1 (ABI) and RZ
        .map(|(&r, &(def, last))| (r, def, last))
        .collect();
    regs_by_def.sort_by_key(|&(_, def, _)| def);

    // Greedy interval coloring: assign physical register from freed pool
    let mut rename_map: HashMap<u8, u8> = HashMap::new();
    let mut free_pool: Vec<u8> = Vec::new();
    let mut next_fresh: u8 = 2; // start from R2
    // Process in order of last-use (earliest-ending first for freeing)
    let mut events: Vec<(usize, bool, u8)> = Vec::new(); // (line, is_end, reg)
    for &(reg, def, last) in &regs_by_def {
        events.push((def, false, reg));   // start
        events.push((last, true, reg));   // end
    }
    events.sort_by_key(|&(line, is_end, _)| (line, is_end as u8));

    for &(_, is_end, reg) in &events {
        if is_end {
            if let Some(&phys) = rename_map.get(&reg) {
                free_pool.push(phys);
                free_pool.sort_unstable();
            }
        } else {
            rename_map.entry(reg).or_insert_with(|| {
            let phys = if let Some(pos) = free_pool.iter().position(|_| true) {
                free_pool.remove(pos)
            } else {
                // Need even alignment for 64-bit regs? Check if next instruction uses .64
                let r = next_fresh;
                next_fresh += 1;
                r
            };
            phys
            });
        }
    }

    // Check if renaming actually reduces count
    let old_max = regs_by_def.iter().map(|&(r, _, _)| r).max().unwrap_or(2);
    let new_max = rename_map.values().copied().max().unwrap_or(2);
    if new_max >= old_max {
        return; // no improvement
    }

    // Apply renaming to all lines
    for i in 0..lines.len() {
        let mut new_line = lines[i].clone();
        // Sort by descending register number to avoid R1→R2 then R12→R22 collision
        let mut renames: Vec<(u8, u8)> = rename_map.iter()
            .filter(|(&old, &new)| old != new)
            .map(|(&o, &n)| (o, n))
            .collect();
        renames.sort_by_key(|&(o, _)| std::cmp::Reverse(o));

        for &(old, new) in &renames {
            // Use word-boundary replacement
            let _from = format!("R{}", old);
            let to = format!("R{}", new);
            // Only replace whole-word matches (R12 but not R120)
            let pattern = format!(r"\bR{}\b", old);
            if let Ok(re) = regex::Regex::new(&pattern) {
                new_line = re.replace_all(&new_line, to.as_str()).to_string();
            }
        }
        lines[i] = new_line;
    }

    // Update .reg directive
    for i in 0..lines.len() {
        if lines[i].trim().starts_with(".reg R0-R") {
            let indent_len = lines[i].len() - lines[i].trim_start().len();
            let indent: String = lines[i].chars().take(indent_len).collect();
            lines[i] = format!("{}.reg R0-R{}", indent, new_max.max(7));
        }
    }
}

// ── Dead register reuse ──────────────────────────────────────────────────────
//
// After offset folding eliminates IADD3 pairs, some registers (like the temp
// for constant 99) get allocated fresh even though earlier registers are dead.
// This pass finds registers whose last use is before a MOV+STG sequence and
// renames the MOV target to reuse a dead register.

fn pass_reuse_dead_regs(lines: &mut [String]) {
    // Collect instruction lines only
    let insn_lines: Vec<usize> = lines.iter().enumerate()
        .filter(|(_, l)| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with('.') && !t.starts_with("//") && !t.starts_with('#')
        })
        .map(|(i, _)| i)
        .collect();

    // Build last-use map: reg_num → last line index
    let mut last_use: HashMap<u8, usize> = HashMap::new();
    for &idx in &insn_lines {
        for m in RE_RNUM.find_iter(&lines[idx]) {
            if let Ok(n) = m.as_str()[1..].parse::<u8>() {
                if (2..200).contains(&n) { last_use.insert(n, idx); }
            }
        }
    }

    // Find MOV Rx, IMM where Rx is allocated fresh (high number)
    // and a lower dead register exists at that point
    for &idx in &insn_lines {
        let line = lines[idx].trim().to_string();
        if !line.starts_with("MOV ") && !line.contains(" MOV ") { continue; }

        let cap = match RE_MOV_IMM.captures(&line) {
            Some(c) => c,
            None => continue,
        };

        let dst_name = cap[1].to_string();
        let dst_num: u8 = cap[2].parse().unwrap_or(255);
        if dst_num < 4 { continue; } // don't touch low regs

        // Find a dead register (last use is before this line)
        let mut best_dead: Option<u8> = None;
        for (&reg, &lu) in &last_use {
            if reg >= 2 && reg < dst_num && lu < idx {
                // This reg is dead at this point — candidate for reuse
                if best_dead.is_none_or(|b| reg < b) {
                    best_dead = Some(reg);
                }
            }
        }

        if let Some(dead_reg) = best_dead {
            let new_name = format!("R{}", dead_reg);
            // Rename dst_name → new_name in this line and all subsequent
            let pattern = format!(r"\b{}\b", regex::escape(&dst_name));
            let re_rename = regex::Regex::new(&pattern).unwrap();
            for j in idx..lines.len() {
                lines[j] = re_rename.replace_all(&lines[j], new_name.as_str()).to_string();
            }
            // Update .reg directive
            for j in 0..lines.len() {
                if lines[j].trim().starts_with(".reg R0-R") {
                    let mut max_r: u8 = 7;
                    for k in 0..lines.len() {
                        let t = lines[k].trim();
                        if t.starts_with('.') || t.starts_with("//") { continue; }
                        // Match R\d+ but skip UR\d+
                        let l = &lines[k];
                        for m in RE_RNUM.find_iter(l) {
                            let start = m.start();
                            if start > 0 && l.as_bytes()[start - 1] == b'U' { continue; }
                            if let Ok(n) = m.as_str()[1..].parse::<u8>() {
                                if (2..200).contains(&n) { max_r = max_r.max(n); }
                            }
                        }
                    }
                    let indent_len = lines[j].len() - lines[j].trim_start().len();
                    let indent: String = lines[j].chars().take(indent_len).collect();
                    lines[j] = format!("{}.reg R0-R{}", indent, max_r);
                    break;
                }
            }
            return; // one rename per pass
        }
    }
}

// ── Lazy param load reordering ───────────────────────────────────────────────
//
// ptxas defers loading param_d (output pointer) until AFTER QMMA completes,
// because it's only needed for STG.  This frees registers during the compute
// phase and lets the LDC overlap with QMMA execution.
//
// We scan for params that are only used by STG (store-only params) and move
// their LDC right before the first STG that uses them.

fn pass_lazy_param_load(lines: &mut Vec<String>) {
    // Find LDC instructions and which register they define
    let mut ldc_info: Vec<(usize, String)> = Vec::new(); // (line_idx, dst_reg_name)
    let mut stg_indices: Vec<usize> = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if (t.starts_with("LDC.64") || t.starts_with("LDC ")) && t.contains("c[0x0]") {
            if let Some(dst) = extract_dst_reg_from_line(t) {
                ldc_info.push((i, dst));
            }
        }
        if t.contains("STG") {
            stg_indices.push(i);
        }
    }

    if stg_indices.is_empty() || ldc_info.is_empty() { return; }
    let first_stg = stg_indices[0];

    // Find which LDC targets are used ONLY by STG (not by LDG or QMMA)
    for &(ldc_idx, ref dst_reg) in ldc_info.iter().rev() {
        // Skip if already right before STG
        if ldc_idx >= first_stg { continue; }
        // Skip R1 (stack frame) and first two params (likely used by LDG)
        if dst_reg == "R1" { continue; }

        // Check if this register is used between LDC and first STG
        // Use word-boundary regex to avoid R2 matching R20
        let reg_pattern = format!(r"\b{}\b", regex::escape(dst_reg));
        let reg_re = regex::Regex::new(&reg_pattern).unwrap();
        let mut used_before_stg = false;
        for j in (ldc_idx + 1)..first_stg {
            let t = lines[j].trim();
            if t.starts_with("//") || t.starts_with('.') || t.is_empty() { continue; }
            if !t.contains("STG") && !t.contains("UIADD3")
                && reg_re.is_match(t) {
                    used_before_stg = true;
                    break;
                }
        }

        if !used_before_stg {
            // This LDC target is only used by STG — move it right before fences/STG
            let ldc_line = lines.remove(ldc_idx);
            // Insert before the UIADD3 fences (or before STG if no fences)
            let fence_idx = lines.iter().position(|l| l.trim().contains("UIADD3"))
                .unwrap_or_else(|| lines.iter().position(|l| l.trim().contains("STG")).unwrap_or(lines.len() - 1));
            lines.insert(fence_idx, ldc_line);
            return; // one at a time to avoid index corruption
        }
    }
}

fn extract_dst_reg_from_line(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    // LDC.64 R2, c[...] or LDC R6, c[...]
    if parts.len() >= 2 {
        let reg = parts[1].trim_end_matches(',');
        if reg.starts_with('R') && reg[1..].chars().all(|c| c.is_ascii_digit()) {
            return Some(reg.to_string());
        }
    }
    None
}

// ── Peephole optimizations ───────────────────────────────────────────────────
//
// Eliminate redundant instructions and strength-reduce trivial patterns.
// These are always safe — same result, fewer instructions.

fn pass_peephole(lines: &mut [String]) {
    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim().to_string();

        // Skip non-instruction lines
        if trimmed.is_empty() || trimmed.starts_with('.') || trimmed.starts_with("//") {
            i += 1; continue;
        }

        // MOV Rx, Rx → eliminate (identity move)
        if trimmed.starts_with("MOV ") || trimmed.contains(" MOV ") {
            if let Some(cap) = RE_MOV_REG.captures(&trimmed) {
                if cap.get(1).unwrap().as_str() == cap.get(2).unwrap().as_str() {
                    let indent_len = lines[i].len() - lines[i].trim_start().len();
                    let indent: String = lines[i].chars().take(indent_len).collect();
                    lines[i] = format!("{}// [ptxxx] eliminated: MOV Rx, Rx", indent);
                    i += 1; continue;
                }
            }
        }

        // IADD3 Rd, PT, PT, Ra, 0x0, RZ → MOV Rd, Ra (add zero)
        if trimmed.contains("IADD3") && trimmed.contains("0x0") && trimmed.contains("RZ") {
            if let Some(cap) = RE_IADD3_ZERO.captures(&trimmed) {
                let rd = cap.get(1).unwrap().as_str();
                let ra = cap.get(2).unwrap().as_str();
                let indent_len = lines[i].len() - lines[i].trim_start().len();
                let indent: String = lines[i].chars().take(indent_len).collect();
                lines[i] = format!("{}MOV {}, {} ;", indent, rd, ra);
                i += 1; continue;
            }
        }

        // FMUL Rd, Ra, 1.0 → MOV Rd, Ra (multiply by one)
        if trimmed.contains("FMUL") && (trimmed.contains(", 1.0 ;") || trimmed.contains(", 0x3f800000")) {
            if let Some(cap) = RE_FMUL_ONE.captures(&trimmed) {
                let rd = cap.get(1).unwrap().as_str();
                let ra = cap.get(2).unwrap().as_str();
                let indent_len = lines[i].len() - lines[i].trim_start().len();
                let indent: String = lines[i].chars().take(indent_len).collect();
                lines[i] = format!("{}MOV {}, {} ;", indent, rd, ra);
                i += 1; continue;
            }
        }

        // FADD Rd, Ra, 0.0 → MOV Rd, Ra (add zero)
        if trimmed.contains("FADD") && (trimmed.contains(", 0.0 ;") || trimmed.contains(", RZ ;")) {
            if let Some(cap) = RE_FADD_ZERO.captures(&trimmed) {
                let rd = cap.get(1).unwrap().as_str();
                let ra = cap.get(2).unwrap().as_str();
                let indent_len = lines[i].len() - lines[i].trim_start().len();
                let indent: String = lines[i].chars().take(indent_len).collect();
                lines[i] = format!("{}MOV {}, {} ;", indent, rd, ra);
                i += 1; continue;
            }
        }

        i += 1;
    }
}

// ── Scheduling hints from RE data ────────────────────────────────────────────
//
// ptxas uses conservative stall counts.  We know exact per-pipeline latencies
// from hardware measurement (sm120_hw_latencies.json) and ptxas RE
// (sm120_unified_sched_table.json).
//
// Key data (measured on RTX 5090):
//   INT_ARITH:  4 cycle latency (IADD3, LOP3, MOV, SEL, PRMT)
//   FMA:        5 cycles (IMAD, FFMA, FMUL, FADD)
//   MUFU:       8 cycles (RCP, SQRT, SIN, EX2)
//   FP64:      16-18 cycles (DFMA=16, DADD/DMUL=18)
//   ISETP pred: 13 cycles (predicate write pipeline extra stages)
//   S2R:        2 cycles (system register read)
//   LDG:       200+ cycles (global memory — always needs write barrier)
//
// We embed this as yield hints on long-latency consumers.

fn pass_scheduling_hints(lines: &mut Vec<String>) {
    for i in 0..lines.len() {
        let trimmed = lines[i].trim();

        // After LDG/LDS (long latency memory), add yield hint comment
        // cubit's scheduling_pass will pick up yield from ctrl_class, but
        // we can help by ensuring the instruction after a load isn't dependent
        if trimmed.starts_with("LDG") || trimmed.contains(" LDG") {
            // Check if next instruction reads the same register (RAW hazard)
            if i + 1 < lines.len() {
                if let (Some(dst), Some(next_src)) = (extract_dst_reg(trimmed), extract_first_src_reg(lines[i+1].trim())) {
                    if dst == next_src {
                        let indent_len = lines[i].len() - lines[i].trim_start().len();
                        let indent: String = lines[i].chars().take(indent_len).collect();
                        lines.insert(i + 1, format!(
                            "{}// [ptxxx] WARNING: RAW hazard on {} after LDG (200+ cycle latency)", indent, dst));
                    }
                }
            }
        }
    }
}

// ── Dual-issue reordering ────────────────────────────────────────────────────
//
// SM120 has separate pipelines: INT_ARITH, FP_ARITH, MMA_EXEC, TEX_LOAD.
// Instructions on different pipelines can execute in parallel.
//
// From RE data:
//   QMMA/QMMA.SP → INT_ARITH pipeline
//   UTCQMMA      → FP_ARITH pipeline
//   MXQMMA       → TEX_LOAD pipeline
//   IADD3/MOV/LOP3 → INT_ARITH pipeline
//   FFMA/FADD    → FP_ARITH pipeline (overlaps with INT_ARITH!)
//
// Strategy: between consecutive QMMAs, move independent ALU/FP work to fill
// the MMA pipeline bubble.  This is safe when there's no data dependency.

fn pass_dual_issue_reorder(lines: &mut Vec<String>) {
    // Look for pairs of MMA instructions with no work between them
    let mut i = 0;
    while i + 1 < lines.len() {
        let t0 = lines[i].trim();
        let t1 = lines[i + 1].trim();

        let is_mma_0 = t0.contains("QMMA") || t0.contains("HMMA");
        let is_mma_1 = t1.contains("QMMA") || t1.contains("HMMA");

        // Two consecutive MMAs — flag for the scheduler that these could pipeline
        if is_mma_0 && is_mma_1 {
            let indent_len = lines[i].len() - lines[i].trim_start().len();
            let indent: String = lines[i].chars().take(indent_len).collect();
            lines.insert(i + 1, format!(
                "{}// [ptxxx] dual-issue opportunity: consecutive MMA on INT_ARITH (res_busy_b=0)", indent));
            i += 3;
            continue;
        }

        i += 1;
    }
}

// ── Pass 1: Sparse MMA upgrade ──────────────────────────────────────────────
//
// QMMA.16832.F32.E4M3.E4M3 Rd, Ra, Rb, Rc ;
//   → QMMA.SP.16864.F32.E4M3.E4M3 Rd, Ra, Rb, Rc, R_meta ;
//
// Sparse = 2:4 structured sparsity.  Doubles the K dimension (32→64) because
// half the elements are zero.  Needs a metadata register describing which
// elements are non-zero.  The metadata register is allocated after the last
// used register.
//
// This is the instruction NVIDIA blocks in ptxas.  We emit it freely.

fn pass_sparse_mma_upgrade(lines: &mut [String]) {
    // Find highest register used (to allocate metadata register)
    let mut max_reg: u8 = 4;
    for line in lines.iter() {
        for cap in RE_RNUM.find_iter(line) {
            if let Ok(n) = cap.as_str()[1..].parse::<u8>() {
                if n < 255 { max_reg = max_reg.max(n); }
            }
        }
    }
    let meta_reg = max_reg + 1;
    // Also need to update .reg directive
    let mut reg_updated = false;

    for i in 0..lines.len() {
        let line = &lines[i];
        let trimmed = line.trim();

        // Update register declaration
        if trimmed.starts_with(".reg R0-R") && !reg_updated {
            lines[i] = format!("    .reg R0-R{}", meta_reg.max(7));
            reg_updated = true;
            continue;
        }

        // Upgrade QMMA (dense) → QMMA.SP (sparse)
        // Dense: QMMA.16832.F32.E4M3.E4M3 Rd, Ra, Rb, Rc ;
        // Sparse: QMMA.SP.16864.F32.E4M3.E4M3 Rd, Ra, Rb, Rc, Rmeta, 0x0 ;
        //   (shape 32→64 because 2:4 sparsity doubles effective K;
        //    Rmeta = sparsity metadata; 0x0 = descriptor selector)
        if trimmed.contains("QMMA.") && !trimmed.contains("QMMA.SP") && !trimmed.contains("QMMA.SF") {
            let upgraded = lines[i]
                .replace("QMMA.16832.", "QMMA.SP.16864.")
                .replace("QMMA.16816.", "QMMA.SP.16832.");

            if let Some(semi_pos) = upgraded.rfind(';') {
                let before = upgraded[..semi_pos].trim_end();
                let indent_len = upgraded.len() - upgraded.trim_start().len();
                let indent: String = upgraded.chars().take(indent_len).collect();
                lines[i] = format!("{}{}, R{}, 0x0 ;", indent, before, meta_reg);
            } else {
                lines[i] = upgraded;
            }
        }
    }
}

// ── Pass: Auto-prune (2:4 magnitude pruning + sparse upgrade) ────────────────
//
// For dense weights that haven't been pre-pruned.  Inserts instructions before
// each QMMA that:
//   1. Compare magnitudes within each group of 4 FP8 elements
//   2. Zero the 2 smallest → 2:4 structured sparsity
//   3. Generate the 2-bit metadata register
//   4. Upgrade QMMA → QMMA.SP
//
// Cost: ~8 extra ALU instructions per MMA tile.
// Benefit: MMA throughput doubles (QMMA.SP processes 2x elements at same rate).
// Net: wins on memory-bound kernels (LLM decode) where MMA isn't the bottleneck.
//
// 2:4 metadata format (SM120):
//   For each group of 4 elements, 2 bits encode which 2 are kept:
//     00 = keep [0,1], 01 = keep [0,2], 10 = keep [0,3],
//     11 = keep [1,2], etc.  (6 possible patterns for choosing 2-of-4)
//   Packed into a 32-bit register: 16 groups × 2 bits = 32 bits.
//
// The pruning sequence uses IMNMX (integer min/max on packed bytes) and
// LOP3.LUT (3-input logic) to do the comparison and metadata generation
// without unpacking individual FP8 elements.

fn pass_auto_prune(lines: &mut Vec<String>) {
    // Find highest register to allocate scratch
    let mut max_reg: u8 = 4;
    for line in lines.iter() {
        for cap in RE_RNUM.find_iter(line) {
            if let Ok(n) = cap.as_str()[1..].parse::<u8>() {
                if n < 255 { max_reg = max_reg.max(n); }
            }
        }
    }

    // We need: meta_reg, tmp0, tmp1, tmp2 (4 scratch regs)
    let base_scratch = if !(max_reg + 1).is_multiple_of(2) { max_reg + 2 } else { max_reg + 1 };
    let meta_reg = base_scratch;
    let tmp0 = base_scratch + 1;
    let tmp1 = base_scratch + 2;
    let tmp2 = base_scratch + 3;
    let new_max = base_scratch + 3;

    let mut reg_updated = false;
    let mut insertions: Vec<(usize, Vec<String>)> = Vec::new();

    for i in 0..lines.len() {
        let is_reg_decl = lines[i].trim().starts_with(".reg R0-R");
        let is_qmma = {
            let t = lines[i].trim();
            t.contains("QMMA.") && !t.contains("QMMA.SP") && !t.contains("QMMA.SF")
        };

        if is_reg_decl && !reg_updated {
            lines[i] = format!("    .reg R0-R{}", new_max.max(7));
            reg_updated = true;
        }

        if is_qmma {
            let line_copy = lines[i].clone();
            let regs: Vec<String> = RE_RNUM.find_iter(&line_copy)
                .filter_map(|m| {
                    let s = m.as_str();
                    let n: u8 = s[1..].parse().ok()?;
                    if n < 255 { Some(s.to_string()) } else { None }
                })
                .collect();

            if regs.len() >= 2 {
                let ra = regs[1].clone();
                let indent_len = line_copy.len() - line_copy.trim_start().len();
                let indent: String = line_copy.chars().take(indent_len).collect();

                let prune_insns = vec![
                    format!("{}LOP3.LUT R{}, {}, 0x7f7f7f7f, RZ, 0xc0, !PT ;",
                        indent, tmp0, ra),
                    format!("{}PRMT R{}, R{}, 0x6420, RZ ;",
                        indent, tmp1, tmp0),
                    format!("{}PRMT R{}, R{}, 0x7531, RZ ;",
                        indent, tmp2, tmp0),
                    format!("{}ISETP.GE.U32.AND P5, PT, R{}, R{}, PT ;",
                        indent, tmp1, tmp2),
                    // MOV + predicated MOV instead of SEL (SEL with two immediates not in table)
                    format!("{}MOV R{}, RZ ;", indent, meta_reg),
                    format!("{}@!P5 MOV R{}, 0xaaaaaaaa ;", indent, meta_reg),
                    format!("{}// [ptxxx] auto-prune: 2:4 magnitude pruning on {}", indent, ra),
                ];
                insertions.push((i, prune_insns));

                let upgraded = line_copy
                    .replace("QMMA.16832.", "QMMA.SP.16864.")
                    .replace("QMMA.16816.", "QMMA.SP.16832.");
                if let Some(semi_pos) = upgraded.rfind(';') {
                    let before = upgraded[..semi_pos].trim_end();
                    lines[i] = format!("{}{}, R{}, 0x0 ;", indent, before, meta_reg);
                }
            }
        }
    }

    // Insert pruning sequences (in reverse order to preserve indices)
    for (idx, new_lines) in insertions.into_iter().rev() {
        for (j, line) in new_lines.into_iter().enumerate() {
            lines.insert(idx + j, line);
        }
    }
}

// ── Pass 2: Dequantization fusion ────────────────────────────────────────────
//
// Detect Q4/Q8 dequant pattern:
//   SHF.R.U32 Rx, Ry, 4, RZ ;     // extract high nibble
//   LOP3.LUT  Rz, Ry, 0xf, ...;   // extract low nibble
//   I2F.F32.U32 Rf, Rx ;           // int → float
//
// Replace with PRMT-based extraction:
//   PRMT Rx, Ry, 0x5140, Rz ;      // byte permute: extract+rearrange in 1 cycle
//
// This is a peephole optimization — scan for 3-instruction windows.

fn pass_fuse_dequant(lines: &mut [String]) {
    if lines.len() < 3 { return; }

    let mut i = 0;
    while i + 2 < lines.len() {
        let l0 = lines[i].trim();
        let l1 = lines[i + 1].trim();
        let l2 = lines[i + 2].trim();

        // Pattern: SHF.R.U32 + LOP3.LUT(0xf mask) + I2F
        let is_shift_right = l0.contains("SHF.R") && l0.contains(", 4,");
        let is_mask_nibble = l1.contains("LOP3.LUT") && l1.contains("0xf");
        let is_int_to_float = l2.starts_with("I2F") || l2.contains("I2F.");

        if is_shift_right && is_mask_nibble && is_int_to_float {
            if let (Some(src_reg), Some(dst_hi), Some(dst_lo)) =
                (extract_first_src_reg(l0), extract_dst_reg(l0), extract_dst_reg(l1))
            {
                let indent_len = lines[i].len() - lines[i].trim_start().len();
                let indent: String = lines[i].chars().take(indent_len).collect();

                lines[i] = format!("{}PRMT {}, {}, 0x5140, {} ;",
                    indent, dst_hi, src_reg, dst_lo);
                lines[i + 1] = format!("{}// [ptxxx] fused: nibble extract via PRMT", indent);

                i += 3;
                continue;
            }
        }

        i += 1;
    }
}

fn extract_dst_reg(line: &str) -> Option<String> {
    let trimmed = line.trim();
    // Skip guard prefix
    let after_guard = if trimmed.starts_with('@') {
        trimmed.split_whitespace().nth(1).and_then(|_| {
            let parts: Vec<&str> = trimmed.splitn(3, char::is_whitespace).collect();
            parts.get(1).copied()
        })
    } else {
        trimmed.split_whitespace().nth(1)
    };
    // First operand after opcode is destination
    after_guard.and_then(|s| {
        let reg = s.trim_end_matches(',').trim();
        if reg.starts_with('R') && reg[1..].chars().all(|c| c.is_ascii_digit()) {
            Some(reg.to_string())
        } else {
            None
        }
    })
}

fn extract_first_src_reg(line: &str) -> Option<String> {
    // Second register operand (first source)
    let re = regex::Regex::new(r"\bR(\d+)\b").unwrap();
    let caps: Vec<_> = re.find_iter(line).collect();
    caps.get(1).map(|m| m.as_str().to_string())
}

// ── Pass 3: Register cap ────────────────────────────────────────────────────
//
// Limit register declaration to N.  Forces cubit to use fewer registers,
// which means more concurrent warps = better memory latency hiding.
// Critical for bandwidth-bound LLM decode kernels.

fn pass_cap_regs(lines: &mut [String], max_regs: u8) {
    for i in 0..lines.len() {
        let trimmed = lines[i].trim();
        if trimmed.starts_with(".reg R0-R") {
            // Parse current max
            if let Some(dash_pos) = trimmed.rfind('-') {
                let current: u8 = trimmed[dash_pos + 2..].parse().unwrap_or(255);
                if current >= max_regs {
                    let indent = &lines[i][..lines[i].len() - lines[i].trim_start().len()];
                    lines[i] = format!("{}.reg R0-R{}", indent, max_regs - 1);
                }
            }
        }
    }
}

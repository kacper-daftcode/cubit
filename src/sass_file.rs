//! Parser for a complete .sass source file with directives and instructions.
//!
//! Format:
//! ```text
//! .entry my_kernel
//!     .reg R0-R47
//!     .param u64 input_ptr
//!     .param u64 output_ptr
//!     .shared .align 16 smem[4096]
//!
//!     S2R R0, SR_TID.X ;                 [B------:R-:W0:-:S15]
//!     S2R R1, SR_CTAID.X ;
//!     loop:
//!       IMAD R2, R0, 0x4, R1 ;
//!       BRA loop ;
//! .endentry
//! ```

use crate::directives::{KernelResources, parse_directive};
use crate::ir::Instruction;
use crate::parser::{parse_multi_sass, resolve_labels};

/// A parsed kernel definition from a .sass source file.
#[derive(Debug, Clone)]
pub struct KernelDef {
    /// Kernel name (from `.entry name`).
    pub name: String,
    /// Resource declarations (.reg, .param, .shared, etc.).
    pub resources: KernelResources,
    /// Assembled instructions in order.
    pub instructions: Vec<Instruction>,
    /// Base address of first instruction (always 0 in a standalone file).
    pub base_addr: u32,
}

/// A complete parsed .sass file.
#[derive(Debug, Clone)]
pub struct SassFile {
    pub kernels: Vec<KernelDef>,
}

/// Parse a .sass source file string into a SassFile.
pub fn parse_sass_file_str(text: &str) -> anyhow::Result<SassFile> {
    let mut kernels = Vec::new();
    let mut current_name: Option<String> = None;
    let mut current_res = KernelResources::default();
    let mut body_lines: Vec<String> = Vec::new();

    let mut file_era100 = false;

    for line in text.lines() {
        let t = line.trim();

        if t.starts_with(";; era=sm100") {
            file_era100 = true;
            continue;
        }

        // Skip blank lines and comments at top level
        if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
            if current_name.is_some() {
                body_lines.push(line.to_string());
            }
            continue;
        }

        // .entry <name> or .func <name>
        if let Some(rest) = t.strip_prefix(".entry").or_else(|| t.strip_prefix(".func")) {
            // A new .entry while another kernel is still open implicitly closes it
            // (emitters without .endentry previously lost all but the last kernel).
            if let Some(prev) = current_name.take() {
                let body = body_lines.join("\n");
                let insns = parse_kernel_body(&body, &mut current_res);
                kernels.push(KernelDef {
                    name: prev,
                    resources: current_res.clone(),
                    instructions: insns,
                    base_addr: 0,
                });
            }
            let name = rest.trim().to_string();
            current_name = Some(name);
            current_res = KernelResources::default();
            current_res.era100 = file_era100;
            body_lines.clear();
            continue;
        }

        // .endentry / .endfunc — finish current kernel
        if t.starts_with(".endentry") || t.starts_with(".endfunc") {
            if let Some(name) = current_name.take() {
                let body = body_lines.join("\n");
                let insns = parse_kernel_body(&body, &mut current_res);
                kernels.push(KernelDef {
                    name,
                    resources: current_res.clone(),
                    instructions: insns,
                    base_addr: 0,
                });
            }
            body_lines.clear();
            continue;
        }

        // Within a kernel block
        if current_name.is_some() {
            body_lines.push(line.to_string());
        }
    }

    // If file ended without .endentry, finalize any open kernel
    if let Some(name) = current_name {
        let body = body_lines.join("\n");
        let insns = parse_kernel_body(&body, &mut current_res);
        kernels.push(KernelDef {
            name,
            resources: current_res,
            instructions: insns,
            base_addr: 0,
        });
    }

    Ok(SassFile { kernels })
}

/// Parse the body of a kernel: resource directives + instruction lines + labels.
fn parse_kernel_body(body: &str, res: &mut KernelResources) -> Vec<Instruction> {
    // Separate directive lines from instruction lines
    let mut instr_text = String::new();

    for line in body.lines() {
        // Strip inline // or # comments first, so a comment (and any ';' or text in
        // it) can't corrupt directive parsing (e.g. `.shared smem[N] // note`) or
        // instruction splitting downstream.
        let nocomment = if let Some(p) = line.find("//") { &line[..p] }
                        else if let Some(p) = line.find('#') { &line[..p] }
                        else { line };
        let t = nocomment.trim();
        if t.is_empty() { continue; }

        // Try directive first
        if t.starts_with('.') {
            parse_directive(t, res);
            continue;
        }

        // Everything else goes to instruction parser
        instr_text.push_str(t);
        instr_text.push('\n');
    }

    // Use the multi-instruction parser + label resolver
    let stmts = parse_multi_sass(&instr_text, 0);
    resolve_labels(stmts, 0)
}

/// Auto-detect max register from instruction list and update resources.
pub fn auto_detect_resources(def: &mut KernelDef) {
    if def.resources.max_reg.is_some() { return; }
    let mut max_reg = 0u32;
    for insn in &def.instructions {
        for op in &insn.operands {
            if let crate::ir::Operand::Reg { num, .. } = op {
                if *num != 255 { max_reg = max_reg.max(*num as u32); }
            }
        }
    }
    if max_reg > 0 {
        def.resources.max_reg = Some(max_reg);
    }
}

/// Build a KernelMeta from a KernelDef's resources and encoded instruction bytes.
/// The `code_bytes` are used to find EXIT instruction offsets.
pub fn kernel_def_to_meta(
    def: &KernelDef,
    code_bytes: &[u8],
) -> crate::eiattr::KernelMeta {
    use crate::eiattr::{KernelMeta, KernelParam as EiKernelParam};

    // Find EXIT instruction offsets by opcode pattern.
    // EXIT and_base = 0x...094d; with guard=PT bits[15:12]=7 → lo16=0x794d
    // EXIT_P and_base = 0x...894d → lo16=0x?94d with various guards
    // Match any instruction where lo12 (bits[11:0]) matches 0x94d (EXIT family)
    let mut exit_offsets = Vec::new();
    for (i, chunk) in code_bytes.chunks(16).enumerate() {
        if chunk.len() < 16 { break; }
        let lo16 = u16::from_le_bytes([chunk[0], chunk[1]]);
        let lo12 = lo16 & 0x0FFF;
        if lo12 == 0x094d || lo12 == 0x094e || lo12 == 0x094f {
            exit_offsets.push((i * 16) as u32);
        }
    }

    // Build parameter list from directives
    let mut offset = 0u32;
    let params: Vec<EiKernelParam> = def.resources.params.iter().enumerate()
        .map(|(i, p)| {
            let size = p.ty.size();
            let aligned_offset = (offset + size - 1) & !(size - 1);
            offset = aligned_offset + size;
            EiKernelParam {
                index: i as u32,
                ordinal: i as u32,
                offset: aligned_offset,
                size,
            }
        }).collect();

    let cbank_param_size = offset as u16;
    // QMMA uses internal registers beyond the explicit operands.
    // Tungsten uses regcount=48 for QMMA kernels.
    let has_qmma = def.instructions.iter().any(|insn| insn.opcode == "QMMA");
    let min_regs = if has_qmma { 48 } else { 4 };
    let regcount = def.resources.reg_count().max(min_regs);

    let (merc_param_order, merc_param_write, merc_stg_desc_pos, merc_bar_pred,
         merc_param_uniform, merc_param_regpath, merc_param_width,
         merc_param_loads, merc_cbank_lane, merc_s2r_lanes, merc_predmem,
         merc_ldgconst, merc_load_flags, merc_atom_pool_hits) =
        merc_param_scan(&def.instructions);
    let (merc_bar_pos, merc_stg_pos, merc_stg_off, merc_bar_args) =
        merc_exec_positions(&def.instructions);
    let (merc_xor, merc_xor_reg) = merc_xor_scan(&def.instructions);
    let merc_atoms = merc_atom_scan(&def.instructions);
    // mk14.3: LDGSTS pinned/wait (wspoldzielony skaner tekstowy).
    let (merc_ldgsts_pin, merc_ldgsts_wait) = {
        let lines: Vec<(u32, String)> = def
            .instructions
            .iter()
            .map(|i| ((i.addr / 16) as u32, i.raw_text.clone()))
            .collect();
        let (pn, wt) = crate::mercury::merc_ldgsts_scan(&lines);
        (pn.map(|x| vec![x]).unwrap_or_default(),
         wt.map(|x| vec![x]).unwrap_or_default())
    };
    let merc_utca = merc_utca_scan(&def.instructions);
    let merc_atom_smem = merc_atom_smem_scan(&def.instructions);
    let merc_stg_ser = merc_stg_series(&def.instructions);
    let (merc_stg_dreg, merc_stg_dur, merc_stg_guard, merc_stg_areg, merc_stg_wsel) =
        merc_stg_meta(&def.instructions);
    let merc_mma = merc_mma_scan(&def.instructions);
    let merc_f64imm = merc_f64imm_scan(&def.instructions);
    // mk51: DFMA z natychmiastowym f64 (020d1c0e/020d1a0e).
    let merc_dfmaimm = merc_dfmaimm_scan(&def.instructions);
    let merc_pad_pos: Vec<u32> = def
        .instructions
        .iter()
        .filter(|i| crate::mercury::is_uiadd3_killpad(&i.raw_text))
        .map(|i| (i.addr / 16) as u32)
        .collect();
    // mk13: predykowany BRA -> bit bitmapy; LOP3 z destem Pn -> bez bitu,
    // mini-rekord 42 2a 02 06 w lane (gold q_switch/p_call/d_sw4_store).
    let mut merc_guarded_bra: Vec<u32> = Vec::new();
    let mut merc_lop3_pdest: Vec<u32> = Vec::new();
    let mut merc_s2r_sr: Vec<u8> = Vec::new();
    let mut merc_s2r_dest: Vec<u32> = Vec::new();
    // mk28: samo-petle BRA (spin-trap po strefie funkcji wewnetrznych),
    // flagi klas CALL/BSSY (EIATTR 0x1e + pusta .rela.text.K) oraz liste
    // site'ow operacji warp-wide do EIATTR 0x31 (INT_WARP_WIDE).
    let mut merc_bra_selfloop: Vec<u32> = Vec::new();
    let mut n_call = 0u32;
    let mut has_bssy = false;
    let mut has_voteu = false;
    let mut wwide: Vec<u32> = Vec::new();
    for ins in &def.instructions {
        let lane = (ins.addr / 16) as u32;
        if ins.opcode == "CALL" {
            n_call += 1;
        }
        if ins.opcode == "BSSY" {
            has_bssy = true;
        }
        match crate::mercury::wwide_class(&ins.opcode_full, &ins.opcode) {
            Some(b'v') => {
                has_voteu = true;
                wwide.push(ins.addr);
            }
            Some(_) => wwide.push(ins.addr),
            None => {}
        }
        if ins.opcode == "BRA"
            && ins
                .operands
                .iter()
                .any(|o| matches!(o, crate::ir::Operand::BranchTarget(t) if *t == ins.addr))
        {
            merc_bra_selfloop.push(lane);
        }
        if ins.opcode == "S2R" {
            // mk13: enum SR -> b12 anchor-rekordu (rownolegle do
            // merc_s2r_lanes z merc_param_scan — oba w kolejnosci adresow).
            let sr = crate::mercury::s2r_sr_name(&ins.raw_text);
            merc_s2r_sr.push(crate::mercury::merc_s2r_sr_enum(&sr));
            // mk17a: numer R dest -> payload f4 anchor-rekordu.
            merc_s2r_dest.push(crate::mercury::merc_s2r_dest_reg(&ins.raw_text).unwrap_or(0));
        }
        if ins.opcode == "BRA" {
            if let Some(g) = &ins.guard {
                if g.pred != 7 {
                    merc_guarded_bra.push(lane);
                }
            }
        }
        if ins.opcode == "LOP3" && crate::mercury::lop3_writes_pred(&ins.raw_text) {
            merc_lop3_pdest.push(lane);
        }
    }

    // mk30: rodziny b_* (SYNCS/mbarrier/TMA/minis) — glowny skan.
    let mc = merc_mc_scan(&def.instructions);
    // mk40: store-matrix (ST.E/STL) + mini-slownik korpusowy.
    let merc_store2 = merc_store2_scan(&def.instructions);
    let merc_mini2 = merc_mini2_scan(&def.instructions);
    // mk42: edge-rekordy LD-desc (02223232) + maxUR deskryptorow.
    let (merc_edge_ld, merc_edge_maxur) = merc_edge_ld_scan(&def.instructions);
    // mk50: edge-rekordy LDG-desc (02221e32) w kernelach annotated_ptr.
    let merc_edge_ldg = merc_edge_ldg_scan(&def.name, &def.instructions);
    // mk35: skan pomocniczy (dst-reg siatki rec desc/0132, guardy BAR, ...).
    let m35 = merc_mk35_scan(&def.instructions);
    // mk41: bramka rodziny dla lea18 (przed borrowami w literalu KernelMeta).
    let mf_lea_gate =
        !(mc.exch.is_empty() && mc.arrive.is_empty() && mc.phase.is_empty());
    let m35_dreg_map: std::collections::HashMap<u32, u8> =
        m35.load_dreg.iter().copied().collect();
    let m35_bar_map: std::collections::HashMap<u32, u8> =
        m35.bar_guard.iter().copied().collect();
    let m35_load_dreg_par: Vec<u8> = merc_param_loads
        .iter()
        .map(|&(lane, _, _, _, _)| m35_dreg_map.get(&lane).copied().unwrap_or(255))
        .collect();
    let m35_bar_guard_par: Vec<u8> = merc_bar_pos
        .iter()
        .map(|&lane| m35_bar_map.get(&lane).copied().unwrap_or(0xf8))
        .collect();

    let usetp52 = merc_usetp_scan(&def.instructions);
    KernelMeta {
        name: def.name.clone(),
        regcount,
        frame_size: 0,
        min_stack_size: 0,
        maxreg_count: 0xFF,
        // mk20: brak dyrektywy .bar -> wyprowadz z instrukcji BAR/SYNCS
        // (EIATTR num_barriers = max(id)+1). Sciezka legacy emituje rekordy
        // BAR per-count i bez tego gubila k_sync (__syncthreads, zero loadow
        // -> legacy-path) w E2E asm-path.
        num_barriers: (def.resources.num_barriers as u8).max(
            merc_bar_args.iter().map(|&(id, _)| (id + 1) as u8).max().unwrap_or(0),
        ),
        exit_offsets,
        cbank_param_size,
        params,
        cuda_api_version: 0x83,  // SM120 CUDA 12.8 API version
        shared_size: def.resources.shared_size(),
        merc_param_order,
        merc_param_write,
        merc_stg_desc_pos,
        merc_bar_pred,
        merc_dynldg: merc_select_dynldg(&def.instructions),
        merc_bar_pos,
        merc_bar_args,
        merc_stg_pos,
        merc_param_uniform,
        merc_param_regpath,
        merc_param_width,
        merc_xor,
        merc_xor_reg,
        merc_stg_off,
        merc_stg_ser,
        merc_stg_dreg,
        merc_stg_dur,
        merc_stg_guard,
        merc_stg_areg,
        merc_stg_wsel,
        merc_mma,
        merc_f64imm,
        merc_dfmaimm,
        merc_pad_pos,
        merc_param_loads,
        merc_cbank_lane,
        merc_s2r_lanes,
        merc_s2r_guard: def
            .instructions
            .iter()
            .filter(|i| i.opcode == "S2R")
            .map(|i| merc_guard_code(i.guard.as_ref()))
            .collect(),
        merc_predmem,
        merc_ldgconst,
        merc_load_flags,
        merc_atom_pool_hits,
        merc_guarded_bra,
        merc_s2r_sr,
        merc_s2r_dest,
        merc_lop3_pdest,
        // mk19: duchy syncwarp z dyrektywy .merc_syncwarp (znacznik z
        // disassemble --frozen; bez znacznika — pusto, jak dawniej).
        merc_syncwarp: {
            let mut v = def.resources.merc_syncwarp.clone();
            v.sort_unstable();
            v.dedup();
            v
        },
        merc_atoms,
        merc_ldgsts_pin,
        merc_ldgsts_wait,
        merc_utca,
        merc_atom_smem,
        merc_bra_selfloop,
        merc_store2,
        merc_mini2,
        merc_edge_ld,
        merc_edge_maxur,
        merc_edge_ldg,
        // nvcc (EIATTR 0x31): liste site'ow warp-wide emituje tylko gdy
        // kernel zawiera VOTEU (fit na 119 kernelach labu: 5/5 z VOTEU maja
        // atrybut, zaden bez VOTEU).
        merc_wwide_sites: if has_voteu { wwide } else { Vec::new() },
        merc_cgsites: def.resources.merc_cgsites.iter().map(|&(s, _)| s).collect(),
        merc_cgmasks: def.resources.merc_cgsites.iter().map(|&(_, m)| m).collect(),
        has_call: n_call > 0,
        has_bssy,
        merc_mc_exch: mc.exch,
        merc_mc_arrive: mc.arrive,
        merc_mc_phase: mc.phase,
        merc_mc_d1: mc.uiadd3_1m,
        merc_mc_ushf_fin: mc.ushf_fin,
        merc_mc_voteu_all: mc.voteu_all,
        merc_mc_mov400: mc.mov400,
        // mk41 (rozbicie bramki korpusowo-labowej):
        //  era-100 && !m-family -> mini dla LEA I ULEA z 0x18 (korpus sm_100);
        //  m-family            -> tylko LEA-0x18 (mk30, mkvmem* itd.);
        //  era-103a bez famil  -> brak mini (k_lds: ULEA bez minia).
        // mk41 stan: mini 4100000a dla site'ow LEA ..., 0x18:
        //  - era-103a: jak przed mk41 (mk30: tylko m-family; ULEA nigdy).
        //  - era-100 : m-family -> LEA; poza m-family -> tez LEA (korpus).
        //  ULEA-0x18: NIEPEWNE (mkvmem2.sm_100 brak minia vs xlab ulea z nim)
        //  — parked (mk41-resid).
        merc_mc_lea18: {
            let m_family = mf_lea_gate;
            if m_family || def.resources.era100 {
                mc.lea18.clone()
            } else {
                Vec::new()
            }
        },
        merc_era100: def.resources.era100,
        merc_ws_minis: mc.ws,
        merc_uvcount: mc.uvcount,
        // mk43: mini 4100100a (UMOV URn, URm) tylko era sm_103a (lab
        // b_ldmatrix: 1 site, 1 rekord). Korpus sm_100: nvcc ich NIE
        // emituje, a nasza nad-emisja psula i rekordy i bitmape (kasowanie
        // bitow t4). Wyjatki corpusowe csrmv_v3 x3 (para UMOV-RR -> LDS
        // [UR4] tuz za) = parked.
        merc_umov_rr: if def.resources.era100 { Vec::new() } else { mc.umov_rr },
        merc_ublkcp: mc.ublkcp,
        merc_plop3_tx: mc.plop3_tx,
        merc_plop3_rec: mc.plop3_rec,
        merc_cs2r_rec: mc.cs2r_rec,
        merc_geo_rec: mc.geo_rec,
        merc_lop3not_rec: mc.lop3not_rec,
        merc_redg2_rec: mc.redg2_rec,
        merc_atomg2_rec: mc.atomg2_rec,
        merc_fence_async: mc.fence_async,
        merc_ldgsts_b128: mc.ldgsts_b128,
        merc_s2ur_cga: mc.s2ur_cga,
        merc_bsync_close: mc.bsync_close,
        merc_hfma2_const: mc.hfma2_const,
        merc_mc_ulea_x: mc.ulea_x,
        merc_mc_bra_np: mc.bra_np_loop,
        merc_mc_nodeless: mc.nodeless,
        merc_param_load_dreg: m35_load_dreg_par,
        merc_bar_guard: m35_bar_guard_par,
        merc_isetp_ur: m35.isetp_ur,
        merc_xsetp_pairs: merc_xsetp_scan(&def.instructions),
        merc_usetp_minis: {
            let (m, _) = &usetp52;
            m.clone()
        },
        merc_ulea_upco: usetp52.1.clone(),
        merc_redux: m35.redux,
        merc_cbank358_dreg: m35.cbank358_dreg,
    }
}

/// Mercury desc-order support: skanuje SASS po `LDC(.64)?.U?Rx, c[0x0][0x380+8k]`
/// (param slot k) i pierwszych uzyciach adresowych; zwraca
/// (kolejnosc pierwszego uzycia parametrow, bitmaska write-first).
/// Model zmierzony na mikrolabie r_*/s_* (mk8).
/// true gdy kernel ma LDG z rejestrowym offsetem [Rx.64+0x...] (era-103a
/// wyzwalacz rekordu cflow 0x41; dane: k_ld/k_ldcg/k_ldg2/c_ld_dyn vs c_ld_fix).
fn merc_select_dynldg(instructions: &[Instruction]) -> bool {
    instructions.iter().any(|ins| {
        let t = &ins.raw_text;
        ins.opcode == "LDG"
            && (t.contains(".64+0x") || t.contains(".64]") && t.contains('['))
    })
}

fn merc_exec_positions(
    instructions: &[Instruction],
) -> (Vec<u32>, Vec<u32>, Vec<i32>, Vec<(u32, u32)>) {
    let mut bar_pos = Vec::new();
    let mut bar_args = Vec::new();
    let mut stg_pos = Vec::new();
    let mut stg_off: Vec<i32> = Vec::new();
    for ins in instructions {
        let slot = (ins.addr / 16) as u32;
        match ins.opcode.as_str() {
            // mk30b: rekordy 01475a16 dostaja TYLKO prawdziwe BAR.SYNC;
            // SYNCS.* (mbarrier EXCH/ARRIVE/PHASECHK/...) maja wlasne
            // rodziny rekordow (mk30: 011b36/021b2c/021b4c/021b5e).
            "BAR" => {
                bar_pos.push(slot);
                // mk13: named barrier args `BAR.SYNC.DEFER_BLOCKING 0x1, 0x20`
                // -> (id, cnt); zwykly BAR bez argumentow -> (0, 0).
                let tt = ins.raw_text.trim();
                let g2 = if tt.starts_with('@') {
                    tt.find(char::is_whitespace).map(|k| tt[k..].trim()).unwrap_or("")
                } else {
                    tt
                };
                let rest = g2
                    .find(char::is_whitespace)
                    .map(|k| g2[k..].trim())
                    .unwrap_or("");
                let mut it = rest.split(',');
                let pa = |t: &str| -> u32 {
                    let t = t.trim().trim_end_matches(';');
                    if let Some(h) = t.strip_prefix("0x") {
                        u32::from_str_radix(h, 16).unwrap_or(0)
                    } else {
                        t.parse::<u32>().unwrap_or(0)
                    }
                };
                let id = it.next().map(pa).unwrap_or(0);
                let cnt = it.next().map(pa).unwrap_or(0);
                bar_args.push((id, cnt));
            }
            "STG" => {
                stg_pos.push(slot);
                // mk41: imm z ostatniego nawiasu [R..64(+0x..|+-0x..)] —
                // dowolna szerokosc transferu i ujemne przesuniecia.
                let off: i32 = match ins.raw_text.rfind('[') {
                    Some(lb) => {
                        let rb = ins.raw_text[lb..].find(']').map(|k| lb + k).unwrap_or(ins.raw_text.len());
                        let inner = &ins.raw_text[lb + 1..rb];
                        match inner.rfind('+') {
                            Some(pl) => {
                                let tail = inner[pl + 1..].trim();
                                if tail.starts_with('U') { 0 } else {
                                    let neg = tail.starts_with('-');
                                    let tt = tail.trim_start_matches('-');
                                    i32::from_str_radix(tt.trim_start_matches("0x"),
                                        if tt.starts_with("0x") { 16 } else { 10 }).map(|v| if neg { -v } else { v }).unwrap_or(0)
                                }
                            }
                            None => 0,
                        }
                    }
                    None => 0,
                };
                stg_off.push(off);
            }
            _ => {}
        }
    }
    (bar_pos, stg_pos, stg_off, bar_args)
}

/// Mercury 0229: skan `LOP3.LUT Rd, Rs, imm32, RZ, 0x3c` (= SASS-forma C-level
/// `xor dst, src, imm`). Zwraca (lane, dst, src, imm, guard). fs6-lab:
/// tylko lut=0x3c z imm w slocie srcB i RZ w slocie srcC dostaje rekord 0229;
/// or/and (lut 0xfc/0xc0) zostaja zwyklymi bitami; nor/neg-formy rowniez nie.
/// lane takiej instrukcji NIE dostaje bitu bitmapy (rekord pelny zastepuje
/// wezel typu4-flag1).
/// mk10b: indeks STG w biezacej serii blokowej + null-tail flag (bit7).
/// Granice serii: instrukcja-bedaca-targetem skoku oraz pozycja po EXIT/RET/
/// CALL/BRA/BRX/JMP/BREAK/BSSY/BSYNC (navic odpowiednia na s_stg_branch).
/// mk12: per-STG (dreg/dur/guard) — merc_stg_meta ponizej. dreg: kursor
/// rekordu 02 38 na bajtach [19],[20] (u16 LE) = dreg << 6; RZ jako 0x3ff
/// (R3->0x00c0, R5->0x0140, R7->0x01c0, R9->0x0240, R11->0x02c0,
/// R21->0x0540, RZ->0xffc0). Zastepuje model mk10b (40|par<<7, 1+(ser>>1)
/// == seria R5+2n). dur: desc-UR -> (b17,b18) = (dur<<6)|2 (fala A:
/// UR6 -> 0x0182 dla k_lds/v_sm*/k_smem). guard: @Pn -> b4=00,
/// @!Pn -> b4=01, brak -> f8 (jak w rekordzie 0229; d_ifearly_stg).

/// mk41: pelny kod predykatu rekordow capmerc: 0xf8 = brak guarda,
/// @Pn -> (n<<3), @!Pn -> (n<<3)|1, @UPn -> (n<<3)|2, @!UPn -> (n<<3)|3.
pub fn merc_guard_code(g: Option<&crate::ir::Guard>) -> u8 {
    match g {
        Some(g) if !(g.pred == 7 && !g.negated) => {
            let mut v = g.pred << 3;
            if g.uniform {
                v |= 2;
            }
            if g.negated {
                v |= 1;
            }
            v
        }
        _ => 0xf8,
    }
}

fn merc_stg_meta(
    instructions: &[Instruction],
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    // mk12 (kursor) + fala A: per-STG (dreg danych, desc-UR, wariant guardu).
    // mk40: + wsel (width per-STG; korpus miesza szerokosci w kernelu).
    let mut dreg = Vec::new();
    let mut dur = Vec::new();
    let mut guard = Vec::new();
    let mut areg = Vec::new();
    let mut wsel = Vec::new();
    for ins in instructions {
        if ins.opcode != "STG" {
            continue;
        }
        let txt = ins.raw_text.trim_end_matches([';', ' ']);
        wsel.push(if ins.opcode_full.contains(".128") {
            4
        } else if ins.opcode_full.contains(".64") {
            3
        } else if ins.opcode_full.contains(".U16") || ins.opcode_full.contains(".S16") {
            1
        } else if ins.opcode_full.contains(".U8") || ins.opcode_full.contains(".S8") {
            0
        } else {
            2
        });
        let tail = txt.rsplit(',').next().unwrap_or("").trim();
        let d = if tail == "RZ" {
            255u8
        } else {
            tail
                .strip_prefix('R')
                .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse::<u32>().ok())
                .map(|v| v.min(255) as u8)
                .unwrap_or(255)
        };
        dreg.push(d);
        let u: u8 = txt
            .find("desc[UR")
            .and_then(|k| {
                txt[k + 7..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<String>()
                    .parse::<u32>()
                    .ok()
            })
            .map(|v| v.min(255) as u8)
            .unwrap_or(4);
        dur.push(u);
        // mk32: niski rejestr pary adresowej [R<num>.64] (ostatni nawias
        // [R.. w operandach STG; kursor dp (b12/b13) rekordu 0238 ==
        // (areg<<6)|2 — dowod mk32/matrix 144/144). UR-absolutny/RZ -> 255.
        let a: u8 = {
            let mut out = 255u8;
            let mut pos = 0usize;
            while let Some(k) = txt[pos..].find("[R") {
                let k2 = pos + k + 2;
                let digits: String = txt[k2..]
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if !digits.is_empty() {
                    if let Ok(v) = digits.parse::<u32>() {
                        out = v.min(255) as u8;
                    }
                }
                pos = k2;
            }
            out
        };
        areg.push(a);
        // mk41: pelny kod predykatu (0xf8 = brak, Pn<<3|neg / UPn<<3|2|neg)
        let g: u8 = match &ins.guard {
            Some(g) if !(g.pred == 7 && !g.negated) => {
                let mut v = g.pred << 3;
                if g.uniform { v |= 2; }
                if g.negated { v |= 1; }
                v
            }
            _ => 0xf8,
        };
        guard.push(g);
    }
    (dreg, dur, guard, areg, wsel)
}

fn merc_stg_series(instructions: &[Instruction]) -> Vec<u8> {
    let mut bounds: std::collections::HashSet<u32> = std::collections::HashSet::new();
    for ins in instructions {
        let base = ins.opcode.as_str();
        if matches!(base,
            "BRA" | "BRX" | "JMP" | "JMPX" | "CALL" | "RET" | "EXIT" | "BREAK" |
            "BSSY" | "BSYNC") {
            bounds.insert(ins.addr / 16 + 1);
        }
        // target absolutny skoku (cubit drukuje 0xHEX w 16B-adresach)
        if matches!(base, "BRA" | "BRX" | "JMP" | "JMPX" | "CALL") {
            if let Some(pos) = ins.raw_text.find("0x") {
                let h = &ins.raw_text[pos + 2..];
                let hexdig: String =
                    h.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
                if let Ok(tv) = u32::from_str_radix(&hexdig, 16) {
                    if tv % 16 == 0 {
                        bounds.insert(tv / 16);
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    let mut ser = 0u8;
    for ins in instructions {
        let slot = ins.addr / 16;
        if bounds.contains(&slot) {
            ser = 0;
        }
        if ins.opcode == "STG" {
            let nulltail = ins.raw_text.trim_end_matches([';', ' ']).ends_with(", RZ");
            out.push(((nulltail as u8) << 7) | ser.min(126));
            ser = ser.saturating_add(1);
        }
    }
    out
}

/// mk14: skan rekordow atomowych ATOMG/ATOMS (RED* obsluguje legacy REC_ATOM).
/// Format tuple zgodny z eiattr::KernelMeta::merc_atoms.
fn merc_atom_scan(instructions: &[Instruction]) -> Vec<(u32, u8, u8, u8, u8, u8, u8, u8)> {
    let mut out = Vec::new();
    let reg_of = |t: &str| -> u8 {
        let t = t.trim().trim_end_matches(';').trim_end_matches(')');
        if t == "RZ" || t == "URZ" {
            return 255;
        }
        let d = t.trim_start_matches(['R', 'U']);
        if d.chars().all(|c| c.is_ascii_digit()) && !d.is_empty() {
            d.parse::<u32>().ok().map(|v| v.min(255) as u8).unwrap_or(255)
        } else {
            255
        }
    };
    for ins in instructions {
        let lane = (ins.addr / 16) as u32;
        let base = ins.opcode.as_str();
        if !base.starts_with("ATOM") {
            continue;
        }
        let mut toks = ins.raw_text.split_whitespace();
        let mut first = toks.next().unwrap_or("");
        let mut guard = 0u8;
        if first.starts_with('@') {
            guard = if first.starts_with("@!") { 2 } else { 1 };
            first = toks.next().unwrap_or("");
        }
        if !base.starts_with("ATOMS") && !first.starts_with(base) && !first.starts_with("ATOM") {
            continue;
        }
        // mk49: lane'y z rekordami 024e*32 NIE dostaja mk14-tuple;
        // CAST.SPIN / ATOM.E.CAS.* sa bezrekordowe (merc_atomg2_recordless).
        if crate::mercury::merc_atomg2_record(&ins.raw_text, merc_guard_code(ins.guard.as_ref()))
            .is_some()
            || crate::mercury::merc_atomg2_recordless(&ins.raw_text)
        {
            continue;
        }
        let rest: Vec<&str> = toks.collect();
        let rest = rest.join(" ");
        let rest = rest.trim_end_matches(';');
        let parts: Vec<&str> = rest.split(',').map(|x| x.trim()).collect();
        // mk19: dekoder trzyma CAS w grupie modyfikatorow (bazowy
        // opcode to "ATOMG") — detekcja po pelnym mnemoniku, jak
        // w lustrze main.rs (base0 || body.contains(".CAS")).
        let is_cas = base.contains("CAS") || first.contains(".CAS");
        if base.starts_with("ATOMS") {
            // ATOMS.<op> Rd, [URx], Rv
            if parts.len() < 3 {
                continue;
            }
            out.push((lane, crate::mercury::MERC_ATOM_CLS_SHARED, guard,
                      reg_of(parts[0]), 255, reg_of(parts[2]), 255, 0));
        } else {
            // ATOMG.E.<sub>.STRONG.<scope> PT, Rd, <addr>, Rv[, Rd2]
            if parts.len() < 3 {
                continue;
            }
            let dst = reg_of(parts[0].trim_start_matches("PT,").trim());
            // dest tok moze zawierac "PT, R5" jako parts[0] po split(',')?
            // split(',') dzieli "PT" i "R5" osobno — obsluga ponizej.
            let (dst_idx, addr_idx) = if parts[0].contains("PT") && !parts[0].contains('R') {
                (1usize, 2usize)
            } else {
                (0usize, 1usize)
            };
            let dst = if dst_idx < parts.len() { reg_of(parts[dst_idx]) } else { dst };
            if addr_idx >= parts.len() {
                continue;
            }
            let addr_part = parts[addr_idx];
            // adres: [R4] albo desc[UR4][R2.64] — ostatni wewnetrzny [..]
            let addr = {
                let mut a = 255u8;
                let mut s2 = addr_part;
                while let Some(o) = s2.rfind('[') {
                    let inner = &addr_part[o + 1..];
                    let end = inner.find(']').unwrap_or(inner.len());
                    let tok = &inner[..end];
                    let r = reg_of(tok.split('+').next().unwrap_or("").split('.').next().unwrap_or(""));
                    if r != 255 {
                        a = r;
                        break;
                    }
                    s2 = &addr_part[..o];
                }
                a
            };
            if is_cas {
                if parts.len() < addr_idx + 3 {
                    continue;
                }
                out.push((lane, crate::mercury::MERC_ATOM_CLS_CAS, guard, dst, addr,
                          reg_of(parts[addr_idx + 1]), reg_of(parts[addr_idx + 2]), 0));
            } else {
                if parts.len() < addr_idx + 2 {
                    continue;
                }
                let sub6: u8 = if base.starts_with("ATOMG") && ins.raw_text.contains(".EXCH") {
                    0x80
                } else {
                    0
                };
                out.push((lane, crate::mercury::MERC_ATOM_CLS_G4, guard, dst, addr,
                          reg_of(parts[addr_idx + 1]), 255, sub6));
            }
        }
    }
    out
}


/// mk30: skan rodziny mikrokernlowej b_* (mbarrier/TMA/minis; sciezka laned).
/// Rodowod: analysis/merclab/mk30/ + /tmp/mk30/lab (m_init/m_arr/m_wait/
/// bulk1/uvc) + capture mk26 na tych kernelach.
#[derive(Default)]
pub struct MercMcScan {
    pub exch: Vec<(u32, bool, u8, u8)>, // SYNCS.EXCH.64: (lane, guarded, addrUR, valUR)
    pub arrive: Vec<(u32, u8)>,         // SYNCS.ARRIVE.TRANS64: (lane, b4-guard)
    pub phase: Vec<u32>,                // SYNCS.PHASECHK lanes
    pub uiadd3_1m: Vec<(u32, bool)>,    // UIADD3 ...0x100000 (host blobow d1)
    pub ushf_fin: Vec<u32>,             // USHF.L imm==1 po USHF imm==0xb (mini 414c)
    pub voteu_all: Vec<u32>,            // VOTEU.*.ALL lanes (mini 414c)
    pub mov400: Vec<u32>,               // MOV Rn, 0x400 w rodzinie mbarrier
    pub lea18: Vec<u32>,                // LEA R0, R*, R0, 0x18 (mini 4100)
    /// mk41: ULEA ..., 0x18 — mini tylko w erze-100.
    pub ulea18: Vec<u32>,
    pub ws: Vec<(u32, u8)>,             // WARPSYNC.ALL: (lane, 0x76/0x6e)
    pub uvcount: Vec<u32>,              // UVIRTCOUNT.DEALLOC (mini 4144)
    pub umov_rr: Vec<u32>,              // UMOV URx, URy (mini 4100-10)
    pub ublkcp: Vec<u32>,               // __raw__ UBLKCP (rekord 02232826)
    pub plop3_tx: Vec<(u32, u8)>,       // PLOP3 expect_tx: (lane, 0/1/2 = A/B/C)
    /// mk44: generalne rekordy 0110060a (dual-output, bez UP) — (lane, 16B).
    pub plop3_rec: Vec<(u32, [u8; 16])>,
    /// mk45: rekordy 010b0c0a (CS2R Rd, SRZ) — (lane, 16B).
    pub cs2r_rec: Vec<(u32, [u8; 16])>,
    /// mk46: rekordy 010b060a geo-anchor (S2UR-geo + LDCU okno drivera).
    pub geo_rec: Vec<(u32, [u8; 16])>,
    /// mk47: rekordy 012b{00|04}0a (LOP3.LUT NOT-MOV LUT=0x33) — (lane, 16B).
    pub lop3not_rec: Vec<(u32, [u8; 16])>,
    /// mk48: rekordy 024d*32 (REDG desc/non-desc) — (lane, 32B).
    pub redg2_rec: Vec<(u32, [u8; 32])>,
    /// mk49: rekordy 024e*32 (ATOM.E/ATOMG/ATOMS) — (lane, 32B).
    pub atomg2_rec: Vec<(u32, [u8; 32])>,
    pub fence_async: Vec<u32>,          // FENCE.*ASYNC* lanes
    pub ldgsts_b128: bool,              // LDGSTS .128 (pinned-blob wariant)
    pub s2ur_cga: Vec<(u32, bool, u8)>, // S2UR ?, SR_CgaCtaId: (lane, guarded, dstUR) mk41
    pub bsync_close: Vec<u32>,          // BSYNC lanes (rekord 51-010109 regionu)
    pub hfma2_const: Vec<u32>,          // HFMA2 R?,RZ,RZ,<imm> (bez bitu)
    pub ulea_x: Vec<u32>,               // ULEA ... 0x18 z dest == EXCH addr UR (bit 0)
    pub bra_np_loop: Vec<u32>,          // braided BRA bez " PT, " w m-family (bit 0)
    /// mk34 (node-model g5b): lane'e bez wezlow capmerc = bez slotu bitmapy
    /// (para USHF licznika mbarrier + FENCE.ASYNC; tylko m-family).
    pub nodeless: Vec<u32>,
}

/// mk35: skany pomocnicze domkniecia mk35 (REDUX/CREDUX dst-grid,
/// ISETP-UR mini, guardy BAR per-lane, dst-reg loadow param, dst loadu
/// c[0x358]). Oddzielna funkcja (nie rozbudowujemy krotki merc_param_scan).
pub struct MercMk35 {
    /// (lane, dreg) dla loadow param-window LDC/LDCU (c[0x380..]).
    pub load_dreg: Vec<(u32, u8)>,
    /// (lane, dowod-cstack? nie) guard per BAR-lane (0=brak,1=@P,2=@!P).
    pub bar_guard: Vec<(u32, u8)>,
    /// lane'y ISETP.* z operandem UR i bez .EX — bar_if2 klasa minis
    /// 42 10 32 14 (zakres 1-probkowy mk35; NE+UR, bez EX).
    pub isetp_ur: Vec<u32>,
    /// rekordy 0132: (lane, kind 0=typed-REDUX/1=CREDUX, dreg).
    pub redux: Vec<(u32, u8, u8)>,
    /// dst-reg loadu okna c[0x358] (cbank-variant ladder: (dreg<<6)|3).
    pub cbank358_dreg: Option<u8>,
}

pub fn merc_mk35_scan(instructions: &[Instruction]) -> MercMk35 {
    let mut o = MercMk35 {
        load_dreg: Vec::new(),
        bar_guard: Vec::new(),
        isetp_ur: Vec::new(),
        redux: Vec::new(),
        cbank358_dreg: None,
    };
    let regnum = |tok: &str| -> Option<u8> {
        let tok = tok.trim().trim_end_matches(';').trim_end_matches(|c| c == ')' || c == ']');
        let d = tok.trim_start_matches(['R', 'U']);
        if !d.is_empty() && d.chars().all(|c| c.is_ascii_digit()) {
            d.parse::<u32>().ok().map(|v| v.min(255) as u8)
        } else {
            None
        }
    };
    for ins in instructions {
        let lane = (ins.addr / 16) as u32;
        let guard: u8 = merc_guard_code(ins.guard.as_ref());
        let base = ins.opcode.as_str();
        let full = ins.opcode_full.as_str();
        let t = ins.raw_text.as_str();
        if base == "BAR" {
            o.bar_guard.push((lane, guard));
        }
        if base == "LDC" || base == "LDCU" {
            if let Some(cp) = t.find("c[0x0][0x") {
                let hexs = &t[cp + 9..];
                let end = hexs.find(']').unwrap_or(0);
                if let Ok(off) = u32::from_str_radix(&hexs[..end], 16) {
                    // dest = pierwszy token po opcode (tekst ze stripped powiazane
                    // przez guard: bierzemy z raw_text po '@'-przecinku)
                    let body = t.trim_start();
                    let body = match body.strip_prefix('@') {
                        Some(r) => r.split_once(char::is_whitespace).map(|(_, x)| x.trim_start()).unwrap_or(body),
                        None => body,
                    };
                    let dest = body.split(',').next().unwrap_or("")
                        .split_whitespace().last().unwrap_or("");
                    if off == 0x358 && o.cbank358_dreg.is_none() {
                        o.cbank358_dreg = regnum(dest);
                    }
                    if off >= 0x380 {
                        if let Some(d) = regnum(dest) {
                            o.load_dreg.push((lane, d));
                        }
                    }
                }
            }
        }
        // mk41: regula mk35 (NE+UR bez .EX) WYGASZONA — falszywie zakladala
        // mini na pojedynczym ISETP; prawdziwe zrodlo = para z .EX
        // (merc_xsetp_scan). Pole isetp_ur zostaje puste.
        let _ = (base, full, t);
        if base == "REDUX" {
            // gole REDUX (full=="REDUX") = stary warp-vote: bit, bez rekordu;
            // typowane -> rekord 0132 z dst-grid. at_and vs p_redux (mk35).
            if full != "REDUX" {
                let body = t.trim_start();
                let body = match body.strip_prefix('@') {
                    Some(r) => r.split_once(char::is_whitespace).map(|(_, x)| x.trim_start()).unwrap_or(body),
                    None => body,
                };
                let d = body.split(',').next().unwrap_or("")
                    .split_whitespace().last().unwrap_or("");
                o.redux.push((lane, 0u8, regnum(d).unwrap_or(255)));
            }
        }
        if base == "CREDUX" {
            let body = t.trim_start();
            let body = match body.strip_prefix('@') {
                Some(r) => r.split_once(char::is_whitespace).map(|(_, x)| x.trim_start()).unwrap_or(body),
                None => body,
            };
            let d = body.split(',').next().unwrap_or("")
                .split_whitespace().last().unwrap_or("");
            o.redux.push((lane, 1u8, regnum(d).unwrap_or(255)));
        }
    }
    o
}

/// mk41: para ISETP(non-EX) [head] + ISETP.*.EX [tail] -> JEDEN mini na lane
/// heada. Klasy: 0=para czysto-rejestrowa (42102e14); 1=imm w head (42103006);
/// 2=operand UR w parze (42103214). Head kasuje bit bitmapy.
/// (Zmiana mk35: poprzednia regula NE+UR-noEX strzelala faux w korpusie.)
pub fn merc_xsetp_scan(instructions: &[Instruction]) -> Vec<(u32, u8)> {
    let mut last_by_p: std::collections::HashMap<String, (u32, bool, bool)> =
        std::collections::HashMap::new();
    let mut out: Vec<(u32, u8)> = Vec::new();
    for ins in instructions {
        if ins.opcode != "ISETP" {
            continue;
        }
        let full = ins.opcode_full.as_str();
        let b0 = ins.raw_text.as_str().trim_start();
        let body = match b0.strip_prefix('@') {
            Some(r) => r
                .split_once(char::is_whitespace)
                .map(|(_, x)| x.trim_start())
                .unwrap_or(b0),
            None => b0,
        };
        // odcinam slowo opkodu (opcode ze spacja-przed operandami)
        let body_ops = match body.find(char::is_whitespace) {
            Some(k) => body[k..].trim_start(),
            None => continue,
        };
        let toks: Vec<&str> = body_ops.split(',').map(|s| s.trim().trim_end_matches(';').trim_end()).collect();
        if toks.is_empty() {
            continue;
        }
        let dst_pred = toks[0];
        if !dst_pred.starts_with('P') || dst_pred == "PT" {
            continue;
        }
        let has_ur = {
            let mut found = false;
            for m in regex_like_ur(body) {
                found = true;
                let _ = m;
            }
            found
        };
        let has_imm = toks.iter().skip(1).any(|tk| {
            let tk = tk.trim();
            tk.starts_with("0x")
                || tk.starts_with("-0x")
                || tk
                    .trim_start_matches('-')
                    .chars()
                    .all(|c| c.is_ascii_digit())
                    && !tk.is_empty()
        });
        if full.contains(".EX") {
            let last = toks.last().copied().unwrap_or("").trim_start_matches('!');
            if let Some(&(hlane, h_ur, h_imm)) = last_by_p.get(last) {
                let cls: u8 = if h_ur || has_ur { 2 } else if h_imm { 1 } else { 0 };
                out.push((hlane, cls));
            }
        } else {
            last_by_p.insert(
                dst_pred.to_string(),
                ((ins.addr / 16) as u32, has_ur, has_imm),
            );
        }
    }
    out.sort_by_key(|x| x.0);
    out
}

/// mk52: minis UISETP (UP-dst) + ULEA carry-out (korpus sm_100, merclab/mk52
/// c1..c26 — walidacja licznikowo-emulatorowa + bitmapa korpusu):
///  * para UISETP(non-EX, dst UPn) [head] i UISETP.*.EX (..., UPn ostatnim
///    operandem) [tail] -> mini klasowe na lane heada: 42103406 gdy head LUB
///    tail ma literal imm; 42103614 w przeciwnym razie. Bezposrednio po nim
///    mini 42104014 — gdy tail sam imm NIE ma.
///  * UISETP non-EX lancuch (ostatni operand = !?UP<num>, pisarz dowolny):
///    pojedyncze mini na wlasnym lane — 42103406 gdy ma imm, inaczej 42103614.
///  * ULEA z carry-out (2. token = UP<num>): mini 42254214 na wlasnym lane.
///    (ULEA.HI.X z samym carry-in: bez rekordu; zweryfikowane ormtr-9/9.)
/// kind: 0=42103614, 1=42103406, 2=42104014. Kolejnosc elementow = kolejnosc
/// lane (sort stabilny wstrzykuje pare (class,4014) na tym samym lane).
pub fn merc_usetp_scan(instructions: &[Instruction]) -> (Vec<(u32, u8)>, Vec<u32>) {
    let mut heads: std::collections::HashMap<String, (u32, bool)> =
        std::collections::HashMap::new();
    let mut minis: Vec<(u32, u8)> = Vec::new();
    let mut ulea: Vec<u32> = Vec::new();
    for ins in instructions {
        let lane = (ins.addr / 16) as u32;
        let b0 = ins.raw_text.as_str().trim_start();
        let body = match b0.strip_prefix('@') {
            Some(r) => r
                .split_once(char::is_whitespace)
                .map(|(_, x)| x.trim_start())
                .unwrap_or(b0),
            None => b0,
        };
        let body_ops = match body.find(char::is_whitespace) {
            Some(k) => body[k..].trim_start(),
            None => "",
        };
        let toks: Vec<&str> = body_ops
            .split(',')
            .map(|s| s.trim().trim_end_matches(';').trim_end())
            .filter(|s| !s.is_empty())
            .collect();
        let is_up = |t: &str| -> bool {
            let t = t.trim_start_matches('!');
            t.len() > 2 && t.starts_with("UP") && t[2..].chars().all(|c| c.is_ascii_digit())
        };
        if ins.opcode == "ULEA" {
            // forma: ULEA URd, UPcout, srcA, srcB[, shift]
            if toks.len() >= 2 && is_up(toks[1]) {
                ulea.push(lane);
            }
            continue;
        }
        if ins.opcode != "UISETP" {
            continue;
        }
        if toks.is_empty() {
            continue;
        }
        let dstp = toks[0];
        let imm = merc_lane_has_imm(&toks[1..]);
        if ins.opcode_full.contains(".EX") {
            let last = toks.last().copied().unwrap_or("").trim_start_matches('!');
            if is_up(last) {
                if let Some(&(hlane, head_imm)) = heads.get(last) {
                    minis.push((hlane, if head_imm || imm { 1 } else { 0 }));
                    if !imm {
                        minis.push((hlane, 2));
                    }
                }
            }
        } else {
            let last = toks.last().copied().unwrap_or("").trim_start_matches('!');
            if is_up(last) {
                // lancuch: wynik UPn konsumowany U-sekventialnie — mini wg
                // wlasnego imm (klasa 3406/3614), na wlasnym lane.
                minis.push((lane, if imm { 1 } else { 0 }));
            }
        }
        let dstv = dstp.trim_start_matches('!');
        if dstv.len() > 2 && dstv.starts_with("UP") && dstv[2..].chars().all(|c| c.is_ascii_digit()) {
            heads.insert(dstv.to_string(), (lane, imm));
        }
    }
    (minis, ulea)
}

/// mk52: literal imm wsrod tokenow — definicja jak w merc_xsetp_scan (mk41).
fn merc_lane_has_imm(toks: &[&str]) -> bool {
    toks.iter().any(|tk| {
        let tk = tk.trim();
        tk.starts_with("0x")
            || tk.starts_with("-0x")
            || (tk
                .trim_start_matches('-')
                .chars()
                .all(|c| c.is_ascii_digit())
                && !tk.is_empty())
    })
}

/// mk41: wykrycie operandu UR<num> (nie URZ — to stala) w tekscie instrukcji.
fn regex_like_ur(body: &str) -> Vec<()> {
    let b = body.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < b.len() {
        if b[i] == b'U' && b[i + 1] == b'R' && b[i + 2].is_ascii_digit() {
            let prev_ok = i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
            if prev_ok {
                out.push(());
            }
        }
        i += 1;
    }
    out
}

pub fn merc_mc_scan(instructions: &[Instruction]) -> MercMcScan {
    let mut o = MercMcScan::default();
    let bar_lanes: Vec<u32> = instructions
        .iter()
        .filter(|i| i.opcode == "BAR")
        .map(|i| (i.addr / 16) as u32)
        .collect();
    let ws_lanes: Vec<u32> = instructions
        .iter()
        .filter(|i| i.opcode == "WARPSYNC" && i.opcode_full.contains(".ALL"))
        .map(|i| (i.addr / 16) as u32)
        .collect();
    let mut saw_ushf_0b: Option<u32> = None;
    for ins in instructions {
        let lane = (ins.addr / 16) as u32;
        let t = &ins.raw_text;
        let guarded = ins.guard.as_ref().map(|g| g.pred != 7).unwrap_or(false);
        match ins.opcode.as_str() {
            "SYNCS" => {
                if t.contains("EXCH") {
                    // SYNCS.EXCH.64 URZ, [UR6], UR4 -> addr=UR6 val=UR4:
                    // UR-tokeny w kolejnosci tekstowej; dst URZ pomijany
                    // (Z nie parsuje sie do liczby).
                    let mut urs = t
                        .split(|c: char| c == '[' || c == ']' || c == ',' || c == ' ')
                        .filter_map(|tok| {
                            let tk = tok.trim().trim_end_matches(';');
                            tk.strip_prefix("UR").and_then(|n| n.parse::<u8>().ok())
                        });
                    let addr = urs.next().unwrap_or(6);
                    let val = urs.next().unwrap_or(4);
                    o.exch.push((lane, guarded, addr, val));
                } else if t.contains("ARRIVE") {
                    let b4: u8 = match &ins.guard {
                        Some(g) if g.pred != 7 && g.negated => 0x01,
                        Some(g) if g.pred != 7 => 0x00,
                        _ => 0xf8,
                    };
                    o.arrive.push((lane, b4));
                } else if t.contains("PHASECHK") {
                    o.phase.push(lane);
                }
            }
            "UIADD3" if t.contains("0x100000") => o.uiadd3_1m.push((lane, guarded)),
            "VOTEU" if ins.opcode_full.contains(".ALL") => o.voteu_all.push(lane),
            "MOV" if t.contains(", 0x400") => o.mov400.push(lane),
            // mk41: mini 4100000a = kazdy LEA/ULEA z imm 0x18 (korpus sm_100:
            // nr_orow == n_sitow w 90%+; mk30-wyjasnienie po m-family bylo
            // artefaktem bramki SYNCS).
            x if (x == "LEA" || x == "ULEA") && t.contains(", 0x18") && !ins.opcode_full.contains("HI") => {
                if x == "ULEA" { o.ulea18.push(lane) } else { o.lea18.push(lane) }
            }
            "UMOV" => {
                // strip prowadzacy guard @.. (frozen/surowy tekst z pikladem)
                let body0 = t.trim();
                let body = match body0.strip_prefix('@') {
                    Some(r) => r.split_once(char::is_whitespace).map(|(_, x)| x.trim_start()).unwrap_or(body0),
                    None => body0,
                };
                let rest = body.trim_start_matches("UMOV").trim_start();
                let mut it = rest.split(',');
                let d = it.next().unwrap_or("").trim();
                let s = it.next().unwrap_or("").trim().trim_end_matches(';');
                if d.starts_with("UR") && s.starts_with("UR") {
                    o.umov_rr.push(lane);
                }
            }
            "UVIRTCOUNT" if ins.opcode_full.contains("DEALLOC") => o.uvcount.push(lane),
            "FENCE" if t.contains("ASYNC") => o.fence_async.push(lane),
            "PLOP3" => {
                if !guarded && t.contains("P0, PT, PT, PT, PT, 0x80, 0x8") {
                    o.plop3_tx.push((lane, 0));
                } else if t.contains("P0, PT, P1, PT, PT, 0x8, 0x80") {
                    o.plop3_tx.push((lane, 1));
                } else if !guarded && t.contains("P1, PT, PT, PT, PT, 0x8, 0x80") {
                    o.plop3_tx.push((lane, 2));
                }
                // mk44: generyczny rekord 0110060a (korpus EQ 5902/5902).
                if let Some(r) = crate::mercury::merc_plop3_record(t, merc_guard_code(ins.guard.as_ref())) {
                    o.plop3_rec.push((lane, r));
                }
            }
            "CS2R" => {
                // mk45: rekord 010b0c0a (CS2R R<d>, SRZ).
                if let Some(r) = crate::mercury::merc_cs2r_srz_record(t, merc_guard_code(ins.guard.as_ref())) {
                    o.cs2r_rec.push((lane, r));
                }
            }
            "LOP3" => {
                // mk47: rekord 012b{00|04}0a (LOP3.LUT NOT-MOV, LUT=0x33).
                if let Some(r) = crate::mercury::merc_lop3_not_record(t, merc_guard_code(ins.guard.as_ref())) {
                    o.lop3not_rec.push((lane, r));
                }
            }
            "REDG" => {
                // mk48: rekordy 024d{0e|24|2e}32 (REDG desc/non-desc).
                if let Some(r) = crate::mercury::merc_redg_record(t, merc_guard_code(ins.guard.as_ref())) {
                    o.redg2_rec.push((lane, r));
                }
            }
            "ATOM" | "ATOMG" | "ATOMS" => {
                // mk49: rekordy 024e*32 (ATOM.E/ATOMG/ATOMS).
                if let Some(r) =
                    crate::mercury::merc_atomg2_record(t, merc_guard_code(ins.guard.as_ref()))
                {
                    o.atomg2_rec.push((lane, r));
                }
            }
            "LDGSTS" if ins.opcode_full.contains(".128") => o.ldgsts_b128 = true,
            "S2UR" => {
                // mk46: geo-anchor 010b060a (CTAID.* / CgaCtaId / SWINHI).
                if let Some((d, role, cls)) =
                    crate::mercury::merc_geo_anchor(t, "S2UR", &ins.opcode_full)
                {
                    o.geo_rec
                        .push((lane, crate::mercury::merc_geo_record(d, role, cls, crate::sass_file::merc_guard_code(ins.guard.as_ref()))));
                    if t.contains("SR_CgaCtaId") {
                        // mk41: payload smem-anchora (b10,b11) = (dstUR<<6)|1.
                        o.s2ur_cga.push((lane, guarded, d.min(255) as u8));
                    }
                }
            }
            "LDCU" => {
                // mk46: LDCU z okna stalych drivera -> geo-anchor 010b060a.
                if let Some((d, role, cls)) =
                    crate::mercury::merc_geo_anchor(t, "LDCU", &ins.opcode_full)
                {
                    o.geo_rec
                        .push((lane, crate::mercury::merc_geo_record(d, role, cls, crate::sass_file::merc_guard_code(ins.guard.as_ref()))));
                }
            }
            "BSYNC" => o.bsync_close.push(lane),
            "HFMA2" if t.matches("RZ").count() >= 2 => o.hfma2_const.push(lane),
            _ => {}
        }
        if ins.opcode == "USHF" {
            let parts: Vec<&str> = t.split(',').collect();
            let imm = parts.get(2).map(|s| s.trim());
            if imm == Some("0xb") {
                saw_ushf_0b = Some(lane);
            } else if imm == Some("0x1") && saw_ushf_0b.is_some() {
                o.ushf_fin.push(lane);
                o.nodeless.push(saw_ushf_0b.unwrap());
                o.nodeless.push(lane);
            }
        }
        if ins.opcode == "__raw__" {
            // UBLKCP.S.G — slowo z niskimi bajtami 0x73ba (lab bulk1/bulk2/
            // b_bulk_cp; mk30 wzorzec passthrough `__raw__0x...0073ba`).
            let tx = t.trim().trim_end_matches(';');
            if tx.ends_with("0073ba") {
                o.ublkcp.push(lane);
            }
        }
    }
    // mov400: tylko w rodzinie mbarrier; poza nia MOV zostaje zwyklym MOV.
    let m_fam = !(o.exch.is_empty() && o.arrive.is_empty() && o.phase.is_empty());
    if !m_fam {
        o.mov400.clear();
        o.nodeless.clear();
    } else {
        // mk34: MOV-400 ma wezel t4 z flaga (g5b b_mbarrier n15/lane17) —
        // ushf-fin-era regula kasujaca byla w przestrzeni lane, nie node.
        o.mov400.clear();
        // FENCE.ASYNC bez wezla (b_bulk_cp lane18)
        let fl = o.fence_async.clone();
        for l in fl {
            if !o.nodeless.contains(&l) {
                o.nodeless.push(l);
            }
        }
        o.nodeless.sort_unstable();
        o.nodeless.dedup();
    }
    // mk41 ODSLOWIENIE bramki mk30: korpus sm_100 ma mini 4100000a przy
    // KAZDYM LEA/ULEA ..., 0x18 (rekord-count == site-count; 90%+ kerneli).
    // Bramka m-family mk30 = artefakt probkowania.
    // mk34 ODSLOWIENIE (node-model g5b): ulea_x/bra_np_loop zostaja puste —
    // patrz adnotacja przy McScanOut.nodeless w mercury.rs.
    // WARPSYNC.ALL minis: b2 = 0x6e gdy w (lane, next-ws] jest BAR.SYNC.
    for (k, &wl) in ws_lanes.iter().enumerate() {
        let end = ws_lanes.get(k + 1).copied().unwrap_or(u32::MAX);
        let has_bar = bar_lanes.iter().any(|&b| b > wl && b < end);
        o.ws.push((wl, if has_bar { 0x6e_u8 } else { 0x76_u8 }));
    }
    o
}

/// mk27: UTCATOMSWS (tcgen05 tmem alloc na oknie smem): (lane, kind).
/// kind 0 = FIND_AND_SET, 1 = AND (inne podoperacje na pozniej).
fn merc_utca_scan(instructions: &[Instruction]) -> Vec<(u32, u8)> {
    let mut out = Vec::new();
    for ins in instructions {
        if ins.opcode != "UTCATOMSWS" {
            continue;
        }
        let t = &ins.raw_text;
        let kind = if t.contains("FIND_AND_SET") { 0u8 } else if t.contains(".AND") { 1 } else { 2 };
        out.push(((ins.addr / 16) as u32, kind));
    }
    out
}

/// mk27: ATOMS z imm w adresie [URx+0xNN]: (lane, imm_bajty, op 0=OR/1=AND/2=inny).
fn merc_atom_smem_scan(instructions: &[Instruction]) -> Vec<(u32, u32, u8)> {
    let mut out = Vec::new();
    for ins in instructions {
        if !ins.opcode.starts_with("ATOMS") {
            continue;
        }
        // adres-klamra z imm
        let t = &ins.raw_text;
        let Some(ob) = t.find('[') else { continue };
        let inner = &t[ob + 1..];
        let Some(cb) = inner.find(']') else { continue };
        let tok = &inner[..cb];
        let Some(p) = tok.find('+') else { continue };
        let im = tok[p + 1..].trim();
        let imm = u32::from_str_radix(im.trim_start_matches("0x"), 16)
            .or_else(|_| im.parse::<u32>())
            .unwrap_or(0);
        let op = if t.contains(".OR") {
            0u8
        } else if t.contains(".AND") {
            1
        } else {
            2
        };
        out.push(((ins.addr / 16) as u32, imm, op));
    }
    out
}

fn merc_xor_scan(
    instructions: &[Instruction],
) -> (Vec<(u32, u32, u32, u32, u8)>, Vec<(u32, u32, u32, u32, u8)>) {
    let mut out = Vec::new();
    let mut out_reg = Vec::new();
    for ins in instructions {
        if ins.opcode != "LOP3" {
            continue;
        }
        let mut toks = ins.raw_text.split_whitespace();
        let mut first = toks.next().unwrap_or("");
        let mut guard = 0u8;
        if first.starts_with('@') {
            guard = if first.starts_with("@!") { 2 } else { 1 };
            first = toks.next().unwrap_or("");
        }
        if !first.starts_with("LOP3") {
            continue;
        }
        let rest = toks.collect::<Vec<_>>().join(" ");
        let rest = rest.trim_end_matches(';');
        let parts: Vec<&str> = rest.split(',').map(|x| x.trim()).collect();
        if parts.len() < 5 {
            continue;
        }
        if parts[4] != "0x3c" || !parts[3].starts_with("RZ") {
            continue;
        }
        let reg = |t: &str| -> Option<u32> {
            t.strip_prefix('R')
                .and_then(|d| if d.chars().all(|c| c.is_ascii_digit()) { d.parse::<u32>().ok() } else { None })
        };
        match parts[2]
            .strip_prefix("0x")
            .and_then(|h| u32::from_str_radix(h, 16).ok())
        {
            Some(imm) => {
                let (Some(dst), Some(src)) = (reg(parts[0]), reg(parts[1])) else {
                    continue;
                };
                out.push(((ins.addr / 16) as u32, dst, src, imm, guard));
            }
            None => {
                // mk13: forma rejestrowa A^B (0x3c, trzy rejestry) — osobny
                // 16B rekord 0129: dst@[10]=(d<<6)|1, srcA@[12]=a<<6,
                // srcB@[14]=b<<6; lane bez bitu bitmapy jak 0229 (gold lp1).
                let (Some(dst), Some(src_a), Some(src_b)) =
                    (reg(parts[0]), reg(parts[1]), reg(parts[2]))
                else {
                    continue;
                };
                out_reg.push(((ins.addr / 16) as u32, dst, src_a, src_b, guard));
            }
        }
    }
    (out, out_reg)
}

/// Mercury mk11: instrukcje MMA (HMMA/DMMA/IMMA/...) -> rekord 025a w lane.
/// Model byte-exact (mma_model.py, korpus 15.6k rekordow). Rekord trzyma
/// numery rejestrow D/A/B/C z tekstu SASS (znaki/-NIE istotne, .reuse tez).
/// b8flags (code63/code72) dopelnia main.rs po enkodacji (pole lane->word).
fn merc_mma_scan(instructions: &[Instruction]) -> Vec<(u32, u8, u8, u8, u8, u8, u8)> {
    let mut out = Vec::new();
    let regno = |t: &str| -> Option<u8> {
        let t = t.trim_end_matches(';').trim().trim_start_matches(['-', '+']);
        let t = t.split('.').next().unwrap_or(t);
        if t == "RZ" {
            return Some(255);
        }
        let d = t.strip_prefix('R')?;
        if d.chars().all(|c| c.is_ascii_digit()) {
            d.parse::<u8>().ok()
        } else {
            None
        }
    };
    for ins in instructions {
        let mut toks = ins.raw_text.split_whitespace();
        let mut first = toks.next().unwrap_or("");
        if first.starts_with('@') {
            first = toks.next().unwrap_or("");
        }
        let Some(cls) = crate::mercury::merc_mma_class(first) else {
            continue;
        };
        let rest = toks.collect::<Vec<_>>().join(" ");
        let rest = rest.trim_end_matches(';');
        let parts: Vec<&str> = rest.split(',').map(|x| x.trim()).collect();
        if parts.len() < 4 {
            continue;
        }
        let (Some(d), Some(a), Some(b), Some(c)) =
            (regno(parts[0]), regno(parts[1]), regno(parts[2]), regno(parts[3]))
        else {
            continue;
        };
        out.push(((ins.addr / 16) as u32, cls, d, a, b, c, 0u8));
    }
    out
}

/// mk51: parser operandu R-bank z flagami nvdisasm — zwraca
/// (reg, neg, abs); RZ -> 0x3ff (siatka rekordow (r<<6)|f uzywa 10 bitow);
/// URZ/URn/c[..]/inne -> None (fail-closed jak mk48/49/50).
pub fn merc_f64_reg(t: &str) -> Option<(u16, bool, bool)> {
    let mut t = t.trim().trim_end_matches(';').trim();
    let mut neg = false;
    if let Some(r) = t.strip_prefix('-') {
        neg = true;
        t = r;
    }
    let abs = t.len() > 1 && t.starts_with('|') && t.ends_with('|');
    if abs {
        t = t[1..t.len() - 1].trim();
        if let Some(r) = t.strip_prefix('-') {
            neg = true;
            t = r;
        }
    }
    let t = t.split('.').next().unwrap_or(t); // .reuse itd.
    if t == "RZ" {
        return Some((0x3ff, neg, abs));
    }
    let ds = t.strip_prefix('R')?;
    if !ds.is_empty() && ds.bytes().all(|c| c.is_ascii_digit()) {
        Some((ds.parse::<u16>().ok()?, neg, abs))
    } else {
        None
    }
}

/// mk51: literal imm f64 w stylach nvdisasm ORAZ cubit-print
/// ("1", "+INF"/"-INF", "NAN"/"QNAN", dlugie decymale %.20g).
pub fn merc_f64_lit(t: &str) -> Option<f64> {
    let t = t.trim().trim_end_matches(';').trim();
    if t.is_empty() {
        return None;
    }
    let up = t.to_ascii_uppercase();
    match up.as_str() {
        "INF" | "+INF" | "INFINITY" | "+INFINITY" => return Some(f64::INFINITY),
        "-INF" | "-INFINITY" => return Some(f64::NEG_INFINITY),
        "NAN" | "+NAN" | "-NAN" | "QNAN" | "+QNAN" | "-QNAN" => return Some(f64::NAN),
        _ => {}
    }
    if up.contains('P') || up.contains("0X") {
        return None; // staloprzecinkowe/szesnastkowe poza modelem (korpus: brak)
    }
    t.parse::<f64>().ok()
}

/// mk51: podzial raw_text na (mnemonik, operandy) z pominieciem guarda.
fn merc_f64_split(raw: &str) -> Option<(String, Vec<String>)> {
    let mut toks = raw.split_whitespace();
    let mut first = toks.next().unwrap_or("");
    if first.starts_with('@') {
        first = toks.next().unwrap_or("");
    }
    let rest = toks.collect::<Vec<_>>().join(" ");
    let rest = rest.trim_end_matches(';');
    if rest.is_empty() {
        return None;
    }
    Some((
        first.to_string(),
        rest.split(',').map(|x| x.trim().to_string()).collect(),
    ))
}

/// Mercury mk11+mk51: DMUL/DADD z natychmiastowym f64 -> rekordy
/// 020f120e/020c1e0e. Ostatni operand musi byc literalnym floatem.
/// mk51: (lane, variant, d, a, imm_top32, pred, b7=2*negA+4*absA);
/// zrodlo RZ kodowane jako 0x3ff (korpusowe 0xffc0 bez flagi |2).
pub fn merc_f64imm_scan(
    instructions: &[Instruction],
) -> Vec<(u32, u8, u16, u16, u32, u8, u8)> {
    let mut out = Vec::new();
    for ins in instructions {
        let Some((first, parts)) = merc_f64_split(&ins.raw_text) else {
            continue;
        };
        let variant = if first.starts_with("DMUL") {
            0u8
        } else if first.starts_with("DADD") {
            1u8
        } else {
            continue;
        };
        if parts.len() != 3 {
            continue;
        }
        let Some(immf) = merc_f64_lit(&parts[2]) else {
            continue; // forma reg-reg — bez rekordu (potwierdzenie: mk11-lab)
        };
        let (Some((d, _, _)), Some((a, nega, absa))) =
            (merc_f64_reg(&parts[0]), merc_f64_reg(&parts[1]))
        else {
            continue;
        };
        let imm_top = ((immf.to_bits()) >> 32) as u32;
        let pred = merc_guard_code(ins.guard.as_ref());
        let b7: u8 = (if nega { 2 } else { 0 }) | (if absa { 4 } else { 0 });
        out.push(((ins.addr / 16) as u32, variant, d, a, imm_top, pred, b7));
    }
    out
}

/// mk51: DFMA z natychmiastowym f64 -> rekordy 020d1c0e (imm w ostatnim
/// slocie) / 020d1a0e (imm w srodkowym slocie) w lane.
/// (lane, variant [0=last,1=mid], pred, b7, d, a, b, imm64bits).
/// b7 = 2*negA + 8*negB + 4*absA + 16*absB (merclab/mk51 c9/c10 EXACT).
pub fn merc_dfmaimm_scan(
    instructions: &[Instruction],
) -> Vec<(u32, u8, u8, u8, u16, u16, u16, u64)> {
    let mut out = Vec::new();
    for ins in instructions {
        let Some((first, parts)) = merc_f64_split(&ins.raw_text) else {
            continue;
        };
        if !first.starts_with("DFMA") || parts.len() != 4 {
            continue;
        }
        let Some((d, _, _)) = merc_f64_reg(&parts[0]) else {
            continue;
        };
        let pred = merc_guard_code(ins.guard.as_ref());
        if let (Some((a, n1, ab1)), Some((b, n2, ab2)), Some(immf)) =
            (merc_f64_reg(&parts[1]), merc_f64_reg(&parts[2]), merc_f64_lit(&parts[3]))
        {
            let b7: u8 = (if n1 { 2 } else { 0 })
                | (if n2 { 8 } else { 0 })
                | (if ab1 { 4 } else { 0 })
                | (if ab2 { 16 } else { 0 });
            out.push((
                (ins.addr / 16) as u32,
                0u8,
                pred,
                b7,
                d,
                a,
                b,
                immf.to_bits(),
            ));
        } else if let (Some((a, n1, ab1)), Some(immf), Some((b, n2, ab2))) =
            (merc_f64_reg(&parts[1]), merc_f64_lit(&parts[2]), merc_f64_reg(&parts[3]))
        {
            let b7: u8 = (if n1 { 2 } else { 0 })
                | (if n2 { 8 } else { 0 })
                | (if ab1 { 4 } else { 0 })
                | (if ab2 { 16 } else { 0 });
            out.push((
                (ins.addr / 16) as u32,
                1u8,
                pred,
                b7,
                d,
                a,
                b,
                immf.to_bits(),
            ));
        }
    }
    out
}

fn merc_param_scan(
    instructions: &[Instruction],
) -> (Option<Vec<u32>>, u32, Vec<u32>, bool, u32, u32, Vec<u8>, Vec<(u32, u32, u8, u8, u8)>, Option<u32>, Vec<u32>, bool, Vec<(u32, u32)>, Vec<u8>, Vec<(u32, u8)>) {
    // reg name -> (param idx, idx w puli deskryptorow (pi,mech))
    let mut reg_of: Vec<(String, u32, u32)> = Vec::new();
    let mut order: Vec<u32> = Vec::new();
    let mut write_mask: u32 = 0;
    let mut stg_desc_pos: Vec<u32> = Vec::new();
    let mut bar_predicated = false;
    let mut uniform_mask: u32 = 0; // bit pi: slot zaladowany przez LDCU*
    let mut regpath_mask: u32 = 0; // bit pi: slot zaladowany przez LDC*
    let mut widths: Vec<u8> = Vec::new(); // per-param: max transfer bytes
    // mk10c: per-load rekordy + lane + pula deskryptorow (pi, unif01)
    let mut loads: Vec<(u32, u32, u8, u8, u8)> = Vec::new();
    let mut cbank_lane: Option<u32> = None;
    let mut s2r_lanes: Vec<u32> = Vec::new();
    let mut predmem = false;
    let mut pool: Vec<(u32, u8)> = Vec::new();
    let mut ldgconst: Vec<(u32, u32)> = Vec::new();
    // mk18: lane'y CALL (granice regioni) + flagi per-load + targi atomowe puli
    let mut call_lanes: Vec<u32> = Vec::new();
    let mut load_flags: Vec<u8> = Vec::new();
    let mut atom_pool_hits: std::collections::BTreeSet<(u32, u8)> = std::collections::BTreeSet::new();

    fn note(m: &mut u32, pi: u32) {
        if pi < 32 {
            *m |= 1u32 << pi;
        }
    }
    for ins in instructions {
        // mk13b: tekst roboczy BEZ guarda prowadzacego (@Pn/@!Pn/@UPn) —
        // dest-parse LDC bral dotad nth(1) po surowym tekscie, co dla
        // predykowanych loadow dawalo smiec ("LDC.64" zamiast R2) i gubilo
        // binding STG (d_ifearly_exit/d_ifearly_stg: STG dp=MAX).
        let t_full = ins.raw_text.as_str();
        let t: &str = match t_full.trim_start().strip_prefix('@') {
            Some(rest) => rest
                .split_once(char::is_whitespace)
                .map(|(_, r)| r.trim_start())
                .unwrap_or(t_full),
            None => t_full,
        };
        let lane = (ins.addr / 16) as u32;
        let guard_v: u8 = merc_guard_code(ins.guard.as_ref());
        let base0 = ins.opcode_full.split('.').next().unwrap_or("");
        if base0 == "S2R" {
            s2r_lanes.push(lane);
        }
        if base0 == "CALL" {
            call_lanes.push(lane);
        }
        // LDC / LDCU load z okna parametrow [0x380..]
        let is_ldcu = ins.opcode == "LDCU";
        if ins.opcode == "LDC" || is_ldcu {
            if let Some(cp) = t.find("c[0x0][0x") {
                let hexs = &t[cp + 9..];
                let end = hexs.find(']').unwrap_or(0);
                if let Ok(off) = u32::from_str_radix(&hexs[..end], 16) {
                    if off == 0x358 && is_ldcu && cbank_lane.is_none() {
                        cbank_lane = Some(lane);
                    }
                    if off >= 0x380 {
                        // mk19: rekordy desc sa kluczowane SUROWYM offsetem
                        // (rel = off-0x380), nie indeksem 8B (pi). Dowod
                        // korpusowy join2/join3: 19666/19666 match tail==rel.
                        // pi (rel>>3) zostaje tylko do masek bitowych/widths.
                        let rel = off - 0x380;
                        let pi = rel / 8;
                        let uflag: u8 = if is_ldcu { 1 } else { 0 };
                        // lead operand = dest reg
                        let depth = t.find(',').unwrap_or(t.len());
                        let dest = t[..depth]
                            .split_whitespace()
                            .nth(1)
                            .unwrap_or("")
                            .trim_end_matches(".64")
                            .to_string();
                        // szerokosc transferu
                        let full = ins.opcode_full.as_str();
                        let w: u8 = if full.contains(".128") {
                            16
                        } else if full.contains(".64") {
                            8
                        } else if full.contains(".U16") {
                            2
                        } else if full.contains(".U8") {
                            1
                        } else {
                            4
                        };
                        loads.push((lane, rel, uflag, w, guard_v));
                        // mk18 bit1: load PO ktoregokolwiek CALL (skan jest
                        // w kolejnosci kodu — call_lanes zawiera tylko wczesniejsze).
                        let fl: u8 = if call_lanes.is_empty() { 0 } else { 2 };
                        load_flags.push(fl);
                        // pula deskryptorow (pi, mechanizm) — TYLKO loady
                        // szerokie (>=8B); skalarne (4B) rekordy nie maja
                        // slotu w puli STG-binding (k_stg2: (41,02) bez slota).
                        let pool_idx = if w >= 8 {
                            match pool.iter().position(|&e| e == (rel, uflag)) {
                                Some(k) => k as u32,
                                None => {
                                    pool.push((rel, uflag));
                                    (pool.len() - 1) as u32
                                }
                            }
                        } else {
                            u32::MAX
                        };
                        if !dest.is_empty() {
                            // mk19: reg_of[*.1] = rel (surowy) — klucze puli i
                            // atom-hits potrzebuja exact; maski schodza >>3.
                            reg_of.push((dest.clone(), rel, pool_idx));
                            // wide loads: high-half rejestrow pary (UR7 dla LDCU.64 UR6 itd.)
                            if full.contains(".64") || full.contains(".128") {
                                let num: Option<(bool, u32)> =
                                    if let Some(n) = dest.strip_prefix("UR") {
                                        n.parse::<u32>().ok().map(|v| (true, v))
                                    } else if let Some(n) = dest.strip_prefix('R') {
                                        n.parse::<u32>().ok().map(|v| (false, v))
                                    } else {
                                        None
                                    };
                                if let Some((is_u, n)) = num {
                                    let pfx = if is_u { "UR" } else { "R" };
                                    reg_of.push((format!("{}{}", pfx, n + 1), rel, pool_idx));
                                }
                            }
                        }
                        if is_ldcu {
                            note(&mut uniform_mask, pi);
                        } else {
                            note(&mut regpath_mask, pi);
                        }
                        if (pi as usize) >= widths.len() {
                            widths.resize(pi as usize + 1, 0);
                        }
                        if widths[pi as usize] < w {
                            widths[pi as usize] = w;
                        }
                    }
                }
            }
        }
        // mk13: LDG.E.CONSTANT przez desc[URx][Rn.64] = osobny klucz puli
        // (pi, 2) w kolejnosci kodu — nvcc numeruje sloty STG z tym wpisem
        // (gold v_ldg_u64: STG pi1 -> s=2, bo LDG.C@3 = (pi0,2) -> s=1).
        if base0 == "LDG" && ins.opcode_full.contains(".CONSTANT") {
            if let Some(lb) = t.rfind('[') {
                let inner = &t[lb + 1..t[lb + 1..].find(']').map(|e| lb + 1 + e).unwrap_or(t.len())];
                let root: String = inner
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric())
                    .collect();
                if let Some((_, pi, pidx)) = reg_of.iter().find(|(rn, _, _)| *rn == root) {
                    if *pidx != u32::MAX {
                        let key = (*pi, 2u8);
                        if !pool.contains(&key) {
                            pool.push(key);
                        }
                        ldgconst.push((lane, *pi));
                    }
                }
            }
        }
        // alias-flow UR/R: dest <- zrodla sledzone (shape IADD3 R2, P0, PT, R0, UR6, RZ)
        if matches!(
            base0,
            "MOV" | "IMAD" | "IADD3" | "LEA" | "SHF" | "SEL" | "UIADD3" | "UMOV" | "IMNMX"
                | "PRMT" | "IABS" | "SHFL"
        ) {
            if let Some(ci) = t.find(',') {
                let dest = t[..ci]
                    .split_whitespace()
                    .last()
                    .unwrap_or("")
                    .trim_matches(|c: char| !c.is_alphanumeric());
                if !dest.is_empty()
                    && (dest.starts_with('R') || dest.starts_with('U'))
                    && dest.chars().skip(1).all(|c| c == 'Z' || c.is_ascii_digit())
                {
                    let srcs = &t[ci + 1..];
                    for (rn, pi, pidx) in &reg_of {
                        // pasuj gole wystapienie tokenu rejestru w operandach zrodlowych
                        let mut hit = false;
                        for m in srcs.match_indices(rn.as_str()) {
                            let at = m.0;
                            let after = srcs[at + rn.len()..].chars().next();
                            let ok_end = after.map(|c| !c.is_ascii_digit()).unwrap_or(true);
                            if ok_end {
                                hit = true;
                                break;
                            }
                        }
                        if hit {
                            reg_of.push((dest.to_string(), *pi, *pidx));
                            break;
                        }
                    }
                }
            }
        }
        // memory-desc use: desc[URx][Ry.64] / plain [Rx]
        let is_mem = matches!(
            base0,
            "LDG" | "STG" | "ATOMG" | "ATOMS" | "RED" | "REDG" | "LDS" | "STS" | "LD" | "ST"
        );
        let mut stg_binding: Option<u32> = None;
        if is_mem {
            if guard_v != 0xf8 {
                predmem = true;
            }
            for (rn, pi, pidx) in &reg_of {
                // uzycie jako baza adresu: [Rx ...] lub desc[...Rx...]
                let needle1 = format!("[{}.", rn);
                let needle2 = format!("[{},", rn);
                let needle3 = format!("[{}]", rn);
                let used = t.contains(&needle1) || t.contains(&needle2) || t.contains(&needle3);
                let opi = (*pi >> 3).min(31);
                if used && !order.contains(&opi) {
                    order.push(opi);
                }
                // mk10c: write-bit przy kazdym store-uzyciu (nie tylko przy
                // pierwszym) — r2_wr dowod, ze read->write param ginie inaczej.
                if used
                    && matches!(base0, "STG" | "ATOMG" | "ATOMS" | "RED" | "REDG" | "STS" | "ST")
                {
                    write_mask |= 1u32 << (*pi >> 3).min(31);
                }
                // mk18: atom-family (24d/24e rekordy) zjada adres -> oznacz
                // KLUCZ puli (pi, mech) — odporny na wstawki ldgconst (pi,2).
                if used
                    && *pidx != u32::MAX
                    && matches!(base0, "ATOMG" | "ATOMS" | "RED" | "REDG")
                {
                    if let Some(&(_, mech)) = pool.get(*pidx as usize) {
                        atom_pool_hits.insert((*pi, mech));
                    }
                }
                // mk10c: STG binding -> indeks PULI deskryptorow (pi, mech)
                // zrodlowego loadu roota adresowego (nie pozycja param-queue).
                // mk13b: NIE pushowac tutaj (aliasowe duplikaty reg_of dawaly
                // wiele wpisow na STG) — jeden binding per instrukcja, patrz
                // nizej.
                if used
                    && matches!(base0, "STG" | "ATOMG" | "ATOMS" | "RED" | "REDG")
                    && stg_binding.is_none()
                {
                    stg_binding = Some(*pidx);
                }
            }
            // mk13b: nvcc numeruje slot per INSTRUKCJA STG — dokladnie jeden
            // wpis. Root adresu = ostatni nawias kwadratowy (jak mk_gold /
            // main-rs mirror); fallback = binding z petli, inaczej UNKNOWN.
            if matches!(base0, "STG" | "ATOMG" | "ATOMS" | "RED" | "REDG") {
                let mut binding = if let Some(lb) = t.rfind('[') {
                    let end = t[lb..].find(']').map(|e| lb + e).unwrap_or(t.len());
                    let root: String = t[lb + 1..end]
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric())
                        .collect();
                    reg_of
                        .iter()
                        .find(|(rn, _, _)| *rn == root)
                        .map(|(_, _, p)| *p)
                        .or(stg_binding)
                        .unwrap_or(u32::MAX)
                } else {
                    stg_binding.unwrap_or(u32::MAX)
                };
                // mk18: STG po granicy CALL — nvcc wiąże slot z PIERWSZYM
                // wpisem puli tego samego pi (q_tail_call: post-CALL reload
                // REG dostaje s=0 = wpis UNIF; v_a/p_call: flow juz dawalo 0).
                if base0 == "STG" && !call_lanes.is_empty() && binding != u32::MAX {
                    if let Some((pi_of, _)) = pool.get(binding as usize) {
                        if let Some(first) = pool.iter().position(|&(pp, _)| pp == *pi_of) {
                            binding = first as u32;
                        }
                    }
                }
                // mk18: wpis slota TYLKO dla STG (mk_gold/main.rs mirror
                // dyscyplina: b0==STG). Rekordy atomowe maja slot wlasny
                // (build_atom_rec z krotki) — push dla nich przesuwal
                // indeksy stg_i vs manifest (p_atomg E2E off-by-one).
                if base0 == "STG" {
                    stg_desc_pos.push(binding);
                }
            }
        }
        if base0 == "BAR" && ins.guard.is_some() {
            bar_predicated = true;
        }
    }
    (if order.is_empty() { None } else { Some(order) },
     write_mask,
     stg_desc_pos,
     bar_predicated,
     uniform_mask,
     regpath_mask,
     widths,
     loads,
     cbank_lane,
     s2r_lanes,
     predmem,
     ldgconst,
     load_flags,
     atom_pool_hits.into_iter().collect())
}

/// mk40 (korpus sm_100; analysis/merclab/mk40/stgfields.rs, EXACT fits):
/// slownik klas mini-rekordow 4B emitowanych per-lane. Rekord = LE u32
/// bajtow b0..b3. Wszystkie te klasy maja w korpusie bit bitmapy = 0
/// (rekord zastepuje wezel t4); klasy untracked (BREAK/PREEXIT/BAR) bit=0
/// z definicji tracked-listy.
pub fn merc_mini2_scan(instructions: &[Instruction]) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for ins in instructions {
        let lane = (ins.addr / 16) as u32;
        let full = ins.opcode_full.as_str();
        let m = match ins.opcode.as_str() {
            "FFMA2" => 0x26140d42,                    // 42 0d 14 26 (EXACT)
            "HADD2" => 0x0a260c41,                    // 41 0c 26 0a (HADD2+HADD2.BF16 EXACT)
            "BREAK" => 0x0a000541,                    // 41 05 00 0a (EXACT, untracked)
            "PREEXIT" => 0x0a026241,                  // 41 62 02 0a (EXACT, untracked)
            "BAR" if full.contains(".ARV") => 0x16124741, // 41 47 12 16 (EXACT, untracked)
            // mk43: pisownia nvdisasm (mk40): "F2I.U64.TRUNC"; printer cubit
            // emituje suffiksy w odwrotnej kolejnosci: "F2I.[FTZ.][NTZ.]TRUNC.U64".
            "F2I" if full.contains("TRUNC") && full.ends_with(".U64") => 0x45241241, // 41 12 24 45
            "F2F" if full.starts_with("F2F.BF16.F32") => 0x0a0e1241,  // 41 12 0e 0a
            // mk43: F2FP TF32 (cubit: "F2FP.F32.PACK_B.TF32"; nvdisasm:
            // F2FP.TF32.F32.PACK) — EXACT 384==384 na 2 kernelach
            // cutlass_80_tensorop (korpus); bit t4 kasowany jak reszta mini2.
            "F2FP" if full.contains("TF32") => 0x0b6c1241,
            "IMAD" if full == "IMAD.WIDE.U32.X" => 0x06342042,        // 42 20 34 06
            "UIMAD" if full == "UIMAD.WIDE.U32.X" => 0x06382042,      // 42 20 38 06
            _ => continue,
        };
        out.push((lane, m));
    }
    out.sort_by_key(|&(l, _)| l);
    out
}

/// mk42 (dekod mk37/mk38 + domkniecie w mk42/edge9..edge13): kazdy LD
/// (generic, base "LD") z adresem w formie desc[URm][Ry.64(+off)] dostaje
/// rekord edge 02 22 32 32. Selekcja EXACT (1721/1721 kerneli korpusu
/// sm_100; duplikaty loop-instancji zgodne). LD bez desc-bracket: brak
/// rekordu (10 kerneli gate-fail w korpusie = LD plain). Rekord niesie
/// (X,Y,C,off) z gridem i stala per-kernel [19:21)=(maxDescUR<<6)|2.
/// Era sm_103a: brak nosnikow LD-desc w dostepnych probkach (FA4, lab-119
/// nie zawieraja LD.E w ogole) — regula bez bramki ery (otwarty temat).
pub fn merc_edge_ld_scan(
    instructions: &[Instruction],
) -> (Vec<(u32, u8, u8, u8, u8, u16, u16, u8, u32)>, u16) {
    let mut out = Vec::new();
    let mut maxur: u16 = 0;
    for ins in instructions {
        let t = ins.raw_text.as_str();
        // max UR w desc[URn] (wszystkie instrukcje kernela)
        let mut p = 0usize;
        while let Some(pos) = t[p..].find("desc[UR") {
            let s2 = &t[p + pos + 7..];
            let k = s2.bytes().take_while(|c| c.is_ascii_digit()).count();
            if k > 0 {
                if let Ok(v) = s2[..k].parse::<u16>() {
                    maxur = maxur.max(v);
                }
            }
            p += pos + 7 + k.max(1);
        }
        if ins.opcode != "LD" || !t.contains("desc[UR") {
            continue;
        }
        let full = ins.opcode_full.as_str();
        let c: u8 = if full.contains(".128") {
            7
        } else if full.contains(".64") {
            3
        } else {
            1
        };
        let b6: u8 = if full.contains(".U8") {
            0x10
        } else if full.contains(".S8") {
            0x11
        } else if full.contains(".U16") {
            0x12
        } else if full.contains(".S16") {
            0x13
        } else if full.contains(".128") {
            0x16
        } else if full.contains(".64") {
            0x15
        } else {
            0x14
        };
        let (b7, b8) = if full.contains("STRONG.SYS") {
            (0x10u8, 0x01u8)
        } else {
            (0x08u8, 0x00u8)
        };
        // dst: token "R<num>" miedzy op-tokenem a pierwszym przecinkiem
        let x: u16 = {
            let mut it = t.splitn(2, ',');
            let head = it.next().unwrap_or("");
            let toks: Vec<&str> = head.split_whitespace().collect();
            let dst = toks.last().copied().unwrap_or("");
            let dst = dst.trim_start_matches(['!', '-', '|', '@']).trim();
            let ddst = dst.strip_prefix('R').and_then(|r| {
                let r = r.trim_end_matches(';');
                if !r.is_empty() && r.bytes().all(|c| c.is_ascii_digit()) {
                    r.parse::<u16>().ok()
                } else {
                    None
                }
            });
            match ddst {
                Some(v) => v,
                None => continue, // RZ / UR / nieznany — korpus: brak rekordu
            }
        };
        // bracket adresu: grupa "[" tuz po zamknieciu desc[URm]
        let dp = match t.find("desc[UR") {
            Some(v) => v,
            None => continue,
        };
        let dclose = match t[dp..].find(']') {
            Some(v) => dp + v,
            None => continue,
        };
        let rest = &t[dclose + 1..];
        if !rest.starts_with('[') {
            continue;
        }
        let gclose = match rest.find(']') {
            Some(v) => v,
            None => continue,
        };
        let inner = &rest[1..gclose];
        let ib = inner.as_bytes();
        if ib.first() != Some(&b'R') {
            continue;
        }
        let k = ib.iter().skip(1).take_while(|c| c.is_ascii_digit()).count();
        if k == 0 {
            continue;
        }
        let y: u16 = match inner[1..1 + k].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let off: u32 = if let Some(pl) = inner[1 + k..].find('+') {
            let tail = inner[1 + k + pl + 1..].trim();
            if tail.starts_with('U') || tail.starts_with("UR") {
                continue; // [Ry+URn] — poza modelem (korpus: brak przypadkow)
            }
            let neg = tail.starts_with('-');
            let tt = tail.trim_start_matches('-');
            let radix = if tt.starts_with("0x") { 16 } else { 10 };
            match i64::from_str_radix(tt.trim_start_matches("0x"), radix) {
                Ok(v) => (if neg { -v } else { v }) as u32,
                Err(_) => continue,
            }
        } else {
            0
        };
        let lane = (ins.addr / 16) as u32;
        let b4 = merc_guard_code(ins.guard.as_ref());
        out.push((lane, b4, b6, b7, b8, x, y, c, off));
    }
    out.sort_by_key(|e| e.0);
    (out, maxur)
}

/// mk50: rekordy 02 22 1e 32 = krawedzie DEF-USE dla LDG z deskryptorem w
/// kernelach *annotated_ptr* (cuda::annotated_ptr — korpusowo tylko
/// libcublas.so.72 sm_100; cuds_symv_*). Bramka dwustopniowa (c8/c8b):
///  1) nazwa kernela zawiera "annotated_ptr" (c8: bez tego kroku 133
///     falszywych predykcji w cusolver.438/456 + cublasLt.567 — lane'y
///     tekstowo identyczne; zero wspolnych kerneli z rodzina 02223232);
///  2) desc[URm] uzywany w formie desc WYLACZNIE przez lane'y bazowe LDG
///     (c7b: 238 UR-ow LDG-only maja rekordy; 40+32 dzielone ze
///     STG/REDG/LDGSTS — zadne — oraz 68 LDCU-only tez nie; regula pelna
///     daje EXACT 72/72 z porzadkiem lane-rosnaco).
/// Payload: jak merc_edge_ld, poza b6 = 16*(log2B-2)+0x40 (0x40/0x50/0x60
/// dla 4B/8B/16B; inne formy LDG (.U8/.U16/.CONSTANT/...) — niewiadome,
/// fail-closed bez rekordu) oraz V = desc-UR lane'u (NIE max globalny).
pub fn merc_edge_ldg_scan(
    name: &str,
    instructions: &[Instruction],
) -> Vec<(u32, u8, u8, u16, u16, u8, u16, u32)> {
    let mut out = Vec::new();
    if !name.contains("annotated_ptr") {
        return out;
    }
    let mut ur_ldg = std::collections::HashSet::<u16>::new();
    let mut ur_other = std::collections::HashSet::<u16>::new();
    for ins in instructions {
        let t = ins.raw_text.as_str();
        let mut p = 0usize;
        while let Some(pos) = t[p..].find("desc[UR") {
            let s2 = &t[p + pos + 7..];
            let k = s2.bytes().take_while(|c| c.is_ascii_digit()).count();
            if k > 0 {
                if let Ok(v) = s2[..k].parse::<u16>() {
                    if ins.opcode == "LDG" {
                        ur_ldg.insert(v);
                    } else {
                        ur_other.insert(v);
                    }
                }
            }
            p += pos + 7 + k.max(1);
        }
    }
    let ldg_only: std::collections::HashSet<u16> =
        ur_ldg.difference(&ur_other).copied().collect();
    if ldg_only.is_empty() {
        return out;
    }
    for ins in instructions {
        if ins.opcode != "LDG" {
            continue;
        }
        let t = ins.raw_text.as_str();
        if !t.contains("desc[UR") {
            continue;
        }
        let full = ins.opcode_full.as_str();
        let (b6, c): (u8, u8) = if full.contains(".128") {
            (0x60, 7)
        } else if full.contains(".64") {
            (0x50, 3)
        } else if full == "LDG.E" {
            (0x40, 1)
        } else {
            continue; // LDG.E.U8/.U16/.S8/.STRONG itd. — korpusowo bez rekordow
        };
        let x: u16 = {
            let mut it = t.splitn(2, ',');
            let head = it.next().unwrap_or("");
            let toks: Vec<&str> = head.split_whitespace().collect();
            let dst = toks.last().copied().unwrap_or("");
            let dst = dst.trim_start_matches(['!', '-', '|', '@']).trim();
            match dst.strip_prefix('R').and_then(|r| {
                let r = r.trim_end_matches(';');
                if !r.is_empty() && r.bytes().all(|c| c.is_ascii_digit()) {
                    r.parse::<u16>().ok()
                } else {
                    None
                }
            }) {
                Some(v) => v,
                None => continue,
            }
        };
        let dp = match t.find("desc[UR") {
            Some(v) => v,
            None => continue,
        };
        let v: u16 = {
            let s2 = &t[dp + 7..];
            let k = s2.bytes().take_while(|c| c.is_ascii_digit()).count();
            if k == 0 {
                continue;
            }
            match s2[..k].parse() {
                Ok(v) => v,
                Err(_) => continue,
            }
        };
        if !ldg_only.contains(&v) {
            continue;
        }
        let dclose = match t[dp..].find(']') {
            Some(v2) => dp + v2,
            None => continue,
        };
        let rest = &t[dclose + 1..];
        if !rest.starts_with('[') {
            continue;
        }
        let gclose = match rest.find(']') {
            Some(v2) => v2,
            None => continue,
        };
        let inner = &rest[1..gclose];
        let ib = inner.as_bytes();
        if ib.first() != Some(&b'R') {
            continue;
        }
        let k = ib.iter().skip(1).take_while(|c| c.is_ascii_digit()).count();
        if k == 0 {
            continue;
        }
        // wymagamy formy .64 (korpus: wszystkie rekordy maja pary .64)
        if !inner[1 + k..].starts_with(".64") {
            continue;
        }
        let y: u16 = match inner[1..1 + k].parse() {
            Ok(v2) => v2,
            Err(_) => continue,
        };
        let off: u32 = if let Some(pl) = inner[1 + k..].find('+') {
            let tail = inner[1 + k + pl + 1..].trim();
            if tail.starts_with('U') {
                continue; // [Ry.64+URn] — poza modelem
            }
            let neg = tail.starts_with('-');
            let tt = tail.trim_start_matches('-');
            let radix = if tt.starts_with("0x") { 16 } else { 10 };
            match i64::from_str_radix(tt.trim_start_matches("0x"), radix) {
                Ok(v3) => (if neg { -v3 } else { v3 }) as u32,
                Err(_) => continue,
            }
        } else {
            0
        };
        let lane = (ins.addr / 16) as u32;
        let b4 = merc_guard_code(ins.guard.as_ref());
        out.push((lane, b4, b6, x, y, c, v, off));
    }
    out.sort_by_key(|e| e.0);
    out
}

/// mk40: store-matrix (mk40/stgfields): lane'y ST.E (rekord 0238 b2=0x2a,
/// b3=0x32) i STL (b2=0x20, b3=0x06). STG zostaje na legacy merc_stg_*.
/// Krotki: (lane, cls, wsel, areg, dur, dreg, imm, b4) z dokladnoscia do
/// nieznanych pol opisanych w eiattr.rs: merc_store2.
pub fn merc_store2_scan(instructions: &[Instruction]) -> Vec<(u32, u8, u8, u16, u16, u16, i32, u8)> {
    let mut out = Vec::new();
    for ins in instructions {
        let cls: u8 = match ins.opcode.as_str() {
            "ST" => 1,
            "STL" => 2,
            _ => continue,
        };
        let lane = (ins.addr / 16) as u32;
        let full = ins.opcode_full.as_str();
        if full.contains("ENL2") {
            continue; // mk40-park: ENL2.256 (28 rekordow w korpusie)
        }
        let wsel: u8 = if full.contains(".128") {
            4
        } else if full.contains(".64") {
            3
        } else if full.contains(".U16") || full.contains(".S16") {
            1
        } else if full.contains(".U8") || full.contains(".S8") {
            0
        } else {
            2
        };
        // parse operandow z raw_text: adres = ostatnia grupa [...]
        let t = ins.raw_text.as_str();
        let mut dur: u16 = 0xffff;
        let mut areg: u16 = 0xffff;
        let mut dreg: u16 = 0x3ff;
        let mut imm: i32 = 0;
        if let Some(dp) = t.find("desc[UR") {
            let rest = &t[dp + 7..];
            if let Some(end) = rest.find(']') {
                if let Ok(v) = rest[..end].trim().parse::<u16>() {
                    dur = v.min(0x3ff);
                }
            }
        }
        if let Some(lb) = t.rfind('[') {
            if let Some(rb) = t[lb..].find(']') {
                let inner = &t[lb + 1..lb + rb];
                // token R<num> na poczatku (np. "R2.64+0x4", "R98", "R9+UR4")
                let bytes = inner.as_bytes();
                if bytes.first() == Some(&b'R') {
                    let mut k = 1;
                    while k < bytes.len() && bytes[k].is_ascii_digit() {
                        k += 1;
                    }
                    if let Ok(v) = inner[1..k].parse::<u16>() {
                        areg = v.min(0x3ff);
                    }
                }
                // imm: "+0x.." lub "+-0x.." (bez UR-skladnika)
                if let Some(pl) = inner.rfind('+') {
                    let tail = &inner[pl + 1..];
                    if !tail.starts_with('U') {
                        let tail = tail.trim();
                        let neg = tail.starts_with('-');
                        let tt = tail.trim_start_matches('-');
                        if let Ok(v) = i32::from_str_radix(
                            tt.trim_start_matches("0x"),
                            if tt.starts_with("0x") { 16 } else { 10 },
                        ) {
                            imm = if neg { -v } else { v };
                        }
                    }
                }
                // dreg: pierwszy token R<num>|RZ po zamykajacym ']'
                let after = &t[lb + rb + 1..];
                if let Some(cm) = after.find(',') {
                    let tok = after[cm + 1..]
                        .split(',')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .trim_end_matches(';');
                    if tok == "RZ" {
                        dreg = 0x3ff;
                    } else if let Some(rn) = tok.strip_prefix('R') {
                        if let Ok(v) = rn.parse::<u16>() {
                            dreg = v.min(0x3ff);
                        }
                    }
                }
            }
        }
        let b4: u8 = match &ins.guard {
            Some(g) if g.pred != 7 => {
                let mut v = g.pred << 3;
                if g.uniform {
                    v |= 2;
                }
                if g.negated {
                    v |= 1;
                }
                v
            }
            _ => 0xf8,
        };
        out.push((lane, cls, wsel, areg, dur, dreg, imm, b4));
    }
    out.sort_by_key(|r| r.0);
    out
}

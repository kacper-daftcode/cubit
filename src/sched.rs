//! Instruction-reordering scheduler pass (M4.5/BARRACUDA b1):
//! plan (permutation) -> legality check -> apply.
//!
//! M4.5 scope: mode "identity" only. The pass builds the dependency graph
//! any future reordering must respect, then applies the ZERO permutation and
//! emits the input byte-verbatim. The machine-checked content (mirroring the
//! M4.1 RA identity doctrine) is:
//!   * every instruction was classified (register roles from M3.5 data,
//!     predicate roles Strict-mode M2, ctrl class from the active ISA
//!     table) -- anything unknown fails the run closed;
//!   * the dependency graph was CONSTRUCTED and the identity permutation was
//!     verified against EVERY edge by the same checker a later mutating
//!     mode must pass (`verify_permutation`);
//!   * zero instructions moved (machine-counted, not claimed).
//!
//! Dependency semantics (what a legal permutation must preserve):
//!   * RAW/WAW/WAR on the R and UR domains (reg_liveness transfer roles;
//!     RZ/URZ sinks are already excluded there) and on the P and UP
//!     domains (pred_liveness Strict mode -- the documented superset);
//!   * a conservative MEMORY chain over the read/write memory classes
//!     (LDG/STG/LDS/STS/LDL/STL/generic/atomics/TEX/LDGSTS): consecutive
//!     memory ops stay ordered (aliasing undecidable statically at this
//!     layer). Constant-bank reads (LDC family) are NOT in the chain --
//!     c[..] is read-only and cannot alias the writable spaces;
//!   * ANCHORs, which no instruction may cross: control flow (BRA/CALL/
//!     RET/EXIT/BSSY/BSYNC...), barriers (BAR/DEPBAR...), NOP, hand-sched
//!     instructions (`[B..:R..:W..:Y:S..]` prefix = owner-authored schedule),
//!     and the LDCU family (constant-uniform epoch/discriminator risk,
//!     design.md sec.7: relative positions of LDCU vs desc[UR] users are
//!     load-bearing). Anchor edges are emitted against the surrounding
//!     anchor pair (previous-anchor -> i -> next-anchor plus the
//!     consecutive-anchor chain), which transitivity lifts to full
//!     no-crossing at O(n) edges.
//!
//! Deferred (M4.6): non-identity modes (windowed list scheduler), ctrl-word
//! re-derivation after moves (reallocate_barriers + scoreboard verify),
//! m9 cost-plugin oracle. The ctrl words ride WITH their instructions in
//! identity mode; after any real move they must be re-derived (see
//! design.md sec.5), which is why `scoreboard_bound` is counted in the
//! report now.

use crate::ctrl_class::CtrlClass;
use crate::ir::Instruction;
use crate::pred_liveness::{self, XferMode};
use crate::reg_liveness;
use crate::table::IsaTable;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Scheduling mode. M4.5 gates `identity`; the mutating mode arrives in
/// M4.6 (windowed list scheduler with the m9 cost plugin).
#[derive(Debug, Clone)]
pub enum SchedMode {
    Identity,
}

/// CLI/pyo3 mode spelling.
pub fn parse_mode_kind(s: &str) -> Result<&'static str> {
    match s {
        "identity" => Ok("identity"),
        other => bail!(
            "sched: unknown mode '{other}' (implemented: 'identity' -- M4.5; \
             windowed list scheduling is M4.6)"
        ),
    }
}

/// Dependency-edge classes. R/UR/P/UP triples come straight from the
/// transfer-role data; `MemChain` and `Anchor` are the conservative
/// semantic orderings documented in the module header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EdgeClass {
    RawR,
    WarR,
    WawR,
    RawUr,
    WarUr,
    WawUr,
    RawP,
    WarP,
    WawP,
    RawUp,
    WarUp,
    WawUp,
    MemChain,
    Anchor,
}

impl EdgeClass {
    pub fn name(&self) -> &'static str {
        match self {
            Self::RawR => "raw_r",
            Self::WarR => "war_r",
            Self::WawR => "waw_r",
            Self::RawUr => "raw_ur",
            Self::WarUr => "war_ur",
            Self::WawUr => "waw_ur",
            Self::RawP => "raw_p",
            Self::WarP => "war_p",
            Self::WawP => "waw_p",
            Self::RawUp => "raw_up",
            Self::WarUp => "war_up",
            Self::WawUp => "waw_up",
            Self::MemChain => "mem_chain",
            Self::Anchor => "anchor",
        }
    }
}

/// Dependency graph over one kernel's instruction stream.
#[derive(Debug, Clone)]
pub struct DepGraph {
    pub n: usize,
    /// (producer_or_earlier, consumer_or_later, class); deduped, sorted.
    pub edges: Vec<(u32, u32, EdgeClass)>,
    /// Indices the anchor policy froze (boundary set).
    pub anchors: Vec<u32>,
    pub n_hand_sched: usize,
    /// Instructions whose ctrl word participates in the scoreboard
    /// (wait_mask != 0 or a real barrier assigned) -- M4.6 must re-derive
    /// these after any move; counted now for visibility.
    pub n_scoreboard_bound: usize,
    /// Peak live sets (pressure data for the M4.6 cost plugin).
    pub live_peak_r: usize,
    pub live_peak_ur: usize,
    /// Instructions classified via the explicit base-op fallback (table
    /// gap census; tripwire for the sm103a ctrl_class completion).
    pub n_class_fallback: usize,
}

/// Per-kernel pass report (JSON-serializable for the CLI --report stream).
#[derive(Debug, Clone, Serialize)]
pub struct KernelSchedReport {
    pub name: String,
    pub n_ins: usize,
    pub anchors: usize,
    pub hand_sched: usize,
    pub scoreboard_bound: usize,
    pub edges_total: usize,
    pub edges_by_class: BTreeMap<String, usize>,
    pub live_peak_r: usize,
    pub live_peak_ur: usize,
    /// Instructions whose position changed. Invariant 0 in identity mode.
    pub moved: usize,
    /// Explicit base-op fallback classifications (table-gap census).
    pub class_fallback: usize,
    /// Fail-closed signals (run refuses to produce output when non-empty;
    /// recorded for the report on the validation path).
    pub unknown_ops: Vec<String>,
    pub unknown_classes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SchedRunReport {
    pub mode: String,
    pub kernels: Vec<KernelSchedReport>,
}

/// Full pass output. `out_text` is byte-verbatim input in identity mode;
/// mutating modes (M4.6) will route through an emitter with a re-parse
/// proof, like RA's splice emitter (M4.2).
pub struct SchedRun {
    pub file: crate::sass_file::SassFile,
    pub out_text: String,
    pub report: SchedRunReport,
}

/// Raw/WAW/WAR edges for one register domain. `defs`/`uses` are the
/// transfer sets per instruction (any of R/UR/P/UP).
fn domain_edges(
    n: usize,
    defs: &dyn Fn(usize) -> BTreeSet<u8>,
    uses: &dyn Fn(usize) -> BTreeSet<u8>,
    raw: EdgeClass,
    war: EdgeClass,
    waw: EdgeClass,
    out: &mut BTreeSet<(u32, u32, EdgeClass)>,
) {
    let mut last_def: HashMap<u8, u32> = HashMap::new();
    let mut readers: HashMap<u8, Vec<u32>> = HashMap::new();
    for i in 0..n {
        let iu = i as u32;
        for r in uses(i) {
            if let Some(&d) = last_def.get(&r) {
                out.insert((d, iu, raw));
            }
            readers.entry(r).or_default().push(iu);
        }
        for r in defs(i) {
            if let Some(&d) = last_def.get(&r) {
                out.insert((d, iu, waw));
            }
            if let Some(rs) = readers.get(&r) {
                for &u in rs {
                    // self-dependency (instruction reads and writes the same
                    // register) is inherent, not an ordering constraint.
                    if u != iu {
                        out.insert((u, iu, war));
                    }
                }
            }
            last_def.insert(r, iu);
            readers.insert(r, Vec::new());
        }
    }
}

/// True for ctrl classes that read or write an aliasing-capable memory
/// space (conservative program-order chain members).
fn is_mem_chain_class(cc: &CtrlClass) -> bool {
    matches!(
        cc,
        CtrlClass::Ldg
            | CtrlClass::LdGeneric
            | CtrlClass::Lds
            | CtrlClass::Ldl
            | CtrlClass::Stg
            | CtrlClass::StGeneric
            | CtrlClass::Sts
            | CtrlClass::Stl
            | CtrlClass::Atomg
            | CtrlClass::Atoms
            | CtrlClass::Ldgsts
            | CtrlClass::Tex
    )
}

/// Base-op fallback classes for rows the active table does not classify
/// (M4.5 doctrine: classification is load-bearing data, so a fallback must
/// be EXPLICIT and anchored in the fleet's production knowledge -- the
/// opcode lists scheduling_pass already runs on silicon-published kernels
/// -- never silent). Every fallback hit is counted in the report
/// (`class_fallback` tripwire); the census feeds the sm103a table ctrl_class
/// completion tracked as M4-open/b4-follow-up.
/// Members semantic-only: MEM = reads/writes an aliasing-capable space
/// (constant-bank reads LDC are NOT members); ANCHOR = control flow /
/// barrier-sync / NOP / LDCU-family (c[0x0] uniform epoch, design.md sec.7).
pub fn fallback_class(ins: &Instruction) -> Option<CtrlClass> {
    const MEM: &[&str] = &[
        "LDG", "LDGX", "LD", "LDS", "LDSM", "LDTM", "LDL", "LDGSTS", "LDGDEPBAR",
        "ST", "STG", "STS", "STL", "STTM", "STAS",
        "ATOM", "ATOMS", "ATOMG", "RED", "REDG",
        "UTMALDG", "UTMASTG", "UTMAREDG", "STSM", "UTCATOMSWS",
        "TEX", "TLD", "TXQ",
    ];
    const ANCHOR: &[&str] = &[
        // control flow (fixes block boundaries)
        "BRA", "BRX", "BRXU", "CALL", "JMP", "JMX", "JMXU", "RET", "EXIT",
        "PREEXIT", "BREAK", "BPT", "RPCMOV",
        // barriers / sync / fences / cache control
        "BAR", "DEPBAR", "MEMBAR", "ERRBAR", "CGAERRBAR", "FENCE", "CCTL",
        "BSSY", "BSYNC", "WARPSYNC", "ACQBULK", "ELECT", "USETMAXREG",
        // cluster/tensor-memory sync & administrative barriers
        "SYNCS", "UCGABAR", "UTCBAR", "UTMACCTL", "UTMACMDFLUSH", "UTMAPF",
        "ENDCOLLECTIVE",
        // static-issue nops / timing
        "NOP", "NANOSLEEP", "YIELD", "KILL",
        // constant-uniform epoch (prolog descriptor/table reloads)
        "LDCU", "ULDC",
    ];
    let op = ins.opcode.as_str();
    if MEM.contains(&op) {
        // Map store-ish bases to the store class; loads to their load class.
        // The sched pass consumes only the two predicates (mem-chain /
        // anchor), so the exact class returned here is documentary.
        return Some(match op {
            "ST" | "STG" => CtrlClass::Stg,
            "STS" => CtrlClass::Sts,
            "STL" => CtrlClass::Stl,
            "LDL" => CtrlClass::Ldl,
            "LDS" | "LDSM" => CtrlClass::Lds,
            "ATOM" | "ATOMG" | "RED" | "REDG" => CtrlClass::Atomg,
            "ATOMS" => CtrlClass::Atoms,
            "TEX" | "TLD" | "TXQ" => CtrlClass::Tex,
            "LDGSTS" | "LDGDEPBAR" => CtrlClass::Ldgsts,
            _ => CtrlClass::Ldg,
        });
    }
    if ANCHOR.contains(&op) {
        return Some(match op {
            "LDCU" | "ULDC" => CtrlClass::Ldcu,
            "NOP" => CtrlClass::Nop,
            "EXIT" => CtrlClass::ExitStatic,
            "BAR" | "DEPBAR" | "MEMBAR" | "ERRBAR" | "CGAERRBAR" | "FENCE" | "CCTL"
            | "WARPSYNC" | "ACQBULK" | "ELECT" | "USETMAXREG" => CtrlClass::Barrier,
            _ => CtrlClass::CtrlFlow,
        });
    }
    // Data-processing base ops whose rows the table may not classify; none
    // of them touches memory-order or control anchoring, so AluSimple is the
    // truthful neutral class for THIS pass's two predicates.
    const NEUTRAL_ALU: &[&str] = &[
        "UIMAD", "UIADD3", "ULOP3", "ULEA", "UISETP", "USEL", "UMOV", "USHF",
        "UPLOP3", "UPRMT", "UIDP", "VIADD", "VIMNMX", "VIADDMNMX", "VIMNMX3",
        "IMAD", "IADD3", "LOP3", "LEA", "ISETP", "SEL", "MOV", "SHF", "PRMT", "IMNMX",
        "FADD", "FMUL", "FFMA", "HFMA2", "HMUL2", "HADD2", "HSET2", "HSETP2",
        "DFMA", "DMUL", "DADD", "DSETP", "FSETP", "FSEL", "FMNMX", "FMNMX3",
        "FADD2", "FMUL2", "FFMA2", "IDP", "MUFU", "FCHK", "FLO", "UFLO",
        "POPC", "BREV", "IABS", "FRND", "I2F", "I2FP", "F2F", "F2FP", "F2I",
        "F2IP", "I2D", "D2I", "P2R", "R2P", "S2R", "CS2R", "S2UR", "UP2UR",
        "R2UR", "R2P", "S2P", "B2R", "QSPC", "LEPC", "PLOP3", "VOTE", "VOTEU",
        "CREDUX", "REDUX", "MATCH", "SHFL", "SGXT", "BMOV", "LDC",
        // warp/tensor-cooperative MMA families: accumulator legality flows
        // through the R/UR transfer sets (BUG-037 quad-alignment is enforced
        // in the encoder); neither mem-chain nor anchor members.
        "IMMA", "QMMA", "OMMA", "HMMA", "DMMA", "UTCHMMA", "UTCIMMA", "UTCQMMA",
        "UPOPC",
    ];
    if NEUTRAL_ALU.contains(&op) {
        return Some(CtrlClass::AluSimple);
    }
    None
}

/// True for ctrl classes the anchor policy freezes. hand_sched is handled
/// separately (IR flag, not a class).
fn is_anchor_class(cc: &CtrlClass) -> bool {
    matches!(
        cc,
        CtrlClass::Barrier
            | CtrlClass::CtrlFlow
            | CtrlClass::ExitStatic
            | CtrlClass::Nop
            | CtrlClass::Ldcu
            | CtrlClass::Ldcu64
    )
}

/// Build the dependency graph for one kernel. Fail-closed: any
/// instruction with unknown register roles, unknown predicate roles
/// (Strict mode), or a ctrl class the active table cannot classify stops
/// the pass with attribution.
pub fn build_graph(insns: &[Instruction], table: &IsaTable) -> Result<DepGraph> {
    let n = insns.len();
    let rx: Vec<reg_liveness::RegXfer> = insns.iter().map(reg_liveness::reg_xfer).collect();
    let px: Vec<pred_liveness::PredXfer> =
        insns.iter().map(|i| pred_liveness::pred_xfer(i, XferMode::Strict)).collect();

    let mut unknown_ops: Vec<String> = Vec::new();
    for (i, (ins, (r, p))) in insns.iter().zip(rx.iter().zip(px.iter())).enumerate() {
        if !r.known || !p.known {
            unknown_ops.push(format!("{} @0x{:x} (idx {i})", ins.opcode_full, ins.addr));
        }
    }
    if !unknown_ops.is_empty() {
        bail!(
            "sched: {} instruction(s) with unknown operand roles: {}",
            unknown_ops.len(),
            unknown_ops[..unknown_ops.len().min(8)].join(", ")
        );
    }

    let mut classes = Vec::with_capacity(n);
    let mut unknown_classes: Vec<String> = Vec::new();
    let mut n_class_fallback = 0usize;
    for (i, ins) in insns.iter().enumerate() {
        let cc = match table.ctrl_class(&ins.key).cloned() {
            Some(cc) if cc != CtrlClass::Unknown => cc,
            _ => match fallback_class(ins) {
                Some(cc) => {
                    n_class_fallback += 1;
                    cc
                }
                None => {
                    unknown_classes.push(format!(
                        "{} key {} @0x{:x} (idx {i})",
                        ins.opcode_full, ins.key, ins.addr
                    ));
                    CtrlClass::Unknown
                }
            },
        };
        classes.push(cc);
    }
    if !unknown_classes.is_empty() {
        bail!(
            "sched: {} instruction(s) with no ctrl_class in the active table and no              grounded fallback base-op: {}",
            unknown_classes.len(),
            unknown_classes[..unknown_classes.len().min(8)].join(", ")
        );
    }

    let mut edges: BTreeSet<(u32, u32, EdgeClass)> = BTreeSet::new();

    // Register domains.
    domain_edges(
        n,
        &|i| rx[i].rdefs.clone(),
        &|i| rx[i].ruses.clone(),
        EdgeClass::RawR,
        EdgeClass::WarR,
        EdgeClass::WawR,
        &mut edges,
    );
    domain_edges(
        n,
        &|i| rx[i].udefs.clone(),
        &|i| rx[i].uuses.clone(),
        EdgeClass::RawUr,
        EdgeClass::WarUr,
        EdgeClass::WawUr,
        &mut edges,
    );
    // Predicate domains (Strict: P domain plus the documented UP superset).
    domain_edges(
        n,
        &|i| px[i].defs.clone(),
        &|i| px[i].uses.clone(),
        EdgeClass::RawP,
        EdgeClass::WarP,
        EdgeClass::WawP,
        &mut edges,
    );
    domain_edges(
        n,
        &|i| px[i].udefs.clone(),
        &|i| px[i].uuses.clone(),
        EdgeClass::RawUp,
        EdgeClass::WarUp,
        EdgeClass::WawUp,
        &mut edges,
    );

    // Conservative memory chain: consecutive memory-class ops stay ordered.
    let mut prev_mem: Option<u32> = None;
    for (i, cc) in classes.iter().enumerate() {
        if is_mem_chain_class(cc) {
            if let Some(p) = prev_mem {
                edges.insert((p, i as u32, EdgeClass::MemChain));
            }
            prev_mem = Some(i as u32);
        }
    }

    // Anchors + their no-crossing edges (previous-anchor -> i -> next-anchor,
    // plus the consecutive-anchor chain; transitivity covers the rest).
    let anchors: Vec<u32> = (0..n)
        .filter(|&i| insns[i].hand_sched || is_anchor_class(&classes[i]))
        .map(|i| i as u32)
        .collect();
    let aset: BTreeSet<u32> = anchors.iter().copied().collect();
    for w in anchors.windows(2) {
        edges.insert((w[0], w[1], EdgeClass::Anchor));
    }
    for i in 0..n as u32 {
        if aset.contains(&i) {
            continue;
        }
        let next = anchors.partition_point(|&a| a < i);
        if next > 0 {
            edges.insert((anchors[next - 1], i, EdgeClass::Anchor));
        }
        if next < anchors.len() {
            edges.insert((i, anchors[next], EdgeClass::Anchor));
        }
    }

    let n_hand_sched = insns.iter().filter(|i| i.hand_sched).count();
    let n_scoreboard_bound = insns
        .iter()
        .filter(|i| i.ctrl.wait_mask != 0 || i.ctrl.write_bar != 7 || i.ctrl.read_bar != 7)
        .count();

    // Pressure snapshot for the M4.6 cost plugin (peak live-in sets).
    let live = reg_liveness::liveness(insns);
    let live_peak_r = live.iter().map(|l| l.rlive_in.len()).max().unwrap_or(0);
    let live_peak_ur = live.iter().map(|l| l.ulive_in.len()).max().unwrap_or(0);

    Ok(DepGraph {
        n,
        edges: edges.into_iter().collect(),
        anchors,
        n_hand_sched,
        n_scoreboard_bound,
        live_peak_r,
        live_peak_ur,
        n_class_fallback,
    })
}

/// Check a permutation against every dependency edge. `perm` lists OLD
/// instruction indices in NEW program order. This is the legality gate a
/// mutating M4.6 mode must pass after every move; identity mode exercises
/// it on the trivial permutation so the checker itself is machine-verified
/// on real graphs.
pub fn verify_permutation(g: &DepGraph, perm: &[u32]) -> Result<()> {
    if perm.len() != g.n {
        bail!(
            "sched: permutation length {} != kernel length {}",
            perm.len(),
            g.n
        );
    }
    let mut pos = vec![u32::MAX; g.n];
    for (k, &old) in perm.iter().enumerate() {
        if old as usize >= g.n {
            bail!("sched: permutation index {old} out of range {}", g.n);
        }
        if pos[old as usize] != u32::MAX {
            bail!("sched: permutation repeats instruction {old}");
        }
        pos[old as usize] = k as u32;
    }
    for &(a, b, cls) in &g.edges {
        if pos[a as usize] >= pos[b as usize] {
            bail!(
                "sched: illegal permutation -- {} edge {} -> {} inverted \
                 (positions {} >= {})",
                cls.name(),
                a,
                b,
                pos[a as usize],
                pos[b as usize]
            );
        }
    }
    Ok(())
}

/// Run the pass over a whole SASS file.
pub fn run_file(text: &str, mode: SchedMode, table: &IsaTable) -> Result<SchedRun> {
    let SchedMode::Identity = mode;
    let file = crate::sass_file::parse_sass_file_str_strict(text)
        .context("sched: strict parse failed")?;

    let mut reports = Vec::new();
    for k in &file.kernels {
        let g = build_graph(&k.instructions, table)
            .with_context(|| format!("sched: kernel {}", k.name))?;
        let perm: Vec<u32> = (0..g.n as u32).collect();
        verify_permutation(&g, &perm)
            .with_context(|| format!("sched: kernel {}", k.name))?;
        let moved = perm.iter().enumerate().filter(|(k, &o)| o != *k as u32).count();
        if moved != 0 {
            bail!(
                "sched: identity mode moved {moved} instruction(s) in {} -- internal error",
                k.name
            );
        }
        let mut by_class: BTreeMap<String, usize> = BTreeMap::new();
        for &(_, _, cls) in &g.edges {
            *by_class.entry(cls.name().to_string()).or_default() += 1;
        }
        reports.push(KernelSchedReport {
            name: k.name.clone(),
            n_ins: g.n,
            anchors: g.anchors.len(),
            hand_sched: g.n_hand_sched,
            scoreboard_bound: g.n_scoreboard_bound,
            edges_total: g.edges.len(),
            edges_by_class: by_class,
            live_peak_r: g.live_peak_r,
            live_peak_ur: g.live_peak_ur,
            moved,
            class_fallback: g.n_class_fallback,
            unknown_ops: Vec::new(),
            unknown_classes: Vec::new(),
        });
    }

    // Identity emission: byte-verbatim input. A drifting renderer would be
    // caught downstream by the byte-exact gates (G11b); mutating modes get
    // a re-parse proof here (M4.6), mirroring ra::verify_splice_proof.
    let out_text = text.to_string();
    Ok(SchedRun {
        file,
        out_text,
        report: SchedRunReport {
            mode: "identity".to_string(),
            kernels: reports,
        },
    })
}

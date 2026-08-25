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
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Scheduling mode. M4.5 gates `identity`; M4.6 adds `list` (windowed list
/// scheduler with the m9 cost plugin, plan-driven like RA's pin mode).
#[derive(Debug, Clone)]
pub enum SchedMode {
    Identity,
    List(SchedPlan),
}

/// CLI/pyo3 mode spelling. `list` carries its plan separately, so this only
/// validates the name; builders live in main.rs / python.rs.
pub fn parse_mode_kind(s: &str) -> Result<&'static str> {
    match s {
        "identity" => Ok("identity"),
        "list" => Ok("list"),
        other => bail!(
            "sched: unknown mode '{other}' (implemented: 'identity' -- M4.5, \
             'list' -- M4.6 windowed list scheduling)"
        ),
    }
}

/// Windowed scheduling plan for ONE kernel (M4.6). Moves apply ONLY inside
/// the declared windows ([start, end) instruction indices, 0-based,
/// end-exclusive -- G8b-window convention, same as RA's pin plan).
/// Everything outside the windows keeps its line byte-verbatim (splice
/// semantics), and pinned interior instructions keep their positions.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SchedKernelPlan {
    #[serde(default)]
    pub windows: Vec<(u32, u32)>,
    /// M4.7 replay: explicit per-window orders (OLD instruction indices in
    /// NEW program order; each entry must be a permutation of its window
    /// [s, e)). When present, the list optimizer is BYPASSED for that
    /// window: the given order is machine-checked (pin fixed points +
    /// verify_permutation over the whole kernel) and priced by the same
    /// cost model, then emitted. This is the eDSL seed-mutation contract:
    /// the author assigns the order by hand, the pass proves legality and
    /// emits exactly it -- the scheduler never silently "repairs" an
    /// authored schedule, it refuses illegal ones.
    #[serde(default)]
    pub orders: Option<Vec<Vec<u32>>>,
}

/// Whole-file scheduling plan, keyed by kernel name.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SchedPlan {
    #[serde(default)]
    pub kernels: BTreeMap<String, SchedKernelPlan>,
}

/// m9-derived cost model (DATA per arch, e.g. tables/cost_sm103a.json).
/// The scheduler never invents physics: it reads credits and the
/// quantum-masked dependency latency from this file; anything the file
/// does not classify takes `credits_default` and is counted in the
/// `credits_defaulted` tripwire (explicit, like the M4.5 class fallback).
#[derive(Debug, Clone, Deserialize)]
pub struct CostModel {
    pub arch: String,
    /// Dispatch quantum estimate in cycles (m9 warp-ipc inversion).
    pub quantum_cy: f64,
    /// Producer->consumer link latency in issue slots (quantum-masked ALU
    /// dependency distance on sm_103a/sm_120, ceil(quantum)).
    pub dep_link_latency_slots: f64,
    pub credits_default: f64,
    #[serde(default)]
    pub credits: BTreeMap<String, f64>,
}

impl CostModel {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("sched: cannot read cost model {}", path.display()))?;
        let mut cm: CostModel = serde_json::from_str(&text)
            .with_context(|| format!("sched: cost model {} is not valid M4.6 JSON", path.display()))?;
        if cm.arch.is_empty() || cm.quantum_cy <= 0.0 || cm.dep_link_latency_slots < 0.0 {
            bail!(
                "sched: cost model {} fails sanity (arch/quantum/dep_link)",
                path.display()
            );
        }
        cm.credits.retain(|_, v| *v >= 0.0);
        Ok(cm)
    }

    pub fn from_str_json(text: &str) -> Result<Self> {
        let cm: CostModel = serde_json::from_str(text)
            .context("sched: inline cost model is not valid M4.6 JSON")?;
        if cm.arch.is_empty() || cm.quantum_cy <= 0.0 || cm.dep_link_latency_slots < 0.0 {
            bail!("sched: inline cost model fails sanity (arch/quantum/dep_link)");
        }
        Ok(cm)
    }

    /// Issue-slot cost of one instruction. Lookup order: full opcode
    /// (`IMAD.WIDE.MOV`), then base + each single modifier (`IMAD.WIDE`),
    /// then base opcode (`IMAD`), then `credits_default` (counted).
    pub fn credit_of(&self, ins: &Instruction, defaulted: &mut usize) -> f64 {
        let mut cand: Vec<String> = vec![ins.opcode_full.clone()];
        for m in &ins.modifiers {
            cand.push(format!("{}{}", ins.opcode, m));
        }
        cand.push(ins.opcode.clone());
        for c in cand {
            if let Some(v) = self.credits.get(&c) {
                return *v;
            }
        }
        *defaulted += 1;
        self.credits_default
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
    /// M4.6 list mode: per-window outcome (empty in identity mode).
    #[serde(default)]
    pub windows: Vec<WindowSchedReport>,
    /// M4.6 list mode: instructions priced via `credits_default` because
    /// the cost model names neither their full opcode nor their base
    /// (tripwire for cost-table completion, like `class_fallback`).
    #[serde(default)]
    pub credits_defaulted: usize,
}

/// M4.6 per-window report entry.
#[derive(Debug, Clone, Serialize)]
pub struct WindowSchedReport {
    pub start: u32,
    pub end: u32,
    /// Instructions eligible to move (not pinned).
    pub movers: usize,
    /// In-window instructions holding their position, by reason.
    pub pinned: usize,
    pub pin_reasons: BTreeMap<String, usize>,
    /// Segments = maximal mover runs between pins/anchors.
    pub segments: usize,
    /// Ready-time model span of the original in-segment order.
    pub cost_before: f64,
    /// Same model applied to the scheduled order.
    pub cost_after: f64,
    /// Movers that actually changed position inside the window.
    pub moved: usize,
    /// M4.7: true when the emitted order came from an explicit plan entry
    /// (authored replay) rather than the list optimizer.
    pub replay: bool,
}

/// M5 (BARRACUDA author surface): pin/mover introspection entry for one
/// scheduling window. `movable` = sorted instruction indices the author may
/// permute; `pins` = fixed points with reasons; `segments` = maximal mover
/// runs between pins (the true authoring units -- a mover can never cross
/// a pin, `verify_permutation` already enforces it at apply time).
#[derive(Debug, Clone, Serialize)]
pub struct WindowPinsReport {
    pub kernel: String,
    pub start: u32,
    pub end: u32,
    pub movable: Vec<u32>,
    pub pins: BTreeMap<u32, String>,
    pub segments: Vec<Vec<u32>>,
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
    build_graph_ex(insns, table, &BTreeSet::new())
}

/// `build_graph` with the M4.6 anchor override: indices in `movable` lose
/// their hand_sched freeze (a declared scheduling window un-pins owner
/// control words ONLY there). Anchor-CLASS membership is untouched -- the
/// pass never unfreezes control flow / barriers / NOP / LDCU semantics.
pub fn build_graph_ex(
    insns: &[Instruction],
    table: &IsaTable,
    movable: &BTreeSet<u32>,
) -> Result<DepGraph> {
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
        .filter(|&i| {
            is_anchor_class(&classes[i])
                || (insns[i].hand_sched && !movable.contains(&(i as u32)))
        })
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
    match mode {
        SchedMode::Identity => run_file_identity(text, table, None),
        SchedMode::List(_) => bail!(
            "sched: mode 'list' requires a cost model -- use run_file_cost()"
        ),
    }
}

/// M4.6 entry point: `run_file` plus the cost model the list scheduler
/// prices moves with. Identity mode ignores the model (kept out of the
/// report; the identity gates pin zero cost-table coupling).
pub fn run_file_cost(
    text: &str,
    mode: SchedMode,
    table: &IsaTable,
    cost: Option<&CostModel>,
) -> Result<SchedRun> {
    match mode {
        SchedMode::Identity => run_file_identity(text, table, None),
        SchedMode::List(plan) => run_file_list(text, &plan, table, cost),
    }
}

fn run_file_identity(
    text: &str,
    table: &IsaTable,
    _plan: Option<&SchedPlan>,
) -> Result<SchedRun> {
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
            windows: Vec::new(),
            credits_defaulted: 0,
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

// ===========================================================================
// M4.6: windowed list scheduling (m9 cost plugin)
// ===========================================================================
//
// Mechanics (design.md sec.5 "M4.6 sched-move"):
//   * declared windows un-pin the owner control words there and ONLY there;
//     everything outside the windows stays byte-verbatim (splice doctrine,
//     same as RA's pin mode);
//   * an in-window instruction is PINNED (holds its position) when it is
//     a label carrier (branch targets = absolute addresses, moving them
//     would change bytes outside the window), a memory-chain member, a
//     scoreboard participant (wait/read/write barrier bits set), or a NOP;
//     control-flow / barrier / LDCU-class instructions inside a window
//     ABORT the run (a scheduling window crossing those is a plan error);
//   * pinned instructions are anchors, so the M4.5 anchor-edge construction
//     confines every mover to its segment automatically -- the same
//     `verify_permutation` checker proves segment discipline for free;
//   * movers keep their ctrl words (stall fields ride with the seed --
//     raise-only doctrine, BUG-036 cap 11); only the ORDER of lines is
//     optimized, priced by the m9 cost model (ready-time + critical-path
//     slack, single-warp issue stream).
//
// Emission: window lines are the ORIGINAL lines reordered (verbatim,
// labels/prefixes/!rsd included); the result is proven by a full re-parse
// equality against the planned permutation (mirrors ra::verify_splice_proof).

/// Why an in-window instruction may not move.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinReason {
    Label,
    MemChain,
    Scoreboard,
    Nop,
}

impl PinReason {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Label => "label",
            Self::MemChain => "mem_chain",
            Self::Scoreboard => "scoreboard",
            Self::Nop => "nop",
        }
    }
}

/// Classification of one instruction line inside a body scan.
#[derive(Debug, Clone)]
enum BodyLine {
    /// Instruction line; value = (instruction index, carries a label).
    Ins(usize, bool),
    /// Label-only line; value = instructions seen before it in this kernel.
    LabelOnly(usize),
    /// Anything else (directives, blanks, comments).
    Other,
}

/// Scan one .entry body per kernel the way the strict parser counts
/// instructions (same line-walk convention as ra::emit_spliced; aligned by
/// the byte-exact gates). Returns per kernel (name, lines).
fn scan_body_lines(text: &str) -> Vec<(String, Vec<BodyLine>)> {
    use regex::Regex;
    use std::sync::LazyLock;
    static RE_LABEL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_.$]*\s*:\s*").unwrap());

    let mut out: Vec<(String, Vec<BodyLine>)> = Vec::new();
    let mut in_kernel = false;
    let mut cur_name = String::new();
    let mut lines: Vec<BodyLine> = Vec::new();
    let mut ins_count = 0usize;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with(".entry") || t.starts_with(".func") {
            if in_kernel {
                out.push((std::mem::take(&mut cur_name), std::mem::take(&mut lines)));
            }
            in_kernel = true;
            cur_name = t.split_whitespace().nth(1).unwrap_or("").to_string();
            ins_count = 0;
            continue;
        }
        if t.starts_with(".endentry") || t.starts_with(".endfunc") {
            if in_kernel {
                out.push((std::mem::take(&mut cur_name), std::mem::take(&mut lines)));
            }
            in_kernel = false;
            continue;
        }
        if !in_kernel {
            continue;
        }
        if t.is_empty() || t.starts_with("//") || t.starts_with('#') || t.starts_with('.') {
            lines.push(BodyLine::Other);
            continue;
        }
        let mut rest = t;
        let mut had_label = false;
        while let Some(c) = RE_LABEL.captures(rest) {
            had_label = true;
            rest = &rest[c.get(0).unwrap().as_str().len()..];
        }
        if rest.is_empty() {
            lines.push(BodyLine::LabelOnly(ins_count));
            continue;
        }
        lines.push(BodyLine::Ins(ins_count, had_label));
        ins_count += 1;
    }
    if in_kernel {
        out.push((cur_name, lines));
    }
    out
}

/// One permuted window for the emitter: lines of instructions
/// [start, start + new_order.len()) re-emitted in `new_order` sequence
/// (original indices; pinned entries hold their offsets).
pub struct WindowEmit {
    pub kernel_idx: usize,
    pub start: u32,
    pub new_order: Vec<u32>,
}

/// Emit the list-mode output text: outside windows byte-verbatim; inside a
/// window the ORIGINAL instruction lines reordered per plan. One
/// instruction per line is required (labels on the same line are fine);
/// anything else aborts the run (fail-closed).
pub fn emit_permuted_splice(original: &str, edits: &[WindowEmit]) -> Result<String> {
    use regex::Regex;
    use std::sync::LazyLock;
    static RE_LABEL: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_.$]*\s*:\s*").unwrap());

    // (kernel_idx, ins_idx) -> new position's source is derived per window:
    // map each edited window to (start, set of covered indices).
    let mut per_kernel: BTreeMap<usize, Vec<&WindowEmit>> = BTreeMap::new();
    for e in edits {
        per_kernel.entry(e.kernel_idx).or_default().push(e);
    }
    for (kidx, ws) in &per_kernel {
        let mut covered: BTreeSet<u32> = BTreeSet::new();
        for w in ws {
            if w.new_order.is_empty() {
                bail!("sched: emitter: empty window edit on kernel {kidx}");
            }
            let expect: Vec<u32> = (w.start..w.start + w.new_order.len() as u32).collect();
            let mut sorted = w.new_order.clone();
            sorted.sort();
            if sorted != expect {
                bail!(
                    "sched: emitter: window @{kidx}[{}] new_order is not a \
                     permutation of its own range",
                    w.start
                );
            }
            for &i in &w.new_order {
                if !covered.insert(i) {
                    bail!("sched: emitter: overlapping window edits on kernel {kidx}");
                }
            }
        }
    }

    let mut out_lines: Vec<String> = Vec::new();
    let mut in_kernel = false;
    let mut kidx: isize = -1;
    let mut ins_count = 0usize;
    let mut pending: Option<(&WindowEmit, Vec<String>)> = None;

    let lines_iter = original.lines().peekable();
    for line in lines_iter {
        let t = line.trim();
        if t.starts_with(".entry") || t.starts_with(".func") {
            in_kernel = true;
            kidx += 1;
            ins_count = 0;
            out_lines.push(line.to_string());
            continue;
        }
        if t.starts_with(".endentry") || t.starts_with(".endfunc") {
            in_kernel = false;
            out_lines.push(line.to_string());
            continue;
        }
        if !in_kernel || t.is_empty() || t.starts_with("//") || t.starts_with('#') || t.starts_with('.')
        {
            out_lines.push(line.to_string());
            continue;
        }
        let mut rest = t;
        while let Some(c) = RE_LABEL.captures(rest) {
            rest = &rest[c.get(0).unwrap().as_str().len()..];
        }
        if rest.is_empty() {
            out_lines.push(line.to_string()); // lone label line
            continue;
        }
        let idx = ins_count;
        ins_count += 1;
        let cur_k = kidx as usize;
        // inside a window? buffer; at window end, flush permuted.
        let hit = per_kernel.get(&cur_k).and_then(|ws| {
            ws.iter()
                .find(|w| w.start <= idx as u32 && (idx as u32) < w.start + w.new_order.len() as u32)
        });
        match (pending.take(), hit) {
            (None, None) => out_lines.push(line.to_string()),
            (None, Some(w)) => pending = Some((w, vec![line.to_string()])),
            (Some((w, mut buf)), Some(_)) => {
                buf.push(line.to_string());
                pending = Some((w, buf));
            }
            (Some((w, buf)), None) => {
                bail!(
                    "sched: emitter: window @{cur_k}[{}] underflow: got {} line(s)",
                    w.start,
                    buf.len()
                );
            }
        }
        if let Some((w, buf)) = &pending {
            if buf.len() == w.new_order.len() {
                let (w, buf) = pending.take().unwrap();
                for &oi in &w.new_order {
                    let off = (oi - w.start) as usize;
                    out_lines.push(buf[off].clone());
                }
            }
        }
    }
    if pending.is_some() {
        bail!("sched: emitter: unterminated window buffer at EOF");
    }
    let mut out = out_lines.join("\n");
    if original.ends_with('\n') {
        out.push('\n');
    }
    Ok(out)
}

/// Field-level equality between the planned permutation of the IR and the
/// re-parsed emitted text (mirrors ra::verify_splice_proof).
fn verify_permute_proof(
    orig: &crate::sass_file::SassFile,
    out_text: &str,
    perms: &BTreeMap<usize, Vec<u32>>,
) -> Result<()> {
    let re = crate::sass_file::parse_sass_file_str_strict(out_text)
        .context("sched: permuted output failed strict re-parse")?;
    if re.kernels.len() != orig.kernels.len() {
        bail!("sched: permute proof: kernel count drifted");
    }
    for (kidx, (a, b)) in orig.kernels.iter().zip(re.kernels.iter()).enumerate() {
        if a.name != b.name || a.instructions.len() != b.instructions.len() {
            bail!("sched: permute proof: kernel {} shape drifted", a.name);
        }
        let identity: Vec<u32> = (0..a.instructions.len() as u32).collect();
        let perm = perms.get(&kidx).unwrap_or(&identity);
        for (p, (x, &src)) in b.instructions.iter().zip(perm.iter()).enumerate() {
            let y = &a.instructions[src as usize];
            if x.opcode_full != y.opcode_full
                || x.modifiers != y.modifiers
                || x.guard != y.guard
                || x.operands != y.operands
                || x.ctrl != y.ctrl
                || x.rsd != y.rsd
                || x.hand_sched != y.hand_sched
            {
                bail!(
                    "sched: permute proof: instruction {p} of kernel {} does not \
                     carry the fields of source instruction {src} ({})",
                    a.name,
                    y.opcode_full
                );
            }
        }
    }
    Ok(())
}

/// Critical-path height + ready-time evaluation live inline in
/// `run_file_list` (baseline) and `schedule_segment` (policy).
///
/// List-schedule one segment of movers. `edges_in`/`edges_out`: interior
/// edges (both endpoints movers of this segment). Deterministic: priority
/// tuple (earliest availability, -critical_path_height, original index).
/// Ready-time span of a GIVEN order over one segment (the same model the
/// list scheduler prices moves with; M4.6 baseline + M4.7 replay share it).
fn simulate_order_span(
    order: &[u32],
    insns: &[Instruction],
    credits: &HashMap<u32, f64>,
    lat: f64,
    pred: &HashMap<u32, Vec<u32>>,
) -> f64 {
    let mut end: HashMap<u32, f64> = HashMap::new();
    let mut cursor = 0.0f64;
    let mut span = 0.0f64;
    for &i in order {
        let mut avail = 0.0f64;
        if let Some(ps) = pred.get(&i) {
            for &p in ps {
                // Replay mode tolerates illegal authored orders through the
                // SIMULATION (the mandatory verify_permutation afterwards is
                // what refuses them): an uninverted producer is always in
                // `end`; an inverted one is ignored here so the cost number
                // is still well-defined for the report.
                if let Some(&pe) = end.get(&p) {
                    avail = avail.max(pe + lat);
                }
            }
        }
        let t = cursor.max(avail);
        let e = t + credits[&i] + insns[i as usize].ctrl.stall as f64;
        end.insert(i, e);
        cursor = e;
        span = span.max(e);
    }
    span
}

fn schedule_segment(
    movers: &[u32],
    insns: &[Instruction],
    credits: &HashMap<u32, f64>,
    lat: f64,
    succ: &HashMap<u32, Vec<u32>>,
    pred: &HashMap<u32, Vec<u32>>,
    height: &HashMap<u32, f64>,
) -> (Vec<u32>, f64) {
    let mut indeg: HashMap<u32, usize> = movers.iter().map(|&m| (m, 0)).collect();
    for (&s, ps) in pred {
        indeg.insert(s, ps.len());
    }
    let mut avail: HashMap<u32, f64> = movers.iter().map(|&m| (m, 0.0)).collect();
    let mut end: HashMap<u32, f64> = HashMap::new();
    let mut ready: Vec<u32> = movers
        .iter()
        .copied()
        .filter(|m| *indeg.get(m).unwrap_or(&0) == 0)
        .collect();
    let mut order = Vec::with_capacity(movers.len());
    let mut cursor = 0.0f64;
    let mut span = 0.0f64;
    while !ready.is_empty() {
        // No voluntary bubble while useful work exists: prefer the most
        // critical node that can issue AT the cursor (avail <= cursor);
        // only when nothing is issuable does the cursor jump to the
        // earliest availability (a forced bubble), taking the most
        // critical node there. Ties: min availability, then min index
        // (deterministic).
        const EPS: f64 = 1e-9;
        let issuable: Vec<u32> = ready
            .iter()
            .copied()
            .filter(|v| avail[v] <= cursor + EPS)
            .collect();
        let (pool, jump): (Vec<u32>, Option<f64>) = if issuable.is_empty() {
            let nxt = ready.iter().map(|v| avail[v]).fold(f64::INFINITY, f64::min);
            (ready.iter().copied().filter(|v| avail[v] <= nxt + EPS).collect(), Some(nxt))
        } else {
            (issuable, None)
        };
        let mut pool = pool;
        pool.sort_by(|a, b| {
            height[b]
                .partial_cmp(&height[a])
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| avail[a].partial_cmp(&avail[b]).unwrap_or(std::cmp::Ordering::Equal))
                .then_with(|| a.cmp(b))
        });
        let v = pool[0];
        if let Some(j) = jump {
            cursor = cursor.max(j);
        }
        ready.retain(|x| *x != v);
        let t = cursor.max(avail[&v]);
        let e = t + credits[&v] + insns[v as usize].ctrl.stall as f64;
        end.insert(v, e);
        cursor = e;
        span = span.max(e);
        order.push(v);
        if let Some(ss) = succ.get(&v) {
            for &s in ss {
                let a = avail.entry(s).or_insert(0.0);
                *a = a.max(e + lat);
                let d = indeg.get_mut(&s).expect("segment indegree");
                *d -= 1;
                if *d == 0 {
                    ready.push(s);
                }
            }
        }
    }
    (order, span)
}

/// Run the M4.6 windowed list scheduler over a whole SASS file.
/// M5 (BARRACUDA author surface): pin/mover introspection for a
/// scheduling plan. Read-only: same strict parse, same plan/window shape
/// validation, same pin classification (`classify_window`) as the
/// list/replay planner; no cost model, no emission. Fail-closed like the
/// planner: any contract violation is an error and no partial report is
/// produced for the offending kernel.
pub fn window_pins(
    text: &str,
    plan: &SchedPlan,
    table: &IsaTable,
) -> Result<Vec<WindowPinsReport>> {
    let file = crate::sass_file::parse_sass_file_str_strict(text)
        .context("sched: strict parse failed")?;
    for kname in plan.kernels.keys() {
        if !file.kernels.iter().any(|k| &k.name == kname) {
            bail!(
                "sched: plan names unknown kernel {kname:?} (file has: {:?})",
                file.kernels.iter().map(|k| &k.name).collect::<Vec<_>>()
            );
        }
    }
    let scans = scan_body_lines(text);
    if scans.len() != file.kernels.len() {
        bail!("sched: body-line scan and parser disagree on kernel count");
    }
    let mut out = Vec::new();
    for (kidx, k) in file.kernels.iter().enumerate() {
        let Some(kp) = plan.kernels.get(&k.name) else {
            continue;
        };
        let n = k.instructions.len();
        let (scan_name, scan_lines) = &scans[kidx];
        if scan_name != &k.name {
            bail!(
                "sched: body-line scan / parser kernel-name mismatch ({scan_name} vs {})",
                k.name
            );
        }
        let scan_ins = scan_lines
            .iter()
            .filter(|l| matches!(l, BodyLine::Ins(_, _)))
            .count();
        if scan_ins != n {
            bail!(
                "sched: body-line scan counted {scan_ins} instructions in {} but \
                 the parser sees {n}",
                k.name
            );
        }
        let mut labeled: BTreeSet<u32> = BTreeSet::new();
        for l in scan_lines {
            if let BodyLine::Ins(i, true) = l {
                labeled.insert(*i as u32);
            }
        }
        // identical window-shape validation as the list planner
        let mut prev_e = 0u32;
        let mut first = true;
        for &(s, e) in &kp.windows {
            if !first && s < prev_e {
                bail!("sched: plan for {}: overlapping/unsorted windows (at [{s},{e}))", k.name);
            }
            first = false;
            prev_e = e;
            if s >= e {
                bail!("sched: plan for {}: empty window [{s},{e})", k.name);
            }
            if e as usize > n {
                bail!(
                    "sched: plan for {}: window [{s},{e}) out of range ({n} instructions)",
                    k.name
                );
            }
        }
        for &(s, e) in &kp.windows {
            let (mv, pins) = classify_window(k, table, &labeled, scan_lines, s, e)
                .with_context(|| format!("sched: kernel {}", k.name))?;
            let mut segments: Vec<Vec<u32>> = Vec::new();
            for &i in &mv {
                match segments.last_mut() {
                    Some(run) if *run.last().expect("nonempty run") + 1 == i => run.push(i),
                    _ => segments.push(vec![i]),
                }
            }
            out.push(WindowPinsReport {
                kernel: k.name.clone(),
                start: s,
                end: e,
                movable: mv.into_iter().collect(),
                pins: pins
                    .into_iter()
                    .map(|(i, r)| (i, r.name().to_string()))
                    .collect(),
                segments,
            });
        }
    }
    Ok(out)
}


type ClassifyWindowOut = (BTreeSet<u32>, Vec<(u32, PinReason)>);

/// Classify one scheduling window into movers and pins; the single source
/// of truth for pin semantics, shared by the list/replay planner
/// (`run_file_list`) and the pin-introspection entry (`window_pins`, M5).
/// Fail-closed: anchor-class crossing (non-NOP), label-only line strictly
/// inside the window, or zero movable instructions.
#[allow(clippy::too_many_arguments)]
fn classify_window(
    k: &crate::sass_file::KernelDef,
    table: &IsaTable,
    labeled: &BTreeSet<u32>,
    scan_lines: &[BodyLine],
    s: u32,
    e: u32,
) -> Result<ClassifyWindowOut> {
    let mut movable: BTreeSet<u32> = BTreeSet::new();
    let mut pins: Vec<(u32, PinReason)> = Vec::new();
    for i in s..e {
        let ins = &k.instructions[i as usize];
        let cc = match table.ctrl_class(&ins.key).cloned() {
            Some(cc) if cc != CtrlClass::Unknown => cc,
            _ => fallback_class(ins).with_context(|| {
                format!(
                    "sched: no ctrl_class for {} key {} @0x{:x} (idx {i})",
                    ins.opcode_full, ins.key, ins.addr
                )
            })?,
        };
        if is_anchor_class(&cc) {
            if matches!(cc, CtrlClass::Nop) {
                pins.push((i, PinReason::Nop));
                continue;
            }
            bail!(
                "sched: window [{s},{e}) of {} contains anchor-class \
                 instruction {} (idx {i}, class {:?}) -- scheduling \
                 windows must not cross control flow / barriers / LDCU",
                k.name,
                ins.opcode_full,
                cc
            );
        }
        if is_mem_chain_class(&cc) {
            pins.push((i, PinReason::MemChain));
            continue;
        }
        if ins.ctrl.wait_mask != 0 || ins.ctrl.write_bar != 7 || ins.ctrl.read_bar != 7 {
            pins.push((i, PinReason::Scoreboard));
            continue;
        }
        if labeled.contains(&i) {
            pins.push((i, PinReason::Label));
            continue;
        }
        movable.insert(i);
    }
    // label-only lines strictly inside the window text region would float
    // under reordering -- refuse them (fail-closed).
    for l in scan_lines {
        if let BodyLine::LabelOnly(before) = l {
            let b = *before as u32;
            if s < b && b < e {
                bail!(
                    "sched: window [{s},{e}) of {} contains a label-only \
                     line after instruction {b} -- unsupported (put the \
                     label on an instruction line)",
                    k.name
                );
            }
        }
    }
    if movable.is_empty() {
        bail!(
            "sched: window [{s},{e}) of {} has zero movable instructions",
            k.name
        );
    }
    Ok((movable, pins))
}

fn run_file_list(
    text: &str,
    plan: &SchedPlan,
    table: &IsaTable,
    cost: Option<&CostModel>,
) -> Result<SchedRun> {
    let cost = cost
        .ok_or_else(|| anyhow::anyhow!("sched: mode 'list' requires a cost model (--cost)"))?;
    let file = crate::sass_file::parse_sass_file_str_strict(text)
        .context("sched: strict parse failed")?;
    for kname in plan.kernels.keys() {
        if !file.kernels.iter().any(|k| &k.name == kname) {
            bail!(
                "sched: plan names unknown kernel {kname:?} (file has: {:?})",
                file.kernels.iter().map(|k| &k.name).collect::<Vec<_>>()
            );
        }
    }
    let scans = scan_body_lines(text);
    if scans.len() != file.kernels.len() {
        bail!("sched: body-line scan and parser disagree on kernel count");
    }

    let mut perms: BTreeMap<usize, Vec<u32>> = BTreeMap::new();
    let mut edits: Vec<WindowEmit> = Vec::new();
    let mut reports = Vec::new();

    for (kidx, k) in file.kernels.iter().enumerate() {
        let n = k.instructions.len();
        let (scan_name, scan_lines) = &scans[kidx];
        if scan_name != &k.name {
            bail!("sched: body-line scan / parser kernel-name mismatch ({scan_name} vs {})", k.name);
        }
        let scan_ins = scan_lines
            .iter()
            .filter(|l| matches!(l, BodyLine::Ins(_, _)))
            .count();
        if scan_ins != n {
            bail!(
                "sched: body-line scan counted {scan_ins} instructions in {} but \
                 the parser sees {n}",
                k.name
            );
        }
        // label carriers and label-only lines
        let mut labeled: BTreeSet<u32> = BTreeSet::new();
        for l in scan_lines {
            if let BodyLine::Ins(i, true) = l {
                labeled.insert(*i as u32);
            }
        }
        let kp = match plan.kernels.get(&k.name) {
            None => {
                // kernel not planned: identity; report via the shared census
                // path so the run report stays complete for every kernel.
                let g = build_graph(&k.instructions, table)
                    .with_context(|| format!("sched: kernel {}", k.name))?;
                let mut by_class: BTreeMap<String, usize> = BTreeMap::new();
                for &(_, _, cls) in &g.edges {
                    *by_class.entry(cls.name().to_string()).or_default() += 1;
                }
                reports.push(KernelSchedReport {
                    name: k.name.clone(),
                    n_ins: n,
                    anchors: g.anchors.len(),
                    hand_sched: g.n_hand_sched,
                    scoreboard_bound: g.n_scoreboard_bound,
                    edges_total: g.edges.len(),
                    edges_by_class: by_class,
                    live_peak_r: g.live_peak_r,
                    live_peak_ur: g.live_peak_ur,
                    moved: 0,
                    class_fallback: g.n_class_fallback,
                    unknown_ops: Vec::new(),
                    unknown_classes: Vec::new(),
                    windows: Vec::new(),
                    credits_defaulted: 0,
                });
                continue;
            }
            Some(kp) => kp,
        };
        if kp.windows.is_empty() {
            bail!("sched: plan for kernel {}: no windows (list mode needs >=1)", k.name);
        }
        let mut prev_e = 0u32;
        let mut first = true;
        for &(s, e) in &kp.windows {
            if !first && s < prev_e {
                bail!("sched: plan for {}: overlapping/unsorted windows (at [{s},{e}))", k.name);
            }
            first = false;
            prev_e = e;
            if s >= e {
                bail!("sched: plan for {}: empty window [{s},{e})", k.name);
            }
            if e as usize > n {
                bail!(
                    "sched: plan for {}: window [{s},{e}) out of range ({n} instructions)",
                    k.name
                );
            }
        }

        // classify + graph with movable override (single source of truth:
        // classify_window, shared with the M5 pin-introspection entry)
        let mut movable: BTreeSet<u32> = BTreeSet::new();
        let mut pin_of: HashMap<u32, PinReason> = HashMap::new();
        for &(s, e) in &kp.windows {
            let (mv, pins) = classify_window(k, table, &labeled, scan_lines, s, e)
                .with_context(|| format!("sched: kernel {}", k.name))?;
            movable.extend(mv);
            for (i, r) in pins {
                pin_of.insert(i, r);
            }
        }

        let g = build_graph_ex(&k.instructions, table, &movable)
            .with_context(|| format!("sched: kernel {}", k.name))?;

        // M4.7 replay: validate explicit orders BEFORE any emission attempt
        // (fail-closed; no partial output survives a contract violation).
        if let Some(ords) = &kp.orders {
            if ords.len() != kp.windows.len() {
                bail!(
                    "sched: plan for {}: orders has {} entries for {} windows",
                    k.name,
                    ords.len(),
                    kp.windows.len()
                );
            }
            for (&(ws, we), wo) in kp.windows.iter().zip(ords.iter()) {
                let mut sorted = wo.clone();
                sorted.sort();
                let expect: Vec<u32> = (ws..we).collect();
                if sorted != expect {
                    bail!(
                        "sched: replay order for {} [{ws},{we}) is not a                          permutation of its window range (gaps/duplicates/                         out-of-range entries)",
                        k.name
                    );
                }
                for (j, &oi) in wo.iter().enumerate() {
                    let pos = ws + j as u32;
                    if pin_of.contains_key(&pos) && oi != pos {
                        bail!(
                            "sched: replay order for {} [{ws},{we}) moves pinned                              instruction {pos} ({}) -- authored orders may only                              permute movable instructions",
                            k.name,
                            pin_of[&pos].name()
                        );
                    }
                }
            }
        }

        // per-window scheduling
        let mut perm: Vec<u32> = (0..n as u32).collect();
        let mut win_reports = Vec::new();
        let mut credits_defaulted = 0usize;
        let mut credits: HashMap<u32, f64> = HashMap::new();
        for i in 0..n as u32 {
            if movable.contains(&i) {
                let c = cost.credit_of(&k.instructions[i as usize], &mut credits_defaulted);
                credits.insert(i, c);
            }
        }
        for (wi, &(ws, we)) in kp.windows.iter().enumerate() {
            let replay_order: Option<Vec<u32>> =
                kp.orders.as_ref().map(|ords| ords[wi].clone());
            // segments = maximal mover runs
            let mut segments: Vec<Vec<u32>> = Vec::new();
            let mut cur: Vec<u32> = Vec::new();
            for i in ws..we {
                if movable.contains(&i) {
                    cur.push(i);
                } else if !cur.is_empty() {
                    segments.push(std::mem::take(&mut cur));
                }
            }
            if !cur.is_empty() {
                segments.push(cur);
            }
            let in_win: BTreeSet<u32> = (ws..we).collect();
            let mut succ: HashMap<u32, Vec<u32>> = HashMap::new();
            let mut pred: HashMap<u32, Vec<u32>> = HashMap::new();
            {
                let mut seen: BTreeSet<(u32, u32)> = BTreeSet::new();
                for &(a, b, cls) in &g.edges {
                    if cls == EdgeClass::Anchor {
                        continue;
                    }
                    if !in_win.contains(&a) || !in_win.contains(&b) {
                        continue;
                    }
                    if !movable.contains(&a) || !movable.contains(&b) {
                        // edges touching pins are position-guaranteed already
                        continue;
                    }
                    if seen.insert((a, b)) {
                        succ.entry(a).or_default().push(b);
                        pred.entry(b).or_default().push(a);
                    }
                }
            }
            // critical-path heights on the interior DAG (movers only)
            let mut height: HashMap<u32, f64> = HashMap::new();
            {
                // longest path to segment end: reverse topo (segments are
                // small; simple relaxation over topological order).
                let mut topo: Vec<u32> = Vec::new();
                {
                    let seg_set: BTreeSet<u32> = segments.iter().flatten().copied().collect();
                    let mut ind: HashMap<u32, usize> =
                        seg_set.iter().map(|&m| (m, 0)).collect();
                    for (&b, ps) in &pred {
                        if seg_set.contains(&b) {
                            ind.insert(b, ps.len());
                        }
                    }
                    let mut rq: Vec<u32> =
                        ind.iter().filter(|(_, &d)| d == 0).map(|(&m, _)| m).collect();
                    while let Some(v) = rq.pop() {
                        topo.push(v);
                        if let Some(ss) = succ.get(&v) {
                            for &s2 in ss {
                                let d = ind.get_mut(&s2).unwrap();
                                *d -= 1;
                                if *d == 0 {
                                    rq.push(s2);
                                }
                            }
                        }
                    }
                }
                for &v in topo.iter().rev() {
                    let h = succ.get(&v).map(|ss| {
                        ss.iter()
                            .map(|s2| height[s2] + cost.dep_link_latency_slots)
                            .fold(0.0f64, f64::max)
                    });
                    height.insert(v, credits[&v] + h.unwrap_or(0.0));
                }
            }
            let mut win_before = 0.0f64;
            let mut win_after = 0.0f64;
            let mut win_moved = 0usize;
            for seg in &segments {
                // interior edges of THIS segment only
                let seg_set: BTreeSet<u32> = seg.iter().copied().collect();
                let s_succ: HashMap<u32, Vec<u32>> = succ
                    .iter()
                    .filter(|(a, _)| seg_set.contains(a))
                    .map(|(a, bs)| {
                        (
                            *a,
                            bs.iter().copied().filter(|b| seg_set.contains(b)).collect(),
                        )
                    })
                    .collect();
                let s_pred: HashMap<u32, Vec<u32>> = pred
                    .iter()
                    .filter(|(b, _)| seg_set.contains(b))
                    .map(|(b, as_)| {
                        (
                            *b,
                            as_.iter().copied().filter(|a| seg_set.contains(a)).collect(),
                        )
                    })
                    .collect();
                // baseline: original order under the same model
                let before = simulate_order_span(
                    seg,
                    &k.instructions,
                    &credits,
                    cost.dep_link_latency_slots,
                    &s_pred,
                );
                let (order, after) = match &replay_order {
                    Some(wo) => {
                        // M4.7 replay: forced order -- the author's sequence
                        // restricted to this segment's movers (pins are
                        // fixed points, validated above). Priced by the same
                        // model, never re-optimized, never parity-flattened.
                        let forced: Vec<u32> =
                            wo.iter().copied().filter(|x| seg_set.contains(x)).collect();
                        let a = simulate_order_span(
                            &forced,
                            &k.instructions,
                            &credits,
                            cost.dep_link_latency_slots,
                            &s_pred,
                        );
                        (forced, a)
                    }
                    None => {
                        let (mut order, mut after) = schedule_segment(
                            seg,
                            &k.instructions,
                            &credits,
                            cost.dep_link_latency_slots,
                            &s_succ,
                            &s_pred,
                            &height,
                        );
                        // Parity keeps the seed: on a cost-neutral segment the
                        // owner's order IS the optimum the model can see (mulmod
                        // is stall-saturated; measured physics already lives in
                        // the stall fields), so emit the original order rather
                        // than churning a certified schedule for zero gain.
                        if after >= before - 1e-9 {
                            order = seg.clone();
                            after = before;
                        }
                        (order, after)
                    }
                };
                win_before += before;
                win_after += after;
                for (slot, &ni) in seg.iter().zip(order.iter()) {
                    win_moved += (slot != &ni) as usize;
                    perm[*slot as usize] = ni;
                }
            }
            let mut pin_reasons: BTreeMap<String, usize> = BTreeMap::new();
            for i in ws..we {
                if let Some(r) = pin_of.get(&i) {
                    *pin_reasons.entry(r.name().to_string()).or_default() += 1;
                }
            }
            // Replay windows are legality-gated EARLY: the full-kernel
            // permutation is complete up to and including this window
            // (identity outside), so an authored edge inversion is refused
            // here, before any cost bookkeeping or emission.
            if replay_order.is_some() {
                verify_permutation(&g, &perm).with_context(|| {
                    format!("sched: replay order for {} [{ws},{we})", k.name)
                })?;
            }
            // Regression refusal applies to OPTIMIZER-emitted orders only;
            // a replayed (authored) order is reported with its cost delta
            // and emitted as written -- author sovereignty (M4.7), the
            // legality proof is still mandatory above.
            if replay_order.is_none() && win_after > win_before + 1e-9 {
                bail!(
                    "sched: list policy made window [{ws},{we}) of {} WORSE by the \
                     cost model ({win_before:.1} -> {win_after:.1}) -- refusing to \
                     emit a regression",
                    k.name
                );
            }
            let new_order: Vec<u32> = (ws..we).map(|p| perm[p as usize]).collect();
            edits.push(WindowEmit {
                kernel_idx: kidx,
                start: ws,
                new_order,
            });
            win_reports.push(WindowSchedReport {
                start: ws,
                end: we,
                movers: (ws..we).filter(|i| movable.contains(i)).count(),
                pinned: (ws..we).filter(|i| pin_of.contains_key(i)).count(),
                pin_reasons,
                segments: segments.len(),
                cost_before: win_before,
                cost_after: win_after,
                moved: win_moved,
                replay: replay_order.is_some(),
            });
        }

        verify_permutation(&g, &perm)
            .with_context(|| format!("sched: kernel {}", k.name))?;
        let moved = perm.iter().enumerate().filter(|(p, &o)| o != *p as u32).count();
        perms.insert(kidx, perm);

        let mut by_class: BTreeMap<String, usize> = BTreeMap::new();
        for &(_, _, cls) in &g.edges {
            *by_class.entry(cls.name().to_string()).or_default() += 1;
        }
        reports.push(KernelSchedReport {
            name: k.name.clone(),
            n_ins: n,
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
            windows: win_reports,
            credits_defaulted,
        });
    }

    let out_text =
        emit_permuted_splice(text, &edits).context("sched: permuted splice emission failed")?;
    verify_permute_proof(&file, &out_text, &perms)?;
    Ok(SchedRun {
        file,
        out_text,
        report: SchedRunReport {
            mode: "list".to_string(),
            kernels: reports,
        },
    })
}

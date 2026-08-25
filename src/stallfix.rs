//! POSTFIX-103 v0 -- stall-sufficiency legalizer for sm_103a (BARRACUDA b1).
//!
//! Silicon-measured minimum-stall floors per dependency path (STALLSUF-1
//! census on B300, 2026-08-22: results/stallsuf/STALLSUF-1.md). The era
//! stalls S00..S03 are physically insufficient when the consumer sits in
//! the DIRECTLY NEXT slot (d0): rpath/P-carry ALU paths need >=4,
//! IMAD(.WIDE).X cout -> IADD3.X cin needs 5, and a @P-guard consumer
//! directly after its producer needs 7 -- while a guard with exactly one
//! instruction in between is FLAKY at every S<=8 under occupancy, so no
//! stall legalizes it (schedule rejected, fail-closed). Stalls are a 4-bit
//! field with the BUG-036 policy cap at 11 (>=12 hangs).
//!
//! Doctrine:
//!   * rules are DATA (the stallfix section of the canonical table), scope-locked by
//!     `arch`; the pass invents no physics and arch mismatch is an error;
//!   * raise-only: an existing stall is never lowered and B/R/W/Y bits are
//!     never touched -- the emission diff is exactly the stall digits of
//!     the `[B..:R..:W..:Y:Sxx]` prefix (1 byte per raise at slot +0xd);
//!   * region contract: a declared window must consist of hand-scheduled
//!     instructions (explicit ctrl prefixes); a naked instruction inside a
//!     window aborts the run. Dependencies leaving a window are invisible
//!     to v0 (documented; wrapper-independent consumers outside the
//!     region keep their wrapper-assigned stalls);
//!   * fail-closed everywhere: strict parse, plan/arch/window violations
//!     and the guard-d1 pathology all stop the run with no output.
//!
//! Producer/consumer classes are the measured v0 allowlist (identical
//! classification to the silicon-validated reference
//! work/stallsuf/postfix_ss.py): producers are IADD3.X (dual cout at
//! operand 1/2), ISETP.* (dest at operand 0) and ".X"/IMAD.WIDE forms
//! with cout at operand 1; cin consumers are IADD3.X (last two operands)
//! and IMAD*.X (last operand); guards are non-uniform @Pn/@!Pn.
//!
//! v1 (F-ss4, 2026-08-22, census-hi on B300, results/stallsuf/
//! F-SS4-CENSUS-HI.md): guard-D1 is class-resolved by the CONSUMER op:
//!   * isetp-class (@P on ISETP.*): measured LEGAL for producer stalls
//!     5..=11 (3 runs x 2 occupancy tiers); rule R6 floors the producer
//!     at `guard_d1_isetp_floor` (raise-only, cap applies);
//!   * isetp-class with producer stall >= `legacy_stall_risk_from` (12):
//!     the measured bad band -- a violation (raise-only cannot lower);
//!   * atomic-class (@P on ATOM*/RED*): a violation on sm_103a -- the
//!     guarded-atomic forms are silicon-gated (non-EL guarded: silent
//!     corruption even with an always-true guard; .EL: ILLEGAL_ADDRESS
//!     with the default descriptor);
//!   * data-class: forbidden as in v0 (FLAKY at every S<=8 under
//!     occupancy; census-hi extended: S09/S10 flaky too, S11 was a
//!     probe-geometry island -- not a policy-grade floor).
//!
//! Additionally every guard relation whose producer stall is >=
//! `legacy_stall_risk_from` is emitted as a report-only risk row
//! (postfix can neither lower nor fix it; elimination is the remedy).
//!
//! v2 (F-ss6, 2026-08-22, uniform-domain census on B300,
//! results/stallsuf/F-SS2.md): the measured allowlist grows the UR/UP
//! domain and the R2UR conversion boundary (rules are again DATA):
//!   * R7-urpath (floor_global): uniform-ALU UR write -> same-domain
//!     UR/UP-carry read at d0 needs S>=4 -- identical physics to the
//!     vector ALU paths, so R1 already carries the floor; R7 only adds
//!     rule attribution (ucarry = UIADD3.X dual-carry chain, uwide =
//!     UIMAD.WIDE UR-pair chain, both measured at S04);
//!   * R8-xread (`floor_xread_d0` = 6): uniform-ALU UR write consumed by
//!     a VECTOR op (UR operand) at d0 -- cross-domain read costs +2;
//!   * R9-r2ur (`floor_r2ur_d0` = 8): the R2UR conversion boundary in
//!     EITHER direction at d0 (vector-ALU R write feeding R2UR, or an
//!     R2UR-written UR feeding an ALU-class consumer) costs +4;
//!   * R10-uguard (`floor_uguard_d0` = 10 / `floor_uguard_d1` = 8):
//!     UISETP UP-write -> @UP/@!UP guard. Unlike the P-domain guard-D1
//!     pathology, the uniform guard at D1 is REPAIRABLE with stalls
//!     (measured clean band 8..=11); D2+ is clean at any stall. No
//!     uniform-guard site is ever a hard error.
//!
//! Transfer sets come from the M3.5/M2 data-driven classifiers
//! (reg_liveness::reg_xfer / pred_liveness::pred_xfer Strict) restricted
//! to the measured class allowlist; unknown families simply carry no
//! tracked state (same doctrine as the v0 P-domain classes).

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

use crate::ir::Instruction;
use crate::ir::Operand;
use crate::sass_file::SassFile;

use crate::pred_liveness::{pred_xfer, XferMode};
use crate::reg_liveness::{reg_xfer, role_class};

/// Measured rules (DATA). `arch` must match the plan's arch (scope lock).
#[derive(Debug, Clone, Deserialize)]
pub struct StallRules {
    pub arch: String,
    /// 4-bit field; policy cap 11 (BUG-036: >=12 hangs).
    pub cap_stall: u8,
    /// R1 global floor for every in-window instruction.
    pub floor_global: u8,
    /// IMAD* cout -> IADD3.X cin, consumer directly next (d0).
    pub floor_dmix_d0: u8,
    /// any measured P producer -> @P guard, consumer directly next (d0).
    pub floor_guard_d0: u8,
    /// guard with TWO instructions between producer and consumer.
    pub floor_guard_d2: u8,
    /// guard with exactly ONE instruction between: forbidden for the
    /// data/atomic consumer classes (v1: isetp-class goes through R6).
    #[serde(default = "default_true")]
    pub guard_d1_forbid: bool,
    /// v1 R6: producer floor for guard-D1 pairs whose consumer is an
    /// ISETP-class op (measured legal band 5..=11 on B300).
    #[serde(default = "default_d1_isetp_floor")]
    pub guard_d1_isetp_floor: u8,
    /// v1: producers with stall >= this inside a guard relation are
    /// report-only risk rows (measured bad-zone pockets at 12/13 on
    /// sm_103a; raise-only cannot help, elimination is the remedy).
    #[serde(default = "default_legacy_risk_from")]
    pub legacy_stall_risk_from: u8,
    /// v2 R8: uniform-ALU UR write -> VECTOR consumer UR operand at d0
    /// (cross-domain read; measured uxread class).
    #[serde(default = "default_xread_d0")]
    pub floor_xread_d0: u8,
    /// v2 R9: R2UR conversion boundary at d0, either direction
    /// (vector-ALU R write -> R2UR read, or R2UR UR write -> consumer).
    #[serde(default = "default_r2ur_d0")]
    pub floor_r2ur_d0: u8,
    /// v2 R10: UISETP UP write -> uniform @UP guard at d0.
    #[serde(default = "default_uguard_d0")]
    pub floor_uguard_d0: u8,
    /// v2 R10: UISETP UP write -> uniform @UP guard at d1 (REPAIRABLE
    /// unlike the P-domain D1 pathology; measured clean band 8..=11).
    #[serde(default = "default_uguard_d1")]
    pub floor_uguard_d1: u8,
    #[serde(default)]
    pub rules_version: String,
    #[serde(default)]
    pub provenance: serde_json::Value,
}

fn default_xread_d0() -> u8 {
    6
}

fn default_r2ur_d0() -> u8 {
    8
}

fn default_uguard_d0() -> u8 {
    10
}

fn default_uguard_d1() -> u8 {
    8
}

fn default_d1_isetp_floor() -> u8 {
    5
}

fn default_legacy_risk_from() -> u8 {
    12
}

fn default_true() -> bool {
    true
}

impl StallRules {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("stallfix: cannot read rules {}", path.display()))?;
        Self::from_str_json(&text)
            .with_context(|| format!("stallfix: rules {}", path.display()))
    }

    pub fn from_str_json(text: &str) -> Result<Self> {
        let owned;
        let text = match crate::table::IsaTable::embedded_section(text, "stallfix") {
            Some(sec) => { owned = sec; &owned }
            None => text,
        };
        let r: StallRules = serde_json::from_str(text)
            .context("stallfix: rules JSON is not valid POSTFIX-103 JSON")?;
        r.sanity()?;
        Ok(r)
    }

    fn sanity(&self) -> Result<()> {
        if self.arch.is_empty() {
            bail!("stallfix: rules.arch is empty");
        }
        if self.cap_stall > 15 {
            bail!(
                "stallfix: rules.cap_stall {} exceeds the 4-bit stall field",
                self.cap_stall
            );
        }
        for (name, f) in [
            ("floor_global", self.floor_global),
            ("floor_dmix_d0", self.floor_dmix_d0),
            ("floor_guard_d0", self.floor_guard_d0),
            ("floor_guard_d2", self.floor_guard_d2),
            ("guard_d1_isetp_floor", self.guard_d1_isetp_floor),
            ("floor_xread_d0", self.floor_xread_d0),
            ("floor_r2ur_d0", self.floor_r2ur_d0),
            ("floor_uguard_d0", self.floor_uguard_d0),
            ("floor_uguard_d1", self.floor_uguard_d1),
        ] {
            if f > self.cap_stall {
                bail!(
                    "stallfix: rules.{} ({}) > cap_stall ({}) -- malformed rules",
                    name,
                    f,
                    self.cap_stall
                );
            }
        }
        if self.legacy_stall_risk_from > 15 {
            bail!("stallfix: rules.legacy_stall_risk_from exceeds the 4-bit field");
        }
        Ok(())
    }
}

/// Windowed legalize plan for ONE kernel: [start, end) instruction indices,
/// 0-based, end-exclusive (G8b convention, identical to ra/sched plans).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct StallKernelPlan {
    #[serde(default)]
    pub windows: Vec<(u32, u32)>,
}

/// Whole-file plan keyed by kernel name; `arch` scope-locks the run to the
/// measured rules file.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct StallFixPlan {
    pub arch: String,
    #[serde(default)]
    pub kernels: BTreeMap<String, StallKernelPlan>,
}

/// One applied raise, with the measured rule(s) responsible for the floor.
#[derive(Debug, Clone, Serialize)]
pub struct RaiseRecord {
    pub ins_idx: u32,
    pub old_stall: u8,
    pub new_stall: u8,
    pub rules: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistEntry {
    pub old: u8,
    pub new: u8,
    pub count: usize,
}

/// v1: one guard-D1 site (exactly one instruction between producer and
/// guard consumer) with its measured consumer-class and the action the
/// pass took (or would have to take) under the v1 class rules.
#[derive(Debug, Clone, Serialize)]
pub struct D1Site {
    pub prod_idx: u32,
    pub prod_op: String,
    pub prod_stall: u8,
    pub guard_idx: u32,
    pub guard_op: String,
    pub class: String,
    pub action: String,
}

/// v1: a guard relation whose producer stall sits in the legacy S>=12
/// zone (measured bad-band pockets on sm_103a for some classes; postfix
/// can neither lower nor raise-legalize -- risk row, report-only).
#[derive(Debug, Clone, Serialize)]
pub struct HighStallRisk {
    pub prod_idx: u32,
    pub prod_op: String,
    pub prod_stall: u8,
    pub guard_idx: u32,
    pub guard_op: String,
    pub dist: u32,
    pub class: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KernelStallReport {
    pub name: String,
    pub n_ins: usize,
    pub windows: Vec<(u32, u32)>,
    pub n_annotated: usize,
    pub raises: Vec<RaiseRecord>,
    pub n_raises: usize,
    pub hist: Vec<HistEntry>,
    /// In-window input stalls already above the policy cap (left untouched,
    /// reported; raise-only never lowers them).
    pub input_above_cap: Vec<u32>,
    /// v1: all guard-D1 sites seen in the windows (any class).
    #[serde(default)]
    pub d1_sites: Vec<D1Site>,
    /// v1: guard relations with producer stall >= legacy_stall_risk_from.
    #[serde(default)]
    pub high_stall_risk: Vec<HighStallRisk>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StallFixReport {
    pub arch: String,
    pub cap_stall: u8,
    #[serde(default)]
    pub rules_version: String,
    pub kernels: Vec<KernelStallReport>,
    pub total_raises: usize,
    pub provenance: serde_json::Value,
}

#[derive(Debug)]
pub struct StallFixRun {
    pub file: SassFile,
    pub out_text: String,
    pub report: StallFixReport,
}

// ---------------------------------------------------------------------------
// Measured v0 classification (port of work/stallsuf/postfix_ss.py semantics
// onto the typed IR; gate G-SS3a pins byte-identity of the two engines).
// ---------------------------------------------------------------------------

fn pred_num(o: &Operand) -> Option<u8> {
    match o {
        Operand::Pred { num, .. } => Some(*num),
        _ => None,
    }
}

/// Predicate cout set of the measured producer classes (P0..P6; PT never
/// counts as a produced value here).
fn p_writes(ins: &Instruction) -> Vec<u8> {
    let op = ins.opcode_full.as_str();
    let ops = &ins.operands;
    let pick = |i: usize| -> Option<u8> { ops.get(i).and_then(pred_num).filter(|&n| n <= 6) };
    if op == "IADD3.X" {
        [pick(1), pick(2)].into_iter().flatten().collect()
    } else if op.starts_with("ISETP") {
        pick(0).into_iter().collect()
    } else if op.contains(".X") || op.starts_with("IMAD.WIDE") {
        pick(1).into_iter().collect()
    } else {
        Vec::new()
    }
}

/// Carry-in predicate reads of the measured consumer classes (P0..P5).
fn p_read_cin(ins: &Instruction) -> Vec<u8> {
    let op = ins.opcode_full.as_str();
    let ops = &ins.operands;
    let take = |o: &Operand| -> Option<u8> {
        match o {
            Operand::Pred { num, neg } if !neg && *num <= 5 => Some(*num),
            _ => None,
        }
    };
    if op == "IADD3.X" {
        let n = ops.len();
        let mut out = Vec::new();
        if n >= 1 {
            out.extend(take(&ops[n - 1]));
        }
        if n >= 2 {
            out.extend(take(&ops[n - 2]));
        }
        out
    } else if op.starts_with("IMAD.WIDE.U32.X") || (op.contains(".X") && op.starts_with("IMAD")) {
        ops.last().and_then(take).into_iter().collect()
    } else {
        Vec::new()
    }
}

/// Non-uniform guard predicate (@Pn/@!Pn, P0..P6) if this instruction is
/// predicate-guard executed.
fn guard_pred(ins: &Instruction) -> Option<u8> {
    ins.guard
        .as_ref()
        .and_then(|g| if !g.uniform && g.pred <= 6 { Some(g.pred) } else { None })
}

/// v1: measured consumer-class of a guard consumer (F-SS4 census-hi):
/// ISETP.* consumers are their own physics class (P -> P path), ATOM*/RED*
/// are the atomic-memory class (guarded forms silicon-gated on sm_103a),
/// everything else is the generic data class of STALLSUF-1.
fn guard_consumer_class(ins: &Instruction) -> &'static str {
    let op = ins.opcode_full.as_str();
    if op.starts_with("ISETP") {
        "isetp"
    } else if op.starts_with("ATOM") || op.starts_with("RED") {
        "atomic"
    } else {
        "data"
    }
}

// ---------------------------------------------------------------------------
// v2 uniform-domain / boundary classification (F-SS2 census, B300
// 2026-08-22). Transfer sets come from the M3.5/M2 data-driven
// classifiers; the producer/consumer sides below are restricted to the
// classes the silicon census actually measured. Unknown families carry no
// tracked state -- identical doctrine to the v0 P-domain allowlist.
// ---------------------------------------------------------------------------

/// Base opcode of a uniform-family op is U-prefixed (UIADD3/UIMAD/ULOP3/
/// UMOV/UISETP/ULDC/...). The R2UR/UR2R converters are NOT uniform ops:
/// they sit on the cross-domain boundary (rule R9).
fn is_uniform_op(ins: &Instruction) -> bool {
    ins.opcode.starts_with('U')
}

/// v2 producer-side tracked outputs of one instruction.
#[derive(Default)]
struct UProd {
    /// Uniform-ALU UR defs (measured producers: UIADD3/UIMAD(.WIDE)) --
    /// feeds R7 (uniform consumer) / R8 (vector consumer).
    ur_alu: BTreeSet<u8>,
    /// R2UR UR defs -- feeds R9 (boundary producer side).
    ur_r2ur: BTreeSet<u8>,
    /// Vector-ALU/cmp R defs -- feeds R9 (an R2UR consumer at d0).
    r_vec: BTreeSet<u8>,
    /// UISETP UP defs -- feeds R10 (uniform guard).
    up_isetp: BTreeSet<u8>,
    /// UIADD3.X UP carry-out defs -- R7 chain member (ucarry class).
    up_carry: BTreeSet<u8>,
}

fn uprod(ins: &Instruction) -> UProd {
    let mut p = UProd::default();
    let rx = reg_xfer(ins);
    if rx.known {
        let cls = role_class(ins.opcode.as_str());
        if is_uniform_op(ins) && cls == Some("alu") {
            p.ur_alu = rx.udefs.clone();
        }
        if !is_uniform_op(ins) && matches!(cls, Some("alu") | Some("cmp")) {
            p.r_vec = rx.rdefs.clone();
        }
        if ins.opcode == "R2UR" {
            p.ur_r2ur = rx.udefs.clone();
        }
    }
    let px = pred_xfer(ins, XferMode::Strict);
    if ins.opcode == "UISETP" {
        p.up_isetp = px.udefs.clone();
    }
    if ins.opcode == "UIADD3" && ins.modifiers.iter().any(|m| m == ".X") {
        p.up_carry = px.udefs;
    }
    p
}

// ---------------------------------------------------------------------------
// Core pass
// ---------------------------------------------------------------------------

pub fn run_file(text: &str, plan: &StallFixPlan, rules: &StallRules) -> Result<StallFixRun> {
    rules.sanity()?;
    if plan.arch != rules.arch {
        bail!(
            "stallfix: plan arch '{}' != rules arch '{}' -- the measured floors \
             are scope-locked; refusing to run",
            plan.arch,
            rules.arch
        );
    }
    let file = crate::sass_file::parse_sass_file_str_strict(text)
        .context("stallfix: strict parse failed")?;

    // Per (kernel_idx, ins_idx) floor computation with rule attribution.
    let mut floors: BTreeMap<(usize, u32), (u8, BTreeSet<&'static str>)> = BTreeMap::new();
    let mut above_cap: BTreeMap<usize, Vec<u32>> = BTreeMap::new();
    let mut n_annotated: BTreeMap<usize, usize> = BTreeMap::new();
    // v1: full maps instead of bail-at-first -- a run is either clean,
    // or it aborts with the COMPLETE D1 site list (input for D1 elimination).
    let mut d1_sites: BTreeMap<usize, Vec<D1Site>> = BTreeMap::new();
    let mut risk_rows: BTreeMap<usize, Vec<HighStallRisk>> = BTreeMap::new();
    let mut d1_violations: Vec<serde_json::Value> = Vec::new();

    for (kidx, k) in file.kernels.iter().enumerate() {
        let kp = match plan.kernels.get(&k.name) {
            Some(p) => p,
            None => continue,
        };
        // window validation: sorted, in-range, non-overlapping
        let mut last_end = 0u32;
        let n = k.instructions.len() as u32;
        for &(s, e) in &kp.windows {
            if s >= e {
                bail!("stallfix: kernel {}: window [{s},{e}) is empty", k.name);
            }
            if e > n {
                bail!(
                    "stallfix: kernel {}: window [{s},{e}) past end (n_ins={})",
                    k.name,
                    n
                );
            }
            if s < last_end {
                bail!("stallfix: kernel {}: overlapping/unsorted windows", k.name);
            }
            last_end = e;
        }
        // window id per instruction index (same-window consumer rule)
        let mut win_of: Vec<i64> = vec![-1; k.instructions.len()];
        for (wpos, &(s, e)) in kp.windows.iter().enumerate() {
            for i in s..e {
                win_of[i as usize] = wpos as i64;
                let ins = &k.instructions[i as usize];
                if !ins.hand_sched {
                    bail!(
                        "stallfix: kernel {}: instruction {} inside window [{},{}) has \
                         no ctrl prefix -- the legalize region must be fully \
                         hand-scheduled (frozen)",
                        k.name,
                        i,
                        s,
                        e
                    );
                }
                *n_annotated.entry(kidx).or_default() += 1;
                if ins.ctrl.stall > rules.cap_stall {
                    above_cap.entry(kidx).or_default().push(i);
                }
                floors
                    .entry((kidx, i))
                    .or_insert((0, BTreeSet::new()))
                    .1
                    .insert("R1");
                let f = floors.get_mut(&(kidx, i)).unwrap();
                if rules.floor_global > f.0 {
                    f.0 = rules.floor_global;
                }
            }
        }
        if kp.windows.is_empty() {
            continue;
        }

        let meets = |f: &mut (u8, BTreeSet<&'static str>), val: u8, why: &'static str| {
            f.1.insert(why);
            if val > f.0 {
                f.0 = val;
            }
        };

        for (wpos, &(ws, we)) in kp.windows.iter().enumerate() {
            for i in ws..we {
                let prod_ins = &k.instructions[i as usize];
                let ws_set = p_writes(prod_ins);
                let up = uprod(prod_ins);
                let up_any = !up.ur_alu.is_empty()
                    || !up.ur_r2ur.is_empty()
                    || !up.r_vec.is_empty()
                    || !up.up_isetp.is_empty()
                    || !up.up_carry.is_empty();
                if ws_set.is_empty() && !up_any {
                    continue;
                }
                let mut live: BTreeSet<u8> = ws_set.into_iter().collect();
                let mut live_ur_alu = up.ur_alu.clone();
                let mut live_ur_r2ur = up.ur_r2ur.clone();
                let mut live_r_vec = up.r_vec.clone();
                let mut live_up_isetp = up.up_isetp.clone();
                let mut live_up_carry = up.up_carry.clone();
                // scan consumers at slot distance 1..3 inside the same window
                let mut d = 1u32;
                while d <= 3
                    && !(live.is_empty()
                        && live_ur_alu.is_empty()
                        && live_ur_r2ur.is_empty()
                        && live_r_vec.is_empty()
                        && live_up_isetp.is_empty()
                        && live_up_carry.is_empty())
                {
                    let j = i + d;
                    if j >= we || win_of[j as usize] != wpos as i64 {
                        break;
                    }
                    let cons = &k.instructions[j as usize];
                    let cin = p_read_cin(cons);
                    let grd = guard_pred(cons);
                    // v2 consumer-side view: data-driven transfer sets.
                    let crx = reg_xfer(cons);
                    let cpx = pred_xfer(cons, XferMode::Strict);
                    let cons_cls = role_class(cons.opcode.as_str());
                    let cons_alu = crx.known && matches!(cons_cls, Some("alu") | Some("cmp"));
                    if d == 1 {
                        // R7/R8: live uniform-ALU UR defs consumed at d0 by
                        // a same-domain op (R7, floor == R1) resp. a VECTOR
                        // op reading the UR operand (R8, cross-domain +2).
                        if !live_ur_alu.is_empty()
                            && cons_alu
                            && !crx.uuses.is_disjoint(&live_ur_alu)
                        {
                            let f = floors.get_mut(&(kidx, i)).unwrap();
                            if is_uniform_op(cons) {
                                meets(f, rules.floor_global, "R7-urpath");
                            } else {
                                meets(f, rules.floor_xread_d0, "R8-xread");
                            }
                        }
                        // R7 chain member: dual carry-in of UIADD3.X (the
                        // measured ucarry class; Strict uuses also carries
                        // an @UP guard read here -- floor is R1's either
                        // way, so the attribution is exact).
                        if cons.opcode == "UIADD3" && !cpx.uuses.is_disjoint(&live_up_carry) {
                            let f = floors.get_mut(&(kidx, i)).unwrap();
                            meets(f, rules.floor_global, "R7-urpath");
                        }
                        // R9: R2UR conversion boundary at d0, either
                        // direction (vector-ALU R write feeding the R2UR
                        // read; R2UR-written UR feeding an ALU-class op).
                        if cons.opcode == "R2UR" && !live_r_vec.is_empty() {
                            let hit = cons.operands.iter().skip(1).any(|o| match o {
                                Operand::Reg { num, .. } => *num != 255 && live_r_vec.contains(num),
                                _ => false,
                            });
                            if hit {
                                let f = floors.get_mut(&(kidx, i)).unwrap();
                                meets(f, rules.floor_r2ur_d0, "R9-r2ur");
                            }
                        }
                        if cons_alu && !crx.uuses.is_disjoint(&live_ur_r2ur) {
                            let f = floors.get_mut(&(kidx, i)).unwrap();
                            meets(f, rules.floor_r2ur_d0, "R9-r2ur");
                        }
                        // R10: UISETP UP write -> uniform @UP guard (d0).
                        if let Some(g) = &cons.guard {
                            if g.uniform && g.pred < 7 && live_up_isetp.contains(&g.pred) {
                                let f = floors.get_mut(&(kidx, i)).unwrap();
                                meets(f, rules.floor_uguard_d0, "R10-uguard-d0");
                            }
                        }
                    } else if d == 2 {
                        // R10: same pair at D1 is REPAIRABLE with stalls
                        // (F-SS2: clean band 8..=11; unlike the P-domain
                        // guard-D1 pathology it is never a hard error).
                        if let Some(g) = &cons.guard {
                            if g.uniform && g.pred < 7 && live_up_isetp.contains(&g.pred) {
                                let f = floors.get_mut(&(kidx, i)).unwrap();
                                meets(f, rules.floor_uguard_d1, "R10-uguard-d1");
                            }
                        }
                    }
                    for p in live.clone() {
                        if d == 1 && cin.contains(&p) {
                            // cin chain at d0: dmix floor for IMAD* -> IADD3.X,
                            // everything else is covered by R1 (floor 4 >= 1..4).
                            if cons.opcode_full == "IADD3.X"
                                && k.instructions[i as usize].opcode_full.starts_with("IMAD")
                            {
                                let f = floors.get_mut(&(kidx, i)).unwrap();
                                meets(f, rules.floor_dmix_d0, "R2-dmix-d0");
                            }
                        }
                        if grd == Some(p) {
                            let f = floors.get_mut(&(kidx, i)).unwrap();
                            let prod = &k.instructions[i as usize];
                            let prod_stall = prod.ctrl.stall;
                            let class = guard_consumer_class(cons);
                            match d {
                                1 => {
                                    meets(f, rules.floor_guard_d0, "R3-guard-d0");
                                    if prod_stall >= rules.legacy_stall_risk_from {
                                        risk_rows.entry(kidx).or_default().push(HighStallRisk {
                                            prod_idx: i,
                                            prod_op: prod.opcode_full.clone(),
                                            prod_stall,
                                            guard_idx: j,
                                            guard_op: cons.opcode_full.clone(),
                                            dist: d,
                                            class: class.to_string(),
                                        });
                                    }
                                }
                                2 => {
                                    let mut site = D1Site {
                                        prod_idx: i,
                                        prod_op: prod.opcode_full.clone(),
                                        prod_stall,
                                        guard_idx: j,
                                        guard_op: cons.opcode_full.clone(),
                                        class: class.to_string(),
                                        action: "noop".to_string(),
                                    };
                                    if !rules.guard_d1_forbid {
                                        site.action = "allowed-by-rules".to_string();
                                    } else {
                                        match class {
                                            // R6 (v1 census-hi): isetp-class D1 legal for
                                            // producer stalls 5..=cap; >=12 measured bad.
                                            "isetp" if prod_stall < rules.legacy_stall_risk_from => {
                                                meets(f, rules.guard_d1_isetp_floor,
                                                      "R6-guard-d1-isetp");
                                                site.action =
                                                    if prod_stall < rules.guard_d1_isetp_floor {
                                                        format!("floor-raise:S{:02}->S{:02}",
                                                                prod_stall,
                                                                rules.guard_d1_isetp_floor)
                                                    } else {
                                                        "noop".to_string()
                                                    };
                                            }
                                            "isetp" => {
                                                site.action = "violation".to_string();
                                                d1_violations.push(serde_json::json!({
                                                    "kernel": k.name, "prod_idx": i,
                                                    "prod_op": prod.opcode_full,
                                                    "prod_stall": prod_stall,
                                                    "guard_idx": j,
                                                    "guard_op": cons.opcode_full,
                                                    "class": class,
                                                    "reason": "guard-D1 (isetp-class) with \
                                                        producer stall >= 12: measured bad \
                                                        band on sm_103a (F-SS4 census-hi: \
                                                        S12/S13 FLAKY/MISMATCH at occupancy; \
                                                        S14/15 clean is a resonance pocket, \
                                                        not a policy target). Raise-only \
                                                        cannot lower -- eliminate the D1 \
                                                        distance instead."
                                                }));
                                            }
                                            "atomic" => {
                                                site.action = "violation".to_string();
                                                d1_violations.push(serde_json::json!({
                                                    "kernel": k.name, "prod_idx": i,
                                                    "prod_op": prod.opcode_full,
                                                    "prod_stall": prod_stall,
                                                    "guard_idx": j,
                                                    "guard_op": cons.opcode_full,
                                                    "class": class,
                                                    "reason": "guard-D1 on an atomic-memory \
                                                        consumer: guarded-atomic forms are \
                                                        silicon-gated on sm_103a (F-SS4 \
                                                        census-hi: guarded non-EL ATOMG = \
                                                        silent corruption even with an \
                                                        always-true guard; .EL = \
                                                        ILLEGAL_ADDRESS on the default \
                                                        descriptor). No stall fixes this -- \
                                                        the form needs the descriptor-policy \
                                                        port (O1-road), not postfix."
                                                }));
                                            }
                                            _ => {
                                                site.action = "violation".to_string();
                                                d1_violations.push(serde_json::json!({
                                                    "kernel": k.name, "prod_idx": i,
                                                    "prod_op": prod.opcode_full,
                                                    "prod_stall": prod_stall,
                                                    "guard_idx": j,
                                                    "guard_op": cons.opcode_full,
                                                    "class": class,
                                                    "reason": "guard-D1 (data-class) is \
                                                        FLAKY at every S<=10 under occupancy \
                                                        (STALLSUF-1 + F-SS4 census-hi: \
                                                        S09/S10 flaky too; S11 was a \
                                                        probe-geometry island, not a \
                                                        policy-grade floor). no stall \
                                                        legalizes this schedule -- \
                                                        eliminate the D1 distance instead."
                                                }));
                                            }
                                        }
                                    }
                                    d1_sites.entry(kidx).or_default().push(site);
                                }
                                3 => {
                                    meets(f, rules.floor_guard_d2, "R3-guard-d2");
                                    if prod_stall >= rules.legacy_stall_risk_from {
                                        risk_rows.entry(kidx).or_default().push(HighStallRisk {
                                            prod_idx: i,
                                            prod_op: prod.opcode_full.clone(),
                                            prod_stall,
                                            guard_idx: j,
                                            guard_op: cons.opcode_full.clone(),
                                            dist: d,
                                            class: class.to_string(),
                                        });
                                    }
                                }
                                _ => unreachable!(),
                            }
                        }
                    }
                    // kills: a consumer that (re)writes a tracked predicate ends
                    // that chain (its reads above already fired).
                    for p in p_writes(cons) {
                        live.remove(&p);
                    }
                    // v2 domain kills: a (re)write of a tracked UR/UP/R by
                    // the consumer ends that chain. Unknown register-
                    // carrying families do not kill (v0 doctrine).
                    if crx.known {
                        for u in &crx.udefs {
                            live_ur_alu.remove(u);
                            live_ur_r2ur.remove(u);
                        }
                        for r in &crx.rdefs {
                            live_r_vec.remove(r);
                        }
                    }
                    for u in &cpx.udefs {
                        live_up_isetp.remove(u);
                        live_up_carry.remove(u);
                    }
                    d += 1;
                }
            }
        }
    }

    // v1: zebrane naruszenia guard-D1 = jeden fail z kompletna mapa stanowisk
    if !d1_violations.is_empty() {
        bail!(
            "stallfix: {} guard-D1 site(s) cannot be legalized in place under \
             the v1 class rules (raise-only, cap {}):\n{}",
            d1_violations.len(),
            rules.cap_stall,
            d1_violations
                .iter()
                .map(|v| serde_json::to_string(v).unwrap())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    // plan kernels that name no kernel in the file are an error (strict plan)
    let known: BTreeSet<&str> = file.kernels.iter().map(|k| k.name.as_str()).collect();
    for name in plan.kernels.keys() {
        if !known.contains(name.as_str()) {
            bail!("stallfix: plan names unknown kernel '{name}'");
        }
    }

    // Apply raises (raise-only, capped; input above cap is left untouched).
    let mut edits: BTreeMap<(usize, u32), u8> = BTreeMap::new();
    let mut reports: Vec<KernelStallReport> = Vec::new();
    let mut total_raises = 0usize;
    for (kidx, k) in file.kernels.iter().enumerate() {
        let kp = match plan.kernels.get(&k.name) {
            Some(p) => p,
            None => continue,
        };
        let mut raises: Vec<RaiseRecord> = Vec::new();
        let mut hist: BTreeMap<(u8, u8), usize> = BTreeMap::new();
        for (&(fk, i), &(fl, ref why)) in &floors {
            if fk != kidx {
                continue;
            }
            let ins = &k.instructions[i as usize];
            let cur = ins.ctrl.stall;
            let new = fl.min(rules.cap_stall);
            if new > cur {
                edits.insert((kidx, i), new);
                *hist.entry((cur, new)).or_default() += 1;
                total_raises += 1;
                raises.push(RaiseRecord {
                    ins_idx: i,
                    old_stall: cur,
                    new_stall: new,
                    rules: why.iter().map(|s| s.to_string()).collect(),
                });
            }
        }
        let hist = hist
            .into_iter()
            .map(|((old, new), count)| HistEntry { old, new, count })
            .collect();
        let n_raises = raises.len();
        reports.push(KernelStallReport {
            name: k.name.clone(),
            n_ins: k.instructions.len(),
            windows: kp.windows.clone(),
            n_annotated: *n_annotated.get(&kidx).unwrap_or(&0),
            raises,
            n_raises,
            hist,
            input_above_cap: above_cap.get(&kidx).cloned().unwrap_or_default(),
            d1_sites: d1_sites.get(&kidx).cloned().unwrap_or_default(),
            high_stall_risk: risk_rows.get(&kidx).cloned().unwrap_or_default(),
        });
    }

    let out_text = emit_stall_splice(text, &edits)?;
    // re-parse proof: the emitted text parses to exactly the input file with
    // only the listed stall fields changed (mirrors ra::verify_splice_proof).
    verify_splice(text, &out_text, &file, &edits)?;

    Ok(StallFixRun {
        file,
        out_text,
        report: StallFixReport {
            arch: rules.arch.clone(),
            cap_stall: rules.cap_stall,
            rules_version: rules.rules_version.clone(),
            kernels: reports,
            total_raises,
            provenance: rules.provenance.clone(),
        },
    })
}

// ---------------------------------------------------------------------------
// Emission: in-place stall-digit replacement of the ctrl prefix; every other
// character of every line is byte-verbatim (raise-only, BUG-036 cap).
// ---------------------------------------------------------------------------

static CC_LINE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\[B[0-5-]{6}:R[0-5-]:W[0-5-]:[Y-]:S(\d{2})\]").unwrap()
});

pub fn emit_stall_splice(original: &str, edits: &BTreeMap<(usize, u32), u8>) -> Result<String> {
    use std::collections::BTreeSet;

    static RE_LABEL: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"^[A-Za-z_][A-Za-z0-9_.$]*\s*:\s*").unwrap()
    });

    let mut out_lines: Vec<String> = Vec::new();
    let mut in_kernel = false;
    let mut kidx: isize = -1;
    let mut ins_count = 0u32;
    for line in original.lines() {
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
        let want = edits.get(&(kidx as usize, idx)).copied();
        match want {
            None => out_lines.push(line.to_string()),
            Some(new_stall) => {
                let caps = CC_LINE_RE.captures(line).ok_or_else(|| {
                    anyhow::anyhow!(
                        "stallfix: emitter: instruction line for raise has no ctrl \
                         prefix: {line:?}"
                    )
                })?;
                let digits = caps.get(1).unwrap().range();
                let mut nl = line.to_string();
                nl.replace_range(digits.clone(), &format!("{new_stall:02}"));
                // character-level diff proof: only the two stall digits moved
                if nl.len() != line.len() {
                    bail!("stallfix: emitter: line length changed on raise: {line:?}");
                }
                let mut diffs = 0;
                let mut diff_pos: BTreeSet<usize> = BTreeSet::new();
                for (a, b) in line.bytes().zip(nl.bytes()) {
                    if a != b {
                        diffs += 1;
                    }
                }
                for (pos, (a, b)) in line.bytes().zip(nl.bytes()).enumerate() {
                    if a != b {
                        diff_pos.insert(pos);
                    }
                }
                if diffs > 2 || !diff_pos.iter().all(|&p| digits.contains(&p)) {
                    bail!(
                        "stallfix: emitter: raise changed bytes outside the stall \
                         digits on {line:?}"
                    );
                }
                out_lines.push(nl);
            }
        }
    }
    let mut out = out_lines;
    if original.ends_with('\n') {
        out.push(String::new());
    }
    Ok(out.join("\n"))
}

/// Emission proof: strict re-parse of the output; every instruction equals
/// the input's (guard/opcode/operands/ctrl/rsd) except the raised stall
/// fields, which equal the plan values. Also: identical instruction count
/// per kernel.
fn verify_splice(
    original_text: &str,
    out_text: &str,
    input_file: &SassFile,
    edits: &BTreeMap<(usize, u32), u8>,
) -> Result<()> {
    let reparsed = crate::sass_file::parse_sass_file_str_strict(out_text)
        .context("stallfix: emission re-parse failed (internal drift)")?;
    if reparsed.kernels.len() != input_file.kernels.len() {
        bail!("stallfix: re-parse kernel count drift");
    }
    // whole-file line discipline: only lines carrying raises may differ
    if original_text.lines().count() != out_text.lines().count() {
        bail!("stallfix: emission changed the line count");
    }
    for (kidx, (kin, kout)) in input_file.kernels.iter().zip(&reparsed.kernels).enumerate() {
        if kin.instructions.len() != kout.instructions.len() {
            bail!("stallfix: kernel {}: instruction count drift", kin.name);
        }
        for (i, (a, b)) in kin.instructions.iter().zip(&kout.instructions).enumerate() {
            let raised = edits.get(&(kidx, i as u32)).copied();
            if a.opcode_full != b.opcode_full
                || a.guard != b.guard
                || a.operands != b.operands
                || a.rsd != b.rsd
                || a.hand_sched != b.hand_sched
                || a.ctrl.write_bar != b.ctrl.write_bar
                || a.ctrl.read_bar != b.ctrl.read_bar
                || a.ctrl.wait_mask != b.ctrl.wait_mask
                || a.ctrl.yield_flag != b.ctrl.yield_flag
            {
                bail!(
                    "stallfix: re-parse drift at kernel {} ins {} (non-stall fields \
                     must be invariant)",
                    kin.name,
                    i
                );
            }
            match raised {
                Some(ns) => {
                    if b.ctrl.stall != ns {
                        bail!(
                            "stallfix: re-parse stall mismatch at {} ins {}: wanted {}, \
                             got {}",
                            kin.name,
                            i,
                            ns,
                            b.ctrl.stall
                        );
                    }
                }
                None => {
                    if a.ctrl.stall != b.ctrl.stall {
                        bail!(
                            "stallfix: re-parse stall drift at {} ins {} outside the \
                             raise set",
                            kin.name,
                            i
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

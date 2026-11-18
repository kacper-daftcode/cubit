//! `CUBIT_WAIT_DRAINED=head | paths` (opt-in, default off; honoured only together with
//! `CUBIT_WAIT_POLICY=1`, whose flow graph it works on): a wait is not written where another
//! wait has drained its scoreboard.
//!
//! The barrier allocator (`scheduling_pass::reallocate_barriers`) writes waits USE BY USE: every
//! use — a batch of producers on one write barrier, or one read barrier — gets its first readers
//! on every path, the colouring gives the use a scoreboard, and one bit a waiter goes into the
//! word. A wait written for ANOTHER use on the same scoreboard is never credited. So a word
//! waits for a result of the round before although the head of its own round has drained that
//! scoreboard, a second reader waits behind the wait of another use, and the first reader of a
//! round waits for what the tail of the round before drained. A wait bit on an empty scoreboard
//! costs nothing; but a scoreboard counts, and where a younger result has armed it since, the
//! word blocks behind a result it does not read.
//!
//! The rule runs ONE forward scan on the control-flow graph ([`Armers::scan`]): the state at a
//! word is the set of words that armed a scoreboard — by a write barrier or a read barrier — and
//! that SOME path has not waited since (the sets are united where paths meet, so "not in the
//! set" means drained on every path). A wait bit of any word drains its scoreboard, a `DEPBAR`
//! too. With it:
//!
//! * `head` — **a wait for the barriers of the round before is not written behind the first wait
//!   of its own round on that scoreboard.** The bit goes when every word that arms a barrier the
//!   bit was written for reaches the waiter only over a back edge of the flow graph, and on
//!   every path from every loop head behind that edge down to the waiter another word waits the
//!   scoreboard in front of it.
//! * `paths` — **a wait is written on the first word of every path that needs it and nowhere
//!   behind it**: the fixed point. In the order of the flow without its back edges a wait is
//!   placed when a barrier it was written for can still be armed at its word; then, one at a
//!   time in the same order, a placed wait is taken off again while every waiter of every use
//!   still stands behind a wait of the use's scoreboard on every path from its setters.
//!
//! Two kinds of bits go. On an EMPTY scoreboard (nothing armed since its last wait on any path)
//! the machine's state is the same at every word with and without the bit. Behind a LANDED
//! result — the scoreboard holds something, but nothing the bit was written for — the bit
//! released what the word does not need, and without it that stays pending up to the next wait
//! of the scoreboard: this changes the machine, and it can put two results on one scoreboard in
//! front of one wait that the allocator's own waits kept apart. Such a set is formed only in two
//! shapes ([`may_fly_together`]): plain shared loads that are one of
//! `scheduling_pass::MEASURED_SHARED_SETS` by their forms, and guarded loads of one form the
//! allocator batches, each under a predicate of its own. For any other pair the nearest wait in
//! front of the place where the two would meet stays (the scan unites the paths: two results
//! that reach one word on different paths count as a set).
//!
//! Not touched: the colouring (every scoreboard number stays), a hand-scheduled word (its bits
//! stay; it arms and drains like any other), a wait the allocator did not write for a use, the
//! word of an ordered event ([`ordered_event`]: what its wait holds back is not an operand), and
//! a wait whose own barrier — the release of a read barrier included — can still be armed. The
//! rule stands in front of the allocator's two closing clauses (a second writer of a pending
//! register, a reader of two guarded producers): they close the schedule on the waits that stand.
//!
//! A PARKED wait is a wait written for a use: for a reader that cannot carry a wait the allocator
//! writes it on the latest word in front of the reader that can, and tells the rule so. The word
//! that carries it may be a waiter of another use on the same scoreboard; a bit is judged by
//! every use it was written for, and it goes only where all of them are drained.
//!
//! THE LEGALITY OF TAKING A WAIT OFF, beyond the uses. A bit is judged by the uses it was written
//! for, on the paths of the flow graph. Two things stand outside that statement, and the rule
//! holds both:
//!
//! * **The jump tables.** The flow graph reads no table: it gives a register-indirect branch the
//!   word behind it, every block no branch names and (here) the join of its case blocks. A table
//!   entry may name any word -- one a branch names too --, and that is a path the graph does not
//!   have. The closing check of [`apply`] therefore walks, beside the graph, every entry of
//!   every dispatch's table ([`put_constants`]: the kernel's constant section of bank 2 as the
//!   template of the build holds it; [`jump_table`]: the one form the vendor's compiler
//!   writes). A dispatch whose table cannot be read -- no template, another form, an entry that
//!   is no word of the kernel -- keeps every bit written for a barrier that can still be armed
//!   where it issues.
//! * **The fields.** A wait releases every barrier armed on its scoreboard, also the read
//!   barrier of a word that no use of the bit names: a wait written for one use can be the wait
//!   that another word's late operand rests on. Where the allocator shares a wait on purpose it
//!   tells the rule (`CUBIT_LOAD_COVER`'s sharing leaves an arrive's read barrier to a wait of the
//!   loop's head: the wait at the rewrite, else the one in front of it, is written for its use
//!   too). Whatever else shares a wait unsaid is held by the guard on the fields: no wait comes off
//!   where the waiting word, or a word behind it in front of the next wait of the scoreboard,
//!   rewrites a source of a word whose read barrier that wait released. Its oracle is the
//!   write-after-read half of the path audit (`scheduling_pass::report_war_on_paths`): the
//!   schedule the rule leaves names no rewrite that the fields it started from do not name.

use crate::cfg_flow::Cfg;
use crate::ir::{Instruction, Operand};
use crate::scheduling_pass as sp;
use std::collections::{BTreeMap, BinaryHeap, HashMap, HashSet};

const NB: usize = sp::NUM_BARRIERS;

/// The two values of `CUBIT_WAIT_DRAINED`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drained {
    /// behind the first wait of its round, no wait for the barriers of the round before
    Head,
    /// the fixed point: a wait on the first word of every path that needs it
    Paths,
}

impl Drained {
    pub fn name(self) -> &'static str {
        match self {
            Drained::Head => "head",
            Drained::Paths => "paths",
        }
    }
}

/// `CUBIT_WAIT_DRAINED` as written: `Ok(None)` when unset, empty or `0`, and when
/// `CUBIT_WAIT_POLICY=1` is not honoured (the rule works on its flow graph); the value for
/// `head` and `paths`; the message of the refusal for anything else.
pub fn request() -> Result<Option<Drained>, String> {
    let on = |v: Drained| Ok(sp::wait_policy().then_some(v));
    match std::env::var("CUBIT_WAIT_DRAINED") {
        Err(_) => Ok(None),
        Ok(v) if v.is_empty() || v == "0" => Ok(None),
        Ok(v) if v == "head" => on(Drained::Head),
        Ok(v) if v == "paths" => on(Drained::Paths),
        Ok(v) => Err(format!(
            "CUBIT_WAIT_DRAINED={v}: the values are `head` (no wait for a barrier of the round before behind the first wait of its own round) and `paths` (a wait on the first word of every path that needs it); unset = every wait as the allocator writes it"
        )),
    }
}

/// A wait bit the allocator wrote for a use: on `word`, of scoreboard `sb`, for the barriers the
/// words `setters` arm.
#[derive(Clone, Debug)]
pub struct Written {
    pub word: usize,
    pub sb: u8,
    pub setters: Vec<usize>,
}

/// What the rule did to one kernel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// wait bits not written on a scoreboard nothing had armed since its last wait
    pub empty: usize,
    /// wait bits not written behind something the bit was not written for
    pub landed: usize,
    /// wait bits of the rule's kind that stay: without them two results would fly together in a
    /// set that is not measured
    pub kept: usize,
    /// wait bits of the rule's kind that stay for a jump table: an entry of a dispatch's table
    /// is a path the flow graph does not have, or the table cannot be read
    pub tables: usize,
    /// wait bits of the rule's kind that stay for the fields: without them a word would rewrite
    /// a source of a word whose read barrier no wait has released
    pub fields: usize,
}

thread_local! {
    static LAST: std::cell::Cell<Option<(Drained, Report)>> = const { std::cell::Cell::new(None) };
    static CONSTANTS: std::cell::RefCell<Option<Vec<u8>>> = const { std::cell::RefCell::new(None) };
}

/// The constant section of bank 2 of the kernel the allocator runs next, as the template of the
/// build holds it (`cubit asm -T`: the output keeps the template's bytes) -- the jump tables of
/// its register-indirect branches. `None`: there is no template, or it has no such section;
/// every dispatch of the kernel is then one whose table cannot be read. It stays until the next
/// call; [`apply`] alone reads it.
pub fn put_constants(bytes: Option<Vec<u8>>) {
    CONSTANTS.with(|s| *s.borrow_mut() = bytes);
}

/// The section `.nv.constant2.<kernel>` of a cubin, for [`put_constants`].
pub fn constants_of(cubin: &crate::elf::CubinFile, kernel: &str) -> Option<Vec<u8>> {
    let section = cubin.find_section(&format!(".nv.constant2.{kernel}"))?;
    cubin.section_bytes(section).map(<[u8]>::to_vec)
}

/// The report of the last kernel the allocator ran the rule on (once).
pub fn take_report() -> Option<(Drained, Report)> {
    LAST.with(|l| l.take())
}

pub(crate) fn put_report(mode: Drained, r: Report) {
    LAST.with(|l| l.set(Some((mode, r))));
}

/// The word of an ordered event: control flow and convergence, the thread set of the warp, a
/// synchronisation word, an atomic, the predicate set as a whole, a read of a timer. What a wait
/// on such a word holds back is not one of its operands, and the rule leaves every bit there.
pub fn ordered_event(insn: &Instruction) -> bool {
    let op = insn.opcode.as_str();
    if sp::is_control_flow(op)
        || matches!(
            op,
            "BRX" | "JMX" | "BRXU" | "JMXU" | "JCAL" | "TRAP" | "RTT"
                | "WARPSYNC" | "ENDCOLLECTIVE" | "YIELD" | "NANOSLEEP" | "PREEXIT" | "BPT" | "VOTE" | "VOTEU" | "ELECT"
                | "BAR" | "SYNCS" | "ARRIVES" | "UBLKCP" | "ACQBULK" | "LDGSTS" | "LDGDEPBAR" | "UTMACMDFLUSH"
                | "UTMALDG" | "UTMASTG" | "UTMACCTL" | "CGABAR" | "UCGABAR_ARV" | "UCGABAR_WAIT" | "USETMAXREG"
                | "FENCE" | "MEMBAR" | "DEPBAR" | "ERRBAR" | "CGAERRBAR" | "CCTL" | "PMTRIG"
                | "ATOM" | "ATOMG" | "ATOMS" | "RED" | "REDG"
                | "P2R" | "R2P"
        )
    {
        return true;
    }
    if crate::sync_class::enabled() && crate::sync_class::classify(insn).is_some() {
        return true;
    }
    if matches!(op, "S2R" | "CS2R" | "S2UR" | "CS2UR") {
        let text = insn.raw_text.to_uppercase();
        return text.contains("TIMER") || text.contains("CLOCK");
    }
    false
}

/// May the results of the two words fly together on one scoreboard in front of one wait where
/// the allocator's own waits kept them apart? `set` = every result pending with them, in text
/// order. Yes for a set of plain shared loads that is one of
/// `scheduling_pass::MEASURED_SHARED_SETS` by its forms, and for two guarded loads of one form
/// the allocator batches, each under a predicate of its own.
pub fn may_fly_together(insns: &[Instruction], set: &[usize], a: usize, b: usize) -> bool {
    let guard = |k: usize| insns[k].guard.as_ref().filter(|g| g.pred < 7).map(|g| (g.uniform, g.pred));
    let forms: Vec<&str> = set.iter().map(|&k| insns[k].opcode_full.as_str()).collect();
    if set.iter().all(|&k| guard(k).is_none() && !insns[k].hand_sched) && sp::MEASURED_SHARED_SETS.contains(&forms.as_slice()) {
        return true;
    }
    match (guard(a), guard(b)) {
        (Some(x), Some(y)) => {
            x != y
                && insns[a].opcode_full == insns[b].opcode_full
                && insns[a].opcode.starts_with("LD")
                && sp::batch_form(&insns[a])
                && sp::batch_form(&insns[b])
        }
        _ => false,
    }
}

/// The words that arm a scoreboard — a word with a write barrier, a word with a read barrier —
/// and the forward scan over them.
pub struct Armers {
    /// one entry a barrier a word sets: (the word, the scoreboard, a write barrier?)
    pub who: Vec<(usize, u8, bool)>,
    /// the entries a word sets
    pub of_word: Vec<Vec<usize>>,
    /// per scoreboard, the entries on it as a bit set
    on_sb: Vec<Vec<u64>>,
    /// the entries that are results (write barriers) as a bit set
    results: Vec<u64>,
    width: usize,
}

/// The state of the scan at the ENTRY of every word (in front of its own wait).
pub struct Pending {
    width: usize,
    bits: Vec<u64>,
    /// the words some path from the kernel's entry reaches
    pub reached: Vec<bool>,
}

impl Pending {
    pub fn at(&self, j: usize) -> &[u64] {
        &self.bits[j * self.width..(j + 1) * self.width]
    }
    /// Can the barrier `id` still be armed when word `j` issues?
    pub fn has(&self, j: usize, id: usize) -> bool {
        (self.bits[j * self.width + id / 64] >> (id % 64)) & 1 == 1
    }
}

impl Armers {
    pub fn of(insns: &[Instruction]) -> Armers {
        let n = insns.len();
        let mut who: Vec<(usize, u8, bool)> = Vec::new();
        let mut of_word: Vec<Vec<usize>> = vec![Vec::new(); n];
        for (i, x) in insns.iter().enumerate() {
            for (sb, result) in [(x.ctrl.write_bar, true), (x.ctrl.read_bar, false)] {
                if (sb as usize) < NB {
                    of_word[i].push(who.len());
                    who.push((i, sb, result));
                }
            }
        }
        let width = who.len().div_ceil(64).max(1);
        let mut on_sb = vec![vec![0u64; width]; NB];
        let mut results = vec![0u64; width];
        for (id, &(_, sb, result)) in who.iter().enumerate() {
            on_sb[sb as usize][id / 64] |= 1u64 << (id % 64);
            if result {
                results[id / 64] |= 1u64 << (id % 64);
            }
        }
        Armers { who, of_word, on_sb, results, width }
    }

    /// The barriers of scoreboard `sb` in the state `s` (`results_only`: the write barriers).
    pub fn on(&self, s: &[u64], sb: u8, results_only: bool) -> Vec<usize> {
        let mut out = Vec::new();
        for k in 0..self.width {
            let mut m = s[k] & self.on_sb[sb as usize][k];
            if results_only {
                m &= self.results[k];
            }
            while m != 0 {
                out.push(k * 64 + m.trailing_zeros() as usize);
                m &= m - 1;
            }
        }
        out
    }

    /// The forward scan: at the entry of every word, the barriers that some path from the
    /// kernel's entry leaves armed — set by a word on the way and waited by no word since.
    /// `waits` = the scoreboards each word waits (its wait mask, the scoreboard of a `DEPBAR`).
    pub fn scan(&self, c: &Cfg, waits: &[u8]) -> Pending {
        let n = c.succ.len();
        let w = self.width;
        let mut bits = vec![0u64; n * w];
        let mut reached = vec![false; n];
        if n == 0 {
            return Pending { width: w, bits, reached };
        }
        reached[0] = true;
        let mut queued = vec![false; n];
        let mut work: Vec<usize> = vec![0];
        queued[0] = true;
        let mut s = vec![0u64; w];
        while let Some(j) = work.pop() {
            queued[j] = false;
            s.copy_from_slice(&bits[j * w..(j + 1) * w]);
            for (sb, on) in self.on_sb.iter().enumerate() {
                if waits[j] & (1 << sb) != 0 {
                    for k in 0..w {
                        s[k] &= !on[k];
                    }
                }
            }
            for &id in &self.of_word[j] {
                s[id / 64] |= 1u64 << (id % 64);
            }
            for &t in &c.succ[j] {
                let mut grew = !reached[t];
                for k in 0..w {
                    let add = s[k] & !bits[t * w + k];
                    if add != 0 {
                        bits[t * w + k] |= add;
                        grew = true;
                    }
                }
                if grew {
                    reached[t] = true;
                    if !queued[t] {
                        queued[t] = true;
                        work.push(t);
                    }
                }
            }
        }
        Pending { width: w, bits, reached }
    }
}

/// The flow graph by rounds: its back edges (an edge into a word that dominates its source), the
/// loop heads, and the order of the flow without the back edges.
struct Rounds {
    /// the edges the rounds are read on (see [`Rounds::of`])
    succ: Vec<Vec<usize>>,
    succ_f: Vec<Vec<usize>>,
    heads: Vec<usize>,
    order: Vec<usize>,
}

/// (the successors alone, for [`Rounds::of`])
struct Graph {
    succ: Vec<Vec<usize>>,
}

fn is_dispatch(insn: &Instruction) -> bool {
    matches!(insn.opcode.as_str(), "BRX" | "JMX" | "BRXU" | "JMXU")
}

/// The flow graph with one more kind of edge: from a register-indirect branch to the word its
/// case blocks leave to. A table entry of a case without code of its own names that word, and
/// the graph, which reads no table, gives a dispatch only the blocks that no branch names. A
/// case block ends in front of the next one; where it ends with an unconditional branch, the
/// dispatch reaches that branch's target too. More paths than the allocator's graph has: on
/// them a wait is kept, never lost.
fn with_joins(c: &Cfg, insns: &[Instruction]) -> Cfg {
    let n = c.succ.len();
    let dispatch: Vec<usize> = (0..n).filter(|&i| is_dispatch(&insns[i])).collect();
    let mut succ = c.succ.clone();
    for &d in &dispatch {
        let own = |t: usize| t > d + 1 && dispatch.iter().rev().find(|&&x| x < t) == Some(&d);
        for t in c.indirect_targets.iter().copied().filter(|&t| own(t)) {
            let last = t - 1;
            if insns[last].opcode == "BRA" && !crate::cfg_flow::is_conditional(&insns[last]) {
                for &x in &c.succ[last] {
                    if !succ[d].contains(&x) {
                        succ[d].push(x);
                    }
                }
            }
        }
        succ[d].sort_unstable();
    }
    graph_of(succ, c)
}

/// The graph of the edges `succ`, with the tail and the unnamed blocks of `c`.
fn graph_of(succ: Vec<Vec<usize>>, c: &Cfg) -> Cfg {
    let mut pred: Vec<Vec<usize>> = vec![Vec::new(); succ.len()];
    for (i, ss) in succ.iter().enumerate() {
        for &t in ss {
            if !pred[t].contains(&i) {
                pred[t].push(i);
            }
        }
    }
    Cfg { succ, pred, tail: c.tail, indirect_targets: c.indirect_targets.clone() }
}

/// The graph `c` with one more kind of edge: from a register-indirect branch to every word an
/// entry of its table names (`tables`: a dispatch and the words of its table, `None` where the
/// table cannot be read). An entry may name a word that a branch names too; the graph, which
/// reads no table, has no edge to it from the dispatch.
fn with_tables(c: &Cfg, tables: &[(usize, Option<Vec<usize>>)]) -> Cfg {
    let mut succ = c.succ.clone();
    for (d, table) in tables {
        for &t in table.iter().flatten() {
            if !succ[*d].contains(&t) {
                succ[*d].push(t);
            }
        }
        succ[*d].sort_unstable();
    }
    graph_of(succ, c)
}

/// The table of the register-indirect branch at word `d`, read from the kernel's constant
/// section of bank 2 (`constants`): the words its entries name, in text order, each once.
/// `None` where the words in front of the dispatch are not the form the vendor's compiler
/// writes, or an entry is not the address of a word of the kernel in front of its dead tail.
///
/// The form -- every dispatch of the vendor's own MoE kernels has it, 113 in 55 kernels:
///
/// ```text
/// VIMNMX.U32 Rk, Rk, K, PT            the clamp: K + 1 entries
/// IMAD.SHL.U32 Ry, Rk, 0x4, RZ        four bytes an entry
/// LDC R, c[0x2][Ry+off]               an entry: the address of its target in the kernel
/// ...
/// BRX R -<the address of the word behind the dispatch>
/// ```
///
/// Each of the three words is the nearest one in front that writes its register, none of the
/// four stands under a guard, all stand within nine words in front of the dispatch, and
/// nothing enters between the clamp and the dispatch on the graph `c`.
pub fn jump_table(insns: &[Instruction], c: &Cfg, d: usize, constants: &[u8]) -> Option<Vec<usize>> {
    let addr = |i: usize| -> u32 {
        if insns[i].addr > 0 || i == 0 {
            insns[i].addr
        } else {
            (i * 16) as u32
        }
    };
    let x = insns.get(d)?;
    if x.opcode != "BRX" || x.guard.is_some() {
        return None;
    }
    let reg = match x.operands.first() {
        Some(Operand::Reg { num, .. }) if *num < 255 => *num,
        _ => return None,
    };
    // the entries are addresses in the kernel: the offset of the dispatch takes its own place back
    let offset = x.operands.iter().rev().find_map(|o| match o {
        Operand::Imm32(v) => Some(*v),
        _ => None,
    })?;
    if offset != -(addr(d) as i64 + 16) {
        return None;
    }
    let plain = |j: usize, form: &str| insns[j].opcode_full == form && insns[j].guard.is_none();
    let floor = d.saturating_sub(9);
    // the nearest word in front of `from` that writes the general register `r`
    let writer = |r: u8, from: usize| (floor..from).rev().find(|&j| sp::dest_regs(&insns[j]).contains(&(false, r as u16)));
    let load = writer(reg, d)?;
    let (index, at) = match insns[load].operands.as_slice() {
        [Operand::Reg { num, .. }, Operand::ConstMem { bank: 2, base_reg: Some(b), ur_reg: None, offset }]
            if plain(load, "LDC") && *num == reg && *offset >= 0 =>
        {
            (*b, *offset as usize)
        }
        _ => return None,
    };
    let scale = writer(index, load)?;
    let clamped = match insns[scale].operands.as_slice() {
        [Operand::Reg { num, .. }, Operand::Reg { num: k, .. }, Operand::Imm32(4), Operand::Reg { num: 255, .. }]
            if plain(scale, "IMAD.SHL.U32") && *num == index =>
        {
            *k
        }
        _ => return None,
    };
    let clamp = writer(clamped, scale)?;
    let last = match insns[clamp].operands.as_slice() {
        [Operand::Reg { num, .. }, Operand::Reg { num: k, .. }, Operand::Imm32(v), Operand::Pred { num: 7, neg: false }]
            if plain(clamp, "VIMNMX.U32") && *num == clamped && *k == clamped && (0..4096).contains(v) =>
        {
            *v as usize
        }
        _ => return None,
    };
    if !(clamp + 1..=d).all(|j| c.pred[j].len() == 1 && c.pred[j][0] == j - 1) {
        return None;
    }
    let mut word_at: HashMap<u32, usize> = HashMap::new();
    for i in 0..c.tail.min(insns.len()) {
        word_at.entry(addr(i)).or_insert(i);
    }
    let mut targets: Vec<usize> = Vec::new();
    for e in 0..=last {
        let p = at + 4 * e;
        let entry: [u8; 4] = constants.get(p..p + 4)?.try_into().ok()?;
        let t = *word_at.get(&u32::from_le_bytes(entry))?;
        if !targets.contains(&t) {
            targets.push(t);
        }
    }
    targets.sort_unstable();
    Some(targets)
}

impl Rounds {
    /// The rounds of the graph `c`. The flow graph gives every register-indirect branch every
    /// block that no branch names (more paths than exist: no table is read), which opens a side
    /// door from one dispatch into the loops of another and hides their back edges. For the
    /// ROUNDS a dispatch reaches the unnamed blocks behind it up to the next dispatch — its own
    /// case blocks as nvcc lays them out; what the rounds propose is then checked on the whole
    /// graph ([`apply`]: every waiter of every use stays behind a wait on every path of `c`).
    fn of(c: &Cfg, insns: &[Instruction]) -> Rounds {
        let n = c.succ.len();
        let none = usize::MAX;
        let dispatch: Vec<usize> = (0..n).filter(|&i| is_dispatch(&insns[i])).collect();
        let mut succ: Vec<Vec<usize>> = c.succ.clone();
        for &d in &dispatch {
            succ[d].retain(|&t| !c.indirect_targets.contains(&t) || t == d + 1 || dispatch.iter().rev().find(|&&x| x < t).is_none_or(|&x| x == d));
        }
        let c = &Graph { succ };
        // the reverse postorder of a depth-first walk from the kernel's entry
        let mut seen = vec![false; n];
        let mut post: Vec<usize> = Vec::new();
        if n > 0 {
            let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
            seen[0] = true;
            while let Some(top) = stack.len().checked_sub(1) {
                let (u, k) = stack[top];
                if k < c.succ[u].len() {
                    stack[top].1 += 1;
                    let v = c.succ[u][k];
                    if !seen[v] {
                        seen[v] = true;
                        stack.push((v, 0));
                    }
                } else {
                    post.push(u);
                    stack.pop();
                }
            }
        }
        let rpo: Vec<usize> = post.iter().rev().copied().collect();
        let mut idx = vec![none; n];
        for (k, &u) in rpo.iter().enumerate() {
            idx[u] = k;
        }
        let mut pred: Vec<Vec<usize>> = vec![Vec::new(); n];
        for &u in &rpo {
            for &v in &c.succ[u] {
                pred[v].push(u);
            }
        }
        // immediate dominators (the iteration over the reverse postorder)
        let mut idom = vec![none; n];
        if n > 0 {
            idom[0] = 0;
        }
        let mut changed = true;
        while changed {
            changed = false;
            for &u in rpo.iter().skip(1) {
                let mut new = none;
                for &p in &pred[u] {
                    if idom[p] == none {
                        continue;
                    }
                    if new == none {
                        new = p;
                        continue;
                    }
                    let (mut a, mut b) = (p, new);
                    while a != b {
                        while idx[a] > idx[b] {
                            a = idom[a];
                        }
                        while idx[b] > idx[a] {
                            b = idom[b];
                        }
                    }
                    new = a;
                }
                if new != none && idom[u] != new {
                    idom[u] = new;
                    changed = true;
                }
            }
        }
        let dominates = |v: usize, u: usize| -> bool {
            let mut x = u;
            loop {
                if x == v {
                    return true;
                }
                let p = idom[x];
                if p == none || p == x {
                    return false;
                }
                x = p;
            }
        };
        let mut succ_f: Vec<Vec<usize>> = c.succ.clone();
        let mut heads: Vec<usize> = Vec::new();
        for &u in &rpo {
            let back: Vec<usize> = c.succ[u].iter().copied().filter(|&v| dominates(v, u)).collect();
            if !back.is_empty() {
                succ_f[u].retain(|v| !back.contains(v));
                heads.extend(back);
            }
        }
        heads.sort_unstable();
        heads.dedup();
        // the order of the flow without back edges, the smallest ready word first
        let mut indeg = vec![0usize; n];
        for (u, ss) in succ_f.iter().enumerate() {
            for &v in ss {
                if v != u {
                    indeg[v] += 1;
                }
            }
        }
        let mut heap: BinaryHeap<std::cmp::Reverse<usize>> = (0..n).filter(|&u| indeg[u] == 0).map(std::cmp::Reverse).collect();
        let mut order: Vec<usize> = Vec::with_capacity(n);
        let mut placed = vec![false; n];
        while let Some(std::cmp::Reverse(u)) = heap.pop() {
            order.push(u);
            placed[u] = true;
            for &v in &succ_f[u] {
                if v != u {
                    indeg[v] -= 1;
                    if indeg[v] == 0 {
                        heap.push(std::cmp::Reverse(v));
                    }
                }
            }
        }
        order.extend((0..n).filter(|&u| !placed[u]));
        Rounds { succ: c.succ.clone(), succ_f, heads, order }
    }
}

/// The words reached from `starts` over the edges `sc`.
fn reach(sc: &[Vec<usize>], starts: &[usize]) -> Vec<bool> {
    let mut seen = vec![false; sc.len()];
    let mut stack: Vec<usize> = starts.to_vec();
    while let Some(u) = stack.pop() {
        if seen[u] {
            continue;
        }
        seen[u] = true;
        stack.extend(sc[u].iter().copied());
    }
    seen
}

/// Is `w` reached from `from` (itself included) over the edges `sc` when a word that waits
/// scoreboard `sb` ends a path?
fn reaches_unwaited(sc: &[Vec<usize>], from: usize, w: usize, waits: &[u8], sb: u8) -> bool {
    let mut seen = vec![false; sc.len()];
    let mut stack = vec![from];
    while let Some(u) = stack.pop() {
        if seen[u] {
            continue;
        }
        seen[u] = true;
        if u == w {
            return true;
        }
        if waits[u] & (1 << sb) != 0 {
            continue;
        }
        stack.extend(sc[u].iter().copied());
    }
    false
}

/// The wait bits (word, scoreboard), each with the barriers it was written for.
type Bits = BTreeMap<(usize, u8), Vec<usize>>;

/// `head`: the bits written for barriers of the round before that stand behind the first wait
/// of their own round on the scoreboard.
fn head_kind(r: &Rounds, arm: &Armers, waits: &[u8], bits: &Bits) -> Vec<(usize, u8)> {
    let mut inside: HashMap<usize, Vec<bool>> = HashMap::new(); // reached without a back edge
    let mut whole: HashMap<usize, Vec<bool>> = HashMap::new(); // reached at all
    let mut out = Vec::new();
    for (&(w, sb), ids) in bits {
        let mut all = !ids.is_empty();
        for &id in ids {
            let s = arm.who[id].0;
            // the setter reaches the waiter inside its round: the bit is a first wait, or a repeat
            if inside.entry(s).or_insert_with(|| reach(&r.succ_f, &r.succ_f[s]))[w] {
                all = false;
                break;
            }
            let from_s = whole.entry(s).or_insert_with(|| reach(&r.succ, &r.succ[s]));
            if !from_s[w] {
                all = false;
                break;
            }
            let behind: Vec<usize> = r.heads.iter().copied().filter(|&h| from_s[h]).collect();
            let mut heads: Vec<usize> = Vec::new();
            for h in behind {
                if h == w || inside.entry(h).or_insert_with(|| reach(&r.succ_f, &r.succ_f[h]))[w] {
                    heads.push(h);
                }
            }
            // on every path from every such head down to the waiter another word waits first
            if heads.is_empty() || heads.iter().any(|&h| h == w || reaches_unwaited(&r.succ_f, h, w, waits, sb)) {
                all = false;
                break;
            }
        }
        if all {
            out.push((w, sb));
        }
    }
    out
}

/// `paths`: the bits that are not on the first waiting word of a path — the sweep in the order
/// of the flow, then the trim.
fn fixed_point(c: &Cfg, r: &Rounds, arm: &Armers, waits: &[u8], bits: &Bits) -> Vec<(usize, u8)> {
    let n = waits.len();
    let mut placed = vec![0u8; n];
    let mut st = arm.scan(c, &placed);
    for &w in &r.order {
        for sb in 0..NB as u8 {
            let bit = 1u8 << sb;
            if waits[w] & bit == 0 {
                continue;
            }
            let needed = match bits.get(&(w, sb)) {
                Some(ids) if st.reached[w] => ids.iter().any(|&id| st.has(w, id)),
                _ => true,
            };
            if needed {
                placed[w] |= bit;
                st = arm.scan(c, &placed);
            }
        }
    }
    // every waiter of every use behind a wait of its scoreboard on every path from its setters
    let covered = |placed: &[u8], st: &Pending| -> bool {
        bits.iter().all(|(&(x, sb), ids)| placed[x] & (1 << sb) != 0 || !st.reached[x] || !ids.iter().any(|&id| st.has(x, id)))
    };
    loop {
        let mut changed = false;
        for &w in &r.order {
            for sb in 0..NB as u8 {
                let bit = 1u8 << sb;
                if placed[w] & bit == 0 || !bits.contains_key(&(w, sb)) {
                    continue;
                }
                placed[w] &= !bit;
                if covered(&placed, &arm.scan(c, &placed)) {
                    changed = true;
                } else {
                    placed[w] |= bit;
                }
            }
        }
        if !changed {
            break;
        }
    }
    bits.keys().copied().filter(|&(w, sb)| placed[w] & (1 << sb) == 0).collect()
}

/// The pairs of results that are pending together somewhere under the waits `st` was scanned
/// with: per result, the results it shares a word's state with.
fn together(arm: &Armers, st: &Pending) -> Vec<Vec<u64>> {
    let mut out = vec![vec![0u64; arm.width]; arm.who.len()];
    for j in 0..st.reached.len() {
        if !st.reached[j] {
            continue;
        }
        let s = st.at(j);
        for sb in 0..NB as u8 {
            let set = arm.on(s, sb, true);
            for &p in &set {
                for &q in &set {
                    out[p][q / 64] |= 1u64 << (q % 64);
                }
            }
        }
    }
    out
}

/// The nearest waits the rule took off in front of word `z` through which the barrier `id`
/// flows to `z` (the wait of the word `skip` is passed), and whether `id` also reaches `z` from
/// its own word with no such wait between.
#[allow(clippy::too_many_arguments)]
fn nearest(c: &Cfg, arm: &Armers, st: &Pending, cur: &[u8], off: &HashSet<(usize, u8)>, z: usize, id: usize, skip: Option<usize>) -> (Vec<usize>, bool) {
    let (word, sb, _) = arm.who[id];
    let bit = 1u8 << sb;
    let mut seen = vec![false; cur.len()];
    let mut stack: Vec<usize> = c.pred[z].clone();
    let mut found: Vec<usize> = Vec::new();
    let mut own = false;
    while let Some(j) = stack.pop() {
        if seen[j] || !st.reached[j] {
            continue;
        }
        seen[j] = true;
        let through = st.has(j, id) && cur[j] & bit == 0;
        if j == word {
            own = true;
        } else if !through {
            continue;
        }
        if through {
            if off.contains(&(j, sb)) && Some(j) != skip {
                found.push(j);
            } else {
                stack.extend(c.pred[j].iter().copied());
            }
        }
    }
    found.sort_unstable();
    (found, own)
}

/// What [`apply`] returns: the bits it took off as (word, scoreboard, behind a landed result?),
/// and how many bits of the rule's kind stay -- for an unmeasured set, for a jump table, for
/// the fields (see [`Report`]).
pub struct Outcome {
    pub off: Vec<(usize, u8, bool)>,
    pub kept: usize,
    pub tables: usize,
    pub fields: usize,
}

/// The closing check: every waiter of every use behind a wait of the use's scoreboard on every
/// path of `g` from its setters (its own wait counts) -- a candidate whose word is not, stays.
/// `blind` = the dispatches whose table cannot be read: nobody knows where they lead, so a
/// candidate stays when a barrier it was written for can still be armed where one of them
/// issues, and when the graph does not reach its word at all.
fn close(arm: &Armers, g: &Cfg, waits: &[u8], bits: &Bits, cands: &mut Vec<(usize, u8)>, blind: &[usize]) {
    loop {
        let mut cur = waits.to_vec();
        for &(w, sb) in cands.iter() {
            cur[w] &= !(1 << sb);
        }
        let st = arm.scan(g, &cur);
        let crosses = |id: usize| blind.iter().any(|&d| st.reached[d] && st.has(d, id) && cur[d] & (1 << arm.who[id].1) == 0);
        let open: Vec<(usize, u8)> = cands
            .iter()
            .copied()
            .filter(|k| {
                if !st.reached[k.0] {
                    return !blind.is_empty();
                }
                bits.get(k).is_some_and(|ids| ids.iter().any(|&id| st.has(k.0, id) || crosses(id)))
            })
            .collect();
        if open.is_empty() {
            break;
        }
        cands.retain(|k| !open.contains(k));
    }
}

/// The rule, on the barrier fields as the allocator emitted them. `written` = the wait bits it
/// wrote for its uses. Only wait bits are taken off; no barrier and no other field moves.
pub fn apply(insns: &mut [Instruction], c: &Cfg, written: &[Written], mode: Drained) -> Outcome {
    let n = insns.len();
    // (the rule's own graph: the allocator's, and from every dispatch the join of its case blocks)
    let wide = with_joins(c, insns);
    let c = &wide;
    // the jump tables: every dispatch with the words its table names, `None` where it cannot be read
    let constants = CONSTANTS.with(|s| s.borrow().clone());
    let tables: Vec<(usize, Option<Vec<usize>>)> = (0..n)
        .filter(|&i| is_dispatch(&insns[i]))
        .map(|d| (d, constants.as_deref().and_then(|bytes| jump_table(insns, c, d, bytes))))
        .collect();
    // the rewrites of an operand in flight that the path audit names on the fields as emitted
    let named: HashSet<(usize, usize, usize)> = sp::report_war_on_paths(insns).pairs.into_iter().collect();
    let arm = Armers::of(insns);
    let waits: Vec<u8> = insns.iter().map(crate::store_paths::waits).collect();
    // the bits the rule judges: written for a use on a word cubit schedules, every setter of the
    // use armed on that scoreboard as the fields stand
    let mut bits: Bits = BTreeMap::new();
    let mut unsure: HashSet<(usize, u8)> = HashSet::new();
    for x in written {
        if x.word >= n || insns[x.word].hand_sched || insns[x.word].ctrl.wait_mask & (1 << x.sb) == 0 {
            continue;
        }
        let ids = bits.entry((x.word, x.sb)).or_default();
        for &s in &x.setters {
            let on: Vec<usize> = arm.of_word[s].iter().copied().filter(|&id| arm.who[id].1 == x.sb).collect();
            if on.is_empty() {
                unsure.insert((x.word, x.sb));
            }
            for id in on {
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
        }
    }
    bits.retain(|k, ids| !ids.is_empty() && !unsure.contains(k));
    let rounds = Rounds::of(c, insns);
    let mut cands = match mode {
        Drained::Head => head_kind(&rounds, &arm, &waits, &bits),
        Drained::Paths => fixed_point(c, &rounds, &arm, &waits, &bits),
    };
    cands.retain(|&(w, _)| !ordered_event(&insns[w]));
    // on the whole graph: every waiter of every use behind a wait of the use's scoreboard on
    // every path from its setters (its own wait counts) -- a bit whose word is not, stays
    close(&arm, c, &waits, &bits, &mut cands, &[]);
    // ... and on the jump tables, which the graph does not read: the same check with every entry
    // of every dispatch's table as an edge, and with the dispatches whose table cannot be read
    let mut for_tables = 0usize;
    if !tables.is_empty() {
        let on_graph = cands.len();
        let blind: Vec<usize> = tables.iter().filter(|t| t.1.is_none()).map(|t| t.0).collect();
        close(&arm, &with_tables(c, &tables), &waits, &bits, &mut cands, &blind);
        for_tables = on_graph - cands.len();
    }
    // the guard: no two results fly together that the allocator's waits kept apart, but in the
    // two measured shapes -- the nearest wait in front of the place where they would meet stays
    let before = arm.scan(c, &waits);
    let apart = together(&arm, &before);
    let mut cur = waits.clone();
    let mut off: HashSet<(usize, u8)> = HashSet::new();
    for &(w, sb) in &cands {
        cur[w] &= !(1 << sb);
        off.insert((w, sb));
    }
    let mut kept = 0usize;
    while !off.is_empty() {
        let st = arm.scan(c, &cur);
        let mut new_set: Option<(usize, usize, usize)> = None;
        'words: for z in 0..n {
            if !st.reached[z] {
                continue;
            }
            for sb in 0..NB as u8 {
                let set = arm.on(st.at(z), sb, true);
                if set.len() < 2 {
                    continue;
                }
                let words: Vec<usize> = set.iter().map(|&id| arm.who[id].0).collect();
                for (i, &p) in set.iter().enumerate() {
                    for &q in &set[i + 1..] {
                        if (apart[p][q / 64] >> (q % 64)) & 1 == 0 && !may_fly_together(insns, &words, arm.who[p].0, arm.who[q].0) {
                            new_set = Some((z, p, q));
                            break 'words;
                        }
                    }
                }
            }
        }
        let Some((z, p, q)) = new_set else { break };
        let sb = arm.who[p].1;
        // the waits that part `a` from `b` in front of `z`: those in front of the word of `b`
        // first -- the wait that drained the older result before the younger was issued --, the
        // wait of that word itself where there is none
        let part = |a: usize, b: usize| -> Option<Vec<usize>> {
            [Some(arm.who[b].0), None].into_iter().find_map(|skip| {
                let (found, own) = nearest(c, &arm, &st, &cur, &off, z, a, skip);
                (!own && !found.is_empty()).then_some(found)
            })
        };
        let back: Vec<usize> = part(p, q).or_else(|| part(q, p)).unwrap_or_else(|| {
            // (no single wait parts the two: every bit of the scoreboard stands as it was written)
            off.iter().filter(|k| k.1 == sb).map(|k| k.0).collect()
        });
        let mut restored = 0;
        for w in back {
            if off.remove(&(w, sb)) {
                cur[w] |= 1 << sb;
                restored += 1;
            }
        }
        if restored == 0 {
            // (cannot happen: with every bit of the scoreboard back the state is the allocator's)
            for (w, s) in off.drain() {
                cur[w] |= 1 << s;
                restored += 1;
            }
        }
        kept += restored;
    }
    for &(w, sb) in &off {
        insns[w].ctrl.wait_mask &= !(1 << sb);
    }
    // the guard on the fields: a wait releases every barrier armed on its scoreboard, also the
    // read barrier of a word that no use of the bit names. The path audit says where that was
    // so: while the schedule names a rewrite of an operand in flight that the fields as emitted
    // do not name, the wait that ended the reader's flight comes back -- the rewriting word's
    // own where the rule took it off, else the nearest waits it took off in front of the
    // rewriting word on the paths one of the reader's barriers comes down to it (else every bit
    // it took off in front of which such a barrier can still be armed)
    let mut for_fields = 0usize;
    while !off.is_empty() {
        let fresh = sp::report_war_on_paths(insns).pairs.into_iter().find(|p| !named.contains(p));
        let Some((rewriter, reader, _)) = fresh else { break };
        let ends = &arm.of_word[reader];
        let ends_on = |sb: u8| ends.iter().any(|&id| arm.who[id].1 == sb);
        let mut back: Vec<(usize, u8)> = off.iter().copied().filter(|&(w, sb)| w == rewriter && ends_on(sb)).collect();
        if back.is_empty() {
            let st = arm.scan(c, &cur);
            for &id in ends {
                let (found, _) = nearest(c, &arm, &st, &cur, &off, rewriter, id, None);
                back.extend(found.into_iter().map(|w| (w, arm.who[id].1)));
            }
            if back.is_empty() {
                back = off
                    .iter()
                    .copied()
                    .filter(|&(w, sb)| st.reached[w] && ends.iter().any(|&id| arm.who[id].1 == sb && st.has(w, id)))
                    .collect();
            }
        }
        if back.is_empty() {
            back = off.iter().copied().filter(|&(_, sb)| ends_on(sb)).collect();
        }
        if back.is_empty() {
            // (cannot happen: with every bit back the fields are the allocator's)
            back = off.iter().copied().collect();
        }
        for (w, sb) in back {
            if off.remove(&(w, sb)) {
                cur[w] |= 1 << sb;
                insns[w].ctrl.wait_mask |= 1 << sb;
                for_fields += 1;
            }
        }
    }
    let mut out: Vec<(usize, u8, bool)> = off
        .iter()
        .map(|&(w, sb)| (w, sb, before.reached[w] && !arm.on(before.at(w), sb, false).is_empty()))
        .collect();
    out.sort_unstable();
    Outcome { off: out, kept, tables: for_tables, fields: for_fields }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel(body: &str) -> Vec<Instruction> {
        let src = format!(".entry t\n    .param u64 io\n{body}.endentry\n");
        crate::sass_file::parse_sass_file_str_strict(&src).unwrap().kernels[0].instructions.clone()
    }

    /// The scoreboards (as armed words) pending at the entry of word `j`.
    fn pending(k: &[Instruction], j: usize) -> Vec<usize> {
        let c = Cfg::build(k);
        let arm = Armers::of(k);
        let waits: Vec<u8> = k.iter().map(crate::store_paths::waits).collect();
        let st = arm.scan(&c, &waits);
        let mut v: Vec<usize> = (0..arm.who.len()).filter(|&id| st.has(j, id)).map(|id| arm.who[id].0).collect();
        v.sort_unstable();
        v
    }

    const LOAD: &str = "    [B------:R-:W0:-:S02] LDG.E R4, desc[UR8][R2.64] ;\n";

    #[test]
    fn on_a_straight_line_a_wait_drains_and_the_next_word_finds_nothing() {
        let k = kernel(&format!("{LOAD}    [B------:R-:W-:-:S01] MOV R9, R8 ;\n    [B0-----:R-:W-:-:S01] MOV R6, R4 ;\n    [B------:R-:W-:-:S01] MOV R7, R4 ;\n    [B------:R-:W-:-:S05] EXIT ;\n"));
        assert_eq!(pending(&k, 1), vec![0], "the load is armed behind its word");
        assert_eq!(pending(&k, 2), vec![0], "the state is the one in front of the word's own wait");
        assert!(pending(&k, 3).is_empty(), "the wait of word 2 drained scoreboard 0");
    }

    #[test]
    fn in_a_diamond_a_wait_on_one_arm_does_not_drain_for_the_join() {
        let k = kernel(&format!(
            "{LOAD}    [B------:R-:W-:-:S13] ISETP.NE.AND P0, PT, R5, RZ, PT ;\n    [B------:R-:W-:-:S05] @P0 BRA L_else ;\n    [B0-----:R-:W-:-:S02] MOV R6, R4 ;\n    [B------:R-:W-:-:S05] BRA L_join ;\nL_else:\n    [B------:R-:W-:-:S01] MOV R6, R11 ;\nL_join:\n    [B------:R-:W-:-:S01] MOV R9, R6 ;\n    [B------:R-:W-:-:S05] EXIT ;\n"
        ));
        assert!(pending(&k, 4).is_empty(), "behind the wait of the first arm");
        assert_eq!(pending(&k, 5), vec![0], "the second arm");
        assert_eq!(pending(&k, 6), vec![0], "the join: one path has not waited");
    }

    #[test]
    fn in_a_loop_the_result_of_the_round_before_is_armed_at_the_head() {
        let k = kernel(&format!(
            "    [B------:R-:W-:-:S01] MOV R5, RZ ;\nL_top:\n    [B------:R-:W-:-:S01] MOV R9, R8 ;\n{LOAD}    [B------:R-:W-:-:S01] IADD3 R5, R5, 0x1, RZ ;\n    [B------:R-:W-:-:S13] ISETP.NE.AND P0, PT, R5, 0x8, PT ;\n    [B------:R-:W-:-:S05] @P0 BRA L_top ;\n    [B0-----:R-:W-:-:S01] MOV R6, R4 ;\n    [B------:R-:W-:-:S05] EXIT ;\n"
        ));
        assert_eq!(pending(&k, 1), vec![2], "over the back edge");
        assert_eq!(pending(&k, 6), vec![2]);
        assert!(pending(&k, 7).is_empty());
        let r = Rounds::of(&Cfg::build(&k), &k);
        assert_eq!(r.heads, vec![1], "the loop head is the target of the back edge");
        assert_eq!(r.succ_f[5], vec![6], "the back edge is no edge of a round");
    }

    #[test]
    fn a_divergence_branch_carries_the_state_to_its_out_of_line_block_and_to_the_word_behind_it() {
        let k = kernel(&format!(
            "{LOAD}    [B------:R-:W-:-:S01] UMOV UR4, 0xffffffff ;\n    [B------:R-:W-:-:S06] BRA.DIV UR4, L_slow ;\n    [B0-----:R-:W-:-:S02] MOV R6, R4 ;\nL_join:\n    [B------:R-:W-:-:S01] MOV R9, R6 ;\n    [B------:R-:W-:-:S05] EXIT ;\nL_slow:\n    [B------:R-:W-:-:S02] MOV R10, R4 ;\n    [B------:R-:W-:-:S05] BRA L_join ;\n"
        ));
        assert_eq!(pending(&k, 3), vec![0], "the fast path");
        assert_eq!(pending(&k, 6), vec![0], "the out-of-line block: no word waited on its path");
        assert_eq!(pending(&k, 4), vec![0], "the join: the out-of-line block returns without a wait");
    }

    #[test]
    fn a_register_indirect_branch_carries_the_state_to_every_case_block() {
        let k = kernel(&format!(
            "{LOAD}    [B------:R-:W1:-:S02] LDC R50, c[0x2][R20] ;\n    [B-1----:R-:W-:-:S05] BRX R50 -0x30 ;\n    [B0-----:R-:W-:-:S01] MOV R1, R4 ;\n    [B------:R-:W-:-:S05] BRA L_j ;\n    [B------:R-:W-:-:S01] MOV R1, R3 ;\n    [B------:R-:W-:-:S05] BRA L_j ;\nL_j:\n    [B------:R-:W-:-:S05] EXIT ;\n"
        ));
        assert_eq!(pending(&k, 3), vec![0], "the first case block: scoreboard 1 was waited by the dispatch, 0 was not");
        assert_eq!(pending(&k, 5), vec![0], "the second case block is reached from the dispatch too");
        assert_eq!(pending(&k, 7), vec![0], "the join: the second block did not wait");
    }

    /// A dispatch of the vendor's form at word 4 (its table at `c[0x2][R21+0x8]`, two entries), two case
    /// blocks and the word a branch names. `clamp` = the word that bounds the index.
    fn dispatch(clamp: &str) -> Vec<Instruction> {
        kernel(&format!(
            "{LOAD}    [B------:R-:W-:-:S01] {clamp} ;\n    [B------:R-:W-:-:S01] IMAD.SHL.U32 R21, R20, 0x4, RZ ;\n    [B------:R-:W1:-:S02] LDC R22, c[0x2][R21+0x8] ;\n    [B-1----:R-:W-:-:S05] BRX R22 -0x50 ;\n    [B------:R-:W-:-:S01] MOV R1, R4 ;\n    [B------:R-:W-:-:S05] BRA L_x ;\n    [B------:R-:W-:-:S01] MOV R2, R4 ;\nL_x:\n    [B------:R-:W-:-:S05] EXIT ;\n"
        ))
    }

    fn table(entries: &[u32]) -> Vec<u8> {
        let mut bytes = vec![0xffu8; 8];
        bytes.extend(entries.iter().flat_map(|a| a.to_le_bytes()));
        bytes
    }

    #[test]
    fn the_table_of_a_dispatch_is_read_from_the_constant_section() {
        let k = dispatch("VIMNMX.U32 R20, R20, 0x1, PT");
        let c = Cfg::build(&k);
        // the word behind the dispatch and the word the branch names (the flow graph has no edge to that one)
        assert_eq!(jump_table(&k, &c, 4, &table(&[0x50, 0x80])), Some(vec![5, 8]));
        assert!(!c.succ[4].contains(&8) && with_tables(&c, &[(4, Some(vec![5, 8]))]).succ[4].contains(&8));
        // an entry twice is one word
        assert_eq!(jump_table(&k, &c, 4, &table(&[0x70, 0x70])), Some(vec![7]));
    }

    #[test]
    fn a_table_that_is_not_of_the_one_form_is_not_read() {
        let k = dispatch("VIMNMX.U32 R20, R20, 0x1, PT");
        let c = Cfg::build(&k);
        assert_eq!(jump_table(&k, &c, 4, &table(&[0x50])), None, "a table shorter than the clamp says");
        assert_eq!(jump_table(&k, &c, 4, &table(&[0x50, 0x84])), None, "an entry inside a word");
        assert_eq!(jump_table(&k, &c, 4, &table(&[0x50, 0x900])), None, "an entry behind the kernel");
        assert_eq!(jump_table(&k, &c, 3, &table(&[0x50, 0x80])), None, "no dispatch");
        // no clamp in front of the scale: nothing says how many entries the table has
        let k = dispatch("MOV R20, R4");
        assert_eq!(jump_table(&k, &Cfg::build(&k), 4, &table(&[0x50, 0x80])), None);
        // another offset than the address behind the dispatch: the entries are no addresses of the kernel
        let mut k = dispatch("VIMNMX.U32 R20, R20, 0x1, PT");
        k[4].operands[1] = Operand::Imm32(-0x40);
        assert_eq!(jump_table(&k, &Cfg::build(&k), 4, &table(&[0x50, 0x80])), None);
    }

    #[test]
    fn the_words_of_ordered_events_are_named() {
        let k = kernel("    [B------:R-:W-:-:S01] BSSY B0, L_x ;\n    [B------:R-:W-:-:S01] CS2R R30, SR_GLOBALTIMERLO ;\n    [B------:R-:W-:-:S01] CS2R R20, SRZ ;\n    [B------:R-:W-:-:S01] P2R R16, PR, RZ, 0x1 ;\n    [B------:R-:W-:-:S01] MOV R6, R4 ;\nL_x:\n    [B------:R-:W-:-:S05] EXIT ;\n");
        let named: Vec<bool> = k.iter().map(ordered_event).collect();
        assert_eq!(named, vec![true, true, false, true, false, true]);
    }
}

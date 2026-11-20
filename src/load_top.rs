//! `CUBIT_LOAD_TOP=1` (opt-in, default off; honoured only together with `CUBIT_WAIT_POLICY=1`,
//! whose flow graph it works on): the wait for the result of a global load stands at the top of
//! the loop that holds the load, not at the reader (KNOWN_ISSUES A68).
//!
//! The barrier allocator (`scheduling_pass::reallocate_barriers`) fixes the place of a wait
//! before a scoreboard exists: the first word that reads or rewrites the pending register on
//! every path behind the load (`cfg_flow::Cfg::first_consumers`). What else holds for the load
//! is decided by the colouring: every waiter of another use on the load's scoreboard. For a
//! load whose result the NEXT pass of its loop reads, the reader stands a few words behind the
//! loop's top, and a word that waits the scoreboard for something else on the way round holds
//! for the load too -- a few cycles behind a result that is still in flight. The vendor's
//! assembler waits for such loads ONCE, on the branch that ends the block of the loop's header:
//! every path into the next pass goes through it, and the loads have had the rest of the pass.
//!
//! Under the switch, for a use whose setters are `LDG` words that stand in a natural loop
//! (`scheduling_pass::natural_loops`):
//!
//! * `covers`, in front of the colouring -- **the walk for the first consumers ends at the
//!   TOPS**: the `BRA` that ends the header's block of every natural loop that holds the load
//!   (`tops`). The waiters of the use are the tops a path reaches and the first consumers a
//!   path reaches WITHOUT a top. A reader -- or a rewriter of the pending register -- loses its
//!   wait only where EVERY path from the load to it passes a top; where one path goes round the
//!   tops the walk finds the word and it keeps its wait. A top is taken only if it takes a
//!   reader.
//! * `scoreboards`, behind the colouring -- **the use takes the scoreboard on which no word
//!   waits for another use while its loads are in flight, and on which none of its own readers
//!   that keep their wait stands behind the result of another use**: none inside the loops that
//!   hold the loads, then the fewest outside, then the lowest number. If no scoreboard is clean
//!   the use keeps the allocator's, and its tops. The words that waited for something else on
//!   the old scoreboard keep their bit and no longer hold for the load.
//! * `mirror`, at the end of the allocation -- **a word of an ordered event that was a first
//!   wait behind a read barrier stays a wait behind it where the read barrier comes out on
//!   another scoreboard** (the mirror clause). The allocator asks, on a copy and in silence,
//!   what the same recipe writes without the switch; an event word that was the first wait on
//!   the old number of such a read barrier, and that a path still reaches with no wait of the
//!   new number in front of it, waits the new number too. Only wait bits are added
//!   (`CUBIT_DUMP_USES`: one `MIRROR` line a bit).
//!
//! What the rule does not do:
//!
//! * **No wait comes off a word of an ordered event** (`wait_drained::ordered_event`): such a
//!   first consumer keeps its wait behind any top. The wait the rule writes is a wait PUT ON a
//!   branch.
//! * **The rule rewrites no read-barrier use.** It speaks of the write barrier of an `LDG`; a
//!   wait that releases the read barrier of a word whose source the waiting word rewrites is
//!   written for that use and stays on the word that carries it. The load's own read barrier
//!   too: the walk for the words that rewrite its base ends at the first consumers, as
//!   without the rule, not at the tops. **A read barrier may still come out on another
//!   scoreboard than without the switch**: the colouring answers the new flights of the
//!   loads, and a read-barrier use can be given another number, its setter and its waiters
//!   together (on cubit's own frame of `fc1_kernel_wg<4,1,1,0,0>`: nine `LDS` words). A word
//!   of an ordered event that carried the old number for ANOTHER use, and was the first wait
//!   behind that read barrier, would then overtake the operand read: `mirror` holds it.
//! * **No top in a block that holds a word with a write barrier** (the wait would stand right
//!   behind that word -- the place the rule takes waits away from), none on a word that cannot
//!   carry a wait or that the author scheduled, none in a text without a loop, and none for a
//!   reader of the load's own pass: the walk reaches it before a top.
//! * **A flight that crosses a register-indirect branch is not covered.** The flow graph reads
//!   no jump table (KNOWN_ISSUES A67): a table entry may name a word the graph does not reach
//!   from the dispatch, and "every path passes a top" would be a statement about the graph
//!   alone. Such a use keeps its first consumers.
//! * Nothing for a hand-scheduled producer (the allocator's pinned uses are not its uses) and
//!   nothing without the flow graph.
//!
//! TWO LOADS IN FLIGHT ON ONE WRITE BARRIER. Loads that wait at one top may take one
//! scoreboard, and then no wait stands between them: the second is issued while the first is in
//! flight on the same write barrier. This allocator's own batching rule refuses exactly that for
//! global loads of different address streams ("a write barrier is last-only", with an observed
//! stale read behind the sentence), while `CUBIT_SB_SHARE` ("scoreboards are counters") and the
//! vendor's schedule at such words say the other. The rule shares a barrier between the loads
//! it puts in front of one top ONLY under its switch; it moves a use onto no scoreboard on
//! which another write-barrier use flies beside the loads (`scoreboards`: such a scoreboard is
//! barred), and the rule that takes waits off (`wait_drained::may_fly_together`) learns
//! nothing from it. `CUBIT_VERIFY` names the readers of the older load of such a pair
//! (`RECYCLE-STALE`). The vendor's practice at such words; measured on two card models for two
//! loads of the one form `LDG.E.CONSTANT` of one thread on one write barrier, in five shapes, no
//! further. A build under the switch is a candidate only after its own text is read on both models.

use crate::cfg_flow::Cfg;
use crate::ir::Instruction;
use crate::scheduling_pass as sp;

/// A natural loop that has a top.
pub(crate) struct Loop {
    /// the loop's header: the first word of the block the top ends
    pub head: usize,
    /// the `BRA` that ends the block of the loop's header: the word that carries the wait
    pub top: usize,
    /// the words of the loop
    pub body: Vec<bool>,
    words: usize,
}

/// The natural loops of the kernel that have a top, the innermost first. The top is the last
/// word of the header's block -- the words behind the header that nothing else enters, up to
/// the first that does not simply fall through -- when it is a `BRA` of the loop that can carry
/// a wait, that the author did not schedule, and when no word of the block arms a write barrier
/// (`arms`).
pub(crate) fn tops(insns: &[Instruction], c: &Cfg, can_wait: &[bool], arms: &[bool]) -> Vec<Loop> {
    let mut out: Vec<Loop> = Vec::new();
    for (h, body) in sp::natural_loops(insns) {
        let mut k = h;
        while c.succ[k].len() == 1 && c.succ[k][0] == k + 1 && c.pred[k + 1].len() == 1 {
            k += 1;
        }
        if insns[k].opcode != "BRA" || !can_wait[k] || insns[k].hand_sched || !body[k] || (h..=k).any(|j| arms[j]) {
            continue;
        }
        let words = body.iter().filter(|&&b| b).count();
        out.push(Loop { head: h, top: k, body, words });
    }
    out.sort_by_key(|l| (l.words, l.top));
    out
}

/// What the rule made of one use.
pub(crate) struct Cover {
    /// the waiters of the use: the tops a path reaches, the first consumers a path reaches
    /// without a top, and the ordered events among the consumers behind a top
    pub waiters: Vec<usize>,
    /// the words the barrier is live on
    pub on: Vec<usize>,
    /// the tops that carry the wait
    pub tops: Vec<usize>,
    /// the blocks they end: (the loop's header, the top)
    pub blocks: Vec<(usize, usize)>,
    /// the first consumers without the tops: the words the walk for the load's READ barrier ends at,
    /// as without the rule (no read-barrier use gets a cover, the load's own neither)
    pub plain: Vec<usize>,
    /// the first consumers that lose their wait
    pub off: Vec<usize>,
    /// the words of the loops that hold the loads
    pub inside: Vec<bool>,
}

/// The waiters of the loads `group` (their pending registers `dsts`) under the rule; `None`
/// where the rule does not speak: a setter is no `LDG`, no loop with a top holds the loads, no
/// top takes a reader, or the flight crosses a register-indirect branch. The other arguments
/// are those of [`Cfg::first_consumers`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn covers(
    c: &Cfg,
    loops: &[Loop],
    insns: &[Instruction],
    reads: &[Vec<u16>],
    writes: &[Vec<u16>],
    guarded: &[bool],
    group: &[usize],
    dsts: &[u16],
    settles: bool,
) -> Option<Cover> {
    if !group.iter().all(|&g| insns[g].opcode == "LDG") {
        return None;
    }
    let mine: Vec<&Loop> = loops.iter().filter(|l| group.iter().all(|&g| l.body[g])).collect();
    if mine.is_empty() {
        return None;
    }
    let walk = |stops: &[usize]| c.first_consumers(reads, writes, guarded, group, dsts, settles, stops);
    let (plain, on_plain) = walk(&[]);
    let ordered = |r: usize| crate::wait_drained::ordered_event(&insns[r]);
    // the first consumers that lose their wait when the use waits on `w`
    let lost = |w: &[usize]| -> Vec<usize> { plain.iter().copied().filter(|&r| !w.contains(&r) && !ordered(r)).collect() };
    let mut tops: Vec<usize> = mine.iter().map(|l| l.top).collect();
    let (mut w, mut on) = walk(&tops);
    // a top is taken only if it takes a reader: one that no path reaches, or without which
    // every consumer that lost its wait is still behind another top, goes -- the innermost
    // such top first, then the question again
    loop {
        let off = lost(&w);
        let idle = tops.iter().position(|&t| {
            if !w.contains(&t) {
                return true;
            }
            let rest: Vec<usize> = tops.iter().copied().filter(|&x| x != t).collect();
            let without = walk(&rest).0;
            !off.iter().any(|r| without.contains(r))
        });
        let Some(p) = idle else { break };
        tops.remove(p);
        if tops.is_empty() {
            return None;
        }
        (w, on) = walk(&tops);
    }
    // (the graph reads no jump table: a flight that crosses a dispatch is not covered)
    if on.iter().any(|&j| matches!(insns[j].opcode.as_str(), "BRX" | "JMX" | "BRXU" | "JMXU")) {
        return None;
    }
    let off = lost(&w);
    // the ordered events among the consumers behind a top keep their wait; the barrier then
    // counts as live wherever it was without the tops
    let stay: Vec<usize> = plain.iter().copied().filter(|&r| !w.contains(&r) && ordered(r)).collect();
    if !stay.is_empty() {
        w.extend(stay);
        w.sort_unstable();
        on.extend(on_plain);
        on.sort_unstable();
        on.dedup();
    }
    let inside: Vec<bool> = (0..insns.len()).map(|j| mine.iter().any(|l| l.body[j])).collect();
    let blocks: Vec<(usize, usize)> = mine.iter().filter(|l| tops.contains(&l.top)).map(|l| (l.head, l.top)).collect();
    Some(Cover { waiters: w, on, tops, blocks, plain, off, inside })
}

/// A use as the colouring left it, for [`scoreboards`]: `colour` is 7 for a use that is not
/// written; `pinned`: the colour is the author's.
pub(crate) struct UseView {
    pub setters: Vec<usize>,
    pub waiters: Vec<usize>,
    pub segs: Vec<(usize, usize)>,
    pub is_rb: bool,
    pub colour: u8,
    pub pinned: bool,
}

/// The scoreboard clause, behind the colouring: for every use that waits at the tops of its
/// loops (`topped`: the use and what [`covers`] made of it), in text order, the scoreboard it
/// moves to -- `(use, scoreboard)` for those that move.
///
/// For a scoreboard `b` the words that HOLD are counted: the words that wait on `b` for another
/// use (`waits`: the bits a word carries by its author's hand) and that a path from one of the
/// use's loads reaches without passing one of the use's own waiters or another wait on `b` --
/// they would stand behind the load in flight; a word in the block of one of the use's tops is
/// not counted, the top behind it waits anyway --, and the use's own first consumers that keep
/// their wait and stand where the result of another write-barrier use on `b` is in flight --
/// they would stand behind that one. The use takes the scoreboard with none inside the loops
/// that hold its loads, then the fewest outside, then the lowest number; never one below
/// `lowest` (the copy group's), the scoreboard of the other barrier of one of its own words,
/// one a pinned use holds over its flight, or one on which a write-barrier use that is none of
/// `topped` flies beside its loads. If no scoreboard is clean it keeps the allocator's.
/// `apart` (`CUBIT_SB_APART`, see `crate::sb_apart`): a scoreboard on which a read-barrier use
/// is pending over the flight of the use is barred too -- the allocator's own among them.
/// `CUBIT_DUMP_USES` prints one `TOP` line a use: the scoreboard and where it moves, the loads,
/// the tops, the consumers that lost their wait and those that keep it, the counts by
/// scoreboard, the scoreboards that are barred, the words that hold on the allocator's.
pub(crate) fn scoreboards(c: &Cfg, uses: &[UseView], topped: &[(usize, Cover)], waits: &[u8], lowest: u8, apart: bool) -> Vec<(usize, u8)> {
    scoreboards_as(c, uses, topped, waits, lowest, apart, std::env::var("CUBIT_DUMP_USES").is_ok())
}

/// [`scoreboards`] with the dump said: without it the clause is only ASKED what it would do -- the
/// numbers without the bar of `CUBIT_SB_APART`, which `sb_apart::kept` holds the numbers with it
/// against.
pub(crate) fn scoreboards_as(c: &Cfg, uses: &[UseView], topped: &[(usize, Cover)], waits: &[u8], lowest: u8, apart: bool, dump: bool) -> Vec<(usize, u8)> {
    const NB: usize = sp::NUM_BARRIERS;
    let mut colour: Vec<u8> = uses.iter().map(|x| x.colour).collect();
    let live = |x: &UseView, j: usize| x.segs.iter().any(|&(a, b)| a <= j && j <= b);
    let mut moves: Vec<(usize, u8)> = Vec::new();
    for (u, t) in topped {
        let (u, me) = (*u, &uses[*u]);
        let own = colour[u];
        if own as usize >= NB {
            continue;
        }
        let mut inside = [0usize; NB];
        let mut outside = [0usize; NB];
        let mut barred = [false; NB];
        // (for the dump: the words that hold on the allocator's scoreboard)
        let mut held: Vec<usize> = Vec::new();
        for b in 0..NB as u8 {
            let others: Vec<usize> = (0..uses.len()).filter(|&v| v != u && colour[v] == b).collect();
            barred[b as usize] = b < lowest
                || others.iter().any(|&v| {
                    let x = &uses[v];
                    (x.is_rb && x.setters.iter().any(|s| me.setters.contains(s)))
                        || (x.pinned && x.segs.iter().any(|&(a0, a1)| me.segs.iter().any(|&(b0, b1)| a0 <= b1 && b0 <= a1)))
                        || (!x.is_rb
                            && !topped.iter().any(|(w, _)| *w == v)
                            && (x.setters.iter().any(|&s| live(me, s)) || me.setters.iter().any(|&s| live(x, s))))
                        || (apart && x.is_rb && crate::sb_apart::meet(&x.segs, &me.segs))
                });
            let waits_b = |j: usize| waits[j] & (1 << b) != 0 || others.iter().any(|&v| uses[v].waiters.contains(&j));
            let mut hold: Vec<usize> = Vec::new();
            let mut seen = vec![false; c.succ.len()];
            let mut stack: Vec<usize> = me.setters.iter().flat_map(|&s| c.succ[s].iter().copied()).collect();
            while let Some(j) = stack.pop() {
                if std::mem::replace(&mut seen[j], true) || me.setters.contains(&j) || me.waiters.contains(&j) {
                    continue;
                }
                // (a word in the block of one of the use's tops waits where the top waits)
                if waits_b(j) && !t.blocks.iter().any(|&(h, k)| h <= j && j < k) {
                    hold.push(j);
                    continue;
                }
                stack.extend(c.succ[j].iter().copied());
            }
            for &w in me.waiters.iter().filter(|w| !t.tops.contains(w)) {
                if others.iter().any(|&v| !uses[v].is_rb && live(&uses[v], w) && !uses[v].waiters.contains(&w)) {
                    hold.push(w);
                }
            }
            for &j in &hold {
                if t.inside[j] {
                    inside[b as usize] += 1;
                } else {
                    outside[b as usize] += 1;
                }
            }
            if b == own {
                hold.sort_unstable();
                held = hold;
            }
        }
        let clean = (0..NB as u8).filter(|&b| !barred[b as usize] && inside[b as usize] == 0).min_by_key(|&b| (outside[b as usize], b));
        if dump {
            let kept: Vec<usize> = me.waiters.iter().copied().filter(|w| !t.tops.contains(w)).collect();
            let to = match clean {
                Some(b) if b != own => format!("->{b}"),
                Some(_) => String::new(),
                None => " (no scoreboard clean)".to_string(),
            };
            let bars: String = barred.iter().map(|&x| if x { '1' } else { '0' }).collect();
            eprintln!(
                "TOP b={own}{to} setters={:?} tops={:?} off={:?} kept={:?} inside={inside:?} outside={outside:?} barred={bars} held={held:?}",
                me.setters, t.tops, t.off, kept
            );
        }
        if let Some(b) = clean.filter(|&b| b != own) {
            colour[u] = b;
            moves.push((u, b));
        }
    }
    moves
}

/// The words a walk from the successors of `s` over `paths` meets when a word `ends` names ends
/// a path: such a word is met and not passed. In text order.
fn met(paths: &[Vec<usize>], s: usize, ends: impl Fn(usize) -> bool) -> Vec<usize> {
    let mut seen = vec![false; paths.len()];
    let mut stack: Vec<usize> = paths[s].clone();
    let mut out: Vec<usize> = Vec::new();
    while let Some(j) = stack.pop() {
        if seen[j] {
            continue;
        }
        seen[j] = true;
        if ends(j) {
            out.push(j);
            continue;
        }
        stack.extend(paths[j].iter().copied());
    }
    out.sort_unstable();
    out
}

/// The mirror clause: **a word of an ordered event that was a first wait behind a read barrier
/// stays a wait behind it where the switch gives that read barrier another scoreboard.**
///
/// A read barrier that is pending says that its word has NOT YET READ its operands. Under the
/// switch the colouring answers the new flights of the loads, and a read-barrier use may come
/// out on another scoreboard than without it -- beside a word of an ordered event that keeps
/// its mask, because the bit it carries is written for another use. Without the switch that
/// word was the first wait behind the read barrier; under it the event would overtake the read.
///
/// `before` and `now`: a word, (its read barrier, the scoreboards it waits) -- in the schedule
/// the same recipe writes without the switch, and as the fields stand under it. `paths`: the
/// successors of a word (`wait_drained::paths`). `able`: the words of ordered events that can
/// carry a wait and that cubit schedules. For every word whose read barrier has another number
/// `b` than before: the words of `able` that a walk behind it met FIRST among the words that
/// waited the old number, and that a walk still reaches with no wait of `b` in front of them,
/// wait `b`. A word with a wait of the new number in front of it on every path gets nothing --
/// a wait in front is no wait taken off. `(word, b, the word with the read barrier)`;
/// `CUBIT_DUMP_USES` prints one `MIRROR` line each.
pub(crate) fn mirror(paths: &[Vec<usize>], before: &[(u8, u8)], now: &[(u8, u8)], able: &[bool]) -> Vec<(usize, u8, usize)> {
    const NB: usize = sp::NUM_BARRIERS;
    let dump = std::env::var("CUBIT_DUMP_USES").is_ok();
    let mut waits: Vec<u8> = now.iter().map(|x| x.1).collect();
    let mut out: Vec<(usize, u8, usize)> = Vec::new();
    for (s, (was, is)) in before.iter().zip(now.iter()).enumerate() {
        let (a, b) = (was.0, is.0);
        if a == b || (a as usize) >= NB || (b as usize) >= NB {
            continue;
        }
        // the words of ordered events that were first waits behind the read barrier of `s`
        let first: Vec<usize> = met(paths, s, |j| before[j].1 & (1 << a) != 0).into_iter().filter(|&j| able[j]).collect();
        // ... and of those, the ones a path reaches with no wait of the new number in front
        let mut reached = met(paths, s, |j| waits[j] & (1 << b) != 0 || first.contains(&j));
        reached.retain(|&j| waits[j] & (1 << b) == 0);
        for w in reached {
            if dump {
                eprintln!("MIRROR b={b} word={w} rb={s} moved={a}->{b}");
            }
            waits[w] |= 1 << b;
            out.push((w, b, s));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A straight line of `n` words.
    fn line(n: usize) -> Vec<Vec<usize>> {
        (0..n).map(|j| if j + 1 < n { vec![j + 1] } else { Vec::new() }).collect()
    }

    /// (the read barrier, the scoreboards waited) of a word
    fn f(rb: u8, waits: &[u8]) -> (u8, u8) {
        (rb, waits.iter().fold(0u8, |m, b| m | (1 << b)))
    }

    #[test]
    fn the_event_word_that_was_the_first_wait_behind_a_read_barrier_waits_its_new_number() {
        // word 1 sets a read barrier: scoreboard 1 without the switch, 0 under it; word 2 is the word of an
        // ordered event and waits 1 for another use, in both; word 3 rewrites the source and waits the use
        let before = [f(7, &[]), f(1, &[]), f(7, &[1]), f(7, &[1]), f(7, &[])];
        let now = [f(7, &[]), f(0, &[]), f(7, &[1]), f(7, &[0]), f(7, &[])];
        let able = [false, false, true, false, false];
        assert_eq!(mirror(&line(5), &before, &now, &able), vec![(2, 0, 1)], "the event word waits the new number too");
        // a read barrier that keeps its number, one that is new and one that is gone under the switch: nothing
        assert!(mirror(&line(5), &before, &before, &able).is_empty());
        let new = [f(7, &[]), f(7, &[]), f(7, &[1]), f(7, &[1]), f(7, &[])];
        assert!(mirror(&line(5), &new, &now, &able).is_empty());
        assert!(mirror(&line(5), &before, &new, &able).is_empty());
        // a word that is no word of an ordered event (or cannot carry a wait) gets nothing
        assert!(mirror(&line(5), &before, &now, &[false; 5]).is_empty());
    }

    #[test]
    fn a_wait_in_front_is_no_wait_taken_off() {
        // as above, and under the switch word 2 -- no word of an ordered event -- waits the new number in
        // front of the event word 3 on the only path
        let before = [f(7, &[]), f(1, &[]), f(7, &[]), f(7, &[1]), f(7, &[1])];
        let now = [f(7, &[]), f(0, &[]), f(7, &[0]), f(7, &[1]), f(7, &[0])];
        let able = [false, false, false, true, false];
        assert!(mirror(&line(5), &before, &now, &able).is_empty());
        // ... on one of two paths only: 1 -> 2 -> 3 and 1 -> 3
        let mut two = line(5);
        two[1] = vec![2, 3];
        assert_eq!(mirror(&two, &before, &now, &able), vec![(3, 0, 1)], "the path round the wait reaches the event word");
    }

    #[test]
    fn only_a_first_wait_is_held() {
        // without the switch the plain word 2 waited the old number in front of the event word 3: the event
        // word was no first wait behind the read barrier, and stays none
        let before = [f(7, &[]), f(1, &[]), f(7, &[1]), f(7, &[1]), f(7, &[])];
        let now = [f(7, &[]), f(0, &[]), f(7, &[1]), f(7, &[1]), f(7, &[0])];
        let able = [false, false, false, true, false];
        assert!(mirror(&line(5), &before, &now, &able).is_empty());
        // two event words, each a first wait on a path of its own (1 -> 2 -> 4 and 1 -> 3 -> 4): both wait
        let fork = vec![vec![1], vec![2, 3], vec![4], vec![4], Vec::new()];
        let before = [f(7, &[]), f(2, &[]), f(7, &[2]), f(7, &[2]), f(7, &[2])];
        let now = [f(7, &[]), f(5, &[]), f(7, &[2]), f(7, &[2]), f(7, &[5])];
        let able = [false, false, true, true, false];
        assert_eq!(mirror(&fork, &before, &now, &able), vec![(2, 5, 1), (3, 5, 1)]);
        // a loop: the read barrier of word 3 is first waited by the event word 1 of the next pass
        let round = vec![vec![1], vec![2], vec![3], vec![1, 4], Vec::new()];
        let before = [f(7, &[]), f(7, &[0]), f(7, &[]), f(0, &[]), f(7, &[0])];
        let now = [f(7, &[]), f(7, &[0]), f(7, &[]), f(3, &[]), f(7, &[3])];
        let able = [false, true, false, false, false];
        assert_eq!(mirror(&round, &before, &now, &able), vec![(1, 3, 3)]);
    }
}

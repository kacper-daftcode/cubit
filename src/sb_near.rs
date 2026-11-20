//! `CUBIT_SB_NEAR=1` (opt-in, default off; honoured only together with `CUBIT_WAIT_POLICY=1`):
//! in a loop that holds a copy word, no word waits for a use it does not need when that use was
//! armed a few words in front of it (KNOWN_ISSUES A70).
//!
//! A scoreboard counts. A word that waits it stands until everything armed on it has come
//! back -- the use it waits for and every other use that is in flight there. The colouring
//! (`scheduling_pass::reallocate_barriers`) gives a use the lowest scoreboard that is free over
//! its flight as the allocator knows the flights; where the waits stand is written behind it
//! (the wait rule, the early release of a far read barrier, the batches of constant loads), and
//! so a word comes to wait a scoreboard a few words behind a setter whose use it neither reads
//! nor rewrites: the rewriter of a load's address register behind a register read, the reader
//! of one constant load of a batch behind the other, a branch or a predicate word that
//! releases a far read barrier one word behind a copy word. The word stands until the near use
//! has landed.
//!
//! Under the switch, at the END of the allocation and on the FIELDS of the schedule as every
//! clause in front of it left them -- which word arms which scoreboard, which word waits which:
//!
//! * `moves` -- **a use in the innermost loop round a copy word (`LDGSTS`) is NAMED when the
//!   first word that waits its scoreboard on a path behind its setter stands at most `REACH`
//!   (8) words behind it, needs nothing of the use and needs no younger use on that
//!   scoreboard** (one armed between the two). Two kinds of uses, and no other:
//!   **the result of a constant load or of a register read** (`LDC`, `LDCU`, `S2R`, `S2UR`,
//!   `CS2R`, `CS2UR`), under any word that is no waiter of the use and reads and rewrites
//!   nothing the setter writes; and **the read barrier of a copy word, under the word of an
//!   ordered event** (`wait_drained::ordered_event`) that is no waiter of the use.
//!   **A named use takes the lowest scoreboard that is EMPTY over its flight by the fields**:
//!   nothing pending there on any path while the use is in flight, nothing armed there inside
//!   the flight, no word of the flight that waits it but the words that need the use; never
//!   one below the copy group's. The flight is every word a path from the setter passes in
//!   front of the first word that needs the use. The uses are taken in text order (of one
//!   word the read barrier first), each on the fields the moves in front of it left.
//! * **A load of a batch leaves it as a use of its own**: the other loads keep the scoreboard
//!   and the batch's waiters; the load that leaves is waited by the first words behind it that
//!   read or rewrite what it writes.
//! * **The registers of a moved copy word count the uniform register of its descriptor**: the
//!   first word on a path that rewrites it needs the read barrier as the first rewriter of an
//!   operand register does, and is the word that waits the new number on that path.
//! * **The wait of the new number goes on the first word that needs the use on every path, and
//!   no wait bit comes off**: a word that waited the old scoreboard keeps that bit, with the
//!   new one beside it where the word needs the use.
//!
//! What the rule does not do:
//!
//! * Nothing outside the loops that hold a copy word, nothing for a result of another kind,
//!   nothing for the read barrier of another word, and nothing for a copy word's read barrier
//!   where the near wait is no word of an ordered event.
//! * **Where no scoreboard is empty by the fields the use stays.** So does a use the author
//!   numbered, one with a setter under a guard (the wait of a guarded producer may stand on a
//!   later reader of its register: the fields do not say for whom), and one with a word that
//!   needs the use and cannot carry a wait.
//! * No barrier comes or goes: one scoreboard number changes on the setter, one wait bit is put
//!   on each first word that needs the use.
//! * Nothing in a trial of the allocator, nothing in the run that asks what the recipe writes
//!   without `CUBIT_LOAD_TOP` and `CUBIT_SB_APART`, nothing without the flow graph of
//!   `CUBIT_SYNC_CLASSES`.
//!
//! What the rule leaves: the word that waited the old scoreboard for another use no longer
//! stands behind the use that moved -- it issues with that use in flight, as every word of the
//! flight that needs nothing of it does. Behind a copy word that word is the word of an ordered
//! event: it keeps its bit, is no longer a wait on the copy word's operand read, and the
//! latency legaliser no longer asks the arming distance between the two -- the copy word's
//! stall may fall to what its other requirements leave. `CUBIT_DUMP_USES` prints one `NEAR`
//! line a named use: the scoreboard and where it goes, `rb` or `wb`, the setter, the words
//! that waited it without need, the words that wait the new number, and for each scoreboard
//! what bars it (`a` words that arm it inside the flight, `h` words of the flight that wait
//! it, `p` words on which something is pending there; `-` empty, `<` below the copy group's,
//! `=` its own).

use crate::load_top::UseView;
use crate::scheduling_pass as sp;

const NB: usize = sp::NUM_BARRIERS;

/// How far behind a setter the first wait of its scoreboard may stand for the use to be named,
/// in words on a path: the farthest of the shapes the rule was written on -- the second
/// constant load of a batch and the first reader of the batch -- stands seven words apart and
/// a reach of twelve names no further use in that loop, and it is counted in words, not in
/// cycles, because the allocator runs in front of the passes that raise and lower the stall
/// fields.
pub(crate) const REACH: usize = 8;

/// A word as the rule reads it: its fields as the allocation left them, and what it is.
#[derive(Clone, Debug, Default)]
pub(crate) struct Word {
    /// the scoreboards it waits (its wait mask, the scoreboard of a `DEPBAR`)
    pub waits: u8,
    /// its read barrier (7: none)
    pub rb: u8,
    /// its write barrier (7: none)
    pub wb: u8,
    /// the registers it reads and the registers it writes, as the allocator keys them
    pub reads: Vec<u16>,
    pub writes: Vec<u16>,
    /// a constant load or a register read: `LDC`, `LDCU`, `S2R`, `S2UR`, `CS2R`, `CS2UR`
    pub constant: bool,
    /// a copy word (`LDGSTS`) that can run
    pub copy: bool,
    /// of a copy word: the uniform register of its descriptor, as the allocator keys registers
    pub desc: Vec<u16>,
    /// the word of an ordered event (`wait_drained::ordered_event`)
    pub event: bool,
    /// inside the innermost loop round a copy word
    pub in_copy_loop: bool,
    /// under a guard: the word may be skipped
    pub guarded: bool,
    /// cubit schedules the word (its fields are not the author's)
    pub free: bool,
    /// the word can carry a wait
    pub can_wait: bool,
}

/// One move: the setter, which of its barriers (the read barrier of a copy word | the write
/// barrier of a result), the scoreboard it leaves and the one it takes, and the words that get
/// the wait of the new number.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Move {
    pub setter: usize,
    pub read_barrier: bool,
    pub from: u8,
    pub to: u8,
    pub waiters: Vec<usize>,
}

/// From the issue of `s`, along every path, up to [`REACH`] words: the first words that wait
/// scoreboard `b`, and the words passed in front of them (`s` among them).
fn reach(paths: &[Vec<usize>], waits: &[u8], s: usize, b: u8) -> (Vec<usize>, Vec<bool>) {
    let n = waits.len();
    let bit = 1u8 << b;
    let mut passed = vec![false; n];
    let mut first = vec![false; n];
    passed[s] = true;
    let mut front = vec![s];
    for _ in 0..REACH {
        let mut next = Vec::new();
        for &j in &front {
            for &k in &paths[j] {
                if waits[k] & bit != 0 {
                    first[k] = true;
                } else if !passed[k] {
                    passed[k] = true;
                    next.push(k);
                }
            }
        }
        front = next;
    }
    ((0..n).filter(|&k| first[k]).collect(), passed)
}

/// The forward scan of the fields: at the entry of every word (in front of its own wait), the
/// scoreboards on which a barrier of another word than `s` is still armed on some path -- set
/// by a word on the way and waited by no word since. `fields`: a word's (waits, read barrier,
/// write barrier).
fn pending(paths: &[Vec<usize>], fields: &[(u8, u8, u8)], s: usize) -> Vec<u8> {
    let n = fields.len();
    let mut at = vec![0u8; n];
    let mut queued = vec![true; n];
    let mut work: Vec<usize> = (0..n).rev().collect();
    while let Some(j) = work.pop() {
        queued[j] = false;
        let (waits, rb, wb) = fields[j];
        let mut st = at[j] & !waits;
        if j != s {
            for b in [rb, wb] {
                if (b as usize) < NB {
                    st |= 1 << b;
                }
            }
        }
        for &k in &paths[j] {
            if st & !at[k] != 0 {
                at[k] |= st;
                if !queued[k] {
                    queued[k] = true;
                    work.push(k);
                }
            }
        }
    }
    at
}

/// The rule, on the fields: the moves in text order -- `paths`: the successors of every word
/// (`wait_drained::paths`); `words`: the fields and the kinds; `uses`: the allocator's uses with
/// the scoreboards they are written on (7: not written); `lowest`: the copy group's bound. The
/// caller writes each move: the setter's read barrier or write barrier, one wait bit on each of
/// its waiters.
pub(crate) fn moves(paths: &[Vec<usize>], words: &[Word], uses: &[UseView], lowest: u8) -> Vec<Move> {
    let n = words.len();
    let dump = std::env::var("CUBIT_DUMP_USES").is_ok();
    let mut fields: Vec<(u8, u8, u8)> = words.iter().map(|w| (w.waits, w.rb, w.wb)).collect();
    // does word `x` read or rewrite a register word `s` writes
    let touches = |x: usize, s: usize| words[s].writes.iter().any(|k| words[x].reads.contains(k) || words[x].writes.contains(k));
    let mut out: Vec<Move> = Vec::new();
    // (the words in text order; of one word the read barrier first)
    for (s, is_rb) in (0..n).flat_map(|s| [(s, true), (s, false)]) {
        let me = &words[s];
        let b = if is_rb { fields[s].1 } else { fields[s].2 };
        let of_the_kind = if is_rb { me.copy } else { me.constant };
        if !of_the_kind || !me.in_copy_loop || !me.free || me.guarded || (b as usize) >= NB {
            continue;
        }
        // the use the field stands for: the use of that kind on that scoreboard with the word among its setters
        let Some(u) = (0..uses.len()).rev().find(|&u| uses[u].is_rb == is_rb && uses[u].colour == b && uses[u].setters.contains(&s)) else {
            continue;
        };
        let mine = &uses[u];
        if mine.pinned || mine.setters.iter().any(|&t| words[t].guarded || !words[t].free) {
            continue;
        }
        let batch = !is_rb && mine.setters.len() > 1;
        // does word `x` need the use of `s`: a setter of the use, a waiter of it (of a batch of results: one
        // that reads or rewrites what `s` writes); of a result, a word that reads or rewrites what `s` writes;
        // of the read barrier of a copy word, a word that rewrites the uniform register of its descriptor
        let needs = |x: usize| {
            mine.setters.contains(&x)
                || (mine.waiters.contains(&x) && !batch)
                || if is_rb { me.desc.iter().any(|k| words[x].writes.contains(k)) } else { touches(x, s) }
        };
        // ---- named: a first wait of the scoreboard inside the reach that needs nothing of the use and no
        // younger use there -- under a read barrier, only the word of an ordered event ----
        let waits: Vec<u8> = fields.iter().map(|f| f.0).collect();
        let (first, between) = reach(paths, &waits, s, b);
        let without_need: Vec<usize> = first
            .into_iter()
            .filter(|&x| {
                if needs(x) || (is_rb && !words[x].event) {
                    return false;
                }
                let younger = uses.iter().enumerate().any(|(v, other)| {
                    other.colour == b
                        && other.waiters.contains(&x)
                        && other.setters.iter().any(|&t| t != s && between[t] && (v != u || touches(x, t)))
                });
                !younger
            })
            .collect();
        if without_need.is_empty() {
            continue;
        }
        // ---- the flight by the fields: every word a path from the setter passes in front of the first word
        // that needs the result; that word ends the path unless it stands under a guard ----
        let mut flight = vec![false; n];
        let mut waiters: Vec<usize> = Vec::new();
        let mut seen = vec![false; n];
        let mut stack: Vec<usize> = paths[s].clone();
        while let Some(j) = stack.pop() {
            if j == s || seen[j] {
                continue;
            }
            seen[j] = true;
            if needs(j) {
                waiters.push(j);
                if !words[j].guarded {
                    continue;
                }
            } else {
                flight[j] = true;
            }
            stack.extend(paths[j].iter().copied());
        }
        waiters.sort_unstable();
        // ---- the lowest scoreboard that is empty over the flight ----
        let pend = pending(paths, &fields, s);
        let in_flight = |j: usize| flight[j] || waiters.contains(&j);
        let mut to: Option<u8> = None;
        let mut bars: Vec<String> = Vec::new();
        for c in 0..NB as u8 {
            if c == b || c < lowest {
                bars.push(if c == b { "=" } else { "<" }.to_string());
                continue;
            }
            let bit = 1u8 << c;
            let a = (0..n).filter(|&j| in_flight(j) && (fields[j].1 == c || fields[j].2 == c)).count();
            let h = (0..n).filter(|&j| flight[j] && fields[j].0 & bit != 0).count();
            let p = (0..n).filter(|&j| (in_flight(j) || j == s) && pend[j] & bit != 0).count();
            if a + h + p == 0 {
                if to.is_none() {
                    to = Some(c);
                }
                bars.push("-".to_string());
            } else {
                bars.push(format!("a{a}h{h}p{p}"));
            }
        }
        // (a word that needs the use and cannot carry a wait: the use stays)
        let able = waiters.iter().all(|&j| words[j].free && words[j].can_wait);
        let to = to.filter(|_| able);
        if dump {
            let goes = match to {
                Some(c) => format!("->{c}"),
                None if able => " (no scoreboard empty)".to_string(),
                None => " (a waiter cannot wait)".to_string(),
            };
            let kind = if is_rb { "rb" } else { "wb" };
            eprintln!("NEAR b={b}{goes} {kind} setter={s} without_need={without_need:?} waiters={waiters:?} bars=[{}]", bars.join(" "));
        }
        let Some(c) = to else { continue };
        if is_rb {
            fields[s].1 = c;
        } else {
            fields[s].2 = c;
        }
        for &j in &waiters {
            fields[j].0 |= 1 << c;
        }
        out.push(Move { setter: s, read_barrier: is_rb, from: b, to: c, waiters });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A straight line of `n` plain words that cubit schedules.
    fn line(n: usize) -> (Vec<Vec<usize>>, Vec<Word>) {
        let paths = (0..n).map(|j| if j + 1 < n { vec![j + 1] } else { Vec::new() }).collect();
        let words = (0..n).map(|_| Word { rb: 7, wb: 7, free: true, can_wait: true, ..Word::default() }).collect();
        (paths, words)
    }
    fn wb(setters: &[usize], waiters: &[usize], colour: u8) -> UseView {
        UseView { setters: setters.to_vec(), waiters: waiters.to_vec(), segs: Vec::new(), is_rb: false, colour, pinned: false }
    }
    fn rb(setter: usize, waiter: usize, colour: u8) -> UseView {
        UseView { is_rb: true, ..wb(&[setter], &[waiter], colour) }
    }
    /// Word `j` is a constant load in a loop that holds a copy word; it writes register `reg` on
    /// scoreboard `b`.
    fn constant(words: &mut [Word], j: usize, reg: u16, b: u8) {
        words[j].constant = true;
        words[j].in_copy_loop = true;
        words[j].wb = b;
        words[j].writes = vec![reg];
    }

    /// The read barrier of word 2 is pending to word 5, its rewriter, on scoreboard 0; word 4 is a
    /// register read on scoreboard 0 whose reader is word 7.
    fn a_result_in_front_of_a_rewriter() -> (Vec<Vec<usize>>, Vec<Word>, Vec<UseView>) {
        let (paths, mut words) = line(10);
        words[2].rb = 0;
        constant(&mut words, 4, 40, 0);
        words[5].waits = 1 << 0;
        words[7].reads = vec![40];
        (paths, words, vec![rb(2, 5, 0), wb(&[4], &[7], 0)])
    }

    #[test]
    fn a_near_result_takes_the_lowest_scoreboard_that_is_empty_by_the_fields() {
        let (paths, words, uses) = a_result_in_front_of_a_rewriter();
        assert_eq!(moves(&paths, &words, &uses, 0), vec![Move { read_barrier: false, setter: 4, from: 0, to: 1, waiters: vec![7] }]);
        // never below the copy group's
        assert_eq!(moves(&paths, &words, &uses, 2), vec![Move { read_barrier: false, setter: 4, from: 0, to: 2, waiters: vec![7] }]);
        // a result that is pending on 1 when the setter issues, a word of the flight that arms 1, a word of the
        // flight that waits 1: each bars the scoreboard
        for bar in 0..3 {
            let mut w = words.clone();
            match bar {
                0 => w[1].wb = 1,
                1 => w[6].rb = 1,
                _ => w[6].waits = 1 << 1,
            }
            assert_eq!(moves(&paths, &w, &uses, 0), vec![Move { read_barrier: false, setter: 4, from: 0, to: 2, waiters: vec![7] }], "bar {bar}");
        }
        // ... a result on 1 that was waited in front of the setter does not, and the reader may wait 1 already
        let mut w = words.clone();
        w[1].wb = 1;
        w[3].waits = 1 << 1;
        w[7].waits = 1 << 1;
        assert_eq!(moves(&paths, &w, &uses, 0), vec![Move { read_barrier: false, setter: 4, from: 0, to: 1, waiters: vec![7] }]);
    }

    #[test]
    fn a_use_is_named_only_by_a_near_wait_that_needs_nothing_of_it() {
        let (paths, words, uses) = a_result_in_front_of_a_rewriter();
        // the first wait of the scoreboard is the result's own reader: nothing is named
        let mut w = words.clone();
        w[5].waits = 0;
        w[7].waits = 1 << 0;
        assert!(moves(&paths, &w, &uses, 0).is_empty());
        // the rewriter reads the result: it needs it
        let mut w = words.clone();
        w[5].reads = vec![40];
        assert!(moves(&paths, &w, &uses, 0).is_empty());
        // the wait stands beyond the reach
        let (paths, mut far) = line(20);
        far[2].rb = 0;
        constant(&mut far, 4, 40, 0);
        far[4 + REACH + 1].waits = 1 << 0;
        far[15].reads = vec![40];
        let uses = vec![rb(2, 4 + REACH + 1, 0), wb(&[4], &[15], 0)];
        assert!(moves(&paths, &far, &uses, 0).is_empty());
        far[4 + REACH + 1].waits = 0;
        far[4 + REACH].waits = 1 << 0;
        assert_eq!(moves(&paths, &far, &uses, 0).len(), 1, "at the reach it is named");
        // the word needs a younger use on the scoreboard, armed between the two: its wait covers the result
        let mut young = far.clone();
        young[6].wb = 0;
        let mut with = vec![rb(2, 4 + REACH, 0), wb(&[4], &[15], 0), wb(&[6], &[4 + REACH], 0)];
        assert!(moves(&paths, &young, &with, 0).is_empty());
        // ... not one that is armed in front of the setter
        young[6].wb = 7;
        young[3].wb = 0;
        with[2] = wb(&[3], &[4 + REACH], 0);
        assert_eq!(moves(&paths, &young, &with, 0).len(), 1);
    }

    #[test]
    fn a_load_leaves_its_batch_with_its_own_first_readers() {
        // two constant loads on scoreboard 1, ONE use; the reader of the first (word 6) is the batch's waiter,
        // the reader of the second stands at word 9
        let (paths, mut words) = line(12);
        constant(&mut words, 2, 40, 1);
        constant(&mut words, 4, 42, 1);
        words[6].reads = vec![40];
        words[6].waits = 1 << 1;
        words[9].reads = vec![42];
        let uses = vec![wb(&[2, 4], &[6], 1)];
        assert_eq!(moves(&paths, &words, &uses, 0), vec![Move { read_barrier: false, setter: 4, from: 1, to: 0, waiters: vec![9] }], "the first load stays: its reader is the first wait");
        // the batch's waiter reads both: nothing is named
        let mut both = words.clone();
        both[6].reads = vec![40, 42];
        assert!(moves(&paths, &both, &uses, 0).is_empty());
    }

    #[test]
    fn what_the_rule_leaves_alone() {
        let (paths, words, uses) = a_result_in_front_of_a_rewriter();
        let stays = |w: &[Word], u: &[UseView]| moves(&paths, w, u, 0).is_empty();
        // outside a loop that holds a copy word; a result of another kind
        let mut w = words.clone();
        w[4].in_copy_loop = false;
        assert!(stays(&w, &uses));
        let mut w = words.clone();
        w[4].constant = false;
        assert!(stays(&w, &uses));
        // a setter under a guard, a word of the author, a use the author numbered
        let mut w = words.clone();
        w[4].guarded = true;
        assert!(stays(&w, &uses));
        let mut w = words.clone();
        w[4].free = false;
        assert!(stays(&w, &uses));
        let mut pinned = vec![rb(2, 5, 0), wb(&[4], &[7], 0)];
        pinned[1].pinned = true;
        assert!(stays(&words, &pinned));
        // a reader that cannot carry a wait
        let mut w = words.clone();
        w[7].can_wait = false;
        assert!(stays(&w, &uses));
        // no scoreboard is empty: a result pending on each of the others
        let mut w = words.clone();
        for (j, b) in [(0usize, 1u8), (0, 2), (1, 3), (1, 4), (3, 5)] {
            if w[j].wb == 7 {
                w[j].wb = b;
            } else {
                w[j].rb = b;
            }
        }
        assert!(stays(&w, &uses));
        // a use that is not written has no field
        let unwritten = vec![rb(2, 5, 0), wb(&[4], &[7], 7)];
        assert!(stays(&words, &unwritten));
    }

    #[test]
    fn a_reader_under_a_guard_does_not_end_the_flight() {
        // the first reader (word 7) may be skipped: the reader behind it (word 9) waits the new number too,
        // and the flight runs on to it -- a word that arms 1 at word 8 bars the scoreboard
        let (paths, mut words, uses) = a_result_in_front_of_a_rewriter();
        words[7].guarded = true;
        words[9].reads = vec![40];
        assert_eq!(moves(&paths, &words, &uses, 0), vec![Move { read_barrier: false, setter: 4, from: 0, to: 1, waiters: vec![7, 9] }]);
        words[8].wb = 1;
        assert_eq!(moves(&paths, &words, &uses, 0), vec![Move { read_barrier: false, setter: 4, from: 0, to: 2, waiters: vec![7, 9] }]);
    }

    /// The read barrier of word 2 (a store) is pending to word 5, its rewriter and the word of an
    /// ordered event, on scoreboard 0; word 4 is a copy word with its read barrier on 0 too and
    /// the uniform register 600 in its descriptor; word 8 is the first rewriter of its registers.
    fn a_copy_word_in_front_of_an_event_word() -> (Vec<Vec<usize>>, Vec<Word>, Vec<UseView>) {
        let (paths, mut words) = line(12);
        words[2].rb = 0;
        words[4].copy = true;
        words[4].in_copy_loop = true;
        words[4].rb = 0;
        words[4].desc = vec![600];
        words[5].waits = 1 << 0;
        words[5].event = true;
        (paths, words, vec![rb(2, 5, 0), rb(4, 8, 0)])
    }

    #[test]
    fn the_read_barrier_of_a_copy_word_moves_only_under_the_word_of_an_ordered_event() {
        let (paths, words, uses) = a_copy_word_in_front_of_an_event_word();
        assert_eq!(moves(&paths, &words, &uses, 0), vec![Move { read_barrier: true, setter: 4, from: 0, to: 1, waiters: vec![8] }]);
        // a plain word that waits the scoreboard behind the copy word names nothing
        let mut plain = words.clone();
        plain[5].event = false;
        assert!(moves(&paths, &plain, &uses, 0).is_empty());
        // the event word is the first rewriter of the copy word's registers: it needs the read barrier
        let own = vec![rb(2, 5, 0), rb(4, 5, 0)];
        assert!(moves(&paths, &words, &own, 0).is_empty());
        // a word that is no copy word keeps its read barrier, whatever waits behind it
        let mut other = words.clone();
        other[4].copy = false;
        assert!(moves(&paths, &other, &uses, 0).is_empty());
    }

    #[test]
    fn the_registers_of_a_moved_copy_word_count_the_uniform_register_of_its_descriptor() {
        // word 6 rewrites the descriptor's uniform register in front of the allocator's waiter (word 8): it
        // is the first rewriter on the path and waits the new number; the waiter behind it is not reached
        let (paths, mut words, uses) = a_copy_word_in_front_of_an_event_word();
        words[6].writes = vec![600];
        assert_eq!(moves(&paths, &words, &uses, 0), vec![Move { read_barrier: true, setter: 4, from: 0, to: 1, waiters: vec![6] }]);
        // an event word that rewrites that register needs the read barrier: nothing is named
        words[6].writes = Vec::new();
        words[5].writes = vec![600];
        assert!(moves(&paths, &words, &uses, 0).is_empty());
    }

    #[test]
    fn the_two_clauses_take_their_turns_in_text_order() {
        // behind the copy word a constant load at word 6 on scoreboard 0, read at word 10; word 7 waits 0 for
        // the read barrier of word 3 and reads nothing of the load -- the load's result is named too
        let (paths, mut words, mut uses) = a_copy_word_in_front_of_an_event_word();
        words[3].rb = 0;
        constant(&mut words, 6, 40, 0);
        words[7].waits = 1 << 0;
        words[10].reads = vec![40];
        uses.push(rb(3, 7, 0));
        uses.push(wb(&[6], &[10], 0));
        // the copy word's read barrier takes 1 and is waited at word 8; the result finds 1 taken over its
        // flight -- that read barrier is pending there -- and takes 2
        assert_eq!(
            moves(&paths, &words, &uses, 0),
            vec![
                Move { read_barrier: true, setter: 4, from: 0, to: 1, waiters: vec![8] },
                Move { read_barrier: false, setter: 6, from: 0, to: 2, waiters: vec![10] },
            ]
        );
    }
}

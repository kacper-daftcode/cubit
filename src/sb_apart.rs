//! `CUBIT_SB_APART=1` (opt-in, default off; honoured only together with `CUBIT_WAIT_POLICY=1`):
//! a write-barrier use shares no scoreboard with a read barrier that is pending over its flight
//! (KNOWN_ISSUES A69).
//!
//! A scoreboard counts. A word that waits it stands until everything armed on it has come
//! back: the result the word reads, and every operand read that another word still has pending
//! there (a read barrier). The colouring (`scheduling_pass::reallocate_barriers`) gives a use
//! the lowest scoreboard that is free over its flight -- and under `CUBIT_SB_KIND=wide` a read
//! barrier JOINS the low scoreboards and keeps none of them busy. A short producer behind such
//! a word (`S2R`, `POPC`, a constant load) then takes the scoreboard the read barrier stands
//! on, and its reader, a few words on, waits behind every operand read that is pending there.
//!
//! Under the switch, behind the colouring and behind `load_top::scoreboards`:
//!
//! * `moves` -- **a write-barrier use that has a read-barrier use on its scoreboard whose
//!   flight meets its own moves to the lowest scoreboard on which nothing is in flight over its
//!   flight**: no read barrier, no other result, no use the author numbered; never one below
//!   the copy group's, never the scoreboard of a load that waits at the tops of its loops, and
//!   none on which a word of the flight already carries a wait that no use of the allocator
//!   wrote (the author's, a drain). Its setters arm the new scoreboard and its waiters wait
//!   the new one. Where no scoreboard is free the use stays.
//! * `load_top::scoreboards` takes no scoreboard on which a read barrier is pending over the
//!   flight of the load (its `apart`): a load that waits at the tops of its loops is moved by
//!   that clause alone, and not onto such a scoreboard.
//!
//! What the rule does not do:
//!
//! * **No wait comes off a word and no barrier goes.** A use that moves keeps every setter
//!   and every waiter; the number changes on all of them together. A word of an ordered event
//!   among the waiters waits as before, under the new number.
//! * **No read-barrier use is touched**, and the wait that releases a read barrier stays on
//!   the word that rewrites the source, on the scoreboard the read-barrier use names.
//! * **No use joins another use in flight.** The scoreboard a use moves to is free over the
//!   whole flight -- the allocator's own condition for a scoreboard it gives without sharing --
//!   so the move puts no result beside another result.
//! * **No use takes the scoreboard of a load that waits at the tops of its loops**, wherever
//!   that load flies: the words that wait such a scoreboard are the tops, and the clause of
//!   `CUBIT_LOAD_TOP` chose it for having no other.
//! * **Nothing for a use with a setter under a guard.** The fourth clause of
//!   `CUBIT_WAIT_POLICY` writes the wait of a guarded producer on a later reader of its
//!   register, behind the colouring (`cfg_flow::Cfg::stacked_guarded_readers`): the flight the
//!   colouring knows is not all of that use, and a scoreboard that is free over it may carry
//!   another result where that reader stands.
//! * Nothing for a use the author numbered, nothing in the trial of `CUBIT_SB_KIND`, and
//!   nothing without the flow graph of `CUBIT_SYNC_CLASSES`.
//!
//! What the rule leaves: where every other scoreboard carries a read barrier or a result over
//! the flight, the use stays beside the read barrier (`CUBIT_DUMP_USES` prints one `APART`
//! line a use that shares, with what bars each scoreboard). A word that waited the old
//! scoreboard for the use that moved no longer releases what else was pending there. The wait
//! of every read barrier is written on its own waiters and stays -- and where the wait rule
//! (`CUBIT_WAIT_DRAINED`) had left it unwritten behind such a word, it is written again: on a
//! rewriter that may now stand behind a result of a use that stayed on that scoreboard. A wait
//! that stood in front of a word by coincidence -- in front of a rewriter of the GUARD of an
//! event word, which the allocator does not protect (KNOWN_ISSUES A68), or between two uses of
//! different kinds on one scoreboard -- may go or come with the number.

use crate::load_top::UseView;
use crate::scheduling_pass as sp;

/// Do two flights meet: is there a word on which both uses are pending.
pub(crate) fn meet(a: &[(usize, usize)], b: &[(usize, usize)]) -> bool {
    a.iter().any(|&(a0, a1)| b.iter().any(|&(b0, b1)| a0 <= b1 && b0 <= a1))
}

/// The clause, behind the colouring: for every write-barrier use that the allocator coloured
/// and that is none of `topped` (the uses that wait at the tops of their loops: theirs is
/// `load_top::scoreboards`) and none of `guarded` (the uses with a setter under a guard), in
/// text order, the scoreboard it moves to -- `(use, scoreboard)` for those that move.
///
/// A use SHARES when a read-barrier use on its scoreboard has a flight that meets its own. It
/// moves to the lowest scoreboard that is FREE: not below `lowest` (the copy group's), not the
/// scoreboard of one of `topped`, no other use on it with a flight that meets its own -- a
/// read barrier, another result, a use the author numbered --, and no word of its flight that
/// already carries a wait on it (`waits`: the bits a word has by its author's hand or by a
/// drain) other than its own setters and waiters. A use that finds none stays.
/// `CUBIT_DUMP_USES` prints one `APART` line a use that shares: the scoreboard and where it
/// moves, the setters, the setters of the read barriers beside it, and for each scoreboard
/// what bars it (`r` read barriers, `w` results, `h` words that would hold; `-` free, `<`
/// below the copy group's, `t` a scoreboard of the loads at the tops, `=` its own).
pub(crate) fn moves(uses: &[UseView], topped: &[usize], guarded: &[usize], waits: &[u8], lowest: u8) -> Vec<(usize, u8)> {
    const NB: usize = sp::NUM_BARRIERS;
    let dump = std::env::var("CUBIT_DUMP_USES").is_ok();
    let mut colour: Vec<u8> = uses.iter().map(|x| x.colour).collect();
    // (the scoreboards of the loads that wait at the tops of their loops: no use moves onto one)
    let loads: Vec<u8> = topped.iter().map(|&t| uses[t].colour).filter(|&b| (b as usize) < NB).collect();
    let mut order: Vec<usize> = (0..uses.len())
        .filter(|&u| {
            !uses[u].is_rb
                && !uses[u].pinned
                && (uses[u].colour as usize) < NB
                && !uses[u].setters.is_empty()
                && !topped.contains(&u)
                && !guarded.contains(&u)
        })
        .collect();
    order.sort_by_key(|&u| (uses[u].setters[0], u));
    let mut moves: Vec<(usize, u8)> = Vec::new();
    for u in order {
        let me = &uses[u];
        let own = colour[u];
        let beside: Vec<usize> = (0..uses.len()).filter(|&v| v != u && colour[v] == own && uses[v].is_rb && meet(&uses[v].segs, &me.segs)).collect();
        if beside.is_empty() {
            continue;
        }
        let mut free: Option<u8> = None;
        let mut bars: Vec<String> = Vec::new();
        for b in 0..NB as u8 {
            if b == own || b < lowest || loads.contains(&b) {
                bars.push(if b == own { "=" } else if b < lowest { "<" } else { "t" }.to_string());
                continue;
            }
            let (mut r, mut w) = (0usize, 0usize);
            for v in (0..uses.len()).filter(|&v| v != u && colour[v] == b && meet(&uses[v].segs, &me.segs)) {
                if uses[v].is_rb {
                    r += 1;
                } else {
                    w += 1;
                }
            }
            let h = me
                .segs
                .iter()
                .flat_map(|&(a0, a1)| a0..=a1.min(waits.len().saturating_sub(1)))
                .filter(|&j| waits[j] & (1 << b) != 0 && !me.setters.contains(&j) && !me.waiters.contains(&j))
                .count();
            if r + w + h == 0 {
                if free.is_none() {
                    free = Some(b);
                }
                bars.push("-".to_string());
            } else {
                bars.push(format!("r{r}w{w}h{h}"));
            }
        }
        if dump {
            let to = match free {
                Some(b) => format!("->{b}"),
                None => " (no scoreboard free)".to_string(),
            };
            let rbs: Vec<usize> = beside.iter().map(|&v| uses[v].setters.first().copied().unwrap_or(0)).collect();
            eprintln!("APART b={own}{to} setters={:?} waiters={:?} beside={rbs:?} bars=[{}]", me.setters, me.waiters, bars.join(" "));
        }
        if let Some(b) = free {
            colour[u] = b;
            moves.push((u, b));
        }
    }
    moves
}

/// The bits that stay, behind both clauses: `uses` with the scoreboards as the switch leaves
/// them, `old` the scoreboards without it, `ordered` the words of ordered events
/// (`wait_drained::ordered_event`). A waiter of a write-barrier use whose number the switch
/// changed that is the word of an ordered event KEEPS its bit on the scoreboard the use left
/// while a read-barrier use that keeps that number is pending on the word: the bit was a wait
/// on that read barrier too, and a wait whose number changes while its setter does not is a
/// wait taken off the word. `(word, scoreboard, the read-barrier use)`, one a word and
/// scoreboard. `CUBIT_DUMP_USES` prints one `KEPT` line each.
pub(crate) fn kept(uses: &[UseView], old: &[u8], ordered: &[bool]) -> Vec<(usize, u8, usize)> {
    const NB: usize = sp::NUM_BARRIERS;
    let dump = std::env::var("CUBIT_DUMP_USES").is_ok();
    let mut out: Vec<(usize, u8, usize)> = Vec::new();
    for (u, me) in uses.iter().enumerate() {
        let (a, b) = (old[u], me.colour);
        if me.is_rb || me.pinned || a == b || (a as usize) >= NB || (b as usize) >= NB {
            continue;
        }
        for &w in &me.waiters {
            if !ordered.get(w).copied().unwrap_or(false) || out.iter().any(|&(x, y, _)| x == w && y == a) {
                continue;
            }
            let pending = (0..uses.len()).find(|&v| uses[v].is_rb && uses[v].colour == a && old[v] == a && uses[v].segs.iter().any(|&(s0, s1)| s0 <= w && w <= s1));
            if let Some(v) = pending {
                if dump {
                    eprintln!("KEPT b={a} word={w} moved={a}->{b} setters={:?} rb={:?}", me.setters, uses[v].setters);
                }
                out.push((w, a, v));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wb(setter: usize, waiter: usize, colour: u8) -> UseView {
        UseView { setters: vec![setter], waiters: vec![waiter], segs: vec![(setter, waiter)], is_rb: false, colour, pinned: false }
    }
    fn rb(setter: usize, waiter: usize, colour: u8) -> UseView {
        UseView { is_rb: true, ..wb(setter, waiter, colour) }
    }

    #[test]
    fn a_result_beside_a_pending_read_barrier_takes_the_lowest_free_scoreboard() {
        // the read barrier of word 3 is pending to word 8 on scoreboard 1; two short results on 1 beside
        // it; the result of word 3 itself flies on 0 over both
        let uses = vec![wb(3, 9, 0), rb(3, 8, 1), wb(4, 5, 1), wb(6, 7, 1)];
        let waits = vec![0u8; 12];
        assert_eq!(moves(&uses, &[], &[], &waits, 0), vec![(2, 2), (3, 2)], "0 carries a result over both flights; 2 is free for each in turn");
        // nothing shares: nothing moves
        let apart = vec![wb(3, 9, 0), rb(3, 8, 1), wb(4, 5, 2), wb(6, 7, 2)];
        assert!(moves(&apart, &[], &[], &waits, 0).is_empty());
    }

    #[test]
    fn a_use_stays_where_every_scoreboard_carries_something_over_its_flight() {
        let mut uses = vec![rb(3, 8, 1), wb(4, 5, 1)];
        // a result in flight over word 4 on each of 0, 2, 3, 4; a read barrier on 5
        for b in [0u8, 2, 3, 4] {
            uses.push(wb(2, 6, b));
        }
        uses.push(rb(1, 9, 5));
        let waits = vec![0u8; 12];
        assert!(moves(&uses, &[], &[], &waits, 0).is_empty(), "no scoreboard is free: the use stays");
        // one of them ends in front of the flight: that scoreboard is free
        uses[4] = wb(1, 3, 3);
        assert_eq!(moves(&uses, &[], &[], &waits, 0), vec![(1, 3)]);
    }

    #[test]
    fn the_bars_of_a_free_scoreboard() {
        let uses = vec![rb(3, 8, 1), wb(4, 6, 1)];
        let waits = vec![0u8; 12];
        // never below the copy group's
        assert_eq!(moves(&uses, &[], &[], &waits, 0), vec![(1, 0)]);
        assert_eq!(moves(&uses, &[], &[], &waits, 1), vec![(1, 2)]);
        // a word of the flight that carries a wait on 0 by hand would hold behind the result: 0 is barred --
        // the use's own waiter may carry it
        let mut hand = waits.clone();
        hand[5] = 1 << 0;
        assert_eq!(moves(&uses, &[], &[], &hand, 0), vec![(1, 2)]);
        let mut own = waits.clone();
        own[6] = 1 << 0;
        assert_eq!(moves(&uses, &[], &[], &own, 0), vec![(1, 0)]);
        // a use the author numbered does not move, and its scoreboard is not free over its flight
        let mut pinned = vec![rb(3, 8, 1), wb(4, 6, 1), wb(2, 5, 0)];
        pinned[2].pinned = true;
        assert_eq!(moves(&pinned, &[], &[], &waits, 0), vec![(1, 2)]);
        pinned[1].pinned = true;
        assert!(moves(&pinned, &[], &[], &waits, 0).is_empty());
        // a use that waits at the tops of its loops is not this clause's, a use with a setter under a guard is
        // left alone, and one that is not written has no scoreboard
        assert!(moves(&uses, &[1], &[], &waits, 0).is_empty());
        assert!(moves(&uses, &[], &[1], &waits, 0).is_empty());
        // no use takes the scoreboard of a load that waits at a top, wherever that load flies
        let far = vec![rb(3, 8, 1), wb(4, 6, 1), wb(40, 60, 0)];
        assert_eq!(moves(&far, &[], &[], &waits, 0), vec![(1, 0)], "0 is free over the flight");
        assert_eq!(moves(&far, &[2], &[], &waits, 0), vec![(1, 2)], "0 is the scoreboard of a load at a top");
        let unwritten = vec![rb(3, 8, 1), wb(4, 6, 7)];
        assert!(moves(&unwritten, &[], &[], &waits, 0).is_empty());
        let rb_unwritten = vec![rb(3, 8, 7), wb(4, 6, 1)];
        assert!(moves(&rb_unwritten, &[], &[], &waits, 0).is_empty());
    }

    #[test]
    fn flights_meet_on_a_word_they_share() {
        assert!(meet(&[(3, 8)], &[(8, 9)]));
        assert!(!meet(&[(3, 8)], &[(9, 12)]));
        assert!(meet(&[(20, 30), (2, 4)], &[(4, 6)]), "a flight that wraps round a loop meets at the loop's top");
    }

    #[test]
    fn the_word_of_an_ordered_event_keeps_its_bit_while_a_read_barrier_is_pending_on_it() {
        // the read barrier of word 3 is pending to word 8 on scoreboard 1; the results of words 4 and 6 went
        // from 1 to 2 with the switch; word 5 is the word of an ordered event, word 7 is not
        let uses = vec![rb(3, 8, 1), wb(4, 5, 2), wb(6, 7, 2)];
        let old = [1u8, 1, 1];
        let mut ordered = vec![false; 12];
        ordered[5] = true;
        assert_eq!(kept(&uses, &old, &ordered), vec![(5, 1, 0)], "the event word keeps bit 1; the plain reader goes with its number");
        // a use whose number did not change keeps nothing, and neither does a waiter behind the read barrier's flight
        assert!(kept(&uses, &[1, 2, 2], &ordered).is_empty());
        let behind = vec![rb(3, 4, 1), wb(4, 5, 2)];
        assert!(kept(&behind, &[1, 1], &ordered).is_empty(), "the read barrier was released at word 4");
        // a read barrier that itself is on another number than the one the use left is not the one the bit released
        let other = vec![rb(3, 8, 0), wb(4, 5, 2)];
        assert!(kept(&other, &[0, 1], &ordered).is_empty());
    }
}

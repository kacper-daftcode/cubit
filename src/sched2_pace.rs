//! `CUBIT_SCHED2_PACE=tensor` (opt-in; needs the legaliser, `CUBIT_SCHED2=1 CUBIT_SCHED2_LAT=<table>`):
//! in a tensor loop two words of one arithmetic unit do not issue in consecutive cycles.
//!
//! The vendor's schedules pace one unit of the datapath: a word whose opcode is `IADD3`, `LEA`,
//! `LOP3`, `PRMT` or `SHF` and whose NEXT word in the text is one of the five too stands at a
//! stall of 2 or more — in his schedules of the served FC1, of its r33 form and of the served
//! FC2 in 507 of 507 places, inside the tensor loop and outside it, never at 1. cubit's table
//! has no such row, and none is needed for a legal schedule: one cycle between two such words is
//! what cubit's own schedules carry on a card. The pacing says where cycles stand.
//!
//! Under the switch such a word of a tensor loop (`scheduling_pass::tensor_loop_words`: the
//! innermost loop around a warp tensor word, first word to backward branch) takes a stall of 2 as
//! its FLOOR, in front of the legaliser. The legaliser then raises and the lowering pass lowers
//! exactly as without the switch, and neither goes below the floor: a wait still stands on the
//! last word in front of its reader, and it is shorter by the cycles the pacing has already put
//! between the producer and the reader. In the vendor's text that reads as "the wait stands
//! early": the holds in front of his tensor words are shorter than cubit's, and the words behind
//! the producers are longer.
//!
//! What stays as it is: a hand-scheduled word; a word of the unit in front of a word of another
//! opcode (`MOV`, `IMAD`, a load, a tensor word, a branch); every word outside the tensor loops
//! (the vendor paces the whole kernel — no card has read cubit's frame paced, so no value of the
//! switch does it); a word that already stands at 2 or more. No row of the dependency table
//! moves.

use crate::ir::Instruction;
use crate::scheduling_pass as sp;

/// The opcodes of the paced unit.
pub const PACED_OPCODES: [&str; 5] = ["IADD3", "LEA", "LOP3", "PRMT", "SHF"];

/// The stall a word of the unit carries at least in front of another word of the unit.
pub const PACE: u8 = 2;

/// `CUBIT_SCHED2_PACE` as written: `Ok(true)` for `tensor`, `Ok(false)` when unset, empty or
/// `0`, the message of the refusal for any other value.
pub fn request() -> Result<bool, String> {
    match std::env::var("CUBIT_SCHED2_PACE") {
        Err(_) => Ok(false),
        Ok(v) if v.is_empty() || v == "0" => Ok(false),
        Ok(v) if v == "tensor" => Ok(true),
        Ok(v) => Err(format!(
            "CUBIT_SCHED2_PACE={v}: the only value is `tensor` (in a tensor loop a word of the unit IADD3 | LEA | LOP3 | PRMT | SHF stands at a stall of 2 at least in front of another word of the unit, set in front of the legaliser); unset = the stalls as the scheduler writes them"
        )),
    }
}

/// The words the pacing speaks of, in text order: a word of a tensor loop that cubit schedules,
/// of the unit, whose next word in the text is of the unit too — whatever stall it carries.
pub fn paced(insns: &[Instruction]) -> Vec<usize> {
    let inside = sp::tensor_loop_words(insns);
    let unit = |x: &Instruction| PACED_OPCODES.contains(&x.opcode.as_str());
    (0..insns.len().saturating_sub(1)).filter(|&i| inside[i] && !insns[i].hand_sched && unit(&insns[i]) && unit(&insns[i + 1])).collect()
}

/// The floor: every word of [`paced`] that stands below [`PACE`] takes it. Returns the number of
/// such words and the cycles added. To be run in front of the legaliser (and in front of the
/// snapshot the lowering pass takes its floors from). No flag, wait or barrier moves.
pub fn apply(insns: &mut [Instruction]) -> (usize, usize) {
    let (mut words, mut cycles) = (0, 0);
    for i in paced(insns) {
        let s = insns[i].ctrl.stall;
        if s < PACE {
            insns[i].ctrl.stall = PACE;
            words += 1;
            cycles += (PACE - s) as usize;
        }
    }
    (words, cycles)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(s: &str, addr: u32, stall: u8) -> Instruction {
        let mut i = crate::parse_sass(s, addr).unwrap();
        i.hand_sched = false;
        i.ctrl.stall = stall;
        i.ctrl.yield_flag = true;
        i.ctrl.write_bar = 7;
        i.ctrl.read_bar = 7;
        i.ctrl.wait_mask = 0;
        i
    }

    fn stalls(k: &[Instruction]) -> Vec<u8> {
        k.iter().map(|x| x.ctrl.stall).collect()
    }

    /// [0 ..= 1] a pair of the unit outside every loop | [2 ..= 9] a loop around a tensor word | [10] frame
    fn kernel() -> Vec<Instruction> {
        vec![
            word("LOP3.LUT R4, R5, R6, RZ, 0x3c, !PT", 0x00, 1),
            word("LOP3.LUT R7, R5, R6, RZ, 0xc0, !PT", 0x10, 1),
            word("PRMT R31, R9, 0x5140, R10", 0x20, 1),
            word("MOV R12, R9", 0x30, 1),
            word("LOP3.LUT R28, R9, R10, RZ, 0x3c, !PT", 0x40, 1),
            word("LOP3.LUT R29, R9, R10, RZ, 0xc0, !PT", 0x50, 1),
            word("SHF.R.U32.HI R30, RZ, 0x2, R9", 0x60, 4),
            word("HMMA.16816.F32 R24, R12, R16, R24", 0x70, 1),
            word("IADD3 R20, PT, PT, R20, 0x1, RZ", 0x80, 1),
            word("BRA 0x20", 0x90, 5),
            word("MOV R9, R10", 0xa0, 1),
        ]
    }

    #[test]
    fn a_unit_word_in_front_of_a_unit_word_of_a_tensor_loop_takes_the_floor() {
        let mut k = kernel();
        assert_eq!(paced(&k), [4, 5], "the two LOP3 of the loop: the second stands in front of a SHF");
        let flags: Vec<bool> = k.iter().map(|x| x.ctrl.yield_flag).collect();
        assert_eq!(apply(&mut k), (2, 2));
        assert_eq!(stalls(&k), [1, 1, 1, 1, 2, 2, 4, 1, 1, 5, 1]);
        assert_eq!(k.iter().map(|x| x.ctrl.yield_flag).collect::<Vec<_>>(), flags, "no flag moves");
        assert_eq!(apply(&mut k), (0, 0), "a second pass finds nothing");
    }

    #[test]
    fn another_opcode_behind_it_a_pair_outside_the_loop_and_an_authors_word_stay() {
        let k = kernel();
        // [0] in front of [1]: outside every loop; [2] PRMT in front of a MOV; [6] SHF in front of the tensor word;
        // [8] IADD3 in front of the branch
        assert!(!paced(&k).iter().any(|i| [0, 2, 6, 8].contains(i)));
        let mut k = kernel();
        k[4].hand_sched = true;
        assert_eq!(paced(&k), [5]);
        assert_eq!(apply(&mut k), (1, 1));
        assert_eq!(k[4].ctrl.stall, 1);
    }

    #[test]
    fn a_word_that_stands_at_two_or_more_is_left() {
        let mut k = kernel();
        k[4].ctrl.stall = 3;
        k[5].ctrl.stall = 2;
        assert_eq!(apply(&mut k), (0, 0));
        assert_eq!(stalls(&k)[4..6], [3, 2]);
    }

    #[test]
    fn every_pair_of_the_five_opcodes_is_paced_and_no_other() {
        for a in ["IADD3 R28, PT, PT, R9, 0x1, RZ", "LEA R28, R9, R10, 0x2", "LOP3.LUT R28, R9, R10, RZ, 0x3c, !PT", "PRMT R28, R9, 0x5140, R10", "SHF.L.U32 R28, R9, 0x1f, RZ"] {
            for (b, yes) in [
                ("IADD3 R29, PT, PT, R9, 0x2, RZ", true),
                ("LEA R29, R9, R10, 0x2", true),
                ("LOP3.LUT R29, R9, R10, RZ, 0xc0, !PT", true),
                ("PRMT R29, R9, 0x7362, R10", true),
                ("SHF.R.U32.HI R29, RZ, 0x2, R9", true),
                ("MOV R29, R9", false),
                ("IMAD R29, R9, 0x8, R10", false),
                ("ISETP.NE.AND P1, PT, R9, RZ, PT", false),
            ] {
                let k = vec![word(a, 0x00, 1), word(b, 0x10, 1), word("HMMA.16816.F32 R24, R12, R16, R24", 0x20, 1), word("BRA 0x0", 0x30, 5)];
                assert_eq!(paced(&k) == [0], yes, "`{a}` in front of `{b}`");
            }
        }
    }

    #[test]
    fn a_kernel_without_a_tensor_loop_is_not_touched() {
        let mut k = vec![word("LOP3.LUT R4, R5, R6, RZ, 0x3c, !PT", 0x00, 1), word("LOP3.LUT R7, R5, R6, RZ, 0xc0, !PT", 0x10, 1), word("BRA 0x0", 0x20, 5)];
        assert_eq!(apply(&mut k), (0, 0));
    }
}

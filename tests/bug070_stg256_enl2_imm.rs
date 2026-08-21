//! BUG-070 (F2Q-070): STG.256 desc[UR][R.64+imm] immediate silently corrupted.
//!
//! Repro (severity A, from b12-full-1 probes): work/m9-103a/pf/tS4.sass:
//!   STG.E.ENL2.256 desc[UR4][R54.64+0x20], R40, R44  -> emitted word decoded
//!   back (and executed) as imm -0x20; +0x40 and up collapsed to imm 0. No
//!   WARN at `cubit asm`. Root: sm103a.json STG_dARI_R_R [256,E,ENL2] b4fill
//!   row truncated the desc-offset field to 1 bit @40 (+ baked guard=PT).
//!   Decode-side sign_extend(1 bit) then rendered +0x20 as `+-0x20`.
//!
//! Oracle (nvdisasm/cuobjdump 13.3, byte-patched cubin sweeps,
//! results/cubitfix/070/probe_sweep.txt):
//!   - STG.256 desc offset = UNSIGNED 16-bit window @[55:40], offset = win<<5
//!     (win 0x8000 -> +0x100000, win 0xffff -> +0x1fffe0); family-wide
//!     (ENL2, EL.ENL2, EL.ELL2, ELL2-NA, EFL2-NA all share it).
//!   - guard = bits[15:12] (7=PT, 0..6 = @P0..@P6) on the ENL2 row too.
//!   - LDG.256's shr2 20-bit window IS signed (win 0x80000 -> +-0x200000):
//!     untouched by this fix.
//!
//! Fix: (a) data: ENL2 group gets the sibling geometry (16-bit imm window,
//! guard field, guard bits cleared from and_base, variable_mask widened to
//! the new field bits); all 5 STG.256 groups switch to the new unsigned
//! `sub_imm2_shr5u` extraction; (b) code: encoder fails CLOSED on
//! negative/misaligned/overflow desc offsets instead of masking-truncation
//! (BUG-043-class loud failure), decoder renders the window unsigned.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

// Oracle-verified <word payload (sched dword stripped), canonical text>.
static GOLD: &[(u128, &str)] = &[
    // tS4 repro family (STG.E.ENL2.256 desc[UR4][R54.64...], R40, R44)
    (0x000000000f121804f8000028362c797fu128, "STG.E.ENL2.256 desc[UR4][R54.64], R40, R44"),
    (0x000000000f121804f8000128362c797fu128, "STG.E.ENL2.256 desc[UR4][R54.64+0x20], R40, R44"),
    (0x000000000f121804f8001f28362c797fu128, "STG.E.ENL2.256 desc[UR4][R54.64+0x3e0], R40, R44"),
    (0x000000000f121804f8800028362c797fu128, "STG.E.ENL2.256 desc[UR4][R54.64+0x100000], R40, R44"),
    (0x000000000f121804f8ffff28362c797fu128, "STG.E.ENL2.256 desc[UR4][R54.64+0x1fffe0], R40, R44"),
    (0x000000000f121804f8000128362c097fu128, "@P0 STG.E.ENL2.256 desc[UR4][R54.64+0x20], R40, R44"),
    (0x000000000f121804f8000028362c697fu128, "@P6 STG.E.ENL2.256 desc[UR4][R54.64], R40, R44"),
    // sibling group (EL.ENL2.STRONG.GPU): same unsigned window semantics
    (0x000000000f22f804f8000408040c797fu128, "STG.E.EL.ENL2.256.STRONG.GPU desc[UR4][R4.64+0x80], R8, R12"),
    (0x000000000f22f804f8800008040c797fu128, "STG.E.EL.ENL2.256.STRONG.GPU desc[UR4][R4.64+0x100000], R8, R12"),
];

#[test]
fn bug070_decode_render_reencode_exact() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let mut fails = Vec::new();
    for &(word, golden) in GOLD {
        let d = match idx.decode(word, 0, &t) {
            Ok(d) => d,
            Err(e) => { fails.push(format!("word {word:032x}: decode fail: {e}")); continue; }
        };
        let text = cubit::printer::to_sass(&d);
        if text != golden {
            fails.push(format!("word {word:032x}: render {text:?} != golden {golden:?}"));
            continue;
        }
        let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
        let w2 = encode_instruction(&insn, &t).unwrap();
        if (w2 & !SCHED) != (word & !SCHED) {
            fails.push(format!("re-encode diff {w2:032x} vs {word:032x}"));
        }
    }
    assert!(fails.is_empty(), "{} failures:\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn bug070_encode_imm_window_payload() {
    // The tS4 repro: text -> exact window bits at [55:40].
    let t = t103a();
    for (sass, win) in [
        ("STG.E.ENL2.256 desc[UR4][R54.64], R40, R44 ;", 0x0000u64),
        ("STG.E.ENL2.256 desc[UR4][R54.64+0x20], R40, R44 ;", 0x0001),
        ("STG.E.ENL2.256 desc[UR4][R54.64+0x3e0], R40, R44 ;", 0x001f),
        ("STG.E.ENL2.256 desc[UR4][R54.64+0x100000], R40, R44 ;", 0x8000),
        ("STG.E.ENL2.256 desc[UR4][R54.64+0x1fffe0], R40, R44 ;", 0xffff),
    ] {
        let insn = parse_sass(sass, 0).unwrap();
        let w = encode_instruction(&insn, &t).unwrap();
        assert_eq!((w >> 40) & 0xffff, win as u128, "window for {sass:?}");
    }
}

#[test]
fn bug070_encode_fail_closed_on_unrepresentable() {
    // Silent-corruption class now fails closed (asm rc!=0 path, BUG-043).
    let t = t103a();
    for (sass, why) in [
        // negative offset on an unsigned window
        ("STG.E.ENL2.256 desc[UR4][R54.64+-0x20], R40, R44 ;", "negative"),
        ("STG.E.EL.ENL2.256.STRONG.GPU desc[UR4][R4.64+-0x80], R8, R12 ;", "negative"),
        // sub-granule offset (window granularity is 0x20)
        ("STG.E.ENL2.256 desc[UR4][R54.64+0x28], R40, R44 ;", "misaligned"),
        // window overflow (max encodable is 0x1fffe0)
        ("STG.E.ENL2.256 desc[UR4][R54.64+0x200000], R40, R44 ;", "overflow"),
    ] {
        let insn = parse_sass(sass, 0).unwrap();
        assert!(encode_instruction(&insn, &t).is_err(),
            "expected fail-closed ({why}) for {sass:?}");
    }
}

#[test]
fn bug070_ldg_signed_window_untouched() {
    // LDG.256's 20-bit shr2 window stays signed (nvdisasm oracle):
    // +-0x20 must still round-trip on the load side.
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let insn = parse_sass(
        "LDG.E.EL.ENL2.256.STRONG.GPU R12, R8, desc[UR4][R2.64+-0x20] ;", 0).unwrap();
    let w = encode_instruction(&insn, &t).unwrap();
    let d = idx.decode(w & !SCHED, 0, &t).unwrap();
    let text = cubit::printer::to_sass(&d);
    assert_eq!(text, "LDG.E.EL.ENL2.256.STRONG.GPU R12, R8, desc[UR4][R2.64+-0x20]");
}

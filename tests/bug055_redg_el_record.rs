//! BUG-055 (sm120 i132 -> F2): .nv.capmerc REDG.EL-desc records — 4B drift
//! (0x28200 -> 0x14200 at KernelA+0xd08/+0x16b8) on era-frozen text + new
//! binary, publish oracle FAIL. Root cause analysis (data, not opinion):
//!
//!   gold rt98_pub facts (nvcc byte-truth, section-exact):
//!    - KernelB REDG.E.ADD.EL [R209.U32+UR20] x20 (imm=0)      -> record d=0
//!    - KernelA REDG.E.{AND,OR}.EL [R*.U32+UR20+0xa2400] x2   -> record d=10
//!    - KernelA REDG.E.ADD.EL [R84/RZ..+UR20+0x400/0x100] x2  -> NO record
//!
//!   The record's d@[17:19) = (imm[23:16]<<6)|2 for the `.EL` desc class:
//!   the immediate's top byte carries the descriptor-table slot, and it is
//!   invariant across text generations (era-glyph `desc[UR10]`, v2-glyph
//!   `desc[UR20]`, nvdisasm-glyph `[R.U32+UR20]` all carry imm 0xa2400 and
//!   must produce the SAME record). BUG-049's "d = word_field>>1" coincided
//!   with imm[23:16] on the AND/OR lanes (both 10) but double-halved era
//!   text to 5 and would emit 10 for KernelB ADD (gold 0). Glyph numbers
//!   mean different things per decoder generation; the immediate does not.
//!
//!   Old-binary (bbf7412) + era text == gold capmerc byte-exact (the era
//!   decoder's imm-top-byte lie fed identity embedding, and the !rsd tails
//!   suppressed exactly the two no-record lanes) — the fix restores that
//!   byte-parity by LAW, not by coincidence, and additionally covers the
//!   nvdisasm-canonical glyph the fixed decoder now emits.
//!
//! nvdisasm 13.3 bit-flip evidence (BUG-049 sweep_redg.txt): desc field is
//! bits [64:72) of the word (flip bit 70 -> UR84, bit 71 -> UR148).

use cubit::mercury::merc_redg_record;

/// rt98_pub.cubin .nv.capmerc.text.KernelA @0xcf8 — REDG.E.AND (guard @P2).
const GOLD_AND: &str = "024d2432100050a00100000082100a0000820200100000000000000000240a00";
/// rt98_pub.cubin .nv.capmerc.text.KernelA @0x16b8 — REDG.E.OR (guard PT).
const GOLD_OR: &str = "024d2432f80060a00100000042060a00008202c0050000000000000000240a00";
/// rt98_pub.cubin .nv.capmerc.text.KernelB @0x2fc — REDG.E.ADD (guard @P4).
const GOLD_ADD_KB: &str = "024d2432200000a00100000042340a0000020040140000000000000000000000";

fn hex(r: &[u8; 32]) -> String {
    r.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn era_glyph_imm_slot_rule_byte_exact() {
    // Era-frozen text (publish pipeline input, md5 9962e535): desc[UR10] is
    // the era decoder lie; the record must still equal nvcc gold.
    let r = merc_redg_record(
        "REDG.E.AND.EL.STRONG.GPU PT, desc[UR10][R66.64+0xa2400], R64 ;",
        0x10,
    )
    .expect("era AND must carry a record");
    assert_eq!(hex(&r), GOLD_AND, "era-glyph record drifted (BUG-055)");
    // v2 truth-in-legacy-glyph text (tb_i82p2 render): same bytes.
    let r = merc_redg_record(
        "REDG.E.AND.EL.STRONG.GPU PT, desc[UR20][R66.64+0xa2400], R64 ;",
        0x10,
    )
    .expect("v2 AND must carry a record");
    assert_eq!(hex(&r), GOLD_AND, "v2-glyph record drifted");
    let r = merc_redg_record(
        "REDG.E.OR.EL.STRONG.GPU PT, desc[UR20][R25.64+0xa2400], R23 ;",
        0xf8,
    )
    .expect("OR record");
    assert_eq!(hex(&r), GOLD_OR, "OR record drifted");
    // KernelB ADD era/v2 glyph: imm 0 -> slot 0 (NOT word_field/2 = 10).
    let r = merc_redg_record(
        "REDG.E.ADD.EL.STRONG.GPU PT, desc[UR0][R209.64], R81 ;",
        0x20,
    )
    .expect("KB ADD must carry a record");
    assert_eq!(hex(&r), GOLD_ADD_KB, "KB ADD record drifted");
}

#[test]
fn nvdisasm_glyph_supported() {
    // The fixed decoder's canonical render: [Rn.U32+URm(+0ximm)].
    let r = merc_redg_record(
        "REDG.E.AND.EL.STRONG.GPU [R66.U32+UR20+0xa2400], R64 ;",
        0x10,
    )
    .expect("nvdisasm glyph AND must carry a record");
    assert_eq!(hex(&r), GOLD_AND, "nvdisasm-glyph AND drifted");
    let r = merc_redg_record(
        "@P2 REDG.E.AND.EL.STRONG.GPU [R66.U32+UR20+0xa2400], R64 ;",
        0x10,
    )
    .expect("guarded nvdisasm glyph AND");
    assert_eq!(hex(&r), GOLD_AND);
    let r = merc_redg_record(
        "REDG.E.OR.EL.STRONG.GPU [R25.U32+UR20+0xa2400], R23 ;",
        0xf8,
    )
    .expect("OR nvdisasm glyph");
    assert_eq!(hex(&r), GOLD_OR);
    let r = merc_redg_record(
        "@P4 REDG.E.ADD.EL.STRONG.GPU [R209.U32+UR20], R81 ;",
        0x20,
    )
    .expect("KB ADD nvdisasm glyph");
    assert_eq!(hex(&r), GOLD_ADD_KB);
}

#[test]
fn recordless_lanes_stay_recordless() {
    // Gold KernelA ADD lanes with plain-range offsets carry NO record
    // (imm[23:16]==0 && imm!=0). Era text reaches the same absence through
    // the !rsd data-tail parse failure — both suppressions pinned.
    assert!(merc_redg_record(
        "REDG.E.ADD.EL.STRONG.GPU PT, desc[UR0][R84.64], R23 !rsd[50:1] ;",
        0x10,
    )
    .is_none());
    assert!(merc_redg_record(
        "REDG.E.ADD.EL.STRONG.GPU [R84.U32+UR20+0x400], R23 ;",
        0x10,
    )
    .is_none());
    assert!(merc_redg_record(
        "REDG.E.ADD.EL.STRONG.GPU [RZ.U32+UR20+0x100], R23 ;",
        0x10,
    )
    .is_none());
}

#[test]
fn non_el_desc_identity_untouched() {
    // mk48 law (22342/22342 byte-exact sm_100 corpus): non-EL desc[URn]
    // embeds n directly, offset presence does not suppress the record.
    let r = merc_redg_record(
        "REDG.E.ADD.STRONG.GPU desc[UR7][R12.64+0x4], R5 ;",
        0xf8,
    )
    .expect("non-EL desc record");
    let d = (u16::from_le_bytes([r[17], r[18]]) >> 6) & 0x3ff;
    assert_eq!(d, 7, "non-EL identity broken");
    assert_eq!(&r[28..32], &4i32.to_le_bytes());
    // non-EL negative-offset form (cublas.72 era pattern) keeps identity too.
    let r = merc_redg_record(
        "REDG.E.ADD.STRONG.GPU desc[UR12][R10.64+-0x8], R28 ;",
        0xf8,
    )
    .expect("non-EL neg-offset record");
    let d = (u16::from_le_bytes([r[17], r[18]]) >> 6) & 0x3ff;
    assert_eq!(d, 12, "non-EL negative-offset identity broken");
    assert_eq!(&r[28..32], &(-8i32).to_le_bytes());
}

#[test]
fn suppressed_probe_marks_recordless_lanes() {
    // Tail-accounting contract: suppressed EL plain-range lanes must be
    // excluded from placeholder backfill (elf_builder name-count branch).
    use cubit::mercury::merc_redg2_suppressed;
    assert!(merc_redg2_suppressed(
        "REDG.E.ADD.EL.STRONG.GPU [R84.U32+UR20+0x400], R23 ;"
    ));
    assert!(merc_redg2_suppressed(
        "@P0 REDG.E.ADD.EL.STRONG.GPU [RZ.U32+UR20+0x100], R23 ;"
    ));
    assert!(merc_redg2_suppressed(
        "REDG.E.ADD.EL.STRONG.GPU PT, desc[UR0][R84.64+0x2400], R23 ;"
    ));
    // Recorded lanes are not suppressed.
    assert!(!merc_redg2_suppressed(
        "REDG.E.AND.EL.STRONG.GPU [R66.U32+UR20+0xa2400], R64 ;"
    ));
    assert!(!merc_redg2_suppressed(
        "REDG.E.ADD.EL.STRONG.GPU [R209.U32+UR20], R81 ;"
    ));
    // Non-REDG / non-EL / non-desc never match.
    assert!(!merc_redg2_suppressed("ATOMG.E.ADD.EL.STRONG.GPU PT, R214, desc[UR38][R82.64], R77 ;"));
    assert!(!merc_redg2_suppressed("REDG.E.ADD.STRONG.GPU desc[UR7][R12.64+0x4], R5 ;"));
    assert!(!merc_redg2_suppressed("REDG.E.ADD.STRONG.GPU [R11], R5 ;"));
    assert!(!merc_redg2_suppressed("IMAD.MOV.U32 R1, RZ, RZ, RZ ;"));
}

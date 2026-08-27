//! BUG-198 — UTCATOMSWS_UP_UR_UR dest-UP window -> vendor law [81:84) w3
//! (owner: loop5/blind iter94). Data-only patch198.py (3 moves x 3 tables:
//! sm103a/sm120/sm100a): harvested rows scraped the UP-dest token from
//! coincidence windows — (6,4) == opcode nibble (always 7 in corpus == UPT),
//! (19,4) sits INSIDE the tok2 ureg window (16,8) — indistinguishable on the
//! production corpus (every 2CTA anchor is UP0, every plain FIND_AND_SET
//! anchor is UPT), but:
//!   DECODE: 2CTA words with dest UPk!=0 were a HOLE (and_base locked 0,
//!     no field covered [81:84)); ureg fabrykacja — (19,4) extracted a
//!     phantom UP-dest from the *source* UR (UR12 anchor printed UP1);
//!     mg 'ALIGN,FIND_AND_SET' carried a 4-bit window admitting inert bit84
//!     (printed junk "UP8").
//!   ENCODE (silent wrong-code): authored UPk!=UP7 on mg FIND_AND_SET scraped
//!     k into OPCODE bits (6,4) -> nvdisasm-invalid word; authored UPk!=UP0 on
//!     mg 2CTA,ALIGN,FIND_AND_SET scraped k into the tok2 ureg bits.
//! Vendor law (arb198.json: nvdisasm 13.3.73 bit-walk on corpus donors
//! 77_blackwell_mla_2sm_fp8 / 77_blackwell_fmha_fp8 / libcublasLt sm_100a):
//! dest-UP = bits [81:84), values 0..7 = UP0..UP6,UPT (A1/A2/A5/B1/B4);
//! bit84 inert (A3/B3, no glyph change) -> stays out of fields (fail-closed).
//! Guard [15:12] is generic (decoder.rs match-excluded); the ALIGN mgs carry
//! no guard field and guarded forms roundtrip byte-exact without one (ctl
//! proven) — no guard columns added.
//! Battery A (atomdb 30,406, incl. 33 UTCATOMSWS anchors) and corpus A/B
//! (sm120 392 / sm103 2014) are byte-exact.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn tab(p: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(p)).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

const TABS: [&str; 3] = ["tables/sm103a.json", "tables/sm120.json", "tables/sm100a.json"];

/// t198_1: plain FIND_AND_SET donor sweep on the vendor-law window: the
/// dest-UP token must track bits [81:84) identity (UP0..UP6,UPT) and
/// re-encode byte-exact. Pre-fix: HOLE or .ALIGN-absorb for k!=7.
#[test]
fn t198_1_plain_fas_dest_up_law() {
    let lo: u64 = 0x00000005000485e3; // @!UP0 UTCATOMSWS.FIND_AND_SET UPT, UR4, UR5 (cublas sm_100a)
    let hi: u64 = 0x000e6400080e0000;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for k in 0u64..8 {
            let w = (((hi & !((0x7u64 << 17) | 0)) | (k << 17)) as u128) << 64 | (lo as u128);
            let want_p = if k == 7 { "UPT".to_string() } else { format!("UP{k}") };
            let text = dec(&t, &idx, w);
            assert_eq!(
                text,
                format!("@!UP0 UTCATOMSWS.FIND_AND_SET {want_p}, UR4, UR5"),
                "{p}: plain FAS dest-UP law k={k}"
            );
            assert_eq!(enc(&t, &text), w & !SCHED, "{p}: roundtrip byte-exact k={k}");
        }
    }
}

/// t198_2: 2CTA,ALIGN donor sweep: same vendor law [81:84). Pre-fix the dest
/// bits were ab-locked to 0 (UPk!=0 = decode HOLE; encode scraped k into the
/// tok2 ureg window).
#[test]
fn t198_2_2cta_dest_up_law() {
    let lo: u64 = 0x00000004000475e3; // UTCATOMSWS.2CTA.FIND_AND_SET.ALIGN UP0, UR4, UR4 (mla_2sm)
    let hi: u64 = 0x000e640008200800;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for k in 0u64..8 {
            let w = (((hi & !(0x7u64 << 17)) | (k << 17)) as u128) << 64 | (lo as u128);
            let want_p = if k == 7 { "UPT".to_string() } else { format!("UP{k}") };
            let text = dec(&t, &idx, w);
            assert_eq!(
                text,
                format!("UTCATOMSWS.2CTA.FIND_AND_SET.ALIGN {want_p}, UR4, UR4"),
                "{p}: 2CTA dest-UP law k={k}"
            );
            assert_eq!(enc(&t, &text), w & !SCHED, "{p}: roundtrip byte-exact k={k}");
        }
    }
}

/// t198_3: no fabrykacja — the dest token must NOT track the tok2 ureg bits:
/// a 2CTA word with UR12 source and dest window 0 prints UP0 (pre-fix the
/// overlap window (19,4) printed phantom UP1 from the UR bits).
#[test]
fn t198_3_no_ureg_fabrykacja() {
    let lo: u64 = 0x00000004000c75e3; // donor with (16,8)=12 -> UR12
    let hi: u64 = 0x000e640008200800;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        let w = (hi as u128) << 64 | (lo as u128);
        let text = dec(&t, &idx, w);
        assert_eq!(text, "UTCATOMSWS.2CTA.FIND_AND_SET.ALIGN UP0, UR12, UR4", "{p}");
        assert_eq!(enc(&t, &text), w & !SCHED, "{p}: roundtrip");
    }
}

/// t198_4: ALIGN (non-2CTA) retention — the mg that was already corpus-correct
/// must stay vendor-exact (posture: passes pre- AND post-fix).
#[test]
fn t198_4_align_retention() {
    let lo: u64 = 0x00000004000475e3;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for (k, hi) in [(0u64, 0x000e640008000800u64), (1, 0x000e640008020800), (2, 0x000e640008040800)] {
            let w = (hi as u128) << 64 | (lo as u128);
            let want_p = if k == 7 { "UPT".to_string() } else { format!("UP{k}") };
            let text = dec(&t, &idx, w);
            assert_eq!(text, format!("UTCATOMSWS.FIND_AND_SET.ALIGN {want_p}, UR4, UR4"), "{p} k={k}");
            assert_eq!(enc(&t, &text), w & !SCHED, "{p} k={k}: roundtrip");
        }
    }
}

/// t198_5: inert bit84 is fail-closed — a bit84=1 variant of any donor shape
/// must be a decode HOLE (pre-fix mg ALIGN admitted it and printed junk UP8).
#[test]
fn t198_5_bit84_fail_closed() {
    let lo: u64 = 0x00000004000475e3;
    for p in TABS {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for hi in [0x000e640008000800u64, 0x000e640008200800] {
            let w = (((hi | (1u64 << 20)) as u128) << 64) | (lo as u128); // bit84 = hi bit 20
            assert!(idx.decode(w, 0, &t).is_err(), "{p}: bit84=1 must stay a hole (hi {hi:#x})");
        }
    }
}

/// t198_6: ENCODE-side law — authored UP2 on the plain FIND_AND_SET mg must
/// land in [81:84) leaving the opcode nibble (6,4) at its canonical 7. Pre-fix
/// the authored k scraped into opcode bits (6,4) -> nvdisasm-invalid word.
#[test]
fn t198_6_encode_no_opcode_scrape() {
    for p in TABS {
        let t = tab(p);
        let w = enc(&t, "UTCATOMSWS.FIND_AND_SET UP2, UR4, UR5");
        assert_eq!(w & 0x3C0, 7 << 6, "{p}: opcode nibble (6,4) must stay 7, got {:x}", (w >> 6) & 0xf);
        assert_eq!((w >> 81) & 7, 2, "{p}: dest-UP must land at [81:84)");
        let w2 = enc(&t, "UTCATOMSWS.2CTA.FIND_AND_SET.ALIGN UP2, UR4, UR4");
        assert_eq!((w2 >> 16) & 0xff, 4, "{p}: 2CTA encode must not touch tok2 ureg (16,8)");
        assert_eq!((w2 >> 81) & 7, 2, "{p}: 2CTA dest-UP at [81:84)");
    }
}

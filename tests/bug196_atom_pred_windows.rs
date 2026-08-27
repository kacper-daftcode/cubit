//! BUG-196 — ATOM-family dest-pred windows moved to the vendor law
//! (owner: loop5/blind iter93). Data-only patch196.py (60 rows across
//! sm103a+sm120): the harvested donor rows scraped the P-dest token
//! from coincidence windows — (77,4) = scope nibble, (12,4) = guard,
//! (28,4) = base-reg HI nibble, (82,4) = pred+1, (7,4) = opcode bits —
//! observationally identical on PT-anchored corpora, but:
//!   DECODE: fabricated dest-P (e.g. `@P2 ATOMG.E.EXCH... P2,` for a vendor
//!     `PT` word), phantom P from base-reg nibble, scope garbage absorbed
//!     through the excluded window.
//!   ENCODE (silent wrong-code): authored dest-P != PT scraped INTO
//!     scope/guard/opcode/base-reg bits (P4 -> scope SM.PRIVATE word,
//!     P3 MAX.S64 -> base reg R10 -> R58).
//! Vendor law (arb196b.json, nvdisasm 13.3.73 bit-walk over 6 donor words
//! + paired-anchor census): dest pred = bits [81:84) identity P0..P6,PT;
//! bit84 = .EF-form flag (zero 32M-corpus exposure -> stays baked, fail-closed).
//!
//! Ride-after base: merge of BUG-195 (6d653be) scope/width rows. Battery A
//! (atomdb 30,406) and corpus A/B (sm120 392 / sm103 2014) are byte-exact.

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

/// dest-pred Pk (plain form, bit84=1) on the ATOMG.E.MAX.S64.STRONG.GPU
/// donor word: [81:84) = k must render Pk/PT and re-encode byte-exact.
/// Pre-fix the row scraped k from the scope nibble (77,4): Pk-dest words
/// were decode HOLES; encode scraped k into the scope field.
#[test]
fn t196_1_dest_pred_coverage_atomg_max_s64() {
    for p in ["tables/sm103a.json"] {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        let lo: u64 = 0x80000006020279a8;
        let hi_d: u64 = 0x091ef704; // donor data[64:96): PT, plain (b84=1)
        for k in 0u64..8 {
            let hi = ((hi_d & !(0x7 << 17)) | (k << 17)) as u128;
            let w = (hi << 64) | (lo as u128);
            let want_p = if k == 7 { "PT".to_string() } else { format!("P{k}") };
            let text = dec(&t, &idx, w);
            assert_eq!(
                text,
                format!("ATOMG.E.MAX.S64.STRONG.GPU {want_p}, R2, desc[UR4][R2.64], R6"),
                "{p}: dest-pred law k={k}"
            );
            assert_eq!(enc(&t, &text), w, "{p}: roundtrip byte-exact k={k}");
        }
    }
}

/// guard window [12:16) must NOT leak into the dest-P token: guarded
/// EXCH/INC words render dest = PT (decode-only; encode of guarded non-EL
/// atomics is fail-closed by the BUG-080 silicon policy).
#[test]
fn t196_2_guard_does_not_fabricate_dest() {
    for p in ["tables/sm103a.json", "tables/sm120.json"] {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for (want, lo, hi) in [
            ("@P0 ATOMG.E.EXCH.STRONG.GPU PT, RZ, desc[UR8][R10.64], R3", 0x800000030aff09a8u64, 0x0c1ef108u64),
            ("@P2 ATOMG.E.EXCH.STRONG.GPU PT, RZ, desc[UR8][R10.64], R3", 0x800000030aff29a8u64, 0x0c1ef108u64),
            ("@P6 ATOMG.E.EXCH.STRONG.GPU PT, RZ, desc[UR8][R10.64], R3", 0x800000030aff69a8u64, 0x0c1ef108u64),
            ("@P3 ATOMG.E.INC.STRONG.GPU PT, R2, desc[UR14][R2.64], R5", 0x80000005020239a8u64, 0x099ef10eu64),
        ] {
            let w = (((hi as u128)) << 64) | ((lo as u128));
            assert_eq!(&dec(&t, &idx, w), want, "{p}: guard/dest separation");
        }
        // encode must stay fail-closed on sm103a (BUG-080 silicon policy;
        // sm120 encodes guarded atomics fine) even though decode is exact
        if p.ends_with("sm103a.json") {
            let insn = parse_sass("@P2 ATOMG.E.EXCH.STRONG.GPU PT, RZ, desc[UR8][R10.64], R3", 0).unwrap();
            assert!(encode_instruction(&insn, &t).is_err(), "{p}: guarded non-EL atomic encode must fail");
        }
    }
}

/// base-reg HI nibble [28:32) must not demangle into dest-P: R>=16 bases
/// keep dest P0 and the true base (was: phantom P1/PT + R<16-only rows).
#[test]
fn t196_3_basereg_hi_not_pred() {
    for p in ["tables/sm103a.json"] {
        let t = tab(p);
        let idx = DecodeIndex::build(&t);
        for (want, lo) in [
            ("ATOM.E.MAX.S64.STRONG.GPU P0, RZ, desc[UR4][R26.64+0x8], R4", 0x800008041aff798au64),
            ("ATOM.E.MAX.S64.STRONG.GPU P0, RZ, desc[UR4][R122.64+0x8], R4", 0x800008047aff798au64),
        ] {
            let w = (0x0910f704u128 << 64) | ((lo as u128));
            assert_eq!(&dec(&t, &idx, w), want, "{p}: base-reg not demangled as pred");
        }
    }
}

/// authored dest-Pk encodes to the vendor-law position ([81:84)) with scope
/// / opcode / base-reg bits untouched (pre-fix: silent clobber — encode of
/// `ATOMG.E.ADD.STRONG.GPU P4` emitted a scope=SM.PRIVATE word).
#[test]
fn t196_4_authored_dest_pred_encodes_vendor_law() {
    let t = tab("tables/sm103a.json");
    let idx = DecodeIndex::build(&t);
    for (text, lo, hi_d) in [
        ("ATOMG.E.ADD.STRONG.GPU P4, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x0818f104u64),
        ("ATOMG.E.INC.STRONG.GPU P3, R2, desc[UR14][R2.64], R5", 0x80000005020279a8u64, 0x0996f10eu64),
        ("ATOM.E.MAX.S64.STRONG.GPU P3, RZ, desc[UR4][R10.64+0x8], R4", 0x800008040aff798au64, 0x0916f704u64),
        ("ATOMG.E.FTZ.ADD.F32.RN.STRONG.GPU P2, R3, desc[UR4][R2.64], R7", 0x80000007020379a3u64, 0x0c14f304u64),
        ("ATOMG.E.OR.STRONG.GPU P6, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x0b1cf104u64),
        ("ATOMG.E.ADD.F64.RN.STRONG.GPU P1, R2, [R6+0x8], R4", 0x00000804060273a3u64, 0x0012ff00u64),
        ("ATOMG.E.MAX.S32.STRONG.GPU P5, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x091af304u64),
        ("ATOMG.E.CAS.STRONG.GPU P3, R5, [R4], R6, R7", 0x00000006040573a9u64, 0x0016e107u64),
    ] {
        let w = (((hi_d as u128)) << 64) | ((lo as u128));
        assert_eq!(enc(&t, text), w, "authored dest-P must land at [81:84): {text}");
        assert_eq!(&dec(&t, &idx, w), text, "roundtrip: {text}");
    }
}

/// PT canonical texts keep byte-exact encodings (chain guard): the row's
/// canonical word of each moved window must equal the pre-fix encoding.
#[test]
fn t196_5_pt_canonical_unchanged() {
    let t = tab("tables/sm103a.json");
    for (text, lo, hi_d) in [
        ("ATOMG.E.ADD.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x081ef104u64),
        ("ATOMG.E.INC.STRONG.GPU PT, R2, desc[UR14][R2.64], R5", 0x80000005020279a8u64, 0x099ef10eu64),
        ("ATOMG.E.EXCH.STRONG.GPU PT, RZ, desc[UR8][R10.64], R3", 0x800000030aff79a8u64, 0x0c1ef108u64),
    ] {
        assert_eq!(enc(&t, text), (((hi_d as u128)) << 64) | ((lo as u128)), "{text}");
    }
}

/// sm120 lanes: the patched sm120 rows (dotted ADD key, CAS, F64, CAST)
/// decode+encode vendor words byte-exact post-move.
#[test]
fn t196_6_sm120_lanes() {
    let t = tab("tables/sm120.json");
    let idx = DecodeIndex::build(&t);
    for (text, lo, hi_d) in [
        ("ATOMG.E.ADD.STRONG.GPU PT, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x081ef104u64),
        ("ATOMG.E.ADD.STRONG.GPU P4, R3, desc[UR4][R2.64], R7", 0x80000007020379a8u64, 0x0818f104u64),
        ("ATOMG.E.CAS.STRONG.SYS PT, R3, [R8], R2, R3", 0x00000002080373a9u64, 0x001f4103u64),
    ] {
        let w = (((hi_d as u128)) << 64) | ((lo as u128));
        assert_eq!(&dec(&t, &idx, w), text, "sm120 decode: {text}");
        assert_eq!(enc(&t, text), w, "sm120 encode: {text}");
    }
}

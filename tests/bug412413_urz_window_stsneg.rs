//! BUG-412 + BUG-413(i) pins (F2-iter230, loop5/blind front2 base-prompt,
//! 2026-09-08): shared-bracket UR window URZ law + sm121a STS_ARURI_R ''
//! donor closure (canonical 67a0c22 -> e4f0915; ENGINE printer.rs arm
//! format_sts_lds_addr; patch412413.py replayable+idempotent).
//!
//! BUG-412 vendor law (arb412 96 probes on the LDS.S8/LDSM 8-bit and STS
//! 9-bit bracket windows + arb412b 40 RZ-base probes + arb399a 36 legacy
//! cells, nvdisasm 13.3.73 raw -b per-word, x4 models SM100a/SM103a/
//! SM120/SM121a unanimous on EVERY probe, DIVERGENT=0): the printed
//! numeral is the LOW 8 BITS of the window; all-ones 0xff = URZ sink;
//! numerals 0..254 literal (UR63/UR64/UR127/UR128/UR254 anchors); STS
//! 9-bit window b72 PRINT-INERT (0x100+v prints "UR{v}", 0x17e->UR126,
//! 0x1ff->URZ, 0x0ff->URZ). Defect pre: engine printed UR255 (8-bit) /
//! UR511 (9-bit) for the sink code and "UR256"+" for b72-set values
//! (412-kand posture, t399_4; 225-cell measured delta of which 189 text
//! fixes + 36 text-stable claim migrations sm121a-only).
//!
//! BUG-413(i): sm121a STS_ARURI_R '' was a BUG-152-era row (no sub_imm1,
//! sub_ur1 era-clipped 8b, 0x7988-era shape+loose care): negative-offset
//! STS UR mints refused (t399_2/3 EXPECTED_REFUSE) and sink/b72-set UR
//! cells misrouted to STS_AURI_R/STS_ARUR_R dropping the R10 base
//! ("[URZ+-0x800000]" vs vendor "[R10+URZ+-0x800000]"). Fix = '' row
//! cloned from the sm100a/103a/120 donor (identical x3, asserted).
//!
//! 413(ii)/(iii) encode-side RZ-elided mints (LDSM AURI row absent;
//! LDS.S8 BUG-132 silent-mod cordon) CLOSED z atrybucja BUG-413(ii)/(iii)
//! (F2-iter231, canonical e4f0915 -> 487757b, pins t413ii_1..7).
//!
//! Witness data: tests/bug412413_data.inc (machine-built by
//! work/bug412413/gen412pins.py; no hand hex; self-checks abort).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug412413_data.inc");

const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<(String, String)> {
    idx.decode(w, 0, t)
        .map(|d| {
            (
                to_sass(&d).trim().trim_end_matches(';').to_string(),
                format!("{}|{}", d.key, d.mod_group),
            )
        })
        .ok()
}
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let ins = parse_sass(text, 0).ok()?;
    encode_instruction(&ins, t).ok()
}

/// t412_1: LDS.S8/LDSM 8-bit bracket window: every measured word renders
/// vendor-exact on all four legs (numerals literal, 0xff = URZ).
#[test]
fn t412_1_lds_ldsm_window_vendor_exact() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let mut n = 0u32;
        for (w, tag, vendor) in LAW412_LDS {
            if leg == "sm120" && sm120_fails_closed(w) {
                assert!(dec(&t, &idx, w).is_none(), "[{leg}] {tag}: a measured row tolerates the text-inert bit 72");
                n += 1;
                continue;
            }
            let (got, _) = dec(&t, &idx, w).unwrap_or_else(|| panic!("[{leg}] {tag} hole"));
            assert_eq!(got, vendor, "[{leg}] {tag}");
            n += 1;
        }
        assert_eq!(n, 54);
    }
}

/// t412_2: STS 9-bit window incl the b72 print-inert collapse
/// (0x100+v -> "UR{v}", 0x0ff/0x1ff -> "URZ") vendor-exact x4.
/// 2026-11-08 (T-19, rows-memory-2026-11-07): the measured `STS_ARURI_R` rows read the UR base in 8 bits -- bit 72 is
/// text-inert for nvdisasm 13.1 on every width (tools/probes/re_sm120_rows.py --family memory; the 2026-09 harvest kept a
/// 9-bit window). On sm120 the grid's bit-72 carriers are holes now (the measured-row convention, 0 census witnesses); the
/// three other legs keep the harvest tolerance.
fn sm120_fails_closed(w: u128) -> bool {
    w & (1u128 << 72) != 0
}
include!("t25_fail_closed.inc");
/// T-25 (2026-11-09): the STS rows are measured on sm100a / sm103a as well (rows-memory-2026-11-07 on -b SM100 / SM103) --
/// a bit-72 carrier is a hole on every measured leg; the clean word's reading (tests/t25_fail_closed.inc) keeps the pin.
fn dec_fc(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<(String, String)> {
    dec(t, idx, w).or_else(|| {
        t25_closed(t, w).map(|s| (s.trim().trim_end_matches(';').to_string(), String::from("(fail-closed: the clean word's row)")))
    })
}

#[test]
fn t412_2_sts_9bit_window_b72_inert() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let mut n = 0u32;
        for (w, tag, vendor) in LAW412_STS {
            if leg == "sm120" && sm120_fails_closed(w) {
                assert!(dec(&t, &idx, w).is_none(), "[{leg}] {tag}: a measured row tolerates the text-inert bit 72");
                n += 1;
                continue;
            }
            let (got, _) = dec_fc(&t, &idx, w).unwrap_or_else(|| panic!("[{leg}] {tag} hole"));
            assert_eq!(got, vendor, "[{leg}] {tag}");
            n += 1;
        }
        assert_eq!(n, 42);
    }
}

/// t412_3: RZ-base (AURI-shaped, base elided in print) words vendor-exact
/// x4 on all three carriers.
#[test]
fn t412_3_rz_elided_vendor_exact() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let mut n = 0u32;
        for (w, tag, vendor) in LAW412_RZ {
            if leg == "sm120" && sm120_fails_closed(w) {
                assert!(dec(&t, &idx, w).is_none(), "[{leg}] {tag}: a measured row tolerates the text-inert bit 72");
                n += 1;
                continue;
            }
            let (got, _) = dec(&t, &idx, w).unwrap_or_else(|| panic!("[{leg}] {tag} hole"));
            assert_eq!(got, vendor, "[{leg}] {tag}");
            n += 1;
        }
        assert_eq!(n, 40);
    }
}

/// t412_4: legacy negative-glyph cell inventory (arb399a subset) stays
/// vendor-exact x4 (the 399-era contract on these carriers is untouched).
#[test]
fn t412_4_arb399a_cells_vendor_exact() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let mut n = 0u32;
        for (w, tag, vendor) in LAW412_399A {
            if leg == "sm120" && sm120_fails_closed(w) {
                assert!(dec(&t, &idx, w).is_none(), "[{leg}] {tag}: a measured row tolerates the text-inert bit 72");
                n += 1;
                continue;
            }
            let (got, _) = dec_fc(&t, &idx, w).unwrap_or_else(|| panic!("[{leg}] {tag} hole"));
            assert_eq!(got, vendor, "[{leg}] {tag}");
            n += 1;
        }
        assert_eq!(n, 36);
    }
}

/// t412_5: pre-fix class renders (UR255/UR511 sink literals, R10-drop
/// misroutes) must not reappear on any leg.
#[test]
fn t412_5_prefix_renders_must_not_reappear() {
    let words: std::collections::HashMap<&str, u128> = LAW412_LDS
        .iter()
        .chain(LAW412_STS.iter())
        .chain(LAW412_RZ.iter())
        .chain(LAW412_399A.iter())
        .map(|(w, tag, _)| (*tag, *w))
        .collect();
    for (tag, leg, pre_text) in PRE412 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let w = words[tag];
        // T-19 (2026-11-08): a bit-72 carrier is a hole on sm120 (see `sm120_fails_closed`) -- no render to compare
        if leg == "sm120" && sm120_fails_closed(w) {
            assert!(dec(&t, &idx, w).is_none(), "[{leg}] {tag}: a measured row tolerates the text-inert bit 72");
            continue;
        }
        let (got, _) = dec_fc(&t, &idx, w).unwrap_or_else(|| panic!("[{leg}] {tag} hole"));
        assert_ne!(got, pre_text, "[{leg}] {tag} pre-fix render reappeared");
    }
}

/// t412_6: URZ/UR255 alias doctrine on the bracket window: both spellings
/// mint the same word, parsing to the URZ sink (0xff); the canonical
/// reprint is the vendor URZ glyph. Doctrine mirrors the 160 desc-window
/// sink law; "UR255" as text input is a legacy alias, never vendor-printed
/// in these brackets.
#[test]
fn t412_6_urz_alias_and_reprint() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let (w_a, w_b) = (
            enc(&t, "LDS.S8 R93, [R10+URZ+-0x1] ;").unwrap(),
            enc(&t, "LDS.S8 R93, [R10+UR255+-0x1] ;").unwrap(),
        );
        assert_eq!(w_a, w_b, "[{leg}] UR255 alias must mint the URZ word");
        let (reprint, _) = dec(&t, &idx, w_a).unwrap();
        assert_eq!(reprint, "LDS.S8 R93, [R10+URZ+-0x1]", "[{leg}] reprint");
    }
}

/// t413_1: sm121a encode close-out -- every MINT413 text mints on every
/// leg to the machine-pinned word (x4-identical in the generator),
/// reprints to the vendor glyph, claims the ARURI-family rows. The 5
/// former EXPECTED_REFUSE texts are inside MINT413 (STS negatives).
#[test]
fn t413_1_encode_closeout_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (text, word_want, reprint_want) in MINT413 {
            let w = enc(&t, text).unwrap_or_else(|| panic!("[{leg}] mint refuses: {text}"));
            assert_eq!(w, word_want, "[{leg}] mint word drift: {text}");
            let (reprint, km) = dec(&t, &idx, w).unwrap();
            assert_eq!(reprint, reprint_want, "[{leg}] reprint: {text}");
            assert!(
                km.starts_with("STS_ARURI_R|")
                    || km.starts_with("LDS_R_ARURI|")
                    || km.starts_with("LDSM_R_ARURI|"),
                "[{leg}] claim {km} for {text}"
            );
        }
    }
}

/// t413_2: sm121a STS carrier claim map -- all STS carrier cells
/// (incl the 36 text-stable migration cells, formerly STS_ARUR_R/
/// STS_AURI_R by tie-break) claim STS_ARURI_R|'' post-graft.
#[test]
fn t413_2_sm121a_claim_map() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    let words: std::collections::HashMap<&str, u128> = LAW412_STS
        .iter()
        .chain(LAW412_RZ.iter())
        .chain(LAW412_399A.iter())
        .map(|(w, tag, _)| (*tag, *w))
        .collect();
    let mut n = 0u32;
    for (tag, km_want) in CLAIM121A {
        let (_, km) = dec(&t, &idx, words[tag]).unwrap();
        assert_eq!(km, km_want, "{tag} claim drift");
        n += 1;
    }
    assert_eq!(n, 70);
}

/// t413_3: donor-row structural contract -- sm121a STS_ARURI_R ''
/// equals the sibling shape (meta-stripped) and the graft stands at the
/// pinned canonical revision.
#[test]
fn t413_3_donor_contract_and_source_pin() {
    // Current byte-pinned cut; historical fixture provenance remains unchanged.
    const CURRENT_VENDORED_CANON: &str = "05068b63fbed413edb967566c6c81a6764e3c23f" /* 2026-11-06 T-11 (was c258f8a, T-10) */ /* 2026-11-06 T-10 (was b75cc20, T-9) */;
    assert_eq!(CANON412413, "9c0e4cec355119065444f59d0710de372b9d0577", "historical fixture revision drift");

    let t121 = tab("sm121a");
    let e121 = t121.get("STS_ARURI_R", "").unwrap();
    let mut want_base = 0u128;
    let mut want_vm = 0u128;
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        let e = t.get("STS_ARURI_R", "").unwrap();
        if want_base == 0 {
            want_base = e.and_base;
            want_vm = e.variable_mask;
        }
        // T-19 (2026-11-08): the sm120 donor is measured (tools/probes/re_sm120_rows.py --family memory) -- its mask is
        // its fields (the 8-bit UR base, bit 72 text-inert), a subset of the harvest mask the other legs keep
        // T-25 (2026-11-09): sm100a / sm103a measured as well (rows-memory-2026-11-07 on -b SM100 / SM103)
        if e.row_probe {
            // (the harvest mask was narrower than its own fields in places -- bits 40 / 41, 70 / 71, 78 / 79 of the offset,
            // the UR base and the address scale -- so the two masks are compared only through the constant bits)
            let either = want_vm | e.variable_mask;
            assert_eq!(e.and_base & !either, want_base & !either, "{leg} donor base drift (outside both masks)");
            let fields: u128 = e.fields.iter().fold(0, |m, f| m | (((1u128 << f.bits) - 1) << f.shift));
            assert_eq!(e.variable_mask, fields, "{leg} measured donor: the mask is its fields");
            continue;
        }
        assert_eq!(e.and_base, want_base, "{leg} donor base drift");
        assert_eq!(e.variable_mask, want_vm, "{leg} donor vm drift");
    }
    // T-25 (2026-11-09): the three sibling legs are measured, sm121a keeps the bug412413 harvest row (the 9-bit UR field
    // over bit 72) -- the shapes are compared through the constant bits outside both masks, as above
    let either = want_vm | e121.variable_mask;
    assert_eq!(
        e121.and_base & !either, want_base & !either,
        "sm121a is not the donor shape (base, outside both masks)"
    );
    if e121.row_probe {
        let fields: u128 = e121.fields.iter().fold(0, |m, f| m | (((1u128 << f.bits) - 1) << f.shift));
        assert_eq!(e121.variable_mask, fields, "sm121a measured donor: the mask is its fields");
    } else {
        assert_eq!(
            e121.variable_mask, 0x3fe3e008001313ffffffcffff00f000u128,
            "sm121a is not the donor shape (vm; the bug412413 harvest mask)"
        );
    }
    // FLIP F2-iter238 (BUG-425 graft 52cb73c, z atrybucja): the donor row
    // gains the measured addr_scale field {2b@78,tok1} (arb425 law x4:
    // b78=.X4 b79=.X8 both=.X16 uniform on the ARURI frame); and_base/vm
    // equality with the sibling legs stands (asserts above).
    assert_eq!(
        e121.fields.len(),
        6,
        "donor shape field count (5+addr_scale)"
    );
    // SOURCE pin: canonical revision carries the 413(i) graft
    let src = std::fs::read_to_string("tables/SOURCE.json").unwrap();
    assert!(
        src.contains(CURRENT_VENDORED_CANON),
        "SOURCE.json must pin canonical {CANON412413} (BUG-412+413(i) graft F2-iter230; rides e4f0915"
    );
}

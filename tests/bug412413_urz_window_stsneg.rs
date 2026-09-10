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
            let (got, _) = dec(&t, &idx, w).unwrap_or_else(|| panic!("[{leg}] {tag} hole"));
            assert_eq!(got, vendor, "[{leg}] {tag}");
            n += 1;
        }
        assert_eq!(n, 54);
    }
}

/// t412_2: STS 9-bit window incl the b72 print-inert collapse
/// (0x100+v -> "UR{v}", 0x0ff/0x1ff -> "URZ") vendor-exact x4.
#[test]
fn t412_2_sts_9bit_window_b72_inert() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let mut n = 0u32;
        for (w, tag, vendor) in LAW412_STS {
            let (got, _) = dec(&t, &idx, w).unwrap_or_else(|| panic!("[{leg}] {tag} hole"));
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
            let (got, _) = dec(&t, &idx, w).unwrap_or_else(|| panic!("[{leg}] {tag} hole"));
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
        let (got, _) = dec(&t, &idx, w).unwrap_or_else(|| panic!("[{leg}] {tag} hole"));
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
        assert_eq!(e.and_base, want_base, "{leg} donor base drift");
        assert_eq!(e.variable_mask, want_vm, "{leg} donor vm drift");
    }
    assert_eq!(
        e121.and_base, want_base,
        "sm121a is not the donor shape (base)"
    );
    assert_eq!(
        e121.variable_mask, want_vm,
        "sm121a is not the donor shape (vm)"
    );
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
        src.contains(CANON412413),
        "SOURCE.json must pin canonical {CANON412413} (BUG-412+413(i) graft F2-iter230; rides e4f0915"
    );
}

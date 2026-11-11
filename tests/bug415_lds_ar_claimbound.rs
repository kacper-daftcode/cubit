//! BUG-415 pins (F2-iter229, loop5/blind front2, 2026-09-08): sm121a '?AR'
//! LDS.S8/U16/U8 claim-boundary closure (canonical 2ae87b3 -> 67a0c22;
//! ENGINE cubit src ZERO changes; table graft only, patch415.py
//! replayable+idempotent, replay from pristine 2ae87b3 byte-exact
//! 8277ed41, idem all-skip RC=0). Tail of 388/398 (registration 415-kand
//! LOW, 398.md sec.6; verify388post 9-cell S8 subset).
//!
//! Vendor law arb415 (63 probes, per-bit singles+fill on all six LDS size
//! carriers + boundary b72/76..80 + payload-under-junk, nvdisasm 13.3.73
//! raw -b per-word, x4 models SM100a/SM103a/SM120/SM121a unanimous on
//! EVERY probe, DIVERGENT=0): junk band [64:72) PURE INERT x4 on
//! '','64','128',S8,U16,U8 carriers (plain [R+imm] text kept under
//! singles+fill and imm/reg payloads); b78/b79 = the .X4/.X8 addr-scale
//! window (ALIVE -- not in scope; stays HOLE, coverage note).
//!
//! Defect (measure415_pre on publish cubit_py-81a50119 + canonical
//! 2ae87b3): junk-band singles/fill on the S8/U16/U8 carriers with
//! ZERO-imm payload flipped the strict claim to the era LDS.<sz>_R_AR
//! rows (BUG-152 era, guard=7 baked into care, band under their vm) whose
//! tok2 has no printer arm -> fallback '?AR' (30 cells, sm121a-only;
//! bases + imm-payload junk cells already exact pre: the era row's
//! [48:64) care rejects nonzero imm). '',64,128 carriers + legs
//! 100a/103a/120 vendor-exact pre.
//!
//! Graft (sm121a ONLY; and_base invariant x5): LDS_R_ARI|S8 + U16
//! vm |= [64:72) (monotone relax = strict claim), LDS.S8/U16/U8_R_AR
//! vm &= ~[64:72) (measured tighten; their base-word claims are
//! band==0, unchanged by construction). U8 junk routes to the
//! LDS.U8_R_ARI|'' remnant arm (prints vendor-exact; base stays on
//! LDS_R_ARI|U8). Canonical junk-drop at re-encode (encoder mints the
//! band==0 shape pre and post).
//!
//! Witness data: tests/bug415_data.inc (machine-built by
//! work/bug415/gen415pins.py from arb415_law.json + claims415.json +
//! measure415_pre2/post2; no hand hex; self-checks abort).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug415_data.inc");
include!("bug420_lds_addrscale_data.inc");

/// 2026-11-08 (T-18, rows-memory-2026-11-07): on sm120 these law-grid words carry a bit the measured
/// LDS / STS / LDSM / STSM rows fail closed on -- the text-inert control / sub-UR / gap bits nvdisasm
/// names as the base word (verified: nvdisasm text == the base text, 0 census witnesses). The measured-row
/// convention; the three other legs keep the harvest tolerance.
const SM120_FAIL_CLOSED: &[u128] = &[
    0x000fc80000000001000000000a5b7984u128,
    0x000fc80000000002000000000a5b7984u128,
    0x000fc80000000004000000000a5b7984u128,
    0x000fc80000000008000000000a5b7984u128,
    0x000fc80000000010000000000a5b7984u128,
    0x000fc80000000020000000000a5b7984u128,
    0x000fc80000000040000000000a5b7984u128,
    0x000fc8000000008000000000045b7984u128,
    0x000fc80000000080000000000a5b7984u128,
    0x000fc800000000ff000000000a5b7984u128,
    0x000fc80000000100000000000a5b7984u128,
    0x000fc80000000900000000000a5b7984u128,
    0x000fc80000000b00000000000a5b7984u128,
    0x000fc80000000d00000000000a5b7984u128,
    0x000fc80000001000000000000a5b7984u128,
    0x000fc80000001800000000000a5b7984u128,
    0x000fc80000001a00000000000a5b7984u128,
    0x000fc80000001c00000000000a5b7984u128,
    0x000fc80000002000000000000a5b7984u128,
    0x000fc80000002800000000000a5b7984u128,
    0x000fc80000002a00000000000a5b7984u128,
    0x000fc80000002c00000000000a5b7984u128,
    0x000fc80000010000000000000a5b7984u128,
    0x000fc80000010800000000000a5b7984u128,
    0x000fc80000010a00000000000a5b7984u128,
    0x000fc80000010c00000000000a5b7984u128,
    0x000fe20008000100000000040a5d7984u128,
    0x000fe20008000100000055040a5d7984u128,
    0x000fe2000800010000005504ff5d7984u128,
    0x000fe20008000300000000040a5d7984u128,
    0x000fe20008000300000055040a5d7984u128,
    0x000fe20008000500000000040a5d7984u128,
    0x000fe20008000500000055040a5d7984u128,
    0x000fe2000800050000005504ff5d7984u128,
    0x000fe20008000900000000040a5d7984u128,
    0x000fe20008000900000055040a5d7984u128,
    0x000fe2000800090000005504ff5d7984u128,
    0x000fe20008000b00000000040a5d7984u128,
    0x000fe20008000b00000055040a5d7984u128,
    0x000fe20008000b0000005504ff5d7984u128,
    0x000fe20008000d00000000040a5d7984u128,
    0x000fe20008000d00000055040a5d7984u128,
    0x000fe20008000d0000005504ff5d7984u128,
    0x000fe20008001000000000040a5d7984u128,
    0x000fe20008001000000055040a5d7984u128,
    0x000fe2000800100000005504ff5d7984u128,
    0x000fe20008001200000000040a5d7984u128,
    0x000fe20008001200000055040a5d7984u128,
    0x000fe20008001400000000040a5d7984u128,
    0x000fe20008001400000055040a5d7984u128,
    0x000fe2000800140000005504ff5d7984u128,
    0x000fe20008001800000000040a5d7984u128,
    0x000fe20008001800000055040a5d7984u128,
    0x000fe2000800180000005504ff5d7984u128,
    0x000fe20008001a00000000040a5d7984u128,
    0x000fe20008001a00000055040a5d7984u128,
    0x000fe20008001a0000005504ff5d7984u128,
    0x000fe20008001c00000000040a5d7984u128,
    0x000fe20008001c00000055040a5d7984u128,
    0x000fe20008001c0000005504ff5d7984u128,
    0x000fe20008002000000000040a5d7984u128,
    0x000fe20008002000000055040a5d7984u128,
    0x000fe2000800200000005504ff5d7984u128,
    0x000fe20008002200000000040a5d7984u128,
    0x000fe20008002200000055040a5d7984u128,
    0x000fe20008002400000000040a5d7984u128,
    0x000fe20008002400000055040a5d7984u128,
    0x000fe2000800240000005504ff5d7984u128,
    0x000fe20008002800000000040a5d7984u128,
    0x000fe20008002800000055040a5d7984u128,
    0x000fe2000800280000005504ff5d7984u128,
    0x000fe20008002a00000000040a5d7984u128,
    0x000fe20008002a00000055040a5d7984u128,
    0x000fe20008002a0000005504ff5d7984u128,
    0x000fe20008002c00000000040a5d7984u128,
    0x000fe20008002c00000055040a5d7984u128,
    0x000fe20008002c0000005504ff5d7984u128,
    0x000fe20008010000000000040a5d7984u128,
    0x000fe20008010000000055040a5d7984u128,
    0x000fe2000801000000005504ff5d7984u128,
    0x000fe20008010200000000040a5d7984u128,
    0x000fe20008010200000055040a5d7984u128,
    0x000fe20008010400000000040a5d7984u128,
    0x000fe20008010400000055040a5d7984u128,
    0x000fe2000801040000005504ff5d7984u128,
    0x000fe20008010800000000040a5d7984u128,
    0x000fe20008010800000055040a5d7984u128,
    0x000fe2000801080000005504ff5d7984u128,
    0x000fe20008010a00000000040a5d7984u128,
    0x000fe20008010a00000055040a5d7984u128,
    0x000fe20008010a0000005504ff5d7984u128,
    0x000fe20008010c00000000040a5d7984u128,
    0x000fe20008010c00000055040a5d7984u128,
    0x000fe20008010c0000005504ff5d7984u128,
    0x000fe800000002010000000006217984u128,
    0x000fe80000000201000000000a5b7984u128,
    0x000fe80000000202000000000a5b7984u128,
    0x000fe80000000204000000000a5b7984u128,
    0x000fe80000000204000155000a5b7984u128,
    0x000fe80000000208000000000a5b7984u128,
    0x000fe80000000210000000000a5b7984u128,
    0x000fe80000000220000000000a5b7984u128,
    0x000fe80000000240000000000a5b7984u128,
    0x000fe80000000280000000000a5b7984u128,
    0x000fe800000002ff0000000006217984u128,
    0x000fe800000002ff000000000a5b7984u128,
    0x000fe800000002ff000155000a5b7984u128,
    0x000fe80000000300000000000a5b7984u128,
    0x000fe80000000401000000000a5b7984u128,
    0x000fe80000000402000000000a5b7984u128,
    0x000fe80000000404000000000a5b7984u128,
    0x000fe80000000408000000000a5b7984u128,
    0x000fe80000000410000000000a5b7984u128,
    0x000fe80000000420000000000a5b7984u128,
    0x000fe80000000440000000000a5b7984u128,
    0x000fe80000000440000077000a5b7984u128,
    0x000fe80000000480000000000a5b7984u128,
    0x000fe800000004ff000000000a5b7984u128,
    0x000fe80000000500000000000a5b7984u128,
    0x000fe80000001200000000000a5b7984u128,
    0x000fe80000001400000000000a5b7984u128,
    0x000fe80000002200000000000a5b7984u128,
    0x000fe80000002400000000000a5b7984u128,
    0x000fe80000010200000000000a5b7984u128,
    0x000fe80000010400000000000a5b7984u128,
];


fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<(String, String)> {
    idx.decode(w, 0, t)
        .map(|d| (to_sass(&d), format!("{}|{}", d.key, d.mod_group)))
        .ok()
}
include!("t25_fail_closed.inc");
/// T-25 (2026-11-09): the LDS rows are measured on sm100a / sm103a (rows-memory-2026-11-07 on -b SM100 / SM103) and the
/// `LDS_R_ARI` `S8` row on sm121a (-b SM121): they fail closed on the junk band [71:64]; the clean word's reading keeps
/// the vendor pin (the claim of a HOLE is not a claim -- `CLOSED` stands in for the row).
const CLOSED: &str = "(fail-closed: the clean word's row)";
fn dec_fc(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<(String, String)> {
    dec(t, idx, w).or_else(|| t25_closed(t, w).map(|s| (s, CLOSED.to_string())))
}
/// t415_1: sm121a class cells decode vendor-exact x36 and claim the
/// contract rows (S8 -> LDS_R_ARI|S8, U16 -> LDS_R_ARI|U16, U8 junk ->
/// LDS.U8_R_ARI, U8 base -> LDS_R_ARI|U8).
#[test]
fn t415_1_sm121a_vendor_exact_claims() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    let mut n = 0u32;
    for (word, tag, vendor) in PROBES415 {
        let (got, km) = dec_fc(&t, &idx, word).unwrap_or_else(|| panic!("[{tag}] hole"));
        assert_eq!(got, vendor, "[{tag}] render drift");
        let want = CLAIM415.iter().find(|(tg, _)| *tg == tag).unwrap().1;
        if km != CLOSED {
            assert_eq!(km, want, "[{tag}] claim drift: {km}");
        }
        n += 1;
    }
    assert_eq!(n, 36, "class set drifted");
}

/// t415_2: attribution capture -- the 30 pre-fix '?AR' era renders must not
/// reappear (fix footprint == those cells; publish-201191ff + pre-canonical
/// 2ae87b3 captures in measure415_pre2).
#[test]
fn t415_2_era_fallback_must_not_reappear() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    let mut n = 0u32;
    for tag in PRE415_AR {
        let (word, _, vendor) = PROBES415.iter().find(|(_, tg, _)| *tg == tag).unwrap();
        let (got, _) = dec_fc(&t, &idx, *word).unwrap();
        assert!(
            !got.contains("?AR"),
            "[{tag}] era fallback '?AR' reappeared"
        );
        assert_eq!(&got, vendor, "[{tag}] not vendor-exact");
        n += 1;
    }
    assert_eq!(n, 30, "fix footprint drifted");
}

/// t415_3: sibling legs byte-invariant x3 (their tables are untouched by
/// the graft; cells must keep decoding vendor-exact).
#[test]
fn t415_3_sibling_legs_invariant() {
    for (arch, want_tab) in [("sm100a", 0usize), ("sm103a", 1), ("sm120", 2)] {
        let _ = want_tab;
        let t = tab(arch);
        let idx = DecodeIndex::build(&t);
        let mut n = 0u32;
        for (word, tag, vendor) in PROBES415 {
            // T-18: the measured LDS rows fail closed on their text-inert bits on sm120 (SM120_FAIL_CLOSED)
            if arch == "sm120" && SM120_FAIL_CLOSED.contains(&word) {
                assert!(dec(&t, &idx, word).is_none(), "[{arch} {tag}]: measured row tolerates a text-inert bit");
                n += 1;
                continue;
            }
            // (T-25: sm100a / sm103a measured as well -- the clean word's reading)
            let (got, _) = dec_fc(&t, &idx, word).unwrap_or_else(|| panic!("[{arch} {tag}] hole"));
            assert_eq!(&got, vendor, "[{arch} {tag}] drift");
            n += 1;
        }
        assert_eq!(n, 36);
    }
}

/// t415_4: mint circle + canonical junk-drop: every class text re-encodes
/// to the cell word with the inert band zeroed (word & ~([64:72)) ...
/// control prefix authored by the encoder matches the carrier corpus
/// control word by convention).
#[test]
fn t415_4_mint_circle_junk_drop() {
    const BAND: u128 = 0xffu128 << 64;
    const M96: u128 = (1u128 << 96) - 1;
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    let mut n = 0u32;
    for (word, tag, _vendor) in PROBES415 {
        let (txt, _) = dec_fc(&t, &idx, word).unwrap();
        let ins = parse_sass(&format!("{txt} ;"), 0).unwrap();
        let remint = encode_instruction(&ins, &t).unwrap();
        // payload domain: canonical cell == word with the band zeroed
        // (ctrl prefix [127:96) authored by the encoder own convention)
        assert_eq!(
            remint & M96,
            word & M96 & !BAND,
            "[{tag}] canonical mint drift"
        );
        assert_eq!(
            remint & BAND,
            0,
            "[{tag}] mint must not carry the junk band"
        );
        let (txt2, _) = dec(&t, &idx, remint).unwrap();
        assert_eq!(txt, txt2, "[{tag}] mint circle open");
        n += 1;
    }
    assert_eq!(n, 36);
}

/// t415_5: boundary postures HELD until BUG-420 (F2-iter232, canonical
/// 0eddad5): the six HOLE415 words decode vendor-exact x4 now (machine
/// comments below); the fn still guards the canonical pin + vm band claims.
/// Historical pin text (pre-420): boundary postures hold (HOLE415 pre==post, x4 legs, incl. the
/// .X4/.X8 addr-scale window = registered coverage note) + authored
/// '.X4' mint fails closed (no row) + graff hygiene: SOURCE pin CANON415,
/// row-shape anchors, band configurations.
#[test]
fn t415_5_boundaries_and_graft_hygiene() {
    // Current byte-pinned cut; historical fixture provenance remains unchanged.
    const CURRENT_VENDORED_CANON: &str = "8d74daaff39558e41164d1160d75128ad7b417e0" /* 2026-11-06 T-11 (was c258f8a, T-10) */ /* 2026-11-06 T-10 (was b75cc20, T-9) */;
    assert_eq!(CANON415, "9c0e4cec355119065444f59d0710de372b9d0577", "historical fixture revision drift");

    // FLIP (BUG-420, F2-iter232, canonical 0eddad5): the six HOLE415
    // boundary words now DECODE vendor-exact x4 -- b72/b76/b77/b80 inert ->
    // base glyph; b78/b79 -> .X4/.X8 (arb420 law 195 probes x4 AGREE EVERY).
    // Expected texts are machine witnesses in bug420_lds_addrscale_data.inc
    // (LAW420_DECODE tags f1.S8.b72/b76/b77/b78/b79/b80 == these words).
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        let idx = DecodeIndex::build(&t);
        for (word, tag) in HOLE415 {
            let newtag = format!("f1.{}", tag.replace("bd", "b"));
            // T-18: on sm120 the measured LDS rows fail closed on their text-inert bits (SM120_FAIL_CLOSED) -- the
            // 2026-08 heal of these words is replaced by the measured-row convention; the three other legs keep it.
            if arch == "sm120" && SM120_FAIL_CLOSED.contains(&word) {
                assert!(idx.decode(word, 0, &t).is_err(), "[{arch}] {newtag}: measured row tolerates a text-inert bit");
                continue;
            }
            let exp: &str = LAW420_DECODE
                .iter()
                .find(|(w2, t2, _)| *w2 == word && **t2 == newtag)
                .map(|(_, _, e)| *e)
                .unwrap_or_else(|| panic!("{newtag} absent from LAW420 decode pins"));
            // (T-25: the LDS rows measured on the other legs fail closed as well -- the clean word's reading)
            let got = idx
                .decode(word, 0, &t)
                .map(|d| to_sass(&d))
                .ok()
                .or_else(|| t25_closed(&t, word))
                .map(|s| s.trim().trim_end_matches(';').to_string())
                .unwrap_or_else(|| panic!("[{arch}] {newtag} regressed to HOLE"));
            assert_eq!(got, exp, "[{arch}] {newtag}");
        }
    }
    // FLIP (BUG-420): authored .X4 mint now closes a byte-exact circle on
    // every leg via the grafted addr_scale field (mint420 witness x4 in
    // bug420_lds_addrscale_data.inc; was fail-closed pre-420, documented in
    // the F2-iter229 report sec.6).
    {
        // low96 vs the machine-generated mint420 witness: the era/scheduling
        // halo [127:96] is outer-pipeline work, out of encode_instruction's
        // scope (norm M96 z t413ii_2, LDS.S8 era bits 97/99/101/105/107/109).
        const M96: u128 = (1u128 << 96) - 1;
        let want = MINT420
            .iter()
            .find(|(text, _, _)| *text == "LDS.S8 R91, [R10.X4] ;")
            .map(|(_, w, _)| *w)
            .expect("MINT420 pins the .X4 text");
        for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
            let t = tab(arch);
            let ins = parse_sass("LDS.S8 R91, [R10.X4] ;", 0).unwrap();
            let w = encode_instruction(&ins, &t)
                .unwrap_or_else(|_| panic!("[{arch}] .X4 mint still refusing"));
            assert_eq!(w & M96, want & M96, "[{arch}] .X4 mint word low96 drift");
        }
    }
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        m["base_revision"].as_str().unwrap() == CURRENT_VENDORED_CANON,
        "SOURCE.json must pin canonical {CANON415} (BUG-415 graft F2-iter229 z atrybucja; 415 rides 2ae87b3 = BUG-419 < 418 < 417 < 414 < 409 < 395 < 405/406): {:?}",
        m["base_revision"]
    );
    let tabj: serde_json::Value =
        serde_json::from_str(&cubit::table::read_table_text("tables/sm121a.json").unwrap()).unwrap();
    let band = 0xffu128 << 64;
    let vm_of = |key: &str, mg: &str| -> u128 {
        u128::from_str_radix(
            tabj["instructions"][key]["mod_groups"][mg]["variable_mask"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap()
    };
    // 2026-11-09 (T-25, rows-memory-2026-11-07 on -b SM121): the S8 owning row is measured -- its mask is its fields, the
    // band fails closed; the U16 row keeps the 415 band; the U8 rescuer key is an alias clone of LDS_R_ARI (its U8 row)
    assert_eq!(tabj["instructions"]["LDS_R_ARI"]["mod_groups"]["S8"]["_src"], "rows-memory-2026-11-07", "S8 owning row measured");
    assert_eq!(vm_of("LDS_R_ARI", "S8") & band, 0, "S8 owning row (measured) must fail closed on the band");
    assert_eq!(
        vm_of("LDS_R_ARI", "U16") & band,
        band,
        "U16 owning row lost the band"
    );
    assert_eq!(tabj["_meta"]["key_aliases"]["LDS.U8_R_ARI"], "LDS_R_ARI", "U8 rescuer key: an alias clone (T-25)");
    // (the U8 band words read through the clean word, t415_1 / t415_4: the plain key's U8 row never carried the band)
    assert_eq!(vm_of("LDS_R_ARI", "U8") & band, 0, "U8 owning row: the band stays outside the mask");
    for key in ["LDS.S8_R_AR", "LDS.U16_R_AR", "LDS.U8_R_AR"] {
        assert_eq!(
            vm_of(key, "") & band,
            0,
            "{key} era row re-relaxed the band"
        );
        assert_eq!(
            tabj["instructions"][key]["mod_groups"][""]["and_base"]
                .as_str()
                .unwrap()
                .len(),
            34,
            "{key} and_base moved"
        );
    }
    assert_eq!(
        tabj["instructions"]["LDS_R_ARI"]["mod_groups"]["S8"]["and_base"]
            .as_str()
            .unwrap(),
        "0x00000000000002000000000000000984", // 2026-11-03 hygiene pass: control word (bit 109) cleared
        "S8 owning row and_base moved"
    );
}

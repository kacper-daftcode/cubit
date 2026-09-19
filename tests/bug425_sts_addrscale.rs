//! BUG-425 pins (F2-iter238, loop5/blind front2, 2026-09-09): STS-family
//! addr-scale .X4/.X8/.X16 window [79:78] closure + sm121a loose-AURI
//! misclaim repair. Canonical 616f185 -> 52cb73c (patch425.py
//! replayable+idempotent; law-claim self-check 508/508; ENGINE = one new
//! printer arm format_sts_auri_addr + pre-existing BUG-420 sts_lds arm).
//! Vendor law arb425 (130 probes, nvdisasm 13.3.73 raw -b, x4 models
//! SM100a/SM103a/SM120/SM121a AGREE EVERY / DIVERGENT=0): scale window
//! UNIFORM on every STS width carrier ('',64,128,U8,U16) x frame
//! (plain-ARI/ARURI/AURI-space RZ-elided); inert singles b72/b76/b77/b80
//! PURE INERT x4; STSM b78/b79 = enum walk (contract = never .Xn).
//!
//! Witness data: tests/bug425_data.inc (machine-built by
//! work/bug425/gen425pins.py from arb425_law + measure425_post + fresh x4
//! mints; self-checks abort; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug425_data.inc");

const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<(String, String)> {
    idx.decode(w, 0, t).ok().map(|d| {
        (
            to_sass(&d).trim().trim_end_matches(';').to_string(),
            format!("{}|{}", d.key, d.mod_group),
        )
    })
}
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let ins = parse_sass(text, 0).ok()?;
    encode_instruction(&ins, t).ok()
}

/// t425_1: every measured legal425 cell (law grid 120 + 7 payload) decodes
/// vendor-exact x4 and claims a grafted STS canonical row (km witness from
/// measure425_post). The 6 sm121a AURI-space U8/U16 scale cells print
/// '[RZ.Xn+URm+off]' via the new printer arm (ENGINE witness).
#[test]
fn t425_1_law_decode_lattice_vendor_exact_x4() {
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag, exp, kms) in LAW425_DECODE {
            let (got, km) = dec(&t, &idx, *w)
                .unwrap_or_else(|| panic!("[{leg}] {tag} HOLE (must be vendor-exact)"));
            assert_eq!(Some(got.as_str()), exp[li], "[{leg}] {tag} text");
            assert_eq!(km, kms[li], "[{leg}] {tag} claim-km");
        }
    }
    assert_eq!(LAW425_DECODE.len(), 127);
}

/// t425_2: standing surface (15 base + 3 pre-128 scale) rides byte-exact;
/// STSM contract cells stay loud (HOLE per-leg posture); refuse forms stay
/// fail-closed; POSTURE430STS (unbound/dual scale tokens, klasa 430,
/// OLD==NEW) pins as base-word mint.
#[test]
fn t425_2_standing_refuse_posture() {
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag, texts) in LAW425_STANDING {
            let (got, _) =
                dec(&t, &idx, *w).unwrap_or_else(|| panic!("[{leg}] {tag} standing HOLE"));
            assert_eq!(
                Some(got.as_str()),
                texts[li],
                "[{leg}] {tag} standing drift"
            );
        }
        for (w, tag, holes) in HOLE425 {
            assert_eq!(
                dec(&t, &idx, *w).is_none(),
                holes[li],
                "[{leg}] {tag} STSM contract"
            );
        }
        for text in REFUSE425 {
            assert!(enc(&t, text).is_none(), "[{leg}] refuse minted: {text}");
        }
        let base = enc(&t, "STS [R10], R4 ;").unwrap();
        for text in POSTURE430STS {
            let w = enc(&t, text)
                .unwrap_or_else(|| panic!("[{leg}] posture must mint-as-plain: {text}"));
            assert_eq!(w, base, "[{leg}] posture silent-drop drift: {text}");
        }
    }
    assert_eq!(LAW425_STANDING.len(), 18);
    assert_eq!(HOLE425.len(), 3);
    assert_eq!(REFUSE425.len(), 1); // ride F2-iter244 (BUG-438 flip438b): MT88.4 mint heal left REFUSE425
    assert_eq!(POSTURE430STS.len(), 3);
}

/// t425_3: authored forms mint circles: encode -> word witness, decode ->
/// authored text. sm121a era-mint sparsity (two AURI/AURI-U width forms)
/// fails LOUD (BUG-132) = None slot; mint coverage >= 3 legs per text.
#[test]
fn t425_3_mint_circles_x4() {
    const M96: u128 = (1 << 96) - 1;
    for (li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (text, words) in MINT425 {
            match words[li] {
                Some(word) => {
                    let got =
                        enc(&t, text).unwrap_or_else(|| panic!("[{leg}] mint refuse: {text}"));
                    assert_eq!(got & M96, word & M96, "[{leg}] low96 drift: {text}");
                    let (back, _) =
                        dec(&t, &idx, got).unwrap_or_else(|| panic!("[{leg}] circle hole: {text}"));
                    assert_eq!(
                        back,
                        text.trim().trim_end_matches(';').trim_end(),
                        "[{leg}] reprint: {text}"
                    );
                }
                None => {
                    assert!(
                        enc(&t, text).is_none(),
                        "[{leg}] None-slot must refuse loud: {text}"
                    );
                }
            }
        }
    }
    assert_eq!(MINT425.len(), 13);
}

/// t425_4: census + donor shape x4 legs + R4 law (sm121a AURI [31:24]
/// RZ-baked in care) + addr_scale field presence on every mg of the three
/// STS canonical keys.
#[test]
fn t425_4_census_and_donor_shape() {
    for leg in LEGS {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let census = |key: &str, want: &[&str]| {
            let mgs = &raw["instructions"][key]["mod_groups"];
            let mut got: Vec<&str> = mgs
                .as_object()
                .unwrap()
                .keys()
                .map(|k| k.as_str())
                .collect();
            got.sort();
            assert_eq!(got, want, "[{leg}] {key} census drift");
        };
        match leg {
            "sm100a" => {
                census("STS_ARI_R", CENSUS425_SM100A_STS_ARI_R);
                census("STS_ARURI_R", CENSUS425_SM100A_STS_ARURI_R);
                census("STS_AURI_R", CENSUS425_SM100A_STS_AURI_R);
            }
            "sm103a" => {
                census("STS_ARI_R", CENSUS425_SM103A_STS_ARI_R);
                census("STS_ARURI_R", CENSUS425_SM103A_STS_ARURI_R);
                census("STS_AURI_R", CENSUS425_SM103A_STS_AURI_R);
            }
            "sm120" => {
                census("STS_ARI_R", CENSUS425_SM120_STS_ARI_R);
                census("STS_ARURI_R", CENSUS425_SM120_STS_ARURI_R);
                census("STS_AURI_R", CENSUS425_SM120_STS_AURI_R);
            }
            _ => {
                census("STS_ARI_R", CENSUS425_SM121A_STS_ARI_R);
                census("STS_ARURI_R", CENSUS425_SM121A_STS_ARURI_R);
                census("STS_AURI_R", CENSUS425_SM121A_STS_AURI_R);
            }
        }
        for key in ["STS_ARI_R", "STS_ARURI_R", "STS_AURI_R"] {
            for (mgn, mg) in raw["instructions"][key]["mod_groups"].as_object().unwrap() {
                let names: Vec<&str> = mg["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| f["extraction"].as_str().unwrap())
                    .collect();
                assert!(
                    names.contains(&"addr_scale"),
                    "{leg}/{key}|{mgn}: addr_scale field missing post-BUG-425"
                );
            }
        }
        if leg == "sm121a" {
            for mgn in ["", "64"] {
                let vm = u128::from_str_radix(
                    raw["instructions"]["STS_AURI_R"]["mod_groups"][mgn]["variable_mask"]
                        .as_str()
                        .unwrap()
                        .trim_start_matches("0x"),
                    16,
                )
                .unwrap();
                assert_eq!(
                    vm & (0xff << 24),
                    0,
                    "sm121a STS_AURI_R|{mgn:?}: [31:24] must be in care post-BUG-425"
                );
            }
        }
    }
}

/// t425_5: vendored tables pin canonical 54c5b02 = BUG-439 graft F2-iter243 (ride; was 3032686 = BUG-423 F2-iter242, 61858fb = BUG-433 F2-iter241; older 0a6b178 = BUG-435+434+435b, 1810912 hop, 70eb0fe = BUG-416; older: 52cb73c = BUG-425+425b graft F2-iter238).
#[test]
fn t425_5_source_pins_52cb73c() {
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        m["base_revision"].as_str().unwrap().starts_with("cc2f62c"), // ride F2-iter278 (BUG-467 canonical graft 668f842; was 67b54f4 BUG-466)
        "SOURCE.json must pin canonical 57e7ecd [was ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, 1810912 = 435+434 hop, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b, 3f6ca6f = BUG-425, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424, 13e13b6 = BUG-421+422] (BUG-442 graft F2-iter246 z atrybucja; ride-chain): {:?}",
        m["base_revision"]
    );
    assert!(CANON425.starts_with("cc2f62c"), "CANON425 const drift");
}

/// t425_6: inert-singles law direct witness -- b72/b76/b77/b80 decode to
/// the same text as base on every carrier x frame x4 (observability of the
/// vm-relax: neighbor words now claim vendor-exact instead of HOLE).
#[test]
fn t425_6_inert_singles_visible() {
    for (_li, leg) in LEGS.iter().enumerate() {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let mut n = 0;
        for (w, tag, exp, _) in LAW425_DECODE {
            if tag.ends_with(".b72")
                || tag.ends_with(".b76")
                || tag.ends_with(".b77")
                || tag.ends_with(".b80")
            {
                let (got, _) = dec(&t, &idx, *w).unwrap();
                assert_eq!(&got, exp[_li].unwrap(), "[{leg}] {tag} inert text");
                n += 1;
            }
        }
        assert_eq!(n, 60, "[{leg}] inert cells census drift");
    }
}

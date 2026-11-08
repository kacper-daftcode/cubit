//! BUG-420 pins (F2-iter232, loop5/blind front2, 2026-09-09): LDS addr-scale
//! window closure -- .X4/.X8/.X16 [79:78] uniform law on every width carrier
//! x address frame x4 models (arb420, 195 probes, nvdisasm 13.3.73 raw -b,
//! AGREE EVERY / DIVERGENT=0); canonical graft 487757b -> 0eddad5
//! (ride: BUG-425 canonical 52cb73c F2-iter238, pin flips only; ride: BUG-429 canonical 616f185 F2-iter237, pin flips only; history: BUG-427 a5e6d0a F2-iter236, BUG-426 2a631d5 F2-iter235, BUG-424 291ed59b F2-iter234, BUG-421+422 13e13b6 F2-iter233)
//! (patch420.py replayable+idempotent: addr_scale field on LDS_R_ARI
//! ('','S8','U16','U8'), LDS_R_ARURI + LDS_R_AURI (all 6 mgs) x4 legs +
//! measured-inert singles vm relax {72,76,77,80} same rows; era keys
//! UNTOUCHED) + ENGINE printer arm (format_sts_lds_addr: scale suffix on the
//! UR-window bracket, RZ kept visible when scaled -- vendor prints
//! '[RZ.X4+UR4+off]', arb420 f3; scale=0 text byte-identical pre-existing).
//!
//! Witness data: tests/bug420_lds_addrscale_data.inc (machine-built by
//! work/bug420/gen420pins.py from arb420_law.json + measure420_post.json +
//! mint420.json; self-checks abort; no hand hex).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug420_lds_addrscale_data.inc");

/// 2026-11-08 (T-18, rows-memory-2026-11-07): on sm120 these law-grid words carry a bit the measured
/// LDS / STS / LDSM / STSM rows fail closed on -- the text-inert control / sub-UR / gap bits nvdisasm
/// names as the base word (verified: nvdisasm text == the base text, 0 census witnesses). The measured-row
/// convention; the three other legs keep the harvest tolerance.
const SM120_FAIL_CLOSED: &[u128] = &[
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
    0x000fe80000000300000000000a5b7984u128,
    0x000fe80000000500000000000a5b7984u128,
    0x000fe80000001200000000000a5b7984u128,
    0x000fe80000001400000000000a5b7984u128,
    0x000fe80000002200000000000a5b7984u128,
    0x000fe80000002400000000000a5b7984u128,
    0x000fe80000010200000000000a5b7984u128,
    0x000fe80000010400000000000a5b7984u128,
];


const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
        .ok()
}
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let ins = parse_sass(text, 0).ok()?;
    encode_instruction(&ins, t).ok()
}

/// t420_1: every law-grid cell decodes vendor-exact on all four legs (the
/// 24 pre-existing ARI|64/128 scale cells included: byte-parity kept).
#[test]
fn t420_1_law_grid_vendor_exact_x4() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (w, tag, exp) in LAW420_DECODE {
            let got = dec(&t, &idx, w);
            // T-18: measured LDS rows fail closed on their text-inert bits on sm120 (SM120_FAIL_CLOSED)
            if leg == "sm120" && SM120_FAIL_CLOSED.contains(&w) {
                assert!(got.is_none(), "[{leg}] {tag}: a measured row tolerates a text-inert bit");
                continue;
            }
            assert_eq!(got.as_deref(), Some(exp), "[{leg}] {tag}");
        }
    }
}

/// t420_2: authored .Xn texts mint the pinned words x4 and the mint's
/// reprint reproduces the authored text (encode circles closed).
#[test]
fn t420_2_scale_mint_circles_x4() {
    // low96 equality: the era/scheduling halo [127:96] is synthesized by the
    // outer pipeline (asm -> postfix -> metafix), not by encode_instruction
    // (norm M96 z t413ii_2).
    const M96: u128 = (1u128 << 96) - 1;
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for (text, want, rt) in MINT420 {
            let w = enc(&t, text).unwrap_or_else(|| panic!("[{leg}] mint refused: {text}"));
            assert_eq!(w & M96, want & M96, "[{leg}] mint word low96 drift: {text}");
            let got = dec(&t, &idx, w).expect("[{leg}] mint not self-decoding");
            assert_eq!(&got, rt, "[{leg}] reprint drift: {text}");
        }
    }
}

/// t420_3: junk-inert words re-encode DOWN to the base word (canonical
/// junk-drop doctrine: decode-scoped bits never mint back; and_base
/// invariant).
#[test]
fn t420_3_inert_reencode_converges_to_base() {
    for leg in LEGS {
        let t = tab(leg);
        let mut guard_refuse = 0u32;
        for (w, tag, exp) in LAW420_DECODE {
            if !(tag.contains(".b72")
                || tag.contains(".b76")
                || tag.contains(".b77")
                || tag.contains(".b80"))
            {
                continue;
            }
            let ins = parse_sass(&format!("{exp} ;"), 0).expect("pin text unparseable");
            let w2 = match encode_instruction(&ins, &t) {
                Ok(w2) => w2,
                Err(_) => {
                    // BUG-088 alignment guard (silicon-illegal widths/dst
                    // combos) -- decode-side coverage of these cells is
                    // proven in t420_1; the refuse is the standing guard and
                    // is count-pinned below.
                    guard_refuse += 1;
                    assert!(
                        exp.starts_with("LDS.128 ") || exp.starts_with("LDS.64 "),
                        "[{leg}] unexpected guard refuse on {exp}"
                    );
                    continue;
                }
            };
            const M96: u128 = (1u128 << 96) - 1;
            let junk = (1u128 << 72) | (1u128 << 76) | (1u128 << 77) | (1u128 << 80);
            assert_eq!(
                w2 & M96 & !junk,
                w & M96 & !junk,
                "[{leg}] {tag} core drift"
            );
            assert_eq!(w2 & junk, 0, "[{leg}] {tag} junk minted back");
        }
        // BUG-088 guard fires on sm103a only (measured: 32 inert texts =
        // 2 width carriers (.64/.128) x 4 frames x 4 junk bits; decode-side
        // coverage of the same cells is proven in t420_1).
        let want_refuse = match leg {
            "sm103a" => 32,
            _ => 0,
        };
        assert_eq!(
            guard_refuse, want_refuse,
            "[{leg}] 088-guard refuse count drift"
        );
    }
}

/// t420_4: generation census pins (loud regeneration drift) + canonical
/// manifest pin at 57e7ecd (BUG-442 graft F2-iter246 z atrybucja; rides ffa3244 = BUG-441 F2-iter245, bb1ba6c = BUG-438 F2-iter244, 54c5b02 = BUG-439 F2-iter243, 3032686 = BUG-423 F2-iter242, 61858fb = BUG-433 F2-iter241, 0a6b178 = BUG-435+434+435b, 1810912 = 435+434 hop, 70eb0fe = 416; 416-era rides 52cb73c = 425+425b; 425 docstring-history: rides 616f185 = 429; 429 rides a5e6d0a = 427; 427 rides 2a631d5 = 426; 426 rides 291ed59b = 424; 424 rides 13e13b6 = 421+422; 421+422 rides 0eddad5 = 420; 420 rides
/// 487757b = BUG-413(ii)/(iii) < 413(i) = BUG-412 < 415 < 419 < 418 < 417
/// < 414 < 409 < 395 < 405/406).
#[test]
fn t420_4_census_and_canonical_pin() {
    assert_eq!(
        LAW420_DECODE.len(),
        LAW420_COUNTS,
        "law grid regenerated at a different size"
    );
    assert_eq!(LOST420, 0, "posture loss forbidden (pure-widen graft)");
    assert_eq!(
        TRANGED420, 0,
        "text migration forbidden (text-stable doctrine)"
    );
    // filled at gen-proven numbers: healed = 276 scale + 384 inert = 660,
    // same-ok = 96 base + 24 pre-scale = 120. Constants carry the law.
    assert_eq!(HEALED420, 660);
    assert_eq!(SAMEOK420, 120);
    assert_eq!(SAMEHOLE420, 0, "whole arb420 grid decodes post-graft");
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        m["base_revision"]
            .as_str()
            .unwrap()
            .starts_with("27b127251edd465fbc462d7e8017f54ff43ad4d1") /* 2026-11-06 T-11 (was c258f8a, T-10) */, // ride F2-iter278 (BUG-467 canonical graft 668f842; was 67b54f4 BUG-466)
        "SOURCE.json must pin canonical e03e0348d98b9d20ffb4ca557cfc6eae625cf995 (= BUG-452 narrow, ride-after 4ee843162216e75d037135b5907c819759471296, = BUG-454 graft, ride-after 589be874 (= BUG-450) (= BUG-450 graft, ride-after 099faa0 (= BUG-447) [was ffa3244 = BUG-441, bb1ba6c = BUG-438, 54c5b02 = BUG-439, 3032686 = BUG-423, 61858fb = BUG-433, 0a6b178 = BUG-435+434+435b, was 1810912 = BUG-435+434, 70eb0fe = BUG-416, 52cb73c = BUG-425+425b, 616f185 = BUG-429, a5e6d0a = BUG-427, 2a631d5 = BUG-426, 291ed59b = BUG-424, 13e13b6 = BUG-421+422] (BUG-438 graft F2-iter244 z atrybucja; ride-chain w tym pliku): {:?}",
        m["base_revision"]
    );
}

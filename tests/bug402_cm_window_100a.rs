//! BUG-402 pins (F2-iter217, loop5/blind front2, 2026-09-06): sm100a cm-window
//! declarations widened to the vendor-measured windows (canonical dd477eb ->
//! 96f196b, patch402.py graft replayable+idempotent; ENGINE src ZERO changes;
//! ONE table sm100a, other legs byte-invariant, measured isolated).
//!
//! Vendor law (arb402.py = arb389b mechanics upgraded to a per-bit walk):
//! bits [60:37) walked singly + sign16/sign17/maxpos17/allones22 composites
//! on full-128 words; '' row anchored on a corpus word
//! (LDCU UR5, c[0x0][0x394], libcublas.so.1011.sm_100.cubin), S16 rows
//! synthesized from sibling-donor ctrl prefixes (zero corpus claims,
//! census402); nvdisasm 13.3.73 raw -b x4 models AGREE on ALL 108 probes,
//! DIVERGENT=0; UR state swept URZ + UR5 on the '' row:
//!   LDCU_UR_cAI|''/|S16 : offset = [54:37) SIGNED-17 (b53 = sign)
//!                         bank = [59:54); b59 INERT; UR-carried == URZ law.
//!   LDC_R_cAI|S16       : offset = [54:38) SIGNED-16 (b53 = sign)
//!                         bank = [59:54); b59 INERT (b37 dead, 409-kand).
//! Pre-fix declarations (12b/11b cm16_off + sub_imm0 24b) silently dropped
//! offset bits [53:49) and re-routed them into a phantom bank
//! (measure402_pre on publish cubit_py-650b9977; sample: b49 word
//! vendor c[0x0][UR5+0x1394] vs engine c[0x0][UR5+0x394]; b54..b58 banks
//! 0x1..0x10 rendered c[0x0]).
//!
//! Witness data: tests/bug402_data.inc (machine-built by
//! work/bug402/gen402pins.py from arb402_law.json + claim100a_words.json
//! verbatim; class column: exact / 401 / 409; [F2-iter224] all classes
//! exact: 401 landed F2-iter218, 409 landed F2-iter224 (BUG-409 arm+graft,
//! results/cubitfix/409.md)).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const LEGS4: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let ins = parse_sass(text, 0).map_err(|e| e.to_string())?;
    encode_instruction(&ins, t).map_err(|e| e.to_string())
}

include!("bug402_data.inc");

/// t402_1: probe matrix vs vendor law on sm100a, classified.
/// 108 cells vendor-exact (401 landed F2-iter218: +4 ex-401 words;
/// 409 landed F2-iter224: +4 ex-409 words -- LDC_R_cAI|S16 claim-priority
/// arm + vm|b37 graft, results/cubitfix/409.md; posture arm removed, all
/// ex-409 words are class "exact" in bug402_data.inc and flow through the
/// vendor-equality arm).
#[test]
fn t402_1_probe_matrix_classified() {
    let t = tab("sm100a");
    let idx = DecodeIndex::build(&t);
    let mut n_exact = 0u32;
    for (word, tag, vendor, class) in PROBES402 {
        let d = idx.decode(word, 0, &t);
        match class {
            "exact" => {
                let got = d.map(|x| to_sass(&x)).unwrap_or_else(|_| "ERR".into());
                assert_eq!(got, vendor, "[{tag}] word {word:032x}");
                n_exact += 1;
            }
            other => panic!("unknown class {other}"),
        }
    }
    assert_eq!(n_exact, 108, "class counts drifted");
}

/// t402_2: corpus claim sample renders byte-stable post-graft
/// (sample = every-350th of all 13,678 distinct '' claim words + ALL 49
/// distinct UR-carried words; expected = publish-650b9977 pre-render,
/// verified identical post-graft on the full 13,678-word set: 0 diffs).
#[test]
fn t402_2_corpus_claims_render_stable() {
    let t = tab("sm100a");
    let idx = DecodeIndex::build(&t);
    for (word, want) in CLAIMS402 {
        let got = dec(&t, &idx, word).unwrap_or_else(|| panic!("claim lost: {word:032x}"));
        assert_eq!(got, want, "render drift {word:032x}");
    }
}

/// t402_3: previously-dropped offsets now mint vendor-true (minted payload
/// == measured law word; render == authored text), bank mints into [59:54).
#[test]
fn t402_3_previously_dropped_offsets_mint() {
    let t = tab("sm100a");
    let idx = DecodeIndex::build(&t);
    // offset bits [53:49) were silently truncated pre-fix (probe b49 word):
    let w = enc(&t, "LDCU UR4, c[0x0][0x1394] ;").expect("mints post-402");
    let anchor = PROBES402
        .iter()
        .find(|(_, tag, _, _)| *tag == "A|b49")
        .unwrap()
        .0;
    // b49 = URZ anchor | (1<<49): the authored text must mint the law
    // word's PAYLOAD (anchor dest is UR5; UR4 swaps ureg bits [24:16);
    // sub_ur1 stays the URZ sentinel; ctrl prefix [127:96) is authored
    // by the encoder from and_base, so compare in the M96 domain):
    const M96: u128 = (1u128 << 96) - 1;
    let want = (anchor & !(0xffu128 << 16)) | (4u128 << 16);
    assert_eq!(w & M96, want & M96, "mint drift vs law word payload");
    let got = dec(&t, &idx, w).unwrap();
    assert_eq!(got, "LDCU UR4, c[0x0][0x1394]");
    // bank channel: c[0x3] must land at [59:54) (pre-fix: phantom bits 49..)
    let w = enc(&t, "LDCU UR4, c[0x3][0x358] ;").expect("bank mints");
    assert_eq!((w >> 54) & 0x1f, 3, "bank must live at [59:54)");
    assert_eq!(dec(&t, &idx, w).as_deref(), Some("LDCU UR4, c[0x3][0x358]"));
    // degenerate-window mints (t389_4b values, signed-17 roundtrip):
    for (text, want) in [
        ("LDCU UR4, c[0x0][+0x1fff] ;", "LDCU UR4, c[0x0][0x1fff]"),
        ("LDCU UR4, c[0x0][+0x7fff] ;", "LDCU UR4, c[0x0][0x7fff]"),
        ("LDCU UR4, c[0x0][-0x8000] ;", "LDCU UR4, c[0x0][-0x8000]"),
    ] {
        let w = enc(&t, text).unwrap_or_else(|e| panic!("post-402 mints: {text}: {e}"));
        let rt = dec(&t, &idx, w).unwrap();
        assert_eq!(rt, want, "roundtrip drift {text}");
    }
}

/// t402_4: sign-window law on all three grafted rows (mint + render).
#[test]
fn t402_4_sign_window_law() {
    let t = tab("sm100a");
    let idx = DecodeIndex::build(&t);
    for (text, want) in [
        ("LDCU UR4, c[0x0][-0x8000] ;", "LDCU UR4, c[0x0][-0x8000]"),
        ("LDCU UR4, c[0x0][0x8000] ;", "LDCU UR4, c[0x0][0x8000]"),
        (
            "LDCU.S16 UR0, c[0x0][-0x10000] ;",
            "LDCU.S16 UR0, c[0x0][-0x10000]",
        ),
        (
            "LDCU.S16 UR0, c[0x0][0x8000] ;",
            "LDCU.S16 UR0, c[0x0][0x8000]",
        ),
        (
            "LDC.S16 R0, c[0x0][-0x8000] ;",
            "LDC.S16 R0, c[0x0][-0x8000]",
        ),
        ("LDC.S16 R0, c[0x0][0x4022] ;", "LDC.S16 R0, c[0x0][0x4022]"),
    ] {
        let w = enc(&t, text).unwrap_or_else(|e| panic!("mint {text}: {e}"));
        let got = dec(&t, &idx, w).unwrap();
        assert_eq!(got, want, "sign circle {text}");
    }
}

/// t402_5: bit 59 is vendor-measured INERT on every grafted shape; the
/// vm-relax keeps acceptance and renders identical text with/without b59.
#[test]
fn t402_5_bit59_inert_acceptance() {
    let t = tab("sm100a");
    let idx = DecodeIndex::build(&t);
    const B59: u128 = 1u128 << 59;
    let mut checked = 0u32;
    for (word, tag, _vendor, class) in PROBES402 {
        if class != "exact" {
            continue;
        } // b59-composites skip residua
        if tag.contains("b59") {
            continue;
        } // don't double the bit itself
        // C-row skipped: bit59 ALSO lands inside the cARI|S16 claim window
        // ([409 landed F2-iter224] the claim is vendor-true now; coverage of
        // the C-row inert render moved to the t409_1 pin set, kept skipped
        // here to preserve this test's original per-row span).
        if tag.starts_with("C|") {
            continue;
        }
        let base = dec(&t, &idx, word).unwrap_or_else(|| panic!("base dec {tag}"));
        let lifted = dec(&t, &idx, word | B59)
            .unwrap_or_else(|| panic!("b59=1 must stay decodable [{tag}]"));
        assert_eq!(base, lifted, "[{tag}] b59 not inert");
        checked += 1;
    }
    assert!(checked >= 70, "coverage too thin: {checked}");
}

/// t402_6: other legs byte-invariant by sync (--check), behavior-anchored:
/// the '' claim anchor renders the same on sm103a/sm120/sm121a as pre-graft
/// (sibling tables untouched), and sibling-leg S16 law words stay
/// vendor-exact where rows exist; known sibling holes documented:
/// b59=1 on sm103a/sm120 '' rows = HOLE (registered follow-up, exposure-0),
/// S16 rows absent on sm121a (arch coverage, pre-existing).
#[test]
fn t402_6_other_legs_behavior_anchor() {
    let anchor = CLAIMS402[0].0;
    let want = CLAIMS402[0].1;
    for leg in ["sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got =
            dec(&t, &idx, anchor).unwrap_or_else(|| panic!("[{leg}] sibling claim anchor lost"));
        assert_eq!(got, want, "[{leg}] sibling render drift");
    }
    // sibling '' rows: b59 acceptance hole = pinned posture (registered;
    // NOT fixed in 402 -- table polygon t172_6 guards donor-clone parity).
    for leg in ["sm103a", "sm120"] {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        assert!(
            dec(&t, &idx, anchor | (1u128 << 59)).is_none(),
            "[{leg}] b59 hole closed? flip posture pin + report"
        );
    }
    // sibling S16 rows keep their pre-existing vendor-exact law (they were
    // the graft donors); spot the S16 sign probe on sm103a/sm120.
    let (bword, _, btext, _) = PROBES402
        .iter()
        .find(|(_, tag, _, _)| *tag == "B|sign17")
        .unwrap();
    for leg in ["sm103a", "sm120"] {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        assert_eq!(
            dec(&t, &idx, *bword).as_deref(),
            Some(*btext),
            "[{leg}] S16 law drift"
        );
        let t121 = tab("sm121a");
        let idx121 = DecodeIndex::build(&t121);
        assert!(
            dec(&t121, &idx121, *bword).is_none(),
            "sm121a S16 absent = pre-existing"
        );
    }
}

/// t402_7: table polygon of the three grafted rows (fields/vm/and_base).
#[test]
fn t402_7_grafted_row_polygon() {
    let j: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm100a.json").unwrap()).unwrap();
    let shape = |key: &str, mg: &str| -> (Vec<(String, u64, u64)>, u128, String) {
        let row = j
            .pointer(&format!("/instructions/{key}/mod_groups/{mg}"))
            .unwrap();
        let fs = row["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| {
                (
                    f["extraction"].as_str().unwrap().to_string(),
                    f["bits"].as_u64().unwrap(),
                    f["shift"].as_u64().unwrap(),
                )
            })
            .collect();
        let vm = u128::from_str_radix(
            row["variable_mask"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        (fs, vm, row["and_base"].as_str().unwrap().to_string())
    };
    let (fs, vm, ab) = shape("LDCU_UR_cAI", "");
    assert_eq!(
        fs,
        [
            ("guard".into(), 4, 12),
            ("ureg".into(), 8, 16),
            ("cm17_off".into(), 22, 37),
            ("sub_ur1".into(), 8, 24)
        ]
    );
    assert_eq!(vm & (1 << 59), 1 << 59);
    assert_eq!(
        u128::from_str_radix(ab.trim_start_matches("0x"), 16).unwrap(),
        0x000e00000800080000000000000007acu128
    );
    let (fs, vm, _ab) = shape("LDCU_UR_cAI", "S16");
    assert_eq!(fs, [("ureg".into(), 8, 16), ("cm17_off".into(), 22, 37)]);
    assert_eq!(vm & (1 << 59), 1 << 59);
    let (fs, vm, ab) = shape("LDC_R_cAI", "S16");
    assert_eq!(
        fs,
        [
            ("guard".into(), 4, 12),
            ("reg".into(), 8, 16),
            ("cm16_off".into(), 21, 38)
        ]
    );
    assert_eq!(vm & (1 << 59), 1 << 59);
    assert_eq!(
        u128::from_str_radix(ab.trim_start_matches("0x"), 16).unwrap(),
        0xe20000000060000000880ff000b82u128
    );
}

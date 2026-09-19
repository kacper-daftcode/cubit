//! BUG-446 pins (F2-iter249, loop5/blind front2, 2026-09-12): sm121a
//! LDG/STG EFL2.256 NA ARURI family -- the plain-u32-ur print arm leaked
//! the BUG-099 raw-bit width rule ('.64' when b90&&b91) into a family that
//! has NO width bit: STG bits [90:88]+[63:59] are the policy-imm byte
//! (0xff = elided trailing imm), LDG bits [90:87] the pred-out code. Engine
//! additionally DROPPED the family offset window (sub_imm2_shr5: STG 19b /
//! LDG 17b signed<<5) from the printed address. Canonical UNCHANGED 57e7ecd
//! (ENGINE-only: ONE soak -- format_plain_u32_ur gains the family flag from
//! its LDG.E/STG.E call site; sub_imm2_shr5 arm added; rest of src ZERO).
//! Vendor law arb446 (54 probes, nvdisasm 13.3.73 raw -b x4 models AGREE
//! EVERY/DIVERGENT=0; work/bug446/arb446_law.json): '[Rx.U32+URy]' INVARIANT
//! under full policy-byte + dead-bit + pred_inv4 sweeps; b91=0 kill x4
//! (rc=1); b72/b73/b87 render-neutral on STG; policy/pred/imm/URZ/RZ data
//! moves print 1:1. (post-447 ride, F2-iter252: x3 legs przepisane przez graft 099faa0
//! donor-clone 121a NA-ARURI; X3STAND446 = 150 vendor-heal + 6 rz-move,
//! atrybucja '// healed 447' w .inc.)
//! Defect evidence: vdrift442_full 110 corpus cells
//! (sm121a leg; krb_rt4/rt84e/ts2_sk4k) '...64+UR38' vs vendor '...U32+UR38'.
//! Defect pre->post (measure446_pre/work; PRISTINE parent 28ae97ae build
//! /tmp/pre446): sm121a 22 MATCH/30 WRONG/2 POSTURE -> 50 MATCH/2 WRONG
//! (2 standing = base-RZ elision class [URn], 448-kand: encode-path study
//! pending) /2 POSTURE; x3 legs byte-invariant (X3STAND446: desc-misroute
//! snap = 447-kand standing class: x3 tables lack the family rows; vendor
//! prints plain U32 there too -- arb446 x4 unanimity proof).
//!
//! Witness data: tests/bug446_data.inc (machine-built by
//! work/bug446/gen446pins.py; rc=2 fail-closed; no hand hex; mints
//! nvdisasm-crossed x4 at generation time).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug446_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
const LEGS446: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}

/// t446_1: healed grid -- sm121a decode == vendor text on every cell that
/// was WRONG pre (28: width-glyph + dropped-imm classes, all family members:
/// STG STRONG.GPU / MMIO.SYS.ORDERED, LDG STRONG.GPU / CONSTANT.GPU / LTC64B).
#[test]
fn t446_1_heal_grid() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (w, vendor) in LAW446_HEAL {
        let got = dec(&t, &idx, *w);
        assert_eq!(
            got.as_deref(),
            Some(*vendor),
            "[sm121a] heal drift {w:#034x}"
        );
    }
}

/// t446_2: stable grid -- cells that were already MATCH pre (b90-luck, LDG
/// policy/pred cells) MUST NOT drift post (fail-closed overreach tripwire).
#[test]
fn t446_2_stable_grid() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (w, vendor) in LAW446_STABLE {
        let got = dec(&t, &idx, *w);
        assert_eq!(
            got.as_deref(),
            Some(*vendor),
            "[sm121a] stable drift {w:#034x}"
        );
    }
}

/// t446_3: base-RZ cells -- width glyph + base elision BOTH healed (BUG-448,
/// flip448 F4): text == vendor bare '[UR38]'. Machine-flipped snap text.
#[test]
fn t446_3_rzstand_snap() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (w, snap) in SNAP446_RZSTAND {
        let got = dec(&t, &idx, *w);
        assert_eq!(
            got.as_deref(),
            Some(*snap),
            "[sm121a] rzstand snap drift {w:#034x}"
        );
    }
}

/// t446_4: x3 legs byte-invariant (pre == post on every law word: HOLE stays
/// HOLE, desc-misroute snap unchanged = 447-kand standing). The fix is
/// 121a-row-scoped; any x3 drift fails closed here.
/// ride 447 (F2-iter252): graft 099faa0 przepisal WSZYSTKIE 156 komorek
/// X3STAND446 (150 vendor-heal + 6 rz-move; .inc nosis atrybucje w linii).
/// Test dalej fail-closed: kazde odchylenie od zupinowanego stanu post-447.
#[test]
fn t446_4_x3_invariant() {
    for (w, leg, pre) in X3STAND446 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), *pre, "[{leg}] x3 drift {w:#034x}");
    }
}

/// t446_5: b91=0 kill posture -- vendor rc=1 x4; engine must hole/refuse
/// on all four legs (pre == post == HOLE).
#[test]
fn t446_5_kill_posture() {
    for leg in LEGS446 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        for w in POST446_KILL {
            assert_eq!(dec(&t, &idx, *w), None, "[{leg}] kill claimed {w:#034x}");
        }
    }
}

/// t446_6: mints + circles -- encode(vendor text) == mint word (full 128b;
/// era normalized to the encode control word), decode(mint) == vendor text.
/// 121a rows: mint runs on sm121a only (family rows absent on x3).
#[test]
fn t446_6_mints() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (w, text) in MASKMINT446 {
        let got = enc(&t, text).unwrap_or_else(|e| panic!("[sm121a] mint refuse {text}: {e}"));
        assert_eq!(got, *w, "[sm121a] mint drift {text}");
        let back = dec(&t, &idx, got).unwrap_or_else(|| panic!("[sm121a] mint HOLE {text}"));
        assert_eq!(&back, text, "[sm121a] circle drift {text} -> {back}");
    }
}

/// t446_7: dead-bit normalization -- decode(law word with dead bits) ==
/// vendor text; encode normalizes the dead bits to zero.
#[test]
fn t446_7_deadnorm() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (law, mint) in DEADNORM446 {
        let a = dec(&t, &idx, *law).expect("law word HOLE");
        let b = dec(&t, &idx, *mint).expect("mint HOLE");
        assert_eq!(a, b, "dead-bit render split {law:#034x}");
    }
}

/// t446_8: corpus evidence (vdrift442_full STANDING-RESIDUAL -> healed):
/// 3 unique words / 110 slots; decode == vendor text on sm121a, mint lo96.
#[test]
fn t446_8_corpus() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (w, vendor) in CORPUS446 {
        let got = dec(&t, &idx, *w);
        assert_eq!(
            got.as_deref(),
            Some(*vendor),
            "[sm121a] corpus drift {w:#034x}"
        );
        let mint = enc(&t, vendor).expect("corpus mint refuse");
        assert_eq!(
            mint & ((1u128 << 96) - 1),
            w & ((1u128 << 96) - 1),
            "[sm121a] corpus mint lo96 drift"
        );
    }
}

/// t446_9: canonical pin -- ENGINE-only bug: blackwell-isa HEAD stays the
/// BUG-442 canonical 57e7ecd; no vendored-table diff rides this commit.
#[test]
fn t446_9_canonical_unchanged() {
    // public-line hygiene: lane-side live rev-parse hermetized to the vendored manifest pin
    let head = std::fs::read_to_string("tables/SOURCE.json").unwrap();
    assert!(head.contains(CANON446), "canonical moved: {head}");
    let src = std::fs::read_to_string("tables/SOURCE.json").unwrap();
    assert!(src.contains("cc2f62c"), "tables SOURCE drift (ride F2-iter275 BUG-466 ELL2-plain; was 23976eb F2-iter272 BUG-465; ride F2-iter267 BUG-432 ari-cavity; was a64b82b BUG-463 ltc-widths; ride F2-iter263 BUG-453 graft; was e03e034 F2-iter260 BUG-452 narrow; ride F2-iter258 BUG-454 graft; was 589be87 F2-iter255 BUG-450 graft; was 099faa0 F2-iter252 BUG-447): {src}"); // flip-ride 467: pin 67b54f4 -> 668f842
}

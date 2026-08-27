//! BUG-188 (F2-iter90, front2/blind): UR-9bit residue — 10 rows of
//! tables/sm120.json re-carried sub_r{0,1}@24 with bits==9 after the
//! BUG-148 narrowing was lost in the canonical sync (i87 rehearsal
//! "148-residuum", fleet note i87 sec.3.5). Vendor arbitration
//! (nvdisasm-13.3.73 sm_120a, in-place patch of ptx3_120.cubin,
//! work/bug188/arb/arb188.json) proves the class is a LIVE silent
//! decode defect on main 2bd2a82, not a harvest cosmetic:
//!   * odd second data register (bit32=1 folds into the 9-bit [24:33)
//!     sink window): main 2bd2a82 renders
//!       ATOMS.CAST.SPIN P0, [R256+0x14], R3, R3     (main, wrong)
//!     vendor: ATOMS.CAST.SPIN P0, [R0+0x14], R3, R3
//!   * bit32 poked on the INC/POPC UR-addressed shape: main renders
//!     [R511+UR4+0xc]; vendor ignores the bit: [UR4+0xc].
//! Fix = data-only 9->8 narrowing of exactly the 10 residue rows
//! (patch188.py; _src "f2-188-2026-08-26"). Anchored populations are
//! empty for these rows on ALL measured corpora (1.88M sm120 words,
//! 32M hexdb atom lines, 9,130 atom census) — but 5/5 odd-reg probes
//! are vendor-wrong pre-fix, so the live-defect class (BUG-143 E1 /
//! 147 / 148) is confirmed on sm120 rails with the fleet's arbitration
//! method instead of geometry transfer alone.
//!
//! Pins below additionally lock the AURI-vs-dARI priority audit
//! (fleet-note i87 sec.3.5): the i87-rejected ATOMS_R_dARI
//! ['32,INC,POPC'] row (142-era) STEALS every INC/POPC anchor probe
//! when injected next to ATOMS_R_AURI (winner matrix
//! work/bug188/winner188.json: 14/14 stolen, all vendor-wrong).
//! Compose decision (i) re-validated machine-exactly.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::{Extraction, IsaTable};

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text} ;"), 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

/// Live-defect class: odd sibling reg@32 (bit32=1) must not fold into the
/// [24:33) base-R sink. Words arbitrated byte-exact by nvdisasm-13.3.73
/// (arb188.json C_cast_*).
const CAST_ODD: &[(u128, &str)] = &[
    (0x000e240001800003_000014030000758d, "ATOMS.CAST.SPIN P0, [R0+0x14], R3, R3 ;"),
    (0x000e240001800003_000014050000758d, "ATOMS.CAST.SPIN P0, [R0+0x14], R5, R3 ;"),
    (0x000e240001800003_000014070000758d, "ATOMS.CAST.SPIN P0, [R0+0x14], R7, R3 ;"),
    (0x000e240001800003_000014ff0000758d, "ATOMS.CAST.SPIN P0, [R0+0x14], RZ, R3 ;"),
];

#[test]
fn t188_1_cast_spin_odd_sibling_reg_no_r256_hallucination() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (w, want) in CAST_ODD {
        let got = dec(&t, &idx, *w);
        let got = got.trim_end_matches(" ;").to_string();
        assert_eq!(&got, want.trim_end_matches(" ;"), "vendor parity for {w:#034x}");
        assert!(!got.contains("R256"), "R+256 hallucination regressed: {got}");
    }
}

#[test]
fn t188_2_cast_spin_odd_sibling_reg_encode_payload_exact() {
    let t = t120();
    for (w, text) in CAST_ODD {
        let text = text.trim_end_matches(" ;");
        assert_eq!(enc(&t, text), w & !SCHED, "encode payload parity: {text}");
    }
}

/// INC/POPC UR-addressed anchor set (arb188 A_/B_ walk): decode == vendor.
const INC_CLUSTER: &[(u128, &str)] = &[
    (0x000fe8000d800004_00000c00ffff7f8c, "ATOMS.POPC.INC.32 RZ, [UR4+0xc]"),
    (0x000fe8000d800000_00000c00ffff7f8c, "ATOMS.POPC.INC.32 RZ, [UR0+0xc]"),
    (0x000fe8000d80003f_00000c00ffff7f8c, "ATOMS.POPC.INC.32 RZ, [UR63+0xc]"),
    (0x000fe8000d8000ff_00000c00ffff7f8c, "ATOMS.POPC.INC.32 RZ, [URZ+0xc]"),
    (0x000fe8000d800004_00000c0000ff7f8c, "ATOMS.POPC.INC.32 RZ, [R0+UR4+0xc]"),
    (0x000fe8000d800004_00000c0004ff7f8c, "ATOMS.POPC.INC.32 RZ, [R4+UR4+0xc]"),
    (0x000fe8000d800004_00000c0006ff7f8c, "ATOMS.POPC.INC.32 RZ, [R6+UR4+0xc]"),
    (0x000fe8000d800004_00001c00ffff7f8c, "ATOMS.POPC.INC.32 RZ, [UR4+0x1c]"),
    (0x000fe8000d800004_00121c00ffff7f8c, "ATOMS.POPC.INC.32 RZ, [UR4+0x121c]"),
    (0x000e24000c000004_00001c00ff00798c, "ATOMS.EXCH R0, [UR4+0x1c], R0"),
    (0x000e24000c0000ff_00001c00ff00798c, "ATOMS.EXCH R0, [URZ+0x1c], R0"),
];

#[test]
fn t188_3_inc_popc_cluster_decode_vendor_exact() {
    let t = t120();
    let idx = DecodeIndex::build(&t);
    for (w, want) in INC_CLUSTER {
        let got = dec(&t, &idx, *w);
        assert_eq!(&got, want, "INC/POPC cluster parity for {w:#034x}");
    }
}

/// bit32=1 on a residue-row shape must not fold into the sink numeral:
/// text is the base form, re-encode diff isolates exactly bit32 (!rsd law
/// of t148_5). Vendor (arb188 A_bit32): ignores the bit.
#[test]
fn t188_4_bit32_residual_not_folded_into_sink() {
    let poked: u128 = 0x000fe8000d800004_00000c01ffff7f8c; // A_popc ^ 1<<32
    let t = t120();
    let idx = DecodeIndex::build(&t);
    let got = dec(&t, &idx, poked);
    assert_eq!(got, "ATOMS.POPC.INC.32 RZ, [UR4+0xc]",
        "no R511 hallucination (bit32 fold): {got}");
    let reenc = enc(&t, &got);
    let delta = (poked ^ reenc) & !SCHED;
    assert_eq!(delta, 1u128 << 32, "only bit32 may be unexplained: {delta:#036x}");
}

/// Priority-audit watchtower: the rejected 142-era descriptor row for the
/// shared-atom INC/POPC family must not return silently. If it is ever
/// modeled again, it must LOSE decode to the AURI/ARURI rows for the
/// anchored plain forms (winner matrix work/bug188/winner188.json —
/// `dari` column): when present next to today's AURI it stole 14/14
/// vendor-true renders into fabricated `desc[UR4][RZ.64..]` text.
#[test]
fn t188_5_atoms_r_dari_inc_popc_not_modeled() {
    let t = t120();
    let present = t
        .get("ATOMS_R_dARI", "32,INC,POPC")
        .map(|_| ())
        .is_some();
    assert!(!present,
        "ATOMS_R_dARI['32,INC,POPC'] resurrected without re-arbitration — \
         see results/cubitfix/188.md sec.4 before unpinning (currently steals \
         decode from ATOMS_R_AURI, vendor-wrong desc[] render)");
}

/// Width watchtower scoped to the 188 class (t148_4 covers the whole table):
/// the 10 residue rows must stay at bits==8 with the f2-188 _src.
#[test]
fn t188_6_residue_rows_narrowed_with_attribution() {
    let t = t120();
    let expect = [
        ("ATOMS_R_ARI", "32,INC,POPC"),
        ("ATOMS_R_ARURI", "32,INC,POPC"),
        ("ATOMS_P_ARI_R_R", "CAST,SPIN"),
        ("ATOMS_P_ARI_R_R", "64,CAST,SPIN"),
        ("ATOM_P_R_ARI_R_R", "CAST,E,SPIN"),
        ("ATOM_P_R_ARI_R_R", "64,CAST,E,SPIN"),
        ("ATOMG_P_R_ARI_R", "ADD,E,F64,GPU,RN,STRONG"),
        ("REDG_dARI_R", "ADD,E,F64,GPU,RN,STRONG"),
        ("REDG_dARI_R", "64,E,GPU,MIN,STRONG"),
        ("REDG_dARI_R", "64,E,GPU,MAX,STRONG"),
    ];
    for (key, gn) in expect {
        let e = t.get(key, gn).unwrap_or_else(|| panic!("row {key}[{gn:?}] missing"));
        let w9 = e.fields.iter().filter(|f| {
            f.shift == 24 && f.bits == 9
                && matches!(f.extraction, Extraction::SubR(0) | Extraction::SubR(1))
        }).count();
        assert_eq!(w9, 0, "{key}[{gn:?}] re-widened to 9 bits");
        let w8 = e.fields.iter().filter(|f| {
            f.shift == 24 && f.bits == 8
                && matches!(f.extraction, Extraction::SubR(0) | Extraction::SubR(1))
        }).count();
        assert_eq!(w8, 1, "{key}[{gn:?}] lost the 8-bit sink field");
    }
}

//! BUG-173 (F2-iter82, front2/blind; queue = fleet note 167 sec.7(b)
//! "173-kand hygiene" + note 172 sec.7(c) "173/174 F2"): sm120
//! LDCU_UR_cARI shell-key hygiene (165-style recipe).
//!
//! Root: key LDCU_UR_cARI (4 group shells '','64','128','U8') describes a
//! geometry that is vendor-ILLEGAL -- LDCU with an R-shaped index.
//! Arbitration (nvdisasm 13.3.73 [cuda_13.3], work/bug173/arb/arb173.json):
//! 6/6 R-index probes (width 0,1,2,4,5,6 = bit91 flip of the LEGAL LDC
//! R-idx donor) -> "Unrecognized operation for functional unit 'uC'";
//! controls LEGAL: LDC.64/U8 R-idx, LDCU.64 UR-idx (cAURI, parked-152),
//! LDCU.64 non-idx.
//! Census-first (work/bug173/census173.json): shells carry no operand
//! fields for the index (2 fields: partial UR/imm); they loose-mask-match
//! 431k+ real vendor words of the NON-indexed LDCU_UR_cAI class (sentinel
//! idx byte 0xff @[24:32)) on hexdb 32.2M; corpus sm120 44 words matched.
//! Winner census (work/bug173/winner_census.json): 44/44 matched words are
//! decoded by the canonical LDCU_UR_cAI key => shell_wins = 0 (never-winner
//! on real populations, pre-remodel by mask); real corpus texts (2014 sm103
//! + 392 sm120 renders) never feed an LDCU R-index/UR-index form to the
//! encoder; encode of the R-index text form already fails (no idx field)
//! and decode of the synthetic probes is FAIL-CLOSED pre-fix.
//! Fix = data-only (work/bug173/patch173.py): DELETE key LDCU_UR_cARI.
//! Behavior change: zero on every real population (shell never won);
//! removes a fabrication hazard (loose shells with an ILLEGAL geometry
//! could start winning after any canonical-mask change).
//! Out of scope (documented): the LDCU.64_UR_cAI_II_II_? fabrication on
//! the LEGAL LDCU.64 UR-idx word (parked-152 cAURI remodel, pinned
//! pre==post in t173_5); 174-kand LDC-idx RZ-sentinel (separate class).
//! Compose: key disjoint from every parked patch (machine-checked).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;
fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    let d = idx.decode(w, 0, t).expect("decode");
    cubit::printer::to_sass(&d).split("/* @sched").next().unwrap().trim().to_string()
}
fn dec_res(idx: &DecodeIndex, w: u128, t: &IsaTable) -> bool { idx.decode(w, 0, t).is_ok() }
fn enc_res(t: &IsaTable, text: &str) -> bool {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).map(|w| w & !SCHED).is_ok()
}
fn w(hex: &str) -> u128 { u128::from_str_radix(hex, 16).unwrap() }

/// t173_1: the vendor-ILLEGAL-geometry key LDCU_UR_cARI is gone from the
/// table (4 shell groups '', '64', '128', 'U8' deleted).
#[test]
fn t173_1_key_absent() {
    let t = t120();
    assert!(t.entries.get("LDCU_UR_cARI").is_none(),
        "LDCU_UR_cARI must be deleted (vendor-ILLEGAL geometry, never-winner)");
    // canonical neighbors must stay:
    for k in ["LDCU_UR_cAI", "LDCU_UR_cAURI"] {
        assert!(t.entries.get(k).is_some(), "{k} must remain");
    }
}

/// t173_2: real vendor words that mask-matched the shells keep their exact
/// nvdisasm-13.3 render (won by canonical LDCU_UR_cAI) -- one per shell grp.
#[test]
fn t173_2_real_words_unchanged() {
    let t = t120(); let idx = DecodeIndex::build(&t);
    let cases = [
        ("000e6c00080008000000ae00ff0477ac", "LDCU UR4, c[0x0][0x570]"),      // shell ''
        ("000ea20008000a0000006b00ff0877ac", "LDCU.64 UR8, c[0x0][0x358]"),   // shell '64'
        ("000f620008000c0000008400ff1477ac", "LDCU.128 UR20, c[0x0][0x420]"), // shell '128'
        ("000e2200080000000000bc80ff0477ac", "LDCU.U8 UR4, c[0x0][0x5e4]"),   // shell 'U8'
    ];
    for (hw, want) in cases {
        assert_eq!(dec(&idx, w(hw), &t), want, "decode {hw}");
    }
}

/// t173_3: synthetic LDCU R-index probes (vendor-ILLEGAL, 6 widths) stay
/// decode fail-closed (no fabrication, pre == post behavior).
#[test]
fn t173_3_ridx_probes_fail_closed() {
    let t = t120(); let idx = DecodeIndex::build(&t);
    for hw in [
        "000e24000800080000c0000018187b82", // width=4 plain
        "000e240008000a0000c0000018187b82", // width=5 64
        "000e24000800000000c0000018187b82", // width=0 U8
        "000e240008000c0000c0000018187b82", // width=6 128 (new probe vs 167 round2)
        "000e24000800020000c0000018187b82", // width=1 S8
        "000e24000800040000c0000018187b82", // width=2 U16
    ] {
        assert!(!dec_res(&idx, w(hw), &t), "probe {hw} must stay fail-closed");
    }
}

/// t173_4: encode of the LDCU R-index text form stays fail-closed
/// (shells had no idx operand field: encode was already impossible).
#[test]
fn t173_4_encode_ridx_fail_closed() {
    let t = t120();
    assert!(!enc_res(&t, "LDCU.64 UR5, c[0x0][R5+0x258] ;"));
    assert!(!enc_res(&t, "LDCU UR4, c[0x0][R9] ;"));
    assert!(!enc_res(&t, "LDCU.U8 UR7, c[0x3][R12+0x10] ;"));
}

/// t173_5: parked-152 domain untouched -- decode of the LEGAL LDCU.64
/// UR-idx word keeps its pre-fix render verbatim (known pre-existing
/// fabrication via LDCU.64_UR_cAI_II_II_?; remodel = parked 152).
#[test]
fn t173_5_uridx_domain_parked152_unchanged() {
    let t = t120(); let idx = DecodeIndex::build(&t);
    let got = dec(&idx, w("000f220008000a0000004b00050577ac"), &t);
    assert_eq!(got, "LDCU.64 UR0, c[0x0][0x0], 0x0, 0x0, UR0",
        "parked-152 domain render must stay pre==post");
    // positive control: LEGAL non-indexed LDCU.64 keeps its canonical text:
    assert_eq!(dec(&idx, w("000ea20008000a0000006b00ff0877ac"), &t),
        "LDCU.64 UR8, c[0x0][0x358]");
}

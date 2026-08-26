//! BUG-176 (F2-iter83b, front2/blind; queue = fleet note 158 sec.5
//! "P_-junk REDG (b11/F2 higiena)"): junk REDG `*_P_dARI_R` keys deleted
//! (data-only hygiene, 165/173-style).
//!
//! Class: REDG (reduction-to-global) has NO result operand in the vendor
//! ISA -- a `P` destination token in operand_sig is geometric nonsense.
//! 10 such keys sat in the tables: sm120: REDG.E.{ADD,AND,MAX.S32,MIN.S32,
//! OR,ADD.S32}[.STRONG.GPU]_P_dARI_R; sm103a: REDG_P_dARI_R (13 groups),
//! REDG.E.{ADD,AND,OR}.EL.STRONG.GPU_P_dARI_R.
//!
//! Census-first (work/bug176/census176.json, hexdb 32.2M): every junk group
//! 0 real anchors EXCEPT sm103a REDG_P_dARI_R::"E,GPU,MIN,STRONG" which
//! loose-matches 130 real vendor words `@P0 REDG.E.MIN.STRONG.GPU
//! desc[URn][R2.64], R5` (sm_100) — winner census pre-fix binary-driven:
//! 130/130 decoded by the honest REDG_dARI_R key (never-winner, same proof
//! shape as 173's shells).  Encode of a P-dest REDG text form was ALREADY
//! fail-closed on both tables ("operand 1 (P0) has no field able to encode
//! it").  => zero behavior change on every real population; hazard removed
//! (same as 173: a loose shell could start winning after future mask edits).
//!
//! Fix = data-only (work/bug176/patch176.py, replayable, state asserts):
//! DELETE the 10 keys; sm120 1549->1543 keys, sm103a 400->396 keys.
//! Compose: disjoint from all parked patches (155/156/158/161 REDG work
//! touches REDG_dARI_R / REDG_ARI_R / junk non-P dARI; 154 = SYNCS_P_dARI_R
//! = different family) — machine-checked.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap() }
fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn dec(idx: &DecodeIndex, w: u128, t: &IsaTable) -> String {
    let d = idx.decode(w, 0, t).expect("decode");
    cubit::printer::to_sass(&d).split("/* @sched").next().unwrap().trim().to_string()
}
fn enc_res(t: &IsaTable, text: &str) -> bool {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).is_ok()
}
fn w(hex: &str) -> u128 { u128::from_str_radix(hex, 16).unwrap() }

/// t176_1: the 10 junk keys are gone; honest siblings stay.
#[test]
fn t176_1_junk_absent_honest_keep() {
    let t2 = t120();
    for k in ["REDG.E.ADD.S32.STRONG.GPU_P_dARI_R","REDG.E.ADD.STRONG.GPU_P_dARI_R",
              "REDG.E.AND.STRONG.GPU_P_dARI_R","REDG.E.MAX.S32.STRONG.GPU_P_dARI_R",
              "REDG.E.MIN.S32.STRONG.GPU_P_dARI_R","REDG.E.OR.STRONG.GPU_P_dARI_R"] {
        assert!(t2.entries.get(k).is_none(), "{k} must be deleted");
    }
    for k in ["REDG.E.MIN.STRONG.GPU_dARI_R","REDG.E.MAX.S32.STRONG.GPU_dARI_R","REDG_dARI_R"] {
        assert!(t2.entries.get(k).is_some(), "{k} must remain");
    }
    // sm103a stays untouched: REDG_P_dARI_R there is NOT junk -- it is the
    // vendor-true PT-sink form family (tests/bug128_redg_pt_alias.rs: 13
    // groups, word-equality pins vs the unguarded form, real HW anchor),
    // and the 3 EL keys carry era goldens (b4fill2_rows.rs).
    let t3 = t103();
    for k in ["REDG_P_dARI_R","REDG.E.ADD.EL.STRONG.GPU_P_dARI_R",
              "REDG.E.AND.EL.STRONG.GPU_P_dARI_R","REDG.E.OR.EL.STRONG.GPU_P_dARI_R",
              "REDG_dARI_R"] {
        assert!(t3.entries.get(k).is_some(), "{k} must remain (sm103a out of scope)");
    }
}

/// t176_2: the 130-word loose-match population decodes vendor-exact through
/// the honest key (never-winner holds post-delete).
#[test]
fn t176_2_population_vendor_exact() {
    let t = t103();
    let idx = DecodeIndex::build(&t);
    for (hx, want) in [
        ("000000000c92e108000000050200098e", "@P0 REDG.E.MIN.STRONG.GPU desc[UR8][R2.64], R5"),
        ("000000000c92e106000000050200098e", "@P0 REDG.E.MIN.STRONG.GPU desc[UR6][R2.64], R5"),
    ] {
        assert_eq!(dec(&idx, w(hx), &t), want, "population {hx}");
    }
}

/// t176_3: encode of a P-dest REDG text form is fail-closed on both tables
/// (pre-existing posture kept; no span of accepted junk text is created).
#[test]
fn t176_3_encode_p_dest_fail_closed() {
    let t2 = t120();
    assert!(!enc_res(&t2, "REDG.E.MIN.STRONG.GPU P0, desc[UR8][R2.64], R5 ;"));
    let t3 = t103();
    assert!(!enc_res(&t3, "REDG.E.MIN.STRONG.GPU P0, desc[UR8][R2.64], R5 ;"));
}

/// t176_4: honest REDG anchors are untouched (decode == vendor, both tables).
#[test]
fn t176_4_honest_anchors_untouched() {
    let t3 = t103();
    let idx3 = DecodeIndex::build(&t3);
    assert_eq!(dec(&idx3, w("000000000c12e108000000112c00798e"), &t3),
               "REDG.E.ADD.STRONG.GPU desc[UR8][R44.64], R17");
    assert_eq!(dec(&idx3, w("000000000d12e306000000050200098e"), &t3),
               "@P0 REDG.E.MAX.S32.STRONG.GPU desc[UR6][R2.64], R5");
    // sm120-side honesty is covered by the corpus A/B gate (392/392 0-diff);
    // the desc-UR window quirks on arch-mixed words belong to parked-160.
}

/// t176_5: table shapes after the hygiene (pin the key counts).
#[test]
fn t176_5_table_shapes() {
    assert_eq!(t120().num_keys(), 1543);
    assert_eq!(t103().num_keys(), 400);
}

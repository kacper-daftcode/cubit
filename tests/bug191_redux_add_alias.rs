//! BUG-191 (iter90, loop5/blind; queue item = "REDUX default-op census
//! (krzem b12, LOW, z BUG-132)", since 132.md sec.6).
//!
//! LAW (triple evidence, results/cubitfix/191.md):
//!   * ptxas-13.3.73 lowers redux.sync.add.u32 -> `REDUX.SUM`,
//!     redux.sync.and.b32 -> BARE `REDUX` (glyph-less = AND);
//!   * B300 silicon (work/i90/silicon/redux_op{0,1,2}.cubin, patched-op
//!     probes of the vendor REDUX.SUM word): op[78:81)=0 unique-attr
//!     [AND] on both discriminating patterns, 1=[OR], 2=[XOR], native
//!     3=[SUM] -- the [78:81) field IS AND/OR/XOR/SUM semantics;
//!   * corpus census (9,417 hexdb lanes, work/i90/silicon/redux_census.tsv)
//!     agrees 1:1 with the glyph<->opbity map for every anchored form.
//!   op: 0=AND(bare) 1=OR 2=XOR 3=SUM; bit73=.S32 (CREDUX base 72cc
//!   carries MIN=2/MAX=0 instead -- untouched here).
//!
//! Pre-fix defect (silent wrong-code, encode-side): `REDUX.ADD.U32` rode
//! MOD_DROP_TOLERATED and selected the "" row -> word op=0 -> hardware
//! computes AND where the author wrote ADD. nvdisasm arbitration of the
//! pre-fix product: `REDUX UR11, R10` (sic!). Now ADD is a real alias of
//! the SUM row.
//!
//! Neg-ctl: on main 2bd2a82 = mechanical 5F/1P: the tolerated set was
//! checked by SUBSET of {ADD,U32}, so bare `REDUX.ADD` and even
//! `REDUX.U32` also silently encoded the op=0 AND word pre-fix -- only
//! t191_6 (canonical byte-pins) passes on both sides.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t100() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm100a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}
fn enc_res(t: &IsaTable, text: &str) -> Result<u128, String> {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).map(|w| w & !SCHED).map_err(|e| e.to_string())
}
fn dec(t: &IsaTable, w: u128) -> String {
    let idx = DecodeIndex::build(t);
    let d = idx.decode(w, 0, t).expect("decode");
    let s = cubit::printer::to_sass(&d);
    s.split("/* @sched").next().unwrap().trim().to_string()
}
fn w(hex: &str) -> u128 {
    u128::from_str_radix(hex, 16).unwrap()
}

/// Vendor gold words, sched-masked (arbiter = nvdisasm-13.3.73 on the
/// ptxas-emitted cubin + in-place op-field patches, work/i90/silicon).
const W_SUM: &str = "0000c00000000000000673c4"; // `REDUX.SUM UR6, R0`
const W_AND: &str = "0000000000000000000673c4"; // bare `REDUX UR6, R0`
const W_OR: &str = "0000400000000000000673c4";  // `REDUX.OR UR6, R0`
const W_SUM32: &str = "0000c200000000000a0873c4"; // `REDUX.SUM.S32 UR8, R10`

/// t191_1: the alias encodes byte-exact to the vendor REDUX.SUM word.
#[test]
fn t191_1_add_alias_is_vendor_sum_word() {
    for t in [t103(), t100()] {
        assert_eq!(enc(&t, "REDUX.ADD.U32 UR6, R0"), w(W_SUM));
    }
}

/// t191_2: alias == direct SUM text, on every arch table carrying a SUM row.
#[test]
fn t191_2_alias_matches_direct_sum_text() {
    for t in [t103(), t100(), t120()] {
        assert_eq!(
            enc(&t, "REDUX.ADD.U32 UR6, R0"),
            enc(&t, "REDUX.SUM UR6, R0")
        );
    }
}

/// t191_3: the authored word decodes back as `REDUX.SUM` (vendor glyph).
#[test]
fn t191_3_alias_word_decodes_as_sum() {
    let t = t103();
    let word = enc(&t, "REDUX.ADD.U32 UR6, R0");
    assert_eq!(dec(&t, word), "REDUX.SUM UR6, R0");
    assert_eq!(dec(&t, w(W_SUM)), "REDUX.SUM UR6, R0");
}

/// t191_4: non-canonical ADD spellings stay fail-closed (no silent
/// broadening of the alias).
#[test]
fn t191_4_partial_add_forms_refused() {
    for t in [t103(), t120()] {
        for bad in ["REDUX.ADD UR6, R0", "REDUX.ADD.S32 UR6, R0", "REDUX.U32 UR6, R0"] {
            assert!(
                enc_res(&t, bad).is_err(),
                "expected fail-closed for {bad:?} on this table"
            );
        }
    }
}

/// t191_5: bug080 t5 compatibility — the guarded authored form still
/// encodes, and now produces the SUM semantics word (guard slot set),
/// not the op=0 AND word.
#[test]
fn t191_5_guarded_bug080_form_semantics() {
    let t = t103();
    let gw = enc(&t, "@P0 REDUX.ADD.U32 UR6, R0");
    assert_eq!(gw & !(0xFu128 << 12), w(W_SUM) & !(0xFu128 << 12));
    assert_ne!(gw & ((7u128) << 78), 0, "must not be the op=0 AND word");
    let dt = dec(&t, gw);
    assert!(dt.contains("REDUX.SUM"), "decode {dt:?}");
}

/// t191_6: canonical ops unchanged — bare=AND and OR byte-pinned to vendor
/// gold; XOR has no sm103a table row and stays fail-closed; the S32 sibling
/// word and both mod spellings pin the row.
#[test]
fn t191_6_canonical_ops_untouched() {
    let t = t103();
    assert_eq!(enc(&t, "REDUX UR6, R0"), w(W_AND));
    assert_eq!(enc(&t, "REDUX.OR UR6, R0"), w(W_OR));
    assert!(enc_res(&t, "REDUX.XOR UR6, R0").is_err());
    assert_eq!(enc(&t, "REDUX.SUM.S32 UR8, R10"), w(W_SUM32));
    assert_eq!(enc(&t, "REDUX.S32.SUM UR8, R10"), w(W_SUM32));
}

//! BUG-149 (iter70, front-main; BUG-147 sec.5 candidate): the five raw
//! uniform-indexed LDG mod groups of tables/sm103a.json
//! (LDG.E[|.64|.128|.EL.STRONG.GPU|.NA.STRONG.SM], addr_width U32) baked
//! byte [88:96) == 0x18 in and_base while every vendor witness carries 0x08.
//! Bit 92 has no field window and no variable_mask cover, so:
//!   - encode OR-polluted the payload ('LDG.E.64 R6, [RZ.U32+UR8]' emitted
//!     0x181e0b.. where vendor is 0x081e0b..; battery BUG-147 1-mismatch),
//!   - strict decode no-matched the vendor words, and the LDG.E.64/E ones
//!     were absorbed by the junk row LDG_R_ARURI::64,E (and_base == raw-word
//!     constants, sub_* field shape) whose ARURI printer path emits
//!     desc[URn][RZ.64] = fabricated descriptor semantics for raw words.
//!
//! Corpus census (work/i70): 10/10 vendor anchors byte11==0x08
//! (LDG.E x1, LDG.E.64 x8, LD.E x1); 8/8 matchers of the impersonator's
//! match-spec are raw words. nvdisasm-13.3 arbitration: synthetic fixed
//! words decode to the raw text for .64/.128/.EL/.NA incl. imm window
//! [40:64) ('+0x4000') and UR window [32:38); the polluted bit92=1 word
//! renders identically (renderer-visible don't-care) but nvcc never sets it.
//!
//! Fix (data-only, work/i70/patch149.py): and_base bit92 -> 0 on the five
//! raw rows; LDG_R_ARURI::64,E row deleted (encode never routed through it:
//! raw text -> LDG.E.64_R_ARURI via addr_width, desc text -> LDG_R_dARI).
//! All five rows get variable_mask bit92 set (era-variant window: 63 unique
//! bit92=1 era anchors in the frozen rt98/rc4 sm120 vendor cubins; decode of
//! the era words is pinned GOLD vendor-exact in tests/b4fill2_rows.rs).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

fn parts(lo: u64, hi32: u32) -> u128 { (lo as u128) | ((hi32 as u128) << 64) }

// Live corpus witnesses (hexdb 2014 cubins, F2-iter67 build): byte11 == 0x08.
const RAW_WITNESS: &[(u64, u32, &str)] = &[
    (0x00000004ff067981, 0x081e0b00, "LDG.E.64 R6, [RZ.U32+UR4]"),
    (0x00000008ff027981, 0x081e0b00, "LDG.E.64 R2, [RZ.U32+UR8]"),
    (0x00000008ff067981, 0x081e0b00, "LDG.E.64 R6, [RZ.U32+UR8]"),
    (0x00000004ff007981, 0x081e0900, "LDG.E R0, [RZ.U32+UR4]"),
    (0x00000004ff007980, 0x08100900, "LD.E R0, [RZ.U32+UR4]"),
];

// nvdisasm-13.3-arbitrated synthetic words (zero corpus witnesses):
// patched constants, decoded by nvdisasm to exactly these texts.
const SYNTH_WITNESS: &[(u64, u32, &str)] = &[
    (0x00000008ff067981, 0x081e0d00, "LDG.E.128 R6, [RZ.U32+UR8]"),
    (0x00000008ff067981, 0x082ee900, "LDG.E.EL.STRONG.GPU R6, [RZ.U32+UR8]"),
    (0x00000008ff067981, 0x085ea900, "LDG.E.NA.STRONG.SM R6, [RZ.U32+UR8]"),
    (0x0000400008ff067981, 0x081e0b00, "LDG.E.64 R6, [RZ.U32+UR8+0x4000]"),
    (0x0000000cff067981, 0x081e0b00, "LDG.E.64 R6, [RZ.U32+UR12]"),
    (0x00000008ff027981, 0x081e0b00, "LDG.E.64 R2, [RZ.U32+UR8]"),
    (0x0000000802067981, 0x081e0b00, "LDG.E.64 R6, [R2.U32+UR8]"),
];

#[test]
fn t149_1_witness_decode_vendor_exact() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (lo, hi32, want) in RAW_WITNESS.iter().chain(SYNTH_WITNESS) {
        let got = dec(&t, &idx, parts(*lo, *hi32));
        assert_eq!(&got, want, "raw-U32 decode must match vendor (no desc fabrication)");
        assert!(!got.contains("desc["), "desc fabrication regressed: {got}");
        assert!(!got.contains("!rsd"), "residue regressed: {got}");
    }
}

#[test]
fn t149_2_witness_encode_byte_exact() {
    let t = t103a();
    for (lo, hi32, text) in RAW_WITNESS.iter().chain(SYNTH_WITNESS) {
        assert_eq!(enc(&t, text), parts(*lo, *hi32), "encode parity: {text}");
    }
}

#[test]
fn t149_3_desc_space_untouched() {
    // The descriptor form is a different bit space (byte11 == 0x0c, byte9|0x10):
    // LDG_R_dARI owns it; the fix must not steal or shadow any of it (268k
    // corpus anchors, byte11==0x0c on 100% of desc words).
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let (lo, hi32) = (0x00000008_02067981u64, 0x0c1e1b00u32);
    let got = dec(&t, &idx, parts(lo, hi32));
    assert_eq!(got, "LDG.E.64 R6, desc[UR8][R2.64]");
    assert_eq!(enc(&t, "LDG.E.64 R6, desc[UR8][R2.64]"), parts(lo, hi32));
    // and with an immediate in [40:64)
    let (lo2, _hi2) = (0x00010008_02067981u64, 0x0c1e1b00u32);
    assert_eq!(dec(&t, &idx, parts(lo2, 0x0c1e1b00)), "LDG.E.64 R6, desc[UR8][R2.64+0x100]");
    assert_eq!(enc(&t, "LDG.E.64 R6, desc[UR8][R2.64+0x100]"), parts(lo2, 0x0c1e1b00));
}

#[test]
fn t149_4_bit92_era_variant_roundtrip() {
    // Bit92 is an arch/era variant: sm120-nvcc vendor words carry 1 (63 unique
    // era anchors in the frozen rt98/rc4 cubins, pinned GOLD in
    // tests/b4fill2_rows.rs), sm_100/103-nvcc carry 0 (10/10 hexdb anchors).
    // Decode must accept BOTH and print the same raw text; encode emits the
    // arch-canonical 0; the !rsd[92:1] overlay carries the era bit so the
    // text round-trip stays byte-exact.
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let era = parts(0x00000008ff067981u64, 0x181e0b00u32);
    let got = dec(&t, &idx, era);
    assert_eq!(got, "LDG.E.64 R6, [RZ.U32+UR8]");
    assert_eq!(enc(&t, &got), parts(0x00000008ff067981, 0x081e0b00),
               "canonical encode = nvcc sm103 byte (bit92=0)");
    let overlay = enc(&t, "LDG.E.64 R6, [RZ.U32+UR8] !rsd[92:1]");
    assert_eq!(overlay, era, "rsd overlay must reproduce the era word");
}

#[test]
fn t149_5_table_class_invariants() {
    let t = t103a();
    // impersonator removed from the decode surface
    let aruri = t.entries.get("LDG_R_ARURI").expect("LDG_R_ARURI key");
    assert!(!aruri.mod_groups.contains_key("64,E"),
            "LDG_R_ARURI::64,E impersonator regressed");
    assert!(aruri.mod_groups.contains_key("E"), "LDG_R_ARURI::E (aw=64) must stay");
    // all five raw rows: bit92 clear, addr_width kept, ureg+imm fields intact
    for (key, mg) in [
        ("LDG.E_R_ARURI", "E"),
        ("LDG.E.64_R_ARURI", "64,E"),
        ("LDG.E.128_R_ARURI", "128,E"),
        ("LDG.E.EL.STRONG.GPU_R_ARURI", "E,EL,GPU,STRONG"),
        ("LDG.E.NA.STRONG.SM_R_ARURI", "E,NA,SM,STRONG"),
    ] {
        let g = t.entries.get(key).unwrap().mod_groups.get(mg).unwrap();
        assert_eq!(g.and_base & (1u128 << 92), 0, "{key}::{mg} bit92 set");
        assert_ne!(g.variable_mask & (1u128 << 92), 0,
                   "{key}::{mg} vm92 era-window removed");
        let exts: Vec<String> = g.fields.iter().map(|f| format!("{:?}", f.extraction)).collect();
        assert!(exts.iter().any(|e| e == "UReg"), "{key}::{mg} lost ureg");
        assert!(exts.iter().any(|e| e.starts_with("Imm") || e == "Imm"), "{key}::{mg} lost imm");
    }
    // STG-side raw rows were already correct (0x08) and must stay untouched
    let stg = t.entries.get("STG.E.64_ARURI_R").unwrap().mod_groups.get("64,E").unwrap();
    assert_eq!((stg.and_base >> 88) & 0xff, 0x08);
    // era anchors used above were rt98 KernelB (sm120 vendor) words
}

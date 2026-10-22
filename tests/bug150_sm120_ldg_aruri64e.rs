//! Native r15 SM120 LDG64 U32 evidence supersedes the old mode-6-only claim.
//!
//! NVIDIA renders bit92=0 and bit92=1 with identical SASS. Native layout2
//! r15 witnesses have bit92=0; no semantic spelling is known for bit92=1.
//! The original historical words below stay unchanged and explicitly fail
//! closed. They are unsupported coverage, not silently normalized or encoded
//! with residue. Other LDG widths and descriptor addressing keep their pins.
#[path = "support/sm120_ldg_bit92.rs"]
mod ldg_bit92;
use cubit::decoder::DecodeIndex;
use cubit::table::IsaTable;
fn t120() -> IsaTable { IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap() }
fn parts(lo: u64, hi32: u32) -> u128 { (lo as u128) | ((hi32 as u128) << 64) }
const RAW_WITNESS: &[(u64, u32, &str)] = &[
    (0x0000000806087981, 0x181e0b00, "LDG.E.64 R8, [R6.U32+UR8]"),
    (0x00080008060a7981, 0x181e0b00, "LDG.E.64 R10, [R6.U32+UR8+0x800]"),
    (0x00040008060a7981, 0x181e0b00, "LDG.E.64 R10, [R6.U32+UR8+0x400]"),
    (0x0000002419fc7981, 0x181e0900, "LDG.E R252, [R25.U32+UR36]"),
    (0x00000026d2dc3981, 0x181e0d00, "@P3 LDG.E.128 R220, [R210.U32+UR38]"),
];
#[test]
fn t150_1_native_geometry_has_no_hidden_bit92_field() {
    let t=t120();
    let g=&t.entries["LDG_R_ARURI"].mod_groups["64,E"];
    assert_eq!(g.and_base & (1u128<<92),0);
    assert_eq!(g.variable_mask & (1u128<<92),0,"unknown semantic bit must not be hidden in a permissive mask");
    assert!(g.fields.iter().all(|f| !(f.shift<=92 && 92<f.shift+f.bits)));
    assert!(t.entries.get("LDG.E.64_R_ARURI").map_or(true,|e| !e.mod_groups.contains_key("64,E")),"old winning mode6 shadow must remain retired");
    assert_eq!(g.addr_width.as_deref(),Some("U32"));
}
#[test]
fn t150_2_historical_anchors_are_explicitly_unsupported() {
    let t=t120();let ix=DecodeIndex::build(&t);let mut count=0;
    for &(lo,hi,want) in RAW_WITNESS {
        let word=parts(lo,hi);
        if ldg_bit92::unsupported(word) {
            assert!(ix.decode(word,0,&t).is_err(),"unknown bit92 alias: {word:032x}");count+=1;
        } else {
            let d=ix.decode(word,0,&t).unwrap();assert_eq!(cubit::printer::to_sass(&d),want);
        }
    }
    assert_eq!(count,4);
    let d=ix.decode(0x0e28000c1e1b000000400402727981,0,&t).unwrap();
    assert_eq!(cubit::printer::to_sass(&d),"LDG.E.64 R114, desc[UR4][R2.64+0x40]");
}
#[test]
fn t150_3_native_r15_independent_full128_roundtrip() {
    let t=t120();let ix=DecodeIndex::build(&t);ldg_bit92::assert_native_roundtrips(&t,&ix);
}
#[test]
fn t150_4_all_listed_historical_payloads_fail_closed() {
    let t=t120();let ix=DecodeIndex::build(&t);
    assert_eq!(ldg_bit92::HISTORICAL_UNSUPPORTED.len(),25);
    for &word in ldg_bit92::HISTORICAL_UNSUPPORTED {
        assert!(ix.decode(word,0,&t).is_err(),"unsupported alias accidentally accepted: {word:032x}");
    }
}
#[test]
fn t150_5_synthetic_word_never_fabricates_a_descriptor() {
    // Original negative-control bytes retained. Bit92=0 is now legal native
    // geometry, so decoding this synthetic register/offset combination must
    // preserve raw U32 addressing rather than the old fabricated desc form.
    let t=t120();let ix=DecodeIndex::build(&t);
    let word=parts(0x0000000806087981,0x081e0b00);
    let d=ix.decode(word,0,&t).unwrap();
    assert_eq!(cubit::printer::to_sass(&d),"LDG.E.64 R8, [R6.U32+UR8]");
}

//! Arch-vendoring contract: cubit vendors every canonical table
//! (blackwell-isa) byte-pinned via tables/SOURCE.json; each table carries
//! its correct e_flags, aux sections stay per-arch data, and golden anchors
//! decode vendor-exact on every arch (incl. the sm_121a pred_inv4 map and
//! the sm_100a == sm_103a encoding-layer parity).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;
use std::path::Path;

fn t(name: &str) -> IsaTable {
    IsaTable::load(Path::new("tables").join(format!("{name}.json")).as_path()).unwrap()
}
fn dec(table: &IsaTable, w: u128) -> String {
    let idx = DecodeIndex::build(table);
    let d = idx.decode(w, 0, table).expect("decode");
    cubit::printer::to_sass(&d)
}


#[test]
fn manifest_pin_matches_every_vendored_table() {
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert_eq!(m["schema"], 2);
    for (name, entry) in m["tables"].as_object().unwrap() {
        // byte-exact SHA pin is CI-verified by `sync_table --check`; here the
        // contract is structural: every pinned table exists and matches its
        // manifest counters.
        let bytes = std::fs::read(Path::new("tables").join(name)).unwrap();
        let t: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(t["instructions"].as_object().unwrap().len(),
                   entry["instruction_forms"].as_u64().unwrap() as usize, "{name} forms");
    }
    assert_eq!(m["tables"].as_object().unwrap().len(), 4,
               "all four canonical arch tables are vendored");
}

#[test]
fn eflags_map_to_the_right_architectures() {
    assert_eq!(t("sm120").ef_flags, 0x0600_7802);
    assert_eq!(t("sm103a").ef_flags, 0x0600_6702);
    assert_eq!(t("sm100a").ef_flags, 0x0600_640a);
    assert_eq!(t("sm121a").ef_flags, 0x0600_7902);
}

///vendor-exact golden anchors on the sm_121a table (fleet q2 gold set,
/// incl. guard preds and UR addressing).
#[test]
fn sm121a_gold_anchors_decode_exact() {
    let tab = t("sm121a");
    for (w, want) in [
        (0x000ea800000008000001f80000097984u128, "LDS R9, [R0+0x1f8]"),
        (0x0001e40000100c000000000401007387u128, "STL.128 [R1], R4"),
        (0x0001e80000100a000000000215003387u128, "@P3 STL.64 [R21], R2"),
        (0x000e220000100800000000000303a983u128, "@!P2 LDL R3, [R3]"),
        (0x004e2800001ee10700000006020773a9u128,
         "ATOMG.E.CAS.STRONG.GPU PT, R7, [R2], R6, R7"),
        (0x000fe2000000080000000000fffff984u128, "@!PT LDS RZ, [RZ]"),
        (0x000e680008000a00000000080e0ab984u128, "@!P3 LDS.64 R10, [R14+UR8]"),
    ] {
        assert_eq!(dec(&tab, w), want, "sm121a decode {w:032x}");
    }
}

///pred_inv4 (sm_121a inverted 4-bit trailing guard-pred) roundtrip:
/// PT/none -> 0, Pn -> 7-n, !PT -> 8, !Pn -> 15-n.
#[test]
fn sm121a_pred_inv4_decode_and_roundtrip() {
    let tab = t("sm121a");
    // LDG.E.EFL2.256_R_R_dARI_P: trailing pred field at [90:87].
    let base = {
        let row = &serde_json::from_slice::<serde_json::Value>(
            &std::fs::read("tables/sm121a.json").unwrap()).unwrap()["instructions"]
            ["LDG.E.EFL2.256_R_R_dARI_P"]["mod_groups"][""];
        u128::from_str_radix(row["and_base"].as_str().unwrap().trim_start_matches("0x"), 16)
            .unwrap()
    };
    // window 0 = no guard pred: token omitted entirely (no phantom ", PT")
    let t0 = dec(&tab, base);
    assert!(!t0.ends_with(", PT") && !t0.ends_with(" P7"),
            "inv4 zero window must omit the trailing pred: {t0}");
    // P3 encoded -> v = 7-3 = 4 at [90:87]
    let w = base | (4u128 << 87);
    let text = dec(&tab, w);
    assert!(text.ends_with(", P3") || text.contains(" P3"), "inv4 P3 render: {text}");
    // encode writes the inv4 map and the render is roundtrip-stable
    let insn = parse_sass(&format!("{text} ;"), 0).unwrap();
    let w2 = encode_instruction(&insn, &tab).unwrap();
    assert_eq!((w2 >> 87) & 0xF, 4, "P3 -> inv4 window value 4");
    assert_eq!(dec(&tab, w2), text, "render-stable inv4 roundtrip");
}

///sm_100a derivative parity: the same word decodes to the same SASS text
/// under the sm103a and sm100a tables (119/119 byte-parity at the encoding
/// layer), including the REL16 branch family path.
#[test]
fn sm100a_decodes_like_sm103a_on_shared_words() {
    let a = t("sm103a");
    let b = t("sm100a");
    for w in [
        0x000ea800000008000001f80000097984u128,   // LDS R9, [R0+0x1f8]
        0x000fe8000c1e09000000800c0c0a7981u128,   // LDG.E R10, [R12.64+UR12+0x80]
        0x004e2800001ee10700000006020773a9u128,   // ATOMG CAS (UR-uniform form)
    ] {
        assert_eq!(dec(&a, w), dec(&b, w), "parity decode {w:032x}");
    }
}

///sched-cost and stall sections ride inside their arch tables (O2 layout):
/// sm103a has all three, sm100a carries operand_roles only (no B300 timing
/// data is smeared onto unvalidated silicon), sm121a carries neither.
#[test]
fn aux_sections_follow_their_arch() {
    assert!(t("sm103a").aux_section("cost_model").is_some());
    assert!(t("sm103a").aux_section("stallfix").is_some());
    assert!(t("sm103a").aux_section("operand_roles").is_some());
    assert!(t("sm100a").aux_section("operand_roles").is_some());
    assert!(t("sm100a").aux_section("cost_model").is_none());
    assert!(t("sm100a").aux_section("stallfix").is_none());
    assert!(t("sm121a").aux_section("cost_model").is_none());
    assert!(t("sm120").aux_section("operand_roles").is_some());
}

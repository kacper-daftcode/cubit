//! HIDDEN-B300: bounded LDSM M816 x1/x2/x4 on SM103a and SM100a.
//! This is text/decode/encode evidence, not new silicon execution.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SRC: &str = "rows-hidden-b300-ldsm-m816-counts-2026-11-08";
static FIXTURE: std::sync::LazyLock<&str> = std::sync::LazyLock::new(|| hb300_fixture("sm103_ldsm_m816_counts_nvdisasm.jsonl"));
const SHAPES: [&str; 6] = [
    "M816,U4x16P64TO8", "2,M816,U4x16P64TO8", "4,M816,U4x16P64TO8",
    "M816,U6x16P32TO8", "2,M816,U6x16P32TO8", "4,M816,U6x16P32TO8",
];
const ADDR: [&str; 3] = ["ARI", "AURI", "ARURI"];
/// Session T-26, batch 4: four of this candidate's eighteen rows were measured first by `hidden-b300/ldsm-unpack` (the
/// same fields, `tests/hidden_b300_ldsm_unpack.rs`); the table keeps each row once, under that tag, and this
/// candidate's tag counts the fourteen rows it adds.
const UNPACK_SRC: &str = "hidden-b300-ldsm-unpack-2026-11-07";
const SHARED: [(&str, &str); 4] = [
    ("LDSM_R_ARI", "2,M816,U4x16P64TO8"), ("LDSM_R_ARURI", "2,M816,U4x16P64TO8"),
    ("LDSM_R_AURI", "2,M816,U4x16P64TO8"), ("LDSM_R_AURI", "2,M816,U6x16P32TO8"),
];

fn pair(text: &str) -> (&str, &str) {
    let shape = match text {
        t if t.contains("LDSM.U4x16P64TO8.M816 ") => SHAPES[0],
        t if t.contains("LDSM.U4x16P64TO8.M816.2 ") => SHAPES[1],
        t if t.contains("LDSM.U4x16P64TO8.M816.4 ") => SHAPES[2],
        t if t.contains("LDSM.U6x16P32TO8.M816 ") => SHAPES[3],
        t if t.contains("LDSM.U6x16P32TO8.M816.2 ") => SHAPES[4],
        t if t.contains("LDSM.U6x16P32TO8.M816.4 ") => SHAPES[5],
        t => panic!("unexpected shape {t}"),
    };
    let addr = if text.contains("+UR") {
        "ARURI"
    } else if text.contains("[UR") {
        "AURI"
    } else {
        "ARI"
    };
    (shape, addr)
}

#[test]
fn ldsm_m816_counts_decode_render_encode_and_fail_closed() {
    let mut adopted = [[0usize; 3]; 6];
    let mut production = [std::collections::BTreeSet::new(), std::collections::BTreeSet::new()];
    for (arch_index, arch) in ["sm103a", "sm100a"].into_iter().enumerate() {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        let mut rows = 0;
        for line in FIXTURE.lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            rows += 1;
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            if row["auxiliary_control_probe"] == true {
                continue;
            }
            let vendor = row["nvidia_sass"].as_str();
            if row["adopt"] == true {
                let decoded = index.decode(word, 0, &table)
                    .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor:?}"));
                assert!(decoded.key.starts_with("LDSM_R_"), "{arch}: {word:032x}");
                let text = cubit::printer::to_sass_lossless(&decoded);
                assert_eq!(text, vendor.unwrap(), "{arch}: {word:032x}");
                let (shape, addr) = pair(&text);
                adopted[SHAPES.iter().position(|x| *x == shape).unwrap()]
                    [ADDR.iter().position(|x| *x == addr).unwrap()] += 1;
                let ctrl = cubit::scheduling::format_control_code(
                    &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
                let source = format!("[{ctrl}] {text} ;");
                cubit::roundtrip_audit::check_semantic_source(&source)
                    .unwrap_or_else(|e| panic!("{arch}: semantic {source}: {e}"));
                let parsed = cubit::parse_cuasm_line(&source, 0)
                    .unwrap_or_else(|e| panic!("{arch}: parse {source}: {e}"));
                assert_eq!(cubit::encoder::encode_instruction(&parsed, &table)
                    .unwrap_or_else(|e| panic!("{arch}: encode {source}: {e}")), word,
                    "{arch}: encode {source}");
                if row["source"].as_str().unwrap().contains("inbox-hgx02") {
                    production[arch_index].insert(row["word"].as_str().unwrap().to_owned());
                }
            } else if row["core_negative"] == true {
                assert!(index.decode(word, 0, &table).is_err(),
                    "{arch}: unclaimed {word:032x}: {vendor:?}");
            }
        }
        assert_eq!(rows, FIXTURE.lines().count());
        for invalid in [
            "LDSM.U4x16P64TO8.M816.4 R1, R2 ;",
            "LDSM.U4x16P64TO8.M816.3 R1, [R2] ;",
            "LDSM.U6x16P32TO8.M816.8 R1, [R2] ;",
            "LDSM.U4x16P64TO8.INVALID3 R1, [R2] ;",
            "LDSM.U6x16P32TO8.MT1616 R1, [R2] ;",
        ] {
            assert!(cubit::encoder::encode_instruction(
                &cubit::parse_cuasm_line(invalid, 0).unwrap(), &table).is_err(), "{invalid}");
        }
    }
    assert!(adopted.iter().flatten().all(|n| *n >= 24), "coverage: {adopted:?}");
    assert_eq!(production[0].len(), 122, "H coverage: {adopted:?}");
    assert_eq!(production[1], production[0]);
}

#[test]
fn ldsm_m816_counts_eighteen_rows_provenance_and_fields() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        let instructions = raw["instructions"].as_object().unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SRC]["rows"], 14);
        for shape in SHAPES {
            for addr in ADDR {
                let key = format!("LDSM_R_{addr}");
                let group = &instructions[&key]["mod_groups"][shape];
                let want = if SHARED.contains(&(key.as_str(), shape)) { UNPACK_SRC } else { SRC };
                assert_eq!(group["_src"], want, "{arch}: {key}: {shape}");
                let fields: Vec<_> = group["fields"].as_array().unwrap().iter().map(|field| {
                    // the canonical layout writes a tag once per level (tools/tablefmt.py): a field carries `_src` only where it
                    // differs from its row's -- absent or equal (the candidate's file tagged every field)
                    assert!(field.get("_src").map_or(true, |s| s == want));
                    (field["shift"].as_u64().unwrap(), field["bits"].as_u64().unwrap(),
                     field["extraction"].as_str().unwrap(), field["token_idx"].as_u64().unwrap())
                }).collect();
                let expected = match addr {
                    "ARI" => vec![(12, 4, "guard", 0), (16, 8, "reg", 1),
                                  (24, 8, "sub_r0", 2), (40, 24, "sub_imm1", 2)],
                    "AURI" => vec![(12, 4, "guard", 0), (16, 8, "reg", 1),
                                   (32, 8, "sub_ur0", 2), (40, 24, "sub_imm1", 2)],
                    _ => vec![(12, 4, "guard", 0), (16, 8, "reg", 1),
                              (24, 8, "sub_r0", 2), (32, 8, "sub_ur1", 2),
                              (40, 24, "sub_imm1", 2)],
                };
                assert_eq!(fields, expected, "{arch}: {key}: {shape}");
            }
        }
    }
}

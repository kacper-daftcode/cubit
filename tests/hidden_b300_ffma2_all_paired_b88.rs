//! Measured production all-paired FFMA2 and bit88 mapping; CPU only, no GPU.
include!("hb300_fixture.inc");
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| {
    [
        (
            "sm103a",
            hb300_fixture("sm103a_ffma2_all_paired_b88_nvdisasm.jsonl"),
        ),
        (
            "sm100a",
            hb300_fixture("sm100a_ffma2_all_paired_b88_nvdisasm.jsonl"),
        ),
    ]
});

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| {
        ARCHES
            .iter()
            .map(|(arch, _)| {
                let table =
                    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
                let index = DecodeIndex::build(&table);
                (table, index)
            })
            .collect()
    })
}

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn rows(arch: &str, role: &str) -> Vec<Value> {
    let fixture = &ARCHES[usize::from(arch == "sm100a")].1;
    fixture
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|row: &Value| row["role"] == role)
        .collect()
}

fn check_word(row: &Value, arch: &str) {
    let word = hex(&row["word"]);
    let text = row["nvidia_sass"].as_str().unwrap();
    let (table, index) = &tables()[usize::from(arch == "sm100a")];
    let decoded = index
        .decode(word, 0, table)
        .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
    assert_eq!(
        (decoded.key.as_str(), decoded.mod_group.as_str()),
        ("FFMA2_R_R_R_R", ""),
        "{arch} {word:032x}"
    );
    assert_eq!(
        cubit::printer::to_sass(&decoded),
        text,
        "{arch} {word:032x}"
    );
    assert_eq!(
        cubit::printer::to_sass_lossless(&decoded),
        text,
        "{arch} {word:032x}"
    );
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    if row["role"] == "production_text" {
        // Vendor-text-inert low-word bits are evidence, not encodable fields.
        // They must not be promoted merely to force a whole-word roundtrip.
        return;
    }
    let actual = cubit::encoder::encode_instruction(&parsed, table).unwrap();
    let expected = word & !(7u128 << 125);
    assert_eq!(
        actual,
        expected,
        "{arch} {}: xor={:032x}; bit88 must be multiplier token3 shape",
        row["word"].as_str().unwrap(),
        actual ^ expected
    );
}

#[test]
fn production_text_and_canonical_words_roundtrip() {
    for (arch, _) in ARCHES.iter() {
        let mut fixture_rows = rows(arch, "adopt");
        fixture_rows.extend(rows(arch, "production_text"));
        let production = fixture_rows
            .iter()
            .filter(|row| row["generation"] == "production")
            .count();
        assert!(production > 0, "{arch}: H production witnesses");
        for row in &fixture_rows {
            check_word(row, arch);
        }
    }
}

#[test]
fn independent_multiplier_shape_cross_roundtrip() {
    for (arch, _) in ARCHES.iter() {
        let rows = rows(arch, "shape_roundtrip");
        assert!(
            rows.iter().any(|row| row["label"] == "ra-b-shape-cross:10"),
            "{arch}: scalar Ra + scalar multiplier falsifies token2 mapping"
        );
        for row in &rows {
            check_word(row, arch);
        }
    }
}

#[test]
fn measured_row_provenance_and_field_mapping() {
    const SOURCE: &str = "engine-l1a-ffma2-shapes-2026-11-13";
    for (arch, _) in ARCHES.iter() {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 1);
        let entry = &raw["instructions"]["FFMA2_R_R_R_R"];
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 1);
        let group = &entry["mod_groups"][""];
        assert_eq!(group["_src"], SOURCE);
        assert_eq!(
            hex(&group["and_base"]),
            0x00000000000000000000000000000249u128
        );
        assert_eq!(
            hex(&group["variable_mask"]),
            0x1c000000012e0fffc00000fffffff000u128
        );
        let fields = group["fields"].as_array().unwrap();
        let bit88: Vec<_> = fields.iter().filter(|field| field["shift"] == 88).collect();
        assert_eq!(bit88.len(), 1);
        assert_eq!(
            (
                bit88[0]["extraction"].as_str(),
                bit88[0]["token_idx"].as_i64(),
                bit88[0]["bits"].as_u64()
            ),
            (Some("opmod:F32"), Some(3), Some(1))
        );
        assert_eq!(
            bit88[0]
                .get("_src")
                .or_else(|| group.get("_src"))
                .and_then(Value::as_str),
            Some(SOURCE)
        );
        assert!(!fields
            .iter()
            .any(|field| field["shift"] == 88 && field["extraction"] == "opmod:F32x2"));
    }
}

#[test]
fn legacy_fields_and_non_b300_tables_stay_scoped() {
    for arch in ["sm103a", "sm100a"] {
        let raw: Value = serde_json::from_slice(
            &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap(),
        )
        .unwrap();
        let fields = raw["instructions"]["FFMA2_R_R_R_R"]["mod_groups"][""]["fields"]
            .as_array()
            .unwrap()
            .clone();
        let fields: Vec<_> = fields
            .iter()
            .map(|field| {
                (
                    field["shift"].as_u64().unwrap(),
                    field["token_idx"].as_u64().unwrap(),
                    field["extraction"].as_str().unwrap(),
                )
            })
            .filter(|field| field.0 != 88)
            .collect();
        assert_eq!(
            fields,
            vec![
                (12, 0, "guard"),
                (16, 1, "reg"),
                (24, 2, "reg"),
                (72, 2, "neg"),
                (73, 2, "abs"),
                (81, 2, "opmod:LO_HI"),
                (82, 2, "opmod:F32"),
                (83, 2, "opmod:NP"),
                (122, 2, "reuse"),
                (32, 3, "reg"),
                (62, 3, "abs"),
                (63, 3, "neg"),
                (123, 3, "reuse"),
                (64, 4, "reg"),
                (74, 4, "abs"),
                (75, 4, "neg"),
                (85, 4, "opmod:F32"),
                (124, 4, "reuse"),
            ]
        );
    }
    let sm120: Value = serde_json::from_slice(
        &cubit::table::read_table_bytes(std::path::Path::new("tables/sm120.json")).unwrap(),
    )
    .unwrap();
    let fields = sm120["instructions"]["FFMA2_R_R_R_R"]["mod_groups"][""]["fields"]
        .as_array()
        .unwrap();
    assert!(
        fields.iter().any(|field| field["shift"] == 88
            && field["token_idx"] == 2
            && field["extraction"] == "opmod:F32x2"),
        "SM120 donor was deliberately not rewritten by this B300-only repair"
    );
}

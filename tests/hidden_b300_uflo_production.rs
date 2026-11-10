//! Complete-word UFLO UR,UR measurements; no uniform execution semantic claim.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{collections::BTreeSet, sync::OnceLock};

const SOURCE: &str = "rows-uflo-production-2026-11-08";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    ("sm103a", hb300_fixture("sm103a_uflo_production_nvdisasm.jsonl")),
    ("sm100a", hb300_fixture("sm100a_uflo_production_nvdisasm.jsonl")),
]);

fn tables() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static TABLES: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    TABLES.get_or_init(|| ARCHES.iter().map(|(arch, _)| {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    }).collect())
}

fn rows(fixture: &str) -> impl Iterator<Item=Value> + '_ {
    fixture.lines().map(|line| serde_json::from_str(line).unwrap())
}

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn encode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).unwrap()
}

#[test]
fn measured_production_and_all_four_modifier_groups_roundtrip() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let mut production = 0usize;
        let mut bases = BTreeSet::new();
        let mut positive_by_group = [0usize; 4];
        let group_index = |group: &str| match group {
            "" => 0, "U32" => 1, "SH" => 2, "SH,U32" => 3,
            other => panic!("unexpected modifier group {other}"),
        };
        for row in rows(fixture) {
            if row["kind"] != "positive" { continue; }
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let group = row["mod_group"].as_str().unwrap();
            positive_by_group[group_index(group)] += 1;
            if row["generation"] == "production" { production += 1; }
            if row["generation"] == "base" { bases.insert(group.to_owned()); }
            let decoded = index.decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {word:032x}: {error}"));
            assert_eq!(decoded.key, "UFLO_UR_UR", "{arch} {word:032x}");
            assert_eq!(decoded.mod_group, group, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text, "{arch} {word:032x}");
            assert_eq!(cubit::printer::to_sass(&decoded), text, "{arch} {word:032x}");
            assert_eq!(encode(table, word, text), word & !(7u128 << 125));
        }
        assert_eq!(production, 10, "{arch}: stored production witnesses");
        assert_eq!(bases, ["", "SH", "SH,U32", "U32"].into_iter().map(str::to_owned).collect());
        assert_eq!(positive_by_group, [527, 527, 527, 537],
                   "{arch}: 10 production plus four complete measured modifier groups");

        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(
            std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 4);
        let entry = &raw["instructions"]["UFLO_UR_UR"];
        assert_eq!(entry["_src"], SOURCE);
        assert_eq!(entry["operand_sig"], "UR_UR");
        assert_eq!(entry["scheduling"]["latency_source"], "synthetic");
        assert_eq!(entry["mod_groups"].as_object().unwrap().len(), 4);
        for group in ["", "U32", "SH", "SH,U32"] {
            let value = &entry["mod_groups"][group];
            assert_eq!(value["_src"], SOURCE);
            assert!(positive_by_group[group_index(group)] > 0);
            assert_eq!(hex(&value["and_base"]) >> 96, 0);
            let fields = value["fields"].as_array().unwrap();
            assert_eq!(&fields[..4], &serde_json::json!([
                {"bits":4,"extraction":"guard","shift":12,"token_idx":0},
                {"bits":8,"extraction":"ureg_ff","shift":16,"token_idx":1},
                {"bits":8,"extraction":"ureg_ff","shift":32,"token_idx":2},
                {"bits":1,"extraction":"inv","shift":63,"token_idx":2},
            ]).as_array().unwrap()[..], "{arch} {group}");
            for field in &fields[4..] {
                assert_eq!(field["extraction"], "reuse");
                assert_eq!(field["token_idx"], 2);
            }
        }
    }
}

#[test]
fn unlicensed_words_and_reuse_do_not_enter_uflo() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, index) = &tables()[index];
        let mut negative = 0usize;
        let mut adjacent = 0usize;
        let mut other = 0usize;
        let mut control = 0usize;
        let mut refused_reuse = 0usize;
        for row in rows(fixture) {
            let kind = row["kind"].as_str().unwrap();
            if matches!(kind, "positive" | "control_plane") {
                control += usize::from(kind == "control_plane");
                continue;
            }
            let word = hex(&row["word"]);
            if let Ok(decoded) = index.decode(word, 0, table) {
                assert_ne!(decoded.key, "UFLO_UR_UR", "{arch} overmatch {kind} {word:032x}");
            }
            match kind {
                "negative" => { negative += 1; assert!(index.decode(word, 0, table).is_err(),
                    "{arch}: invalid/text-inert word accepted {word:032x}"); },
                "adjacent_modifier" => adjacent += 1,
                "other_family" => other += 1,
                "no_text_candidate" => panic!("unnamed silicon candidate requires separate measurement"),
                other => panic!("unclassified negative {other}"),
            }
            if row["generation"] == "reuse_control" && kind != "positive" { refused_reuse += 1; }
        }
        assert!(negative >= 200 && adjacent >= 4 && control > 0,
                "{arch}: missing negative/adjacent/control census: {negative}/{adjacent}/{control}");
        assert_eq!(other, 0, "{arch}: every UFLO source inversion remains inside its own group");
        assert_eq!(refused_reuse, 12,
                   "{arch}: every measured reuse control is refused, none is adopted");
    }
}

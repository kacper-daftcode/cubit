//! Plain production ATOMG EXCH/CAS.64 vendor text; no GPU atomic execution.
include!("hb300_fixture.inc");
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::sync::OnceLock;

const SOURCE: &str = "rows-atomg-plain-production-2026-11-10";
static ARCHES: std::sync::LazyLock<[(&str, &str); 2]> = std::sync::LazyLock::new(|| [
    (
        "sm103a",
        hb300_fixture("sm103a_atomg_plain_production_nvdisasm.jsonl"),
    ),
    (
        "sm100a",
        hb300_fixture("sm100a_atomg_plain_production_nvdisasm.jsonl"),
    ),
]);

#[derive(Clone, Copy)]
struct Census {
    production: usize,
    positive: usize,
    guards: usize,
    bytes: usize,
    crosses: usize,
    reuse_decoded: usize,
}

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

fn rows(fixture: &str) -> impl Iterator<Item = Value> + '_ {
    fixture
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
}

fn hex(value: &Value) -> u128 {
    u128::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn encode(table: &IsaTable, word: u128, text: &str) -> Result<u128, String> {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let parsed = cubit::parse_cuasm_line(&format!("[{control}] {text} ;"), 0).unwrap();
    cubit::encoder::encode_instruction(&parsed, table).map_err(|error| error.to_string())
}

fn check_family(family: &str, key: &str, group: &str, expected: Census) {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let (mut production, mut positive, mut guards, mut bytes, mut crosses) =
            (0usize, 0usize, 0usize, 0usize, 0usize);
        let mut guarded_encode_refusals = 0usize;
        for row in rows(fixture) {
            if row["family"] != family || row["kind"] != "positive" {
                continue;
            }
            positive += 1;
            match row["generation"].as_str().unwrap() {
                "production" => production += 1,
                "guard" => guards += 1,
                "byte_field" => bytes += 1,
                "cross" => crosses += 1,
                "base" | "output_predicate" | "immediate" | "single_lower_bit"
                | "address_class" => {}
                other => panic!("unexpected positive generation {other}"),
            }
            let word = hex(&row["word"]);
            let text = row["nvidia_sass"].as_str().unwrap();
            let decoded = decoder
                .decode(word, 0, table)
                .unwrap_or_else(|error| panic!("{arch} {family} {word:032x}: {error}"));
            assert_eq!(decoded.key, key, "{arch} {family} {word:032x}");
            assert_eq!(decoded.mod_group, group, "{arch} {family} {word:032x}");
            assert_eq!(
                cubit::printer::to_sass_lossless(&decoded),
                text,
                "{arch} {family} {word:032x}"
            );
            assert_eq!(cubit::printer::to_sass(&decoded), text);
            let encoded = encode(table, word, text);
            if *arch == "sm103a" && text.starts_with('@') {
                guarded_encode_refusals += 1;
                let error = encoded
                    .expect_err("BUG-080 guarded atomic must remain refused")
                    .to_string();
                assert!(
                    error.contains("BUG-080"),
                    "{arch} {family} {word:032x}: {error}"
                );
            } else {
                assert_eq!(
                    encoded.unwrap(),
                    word & !(7u128 << 125),
                    "{arch} {family} {word:032x} {text}"
                );
            }
        }
        assert_eq!(
            (production, positive, guards, bytes, crosses),
            (
                expected.production,
                expected.positive,
                expected.guards,
                expected.bytes,
                expected.crosses
            ),
            "{arch} {family}: positive census"
        );
        let expected_guarded = rows(fixture)
            .filter(|row| {
                row["family"] == family
                    && row["kind"] == "positive"
                    && row["nvidia_sass"].as_str().unwrap().starts_with('@')
            })
            .count();
        assert_eq!(
            guarded_encode_refusals,
            if *arch == "sm103a" {
                expected_guarded
            } else {
                0
            }
        );

        let mut reuse_total = 0usize;
        let mut reuse_decoded = 0usize;
        for row in rows(fixture) {
            if row["family"] != family || row["generation"] != "reuse_control" {
                continue;
            }
            reuse_total += 1;
            let word = hex(&row["word"]);
            let Ok(decoded) = decoder.decode(word, 0, table) else {
                continue;
            };
            if decoded.key != key || decoded.mod_group != group {
                continue;
            }
            reuse_decoded += 1;
            let text = row["nvidia_sass"].as_str().unwrap();
            assert_eq!(decoded.key, key);
            assert_eq!(cubit::printer::to_sass_lossless(&decoded), text);
            assert_eq!(cubit::printer::to_sass(&decoded), text);
            assert_eq!(encode(table, word, text).unwrap(), word & !(7u128 << 125));
        }
        assert_eq!(
            (reuse_total, reuse_decoded),
            (7, expected.reuse_decoded),
            "{arch} {family}: complete reuse-mask census"
        );
    }
}

#[test]
fn production_exch_and_controlled_fields_roundtrip() {
    check_family(
        "exch",
        "ATOMG_P_R_ARI_R",
        "E,EXCH,GPU,STRONG",
        Census {
            production: 92,
            positive: 1163,
            guards: 15,
            bytes: 765,
            crosses: 243,
            reuse_decoded: 0,
        },
    );
}

#[test]
fn production_cas64_and_controlled_fields_roundtrip() {
    check_family(
        "cas64",
        "ATOMG_P_R_ARI_R_R",
        "64,CAS,E,GPU,STRONG",
        Census {
            production: 25,
            positive: 1346,
            guards: 15,
            bytes: 1015,
            crosses: 243,
            reuse_decoded: 0,
        },
    );
}

fn check_row(arch: &str, key: &str, group_name: &str, model_text: &str) {
    let model: Value = serde_json::from_str(model_text).unwrap();
    let raw: Value = serde_json::from_slice(
        &cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 2);
    let entry = &raw["instructions"][key];
    assert_eq!(entry["base_op"], "ATOMG");
    assert_eq!(entry["operand_sig"], model["operand_sig"]);
    assert_eq!(entry["scheduling"]["pipe_name"], "UNKNOWN");
    assert_eq!(
        entry["mod_groups"].as_object().unwrap().len(),
        model["expected_group_count"]
    );
    let row = &entry["mod_groups"][group_name];
    assert_eq!(row["_src"], SOURCE);
    assert_eq!(hex(&row["and_base"]) >> 96, 0);
    assert_eq!(row["and_base"], model["and_base"]);
    assert_eq!(row["variable_mask"], model["variable_mask"]);
    assert_eq!(row["fields"], model["fields"]);
    assert_eq!(
        row.get("claim_forbid").cloned().unwrap_or(Value::Null),
        model["claim_forbid"]
    );
    let fields = row["fields"].as_array().unwrap();
    let mask = fields.iter().fold(0u128, |mask, field| {
        mask | (((1u128 << field["bits"].as_u64().unwrap()) - 1)
            << field["shift"].as_u64().unwrap())
    });
    assert_eq!(hex(&row["variable_mask"]), mask);
    for bit in [122u64, 123, 124] {
        let live = fields.iter().any(|field| {
            field["shift"] == bit && field["bits"] == 1 && field["extraction"] == "reuse"
        });
        let forbidden = row["claim_forbid"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|claim| {
                claim["shift"] == bit
                    && claim["bits"] == 1
                    && claim["values"] == serde_json::json!([1])
            });
        assert_ne!(
            live, forbidden,
            "{arch}: reuse bit {bit} lacks a text-law decision"
        );
    }
}

#[test]
fn scoped_rows_fields_provenance_and_reuse_decisions_match_measurement() {
    for (arch, _) in *ARCHES {
        check_row(
            arch,
            "ATOMG_P_R_ARI_R",
            "E,EXCH,GPU,STRONG",
            r#"{"and_base":"0x000000000410e10000000000000003a8","claim_forbid":[{"bits":1,"shift":122,"values":[1]},{"bits":1,"shift":123,"values":[1]},{"bits":1,"shift":124,"values":[1]}],"expected_group_count":2,"fields":[{"bits":4,"extraction":"guard","shift":12,"token_idx":0},{"bits":3,"extraction":"pred","shift":81,"token_idx":1},{"bits":8,"extraction":"reg","shift":16,"token_idx":2},{"bits":8,"extraction":"sub_r0","shift":24,"token_idx":3},{"bits":24,"extraction":"sub_imm1","shift":40,"token_idx":3},{"bits":8,"extraction":"reg","shift":32,"token_idx":4}],"key":"ATOMG_P_R_ARI_R","kind_counts":{"adjacent_modifier":518,"control_plane":37,"negative":32,"other_family":1,"positive":1163},"mod_group":"E,EXCH,GPU,STRONG","operand_sig":"P_R_ARI_R","variable_mask":"0x00000000000e0000fffffffffffff000"}"#,
        );
        check_row(
            arch,
            "ATOMG_P_R_ARI_R_R",
            "64,CAS,E,GPU,STRONG",
            r#"{"and_base":"0x000000000010e50000000000000003a9","claim_forbid":[{"bits":1,"shift":122,"values":[1]},{"bits":1,"shift":123,"values":[1]},{"bits":1,"shift":124,"values":[1]}],"expected_group_count":6,"fields":[{"bits":4,"extraction":"guard","shift":12,"token_idx":0},{"bits":3,"extraction":"pred","shift":81,"token_idx":1},{"bits":8,"extraction":"reg","shift":16,"token_idx":2},{"bits":8,"extraction":"sub_r0","shift":24,"token_idx":3},{"bits":24,"extraction":"sub_imm1","shift":40,"token_idx":3},{"bits":8,"extraction":"reg","shift":32,"token_idx":4},{"bits":8,"extraction":"reg","shift":64,"token_idx":5}],"key":"ATOMG_P_R_ARI_R_R","kind_counts":{"adjacent_modifier":514,"control_plane":37,"negative":27,"other_family":2,"positive":1346},"mod_group":"64,CAS,E,GPU,STRONG","operand_sig":"P_R_ARI_R_R","variable_mask":"0x00000000000e00fffffffffffffff000"}"#,
        );
    }
}

#[test]
fn unlicensed_neighbours_inert_fields_and_refusals_fail_closed() {
    for (index, (arch, fixture)) in ARCHES.iter().enumerate() {
        let (table, decoder) = &tables()[index];
        let mut counts = std::collections::BTreeMap::new();
        for row in rows(fixture) {
            let family = row["family"].as_str().unwrap();
            let expected: Value = if family == "exch" {
                serde_json::from_str(r#"{"and_base":"0x000000000410e10000000000000003a8","claim_forbid":[{"bits":1,"shift":122,"values":[1]},{"bits":1,"shift":123,"values":[1]},{"bits":1,"shift":124,"values":[1]}],"expected_group_count":2,"fields":[{"bits":4,"extraction":"guard","shift":12,"token_idx":0},{"bits":3,"extraction":"pred","shift":81,"token_idx":1},{"bits":8,"extraction":"reg","shift":16,"token_idx":2},{"bits":8,"extraction":"sub_r0","shift":24,"token_idx":3},{"bits":24,"extraction":"sub_imm1","shift":40,"token_idx":3},{"bits":8,"extraction":"reg","shift":32,"token_idx":4}],"key":"ATOMG_P_R_ARI_R","kind_counts":{"adjacent_modifier":518,"control_plane":37,"negative":32,"other_family":1,"positive":1163},"mod_group":"E,EXCH,GPU,STRONG","operand_sig":"P_R_ARI_R","variable_mask":"0x00000000000e0000fffffffffffff000"}"#).unwrap()
            } else {
                serde_json::from_str(r#"{"and_base":"0x000000000010e50000000000000003a9","claim_forbid":[{"bits":1,"shift":122,"values":[1]},{"bits":1,"shift":123,"values":[1]},{"bits":1,"shift":124,"values":[1]}],"expected_group_count":6,"fields":[{"bits":4,"extraction":"guard","shift":12,"token_idx":0},{"bits":3,"extraction":"pred","shift":81,"token_idx":1},{"bits":8,"extraction":"reg","shift":16,"token_idx":2},{"bits":8,"extraction":"sub_r0","shift":24,"token_idx":3},{"bits":24,"extraction":"sub_imm1","shift":40,"token_idx":3},{"bits":8,"extraction":"reg","shift":32,"token_idx":4},{"bits":8,"extraction":"reg","shift":64,"token_idx":5}],"key":"ATOMG_P_R_ARI_R_R","kind_counts":{"adjacent_modifier":514,"control_plane":37,"negative":27,"other_family":2,"positive":1346},"mod_group":"64,CAS,E,GPU,STRONG","operand_sig":"P_R_ARI_R_R","variable_mask":"0x00000000000e00fffffffffffffff000"}"#).unwrap()
            };
            let kind = row["kind"].as_str().unwrap();
            if matches!(kind, "positive" | "control_plane") {
                continue;
            }
            *counts
                .entry((family.to_string(), kind.to_string()))
                .or_insert(0usize) += 1;
            let word = hex(&row["word"]);
            let decoded = decoder.decode(word, 0, table);
            if let Ok(decoded) = decoded {
                assert!(
                    decoded.key != expected["key"].as_str().unwrap()
                        || decoded.mod_group != expected["mod_group"].as_str().unwrap(),
                    "{arch} {family} overmatch {kind} {word:032x}"
                );
            }
            if kind == "negative" {
                assert!(
                    decoder.decode(word, 0, table).is_err(),
                    "{arch} {family}: invalid/text-inert word accepted {word:032x}"
                );
            }
        }
        for (family, model_text) in [
            (
                "exch",
                r#"{"and_base":"0x000000000410e10000000000000003a8","claim_forbid":[{"bits":1,"shift":122,"values":[1]},{"bits":1,"shift":123,"values":[1]},{"bits":1,"shift":124,"values":[1]}],"expected_group_count":2,"fields":[{"bits":4,"extraction":"guard","shift":12,"token_idx":0},{"bits":3,"extraction":"pred","shift":81,"token_idx":1},{"bits":8,"extraction":"reg","shift":16,"token_idx":2},{"bits":8,"extraction":"sub_r0","shift":24,"token_idx":3},{"bits":24,"extraction":"sub_imm1","shift":40,"token_idx":3},{"bits":8,"extraction":"reg","shift":32,"token_idx":4}],"key":"ATOMG_P_R_ARI_R","kind_counts":{"adjacent_modifier":518,"control_plane":37,"negative":32,"other_family":1,"positive":1163},"mod_group":"E,EXCH,GPU,STRONG","operand_sig":"P_R_ARI_R","variable_mask":"0x00000000000e0000fffffffffffff000"}"#,
            ),
            (
                "cas64",
                r#"{"and_base":"0x000000000010e50000000000000003a9","claim_forbid":[{"bits":1,"shift":122,"values":[1]},{"bits":1,"shift":123,"values":[1]},{"bits":1,"shift":124,"values":[1]}],"expected_group_count":6,"fields":[{"bits":4,"extraction":"guard","shift":12,"token_idx":0},{"bits":3,"extraction":"pred","shift":81,"token_idx":1},{"bits":8,"extraction":"reg","shift":16,"token_idx":2},{"bits":8,"extraction":"sub_r0","shift":24,"token_idx":3},{"bits":24,"extraction":"sub_imm1","shift":40,"token_idx":3},{"bits":8,"extraction":"reg","shift":32,"token_idx":4},{"bits":8,"extraction":"reg","shift":64,"token_idx":5}],"key":"ATOMG_P_R_ARI_R_R","kind_counts":{"adjacent_modifier":514,"control_plane":37,"negative":27,"other_family":2,"positive":1346},"mod_group":"64,CAS,E,GPU,STRONG","operand_sig":"P_R_ARI_R_R","variable_mask":"0x00000000000e00fffffffffffffff000"}"#,
            ),
        ] {
            let model: Value = serde_json::from_str(model_text).unwrap();
            for (kind, expected) in model["kind_counts"].as_object().unwrap() {
                if matches!(kind.as_str(), "positive" | "control_plane") {
                    continue;
                }
                assert_eq!(
                    counts
                        .get(&(family.to_string(), kind.clone()))
                        .copied()
                        .unwrap_or(0),
                    usize::try_from(expected.as_u64().unwrap()).unwrap(),
                    "{arch} {family} {kind}"
                );
            }
        }
    }
}

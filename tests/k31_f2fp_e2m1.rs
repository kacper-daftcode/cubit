//! K3.1 trtllm-gen MoE: BF16/E2M1 UNPACK_B with register and immediate E8M0 scale.
//! Evidence: independent SM103/SM100 nvdisasm 13.3.73 raw probes + H's 861
//! production words (11,520 occurrences), and H's B300 silicon result.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const SOURCE: &str = "k31-f2fp-e2m1-sm103-sm100-2026-11-07";
const KEYS: [&str; 2] = [
    "F2FP.BF16.E2M1.UNPACK_B_R_R_R",
    "F2FP.BF16.E2M1.UNPACK_B_R_R_FI",
];

fn table(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}

fn fixture() -> Vec<Value> {
    include_str!("fixtures/k31_f2fp_e2m1_nvdisasm.jsonl")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (word >> 96) as u32,
    ));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none(), "{source}");
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

#[test]
fn all_witnesses_and_valid_field_probes_round_trip_all_128_bits() {
    for arch in ["sm103a", "sm100a"] {
        let want_arch = if arch == "sm103a" { "SM103" } else { "SM100" };
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let (mut n, mut production, mut occurrences) = (0, 0, 0);
        for row in fixture() {
            // Production witnesses are SM103-only in H's stream; replay them on
            // both tables. Independent SM100 field probes prove the same text law.
            if (row["arch"] != want_arch && row.get("occurrences").is_none()) || row["nvidia_sass"].is_null() || row.get("lattice").is_some() {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            if row["probe"] == "scale-selector" && ((word >> 24) & 7) >= 6 { continue; }
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let decoded = index
                .decode(word, 0, &table)
                .unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor}"));
            assert!(
                KEYS.contains(&decoded.key.as_str()),
                "{arch}: {word:032x}: {}: {vendor}",
                decoded.key
            );
            let lossless = cubit::printer::to_sass_lossless(&decoded);
            let own = if decoded.key.ends_with("UNPACK_B_R_R_FI")
                && f32::from_bits(((word >> 32) & 0xffff_ffff) as u32).is_nan() {
                cubit::printer::to_sass(&decoded)
            } else {
                lossless.clone()
            };
            assert_eq!(own, vendor, "{arch}: {word:032x}");
            assert_eq!(reencode(&table, word, &lossless), word, "{arch}: {vendor}: lossless: {lossless}");
            n += 1;
            if row.get("occurrences").is_some() {
                production += 1;
                occurrences += row["occurrences"].as_u64().unwrap();
            }
        }
        assert_eq!(production, 861, "{arch}: H witness census");
        assert_eq!(occurrences, 11520, "{arch}: H occurrence census");
        assert!(
            n > production + 90,
            "{arch}: independent field and boundary probes: {n}"
        );
    }
}

#[test]
fn unclaimed_lattice_words_and_selector_codes_do_not_claim_the_new_rows() {
    for arch in ["sm103a", "sm100a"] {
        let want_arch = if arch == "sm103a" { "SM103" } else { "SM100" };
        let table = table(arch);
        let index = DecodeIndex::build(&table);
        let mut n = 0;
        for row in fixture() {
            if row["arch"] != want_arch {
                continue;
            }
            let lattice = row.get("lattice").is_some();
            let invalid_selector = row["probe"] == "scale-selector"
                && ((u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() >> 24) & 7)
                    >= 6;
            if !lattice && !invalid_selector {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            if let Ok(d) = index.decode(word, 0, &table) {
                assert!(
                    !KEYS.contains(&d.key.as_str()),
                    "{arch}: {word:032x} -> {}: {:?}",
                    d.key,
                    row["nvidia_sass"]
                );
            }
            n += 1;
        }
        assert!(n >= 70, "{arch}: only {n} lattice probes");
        for selector in ["H0", "H1", "B0", "B1", "B2", "B3"] {
            let text = format!("F2FP.BF16.E2M1.UNPACK_B R11, R2, R5.{selector}");
            let parsed = cubit::parse_sass(&text, 0).unwrap();
            assert!(
                cubit::encoder::encode_instruction(&parsed, &table).is_ok(),
                "{arch}: {text}"
            );
        }
    }
}

#[test]
fn rows_fields_and_provenance_are_measured() {
    for arch in ["sm103a", "sm100a"] {
        let bytes =
            cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json")))
                .unwrap();
        let raw: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 2);
        let number = |v: &Value| {
            u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
        };
        for key in KEYS {
            assert_eq!(raw["instructions"][key]["_src"], SOURCE);
            let groups = raw["instructions"][key]["mod_groups"].as_object().unwrap();
            assert_eq!(groups.len(), 1, "{arch}: {key}");
            let g = &groups[""];
            assert_eq!(g["_src"], SOURCE);
            let field_mask = g["fields"]
                .as_array()
                .unwrap()
                .iter()
                .fold(0u128, |mask, f| {
                    mask | (((1u128 << f["bits"].as_u64().unwrap()) - 1)
                        << f["shift"].as_u64().unwrap())
                });
            assert_eq!(number(&g["variable_mask"]), field_mask, "{arch}: {key}");
            assert_eq!(number(&g["and_base"]) & field_mask, 0);
            assert_eq!(number(&g["and_base"]) >> 105, 0);
        }
    }
}

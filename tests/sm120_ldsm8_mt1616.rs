//! SM120 LDSM byte-matrix x1/x2: independent NVIDIA full-128-bit witnesses.
//! This is decoder/assembler coverage; it makes no GPU mapping or latency claim.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

fn table_path() -> PathBuf {
    std::env::var_os("CUBIT_TABLE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tables/sm120.json"))
}

fn table_and_index() -> &'static (IsaTable, DecodeIndex) {
    static TABLE: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    TABLE.get_or_init(|| {
        let table = IsaTable::load(&table_path()).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    })
}

fn fixture() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("fixtures/sm120_ldsm8_mt1616.json")).unwrap()
    })
}

fn word(row: &Value) -> u128 {
    let hex = row["code"].as_str().unwrap();
    assert_eq!(hex.len(), 32);
    u128::from_str_radix(hex, 16).unwrap()
}

fn normalized(text: &str) -> String {
    let text = text.trim().trim_end_matches(';').trim();
    let (guard, body) = if text.starts_with('@') {
        let (guard, body) = text.split_once(' ').unwrap();
        (format!("{guard} "), body)
    } else {
        (String::new(), text)
    };
    let (opcode, operands) = body.split_once(' ').unwrap();
    let mut pieces = opcode.split('.');
    let base = pieces.next().unwrap();
    let mut modifiers: Vec<_> = pieces.collect();
    modifiers.sort_unstable();
    format!(
        "{guard}{} {}",
        std::iter::once(base)
            .chain(modifiers)
            .collect::<Vec<_>>()
            .join("."),
        operands.replace("+-", "-")
    )
}

fn check(row: &Value, expected_frame: Option<&str>) {
    let (table, index) = table_and_index();
    let bits = word(row);
    let pc = u32::try_from(row["oracle_pc"].as_u64().unwrap()).unwrap();
    let vendor = row["nvdisasm"].as_str().unwrap();
    let decoded = index.decode(bits, pc, table).unwrap();
    if let Some(frame) = expected_frame {
        if frame == "AURI" {
            // An elided RZ base also matches the canonical ARURI spelling.
            // The complete vendor text and full128 roundtrip below still
            // require the exact uniform-only address, including its offset.
            assert!(matches!(
                decoded.key.as_str(),
                "LDSM_R_AURI" | "LDSM_R_ARURI"
            ));
        } else {
            assert_eq!(decoded.key, format!("LDSM_R_{frame}"));
        }
        assert_eq!(
            decoded.mod_group,
            if row["count"] == 2 {
                "2,8,MT1616"
            } else {
                "8,MT1616"
            }
        );
    }
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(
        normalized(&own),
        normalized(vendor),
        "{bits:032x} at {pc:x}"
    );
    let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32(
        (bits >> 96) as u32,
    ));
    for text in [vendor, own.as_str()] {
        let source = format!("[{control}] {text} ;");
        cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
        let parsed = cubit::parse_cuasm_line(&source, pc).unwrap();
        assert!(parsed.hand_sched && parsed.rsd.is_none());
        assert_eq!(
            cubit::encoder::encode_instruction(&parsed, table).unwrap(),
            bits,
            "All128bits must come from ordinary source: {source}"
        );
    }
}

#[test]
fn all_142_vendor_register_address_offset_guard_witnesses_roundtrip_full128() {
    let rows = fixture()["field_witnesses"].as_array().unwrap();
    assert_eq!(rows.len(), 142);
    for row in rows {
        check(row, Some(row["frame"].as_str().unwrap()));
        assert_eq!(
            normalized(row["expected"].as_str().unwrap()),
            normalized(row["nvdisasm"].as_str().unwrap())
        );
    }
}

#[test]
fn all_three_independent_ptx_compiler_instructions_roundtrip_full128() {
    let rows = fixture()["compiler_witnesses"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for row in rows {
        check(row, None);
    }
}

#[test]
fn six_new_groups_clone_measured_siblings_and_every_old_group_stays_exact() {
    let raw: Value = serde_json::from_slice(&std::fs::read(table_path()).unwrap()).unwrap();
    assert_eq!(fixture()["source"], "sm120-ldsm8-2026-10-22");
    let number =
        |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for frame in ["ARI", "ARURI", "AURI"] {
        let key = format!("LDSM_R_{frame}");
        let groups = raw["instructions"][&key]["mod_groups"].as_object().unwrap();
        let mut old = groups.clone();
        for (new_name, donor_name) in [("8,MT1616", "16,MT1616"), ("2,8,MT1616", "16,2,MT1616")] {
            let new = old.remove(new_name).unwrap();
            let donor = &groups[donor_name];
            assert_eq!(new["_src"], fixture()["source"]);
            assert_eq!(
                number(&new["and_base"]),
                number(&donor["and_base"]) | (7 << 75)
            );
            let mut geometry = new.as_object().unwrap().clone();
            let mut original = donor.as_object().unwrap().clone();
            for value in [&mut geometry, &mut original] {
                for field in ["and_base", "_src", "_note"] {
                    value.remove(field);
                }
            }
            assert_eq!(
                geometry, original,
                "{key} {new_name}: fields/mask/count changed"
            );
        }
        // The snapshot includes complete old dictionaries, including every
        // field, mask, base, count and provenance; no old row may be weakened.
        assert_eq!(
            Value::Object(old),
            fixture()["old_mod_groups"][&key],
            "{key}"
        );
    }
}

#[test]
fn x4_invalid3_and_unsupported_datatypes_remain_unclaimed() {
    let (table, index) = table_and_index();
    let rows = fixture()["unclaimed_words"].as_array().unwrap();
    assert_eq!(rows.len(), 26);
    for row in rows {
        assert!(
            index
                .decode(word(row), row["oracle_pc"].as_u64().unwrap() as u32, table)
                .is_err(),
            "Unmeasured/unsupported word claimed: {row}"
        );
    }
    for address in ["[R4]", "[R4+UR5]", "[UR5]"] {
        for opcode in [
            "LDSM.8.MT1616.4",
            "LDSM.8.MT1616.INVALID3",
            "LDSM.U4x16P64TO8.MT1616",
            "LDSM.U6x16P32TO8.MT1616",
        ] {
            let source = format!("{opcode} R12, {address}");
            if let Ok(parsed) = cubit::parse_sass(&source, 0) {
                assert!(
                    cubit::encoder::encode_instruction(&parsed, table).is_err(),
                    "{source}"
                );
            }
        }
    }
}

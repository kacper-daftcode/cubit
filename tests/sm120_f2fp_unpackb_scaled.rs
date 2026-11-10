//! The scaled F2FP UNPACK_B rows (opcode 0x63e) on sm120 / sm121a: `F2FP.BF16.<E2M1|E2M3|E3M2|E4M3|E5M2>[.RELU]
//! [.SATFINITE].UNPACK_B Rd, Rs, Rscale.<sel>` -- the unpack with an E8M0 block scale in a register, the word the
//! two-instruction dequantisation of an e4m3 / e2m1 pair is written with. The 20 rows are the rows the B300 measurement
//! lane measured on sm103a / sm100a (`tests/hidden_b300_f2fp_unpackb.rs`); they are on these two tables because nvdisasm
//! 13.1 names every word of the lane's two lattices identically on `-b SM120`, `-b SM121`, `-b SM103` and `-b SM100`
//! (fixture `sm120_f2fp_unpackb_scaled_nvdisasm.jsonl.gz`: 2 406 distinct complete words x the two targets, one word
//! per call -- 328 named, 914 printed with a vendor glyph, 1 164 rejected), and because the E4M3 and E2M1 words with
//! the selectors B0 / H0 execute on sm_120 silicon as the five-instruction route does (the scheduler session's probe of
//! 2026-11-10, all 65 536 byte pairs x 256 scale bytes); the other types and selectors are text-measured only, and
//! nothing was executed on GB10. Pinned here: the rows' own 212 words decode to nvdisasm's text and re-encode to the
//! word; every other instruction word of the lattice fails closed (text-inert neighbours, the unclaimed types E0M3 /
//! S2_6, the selector values 6 / 7, the immediate-scale form at 0xe3e); the rows equal sm103a's field for field.
include!("hb300_fixture.inc");

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

const KEY: &str = "F2FP_R_R_R";
const TYPES: [&str; 5] = ["E2M1", "E2M3", "E3M2", "E4M3", "E5M2"];
const ARCHES: [(&str, &str, &str); 2] = [
    ("sm120", "SM120", "f2fp-unpackb-scaled-sm120-2026-11-10"),
    ("sm121a", "SM121", "f2fp-unpackb-scaled-sm121-2026-11-10"),
];
/// The lane's tag on the donor rows of sm103a / sm100a.
const DONOR_SRC: &str = "f2fp-unpackb-mxfp6-mxfp8-silicon-2026-11-07";

fn raw(arch: &str) -> Value {
    serde_json::from_slice(&cubit::table::read_table_bytes(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()).unwrap()
}

fn groups() -> Vec<String> {
    let mut v = Vec::new();
    for typ in TYPES {
        for prefix in ["", "RELU,", "SATFINITE,", "RELU,SATFINITE,"] {
            v.push(format!("BF16,{typ},{prefix}UNPACK_B"));
        }
    }
    v
}

#[test]
fn every_lattice_word_decodes_as_nvdisasm_names_it_or_fails_closed() {
    for (arch, target, _tag) in ARCHES {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        let index = DecodeIndex::build(&table);
        let (mut adopt, mut closed, mut auxiliary) = (0, 0, 0);
        let (mut named, mut glyph, mut rejected) = (0, 0, 0);
        for line in hb300_fixture("sm120_f2fp_unpackb_scaled_nvdisasm.jsonl").lines() {
            let row: Value = serde_json::from_str(line).unwrap();
            if row["arch"] != target {
                continue;
            }
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
            let vendor = row["nvidia_sass"].as_str();
            match vendor {
                None => rejected += 1,
                Some(t) if t.contains("???") || t.contains("INVALID") => glyph += 1,
                Some(_) => named += 1,
            }
            if row["auxiliary_control_probe"] == true {
                // the lane's control-word probes (bits [127:105] varied): nothing is asserted on them
                auxiliary += 1;
            } else if row["adopt"] == true {
                adopt += 1;
                let decoded = index.decode(word, 0, &table).unwrap_or_else(|e| panic!("{arch}: {word:032x}: {e}: {vendor:?}"));
                assert_eq!(decoded.key, KEY, "{arch}: {word:032x}");
                assert!(decoded.mod_group.ends_with("UNPACK_B"), "{arch}: {word:032x}: {}", decoded.mod_group);
                let text = cubit::printer::to_sass_lossless(&decoded);
                assert_eq!(text, vendor.unwrap(), "{arch}: {word:032x}: {}", decoded.mod_group);
                let ctrl = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
                let source = format!("[{ctrl}] {text} ;");
                cubit::roundtrip_audit::check_semantic_source(&source).unwrap_or_else(|e| panic!("{arch}: semantic {source}: {e}"));
                let parsed = cubit::parse_cuasm_line(&source, 0).unwrap_or_else(|e| panic!("{arch}: parse {source}: {e}"));
                assert_eq!(
                    cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{arch}: encode {source}: {e}")),
                    word,
                    "{source}"
                );
            } else {
                closed += 1;
                assert!(index.decode(word, 0, &table).is_err(), "{arch}: a word outside the rows decodes: {word:032x}: {vendor:?}");
            }
        }
        assert_eq!((adopt, closed, auxiliary), (212, 2162, 32), "{arch}");
        assert_eq!((named, glyph, rejected), (328, 914, 1164), "{arch}: nvdisasm 13.1 -b {target}");
    }
}

#[test]
fn the_two_targets_name_every_word_alike() {
    let mut by_word: std::collections::BTreeMap<String, Vec<(String, Option<String>)>> = Default::default();
    for line in hb300_fixture("sm120_f2fp_unpackb_scaled_nvdisasm.jsonl").lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        by_word
            .entry(row["word"].as_str().unwrap().to_string())
            .or_default()
            .push((row["arch"].as_str().unwrap().to_string(), row["nvidia_sass"].as_str().map(str::to_string)));
    }
    assert_eq!(by_word.len(), 2406);
    for (word, v) in &by_word {
        assert_eq!(v.len(), 2, "{word}");
        assert_eq!(v[0].1, v[1].1, "{word}: -b SM120 and -b SM121 differ");
    }
}

#[test]
fn the_attention_dequant_words_assemble_from_text() {
    // the register-scale unpack of an e4m3 pair with the scale byte / half selected on the scale register: the two
    // forms executed on sm_120 silicon, and the E2M1 twin (words named by nvdisasm 13.1 -b SM120, in the fixture)
    for (arch, _target, _tag) in ARCHES {
        let table = IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap();
        for (text, word) in [
            ("F2FP.BF16.E4M3.UNPACK_B R11, R2, R5.B0", 0x0200160500000002020b063e_u128),
            ("F2FP.BF16.E4M3.UNPACK_B R11, R2, R5.H0", 0x0200160500000002000b063e_u128),
            ("F2FP.BF16.E4M3.UNPACK_B R11, R2.H1, R5.B1", 0x0300160500000002030b063e_u128),
            ("F2FP.BF16.E2M1.UNPACK_B R11, R2, R5.B0", 0x0204120500000002020b063e_u128),
        ] {
            let parsed = cubit::parse_cuasm_line(&format!("{text} ;"), 0).unwrap();
            let got = cubit::encoder::encode_instruction(&parsed, &table).unwrap_or_else(|e| panic!("{arch}: {text}: {e}"));
            assert_eq!(got & ((1u128 << 96) - 1) & !0xf000, word, "{arch}: {text}: {got:032x}");
        }
        // the scale selector is mandatory (selector 0 is `.H0`, not an omitted suffix); 6 / 7 have no spelling; a
        // byte selector on a non-E2M1 source and a half selector on an E2M1 source are not forms
        for invalid in [
            "F2FP.BF16.E4M3.UNPACK_B R11, R2, R5 ;",
            "F2FP.BF16.E4M3.UNPACK_B R11, R2, R5.INVALID6 ;",
            "F2FP.BF16.E2M3.UNPACK_B R11, R2.B1, R5.B0 ;",
            "F2FP.BF16.E2M1.UNPACK_B R11, R2.H1, R5.B0 ;",
        ] {
            assert!(
                cubit::encoder::encode_instruction(&cubit::parse_cuasm_line(invalid, 0).unwrap(), &table).is_err(),
                "{arch}: {invalid}"
            );
        }
    }
}

#[test]
fn twenty_rows_per_table_under_their_own_tag_equal_to_the_sm103a_rows() {
    let donor = raw("sm103a");
    let donor_groups = donor["instructions"][KEY]["mod_groups"].as_object().unwrap();
    for (arch, target, tag) in ARCHES {
        let t = raw(arch);
        let src = &t["_meta"]["provenance"]["sources"][tag];
        assert_eq!(src["rows"], 20, "{arch}");
        assert!(src["kind"].as_str().unwrap().contains(&format!("-b {target}")), "{arch}");
        assert_eq!(src["test"], "tests/sm120_f2fp_unpackb_scaled.rs");
        let ins = &t["instructions"][KEY];
        let mg = ins["mod_groups"].as_object().unwrap();
        let mut at_63e = 0;
        for (name, row) in mg {
            let base = u128::from_str_radix(row["and_base"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            if base & 0xfff == 0x63e {
                at_63e += 1;
                assert!(groups().contains(name), "{arch}: an unexpected group at 0x63e: {name}");
            }
        }
        assert_eq!(at_63e, 20, "{arch}");
        for name in groups() {
            let row = &mg[&name];
            assert_eq!(row["_src"], tag, "{arch}: {name}");
            assert_eq!(row["claim_forbid"][0], serde_json::json!({"shift": 24, "bits": 3, "values": [6, 7]}), "{arch}: {name}");
            let d = &donor_groups[&name];
            assert_eq!(d["_src"], DONOR_SRC, "sm103a: {name}");
            // field for field: the same constant bits, mask, fail-closed list and fields (provenance tags apart)
            for k in ["and_base", "variable_mask", "claim_forbid"] {
                assert_eq!(row[k], d[k], "{arch}: {name}: {k}");
            }
            let strip = |v: &Value| -> Vec<Value> {
                v.as_array()
                    .unwrap()
                    .iter()
                    .map(|f| {
                        let mut f = f.as_object().unwrap().clone();
                        f.remove("_src");
                        f.remove("_note");
                        Value::Object(f)
                    })
                    .collect()
            };
            assert_eq!(strip(&row["fields"]), strip(&d["fields"]), "{arch}: {name}: fields");
            let fields = row["fields"].as_array().unwrap();
            assert!(fields.iter().any(|f| f["shift"] == 24 && f["bits"] == 3 && f["extraction"] == "f2fp_scale_sel" && f["token_idx"] == 3));
            if name.contains("E2M1") {
                assert!(fields.iter().any(|f| f["extraction"] == "f2fp_ra_b1" && f["shift"] == 72));
                assert!(fields.iter().any(|f| f["extraction"] == "f2fp_ra_b2" && f["shift"] == 88));
            } else {
                assert!(fields.iter().any(|f| f["shift"] == 88 && f["extraction"] == "opmod:H1" && f["token_idx"] == 2));
            }
        }
    }
}

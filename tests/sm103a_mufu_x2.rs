//! The sm103a MUFU packed-half lanes `MUFU.EX2.BF16x2` / `MUFU.EX2.F16x2 Rd, [-|]Ra[|] | [-|]URa[|] | imm_hi, imm_lo`
//! (opcodes 0x308 / 0xd08 + bit 91 / 0x908), measured with nvdisasm 13.3.73 on `-b SM103` on the B300 host
//! (session T-14, 2026-11-07; `tools/probes/re_sm103_mufu_x2.py`, fixture `tests/fixtures/sm103a_mufu_x2_nvdisasm.jsonl`;
//! nvdisasm 13.0 and 13.1 print the same text for every word). Found by session G's conversion batch (`G/NEEDS_OWNER.md` 5,
//! `T/NEEDS_OWNER.md` 48): on SM103 bit 80 is `.BF16x2` (with the half code 0) and the half code 3 is `.F16x2`; the
//! function [77:74] admits EX2 only in the packed lanes (the other values print `INVALIDn`); the immediate form carries
//! two halves (hi [63:48] printed first, lo [47:32]) as bf16 / f16 literals. On `-b SM120` / `SM100` bit 80 is text-inert
//! and the half code 3 is illegal, so the rows live in `sm103a.json` only (6 rows: the groups `BF16x2,EX2` / `EX2,F16x2`
//! of `MUFU_R_R`, `MUFU_R_UR` and the new key `MUFU_R_FI_FI`). Every probed form word decodes to its measured row,
//! prints the vendor's text and reassembles all 128 bits; the lattice (the INVALIDn functions, the crossed lane bits, the
//! uniform frame, the text-inert bits) stays unclaimed; sm120 / sm100a decode none of the lane words.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, sync::OnceLock};

const SOURCE: &str = "mufu-x2-sm103a-2026-11-07";

fn load(path: &str) -> (IsaTable, DecodeIndex) {
    let table = IsaTable::load(Path::new(path)).unwrap();
    let index = DecodeIndex::build(&table);
    (table, index)
}

fn sm103a() -> &'static (IsaTable, DecodeIndex) {
    static T: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    T.get_or_init(|| load("tables/sm103a.json"))
}

fn sm120() -> &'static (IsaTable, DecodeIndex) {
    static T: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    T.get_or_init(|| load("tables/sm120.json"))
}

fn sm100a() -> &'static (IsaTable, DecodeIndex) {
    static T: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    T.get_or_init(|| load("tables/sm100a.json"))
}

fn fixture() -> Vec<Value> {
    include_str!("fixtures/sm103a_mufu_x2_nvdisasm.jsonl").lines()
        .map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn word_of(row: &Value) -> u128 {
    u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap()
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> u128 {
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none(), "{source}");
    cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{source}: {e}"))
}

#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let (table, index) = sm103a();
    let mut rows_hit: BTreeMap<(String, String), usize> = BTreeMap::new();
    for row in fixture() {
        if row.get("lattice").is_some() {
            continue;
        }
        assert_eq!(row["arch"].as_str(), Some("SM103"));
        let word = word_of(&row);
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        assert!(decoded.mod_group == "BF16x2,EX2" || decoded.mod_group == "EX2,F16x2", "{word:032x}: {}", decoded.mod_group);
        assert!(matches!(decoded.key.as_str(), "MUFU_R_R" | "MUFU_R_UR" | "MUFU_R_FI_FI"), "{word:032x}: {}", decoded.key);
        // the display print is the vendor's text; the lossless print spells a NaN half's payload as a hex literal
        // (KNOWN_ISSUES A8: `-QNAN , +QNAN` cannot carry the payload) and re-encodes all 128 bits
        assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{word:032x}");
        let lossless = cubit::printer::to_sass_lossless(&decoded);
        if vendor.contains("NAN") {
            assert_ne!(lossless, vendor, "{word:032x}: the lossless print must carry the NaN payload");
        } else {
            assert_eq!(lossless, vendor, "{word:032x}");
            assert_eq!(reencode(table, word, vendor), word, "{vendor}");
        }
        assert_eq!(reencode(table, word, &lossless), word, "{lossless}");
        *rows_hit.entry((decoded.key.clone(), decoded.mod_group.clone())).or_default() += 1;
    }
    assert_eq!(rows_hit.len(), 6, "{rows_hit:?}");
    assert_eq!(rows_hit.values().sum::<usize>(), 108);
}

#[test]
fn the_lattice_stays_unclaimed() {
    // the INVALIDn functions, bit 80 on a half code / the half code 3 with bit 80 (illegal), the uniform
    // frame crossed, the text-inert bits: nothing in the sm103a table renders them
    let (table, index) = sm103a();
    let mut n = 0;
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        let word = word_of(&row);
        if let Ok(d) = index.decode(word, 0, table) {
            panic!("{word:032x} ({}) decoded as {} / {}: {}", row["nvidia_sass"], d.key, d.mod_group,
                   cubit::printer::to_sass(&d));
        }
        n += 1;
    }
    assert_eq!(n, 173);
}

#[test]
fn the_lanes_exist_on_sm103a_only() {
    // -b SM120 / SM100: bit 80 is text-inert on MUFU and the half code 3 is illegal -- the measured sm120 rows
    // fail closed on bit 80 (session G's conversion family) and no sm100a row carries either lane
    for (name, (table, index)) in [("sm120", sm120()), ("sm100a", sm100a())] {
        for row in fixture() {
            if row.get("lattice").is_some() {
                continue;
            }
            let word = word_of(&row);
            if let Ok(d) = index.decode(word, 0, table) {
                panic!("{name}: {word:032x} ({}) decoded as {} / {}", row["nvidia_sass"], d.key, d.mod_group);
            }
        }
    }
}

#[test]
fn the_rows_are_measured() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(Path::new("tables/sm103a.json")).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let expect = [
        ("MUFU_R_R", "BF16x2,EX2", 0x0000_0000_0001_0800_0000_0000_0000_0308u128),
        ("MUFU_R_R", "EX2,F16x2", 0x0000_0000_0000_0b00_0000_0000_0000_0308),
        ("MUFU_R_UR", "BF16x2,EX2", 0x0000_0000_0801_0800_0000_0000_0000_0d08),
        ("MUFU_R_UR", "EX2,F16x2", 0x0000_0000_0800_0b00_0000_0000_0000_0d08),
        ("MUFU_R_FI_FI", "BF16x2,EX2", 0x0000_0000_0001_0800_0000_0000_0000_0908),
        ("MUFU_R_FI_FI", "EX2,F16x2", 0x0000_0000_0000_0b00_0000_0000_0000_0908),
    ];
    for (key, group, base) in expect {
        let g = &ins[key]["mod_groups"][group];
        assert!(g.is_object(), "{key} / {group} missing");
        assert_eq!(number(&g["and_base"]), base, "{key} / {group}");
        assert_eq!(g["_src"], SOURCE, "{key} / {group}");
        let names: Vec<(String, u64, u64)> = g["fields"].as_array().unwrap().iter()
            .map(|f| (f["extraction"].as_str().unwrap().to_string(), f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap()))
            .collect();
        let imm = if group.starts_with("BF16x2") { "bf16" } else { "f16" };
        let want: Vec<(String, u64, u64)> = match key {
            "MUFU_R_R" => vec![("guard", 12, 4), ("reg", 16, 8), ("reg", 32, 8), ("abs", 62, 1), ("neg", 63, 1)],
            "MUFU_R_UR" => vec![("guard", 12, 4), ("reg", 16, 8), ("ureg", 32, 8), ("abs", 62, 1), ("neg", 63, 1)],
            _ => vec![("guard", 12, 4), ("reg", 16, 8), (imm, 48, 16), (imm, 32, 16)],
        }.into_iter().map(|(e, s, b)| (e.to_string(), s, b)).collect();
        assert_eq!(names, want, "{key} / {group}");
        // the lane bits are baked, the inert bits are outside the mask (fail-closed)
        let mask = number(&g["variable_mask"]);
        assert_eq!(mask & (0xff_u128 << 72), 0, "{key} / {group}: the half / function / lane bits are constants");
        if key != "MUFU_R_FI_FI" {
            assert_eq!(mask & (1_u128 << 60), 0, "{key} / {group}: .H1 is text-inert in the packed lanes");
        }
    }
    assert_eq!(ins["MUFU_R_FI_FI"]["operand_sig"], "R_FI_FI");
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 6);
}

#[test]
fn the_vendor_spellings_assemble_from_text() {
    let (table, _) = sm103a();
    let ctrl = 0x000f_e200u128 << 96;
    let cases = [
        ("MUFU.EX2.BF16x2 R4, R2", 0x0000_0000_0001_0800_0000_0002_0004_7308u128),
        ("MUFU.EX2.F16x2 R4, -|UR2|", 0x0000_0000_0800_0b00_c000_0002_0004_7d08),
        ("MUFU.EX2.F16x2 R4, 1, 1", 0x0000_0000_0000_0b00_3c00_3c00_0004_7908),
        ("MUFU.EX2.BF16x2 R4, 1, 1", 0x0000_0000_0001_0800_3f80_3f80_0004_7908),
        ("@!P2 MUFU.EX2.BF16x2 RZ, RZ", 0x0000_0000_0001_0800_0000_00ff_00ff_a308),
    ];
    for (text, want) in cases {
        assert_eq!(reencode(table, want | ctrl, text), want | ctrl, "{text}");
    }
}

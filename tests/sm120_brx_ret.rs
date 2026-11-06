//! The SM120 register-indirect control-flow family -- `BRX` (0x949), `BRXU` (0x958 + bit 91), `RET`
//! (0x950; bit 91 = the uniform-register form) -- rebuilt from measurement (session T-10, 2026-11-06;
//! `tools/probes/re_sm120_brx_ret.py`, nvdisasm 13.1 `-b SM120`, 506 form + 29 lattice words, every form
//! text predicted by the layout): register [31:24], a signed 56-bit dword offset at [23:16] + [81:34]
//! (the BRA split) printed as `Rn off*4` by BRX / BRXU (0 elided) and RET.ABS, `Rn PC+16+off*4` by
//! RET.REL; predicate operand [89:87] + `!` 90 before the register; BRX / BRXU 85 `.INC`, 86 `.DEC`,
//! BRXU mode [33:32] `.U` / `.DIV` / `.CONV` (printed after INC / DEC); RET 85 `.ABS` (else `.REL`),
//! 86 `.NODEC`. Eight keys `{BRX,BRXU,RET}[_P]_{R,UR}_II` × one group per legal modifier set = 46 rows
//! replace the 13 harvest keys / 16 rows (`BRX_II` with `imm@18:20` + `reg@25:8`, `BRXU_II` printing
//! `BRXU 0xfffe0220` for the vendor's `BRXU UR20 -0x1fdf0`, `RET.REL.NODEC_II` without a register,
//! `RET.ABS.NODEC_?` without fields, ...).
//! Pins: every form word decodes to the vendor text and re-encodes bit for bit; the lattice stays
//! unclaimed; the vendor spelling (`BRX R8 -0x3f00`: no comma, `BRX R8` for a zero offset) prints and
//! both spellings assemble; the retired dotted keys resolve as aliases.

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::Path, sync::OnceLock};

const SOURCE: &str = "brx-ret-family-2026-11-06";
const CTRL: u128 = 0x000f_e200u128 << 96;
const KEYS: [&str; 8] = ["BRX_R_II", "BRX_P_R_II", "BRXU_UR_II", "BRXU_P_UR_II", "RET_R_II", "RET_P_R_II", "RET_UR_II", "RET_P_UR_II"];
const FIXTURE: &str = include_str!("fixtures/sm120_brx_ret_nvdisasm.jsonl");

fn loaded() -> &'static (IsaTable, DecodeIndex) {
    static T: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    T.get_or_init(|| {
        let table = IsaTable::load(Path::new("tables/sm120.json")).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    })
}

fn fixture() -> Vec<Value> {
    FIXTURE.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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
    let (table, index) = loaded();
    let mut n = 0;
    let mut groups = std::collections::BTreeSet::new();
    for row in fixture() {
        if row.get("lattice").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        let d = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        assert!(KEYS.contains(&d.key.as_str()), "{word:032x}: {}", d.key);
        groups.insert((d.key.clone(), d.mod_group.clone()));
        assert_eq!(cubit::printer::to_sass_lossless(&d), vendor, "{word:032x}");
        assert_eq!(cubit::printer::to_sass(&d), vendor, "{word:032x} (display print)");
        assert_eq!(reencode(table, word, vendor), word, "{vendor}");
        n += 1;
    }
    assert_eq!(n, 506);
    assert_eq!(groups.len(), 46, "every measured row has a witness: {groups:?}");
}

#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = loaded();
    let (mut n, mut undecoded) = (0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        match index.decode(word, 0, table) {
            Err(_) => undecoded += 1,
            Ok(d) => assert_eq!(Some(cubit::printer::to_sass_lossless(&d).as_str()), row["nvidia_sass"].as_str(),
                "lattice word {word:032x} decodes as another text"),
        }
    }
    assert_eq!(n, 29);
    assert_eq!(undecoded, 29, "every lattice word stays unclaimed (INVALID3, the frame bit on BRX, text-inert bits)");
}

/// The vendor spells register and target as one operand; both the vendor's and the comma spelling
/// assemble to the same word, and the census shape `RET.REL.NODEC R2 0x0` (a return to the kernel
/// start) prints as nvdisasm resolves it.
#[test]
fn the_vendor_spelling_prints_and_both_spellings_assemble() {
    let (table, index) = loaded();
    for (vendor, comma, key) in [
        ("BRX R8 -0x3f00", "BRX R8, -0x3f00", "BRX_R_II"),
        ("BRX R8", "BRX R8, 0x0", "BRX_R_II"),
        ("BRX.INC !P3, R8 0x100", "BRX.INC !P3, R8, 0x100", "BRX_P_R_II"),
        ("BRXU.INC.U !P4, UR8 0x100", "BRXU.INC.U !P4, UR8, 0x100", "BRXU_P_UR_II"),
        ("BRXU.CONV URZ -0x200000000000000", "BRXU.CONV URZ, -0x200000000000000", "BRXU_UR_II"),
        ("RET.REL.NODEC R2 0x10", "RET.REL.NODEC R2, 0x10", "RET_R_II"),
        ("RET.ABS.NODEC P2, UR8 0x100", "RET.ABS.NODEC P2, UR8, 0x100", "RET_P_UR_II"),
        ("@P2 RET.REL URZ 0x0", "@P2 RET.REL URZ, 0x0", "RET_UR_II"),
    ] {
        let a = cubit::encoder::encode_instruction(&cubit::parse_cuasm_line(&format!("{vendor} ;"), 0).unwrap(), table)
            .unwrap_or_else(|e| panic!("{vendor}: {e}"));
        let b = cubit::encoder::encode_instruction(&cubit::parse_cuasm_line(&format!("{comma} ;"), 0).unwrap(), table)
            .unwrap_or_else(|e| panic!("{comma}: {e}"));
        assert_eq!(a, b, "{vendor} vs {comma}");
        let d = index.decode(a, 0, table).unwrap();
        assert_eq!(d.key, key, "{vendor}");
        assert_eq!(cubit::printer::to_sass(&d), vendor);
    }
    // the census word: `RET.REL.NODEC R2 0x0` at address 0x2c40 (DeepGEMM) = offset -(0x2c50 / 4)
    let word = cubit::encoder::encode_instruction(&cubit::parse_cuasm_line("RET.REL.NODEC R2 0x0 ;", 0x2c40).unwrap(), table).unwrap();
    assert_eq!(cubit::printer::to_sass(&index.decode(word, 0x2c40, table).unwrap()), "RET.REL.NODEC R2 0x0");
    assert_eq!(cubit::printer::to_sass(&index.decode(word, 0, table).unwrap()), "RET.REL.NODEC R2 -0x2c40");
}

#[test]
fn the_rows_are_the_measured_ones_and_the_harvest_keys_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(Path::new("tables/sm120.json")).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let family: Vec<&String> = ins.keys()
        .filter(|k| matches!(k.split('_').next().unwrap().split('.').next().unwrap(), "BRX" | "BRXU" | "RET"))
        .collect();
    assert_eq!(family.len(), 8, "{family:?}");
    let mut total = 0;
    for key in KEYS {
        let op = key.split('_').next().unwrap();
        let opcode = match op { "BRX" => 0x949, "BRXU" => 0x958, _ => 0x950 };
        for (name, g) in ins[key]["mod_groups"].as_object().unwrap() {
            assert_eq!(g["_src"], SOURCE, "{key} [{name}]");
            let mut field_mask = 0u128;
            for f in g["fields"].as_array().unwrap() {
                field_mask |= ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
            }
            assert_eq!(number(&g["variable_mask"]), field_mask, "{key} [{name}]");
            let ab = number(&g["and_base"]);
            assert_eq!(ab & field_mask, 0, "{key} [{name}]");
            assert_eq!(ab & 0xfff, opcode, "{key} [{name}]");
            assert_eq!((ab >> 91) & 1, u128::from(key.contains("_UR_")), "{key} [{name}]: the frame bit");
            total += 1;
        }
    }
    assert_eq!(total, 46);
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], 46);
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    assert_eq!(aliases["RET.REL.NODEC_R_II"], "RET_R_II");
    assert_eq!(aliases["RET.REL.NODEC_R"], "RET_R_II");
}

//! The `LEA` family rebuilt from measurement (session T-8, 2026-11-06, NEEDS_OWNER 30 / KNOWN_ISSUES T1):
//! `LEA[.HI][.X][.SX32] Rd, [Pd,] Ra, <b>, [Rc,] imm5 [, Pcin]` in its three operand forms (0x211 register,
//! 0x811 imm32, 0xc11 uniform register with the frame bit 91) × the six legal modifier groups, on sm120 /
//! sm103a / sm100a (`tools/probes/re_sm120_lea.py`, nvdisasm 13.1, text-identical on the three targets).
//!
//! Before: 56 keys / 100 harvest rows on sm120 (dozens of `?` junk keys with one sample's operands baked
//! into `and_base`, fields at the wrong bit, the modifier bits 73 / 74 / 80 outside both `and_base` and the
//! mask — the plain `LEA R4, R8, R10, 0x1` word decoded as `LEA.HI.X R4, R8, R10, RZ, 0x1, PT`), the
//! carry-in `, PT` of the `.X` forms dropped from the text, nvdisasm's bitwise-inverse glyph `~R` of the
//! `.X` forms printed as `-R`; on sm103a / sm100a coldface's B300-1 / B300-4 rows measured the UR form
//! with `neg` fields on the `.X` row, and the harvest rows next to them shadowed their `Pd = PT` words.
//!
//! Pins: every measured word decodes to NVIDIA's text through the family's keys and re-encodes bit for
//! bit on the three tables; every lattice word (text-inert bits, the wrong frame, `.SX32` without `.HI`,
//! the unused opcodes) stays unclaimed; the glyph law is enforced by the encoder (`-R` on a `.X` form
//! and `~R` on a non-`.X` form are refused, not dropped); the rows are the measured ones.

use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::Path, sync::OnceLock};

const SOURCE: &str = "lea-family-2026-11-06";
const CTRL: u128 = 0x000f_ca00u128 << 96;
const TABLES: [(&str, &str); 3] = [
    ("tables/sm120.json", include_str!("fixtures/sm120_lea_nvdisasm.jsonl")),
    ("tables/sm103a.json", include_str!("fixtures/sm103a_lea_nvdisasm.jsonl")),
    ("tables/sm100a.json", include_str!("fixtures/sm100a_lea_nvdisasm.jsonl")),
];

fn loaded() -> &'static Vec<(IsaTable, DecodeIndex)> {
    static ALL: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    ALL.get_or_init(|| {
        TABLES
            .iter()
            .map(|(p, _)| {
                let table = IsaTable::load(Path::new(p)).unwrap();
                let index = DecodeIndex::build(&table);
                (table, index)
            })
            .collect()
    })
}

fn fixture(i: usize) -> Vec<Value> {
    TABLES[i].1.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn reencode(table: &IsaTable, word: u128, text: &str) -> anyhow::Result<u128> {
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {text} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none(), "{source}");
    cubit::encoder::encode_instruction(&parsed, table)
}

fn check(i: usize, word: u128, vendor: &str) -> String {
    let (table, index) = &loaded()[i];
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{}: {word:032x}: {e}", TABLES[i].0));
    assert!(decoded.key.starts_with("LEA_"), "{}: {word:032x}: {}", TABLES[i].0, decoded.key);
    // nvdisasm's one-word `-hex` text never shows `.reuse`; the production words carry reuse bits
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own.replace(".reuse", ""), vendor, "{}: {word:032x}", TABLES[i].0);
    assert_eq!(cubit::printer::to_sass(&decoded).replace(".reuse", ""), vendor, "{}: {word:032x} (display print)", TABLES[i].0);
    let again = reencode(table, word, &own).unwrap_or_else(|e| panic!("{}: {own}: {e}", TABLES[i].0));
    assert_eq!(again, word, "{}: {own}", TABLES[i].0);
    decoded.key.clone()
}

#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits_on_the_three_tables() {
    for (i, (name, _)) in TABLES.iter().enumerate() {
        let mut n = 0;
        let mut keys = std::collections::BTreeSet::new();
        for row in fixture(i) {
            if row.get("lattice").is_some() {
                continue;
            }
            let vendor = row["nvidia_sass"].as_str().unwrap();
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            keys.insert(check(i, word, vendor));
            n += 1;
        }
        assert_eq!(n, 615, "{}: form words in the fixture", name);
        assert_eq!(keys.len(), 24, "{}: the 24 keys of the family are all reached: {keys:?}", name);
    }
}

#[test]
fn the_lattice_around_the_family_is_never_rendered_as_another_text() {
    for (i, (name, _)) in TABLES.iter().enumerate() {
        let (table, index) = &loaded()[i];
        let (mut n, mut undecoded) = (0, 0);
        for row in fixture(i) {
            if row.get("lattice").is_none() {
                continue;
            }
            n += 1;
            let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
            match index.decode(word, 0, table) {
                Err(_) => undecoded += 1,
                Ok(d) => {
                    // a lattice word nvdisasm names (text-inert bit) may only print exactly that text
                    let vendor = row["nvidia_sass"].as_str();
                    assert_eq!(Some(cubit::printer::to_sass_lossless(&d).as_str()), vendor,
                        "{}: lattice word {word:032x} decodes as another text", name);
                }
            }
        }
        assert_eq!(n, 209, "{}", name);
        assert_eq!(undecoded, 209, "{}: every lattice word stays unclaimed (inert bits, wrong frame, .SX32 without .HI, unused opcodes)", name);
    }
}

/// The words of the dynamic audit (`T/audit/dyn11`) that used to print another text, a text with a lost
/// operand, or decode through a junk key — now the vendor text on the three tables.
#[test]
fn the_audit_words_print_the_vendor_text() {
    for (word, vendor) in [
        (0x000fe20003870eff0000000a08047211u128, "LEA.HI.X.SX32 R4, P3, R8, R10, 0x1, PT"),
        (0x000fe20000070eff0000000a08047211u128, "LEA.HI.X.SX32 R4, P3, R8, R10, 0x1, P0"),
        (0x000fe200008f5407ffffffff04137811u128, "LEA.HI.X R19, R4, 0xffffffff, R7, 0xa, P1"),
        (0x000fe200038f140a000000fe18117211u128, "LEA.HI.X R17, R24, R254, R10, 0x2, PT"),
        (0x000fe2000b8f15ff0000000e0c097c11u128, "LEA.HI.X R9, ~R12, UR14, RZ, 0x2, PT"),
        (0x000fe200090f15ff0000000e0c097c11u128, "LEA.HI.X R9, ~R12, UR14, RZ, 0x2, P2"),
        (0x000fe200078608ff000000fe08087211u128, "LEA R8, P3, R8, R254, 0x1"),
        (0x000fe200078e08ff000000fe10087211u128, "LEA R8, R16, R254, 0x1"),
        (0x000fe200078490ff000000402e047811u128, "LEA R4, P2, R46, 0x40, 0x12"),
        (0x000fe20002010eff0000001006047211u128, "LEA.HI.X.SX32 R4, P0, R6, R16, 0x1, P4"),
        (0x000fe200078e08ff0000000a08047211u128, "LEA R4, R8, R10, 0x1"),
    ] {
        for i in 0..TABLES.len() {
            check(i, word, vendor);
        }
    }
}

/// One real word per (form, modifier group, carry-in, Rc) class of the 26 372 LEA words in the production
/// census corpus (`L/census/cubins`, nvcc sm_120; the classes were counted by scanning the `.text` words with
/// opcode 0x211 / 0x811 / 0xc11): every non-`.X` word carries nvcc's `!PT` carry-in [90:87] = 0xf and Rc = RZ,
/// bits 84-86 / 92-95 clear, the imm32 window clear on the register / UR forms — the values the rows bake.
#[test]
fn one_production_word_per_class_prints_the_vendor_text() {
    for (word, vendor) in [
        (0x040fe4000f8408ff000000061c1e7c11u128, "LEA R30, P2, R28, UR6, 0x1"),
        (0x040fe800078010ff00000016041e7211u128, "LEA R30, P0, R4, R22, 0x2"),
        (0x000fca00080f0c110000000510177c11u128, "LEA.HI.X R23, R16, UR5, R17, 0x1, P0"),
        (0x000fe400078f28ff000000050c0b9211u128, "@!P1 LEA.HI R11, R12, R5, RZ, 0x5"),
        (0x000fca00088f140500000005042d7c11u128, "LEA.HI.X R45, R4, UR5, R5, 0x2, P1"),
        (0x000fe400090f0c1d000000071c1f7c11u128, "LEA.HI.X R31, R28, UR7, R29, 0x1, P2"),
        (0x000fe200078e10fffffffffe0e0d7811u128, "LEA R13, R14, 0xfffffffe, 0x2"),
        (0x000fe4000f8fe0ff00000010742d7c11u128, "LEA.HI R45, R116, UR16, RZ, 0x1c"),
        (0x000fe200000f1405000000090409a211u128, "@!P2 LEA.HI.X R9, R4, R9, R5, 0x2, P0"),
        (0x000fe400018f14070000000f060f9211u128, "@!P1 LEA.HI.X R15, R6, R15, R7, 0x2, P3"),
        (0x000fc600010f14050000000d040d9211u128, "@!P1 LEA.HI.X R13, R4, R13, R5, 0x2, P2"),
        (0x000fe200078fc8ffffffffff1f119811u128, "@!P1 LEA.HI R17, R31, 0xffffffff, RZ, 0x19"),
        (0x000fc600008f14070000000b060ba211u128, "@!P2 LEA.HI.X R11, R6, R11, R7, 0x2, P1"),
        (0x000fe200098f1412000000071b1f7c11u128, "LEA.HI.X R31, R27, UR7, R18, 0x2, P3"),
        (0x000fe200020f14090000001508158211u128, "@!P0 LEA.HI.X R21, R8, R21, R9, 0x2, P4"),
        (0x000fe400028f140b000000170a178211u128, "@!P0 LEA.HI.X R23, R10, R23, R11, 0x2, P5"),
        (0x000fe2000a0f14090000001906097c11u128, "LEA.HI.X R9, R6, UR25, R9, 0x2, P4"),
        (0x000fe200030f0c030000001302115211u128, "@P5 LEA.HI.X R17, R2, R19, R3, 0x1, P6"),
        (0x000fea00078fe2ff0000000300037211u128, "LEA.HI.SX32 R3, R0, R3, 0x1c"),
        (0x000fe400010f44ff0000000703057211u128, "LEA.HI.X R5, R3, R7, RZ, 0x8, P2"),
        (0x000fc600080f84ff00000007490d7c11u128, "LEA.HI.X R13, R73, UR7, RZ, 0x10, P0"),
        (0x000fe400078fdaffffffffff0b1c9811u128, "@!P1 LEA.HI.SX32 R28, R11, 0xffffffff, 0x1b"),
        (0x040fe200000f2cff0000000903177211u128, "LEA.HI.X R23, R3, R9, RZ, 0x5, P0"),
        (0x000fe400008f44ff00000005031d7211u128, "LEA.HI.X R29, R3, R5, RZ, 0x8, P1"),
        (0x000fe400018f84ff000000ff0c0c7211u128, "LEA.HI.X R12, R12, RZ, RZ, 0x10, P3"),
        (0x000fd200088f14ff0000000500097c11u128, "LEA.HI.X R9, R0, UR5, RZ, 0x2, P1"),
        (0x000fca00098f14ff00000005242b7c11u128, "LEA.HI.X R43, R36, UR5, RZ, 0x2, P3"),
        (0x000fe400000f16ff00000017041f7211u128, "LEA.HI.X.SX32 R31, R4, R23, 0x2, P0"),
        (0x000fe2000b0f146d0000000b6c057c11u128, "LEA.HI.X R5, R108, UR11, R109, 0x2, P6"),
        (0x000fe2000a8f146b0000000b6a097c11u128, "LEA.HI.X R9, R106, UR11, R107, 0x2, P5"),
    ] {
        for i in 0..TABLES.len() {
            check(i, word, vendor);
        }
    }
}

/// The sign glyph follows the form: `-` on the forms without `.X`, `~` on the `.X` forms (nvdisasm 13.1
/// on the three targets). The encoder refuses the other glyph instead of dropping it silently — before,
/// `LEA.HI.X R4, ~R8, UR10, R6, 0x1, PT` minted the word WITHOUT bit 72 through the B300-4 row.
#[test]
fn the_sign_glyph_is_enforced_not_dropped() {
    for (i, (name, _)) in TABLES.iter().enumerate() {
        let (table, _) = &loaded()[i];
        let ok = |text: &str| reencode(table, CTRL, text).unwrap_or_else(|e| panic!("{}: {text}: {e}", name));
        let refused = |text: &str| {
            let e = reencode(table, CTRL, text).err().unwrap_or_else(|| panic!("{}: {text} must be refused", name)).to_string();
            assert!(e.contains("bitwise inverse") || e.contains("negation") || e.contains("absolute value"), "{}: {text}: {e}", name);
        };
        assert_eq!(ok("LEA.HI.X R4, ~R8, UR10, R6, 0x1, PT") & (1 << 72), 1 << 72, "{}", name);
        assert_eq!(ok("LEA.HI.X R4, R8, ~UR10, R6, 0x1, PT") & (1 << 63), 1 << 63, "{}", name);
        assert_eq!(ok("LEA R4, -R8, R10, 0x1") & (1 << 72), 1 << 72, "{}", name);
        assert_eq!(ok("LEA.HI R4, R8, -UR10, R6, 0x1") & (1 << 63), 1 << 63, "{}", name);
        refused("LEA.HI.X R4, -R8, UR10, R6, 0x1, PT");
        refused("LEA.X R4, R8, -R10, 0x1, PT");
        refused("LEA R4, ~R8, R10, 0x1");
        refused("LEA.HI R4, R8, ~UR10, R6, 0x1");
        refused("LEA R4, |R8|, R10, 0x1");
        // the imm32 form has no <b> sign bit: `-0x10` is the 32-bit immediate 0xfffffff0, printed unsigned
        assert_eq!((ok("LEA R4, R8, -0x10, 0x1") >> 32) & 0xffff_ffff, 0xffff_fff0, "{}", name);
    }
}

#[test]
fn the_rows_are_the_measured_ones() {
    for (path, _) in TABLES {
        let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(Path::new(path)).unwrap()).unwrap();
        let ins = raw["instructions"].as_object().unwrap();
        let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
        let lea: Vec<&String> = ins.keys().filter(|k| k.split('_').next().unwrap().split('.').next().unwrap() == "LEA").collect();
        assert_eq!(lea.len(), 24, "{path}: {lea:?}");
        assert!(lea.iter().all(|k| k.starts_with("LEA_") && !k.contains('?')), "{path}: no dotted or `?` keys: {lea:?}");
        let mut rows = 0;
        for key in &lea {
            let groups = ins[*key]["mod_groups"].as_object().unwrap();
            for (name, g) in groups {
                rows += 1;
                assert_eq!(g["_src"], SOURCE, "{path}: {key} {name}");
                let mut field_mask = 0u128;
                for f in g["fields"].as_array().unwrap() {
                    let (shift, bits) = (f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap());
                    let mask = ((1u128 << bits) - 1) << shift;
                    assert_eq!(field_mask & mask, 0, "{path}: {key} {name}: overlapping fields");
                    field_mask |= mask;
                }
                assert_eq!(number(&g["variable_mask"]), field_mask, "{path}: {key} {name}: mask = field union");
                let and_base = number(&g["and_base"]);
                assert_eq!(and_base & field_mask, 0, "{path}: {key} {name}: and_base clear in the fields");
                assert_eq!(and_base >> 105, 0, "{path}: {key} {name}: no baked control bits");
                let mods: Vec<&str> = name.split(',').filter(|m| !m.is_empty()).collect();
                assert_eq!((and_base >> 80) & 1 == 1, mods.contains(&"HI"), "{path}: {key} {name}: bit 80 = .HI");
                assert_eq!((and_base >> 74) & 1 == 1, mods.contains(&"X"), "{path}: {key} {name}: bit 74 = .X");
                assert_eq!((and_base >> 73) & 1 == 1, mods.contains(&"SX32"), "{path}: {key} {name}: bit 73 = .SX32");
                assert_eq!((and_base >> 91) & 1 == 1, key.contains("_UR_"), "{path}: {key} {name}: frame bit on the UR form only");
                let sign = if mods.contains(&"X") { "inv" } else { "neg" };
                let fields = g["fields"].as_array().unwrap();
                let imm32 = fields.iter().any(|f| f["shift"] == 32 && f["bits"] == 32);
                let signs = fields.iter().filter(|f| f["shift"] == 72 || f["shift"] == 63).count();
                assert!(fields.iter().filter(|f| f["shift"] == 72 || f["shift"] == 63).all(|f| f["extraction"] == sign),
                    "{path}: {key} {name}: the sign bits are `{sign}` fields");
                assert_eq!(signs, if imm32 { 1 } else { 2 }, "{path}: {key} {name}: Ra, and Rb/URb unless <b> is the immediate");
                if !key.contains("_P_R_") {
                    assert_eq!((and_base >> 81) & 7, 7, "{path}: {key} {name}: Pd = PT baked");
                }
                if !mods.contains(&"X") {
                    assert_eq!((and_base >> 87) & 0xf, 0xf, "{path}: {key} {name}: carry-in text-inert, nvcc's !PT baked");
                }
            }
        }
        assert_eq!(rows, 36, "{path}");
        let prov = &raw["_meta"]["provenance"]["sources"][SOURCE];
        assert_eq!(prov["rows"], 36, "{path}: provenance entry");
    }
}

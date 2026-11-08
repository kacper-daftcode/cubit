//! SM103a / SM100a global reduction, uniform-indexed address forms (session T-20, 2026-11-08; KNOWN_ISSUES T1 -- the first
//! batch of the B300 line): the two plain keys `REDG_ARURI_R` / `REDG_ARURI64_R` of `sm103a.json` and `sm100a.json` carry the
//! rows `tools/probes/re_sm120_redg.py --arch SM103` / `SM100` measures with nvdisasm 13.1 -- G's sm120 sweep of 2026-11-07
//! (9 334 form + 58 lattice words) prints the same text on the two targets word for word (the probe asserts the law on every
//! word; fixtures `tests/fixtures/sm103a_redg_aruri_nvdisasm.jsonl` / `sm100a_...`). Law, retirement and checks exactly as in
//! `tests/sm120_redg_aruri.rs` (the 6 144 dotted one-group harvest keys of each table retired as `_meta.key_aliases`; 0 witnesses
//! in the B300 publish corpus); this file runs the same five checks over the two tables.
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "redg-aruri-family-2026-11-07";
const CTRL: u128 = 0x000f_e200u128 << 96;
const OPC: u128 = 0x98e;
const KEYS: [&str; 2] = ["REDG_ARURI_R", "REDG_ARURI64_R"];
const SCOPE: [&str; 16] = [
    "", "CONSTANT.PRIVATE", "CONSTANT.CTA", "CONSTANT.CTA.PRIVATE", "STRONG.SM.PRIVATE", "STRONG.SM", "STRONG.GPU.PRIVATE",
    "STRONG.GPU", "MMIO.GPU", "CONSTANT.SM", "STRONG.SYS", "CONSTANT.SM.PRIVATE", "MMIO.SYS", "CONSTANT.VC",
    "CONSTANT.VC.PRIVATE", "CONSTANT.GPU",
];
const CACHE: [&str; 6] = ["EF", "", "EL", "LU", "EU", "NA"];
const TYPE: [&str; 4] = ["", "S32", "64", "S64"];
const OP: [&str; 8] = ["ADD", "MIN", "MAX", "INC", "DEC", "AND", "OR", "XOR"];

fn is_family_key(k: &str) -> bool {
    KEYS.contains(&k)
}

fn is_retired_dotted(k: &str) -> bool {
    k.starts_with("REDG.") && (k.ends_with("_ARURI_R") || k.ends_with("_ARURI64_R"))
}

const TABLES: [(&str, &str, &str); 2] = [
    ("tables/sm103a.json", "SM103", include_str!("fixtures/sm103a_redg_aruri_nvdisasm.jsonl")),
    ("tables/sm100a.json", "SM100", include_str!("fixtures/sm100a_redg_aruri_nvdisasm.jsonl")),
];

fn table_path(i: usize) -> PathBuf {
    TABLES[i].0.into()
}

fn table_and_index(i: usize) -> &'static (IsaTable, DecodeIndex) {
    static TABLE: OnceLock<Vec<(IsaTable, DecodeIndex)>> = OnceLock::new();
    &TABLE.get_or_init(|| {
        TABLES.iter().map(|(path, _, _)| {
            let table = IsaTable::load(std::path::Path::new(path)).unwrap();
            let index = DecodeIndex::build(&table);
            (table, index)
        }).collect()
    })[i]
}

fn fixture(i: usize) -> Vec<Value> {
    TABLES[i].2.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn word_of(row: &Value) -> u128 {
    u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL
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

fn refused(table: &IsaTable, text: &str) -> bool {
    cubit::parser::parse_sass(text, 0).map_or(true, |p| cubit::encoder::encode_instruction(&p, table).is_err())
}

/// Decode, print (display and lossless = the vendor text) and re-encode bit for bit; the `.64` form's RZ base is the
/// vendor's `???255` glyph -- printed as the vendor prints it, refused by the encoder (BUG-461).
fn check(i: usize, word: u128, vendor: &str) -> (String, String) {
    let (table, index) = table_and_index(i);
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{}: {word:032x}: {e}", TABLES[i].0));
    assert!(is_family_key(&decoded.key), "{word:032x}: {}", decoded.key);
    assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{word:032x} (display print)");
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{word:032x} (lossless print)");
    if vendor.contains("???255") {
        assert!(refused(table, vendor), "{vendor}: the degenerate glyph is never minted");
    } else if TABLES[i].1 == "SM103" && vendor.starts_with('@') && !vendor.starts_with("@PT ") {
        // BUG-080 (silicon, B300 2026-08-22): a guard-predicated non-EL reduction is silently broken on sm_103a -- the
        // encoder refuses to mint it on that table (decode and print stay vendor-true, checked above); the word
        // itself is the vendor's, so the refusal is the measured law, not a table defect.
        let control = cubit::scheduling::format_control_code(&cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
        let parsed = cubit::parse_cuasm_line(&format!("[{control}] {vendor} ;"), 0).unwrap();
        match cubit::encoder::encode_instruction(&parsed, table) {
            Err(e) => assert!(e.to_string().contains("BUG-080"), "{vendor}: {e}"),
            Ok(w) => panic!("{vendor}: a guarded non-EL REDG assembled on sm_103a ({w:032x}) -- BUG-080 must refuse it"),
        }
    } else {
        assert_eq!(reencode(table, word, vendor), word, "{vendor}");
    }
    (decoded.key.clone(), decoded.mod_group.clone())
}

/// The modifier bits a group name stands for (the probe's law) in [89:72].
fn law(name: &str) -> u128 {
    let toks: Vec<&str> = name.split(',').collect();
    let has = |t: &str| toks.contains(&t);
    let e = u128::from(has("E"));
    let op = OP.iter().position(|o| has(o)).unwrap_or_else(|| panic!("{name}: no op")) as u128;
    let ty = TYPE.iter().position(|t| !t.is_empty() && has(t)).unwrap_or(0) as u128;
    let cache = CACHE.iter().position(|c| !c.is_empty() && has(c)).unwrap_or(1) as u128;
    let rest: Vec<&str> = toks.iter().copied()
        .filter(|t| *t != "E" && !OP.contains(t) && !TYPE.contains(t) && !CACHE.contains(t)).collect();
    let scope = SCOPE.iter().position(|s| {
        let mut want: Vec<&str> = s.split('.').filter(|t| !t.is_empty()).collect();
        let mut got = rest.clone();
        want.sort_unstable();
        got.sort_unstable();
        want == got
    }).unwrap_or_else(|| panic!("{name}: no scope enum value spells {rest:?}")) as u128;
    (e << 72) | (op << 87) | (ty << 73) | (cache << 84) | (scope << 77)
}

/// Every form word (the 9 216 groups on the canonical operands, the operand lattice of two groups per key -- guard,
/// Ra / Rb / URb at 0, 1, 63 and 255, the offsets +0x1 / +0x10 / +0x1234 / +0x7fffff / -0x800000 / -0x1 -- and one
/// word per key with every field away from its canonical value) decodes to the two keys, prints NVIDIA's text and
/// re-encodes bit for bit (the 16 `???255` glyph words of the `.64` form print the glyph and are refused by the encoder).
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    for i in 0..TABLES.len() {
        let mut n = 0;
        let mut glyph = 0;
        let mut groups = std::collections::BTreeSet::new();
        for row in fixture(i) {
            if row.get("lattice").is_some() {
                continue;
            }
            assert_eq!(row["arch"], TABLES[i].1, "{}: {}", TABLES[i].0, row["word"]);
            let vendor = row["nvidia_sass"].as_str().unwrap();
            groups.insert(check(i, word_of(&row), vendor));
            n += 1;
            glyph += usize::from(vendor.contains("???255"));
        }
        assert_eq!(n, 9334, "{}: form words in the fixture", TABLES[i].0);
        assert_eq!(glyph, 16, "{}: the `.64` form's RZ-base words (the vendor's degenerate glyph)", TABLES[i].0);
        assert_eq!(groups.len(), 6144 + 3072, "{}: every group of the two keys has a form word", TABLES[i].0);
    }
}

/// The lattice: bit 91 clear (the `[Ra(+off)]` form), the text-inert bits [23:16] / 76 / 82 / 83 / 92-95, the
/// INVALID type and cache planes, the descriptor bit, the `.64` base without `.E` (the `???0` glyph plane) -- never
/// claimed by the two keys: undecoded, or (a legal word of another form) decoded to another key with the vendor's text.
/// The encoder refuses the unmodelled spellings.
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
  for i in 0..TABLES.len() {
    let (table, index) = table_and_index(i);
    let (mut n, mut undecoded, mut other) = (0, 0, 0);
    for row in fixture(i) {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let word = word_of(&row);
        let vendor = row["nvidia_sass"].as_str();
        match index.decode(word, 0, table) {
            Err(_) => undecoded += 1,
            Ok(d) => {
                let text = cubit::printer::to_sass_lossless(&d);
                assert!(!is_family_key(&d.key), "lattice word {word:032x} ({vendor:?}) claimed by {} as {text}", d.key);
                let vendor = vendor.unwrap_or_else(|| panic!("illegal word {word:032x} decodes through {} as {text}", d.key));
                assert!(!vendor.contains("???") && !vendor.contains("INVALID"), "{word:032x}: the vendor's glyph {vendor} decodes through {} as {text}", d.key);
                assert_eq!(text, vendor, "{word:032x}: another form's word through {}", d.key);
                other += 1;
            }
        }
    }
    assert_eq!(n, 58);
    assert_eq!(undecoded + other, n);
    assert!(other <= 4, "{other} lattice words are other forms' legal words (the `[Ra]` and descriptor forms)");
    for text in ["REDG.ADD.EL.STRONG.GPU [R2.64+UR4], R6", "REDG.E.ADD.INVALID4.STRONG.GPU [R2.U32+UR4], R6",
                 "REDG.E.ADD.INVALID6.STRONG.GPU [R2.U32+UR4], R6", "REDG.E.ADD.EL.STRONG [R2.U32+UR4], R6",
                 "REDG.E.ADD.EL.SYS.ORDERED [R2.U32+UR4], R6", "REDG.E.ADD.EL.STRONG.GPU [R2.U32+UR4+0x1000000], R6",
                 "REDG.E.ADD.EL.STRONG.GPU [???255.64+UR4], R6"] {
        assert!(refused(table, text), "{text} must be refused");
    }
  }
}

/// The two forms and their bases: bit 90 selects the `.64` base; the U32 form prints RZ (`[RZ.U32+UR4]`) and
/// re-encodes it, the `.64` form prints the glyph and refuses to mint it; the U32 form has a no-`.E` plane
/// (`REDG.ADD.EL.STRONG.GPU`), the `.64` form's no-`.E` words fail closed; a negative offset prints `+-0x1`.
#[test]
fn the_two_address_forms_and_their_bases() {
  for i in 0..TABLES.len() {
    let (table, index) = table_and_index(i);
    let base = 0x000fe2000820e104000000060200798eu128; // REDG.E.ADD.EL.STRONG.GPU [R2.U32+UR4], R6
    let key = |w: u128| index.decode(w, 0, table).unwrap().key;
    assert_eq!(key(base), "REDG_ARURI_R");
    assert_eq!(key(base | (1u128 << 90)), "REDG_ARURI64_R");
    let d = index.decode(base | (1u128 << 90), 0, table).unwrap();
    assert_eq!(cubit::printer::to_sass(&d), "REDG.E.ADD.EL.STRONG.GPU [R2.64+UR4], R6");
    let rz = base | (0xffu128 << 24);
    let d = index.decode(rz, 0, table).unwrap();
    assert_eq!(cubit::printer::to_sass(&d), "REDG.E.ADD.EL.STRONG.GPU [RZ.U32+UR4], R6");
    assert_eq!(reencode(table, rz, "REDG.E.ADD.EL.STRONG.GPU [RZ.U32+UR4], R6"), rz);
    let d = index.decode(rz | (1u128 << 90), 0, table).unwrap();
    assert_eq!(d.key, "REDG_ARURI64_R");
    assert_eq!(cubit::printer::to_sass(&d), "REDG.E.ADD.EL.STRONG.GPU [???255.64+UR4], R6");
    assert!(refused(table, "REDG.E.ADD.EL.STRONG.GPU [???255.64+UR4], R6"));
    let no_e = base & !(1u128 << 72);
    let d = index.decode(no_e, 0, table).unwrap();
    assert_eq!((d.key.as_str(), d.mod_group.as_str()), ("REDG_ARURI_R", "ADD,EL,GPU,STRONG"));
    assert_eq!(cubit::printer::to_sass(&d), "REDG.ADD.EL.STRONG.GPU [R2.U32+UR4], R6");
    assert_eq!(reencode(table, no_e, "REDG.ADD.EL.STRONG.GPU [R2.U32+UR4], R6"), no_e);
    assert!(index.decode(no_e | (1u128 << 90), 0, table).is_err(), "the .64 base without .E is the vendor's ???0 glyph");
    let neg = base | (0xffffffu128 << 40);
    let d = index.decode(neg, 0, table).unwrap();
    assert_eq!(cubit::printer::to_sass(&d), "REDG.E.ADD.EL.STRONG.GPU [R2.U32+UR4+-0x1], R6");
    assert_eq!(reencode(table, neg, "REDG.E.ADD.EL.STRONG.GPU [R2.U32+UR4+-0x1], R6"), neg);
    let typed = (base | (3u128 << 73) | (7u128 << 87)) & !(7u128 << 77) | (14u128 << 77); // XOR.EL.S64.CONSTANT.VC.PRIVATE
    let d = index.decode(typed, 0, table).unwrap();
    assert_eq!(cubit::printer::to_sass(&d), "REDG.E.XOR.EL.S64.CONSTANT.VC.PRIVATE [R2.U32+UR4], R6");
  }
}

/// The two keys carry their full measured lattice (`_src`, mask == the fields, nothing baked under a field, the
/// opcode, bit 91, the base bit and the modifier bits of their group name and nothing else, no `claim_forbid`), no
/// dotted `_ARURI_R` / `_ARURI64_R` key is left, the 6 144 aliases point at the plain key of their operand signature
/// and name one of its groups, the legend = the live count.
#[test]
fn the_rows_are_measured_and_the_dotted_keys_are_gone() {
  for i in 0..TABLES.len() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path(i)).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let left: Vec<&String> = ins.keys().filter(|k| is_retired_dotted(k)).collect();
    assert!(left.is_empty(), "{left:?}");
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    let mut n_alias = 0;
    for (old, new) in aliases {
        if !is_retired_dotted(old) {
            continue;
        }
        n_alias += 1;
        let new = new.as_str().unwrap();
        let (mn, sig) = old.split_once('_').unwrap();
        assert_eq!(new, format!("REDG_{sig}"), "{old} -> {new}");
        assert!(ins.get(old).is_none(), "{old} still a key");
        assert!(is_family_key(new), "{old} -> {new}");
        let mut toks: Vec<&str> = mn.split('.').skip(1).collect();
        toks.sort_unstable();
        let group = toks.join(",");
        assert!(ins[new]["mod_groups"].get(&group).is_some(), "{old}: its spelling names no group {group} of {new}");
    }
    assert_eq!(n_alias, 6144, "the dotted one-group keys of the two uniform-indexed forms");
    let tagged = ins.values().filter_map(|e| e["mod_groups"].as_object()).flat_map(|m| m.values()).filter(|g| g["_src"] == SOURCE).count();
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], tagged);
    assert_eq!(tagged, 6144 + 3072);
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for (key, n_groups, base_bit) in [("REDG_ARURI_R", 6144usize, 0u128), ("REDG_ARURI64_R", 3072, 1u128 << 90)] {
        assert_eq!(ins[key]["_src"], SOURCE, "{key}");
        assert_eq!(ins[key]["base_op"], "REDG", "{key}");
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), n_groups, "{key}");
        for (name, g) in groups {
            assert_eq!(g["_src"], SOURCE, "{key} {name}");
            assert!(g["count"].is_null(), "{key} {name}: measured rows carry no harvest count");
            if base_bit != 0 {
                assert!(name.split(',').any(|t| t == "E"), "{key} {name}: the .64 base needs .E");
            }
            let mut field_mask = 0u128;
            let mut kinds = std::collections::BTreeSet::new();
            for f in g["fields"].as_array().unwrap() {
                let bits = ((1u128 << f["bits"].as_u64().unwrap()) - 1) << f["shift"].as_u64().unwrap();
                assert_eq!(field_mask & bits, 0, "{name}: overlapping fields");
                field_mask |= bits;
                kinds.insert(format!("{}@{}:{}#{}", f["extraction"].as_str().unwrap(), f["shift"], f["bits"], f["token_idx"]));
            }
            assert_eq!(number(&g["variable_mask"]), field_mask, "{key} {name}");
            let base = number(&g["and_base"]);
            assert_eq!(base & field_mask, 0, "{key} {name}");
            assert_eq!(base >> 96, 0, "{key} {name}");
            assert_eq!(base, OPC | (1u128 << 91) | base_bit | law(name), "{key} {name}: and_base = opcode + bit 91 + the base bit + the modifier bits of the name");
            let want: std::collections::BTreeSet<String> = ["guard@12:4#0", "reg@24:8#1", "ureg@64:8#1", "imm@40:24#1", "reg@32:8#2"]
                .into_iter().map(String::from).collect();
            assert_eq!(kinds, want, "{key} {name}: the fields");
            assert!(g.get("claim_forbid").is_none(), "{key} {name}: every base is legal (RZ prints, the .64 glyph is a print matter)");
        }
    }
  }
}

/// Every retired dotted key round-trips through the plain key: the text its spelling names (`REDG.<mods>
/// [R2.U32+UR4], R6` / `[R2.64+UR4], R6`) encodes to a word that decodes to the alias's target and the group its
/// tokens name, and prints the same text back.
#[test]
fn every_alias_round_trips_through_the_plain_key() {
  for i in 0..TABLES.len() {
    let (table, index) = table_and_index(i);
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path(i)).unwrap()).unwrap();
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    let mut n = 0;
    for (old, new) in aliases {
        if !is_retired_dotted(old) {
            continue;
        }
        n += 1;
        let (mn, sig) = old.split_once('_').unwrap();
        let addr = if sig.starts_with("ARURI64") { "[R2.64+UR4]" } else { "[R2.U32+UR4]" };
        let text = format!("{mn} {addr}, R6");
        let parsed = cubit::parser::parse_sass(&text, 0).unwrap_or_else(|e| panic!("{text}: {e}"));
        let word = cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{text}: {e}")) | CTRL;
        let d = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{text}: {word:032x}: {e}"));
        assert_eq!(d.key, new.as_str().unwrap(), "{text}");
        let mut toks: Vec<&str> = mn.split('.').skip(1).collect();
        toks.sort_unstable();
        assert_eq!(d.mod_group, toks.join(","), "{text}");
        assert_eq!(cubit::printer::to_sass(&d), text, "{old}");
    }
    assert_eq!(n, 6144, "{}", TABLES[i].0);
  }
}

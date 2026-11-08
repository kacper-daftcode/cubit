//! SM121a (GB10 / Spark) 256-bit global load, descriptor address form -- the sm120 law of G's batch 10 measured on
//! `-b SM121` (session T-21, 2026-11-08, `tools/probes/re_sm120_ldg256.py probe --form dARI --arch SM121 --witnesses`,
//! nvdisasm 13.1): every one of the 4 888 form words prints the SM120 text, the 81 lattice words behave the same, and
//! the 99 LDG.256 words of the GB10 census corpus (every address form, with their own control codes) obey the law.
//! `apply` created the four plain keys `LDG_R_R_dARI[_II][_P]` (1 152 measured groups each) on a table that had only
//! the 781 dotted one-group harvest keys of 2026-08/09 for the form, retired as `_meta.key_aliases` of the plain key
//! of their operand signature. The sm120 test `tests/sm120_ldg256_dari.rs` is the template (same checks, this table).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "ldg256-family-2026-11-07";
const CTRL: u128 = 0x000f_e200u128 << 96;
const OPC: u128 = 0x97e;
const KEYS: [&str; 4] = ["LDG_R_R_dARI", "LDG_R_R_dARI_II", "LDG_R_R_dARI_P", "LDG_R_R_dARI_II_P"];
const GROUPS_PER_KEY: usize = 1152;
const SCOPE: [&str; 16] = [
    "", "CONSTANT.PRIVATE", "CONSTANT.CTA", "CONSTANT.CTA.PRIVATE", "CONSTANT", "STRONG.SM", "STRONG.GPU.PRIVATE",
    "STRONG.GPU", "MMIO.GPU", "CONSTANT.SM", "STRONG.SYS", "CONSTANT.SM.PRIVATE", "MMIO.SYS", "CONSTANT.VC",
    "CONSTANT.VC.PRIVATE", "CONSTANT.GPU",
];
const CACHE: [&str; 6] = ["EF", "", "EL", "LU", "EU", "NA"];
const L2: [&str; 3] = ["EFL2", "ENL2", "ELL2"];
const LTC: [&str; 4] = ["", "LTC64B", "LTC128B", "LTC256B"];

fn is_family_key(k: &str) -> bool {
    KEYS.contains(&k)
}

fn table_path() -> PathBuf {
    std::env::var_os("CUBIT_TABLE_SM121A").map(PathBuf::from).unwrap_or_else(|| "tables/sm121a.json".into())
}

fn table_and_index() -> &'static (IsaTable, DecodeIndex) {
    static TABLE: OnceLock<(IsaTable, DecodeIndex)> = OnceLock::new();
    TABLE.get_or_init(|| {
        let table = IsaTable::load(&table_path()).unwrap();
        let index = DecodeIndex::build(&table);
        (table, index)
    })
}

fn fixture() -> Vec<Value> {
    include_str!("fixtures/sm121a_ldg256_dari_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
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

fn check(word: u128, vendor: &str) -> (String, String) {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    assert!(is_family_key(&decoded.key), "{word:032x}: {}", decoded.key);
    assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{word:032x}");
    assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{word:032x} (display print)");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
    (decoded.key.clone(), decoded.mod_group.clone())
}

/// The modifier bits a group name stands for (the probe's law) in [86:73].
fn law(name: &str) -> u128 {
    let toks: Vec<&str> = name.split(',').collect();
    let has = |t: &str| toks.contains(&t);
    assert!(has("E") && has("256"), "{name}");
    let cache = CACHE.iter().position(|c| !c.is_empty() && has(c)).unwrap_or(1) as u128;
    let l2 = L2.iter().position(|c| has(c)).unwrap_or_else(|| panic!("{name}: no L2 hint")) as u128;
    let ltc = LTC.iter().position(|c| !c.is_empty() && has(c)).unwrap_or(0) as u128;
    let rest: Vec<&str> = toks.iter().copied()
        .filter(|t| !matches!(*t, "E" | "256") && !CACHE.contains(t) && !L2.contains(t) && !LTC.contains(t)).collect();
    let scope = SCOPE.iter().position(|s| {
        let mut want: Vec<&str> = s.split('.').filter(|t| !t.is_empty()).collect();
        let mut got = rest.clone();
        want.sort_unstable();
        got.sort_unstable();
        want == got
    }).unwrap_or_else(|| panic!("{name}: no scope enum value spells {rest:?}")) as u128;
    (cache << 84) | (l2 << 81) | (ltc << 73) | (scope << 77)
}

/// Every form word (the 4 608 groups on the canonical operands, the operand lattice of two groups per key -- guard,
/// Rd0 / Rd1 / URb at 0, 1, 63 and 255, Ra at 0, 1 and 63, the offsets +0x20 / +0x40 / +0x24680 / +0x1fffe0 /
/// -0x200000 / -0x20, the trailing byte at 0x1 / 0x12 / 0x7f / 0x80 / 0xfe, every trailing predicate -- and one word
/// per key with every field away from its canonical value) decodes to the four keys, prints NVIDIA's text (display
/// and lossless) and re-encodes bit for bit.
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let mut groups = std::collections::BTreeSet::new();
    for row in fixture() {
        if row.get("lattice").is_some() || row.get("witness").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        groups.insert(check(word_of(&row), vendor));
        n += 1;
    }
    assert_eq!(n, 4888, "form words in the fixture");
    assert_eq!(groups.len(), 4 * GROUPS_PER_KEY, "every group of the four keys has a form word");
}

/// The lattice: the frame bit clear, the text-inert bits 83 / 92-95, the INVALID6 / INVALID7 cache codes, the RML2
/// plane (L2 = 3), the illegal address bits (75 clear with 76 set) and `desc[UR][RZ.64]` -- never claimed. The encoder
/// refuses the unmodelled spellings.
#[test]
fn the_lattice_around_the_form_is_never_rendered_as_another_text() {
    let (table, index) = table_and_index();
    let (mut n, mut undecoded) = (0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() || row.get("witness").is_some() {
            continue;
        }
        n += 1;
        let word = word_of(&row);
        match index.decode(word, 0, table) {
            Err(_) => undecoded += 1,
            Ok(d) => panic!("lattice word {word:032x} ({:?}) decodes as {}", row["nvidia_sass"], cubit::printer::to_sass_lossless(&d)),
        }
    }
    assert_eq!((n, undecoded), (81, 81));
    for text in ["LDG.E.EF.EFL2.256 R4, R6, desc[UR4][RZ.64]", "LDG.E.INVALID6.EFL2.256 R4, R6, desc[UR4][R2.64]",
                 "LDG.E.EF.RML2.256.STRONG.GPU R4, R6, desc[UR4][R2.64]", "LDG.E.EF.EFL2.256.STRONG R4, R6, desc[UR4][R2.64]",
                 "LDG.E.EF.EFL2.256.MMIO.CTA R4, R6, desc[UR4][R2.64]", "LDG.E.EF.EFL2.128 R4, R6, desc[UR4][R2.64]"] {
        let refused = cubit::parser::parse_sass(text, 0).map_or(true, |p| cubit::encoder::encode_instruction(&p, table).is_err());
        assert!(refused, "{text} must be refused");
    }
}

/// The elided twins resolve to the plain key: a word with PT and the trailing 0xff decodes to `LDG_R_R_dARI` (the
/// `_P` / `_II` rows claim it too and lose the tie), the trailing byte alone makes it `_II`, the predicate alone `_P`.
#[test]
fn the_pt_and_0xff_twins_resolve_to_the_plain_key() {
    let (table, index) = table_and_index();
    let base = 0x000fe20008007904fe0000040206797eu128; // LDG.E.EF.EFL2.256.CONSTANT.CTA.PRIVATE R4, R6, desc[UR4][R2.64]
    let key = |w: u128| index.decode(w, 0, table).unwrap().key;
    assert_eq!(key(base), "LDG_R_R_dARI");
    assert_eq!(key(base & !(1u128 << 72)), "LDG_R_R_dARI_II"); // 0x7f
    assert_eq!(key(base | (1u128 << 87)), "LDG_R_R_dARI_P"); // P6
    assert_eq!(key((base & !(1u128 << 57)) | (8u128 << 87)), "LDG_R_R_dARI_II_P"); // 0xfe, !PT
    let d = index.decode((base & !(1u128 << 57)) | (8u128 << 87), 0, table).unwrap();
    assert_eq!(cubit::printer::to_sass(&d), "LDG.E.EF.EFL2.256.CONSTANT.CTA.PRIVATE R4, R6, desc[UR4][R2.64], 0xfe, !PT");
}

/// The four keys carry their full measured lattice (`_src`, mask == the fields, nothing baked under a field, the opcode,
/// the frame and the modifier bits of their group name and nothing else, the trailing byte baked at 0xff or carried,
/// the predicate baked at PT or carried, `claim_forbid` on the RZ base), no dotted `_R_R_dARI` key is left, the 781
/// aliases point at the plain key of their operand signature and name one of its groups, the legend names the tag.
#[test]
fn the_rows_are_measured_and_the_dotted_keys_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let left: Vec<&String> = ins.keys().filter(|k| k.starts_with("LDG.") && k.contains("_R_R_dARI")).collect();
    assert!(left.is_empty(), "{left:?}");
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    let mut n_alias = 0;
    for (old, new) in aliases {
        if !(old.starts_with("LDG.") && old.contains("_R_R_dARI")) {
            continue;
        }
        n_alias += 1;
        let new = new.as_str().unwrap();
        let (mn, sig) = old.split_once('_').unwrap();
        assert_eq!(new, format!("LDG_{sig}"), "{old} -> {new}");
        assert!(ins.get(old).is_none(), "{old} still a key");
        assert!(is_family_key(new), "{old} -> {new}");
        let mut toks: Vec<&str> = mn.split('.').skip(1).collect();
        toks.sort_unstable();
        let group = toks.join(",");
        assert!(ins[new]["mod_groups"].get(&group).is_some(), "{old}: its spelling names no group {group} of {new}");
    }
    assert_eq!(n_alias, 781, "the dotted one-group keys of the descriptor form");
    // the legend counts the whole family's tag (one address form per batch): it equals the live count and covers these keys
    let tagged = ins.values().filter_map(|e| e["mod_groups"].as_object()).flat_map(|m| m.values()).filter(|g| g["_src"] == SOURCE).count();
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], tagged);
    assert!(tagged >= 4 * GROUPS_PER_KEY, "{tagged}");
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for key in KEYS {
        assert_eq!(ins[key]["_src"], SOURCE, "{key}");
        assert_eq!(ins[key]["base_op"], "LDG", "{key}");
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), GROUPS_PER_KEY, "{key}");
        let (has_ii, has_p) = (key.contains("_II"), key.ends_with("_P"));
        for (name, g) in groups {
            assert_eq!(g["_src"], SOURCE, "{key} {name}");
            assert!(g["count"].is_null(), "{key} {name}: measured rows carry no harvest count");
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
            let mut want = OPC | (1u128 << 91) | (3u128 << 75) | law(name);
            if !has_ii {
                want |= (0x7fu128 << 57) | (1u128 << 72);
            }
            assert_eq!(base, want, "{key} {name}: and_base = opcode + frame + .64 desc + the modifier bits of the name (+ 0xff)");
            let mut want_fields = vec!["guard@12:4#0", "reg@64:8#1", "reg@16:8#2", "sub_ur0@32:8#3", "sub_r1@24:8#3", "sub_imm2_shr5@40:17#3"];
            let mut tok = 4;
            if has_ii {
                want_fields.push("imm@57:7#4");
                want_fields.push("imm_shr7@72:1#4");
                tok = 5;
            }
            let pred = format!("pred_inv4@87:4#{tok}");
            if has_p {
                want_fields.push(&pred);
            }
            let want_fields: std::collections::BTreeSet<String> = want_fields.into_iter().map(String::from).collect();
            assert_eq!(kinds, want_fields, "{key} {name}: the fields");
            assert_eq!(g["claim_forbid"], serde_json::json!([{"shift": 24, "bits": 8, "values": [255]}]), "{key} {name}: desc[UR][RZ.64] is illegal");
        }
    }
}

/// Every retired dotted key round-trips through the plain key: the text its spelling names (`LDG.<mods> R4, R6,
/// desc[UR4][R2.64]`, with `, 0x0` for the `_II` keys and `, P6` for the `_P` keys) encodes to a word that decodes to
/// the alias's target and the group its tokens name, and prints the same text back.
#[test]
fn every_alias_round_trips_through_the_plain_key() {
    let (table, index) = table_and_index();
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    let mut n = 0;
    for (old, new) in aliases {
        if !(old.starts_with("LDG.") && old.contains("_R_R_dARI")) {
            continue;
        }
        n += 1;
        let (mn, sig) = old.split_once('_').unwrap();
        let mut text = format!("{mn} R4, R6, desc[UR4][R2.64]");
        if sig.contains("_II") {
            text.push_str(", 0x0");
        }
        if sig.ends_with("_P") {
            text.push_str(", P6");
        }
        let parsed = cubit::parser::parse_sass(&text, 0).unwrap_or_else(|e| panic!("{text}: {e}"));
        let word = cubit::encoder::encode_instruction(&parsed, table).unwrap_or_else(|e| panic!("{text}: {e}")) | CTRL;
        let d = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{text}: {word:032x}: {e}"));
        assert_eq!(d.key, new.as_str().unwrap(), "{text}");
        let mut toks: Vec<&str> = mn.split('.').skip(1).collect();
        toks.sort_unstable();
        assert_eq!(d.mod_group, toks.join(","), "{text}");
        assert_eq!(cubit::printer::to_sass(&d), text, "{old}");
    }
    assert_eq!(n, 781);
}

const PLAIN_PREFIX: &str = "LDG_R_R_";

/// The 99 LDG.256 words of the GB10 census corpus (gx4, `/root/sparklab/results/q1/corpus`; every address form of the opcode, their own control codes): each decodes to a plain key of the family or of a sibling form, prints the vendor's text and re-encodes bit for bit.
#[test]
fn the_gb10_census_words_of_the_form_round_trip() {
    let mut n = 0;
    for row in fixture() {
        if row.get("witness").is_none() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap();
        // the corpus words of the opcode span every address form of the family: a plain key of any of them
        let (table, index) = table_and_index();
        let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
        assert!(decoded.key.starts_with(PLAIN_PREFIX) && !decoded.key.contains('.'), "{word:032x}: {}", decoded.key);
        assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor, "{word:032x}");
        assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{word:032x} (display print)");
        assert_eq!(reencode(table, word, vendor), word, "{vendor}");
        n += 1;
    }
    assert_eq!(n, 99, "the GB10 census words of the form in the fixture");
}

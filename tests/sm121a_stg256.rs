//! SM121a (GB10 / Spark) 256-bit global store -- the sm120 law of G's batch 13 measured on `-b SM121` (session
//! T-21, 2026-11-08, `tools/probes/re_sm120_stg256.py probe --arch SM121 --witnesses`, nvdisasm 13.1): every one of the
//! 2 140 form words prints the SM120 text, the 93 lattice words behave the same, and the 68 STG.256 words of the GB10
//! census corpus obey the law. `apply` created `STG_{dARI,ARURI,ARURI64}_R_R[_II]` (288 measured groups each); the
//! 1 157 dotted harvest keys of the form are `_meta.key_aliases` now. The sm120 test `tests/sm120_stg256.rs` is the
//! template (same checks, this table).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "stg256-family-2026-11-07";
const CTRL: u128 = 0x000f_e200u128 << 96;
const OPC: u128 = 0x97f;
const KEYS: [&str; 6] = ["STG_dARI_R_R", "STG_dARI_R_R_II", "STG_ARURI64_R_R", "STG_ARURI64_R_R_II", "STG_ARURI_R_R", "STG_ARURI_R_R_II"];
const GROUPS_PER_KEY: usize = 288;
const SCOPE: [&str; 16] = [
    "", "CONSTANT.PRIVATE", "CONSTANT.CTA", "CONSTANT.CTA.PRIVATE", "STRONG.SM.PRIVATE", "STRONG.SM", "STRONG.GPU.PRIVATE",
    "STRONG.GPU", "MMIO.GPU", "CONSTANT.SM", "STRONG.SYS", "CONSTANT.SM.PRIVATE", "MMIO.SYS", "SYS.ORDERED",
    "STRONG.SYS.ORDERED", "MMIO.SYS.ORDERED",
];
const CACHE: [&str; 6] = ["EF", "", "EL", "LU", "EU", "NA"];
const L2: [&str; 3] = ["EFL2", "ENL2", "ELL2"];

fn is_family_key(k: &str) -> bool {
    KEYS.contains(&k)
}

fn is_retired_dotted(k: &str) -> bool {
    k.starts_with("STG.") && (k.ends_with("_R_R") || k.ends_with("_R_R_II")) && k.contains(".256")
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
    include_str!("fixtures/sm121a_stg256_nvdisasm.jsonl").lines().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn word_of(row: &Value) -> u128 {
    u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL
}

/// The address form of a word: 0 = `[Ra.U32+URb]`, 1 = `[Ra.64+URb]`, 3 = `desc[URb][Ra.64]`.
fn form_of(word: u128) -> u128 {
    (word >> 75) & 3
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

/// Decode, print and re-encode. The display print is the vendor text; so is the lossless one, except for the RZ
/// base of the U32 form, spelled `[RZ.U32+URb(+off)]` (the vendor elides it to the `.64` twin's text; the bare
/// spelling mints the `.64` word, BUG-464). The lossless text gives the word back bit for bit.
fn check(word: u128, vendor: &str) -> (String, String) {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    assert!(is_family_key(&decoded.key), "{word:032x}: {}", decoded.key);
    assert_eq!(cubit::printer::to_sass(&decoded), vendor, "{word:032x} (display print)");
    let lossless = cubit::printer::to_sass_lossless(&decoded);
    if form_of(word) == 0 && (word >> 24) & 0xff == 255 {
        assert_eq!(lossless, vendor.replacen("[UR", "[RZ.U32+UR", 1), "{word:032x} (lossless print of the RZ base)");
        assert_eq!(reencode(table, word, vendor), word | (1u128 << 75), "{vendor}: the bare spelling mints the .64 twin");
    } else {
        assert_eq!(lossless, vendor, "{word:032x} (lossless print)");
    }
    assert_eq!(reencode(table, word, &lossless), word, "{lossless}");
    (decoded.key.clone(), decoded.mod_group.clone())
}

/// The modifier bits a group name stands for (the probe's law) in [86:77].
fn law(name: &str) -> u128 {
    let toks: Vec<&str> = name.split(',').collect();
    let has = |t: &str| toks.contains(&t);
    assert!(has("E") && has("256"), "{name}");
    let cache = CACHE.iter().position(|c| !c.is_empty() && has(c)).unwrap_or(1) as u128;
    let l2 = L2.iter().position(|c| has(c)).unwrap_or_else(|| panic!("{name}: no L2 hint")) as u128;
    let rest: Vec<&str> = toks.iter().copied()
        .filter(|t| !matches!(*t, "E" | "256") && !CACHE.contains(t) && !L2.contains(t)).collect();
    let scope = SCOPE.iter().position(|s| {
        let mut want: Vec<&str> = s.split('.').filter(|t| !t.is_empty()).collect();
        let mut got = rest.clone();
        want.sort_unstable();
        got.sort_unstable();
        want == got
    }).unwrap_or_else(|| panic!("{name}: no scope enum value spells {rest:?}")) as u128;
    (cache << 84) | (l2 << 81) | (scope << 77)
}

/// Every form word (the 1 728 groups on the canonical operands, the operand lattice of two groups per key -- guard,
/// Rs0 / Rs1 / Ra / URb at 0, 1, 63 and 255 (RZ base = `[URb]` on the uniform-indexed forms), the offsets +0x20 /
/// +0x40 / +0x24680 / +0x7fffe0 / -0x800000 / -0x20, the trailing byte at 0x1 / 0x12 / 0x1f / 0x20 / 0x7f / 0x80 /
/// 0xfe -- and one word per key with every field away from its canonical value) decodes to the six keys, prints
/// NVIDIA's text and re-encodes bit for bit.
#[test]
fn every_probed_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut n = 0;
    let mut rz = 0;
    let mut groups = std::collections::BTreeSet::new();
    for row in fixture() {
        if row.get("lattice").is_some() || row.get("witness").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = word_of(&row);
        groups.insert(check(word, vendor));
        n += 1;
        rz += usize::from((word >> 24) & 0xff == 255);
    }
    assert_eq!(n, 2140, "form words in the fixture");
    assert_eq!(rz, 64, "RZ-base form words (the elided `[URb(+off)]` spelling, both uniform-indexed forms)");
    assert_eq!(groups.len(), 6 * GROUPS_PER_KEY, "every group of the six keys has a form word");
}

/// The lattice: the frame bit clear, the text-inert bits [74:72] / 83 / 87 / 92-95, the INVALID6 / INVALID7 cache
/// codes, the INVALID3 L2 plane, the illegal address bits (75 clear with 76 set) and the RZ base of the descriptor
/// form -- never claimed. The encoder refuses the unmodelled spellings (an offset that is not a multiple of 32, one
/// beyond the 19-bit window, INVALID glyphs, a bare STRONG, the load's VC scope, an LTC width).
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
    assert_eq!((n, undecoded), (93, 93));
    for text in ["STG.E.EF.EFL2.256 [R2.U32+UR4+0x10], R6, R8", "STG.E.EF.EFL2.256 [R2.64+UR4+0x800000], R6, R8",
                 "STG.E.INVALID6.EFL2.256 desc[UR4][R2.64], R6, R8", "STG.E.EF.INVALID3.256 desc[UR4][R2.64], R6, R8",
                 "STG.E.EF.EFL2.256.STRONG desc[UR4][R2.64], R6, R8", "STG.E.EF.EFL2.256.CONSTANT.VC desc[UR4][R2.64], R6, R8",
                 "STG.E.EF.EFL2.LTC64B.256 desc[UR4][R2.64], R6, R8", "STG.E.EF.EFL2.256 desc[UR4][RZ.64], R6, R8"] {
        let refused = cubit::parser::parse_sass(text, 0).map_or(true, |p| cubit::encoder::encode_instruction(&p, table).is_err());
        assert!(refused, "{text} must be refused");
    }
}

/// The elided twin resolves to the plain key: a word with the trailing 0xff decodes to `STG_<form>_R_R` (the `_II`
/// row claims it too and loses the tie), any other trailing byte makes it `_II` (both halves of the split byte). The
/// RZ base of the uniform-indexed forms prints `[UR4]` (display); the lossless print keeps `[RZ.U32+UR4]` on the U32
/// form, which re-encodes the U32 word, while the bare spelling mints the `.64` twin (BUG-464).
#[test]
fn the_0xff_twin_resolves_to_the_plain_key() {
    let (table, index) = table_and_index();
    let base = 0x000fe2000f009804f80000060208797fu128; // STG.E.EF.EFL2.256.STRONG.SM.PRIVATE desc[UR4][R2.64], R6, R8
    let key = |w: u128| index.decode(w, 0, table).unwrap().key;
    assert_eq!(key(base), "STG_dARI_R_R");
    assert_eq!(key(base & !(1u128 << 59)), "STG_dARI_R_R_II"); // 0xfe
    assert_eq!(key(base & !(7u128 << 88)), "STG_dARI_R_R_II"); // 0x1f
    let d = index.decode(base & !(1u128 << 59) & !(1u128 << 90), 0, table).unwrap();
    assert_eq!(cubit::printer::to_sass(&d), "STG.E.EF.EFL2.256.STRONG.SM.PRIVATE desc[UR4][R2.64], R6, R8, 0x7e");
    let d = index.decode((base | (0xfu128 << 77)) & !(1u128 << 76), 0, table).unwrap(); // MMIO.SYS.ORDERED, [Ra.64+URb]
    assert_eq!(d.key, "STG_ARURI64_R_R");
    assert_eq!(cubit::printer::to_sass(&d), "STG.E.EF.EFL2.256.MMIO.SYS.ORDERED [R2.64+UR4], R6, R8");
    let u32 = base & !(3u128 << 75);
    assert_eq!(key(u32), "STG_ARURI_R_R");
    let rz = u32 | (0xffu128 << 24);
    let d = index.decode(rz, 0, table).unwrap();
    assert_eq!(d.key, "STG_ARURI_R_R");
    assert_eq!(cubit::printer::to_sass(&d), "STG.E.EF.EFL2.256.STRONG.SM.PRIVATE [UR4], R6, R8");
    assert_eq!(cubit::printer::to_sass_lossless(&d), "STG.E.EF.EFL2.256.STRONG.SM.PRIVATE [RZ.U32+UR4], R6, R8");
    assert_eq!(reencode(table, rz, "STG.E.EF.EFL2.256.STRONG.SM.PRIVATE [RZ.U32+UR4], R6, R8"), rz);
    assert_eq!(reencode(table, rz, "STG.E.EF.EFL2.256.STRONG.SM.PRIVATE [UR4], R6, R8"), rz | (1u128 << 75));
    let d64 = index.decode(rz | (1u128 << 75), 0, table).unwrap();
    assert_eq!(d64.key, "STG_ARURI64_R_R");
    assert_eq!(cubit::printer::to_sass_lossless(&d64), "STG.E.EF.EFL2.256.STRONG.SM.PRIVATE [UR4], R6, R8");
}

/// The six keys carry their full measured lattice (`_src`, mask == the fields, nothing baked under a field, the
/// opcode, the frame, the address bits and the modifier bits of their group name and nothing else, the trailing byte
/// baked at 0xff or carried; `claim_forbid` Ra = RZ on the descriptor form only), no dotted 0x97f key is left, the
/// 1 164 aliases point at the plain key of their operand signature and name one of its groups, the legend = the live count.
#[test]
fn the_rows_are_measured_and_the_dotted_keys_are_gone() {
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for (k, e) in ins {
        if !k.starts_with("STG") || is_family_key(k) {
            continue;
        }
        if let Some(groups) = e["mod_groups"].as_object() {
            for (name, g) in groups {
                assert_ne!(number(&g["and_base"]) & 0xfff, OPC, "{k} {name}: a 0x97f row outside the measured plain keys");
            }
        }
    }
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    let mut n_alias = 0;
    for (old, new) in aliases {
        if !is_retired_dotted(old) {
            continue;
        }
        n_alias += 1;
        let new = new.as_str().unwrap();
        let (mn, sig) = old.split_once('_').unwrap();
        assert_eq!(new, format!("STG_{sig}"), "{old} -> {new}");
        assert!(ins.get(old).is_none(), "{old} still a key");
        assert!(is_family_key(new), "{old} -> {new}");
        let mut toks: Vec<&str> = mn.split('.').skip(1).collect();
        toks.sort_unstable();
        let group = toks.join(",");
        assert!(ins[new]["mod_groups"].get(&group).is_some(), "{old}: its spelling names no group {group} of {new}");
    }
    assert_eq!(n_alias, 1157, "the dotted one-group keys of the 256-bit store");
    let tagged = ins.values().filter_map(|e| e["mod_groups"].as_object()).flat_map(|m| m.values()).filter(|g| g["_src"] == SOURCE).count();
    assert_eq!(raw["_meta"]["provenance"]["sources"][SOURCE]["rows"], tagged);
    assert_eq!(tagged, 6 * GROUPS_PER_KEY);
    for key in KEYS {
        assert_eq!(ins[key]["_src"], SOURCE, "{key}");
        assert_eq!(ins[key]["base_op"], "STG", "{key}");
        let groups = ins[key]["mod_groups"].as_object().unwrap();
        assert_eq!(groups.len(), GROUPS_PER_KEY, "{key}");
        let has_ii = key.ends_with("_II");
        let form = key.split('_').nth(1).unwrap();
        let addr_bits = match form { "dARI" => 3u128 << 75, "ARURI64" => 1u128 << 75, "ARURI" => 0, _ => unreachable!() };
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
            let mut want = OPC | (1u128 << 91) | addr_bits | law(name);
            if !has_ii {
                want |= (0x1fu128 << 59) | (7u128 << 88);
            }
            assert_eq!(base, want, "{key} {name}: and_base = opcode + frame + the address form + the modifier bits of the name (+ 0xff)");
            let mut want_fields = vec!["guard@12:4#0", "sub_imm2_shr5@40:19#1", "reg@32:8#2", "reg@16:8#3"];
            if form == "dARI" {
                want_fields.extend(["sub_ur0@64:8#1", "sub_r1@24:8#1"]);
            } else {
                want_fields.extend(["sub_r0@24:8#1", "sub_ur1@64:8#1"]);
            }
            if has_ii {
                want_fields.extend(["imm@59:5#4", "imm_shr5@88:3#4"]);
            }
            let want_fields: std::collections::BTreeSet<String> = want_fields.into_iter().map(String::from).collect();
            assert_eq!(kinds, want_fields, "{key} {name}: the fields");
            if form == "dARI" {
                assert_eq!(g["claim_forbid"], serde_json::json!([{"shift": 24, "bits": 8, "values": [255]}]), "{key} {name}: desc[UR][RZ.64] is illegal");
            } else {
                assert!(g.get("claim_forbid").is_none(), "{key} {name}: every base is legal on the uniform-indexed forms");
            }
        }
    }
}

/// Every retired dotted key round-trips through the plain key: the text its spelling names (`STG.<mods> <addr>, R6,
/// R8`, with `, 0x0` for the `_II` keys) encodes to a word that decodes to the alias's target and the group its tokens
/// name, and prints the same text back.
#[test]
fn every_alias_round_trips_through_the_plain_key() {
    let (table, index) = table_and_index();
    let raw: Value = serde_json::from_slice(&cubit::table::read_table_bytes(table_path()).unwrap()).unwrap();
    let aliases = raw["_meta"]["key_aliases"].as_object().unwrap();
    let mut n = 0;
    for (old, new) in aliases {
        if !is_retired_dotted(old) {
            continue;
        }
        n += 1;
        let (mn, sig) = old.split_once('_').unwrap();
        let addr = match sig.split('_').next().unwrap() {
            "dARI" => "desc[UR4][R2.64]",
            "ARURI64" => "[R2.64+UR4]",
            "ARURI" => "[R2.U32+UR4]",
            other => panic!("{old}: {other}"),
        };
        let mut text = format!("{mn} {addr}, R6, R8");
        if sig.ends_with("_II") {
            text.push_str(", 0x0");
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
    assert_eq!(n, 1157);
}

const PLAIN_PREFIX: &str = "STG_";

/// The 68 STG.256 words of the GB10 census corpus (their own control codes): each decodes to a plain key of the family, prints the vendor's text and re-encodes bit for bit.
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
    assert_eq!(n, 68, "the GB10 census words of the form in the fixture");
}

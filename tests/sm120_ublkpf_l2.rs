//! SM120 UBLKPF.L2 (bulk L2 prefetch, PTX cp.async.bulk.prefetch.L2) measured with nvdisasm 13.1
//! (tools/re_sm120_ublkpf.py). Every probed word (uniform guard, address UR incl. URZ, size UR incl.
//! URZ, the descriptor UR under bit 76) decodes to NVIDIA's text through the measured keys
//! `UBLKPF_AURI_UR` / `UBLKPF_AURI_UR_II` (`L2`) - not the harvest-era `UBLKPF.L2_AUR_UR` whose
//! AUR signature printed a fabricated `desc[UR24][R24.64]` - and that text reassembles all 128
//! bits. The lattice (descriptor byte without bit 76, text-inert bits, the illegal bit-91 clear)
//! stays unclaimed. The form is the KV-page prefetch of FlashInfer 0.7.2's sparse-MLA prefill
//! kernels (image r21 AOT cubin, 28 words).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "ublkpf-l2-sm120-2026-10-29";
const CTRL: u128 = 0x0003_f000u128 << 96; // control code of the shipped plain words

fn table_path() -> PathBuf {
    std::env::var_os("CUBIT_TABLE").map(PathBuf::from).unwrap_or_else(|| "tables/sm120.json".into())
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
    include_str!("fixtures/sm120_ublkpf_nvdisasm.jsonl").lines()
        .map(|l| serde_json::from_str(l).unwrap()).collect()
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

fn check(word: u128, vendor: &str) {
    let (table, index) = table_and_index();
    let decoded = index.decode(word, 0, table).unwrap_or_else(|e| panic!("{word:032x}: {e}"));
    let key = if vendor.contains("desc[") { "UBLKPF_AURI_UR_II" } else { "UBLKPF_AURI_UR" };
    assert_eq!((decoded.key.as_str(), decoded.mod_group.as_str()), (key, "L2"), "{word:032x}");
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own, vendor, "{word:032x}");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
}

#[test]
fn every_probed_ublkpf_l2_word_matches_nvidia_and_reassembles_all_128_bits() {
    let (mut plain, mut desc, mut urz, mut guarded, mut negated) = (0, 0, 0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        check(word, vendor);
        if vendor.contains("desc[") { desc += 1 } else { plain += 1 }
        urz += vendor.matches("URZ").count();
        guarded += vendor.starts_with("@UP") as usize;
        negated += vendor.starts_with("@!UP") as usize;
    }
    assert_eq!((plain, desc), (31, 39));
    assert!(urz >= 5 && guarded >= 14 && negated >= 16, "{urz} {guarded} {negated}");
}

#[test]
fn the_kv_prefetch_words_of_the_sparse_mla_prefill_kernels_round_trip() {
    // FlashInfer 0.7.2 sparse_mla_prefill_kernel<ModelType 0/2/3/4> and the swapab kernels, r21 AOT cubin
    for (word, vendor) in [
        (0x0003f0000800000400000000180073bcu128, "UBLKPF.L2 [UR24], UR4"),
        (0x0001f00008000007000000000a0083bcu128, "@!UP0 UBLKPF.L2 [UR10], UR7"),
        (0x0003f0000800100600000400100083bcu128, "@!UP0 UBLKPF.L2 [UR16], UR6, desc[UR4]"),
        (0x0001f0000800100500000800060003bcu128, "@UP0 UBLKPF.L2 [UR6], UR5, desc[UR8]"),
    ] {
        check(word, vendor);
    }
}

#[test]
fn the_measured_keys_mirror_the_ublkcp_siblings_and_outrank_the_harvest_key() {
    let raw: Value = serde_json::from_slice(&std::fs::read(table_path()).unwrap()).unwrap();
    let ins = &raw["instructions"];
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let geometry = |g: &Value| g["fields"].as_array().unwrap().iter()
        .map(|f| (f["extraction"].as_str().unwrap().to_string(), f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap(), f["token_idx"].as_u64().unwrap()))
        .collect::<Vec<_>>();
    let plain = &ins["UBLKPF_AURI_UR"]["mod_groups"]["L2"];
    assert_eq!(plain["_src"], SOURCE);
    assert_eq!(number(&plain["and_base"]), 0x3bc | (1 << 91));
    assert_eq!(geometry(plain), [("guard".to_string(), 12, 4, 0), ("sub_ur0".to_string(), 24, 8, 1), ("ureg".to_string(), 64, 8, 2)]);
    assert_eq!(number(&plain["variable_mask"]), (0xfu128 << 12) | (0xffu128 << 24) | (0xffu128 << 64));
    let desc = &ins["UBLKPF_AURI_UR_II"]["mod_groups"]["L2"];
    assert_eq!(desc["_src"], SOURCE);
    assert_eq!(number(&desc["and_base"]), 0x3bc | (1 << 91) | (1 << 76));
    assert_eq!(geometry(desc), [("guard".to_string(), 12, 4, 0), ("sub_ur0".to_string(), 24, 8, 1), ("ureg".to_string(), 64, 8, 2), ("desc_ur".to_string(), 40, 8, 3)]);
    assert_eq!(number(&desc["variable_mask"]), (0xfu128 << 12) | (0xffu128 << 24) | (0xffu128 << 40) | (0xffu128 << 64));
    for key in ["UBLKPF_AURI_UR", "UBLKPF_AURI_UR_II"] {
        assert_eq!(ins[key]["base_op"], "UBLKPF");
        assert_eq!(ins[key]["ctrl_class"], ins["UBLKCP_AURI_AURI_UR_II"]["ctrl_class"], "{key}");
        assert!(ins[key]["mod_groups"][ "L2"]["count"].is_null());
    }
    // the harvest-era key is still in the table but no longer owns the decode of any vendor word
    assert_eq!(ins["UBLKPF.L2_AUR_UR"]["operand_sig"], "AUR_UR");
    let (table, index) = table_and_index();
    let decoded = index.decode(0x0003f0000800000400000000180073bc, 0, table).unwrap();
    assert_eq!(decoded.key, "UBLKPF_AURI_UR");
    assert!(!cubit::printer::to_sass_lossless(&decoded).contains("desc["));
}

#[test]
fn the_lattice_around_the_form_stays_unclaimed() {
    let (table, index) = table_and_index();
    let (mut n, mut illegal, mut inert) = (0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        let decoded = index.decode(word, 0, table).ok();
        match row["nvidia_sass"].as_str() {
            None => {
                illegal += 1;
                assert!(decoded.is_none(), "vendor-illegal word {word:032x} decoded");
            }
            Some(vendor) => {
                assert_eq!(vendor, "UBLKPF.L2 [UR24], UR4");
                if (word >> 96) != 0x0003_f000 {
                    // reuse window [124:122]: the 96-bit claim zone is the base word, so the row owns
                    // these; nvdisasm prints nothing for the bits on UBLKPF (uniform operands never take
                    // `.reuse`)
                    let d = decoded.unwrap();
                    assert_eq!(d.key, "UBLKPF_AURI_UR");
                    assert_eq!(cubit::printer::to_sass_lossless(&d).replace(".reuse", ""), vendor, "{word:032x}");
                } else {
                    // the descriptor byte without bit 76 and the text-inert bits are unclaimable
                    inert += 1;
                    assert!(decoded.is_none(), "text-inert word {word:032x} claimed as {}",
                        cubit::printer::to_sass_lossless(decoded.as_ref().unwrap()));
                }
            }
        }
    }
    assert_eq!(n, 36);
    assert_eq!(illegal, 1, "bit 91 clear");
    assert_eq!(inert, 32, "desc byte x3 without bit 76, bits 16/23/32/39/48/55/63, 72..75, 77..90, 92..95");
    for source in ["UBLKPF [UR24], UR4 ;", "UBLKPF.L2 [UR24+0x10], UR4 ;", "UBLKPF.L2 [R24], UR4 ;", "UBLKPF.L2 [UR24], R4 ;"] {
        if let Ok(parsed) = cubit::parse_sass(source, 0) {
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{source}");
        }
    }
}

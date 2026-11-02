//! SM120 STSM.8.MT168 (8-bit transposed matrix store, PTX stmatrix.sync.aligned.m16n8.xN.trans.b8)
//! measured with nvdisasm 13.1 (tools/re_sm120_stsm8_mt168.py). Every probed word (guard, base
//! register incl. RZ, source register incl. RZ, signed offset, the plain / .2 / .4 counts) decodes
//! to NVIDIA's text - in NVIDIA's modifier order - and that text reassembles all 128 bits. The
//! lattice (INVALID3 count, the text-inert datatype bits 76/77, the other shapes, the bit-80 alias,
//! the [R+UR+imm] address) stays unclaimed. The form is the P-fragment store of FlashInfer 0.7.2's
//! swapab sparse-MLA prefill kernels (image r21 AOT cubin, 40 words).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;
use std::{path::PathBuf, sync::OnceLock};

const SOURCE: &str = "stsm8-mt168-sm120-2026-10-29";
const CTRL: u128 = 0x000f_e800u128 << 96; // control code of the shipped words

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
    include_str!("fixtures/sm120_stsm8_mt168_nvdisasm.jsonl").lines()
        .map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn group_of(vendor: &str) -> &'static str {
    let mnemonic = vendor.trim_start_matches(|c| c != 'S').split(' ').next().unwrap();
    match mnemonic {
        "STSM.8.MT168" => "8,MT168",
        "STSM.8.MT168.2" => "2,8,MT168",
        "STSM.8.MT168.4" => "4,8,MT168",
        other => panic!("{other}"),
    }
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
    assert_eq!((decoded.key.as_str(), decoded.mod_group.as_str()), ("STSM_ARI_R", group_of(vendor)), "{word:032x}");
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own, vendor, "{word:032x}");
    assert_eq!(reencode(table, word, vendor), word, "{vendor}");
}

#[test]
fn every_probed_stsm8_mt168_word_matches_nvidia_and_reassembles_all_128_bits() {
    let mut counts = std::collections::BTreeMap::new();
    let (mut rz_base, mut rz_src, mut negative, mut guarded) = (0, 0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_some() {
            continue;
        }
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        check(word, vendor);
        *counts.entry(group_of(vendor)).or_insert(0) += 1;
        rz_base += (vendor.contains(" [0x") || vendor.contains(" [RZ]")) as usize;
        rz_src += vendor.ends_with(", RZ") as usize;
        negative += vendor.contains("+-0x") as usize;
        guarded += vendor.starts_with('@') as usize;
    }
    assert_eq!(counts.values().sum::<usize>(), 118);
    assert!(counts.values().all(|&n| n >= 32), "{counts:?}");
    assert!(rz_base >= 6 && rz_src >= 6 && negative >= 6 && guarded >= 45, "{rz_base} {rz_src} {negative} {guarded}");
}

#[test]
fn the_p_fragment_stores_of_the_swapab_prefill_kernels_round_trip() {
    // FlashInfer 0.7.2 sparse_mla_prefill_swapab_kernel<ModelType 2/3, 64/128>, r21 AOT cubin
    for (word, vendor) in [
        (0x000fe80000008a00010800446f007844u128, "STSM.8.MT168.4 [R111+0x10800], R68"),
        (0x000fe20000008a00010a00406f007844u128, "STSM.8.MT168.4 [R111+0x10a00], R64"),
        (0x000fe80000008a00010800406f007844u128, "STSM.8.MT168.4 [R111+0x10800], R64"),
    ] {
        check(word, vendor);
    }
}

#[test]
fn the_three_groups_carry_the_donor_fields_with_bit_75_and_a_fail_closed_mask() {
    let raw: Value = serde_json::from_slice(&std::fs::read(table_path()).unwrap()).unwrap();
    let groups = raw["instructions"]["STSM_ARI_R"]["mod_groups"].as_object().unwrap();
    let number = |v: &Value| u128::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    for (name, donor_name, count_bits) in [("8,MT168", "16,MT168", 0u128), ("2,8,MT168", "16,2,MT168", 1 << 72), ("4,8,MT168", "16,4,MT168", 1 << 73)] {
        let (new, donor) = (&groups[name], &groups[donor_name]);
        assert_eq!(new["_src"], SOURCE, "{name}");
        assert_eq!(number(&new["and_base"]), 0x844 | (1 << 75) | (1 << 79) | count_bits, "{name}");
        assert_eq!(number(&new["and_base"]), number(&donor["and_base"]) | (1 << 75), "{name}");
        let geometry = |g: &Value| g["fields"].as_array().unwrap().iter()
            .map(|f| (f["extraction"].as_str().unwrap().to_string(), f["shift"].as_u64().unwrap(), f["bits"].as_u64().unwrap(), f["token_idx"].as_u64().unwrap()))
            .collect::<Vec<_>>();
        assert_eq!(geometry(new), geometry(donor), "{name}");
        assert_eq!(geometry(new), [("guard".to_string(), 12, 4, 0), ("sub_r0".to_string(), 24, 8, 1), ("sub_imm1".to_string(), 40, 24, 1), ("reg".to_string(), 32, 8, 2)]);
        // fail-closed: the variable mask is exactly the measured fields (no bit-80 alias, no reuse)
        let field_mask = (0xfu128 << 12) | (0xffu128 << 24) | (0xff_ffffu128 << 40) | (0xffu128 << 32);
        assert_eq!(number(&new["variable_mask"]), field_mask, "{name}");
        assert!(new["count"].is_null());
    }
}

#[test]
fn the_lattice_around_the_form_stays_unclaimed() {
    let (table, index) = table_and_index();
    let (mut n, mut inert, mut other, mut claimed, mut absorbed) = (0, 0, 0, 0, 0);
    for row in fixture() {
        if row.get("lattice").is_none() {
            continue;
        }
        n += 1;
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | CTRL;
        let vendor = row["nvidia_sass"].as_str().unwrap();
        let decoded = index.decode(word, 0, table).ok();
        if (word >> 96) != 0x000f_e800 {
            // reuse window [124:122]: the 96-bit claim zone is the base word, so the row owns these;
            // nvdisasm prints nothing for the bits on STSM (the lossless text may carry `.reuse`)
            let d = decoded.unwrap();
            assert_eq!((d.key.as_str(), d.mod_group.as_str()), ("STSM_ARI_R", "4,8,MT168"));
            assert_eq!(cubit::printer::to_sass_lossless(&d).replace(".reuse", ""), vendor, "{word:032x}");
            continue;
        }
        let text_inert = vendor == "STSM.8.MT168.4 [R111+0x10800], R68";
        if text_inert { inert += 1 } else { other += 1 }
        let Some(d) = decoded else { continue };
        // Whatever decodes prints NVIDIA's text. Among the distinct neighbours only the genuine
        // STSM.16.MT168.4 word (datatype code 0, the existing 16-bit row) decodes, and it reassembles
        // exactly; INVALID3 count / shape, the text-inert datatype bits 76/77 on either width, the
        // M88 / MT88 shapes, the bit-80 alias and the [R+UR+imm] address are claimed by no row.
        let own = cubit::printer::to_sass_lossless(&d);
        assert_eq!(own, vendor, "{word:032x}");
        if text_inert {
            // the decoder's broad memory-address fallback (priority 2, `_ARI` keys) absorbs the unused
            // Rd/Rc bytes [23:16] / [71:64]; the strict round-trip still flags such words as lossy
            assert!(word & !((0xffu128 << 16) | (0xffu128 << 64)) == 0x000fe80000008a00010800446f007844, "{word:032x}");
            absorbed += 1;
        } else {
            assert_eq!(reencode(table, word, vendor), word, "{vendor}");
            assert_eq!(vendor, "STSM.16.MT168.4 [R111+0x10800], R68", "{word:032x}");
            claimed += 1;
        }
    }
    assert_eq!(n, 34);
    assert_eq!(inert, 22, "bits 16, 23, 64, 71, the datatype codes 3/5/7, bits 80..90 and 92..95");
    assert_eq!(other, 9, "INVALID3 count, four .16 codes, M88 / MT88 / INVALID3 shapes, the UR address");
    assert_eq!((claimed, absorbed), (1, 4));
    for source in [
        "STSM.8.MT168.INVALID3 [R4], R12 ;",
        "STSM.8.M88.4 [R4], R12 ;",
        "STSM.8.MT88.4 [R4], R12 ;",
        "STSM.8.INVALID3.4 [R4], R12 ;",
        "STSM.8.MT168.4 [R4+UR5], R12 ;",
    ] {
        if let Ok(parsed) = cubit::parse_sass(source, 0) {
            assert!(cubit::encoder::encode_instruction(&parsed, table).is_err(), "{source}");
        }
    }
}

#[test]
fn the_8_bit_datatype_prints_before_the_shape_and_the_count_like_nvidia() {
    let (table, index) = table_and_index();
    // the LDSM.8.MT1616 compiler words of blackwell-isa afa885f (CUDA 13.1 ldmatrix...trans.b8) share the order
    for (word, vendor) in [
        (0x000e62000801390000000005000c783bu128, "LDSM.8.MT1616.2 R12, [R0+UR5]"),
        (0x001e220008013800000000050002783bu128, "LDSM.8.MT1616 R2, [R0+UR5]"),
        (0x000fe80000008900010800446f007844u128, "STSM.8.MT168.2 [R111+0x10800], R68"),
        (0x000fe80000008800010800446f007844u128, "STSM.8.MT168 [R111+0x10800], R68"),
    ] {
        let decoded = index.decode(word, 0, table).unwrap();
        assert_eq!(cubit::printer::to_sass_lossless(&decoded), vendor);
    }
}

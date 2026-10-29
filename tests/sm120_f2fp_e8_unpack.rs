//! SM120 F2FP.BF16.E8.UNPACK_B (UE8M0 -> BF16x2, PTX cvt.rn.bf16x2.ue8m0x2) measured with nvdisasm 13.1
//! (tools/re_sm120_f2fp_e8.py). Every probed word (guard, destination, source incl. RZ, .H1, .reuse)
//! decodes to NVIDIA's text and that text reassembles all 128 bits. The form is the block-scale decode of
//! FlashInfer 0.7.2's DeepSeek-V4.1 full-BF16 sparse-MLA prefill kernel (image r21 AOT cubin, 48 words).
use cubit::{decoder::DecodeIndex, table::IsaTable};
use serde_json::Value;

fn table() -> IsaTable {
    let path = std::env::var_os("CUBIT_TABLE").map(std::path::PathBuf::from)
        .unwrap_or_else(|| "tables/sm120.json".into());
    IsaTable::load(&path).unwrap()
}

fn check(table: &IsaTable, index: &DecodeIndex, word: u128, vendor: &str) {
    let decoded = index.decode(word, 0, table).unwrap();
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(own, vendor, "{word:032x}");
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    let source = format!("[{control}] {vendor} ;");
    cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
    let parsed = cubit::parse_cuasm_line(&source, 0).unwrap();
    assert!(parsed.hand_sched && parsed.rsd.is_none());
    assert_eq!(cubit::encoder::encode_instruction(&parsed, table).unwrap(), word, "{source}");
}

#[test]
fn every_probed_f2fp_bf16_e8_unpack_b_word_matches_nvidia_and_reassembles_all_128_bits() {
    let table = table();
    let index = DecodeIndex::build(&table);
    let mut n = 0;
    let (mut h1, mut reuse) = (0, 0);
    for line in include_str!("fixtures/sm120_f2fp_e8_nvdisasm.jsonl").lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        let vendor = row["nvidia_sass"].as_str().unwrap();
        assert!(vendor.contains("F2FP.BF16.E8.UNPACK_B "), "{vendor}");
        // the fixture words carry no control code; the native word of the shipped kernel has 0x000fe200
        let word = u128::from_str_radix(row["word"].as_str().unwrap(), 16).unwrap() | (0x000f_e200u128 << 96);
        check(&table, &index, word, vendor);
        h1 += vendor.ends_with(".H1") as usize;
        reuse += vendor.contains(".reuse") as usize;
        n += 1;
    }
    assert_eq!(n, 36);
    assert!(h1 >= 4 && reuse >= 4, "{h1} .H1 words, {reuse} .reuse words");
}

#[test]
fn the_scale_decode_word_of_the_dsv41_bf16_prefill_kernel_round_trips() {
    // FlashInfer 0.7.2 sparse_mla_prefill_dsv41_bf16_kernel<0, false>, offset 0x15e0 of its section in the
    // r21 AOT cubin: @P1 F2FP.BF16.E8.UNPACK_B R47, R94 (decode_e4m3_or_ue8m0_scale_bf16)
    let table = table();
    let index = DecodeIndex::build(&table);
    check(&table, &index, 0x000fe200020816ff0000005eff2f123eu128, "@P1 F2FP.BF16.E8.UNPACK_B R47, R94");
    // E8 has no F16 destination and the 8-bit sources no BF16 one: those words stay unencodable
    for source in ["F2FP.F16.E8.UNPACK_B R47, R94 ;", "F2FP.BF16.E4M3.UNPACK_B R47, R94 ;"] {
        if let Ok(parsed) = cubit::parse_sass(source, 0) {
            assert!(cubit::encoder::encode_instruction(&parsed, &table).is_err(), "{source}");
        }
    }
}

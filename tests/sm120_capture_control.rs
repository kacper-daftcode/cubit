//! Independent NVIDIA 13.1.80 witnesses from exact native CUPTI captures.
use cubit::{decoder::DecodeIndex, table::IsaTable};

fn table() -> IsaTable {
    let path = std::env::var_os("CUBIT_TABLE").map(std::path::PathBuf::from)
        .unwrap_or_else(|| "tables/sm120.json".into());
    IsaTable::load(&path).unwrap()
}

fn normalize(text: &str) -> String {
    let (opcode, operands) = text.split_once(' ').unwrap_or((text, ""));
    let mut pieces = opcode.split('.');
    let base = pieces.next().unwrap();
    let mut modifiers: Vec<_> = pieces.collect();
    modifiers.sort_unstable();
    format!("{} {}", std::iter::once(base).chain(modifiers).collect::<Vec<_>>().join("."), operands)
}

fn check(table: &IsaTable, index: &DecodeIndex, word: u128, addr: u32, vendor: &str) {
    let decoded = index.decode(word, addr, table).unwrap();
    let own = cubit::printer::to_sass_lossless(&decoded);
    assert_eq!(normalize(&own), normalize(vendor), "{word:032x} at {addr:x}");
    let control = cubit::scheduling::format_control_code(
        &cubit::scheduling::decode_sched_upper32((word >> 96) as u32));
    for text in [vendor, &own] {
        let source = format!("[{control}] {text} ;");
        cubit::roundtrip_audit::check_semantic_source(&source).unwrap();
        let parsed = cubit::parse_cuasm_line(&source, addr).unwrap();
        assert!(parsed.hand_sched && parsed.rsd.is_none());
        assert_eq!(cubit::encoder::encode_instruction(&parsed, table).unwrap(), word, "{source}");
    }
}

#[test]
fn captured_control_operands_match_nvidia_and_reassemble_all_128_bits() {
    let table = table();
    let index = DecodeIndex::build(&table);
    for (word, text) in [
        (0x0001e4000800120400000c08060073bau128,
            "UBLKCP.S.G [UR8], [UR6], UR4, desc[UR12]"),
        (0x000ee400000003000000000008ff73aa, "QSPC.E.L P0, RZ, [R8]"),
        (0x000e240008020600000000b0000079c8, "USETMAXREG.TRY_ALLOC.CTAPOOL UP1, 0xb0"),
        (0x000e64000802110900000003ff0075a7, "SYNCS.PHASECHK.TRANS64.TRYWAIT P1, [UR9], R3"),
        (0x000e64000802100900000003ff0075a7, "SYNCS.PHASECHK.TRANS64 P1, [UR9], R3"),
        (0x0001c0000b980a0000000010ff800dae,
            "@P0 LDGSTS.E.BYPASS.LTC128B.128 [R128+UR0], [RZ.64+0x10]"),
        (0x000fe200081a021800000010ffbc7dae,
            "LDGSTS.E.LTC128B [R188+UR24], [RZ.64+0x10], P0"),
        (0x000fe2000f9a021800000010ffbc7dae,
            "LDGSTS.E.LTC128B [R188+UR24], [RZ.64+0x10], !PT"),
    ] {
        check(&table, &index, word, 0, text);
    }
    // NVIDIA -base 0x9ae0, using the exact physical captured instruction PC.
    check(&table, &index, 0x000fec000b93ffffffffffe9004c7547, 0x9ae0,
        "BRA.U.ANY UP0, 0x8420");
}

#[test]
fn count_and_shared_register_fields_do_not_silently_alias() {
    let table = table();
    for source in ["USETMAXREG.TRY_ALLOC.CTAPOOL UP1, 0x400",
                   "UBLKCP.S.G [UR8], [UR6], UR4, desc[UR256]"] {
        let parsed = cubit::parse_sass(source, 0).unwrap();
        assert!(cubit::encoder::encode_instruction(&parsed, &table).is_err(), "{source}");
    }
    let index = DecodeIndex::build(&table);
    for reg in [0u128, 1, 127, 128, 254] {
        let word = (0x0001c0000b980a0000000010ff800daeu128 & !(255 << 16)) | (reg << 16);
        check(&table, &index, word, 0, &format!(
            "@P0 LDGSTS.E.BYPASS.LTC128B.128 [R{reg}+UR0], [RZ.64+0x10]"));
    }
}

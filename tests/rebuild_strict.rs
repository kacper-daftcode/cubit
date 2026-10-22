//! Rebuilding must use complete encoded instructions and reject lost patches.

use cubit::eiattr::KernelMeta;
use cubit::elf::CubinFile;
use cubit::elf_builder::{build_cubin, rebuild_cubin, KernelEntry};

fn load_table() -> cubit::table::IsaTable {
    let path = std::env::var_os("CUBIT_TABLE").map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tables/sm120.json"));
    cubit::table::IsaTable::load(&path).unwrap()
}

fn section_bytes(bytes: &[u8], name: &str) -> Vec<u8> {
    use object::read::elf::{ElfFile, FileHeader, SectionHeader as _};
    use object::{elf, Endianness};
    let file: ElfFile<'_, elf::FileHeader64<Endianness>> = ElfFile::parse(bytes).unwrap();
    let endian = file.endian();
    let sections = file.elf_header().sections(endian, bytes).unwrap();
    let (_, section) = sections.section_by_name(endian, name.as_bytes()).unwrap_or_else(|| panic!("missing {name}"));
    section.data(endian, bytes).unwrap().to_vec()
}

fn register_allocations(bytes: &[u8]) -> std::collections::BTreeMap<String, (u32, u32)> {
    use object::read::elf::{ElfFile, FileHeader, Sym as _};
    use object::{elf, Endianness};
    let file: ElfFile<'_, elf::FileHeader64<Endianness>> = ElfFile::parse(bytes).unwrap();
    let endian = file.endian();
    let sections = file.elf_header().sections(endian, bytes).unwrap();
    let symbols = sections.symbols(endian, bytes, elf::SHT_SYMTAB).unwrap();
    let global = cubit::eiattr::NvInfoSection::parse(".nv.info", &section_bytes(bytes, ".nv.info")).unwrap();
    global.records.iter().filter(|record| record.attr == 0x2f).map(|record| {
        let (symbol, value) = record.as_func_val().unwrap();
        let name = symbols.symbols()[symbol as usize].name(endian, symbols.strings()).unwrap();
        (String::from_utf8(name.to_vec()).unwrap(), (symbol, value))
    }).collect()
}

const NOP: u128 = 0x000fc000000000000000000000007918;
const EXIT: u128 = 0x000fea0003800000000000000000794d;

fn template(names: &[&str]) -> Vec<u8> {
    let entries: Vec<_> = names.iter().map(|name| KernelEntry {
        name: (*name).to_string(),
        code: [NOP.to_le_bytes(), EXIT.to_le_bytes()].concat(),
        meta: KernelMeta {
            name: (*name).to_string(),
            regcount: 32,
            ..Default::default()
        },
        mercury_stub: None,
        opcodes: None,
    }).collect();
    build_cubin(&entries).unwrap()
}

fn text(bytes: Vec<u8>, name: &str) -> Vec<u8> {
    let cubin = CubinFile::from_bytes(bytes).unwrap();
    let index = cubin.text_sections.iter()
        .position(|(section, _, _)| section == &format!(".text.{name}"))
        .unwrap();
    cubin.text_bytes(index).unwrap().to_vec()
}

#[test]
fn encoded_schedule_and_high_operands_override_matching_low_word() {
    let original = template(&["kernel"]);
    // Same opcode and low operands, different stall, wait, and high operand bits.
    let changed = NOP ^ (7u128 << 105) ^ (1u128 << 117) ^ (1u128 << 80);
    let output = rebuild_cubin(&original, &[("kernel", changed.to_le_bytes().to_vec(), None)]).unwrap();
    let rebuilt = text(output, "kernel");
    assert_eq!(&rebuilt[..16], changed.to_le_bytes().as_slice());
    assert_ne!(&rebuilt[..16], &text(original, "kernel")[..16]);
}

#[test]
fn zero_instruction_never_resurrects_template_code() {
    let original = template(&["kernel"]);
    let output = rebuild_cubin(&original, &[("kernel", vec![0; 16], None)]).unwrap();
    let rebuilt = text(output, "kernel");
    assert_eq!(&rebuilt[..16], &[0; 16]);
    // Alignment padding is newly encoded NOPs, not the old second instruction.
    assert_eq!(&rebuilt[16..32], NOP.to_le_bytes().as_slice());
}

#[test]
fn partial_patch_keeps_unselected_kernel_and_replaces_selected_kernel() {
    let original = template(&["first", "second"]);
    let changed = (NOP ^ (3u128 << 105)).to_le_bytes().to_vec();
    let output = rebuild_cubin(&original, &[("first", changed.clone(), None)]).unwrap();
    assert_eq!(&text(output.clone(), "first")[..16], changed.as_slice());
    assert_eq!(text(output, "second"), text(original, "second"));
}

#[test]
fn rejects_unmatched_and_duplicate_patch_targets() {
    let original = template(&["first", "second"]);
    let code = NOP.to_le_bytes().to_vec();
    let missing = rebuild_cubin(&original, &[("missing", code.clone(), None)]).unwrap_err();
    assert!(missing.to_string().contains("0 matching template"));
    let duplicate = rebuild_cubin(&original, &[
        ("first", code.clone(), None), ("first", code, None),
    ]).unwrap_err();
    assert!(duplicate.to_string().contains("duplicate rebuild patch"));
}

#[test]
fn rejects_empty_and_incomplete_patches() {
    let original = template(&["kernel"]);
    assert!(rebuild_cubin(&original, &[]).is_err());
    for size in [0, 1, 15, 17] {
        assert!(rebuild_cubin(&original, &[("kernel", vec![0; size], None)]).is_err());
    }
}

#[test]
fn single_kernel_rename_still_uses_new_instruction_bytes() {
    let original = template(&["long_kernel_name"]);
    let changed = (NOP ^ (9u128 << 105)).to_le_bytes().to_vec();
    let output = rebuild_cubin(&original, &[("renamed", changed.clone(), None)]).unwrap();
    assert_eq!(&text(output, "renamed")[..16], changed.as_slice());
}

#[test]
fn equal_section_names_with_distinct_schedules_rebuild_by_physical_index() {
    let table = load_table();
    let index = cubit::decoder::DecodeIndex::build(&table);
    let mut original = CubinFile::from_bytes(template(&["duplicate", "duplicate"])).unwrap();
    assert_eq!(original.text_sections.len(), 2);
    assert_eq!(original.text_sections[0].0, original.text_sections[1].0);
    let mut second = original.text_bytes(1).unwrap().to_vec();
    second[..16].copy_from_slice(&(NOP ^ (5u128 << 105)).to_le_bytes());
    original.patch_text(1, &second).unwrap();
    assert_ne!(original.text_bytes(0).unwrap(), original.text_bytes(1).unwrap());
    let mut sources = Vec::new();
    for position in 0..2 {
        let mut failures = Vec::new();
        let (report, source) = cubit::roundtrip_audit::audit_kernel(".text.duplicate", position,
            original.text_bytes(position).unwrap(), &table, &index,
            &mut |failure| { failures.push(failure.clone()); Ok(()) }).unwrap();
        assert!(report.passed, "{failures:#?}");
        sources.push(source);
    }
    assert_ne!(sources[0], sources[1]);
    let mut rebuilt = CubinFile::from_bytes(original.bytes.clone()).unwrap();
    assert!(cubit::roundtrip_audit::patch_semantic_section(&mut rebuilt,
        ".text.duplicate", &sources[0], &table).is_err());
    for (position, source) in sources.iter().enumerate() {
        cubit::roundtrip_audit::patch_semantic_section_at(&mut rebuilt, position, source, &table).unwrap();
    }
    assert_eq!(rebuilt.bytes, original.bytes);
}

#[test]
fn identical_rebuild_preserves_entire_elf_with_short_helpers_and_small_allocations() {
    let entries: Vec<_> = [("short_helper", 8), ("other_kernel", 255)].iter().map(|(name, registers)| KernelEntry {
        name: (*name).into(), code: [NOP.to_le_bytes(), EXIT.to_le_bytes()].concat(),
        meta: KernelMeta { name: (*name).into(), regcount: *registers, shared_size: 64, ..Default::default() },
        mercury_stub: None, opcodes: None,
    }).collect();
    let mut original = CubinFile::from_bytes(build_cubin(&entries).unwrap()).unwrap();
    for (position, size) in [(0, 48), (1, 80)] {
        let code = original.text_bytes(position).unwrap()[..size].to_vec();
        original.patch_text(position, &code).unwrap();
    }
    let patches: Vec<_> = entries.iter().enumerate().map(|(position, entry)|
        (entry.name.as_str(), original.text_bytes(position).unwrap().to_vec(), None)).collect();
    let output = rebuild_cubin(&original.bytes, &patches).unwrap();
    assert_eq!(output, original.bytes, "identical helper code must preserve sizes, resources, symbols and every metadata byte");
}

#[test]
fn register_growth_updates_only_the_symbol_matched_allocation() {
    let entries: Vec<_> = [("first", 255), ("target", 32), ("last", 8)].iter().map(|(name, registers)| KernelEntry {
        name: (*name).into(), code: [NOP.to_le_bytes(), EXIT.to_le_bytes()].concat(),
        meta: KernelMeta { name: (*name).into(), regcount: *registers, shared_size: 64, ..Default::default() },
        mercury_stub: None, opcodes: None,
    }).collect();
    let original = cubit::elf_builder::build_cubin_mercury(&entries).unwrap();
    let allocations = register_allocations(&original);
    let mut cubin = CubinFile::from_bytes(original).unwrap();
    // A matching REGCOUNT byte sequence inside another attribute's payload
    // must retain its meaning and must never become a second resource record.
    let original_info = section_bytes(&cubin.bytes, ".nv.info");
    let mut info_records = cubit::eiattr::NvInfoSection::parse(".nv.info", &original_info).unwrap();
    assert!(info_records.records.iter().rev().take(2).all(|record| record.attr != 0x2f));
    info_records.records.truncate(info_records.records.len() - 2);
    let mut payload = vec![4, 0x2f, 8, 0];
    payload.extend_from_slice(&allocations["target"].0.to_le_bytes());
    payload.extend_from_slice(&7u32.to_le_bytes());
    payload.resize(20, 0);
    info_records.records.push(cubit::eiattr::EiRecord { attr: 0x70, fmt: cubit::eiattr::EiFmt::Sized, data: payload });
    let info = info_records.to_bytes();
    assert_eq!(info.len(), original_info.len());
    cubin.patch_section(cubin.find_section(".nv.info").unwrap(), &info).unwrap();
    let mut code = cubin.text_bytes(1).unwrap().to_vec();
    let parsed = cubit::parse_sass("IMAD.MOV.U32 R96, RZ, RZ, R0 ;", 0).unwrap();
    let word = cubit::encoder::encode_instruction(&parsed, &load_table()).unwrap();
    code[..16].copy_from_slice(&word.to_le_bytes());
    let output = rebuild_cubin(&cubin.bytes, &[("target", code.clone(), None)]).unwrap();
    let after = register_allocations(&output);
    assert_eq!(after["target"].1, 128);
    assert_eq!(after["first"], allocations["first"]);
    assert_eq!(after["last"], allocations["last"]);
    assert_eq!(text(output.clone(), "target"), code);
    for name in [".text.first", ".text.last", ".nv.info.first", ".nv.info.last", ".nv.merc.nv.info"] {
        assert_eq!(section_bytes(&output, name), section_bytes(&cubin.bytes, name), "modified unrelated {name}");
    }
    let records_before = cubit::eiattr::NvInfoSection::parse(".nv.info", &info).unwrap();
    let records_after = cubit::eiattr::NvInfoSection::parse(".nv.info", &section_bytes(&output, ".nv.info")).unwrap();
    assert_eq!(records_before.records.last().unwrap().data, records_after.records.last().unwrap().data);
}

#[test]
fn register_growth_without_a_bound_allocation_is_rejected() {
    let mut cubin = CubinFile::from_bytes(template(&["helper"])).unwrap();
    let mut info = cubit::eiattr::NvInfoSection::parse(".nv.info", &section_bytes(&cubin.bytes, ".nv.info")).unwrap();
    info.records.retain(|record| record.attr != 0x2f);
    cubin.patch_section(cubin.find_section(".nv.info").unwrap(), &info.to_bytes()).unwrap();
    let mut code = cubin.text_bytes(0).unwrap().to_vec();
    let parsed = cubit::parse_sass("IMAD.MOV.U32 R96, RZ, RZ, R0 ;", 0).unwrap();
    let word = cubit::encoder::encode_instruction(&parsed, &load_table()).unwrap();
    code[..16].copy_from_slice(&word.to_le_bytes());
    let error = rebuild_cubin(&cubin.bytes, &[("helper", code, None)]).unwrap_err();
    assert!(error.to_string().contains("no symbol-linked REGCOUNT record"), "{error:#}");
}

#[test]
fn real_register_growth_is_not_hidden_by_an_unchanged_immediate_byte_estimate() {
    let table = load_table();
    let encode = |register| {
        let source = format!("IMAD.MOV.U32 R{register}, RZ, RZ, 0x64 ;");
        cubit::encoder::encode_instruction(&cubit::parse_sass(&source, 0).unwrap(), &table).unwrap()
    };
    let old = encode(1).to_le_bytes();
    let new = encode(100).to_le_bytes();
    assert_eq!((old[2], new[2], old[4], new[4]), (1, 100, 100, 100));
    let mut original = CubinFile::from_bytes(template(&["kernel"])).unwrap();
    let mut code = original.text_bytes(0).unwrap().to_vec();
    code[..16].copy_from_slice(&old);
    original.patch_text(0, &code).unwrap();
    code[..16].copy_from_slice(&new);
    let output = rebuild_cubin(&original.bytes, &[("kernel", code, None)]).unwrap();
    assert_eq!(register_allocations(&output)["kernel"].1, 128);
}

#[test]
fn schedule_and_reuse_edits_preserve_every_metadata_byte() {
    let entry = KernelEntry { name: "kernel".into(), code: [NOP.to_le_bytes(), EXIT.to_le_bytes()].concat(),
        meta: KernelMeta { name: "kernel".into(), regcount: 8, ..Default::default() }, mercury_stub: None, opcodes: None };
    let mut original = CubinFile::from_bytes(build_cubin(&[entry]).unwrap()).unwrap();
    let parsed = cubit::parse_sass("IMAD.MOV.U32 R1, RZ, RZ, 0x64 ;", 0).unwrap();
    let word = cubit::encoder::encode_instruction(&parsed, &load_table()).unwrap();
    let mut code = original.text_bytes(0).unwrap().to_vec();
    code[..16].copy_from_slice(&word.to_le_bytes());
    original.patch_text(0, &code).unwrap();
    code[..16].copy_from_slice(&(word ^ (3u128 << 105) ^ (1u128 << 122)).to_le_bytes());
    let mut expected = CubinFile::from_bytes(original.bytes.clone()).unwrap();
    expected.patch_text(0, &code).unwrap();
    let output = rebuild_cubin(&original.bytes, &[("kernel", code, None)]).unwrap();
    assert_eq!(output, expected.bytes);
    assert_eq!(register_allocations(&output)["kernel"].1, 8);
}

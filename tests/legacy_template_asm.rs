//! The address-listing template CLI must apply all 128 authored bits and
//! refuse a source instruction that cannot be encoded or matched safely.
use cubit::elf::CubinFile;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const ORIGINAL: u128 = 0x000fe200037234000000004f3600720b;
const NOP: u128 = 0x000fc000000000000000000000007918;

struct Fixture {
    root: PathBuf,
    template: PathBuf,
    original: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "cubit_legacy_template_{}_{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        ));
        std::fs::create_dir_all(&root).unwrap();
        let original = minimal_cubin(&[
            (".text.target", [ORIGINAL.to_le_bytes(), NOP.to_le_bytes()].concat()),
            (".text.unselected", NOP.to_le_bytes().to_vec()),
            (".review.metadata", b"metadata must stay untouched".to_vec()),
        ]);
        let template = root.join("template.cubin");
        std::fs::write(&template, &original).unwrap();
        Self { root, template, original }
    }

    fn run(&self, tag: &str, source: &str) -> (Output, PathBuf) {
        let input = self.root.join(format!("{tag}.sass"));
        let output = self.root.join(format!("{tag}.cubin"));
        std::fs::write(&input, source).unwrap();
        let table = std::env::var_os("CUBIT_TABLE").map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join("tables/sm120.json"));
        let result = Command::new(env!("CARGO_BIN_EXE_cubit"))
            .arg("asm").arg("--table").arg(table).arg(&input)
            .arg("--template").arg(&self.template).arg("--output").arg(&output)
            .env_remove("CUBIT_DISABLE_ERRATA").env_remove("CUBIT_FIT_LINT")
            .output().unwrap();
        assert_eq!(std::fs::read(&self.template).unwrap(), self.original, "template was modified");
        (result, output)
    }

    fn rejects(&self, tag: &str, source: &str, diagnostic: &str) {
        let (result, output) = self.run(tag, source);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(!result.status.success(), "{tag} unexpectedly succeeded:\n{}\n{stderr}", String::from_utf8_lossy(&result.stdout));
        assert!(!output.exists(), "{tag} wrote a partial or stale output");
        assert!(stderr.contains(diagnostic), "{tag}: {stderr}");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.root); }
}

// Symbol-free ELF64: the address-listing assembler only needs the code
// sections. A separate metadata payload catches writes outside those bytes.
fn minimal_cubin(sections: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut names = b"\0.shstrtab\0".to_vec();
    let mut name_offsets = Vec::new();
    for (name, _) in sections {
        name_offsets.push(names.len() as u32);
        names.extend_from_slice(name.as_bytes()); names.push(0);
    }
    let mut bytes = vec![0; 64];
    let names_offset = bytes.len(); bytes.extend_from_slice(&names);
    let mut code_offsets = Vec::new();
    for (_, code) in sections {
        while bytes.len() % 16 != 0 { bytes.push(0); }
        code_offsets.push(bytes.len()); bytes.extend_from_slice(code);
    }
    while bytes.len() % 8 != 0 { bytes.push(0); }
    let shoff = bytes.len();
    bytes.resize(shoff + (sections.len() + 2) * 64, 0);
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[16..18].copy_from_slice(&1u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&0xbeu16.to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    bytes[48..52].copy_from_slice(&0x06007802u32.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
    bytes[60..62].copy_from_slice(&((sections.len() + 2) as u16).to_le_bytes());
    bytes[62..64].copy_from_slice(&1u16.to_le_bytes());
    let header = shoff + 64;
    bytes[header..header+4].copy_from_slice(&1u32.to_le_bytes());
    bytes[header+4..header+8].copy_from_slice(&3u32.to_le_bytes());
    bytes[header+24..header+32].copy_from_slice(&(names_offset as u64).to_le_bytes());
    bytes[header+32..header+40].copy_from_slice(&(names.len() as u64).to_le_bytes());
    for (i, (_, code)) in sections.iter().enumerate() {
        let header = shoff + (i + 2) * 64;
        bytes[header..header+4].copy_from_slice(&name_offsets[i].to_le_bytes());
        bytes[header+4..header+8].copy_from_slice(&1u32.to_le_bytes());
        bytes[header+8..header+16].copy_from_slice(&6u64.to_le_bytes());
        bytes[header+24..header+32].copy_from_slice(&(code_offsets[i] as u64).to_le_bytes());
        bytes[header+32..header+40].copy_from_slice(&(code.len() as u64).to_le_bytes());
        bytes[header+48..header+56].copy_from_slice(&16u64.to_le_bytes());
    }
    bytes
}

#[test]
fn authored_high_predicate_and_schedule_replace_the_template_high_word() {
    let fixture = Fixture::new();
    let cc = cubit::scheduling::parse_control_code("B0-2--5:R1:W4:Y:S07").unwrap();
    let packed = cubit::scheduling::encode_control_code(&cc);
    let source = format!("// target\n/*0000*/ FSETP.LE.OR P4, PT, R54, R79, !P2 /* @sched 0x{packed:05x} */ ;\n");
    assert!(!source.contains("__raw__") && !source.contains("!rsd"));
    // Independent NVIDIA anchor, changed only at the documented output-P,
    // input-P/negation, and explicit scheduling windows. Its low64 is equal.
    let changed_mask = (7u128 << 81) | (15u128 << 87) | (0x1ffffu128 << 105);
    let expected = (ORIGINAL & !changed_mask) | (4 << 81) | (10 << 87) | ((packed as u128) << 105);
    assert_eq!(expected as u64, ORIGINAL as u64);
    assert_ne!(expected >> 64, ORIGINAL >> 64);
    let (result, output) = fixture.run("high_word", &source);
    assert!(result.status.success(), "{}\n{}", String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
    let cubin = CubinFile::from_bytes(fixture.original.clone()).unwrap();
    let offset = cubin.text_sections.iter().find(|(name,_,_)| name == ".text.target").unwrap().1 as usize;
    let mut expected_elf = fixture.original.clone();
    expected_elf[offset..offset+16].copy_from_slice(&expected.to_le_bytes());
    assert_eq!(std::fs::read(output).unwrap(), expected_elf, "an authored high64 change was lost or unrelated bytes changed");
}

#[test]
fn unaligned_outside_overflowing_and_duplicate_addresses_fail_without_output() {
    let fixture = Fixture::new();
    fixture.rejects("unaligned", "// target\n/*0001*/ NOP ;\n", "address");
    fixture.rejects("outside", "// target\n/*0020*/ NOP ;\n", "address");
    fixture.rejects("overflow", "// target\n/*100000000*/ NOP ;\n", "address");
    fixture.rejects("duplicate", "// target\n/*0000*/ NOP ;\n/*0000*/ NOP ;\n", "duplicate");
}

#[test]
fn one_unencodable_slot_prevents_an_otherwise_valid_partial_patch() {
    let fixture = Fixture::new();
    fixture.rejects("unencodable", "// target\n/*0000*/ NOP ;\n/*0010*/ NOT_A_REAL_OPCODE R0 ;\n", "failed to encode");
}

#[test]
fn every_authored_kernel_must_match_even_when_another_kernel_is_valid() {
    let fixture = Fixture::new();
    fixture.rejects("no_match", "// missing\n/*0000*/ NOP ;\n", "match");
    fixture.rejects("mixed_match", "// target\n/*0000*/ NOP ;\n// missing\n/*0000*/ NOP ;\n", "match");
}

#[test]
fn ambiguous_physical_section_names_are_not_patched_twice() {
    let mut fixture = Fixture::new();
    fixture.original = minimal_cubin(&[
        (".text.target", ORIGINAL.to_le_bytes().to_vec()),
        (".text.target", NOP.to_le_bytes().to_vec()),
    ]);
    std::fs::write(&fixture.template, &fixture.original).unwrap();
    fixture.rejects("ambiguous", "// target\n/*0000*/ NOP ;\n", "matching template sections");
}

#[test]
fn malformed_schedule_or_trailing_authored_text_is_not_discarded() {
    let fixture = Fixture::new();
    for (tag, source) in [
        ("schedule_overflow", "// target\n/*0000*/ NOP /* @sched 0x20000 */ ;\n"),
        ("schedule_not_hex", "// target\n/*0000*/ NOP /* @sched 0xZZ */ ;\n"),
        ("schedule_unterminated", "// target\n/*0000*/ NOP /* @sched 0x1 ;\n"),
        ("schedule_trailing_text", "// target\n/*0000*/ NOP /* @sched 0x1 */ NOT_A_REAL_OPCODE ;\n"),
    ] { fixture.rejects(tag, source, "schedule"); }
    fixture.rejects("two_inline_addresses", "// target\n/*0000*/ NOP ; /*0010*/ NOT_A_REAL_OPCODE ;\n", "trailing text");
}

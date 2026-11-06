//! A5 (KNOWN_ISSUES, 2026-11-06): a template rebuild (`asm -T` / `--eiattr-from`) copies the
//! template's `.nv.info.<kernel>` records verbatim. Four of them are lists of byte offsets into
//! the kernel's code (`EXIT_INSTR_OFFSETS`, `COOP_GROUP_INSTR_OFFSETS`,
//! `INT_WARP_WIDE_INSTR_OFFSETS`, `MBARRIER_INSTR_OFFSETS` — measured on 759 census kernels; the
//! EXIT list is exactly the EXIT words of the code on every one of them), so an edit that moves
//! the listed instructions leaves the copied records naming other words. The rebuild now checks
//! the opcode at every listed offset against the template's and refuses a stale set by default
//! (`RebuildResources::allow_stale_metadata` / `asm --allow-stale-metadata` writes the cubin
//! with the template's records as they are, with a warning per entry). Same-length edits and
//! schedule-only edits never trip it; the frozen path (`disassemble --frozen` → `asm -T`) is
//! unchanged by construction (identical positions).

use cubit::eiattr::{KernelMeta, NvInfoSection};
use cubit::elf::CubinFile;
use cubit::elf_builder::{
    build_cubin, rebuild_cubin, rebuild_cubin_with_resources, stale_positional_metadata, KernelEntry,
    RebuildResources,
};

const NOP: u128 = 0x000fc000000000000000000000007918;
const EXIT: u128 = 0x000fea0003800000000000000000794d;
/// `IMAD.MOV.U32 R1, RZ, RZ, 0x64` — a same-length payload edit of the first word.
const IMAD_MOV: u128 = 0x000fc400078e00ff0000006400017424;

fn template() -> Vec<u8> {
    build_cubin(&[KernelEntry {
        name: "kernel".into(),
        code: [NOP.to_le_bytes(), EXIT.to_le_bytes()].concat(),
        meta: KernelMeta { name: "kernel".into(), regcount: 32, exit_offsets: vec![0x10], ..Default::default() },
        mercury_stub: None,
        opcodes: None,
    }])
    .unwrap()
}

fn exit_record(bytes: &[u8]) -> Vec<u32> {
    let cubin = CubinFile::from_bytes(bytes.to_vec()).unwrap();
    let idx = cubin.find_section(".nv.info.kernel").unwrap();
    let sec = NvInfoSection::parse(".nv.info.kernel", cubin.section_bytes(idx).unwrap()).unwrap();
    let rec = sec.records.iter().find(|r| r.attr == 0x1c).expect("EXIT_INSTR_OFFSETS in the template");
    rec.data.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect()
}

fn words(ws: &[u128]) -> Vec<u8> {
    ws.iter().flat_map(|w| w.to_le_bytes()).collect()
}

#[test]
fn a5_1_the_template_names_its_exit_and_a_same_length_edit_keeps_it() {
    let original = template();
    assert_eq!(exit_record(&original), vec![0x10]);
    let cubin = CubinFile::from_bytes(original.clone()).unwrap();
    assert!(stale_positional_metadata(&cubin, "kernel", &words(&[NOP, EXIT]), &words(&[NOP, EXIT])).is_empty());
    assert!(stale_positional_metadata(&cubin, "kernel", &words(&[NOP, EXIT]), &words(&[IMAD_MOV, EXIT])).is_empty());
    let output = rebuild_cubin(&original, &[("kernel", words(&[IMAD_MOV, EXIT]), None)]).unwrap();
    assert_eq!(exit_record(&output), vec![0x10]);
}

#[test]
fn a5_2_a_shifting_edit_is_refused_with_the_record_and_both_offsets_named() {
    let original = template();
    // one instruction inserted before the EXIT: the record's 0x10 is a NOP now, the EXIT sits at 0x20
    let shifted = words(&[NOP, NOP, EXIT]);
    let cubin = CubinFile::from_bytes(original.clone()).unwrap();
    let stale = stale_positional_metadata(&cubin, "kernel", &words(&[NOP, EXIT]), &shifted);
    assert_eq!(stale.len(), 2, "{stale:?}");
    assert!(stale[0].contains("EIATTR_EXIT_INSTR_OFFSETS names offset 0x10") && stale[0].contains("0x94d") && stale[0].contains("0x918"), "{}", stale[0]);
    assert!(stale[1].contains("does not name the EXIT at offset 0x20"), "{}", stale[1]);
    let err = rebuild_cubin(&original, &[("kernel", shifted.clone(), None)]).unwrap_err().to_string();
    assert!(err.contains("would be stale") && err.contains("names offset 0x10") && err.contains("--allow-stale-metadata"), "{err}");
    // the EXIT removed altogether: the listed offset lies beyond the (NOP-padded) code
    let one = words(&[IMAD_MOV]);
    let stale = stale_positional_metadata(&cubin, "kernel", &words(&[NOP, EXIT]), &one);
    assert_eq!(stale.len(), 1, "{stale:?}");
    assert!(stale[0].contains("beyond the rebuilt code's 16 bytes"), "{}", stale[0]);
}

#[test]
fn a5_3_allow_stale_metadata_writes_the_template_records_verbatim() {
    let original = template();
    let shifted = words(&[NOP, NOP, EXIT]);
    let policy = RebuildResources { allow_stale_metadata: true, ..Default::default() };
    let output = rebuild_cubin_with_resources(&original, &[("kernel", shifted.clone(), None)], &policy).unwrap();
    // the code is the new one, the record is the template's (what the flag means: copied, not translated)
    let cubin = CubinFile::from_bytes(output.clone()).unwrap();
    assert_eq!(&cubin.text_bytes(0).unwrap()[..48], shifted.as_slice());
    assert_eq!(exit_record(&output), vec![0x10]);
}

#[test]
fn a5_4_schedule_only_edits_are_never_checked() {
    let original = template();
    // the EXIT's stall count changed and the NOP replaced by a zero word would be a payload edit;
    // a pure control-code edit of both words keeps every record (and is not a positional question)
    let resched = words(&[NOP ^ (5u128 << 105), EXIT ^ (3u128 << 105)]);
    let output = rebuild_cubin(&original, &[("kernel", resched.clone(), None)]).unwrap();
    assert_eq!(exit_record(&output), vec![0x10]);
    assert_eq!(&CubinFile::from_bytes(output).unwrap().text_bytes(0).unwrap()[..32], resched.as_slice());
}

use cubit::decoder::DecodeIndex;
use cubit::roundtrip_audit::{audit_cubin, audit_kernel, check_semantic_source, Failure};
use cubit::table::IsaTable;

fn table() -> IsaTable {
    let path = std::env::var_os("CUBIT_TABLE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "tables/sm120.json".into());
    IsaTable::load(&path).unwrap()
}

fn word(table: &IsaTable, sass: &str, addr: u32) -> u128 {
    let insn = cubit::parse_cuasm_line(sass, addr).unwrap();
    cubit::encoder::encode_instruction(&insn, table).unwrap()
}

// Minimal ELF64 with no symbol table: local / anonymous text sections must
// receive exactly the same audit as exported entry points.
fn cubin(sm: u8, sections: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut names = b"\0.shstrtab\0".to_vec();
    let mut offsets = Vec::new();
    for (name, _) in sections {
        offsets.push(names.len() as u32);
        names.extend_from_slice(name.as_bytes());
        names.push(0);
    }
    let mut out = vec![0u8; 64];
    let names_offset = out.len();
    out.extend_from_slice(&names);
    let mut code_offsets = Vec::new();
    for (_, code) in sections {
        while out.len() % 16 != 0 {
            out.push(0);
        }
        code_offsets.push(out.len());
        out.extend_from_slice(code);
    }
    while out.len() % 8 != 0 {
        out.push(0);
    }
    let shoff = out.len();
    out.resize(shoff + (sections.len() + 2) * 64, 0);
    out[0..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    out[16..18].copy_from_slice(&1u16.to_le_bytes());
    out[18..20].copy_from_slice(&0xbeu16.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    out[48..52].copy_from_slice(&(0x0600_0002u32 | ((sm as u32) << 8)).to_le_bytes());
    out[52..54].copy_from_slice(&64u16.to_le_bytes());
    out[58..60].copy_from_slice(&64u16.to_le_bytes());
    out[60..62].copy_from_slice(&((sections.len() + 2) as u16).to_le_bytes());
    out[62..64].copy_from_slice(&1u16.to_le_bytes());
    let h = shoff + 64;
    out[h..h + 4].copy_from_slice(&1u32.to_le_bytes());
    out[h + 4..h + 8].copy_from_slice(&3u32.to_le_bytes());
    out[h + 24..h + 32].copy_from_slice(&(names_offset as u64).to_le_bytes());
    out[h + 32..h + 40].copy_from_slice(&(names.len() as u64).to_le_bytes());
    for (i, (_, code)) in sections.iter().enumerate() {
        let h = shoff + (i + 2) * 64;
        out[h..h + 4].copy_from_slice(&offsets[i].to_le_bytes());
        out[h + 4..h + 8].copy_from_slice(&1u32.to_le_bytes());
        out[h + 8..h + 16].copy_from_slice(&6u64.to_le_bytes());
        out[h + 24..h + 32].copy_from_slice(&(code_offsets[i] as u64).to_le_bytes());
        out[h + 32..h + 40].copy_from_slice(&(code.len() as u64).to_le_bytes());
        out[h + 48..h + 56].copy_from_slice(&16u64.to_le_bytes());
    }
    out
}

#[test]
fn semantic_roundtrip_covers_local_sections_and_resolves_actual_emitted_labels() {
    let t = table();
    let nop = word(&t, "[B0-2--5:R1:W4:Y:S07] NOP ;", 0);
    let bra = word(&t, "[B------:R-:W-:-:S03] BRA 0x0 ;", 16);
    let bytes = cubin(
        120,
        &[
            (
                ".text.entry",
                [nop.to_le_bytes(), bra.to_le_bytes()].concat(),
            ),
            (".text.local_function", nop.to_le_bytes().to_vec()),
        ],
    );
    let mut failures = Vec::new();
    let mut sources = Vec::new();
    let r = audit_cubin(
        &bytes,
        &t,
        &mut |f| {
            failures.push(f.clone());
            Ok(())
        },
        &mut |k, s| {
            sources.push((k.section.clone(), s.to_string()));
            Ok(())
        },
    )
    .unwrap();
    assert!(r.passed, "{r:?}\n{failures:#?}");
    assert_eq!((r.kernels.len(), r.instructions, r.matched), (2, 3, 3));
    assert!(r.kernels.iter().all(|k| k.stream_verified));
    for (kernel, (_, text)) in r.kernels.iter().zip(&sources) {
        use sha2::{Digest, Sha256};
        assert_eq!(kernel.source_sha256, format!("{:x}", Sha256::digest(text.as_bytes())));
    }
    assert!(sources[0].1.contains("BRA L_0"), "{}", sources[0].1);
    assert!(sources[0].1.contains("[B0-2--5:R1:W4:Y:S07]"));
    for (_, text) in sources {
        check_semantic_source(&text).unwrap();
    }
    assert!(failures.is_empty());
}

#[test]
fn reported_text_indices_patch_duplicate_names_without_using_raw_elf_indices() {
    use cubit::{elf::CubinFile, roundtrip_audit::patch_semantic_section_at};
    let t = table();
    let first = word(&t, "[B------:R-:W-:-:S01] NOP ;", 0);
    let second = word(&t, "[B------:R-:W-:-:S07] NOP ;", 0);
    let third = word(&t, "[B------:R-:W-:-:S03] NOP ;", 0);
    let bytes = cubin(120, &[
        (".review.before", b"unchanged metadata".to_vec()),
        (".text.same", first.to_le_bytes().to_vec()),
        (".review.between", b"more unchanged metadata".to_vec()),
        (".text.same", second.to_le_bytes().to_vec()),
        (".text", third.to_le_bytes().to_vec()),
    ]);
    let original = CubinFile::from_bytes(bytes.clone()).unwrap();
    let mut rebuilt = CubinFile::from_bytes(bytes.clone()).unwrap();
    let mut callbacks = Vec::new();
    let report = audit_cubin(&bytes, &t, &mut |_| Ok(()), &mut |kernel, source| {
        let text_index = kernel.text_index.expect("ELF callback needs a patch index");
        assert_eq!(original.text_sections[text_index].0, kernel.section);
        assert_ne!(kernel.section_index, text_index, "raw ELF indices include metadata");
        patch_semantic_section_at(&mut rebuilt, text_index, source, &t)?;
        callbacks.push((kernel.section_index, text_index, source.to_owned()));
        Ok(())
    }).unwrap();
    assert!(report.passed);
    assert_eq!(callbacks.iter().map(|(raw, text, _)| (*raw, *text)).collect::<Vec<_>>(),
        vec![(3, 0), (5, 1), (6, 2)]);
    assert_eq!(report.kernels.iter().map(|k| k.text_index).collect::<Vec<_>>(),
        vec![Some(0), Some(1), Some(2)]);
    assert_eq!(rebuilt.bytes, bytes, "reported mapping must rebuild the entire ELF exactly");

    // The second physical section shares its name with the first. A manual
    // schedule edit must affect only the section identified by text_index.
    let changed = callbacks[1].2.replace("S07", "S09");
    patch_semantic_section_at(&mut rebuilt, report.kernels[1].text_index.unwrap(), &changed, &t).unwrap();
    assert_eq!(rebuilt.text_bytes(0).unwrap(), original.text_bytes(0).unwrap());
    assert_eq!(rebuilt.text_bytes(2).unwrap(), original.text_bytes(2).unwrap());
    assert_eq!(rebuilt.text_bytes(1).unwrap(),
        word(&t, "[B------:R-:W-:-:S09] NOP ;", 0).to_le_bytes());
    let offset = original.text_sections[1].1 as usize;
    let mut expected = bytes;
    expected[offset..offset + 16].copy_from_slice(rebuilt.text_bytes(1).unwrap());
    assert_eq!(rebuilt.bytes, expected, "an edit through the reported index must preserve all other bytes");
}

#[test]
fn non_schedule_residue_is_a_failure_and_never_repaired() {
    let t = table();
    let index = DecodeIndex::build(&t);
    let original = word(&t, "[B------:R-:W-:-:S01] NOP ;", 0);
    let with_residue = original ^ (1u128 << 127);
    let mut failures = Vec::<Failure>::new();
    let (r, source) = audit_kernel(
        ".text.residue",
        2,
        &with_residue.to_le_bytes(),
        &t,
        &index,
        &mut |f| {
            failures.push(f.clone());
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(r.text_index, None, "standalone audit has no ELF index mapping");
    assert!(!r.passed);
    assert_eq!(r.matched, 0);
    assert_eq!(r.mismatches, 1);
    assert!(!r.stream_verified);
    assert!(failures
        .iter()
        .any(|f| f.stage == "mismatch"
            && f.xor.as_deref() == Some("0x80000000000000000000000000000000")));
    check_semantic_source(&source).unwrap();
    assert!(!source.contains("80000000"));
}

#[test]
fn raw_and_residue_escape_hatches_are_forbidden() {
    assert!(check_semantic_source("__raw__0x00000000000000000000000000000000 ;").is_err());
    assert!(check_semantic_source("NOP !rsd[127:1] ;").is_err());
    assert!(check_semantic_source("ISETP.?6 P0, PT, R1, R2, PT ;").is_err());
    assert!(check_semantic_source("LDG R1, [???255.64] ;").is_err());
    assert!(check_semantic_source("SEL R1, R2, ?UP ;").is_err());
    assert!(check_semantic_source("// Why?\n[B------:R-:W-:-:S01] NOP ;").is_ok());
    assert!(check_semantic_source("[B------:R-:W-:-:S01] NOP ;").is_ok());
}

#[test]
fn code_only_semantic_api_refuses_metadata_instead_of_discarding_it() {
    let t = table();
    for directive in [
        ".reg R0-R127", ".maxreg 128", ".pred P0-P3", ".param u64 input",
        ".shared .align 16 scratch[4096]", ".bar B0-B5",
        ".merc_syncwarp 0x20", ".merc_cgsites 0x20",
        ".target sm_80", ".version 8.7", ".address_size 64",
    ] {
        let source = format!("{directive}\n.entry k\n[B------:R-:W-:-:S01] NOP ;\n.endentry\n");
        assert!(cubit::roundtrip_audit::encode_semantic_source(&source, &t).is_err(), "{directive}");
        let source = format!(".entry k\n{directive}\n[B------:R-:W-:-:S01] NOP ;\n.endentry\n");
        assert!(cubit::roundtrip_audit::encode_semantic_source(&source, &t).is_err(), "{directive}");
    }
    let source = ".entry k\n.target: [B------:R-:W-:-:S01] NOP ;\n.endentry\n";
    assert_eq!(cubit::roundtrip_audit::encode_semantic_source(source, &t).unwrap().len(), 16);
}

#[test]
fn unknown_words_and_partial_tails_fail_closed() {
    let t = table();
    let index = DecodeIndex::build(&t);
    let mut failures = Vec::new();
    let (r, source) = audit_kernel(".text.unknown", 2, &[0u8; 17], &t, &index, &mut |f| {
        failures.push(f.clone());
        Ok(())
    })
    .unwrap();
    assert!(!r.passed);
    assert_eq!(r.decode_errors, 1);
    assert_eq!(r.partial_tail_bytes, 1);
    assert!(failures.iter().any(|f| f.stage == "stream_count"));
    assert!(failures.iter().any(|f| f.stage == "partial_tail"));
    check_semantic_source(&source).unwrap();
}

#[test]
fn empty_sections_no_sections_and_wrong_arch_are_errors() {
    let t = table();
    for (bytes, message) in [
        (cubin(120, &[]), "no .text"),
        (
            cubin(120, &[(".text.empty", Vec::new())]),
            "no instructions",
        ),
        (
            cubin(100, &[(".text.wrong_arch", vec![0u8; 16])]),
            "architecture mismatch",
        ),
    ] {
        let e = audit_cubin(&bytes, &t, &mut |_| Ok(()), &mut |_, _| Ok(())).unwrap_err();
        assert!(e.to_string().contains(message), "{e:#}");
    }
    let mut bytes = cubin(120, &[(".text.host", vec![0u8; 16])]);
    bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
    assert!(audit_cubin(&bytes, &t, &mut |_| Ok(()), &mut |_, _| Ok(()))
        .unwrap_err()
        .to_string()
        .contains("EM_CUDA"));
    let mut nonnative = cubin(120, &[(".text.compiler_object", vec![0u8; 16])]);
    nonnative[48] = 1;
    assert!(
        audit_cubin(&nonnative, &t, &mut |_| Ok(()), &mut |_, _| Ok(()))
            .unwrap_err()
            .to_string()
            .contains("code layout 1")
    );
}

#[test]
fn hidden_reuse_hints_use_editable_operand_syntax_without_changing_vendor_prints() {
    let t = table();
    let index = DecodeIndex::build(&t);
    // NVIDIA corpus anchor: IMAD.WIDE.U32.X, yield clear, real reuse on Ra.
    let base = 0x040fc80002080442000000781e427225u128 & !(7u128 << 122);
    for reuse in 0u128..8 {
        for yielding in [false, true] {
            let expected = base | (reuse << 122) | if yielding { 1u128 << 109 } else { 0 };
            let decoded = index.decode(expected, 0, &t).unwrap();
            let vendor = cubit::printer::to_sass(&decoded);
            let semantic = cubit::printer::to_sass_lossless(&decoded);
            assert_eq!(
                vendor.matches(".reuse").count(),
                if yielding {
                    reuse.count_ones() as usize
                } else {
                    0
                }
            );
            assert_eq!(
                semantic.matches(".reuse").count(),
                reuse.count_ones() as usize
            );
            let ctrl = cubit::scheduling::decode_sched_upper32((expected >> 96) as u32);
            let source = format!(
                "[{}] {} ;",
                cubit::scheduling::format_control_code(&ctrl),
                semantic
            );
            check_semantic_source(&source).unwrap();
            assert_eq!(word(&t, &source, 0), expected, "{source}");
            // The lossless mode must leave the original object and default
            // NVIDIA-compatible formatting untouched.
            assert_eq!(decoded.raw_code, expected);
            assert_eq!(cubit::printer::to_sass(&decoded), vendor);
        }
    }
}

#[test]
fn cli_exit_status_is_nonzero_for_failures_and_zero_only_for_complete_pass() {
    let t = table();
    let root = std::env::temp_dir().join(format!(
        "cubit_strict_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let input = root.join("input.cubin");
    let report = root.join("report.json");
    let failures = root.join("failures.jsonl");
    let sass = root.join("sass");
    let rebuilt = root.join("rebuilt");
    let invoke = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_cubit"))
            .arg("roundtrip-strict")
            .arg("--failures")
            .arg(&failures)
            .arg("--report")
            .arg(&report)
            .arg("--sass-dir")
            .arg(&sass)
            .arg("--rebuilt-dir")
            .arg(&rebuilt)
            .arg(&input)
            .output()
            .unwrap()
    };
    std::fs::write(&input, cubin(120, &[(".text.bad", vec![0u8; 16])])).unwrap();
    let failed = invoke();
    assert!(!failed.status.success());
    assert!(!rebuilt.join("input_00000.cubin").exists());
    assert!(std::fs::read_to_string(&failures)
        .unwrap()
        .contains("decode"));
    let bad_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(bad_report[0]["report"]["passed"], false);
    // A fresh output directory is required for each run.
    std::fs::remove_dir_all(&sass).unwrap();
    let nop = word(&t, "[B------:R-:W-:-:S01] NOP ;", 0);
    let nop2 = word(&t, "[B------:R-:W-:-:S09] NOP ;", 0);
    // Real library modules can contain distinct local functions with equal
    // names. Rebuilding must address their physical sections independently.
    std::fs::write(
        &input,
        cubin(
            120,
            &[
                (".text.good", nop.to_le_bytes().to_vec()),
                (".text.good", nop2.to_le_bytes().to_vec()),
            ],
        ),
    )
    .unwrap();
    let passed = invoke();
    assert!(
        passed.status.success(),
        "{}",
        String::from_utf8_lossy(&passed.stderr)
    );
    assert_eq!(
        std::fs::read(rebuilt.join("input_00000.cubin")).unwrap(),
        std::fs::read(&input).unwrap()
    );
    assert!(std::fs::read_to_string(&failures).unwrap().is_empty());
    let good_report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(good_report[0]["report"]["passed"], true);
    assert_eq!(
        good_report[0]["report"]["kernels"][0]["source_name"],
        "good"
    );
    assert_eq!(
        good_report[0]["report"]["kernels"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let stale = invoke();
    assert!(!stale.status.success());
    assert!(String::from_utf8_lossy(&stale.stderr).contains("new or empty"));
    for (variable, value) in [
        ("CUBIT_FIT_LINT", "allow"),
        ("CUBIT_FIT_LINT", "warn"),
        ("CUBIT_DISABLE_ERRATA", "1"),
    ] {
        let bypass = std::process::Command::new(env!("CARGO_BIN_EXE_cubit"))
            .arg("roundtrip-strict")
            .arg(&input)
            .env(variable, value)
            .output()
            .unwrap();
        assert!(
            !bypass.status.success(),
            "strict command accepted {variable}={value}"
        );
        assert!(String::from_utf8_lossy(&bypass.stderr).contains(variable));
    }
    std::fs::remove_dir_all(&root).unwrap();
}

#[test]
fn semantic_rebuild_uses_source_and_keeps_noncode_bytes_verbatim() {
    use cubit::{
        elf::CubinFile,
        roundtrip_audit::{encode_semantic_source, patch_semantic_section},
    };
    let t = table();
    let source = ".entry edited\n[B------:R-:W-:-:S01] NOP ;\n.endentry\n";
    let code = encode_semantic_source(source, &t).unwrap();
    let original = cubin(
        120,
        &[(".text.first", code.clone()), (".text.second", code)],
    );
    let mut rebuilt = CubinFile::from_bytes(original.clone()).unwrap();
    patch_semantic_section(&mut rebuilt, ".text.first", source, &t).unwrap();
    assert_eq!(rebuilt.bytes, original);
    let changed = source.replace("S01", "S07");
    patch_semantic_section(&mut rebuilt, ".text.first", &changed, &t).unwrap();
    assert_ne!(
        rebuilt.text_bytes(0).unwrap(),
        &original[rebuilt.text_sections[0].1 as usize..][..16]
    );
    assert_eq!(
        rebuilt.text_bytes(1).unwrap(),
        CubinFile::from_bytes(original.clone())
            .unwrap()
            .text_bytes(1)
            .unwrap()
    );
    let offset = rebuilt.text_sections[0].1 as usize;
    assert_eq!(&rebuilt.bytes[..offset], &original[..offset]);
    assert_eq!(&rebuilt.bytes[offset + 16..], &original[offset + 16..]);
    assert!(patch_semantic_section(&mut rebuilt, ".text.missing", source, &t).is_err());
    for bad in [
        source.replace("NOP", "__raw__0x0"),
        source.replace("NOP", "NOP !rsd[127:1]"),
        source.replace("[B------:R-:W-:-:S01] ", ""),
        source.replace("NOP ;", "NOP ;\nNOP ;"),
    ] {
        assert!(
            patch_semantic_section(&mut rebuilt, ".text.first", &bad, &t).is_err(),
            "accepted {bad}"
        );
    }
}

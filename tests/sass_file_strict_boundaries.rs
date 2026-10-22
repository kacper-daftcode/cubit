//! Complete-source parsing must never silently omit authored instructions.
use cubit::sass_file::{parse_sass_file_str, parse_sass_file_str_strict};

const ENTRY: &str = ".entry first\n[B------:R-:W-:-:S01] NOP ;\n.endentry\n";

#[test]
fn strict_rejects_instructions_before_after_and_between_functions() {
    let nop = "[B------:R-:W-:-:S01] NOP ;\n";
    for source in [
        format!("{nop}{ENTRY}"),
        format!("{ENTRY}{nop}"),
        format!("{ENTRY}{nop}.func second\nNOP ;\n.endfunc\n"),
        format!("{ENTRY}THIS_IS_INVALID R999 ;\n"),
    ] {
        let error = parse_sass_file_str_strict(&source).unwrap_err().to_string();
        assert!(error.contains("outside .entry/.func block"), "{error}");
        // Legacy tolerant parsing remains available to its existing callers.
        assert!(parse_sass_file_str(&source).is_ok());
    }
}

#[test]
fn strict_rejects_labels_unknown_directives_and_resource_declarations_outside_functions() {
    for stray in ["orphan:", ".L_orphan: NOP ;", ".unknown NOP ;", ".reg R0-R31"] {
        assert!(parse_sass_file_str_strict(&format!("{ENTRY}{stray}\n")).is_err(), "{stray}");
    }
}

#[test]
fn file_headers_and_comments_remain_accepted_without_swallowing_instructions() {
    let source = format!(
        "// header comment ; NOP\n# another comment\n;; era=sm100\n.version 9.3 // version\n.target sm_120, texmode_independent\n.address_size 64; # size\n{ENTRY}// tail comment\n"
    );
    let file = parse_sass_file_str_strict(&source).unwrap();
    assert_eq!(file.kernels.len(), 1);
    assert_eq!(file.kernels[0].instructions.len(), 1);
    assert!(file.kernels[0].resources.era100);
    for header in [
        ".version 9.3; NOP ;", ".target sm_120; NOP ;", ".address_size 64; NOP ;",
        ".version 9.3 NOP", ".target sm_120 NOP", ".address_size 64 NOP",
        ".target", ".versionish 9.3", ".target sm_120,",
    ] {
        assert!(parse_sass_file_str_strict(&format!("{header}\n{ENTRY}")).is_err(), "{header}");
    }
}

#[test]
fn function_markers_require_keyword_boundaries_and_do_not_drop_trailing_text() {
    for source in [
        ".entry\nNOP ;\n.endentry\n".to_owned(),
        ".entryfirst\nNOP ;\n.endentry\n".to_owned(),
        format!("{ENTRY}.endentry\n"),
        ".entry first\nNOP ;\n.endentry NOP ;\n".to_owned(),
        ".entry first\nNOP ;\n.endfuncjunk\n".to_owned(),
    ] {
        assert!(parse_sass_file_str_strict(&source).is_err(), "{source}");
    }
}

#[test]
fn supported_implicit_function_closing_and_resource_directives_remain_valid() {
    let source = ".entry first // entry comment\n.reg R0-R31\nNOP ;\n.func helper # name comment\nNOP ;\n.endfunc // end comment\n.entry final\nNOP ;\n";
    let file = parse_sass_file_str_strict(source).unwrap();
    assert_eq!(file.kernels.iter().map(|k| k.name.as_str()).collect::<Vec<_>>(), ["first", "helper", "final"]);
    assert!(file.kernels.iter().all(|k| k.instructions.len() == 1));
    assert_eq!(file.kernels[0].resources.max_reg, Some(31));
}

#[test]
fn semantic_source_api_rejects_authored_instructions_outside_its_entry() {
    let table = cubit::IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
    let code = cubit::roundtrip_audit::encode_semantic_source(ENTRY, &table).unwrap();
    assert_eq!(code.len(), 16);
    for stray in ["THIS_IS_INVALID R999 ;", "[B------:R-:W-:-:S01] NOP ;"] {
        assert!(cubit::roundtrip_audit::encode_semantic_source(&format!("{ENTRY}{stray}\n"), &table).is_err());
    }
}

#[test]
fn strict_body_rejects_unknown_directives_and_executable_text_after_metadata() {
    for line in [
        ".typo_that_is_not_a_directive [B------:R-:W-:-:S01] EXIT ;",
        ".regR0-R31", ".reg R0-R31 NOP ;", ".maxreg 64; EXIT ;",
        ".param u64 input EXIT", ".param unknown input", ".param u64 input; EXIT ;",
        ".shared .alignment 16 smem[64]", ".shared smem[64] EXIT",
        ".merc_syncwarp 0x20 EXIT", ".merc_cgsites 0x20:0xffffffff EXIT",
        ".pred", ".bar arbitrary", ".version 9.3",
    ] {
        let source = format!(".entry first\nNOP ;\n{line}\n.endentry\n");
        assert!(parse_sass_file_str_strict(&source).is_err(), "silently accepted {line}");
        assert!(parse_sass_file_str(&source).is_ok(), "legacy parsing changed: {line}");
    }
}

#[test]
fn implemented_metadata_directives_are_fully_consumed_and_preserved() {
    let source = ".entry metadata\n.maxreg 64;\n.reg .u32 R0-R31; # first comment // second\n.pred P0-P3;\n.bar B0-B1;\n.param u64 input;\n.shared .align 16 smem[64];\n.merc_cgsites 0x20:0xffffffff, 64:3;\n.merc_syncwarp 0x30;\nNOP ;\n.endentry\n";
    let file = parse_sass_file_str_strict(source).unwrap();
    let kernel = &file.kernels[0];
    assert_eq!(kernel.instructions.len(), 1);
    assert_eq!(kernel.resources.max_reg, Some(63));
    assert_eq!(kernel.resources.max_pred, Some(3));
    assert_eq!(kernel.resources.num_barriers, 2);
    assert_eq!(kernel.resources.params[0].name, "input");
    assert_eq!(kernel.resources.shared[0].name, "smem");
    assert_eq!(kernel.resources.shared[0].align, 16);
    assert_eq!(kernel.resources.shared[0].size, 64);
    assert_eq!(kernel.resources.merc_cgsites, [(32, 0xffff_ffff), (64, 3)]);
    assert_eq!(kernel.resources.merc_syncwarp, [3]);
    let comment_order = parse_sass_file_str_strict(
        ".entry comments\n.reg R0-R7 # first comment // second\nNOP ;\n.endentry\n",
    ).unwrap();
    assert_eq!(comment_order.kernels[0].resources.max_reg, Some(7));
    // A declaration keyword followed by a label separator remains a label,
    // while an actual directive must have a complete, valid payload.
    let file = parse_sass_file_str_strict(".entry x\n.reg: NOP ;\n.endentry\n").unwrap();
    assert_eq!(file.kernels[0].instructions.len(), 1);
    assert!(file.kernels[0].labels[&0].contains(&".reg".to_string()));
}

#[test]
fn semantic_source_api_never_returns_partial_code_for_hidden_body_instructions() {
    let table = cubit::IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
    for source in [
        ".entry x\nNOP ;\n.typo_that_is_not_a_directive [B------:R-:W-:-:S01] EXIT ;\n.endentry\n",
        ".entry x\nNOP ;\n.reg R0-R31; EXIT ;\n.endentry\n",
        ".entry x [B------:R-:W-:-:S01] EXIT ;\nNOP ;\n.endentry\n",
        ".entry x ; [B------:R-:W-:-:S01] EXIT ;\nNOP ;\n.endentry\n",
        ".func helper [B------:R-:W-:-:S01] EXIT ;\nNOP ;\n.endfunc\n",
    ] {
        assert!(cubit::roundtrip_audit::encode_semantic_source(source, &table).is_err(), "accepted partial source: {source}");
    }
}

#[test]
fn bare_merc_cgsites_preserve_the_documented_full_mask() {
    let source = ".entry sites\n.merc_cgsites 0x20, 64;\n.merc_cgsites 0x50:0x3\nNOP ;\n.endentry\n";
    for parse in [parse_sass_file_str, parse_sass_file_str_strict] {
        let file = parse(source).unwrap();
        assert_eq!(file.kernels[0].instructions.len(), 1);
        assert_eq!(file.kernels[0].resources.merc_cgsites,
                   [(32, u32::MAX), (64, u32::MAX), (80, 3)]);
        let rendered = cubit::render::render_file(&file).unwrap();
        let reparsed = parse_sass_file_str_strict(&rendered).unwrap();
        assert_eq!(reparsed.kernels[0].resources.merc_cgsites,
                   file.kernels[0].resources.merc_cgsites);
    }
}

#[test]
fn strict_guard_grammar_never_defaults_malformed_tokens_to_always_true() {
    let table = cubit::IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
    for token in [
        "@Pbanana", "@P0junk", "@UPbanana", "@UPTjunk", "@P", "@!UP",
        "@P7", "@UP8", "@P255", "@P4294967296", "@P00", "@P０", "@!!P0",
    ] {
        let source = format!(".entry guard\n[B------:R-:W-:-:S01] {token} MOV R1, R2 ;\n.endentry\n");
        assert!(parse_sass_file_str_strict(&source).is_err(), "accepted malformed {token}");
        assert!(cubit::roundtrip_audit::encode_semantic_source(&source, &table).is_err(), "encoded malformed {token}");
        assert!(parse_sass_file_str(&source).is_ok(), "changed tolerant parsing of {token}");
    }
    for (token, pred, negated, uniform) in [
        ("@P0", 0, false, false), ("@!P6", 6, true, false), ("@PT", 7, false, false),
        ("@!PT", 7, true, false), ("@UP0", 0, false, true), ("@!UP6", 6, true, true),
        ("@UPT", 7, false, true), ("@!UPT", 7, true, true),
    ] {
        let source = format!(".entry guard\n[B------:R-:W-:-:S01] {token} MOV R1, R2 ;\n.endentry\n");
        let file = parse_sass_file_str_strict(&source).unwrap();
        let guard = file.kernels[0].instructions[0].guard.as_ref().unwrap();
        assert_eq!((guard.pred, guard.negated, guard.uniform), (pred, negated, uniform), "{token}");
    }
}

#[test]
fn strict_control_fields_have_exact_bounds_and_no_trailing_payload() {
    let table = cubit::IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
    for control in [
        "B------:R-:W-:-:S16", "B------:R-:W-:-:S99",
        "B------:R6:W-:-:S01", "B------:R7:W-:-:S01", "B------:R8:W-:-:S01",
        "B------:R-:W6:-:S01", "B------:R-:W7:-:S01", "B------:R-:W8:-:S01",
        "B0123456:R-:W-:-:S01", "B012346:R-:W-:-:S01", "B------:R-:W-:YY:S01",
        "B------:R-:W-:0:S01", "B------:R-:W-:-:S01:extra", "B------:R-:W-:-:S001",
    ] {
        let source = format!(".entry controls\n[{control}] NOP ;\n.endentry\n");
        assert!(parse_sass_file_str_strict(&source).is_err(), "accepted {control}");
        assert!(cubit::roundtrip_audit::encode_semantic_source(&source, &table).is_err(), "encoded {control}");
        assert!(parse_sass_file_str(&source).is_ok(), "changed tolerant parsing of {control}");
    }
    for control in ["B------:R-:W-:-:S00", "B012345:R5:W5:Y:S15"] {
        let source = format!(".entry controls\n[{control}] NOP ;\n.endentry\n");
        let file = parse_sass_file_str_strict(&source).unwrap();
        let expected = &file.kernels[0].instructions[0].ctrl;
        let bytes = cubit::roundtrip_audit::encode_semantic_source(&source, &table).unwrap();
        let word = u128::from_le_bytes(bytes.try_into().unwrap());
        let actual = cubit::scheduling::decode_sched_upper32((word >> 96) as u32);
        assert_eq!(cubit::scheduling::format_control_code(&actual), control);
        assert_eq!((actual.stall, actual.wait_mask, actual.read_bar, actual.write_bar, actual.yield_flag),
                   (expected.stall, expected.wait_mask, expected.read_bar, expected.write_bar, expected.yield_flag));
    }
}

#[test]
fn strict_opaque_annotations_cannot_hide_authored_tokens() {
    let table = cubit::IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
    for annotation in ["&EXIT", "&R999", "?EXIT", "?opaque"] {
        let source = format!(".entry annotations\n[B------:R-:W-:-:S01] NOP {annotation} ;\n.endentry\n");
        assert!(parse_sass_file_str_strict(&source).is_err(), "silently dropped {annotation}");
        assert!(cubit::roundtrip_audit::encode_semantic_source(&source, &table).is_err());
        assert_eq!(parse_sass_file_str(&source).unwrap().kernels[0].instructions.len(), 1);
    }
    let comments = ".entry comments\n# A question? &ordinary comment\n[B------:R-:W-:-:S01] NOP ; // question? &comment\n.endentry\n";
    assert_eq!(cubit::roundtrip_audit::encode_semantic_source(comments, &table).unwrap().len(), 16);
}

#[test]
fn code_only_assembly_rejects_compiler_era_markers_at_every_boundary() {
    let table = cubit::IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
    for marker in [";; era=sm100", ";;era=sm100", "; ; era=sm100", "; ; era = sm100"] {
        for source in [
            format!("{marker}\n{ENTRY}"),
            format!(".entry first\n{marker}\n[B------:R-:W-:-:S01] NOP ;\n.endentry\n"),
            format!("{ENTRY}{marker}\n"),
        ] {
            let error = cubit::roundtrip_audit::encode_semantic_source(&source, &table).unwrap_err();
            assert!(error.to_string().contains("compiler era marker"), "{error:#}");
        }
    }
    // Metadata-aware strict parsing still retains the canonical header, while
    // text that only mentions it inside ordinary comments is code-only safe.
    let file = parse_sass_file_str_strict(&format!(";; era=sm100\n{ENTRY}")).unwrap();
    assert!(file.kernels[0].resources.era100);
    let comments = format!("// ;; era=sm100\n# ; ; era=sm100\n{ENTRY}");
    assert_eq!(cubit::roundtrip_audit::encode_semantic_source(&comments, &table).unwrap().len(), 16);
}

//! Audit an explicit runtime census, retaining missing names and input errors.
//! Usage: audit_manifest manifest.json table.json NEW_output_directory
use anyhow::{bail, Context, Result};
use cubit::{decoder::DecodeIndex, elf::CubinFile, roundtrip_audit::KernelReport, IsaTable};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn fresh_directory(path: &Path) -> Result<()> {
    if path.exists() && fs::read_dir(path)?.next().is_some() {
        bail!("output directory must be new or empty: {}", path.display());
    }
    fs::create_dir_all(path)?;
    Ok(())
}

fn audit_module(
    module: &Value,
    table: &IsaTable,
    ix: &DecodeIndex,
    out: &Path,
    failures: &mut impl Write,
) -> Result<Value> {
    let path = module["path"].as_str().context("module path missing")?;
    let sha = module["sha256"].as_str().context("module sha256 missing")?;
    let bytes = fs::read(path)?;
    let actual_sha = digest(&bytes);
    if actual_sha != sha {
        bail!("SHA256 mismatch: expected {sha}, got {actual_sha}");
    }
    cubit::roundtrip_audit::validate_cubin_header(&bytes, table)?;
    let cub = CubinFile::from_bytes(bytes)?;
    let mut rebuilt = CubinFile::from_bytes(cub.bytes.clone())?;
    let requested = module["sections"]
        .as_array()
        .context("section census missing")?;
    let mut requested_names: Vec<&str> = requested
        .iter()
        .map(|v| v.as_str().context("section name missing"))
        .collect::<Result<_>>()?;
    let selected: HashSet<usize> = if let Some(indices) = module.get("required_text_indices") {
        let indices = indices
            .as_array()
            .context("required_text_indices must be an array")?;
        let selected: HashSet<usize> = indices
            .iter()
            .map(|v| {
                usize::try_from(v.as_u64().context("invalid text index")?)
                    .map_err(anyhow::Error::from)
            })
            .collect::<Result<_>>()?;
        if selected.len() != indices.len() {
            bail!("duplicate required text indices");
        }
        let mut found: Vec<&str> = selected
            .iter()
            .map(|&i| {
                cub.text_sections
                    .get(i)
                    .map(|s| s.0.as_str())
                    .context("required text index out of range")
            })
            .collect::<Result<_>>()?;
        requested_names.sort_unstable();
        found.sort_unstable();
        if requested_names != found {
            bail!("section names do not match the required physical text indices");
        }
        selected
    } else {
        let mut selected = HashSet::new();
        for name in &requested_names {
            let matches: Vec<_> = cub
                .text_sections
                .iter()
                .enumerate()
                .filter(|(_, s)| s.0 == *name)
                .map(|(i, _)| i)
                .collect();
            if matches.len() != 1 || !selected.insert(matches[0]) {
                bail!(
                    "required name is missing/ambiguous/duplicated; specify required_text_indices"
                );
            }
        }
        selected
    };
    if selected.is_empty() {
        bail!("empty section census");
    }
    let mut reports: Vec<KernelReport> = Vec::new();
    for (si, (name, _, _)) in cub.text_sections.iter().enumerate() {
        if !selected.contains(&si) {
            continue;
        }
        let mut sink = |f: &cubit::roundtrip_audit::Failure| -> Result<()> {
            writeln!(failures, "{}", json!({"input":path,"failure":f}))?;
            Ok(())
        };
        let (mut report, source) = cubit::roundtrip_audit::audit_kernel(
            name,
            si,
            cub.text_bytes(si)?,
            table,
            ix,
            &mut sink,
        )?;
        report.text_index = Some(si);
        if report.passed {
            cubit::roundtrip_audit::patch_semantic_section_at(
                &mut rebuilt,
                report.text_index.context("audited section is missing its physical text index")?,
                &source,
                table,
            )?;
        }
        fs::write(out.join("sass").join(format!("{sha}_{si}.sass")), source)?;
        reports.push(report);
    }
    let source_rebuilt = reports.len() == selected.len() && reports.iter().all(|r| r.passed);
    if source_rebuilt {
        if rebuilt.bytes != cub.bytes {
            bail!("ELF differs after semantic source rebuild");
        }
        fs::write(
            out.join("rebuilt").join(format!("{sha}.cubin")),
            &rebuilt.bytes,
        )?;
    }
    let instructions: usize = reports.iter().map(|r| r.instructions).sum();
    let matched: usize = reports.iter().map(|r| r.matched).sum();
    println!(
        "{sha}: {} required sections; {matched}/{instructions} instructions; {}",
        reports.len(),
        if source_rebuilt { "PASS" } else { "FAIL" }
    );
    Ok(
        json!({"input":path,"sha256":sha,"kernels":reports,"instructions":instructions,"matched":matched,
        "passed":source_rebuilt,"rebuilt_required_sections":if source_rebuilt{selected.len()}else{0},
        "total_code_sections":cub.text_sections.len(),"elf_byte_identical":source_rebuilt,
        "code_scope":"manifest_required_sections","manifest_module":module}),
    )
}

fn run(manifest_path: &Path, table_path: &Path, out: &Path) -> Result<()> {
    cubit::roundtrip_audit::check_strict_environment()?;
    let manifest_bytes = fs::read(manifest_path)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    let missing = manifest
        .get("missing")
        .and_then(Value::as_array)
        .context("missing must be explicit array")?;
    let modules = manifest
        .get("modules")
        .and_then(Value::as_array)
        .context("modules must be array")?;
    if modules.is_empty() {
        bail!("empty module census");
    }
    let mut identities = HashSet::new();
    for module in modules {
        let sha = module["sha256"].as_str().context("module sha256 missing")?;
        if !identities.insert(sha) {
            bail!("duplicate module SHA256 {sha}");
        }
    }
    let table_bytes = fs::read(table_path)?;
    let table = IsaTable::from_json(std::str::from_utf8(&table_bytes)?)?;
    let ix = DecodeIndex::build(&table);
    fresh_directory(out)?;
    fs::create_dir(out.join("sass"))?;
    fs::create_dir(out.join("rebuilt"))?;
    fs::write(out.join("manifest.snapshot.json"), &manifest_bytes)?;
    fs::write(out.join("table.snapshot.json"), &table_bytes)?;
    let mut failures = BufWriter::new(fs::File::create(out.join("failures.jsonl"))?);
    let mut reports = Vec::new();
    let mut passed = missing.is_empty();
    for module in modules {
        match audit_module(module, &table, &ix, out, &mut failures) {
            Ok(report) => {
                passed &= report["passed"] == true;
                reports.push(report);
            }
            Err(error) => {
                passed = false;
                let record = json!({"input":module["path"],"stage":"input","error":format!("{error:#}"),
                    "passed":false,"manifest_module":module});
                eprintln!("{}: FAIL: {error:#}", module["path"]);
                writeln!(failures, "{record}")?;
                reports.push(record);
            }
        }
    }
    failures.flush()?;
    let total: u64 = reports
        .iter()
        .filter_map(|r| r["instructions"].as_u64())
        .sum();
    let matched: u64 = reports.iter().filter_map(|r| r["matched"].as_u64()).sum();
    let kernels: usize = reports
        .iter()
        .filter_map(|r| r["kernels"].as_array())
        .map(Vec::len)
        .sum();
    passed &= total > 0;
    let report = json!({"manifest":manifest_path,"manifest_sha256":digest(&manifest_bytes),
        "table":table_path,"table_sha256":digest(&table_bytes),"code_scope":"manifest_required_sections",
        "missing":missing,"modules":reports,"kernels":kernels,"instructions":total,"matched":matched,"passed":passed});
    fs::write(out.join("report.json"), serde_json::to_vec_pretty(&report)?)?;
    println!("TOTAL {kernels} required sections, {matched}/{total} full 128-bit instructions, {} missing names, {}",missing.len(),if passed{"PASS"}else{"FAIL"});
    if !passed {
        bail!("runtime census is incomplete or has semantic roundtrip failures");
    }
    Ok(())
}
fn main() -> Result<()> {
    let a: Vec<_> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    if a.len() != 3 {
        bail!("usage: audit_manifest manifest.json table.json NEW_output_directory");
    }
    run(&a[0], &a[1], &a[2])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        OnceLock,
    };

    static NEXT_CASE: AtomicUsize = AtomicUsize::new(0);
    static TABLE_BYTES: OnceLock<Vec<u8>> = OnceLock::new();

    struct Case {
        root: PathBuf,
        table: PathBuf,
        nop: u128,
    }
    impl Case {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "cubit_manifest_test_{}_{}_{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT_CASE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            let bytes = TABLE_BYTES.get_or_init(|| {
                let source = std::env::var_os("CUBIT_TABLE")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| {
                        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tables/sm120.json")
                    });
                fs::read(source).unwrap()
            });
            let table = root.join("table.json");
            fs::write(&table, bytes).unwrap();
            let isa = IsaTable::from_json(std::str::from_utf8(bytes).unwrap()).unwrap();
            let nop = cubit::encoder::encode_instruction(
                &cubit::parse_cuasm_line("[B------:R-:W-:-:S01] NOP ;", 0).unwrap(),
                &isa,
            )
            .unwrap();
            Self { root, table, nop }
        }
        fn module(&self, filename: &str, sections: &[(&str, Vec<u8>)]) -> Value {
            let path = self.root.join(filename);
            let bytes = cubin(sections);
            fs::write(&path, &bytes).unwrap();
            json!({"path":path,"sha256":digest(&bytes),"sections":sections.iter().map(|(name,_)|*name).collect::<Vec<_>>()})
        }
        fn manifest(&self, filename: &str, modules: Vec<Value>, missing: Vec<&str>) -> PathBuf {
            let path = self.root.join(filename);
            let value = json!({"scope":"test: exact required sections","missing":missing,"modules":modules});
            fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
            path
        }
        fn report(&self, directory: &str) -> Value {
            serde_json::from_slice(
                &fs::read(self.root.join(directory).join("report.json")).unwrap(),
            )
            .unwrap()
        }
    }
    impl Drop for Case {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    // ELF section identity is its physical index, even when names are equal.
    fn cubin(sections: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut strings = b"\0.shstrtab\0".to_vec();
        let mut name_offsets = Vec::new();
        for (name, _) in sections {
            name_offsets.push(strings.len() as u32);
            strings.extend_from_slice(name.as_bytes());
            strings.push(0);
        }
        let mut bytes = vec![0; 64];
        let strings_offset = bytes.len();
        bytes.extend_from_slice(&strings);
        let mut code_offsets = Vec::new();
        for (_, code) in sections {
            while bytes.len() % 16 != 0 {
                bytes.push(0);
            }
            code_offsets.push(bytes.len());
            bytes.extend_from_slice(code);
        }
        while bytes.len() % 8 != 0 {
            bytes.push(0);
        }
        let shoff = bytes.len();
        bytes.resize(shoff + (sections.len() + 2) * 64, 0);
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        bytes[16..18].copy_from_slice(&1u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&0xbeu16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
        bytes[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
        bytes[48..52].copy_from_slice(&0x0600_7802u32.to_le_bytes());
        bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
        bytes[58..60].copy_from_slice(&64u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&((sections.len() + 2) as u16).to_le_bytes());
        bytes[62..64].copy_from_slice(&1u16.to_le_bytes());
        let header = shoff + 64;
        bytes[header..header + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[header + 4..header + 8].copy_from_slice(&3u32.to_le_bytes());
        bytes[header + 24..header + 32].copy_from_slice(&(strings_offset as u64).to_le_bytes());
        bytes[header + 32..header + 40].copy_from_slice(&(strings.len() as u64).to_le_bytes());
        for (i, (_, code)) in sections.iter().enumerate() {
            let header = shoff + (i + 2) * 64;
            bytes[header..header + 4].copy_from_slice(&name_offsets[i].to_le_bytes());
            bytes[header + 4..header + 8].copy_from_slice(&1u32.to_le_bytes());
            bytes[header + 8..header + 16].copy_from_slice(&6u64.to_le_bytes());
            bytes[header + 24..header + 32]
                .copy_from_slice(&(code_offsets[i] as u64).to_le_bytes());
            bytes[header + 32..header + 40].copy_from_slice(&(code.len() as u64).to_le_bytes());
            bytes[header + 48..header + 56].copy_from_slice(&16u64.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn bad_sha_and_unsupported_layout_are_reported_then_good_input_is_still_audited() {
        let case = Case::new();
        let good = case.module(
            "good.cubin",
            &[(".text.good", case.nop.to_le_bytes().to_vec())],
        );
        let mut bad_sha = good.clone();
        bad_sha["sha256"] = json!("0".repeat(64));
        let mut unsupported = case.module(
            "unsupported.cubin",
            &[(".text.unsupported", case.nop.to_le_bytes().to_vec())],
        );
        let path = unsupported["path"].as_str().unwrap();
        let mut bytes = fs::read(path).unwrap();
        bytes[48] = 1;
        fs::write(path, &bytes).unwrap();
        unsupported["sha256"] = json!(digest(&bytes));
        let manifest = case.manifest(
            "manifest.json",
            vec![bad_sha, unsupported, good.clone()],
            vec![],
        );
        assert!(run(&manifest, &case.table, &case.root.join("out")).is_err());
        let report = case.report("out");
        assert_eq!(report["passed"], false);
        assert_eq!(report["modules"].as_array().unwrap().len(), 3);
        assert!(report["modules"][0]["error"]
            .as_str()
            .unwrap()
            .contains("SHA256 mismatch"));
        assert!(report["modules"][1]["error"]
            .as_str()
            .unwrap()
            .contains("unsupported CUDA code layout"));
        assert_eq!(report["modules"][2]["passed"], true);
        assert_eq!(report["matched"], 1);
        assert_eq!(report["kernels"], 1);
        assert!(case
            .root
            .join("out/rebuilt")
            .join(format!("{}.cubin", good["sha256"].as_str().unwrap()))
            .exists());
        let failures = fs::read_to_string(case.root.join("out/failures.jsonl")).unwrap();
        assert_eq!(failures.lines().count(), 2);
        assert!(failures
            .lines()
            .all(|line| serde_json::from_str::<Value>(line).unwrap()["stage"] == "input"));
    }

    #[test]
    fn missing_runtime_name_forces_failure_even_when_every_required_instruction_passes() {
        let case = Case::new();
        let module = case.module(
            "good.cubin",
            &[(".text.good", case.nop.to_le_bytes().to_vec())],
        );
        let manifest = case.manifest("manifest.json", vec![module], vec!["runtime_only_kernel"]);
        assert!(run(&manifest, &case.table, &case.root.join("out")).is_err());
        let report = case.report("out");
        assert_eq!(report["passed"], false);
        assert_eq!(report["missing"], json!(["runtime_only_kernel"]));
        assert_eq!(report["modules"][0]["passed"], true);
        assert_eq!(report["instructions"], 1);
        assert_eq!(report["matched"], 1);
    }

    #[test]
    fn duplicate_section_names_use_every_required_physical_text_index() {
        let case = Case::new();
        let isa = IsaTable::load(&case.table).unwrap();
        let other = cubit::encoder::encode_instruction(
            &cubit::parse_cuasm_line("[B------:R-:W-:-:S07] NOP ;", 0).unwrap(),
            &isa,
        )
        .unwrap();
        let mut module = case.module(
            "duplicates.cubin",
            &[
                (".text.same", case.nop.to_le_bytes().to_vec()),
                (".text.same", other.to_le_bytes().to_vec()),
            ],
        );
        module["required_text_indices"] = json!([0, 1]);
        let manifest = case.manifest("manifest.json", vec![module.clone()], vec![]);
        run(&manifest, &case.table, &case.root.join("out")).unwrap();
        let report = case.report("out");
        assert_eq!(report["passed"], true);
        assert_eq!(report["kernels"], 2);
        assert_eq!(report["matched"], 2);
        assert_eq!(report["modules"][0]["rebuilt_required_sections"], 2);
        let kernels = report["modules"][0]["kernels"].as_array().unwrap();
        assert_eq!(kernels[0]["section_index"], 0);
        assert_eq!(kernels[1]["section_index"], 1);
        assert_eq!(kernels[0]["text_index"], 0);
        assert_eq!(kernels[1]["text_index"], 1);
        let sha = module["sha256"].as_str().unwrap();
        assert!(
            fs::read_to_string(case.root.join("out/sass").join(format!("{sha}_0.sass")))
                .unwrap()
                .contains("S01")
        );
        assert!(
            fs::read_to_string(case.root.join("out/sass").join(format!("{sha}_1.sass")))
                .unwrap()
                .contains("S07")
        );
        assert_eq!(
            fs::read(case.root.join("out/rebuilt").join(format!("{sha}.cubin"))).unwrap(),
            fs::read(module["path"].as_str().unwrap()).unwrap()
        );

        // A failure in the second identically named section must not disappear.
        let mut bad = case.module(
            "duplicate_bad.cubin",
            &[
                (".text.same", case.nop.to_le_bytes().to_vec()),
                (".text.same", vec![0; 16]),
            ],
        );
        bad["required_text_indices"] = json!([0, 1]);
        let manifest = case.manifest("bad_manifest.json", vec![bad], vec![]);
        assert!(run(&manifest, &case.table, &case.root.join("bad_out")).is_err());
        let report = case.report("bad_out");
        assert_eq!(report["kernels"], 2);
        assert_eq!(report["instructions"], 2);
        assert_eq!(report["matched"], 1);
        assert_eq!(report["modules"][0]["kernels"][1]["passed"], false);
        assert_eq!(
            fs::read_dir(case.root.join("bad_out/rebuilt"))
                .unwrap()
                .count(),
            0
        );
        assert!(fs::read_to_string(case.root.join("bad_out/failures.jsonl"))
            .unwrap()
            .lines()
            .any(|line| {
                serde_json::from_str::<Value>(line).unwrap()["failure"]["section_index"] == 1
            }));
    }

    #[test]
    fn ambiguous_names_duplicate_indices_and_name_index_disagreement_fail_closed() {
        let case = Case::new();
        let module = case.module(
            "duplicate.cubin",
            &[
                (".text.same", case.nop.to_le_bytes().to_vec()),
                (".text.same", case.nop.to_le_bytes().to_vec()),
            ],
        );
        for (i, indices, names, error) in [
            (0, None, json!([".text.same"]), "ambiguous"),
            (
                1,
                Some(json!([0, 0])),
                json!([".text.same", ".text.same"]),
                "duplicate required text indices",
            ),
            (
                2,
                Some(json!([0, 1])),
                json!([".text.same"]),
                "section names do not match",
            ),
            (
                3,
                Some(json!([0, 2])),
                json!([".text.same", ".text.same"]),
                "out of range",
            ),
        ] {
            let mut candidate = module.clone();
            candidate["sections"] = names;
            if let Some(indices) = indices {
                candidate["required_text_indices"] = indices;
            }
            let manifest = case.manifest(&format!("manifest_{i}.json"), vec![candidate], vec![]);
            assert!(run(&manifest, &case.table, &case.root.join(format!("out_{i}"))).is_err());
            let report = case.report(&format!("out_{i}"));
            assert_eq!(report["passed"], false);
            assert!(
                report["modules"][0]["error"]
                    .as_str()
                    .unwrap()
                    .contains(error),
                "{report}"
            );
        }
    }

    #[test]
    fn stale_output_is_refused_without_overwriting_its_report_or_artifacts() {
        let case = Case::new();
        let module = case.module(
            "good.cubin",
            &[(".text.good", case.nop.to_le_bytes().to_vec())],
        );
        let manifest = case.manifest("manifest.json", vec![module], vec![]);
        let out = case.root.join("out");
        fs::create_dir(&out).unwrap();
        let stale = b"{\"passed\":true,\"stale\":true}";
        fs::write(out.join("report.json"), stale).unwrap();
        fs::write(out.join("previous.cubin"), b"previous artifact").unwrap();
        let error = run(&manifest, &case.table, &out).unwrap_err().to_string();
        assert!(error.contains("must be new or empty"), "{error}");
        assert_eq!(fs::read(out.join("report.json")).unwrap(), stale);
        assert_eq!(
            fs::read(out.join("previous.cubin")).unwrap(),
            b"previous artifact"
        );
        assert!(!out.join("manifest.snapshot.json").exists());
        let empty = case.root.join("empty_out");
        fs::create_dir(&empty).unwrap();
        run(&manifest, &case.table, &empty).unwrap();
    }

    #[test]
    fn report_hashes_identify_the_exact_persisted_manifest_and_table_bytes() {
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let case = Case::new();
        let module = case.module(
            "good.cubin",
            &[(".text.good", case.nop.to_le_bytes().to_vec())],
        );
        let manifest = case.manifest("manifest.json", vec![module], vec![]);
        let manifest_bytes = [
            b" \n".as_slice(),
            fs::read(&manifest).unwrap().as_slice(),
            b"\n\t".as_slice(),
        ]
        .concat();
        let table_bytes = [
            b"\n \n".as_slice(),
            fs::read(&case.table).unwrap().as_slice(),
            b"\n\t".as_slice(),
        ]
        .concat();
        fs::write(&manifest, &manifest_bytes).unwrap();
        fs::write(&case.table, &table_bytes).unwrap();
        run(&manifest, &case.table, &case.root.join("out")).unwrap();
        let report = case.report("out");
        assert_eq!(report["manifest_sha256"], digest(&manifest_bytes));
        assert_eq!(report["table_sha256"], digest(&table_bytes));
        assert_eq!(
            fs::read(case.root.join("out/manifest.snapshot.json")).unwrap(),
            manifest_bytes
        );
        assert_eq!(
            fs::read(case.root.join("out/table.snapshot.json")).unwrap(),
            table_bytes
        );
        assert_eq!(report["code_scope"], "manifest_required_sections");
        assert_eq!(
            report["modules"][0]["manifest_module"]["sections"],
            json!([".text.good"])
        );
        // Later changes to the original paths cannot change the saved proof.
        fs::write(&manifest, b"changed after the audit").unwrap();
        fs::write(&case.table, b"changed after the audit").unwrap();
        assert_eq!(
            digest(&fs::read(case.root.join("out/manifest.snapshot.json")).unwrap()),
            report["manifest_sha256"]
        );
        assert_eq!(
            digest(&fs::read(case.root.join("out/table.snapshot.json")).unwrap()),
            report["table_sha256"]
        );
    }
}

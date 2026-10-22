use cubit::{encoder::encode_instruction, parser::parse_sass, table::IsaTable};

/// Every child starts with a fresh encoder policy cache. Changing its environment
/// afterwards must not make a permissively initialized encoder acceptable to the
/// strict source API.
#[test]
fn cached_permissive_fit_policy_is_rejected_after_environment_is_cleared() {
    const CHILD: &str = "CUBIT_TEST_CACHED_POLICY_CHILD";
    if let Ok(policy) = std::env::var(CHILD) {
        assert_eq!(std::env::var("CUBIT_FIT_LINT").unwrap(), policy);
        let table = IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
        let oversized = parse_sass("SGXT.U32 R0, R0, 0x100000000 ;", 0).unwrap();
        let encoded = encode_instruction(&oversized, &table)
            .expect("the explicitly permissive warmup must initialize the cache");
        assert_eq!((encoded >> 32) & 0xffff_ffff, 0);
        std::env::remove_var("CUBIT_FIT_LINT");
        let error = cubit::roundtrip_audit::encode_semantic_source(
            ".entry policy_probe\n[B------:R-:W-:-:S01] NOP ;\n.end\n",
            &table,
        )
        .expect_err("strict assembly must reject the effective cached policy");
        assert!(
            error.to_string().contains("cached permissive fit policy"),
            "{error:#}"
        );
        return;
    }
    for policy in ["allow", "warn"] {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("cached_permissive_fit_policy_is_rejected_after_environment_is_cleared")
            .arg("--nocapture")
            .env(CHILD, policy)
            .env("CUBIT_FIT_LINT", policy)
            .env_remove("CUBIT_DISABLE_ERRATA")
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{policy}:\n{}\n{}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
    }
}

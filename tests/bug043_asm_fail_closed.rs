//! BUG-043 (zgloszenie frontu M iter8 / F2Q 042-kand; rejestr sm120: plik 043):
//! `cubit asm` przy niewykodowalnej instrukcji tylko WARN-owal, zostawial
//! zero-word (sciezka directive/ELF) albo bajty szablonu (-T) i konczyl
//! rc=0 — plik wygladal na poprawny, a zawieral smiec.
//! Nawiazywalo to do BUG-039 ("encode OK" bez pliku): kontrakt narzedzia
//! klamal. Do tego wchodzi w interakcje z fail-closed completeness BUG-017:
//! pod zewnetrzna zamrozona tabela (tb_i82, era M1; wiersz STS_ARI_R/128 bez
//! pola addr_scale) `STS.128 [Rn.X16], Rm` przestalo sie enkodowac (poprawnie!
//! — suffix realnie nosi bity 78/79, drop = miss-encoding), a lancuch M1
//! dalej produkowal cubin z 4 zerowymi slotami (po dekodowaniu renderowane
//! jako `@P0 STG.E.GPU.STRONG desc[URZ][R0.64], R0`).
//! Fix: asm (wszystkie trzy sciezki: -T template, build-ELF, directive) jest
//! fail-closed — dowolny blad enkodowania = rc!=0, brak pliku wyjsciowego;
//! jawny escape hatch = `__raw__0x...` w sass.
//! Test: sciezka directive przez prawdziwa binarke + poziom lib.

use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;
use std::process::Command;

const SASS_SCALED: &str = ".entry t\n    .param u64 out\n    LDC.64 R2, c[0x0][0x380] ;\n    STS.128 [R5.X16], R200 ;\n    EXIT ;\n";
const SASS_PLAIN: &str = ".entry t\n    .param u64 out\n    LDC.64 R2, c[0x0][0x380] ;\n    STS.128 [R5], R200 ;\n    EXIT ;\n";

/// Tabela w ksztalcie zamrozonej tb_i82: repo-tabela ze STRZETYM polem
/// addr_scale na STS_ARI_R/128 (stan sprzed 4b266e4).
fn write_stale_table(dir: &std::path::Path) -> std::path::PathBuf {
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm120.json").unwrap()).unwrap();
    let row = &mut v["instructions"]["STS_ARI_R"]["mod_groups"]["128"];
    let fields = row["fields"].as_array_mut().unwrap();
    fields.retain(|f| f["extraction"] != "addr_scale");
    let p = dir.join("bug043_stale_table.json");
    std::fs::write(&p, serde_json::to_string(&v).unwrap()).unwrap();
    p
}

fn run_asm(table: &std::path::Path, sass: &str, tag: &str) -> (std::process::Output, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("bug043_{}_{}", tag, std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join(format!("{tag}.sass"));
    let out = dir.join(format!("{tag}.cubin"));
    let _ = std::fs::remove_file(&out);
    std::fs::write(&src, sass).unwrap();
    let res = Command::new(env!("CARGO_BIN_EXE_cubit"))
        .args([
            "asm",
            "-t",
            table.to_str().unwrap(),
            src.to_str().unwrap(),
            "-o",
            out.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    (res, out)
}

#[test]
fn bug043_asm_fails_closed_on_unencodable_slot() {
    let dir = std::env::temp_dir().join(format!("bug043_tbl_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let table = write_stale_table(&dir);

    let (res, out) = run_asm(&table, SASS_SCALED, "scaled");
    assert!(
        !res.status.success(),
        "asm MUST fail when a slot cannot be encoded; got rc=0.\nstdout:{}\nstderr:{}",
        String::from_utf8_lossy(&res.stdout),
        String::from_utf8_lossy(&res.stderr)
    );
    assert!(
        !out.exists(),
        "asm MUST NOT leave an output cubin on failure: {}",
        out.display()
    );
    let stderr = String::from_utf8_lossy(&res.stderr);
    assert!(
        stderr.contains("addr scale suffix .X16"),
        "diagnostics must name the offending operand: {stderr}"
    );
}

#[test]
fn bug043_asm_plain_form_still_assembles_under_stale_table() {
    let dir = std::env::temp_dir().join(format!("bug043_tbl2_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let table = write_stale_table(&dir);

    let (res, out) = run_asm(&table, SASS_PLAIN, "plain");
    assert!(
        res.status.success() && out.exists(),
        "plain STS.128 (scale field unused) must keep assembling; rc={:?}\nstdout:{}\nstderr:{}",
        res.status.code(),
        String::from_utf8_lossy(&res.stdout),
        String::from_utf8_lossy(&res.stderr)
    );
}

#[test]
fn bug043_lib_level_stale_row_rejects_scaled_addr() {
    let dir = std::env::temp_dir().join(format!("bug043_tbl3_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let table_path = write_stale_table(&dir);
    let table = IsaTable::load(&table_path).unwrap();

    let insn = parse_sass("STS.128 [R5.X16], R200", 0).unwrap();
    let err = encode_instruction(&insn, &table).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("addr scale suffix .X16"), "unexpected error: {msg}");

    // repo-tabela (z polem addr_scale) enkoduje obie formy poprawnie
    let good = IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
    let insn = parse_sass("STS.128 [R5.X16], R200", 0).unwrap();
    assert!(encode_instruction(&insn, &good).is_ok());
}

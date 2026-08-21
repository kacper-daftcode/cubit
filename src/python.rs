//! PyO3 Python bindings for cubit.
//!
//! Usage:
//! ```python
//! import cubit
//!
//! # Encode
//! lo, hi = cubit.encode("IADD3 R5, PT, PT, R9, R4, R5 ;", addr=0)
//!
//! # Decode
//! info = cubit.decode(lo, hi, addr=0)
//! print(info["key"], info["opcode"], info["fields"])
//!
//! # Decode kernel from cubin
//! insns = cubit.decode_kernel("kernel.cubin", "my_kernel")
//! ```

#[cfg(feature = "python")]
use pyo3::prelude::*;

#[cfg(feature = "python")]
use pyo3::types::PyDict;

#[cfg(feature = "python")]
use std::collections::HashMap;

#[cfg(feature = "python")]
use std::path::{Path, PathBuf};

#[cfg(feature = "python")]
use std::sync::{Arc, LazyLock, RwLock};

/// Mutable table registry for the Python bindings.
///
/// M1/BARRACUDA (2026-08-20): historically the bindings loaded exactly one
/// table per process (CUBIT_TABLE env, default tables/sm120.json). BARRACUDA
/// needs native arch selection, so the active table (and its decode index)
/// are held behind a RwLock and can be switched with select_table().
/// Semantics of the legacy path are preserved for the first use.
#[cfg(feature = "python")]
struct TableState {
    /// Cache key of the active table (canonical spec/path), "" before first use.
    current: String,
    tables: HashMap<String, Arc<crate::table::IsaTable>>,
    indexes: HashMap<String, Arc<crate::decoder::DecodeIndex>>,
}

#[cfg(feature = "python")]
static TABLE_STATE: LazyLock<RwLock<TableState>> = LazyLock::new(|| {
    RwLock::new(TableState {
        current: String::new(),
        tables: HashMap::new(),
        indexes: HashMap::new(),
    })
});

/// Resolve a table spec ("sm120", "120a", "sm103a", or a JSON path) to
/// (cache-key, path). Returns Err with the attempted candidates.
#[cfg(feature = "python")]
fn resolve_table_spec(spec: &str) -> Result<(String, PathBuf), String> {
    let mut tried: Vec<String> = Vec::new();
    let p = Path::new(spec);
    if p.is_file() {
        let key = p
            .canonicalize()
            .ok()
            .and_then(|c| c.to_str().map(|s| s.to_string()))
            .unwrap_or_else(|| spec.to_string());
        return Ok((key, p.to_path_buf()));
    }
    // Arch-name forms: "sm120", "120", "sm120a", "120a" -> tables/sm120(a).json
    let mut names: Vec<String> = Vec::new();
    let bare = spec.trim_start_matches("sm");
    for n in [
        spec.to_string(),
        format!("sm{bare}"),
        format!("sm{bare}a"),
        bare.to_string(),
    ] {
        if !names.contains(&n) {
            names.push(n);
        }
    }
    for n in &names {
        for dir in ["tables", concat!(env!("CARGO_MANIFEST_DIR"), "/tables")] {
            let cand = PathBuf::from(dir).join(format!("{n}.json"));
            tried.push(cand.display().to_string());
            if cand.is_file() {
                return Ok((n.clone(), cand));
            }
        }
    }
    Err(format!(
        "unknown table spec '{spec}'; tried: {}",
        tried.join(", ")
    ))
}

/// Load (or fetch from cache) the table for `key_path` and make it active.
#[cfg(feature = "python")]
fn activate_table(key: &str, path: &Path) -> Result<Arc<crate::table::IsaTable>, String> {
    let mut st = TABLE_STATE
        .write()
        .map_err(|e| format!("table state lock: {e}"))?;
    if !st.tables.contains_key(key) {
        let t = crate::table::IsaTable::load(path)
            .map_err(|e| format!("load {}: {e}", path.display()))?;
        st.tables.insert(key.to_string(), Arc::new(t));
    }
    st.current = key.to_string();
    Ok(st.tables[&st.current].clone())
}

#[cfg(feature = "python")]
fn get_table() -> Arc<crate::table::IsaTable> {
    // Fast path: an active table is already selected.
    {
        if let Ok(st) = TABLE_STATE.read() {
            if let Some(t) = st.tables.get(&st.current) {
                return t.clone();
            }
        }
    }
    // Legacy first-use semantics: 1. CUBIT_TABLE env, 2. repo tables/sm120.json.
    if let Ok(p) = std::env::var("CUBIT_TABLE") {
        if let Ok((key, path)) = resolve_table_spec(&p) {
            if let Ok(t) = activate_table(&key, &path) {
                return t;
            }
        }
    }
    if let Ok((key, path)) = resolve_table_spec("sm120") {
        if let Ok(t) = activate_table(&key, &path) {
            return t;
        }
    }
    panic!(
        "Cannot find sm120.json. Set the CUBIT_TABLE env var, call cubit.select_table(), \
         or run from the repo root (tables/sm120.json)."
    );
}

#[cfg(feature = "python")]
fn get_index() -> Arc<crate::decoder::DecodeIndex> {
    {
        if let Ok(st) = TABLE_STATE.read() {
            if let Some(i) = st.indexes.get(&st.current) {
                return i.clone();
            }
        }
    }
    let table = get_table();
    let mut st = TABLE_STATE.write().expect("table state lock");
    let cur = st.current.clone();
    st.indexes
        .entry(cur)
        .or_insert_with(|| Arc::new(crate::decoder::DecodeIndex::build(&table)))
        .clone()
}

/// Encode a SASS instruction to a 128-bit code.
/// Returns (lo64, hi64) tuple.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (sass, addr=0))]
fn encode(sass: &str, addr: u32) -> PyResult<(u64, u64)> {
    let table = get_table();
    let insn = crate::parse_sass(sass, addr)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("parse error: {e}")))?;
    let code = crate::encoder::encode_instruction(&insn, &table)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("encode error: {e}")))?;
    let lo = (code & ((1u128 << 64) - 1)) as u64;
    let hi = (code >> 64) as u64;
    Ok((lo, hi))
}

/// Decode a 128-bit instruction code to a dict with key, opcode, mod_group, fields, scheduling.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (lo, hi, addr=0))]
fn decode<'py>(py: Python<'py>, lo: u64, hi: u64, addr: u32) -> PyResult<Bound<'py, PyDict>> {
    let code = ((hi as u128) << 64) | (lo as u128);
    let table = get_table();
    let index = get_index();
    let decoded = index.decode(code, addr, &table)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("decode error: {e}")))?;

    let dict = PyDict::new(py);
    dict.set_item("key", &decoded.key)?;
    dict.set_item("mod_group", &decoded.mod_group)?;
    dict.set_item("opcode", &decoded.opcode)?;
    dict.set_item("addr", addr)?;

    // Fields as list of dicts
    let fields: Vec<Bound<'py, PyDict>> = decoded.fields.iter().map(|f| {
        let fd = PyDict::new(py);
        fd.set_item("name", &f.name).unwrap();
        fd.set_item("shift", f.shift).unwrap();
        fd.set_item("bits", f.bits).unwrap();
        fd.set_item("value", f.value).unwrap();
        fd.set_item("token_idx", f.token_idx).unwrap();
        fd.set_item("extraction", &f.extraction).unwrap();
        fd
    }).collect();
    dict.set_item("fields", fields)?;

    // Scheduling
    let sched = PyDict::new(py);
    sched.set_item("stall", decoded.ctrl.stall)?;
    sched.set_item("yield_flag", decoded.ctrl.yield_flag)?;
    sched.set_item("write_bar", decoded.ctrl.write_bar)?;
    sched.set_item("read_bar", decoded.ctrl.read_bar)?;
    sched.set_item("wait_mask", decoded.ctrl.wait_mask)?;
    dict.set_item("scheduling", sched)?;

    Ok(dict)
}

/// Decode all instructions from a cubin file's kernel.
/// Returns list of decoded instruction dicts.
#[cfg(feature = "python")]
#[pyfunction]
fn decode_kernel<'py>(py: Python<'py>, cubin_path: &str, kernel_name: &str) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let table = get_table();
    let index = get_index();
    let cubin = crate::elf::CubinFile::load(std::path::Path::new(cubin_path))
        .map_err(|e| pyo3::exceptions::PyIOError::new_err(format!("load error: {e}")))?;

    // Find the kernel's text section
    let sec_idx = cubin.text_sections.iter()
        .position(|(name, _, _)| name.contains(kernel_name))
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err(
            format!("kernel '{}' not found. Available: {:?}", kernel_name,
                cubin.text_sections.iter().map(|(n, _, _)| n).collect::<Vec<_>>())))?;

    let (_, sec_offset, sec_size) = &cubin.text_sections[sec_idx];
    let sec_offset = *sec_offset as usize;
    let sec_size = *sec_size as usize;
    let data = &cubin.bytes[sec_offset..sec_offset + sec_size];

    let mut results = Vec::new();
    let mut offset = 0u32;
    while (offset as usize) + 16 <= data.len() {
        let lo = u64::from_le_bytes(data[offset as usize..offset as usize + 8].try_into().unwrap());
        let hi = u64::from_le_bytes(data[offset as usize + 8..offset as usize + 16].try_into().unwrap());
        let code = ((hi as u128) << 64) | (lo as u128);

        match index.decode(code, offset, &table) {
            Ok(decoded) => {
                let dict = PyDict::new(py);
                dict.set_item("addr", offset)?;
                dict.set_item("key", &decoded.key)?;
                dict.set_item("mod_group", &decoded.mod_group)?;
                dict.set_item("opcode", &decoded.opcode)?;

                let fields: Vec<Bound<'py, PyDict>> = decoded.fields.iter().map(|f| {
                    let fd = PyDict::new(py);
                    fd.set_item("name", &f.name).unwrap();
                    fd.set_item("shift", f.shift).unwrap();
                    fd.set_item("bits", f.bits).unwrap();
                    fd.set_item("value", f.value).unwrap();
                    fd
                }).collect();
                dict.set_item("fields", fields)?;

                let sched = PyDict::new(py);
                sched.set_item("stall", decoded.ctrl.stall)?;
                sched.set_item("yield_flag", decoded.ctrl.yield_flag)?;
                sched.set_item("wait_mask", decoded.ctrl.wait_mask)?;
                dict.set_item("scheduling", sched)?;

                results.push(dict);
            }
            Err(_) => {
                let dict = PyDict::new(py);
                dict.set_item("addr", offset)?;
                dict.set_item("key", "UNKNOWN")?;
                dict.set_item("raw_lo", lo)?;
                dict.set_item("raw_hi", hi)?;
                results.push(dict);
            }
        }
        offset += 16;
    }
    Ok(results)
}

/// Get table info.
#[cfg(feature = "python")]
#[pyfunction]
fn table_info() -> PyResult<(usize, usize)> {
    let table = get_table();
    Ok((table.num_keys(), table.num_groups()))
}

/// Convert a 128-bit instruction code to SASS assembly text.
/// Returns a string like "IADD3 R5, PT, PT, R9, R4, R5" that can be
/// fed back to encode() for a lossless round-trip.
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (lo, hi, addr=0))]
fn to_sass(lo: u64, hi: u64, addr: u32) -> PyResult<String> {
    let table = get_table();
    let index = get_index();
    let code = (lo as u128) | ((hi as u128) << 64);
    let inst = index.decode(code, addr, &table)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(
            format!("decode error: {e}")))?;
    Ok(crate::printer::to_sass(&inst))
}

/// Assemble multiple SASS instructions with label resolution.
/// Returns `(bytes, count)` where bytes is a Python bytes object.
/// Instructions can be separated by `;` or newlines.
/// Labels are supported: `label:` on its own line/token.
///
/// Example:
///   lo_bytes, count = cubit.asm("BRA end; NOP; end: EXIT", addr=0)
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (code, addr=0))]
fn asm(py: Python<'_>, code: &str, addr: u32) -> PyResult<PyObject> {
    let table = get_table();
    let (bytes, count) = crate::assemble(code, addr, &table)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(
            format!("assembly error: {e}")))?;
    let py_bytes = pyo3::types::PyBytes::new_bound(py, &bytes);
    Ok((py_bytes, count).into_py(py))
}

/// Select the active ISA table by arch name ("sm120", "sm103a", ...) or an
/// explicit JSON file path. All subsequent encode/decode/asm calls (and their
/// decode index) use this table. Returns `(num_keys, num_groups)`.
///
/// M1/BARRACUDA: native arch selection (previously only CUBIT_TABLE env at
/// first use). Affects the whole process; see cubit.current_table().
#[cfg(feature = "python")]
#[pyfunction]
fn select_table(spec: &str) -> PyResult<(usize, usize)> {
    let (key, path) = resolve_table_spec(spec)
        .map_err(pyo3::exceptions::PyValueError::new_err)?;
    let table = activate_table(&key, &path)
        .map_err(pyo3::exceptions::PyIOError::new_err)?;
    Ok((table.num_keys(), table.num_groups()))
}

/// Identifier (arch name or path) of the currently active ISA table.
#[cfg(feature = "python")]
#[pyfunction]
fn current_table() -> String {
    if let Ok(st) = TABLE_STATE.read() {
        if !st.current.is_empty() {
            return st.current.clone();
        }
    }
    // Materialize the legacy default so callers get a truthful answer.
    let _ = get_table();
    TABLE_STATE.read().unwrap().current.clone()
}

/// Predicate liveness over a whole .sass source (M2/BARRACUDA).
///
/// Returns one dict per kernel:
///   { "name": str, "n": int, "unknown_ops": [str],
///     "ins": [ { "addr", "op", "raw", "defs", "uses", "udefs", "uuses",
///                "live_in", "live_out", "ulive_in", "known" } ] }
/// Predicate sets are register numbers (0..6); PT/UPT never appear.
/// `mode`: "strict" (documented superset semantics, tracks UP domain too)
/// or "compat" (bit-parity with the s6 reference predcheck.py, P only).
/// Parsing is strict: any unparseable instruction line is a hard error
/// (fail-closed; index space provably matches the source).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (text, mode="strict"))]
fn pred_liveness<'py>(
    py: Python<'py>,
    text: &str,
    mode: &str,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let m = match mode {
        "strict" => crate::pred_liveness::XferMode::Strict,
        "compat" => crate::pred_liveness::XferMode::Compat,
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown mode '{other}'; expected 'strict' or 'compat'"
            )))
        }
    };
    let kernels = crate::pred_liveness::liveness_file(text, m)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("liveness error: {e}")))?;
    let mut out = Vec::new();
    for k in kernels {
        let kd = PyDict::new(py);
        kd.set_item("name", &k.name)?;
        kd.set_item("n", k.ins.len())?;
        kd.set_item("unknown_ops", k.unknown_ops.clone())?;
        let mut rows = Vec::with_capacity(k.ins.len());
        for r in &k.ins {
            let d = PyDict::new(py);
            d.set_item("addr", r.addr)?;
            d.set_item("op", &r.opcode_full)?;
            d.set_item("raw", &r.raw_text)?;
            d.set_item("defs", r.defs.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("uses", r.uses.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("udefs", r.udefs.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("uuses", r.uuses.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("live_in", r.live_in.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("live_out", r.live_out.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("ulive_in", r.ulive_in.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("known", r.known)?;
            rows.push(d);
        }
        kd.set_item("ins", rows)?;
        out.push(kd);
    }
    Ok(out)
}

/// Register liveness over a whole .sass source (M3/BARRACUDA, RA substrate).
///
/// Same row shape as pred_liveness plus CFG successors. Sets:
///   defs/uses = R domain (0..254), udefs/uuses = UR domain (0..63),
///   live_in/live_out = R, ulive_in = UR, succ = CFG successor indexes.
/// Operand roles are corpus-grounded family rules (see reg_liveness.rs);
/// unknown register-carrying families are fail-closed (known=false,
/// kernel["unknown_ops"]).
#[cfg(feature = "python")]
#[pyfunction]
fn reg_liveness<'py>(py: Python<'py>, text: &str) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let kernels = crate::reg_liveness::liveness_file(text)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("reg liveness error: {e}")))?;
    let mut out = Vec::new();
    for k in kernels {
        let kd = PyDict::new(py);
        kd.set_item("name", &k.name)?;
        kd.set_item("n", k.ins.len())?;
        kd.set_item("unknown_ops", k.unknown_ops.clone())?;
        let mut rows = Vec::with_capacity(k.ins.len());
        for r in &k.ins {
            let d = PyDict::new(py);
            d.set_item("addr", r.addr)?;
            d.set_item("op", &r.opcode_full)?;
            d.set_item("raw", &r.raw_text)?;
            d.set_item("succ", r.succ.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("defs", r.rdefs.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("uses", r.ruses.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("udefs", r.udefs.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("uuses", r.uuses.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("live_in", r.rlive_in.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("live_out", r.rlive_out.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("ulive_in", r.ulive_in.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
            d.set_item("known", r.known)?;
            rows.push(d);
        }
        kd.set_item("ins", rows)?;
        out.push(kd);
    }
    Ok(out)
}

/// Register-allocation pass over a whole .sass source (M4/BARRACUDA).
///
/// Modes: "identity" (M4.1), "pin" (M4.2, requires plan JSON).
/// Returns one dict per kernel:
///   name, n, r_used, ur_used, r_max, ur_max, changed, unknown_ops.
/// Raises ValueError on strict-parse failure, unknown role families,
/// plan gaps, pin-contract violations, or a nonzero change count in
/// identity mode (all fail-closed -- see ra.rs).
#[cfg(feature = "python")]
fn ra_reports<'py>(
    py: Python<'py>,
    rep: &crate::ra::RaRunReport,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let mut out = Vec::new();
    for k in &rep.kernels {
        let kd = PyDict::new(py);
        kd.set_item("name", &k.name)?;
        kd.set_item("n", k.n_ins)?;
        kd.set_item("r_used", k.r_used.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
        kd.set_item("ur_used", k.ur_used.iter().map(|v| *v as u32).collect::<Vec<u32>>())?;
        kd.set_item("r_max", k.r_max.map(|v| v as u32))?;
        kd.set_item("ur_max", k.ur_max.map(|v| v as u32))?;
        kd.set_item("changed", k.changed)?;
        kd.set_item("unknown_ops", k.unknown_ops.clone())?;
        kd.set_item("span_notes", k.span_notes.clone())?;
        kd.set_item("span_notes_total", k.span_notes_total)?;
        out.push(kd);
    }
    Ok(out)
}

#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (text, mode="identity", plan=None))]
fn ra_plan<'py>(
    py: Python<'py>,
    text: &str,
    mode: &str,
    plan: Option<&str>,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let parsed = build_ra_mode(mode, plan)?;
    let run = crate::ra::run_file(text, parsed)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("ra error: {e:#}")))?;
    ra_reports(py, &run.report)
}

/// Build an RaMode from the (mode, plan-json) pair, fail-closed.
#[cfg(feature = "python")]
fn build_ra_mode(mode: &str, plan: Option<&str>) -> PyResult<crate::ra::RaMode> {
    let kind = crate::ra::parse_mode_kind(mode)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{e:#}")))?;
    match (kind, plan) {
        ("identity", None) => Ok(crate::ra::RaMode::Identity),
        ("identity", Some(_)) => Err(pyo3::exceptions::PyValueError::new_err(
            "ra: plan is only valid with mode='pin'",
        )),
        ("pin", Some(pj)) => {
            let plan: crate::ra::PinPlan = serde_json::from_str(pj).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("ra: bad plan JSON: {e}"))
            })?;
            Ok(crate::ra::RaMode::Pin(plan))
        }
        ("pin", None) => Err(pyo3::exceptions::PyValueError::new_err(
            "ra: mode='pin' requires a plan JSON",
        )),
        (other, _) => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "ra: mode {other:?} not handled"
        ))),
    }
}

/// M4.2: apply a pin-override plan and return (spliced_text, reports).
/// Fail-closed: validate_pin contract + splice re-parse proof inside
/// ra::run_file; any violation raises ValueError and NO text is produced.
/// M4.5: reordering-scheduler pass (identity mode). Returns
/// (output_text, per-kernel reports). Identity emits the input
/// byte-verbatim; the value is the dependency-graph census the M4.6 list
/// scheduler will consume. Fail-closed doctrine identical to the RA pass
/// (unknown operand roles / ctrl classes stop the run).
#[cfg(feature = "python")]
#[pyfunction]
#[pyo3(signature = (text, mode="identity"))]
fn sched_run<'py>(
    py: Python<'py>,
    text: &str,
    mode: &str,
) -> PyResult<(String, Vec<Bound<'py, PyDict>>)> {
    match crate::sched::parse_mode_kind(mode)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("{e:#}")))?
    {
        "identity" => {}
        "list" => {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "sched: mode 'list' carries plan+cost -- use sched_apply (M4.6)",
            ))
        }
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "sched: mode {other:?} not handled"
            )))
        }
    }
    let table = get_table();
    let run = crate::sched::run_file(text, crate::sched::SchedMode::Identity, &table)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("sched error: {e:#}")))?;
    let mut out = Vec::new();
    for k in &run.report.kernels {
        let kd = PyDict::new(py);
        kd.set_item("name", &k.name)?;
        kd.set_item("n", k.n_ins)?;
        kd.set_item("anchors", k.anchors)?;
        kd.set_item("hand_sched", k.hand_sched)?;
        kd.set_item("scoreboard_bound", k.scoreboard_bound)?;
        kd.set_item("edges_total", k.edges_total)?;
        let bc = PyDict::new(py);
        for (cls, cnt) in &k.edges_by_class {
            bc.set_item(cls, cnt)?;
        }
        kd.set_item("edges_by_class", bc)?;
        kd.set_item("live_peak_r", k.live_peak_r)?;
        kd.set_item("live_peak_ur", k.live_peak_ur)?;
        kd.set_item("moved", k.moved)?;
        kd.set_item("class_fallback", k.class_fallback)?;
        out.push(kd);
    }
    Ok((run.out_text, out))
}

#[cfg(feature = "python")]
#[pyfunction]
fn ra_apply<'py>(
    py: Python<'py>,
    text: &str,
    plan: &str,
) -> PyResult<(String, Vec<Bound<'py, PyDict>>)> {
    let parsed = build_ra_mode("pin", Some(plan))?;
    let run = crate::ra::run_file(text, parsed)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("ra error: {e:#}")))?;
    let reports = ra_reports(py, &run.report)?;
    Ok((run.out_text, reports))
}

/// M4.3a: standalone IR -> text renderer (pyo3 entry). Strict parse of
/// `text`, render from structured IR, structural self-check ALWAYS on (the
/// python caller never sees unproven text). Returns the rendered text.
#[cfg(feature = "python")]
#[pyfunction]
fn render(text: &str) -> PyResult<String> {
    crate::render::run_file(text, true)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("render error: {e:#}")))
}

/// M4.3b: full allocation FROM ZERO (pyo3 entry). Strict parse -> liveness
/// span-group linear scan -> whole-kernel apply -> M4.3a render + render
/// proof. Returns (output_text, per-kernel reports incl. full stats and the
/// renaming plan maps). Fail-closed like the CLI.
#[cfg(feature = "python")]
#[pyfunction]
fn ra_full<'py>(py: Python<'py>, text: &str) -> PyResult<(String, Vec<Bound<'py, PyDict>>)> {
    let run = crate::ra::run_file(text, crate::ra::RaMode::Full)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("ra full: {e:#}")))?;
    let mut out = Vec::new();
    for k in &run.report.kernels {
        let kd = PyDict::new(py);
        kd.set_item("name", &k.name)?;
        kd.set_item("n", k.n_ins)?;
        kd.set_item("changed", k.changed)?;
        if let Some(f) = &k.full {
            let fd = PyDict::new(py);
            fd.set_item("r_watermark", f.r.watermark)?;
            fd.set_item("r_old_max", f.r.old_max)?;
            fd.set_item("r_groups", f.r.groups)?;
            fd.set_item("ur_watermark", f.ur.watermark)?;
            fd.set_item("ur_old_max", f.ur.old_max)?;
            fd.set_item("ur_groups", f.ur.groups)?;
            fd.set_item("entry_pins", &f.entry_pins)?;
            fd.set_item("renamed", f.renamed)?;
            kd.set_item("full", fd)?;
        }
        if let Some(p) = &k.plan {
            let pd = PyDict::new(py);
            let rd = PyDict::new(py);
            for (a, b) in &p.r {
                rd.set_item(a, b)?;
            }
            let ud = PyDict::new(py);
            for (a, b) in &p.ur {
                ud.set_item(a, b)?;
            }
            pd.set_item("r", rd)?;
            pd.set_item("ur", ud)?;
            kd.set_item("plan", pd)?;
        }
        out.push(kd);
    }
    Ok((run.out_text, out))
}

/// M4.6: windowed list scheduling (pyo3 entry). `plan` /
/// `cost` are INLINE JSON strings (same schema as the CLI --plan/--cost
/// files: {"kernels":{"<name>":{"windows":[[s,e),...]}}} and the m9 cost
/// model of tables/cost_sm103a.json). Returns (output_text, per-kernel
/// reports with per-window blocks). Fail-closed like the CLI.
#[cfg(feature = "python")]
#[pyfunction]
fn sched_apply<'py>(
    py: Python<'py>,
    text: &str,
    plan: &str,
    cost: &str,
) -> PyResult<(String, Vec<Bound<'py, PyDict>>)> {
    let plan: crate::sched::SchedPlan = serde_json::from_str(plan)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("sched plan JSON: {e:#}")))?;
    let cm = crate::sched::CostModel::from_str_json(cost)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("sched cost JSON: {e:#}")))?;
    let table = get_table();
    let run = crate::sched::run_file_cost(
        text,
        crate::sched::SchedMode::List(plan),
        &table,
        Some(&cm),
    )
    .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("sched error: {e:#}")))?;
    let mut out = Vec::new();
    for k in &run.report.kernels {
        let kd = PyDict::new(py);
        kd.set_item("name", &k.name)?;
        kd.set_item("n", k.n_ins)?;
        kd.set_item("anchors", k.anchors)?;
        kd.set_item("hand_sched", k.hand_sched)?;
        kd.set_item("scoreboard_bound", k.scoreboard_bound)?;
        kd.set_item("edges_total", k.edges_total)?;
        kd.set_item("live_peak_r", k.live_peak_r)?;
        kd.set_item("live_peak_ur", k.live_peak_ur)?;
        kd.set_item("moved", k.moved)?;
        kd.set_item("class_fallback", k.class_fallback)?;
        kd.set_item("credits_defaulted", k.credits_defaulted)?;
        let wl = pyo3::types::PyList::empty(py);
        for w in &k.windows {
            let wd = PyDict::new(py);
            wd.set_item("start", w.start)?;
            wd.set_item("end", w.end)?;
            wd.set_item("movers", w.movers)?;
            wd.set_item("pinned", w.pinned)?;
            let pr = PyDict::new(py);
            for (reason, cnt) in &w.pin_reasons {
                pr.set_item(reason, cnt)?;
            }
            wd.set_item("pin_reasons", pr)?;
            wd.set_item("segments", w.segments)?;
            wd.set_item("cost_before", w.cost_before)?;
            wd.set_item("cost_after", w.cost_after)?;
            wd.set_item("moved", w.moved)?;
            wd.set_item("replay", w.replay)?;
            wl.append(wd)?;
        }
        kd.set_item("windows", wl)?;
        out.push(kd);
    }
    Ok((run.out_text, out))
}

/// M5 (BARRACUDA author surface): pin/mover introspection for a scheduling
/// plan. JSON contract identical to sched_apply's plan ({"kernels": {name:
/// {"windows": [[s, e), ...]}}}); per window returns kernel/start/end,
/// movable indices, pins {idx: reason} and segments (maximal mover runs).
#[cfg(feature = "python")]
#[pyfunction]
fn sched_pins<'py>(
    py: Python<'py>,
    text: &str,
    plan: &str,
) -> PyResult<Vec<Bound<'py, PyDict>>> {
    let plan: crate::sched::SchedPlan = serde_json::from_str(plan)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("sched plan JSON: {e:#}")))?;
    let table = get_table();
    let reps = crate::sched::window_pins(text, &plan, &table)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("sched error: {e:#}")))?;
    let mut out = Vec::new();
    for w in reps {
        let wd = PyDict::new(py);
        wd.set_item("kernel", &w.kernel)?;
        wd.set_item("start", w.start)?;
        wd.set_item("end", w.end)?;
        wd.set_item("movable", w.movable)?;
        let pd = PyDict::new(py);
        for (i, r) in &w.pins {
            pd.set_item(i, r)?;
        }
        wd.set_item("pins", pd)?;
        let sl = pyo3::types::PyList::empty(py);
        for run in &w.segments {
            sl.append(run)?;
        }
        wd.set_item("segments", sl)?;
        out.push(wd);
    }
    Ok(out)
}

/// Python module definition.
#[cfg(feature = "python")]
#[pymodule]
fn cubit(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encode, m)?)?;
    m.add_function(wrap_pyfunction!(decode, m)?)?;
    m.add_function(wrap_pyfunction!(decode_kernel, m)?)?;
    m.add_function(wrap_pyfunction!(table_info, m)?)?;
    m.add_function(wrap_pyfunction!(select_table, m)?)?;
    m.add_function(wrap_pyfunction!(current_table, m)?)?;
    m.add_function(wrap_pyfunction!(to_sass, m)?)?;
    m.add_function(wrap_pyfunction!(asm, m)?)?;
    m.add_function(wrap_pyfunction!(pred_liveness, m)?)?;
    m.add_function(wrap_pyfunction!(reg_liveness, m)?)?;
    m.add_function(wrap_pyfunction!(ra_plan, m)?)?;
    m.add_function(wrap_pyfunction!(ra_apply, m)?)?;
    m.add_function(wrap_pyfunction!(sched_run, m)?)?;
    m.add_function(wrap_pyfunction!(sched_apply, m)?)?;
    m.add_function(wrap_pyfunction!(sched_pins, m)?)?;
    m.add_function(wrap_pyfunction!(render, m)?)?;
    m.add_function(wrap_pyfunction!(ra_full, m)?)?;
    Ok(())
}

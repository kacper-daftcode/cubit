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
    Ok(())
}

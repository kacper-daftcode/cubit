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
use std::sync::OnceLock;

#[cfg(feature = "python")]
static TABLE: OnceLock<crate::table::IsaTable> = OnceLock::new();

#[cfg(feature = "python")]
static DECODE_INDEX: OnceLock<crate::decoder::DecodeIndex> = OnceLock::new();

#[cfg(feature = "python")]
fn get_table() -> &'static crate::table::IsaTable {
    TABLE.get_or_init(|| {
        // 1. Env var takes priority
        if let Ok(p) = std::env::var("CUBIT_TABLE") {
            if let Ok(t) = crate::table::IsaTable::load(std::path::Path::new(&p)) {
                return t;
            }
        }
        // 2. Try common locations relative to the working directory
        let paths = ["tables/sm120.json", "sm120.json"];
        for p in &paths {
            if let Ok(t) = crate::table::IsaTable::load(std::path::Path::new(p)) {
                return t;
            }
        }
        panic!("Cannot find sm120.json. Set the CUBIT_TABLE env var or run from the repo root (tables/sm120.json).");
    })
}

#[cfg(feature = "python")]
fn get_index() -> &'static crate::decoder::DecodeIndex {
    DECODE_INDEX.get_or_init(|| crate::decoder::DecodeIndex::build(get_table()))
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
    let code = crate::encoder::encode_instruction(&insn, table)
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
    let decoded = index.decode(code, addr, table)
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

        match index.decode(code, offset, table) {
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
    let inst = index.decode(code, addr, table)
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
    let (bytes, count) = crate::assemble(code, addr, table)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(
            format!("assembly error: {e}")))?;
    let py_bytes = pyo3::types::PyBytes::new_bound(py, &bytes);
    Ok((py_bytes, count).into_py(py))
}

/// Python module definition.
#[cfg(feature = "python")]
#[pymodule]
fn cubit(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encode, m)?)?;
    m.add_function(wrap_pyfunction!(decode, m)?)?;
    m.add_function(wrap_pyfunction!(decode_kernel, m)?)?;
    m.add_function(wrap_pyfunction!(table_info, m)?)?;
    m.add_function(wrap_pyfunction!(to_sass, m)?)?;
    m.add_function(wrap_pyfunction!(asm, m)?)?;
    Ok(())
}

//! Control code (scheduling) parsing and encoding.
//!
//! String format: `B------:R-:W-:-:S01`
//!
//! SM120 scheduling: 17-bit word packed into upper32[25:9] of the 128-bit
//! instruction (i.e. `packed << 9`).  Layout of the 17-bit packed word:
//!   wait_mask[16:11] | read_bar[10:8] | write_bar[7:5] | yield[4] | stall[3:0]
//!
//! Derived from tungsten LLVM backend `buildSchedUpper32`.

use crate::ir::ControlCode;
use anyhow::{bail, Result};
use regex::Regex;
use std::sync::LazyLock;

static CC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^B(0|-)(1|-)(2|-)(3|-)(4|-)(5|-):R[0-5\-]:W[0-5\-]:(Y|-):S\d{2}$").unwrap()
});

/// Scheduling field sits at upper32[25:9] — i.e. the 17-bit packed word
/// is shifted left by 9 within the upper32.
pub const SCHED_SHIFT: u32 = 9;
/// Mask covering the scheduling field within upper32.
pub const SCHED_UPPER32_MASK: u32 = 0x03FF_FE00; // bits [25:9]

// Legacy CC_POS kept for inject/extract on full hi64 (scheduling_pass uses these).
pub const CC_POS: u32 = 41;
pub const CC_MASK_UNSHIFTED: u64 = 0x1ffff;
pub const CC_MASK: u64 = CC_MASK_UNSHIFTED << CC_POS;

pub fn parse_control_code(s: &str) -> Result<ControlCode> {
    if !CC_RE.is_match(s) {
        bail!("invalid control code string: {s:?}");
    }
    let parts: Vec<&str> = s.split(':').collect();
    let wait_str = &parts[0][1..];
    let mut wait_mask: u8 = 0;
    for (i, ch) in wait_str.chars().enumerate() {
        if ch != '-' {
            wait_mask |= 1 << i;
        }
    }
    let read_ch = parts[1].as_bytes()[1];
    let read_bar = if read_ch == b'-' { 7 } else { read_ch - b'0' };
    let write_ch = parts[2].as_bytes()[1];
    let write_bar = if write_ch == b'-' { 7 } else { write_ch - b'0' };
    let yield_flag = parts[3] == "Y";
    let stall: u8 = parts[4][1..].parse()?;

    Ok(ControlCode { stall, yield_flag, write_bar, read_bar, wait_mask })
}

/// Encode a ControlCode into a 17-bit packed word (NOT shifted).
pub fn encode_control_code(cc: &ControlCode) -> u32 {
    let c_yield: u32 = if cc.yield_flag { 1 } else { 0 };
    ((cc.wait_mask as u32) << 11)
        | ((cc.read_bar as u32) << 8)
        | ((cc.write_bar as u32) << 5)
        | (c_yield << 4)
        | (cc.stall as u32)
}

/// Encode a ControlCode into upper32 format: packed << 9 (bits [25:9]).
/// This matches tungsten's `buildSchedUpper32`.
pub fn encode_sched_upper32(cc: &ControlCode) -> u32 {
    encode_control_code(cc) << SCHED_SHIFT
}

pub fn decode_control_code(code: u32) -> ControlCode {
    ControlCode {
        stall: (code & 0xf) as u8,
        yield_flag: ((code >> 4) & 1) == 1,
        write_bar: ((code >> 5) & 7) as u8,
        read_bar: ((code >> 8) & 7) as u8,
        wait_mask: ((code >> 11) & 0x3f) as u8,
    }
}

/// Decode scheduling from an upper32 value (extract bits [25:9], unshift).
pub fn decode_sched_upper32(upper32: u32) -> ControlCode {
    decode_control_code((upper32 >> SCHED_SHIFT) & 0x1FFFF)
}

pub fn format_control_code(cc: &ControlCode) -> String {
    let mut wait_chars = ['-'; 6];
    for i in 0..6u8 {
        if (cc.wait_mask & (1 << i)) != 0 {
            wait_chars[i as usize] = char::from(b'0' + i);
        }
    }
    let s_wait: String = wait_chars.iter().collect();
    let s_read = if cc.read_bar == 7 { "-".into() } else { cc.read_bar.to_string() };
    let s_write = if cc.write_bar == 7 { "-".into() } else { cc.write_bar.to_string() };
    let s_yield = if cc.yield_flag { "Y" } else { "-" };
    format!("B{s_wait}:R{s_read}:W{s_write}:{s_yield}:S{:02}", cc.stall)
}

pub fn extract_sched_from_ctrl(ctrl: u64) -> u32 {
    ((ctrl >> CC_POS) & CC_MASK_UNSHIFTED) as u32
}

pub fn inject_sched_into_ctrl(ctrl: u64, sched: u32) -> u64 {
    (ctrl & !CC_MASK) | (((sched as u64) & CC_MASK_UNSHIFTED) << CC_POS)
}

/// Inject scheduling into a 128-bit code (ctrl is upper 64 bits).
pub fn inject_sched_into_code128(code: u128, sched: u32) -> u128 {
    let insn_lo = code as u64;
    let ctrl_hi = (code >> 64) as u64;
    let new_ctrl = inject_sched_into_ctrl(ctrl_hi, sched);
    ((new_ctrl as u128) << 64) | (insn_lo as u128)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let cases = [
            "B--2---:R0:W1:-:S07",
            "B01--4-:R-:W-:-:S05",
            "B------:R-:W-:-:S01",
            "B0----5:R0:W5:Y:S05",
        ];
        for s in cases {
            let cc = parse_control_code(s).unwrap();
            let code = encode_control_code(&cc);
            let cc2 = decode_control_code(code);
            let s2 = format_control_code(&cc2);
            assert_eq!(s, s2, "round-trip failed for {s}");
        }
    }
}

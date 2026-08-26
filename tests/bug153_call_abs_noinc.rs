//! BUG-153 (iter72, follow-up of the parked LOW item "addr-mode
//! @sched-gluing" (141/iter65, F2-Q)): honest re-measure found the iter65
//! "mass asm rc=1 on corpus dumps" claim was measured on 0-byte dump inputs
//! (work/bug141/disasmAB all empty) => artifact. The real per-instruction
//! encode census on fresh dumps (work/i72/census153.json, 32.2M instr,
//! 54,901 fails, 26 classes) is dominated by deliberate fail-closed policy
//! (BUG-088 align 45,412; BUG-080 guarded-ATOM 3,065) and carries exactly
//! ONE previously-unowned semantic class: the printer rendered the
//! register-indirect CALL.ABS form as a fabricated branch address
//! (decode_branch_target(raw) = addr+0x10 under this row's rel==0), a text
//! no table row can re-encode (2,884 corpus lines, cutlass
//! 77_blackwell_fmha_fp8.1 carries 2,882 of them).
//!
//! Vendor census (work/bug142/hexdb/all.tsv, F2-iter67 build):
//!   CALL.ABS.NOINC anchors = 2,158 lines, uniq texts = 7, ALL register
//!   form ("CALL.ABS.NOINC R2|R8|R10|R12|R16|R18|R22"); ZERO immediate-ABS
//!   and ZERO guard-predicated ABS witnesses anywhere in 32.2M lines.
//!   Word shape: lo = 0x????007343 with the register numeral at bits
//!   [24:32); hi32 = 0x03c00000 constant; hi64 high halfword = sched ctl.
//!
//! Fix: printer arm for opcode CALL with mod_group containing "ABS" prints
//! the register operand from bits[31:24] (RZ for the 255 sentinel),
//! mirroring the RET/BRX raw-field arms. Table untouched; encode was
//! already correct (`CALL.ABS.NOINC R2` encoded to the exact vendor lo
//! word pre-fix -- the class was unreachable only because decode printed
//! the fabricated address form).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

const SCHED: u128 = 0xFFFF_FFFFu128 << 96;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(text, 0).expect("parse");
    encode_instruction(&insn, t).expect("encode") & !SCHED
}

fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> String {
    idx.decode(w, 0, t).map(|d| cubit::printer::to_sass(&d)).expect("decode")
}

fn parts(lo: u64, hi32: u32) -> u128 { (lo as u128) | ((hi32 as u128) << 64) }

// Live vendor witnesses: (lo, hi32, register text). All seven uniq
// register numerals observed in the hexdb corpus.
const WITNESS_ABS: &[(u64, u32, &str)] = &[
    (0x0000000002007343, 0x03c00000, "CALL.ABS.NOINC R2"),
    (0x0000000008007343, 0x03c00000, "CALL.ABS.NOINC R8"),
    (0x000000000a007343, 0x03c00000, "CALL.ABS.NOINC R10"),
    (0x000000000c007343, 0x03c00000, "CALL.ABS.NOINC R12"),
    (0x0000000010007343, 0x03c00000, "CALL.ABS.NOINC R16"),
    (0x0000000012007343, 0x03c00000, "CALL.ABS.NOINC R18"),
    (0x0000000016007343, 0x03c00000, "CALL.ABS.NOINC R22"),
];

// Observed sched-control variants of the top halfword for the R2 anchor
// (hexdb hi64 column, high 32 bits of the 128-bit word). Decode must be
// sched-invariant for the class.
const SCHED_HI_VARIANTS: &[u32] = &[
    0x006fea00, 0x00afea00, 0x00cfea00, 0x00efea00, 0x014fea00, 0x018fea00,
    0x01efea00,
];

#[test]
fn t153_1_witness_decode_vendor_exact() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (lo, hi32, want) in WITNESS_ABS {
        // payload form
        assert_eq!(&dec(&t, &idx, parts(*lo, *hi32)), want,
                   "ABS decode must print the register form (vendor)");
        // sched-control variants (payload bytes identical)
        assert_eq!(&dec(&t, &idx, parts(*lo, *hi32)), want);
    }
    for hi in SCHED_HI_VARIANTS {
        let w = parts(0x0000000002007343, 0x03c00000) | ((*hi as u128) << 96);
        assert_eq!(&dec(&t, &idx, w), "CALL.ABS.NOINC R2",
                   "sched variant {hi:#x} must not change render");
    }
}

#[test]
fn t153_2_witness_encode_byte_exact_and_fixed_point() {
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (lo, hi32, text) in WITNESS_ABS {
        assert_eq!(enc(&t, text), parts(*lo, *hi32), "encode parity: {text}");
        assert_eq!(&dec(&t, &idx, enc(&t, text)), text, "text fixed point");
    }
}

#[test]
fn t153_3_rz_sentinel_form_roundtrip() {
    // Defensive: the 255 register numeral prints RZ (no vendor witness;
    // synthetic word derived from the R2 anchor by patching bits[24:32)).
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let w = parts(0x00000000ff007343, 0x03c00000);
    let got = dec(&t, &idx, w);
    assert_eq!(got, "CALL.ABS.NOINC RZ", "255 sentinel must print RZ");
    assert_eq!(enc(&t, &got), w, "RZ roundtrip must be byte-exact");
}

#[test]
fn t153_4_rel_arm_untouched() {
    // Control: the REL path (the only other NOINC group) is unchanged --
    // encode of the hex-target form round-trips and its render keeps the
    // computed address shape ("0x.."), not a register.
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    let w = enc(&t, "CALL.REL.NOINC 0x100");
    let s = dec(&t, &idx, w);
    assert_eq!(s, "CALL.REL.NOINC 0x100", "REL fixed point at addr 0");
    assert!(s.contains("0x"), "REL still prints an address form");
}

#[test]
fn t153_5_abs_render_never_fabricates_address() {
    // Regression lock against the pre-fix defect: ABS renders must never
    // contain a hex-address pseudotarget.
    let t = t103a();
    let idx = DecodeIndex::build(&t);
    for (lo, hi32, text) in WITNESS_ABS {
        let got = dec(&t, &idx, parts(*lo, *hi32));
        assert!(!got.contains("0x"), "ABS render must not fabricate an address: {got}");
        assert_eq!(&got, text);
    }
}

#[test]
fn t153_6_fix_is_printer_only() {
    // Scope lock: the sm103a table row used by the class is unchanged --
    // CALL_R carries the "ABS,NOINC" group with exactly the 8-bit register
    // field at bits[24:32), and CALL_II still carries only "NOINC,REL".
    let t = t103a();
    let g = &t.entries["CALL_R"].mod_groups["ABS,NOINC"];
    assert_eq!(g.fields.len(), 1, "CALL_R[ABS,NOINC] must have the single Ra field");
    let f = &g.fields[0];
    assert_eq!((f.shift, f.bits), (24, 8), "Ra window");
    assert!(t.entries["CALL_II"].mod_groups.get("ABS,NOINC").is_none()
            && t.entries["CALL_II"].mod_groups.get("ABS").is_none(),
            "no immediate-ABS row may appear silently (zero vendor witnesses)");
}

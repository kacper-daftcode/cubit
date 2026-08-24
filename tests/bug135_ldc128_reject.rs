//! BUG-135 (F2-iter62, 2026-08-24; follow-up of BUG-132 t132_6 idiom audit):
//! `LDC.128` with an R-domain destination has NO silicon encoding on
//! Blackwell. Evidence (all work/f2-135/, report results/cubitfix/135.md):
//!   * nvdisasm 13.3 renders the R-domain width enum [74:73] codes 2/3 as
//!     `LDC.INVALID6`/`LDC.INVALID7` (graft probes ldc_graft.cubin, identical
//!     verdict on sm_103a and sm_120a cubins); codes 0=32-bit, 1=.64.
//!   * nvdisasm renders the era byte-pin W_LDC128_R53 (bug088 t5) as PLAIN
//!     32-bit `LDC R53, c[0x0][0x380]` — the pre-132 encoder had silently
//!     dropped the `.128` mod; the 088 silicon campaign's "LDC.128 R-form
//!     unconstrained" conclusion is vacuous (width-dropped probes ran as
//!     32-bit loads; see results/cubitfix/088/probes/p_ldc128_*.cubin).
//!   * ptxas 13.3 NEVER emits R-domain LDC.128 (128-bit constant loads
//!     decompose into 2x LDC.64; probes ldc_probe.cubin/ldc128.cubin), and
//!     the 2049-cubin vendor corpus contains ZERO R-domain LDC.128 renders
//!     (only the uniform-domain LDCU.128 exists: width = bit74).
//!   * Vendor LDCU.128 word pin below is extracted from
//!     corpus/cublas/libcublas.so.841.sm_100.cubin (kernel
//!     sphpr2_kernel_64addr, slot 0x160).
//! Authoring `LDC.128 R..., c[...]` now FAILS CLOSED via the BUG-132
//! verify_mod_group_retained check (no table row expresses the combination;
//! allowlist entry removed). Guidance: emit 2x LDC.64 instead.
//! Decode stays full-fidelity for RE — these are encode-side pins only.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;

fn t103a() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}
fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn enc(t: &IsaTable, text: &str) -> anyhow::Result<u128> {
    let insn = parse_sass(&format!("{text} ;"), 0).map_err(|e| anyhow::anyhow!("parse: {e}"))?;
    encode_instruction(&insn, t)
}
fn dec(t: &IsaTable, w: u128) -> String {
    t.decode_index()
        .decode(w, 0, t)
        .map(|d| cubit::printer::to_sass(&d))
        .expect("decode")
}

/// Vendor truth anchors (payload bits <96; top 32 carry sched/control):
const W_LDCU128_UR20_VENDOR: u128 = 0x000e620008000c0000007400ff1477ac; // LDCU.128 UR20, c[0x0][0x3a0]
const W_ERA_LDC128_DROP: u128 = 0x000fc200000008000000e000ff357b82; // era pin = plain LDC R53, c[0x0][0x380]
const W_PLAIN_LDC_R53: u128 = 0x000fc200000008000000e200ff357b82; // LDC R53, c[0x0][0x388]
const PAYLOAD: u128 = (1u128 << 96) - 1;

#[test]
fn t135_1_ldc128_r_cai_rejected_sm103a() {
    let e = enc(&t103a(), "LDC.128 R53, c[0x0][0x380]").expect_err(
        "LDC.128 R-domain has no encoding — must fail closed (was silently plain LDC pre-135)",
    );
    let m = format!("{e}");
    assert!(m.contains("128"), "error names the dropped width mod: {m}");
    // odd/even dest irrelevant: R54 was the era "even, legal" example
    enc(&t103a(), "LDC.128 R54, c[0x0][0x380]")
        .expect_err("even dest does not rescue a nonexistent encoding");
    enc(&t103a(), "LDC.128 RZ, c[0x0][0x380]")
        .expect_err("RZ dest does not rescue a nonexistent encoding");
}

#[test]
fn t135_2_ldc128_r_cari_rejected_sm103a() {
    enc(&t103a(), "LDC.128 R2, c[0x0][R4]")
        .expect_err("cARI register-offset form likewise has no 128-bit encoding");
}

#[test]
fn t135_3_ldc128_r_rejected_sm120() {
    // LDC.INVALID6/INVALID7 verdict confirmed for sm_120a grafts as well and
    // sm120.json has no R-domain '128' rows either.
    enc(&t120(), "LDC.128 R53, c[0x0][0x380]")
        .expect_err("sm120 must fail closed too (nvdisasm INVALID6/7 on sm_120a grafts)");
}

#[test]
fn t135_4_ldcu128_ur_domain_unaffected_vendor_exact() {
    // The uniform-domain LDCU.128 is REAL silicon (width bit74, corpus-abundant).
    let w = enc(&t103a(), "LDCU.128 UR20, c[0x0][0x3a0]").expect("LDCU.128 must stay encodable");
    assert_eq!(
        w & PAYLOAD,
        W_LDCU128_UR20_VENDOR & PAYLOAD,
        "LDCU.128 payload must stay vendor-exact: ours {w:032x}"
    );
    assert_eq!((w >> 74) & 1, 1, "LDCU.128 = width bit74 set");
    assert_eq!((w >> 73) & 1, 0, "LDCU.128 keeps bit73 (.64) clear");
    // render-claim roundtrip: decode claims the width back
    let txt = dec(&t103a(), w & PAYLOAD);
    assert!(
        txt.contains("LDCU.128"),
        "decode must claim the width: {txt}"
    );
}

#[test]
fn t135_5_invalid_width_word_never_renders_plain_ldc() {
    // Graft twin of the corpus probe: plain LDC word with width code 2 (bit74
    // set) — nvdisasm renders LDC.INVALID6. Our decoder must NOT silently
    // render it as a clean plain LDC: CLI shows `/* ? 0x... */` (unknown-word
    // marker). Accept either a loud decode error or an explicitly marked
    // raw/residue render — never a clean width-less LDC claim.
    let t = t103a();
    let g = W_PLAIN_LDC_R53 | (1u128 << 74);
    if let Ok(d) = t.decode_index().decode(g, 0, &t) {
        let txt = cubit::printer::to_sass(&d);
        assert!(
            txt.contains("__raw__") || txt.contains("rsd") || txt.contains('?'),
            "INVALID-width word must render loud, got clean render: {txt}"
        );
    }
    // ...and the era width-dropped pin is exactly the plain load it encodes
    let era = dec(&t, W_ERA_LDC128_DROP);
    assert!(
        era.contains("LDC R53, c[0x0][0x380]"),
        "era pin is plain LDC: {era}"
    );
    assert!(!era.contains("128"), "no width may be claimed: {era}");
}

#[test]
fn t135_6_legal_widths_untouched() {
    // 32/64-bit encodings are byte-stable across the fix (payload domain):
    let w32 = enc(&t103a(), "LDC R53, c[0x0][0x388]").unwrap();
    assert_eq!(w32, W_PLAIN_LDC_R53, "plain LDC byte-pin");
    let w64 = enc(&t103a(), "LDC.64 R54, c[0x0][0x380]").unwrap();
    assert_eq!(
        w64, 0x000fc20000000a000000e000ff367b82,
        "LDC.64 even byte-pin"
    );
}

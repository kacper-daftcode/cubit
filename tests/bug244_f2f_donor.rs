//! BUG-244 (F2-iter123, front2/blind, 2026-08-28): donor-side F2F.F64.F32
//! vendor-parity closure (canonical 00c3fd2; patch244.py
//! replayable+idempotent). sm120/sm121a byte-untouched.
//!
//! Pre-fix state (gold243_post, 2,406-file battery x4 legs vs vendor
//! nvdisasm 13.3.73 at-address): donors F2F.F64.F32 15,567 DIFF + 1 HOLE
//! per leg (generic row F2F_R_R["F32,F64"] was a both-direction mega-row
//! printing '.F32.F64' for F64-dst words + lossy !rsd[75:1,84:0]
//! re-encode; F2F.F64.F32 R,UR had no row at all).
//!
//! Laws (law244.json census 33,251 uniq vendor words; arb244.json
//! transplant arbiters A/B/C/D):
//!   W1 dst-type cell = (b75,b84): (1,0)=F64-dst, (0,1)=F32-dst;
//!      (0,0)/(1,1) vendor-ILLEGAL; {b76,b85}=1 mandatory (arb244 C);
//!      tok2 neg@63 / abs@62 (arb + 340/140 uniq census words); b73/b74
//!      inert on this cell.
//!   W2 UR F64-dst cell == sm120 226e graft row (arb226e_c print-identical
//!      x{100a,103a,120a}); donor witness ldc64.cubin @0x70.
//!   W3 donor corpus carries 655 uniq GUARDED F64-dst words ([15:12] in
//!      0..14) -> typed rows carry a guard field (sm120 typed row bakes
//!      PT; the donor corpus cannot).
//!   W4 encode route: candidate (typed_key, sorted-mg) probes FIRST ->
//!      typed keys carry the "F32,F64" alias mg (BUG-240 method); the
//!      rebuilt base row owns spelled F2F.F32.F64 via its own cell.
//! VIMNMX.U32 5/leg donor DIFF is NOT in scope: transplants A/B prove the
//! PT,PT elision follows the ELF .target arch (sm_120-target probe cubins
//! vs sm_100-model donor print) == the BUG-238 VIMNMX arch-split class,
//! parked [owner].

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;
fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> u128 {
    let insn = parse_sass(&format!("{text};"), 0).unwrap_or_else(|e| panic!("parse {text}: {e}"));
    encode_instruction(&insn, t).unwrap_or_else(|e| panic!("encode {text}: {e}"))
}

// Vendor witnesses (word96, ctrl stripped to the low 96 bits).
const W_F64DST: u128 = 0x000e2600002018000000000a00067310; // F2F.F64.F32 R6, R10
const W_F64DST_NEG: u128 = W_F64DST | (1u128 << 63); // F2F.F64.F32 R6, -R10
const W_F64DST_ABS: u128 = W_F64DST | (1u128 << 62); // F2F.F64.F32 R6, |R10|
const W_F64DST_G: u128 = (W_F64DST & !(0xfu128 << 12)) | (1u128 << 12); // @P1 ... (guard 1)
const W_F32DST: u128 = 0x002e7000003010000000000600067310; // F2F.F32.F64 R6, R6
const W_UR64: u128 = 0x002e9e00082018000000000600027d10; // F2F.F64.F32 R2, UR6

#[test]
fn t244_1_structure() {
    for arch in ["sm100a", "sm103a"] {
        let t = tab(arch);
        let ins = |k: &str| {
            let e = t.entries.get(k).unwrap_or_else(|| panic!("{arch} {k}"));
            e
        };
        // typed F64-dst key present with alias mg
        for k in ["F2F.F64.F32_R_R", "F2F.F64.F32_R_UR"] {
            let ik = ins(k);
            assert!(ik.mod_groups.contains_key(""), "{arch} {k} mg ''");
            assert!(ik.mod_groups.contains_key("F32,F64"), "{arch} {k} alias mg");
            assert!(k.starts_with("F2F.F64.F32"), "{arch} {k} typed base");
        }
        // F64-dst R,R cell: b75 baked, b84 clear, guard field (W3)
        let r = &ins("F2F.F64.F32_R_R").mod_groups[""];
        assert_eq!((r.and_base >> 75) & 1, 1, "{arch} typed b75");
        assert_eq!((r.and_base >> 84) & 1, 0, "{arch} typed b84");
        assert!(
            r.fields.iter().any(|f| f.shift == 12 && f.bits == 4),
            "{arch} typed guard field (W3)"
        );
        // rebuilt base row: pure F32-dst (b84 baked / b75 clear), no mnemod
        let r = &ins("F2F_R_R").mod_groups["F32,F64"];
        assert_eq!((r.and_base >> 84) & 1, 1, "{arch} base b84");
        assert_eq!((r.and_base >> 75) & 1, 0, "{arch} base b75");
        let has_mnemod = r
            .fields
            .iter()
            .any(|f| format!("{:?}", f.extraction).contains("Mnemod"));
        assert!(!has_mnemod, "{arch} base mnemod ektomia");
        // UR graft row exists
        assert!(
            ins("F2F_R_UR").mod_groups.contains_key("F64,F32"),
            "{arch} UR graft"
        );
    }
}

#[test]
fn t244_2_decode_vendor_true() {
    for arch in ["sm100a", "sm103a"] {
        let t = tab(arch);
        assert_eq!(
            dec(&t, W_F64DST).as_deref(),
            Some("F2F.F64.F32 R6, R10"),
            "{arch}"
        );
        assert_eq!(
            dec(&t, W_F64DST_NEG).as_deref(),
            Some("F2F.F64.F32 R6, -R10")
        );
        assert_eq!(
            dec(&t, W_F64DST_ABS).as_deref(),
            Some("F2F.F64.F32 R6, |R10|")
        );
        assert_eq!(
            dec(&t, W_F64DST_G).as_deref(),
            Some("@P1 F2F.F64.F32 R6, R10"),
            "{arch} guarded"
        );
        assert_eq!(
            dec(&t, W_UR64).as_deref(),
            Some("F2F.F64.F32 R2, UR6"),
            "{arch} HOLE cured"
        );
        // F32-dst unchanged (was already vendor-correct via the old mega-row)
        assert_eq!(dec(&t, W_F32DST).as_deref(), Some("F2F.F32.F64 R6, R6"));
        // W1: off-quadrant cells are vendor-ILLEGAL (arb244 C). The
        // generic sign-window fallback may still absorb them textually on
        // unarmed F2F (226/227 registry doctrine) -- but the printed text
        // must never re-encode to the poisoned word (fidelity gate:
        // disassembler then emits !rsd/__raw__ instead of silent junk).
        for w in [(W_F64DST & !(1u128 << 75)), (W_F64DST | (1u128 << 84))] {
            if let Some(text) = dec(&t, w) {
                let insn = parse_sass(&format!("{text};"), 0).unwrap();
                let ok = encode_instruction(&insn, &t)
                    .map(|rc| rc & M96 == w & M96)
                    .unwrap_or(false);
                assert!(
                    !ok,
                    "{arch} off-quadrant word silently roundtrips as {text}"
                );
            }
        }
    }
}

#[test]
fn t244_3_encode_routes_and_roundtrip() {
    for arch in ["sm100a", "sm103a"] {
        let t = tab(arch);
        // spelled typed text -> right cell words (low 96 bits: ctrl writer-free)
        assert_eq!(
            enc(&t, "F2F.F64.F32 R6, R10") & M96,
            W_F64DST & M96,
            "{arch}"
        );
        assert_eq!(
            enc(&t, "F2F.F32.F64 R6, R6") & M96,
            W_F32DST & M96,
            "{arch}"
        );
        assert_eq!(enc(&t, "F2F.F64.F32 R2, UR6") & M96, W_UR64 & M96, "{arch}");
        assert_eq!(enc(&t, "F2F.F64.F32 R6, -R10") & M96, W_F64DST_NEG & M96);
        assert_eq!(enc(&t, "F2F.F64.F32 R6, |R10|") & M96, W_F64DST_ABS & M96);
        assert_eq!(enc(&t, "@P1 F2F.F64.F32 R6, R10") & M96, W_F64DST_G & M96);
        // roundtrip of the printed forms (no !rsd needed anymore)
        for text in [
            "F2F.F64.F32 R6, R10",
            "F2F.F32.F64 R6, R6",
            "F2F.F64.F32 R2, UR6",
        ] {
            let w = enc(&t, text) & M96;
            let back = dec(&t, w).expect("re-decode");
            assert_eq!(back, text, "{arch} text roundtrip");
        }
    }
}

#[test]
fn t244_4_donor_parity_and_sm120_untouched() {
    let a = tab("sm100a");
    let b = tab("sm103a");
    for k in ["F2F_R_R", "F2F_R_UR", "F2F.F64.F32_R_R", "F2F.F64.F32_R_UR"] {
        for (mg, ra) in &a.entries[k].mod_groups {
            let rb = b.entries[k]
                .mod_groups
                .get(mg)
                .unwrap_or_else(|| panic!("donor parity {k}[{mg}]"));
            assert_eq!(ra.and_base, rb.and_base, "donor parity {k}[{mg}] ab");
            assert_eq!(
                ra.variable_mask, rb.variable_mask,
                "donor parity {k}[{mg}] vm"
            );
            assert_eq!(
                ra.fields.len(),
                rb.fields.len(),
                "donor parity {k}[{mg}] fields"
            );
        }
        assert_eq!(a.entries[k].mod_groups.len(), b.entries[k].mod_groups.len());
    }
    // sm120 watch: typed key still the 226e/240 shape (untouched by 244)
    let t = tab("sm120");
    let ik = &t.entries["F2F.F64.F32_R_R"];
    assert!(ik.mod_groups.contains_key("F32,F64"));
    let r = &ik.mod_groups[""];
    assert_eq!((r.and_base >> 75) & 1, 1);
    assert!(t.entries["F2F_R_UR"].mod_groups.contains_key("F64,F32"));
}

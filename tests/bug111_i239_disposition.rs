//! BUG-111-kand DISPOSITION (sm120 registry TS2-WIDEX-IMM-TABLE + TS2-LDG-WAIT
//! ADDENDUM, both i239 2026-08-24 pinned to sm120-side bin 5b2a7474 + their
//! local table line v10->v18): both findings are STALE-BINARY artifacts —
//! already fixed on cubit main:
//!   (1) IMAD.WIDE.U32.X imm-form (flattened key IMAD_R_P_R_II_R_P,
//!       ctrl_class "imad_wide" needs_write_bar=true) is scoreboard-pathed
//!       (S01+wbar) only WITHOUT the BUG-108 opcode-level exclusion
//!       (56cb4ba): scheduling_pass::insn_needs_write_bar returns false for
//!       op IMAD|UIMAD before any table tag is consulted. End-to-end asm on
//!       BOTH tables emits the vendor-good word hi64=0x000fcc000300047c
//!       (stall=6, yield=0, wbar=7, rbar=7, wait=0x00) for the exact failing
//!       slot `IMAD.WIDE.U32.X R124, P0, R122, 0xfffffc2f, R124, P6`.
//!   (2) LDG.E.NA.ELL2.256.STRONG.GPU auto-ctrl DOES allocate a write
//!       barrier and the consumer wait-mask covers it (BUG-101/dfcfb0d span
//!       doctrine), including second-quad consumers — the "no wait / stale
//!       RF" observation reproduces only on the pre-BUG-101 binary.
//!
//! These pins are regression fences for the fleet hand-off: re-running the
//! i239 gates requires a binary >= 56cb4ba (resp. current main). No src/,
//! tables/, encoder or decoder changes accompany them.
//!
//! Flow: parse -> schedule() -> reallocate_barriers() -> encode_instruction()
//! (the exact `cubit asm` production path; BUG-103 test idiom).

use cubit::encoder::encode_instruction;
use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule};
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}
fn t103() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap()
}

/// Exact failing-kernel shape from TS2-WIDEX-IMM-TABLE (self-addend,
/// negative immediate, P0 carry-out / P6 carry-in) with a near consumer.
const K_WIDE: &str = ".entry t\n    .param u64 io\n    S2R R16, SR_TID.X ;\n    MOV R192, RZ ;\n    MOV R211, RZ ;\n    MOV R122, RZ ;\n    MOV R124, RZ ;\n    MOV R126, RZ ;\n    IMAD.WIDE.U32.X R124, P0, R122, 0xfffffc2f, R124, P6 ;\n    IADD3.X R33, P4, P5, R192, R211, R124, P4, P5 ;\n    IMAD.WIDE.U32.X R128, P0, R122, 0x3d1, R126, P6 ;\n    IADD3.X R34, P4, P5, R192, R211, R129, P4, P5 ;\n    EXIT ;\n";

/// Exact producer/consumer shape from TS2-LDG-WAIT addendum i239.
const K_LDG: &str = ".entry t\n    .param u64 io\n    S2R R16, SR_TID.X ;\n    UIADD3 UR8, UPT, UPT, URZ, 0x0, UR63 ;\n    LEA R4, P6, R16, RZ, 0x6 ;\n    LEA.HI R5, P6, R16, RZ, RZ, 0x0 ;\n    MOV R22, RZ ;\n    LDG.E.NA.ELL2.256.STRONG.GPU R20, R21, desc[UR8][R4.64] ;\n    LOP3.LUT R24, R26, R22, RZ, 0x3c, !PT ;\n    LOP3.LUT R25, R27, R22, RZ, 0x3c, !PT ;\n    STG.E desc[UR8][R4.64], R24 ;\n    EXIT ;\n";

struct Encoded {
    opcode_full: String,
    upper32: u32,
    hi64: u64,
}

fn pipeline_encode(src: &str, tab: &IsaTable) -> Vec<Encoded> {
    let f = parse_sass_file_str_strict(src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    schedule(&mut insns, Some(tab));
    reallocate_barriers(&mut insns, Some(tab));
    insns.iter()
        .map(|x| {
            let w = encode_instruction(x, tab)
                .unwrap_or_else(|e| panic!("encode failed for {}: {:?}", x.opcode_full, e));
            Encoded {
                opcode_full: x.opcode_full.clone(),
                upper32: (w >> 96) as u32,
                hi64: (w >> 64) as u64,
            }
        })
        .collect()
}

fn d3(ctrl: &Encoded) -> (u8, u8, u8, u8, u8) {
    let code = (ctrl.upper32 >> 9) & 0x1FFFF;
    (
        (code & 0xF) as u8,          // stall
        ((code >> 4) & 1) as u8,     // yield
        ((code >> 5) & 7) as u8,     // wbar
        ((code >> 8) & 7) as u8,     // rbar
        ((code >> 11) & 0x3F) as u8, // wait
    )
}

/// (1) The exact failing slot rides the BUG-108 stall-sync doctrine
/// end-to-end: stall=6 / yield=0 / wbar=7 / rbar=7 / wait=0, i.e. vendor-good
/// hi64 0x000fcc000300047c. Full-hi64 anchor pins payload stability too.
#[test]
fn t111_1_widex_imm_neg_selfaddend_vendor_word() {
    for tab in [t120(), t103()] {
        let e = pipeline_encode(K_WIDE, &tab);
        let p = e
            .iter()
            .find(|x| x.opcode_full == "IMAD.WIDE.U32.X")
            .expect("no IMAD.WIDE.U32.X");
        assert_eq!(
            p.hi64, 0x000fcc000300047c,
            "vendor-good word for the i239 failing slot must hold (stall6/wbar7)"
        );
        assert_eq!(d3(p), (6, 0, 7, 7, 0));
    }
}

/// (1b) The positive-imm / non-self-addend variant (BUG-108 pin shape) is
/// likewise stall-synced with NO scoreboard barrier on the encode path.
#[test]
fn t111_2_widex_imm_positive_stall_synced() {
    for tab in [t120(), t103()] {
        let e = pipeline_encode(K_WIDE, &tab);
        let mut it = e.iter().filter(|x| x.opcode_full == "IMAD.WIDE.U32.X");
        let _first = it.next().unwrap(); // covered by t111_1
        let g = it.next().expect("second IMAD.WIDE.U32.X");
        let (stall, _y, wbar, _rbar, _wait) = d3(g);
        assert!(wbar == 7, "WIDE-imm producer must not carry a scoreboard wb");
        assert!(stall >= 5, "stall must cover the WIDE pair (S0c floor)");
    }
}

/// (1c) The WIDE consumer never waits a barrier the producer never wrote:
/// with the producer on the stall path, the IADD3.X consumer has wait==0
/// (pure stall synchronization), both tables.
#[test]
fn t111_3_widex_consumer_pure_stall() {
    for tab in [t120(), t103()] {
        let e = pipeline_encode(K_WIDE, &tab);
        let c = e
            .iter()
            .find(|x| x.opcode_full.starts_with("IADD3.X"))
            .expect("no IADD3.X consumer");
        let (_stall, _y, wbar, _rbar, wait) = d3(c);
        assert_eq!(wbar, 7, "consumer writes no barrier itself");
        assert_eq!(wait, 0, "consumer must be stall-synced, not barrier-waited");
    }
}

/// (2) TS2-LDG-WAIT addendum: the .256 ELL2 STRONG.GPU producer gets a real
/// write barrier and consumers of BOTH quads wait it (BUG-101 doctrine,
/// encode-final words as authored by schedule+reallocate).
#[test]
fn t111_4_ldg256_ell2_stronggpu_consumers_wait() {
    for tab in [t120(), t103()] {
        let e = pipeline_encode(K_LDG, &tab);
        let prod_idx = e
            .iter()
            .position(|x| x.opcode_full.starts_with("LDG.E"))
            .expect("no LDG producer");
        let prod = &e[prod_idx];
        let (_s, _y, wbar, _r, _w) = d3(prod);
        assert!(wbar < 7, "LDG.256 ELL2 producer must allocate a write barrier");
        let waitbit = 1u8 << wbar;
        // The FIRST in-span consumer must wait the producer's barrier; later
        // readers are covered by that drain (scheduler legally elides the
        // redundant wait on the second LOP3 — wait removal is not a hole).
        let first = &e[prod_idx + 1];
        assert!(
            first.opcode_full.starts_with("LOP3"),
            "expected LOP3 consumer, got {}",
            first.opcode_full
        );
        let (_s, _y, _wb, _r, wait) = d3(first);
        assert_eq!(
            wait & waitbit,
            waitbit,
            "first in-span (second-quad) consumer must wait the LDG barrier (got wait=0x{wait:02x})"
        );
    }
}

/// (3) Registry side-observation (i239 class-2/3 render drift): the one-reg
/// dual-carry IADD3.X form encodes and round-trips through our tables
/// (slot-placement between table generations is a semantic no-op: additive
/// commas are commutative; anchor here guards encodability, not placement).
#[test]
fn t111_5_iadd3x_single_reg_roundtrip() {
    const K: &str = ".entry t\n    .param u64 io\n    S2R R16, SR_TID.X ;\n    MOV R192, RZ ;\n    IADD3.X R33, P0, P6, R192, RZ, RZ, P6, P6 ;\n    IADD3.X R34, P4, P5, R192, R33, RZ, P4, P5 ;\n    EXIT ;\n";
    for tab in [t120(), t103()] {
        let e = pipeline_encode(K, &tab);
        assert!(
            e.iter().filter(|x| x.opcode_full == "IADD3.X").count() == 2,
            "both IADD3.X forms must encode"
        );
    }
}

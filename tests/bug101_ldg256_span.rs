//! BUG-101 (sm120 registry TS2-LDG-WAIT i232 sibling-class): the .256 memory
//! forms (LDG_R_R_dARI / STG_dARI_R_R) print TWO 128-bit base registers; per
//! the M3.5 census doctrine each leading base names a 128-bit register quad.
//! scheduling_pass::dest_regs/src_regs only registered the first base register
//! (no .256 span), so a consumer (or overwriter, for stores) of ANY register in
//! the two quads other than the first base never saw the memory op as producer:
//! no write-barrier on the load, no wait on the consumer -> silicon reads stale
//! RF state (cold-miss LDG latencies >> any stall budget).
//!
//! These tests pin the final control words after schedule()+reallocate_barriers()
//! (the exact `cubit asm` flow):
//!   1) head-reg consumer keeps its scoreboard cover (pre-existing behaviour);
//!   2) in-quad consumer (R21) is scoreboarded post-fix (THE HOLE);
//!   3) second-quad consumer (R25) is scoreboarded post-fix (THE HOLE);
//!   4) STG.256: in-quad data overwriter waits the store's read-barrier (WAR);
//!   5) narrow loads (LDG.E.64 pairs) keep their existing cover (no-FP pin).

use cubit::sass_file::parse_sass_file_str_strict;
use cubit::scheduling_pass::{reallocate_barriers, schedule};
use cubit::table::IsaTable;

fn t120() -> IsaTable {
    IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap()
}

const HDR: &str = ".entry t\n    .param u64 io\n    LDC.64 R2, c[0x0][0x380] ;\n    LDC.64 R10, c[0x0][0x388] ;\n    S2R R16, SR_TID.X ;\n    SHF.L.U32 R18, R16, 0x5, RZ ;\n    IMAD.WIDE.U32 R2, R18, 0x1, R2 ;\n";

/// Run the asm-pass pipeline and return (wb, wait_mask) per instruction index.
fn ctrls(body: &str) -> Vec<(u8, u8)> {
    let src = format!("{HDR}{body}    EXIT ;\n");
    let f = parse_sass_file_str_strict(&src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    let tab = t120();
    schedule(&mut insns, Some(&tab));
    reallocate_barriers(&mut insns, Some(&tab));
    insns.iter().map(|x| (x.ctrl.write_bar, x.ctrl.wait_mask)).collect()
}

/// index of the first instruction whose opcode_full contains `frag`
fn idx_of(src: &str, frag: &str) -> usize {
    let s = format!("{HDR}{src}    EXIT ;\n");
    let f = parse_sass_file_str_strict(&s).unwrap();
    f.kernels[0]
        .instructions
        .iter()
        .position(|x| x.opcode_full.contains(frag))
        .unwrap_or_else(|| panic!("no op containing {frag:?}"))
}

const LDG256: &str = "    LDG.E.NA.ELL2.256.STRONG.GPU R20, R24, desc[UR8][R10.64] ;\n";

#[test]
fn t101_1_head_consumer_covered() {
    let body = format!("{LDG256}    LOP3.LUT R30, R20, 0xf, RZ, 0xc0, !PT ;\n");
    let c = ctrls(&body);
    let (l, k) = (idx_of(&body, "LDG.E.NA.ELL2.256"), idx_of(&body, "LOP3"));
    assert!(c[l].0 < 7, "LDG.256 must carry a write barrier, got wb={}", c[l].0);
    assert!(
        c[k].1 & (1 << c[l].0) != 0,
        "head-reg consumer must wait wb{}, got wait={:02x}",
        c[l].0,
        c[k].1
    );
}

#[test]
fn t101_2_in_quad_consumer_covered() {
    let body = format!("{LDG256}    LOP3.LUT R30, R21, 0xf, RZ, 0xc0, !PT ;\n");
    let c = ctrls(&body);
    let (l, k) = (idx_of(&body, "LDG.E.NA.ELL2.256"), idx_of(&body, "LOP3"));
    assert!(c[l].0 < 7, "LDG.256 must carry a write barrier, got wb={}", c[l].0);
    assert!(
        c[k].1 & (1 << c[l].0) != 0,
        "in-quad consumer (R21) must wait wb{} - pre-fix the span hole left it unwatched (TS2 stale-read class), got wait={:02x}",
        c[l].0,
        c[k].1
    );
}

#[test]
fn t101_3_second_quad_consumer_covered() {
    let body = format!("{LDG256}    LOP3.LUT R30, R25, 0xf, RZ, 0xc0, !PT ;\n");
    let c = ctrls(&body);
    let (l, k) = (idx_of(&body, "LDG.E.NA.ELL2.256"), idx_of(&body, "LOP3"));
    assert!(c[l].0 < 7, "LDG.256 must carry a write barrier, got wb={}", c[l].0);
    assert!(
        c[k].1 & (1 << c[l].0) != 0,
        "second-quad consumer (R25 of R24..R27) must wait wb{}, got wait={:02x}",
        c[l].0,
        c[k].1
    );
}

#[test]
fn t101_4_stg256_data_overwriter_waits_rb() {
    let body = format!(
        "{LDG256}    LOP3.LUT R21, R21, 0xf, RZ, 0xc0, !PT ;\n    STG.E.NA.ELL2.256.STRONG.GPU desc[UR8][R10.64], R20, R24 ;\n    MOV R27, RZ ;\n"
    );
    let c = ctrls(&body);
    let s = idx_of(&body, "STG.E.NA.ELL2.256");
    let m = idx_of(&body, "MOV");
    // store carries a read-barrier for its late-latched data quads
    let src = format!("{HDR}{body}    EXIT ;\n");
    let f = parse_sass_file_str_strict(&src).unwrap();
    let mut insns = f.kernels[0].instructions.clone();
    let tab = t120();
    schedule(&mut insns, Some(&tab));
    reallocate_barriers(&mut insns, Some(&tab));
    let rb = insns[s].ctrl.read_bar;
    let _ = c; // (wb,wait) view kept for clarity; read_bar needs the insn set
    assert!(rb < 7, "STG.256 must carry a read barrier, got rb={rb}");
    assert!(
        insns[m].ctrl.wait_mask & (1 << rb) != 0,
        "in-quad (R27 of R24..R27) data overwriter must wait rb{}, got wait={:02x} — pre-fix only R20/R24 were registered",
        rb,
        insns[m].ctrl.wait_mask
    );
}

#[test]
fn t101_5_narrow_load_cover_unchanged() {
    // LDG.E.64 head-pair consumer: already covered pre-fix; pin it so the
    // .256 span change cannot silently regress the mature narrow path.
    let body = "    LDG.E.64 R28, desc[UR8][R10.64] ;\n    LOP3.LUT R30, R29, 0xf, RZ, 0xc0, !PT ;\n";
    let c = ctrls(body);
    let (l, k) = (idx_of(body, "LDG.E.64"), idx_of(body, "LOP3"));
    assert!(c[l].0 < 7, "LDG.E.64 must carry a write barrier, got wb={}", c[l].0);
    assert!(
        c[k].1 & (1 << c[l].0) != 0,
        "R29 (second reg of the .64 pair) consumer must wait wb{}, got wait={:02x}",
        c[l].0,
        c[k].1
    );
}

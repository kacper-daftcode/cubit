//! BUG-333 (F2-iter178, loop5/blind front2, 2026-09-01): sm121a
//! SHFL_P_R_R_II_R['BFLY'] = junk dup-claim mod_group -- DELETE
//! (canonical 1c415e8; engine untouched).
//!
//! Law (arb333, nvdisasm 13.3.73 raw -b, x4 models
//! SM100a/SM103a/SM120/SM121a AGREE on every probe; verdicts
//! work/bug333/arb333_verdicts.json):
//!   bits[11:10] of a SHFL.BFLY word select the tok4/tok5 sources:
//!     00 -> tok4=reg@32, tok5=reg@64    (R-form, P_R_R_R_R)
//!     11 -> tok4=imm5@53, tok5=imm13@40 (II-form, P_R_R_II_II)
//!     01/10 -> vendor rc=1 (ILLEGAL)
//!   reg@64 is WRITE-INERT on the II form (D-set: tok5 always prints
//!   imm13@40) => vendor has NO P_R_R_II_R shape for SHFL.BFLY.
//! The deleted mg claimed EXACTLY the surface of SHFL_P_R_R_R_R['BFLY']
//! (identical and_base/variable_mask, the b82=1 half of the R-form
//! claim) with broken fields (tok1 1b@16, tok0 3b@18 junk, pred 1b@81,
//! reuse@122/123/124): dead-shadowed on decode (the R_R_R_R row owns
//! the prints -- publish f659b8f decodes b82=1 R-anchors P2/P6/PT
//! vendor-equal) and loud-refuse on mint. Donor legs sm100a/sm103a/
//! sm120 never had a BFLY mg in the II_R row. The II_R row keeps 'UP'
//! (corpus-real: SHFL.UP PT,R10,R11,0x1,RZ anchors x49 decode
//! vendor-equal via it).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    let idx = DecodeIndex::build(t);
    idx.decode(w, 0, t).map(|d| to_sass(&d)).ok()
}
fn enc(t: &IsaTable, text: &str) -> Option<u128> {
    let insn = parse_sass(&format!("{text};"), 0).ok()?;
    encode_instruction(&insn, t).ok()
}

/// Corpus anchors (libcublasLt.so.412.sm_100.cubin, decode leg sm121a):
const W_R: u128 = 0x00006400000000100c00000b0a127389; // SHFL.BFLY P0, R18, R10, R11, R16
const W_R6: u128 = 0x00006400000c0010_0c00000b0a127389; // b82=1 half, pred=P6 (was dup-claimed)
const W_II: u128 = 0x000e2400000e00000c201f0013127f89; // SHFL.BFLY PT, R18, R19, 0x1, 0x1f

#[test]
fn t333_1_structure_mg_purged() {
    let t = tab("sm121a");
    let row = t
        .entries
        .get("SHFL_P_R_R_II_R")
        .expect("II_R row must survive (UP mg is corpus-real)");
    assert!(
        !row.mod_groups.contains_key("BFLY"),
        "junk BFLY mg still present in sm121a SHFL_P_R_R_II_R"
    );
    assert!(
        row.mod_groups.contains_key("UP"),
        "II_R row lost its corpus-real UP mg"
    );
    // donors: never had the BFLY mg; pin the invariant
    for leg in ["sm100a", "sm103a", "sm120"] {
        let dt = tab(leg);
        let drow = dt.entries.get("SHFL_P_R_R_II_R").unwrap();
        assert!(
            !drow.mod_groups.contains_key("BFLY"),
            "{leg}: donor II_R row unexpectedly carries BFLY"
        );
    }
    // R_R_R_R['BFLY'] owner row untouched: donor-law fields
    let t2 = tab("sm121a");
    let own = &t2.entries["SHFL_P_R_R_R_R"].mod_groups["BFLY"];
    let has = |ext: Extraction, shift: u32, tok: i32| {
        own.fields
            .iter()
            .any(|f| f.extraction == ext && f.shift == shift && f.token_idx == tok)
    };
    assert!(has(Extraction::Reg, 16, 2), "owner row lost dest@16");
    assert!(has(Extraction::Pred, 81, 1), "owner row lost pred@81");
}

#[test]
fn t333_2_decode_rform_surface_incl_b82_half() {
    // The whole R-form surface (both b82 halves) decodes vendor-equal
    // EXACTLY as on pre-fix publish (shadowed junk mg was print-inert).
    for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(leg);
        assert_eq!(
            dec(&t, W_R).as_deref(),
            Some("SHFL.BFLY P0, R18, R10, R11, R16"),
            "{leg}: b82=0 R-anchor regressed"
        );
    }
    // b82=1 half on sm121a (the deleted mg's claim): owner row answers.
    let t = tab("sm121a");
    assert_eq!(
        dec(&t, W_R6).as_deref(),
        Some("SHFL.BFLY P6, R18, R10, R11, R16"),
        "sm121a: b82=1 half of the R-form claim lost coverage"
    );
}

#[test]
fn t333_3_decode_iiform_anchors() {
    // II-form (bits[11:10]=11): tok4=imm5@53, tok5=imm13@40; reg@64 inert.
    let t = tab("sm121a");
    assert_eq!(
        dec(&t, W_II).as_deref(),
        Some("SHFL.BFLY PT, R18, R19, 0x1, 0x1f"),
        "II-form anchor"
    );
    // reg@64 non-zero on the II form: vendor prints it fine (arb333 D-set,
    // write-inert); the over-strict era pin [71:64]=0 was CLOSED by BUG-358
    // (FLIP, atrybucja: 358, F2-iter185) -- the word now decodes vendor-exact.
    let w_reg64 = W_II | (20u128 << 64);
    assert_eq!(
        dec(&t, w_reg64).as_deref(),
        Some("SHFL.BFLY PT, R18, R19, 0x1, 0x1f"),
        "reg@64-set II-form word: must decode vendor-exact post-358"
    );
}

#[test]
fn t333_4_fail_closed_edges() {
    let t = tab("sm121a");
    // authored II_R-shaped text: no such vendor shape -> loud refuse
    assert!(
        enc(&t, "SHFL.BFLY P0, R18, R10, 0x1, R20").is_none(),
        "phantom II_R text unexpectedly mints"
    );
    assert!(
        enc(&t, "SHFL.BFLY PT, R18, R10, 0x3, R20").is_none(),
        "phantom II_R text unexpectedly mints (PT)"
    );
    // bits[11:10]=01/10: vendor ILLEGAL -> decode hole
    for bits in [1u128 << 10, 1u128 << 11] {
        let w = (W_R & !(0b11u128 << 10)) | bits;
        assert!(dec(&t, w).is_none(), "illegal bits[11:10] word decoded");
    }
}

#[test]
fn t333_5_mint_bytepins_rform_and_iiform() {
    let t = tab("sm121a");
    // R-form mints byte-exact both pred halves (pre-fix publish did):
    assert_eq!(
        enc(&t, "SHFL.BFLY P0, R18, R10, R11, R16"),
        Some(0x000fc20000000010_0c00000b0a127389),
        "R-form mint b82=0"
    );
    assert_eq!(
        enc(&t, "SHFL.BFLY P2, R18, R10, R11, R16"),
        Some(0x000fc20000040010_0c00000b0a127389),
        "R-form mint b82=1 (owner row post-purge)"
    );
    // II-form corpus shape mints (pred window defect = 358-kand, NOT here:
    // PT text mints fine; P0-authored II text still intent-drops pre-358):
    let w = enc(&t, "SHFL.BFLY PT, R18, R19, 0x1, 0x1f").expect("II-form PT mint");
    assert_eq!(
        dec(&t, w).as_deref(),
        Some("SHFL.BFLY PT, R18, R19, 0x1, 0x1f"),
        "II-form mint/readback roundtrip"
    );
    assert_eq!(w & 0xffff, 0x7f89, "II-form mint landed on R-form surface");
}

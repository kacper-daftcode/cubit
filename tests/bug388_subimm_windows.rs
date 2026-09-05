//! BUG-388 (F2-iter208, loop5/blind front2, 2026-09-05): plain sub_imm
//! window decls -> vendor-true geometry (38 arb378-DIVERGE carriers /
//! 104 rows x4 legs + collateral G/H/I-J). Registration 388-kand
//! (378.md sec.7, F2-iter201). Canonical graft patch388.py (c155d00 ->
//! bacdfb5, tables-only) + ENGINE: SubURm1 printer arm (jedyna zmiana
//! src: [URn],[URn+1] para drukowala [URn],[URn]).
//!
//! LAW: arb388 (56 flipow/nosnik x4) + arb388b (lattice: zero/unit/
//! maxpos/sign/allones/combo/granice) + arb388c (per-row rbleed/urclip/
//! junk band+ball), nvdisasm 13.3.73 raw -b, x4 modele SM100a/SM103a/
//! SM120/SM121a AGREE na KAZDEJ sondzie, DIVERGENT=0; zbiezne z BUG-156
//! window-law. Prawo: LDGSTS sm100a tok2 = 12b@32 SIGNED; LDS|S8 /
//! ATOM(G) CAS tok3 / dARI-desc REDG/STG/ST/LDG/LD = 24b@40 SIGNED;
//! sm121a ST/LD ARI = 32b@32 SIGNED; sm121a LDC/LDCU cAI '' =
//! cm16_off/cm17_off (bank 5b@[54..59) + signed 16/17b); UGETNEXT =
//! para 8b@24, offset nie istnieje (DELETE sub_imm1).
//! Pre-fix (publish cubit_py-05d2e7e9 910e172a.., tables pre_tabs @
//! 05d2e7e9; measure_pre388, 2299 komorek): 1050 MATCH / 1154 WRONG
//! (cichy misprint: flip znaku LDC b53, fabrykowane +0x1, corrupt baza
//! R476) / 95 HOLE.
//! Residua (rejestracje, loud w pinach): 398-kand (cAI [24..32) index
//! zanegowany + '?cAURI' fallback; sektory smem-UR LDGSTS/LDCU drukuja
//! inwersje), 399-kand (glif '+-0x' vendor dla negatywnych offsetow
//! plain ARI/ARURI; silnik drukuje '-0x'; t2 ma glyph-norm z licznikiem
//! audytu).
use cubit::decoder::DecodeIndex;
use cubit::table::IsaTable;

const M96: u128 = (1u128 << 96) - 1;

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, w: u128) -> Option<String> {
    DecodeIndex::build(t)
        .decode(w & M96, 0, t)
        .map(|d| cubit::printer::to_sass(&d))
        .ok()
        .map(|s| s.trim_end().trim_end_matches(';').to_string())
}
fn w(hex: &str) -> u128 {
    u128::from_str_radix(hex, 16).unwrap()
}
fn glyph_norm(s: &str) -> String {
    // 399-kand: vendor 'n+-0x' vs engine 'n-0x' (plain ARI/ARURI only)
    s.replace("+-0x", "-0x")
}

/// t388_1 (invariant): window geometry of every grafted row, x4 legs
/// (maszynowo z carriers388.json).
#[test]
fn t388_1_geometry_polygon() {
    let geo: &[(&str, &str, &str, &str, u64, u64, i32)] = &[
        (
            "sm100a",
            "ATOMG_P_R_ARI_R_R",
            "64,CAS,E,STRONG,SYS",
            "sub_imm1",
            24,
            40,
            3,
        ),
        (
            "sm100a",
            "LDGSTS_ARI_ARI",
            "64,E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDGSTS_ARI_ARI_P",
            "128,BYPASS,E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDGSTS_ARI_ARI_P",
            "128,E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDGSTS_ARI_ARI_P",
            "64,E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDGSTS_ARI_ARURI",
            "128,E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDGSTS_ARI_ARURI_P",
            "128,E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDGSTS_ARI_ARURI_P",
            "64,E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDGSTS_ARI_ARURI_P",
            "E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDGSTS_ARURI_ARI",
            "128,BYPASS,E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDGSTS_ARURI_ARI",
            "128,E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDGSTS_ARURI_ARI",
            "64,E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDGSTS_ARURI_ARI",
            "E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDGSTS_ARURI_ARI_P",
            "128,BYPASS,E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDGSTS_ARURI_ARI_P",
            "E,LTC128B",
            "sub_imm1",
            12,
            32,
            2,
        ),
        (
            "sm100a",
            "LDG_R_dARI",
            "128,E,GPU,STRONG",
            "sub_imm2",
            24,
            40,
            2,
        ),
        (
            "sm100a",
            "LDG_R_dARI",
            "128,E,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            2,
        ),
        (
            "sm100a",
            "LDG_R_dARI",
            "E,GPU,STRONG",
            "sub_imm2",
            24,
            40,
            2,
        ),
        (
            "sm100a",
            "LDG_R_dARI",
            "E,GPU,STRONG,U16",
            "sub_imm2",
            24,
            40,
            2,
        ),
        (
            "sm100a",
            "LDG_R_dARI",
            "E,S8,SM,STRONG",
            "sub_imm2",
            24,
            40,
            2,
        ),
        (
            "sm100a",
            "LDG_R_dARI",
            "E,STRONG,SYS,U16",
            "sub_imm2",
            24,
            40,
            2,
        ),
        ("sm100a", "LDS_R_ARURI", "S8", "sub_imm1", 24, 40, 2),
        ("sm100a", "LD_R_dARI", "E,S8", "sub_imm2", 24, 40, 2),
        ("sm100a", "LD_R_dARI", "E,U8", "sub_imm2", 24, 40, 2),
        (
            "sm100a",
            "REDG_dARI_R",
            "64,E,GPU,MAX,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm100a",
            "REDG_dARI_R",
            "64,E,GPU,MIN,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm100a",
            "REDG_dARI_R",
            "64,E,MAX,SM,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm100a",
            "REDG_dARI_R",
            "64,E,MAX,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm100a",
            "REDG_dARI_R",
            "64,E,MIN,SM,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm100a",
            "REDG_dARI_R",
            "64,E,MIN,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm100a",
            "REDG_dARI_R",
            "E,GPU,MAX,S64,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm100a",
            "REDG_dARI_R",
            "E,GPU,MIN,S64,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm100a",
            "REDG_dARI_R",
            "E,MAX,S64,SM,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm100a",
            "REDG_dARI_R",
            "E,MAX,S64,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm100a",
            "REDG_dARI_R",
            "E,MIN,S64,SM,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm100a",
            "REDG_dARI_R",
            "E,MIN,S64,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm100a",
            "STG_dARI_R",
            "128,E,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm100a",
            "STG_dARI_R",
            "E,STRONG,SYS,U16",
            "sub_imm2",
            24,
            40,
            1,
        ),
        ("sm100a", "ST_dARI_R", "E,U8", "sub_imm2", 24, 40, 1),
        (
            "sm100a",
            "UGETNEXTWORKID_AURI_AURI",
            "BROADCAST",
            "sub_ur0",
            8,
            24,
            1,
        ),
        (
            "sm103a",
            "LDG_R_dARI",
            "128,E,GPU,STRONG",
            "sub_imm2",
            24,
            40,
            2,
        ),
        (
            "sm103a",
            "LDG_R_dARI",
            "128,E,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            2,
        ),
        (
            "sm103a",
            "LDG_R_dARI",
            "E,GPU,STRONG",
            "sub_imm2",
            24,
            40,
            2,
        ),
        (
            "sm103a",
            "LDG_R_dARI",
            "E,GPU,STRONG,U16",
            "sub_imm2",
            24,
            40,
            2,
        ),
        (
            "sm103a",
            "LDG_R_dARI",
            "E,S8,SM,STRONG",
            "sub_imm2",
            24,
            40,
            2,
        ),
        (
            "sm103a",
            "LDG_R_dARI",
            "E,STRONG,SYS,U16",
            "sub_imm2",
            24,
            40,
            2,
        ),
        ("sm103a", "LDS_R_ARURI", "S8", "sub_imm1", 24, 40, 2),
        ("sm103a", "LD_R_dARI", "E,S8", "sub_imm2", 24, 40, 2),
        ("sm103a", "LD_R_dARI", "E,U8", "sub_imm2", 24, 40, 2),
        (
            "sm103a",
            "STG_dARI_R",
            "128,E,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm103a",
            "STG_dARI_R",
            "E,STRONG,SYS,U16",
            "sub_imm2",
            24,
            40,
            1,
        ),
        ("sm103a", "ST_dARI_R", "E,U8", "sub_imm2", 24, 40, 1),
        (
            "sm103a",
            "UGETNEXTWORKID_AURI_AURI",
            "BROADCAST",
            "sub_ur0",
            8,
            24,
            1,
        ),
        (
            "sm120",
            "LDG_R_dARI",
            "128,E,GPU,STRONG",
            "sub_imm2",
            24,
            40,
            2,
        ),
        (
            "sm120",
            "LDG_R_dARI",
            "128,E,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            2,
        ),
        ("sm120", "LDG_R_dARI", "E,GPU,STRONG", "sub_imm2", 24, 40, 2),
        (
            "sm120",
            "LDG_R_dARI",
            "E,GPU,STRONG,U16",
            "sub_imm2",
            24,
            40,
            2,
        ),
        (
            "sm120",
            "LDG_R_dARI",
            "E,S8,SM,STRONG",
            "sub_imm2",
            24,
            40,
            2,
        ),
        (
            "sm120",
            "LDG_R_dARI",
            "E,STRONG,SYS,U16",
            "sub_imm2",
            24,
            40,
            2,
        ),
        ("sm120", "LDS_R_ARURI", "S8", "sub_imm1", 24, 40, 2),
        ("sm120", "LD_R_dARI", "E,S8", "sub_imm2", 24, 40, 2),
        ("sm120", "LD_R_dARI", "E,U8", "sub_imm2", 24, 40, 2),
        (
            "sm120",
            "REDG_dARI_R",
            "64,E,GPU,MAX,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "64,E,GPU,MIN,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "64,E,GPU,OR,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "64,E,MAX,SM,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "64,E,MAX,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "64,E,MIN,SM,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "64,E,MIN,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "64,E,OR,SM,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "64,E,OR,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "E,GPU,MAX,S64,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "E,GPU,MIN,S32,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "E,GPU,MIN,S64,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "E,GPU,OR,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "E,MAX,S64,SM,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "E,MAX,S64,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "E,MIN,S32,SM,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "E,MIN,S32,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "E,MIN,S64,SM,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "E,MIN,S64,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "E,OR,SM,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "REDG_dARI_R",
            "E,OR,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "STG_dARI_R",
            "128,E,STRONG,SYS",
            "sub_imm2",
            24,
            40,
            1,
        ),
        (
            "sm120",
            "STG_dARI_R",
            "E,STRONG,SYS,U16",
            "sub_imm2",
            24,
            40,
            1,
        ),
        ("sm120", "ST_dARI_R", "E,U8", "sub_imm2", 24, 40, 1),
        (
            "sm121a",
            "ATOMG_P_R_ARI_R_R",
            "64,CAS,E,STRONG,SYS",
            "sub_imm1",
            24,
            40,
            3,
        ),
        (
            "sm121a",
            "ATOMG_P_R_ARI_R_R",
            "CAS,E,STRONG,SYS",
            "sub_imm1",
            24,
            40,
            3,
        ),
        (
            "sm121a",
            "ATOM_P_R_ARI_R_R",
            "64,CAS,E,STRONG,SYS",
            "sub_imm1",
            24,
            40,
            3,
        ),
        (
            "sm121a",
            "ATOM_P_R_ARI_R_R",
            "CAS,E,STRONG,SYS",
            "sub_imm1",
            24,
            40,
            3,
        ),
        ("sm121a", "LDCU_UR_cAI", "", "cm17_off", 22, 37, 2),
        ("sm121a", "LDC_R_cAI", "", "cm16_off", 21, 38, 2),
        ("sm121a", "LDS_R_ARI", "S8", "sub_imm1", 24, 40, 2),
        ("sm121a", "LDS_R_ARURI", "S8", "sub_imm1", 24, 40, 2),
        ("sm121a", "LD_R_ARI", "128,E", "sub_imm1", 32, 32, 2),
        ("sm121a", "LD_R_ARI", "64,E", "sub_imm1", 32, 32, 2),
        ("sm121a", "LD_R_ARI", "E", "sub_imm1", 32, 32, 2),
        ("sm121a", "LD_R_dARI", "E,S8", "sub_imm2", 24, 40, 2),
        ("sm121a", "LD_R_dARI", "E,U8", "sub_imm2", 24, 40, 2),
        (
            "sm121a",
            "REDG_dARI_R",
            "E,GPU,MIN,S32,STRONG",
            "sub_imm2",
            24,
            40,
            1,
        ),
        ("sm121a", "ST_ARI_R", "128,E", "sub_imm1", 32, 32, 1),
        ("sm121a", "ST_ARI_R", "64,E", "sub_imm1", 32, 32, 1),
        ("sm121a", "ST_ARI_R", "E", "sub_imm1", 32, 32, 1),
        ("sm121a", "ST_dARI_R", "E,U8", "sub_imm2", 24, 40, 1),
    ];
    let mut n = 0;
    for (leg, key, mg, ext, bits, shift, tok) in geo {
        let (ext, tok, bits, shift) = (*ext, *tok, *bits, *shift);
        let j: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let row = j
            .pointer(&format!("/instructions/{key}/mod_groups/{mg}"))
            .unwrap_or_else(|| panic!("{leg} {key}[{mg}] missing"));
        let car: Vec<_> = row["fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|f| f["extraction"] == ext && f["token_idx"].as_i64().unwrap() as i32 == tok)
            .collect();
        assert_eq!(car.len(), 1, "{leg} {key}[{mg}] {ext} tok{tok} count");
        assert_eq!(
            car[0]["bits"].as_u64().unwrap(),
            bits,
            "{leg} {key}[{mg}] bits"
        );
        assert_eq!(
            car[0]["shift"].as_u64().unwrap(),
            shift,
            "{leg} {key}[{mg}] shift"
        );
        n += 1;
    }
    assert_eq!(n, geo.len(), "every grafted row checked");
}

/// t388_2: decode == vendor text, arb388b lattice witnesses x4 legs.
/// Glyph-norm tylko dla udokumentowanej klasy 399 (licznik audytu).
#[test]
fn t388_2_decode_witnesses_vendor_exact() {
    let wits: &[(&str, &str, &str, bool)] = &[
        (
            "sm100a",
            "0009e200099a022200e000001cbd7fae",
            "LDGSTS.E.LTC128B [R189+0xe00], [R28.64+UR34], P3",
            false,
        ),
        (
            "sm100a",
            "0009e200099a022200e000011cbd7fae",
            "LDGSTS.E.LTC128B [R189+0xe00], [R28.64+UR34+0x1], P3",
            false,
        ),
        (
            "sm100a",
            "0009e200099a022200e007ff1cbd7fae",
            "LDGSTS.E.LTC128B [R189+0xe00], [R28.64+UR34+0x7ff], P3",
            false,
        ),
        (
            "sm100a",
            "0009e200099a022200e008001cbd7fae",
            "LDGSTS.E.LTC128B [R189+0xe00], [R28.64+UR34+-0x800], P3",
            false,
        ),
        (
            "sm100a",
            "0009e200099a022200e00fff1cbd7fae",
            "LDGSTS.E.LTC128B [R189+0xe00], [R28.64+UR34+-0x1], P3",
            false,
        ),
        (
            "sm100a",
            "0009e200099a022200e00a001cbd7fae",
            "LDGSTS.E.LTC128B [R189+0xe00], [R28.64+UR34+-0x600], P3",
            false,
        ),
        (
            "sm100a",
            "0003e200099a06ff0018000024737fae",
            "LDGSTS.E.LTC128B.64 [R115+0x180], [R36.64], P3",
            false,
        ),
        (
            "sm100a",
            "0003e200099a06ff0018000124737fae",
            "LDGSTS.E.LTC128B.64 [R115+0x180], [R36.64+0x1], P3",
            false,
        ),
        (
            "sm100a",
            "0003e200099a06ff001807ff24737fae",
            "LDGSTS.E.LTC128B.64 [R115+0x180], [R36.64+0x7ff], P3",
            false,
        ),
        (
            "sm100a",
            "0003e200099a06ff0018080024737fae",
            "LDGSTS.E.LTC128B.64 [R115+0x180], [R36.64+-0x800], P3",
            false,
        ),
        (
            "sm100a",
            "0003e200099a06ff00180fff24737fae",
            "LDGSTS.E.LTC128B.64 [R115+0x180], [R36.64+-0x1], P3",
            false,
        ),
        (
            "sm100a",
            "0003e200099a06ff00180a0024737fae",
            "LDGSTS.E.LTC128B.64 [R115+0x180], [R36.64+-0x600], P3",
            false,
        ),
        (
            "sm100a",
            "0005e2000b9a021a00000000e2bd0dae",
            "@P0 LDGSTS.E.LTC128B [R189+UR26], [R226.64]",
            false,
        ),
        (
            "sm100a",
            "0005e2000b9a021a00000001e2bd0dae",
            "@P0 LDGSTS.E.LTC128B [R189+UR26], [R226.64+0x1]",
            false,
        ),
        (
            "sm100a",
            "0005e2000b9a021a000007ffe2bd0dae",
            "@P0 LDGSTS.E.LTC128B [R189+UR26], [R226.64+0x7ff]",
            false,
        ),
        (
            "sm100a",
            "0005e2000b9a021a00000800e2bd0dae",
            "@P0 LDGSTS.E.LTC128B [R189+UR26], [R226.64+-0x800]",
            false,
        ),
        (
            "sm100a",
            "0005e2000b9a021a00000fffe2bd0dae",
            "@P0 LDGSTS.E.LTC128B [R189+UR26], [R226.64+-0x1]",
            false,
        ),
        (
            "sm100a",
            "0005e2000b9a021a00000a00e2bd0dae",
            "@P0 LDGSTS.E.LTC128B [R189+UR26], [R226.64+-0x600]",
            false,
        ),
        (
            "sm100a",
            "0007f2000b9a0a0600880000e2dc2fae",
            "@P2 LDGSTS.E.LTC128B.128 [R220+0x880], [R226.64+UR6]",
            false,
        ),
        (
            "sm100a",
            "0007f2000b9a0a0600880001e2dc2fae",
            "@P2 LDGSTS.E.LTC128B.128 [R220+0x880], [R226.64+UR6+0x1]",
            false,
        ),
        (
            "sm100a",
            "0007f2000b9a0a06008807ffe2dc2fae",
            "@P2 LDGSTS.E.LTC128B.128 [R220+0x880], [R226.64+UR6+0x7ff]",
            false,
        ),
        (
            "sm100a",
            "0007f2000b9a0a0600880800e2dc2fae",
            "@P2 LDGSTS.E.LTC128B.128 [R220+0x880], [R226.64+UR6+-0x800]",
            false,
        ),
        (
            "sm100a",
            "0007f2000b9a0a0600880fffe2dc2fae",
            "@P2 LDGSTS.E.LTC128B.128 [R220+0x880], [R226.64+UR6+-0x1]",
            false,
        ),
        (
            "sm100a",
            "0007f2000b9a0a0600880a00e2dc2fae",
            "@P2 LDGSTS.E.LTC128B.128 [R220+0x880], [R226.64+UR6+-0x600]",
            false,
        ),
        (
            "sm100a",
            "000fe20008000200000000040a5d7984",
            "LDS.S8 R93, [R10+UR4]",
            false,
        ),
        (
            "sm100a",
            "000fe20008000200000001040a5d7984",
            "LDS.S8 R93, [R10+UR4+0x1]",
            false,
        ),
        (
            "sm100a",
            "000fe200080002007fffff040a5d7984",
            "LDS.S8 R93, [R10+UR4+0x7fffff]",
            false,
        ),
        (
            "sm100a",
            "000fe20008000200800000040a5d7984",
            "LDS.S8 R93, [R10+UR4+-0x800000]",
            true,
        ),
        (
            "sm100a",
            "000fe20008000200ffffff040a5d7984",
            "LDS.S8 R93, [R10+UR4+-0x1]",
            true,
        ),
        (
            "sm100a",
            "000fe20008000200a00000040a5d7984",
            "LDS.S8 R93, [R10+UR4+-0x600000]",
            true,
        ),
        (
            "sm100a",
            "002ea400001f450a00000008140a73a9",
            "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R20], R8, R10",
            false,
        ),
        (
            "sm100a",
            "002ea400001f450a00000108140a73a9",
            "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R20+0x1], R8, R10",
            false,
        ),
        (
            "sm100a",
            "002ea400001f450a7fffff08140a73a9",
            "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R20+0x7fffff], R8, R10",
            false,
        ),
        (
            "sm100a",
            "002ea400001f450a80000008140a73a9",
            "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R20+-0x800000], R8, R10",
            false,
        ),
        (
            "sm100a",
            "002ea400001f450affffff08140a73a9",
            "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R20+-0x1], R8, R10",
            false,
        ),
        (
            "sm100a",
            "002ea400001f450aa0000008140a73a9",
            "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R20+-0x600000], R8, R10",
            false,
        ),
        (
            "sm100a",
            "000fe2000d12e50a000000060800798e",
            "REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64], R6",
            false,
        ),
        (
            "sm100a",
            "000fe2000d12e50a000001060800798e",
            "REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64+0x1], R6",
            false,
        ),
        (
            "sm100a",
            "000fe2000d12e50a7fffff060800798e",
            "REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64+0x7fffff], R6",
            false,
        ),
        (
            "sm100a",
            "000fe2000d12e50a800000060800798e",
            "REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64+-0x800000], R6",
            false,
        ),
        (
            "sm100a",
            "000fe2000d12e50affffff060800798e",
            "REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64+-0x1], R6",
            false,
        ),
        (
            "sm100a",
            "000fe2000d12e50aa00000060800798e",
            "REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64+-0x600000], R6",
            false,
        ),
        (
            "sm100a",
            "0001e2000c115d0a0000000820008986",
            "@!P0 STG.E.128.STRONG.SYS desc[UR10][R32.64], R8",
            false,
        ),
        (
            "sm100a",
            "0001e2000c115d0a0000010820008986",
            "@!P0 STG.E.128.STRONG.SYS desc[UR10][R32.64+0x1], R8",
            false,
        ),
        (
            "sm100a",
            "0001e2000c115d0a7fffff0820008986",
            "@!P0 STG.E.128.STRONG.SYS desc[UR10][R32.64+0x7fffff], R8",
            false,
        ),
        (
            "sm100a",
            "0001e2000c115d0a8000000820008986",
            "@!P0 STG.E.128.STRONG.SYS desc[UR10][R32.64+-0x800000], R8",
            false,
        ),
        (
            "sm100a",
            "0001e2000c115d0affffff0820008986",
            "@!P0 STG.E.128.STRONG.SYS desc[UR10][R32.64+-0x1], R8",
            false,
        ),
        (
            "sm100a",
            "0001e2000c115d0aa000000820008986",
            "@!P0 STG.E.128.STRONG.SYS desc[UR10][R32.64+-0x600000], R8",
            false,
        ),
        (
            "sm100a",
            "0001e8000c1011100000001302007985",
            "ST.E.U8 desc[UR16][R2.64], R19",
            false,
        ),
        (
            "sm100a",
            "0001e8000c1011100000011302007985",
            "ST.E.U8 desc[UR16][R2.64+0x1], R19",
            false,
        ),
        (
            "sm100a",
            "0001e8000c1011107fffff1302007985",
            "ST.E.U8 desc[UR16][R2.64+0x7fffff], R19",
            false,
        ),
        (
            "sm100a",
            "0001e8000c1011108000001302007985",
            "ST.E.U8 desc[UR16][R2.64+-0x800000], R19",
            false,
        ),
        (
            "sm100a",
            "0001e8000c101110ffffff1302007985",
            "ST.E.U8 desc[UR16][R2.64+-0x1], R19",
            false,
        ),
        (
            "sm100a",
            "0001e8000c101110a000001302007985",
            "ST.E.U8 desc[UR16][R2.64+-0x600000], R19",
            false,
        ),
        (
            "sm100a",
            "000164000c1ef5000000000c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64]",
            false,
        ),
        (
            "sm100a",
            "000164000c1ef5000000010c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+0x1]",
            false,
        ),
        (
            "sm100a",
            "000164000c1ef5007fffff0c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+0x7fffff]",
            false,
        ),
        (
            "sm100a",
            "000164000c1ef5008000000c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+-0x800000]",
            false,
        ),
        (
            "sm100a",
            "000164000c1ef500ffffff0c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+-0x1]",
            false,
        ),
        (
            "sm100a",
            "000164000c1ef500a000000c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+-0x600000]",
            false,
        ),
        (
            "sm100a",
            "000222000c1f5d0000000018301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64]",
            false,
        ),
        (
            "sm100a",
            "000222000c1f5d0000000118301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+0x1]",
            false,
        ),
        (
            "sm100a",
            "000222000c1f5d007fffff18301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+0x7fffff]",
            false,
        ),
        (
            "sm100a",
            "000222000c1f5d0080000018301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+-0x800000]",
            false,
        ),
        (
            "sm100a",
            "000222000c1f5d00ffffff18301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+-0x1]",
            false,
        ),
        (
            "sm100a",
            "000222000c1f5d00a0000018301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+-0x600000]",
            false,
        ),
        (
            "sm100a",
            "0002a4000c1efd000000000e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64]",
            false,
        ),
        (
            "sm100a",
            "0002a4000c1efd000000010e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+0x1]",
            false,
        ),
        (
            "sm100a",
            "0002a4000c1efd007fffff0e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+0x7fffff]",
            false,
        ),
        (
            "sm100a",
            "0002a4000c1efd008000000e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+-0x800000]",
            false,
        ),
        (
            "sm100a",
            "0002a4000c1efd00ffffff0e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+-0x1]",
            false,
        ),
        (
            "sm100a",
            "0002a4000c1efd00a000000e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+-0x600000]",
            false,
        ),
        (
            "sm103a",
            "000fe20008000200000000040a5d7984",
            "LDS.S8 R93, [R10+UR4]",
            false,
        ),
        (
            "sm103a",
            "000fe20008000200000001040a5d7984",
            "LDS.S8 R93, [R10+UR4+0x1]",
            false,
        ),
        (
            "sm103a",
            "000fe200080002007fffff040a5d7984",
            "LDS.S8 R93, [R10+UR4+0x7fffff]",
            false,
        ),
        (
            "sm103a",
            "000fe20008000200800000040a5d7984",
            "LDS.S8 R93, [R10+UR4+-0x800000]",
            true,
        ),
        (
            "sm103a",
            "000fe20008000200ffffff040a5d7984",
            "LDS.S8 R93, [R10+UR4+-0x1]",
            true,
        ),
        (
            "sm103a",
            "000fe20008000200a00000040a5d7984",
            "LDS.S8 R93, [R10+UR4+-0x600000]",
            true,
        ),
        (
            "sm103a",
            "0001e2000c115d0a0000000820008986",
            "@!P0 STG.E.128.STRONG.SYS desc[UR10][R32.64], R8",
            false,
        ),
        (
            "sm103a",
            "0001e2000c115d0a0000010820008986",
            "@!P0 STG.E.128.STRONG.SYS desc[UR10][R32.64+0x1], R8",
            false,
        ),
        (
            "sm103a",
            "0001e2000c115d0a7fffff0820008986",
            "@!P0 STG.E.128.STRONG.SYS desc[UR10][R32.64+0x7fffff], R8",
            false,
        ),
        (
            "sm103a",
            "0001e2000c115d0a8000000820008986",
            "@!P0 STG.E.128.STRONG.SYS desc[UR10][R32.64+-0x800000], R8",
            false,
        ),
        (
            "sm103a",
            "0001e2000c115d0affffff0820008986",
            "@!P0 STG.E.128.STRONG.SYS desc[UR10][R32.64+-0x1], R8",
            false,
        ),
        (
            "sm103a",
            "0001e2000c115d0aa000000820008986",
            "@!P0 STG.E.128.STRONG.SYS desc[UR10][R32.64+-0x600000], R8",
            false,
        ),
        (
            "sm103a",
            "0001e8000c1011100000001302007985",
            "ST.E.U8 desc[UR16][R2.64], R19",
            false,
        ),
        (
            "sm103a",
            "0001e8000c1011100000011302007985",
            "ST.E.U8 desc[UR16][R2.64+0x1], R19",
            false,
        ),
        (
            "sm103a",
            "0001e8000c1011107fffff1302007985",
            "ST.E.U8 desc[UR16][R2.64+0x7fffff], R19",
            false,
        ),
        (
            "sm103a",
            "0001e8000c1011108000001302007985",
            "ST.E.U8 desc[UR16][R2.64+-0x800000], R19",
            false,
        ),
        (
            "sm103a",
            "0001e8000c101110ffffff1302007985",
            "ST.E.U8 desc[UR16][R2.64+-0x1], R19",
            false,
        ),
        (
            "sm103a",
            "0001e8000c101110a000001302007985",
            "ST.E.U8 desc[UR16][R2.64+-0x600000], R19",
            false,
        ),
        (
            "sm103a",
            "000164000c1ef5000000000c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64]",
            false,
        ),
        (
            "sm103a",
            "000164000c1ef5000000010c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+0x1]",
            false,
        ),
        (
            "sm103a",
            "000164000c1ef5007fffff0c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+0x7fffff]",
            false,
        ),
        (
            "sm103a",
            "000164000c1ef5008000000c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+-0x800000]",
            false,
        ),
        (
            "sm103a",
            "000164000c1ef500ffffff0c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+-0x1]",
            false,
        ),
        (
            "sm103a",
            "000164000c1ef500a000000c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+-0x600000]",
            false,
        ),
        (
            "sm103a",
            "000222000c1f5d0000000018301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64]",
            false,
        ),
        (
            "sm103a",
            "000222000c1f5d0000000118301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+0x1]",
            false,
        ),
        (
            "sm103a",
            "000222000c1f5d007fffff18301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+0x7fffff]",
            false,
        ),
        (
            "sm103a",
            "000222000c1f5d0080000018301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+-0x800000]",
            false,
        ),
        (
            "sm103a",
            "000222000c1f5d00ffffff18301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+-0x1]",
            false,
        ),
        (
            "sm103a",
            "000222000c1f5d00a0000018301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+-0x600000]",
            false,
        ),
        (
            "sm103a",
            "0002a4000c1efd000000000e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64]",
            false,
        ),
        (
            "sm103a",
            "0002a4000c1efd000000010e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+0x1]",
            false,
        ),
        (
            "sm103a",
            "0002a4000c1efd007fffff0e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+0x7fffff]",
            false,
        ),
        (
            "sm103a",
            "0002a4000c1efd008000000e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+-0x800000]",
            false,
        ),
        (
            "sm103a",
            "0002a4000c1efd00ffffff0e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+-0x1]",
            false,
        ),
        (
            "sm103a",
            "0002a4000c1efd00a000000e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+-0x600000]",
            false,
        ),
        (
            "sm120",
            "000fe20008000200000000040a5d7984",
            "LDS.S8 R93, [R10+UR4]",
            false,
        ),
        (
            "sm120",
            "000fe20008000200000001040a5d7984",
            "LDS.S8 R93, [R10+UR4+0x1]",
            false,
        ),
        (
            "sm120",
            "000fe200080002007fffff040a5d7984",
            "LDS.S8 R93, [R10+UR4+0x7fffff]",
            false,
        ),
        (
            "sm120",
            "000fe20008000200800000040a5d7984",
            "LDS.S8 R93, [R10+UR4+-0x800000]",
            true,
        ),
        (
            "sm120",
            "000fe20008000200ffffff040a5d7984",
            "LDS.S8 R93, [R10+UR4+-0x1]",
            true,
        ),
        (
            "sm120",
            "000fe20008000200a00000040a5d7984",
            "LDS.S8 R93, [R10+UR4+-0x600000]",
            true,
        ),
        (
            "sm120",
            "000fe2000d12e50a000000060800798e",
            "REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64], R6",
            false,
        ),
        (
            "sm120",
            "000fe2000d12e50a000001060800798e",
            "REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64+0x1], R6",
            false,
        ),
        (
            "sm120",
            "000fe2000d12e50a7fffff060800798e",
            "REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64+0x7fffff], R6",
            false,
        ),
        (
            "sm120",
            "000fe2000d12e50a800000060800798e",
            "REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64+-0x800000], R6",
            false,
        ),
        (
            "sm120",
            "000fe2000d12e50affffff060800798e",
            "REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64+-0x1], R6",
            false,
        ),
        (
            "sm120",
            "000fe2000d12e50aa00000060800798e",
            "REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64+-0x600000], R6",
            false,
        ),
        (
            "sm120",
            "0021e4000f12e106000000050200098e",
            "@P0 REDG.E.OR.STRONG.GPU desc[UR6][R2.64], R5",
            false,
        ),
        (
            "sm120",
            "0021e4000f12e106000001050200098e",
            "@P0 REDG.E.OR.STRONG.GPU desc[UR6][R2.64+0x1], R5",
            false,
        ),
        (
            "sm120",
            "0021e4000f12e1067fffff050200098e",
            "@P0 REDG.E.OR.STRONG.GPU desc[UR6][R2.64+0x7fffff], R5",
            false,
        ),
        (
            "sm120",
            "0021e4000f12e106800000050200098e",
            "@P0 REDG.E.OR.STRONG.GPU desc[UR6][R2.64+-0x800000], R5",
            false,
        ),
        (
            "sm120",
            "0021e4000f12e106ffffff050200098e",
            "@P0 REDG.E.OR.STRONG.GPU desc[UR6][R2.64+-0x1], R5",
            false,
        ),
        (
            "sm120",
            "0021e4000f12e106a00000050200098e",
            "@P0 REDG.E.OR.STRONG.GPU desc[UR6][R2.64+-0x600000], R5",
            false,
        ),
        (
            "sm120",
            "004fe2000c92e306000000030400098e",
            "@P0 REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64], R3",
            false,
        ),
        (
            "sm120",
            "004fe2000c92e306000001030400098e",
            "@P0 REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64+0x1], R3",
            false,
        ),
        (
            "sm120",
            "004fe2000c92e3067fffff030400098e",
            "@P0 REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64+0x7fffff], R3",
            false,
        ),
        (
            "sm120",
            "004fe2000c92e306800000030400098e",
            "@P0 REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64+-0x800000], R3",
            false,
        ),
        (
            "sm120",
            "004fe2000c92e306ffffff030400098e",
            "@P0 REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64+-0x1], R3",
            false,
        ),
        (
            "sm120",
            "004fe2000c92e306a00000030400098e",
            "@P0 REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64+-0x600000], R3",
            false,
        ),
        (
            "sm120",
            "000164000c1ef5000000000c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64]",
            false,
        ),
        (
            "sm120",
            "000164000c1ef5000000010c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+0x1]",
            false,
        ),
        (
            "sm120",
            "000164000c1ef5007fffff0c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+0x7fffff]",
            false,
        ),
        (
            "sm120",
            "000164000c1ef5008000000c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+-0x800000]",
            false,
        ),
        (
            "sm120",
            "000164000c1ef500ffffff0c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+-0x1]",
            false,
        ),
        (
            "sm120",
            "000164000c1ef500a000000c0c217981",
            "LDG.E.U16.STRONG.GPU R33, desc[UR12][R12.64+-0x600000]",
            false,
        ),
        (
            "sm120",
            "000222000c1f5d0000000018301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64]",
            false,
        ),
        (
            "sm120",
            "000222000c1f5d0000000118301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+0x1]",
            false,
        ),
        (
            "sm120",
            "000222000c1f5d007fffff18301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+0x7fffff]",
            false,
        ),
        (
            "sm120",
            "000222000c1f5d0080000018301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+-0x800000]",
            false,
        ),
        (
            "sm120",
            "000222000c1f5d00ffffff18301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+-0x1]",
            false,
        ),
        (
            "sm120",
            "000222000c1f5d00a0000018301c7981",
            "LDG.E.128.STRONG.SYS R28, desc[UR24][R48.64+-0x600000]",
            false,
        ),
        (
            "sm120",
            "0002a4000c1efd000000000e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64]",
            false,
        ),
        (
            "sm120",
            "0002a4000c1efd000000010e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+0x1]",
            false,
        ),
        (
            "sm120",
            "0002a4000c1efd007fffff0e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+0x7fffff]",
            false,
        ),
        (
            "sm120",
            "0002a4000c1efd008000000e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+-0x800000]",
            false,
        ),
        (
            "sm120",
            "0002a4000c1efd00ffffff0e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+-0x1]",
            false,
        ),
        (
            "sm120",
            "0002a4000c1efd00a000000e26287981",
            "LDG.E.128.STRONG.GPU R40, desc[UR14][R38.64+-0x600000]",
            false,
        ),
        (
            "sm121a",
            "0201e400001009060000000040007385",
            "ST.E [R64], R6",
            false,
        ),
        (
            "sm121a",
            "0201e400001009060000000140007385",
            "ST.E [R64+0x1], R6",
            false,
        ),
        (
            "sm121a",
            "0201e400001009067fffffff40007385",
            "ST.E [R64+0x7fffffff], R6",
            false,
        ),
        (
            "sm121a",
            "0201e400001009068000000040007385",
            "ST.E [R64+-0x80000000], R6",
            false,
        ),
        (
            "sm121a",
            "0201e40000100906ffffffff40007385",
            "ST.E [R64+-0x1], R6",
            false,
        ),
        (
            "sm121a",
            "0201e40000100906a000000040007385",
            "ST.E [R64+-0x60000000], R6",
            false,
        ),
        (
            "sm121a",
            "0203e20000100d5400000000cc007385",
            "ST.E.128 [R204], R84",
            false,
        ),
        (
            "sm121a",
            "0203e20000100d5400000001cc007385",
            "ST.E.128 [R204+0x1], R84",
            false,
        ),
        (
            "sm121a",
            "0203e20000100d547fffffffcc007385",
            "ST.E.128 [R204+0x7fffffff], R84",
            false,
        ),
        (
            "sm121a",
            "0203e20000100d5480000000cc007385",
            "ST.E.128 [R204+-0x80000000], R84",
            false,
        ),
        (
            "sm121a",
            "0203e20000100d54ffffffffcc007385",
            "ST.E.128 [R204+-0x1], R84",
            false,
        ),
        (
            "sm121a",
            "0203e20000100d54a0000000cc007385",
            "ST.E.128 [R204+-0x60000000], R84",
            false,
        ),
        (
            "sm121a",
            "000fe80000000200000000000a5b7984",
            "LDS.S8 R91, [R10]",
            false,
        ),
        (
            "sm121a",
            "000fe80000000200000001000a5b7984",
            "LDS.S8 R91, [R10+0x1]",
            false,
        ),
        (
            "sm121a",
            "000fe800000002007fffff000a5b7984",
            "LDS.S8 R91, [R10+0x7fffff]",
            false,
        ),
        (
            "sm121a",
            "000fe80000000200800000000a5b7984",
            "LDS.S8 R91, [R10+-0x800000]",
            false,
        ),
        (
            "sm121a",
            "000fe80000000200ffffff000a5b7984",
            "LDS.S8 R91, [R10+-0x1]",
            false,
        ),
        (
            "sm121a",
            "000fe80000000200a00000000a5b7984",
            "LDS.S8 R91, [R10+-0x600000]",
            false,
        ),
        (
            "sm121a",
            "000f680000100d000000000064647980",
            "LD.E.128 R100, [R100]",
            false,
        ),
        (
            "sm121a",
            "000f680000100d000000000164647980",
            "LD.E.128 R100, [R100+0x1]",
            false,
        ),
        (
            "sm121a",
            "000f680000100d007fffffff64647980",
            "LD.E.128 R100, [R100+0x7fffffff]",
            false,
        ),
        (
            "sm121a",
            "000f680000100d008000000064647980",
            "LD.E.128 R100, [R100+-0x80000000]",
            false,
        ),
        (
            "sm121a",
            "000f680000100d00ffffffff64647980",
            "LD.E.128 R100, [R100+-0x1]",
            false,
        ),
        (
            "sm121a",
            "000f680000100d00a000000064647980",
            "LD.E.128 R100, [R100+-0x60000000]",
            false,
        ),
        (
            "sm121a",
            "000fe20008000200000000040a5d7984",
            "LDS.S8 R93, [R10+UR4]",
            false,
        ),
        (
            "sm121a",
            "000fe20008000200000001040a5d7984",
            "LDS.S8 R93, [R10+UR4+0x1]",
            false,
        ),
        (
            "sm121a",
            "000fe200080002007fffff040a5d7984",
            "LDS.S8 R93, [R10+UR4+0x7fffff]",
            false,
        ),
        (
            "sm121a",
            "000fe20008000200800000040a5d7984",
            "LDS.S8 R93, [R10+UR4+-0x800000]",
            true,
        ),
        (
            "sm121a",
            "000fe20008000200ffffff040a5d7984",
            "LDS.S8 R93, [R10+UR4+-0x1]",
            true,
        ),
        (
            "sm121a",
            "000fe20008000200a00000040a5d7984",
            "LDS.S8 R93, [R10+UR4+-0x600000]",
            true,
        ),
        (
            "sm121a",
            "002ea400001f450a00000008140a73a9",
            "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R20], R8, R10",
            false,
        ),
        (
            "sm121a",
            "002ea400001f450a00000108140a73a9",
            "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R20+0x1], R8, R10",
            false,
        ),
        (
            "sm121a",
            "002ea400001f450a7fffff08140a73a9",
            "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R20+0x7fffff], R8, R10",
            false,
        ),
        (
            "sm121a",
            "002ea400001f450a80000008140a73a9",
            "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R20+-0x800000], R8, R10",
            false,
        ),
        (
            "sm121a",
            "002ea400001f450affffff08140a73a9",
            "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R20+-0x1], R8, R10",
            false,
        ),
        (
            "sm121a",
            "002ea400001f450aa0000008140a73a9",
            "ATOMG.E.CAS.64.STRONG.SYS PT, R10, [R20+-0x600000], R8, R10",
            false,
        ),
        (
            "sm121a",
            "000ea400001f410500000004080573a9",
            "ATOMG.E.CAS.STRONG.SYS PT, R5, [R8], R4, R5",
            false,
        ),
        (
            "sm121a",
            "000ea400001f410500000104080573a9",
            "ATOMG.E.CAS.STRONG.SYS PT, R5, [R8+0x1], R4, R5",
            false,
        ),
        (
            "sm121a",
            "000ea400001f41057fffff04080573a9",
            "ATOMG.E.CAS.STRONG.SYS PT, R5, [R8+0x7fffff], R4, R5",
            false,
        ),
        (
            "sm121a",
            "000ea400001f410580000004080573a9",
            "ATOMG.E.CAS.STRONG.SYS PT, R5, [R8+-0x800000], R4, R5",
            false,
        ),
        (
            "sm121a",
            "000ea400001f4105ffffff04080573a9",
            "ATOMG.E.CAS.STRONG.SYS PT, R5, [R8+-0x1], R4, R5",
            false,
        ),
        (
            "sm121a",
            "000ea400001f4105a0000004080573a9",
            "ATOMG.E.CAS.STRONG.SYS PT, R5, [R8+-0x600000], R4, R5",
            false,
        ),
        (
            "sm121a",
            "004fe2000c92e306000000030400098e",
            "@P0 REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64], R3",
            false,
        ),
        (
            "sm121a",
            "004fe2000c92e306000001030400098e",
            "@P0 REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64+0x1], R3",
            false,
        ),
        (
            "sm121a",
            "004fe2000c92e3067fffff030400098e",
            "@P0 REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64+0x7fffff], R3",
            false,
        ),
        (
            "sm121a",
            "004fe2000c92e306800000030400098e",
            "@P0 REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64+-0x800000], R3",
            false,
        ),
        (
            "sm121a",
            "004fe2000c92e306ffffff030400098e",
            "@P0 REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64+-0x1], R3",
            false,
        ),
        (
            "sm121a",
            "004fe2000c92e306a00000030400098e",
            "@P0 REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64+-0x600000], R3",
            false,
        ),
        (
            "sm121a",
            "000ea4000c1013000000000808087980",
            "LD.E.S8 R8, desc[UR8][R8.64]",
            false,
        ),
        (
            "sm121a",
            "000ea4000c1013000000010808087980",
            "LD.E.S8 R8, desc[UR8][R8.64+0x1]",
            false,
        ),
        (
            "sm121a",
            "000ea4000c1013007fffff0808087980",
            "LD.E.S8 R8, desc[UR8][R8.64+0x7fffff]",
            false,
        ),
        (
            "sm121a",
            "000ea4000c1013008000000808087980",
            "LD.E.S8 R8, desc[UR8][R8.64+-0x800000]",
            false,
        ),
        (
            "sm121a",
            "000ea4000c101300ffffff0808087980",
            "LD.E.S8 R8, desc[UR8][R8.64+-0x1]",
            false,
        ),
        (
            "sm121a",
            "000ea4000c101300a000000808087980",
            "LD.E.S8 R8, desc[UR8][R8.64+-0x600000]",
            false,
        ),
    ];
    let mut glyph_audits = 0usize;
    for (leg, hexw, vendor, glyph399) in wits {
        let t = tab(leg);
        let got = dec(&t, w(hexw)).unwrap_or_else(|| panic!("{leg} {hexw} HOLE"));
        if *glyph399 {
            glyph_audits += 1;
            assert!(vendor.contains("+-0x"), "{leg} {hexw} pin drift (class)");
            assert_eq!(glyph_norm(vendor), got, "{leg} {hexw} glyph-class");
        } else {
            assert_eq!(*vendor, got, "{leg} {hexw} != vendor");
        }
    }
    assert!(
        glyph_audits == 12,
        "399 glyph class audit set: {glyph_audits}"
    );
}

/// t388_3: UGETNEXTWORKID.BROADCAST -- para [URv],[URv+1] z jednego
/// pola 8b@24 (arm SubURm1) + junk-band [16..24)+[32..64) relax == vendor.
#[test]
fn t388_3_uget_pair_and_junk_relax() {
    let wits: &[(&str, &str, &str)] = &[
        (
            "sm100a",
            "000fec000800010000000000000003ca",
            "@UP0 UGETNEXTWORKID.BROADCAST [UR0], [UR1]",
        ),
        (
            "sm100a",
            "000fec000800010000000000010003ca",
            "@UP0 UGETNEXTWORKID.BROADCAST [UR1], [UR2]",
        ),
        (
            "sm100a",
            "000fec0008000100000000007f0003ca",
            "@UP0 UGETNEXTWORKID.BROADCAST [UR127], [UR128]",
        ),
        (
            "sm100a",
            "000fec000800010000000000c80003ca",
            "@UP0 UGETNEXTWORKID.BROADCAST [UR200], [UR201]",
        ),
        (
            "sm100a",
            "000fec0008000100ffffffff06ff03ca",
            "@UP0 UGETNEXTWORKID.BROADCAST [UR6], [UR7]",
        ),
        (
            "sm103a",
            "000fec000800010000000000000003ca",
            "@UP0 UGETNEXTWORKID.BROADCAST [UR0], [UR1]",
        ),
        (
            "sm103a",
            "000fec000800010000000000010003ca",
            "@UP0 UGETNEXTWORKID.BROADCAST [UR1], [UR2]",
        ),
        (
            "sm103a",
            "000fec0008000100000000007f0003ca",
            "@UP0 UGETNEXTWORKID.BROADCAST [UR127], [UR128]",
        ),
        (
            "sm103a",
            "000fec000800010000000000c80003ca",
            "@UP0 UGETNEXTWORKID.BROADCAST [UR200], [UR201]",
        ),
        (
            "sm103a",
            "000fec0008000100ffffffff06ff03ca",
            "@UP0 UGETNEXTWORKID.BROADCAST [UR6], [UR7]",
        ),
    ];
    for (leg, hexw, vendor) in wits {
        let t = tab(leg);
        let got = dec(&t, w(hexw)).unwrap_or_else(|| panic!("{leg} {hexw} HOLE"));
        assert_eq!(*vendor, got, "{leg} {hexw} != vendor (UGETNEXT)");
    }
}

/// t388_4: sm121a LDC/LDCU cAI '' -- bank 5b@[54..59) + signed 16/17b
/// offset (cm16_off/cm17_off) + junk-band [32..L)+[59..64) relax.
#[test]
fn t388_4_c121a_bank_sign_junk() {
    let wits: &[(&str, &str, &str)] = &[
        (
            "sm121a",
            "000fe2000000080000000000ff017b82",
            "LDC R1, c[0x0][RZ]",
        ),
        (
            "sm121a",
            "000fe2000000080000000040ff017b82",
            "LDC R1, c[0x0][0x1]",
        ),
        (
            "sm121a",
            "000fe20000000800001fffc0ff017b82",
            "LDC R1, c[0x0][0x7fff]",
        ),
        (
            "sm121a",
            "000fe2000000080000200000ff017b82",
            "LDC R1, c[0x0][-0x8000]",
        ),
        (
            "sm121a",
            "000fe20000000800003fffc0ff017b82",
            "LDC R1, c[0x0][-0x1]",
        ),
        (
            "sm121a",
            "000fe2000000080000400000ff017b82",
            "LDC R1, c[0x1][RZ]",
        ),
        (
            "sm121a",
            "000fe2000000080007c00000ff017b82",
            "LDC R1, c[0x1f][RZ]",
        ),
        (
            "sm121a",
            "000fe20000000800f800df3fff017b82",
            "LDC R1, c[0x0][0x37c]",
        ),
        (
            "sm121a",
            "000e24000800080000000000ff0477ac",
            "LDCU UR4, c[0x0][URZ]",
        ),
        (
            "sm121a",
            "000e24000800080000000020ff0477ac",
            "LDCU UR4, c[0x0][0x1]",
        ),
        (
            "sm121a",
            "000e240008000800001fffe0ff0477ac",
            "LDCU UR4, c[0x0][0xffff]",
        ),
        (
            "sm121a",
            "000e24000800080000200000ff0477ac",
            "LDCU UR4, c[0x0][-0x10000]",
        ),
        (
            "sm121a",
            "000e240008000800003fffe0ff0477ac",
            "LDCU UR4, c[0x0][-0x1]",
        ),
        (
            "sm121a",
            "000e24000800080000400000ff0477ac",
            "LDCU UR4, c[0x1][URZ]",
        ),
        (
            "sm121a",
            "000e24000800080007c00000ff0477ac",
            "LDCU UR4, c[0x1f][URZ]",
        ),
        (
            "sm121a",
            "000e240008000800f800721fff0477ac",
            "LDCU UR4, c[0x0][0x390]",
        ),
    ];
    for (leg, hexw, vendor) in wits {
        let t = tab(leg);
        let got = dec(&t, w(hexw)).unwrap_or_else(|| panic!("{leg} {hexw} HOLE"));
        assert_eq!(*vendor, got, "{leg} {hexw} != vendor (cAI)");
    }
}

/// t388_5 (residua loud): 398-kand -- sm121a cAI adres [24..32) z
/// indexem zanegowanym (vendor R254/UR254 dla wartosci 1) NIE jest
/// wspierany przez silnik; bare '' rows dalej drukuja fallback '?cAURI'
/// albo pomijaja skladowa. Pin strzeze LOUD-stanu az do wlasnego fixa.
#[test]
fn t388_5_resid_398_loud() {
    // LDCU '' z b24=1: vendor 'c[0x0][UR254+0x390]', silnik '?cAURI'-fallback
    let t = tab("sm121a");
    // LDCU_UR_cAI '' anchor word z b24=1 (maszynowo z arb388 rep-word)
    let word = w("000e24000800080000007200ff0477ac");
    let got = dec(&t, word);
    assert_ne!(
        got.as_deref(),
        Some("LDCU UR4, c[0x0][UR254+0x390]"),
        "398-kand: [24..32) index decl landed -- zamknij residuum, nie ten pin"
    );
    // 400-kand: sm121a LD ARI [64..67) vendor pred decl (b64 -> ', P6')
    let w400 = w("000f680000100d010000000064647980");
    let got400 = dec(&t, w400);
    assert_ne!(
        got400.as_deref(),
        Some("LD.E.128 R100, [R100], P6"),
        "400-kand: 121a ARI pred@[64..67) landed -- zamknij residuum"
    );
    // sm121a LDS_R_ARI|S8 [64..72) vendor-inert vs silnik '?AR' fallback
    let w401 = w("000fe80000000201000000000a5b7984");
    let got401 = dec(&t, w401);
    assert_ne!(
        got401.as_deref(),
        Some("LDS.S8 R91, [R10]"),
        "121a LDS S8 [64..72) relax landed -- zamknij residuum"
    );
}

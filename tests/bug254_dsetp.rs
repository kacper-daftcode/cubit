//! BUG-254 (F2-iter130, loop5/blind front2, 2026-08-28): sm121a DSETP =
//! era-generated debris. 30 typed keys (DSETP.<CMP>.<BOOL>_*) + 5 generic
//! shells (R_R_P 9-mg partial / R_UR_P 2-field / R_FI_P 8-field / II_P,L_P
//! junk sharing the UR and_base) produced, on the sm121a leg only:
//! 2,434 HOLE + 2,670 DIFF of 38,317 uniq corpus DSETP words (dec254,
//! law251 census, 2,406-cubin battery, nvdisasm 13.3.73): boolop-flip
//! (vendor OR -> our AND, 660), UR-misroute (UR10 -> 'UR5' half-read +
//! tail pred -> 'UR0', 836), reg-bleed (era reg 8b@26 -> 'R193' for R4 +
//! tail-neg drop, FI imm -> '|R0|', 1,174). Encoder hazard: era 'AND,EQ'
//! encoded 'DSETP.EQ.AND P0, PT, R22, RZ, !P0' into bits re-decoding as
//! 'R252, P0' (tail !P + RZ silently mangled); LT.OR/UR-FI forms had no
//! entry. Ablation (pub-e01f226): deleting the 30 typed keys OR the II/L
//! shells changed NOTHING (zero routing) -> wholesale replacement.
//!
//! Fix (canonical 9fd3368): delete 32 era keys; DSETP_P_P_R_R_P (25 mgs) /
//! _R_UR_P (16) / _R_FI_P (14) mod_groups = byte-copy of sm103a donor rows;
//! key top-levels stay sm121a-native; sync_table ratchet SM121A 467->498
//! (31 grafted mgs carry the proven era-2aE donor ctrl template; deleted
//! era carried none). Laws arb254 (raw -b probes, models SM121a==SM103a on
//! every printed-text probe; work/bug254/arb254/arb254.json): reg tok3
//! 8b@24 / tok4 8b@32 (era @26 disproven: bit26-only -> vendor 'R4'),
//! preds 3b@81/84/87 + neg@90, bool b74=OR b75=XOR both=INVALID3, cmp
//! 4b@[79:76] 16-map, ureg 8b@32 (bit33-only -> 'UR2'), b91 mandatory on
//! UR form. Donor-side/owner registrations (NOT this fix): vendor prints
//! extra sign windows the donor rows lack fields for on AND,EQ (tok3
//! neg@72/abs@73, tok4 abs@62) and UR neg@63/abs@62 -> 259-kand; XOR/inv3
//! decode divergences on corpus-zero words (donor legs identical);
//! reuse-b122 raw SM121a print suppression vs SM103a '.reuse' = 256-sib
//! [owner policy]; graft keeps donor fields (law-parity: 693 R_R + 55 UR
//! corpus words with b122 keep '.reuse').
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

// arb254 witnesses (full 128-bit law251 corpus words).
const W_A: u128 = 0x8fcc0004702000000000ff1600722a; // DSETP.EQ.AND P0, PT, R22, RZ, !P0
const W_B: u128 = 0xfcc0000701400000000181a00a22a; // @!P2 DSETP.LT.OR P0, PT, R26, R24, P0
const W_C: u128 = 0x1fe4000bf0d0000000000aff007e2a; // DSETP.NEU.AND P0, PT, RZ, UR10, PT
const W_D: u128 = 82346584212294211629625602505471018; // DSETP.GE.AND P1, PT, R2, 16777216, PT
const W_BIT26: u128 = (W_A & !((0xFFu128 << 24) | (0xFFu128 << 32))) | (1u128 << 26);
const W_BIT33: u128 = (W_C & !(0xFFu128 << 32)) | (1u128 << 33);

#[test]
fn t254_1_structure() {
    // sm121a DSETP inventory: exactly the 3 generic keys, zero typed shells, zero II/L junk.
    // Session T-20 (2026-11-08): the three keys carry the measured lattice (48 groups each = 16 comparisons
    // x 3 booleans, `fsetp-dsetp-family-2026-11-06`, tools/probes/re_sm120_fsetp_dsetp.py --arch SM121 --
    // the sm120 law of 2026-11-06 holds word for word on -b SM121), no longer the 2026-08-28 byte-copies of
    // the sm103a donor rows (25 / 16 / 14 harvest groups): every donor group is one of the 48, the measured
    // row carries the donor's groups as a subset. tests/sm121a_fsetp_dsetp.rs pins the rows themselves.
    let t = tab("sm121a");
    let donor = tab("sm103a");
    let keys: Vec<&String> = t
        .entries
        .keys()
        .filter(|k| k.starts_with("DSETP"))
        .collect();
    assert_eq!(
        keys.len(),
        3,
        "sm121a DSETP key inventory drifted: {keys:?}"
    );
    for (k, donor_mgs) in [
        ("DSETP_P_P_R_R_P", 25usize),
        ("DSETP_P_P_R_UR_P", 16),
        ("DSETP_P_P_R_FI_P", 14),
    ] {
        let row = t.entries.get(k).unwrap_or_else(|| panic!("{k} missing"));
        assert_eq!(row.mod_groups.len(), 48, "{k} mg count (the measured lattice, T-20)");
        let drow = donor.entries.get(k).unwrap();
        assert_eq!(drow.mod_groups.len(), donor_mgs, "{k}: the sm103a donor's harvest groups (a T1 item of that table)");
        for mg in drow.mod_groups.keys() {
            assert!(row.mod_groups.contains_key(mg), "{k}::{mg}: a donor group outside the measured lattice");
        }
    }
    for arch in ["sm100a", "sm103a", "sm120"] {
        // donors carry exactly 3 DSETP keys too (sanity anchor).
        let d = tab(arch);
        assert_eq!(
            d.entries.keys().filter(|k| k.starts_with("DSETP")).count(),
            3,
            "{arch}"
        );
    }
}

#[test]
fn t254_2_decode_vendor_true() {
    // arb254 witnesses decode == vendor glyph on all four legs.
    let cases: &[(u128, &str)] = &[
        (W_A, "DSETP.EQ.AND P0, PT, R22, RZ, !P0"),
        (W_BIT26, "DSETP.EQ.AND P0, PT, R4, R0, !P0"), // era @26 disproven
        (W_B, "@!P2 DSETP.LT.OR P0, PT, R26, R24, P0"),
        (
            W_B & !(1u128 << 74),
            "@!P2 DSETP.LT.AND P0, PT, R26, R24, P0",
        ),
        (W_A ^ (1u128 << 74), "DSETP.EQ.OR P0, PT, R22, RZ, !P0"),
        (W_C, "DSETP.NEU.AND P0, PT, RZ, UR10, PT"),
        (W_C & !(0xFFu128 << 32), "DSETP.NEU.AND P0, PT, RZ, UR0, PT"),
        (W_BIT33, "DSETP.NEU.AND P0, PT, RZ, UR2, PT"),
        (W_D, "DSETP.GE.AND P1, PT, R2, 16777216, PT"),
    ];
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (i, (w, want)) in cases.iter().enumerate() {
            let got = dec(&t, *w).unwrap_or_else(|| panic!("{arch} case{i} HOLE"));
            assert_eq!(got, *want, "{arch} case{i} decode != vendor (arb254)");
        }
    }
}

#[test]
fn t254_3_encode_payload_exact() {
    let t = tab("sm121a");
    let cases: &[(&str, u128)] = &[
        ("DSETP.EQ.AND P0, PT, R22, RZ, !P0", W_A),
        (
            "DSETP.LT.OR P0, PT, R26, R24, P0",
            (W_B & !(0xFu128 << 12)) | (7u128 << 12),
        ), // no guard = PT code
        ("DSETP.NEU.AND P0, PT, RZ, UR10, PT", W_C),
        ("DSETP.GE.AND P1, PT, R2, 16777216, PT", W_D),
        (
            "DSETP.GT.AND P0, PT, R50, R44, PT",
            0xfe40003f040000000002c3200722a,
        ),
    ];
    for (i, (text, w)) in cases.iter().enumerate() {
        assert_eq!(enc(&t, text) & M96, w & M96, "case{i} encode payload drift");
    }
}

#[test]
fn t254_4_roundtrip() {
    let texts = [
        "DSETP.EQ.AND P0, PT, R22, RZ, !P0",
        "DSETP.LT.OR P0, PT, R26, R24, P0",
        "DSETP.NEU.AND P0, PT, RZ, UR10, PT",
        "DSETP.GEU.XOR P1, PT, R8, R30, P3",
        "DSETP.GE.AND P1, PT, R2, 16777216, PT",
        "DSETP.GT.AND P0, PT, R50, R44, PT",
    ];
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (i, text) in texts.iter().enumerate() {
            let w = enc(&t, text);
            let got = dec(&t, w).unwrap_or_else(|| panic!("{arch} text{i} rt HOLE"));
            assert_eq!(&got, text, "{arch} text{i} roundtrip");
        }
    }
    // word -> text -> word (payload) for the witness set.
    for arch in ["sm100a", "sm103a", "sm120", "sm121a"] {
        let t = tab(arch);
        for (i, w) in [W_A, W_C, W_D].iter().enumerate() {
            let s = dec(&t, *w).unwrap();
            // guard prefix is not re-encodable via this helper; strip it.
            let s2 = s.split(' ').collect::<Vec<_>>();
            let s2 = if s.starts_with('@') {
                s2[1..].join(" ")
            } else {
                s
            };
            let w2 = enc(&t, &s2);
            assert_eq!(w2 & M96, w & M96, "{arch} word{case} payload rt", case = i);
        }
    }
}

#[test]
fn t254_5_sentinels() {
    // (a) b91 mandatory on UR form: cleared -> fail-closed HOLE (vendor rc=1).
    // (b) reuse-b122 prints '.reuse' (law-parity; raw SM121a suppresses =
    //     256-sibling arch divergence [owner policy]) -- four legs identical.
    // (c) b75/both-set decode stays 4-leg identical (vendor: XOR/INVALID3;
    //     donor-side divergence, corpus-zero, 259-kand).
    let tables: Vec<IsaTable> = ["sm100a", "sm103a", "sm120", "sm121a"]
        .iter()
        .map(|a| tab(a))
        .collect();
    for t in &tables {
        assert!(
            dec(t, W_C & !(1u128 << 91)).is_none(),
            "b91-clear must stay fail-closed"
        );
    }
    let r122: Vec<_> = tables
        .iter()
        .map(|t| dec(t, W_C ^ (1u128 << 122)).unwrap())
        .collect();
    assert!(
        r122.windows(2).all(|w| w[0] == w[1]),
        "b122 legs diverged: {r122:?}"
    );
    assert_eq!(r122[0], "DSETP.NEU.AND P0, PT, RZ.reuse, UR10, PT");
    let x75: Vec<_> = tables.iter().map(|t| dec(t, W_A ^ (1u128 << 75)).unwrap()).collect();
    // Native boolean[75:74] is an enum. Independent nvdisasm SM120 probes
    // confirm XOR=2 and INVALID3=3; the latter is deliberately unsupported.
    assert_eq!(x75[2], "DSETP.EQ.XOR P0, PT, R22, RZ, !P0");
    let native = &tables[2];
    let w = W_A ^ (1u128 << 75);
    let ctrl = cubit::scheduling::decode_sched_upper32((w >> 96) as u32);
    let source = format!("[{}] {} ;", cubit::scheduling::format_control_code(&ctrl), x75[2]);
    assert_eq!(encode_instruction(&cubit::parse_cuasm_line(&source, 0).unwrap(), native).unwrap(), w);
    assert!(dec(native, W_A ^ (3u128 << 74)).is_none(), "reserved INVALID3 is unsupported");
    // Session T-20 (2026-11-08): sm121a's DSETP rows are measured (-b SM121, the sm120 law) -- the bit-75 word is
    // the vendor's `.XOR` there too and the INVALID3 word fails closed, exactly as on the native sm120 leg. The
    // two donor tables keep their harvest behaviour (bit 75 read as `.OR` -- vendor-false, a T1 item of sm103a /
    // sm100a) until their own FSETP / DSETP batch; pinned here so the drift is visible when it goes.
    assert_eq!(x75[3], x75[2], "sm121a decodes the boolean like the measured sm120 rows");
    assert!(dec(&tables[3], W_A ^ (3u128 << 74)).is_none(), "sm121a: reserved INVALID3 fails closed (measured rows)");
    assert_eq!(x75[0], x75[1]);
    assert_eq!(x75[0], "DSETP.EQ.OR P0, PT, R22, RZ, !P0", "the donors' harvest reading of bit 75 (vendor: XOR)");
    let inv3: Vec<_> = [0usize, 1].iter().map(|&i| dec(&tables[i], W_A ^ (3u128 << 74)).unwrap()).collect();
    assert!(inv3.windows(2).all(|w| w[0] == w[1]), "donor inv3 legs diverged: {inv3:?}");
    // 260-kand sentinel (registered, donor-side, NOT this fix): unfielded
    // operand-modifier bakes in and_base make the encoder inject modifiers
    // -- DSETP MG slots {R_R_P: AND,NUM (abs62+abs73), GT,OR (abs73), LE,OR
    // (abs73), LTU,OR (abs62); R_FI_P: AND,NE (abs73)} on all four arches.
    // nvdisasm-verified: encode('DSETP.LTU.OR P2, PT, R72, R116, !P4') ->
    // b62=1 -> vendor prints '|R116|'. Pin the 4-leg uniformity + the exact
    // mg/word witness; fix = donor-side surgery [sev decision: owner].
    let q = dec(
        &tables[1],
        enc(&tables[1], "DSETP.LTU.OR P2, PT, R72, R116, !P4"),
    )
    .unwrap();
    assert_eq!(
        q, "DSETP.LTU.OR P2, PT, R72, |R116|, !P4",
        "260-kand witness drifted"
    );
    assert_eq!(dec(native, enc(native, "DSETP.LTU.OR P2, PT, R72, R116, !P4")).unwrap(),
        "DSETP.LTU.OR P2, PT, R72, R116, !P4", "native source signs must be authored");
    let native_row = native.get("DSETP_P_P_R_R_P", "LTU,OR").unwrap();
    assert_eq!((native_row.and_base >> 62) & 1, 0);
    assert_eq!((native_row.variable_mask >> 62) & 1, 1);
    // The sm103a donor keeps the 260-kand bake (a T1 item of that table); on sm121a the measured row (T-20,
    // 2026-11-08) carries `|Rb|` as the field it is -- bit 62 in the mask, not in and_base.
    let mg = tables[1].entries.get("DSETP_P_P_R_R_P").unwrap().mod_groups.get("LTU,OR").unwrap();
    assert_eq!(mg.and_base >> 62 & 1u128, 1u128, "260-kand bake flipped");
    assert_eq!(mg.variable_mask >> 62 & 1u128, 0u128, "260-kand fielded");
    let mg = tables[3].entries.get("DSETP_P_P_R_R_P").unwrap().mod_groups.get("LTU,OR").unwrap();
    assert_eq!(mg.and_base >> 62 & 1u128, 0u128, "sm121a: the measured row bakes no sign");
    assert_eq!(mg.variable_mask >> 62 & 1u128, 1u128, "sm121a: |Rb| is a field of the measured row");
    assert_eq!(dec(&tables[3], enc(&tables[3], "DSETP.LTU.OR P2, PT, R72, R116, !P4")).unwrap(),
        "DSETP.LTU.OR P2, PT, R72, R116, !P4", "sm121a: source signs are authored, not injected");
}

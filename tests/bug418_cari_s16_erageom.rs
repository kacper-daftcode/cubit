//! BUG-418 pins (F2-iter227, loop5/blind front2, 2026-09-08): sm100a
//! LDC_R_cARI|S16 era-geometry closure (canonical b75bef5 -> 18b6cec;
//! ENGINE cubit src ZERO changes; table graft only, patch418.py
//! replayable+idempotent, replay from pristine b75bef5 byte-exact
//! 6933fbb8, idem all-skip RC=0). Tail of BUG-409 (registration 418-kand
//! LOW, 409.md sec.6; posture byte-pinned 27 cells in t409_2, flipped to
//! CLOSED-vendor-exact with attribution this iteration).
//!
//! Vendor law arb418 (50 probes, per-bit lattice on the register-carried
//! S16 frame, nvdisasm 13.3.73 raw -b per-word, x4 models
//! SM100a/SM103a/SM120/SM121a unanimous on EVERY probe, DIVERGENT=0):
//! offset = [38:54) SIGNED 16 (b53 sign -> `+-` glyph); bank = [54:59)
//! 5-bit; [32:38) and [59:73) PURE INERT x4; sub_r1 slot [31:24] = register
//! numeral, 0xff = RZ sentinel -> pure-imm cAI form (BUG-409 arm).
//!
//! Defect (measure418_pre on publish cubit_py-b47836ee, canonical b75bef5):
//! the bug172-era row read the offset from sub_imm2 22b@32 unscaled
//! (`R5+0x880` vs vendor `R5+0x22`), dropped the sign (`0xffe0` for
//! `+-0x1`), and leaked bank from sub_imm0 19b@54 (b59 -> `c[0x20]`):
//! 47/50 sm100a cells WRONG. Donor parity: the sm103a sibling row already
//! carries {reg 8b@16, sub_r1 8b@24, cm16_off 21b@38} and decoded the same
//! cells vendor-exact pre-fix (29/29 non-HOLE).
//!
//! Graft (ONE row, sm100a; and_base invariant; monotone vm relax):
//! fields := donor shape (drop era sub_imm0/sub_imm2), vm |= [32:38)|[59:73)
//! (measured-inert bits the old wide fields masked: keeps the exclusion
//! mask fields_old|vm_old == fields_new|vm_new == [16:73)|control ==>
//! claim-set unchanged by construction, pure render re-interpretation).
//! Siblings byte-invariant: sm103a/sm120 = 29 exact + 21 HOLE (care-punish
//! on measured-inert bits; sibling inert-relax = 411/413 owner scope),
//! sm121a = 50 HOLE (no S16 rows). Corpus exposure ZERO (census402: no S16
//! claims on either row, ab240).
//!
//! Witness data: tests/bug418_data.inc (machine-built by
//! work/bug418x/gen418pins.py from arb418_law.json +
//! measure418_{pre,post}_*.json; no hand hex; self-checks abort rc=2).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug418_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<(String, String)> {
    idx.decode(w, 0, t)
        .map(|d| (to_sass(&d), format!("{}|{}", d.key, d.mod_group)))
        .ok()
}

/// t418_1: sm100a register-carried S16 window decodes vendor-exact x50 and
/// claims the contract row (cARI; slotff routes to cAI per the 409 arm).
#[test]
fn t418_1_sm100a_vendor_exact() {
    let t = tab("sm100a");
    let idx = DecodeIndex::build(&t);
    let mut n = 0u32;
    for (word, tag, vendor) in PROBES418 {
        let (got, km) = dec(&t, &idx, word).unwrap_or_else(|| panic!("[{tag}] hole"));
        assert_eq!(got, vendor, "[{tag}] render drift");
        let want_km = if tag == "slotff" {
            "LDC_R_cAI|S16"
        } else {
            "LDC_R_cARI|S16"
        };
        assert_eq!(km, want_km, "[{tag}] misrouted: {km}");
        n += 1;
    }
    assert_eq!(n, 50, "probe set drifted");
}

/// t418_2: attribution capture -- the pre-fix era renders of the 47 fixed
/// cells (KEEP as attribution: the fix must not silently re-drift; pins the
/// historic defect shape documented in 409.md sec.6).
#[test]
fn t418_2_prefix_attribution_cells_fixed() {
    let t = tab("sm100a");
    let idx = DecodeIndex::build(&t);
    let mut n = 0u32;
    for (word, tag, _vendor) in PROBES418 {
        let Some((_, pre_txt)) = PRE418_100A.iter().find(|(tg, _)| *tg == tag) else {
            continue;
        };
        let (got, _) = dec(&t, &idx, word).unwrap();
        assert_ne!(&got, pre_txt, "[{tag}] era render reappeared");
        assert!(
            !got.contains("+0x880"),
            "[{tag}] era unscaled offset glyph back: {got}"
        );
        n += 1;
    }
    assert_eq!(n, 47, "fix set drifted");
}

/// t418_3: sibling legs byte-invariant end-to-end (engine text + claim),
/// 50 cells x3 legs == the pre-fix publish captures. Sibling inert-relax
/// classes (21 HOLE on 103a/120 where vendor prints) stay registered under
/// 411/413 (donor-parity owner decision per t172_6); sm121a has no S16
/// rows (50 HOLE).
#[test]
fn t418_3_sibling_legs_byte_invariant() {
    for (arch, legtab) in [
        ("sm103a", LEG418_SM103A),
        ("sm120", LEG418_SM120),
        ("sm121a", LEG418_SM121A),
    ] {
        let t = tab(arch);
        let idx = DecodeIndex::build(&t);
        let mut n = 0u32;
        for (word, tag, _vendor) in PROBES418 {
            let (_, want) = legtab.iter().find(|(tg, _)| *tg == tag).unwrap();
            let (wtxt, wkm) = want.rsplit_once("::").unwrap();
            if wtxt.starts_with("ERR") {
                assert!(
                    idx.decode(word, 0, &t).is_err(),
                    "[{arch} {tag}] expected HOLE, got decode"
                );
            } else {
                let (got, km) =
                    dec(&t, &idx, word).unwrap_or_else(|| panic!("[{arch} {tag}] hole"));
                assert_eq!(
                    (got.as_str(), km.as_str()),
                    (wtxt, wkm),
                    "[{arch} {tag}] drift"
                );
            }
            n += 1;
        }
        assert_eq!(n, 50);
    }
}

/// t418_4: mint circle on the landed row: authored register-carried S16
/// texts mint the donor-shape geometry; decode->re-encode circles close;
/// inert-window bits ([32:38)|[59:73)) are dropped by the canonical mint
/// (payload domain [95:0]; ctrl prefix authored by the encoder).
#[test]
fn t418_4_mint_circle() {
    const M96: u128 = (1u128 << 96) - 1;
    let t = tab("sm100a");
    let idx = DecodeIndex::build(&t);
    let probe = |tag: &str| -> u128 { PROBES418.iter().find(|(_, tg, _)| *tg == tag).unwrap().0 };
    let base = probe("base");
    // authored texts -> canonical cells
    let w = enc_probe(&t, "@P0 LDC.S16 R0, c[0x0][R5+0x22] ;");
    assert_eq!(w & M96, base & M96, "core cell mint drift (payload domain)");
    // negative offset sign (b53) round-trips through the '+-' glyph
    let neg = probe("off_all16");
    let (txt, km) = dec(&t, &idx, neg).unwrap();
    assert_eq!(km, "LDC_R_cARI|S16");
    let ins = parse_sass(&format!("{txt} ;"), 0).unwrap();
    let remint = encode_instruction(&ins, &t).unwrap();
    let (txt2, _) = dec(&t, &idx, remint).unwrap();
    assert_eq!(txt, txt2, "negative-offset mint circle");
    // bank + register numeral circle
    let b31 = probe("zero_off_bank31");
    let (txt, _) = dec(&t, &idx, b31).unwrap();
    assert_eq!(txt, "@P0 LDC.S16 R0, c[0x1f][R5]");
    let ins = parse_sass(&format!("{txt} ;"), 0).unwrap();
    let remint = encode_instruction(&ins, &t).unwrap();
    assert_eq!(remint & M96, b31 & M96, "bank/R5 cell mint drift");
    // measured-inert bits are NOT carried by the canonical mint
    let inert = probe("inert_all_lohi");
    let (txt, _) = dec(&t, &idx, inert).unwrap();
    let ins = parse_sass(&format!("{txt} ;"), 0).unwrap();
    let remint = encode_instruction(&ins, &t).unwrap();
    const INERT: u128 = (((1u128 << 6) - 1) << 32) | (((1u128 << 14) - 1) << 59);
    assert_eq!(remint & INERT, 0, "mint must not set measured-inert bits");
    assert_eq!(remint & M96, base & M96, "inert-lifted cell canonical mint");
}

fn enc_probe(t: &IsaTable, text: &str) -> u128 {
    let ins = parse_sass(text, 0).unwrap();
    encode_instruction(&ins, t).unwrap()
}

/// t418_5: graft hygiene + canonical pin (ride-chain with attribution).
#[test]
fn t418_5_graft_hygiene_source_pin() {
    let m: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        m["base_revision"].as_str().unwrap() == CANON418,
        "SOURCE.json must pin canonical 2ae87b3 [was 18b6cec = BUG-418] (BUG-419 graft F2-iter228 z atrybucja; 419 rides 418): {:?}",
        m["base_revision"]
    );
    let tabj: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/sm100a.json").unwrap()).unwrap();
    let mg = &tabj["instructions"]["LDC_R_cARI"]["mod_groups"]["S16"];
    assert_eq!(
        mg["and_base"].as_str().unwrap(),
        "0x2000000006000000000000007b82",
        "and_base moved"
    );
    let vm = u128::from_str_radix(
        mg["variable_mask"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    let relax: u128 = (((1u128 << 6) - 1) << 32) | (((1u128 << 14) - 1) << 59);
    assert_eq!(vm & relax, relax, "graft missing the measured-inert relax");
    let fields: Vec<(String, u64, u64, u64)> = mg["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["extraction"].as_str().unwrap().to_string(),
                f["bits"].as_u64().unwrap(),
                f["shift"].as_u64().unwrap(),
                f["token_idx"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        fields,
        vec![
            ("reg".to_string(), 8, 16, 1),
            ("sub_r1".to_string(), 8, 24, 2),
            ("cm16_off".to_string(), 21, 38, 2),
        ],
        "fields drifted from the donor shape"
    );
}

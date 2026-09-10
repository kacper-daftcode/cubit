//! BUG-414 pins (F2-iter225, loop5/blind front2, 2026-09-08): sm121a
//! dedicated narrow-imm rows of the STS.U8 / LDS.128-II family declared
//! immediate windows that were TOO NARROW (13b@40 / 10b@44 / 20b@44 / 2b@48
//! / 1b@44 / 1b@50 / 7b@44) or missing entirely (AR_II_* rows); the vendor
//! reads ONE 24-bit SIGNED offset window [40:64) on every one of those
//! frames (engine sign-extended from the narrow top bit: corpus payload
//! 0x1001 rendered `-0xfff` where vendor x4 prints `+0x1001`).
//!
//! Vendor law (arb414 55 + arb414b 22 + arb414c 261 + arb414d 20 per-word
//! probes, nvdisasm 13.3.73 raw -b, x4 models SM100a/SM103a/SM120/SM121a
//! unanimous on EVERY probe, DIVERGENT=0): the offsets scale per-bit
//! b53 -> +0x2000 ... b63 -> '+-0x800000' (the standard 24-bit law incl the
//! BUG-399 '+-' glyph), uniformly on the STS.U8 carrier, on every LDS.128
//! narrow-II frame, on the fields=[] AR_II_II_II_? frame.
//!
//! Census (census414_wide, ab240 x sm121a claims through the publish engine
//! f9997774): ONLY STS.U8_ARURI_R claims corpus words (398 distinct claims
//! / 271 payloads; every claim has [53:64)==0; the 59 payloads with
//! bit52 set were mis-rendered). LDS.128-II rows claim ZERO corpus words
//! (graft corpus-invisible by construction). Adjacent STS.U16_ARURI_R
//! (sub_imm1 24b, correct) measured vendor-exact 534/534 (attr_u16).
//!
//! Graft (canonical 2f31522 -> c7f1d39, patch414.py replayable+idempotent,
//! monotone relax, and_base invariant, collision audit zero new/lost
//! family-overlap pairs): imm -> 24b@40 on 9 rows, ADD imm 24b@40 tok2 on
//! 3 no-imm rows, vm |= [40:64). STS.U8_ARI_II (12b@41) NOT grafted: its
//! carrier frame is vendor-REFUSED x4 (row not vendor-realizable from
//! and_base; zero corpus claims; posture pinned t414_6).
//!
//! Witness data: tests/bug414_data.inc (machine-built by
//! work/bug414x/gen414pins.py from arb414{,b,c}_law.json + measure414.json
//! + attr_u16.json; rc=2 self-checks; no hand hex).
//! Foreign flip WITH attribution: t399_6 (414 posture) rewritten into the
//! closed-414 contract below.

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::{Extraction, IsaTable};

include!("bug414_data.inc");

const LEGS: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
const M96: u128 = (1u128 << 96) - 1;

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<(String, String)> {
    idx.decode(w, 0, t)
        .map(|d| (to_sass(&d), format!("{}|{}", d.key, d.mod_group)))
        .ok()
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let ins = parse_sass(text, 0).map_err(|e| e.to_string())?;
    encode_instruction(&ins, t).map_err(|e| e.to_string())
}

/// t414_1: vendor law on the STS.U8 carrier (imm boundary sweep incl sign
/// edges AND the per-bit window flips b53..b63 AND operand/guard geometry)
/// renders vendor-exact on all four legs.
#[test]
fn t414_1_stsu8_law_all_legs() {
    for leg in LEGS {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let mut n = 0u32;
        for (word, tag, vendor) in LAW414 {
            let (got, _km) = dec(&t, &idx, word).unwrap_or_else(|| panic!("[{leg} {tag}] hole"));
            assert_eq!(got, vendor, "[{leg} {tag}] render drift vs vendor x4 law");
            n += 1;
        }
        assert_eq!(n, 59, "[{leg}] law set drifted");
    }
}

/// t414_2: on sm121a every law word claims the dedicated row post-graft
/// (pre-414 the bit53..63 flip words fell off the 13-bit row entirely;
/// the graft both widened the field and relaxed the claim to [40:64)).
#[test]
fn t414_2_stsu8_claim_route_121a() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (word, tag, _vendor) in LAW414 {
        let (_, km) = dec(&t, &idx, word).unwrap_or_else(|| panic!("[{tag}] hole"));
        // FLIP F2-iter238 (BUG-425 graft 52cb73c, z atrybucja): BUG-425 cloned
        // the canonical STS_ARURI_R|U8 row onto sm121a; the 21b-imm-era row's
        // claim surface now routes canonically (text preserved vendor-exact,
        // t414_1 stands; wider 24b imm window == canonical shape).
        assert_eq!(km, "STS_ARURI_R|U8", "[{tag}] misrouted: {km}");
    }
}

/// t414_3: the 59 corpus payloads (ab240, full ctrl words) render
/// vendor-exact on sm121a post-graft (pre: 212/271 vendor-exact; post:
/// 271/271). Machine witnesses from measure414.json (OLD .so + PRE table
/// vs SAME .so + NEW table; vendor raw -b per full word).
#[test]
fn t414_3_corpus_cells_cured() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    let mut n = 0u32;
    for (lo, hi, vendor) in CURED414 {
        let (got, km) = dec(&t, &idx, ((hi as u128) << 64) | lo as u128)
            .unwrap_or_else(|| panic!("corpus cell hole"));
        assert_eq!(got, vendor, "corpus cell not cured");
        // FLIP F2-iter238 (BUG-425 graft 52cb73c): claim migrates era ->
        // canonical clone, text byte-stable (asserted one line up).
        assert_eq!(km, "STS_ARURI_R|U8");
        n += 1;
    }
    assert_eq!(n, 59);
}

/// t414_4: mint circle on the vendor texts (payload domain; ctrl prefix is
/// authored by the encoder epoch rules): decode -> text -> encode -> the
/// same payload. Negative texts ('+-0x') now close the circle on sm121a
/// (pre-414 the 13-bit row folded them; BUG-399 t399_2 tracked the refuse).
#[test]
fn t414_4_mint_circle() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    let mut n = 0u32;
    for (word, tag, vendor) in LAW414 {
        if REFUSE414.iter().any(|(_, tg, _)| *tg == tag) {
            // FLIP F2-iter238 (BUG-425 graft 52cb73c, z atrybucja): the 121a
            // canonical STS_ARURI_R|U8 clone opens these mints BYTE-EXACT
            // (mint==law-word, reprint==vendor; machine-checked
            // work/bug425 measure: 3 sampled cells full circles) -- the
            // pre-425 loud-refusal posture is CLOSED by coverage, not by
            // silence. A reopened-but-wrong mint would fail the circle below.
            let w = enc(&t, &format!("{vendor} ;"))
                .unwrap_or_else(|e| panic!("[{tag}] refuse-clone mint-circle fail: {e}"));
            let (got2, _) = dec(&t, &idx, w).unwrap();
            assert_eq!(got2, vendor, "[{tag}] refuse-clone reprint drift");
            n += 1;
            continue;
        }
        let (got, _) = dec(&t, &idx, word).unwrap();
        let remint = enc(&t, &format!("{got} ;"))
            .unwrap_or_else(|e| panic!("[{tag}] vendor text refuses to mint post-414: {e}"));
        assert_eq!(
            remint & M96,
            word & M96,
            "[{tag}] mint circle payload drift"
        );
        let (got2, _) = dec(&t, &idx, remint).unwrap();
        assert_eq!(got2, got, "[{tag}] second render unstable");
        n += 1;
    }
    // FLIP F2-iter238 (BUG-425): 58 + 1 (ra255 refuse-posture mints through
    // the canonical clone, circle asserted above) = 59 circles.
    assert_eq!(n, 59, "circle set post-BUG-425 = 58 + 1 refuse-clone");
    assert_eq!(REFUSE414.len(), 1, "refusal posture set drifted");
}

/// t414_5: LDS.128-II narrow family -- decoded immediate equals the vendor
/// signed offset on every lattice slice (full-text pins where the row's
/// own operand fields fully explain the bracket; raw-fallback rows pin the
/// imm value only -- their operand geometry is era-baked and corpus-deaf).
#[test]
fn t414_5_lds128ii_imm_lattice() {
    // Every lattice slice was built on a dedicated narrow-II row frame, but
    // engine decode claims the pleno 24-bit LDS_R_* rows on those cells (both
    // pre- and post-graft -- those rows always owned the real claim surface;
    // the narrow-II rows claim ZERO corpus words and lose priority on their
    // own frames). The semantic contract is therefore render-level: the
    // decoded text carries the vendor-signed offset (24-bit law), full-text
    // where the row's operand fields fully explain the bracket.
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    let (mut nv, mut nf) = (0u32, 0u32);
    for (word, tag, voff, vtext, full) in LDS414 {
        let (got, _km) = dec(&t, &idx, word).unwrap_or_else(|| panic!("[{tag}] hole post-graft"));
        if full {
            assert_eq!(got, vtext, "[{tag}] full-text drift");
            nf += 1;
        } else {
            let want = if voff > 0 {
                format!("+0x{voff:x}]")
            } else if voff < 0 {
                format!("+-0x{:x}]", -voff)
            } else {
                String::new()
            };
            if !want.is_empty() {
                assert!(got.contains(&want), "[{tag}] offset drift: {got}");
            } else {
                assert_eq!(got, vtext, "[{tag}] zero-offset full-text drift");
            }
            nv += 1;
        }
    }
    assert_eq!((nf, nv), (58, 5), "LDS slice shape drifted");
}

/// t414_6: postures. (a) 412 CLOSED (F2-iter230, arb412c): the UR255-sentinel
/// cell now renders the vendor URZ text (pin flipped to vendor).
/// (b) STS.U8_ARI_II (12b@41): carrier vendor-REFUSED x4; row geometry
/// UNTOUCHED (posture; zero corpus claims). (c) adjacent STS.U16_ARURI_R
/// (already 24-bit): corpus samples vendor-exact pre==post (tripwire for a
/// wider narrow-imm sweep).
#[test]
fn t414_6_postures_arshield() {
    let t = tab("sm121a");
    let idx = DecodeIndex::build(&t);
    for (word, tag, want) in P412_414 {
        let (got, _) = dec(&t, &idx, word).unwrap();
        assert_eq!(got, want, "[{tag}] 412-posture drifted");
    }
    let mg = &t.entries["STS.U8_ARI_II"].mod_groups[""];
    let imm = mg
        .fields
        .iter()
        .find(|f| matches!(f.extraction, Extraction::Imm))
        .unwrap();
    assert_eq!(
        (imm.bits, imm.shift),
        (12, 41),
        "STS.U8_ARI_II geometry drifted"
    );
    for (lo, hi, want) in U16_414 {
        let (got, _) = dec(&t, &idx, ((hi as u128) << 64) | lo as u128).unwrap();
        assert_eq!(got, want, "U16 adjacent-class tripwire");
    }
}

/// t414_7: graft hygiene -- manifest pinned to the new canonical revision;
/// all 12 rows carry imm 24b@40 with the window relaxed in variable_mask.
#[test]
fn t414_7_graft_hygiene() {
    let src = std::fs::read_to_string("tables/SOURCE.json").unwrap();
    assert!(
        src.contains(CANON414),
        "SOURCE.json not pinned to the 414 canonical"
    );
    for leg in ["sm100a", "sm103a", "sm120"] {
        let t = tab(leg);
        assert!(
            !t.entries.contains_key("STS.U8_ARURI_R")
                || t.entries["STS.U8_ARURI_R"].mod_groups[""]
                    .fields
                    .iter()
                    .all(|f| !(matches!(f.extraction, Extraction::Imm) && f.bits == 13)),
            "[{leg}] sibling leg must stay byte-invariant (no 13b graft there)"
        );
    }
    let t = tab("sm121a");
    for key in [
        "STS.U8_ARURI_R",
        "LDS.128_R_ARI_II",
        "LDS.128_R_ARI_II_?",
        "LDS.128_R_ARI_II_II_?",
        "LDS.128_R_ARI_II_II_II_?",
        "LDS.128_R_ARURI",
        "LDS.128_R_ARURI_II",
        "LDS.128_R_ARURI_II_?",
        "LDS.128_R_ARURI_II_II_?",
        "LDS.128_R_AR_II_?",
        "LDS.128_R_AR_II_II_?",
        "LDS.128_R_AR_II_II_II_?",
    ] {
        let mg = &t.entries[key].mod_groups[""];
        let imm = mg
            .fields
            .iter()
            .find(|f| matches!(f.extraction, Extraction::Imm))
            .unwrap_or_else(|| panic!("{key}: no imm post-graft"));
        assert_eq!(
            (imm.bits, imm.shift),
            (24, 40),
            "{key}: graft geometry drifted"
        );
        let vm = mg.variable_mask;
        let win = ((1u128 << 24) - 1) << 40;
        assert_eq!(vm & win, win, "{key}: claim window not relaxed");
    }
}

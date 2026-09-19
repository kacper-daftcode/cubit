//! BUG-454 pins (F2-iter258, loop5/blind front2, 2026-09-13): REDG
//! plain-ARURI ERR-268 recanon fleet-side.
//! (a) 121a print-mangle: 3,072 kluczy *_ARURI64_R dekoduje sie manglowane
//!     (name-suffix artifact + zapad operanda do samego imm) -- sweep408
//!     RG-GATE-MISS 9,216/3,072x3. ENGINE: printer arm op ARURI64 ->
//!     format_plain_u32_ur (OP_TYPES printer+decoder). Post: 9,216/9,216
//!     heal == vendor (measure454), HOLE-parity 3,072/3,072.
//! (b) x2 (sm100a/sm103a) desc-misroute: era keys
//!     REDG.E.{ADD,AND,OR}.EL.STRONG.GPU_P_dARI_R renderowaly desc+PT mimo
//!     ze vendor x4 drukuje plain [R.U32+UR(+imm)] -- census408: 1,344 slow
//!     / 5 uniq w 56 fixture-kubinach floty. R2 DELETE era keys + R1 GRAFT.
//! (c) x3 HOLE: cala rodzina ARURI_R/ARURI64 absent na x3 mimo vendor-
//!     legal x4 (gated, uC-gate artifact klasy 408). R1 GRAFT 6,144 kluczy
//!     donor-121a verbatim per noga (count=None, _src454; patch454.py
//!     replayable+idempotent, replay z 589be874 byte-exact x4).
//!     sm120: 3 natywne EL ARURI_R (ureg 6b) zastapione donorem (ureg 8b)
//!     = R3 (heal UR64..254 legal x4).
//! Canonical 589be874 -> 4ee8431 -> e03e034 (ride 452; CANON454 pin t454_7).
//! Law: arb454 (157 sond gated ctrl[112:110]=0b111 x4 AGREE EVERY /
//! DIVERGENT=0): width b90, URZ@0xff (bug444), imm win24 signed '+-'
//! (bug438), guard full, rv255=RZ, PT-slot absent. b91=0 R-only =
//! HOLE-parity (pin t454_3). base=255 na ARURI64: vendor '???255.64' --
//! graft claimuje donor-symmetric (standing t454_4, dowod-452; zwezenie
//! = cykl 452). Encode '.64'-address text mints b90=0-side word = pre-
//! existing latent na 121a (publish 75caed16 repro) = 460-kand, NIE
//! scope 454 (decode+print+fidelity fix tylko).
//! Witness data: tests/bug454_data.inc (maszynowe gen454pins.py; rc=2;
//! mints nvdisasm-cross gated x4 w generacji).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug454_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
static ERRATA_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}
const ERA454: u128 = (0xFFFFFFFFu128) << 96;
fn nforms(arch: &str) -> usize {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(format!("tables/{arch}.json")).unwrap())
            .unwrap();
    v["instructions"].as_object().unwrap().len()
}

/// t454_1: heal grid -- decode == vendor text on every leg (fixture x4 +
/// carriers ARURI/ARURI64 heal + 121a print-mangle cure; 468 cells).
#[test]
fn t454_1_heal_grid() {
    for (w, leg, vendor) in LAW454_HEAL {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(got.as_deref(), Some(*vendor), "[{leg}] heal drift {w:#034x}");
    }
}

/// t454_2: fixture words sa teraz claimowane dokladnie przez EL ARURI_R
/// key na kazdej nodze (claim-set; wyklucza podwojny claim).
#[test]
fn t454_2_fixture_claim_single() {
    for (w, leg, _v) in LAW454_HEAL {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let d = idx.decode(*w, 0, &t).expect("fixture HOLE");
        assert!(
            d.key.contains("ARURI"),
            "[{leg}] fixture {w:#034x} routed via {} (nie ARURI clone)",
            d.key
        );
    }
}

/// t454_3: parity-HOLE -- gated-kill (b81 flip) i b91=0 R-only carriers
/// stay HOLE on ALL legs (12 cells).
#[test]
fn t454_3_parity_holes() {
    for (w, leg) in HOLE454 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        assert_eq!(dec(&t, &idx, *w), None, "[{leg}] parity-hole claimed {w:#034x}");
    }
}

/// t454_4: standing -- [ride 461: 2026-09-14, canonical f58ed16] ARURI64
/// base=255 dekoduje vendorskim glifem '???255.64' (452 wybral HOLE-parity;
/// 461 = text-parity, printer-arm BUG-461; werdykt t461_1 z nvdisasm x4).
/// Trajektoria: pre-452 print 'RZ.64' -> 452 HOLE -> 461 glif.
#[test]
fn t454_4_standing() {
    for (w, leg) in STAND454 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w)
            .unwrap_or_else(|| panic!("[{leg}] HOLE after 461 {w:#034x}"));
        assert!(
            got.contains("???255.64"),
            "[{leg}] glyph po 461 {w:#034x}: {got}"
        );
    }
}

/// t454_5: mints -- encode(vendor text) == carrier lo96 (era excluded) +
/// decode == text. Cells z ghatch=true biora BUG-080 refuse-assert +
/// hatch CUBIT_DISABLE_ERRATA na sm103a (wzorzec t450_4).
#[test]
fn t454_5_mints() {
    for (text, leg, w, ghatch) in MINT454 {
        let t = tab(leg);
        let idx = DecodeIndex::build(&t);
        let got = if *ghatch {
            let _g = ERRATA_LOCK.lock().unwrap();
            let e = enc(&t, text).expect_err("[sm103a] BUG-080 keeper must refuse");
            assert!(format!("{e}").contains("BUG-080"), "guard msg: {e}");
            std::env::set_var("CUBIT_DISABLE_ERRATA", "1");
            let r = enc(&t, text);
            std::env::remove_var("CUBIT_DISABLE_ERRATA");
            r.unwrap_or_else(|e| panic!("[{leg}] hatch mint refuse {text}: {e}"))
        } else {
            enc(&t, text).unwrap_or_else(|e| panic!("[{leg}] mint refuse {text}: {e}"))
        };
        assert_eq!(got & !ERA454, *w & !ERA454, "[{leg}] mint lo96 drift {text}");
        let back = dec(&t, &idx, got).unwrap_or_else(|| panic!("[{leg}] mint HOLE {text}"));
        assert_eq!(&back, text, "[{leg}] circle drift {text} -> {back}");
    }
}

/// t454_6: refuse grid -- teksty non-EL guarded na sm103a refuse z
/// cytowaniem BUG-080 (keeper parity, wzorzec t450_5).
#[test]
fn t454_6_refuse_grid() {
    let _g = ERRATA_LOCK.lock().unwrap();
    let t = tab("sm103a");
    for (text, leg) in REFUSE454 {
        assert_eq!(*leg, "sm103a");
        let e = enc(&t, text).expect_err("[sm103a] BUG-080 keeper must refuse");
        assert!(format!("{e}").contains("BUG-080"), "guard msg: {e}");
    }
}

/// t454_8: era-mint continuity -- the frozen chain inputs (text md5
/// 9962e535) spell the era glyph `PT, desc[URd][Rb.64(+0xoff)]`; the
/// BUG-454 encoder companion arm (fail-closed shape [PT, Desc{base}, Reg]
/// on REDG.*.EL.*) mints the exact original fixture words (lo96).
#[test]
fn t454_8_era_mint_continuity() {
    for (text, leg, w) in ERAM454 {
        let t = tab(leg);
        let got = enc(&t, text).unwrap_or_else(|e| panic!("[{leg}] era-mint refuse {text}: {e}"));
        assert_eq!(got & !ERA454, *w & !ERA454, "[{leg}] era-mint lo96 drift {text}");
    }
}

/// t454_7: canonical pin -- SOURCE.json base_revision == BUG-454 graft rev.
#[test]
fn t454_7_canonical_pin() {
    assert_eq!(CANON454, "cc2f62c"); // ride F2-iter275 (BUG-466 ELL2.256 rekanon); was 23976eb; old:  ride F2-iter267 (BUG-432 ari-cavity); was a64b82b (BUG-463 ltc-widths);  ride F2-iter266 (BUG-463 ltc-widths); was f58ed16 (BUG-461 glyph); // ride F2-iter265 (BUG-461 glyph); was f376558 (BUG-462 narrow); // ride F2-iter264 (BUG-462 narrow); was 700524e (BUG-453 graft); // ride F2-iter263 (BUG-453 graft); was e03e034 (BUG-452 narrow) [flip-ride 467: pin 67b54f4 -> 668f842]
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert!(
        src["base_revision"].as_str().unwrap().starts_with(CANON454),
        "SOURCE.json must pin canonical a64b82b (= BUG-463 ltc-widths; was f58ed16 (= BUG-461 glyph; was f376558 (= BUG-462 narrow; was 700524e (= BUG-453 graft; was e03e034 (BUG-452 narrow); was 4ee8431 (BUG-454 graft); was 589be874 = BUG-450): {:?}",
        src["base_revision"]
    );
}

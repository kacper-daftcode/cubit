//! BUG-469 pins (F2-iter282, loop5/blind front2, 2026-09-16): LDG widthless
//! ARURI graft sm121a (PRESTUDY469 plan A+B; iter281 law-complete). Scope:
//!  (A) kopia verbatim 2 kluczy z sm103a -> sm121a (era [127:96] clear):
//!      'LDG.E.EL.ELL2.256.STRONG.GPU_R_R_ARURI',
//!      'LDG.E.NA.ELL2.256.STRONG.GPU_R_R_ARURI' (claim-set == donor x3).
//!  (B) mg adds plain-band b84=1: LDG_R_ARURI x4 sel [69:68], LDG.E_R_ARURI
//!      ride-fix mg['E'] (b92 pinned-1 -> vm, vendor-inert) + mg LTCnm x3,
//!      LDG_R_ARURI_P x4 (+pred_inv4@64), LDG_P_R_ARURI{,_P} (+pred@81;
//!      cf pred7 = split od R-formy).
//!  (C) 4 nowe klucze EF-band b84=0: LDG.E.EF{,.LTCnm}_P_R_ARURI_P.
//!  ENGINE: printer.rs 099-arm guard +('_P_R_ARURI') scopowany (zero
//!  kluczy pre-istniejacych w zasiegu contains('_P_R_ARURI')).
//! Vendor law: arb469 (143) + arb469b (37) nvdisasm 13.3.73 raw -b x4 AGREE
//! EVERY/DIVERGENT=0 + korpus ab240 101 slow vendor-legal x4 (HOLE 121a,
//! publish e7d4a91f). Kills: b91=0 rc=1 x4; cf ra255 (.64+ra255 -> HOLE-
//! parity, vendor '???255.64' = 461-doktryna junk-glyph); EF pred=7 elide
//! ('LDG.E.EF R7,...') claim_forbid (standing 483). Canonical 08a6145 ->
//! bd48e63 (patch469.py replay x2 byte-exact + idem; audity A0(sym x3)/
//! A0b(108 komorek law)/A1(NONE->GRAFT 224/STABLE 894/BAD 0, grid 1118)/
//! A2(corpus 101 graft-winner)/A3(kill+standing not-graft)/A4(x3 byte-equal,
//! 121a delta==plan)/A5(19227->19233)/A7 fail-closed).
//! Witness: tests/bug469_data.inc (maszynowe gen469pins.py rc=2).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;
use std::collections::HashMap;
use std::sync::OnceLock;

include!("bug469_data.inc");

fn pool() -> &'static HashMap<&'static str, (IsaTable, DecodeIndex)> {
    static POOL: OnceLock<HashMap<&'static str, (IsaTable, DecodeIndex)>> = OnceLock::new();
    POOL.get_or_init(|| {
        let mut m = HashMap::new();
        for leg in ["sm100a", "sm103a", "sm120", "sm121a"] {
            let t = IsaTable::load(std::path::Path::new(&format!("tables/{leg}.json"))).unwrap();
            let idx = DecodeIndex::build(&t);
            m.insert(leg, (t, idx));
        }
        m
    })
}
fn dec(leg: &str, w: u128) -> Option<String> {
    let (t, idx) = pool().get(leg).unwrap();
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
fn enc(leg: &str, text: &str) -> Result<u128, String> {
    let (t, _) = pool().get(leg).unwrap();
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}

/// t469_1: heal-decode -- graft-celle (korpus 101 + law plain/P/EF/97e)
/// dekoduje DOKLADNIE tekst vendora na sm121a; pre-fix HOLE potwierdzone
/// maszynowo przez generator (cold publish e7d4a91f + pre_tabs -> None).
#[test]
fn t469_1_heal_decode() {
    for (w, leg, want) in HEAL469 {
        let got = dec(leg, *w);
        assert_eq!(got.as_deref(), Some(*want), "[{leg}] heal {w:#034x}");
    }
}

/// t469_2: anchors standing-adjacent (junk-family/glyph, set76 desc-legal,
/// .128-class 482, 477-raw5): pin = COLD werdykt (tekst albo HOLE) --
/// pre == post wymuszone przez generator; tu asertujemy post == cold-pin.
#[test]
fn t469_2_anchor_parity() {
    for (w, leg, cold) in ANCH469 {
        let got = dec(leg, *w);
        if cold.is_empty() {
            assert!(
                got.is_none(),
                "[{leg}] anchor-drill {w:#034x} -> {got:?} (cold HOLE)"
            );
        } else {
            assert_eq!(got.as_deref(), Some(*cold), "[{leg}] anchor {w:#034x}");
        }
    }
}

/// t469_3: kills -- flip91 (b91=0 rc=1 vendor x4), cf ra255 na .64 arm,
/// EF pred=7 elide (483-standing): engine decode HOLE (fail-closed parity).
#[test]
fn t469_3_kill_parity() {
    for (w, leg) in KILL469 {
        let got = dec(leg, *w);
        assert!(got.is_none(), "[{leg}] kill-claim {w:#034x} -> {got:?}");
    }
}

/// t469_4: mint-circle po graft-clem 121a (asm -> decode == tekst).
/// ENC-noentry standingi (ENCTAIL469) asertuja brak entry (fail-closed).
#[test]
fn t469_4_mint_circle() {
    for (text, leg) in MINT469 {
        let w = enc(leg, text).unwrap_or_else(|e| panic!("[{leg}] mint {text:?}: {e}"));
        let back = dec(leg, w);
        assert_eq!(back.as_deref(), Some(*text), "[{leg}] mint circle {text:?}");
    }
    for (text, leg) in ENCTAIL469 {
        assert!(
            enc(leg, text).is_err(),
            "[{leg}] enc-standing {text:?} otwarte"
        );
    }
}

/// t469_5: census + SOURCE pin == canonical graft bd48e63; x3 nogi STOJA
/// (10267/10267/11405).
#[test]
fn t469_5_census_and_source() {
    for (leg, want) in CENSUS469 {
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let got = raw["instructions"].as_object().unwrap().len();
        assert_eq!(got, *want, "[{leg}] key census post-469");
    }
    let src: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("tables/SOURCE.json").unwrap()).unwrap();
    assert_eq!(
        src["base_revision"].as_str().unwrap(),
        CANON469,
        "SOURCE.json base_revision == canonical graft bd48e63"
    );
}

/// t469_6: graft-record shape -- 4 sel mg na LDG_R_ARURI{,_P}, idiom pol
/// 121a (ureg 8-bit), cf ra255 na armach plain/EF, _src469, era=0,
/// ride-fix mg['E'] na LDG.E_R_ARURI ma b92 w vm.
#[test]
fn t469_6_graft_shape() {
    let raw: serde_json::Value = serde_json::from_str::<serde_json::Value>(
        &std::fs::read_to_string("tables/sm121a.json").unwrap(),
    )
    .unwrap();
    let ins = raw["instructions"].as_object().unwrap();
    // (A) verbatim graft keys
    for k in [
        "LDG.E.EL.ELL2.256.STRONG.GPU_R_R_ARURI",
        "LDG.E.NA.ELL2.256.STRONG.GPU_R_R_ARURI",
    ] {
        let rec = &ins[k];
        assert_eq!(
            rec["_src469"].as_str().unwrap(),
            "bug469-2026-09-16",
            "src469 {k}"
        );
        let mg = &rec["mod_groups"][""];
        let ab = u128::from_str_radix(
            mg["and_base"].as_str().unwrap().trim_start_matches("0x"),
            16,
        )
        .unwrap();
        assert_eq!(ab >> 96, 0, "era clear {k}");
    }
    // (B) mg sets + cf ra255
    let u8field = |mg: &serde_json::Value| -> bool {
        mg["fields"].as_array().unwrap().iter().any(|f| {
            f["extraction"].as_str().unwrap() == "ureg"
                && f["shift"].as_u64().unwrap() == 32
                && f["bits"].as_u64().unwrap() == 8
        })
    };
    for k in ["LDG_R_ARURI", "LDG_R_ARURI_P"] {
        let mgs = ins[k]["mod_groups"].as_object().unwrap();
        for name in ["E", "E,LTC64B", "E,LTC128B", "E,LTC256B"] {
            let mg = &mgs[name];
            assert!(u8field(mg), "{k}[{name}] ureg-8bit");
            assert!(
                mg["claim_forbid"]
                    .as_array()
                    .unwrap()
                    .contains(&serde_json::json!({"shift":24,"bits":8,"values":[255]})),
                "{k}[{name}] cf ra255"
            );
        }
    }
    // LDG_P_R_ARURI_P sel pelny zakres
    let mgs = ins["LDG_P_R_ARURI_P"]["mod_groups"].as_object().unwrap();
    for name in ["E", "E,LTC64B", "E,LTC128B", "E,LTC256B"] {
        assert!(mgs.contains_key(name), "P_R_P[{name}]");
    }
    // ride-fix: b92 w vm
    let vm = u128::from_str_radix(
        ins["LDG.E_R_ARURI"]["mod_groups"]["E"]["variable_mask"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x"),
        16,
    )
    .unwrap();
    assert_ne!(vm >> 92 & 1, 0, "ride-fix b92 vm");
    // (C) EF keys
    for k in [
        "LDG.E.EF_P_R_ARURI_P",
        "LDG.E.EF.LTC64B_P_R_ARURI_P",
        "LDG.E.EF.LTC128B_P_R_ARURI_P",
        "LDG.E.EF.LTC256B_P_R_ARURI_P",
    ] {
        let rec = &ins[k];
        assert_eq!(
            rec["operand_sig"].as_str().unwrap(),
            "P_R_ARURI_P",
            "sig {k}"
        );
        let cf = &rec["mod_groups"][""]["claim_forbid"];
        assert!(cf.as_array().unwrap().len() == 2, "cf pair {k}");
    }
}

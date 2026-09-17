//! BUG-465 pins (F2-iter272, loop5/blind front2, 2026-09-15): modsub lattice
//! nad plain (nNA) ARURI64 EFL2.256 frame -- L1 [85:84] {0:EF,1:base,2:EL,
//! 3:LU} x L2-hint [82:81] {0:EFL2,1:ENL2,2:ELL2; 3 = era-split standing:
//! SM100a/103a 'INVALID3' vs SM120/121a 'RML2.256.???1.???0', nigdy kluczem}
//! x sem [80:77] 16-wartosciowy per-op atlas. LDG i STG atlasy roznia sie na
//! {4: CONSTANT vs STRONG.SM.PRIVATE; 13/14/15: VC-klasa vs *ORDERED}; atlas
//! REDG (iter72) NIE przeniesiony (LDG sem=4 mierzone inaczej). 1146 nowych
//! kluczy/noga x4 (LDG 191 kombinacji x4 formy {,_P,_II,_II_P} + STG 191 x2),
//! canonical 23976eb (clone wlasnych 6 kluczy 464: and_base piny [77:86) +
//! base_op, reszta verbatim, claim_forbid None, count=None). Vendor law:
//! arb465 (123 sondy) + arb465b (382 slowa kratki) nvdisasm 13.3.73 raw -b
//! x4 AGREE EVERY/DIVERGENT=0 poza by-design l2=3 era-split. Dziedziczenie
//! zmierzone: pol-trailer/imm/elide ra255/pred4/band 92-95 identyczne jak
//! na bazie 464; kille b91=0 trzymaja na modsub (G.*). ENGINE delta: guard
//! armu printera ARURI64 poszerzony z starts_with('*_EFL2') na rodzine
//! *{EFL2,ENL2,ELL2}* (base_op niesie token); encoder fallback '_ARURI64'
//! generywny przez clean_opcode (bez zmian). Standing NIEclaimowane
//! (snap pre==post HOLE; t465_3): l2=3 era-split + dARI modsub b76=1
//! (475-kand; bug123 ma EF.ENL2 desc-form z innej klasy adresowej, nie
//! konfliktuje). Witness data: tests/bug465_data.inc (machine-built by
//! work/bug465/gen465pins.py rc=2; no hand hex; mints nvdisasm-crossed x4).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug465_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
const LEGS465: [&str; 4] = ["sm100a", "sm103a", "sm120", "sm121a"];
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}

/// t465_1: lattice grid -- decode == vendor text na calej mierzonej kratce
/// (L1 x L2 x sem minus baza), wszystkie cztery nogi (pre-state = HOLE,
/// dowiedzione w sesji generowania pinow przez publish-464 .so).
#[test]
fn t465_1_lattice_grid() {
    for (w, tag, vendor) in LAW465_LATTICE {
        for leg in LEGS465 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] {tag} lattice drift {w:#034x}"
            );
        }
    }
}

/// t465_2: elide grid -- pol == 0xff na modsub: trailer eliduje sie przez
/// forme bez _II (tie-break krotszym kluczem jak baza 464), decode == vendor.
#[test]
fn t465_2_elide_grid() {
    for (w, tag, vendor) in LAW465_ELIDE {
        for leg in LEGS465 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] {tag} elide drift {w:#034x}"
            );
        }
    }
}

/// t465_3: standing snap -- l2=3 era-split + dARI modsub b76=1 zostaja
/// nieclaimowane (pre==post == HOLE x4; era-split nigdy kluczem wg prawa
/// 463/465, dARI = 475-kand).
#[test]
fn t465_3_standing_snap() {
    for (w, tag, snap) in STAND465 {
        for leg in LEGS465 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            let exp = if *snap == "HOLE" { None } else { Some(*snap) };
            assert_eq!(
                got.as_deref(),
                exp,
                "[{leg}] {tag} standing drift {w:#034x}"
            );
        }
    }
}

/// t465_4: kill snap -- b91=0 pozostaje HOLE x4 rowniez przy modsub.
#[test]
fn t465_4_kill_snap() {
    for (w, tag) in KILL465 {
        for leg in LEGS465 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            assert!(
                dec(&t, &idx, *w).is_none(),
                "[{leg}] {tag} kill claimed {w:#034x}"
            );
        }
    }
}

/// t465_5: control rodziny-bazy 464 -- slowa bazowe (sem=0/l1=1/l2=0 oraz
/// l1-l2 bazowe z lattice) pre==post==vendor x4 (graft nie rusza donora).
#[test]
fn t465_5_control_464_base() {
    for (w, tag, vendor) in CTRL465 {
        for leg in LEGS465 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(got.as_deref(), Some(*vendor), "[{leg}] {tag} control drift");
        }
    }
}

/// t465_6: mint circle -- encode(vendor text) -> decode -> ten sam tekst
/// x4 na reprezentantach wszystkich klas modsub (mints nvdisasm-crossed w
/// generatorze; refuse BUG-060 na sm103a even-base EFL2 jest prawidlowa
/// odpowiedzia fail-closed i tam jest pomijany jak w t464_7).
#[test]
fn t465_6_mint_circle() {
    for (w, vendor) in MINT465 {
        for leg in LEGS465 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] mint-word decode drift {w:#034x}"
            );
            let re = enc(&t, vendor);
            if let Ok(rw) = re {
                let g2 = dec(&t, &idx, rw);
                assert_eq!(g2.as_deref(), Some(*vendor), "[{leg}] re-mint circle drift");
            }
        }
    }
}

/// t465_7: elide-mint circle na modsub -- baza 255 eliduje sie do '[UR38]'
/// pod ENL2 identycznie jak na bazie 464 (encoder fallback _ARURI64).
#[test]
fn t465_7_elide_mint_circle() {
    for (w, vendor) in MINT465_ELIDE {
        for leg in LEGS465 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] elide-word decode drift {w:#034x}"
            );
            let rw =
                enc(&t, vendor).unwrap_or_else(|e| panic!("[{leg}] elide-mint FAIL {vendor}: {e}"));
            let g2 = dec(&t, &idx, rw);
            assert_eq!(g2.as_deref(), Some(*vendor), "[{leg}] elide re-mint drift");
        }
    }
}

/// t465_8: refuse 461 przy modsub -- jawny '[RZ.64+URm]' zostaje refused
/// globalnym armem 461 niezaleznie od L1/L2 tokenu (rownolegle do t464_9).
#[test]
fn t465_8_refuse461() {
    for leg in LEGS465 {
        let t = tab(leg);
        for txt in [
            "LDG.E.EFL2.256 R44, R48, [RZ.64+UR38], 0x99",
            "LDG.E.ENL2.256 R44, R48, [RZ.64+UR38], 0x99",
            "STG.E.EFL2.256 [RZ.64+UR38], R44, R48, 0xa0",
            "STG.E.ELL2.256 [RZ.64+UR38], R44, R48, 0xa0",
        ] {
            let e = enc(&t, txt);
            assert!(e.is_err(), "[{leg}] RZ.64 modsub nie refused: {txt}");
            assert!(
                e.unwrap_err().contains("461"),
                "[{leg}] refuse bez cytatu 461"
            );
        }
    }
}

/// t465_9: atlas audit -- klucze vendored == atlas z prawa (maszynowa
/// enumeracja (l1,l2,sem)); and_base piny [77:86) == wartosci kratki; vm ==
/// vm donora 464 bitowo; per noga +1146 kluczy _src465; LDG/STG atlas
/// divergencja {4,13,14,15} zgodna z klawiszami.
#[test]
fn t465_9_atlas_audit() {
    let l1tok = ["EF", "", "EL", "LU"];
    let l2tok = ["EFL2", "ENL2", "ELL2"];
    let seml = [
        "",
        "CONSTANT.PRIVATE",
        "CONSTANT.CTA",
        "CONSTANT.CTA.PRIVATE",
        "CONSTANT",
        "STRONG.SM",
        "STRONG.GPU.PRIVATE",
        "STRONG.GPU",
        "MMIO.GPU",
        "CONSTANT.SM",
        "STRONG.SYS",
        "CONSTANT.SM.PRIVATE",
        "MMIO.SYS",
        "CONSTANT.VC",
        "CONSTANT.VC.PRIVATE",
        "CONSTANT.GPU",
    ];
    for leg in LEGS465 {
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(format!("tables/{leg}.json")).unwrap())
                .unwrap();
        let ins = v["instructions"].as_object().unwrap();
        let donors_ldg = [
            "LDG.E.EFL2.256_R_R_ARURI64",
            "LDG.E.EFL2.256_R_R_ARURI64_P",
            "LDG.E.EFL2.256_R_R_ARURI64_II",
            "LDG.E.EFL2.256_R_R_ARURI64_II_P",
        ];
        let donors_stg = [
            "STG.E.EFL2.256_ARURI64_R_R",
            "STG.E.EFL2.256_ARURI64_R_R_II",
        ];
        let mut n_src462 = 0usize;
        for (k, e) in ins {
            if e.get("_src465").is_some() {
                n_src462 += 1;
                assert!(!k.contains(".NA."), "{leg}:{k} NA pollution");
                assert!(k.contains(".256"), "{leg}:{k} width lost");
            }
        }
        assert_eq!(n_src462, 1146, "{leg}: _src465 census drift");
        for (ldg, donors) in [(true, &donors_ldg[..]), (false, &donors_stg[..])] {
            for dk in donors {
                assert!(ins.get(*dk).is_some(), "{leg}: donor {dk} absent");
            }
            let dvm = |dk: &str| {
                ins[dk]["mod_groups"][""]["variable_mask"]
                    .as_str()
                    .unwrap()
                    .to_string()
            };
            let sfx = if ldg {
                vec!["", "_P", "_II", "_II_P"]
            } else {
                vec!["", "_II"]
            };
            for sem in 0..16u32 {
                for l1 in 0..4u32 {
                    for l2 in 0..3u32 {
                        if sem == 0 && l1 == 1 && l2 == 0 {
                            continue;
                        }
                        let l1t = if l1tok[l1 as usize].is_empty() {
                            String::new()
                        } else {
                            format!(".{}", l1tok[l1 as usize])
                        };
                        let semt = seml[sem as usize];
                        let semt = if !ldg {
                            match sem {
                                4 => "STRONG.SM.PRIVATE",
                                13 => "SYS.ORDERED",
                                14 => "STRONG.SYS.ORDERED",
                                15 => "MMIO.SYS.ORDERED",
                                _ => semt,
                            }
                        } else {
                            semt
                        };
                        let semt = if semt.is_empty() {
                            String::new()
                        } else {
                            format!(".{semt}")
                        };
                        let bop = format!(
                            "{op}.E{l1t}.{l2}.256{semt}",
                            op = if ldg { "LDG" } else { "STG" },
                            l2 = l2tok[l2 as usize]
                        );
                        let mut pins: u128 = (sem as u128 & 0xF)
                            | (((l2 as u128) & 3) << 4)
                            | (((l1 as u128) & 3) << 7);
                        for (dk, s) in donors.iter().zip(sfx.iter()) {
                            let nk = if ldg {
                                format!("{bop}_R_R_ARURI64{s}")
                            } else {
                                format!("{bop}_ARURI64_R_R{s}")
                            };
                            let e = ins.get(&nk).unwrap_or_else(|| panic!("{leg}: {nk} absent"));
                            let dab = u128::from_str_radix(
                                e["mod_groups"][""]["and_base"]
                                    .as_str()
                                    .unwrap()
                                    .trim_start_matches("0x"),
                                16,
                            )
                            .unwrap();
                            let seg = (dab >> 77) & 0x1FF;
                            assert_eq!(seg, pins, "{leg}:{nk} pin-seg drift");
                            assert_eq!(((dab >> 83) & 1), 0, "{leg}:{nk} b83 standing nie-inert");
                            let vm = e["mod_groups"][""]["variable_mask"].as_str().unwrap();
                            assert_eq!(vm, dvm(dk), "{leg}:{nk} vm != donor vm");
                            assert_eq!(
                                dab & u128::from_str_radix(vm.trim_start_matches("0x"), 16)
                                    .unwrap(),
                                0
                            );
                            assert_eq!(e["operand_sig"], ins[*dk]["operand_sig"]);
                            assert!(e["_src465"].is_string());
                            assert_eq!(e["base_op"], serde_json::Value::String(bop.clone()));
                        }
                        pins &= 0x1FF;
                    }
                }
            }
        }
    }
}

/// t465_10: canonical pin -- catena graftu (tabele vendored by sync).
#[test]
fn t465_10_canonical_pin() {
    let src = std::fs::read_to_string("tables/SOURCE.json").unwrap();
    assert!(
        src.contains(CANON465),
        "SOURCE.json nie pina canonical 465-graftu ({}): {}",
        &CANON465[..8],
        src.lines().nth(3).unwrap_or("")
    );
}

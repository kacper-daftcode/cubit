//! BUG-466 pins (F2-iter275, loop5/blind front2, 2026-09-16): rekanon x3
//! ELL2.256 dARI-era frame do prawdziwej geometrii plain vendora. Legacy
//! wiersze LDG_R_R_dARI/STG_dARI_R_R mgs {'256,E,EL,ELL2,GPU,STRONG',
//! '256,E,ELL2,GPU,NA,STRONG'} nosily desc-geometry (ur 5b@32/9b@64, imm
//! shr2 20b@37 / imm shr5u 16b@40) -- OBALONE vendor-law (arb466 180 sond +
//! arb466b 85 tagow, nvdisasm 13.3.73 raw -b x3 AGREE EVERY/DIVERGENT=0):
//! plain '[R{n}.U32+UR{m}(+/-imm<<5)]', base 255 -> elizja '[URm]', ur
//! 8b@32 (LDG) / 8b@64 (STG), ur 255 -> URZ, imm17 (LDG [56:40)) / imm19
//! (STG [58:40)) signed<<5, b76=1 KILL rc=1 x3. Canonical 67b54f4: delete
//! 4 mgs x3 nogi + 4 klucze *_ARURI z ta sama and_base, vm +bit znaku imm,
//! fields = donor-geo sub_r0/sub_ur1/sub_imm2_shr5; sm121a nietknieta
//! (jej ELL2 dARI row na innym pin-bande = prawdziwy desc, CTRL466 keeper).
//! ENGINE: arm printera ARURI poszerzony o rodzine .ELL2. x
//! {LDG.E.,STG.E.} ride'ujaca efl2_na mode (width U32 fixed + 255-elide).
//! Standing NIEclaimowane (snap pre==post HOLE; wpisane klase STAND466):
//! b75=1 '.64' + LTC sel [74:73] + b80/b81/b85 lattice era-frame (476-kand
//! NOWY) + pred-out [90:87] (477-kand NOWY). Witness data:
//! tests/bug466_data.inc (machine-built by work/bug466467/gen466pins.py
//! rc=2; no hand hex; mints nvdisasm-crossed x3).

use cubit::decoder::DecodeIndex;
use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::printer::to_sass;
use cubit::table::IsaTable;

include!("bug466_data.inc");

fn tab(arch: &str) -> IsaTable {
    IsaTable::load(std::path::Path::new(&format!("tables/{arch}.json"))).unwrap()
}
fn dec(t: &IsaTable, idx: &DecodeIndex, w: u128) -> Option<String> {
    idx.decode(w, 0, t)
        .ok()
        .map(|d| to_sass(&d).trim().trim_end_matches(';').to_string())
}
fn enc(t: &IsaTable, text: &str) -> Result<u128, String> {
    let full = format!(" {text} ;");
    let parsed = parse_sass(&full, 0).map_err(|e| e.to_string())?;
    encode_instruction(&parsed, t).map_err(|e| e.to_string())
}
const X3: [&str; 3] = ["sm100a", "sm103a", "sm120"];

/// t466_1: route grid -- decode == vendor text na wszystkich 90 zmierzonych
/// komorkach x3 (pre-state = desc-form lub HOLE, dowiedzione w sesji przez
/// publish-.so 52c53ecb canopy na tabelach pre_tabs).
#[test]
fn t466_1_route_grid() {
    let mut n = 0;
    for (w, tag, vendor) in LAW466_ROUTE {
        for leg in X3 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] {tag} route drift {w:#034x}"
            );
            n += 1;
        }
    }
    assert_eq!(n, 90 * 3);
}

/// t466_2: elide grid -- baza==255 -> '[URm]' (base elidowany), decode ==
/// vendor x3.
#[test]
fn t466_2_elide_grid() {
    for (w, tag, vendor) in LAW466_ELIDE {
        for leg in X3 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            assert_eq!(
                dec(&t, &idx, *w).as_deref(),
                Some(*vendor),
                "[{leg}] {tag} elide drift {w:#034x}"
            );
        }
    }
}

/// t466_3: standing snap -- band-gaps (b75 '.64'/LTC [74:73]/b80/81/85
/// lattice era-frame, pred-out [90:87]) zostaja nieclaimowane x3 (snap
/// pre==post HOLE; dowod w gen466pins przez publish-.so 52c53ecb).
#[test]
fn t466_3_standing_snap() {
    for (w, tag, snap) in STAND466 {
        for leg in X3 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let exp = if *snap == "HOLE" { None } else { Some(*snap) };
            assert_eq!(
                dec(&t, &idx, *w).as_deref(),
                exp,
                "[{leg}] {tag} standing drift {w:#034x}"
            );
        }
    }
}

/// t466_4: kill snap -- b76=1 = HOLE x3 (vendor rc=1).
#[test]
fn t466_4_kill_snap() {
    for (w, tag) in KILL466 {
        for leg in X3 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            assert!(
                dec(&t, &idx, *w).is_none(),
                "[{leg}] {tag} kill claimed {w:#034x}"
            );
        }
    }
}

/// t466_5: control -- sm121a ELL2 dARI keeper (desc-form == vendor x1,
/// graft nietkniety na 121a) + brak flagi '466-dotkniecia'.
#[test]
fn t466_5_control_121a() {
    for (w, name, vendor) in CTRL466 {
        let t = tab("sm121a");
        let idx = DecodeIndex::build(&t);
        let got = dec(&t, &idx, *w);
        assert_eq!(
            got.as_deref(),
            Some(*vendor),
            "[sm121a] {name} control drift {w:#034x}"
        );
    }
}

/// t466_6: mint circle -- encode(vendor text) -> decode == text wspolnej
/// dla x3 (mints nvdisasm-crossed w generatorze).
#[test]
fn t466_6_mint_circle() {
    for (w, vendor) in MINT466 {
        for leg in X3 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            let got = dec(&t, &idx, *w);
            assert_eq!(
                got.as_deref(),
                Some(*vendor),
                "[{leg}] mint-word decode drift {w:#034x}"
            );
            let re = enc(&t, vendor);
            assert!(re.is_ok(), "[{leg}] mint refuse: {:?}", re.err());
            let rw = re.unwrap();
            // era-blind circle: re-mintowane slowo dekoduje sie na ten sam
            // tekst vendora (era-window encodera != era nosnika).
            let g2 = dec(&t, &idx, rw);
            assert_eq!(g2.as_deref(), Some(*vendor), "[{leg}] re-mint circle drift");
        }
    }
}

/// t466_7: elide-mint circle -- '[URm]' tekst mintuje baze=255 (encoder
/// candidate scope _ARURI + op_sub_reg RZ-default), nvdisasm cross x3.
#[test]
fn t466_7_elide_mint_circle() {
    for (w, vendor) in MINT466_ELIDE {
        for leg in X3 {
            let t = tab(leg);
            let idx = DecodeIndex::build(&t);
            assert_eq!(
                ((w >> 24) & 0xff, dec(&t, &idx, *w).as_deref()),
                (255, Some(*vendor)),
                "[{leg}] elide-mint snap {w:#034x}"
            );
            let re = enc(&t, vendor);
            assert!(re.is_ok(), "[{leg}] elide-mint refuse: {:?}", re.err());
            let rw = re.unwrap();
            assert_eq!((rw >> 24) & 0xff, 255, "[{leg}] elide re-mint base != 255");
            assert_eq!(
                dec(&t, &idx, rw).as_deref(),
                Some(*vendor),
                "[{leg}] elide circle"
            );
        }
    }
}

/// t466_8: refuse -- legacy desc-form text odporny dla x3 (fail-closed):
/// encode('STG.E.EL.ELL2.256.STRONG.GPU desc[UR4][R5.64], R8, R12') --
/// brak klucza *_dARI_R_R w scope ELL2.256 (graft), loader-pure refuse.
/// RIDE475R3 (INC-289e, iter289): para EL wyjezdzila z refuse -- graft 475
/// posiada klucze *ELL2.256.STRONG.GPU_R_R_dARI; slowa mintowane:
/// LDG 000fc2000824f908fe000004030c797e / STG 000fc2000f24f804f8000008050c797f
/// (era-full, nvdisasm x4 AGREE EVERY == tekst; cold474 = None -> czysty
/// gain graftu). Para NA zostaje refuse (nietknieta).
/// t466_8b: mint-positive po RIDE475R3 (INC-289e): EL ELL2.256 STRONG.GPU
/// desc-formy mintuja bajtowo slowa vendora (era-full; x4 AGREE; dowod w
/// work/bug475/arb475snaps/). cold474 = None (gain graftu 475).
#[test]
fn t466_8b_mint_gain_ell2() {
    for (txt, want) in [
        (
            "LDG.E.EL.ELL2.256.STRONG.GPU R8, R12, desc[UR4][R3.64]",
            0x000fc2000824f908fe000004030c797eu128,
        ),
        (
            "STG.E.EL.ELL2.256.STRONG.GPU desc[UR4][R5.64], R8, R12",
            0x000fc2000f24f804f8000008050c797fu128,
        ),
    ] {
        for leg in X3 {
            let t = tab(leg);
            let w = enc(&t, txt).unwrap_or_else(|e| panic!("[{leg}] mint-gain {txt:?}: {e}"));
            assert_eq!(w, want, "[{leg}] mint-gain word {txt:?}");
        }
    }
}

#[test]
fn t466_8_refuse_legacy_desc_form() {
    for leg in X3 {
        let t = tab(leg);
        for txt in [
            "LDG.E.NA.ELL2.256.STRONG.GPU R8, R12, desc[UR4][R3.64]",
            "STG.E.NA.ELL2.256.STRONG.GPU desc[UR4][R5.64], R8, R12",
        ] {
            let re = enc(&t, txt);
            assert!(
                re.is_err(),
                "[{leg}] legacy desc-form minted: {txt} -> {:?}",
                re.ok()
            );
        }
    }
    // 121a keeper: desc-form mintuje nadal (sigma nie ruszona).
    let t = tab("sm121a");
    let re = enc(&t, "LDG.E.ELL2.256 R0, R0, desc[UR0][R40.64]");
    assert!(re.is_ok(), "[sm121a] desc keeper refuse: {:?}", re.err());
}

/// t466_9: canonical pin -- graft ib-summar.
#[test]
fn t466_9_canonical_pin() {
    assert_eq!(CANON466.len(), 40);
    assert!(CANON466.starts_with("cc2f62c"));
}

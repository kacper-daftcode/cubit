//! mk59: rekordy d10102 wariant 47 (34B): per site `WARPSYNC.COLLECTIVE
//! R<mask>, L` (nie-.ALL) z regionem (WC..ENDCOLLECTIVE) zlozonym z samych
//! NOP. Domkniecie korpusowe merclab/mk59 (c1..c10; l2 676 plikow, 18932
//! kerneli): count == #WC (4412/4464; wyjatki = strony 4c/23 fail-closed),
//! 47 iff region pusty (NOP): 19903/19935 (reszta = pojedyncze SHFL w
//! regionie -> wariant 4b); F0 == mask<<6 100% obu wariantow; maski zawsze
//! klasy R. Warianty 4b (SHFL-grid, b13/b30 = koordynaty drzewa regionow
//! mk29) i 4c (VOTE) zaparkowane. b30=0 zawsze w 47-only kernelach
//! (15711/15711); w kernelach mieszanych 47 moze miec b30=1/4 (park mk60+).
//! Emisja zastepuje legacy mk15b (REC_D1_COLLECTIVE const per ENDCOLLECTIVE
//! gdy BSSY) — q_bsync_pair/FA4 sealy zachowane.
use cubit::mercury::{merc_d1wc47_record, merc_d1wc_mask_reg, McScanText, mc_scan_lines};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn it(lane: u32, base: &str, full: &str, text: &str) -> McScanText {
    McScanText {
        lane,
        base: base.into(),
        full: full.into(),
        text: text.into(),
        guarded: false,
        guard_code: 0xf8,
    }
}

#[test]
fn record_bytes() {
    // q_bsync_pair (sealed mk15b gold): maska R0 -> legacy const.
    assert_eq!(
        hex(&merc_d1wc47_record(0)),
        "d10102477c06f8001000000000f80000020000000000000000000000000000000000"
    );
    // symv_up_direct_kernel...Li5 (cublas.255): maska R20 -> (b14,b15)=00 05.
    assert_eq!(
        hex(&merc_d1wc47_record(20)),
        "d10102477c06f8001000000000f80005020000000000000000000000000000000000"
    );
    // maska R6 (symv li4-lo): (6<<6)=0x180 -> b14=80 b15=01.
    assert_eq!(
        hex(&merc_d1wc47_record(6)),
        "d10102477c06f8001000000000f88001020000000000000000000000000000000000"
    );
}

#[test]
fn mask_parse() {
    assert_eq!(merc_d1wc_mask_reg("WARPSYNC.COLLECTIVE R20, `(.L_x_899) ;"), Some(20));
    assert_eq!(merc_d1wc_mask_reg("WARPSYNC.COLLECTIVE R0, 0x1b0 !rsd[21:0,22:0] ;"), Some(0));
    // .ALL bez maski / RZ / smieci -> fail-closed
    assert_eq!(merc_d1wc_mask_reg("WARPSYNC.COLLECTIVE.ALL `(.L_x_8083) ;"), None);
    assert_eq!(merc_d1wc_mask_reg("WARPSYNC.COLLECTIVE RZ, `(.L_x_1) ;"), None);
    assert_eq!(merc_d1wc_mask_reg("WARPSYNC.ALL ;"), None);
}

#[test]
fn scan_rules() {
    // poprawny wzorzec: WC + NOP + EC -> rekord na lane WC, maska R12.
    let items = vec![
        it(9, "IMAD.MOV.U32", "IMAD.MOV.U32", "IMAD.MOV.U32 R12, RZ, RZ, -0x1 ;"),
        it(10, "WARPSYNC", "WARPSYNC.COLLECTIVE", "WARPSYNC.COLLECTIVE R12, `(.L_x_1) ;"),
        it(11, "NOP", "NOP", "NOP ;"),
        it(12, "ENDCOLLECTIVE", "ENDCOLLECTIVE", "ENDCOLLECTIVE ;"),
        it(13, "RET", "RET", "RET ;"),
    ];
    assert_eq!(mc_scan_lines(&items).d1wc47, vec![(10, 12u8)]);

    // region z SHFL (korpusowo wariant 4b — zaparkowany) -> brak rekordu;
    // .ALL (korpusowo bez rekordow); region pusty (WC tuz przed EC) -> brak;
    // dwa NOP-y -> rekord (korpus zawsze 1, ale regula toleruje n>=1).
    let items2 = vec![
        it(0, "WARPSYNC", "WARPSYNC.COLLECTIVE", "WARPSYNC.COLLECTIVE R3, `(.L_a) ;"),
        it(1, "SHFL.IDX", "SHFL.IDX", "SHFL.IDX P0, R2, R24, R5, R13 ;"),
        it(2, "ENDCOLLECTIVE", "ENDCOLLECTIVE", "ENDCOLLECTIVE ;"),
        it(3, "WARPSYNC", "WARPSYNC.COLLECTIVE.ALL", "WARPSYNC.COLLECTIVE.ALL `(.L_b) ;"),
        it(4, "NOP", "NOP", "NOP ;"),
        it(5, "ENDCOLLECTIVE", "ENDCOLLECTIVE", "ENDCOLLECTIVE ;"),
        it(6, "WARPSYNC", "WARPSYNC.COLLECTIVE", "WARPSYNC.COLLECTIVE R7, `(.L_c) ;"),
        it(7, "ENDCOLLECTIVE", "ENDCOLLECTIVE", "ENDCOLLECTIVE ;"),
        it(8, "WARPSYNC", "WARPSYNC.COLLECTIVE", "WARPSYNC.COLLECTIVE R9, `(.L_d) ;"),
        it(9, "NOP", "NOP", "NOP ;"),
        it(10, "NOP", "NOP", "NOP ;"),
        it(11, "ENDCOLLECTIVE", "ENDCOLLECTIVE", "ENDCOLLECTIVE ;"),
    ];
    assert_eq!(mc_scan_lines(&items2).d1wc47, vec![(8, 9u8)]);

    // guard na WC -> fail-closed
    let mut items3 = vec![
        it(9, "IMAD.MOV.U32", "IMAD.MOV.U32", "IMAD.MOV.U32 R12, RZ, RZ, -0x1 ;"),
        it(10, "WARPSYNC", "WARPSYNC.COLLECTIVE", "WARPSYNC.COLLECTIVE R12, `(.L_x_1) ;"),
        it(11, "NOP", "NOP", "NOP ;"),
        it(12, "ENDCOLLECTIVE", "ENDCOLLECTIVE", "ENDCOLLECTIVE ;"),
    ];
    items3[1].guarded = true;
    assert!(mc_scan_lines(&items3).d1wc47.is_empty());
}

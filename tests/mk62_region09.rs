//! mk62 (2026-08-13): rekord 51010109 (18B) — DOMKNIECIE per-region:
//! emisja per zamkniecie regionu BSSY.RECONVERGENT (lane BSYNC) z payloadem
//! dw[12:16] = 2*barrier_id. Reguly korpusowe (merclab/mk62 c1..c31,
//! l2 676 / 18932 kerneli):
//!  * payload EXACT: multiset(dw/2) == multiset(barier regionow) zawsze gdy
//!    count-exact (3267/3267); TLV-order == kolejnosc zamkniec (BSYNC lanes).
//!  * count EXACT po bramce diverge (mk10-era): P2-hybrid H = 6021->8022
//!    kerneli TLV-exact na korpusie (+2001), scisla zawieranie P2<=H
//!    (6021 wspolne, 0 strat) — zmiana gwarancja nie-regresu.
//!  * plain-BSSY (dialekty stalych producentow; 00/39 = inne rodzaje
//!    rekordow regionowych) = park mk29-RE.
use cubit::eiattr::{KernelMeta, KernelParam};
use cubit::elf_builder::generate_mercury_full;
use cubit::ir::{ControlCode, Guard, Instruction};
use cubit::mercury::{merc_barrier_id, merc_region09_record, CapMerc, McScanText, mc_scan_lines};

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
fn dummy_code(n: usize) -> Vec<u8> {
    vec![0u8; n * 16]
}
fn meta_with_load() -> KernelMeta {
    KernelMeta {
        name: "t".into(),
        regcount: 16,
        exit_offsets: vec![0u32],
        cbank_param_size: 8,
        params: vec![KernelParam { index: 0, ordinal: 0, offset: 0, size: 8 }],
        merc_param_loads: vec![(1, 0, 0, 8, 0xf8)],
        merc_param_load_dreg: vec![4],
        ..Default::default()
    }
}
fn recs09(out: &[u8]) -> Vec<String> {
    let cm = CapMerc::parse(out, true).unwrap();
    let mut v = Vec::new();
    for r in &cm.records {
        if r.tag.len() >= 4 && r.tag[..4] == [0x51, 0x01, 0x01, 0x09] {
            let mut b = r.tag.to_vec();
            b.extend_from_slice(&r.payload);
            v.push(hex(&b));
        }
    }
    v
}

#[test]
fn record_layout() {
    // bajty z korpusu (c1 payloady top): dw=2*b, reszta stala.
    assert_eq!(
        hex(&merc_region09_record(0)),
        "51010109020af80001000000000000000000"
    );
    assert_eq!(
        hex(&merc_region09_record(1)),
        "51010109020af80001000000020000000000"
    );
    assert_eq!(
        hex(&merc_region09_record(3)),
        "51010109020af80001000000060000000000"
    );
}

#[test]
fn barrier_parse() {
    assert_eq!(merc_barrier_id("B0, `(.L_x_7) ;"), Some(0));
    assert_eq!(merc_barrier_id("B3, `(.L_x_19) ;"), Some(3));
    assert_eq!(merc_barrier_id("B7"), Some(7));
    assert_eq!(merc_barrier_id("B8"), None);
    assert_eq!(merc_barrier_id("`(.L_x_1)"), None);
}

#[test]
fn scan_pairs() {
    // sloopif-shape: 4 plaskie regiony REC b0 -> 4 rekordy na lane'ach close.
    let items = vec![
        it(1, "BSSY", "BSSY.RECONVERGENT", "BSSY.RECONVERGENT B0, `(.L_x_1) ;"),
        it(4, "BSYNC", "BSYNC.RECONVERGENT", "BSYNC.RECONVERGENT B0 ;"),
        it(5, "BSSY", "BSSY.RECONVERGENT", "BSSY.RECONVERGENT B0, `(.L_x_2) ;"),
        it(8, "BSYNC", "BSYNC.RECONVERGENT", "BSYNC.RECONVERGENT B0 ;"),
        it(9, "BSSY", "BSSY.RECONVERGENT", "BSSY.RECONVERGENT B0, `(.L_x_3) ;"),
        it(12, "BSYNC", "BSYNC.RECONVERGENT", "BSYNC.RECONVERGENT B0 ;"),
        it(13, "BSSY", "BSSY.RECONVERGENT", "BSSY.RECONVERGENT B0, `(.L_x_4) ;"),
        it(16, "BSYNC", "BSYNC.RECONVERGENT", "BSYNC.RECONVERGENT B0 ;"),
    ];
    let o = mc_scan_lines(&items);
    assert!(o.region09_ok);
    assert_eq!(o.region09, vec![(4, 0), (8, 0), (12, 0), (16, 0)]);

    // gniazdo B0+B1 (kolejnosc = porzadek close: wewnetrzny najpierw),
    // plain-flavor nie nosi rekordu.
    let items2 = vec![
        it(1, "BSSY", "BSSY.RECONVERGENT", "BSSY.RECONVERGENT B0, `(.L_a) ;"),
        it(2, "BSSY", "BSSY.RECONVERGENT", "BSSY.RECONVERGENT B1, `(.L_b) ;"),
        it(5, "BSYNC", "BSYNC.RECONVERGENT", "BSYNC.RECONVERGENT B1 ;"),
        it(6, "BSSY", "BSSY", "BSSY B2, `(.L_c) ;"), // plain -> bez rekordu
        it(7, "BSYNC", "BSYNC", "BSYNC B2 ;"),
        it(8, "BSYNC", "BSYNC.RECONVERGENT", "BSYNC.RECONVERGENT B0 ;"),
    ];
    let o2 = mc_scan_lines(&items2);
    assert!(o2.region09_ok);
    assert_eq!(o2.region09, vec![(5, 1), (8, 0)]);

    // niespojna para -> ok=false (legacy w elf_builder).
    let items3 = vec![
        it(1, "BSSY", "BSSY.RECONVERGENT", "BSSY.RECONVERGENT B0 ;"),
        it(2, "BSYNC", "BSYNC", "BSYNC B0 ;"),
        it(3, "BSYNC", "BSYNC", "BSYNC B0 ;"),
    ];
    assert!(!mc_scan_lines(&items3).region09_ok);
    let items4 = vec![
        it(1, "BSSY", "BSSY.RECONVERGENT", "BSSY.RECONVERGENT B0 ;"),
    ];
    assert!(!mc_scan_lines(&items4).region09_ok);
}

#[test]
fn emisja_multi_i_legacy() {
    // dwa regiony REC: closes 5 (b0) i 9 (b1) -> rekordy [dw0, dw2].
    let mut m = meta_with_load();
    m.merc_region09 = Some(vec![(5, 0), (9, 1)]);
    m.merc_bsync_close = vec![5, 9];
    let ops: Vec<String> = {
        let mut v = vec!["NOP".to_string(); 12];
        v[2] = "BSSY.RECONVERGENT".into();
        v[5] = "BSYNC.RECONVERGENT".into();
        v[7] = "BSSY.RECONVERGENT".into();
        v[9] = "BSYNC.RECONVERGENT".into();
        v[11] = "EXIT".into();
        v
    };
    let out = generate_mercury_full(&dummy_code(12), 0x0c, Some(&ops), &m, false);
    assert_eq!(
        recs09(&out),
        vec![
            "51010109020af80001000000000000000000",
            "51010109020af80001000000020000000000"
        ]
    );

    // legacy (brak skanu): dokladnie 1 rekord dw=0 jak dotychczas.
    let mut m2 = meta_with_load();
    m2.merc_region09 = None;
    m2.merc_bsync_close = vec![5, 9];
    let out2 = generate_mercury_full(&dummy_code(12), 0x0c, Some(&ops), &m2, false);
    assert_eq!(
        recs09(&out2),
        vec!["51010109020af80001000000000000000000"]
    );

    // gate wylaczony (WARPSYNC w kernelu): zero rekordow nawet z Some(...).
    let mut ops3 = ops.clone();
    ops3[10] = "WARPSYNC.ALL".into();
    let m3 = meta_with_load();
    let mut m3 = m3;
    m3.merc_region09 = Some(vec![(5, 0), (9, 1)]);
    m3.merc_bsync_close = vec![5, 9];
    let out3 = generate_mercury_full(&dummy_code(12), 0x0c, Some(&ops3), &m3, false);
    assert!(recs09(&out3).is_empty());
}

//! mk48: rekordy 024d{0e|24|2e}32 (32B): host = lane REDG (domkniecie swapu
//! 024d0e32<->024d2432 z atlasu mk46; +307 orig-only 024d2e32 bylo niewidoczne).
//!
//! Korpus sm_100 (676 plikow): parowanie rekord<->lane po kluczu
//! (addr,descUR,data,imm) multiset-EXACT; pelna zgodnosc bajtowa
//! 22342/22342 rekordow, 1322/1335 kerneli (13 = forma non-desc S32,
//! tez obsluzona). Porzadek strumienia == lane-asc (72/72 grup remisowe
//! MIN/MAX o identycznych slotach). Tabela klas:
//!   F32.FTZ.RN -> b2=0e b6=80 b7=44 b8=03
//!   F64.RN     -> b2=0e b6=80 b7=47 b8=03 (slot danych |2)
//!   int desc   -> b2=24 b8=01; b6: ADD 00 / MIN 10 / MAX 20 / AND 50 / OR 60;
//!                 b7 = a0|tcode (.S32 -> 2, .64 -> 3); .64 -> slot danych |2
//!   int non-desc [Rn], Rm -> b2=2e, dane @[17:19)
//! Offset adresu (+0x4/+-0x8) -> [28:32) i32 LE. Guard = drabina mk41 (b4).
use cubit::mercury::merc_redg_record;

trait Hex {
    fn hexify(&self) -> String;
}
impl Hex for [u8; 32] {
    fn hexify(&self) -> String {
        self.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[test]
fn float_forms() {
    // F32.FTZ.RN (cublas.255 syhemvl)
    assert_eq!(
        merc_redg_record("REDG.E.ADD.F32.FTZ.RN.STRONG.GPU desc[UR20][R18.64], R23 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024d0e32f80080440300000082040a00000205c0050000000000000000000000"
    );
    // F32 z offsetem +0x4 (cublas.261)
    assert_eq!(
        merc_redg_record("REDG.E.ADD.F32.FTZ.RN.STRONG.GPU desc[UR12][R34.64+0x4], R49 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024d0e32f80080440300000082080a00000203400c0000000000000004000000"
    );
    // F64.RN bez offsetu (cublas.72 cuds_symv)
    assert_eq!(
        merc_redg_record("REDG.E.ADD.F64.RN.STRONG.GPU desc[UR12][R10.64], R28 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024d0e32f80080470300000082020a0000020302070000000000000000000000"
    );
    // F64 z offsetem ujemnym +-0x8 (cublas.72); slot danych |2 (64-bit)
    assert_eq!(
        merc_redg_record("REDG.E.ADD.F64.RN.STRONG.GPU desc[UR12][R10.64+-0x8], R12 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024d0e32f80080470300000082020a00000203020300000000000000f8ffffff"
    );
}

#[test]
fn int_desc_forms() {
    // ADD domyslny, bez guarda (cusolver.213)
    assert_eq!(
        merc_redg_record("REDG.E.ADD.STRONG.GPU desc[UR6][R2.64], R7 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024d2432f80000a00100000082000a00008201c0010000000000000000000000"
    );
    // ADD @P0 -> b4=0x00 (cusolver.1020)
    assert_eq!(
        merc_redg_record("REDG.E.ADD.STRONG.GPU desc[UR6][R2.64], R7 ;", 0x00)
            .unwrap()
            .hexify(),
        "024d2432000000a00100000082000a00008201c0010000000000000000000000"
    );
    // MIN domyslny @P0 (cublasLt.191 splitKreduce)
    assert_eq!(
        merc_redg_record("REDG.E.MIN.STRONG.GPU desc[UR8][R2.64], R5 ;", 0x00)
            .unwrap()
            .hexify(),
        "024d2432000010a00100000082000a0000020240010000000000000000000000"
    );
    // MAX.S32 @P0 (cublasLt.191)
    assert_eq!(
        merc_redg_record("REDG.E.MAX.S32.STRONG.GPU desc[UR8][R2.64], R5 ;", 0x00)
            .unwrap()
            .hexify(),
        "024d2432000020a20100000082000a0000020240010000000000000000000000"
    );
    // MIN.S32 @P0 (cusolver.1020)
    assert_eq!(
        merc_redg_record("REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64], R9 ;", 0x00)
            .unwrap()
            .hexify(),
        "024d2432000010a20100000002010a0000820140020000000000000000000000"
    );
    // MIN.64: b7=a3, slot danych |2 (cusparse.254)
    assert_eq!(
        merc_redg_record("REDG.E.MIN.64.STRONG.GPU desc[UR10][R2.64], R4 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024d2432f80010a30100000082000a0000820202010000000000000000000000"
    );
    // MAX.64 (cusparse.254)
    assert_eq!(
        merc_redg_record("REDG.E.MAX.64.STRONG.GPU desc[UR10][R8.64], R6 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024d2432f80020a30100000002020a0000820282010000000000000000000000"
    );
    // OR @P0 (cusolver.1915)
    assert_eq!(
        merc_redg_record("REDG.E.OR.STRONG.GPU desc[UR6][R2.64], R5 ;", 0x00)
            .unwrap()
            .hexify(),
        "024d2432000060a00100000082000a0000820140010000000000000000000000"
    );
    // ADD.64 z offsetem +0x8 (cusparse.318)
    assert_eq!(
        merc_redg_record("REDG.E.ADD.64.STRONG.GPU desc[UR6][R6.64+0x8], R8 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024d2432f80000a30100000082010a0000820102020000000000000008000000"
    );
    // int z offsetem +0x4 (cusparse.158)
    assert_eq!(
        merc_redg_record("REDG.E.ADD.STRONG.GPU desc[UR14][R12.64+0x4], R9 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024d2432f80000a00100000002030a0000820340020000000000000004000000"
    );
}

#[test]
fn non_desc_s32() {
    // forma non-desc: REDG.E.ADD.S32.STRONG.GPU [R4], R3 (cublasLt.548
    // cutlass_80 imma-emu kernele) — tag 024d2e32, dane @[17:19).
    assert_eq!(
        merc_redg_record("REDG.E.ADD.S32.STRONG.GPU [R4], R3 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024d2e32f80000a20100000002010a0000c00000000000000000000000000000"
    );
    // drugi wariant z korpusu: [R16], R3
    assert_eq!(
        merc_redg_record("REDG.E.ADD.S32.STRONG.GPU [R16], R3 ;", 0xf8)
            .unwrap()
            .hexify(),
        "024d2e32f80000a20100000002040a0000c00000000000000000000000000000"
    );
}

#[test]
fn rejections() {
    // nie-REDG
    assert!(merc_redg_record("ATOMG.E.ADD.STRONG.GPU desc[UR6][R2.64], R5", 0xf8).is_none());
    // REDG z danymi RZ: forma nieobserwowana w korpusie
    assert!(merc_redg_record("REDG.E.ADD.STRONG.GPU desc[UR6][R2.64], RZ", 0xf8).is_none());
    // float non-desc: forma nieobserwowana
    assert!(merc_redg_record("REDG.E.ADD.F32.FTZ.RN.STRONG.GPU [R4], R3", 0xf8).is_none());
    // non-desc z adresem .64: forma nieobserwowana
    assert!(merc_redg_record("REDG.E.ADD.S32.STRONG.GPU [R4.64], R3", 0xf8).is_none());
}

#[test]
fn guard_ladder_mk41() {
    // @P1 -> b4=0x08; @!P2 -> 0x11 (drabina mk41 zweryfikowana korpusowo
    // w c6: 22342/22342 rekordow z g4() exact, w tym guardowane MIN.S32).
    let r = merc_redg_record("REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64], R9 ;", 0x08).unwrap();
    assert_eq!(r[4], 0x08);
    let r = merc_redg_record("REDG.E.MIN.S32.STRONG.GPU desc[UR6][R4.64], R9 ;", 0x11).unwrap();
    assert_eq!(r[4], 0x11);
}

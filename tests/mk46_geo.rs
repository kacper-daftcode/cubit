//! mk46: rekordy 010b060a (geo-anchory smem): host = S2UR ze SR geometrii
//! (CTAID.X/Y/Z -> role 4/5/6 == id sysreg, CgaCtaId -> 0x2c, SWINHI -> 0x2d;
//! klasa b13=2) LUB LDCU .32 z okna stalych drivera c[0x0][off] (0x360..0x378
//! without 0x36c -> roles 1..6, 0x2f8/0x2fc -> 68/69; class b13=4). Closure
//! korpusowe (676 plikow sm_100, 18932 kerneli): multiset (klasa,rola,dst)
//! EXACT 17674/17674 kerneli z rekordami; porzadek strumienia == porzadek
//! lane (17674/17674); b4 = 0xfa / 0x03 guarded; do not touch the bitmaps.
use cubit::mercury::{merc_geo_anchor, merc_geo_record};

#[test]
fn s2ur_roles() {
    assert_eq!(merc_geo_anchor("S2UR UR5, SR_CgaCtaId ;", "S2UR", "S2UR"), Some((5, 0x2c, 2)));
    assert_eq!(merc_geo_anchor("S2UR UR4, SR_CTAID.X ;", "S2UR", "S2UR"), Some((4, 4, 2)));
    assert_eq!(merc_geo_anchor("S2UR UR6, SR_CTAID.Y ;", "S2UR", "S2UR"), Some((6, 5, 2)));
    assert_eq!(merc_geo_anchor("S2UR UR2, SR_CTAID.Z ;", "S2UR", "S2UR"), Some((2, 6, 2)));
    assert_eq!(merc_geo_anchor("S2UR UR9, SR_SWINHI ;", "S2UR", "S2UR"), Some((9, 0x2d, 2)));
    // outside the map (they don't exist in the corpus as hosts)
    assert_eq!(merc_geo_anchor("S2UR UR4, SR_GLOBALTIMERLO ;", "S2UR", "S2UR"), None);
    assert_eq!(merc_geo_anchor("S2R R0, SR_TID.X ;", "S2R", "S2R"), None);
    // z guardem
    assert_eq!(
        merc_geo_anchor("@!P0 S2UR UR7, SR_CgaCtaId ;", "S2UR", "S2UR"),
        Some((7, 0x2c, 2))
    );
}

#[test]
fn ldcu_window() {
    assert_eq!(merc_geo_anchor("LDCU UR4, c[0x0][0x360] ;", "LDCU", "LDCU"), Some((4, 1, 4)));
    assert_eq!(merc_geo_anchor("LDCU UR5, c[0x0][0x364] ;", "LDCU", "LDCU"), Some((5, 2, 4)));
    assert_eq!(merc_geo_anchor("LDCU UR3, c[0x0][0x368] ;", "LDCU", "LDCU"), Some((3, 3, 4)));
    assert_eq!(merc_geo_anchor("LDCU UR7, c[0x0][0x370] ;", "LDCU", "LDCU"), Some((7, 4, 4)));
    assert_eq!(merc_geo_anchor("LDCU UR8, c[0x0][0x374] ;", "LDCU", "LDCU"), Some((8, 5, 4)));
    assert_eq!(merc_geo_anchor("LDCU UR6, c[0x0][0x378] ;", "LDCU", "LDCU"), Some((6, 6, 4)));
    assert_eq!(merc_geo_anchor("LDCU UR4, c[0x0][0x2f8] ;", "LDCU", "LDCU"), Some((4, 68, 4)));
    assert_eq!(merc_geo_anchor("LDCU UR4, c[0x0][0x2fc] ;", "LDCU", "LDCU"), Some((4, 69, 4)));
    // poza oknem
    assert_eq!(merc_geo_anchor("LDCU UR4, c[0x0][0x36c] ;", "LDCU", "LDCU"), None);
    assert_eq!(merc_geo_anchor("LDCU UR4, c[0x0][0x37c] ;", "LDCU", "LDCU"), None);
    assert_eq!(merc_geo_anchor("LDCU UR4, c[0x0][0x380] ;", "LDCU", "LDCU"), None);
    assert_eq!(merc_geo_anchor("LDCU UR4, c[0x0][0x390] ;", "LDCU", "LDCU"), None);
    // the .64 variant is never a host (corpus: zero .64 in the window)
    assert_eq!(merc_geo_anchor("LDCU.64 UR8, c[0x0][0x360] ;", "LDCU", "LDCU.64"), None);
}

#[test]
fn payload_bytes() {
    // korpus tpttr: (dst=6, rol=CTAID.X=4, cls=2) -> 81 01 04 02
    let r = merc_geo_record(6, 4, 2, 0xf8);
    assert_eq!(r.hexify(), "010b060afa0004000000810104020000");
    // (dst=5, rol=2, cls=4) LDCU 0x364: b10/b11=(5<<6)|1=0x141 -> 41 01
    assert_eq!(merc_geo_record(5, 2, 4, 0xf8).hexify(), "010b060afa0004000000410102040000");
    // (dst=8, rol=4, cls=4) LDCU 0x370: (8<<6)|1=0x201 -> 01 02
    assert_eq!(merc_geo_record(8, 4, 4, 0xf8).hexify(), "010b060afa0004000000010204040000");
    // guarded @!P0 (kod 0x01): b4 = 0x01|2 = 0x03 (korpus symv_tma_ws: dst 9, rol 2c)
    assert_eq!(merc_geo_record(9, 0x2c, 2, 0x01).hexify(), "010b060a03000400000041022c020000");
    // guarded @UP2 (kod 0x12): b4 = 0x12 (korpus xmma kernel_blasl3)
    assert_eq!(merc_geo_record(13, 6, 2, 0x12).hexify(), "010b060a120004000000410306020000");
    // SWINHI
    assert_eq!(merc_geo_record(5, 0x2d, 2, 0xf8).hexify(), "010b060afa000400000041012d020000");
}

trait Hex { fn hexify(&self) -> String; }
impl Hex for [u8; 16] {
    fn hexify(&self) -> String { self.iter().map(|b| format!("{:02x}", b)).collect() }
}

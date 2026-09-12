// BUG-423 witness data (F2-iter242, loop5/blind front2, 2026-09-10):
// sm121a LDSM.16.M88_R_AUR era-key recanon DELETE + LDSM_R_ARURI|16,M88
// vm |= (7<<84) x4 legs. Machine-built by work/bug423/gen423pins.py
// (rc=2 fail-closed; no hand hex) from arb423_law.json x4-vendor law +
// measure423_pre/post (publish 485b75d8 vs work .so).
pub const CANON423: &str = "9b60b92014970a8d386c7dafea93d087862dca5e" /* ride F2-iter255 (BUG-450 graft): 9b60b92014970a8d386c7dafea93d087862dca5e canonical, was 099faa0 = BUG-447 F2-iter252 */; // BUG-447 graft F2-iter252; rides e8d1af3 = BUG-443 F2-iter250, 57e7ecd = BUG-442 F2-iter246, ffa3244 = BUG-441 F2-iter245, bb1ba6c = BUG-438 F2-iter244, 54c5b02 = BUG-439 F2-iter243, 3032686 = BUG-423 F2-iter242, 61858fb = BUG-433 F2-iter241; older: 0a6b178 = BUG-435+434+435b, 1810912 hop, 70eb0fe = BUG-416

/// words whose engine decode was healed to vendor text by the graft
/// (37 fabrication cells sm121a + 36 j84-family HOLE cells x3 = 73
/// cell-legs over these words); vendor text unanimous x4 (arb423 law).
pub const LAW423_HEAL: &[(u128, &str)] = &[
    (0x0000000008000001000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b64 healed x4
    (0x000000000800000100000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b64 healed x4
    (0x0000000008000002000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b65 healed x4
    (0x000000000800000200000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b65 healed x4
    (0x0000000008000004000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b66 healed x4
    (0x000000000800000400000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b66 healed x4
    (0x0000000008000008000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b67 healed x4
    (0x000000000800000800000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b67 healed x4
    (0x0000000008000010000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b68 healed x4
    (0x000000000800001000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b68 healed x4
    (0x0000000008000020000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b69 healed x4
    (0x000000000800002000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b69 healed x4
    (0x0000000008000040000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b70 healed x4
    (0x000000000800004000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b70 healed x4
    (0x0000000008000080000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b71 healed x4
    (0x000000000800008000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b71 healed x4
    (0x00000000080000ff00000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // B.rz.j64all healed x4
    (0x0000000008100000000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b84 healed x4
    (0x000000000810000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b84 healed x4
    (0x000000000810000100000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // B.rz.pair64.84 healed x4
    (0x0000000008200000000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b85 healed x4
    (0x000000000820000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b85 healed x4
    (0x0000000008400000000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b86 healed x4
    (0x000000000840000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b86 healed x4
    (0x000000000870000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // B.rz.j84all healed x4
    (0x00000000087000ff00000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // B.rz.full healed x4
];

/// words already vendor-exact pre-graft that must stay (continuity).
pub const LAW423_STABLE: &[(u128, &str)] = &[
    (0x000000000000000000000004ff10783b, "LDSM.16.M88 R16, [RZ]"), // D.b91clr stable x4
    (0x000000000800000000000000ff10783b, "LDSM.16.M88 R16, [UR0]"), // A.ur0 stable x4
    (0x0000000008000000000000040010783b, "LDSM.16.M88 R16, [R0+UR4]"), // A.base0 stable x4
    (0x0000000008000000000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // A.base5 stable x4
    (0x000000000800000000000004ff00783b, "LDSM.16.M88 R0, [UR4]"), // A.dst0 stable x4
    (0x000000000800000000000004ff10083b, "@P0 LDSM.16.M88 R16, [UR4]"), // A.g0 stable x4
    (0x000000000800000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // A.ref stable x4
    (0x000000000800000000000004ff3f783b, "LDSM.16.M88 R63, [UR4]"), // A.dst63 stable x4
    (0x00000000080000000000003fff10783b, "LDSM.16.M88 R16, [UR63]"), // A.ur63 stable x4
    (0x0000000008000000000000ffff10783b, "LDSM.16.M88 R16, [URZ]"), // A.ur255 stable x4
    (0x000000000800000000000104ff10783b, "LDSM.16.M88 R16, [UR4+0x1]"), // A.imm1 stable x4
    (0x00000000080000007fffff04ff10783b, "LDSM.16.M88 R16, [UR4+0x7fffff]"), // A.imm7fffff stable x4
    (0x000000000800000080000004ff10783b, "LDSM.16.M88 R16, [UR4+-0x800000]"), // A.imm800000 stable x4
    (0x000000000800010000000004ff10783b, "LDSM.16.M88.2 R16, [UR4]"), // E.b72 stable x4
    (0x000000000800010100000004ff10783b, "LDSM.16.M88.2 R16, [UR4]"), // E.b72.b64 stable x4
    (0x000000000800020000000004ff10783b, "LDSM.16.M88.4 R16, [UR4]"), // E.b73 stable x4
    (0x000000010800000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // F.era1 stable x4
    (0x0001c0000800000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // F.era1c000 stable x4
    (0x000fc2000800000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // F.era0fc200 stable x4
];

/// BUG-439-HEALED: D-class singles {b87,b90,b92,b95} -- engine-HOLE
/// posture DOMKNIETE by BUG-439 graft (canonical 54c5b02, ARURI|16,M88
/// vm |= 0x129<<87); decode == vendor-exact x4 (flip439.py BUG-439-healed).
pub const POSTURE439: &[(u128, &str)] = &[
    (0x000000000880000000000004ff10783b, "D.b87"), // BUG-439-healed vendor-exact x4 (was standing-HOLE posture; law arb423/arb439)
    (0x000000000c00000000000004ff10783b, "D.b90"), // BUG-439-healed vendor-exact x4 (was standing-HOLE posture; law arb423/arb439)
    (0x000000001800000000000004ff10783b, "D.b92"), // BUG-439-healed vendor-exact x4 (was standing-HOLE posture; law arb423/arb439)
    (0x000000008800000000000004ff10783b, "D.b95"), // BUG-439-healed vendor-exact x4 (was standing-HOLE posture; law arb423/arb439)
];

/// 440-kand: b122/b123/b124 singles = vendor RC1 REFUSE x4 but the ENGINE
/// era cut [127:96) admits them on every leg (decoder.rs ERA domain =
/// ENGINE-gated, jak 428/430/431; snapped machine text post-graft).
pub const POSTURE440: &[(u128, &str, &str)] = &[
    (0x040000000800000000000004ff10783b, "C.b122", "LDSM.16.M88 R16, [UR4]"), // 440-kand standing engine-era-cut claim (vendor RC1 x4; pre 121a fabricated 'LDSM.16.M88 R16, [UR4]')
    (0x080000000800000000000004ff10783b, "C.b123", "LDSM.16.M88 R16, [UR4]"), // 440-kand standing engine-era-cut claim (vendor RC1 x4; pre 121a fabricated 'LDSM.16.M88 R16, [UR4]')
    (0x100000000800000000000004ff10783b, "C.b124", "LDSM.16.M88 R16, [UR4]"), // 440-kand standing engine-era-cut claim (vendor RC1 x4; pre 121a fabricated 'LDSM.16.M88 R16, [UR4]')
];

/// byte-exact encode mints + text circle, x4 legs (clean carriers).
/// encode-demote (decode-only pins above; machine-checked set): D.b91clr=word drift (cmpmask era/junk excl) 000fc2000000000000000000f; A.ur255=parse error: unencodable memory address "[URZ]": every brack
pub const MINT423: &[(u128, &str)] = &[
    (0x000000000800000000000000ff10783b, "LDSM.16.M88 R16, [UR0]"), // A.ur0 x4 mint byte-exact+circle
    (0x0000000008000000000000040010783b, "LDSM.16.M88 R16, [R0+UR4]"), // A.base0 x4 mint byte-exact+circle
    (0x0000000008000000000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // A.base5 x4 mint byte-exact+circle
    (0x000000000800000000000004ff00783b, "LDSM.16.M88 R0, [UR4]"), // A.dst0 x4 mint byte-exact+circle
    (0x000000000800000000000004ff10083b, "@P0 LDSM.16.M88 R16, [UR4]"), // A.g0 x4 mint byte-exact+circle
    (0x000000000800000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // A.ref x4 mint byte-exact+circle
    (0x000000000800000000000004ff3f783b, "LDSM.16.M88 R63, [UR4]"), // A.dst63 x4 mint byte-exact+circle
    (0x00000000080000000000003fff10783b, "LDSM.16.M88 R16, [UR63]"), // A.ur63 x4 mint byte-exact+circle
    (0x000000000800000000000104ff10783b, "LDSM.16.M88 R16, [UR4+0x1]"), // A.imm1 x4 mint byte-exact+circle
    (0x00000000080000007fffff04ff10783b, "LDSM.16.M88 R16, [UR4+0x7fffff]"), // A.imm7fffff x4 mint byte-exact+circle
    (0x000000000800000080000004ff10783b, "LDSM.16.M88 R16, [UR4+-0x800000]"), // A.imm800000 x4 mint byte-exact+circle
    (0x000000000800010000000004ff10783b, "LDSM.16.M88.2 R16, [UR4]"), // E.b72 x4 mint byte-exact+circle
    (0x000000000800010100000004ff10783b, "LDSM.16.M88.2 R16, [UR4]"), // E.b72.b64 x4 mint byte-exact+circle
    (0x000000000800020000000004ff10783b, "LDSM.16.M88.4 R16, [UR4]"), // E.b73 x4 mint byte-exact+circle
    (0x000000010800000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // F.era1 x4 mint byte-exact+circle
    (0x0001c0000800000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // F.era1c000 x4 mint byte-exact+circle
    (0x000fc2000800000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // F.era0fc200 x4 mint byte-exact+circle
];

/// masked encode mints ([64:72)|[84:87) junk band encode-zeroed) + circle.
pub const MASKMINT423: &[(u128, &str)] = &[
    (0x0000000008000001000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b64 x4 masked-mint (j-band encode-zeroed) + circle
    (0x000000000800000100000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b64 x4 masked-mint (j-band encode-zeroed) + circle
    (0x0000000008000002000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b65 x4 masked-mint (j-band encode-zeroed) + circle
    (0x000000000800000200000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b65 x4 masked-mint (j-band encode-zeroed) + circle
    (0x0000000008000004000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b66 x4 masked-mint (j-band encode-zeroed) + circle
    (0x000000000800000400000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b66 x4 masked-mint (j-band encode-zeroed) + circle
    (0x0000000008000008000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b67 x4 masked-mint (j-band encode-zeroed) + circle
    (0x000000000800000800000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b67 x4 masked-mint (j-band encode-zeroed) + circle
    (0x0000000008000010000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b68 x4 masked-mint (j-band encode-zeroed) + circle
    (0x000000000800001000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b68 x4 masked-mint (j-band encode-zeroed) + circle
    (0x0000000008000020000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b69 x4 masked-mint (j-band encode-zeroed) + circle
    (0x000000000800002000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b69 x4 masked-mint (j-band encode-zeroed) + circle
    (0x0000000008000040000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b70 x4 masked-mint (j-band encode-zeroed) + circle
    (0x000000000800004000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b70 x4 masked-mint (j-band encode-zeroed) + circle
    (0x0000000008000080000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b71 x4 masked-mint (j-band encode-zeroed) + circle
    (0x000000000800008000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b71 x4 masked-mint (j-band encode-zeroed) + circle
    (0x00000000080000ff00000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // B.rz.j64all x4 masked-mint (j-band encode-zeroed) + circle
    (0x0000000008100000000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b84 x4 masked-mint (j-band encode-zeroed) + circle
    (0x000000000810000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b84 x4 masked-mint (j-band encode-zeroed) + circle
    (0x000000000810000100000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // B.rz.pair64.84 x4 masked-mint (j-band encode-zeroed) + circle
    (0x0000000008200000000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b85 x4 masked-mint (j-band encode-zeroed) + circle
    (0x000000000820000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b85 x4 masked-mint (j-band encode-zeroed) + circle
    (0x0000000008400000000000040510783b, "LDSM.16.M88 R16, [R5+UR4]"), // B.r5.b86 x4 masked-mint (j-band encode-zeroed) + circle
    (0x000000000840000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // ride.b86 x4 masked-mint (j-band encode-zeroed) + circle
    (0x000000000870000000000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // B.rz.j84all x4 masked-mint (j-band encode-zeroed) + circle
    (0x00000000087000ff00000004ff10783b, "LDSM.16.M88 R16, [UR4]"), // B.rz.full x4 masked-mint (j-band encode-zeroed) + circle
];

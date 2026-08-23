//! Table-driven PTX → SASS instruction mapping.
//!
//! Each PTX opcode pattern maps to a SASS template describing:
//! - The SASS opcode + modifiers
//! - How PTX operands map to SASS operand slots
//! - Any implicit operands (PT, RZ, etc.)
//!
//! ~70% of PTX instructions are "simple" 1:1 mappings handled by a single
//! table entry.  The remaining ~30% (64-bit ops, ld.param, MMA, cvt) use
//! special-case expansion variants.

/// How a SASS operand slot is filled from the PTX instruction.
#[derive(Debug, Clone, Copy)]
pub enum OpSlot {
    /// PTX operand at index `i`, as a register.
    Src(usize),
    /// PTX operand at index `i`, negated register.
    NegSrc(usize),
    /// PTX operand at index `i`, absolute value.
    AbsSrc(usize),
    /// PTX operand at index `i`, as immediate (pass through).
    Imm(usize),
    /// Implicit predicate PT (always-true, P7).
    PT,
    /// Implicit register RZ (zero, R255).
    RZ,
    /// Implicit negated-PT (!PT).
    NotPT,
    /// b9p13 (phase-3 #11): implicit negated RZ (`-RZ`; abs.f32 unary-FADD
    /// form `FADD d, -RZ, |a|`, anchor corpus p18 O0 0x350).
    NegRZ,
}

/// What kind of SASS output a PTX rule produces.
#[derive(Debug, Clone)]
pub enum SassTemplate {
    /// One PTX instruction → one SASS instruction.
    Single {
        opcode: &'static str,
        slots: &'static [OpSlot],
    },

    /// 64-bit integer add (2 instructions: IADD3 + IADD3.X carry chain).
    Add64,
    /// 64-bit move (2 MOVs for lo/hi halves).
    Mov64,
    /// Load kernel parameter from constant bank.
    LoadParam,
    /// mov from special register (%tid.x etc.) → S2R.
    SpecialRegMov,
    /// Type conversion (cvt.*).
    Cvt,
    /// MMA instruction (complex opcode/type/shape extraction).
    Mma,
    /// Integer comparison → ISETP.
    ISetp,
    /// Float comparison → FSETP.
    FSetp,
    /// Shuffle → SHFL.
    Shfl,
    /// b9p12 (phase-3 #10): popc.b32 = LOP3(~0)/LOP3(&)/POPC idiom.
    Popc32,
    /// b9p12: brev.b32 = BREV; SHF.R.U32.HI by RZ; SGXT.U32 0x20.
    Brev32,
    /// b9p12: clz.b32 = FLO.U32; IADD3 d,PT,PT,-x,0x1f,RZ (31-x fixup).
    Clz32,
    /// b9p12: bfe.u32 with IMMEDIATE pos/len = 8-op vendor -O0 macro.
    BfeU32,
    /// b9p12: bar.red.{and,or}.pred = WARPSYNC.ALL + BAR.RED.x + B2R.RESULT.
    BarRed { or: bool },
    /// b9p12: bar.sync / barrier.sync[.aligned] family (imm / imm+count / pack).
    BarSync { aligned: bool },
    /// b9p12: barrier.arrive[.aligned] (direct II_II / pack + BAR.ARV).
    BarArrive { aligned: bool },
    /// b9p12: discard.global.L2 [a], 128 = CCTL.E.RML2 [pair].
    DiscardL2,
    /// Global load (scalar or vector).
    LdGlobal,
    /// Global store (scalar or vector).
    StGlobal,
    /// Address space conversion (NOP on SM120).
    Nop,
    /// mul.wide.s32/u32 -> IMAD.WIDE / IMAD.WIDE.U32 (64-bit product pair,
    /// zero addend). Vendor form anchored in b9 phase-1 (nvdisasm byte-parity
    /// payload: IMAD.WIDE R2, R9, 0x4, R2 probe).
    MulWide { unsigned: bool },
    /// cvta.to.global.u64: register-pair alias (generic==global VA on
    /// SM103a/120); emits NO code, unifies the dst pair with the src pair.
    AliasPair,
    /// b9 phase-3 P1': PTX predicate logic (and/or/xor/not.pred, mov.pred)
    /// -> PLOP3.LUT predicate-domain. Form + LUT bytes are vendor anchors
    /// (ptxas 13.3 -O0 sm_103a, full 16-byte word parity IDENT x5 over
    /// probes work/b9p3/plp{1,2}): `PLOP3.LUT Pd, PT, Pa, Pb, PT, immA,
    /// immB`; immA is the op as f(a, b) with the third input tied PT
    /// (c=0 rows are don't-care, ptxas choices preserved verbatim:
    /// and/mov = 0x80, or = 0xf8, xor = 0x28, not = 0x08), immB is the
    /// inert second-destination table (Pd1 == PT, writes discarded), kept
    /// verbatim for byte-parity (and/mov = 0x08, or = 0x8f, xor = 0x82,
    /// not = 0x80).
    PredLogic { lut_a: u8, lut_b: u8 },
    /// b9 phase-3 #12 (b9p14): PTX vector shared ld/st are width-joined
    /// hw ops on sm_103a: lane-count x member-width selects the suffix
    /// (v2.b32 -> .64 pair; v2.b64/v4.b32 -> .128 quad; v4.b64 = 256-bit
    /// FAIL-closed, no STS/LDS.256 row). Imm/float-literal group members
    /// materialize via IMAD.MOV.U32 pre-MOVs (vendor form; corpus p29
    /// 0x140-0x180 shows four const MOVs before STS.128). Vendor law
    /// anchors: probes work/b9p14/probes q3/q4 -O0/-O3; corpus p13/p29.
    ///   ld: LDS.128 Qd, [R+imm]   (dst = aligned QUAD)
    ///   st: STS.128 [R+imm], Qs
    /// Same .128 law anchors ld.global.v2.b64 (LDG.E.128) /
    /// st.global.v2.b64 (STG.E.128) via lower_ld/st_global member-width
    /// suffix selection. Guarded forms pass the guard through verbatim.
    /// Process note: reached by EXACT-00030-class exposure (p29 went
    /// half-green on the vec64 fix and surfaced a pre-existing silent
    /// bare-STS flattening of v4.b32 groups + float-imm members).
    SharedVec { store: bool },
    /// b9 phase-3 #2: 64-bit bitwise logic (and/or/xor/not.b64) -> two
    /// 32-bit LOP3.LUT for the lo/hi halves of the register pair. Form and
    /// LUT bytes are vendor anchors (ptxas 13.3 -O0 sm_103a, probes
    /// work/b9p4/probes/bl{1,2,3}; 24-word payload parity IDENT bytes[0:12]
    /// modulo the scheduling dword + decode-equivalence by nvdisasm):
    ///   bin reg-src: LOP3.LUT Rd_{lo,hi}, Ra_{lo,hi}, Rb_{lo,hi}, RZ, lut, !PT
    ///   bin imm-src: LOP3.LUT Rd_{lo,hi}, Ra_{lo,hi}, imm{lo,hi},  RZ, lut, !PT
    ///   unary not:   LOP3.LUT Rd_{lo,hi}, RZ, Ra_{lo,hi}, RZ, 0x33, !PT
    /// and/or/xor tie the third LOP3 input c to RZ (don't-care rows; ptxas
    /// choice preserved verbatim) with a single LUT byte (and = 0xc0 = a&b,
    /// or = 0xfc = a|b, xor = 0x3c = a^b); not ties slot a to RZ and
    /// negates slot b (0x33 = !b) — vendor puts the input in slot b
    /// (measured, bl1), unlike the pre-existing b32 not rule (slot a,
    /// 0x0f), see F1 of results/b9/B9-PHASE3-B64LOG.md. A 64-bit immediate
    /// source splits into 32-bit halves and a zero half renders as RZ
    /// (vendor normalization, measured in bl3 for both halves/all ops).
    B64Logic { lut: u8 },
    /// b9 phase-3 #3: 32-bit add/sub with PTX CC carry chain -> IADD3 /
    /// IADD3.X with physical-predicate carry slots. Vendor anchors (ptxas
    /// 13.3, sm_103a; byte-parity probes work/b9p5/probes cr{1,2,4}_O3,
    /// retro-enc proof neg1 on b9p4 HEAD):
    ///   add.cc:   IADD3   d, Pcf, PT, a, b, RZ
    ///   addc:     IADD3.X d, PT, PT, a, b, RZ, Pcin, !PT
    ///   addc.cc:  IADD3.X d, Pcf, PT, a, b, RZ, Pcin, !PT
    ///   sub.cc:   IADD3   d, Pcf, PT, a, -b, RZ
    ///   subc:     IADD3.X d, PT, PT, ~b, a, RZ, Pcin, !PT
    ///   subc.cc:  IADD3.X d, Pcf, PT, ~b, a, RZ, Pcin, !PT
    /// (-O3 fused single-instruction forms; -O0 splits result/carry into two
    /// IADD3s, semantically equal). Sub-with-carry puts the bitwise-negated
    /// subtrahend in slot A and the minuend in slot B (a + ~b + cin ==
    /// a - b - !cin). Immediate normalization (corpus-attested): addc imm==0
    /// -> RZ; subc imm=v -> arithmetic ~v = -(v+1) as signed imm (-0x1
    /// proven byte-exact). Other immediate shapes are unanchored ->
    /// fail-closed, as are guarded cc-ops (0 in 93,826 corpus sites).
    CarryChain32 { cin: bool, cout: bool, sub: bool },
    /// b9 phase-3 #3: mad.lo.cc.u32 / madc.hi.u32 carry decomposition
    /// (anchor probe cr3 -O0; the -O3 IMAD.WIDE.U32 fusion is a CROSS-op
    /// optimization over the pair, not a per-op lowering - DO NOT copy):
    ///   mad.lo.cc: IMAD.U32 d, a, b, c ; IMAD t, a, b, RZ ;
    ///              IADD3 RZ, Pcf, PT, t, c, RZ
    ///   madc.hi:   IMAD.HI.U32 t, a, b, RZ ;
    ///              IADD3.X d, PT, PT, t, c, RZ, Pcin, !PT  (c==0 -> RZ)
    MadCc { hi: bool },
    /// b9 phase-3 #4: PTX atomic memory op. All lowering decisions are
    /// vendor anchors (ptxas 13.3 sm_103a probes work/b9p6/at1..at7 -- full
    /// byte-parity evidence in results/b9/atomred_parity/). Semantics beyond
    /// decode in lower_atomic (ptx_lower.rs); summary:
    ///   global/generic -> ATOM[G].E.<suffix>.STRONG.<scope> PT, Rd,
    ///                     desc[UR4][Ra.64+off], Rv   (CAS: plain [Ra+off],
    ///                     no desc; compare operand inserted before value)
    ///   shared         -> ATOMS.<suffix> Rd, [Ra+off], Rv   (sem/scope
    ///                     stripped; UR/uniform datapath form not used)
    ///   acq_rel.gpu    -> vendor glue: MEMBAR.ALL.GPU; ERRBAR; CGAERRBAR;
    ///                     <atomic>; CCTL.IVALL   (at5_sem -O0 anchor)
    /// BUG-080 policy: guarded atomic-class ops are fail-closed (silicon
    /// drops them on sm_103a; the encoder hard-fails them upstream).
    Atom,
    /// b9 phase-3 #4: PTX reduction atomic (no return value):
    ///   red.global -> REDG.E.<suffix>.STRONG.GPU desc[UR4][Ra.64+off], Rv
    /// Anchored for add.u32 / add.f32 only (probes at5); other op/type
    /// combos fail closed even where RE-table mgs exist.
    Red,
    /// b9 phase-3 #3: 64-bit shifts -> SHF pair (anchors sh1/sh5; -O0 and
    /// -O3 emit the same pair modulo register naming):
    ///   shl.b64: SHF.L.U64.HI d_hi, a_lo, s, a_hi ; SHF.L.U32 d_lo, a_lo, s, RZ
    ///   shr.u64: SHF.R.U64   d_lo, a_lo, s, a_hi ; SHF.R.U32.HI d_hi, RZ, s, a_hi
    ///   shr.s64: SHF.R.S64   d_lo, a_lo, s, a_hi ; SHF.R.S32.HI d_hi, RZ, s, a_hi
    /// High part first (vendor order; correct for in-place dst==src).
    /// Shift amount is the 32-bit PTX operand 2 (reg or immediate).
    Shift64 { dir_left: bool, signed: bool },
    /// b9 phase-3 #5: fence/membar family -> fixed vendor glue sequences
    /// (no operands). Vendor anchors ptxas 13.3 -O0/-O3 sm_103a, probes
    /// fm1/fm2/fm3 (+O3): O0 and O3 emit IDENTICAL glue.
    ///   membar.cta                  -> MEMBAR.SC.CTA
    ///   membar.gl                   -> MEMBAR.SC.GPU; ERRBAR; CGAERRBAR; CCTL.IVALL
    ///   membar.sys                  -> MEMBAR.SC.SYS; ERRBAR; CGAERRBAR; CCTL.IVALL
    ///   fence.sc.cta / acq_rel.cta  -> MEMBAR.ALL.CTA
    ///   fence.sc.gpu / acq_rel.gpu  -> MEMBAR.ALL.GPU; ERRBAR; CGAERRBAR; CCTL.IVALL
    ///   fence.sc.sys / acq_rel.sys  -> MEMBAR.ALL.SYS; ERRBAR; CGAERRBAR; CCTL.IVALL
    ///   fence.proxy.async.shared::cta -> MEMBAR.ALL.CTA; FENCE.VIEW.ASYNC.S
    ///   fence.proxy.async           -> MEMBAR.ALL.GPU; FENCE.VIEW.ASYNC.S
    /// Fail-closed (no rule): tcgen05.fence::* (tcgen05 = non-goal),
    /// fence.mbarrier_init.*, fence.proxy.alias / fence.proxy.async.global
    /// (FENCE.VIEW.ASYNC.G has no table mg -> b4-feed), fence.cluster forms.
    Fence { lines: &'static [&'static str] },
    /// b9 phase-3 #6: mbarrier family -> SYNCS-class ops with vendor glue.
    /// All lowering decisions are vendor anchors (ptxas 13.3 sm_103a probes
    /// work/b9p8/probes mb1..mb4, -O0 glue per op; byte-parity evidence in
    /// results/b9/mbar_parity/). Address operand is the CTA-local shared
    /// offset carried in an R register; vendor builds the CGA-wide address
    /// per access (S2R SR_CgaCtaId + LEA <<24) and drives the SYNCS op at
    /// [Ra+URZ]. Summary of the anchored forms:
    ///   init [mb], n         -> S2R rx,SR_CgaCtaId ; LEA ra,rx,rb,0x18 ;
    ///                           IADD3 rc,PT,PT,-rc,0x100000,RZ ;
    ///                           SHF.L.U32 rh,rc,0xb,RZ ; SHF.L.U32 rl,rc,0x1,RZ ;
    ///                           R2UR U60,rl ; R2UR U61,rh ; R2UR U62,ra ;
    ///                           SYNCS.EXCH.64 URZ,[U62],U60   (count encoded
    ///                           as (0x100000-n)<<1 | (0x100000-n)<<33 pair)
    ///   try_wait.parity      -> addr glue ; phase (imm->MOV+SHF.L by 31,
    ///                           reg->SHF.L by 31) ;
    ///                           SYNCS.PHASECHK.TRANS64.TRYWAIT Pd,[ra+URZ],rp
    ///   try_wait (hint==0)   -> addr glue ; ...TRYWAIT Pd,[ra+URZ],RZ
    ///   arrive [state|_]     -> addr glue ; SYNCS.ARRIVE.TRANS64.A1T0
    ///                           {Rpair_lo|RZ},[ra+URZ],RZ
    ///   arrive.expect_tx     -> addr glue ; SYNCS.ARRIVE.TRANS64
    ///                           {Rpair_lo|RZ},[ra+URZ],{RZ|Rtx}
    ///   arrive .shared::cluster (dst _, addr already mapa-remapped)
    ///                        -> SYNCS.ARRIVE.TRANS64.RED.A1T0 RZ,[rb+URZ],RZ
    ///   fence.mbarrier_init.release.cluster -> NOP  (vendor anchor mb3:
    ///                           plain NOP after the init EXCH)
    /// Fail-closed (no rule / unsupported arm): any sem/scope suffix not in
    /// the corpus, count/phase/tx/offset shapes outside the anchored ones,
    /// guarded mbarrier ops.
    Mbar { kind: MbarKind },
    /// b9 phase-3 #7: barrier.cluster family -> guarded UCGABAR protocol
    /// with a runtime cluster-presence test (vendor anchors cl1/cl3, ptxas
    /// 13.3 -O0 sm_103a; byte-parity 142/142 in results/b9/cluster_parity/).
    /// Every form reads the cluster gate c[0x0][0x36c] and branches between
    /// the UCGABAR path (real cluster launch) and the degenerate fallback.
    ///   arrive[.release] non-aligned:
    ///     LDC r, c[0x0][0x36c]; ISETP.EQ.U32.AND P0, PT, r, 0x1, PT;
    ///     @!P0 BRA `(else); MOV r, 0xffffffff; WARPSYNC.COLLECTIVE.ALL `(mid);
    ///     [MEMBAR.ALL.GPU; ERRBAR; CGAERRBAR;] UCGABAR_ARV; ENDCOLLECTIVE;
    ///     mid: BRA `(end); else: MOV r, 0xffffffff;
    ///     WARPSYNC.COLLECTIVE r, `(end); NOP; ENDCOLLECTIVE; end:
    ///   arrive[.release].aligned:
    ///     guard; @!P0 BRA `(else); WARPSYNC.ALL; [MEMBAR.ALL.GPU; ERRBAR;
    ///     CGAERRBAR;] UCGABAR_ARV; BRA `(end); else: WARPSYNC.ALL; end:
    ///     (.relaxed drops the MEMBAR chain in both shapes, anchored cl1)
    ///   wait[.acquire] non-aligned:
    ///     guard; @!P0 BRA `(else); MOV r, 0xffffffff;
    ///     WARPSYNC.COLLECTIVE.ALL `(mid); UCGABAR_WAIT; CCTL.IVALL;
    ///     ENDCOLLECTIVE; mid: BRA `(end); else: MOV r2, 0x0; MOV r3, 0x0;
    ///     MOV r, 0xffffffff; WARPSYNC.COLLECTIVE r, `(end);
    ///     SHF.L.U32 r3, r3, 0x10, RZ; LOP3.LUT r3, r3, 0xf, r2, 0xf8, !PT;
    ///     BAR.SYNC.DEFER_BLOCKING r3, r3; SHF.R.U32 r3, r3, 0x10, RZ;
    ///     ENDCOLLECTIVE; end:
    ///   wait[.acquire].aligned:
    ///     guard; @!P0 BRA `(else); WARPSYNC.ALL; UCGABAR_WAIT; CCTL.IVALL;
    ///     BRA `(end); else: WARPSYNC.ALL; BAR.SYNC.DEFER_BLOCKING 0x0; end:
    /// PTX defaults anchored: plain arrive == .release, plain wait == .acquire
    /// (probe cl3: identical glue). Exact-name match like Mbar/Fence: any
    /// other sem suffix is unsupported (fail-closed), as are guarded ops
    /// (none in the 551-ptx corpus).
    ClusterBarrier { arrive: bool, relaxed: bool, aligned: bool },
    /// b9 phase-3 #7: mapa.shared::cluster.u32 -> per-op CGA-wide address
    /// glue + PRMT byte splice (vendor anchors cl2, -O0):
    ///   S2R rc, SR_CgaCtaId ; LEA ra, rc, rb, 0x18 ;
    ///   PRMT d, {RZ | Rct}, 0x654, ra
    /// Bytes 0..2 of d come from the address, byte 3 = target CTA rank.
    /// Imm ctaid != 0 is materialized with a plain MOV first (vendor form);
    /// imm 0 short-circuits to RZ. Fail-closed: non-reg address, ctaid imm
    /// outside 0..=255, guards.
    Mapa,

    /// b9 phase-3 #8: vote.sync family -> WARPSYNC.COLLECTIVE protocol.
    /// Vendor anchors (ptxas 13.3 -O0 sm_103a; probes work/b9p10/probes
    /// vm1 + corpus anchors v_vote1, p_matchany; byte-parity in
    /// results/b9/votematch_parity/):
    ///   vote.sync.ballot.b32 d, p, mask:
    ///     [MOV Rm, imm ;] WARPSYNC.COLLECTIVE Rm, `(L) ;
    ///     VOTE.ANY Rd, PT, Pp ; ENDCOLLECTIVE ; L:
    ///   vote.sync.{any,all}.pred p2, p, mask:
    ///     [MOV Rm, imm ;] WARPSYNC.COLLECTIVE Rm, `(L) ;
    ///     VOTE.{ANY|ALL} Pd, Pp ; ENDCOLLECTIVE ; L:
    /// Note: ballot lowers to the SAME VOTE.ANY opcode with a register
    /// destination (measured, vm1/vote_ballot 0x190). -O3 elides the
    /// WARPSYNC/ENDCOLLECTIVE glue for membermask==0xffffffff (cross-op;
    /// not the per-op anchor). Guards: 0 in corpus -> fail-closed.
    Vote { ballot: bool, all: bool },
    /// match.any.sync.b32 d, a, mask: same WARPSYNC glue around
    ///   MATCH.ANY Rd, Ra  (anchors vm1/match_any + p_matchany).
    MatchAny,
    /// bar.warp.sync mask: bare WARPSYNC.COLLECTIVE pair (anchor bw1):
    ///   [MOV Rm, imm ;] WARPSYNC.COLLECTIVE Rm, `(L) ; ENDCOLLECTIVE ; L:
    WarpSyncMask,
    /// elect.sync d|p, mask: WARPSYNC glue around
    ///   ELECT Pp, UR79, PT ; [MOV Rd, UR79] ;  (anchors ns1/elect_a +
    /// el2/elect_sink). The %rx sink dst skips the MOV (el2 anchor).
    /// UR79 is the vendor's fixed scratch choice at -O0 (el2 0x170).
    ElectSync,
    /// nanosleep.u32 S -> NANOSLEEP imm | R (anchor ns1: NANOSLEEP 0x32 /
    /// NANOSLEEP R0; corpus p24 reg form).
    Nanosleep,
    /// griddepcontrol.launch_dependents -> PREEXIT ; griddepcontrol.wait
    /// -> ACQBULK (anchors ns1/griddep_a + corpus p25, -O0 == -O3 forms).
    GridDep { wait: bool },
    /// cp.async non-bulk family -> LDGSTS + LDGDEPBAR/DEPBAR protocol
    /// (anchors cp1/cp2/cp3 + corpus anchors b_cpasync/p_ldgsts/p13):
    ///   cp.async.{ca,cg}.shared.global[.L2::{128B,256B}] [d], [g], N{, sz}
    ///   N=4 -> .E ; 8 -> .E.64 ; 16 -> .E.128
    ///   .cg -> .BYPASS ; L2 hint -> .LTC128B/.LTC256B
    ///   src-size operand present (any value, imm or reg) -> .ZFILL plus
    ///   the vendor size-adjust glue (ISETP sz==0 -> Pz ; off=(0x10-sz)&0xF
    ///   via IADD3 neg + LOP3 0xc0 ; 64-bit src advance by off through
    ///   IADD3/IADD3.X carry pairs ; LDGSTS ... , !Pz). PTX dst/src offsets
    ///   fold into the address math before the ZFILL pair (anchor cp1).
    ///   Kernel-wide preamble: three `@!PT LDS RZ, [RZ]` once, immediately
    ///   before the first LDGSTS (all anchors incl. -O3).
    CpAsync { bypass: bool, ltc: Option<u16> },
    /// cp.async.commit_group -> LDGDEPBAR ; cp.async.wait_group N ->
    /// DEPBAR.LE SB0, N ; cp.async.wait_all -> LDGDEPBAR + DEPBAR.LE SB0, 0x0
    /// (anchors cp_wait/cp_many/cp_sizes: commit 0x340, wait_group 1
    /// 0x350, wait_all 0x360+0x370).
    CpAsyncBar { commit: bool, all: bool },
    // b9 phase-3 #8 note: cvta.to.shared.u64 maps to AliasPair above (same
    // shape as cvta.to.global.u64) -- vendor corpus anchor b_ldmatrix-ba534d
    // (ptxas 13.3 -O0 sm_103a) lowers a runtime-generic cvta.to.shared to
    // mov-copies; the S2R SR_CgaCtaId + LEA <<24 glue belongs to shared-
    // SYMBOL address materialization (shsym layout, iter35), not to cvta.

    /// b9 phase-3 #9: ldmatrix/stmatrix -> LDSM.16.M88[.4] / STSM.16.M88.4
    /// (canon BUG-098 for LDSM x1/x4; STSM row + anchor added this iter).
    /// Vendor forms (-O0 == -O3, probes ldsm1 + corpus b_ldmatrix/p11/p_ldsm/
    /// p12): `LDSM.16.M88 Rd, [Rn]` (x1, single dst), `LDSM.16.M88.4 Rd4,
    /// [Rn]` (x4, aligned dst quad), `STSM.16.M88.4 [Rn], Rs4` (src quad).
    /// Address is a plain [Rn] 32-bit shared offset (64-bit pair bases yield
    /// their lo half per the AliasPair/cvta convention); nonzero [Rn+imm] is
    /// fail-closed (unattested in corpus), as are x2 forms and guards.
    Ldsm { store: bool },

    /// b9 phase-3 #9: sub.s16 -> neg + u16-clamp + add (anchors b16a imm-a,
    /// b16b reg-reg; -O0 keeps this exact 3-insn core):
    ///   IADD3 t, PT, PT, RZ, -b, RZ ; PRMT t, t, 0x7710, RZ ;
    ///   IADD3 d, PT, PT, a, t, RZ           (a reg)
    ///   IADD3 d, PT, PT, t, imm, RZ         (a imm; imm rides slot B)
    Sub16,
    /// mul.lo.s16: PRMT 0x9910 sign-extend both sources (slot d self-feed
    /// pattern elided to scratch regs) + IMAD d, at, bt, RZ (anchor b16b).
    MulLo16,
    /// mul.hi.u16: PRMT 0x7710 zero-extend both + IMAD.U32 t, at, bt, RZ +
    /// SHF.R.U32.HI d, RZ, 0x10, t (anchor b16a).
    MulHiU16,
    /// shr.u16 d, a, s: imm s -> MOV t,imm; reg s -> VIMNMX.U32 t, PT, PT, s,
    /// 0xffff, PT; then PRMT t, t, 0x7710, RZ ; PRMT at, a, 0x7710, RZ ;
    /// SHF.R.U32.HI d, RZ, t, at (anchors b16a imm + b16b reg).
    ShrU16,
    /// sub.s64 -> carry pair (vendor -O0 slot order! anchors s64_sub):
    ///   IADD3 dlo, Pc, PT, alo, -blo, RZ ;
    ///   IADD3.X dhi, PT, PT, ahi, ~bhi, RZ, Pc, !PT
    /// The internal carry predicate is an anonymous pool slot, NOT the PTX
    /// %cc (plain sub has no cc in PTX). b must be a register pair.
    Sub64,
    /// min.s64 (b reg pair, or imm with hi32==0): unsigned-lo compare then
    /// signed-ex hi + two SELs (anchors s64_min / s64_mini):
    ///   ISETP.LT.U32.AND Pc, PT, alo, blo|imm, PT ;
    ///   ISETP.LT.AND.EX Pc, PT, ahi, bhi|RZ, PT, Pc ;
    ///   SEL dlo, alo, blo|imm, Pc ; SEL dhi, ahi, bhi|RZ, Pc
    MinS64,
    /// clz.b64 (anchor s64_clz, -O0 six-insn core):
    ///   ISETP.EQ.U32.AND Pc, PT, ahi, RZ, PT ; SEL bias, RZ, 0x20, !Pc ;
    ///   SEL x, alo, ahi, Pc ; FLO.U32 x, x ;
    ///   IADD3 x, PT, PT, -x, 0x1f, RZ ; IADD3 d, PT, PT, bias, x, RZ
    Clz64,
    /// popc.b64 (anchor s64_popc): vendor -O0 idiom keeps a LOP3 identity
    /// mask (~0 AND) per half -- emitted verbatim, semantically dead:
    ///   LOP3.LUT m, RZ, RZ, RZ, 0x33, !PT ; LOP3.LUT t, alo, m, RZ, 0xc0,
    ///   !PT ; POPC t, t ; (same for hi) ; IADD3 d, PT, PT, t, u, RZ
    Popc64,
    /// mul.lo.s64 / mad.lo.s64 / mul.hi.u64: shared vendor -O0 mul64
    /// network (anchors s64_mullo/s64_mulloi/s64_madlo/s64_mulhi; -O3 uses
    /// a lean 3..4-op form -- documented divergence):
    ///   t0 = IMAD.WIDE.U32 [Pc0,] alo, blo[, addend]   (addend = RZ pair
    ///        for mul; c pair + Pc0 carry-out for mad)
    ///   t1 = IMAD.WIDE.U32 ahi, blo, RZ
    ///   t2 = IMAD.WIDE.U32 Pc2, alo, bhi, t1
    ///   s1 = IADD3 Pc1, PT, PT??  -> IADD3 s1, Pc1, PT, t2.lo, t0.hi, RZ
    ///   mul: s2 = IADD3 RZ,t2.hi,RZ ; IADD3.X RZ,RZ,RZ,Pc2,!PT
    ///   mad: s2 = IADD3.X  (t2.hi+, cin Pc0) then IADD3.X (dual cin Pc2+Pc0)
    ///   t3 = IMAD.WIDE.U32.X ahi, bhi, s2, Pc1
    /// mul.lo keeps {t0.lo, s1}; mad.lo same (t0 carries c); mul.hi keeps t3.
    Mul64 { kind: Mul64Kind },
    /// cp.async.bulk.shared::cluster.global.mbarrier::complete_tx::bytes
    /// [dst], [src], sz, [mbar] -> UBLKCP + single-lane elect loop with
    /// per-op CGA address glue (vendor anchors corpus b_bulk_cp -O0; -O3
    /// diverges into the uniform datapath -- documented). UR window
    /// UR52..UR56 (fixed, gateway-local; vendor -O0 reuses UR4..9 but UR4
    /// collides with our descriptor window, so the numbering differs from
    /// the anchor while every emitted instruction form stays anchored):
    ///   S2R ct,SR_CgaCtaId ; LEA ad,ct,rb,0x18    (dst CGA glue)
    ///   R2UR UR53,slo ; R2UR UR54,shi             (src global pair)
    ///   SHF.R.U32.HI t,RZ,0x4,sz ; PRMT t,t,0x5410,RZ ; R2UR UR52,t
    ///   S2R+LEA (mbar) ; R2UR UR56,mb ; R2UR UR55,ad
    ///   PLOP3 pl,PT,PT,PT,PT,0x80,0x8 ; LOOP: @pl ELECT pe,URZ,PT ;
    ///   @pe PLOP3 pl,PT,pe,PT,PT,0x8,0x80 ; UBLKCP.S.G [UR55],[UR53],UR52 ;
    ///   PLOP3 pe,PT,PT,PT,PT,0x8,0x80 ; @pl BRA.U.ANY `(LOOP)
    CpAsyncBulk,
    /// mad.wide.u32 -> IMAD.U32 + IMAD.HI.U32 + IADD3/IADD3.X add of the
    /// 64-bit addend (anchor madwi -O0 0x470..04c0; corpus bench_m9 fam).
    MadWide32,
    /// b9p13 (phase-3 #11): add.sat.s32 -> vendor -O0 5-op macro
    /// IADD3 + 2x PLOP3.LUT with R.SIGN sign-inputs + 2x SEL saturation
    /// clamps (anchors corpus p27 O0 0x290-0x2d0 + word-probes work/b9p13;
    /// new table row PLOP3_P_P_R_R_R_II_II, 76-anchor exact fit).
    AddSatS32,
    /// b9p13: sin.approx.f32 / cos.approx.f32 -> FMUL.RZ by 1/(2pi) +
    /// MUFU.SIN/COS (anchors corpus p18 O0 0x4d0/0x500; phase-1 Singles were
    /// guess-mappings dropping the 1/2pi scale = wrong function, O0==-O3 form).
    SinCos { cos: bool },
    /// b9p13: ex2.approx.f32 -> vendor -O0 6-op range-scaled macro
    /// (FSETP.LT vs -126 / FMUL 0.5 / FSEL / MUFU.EX2 / FMUL sq / FSEL,
    /// anchor corpus p18 O0 0x2a0-0x320; -O3 uses guarded 4-op variant,
    /// documented divergence). Replaces phase-1 guess Single MUFU.EX2.
    Ex2Approx,
    /// b9p13: lg2.approx.f32 -> vendor -O0 7-op denormal-guard macro
    /// (FADD |a| / FSETP.LT vs 2^-126 / FMUL 2^24 / FSEL / MUFU.LG2 /
    /// FADD -24 / FSEL, anchor corpus p18 O0 0x3e0-0x4a0; -O3 elides the
    /// guard when the input range is provably normal, documented divergence).
    Lg2Approx,
    /// b9p13: div.approx.f32 -> vendor -O0 8-op macro
    /// (FADD |b| / FSETP.LT vs 2^-126 / FMUL.FTZ-less 2^24 scale of b /
    /// FSEL / MUFU.RCP / FMUL 2^24 scale of a / FSEL / FMUL; anchors corpus
    /// mufu1 O0 0x1c0-0x280 + p18 O0 0xaa0-..). -O3 folds constant divisors
    /// to reciprocal-multiply (documented divergence).
    DivApproxF32,
}

/// b9 phase-3 #9: mul64 flavour (see SassTemplate::Mul64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mul64Kind { Lo, Mad, Hi }

/// b9 phase-3 #6: mbarrier op split (see SassTemplate::Mbar).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MbarKind {
    Init,
    Arrive,
    ArriveExpectTx,
    ArriveCluster,
    TryWaitParity,
    TryWait,
}

/// A single PTX→SASS mapping rule.
pub struct PtxRule {
    /// PTX opcode prefix to match (e.g. "add.s32", "add.u32", "fma.rn.f32").
    pub pattern: &'static str,
    pub template: SassTemplate,
}

use OpSlot::*;
use SassTemplate::*;

/// Master mapping table.  Searched linearly — longest/most-specific match first.
pub static RULES: &[PtxRule] = &[
    // ── Integer arithmetic ───────────────────────────────────────────────
    // 64-bit (must come before 32-bit patterns)
    PtxRule { pattern: "add.u64",       template: Add64 },
    PtxRule { pattern: "add.s64",       template: Add64 },
    // 32-bit
    // Use IADD (2-source) instead of IADD3 (3-source with RZ) to avoid Rc2=RZ ctrl word issue
    // b9 phase-1: plain "IADD" does not exist in the sm_103a/120 tables;
    // vendor shape is the carry-form IADD3 with PT ties (anchor: k2/k3 ptxas
    // probes, e.g. `IADD3 R7, PT, PT, R0, R7, R5`).
    PtxRule { pattern: "add.s32",       template: Single { opcode: "IADD3", slots: &[Src(0), PT, PT, Src(1), Src(2), RZ] } },
    PtxRule { pattern: "add.u32",       template: Single { opcode: "IADD3", slots: &[Src(0), PT, PT, Src(1), Src(2), RZ] } },
    PtxRule { pattern: "sub.s32",       template: Single { opcode: "IADD3", slots: &[Src(0), PT, PT, Src(1), NegSrc(2), RZ] } },
    PtxRule { pattern: "sub.u32",       template: Single { opcode: "IADD3", slots: &[Src(0), PT, PT, Src(1), NegSrc(2), RZ] } },
    PtxRule { pattern: "mul.lo.s32",    template: Single { opcode: "IMAD",  slots: &[Src(0), Src(1), Src(2), RZ] } },
    PtxRule { pattern: "mul.lo.u32",    template: Single { opcode: "IMAD",  slots: &[Src(0), Src(1), Src(2), RZ] } },
    PtxRule { pattern: "mul.hi.s32",    template: Single { opcode: "IMAD.HI", slots: &[Src(0), Src(1), Src(2), RZ] } },
    PtxRule { pattern: "mul.hi.u32",    template: Single { opcode: "IMAD.HI", slots: &[Src(0), Src(1), Src(2), RZ] } },
    PtxRule { pattern: "mad.lo.s32",    template: Single { opcode: "IMAD",  slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "mad.lo.u32",    template: Single { opcode: "IMAD",  slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "mad.hi.s32",    template: Single { opcode: "IMAD.HI", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "mad.hi.u32",    template: Single { opcode: "IMAD.HI", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    // b9p11: plain IMNMX with pred-outputs is SILICON-ILLEGAL on sm_103a (BUG-059;
    // encoder fail-closed; surfaced by test13/test14/b_bulk_cp at asm). Vendor
    // lowering keeps the PT/!PT min/max select trick on VIMNMX[.U32] (anchors
    // mnm1 probe + corpus b_bulk_cp/b16b).
    PtxRule { pattern: "min.s32",       template: Single { opcode: "VIMNMX", slots: &[Src(0), PT, PT, Src(1), Src(2), PT] } },
    PtxRule { pattern: "min.u32",       template: Single { opcode: "VIMNMX.U32", slots: &[Src(0), PT, PT, Src(1), Src(2), PT] } },
    PtxRule { pattern: "max.s32",       template: Single { opcode: "VIMNMX", slots: &[Src(0), PT, PT, Src(1), Src(2), NotPT] } },
    PtxRule { pattern: "max.u32",       template: Single { opcode: "VIMNMX.U32", slots: &[Src(0), PT, PT, Src(1), Src(2), NotPT] } },
    PtxRule { pattern: "neg.s32",       template: Single { opcode: "IADD3", slots: &[Src(0), PT, PT, NegSrc(1), RZ, RZ] } },
    PtxRule { pattern: "abs.s32",       template: Single { opcode: "IABS",  slots: &[Src(0), Src(1)] } },
    // b9p13 (phase-3 #11): add.sat.s32 -> IADD3 + 2x PLOP3.LUT(R.SIGN) + 2x
    // SEL (anchors corpus p27 O0 0x290-0x2d0; O3 form identical role-shape).
    PtxRule { pattern: "add.sat.s32",   template: AddSatS32 },

    // ── Bitwise / shift ──────────────────────────────────────────────────
    PtxRule { pattern: "and.b64",       template: B64Logic { lut: 0xc0 } },
    PtxRule { pattern: "or.b64",        template: B64Logic { lut: 0xfc } },
    PtxRule { pattern: "xor.b64",       template: B64Logic { lut: 0x3c } },
    PtxRule { pattern: "not.b64",       template: B64Logic { lut: 0x33 } },
    PtxRule { pattern: "and.b32",       template: Single { opcode: "LOP3.LUT", slots: &[Src(0), Src(1), Src(2), RZ, Imm(0xc0), NotPT] } },
    PtxRule { pattern: "or.b32",        template: Single { opcode: "LOP3.LUT", slots: &[Src(0), Src(1), Src(2), RZ, Imm(0xfc), NotPT] } },
    PtxRule { pattern: "xor.b32",       template: Single { opcode: "LOP3.LUT", slots: &[Src(0), Src(1), Src(2), RZ, Imm(0x3c), NotPT] } },
    PtxRule { pattern: "not.b32",       template: Single { opcode: "LOP3.LUT", slots: &[Src(0), Src(1), RZ, RZ, Imm(0x0f), NotPT] } },
    // b9 phase-1 (vendor-anchored byte-parity, probes in results/b9):
    // SHF.L.U32 d, a, shift, RZ  /  SHF.R.[US]32.HI d, RZ, shift, a
    PtxRule { pattern: "shl.b32",       template: Single { opcode: "SHF.L.U32", slots: &[Src(0), Src(1), Src(2), RZ] } },
    PtxRule { pattern: "shr.b32",       template: Single { opcode: "SHF.R.U32.HI", slots: &[Src(0), RZ, Src(2), Src(1)] } },
    PtxRule { pattern: "shr.u32",       template: Single { opcode: "SHF.R.U32.HI", slots: &[Src(0), RZ, Src(2), Src(1)] } },
    PtxRule { pattern: "shr.s32",       template: Single { opcode: "SHF.R.S32.HI", slots: &[Src(0), RZ, Src(2), Src(1)] } },
    // b9 phase-3 #3: carry chains (CC.CF). All corpus instances are u32,
    // unguarded (93,826 sites, 0 guards); s32 and guarded shapes -> fail-closed.
    PtxRule { pattern: "add.cc.u32",    template: CarryChain32 { cin: false, cout: true,  sub: false } },
    PtxRule { pattern: "addc.cc.u32",   template: CarryChain32 { cin: true,  cout: true,  sub: false } },
    PtxRule { pattern: "addc.u32",      template: CarryChain32 { cin: true,  cout: false, sub: false } },
    PtxRule { pattern: "sub.cc.u32",    template: CarryChain32 { cin: false, cout: true,  sub: true } },
    PtxRule { pattern: "subc.cc.u32",   template: CarryChain32 { cin: true,  cout: true,  sub: true } },
    PtxRule { pattern: "subc.u32",      template: CarryChain32 { cin: true,  cout: false, sub: true } },
    PtxRule { pattern: "mad.lo.cc.u32", template: MadCc { hi: false } },
    PtxRule { pattern: "madc.hi.u32",   template: MadCc { hi: true } },
    // b9 phase-3 #3: 64-bit shifts and 32-bit funnels (vendor shape anchor
    // sh1/sh2/sh5; funnel PTX order d,a,b,c -> SASS d,a,c(shift),b).
    PtxRule { pattern: "shl.b64",       template: Shift64 { dir_left: true,  signed: false } },
    PtxRule { pattern: "shr.s64",       template: Shift64 { dir_left: false, signed: true } },
    PtxRule { pattern: "shr.u64",       template: Shift64 { dir_left: false, signed: false } },
    PtxRule { pattern: "shf.l.clamp.b32", template: Single { opcode: "SHF.L.U32.HI", slots: &[Src(0), Src(1), Src(3), Src(2)] } },
    PtxRule { pattern: "shf.r.clamp.b32", template: Single { opcode: "SHF.R.U32",    slots: &[Src(0), Src(1), Src(3), Src(2)] } },
    PtxRule { pattern: "shf.l.wrap.b32",  template: Single { opcode: "SHF.L.W.U32.HI", slots: &[Src(0), Src(1), Src(3), Src(2)] } },
    PtxRule { pattern: "shf.r.wrap.b32",  template: Single { opcode: "SHF.R.W.U32",    slots: &[Src(0), Src(1), Src(3), Src(2)] } },
    // b9p12 (phase-3 #10): phase-1 Singles for popc/brev/clz were GUESS-MAPPINGS,
    // never anchor-verified (single FLO.U32 for clz dropped the vendor 31-x fixup =
    // semantic bug, surfaced by corpus p19). Replaced with vendor -O0 macros
    // (anchors: corpus_p19_intmisc O0 0x350-0x370 / 0x380-0x3a0 / 0x3c0-0x3d0).
    PtxRule { pattern: "popc.b32",      template: Popc32 },
    PtxRule { pattern: "brev.b32",      template: Brev32 },
    PtxRule { pattern: "clz.b32",       template: Clz32 },
    // b9p12 (phase-3 #10) intmisc easy-aliasing lane, all vendor -O0 anchored:
    // lop3.b32: LOP3.LUT d,a,b,c,lut,!PT (anchor corpus p20 0x320)
    PtxRule { pattern: "lop3.b32",      template: Single { opcode: "LOP3.LUT", slots: &[Src(0), Src(1), Src(2), Src(3), Src(4), NotPT] } },
    // prmt.b32: PTX d,a,b,c(sel) -> PRMT d,a,sel,b (imm mid / reg mid rows both)
    // (anchors corpus p20 0x330 imm-sel + 0x340 reg-sel)
    PtxRule { pattern: "prmt.b32",      template: Single { opcode: "PRMT", slots: &[Src(0), Src(1), Src(3), Src(2)] } },
    // bfind.u32 = FLO.U32 (index of MSB / -1; also the clz sub-op). bfind.shiftamt
    // = FLO.U32.SH (anchor corpus p19 0x420; plain-bfind probe b9p12_find1).
    PtxRule { pattern: "bfind.shiftamt.u32", template: Single { opcode: "FLO.U32.SH", slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "bfind.u32",     template: Single { opcode: "FLO.U32", slots: &[Src(0), Src(1)] } },
    // sad.u32 = VABSDIFF.U32 d,a,b,c (anchor corpus p19 0x890, row b9p12 49-word fit)
    PtxRule { pattern: "sad.u32",       template: Single { opcode: "VABSDIFF.U32", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    // bfe.u32 imm pos/len = vendor -O0 8-op macro (anchor corpus p20 0x350-0x3c0);
    // reg pos/len, .s32, guarded -> fail-closed (unsupported).
    PtxRule { pattern: "bfe.u32",       template: BfeU32 },

    // ── FP32 arithmetic ──────────────────────────────────────────────────
    PtxRule { pattern: "add.f32",       template: Single { opcode: "FADD", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "add.rn.f32",    template: Single { opcode: "FADD", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "add.ftz.f32",   template: Single { opcode: "FADD", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "sub.f32",       template: Single { opcode: "FADD", slots: &[Src(0), Src(1), NegSrc(2)] } },
    PtxRule { pattern: "sub.rn.f32",    template: Single { opcode: "FADD", slots: &[Src(0), Src(1), NegSrc(2)] } },
    PtxRule { pattern: "mul.f32",       template: Single { opcode: "FMUL", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "mul.rn.f32",    template: Single { opcode: "FMUL", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "mul.ftz.f32",   template: Single { opcode: "FMUL", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "fma.rn.f32",    template: Single { opcode: "FFMA", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "fma.rn.ftz.f32",template: Single { opcode: "FFMA", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "min.f32",       template: Single { opcode: "FMNMX", slots: &[Src(0), Src(1), Src(2), PT] } },
    PtxRule { pattern: "min.ftz.f32",   template: Single { opcode: "FMNMX", slots: &[Src(0), Src(1), Src(2), PT] } },
    PtxRule { pattern: "max.f32",       template: Single { opcode: "FMNMX", slots: &[Src(0), Src(1), Src(2), NotPT] } },
    PtxRule { pattern: "max.ftz.f32",   template: Single { opcode: "FMNMX", slots: &[Src(0), Src(1), Src(2), NotPT] } },

    // ── FP64 arithmetic ──────────────────────────────────────────────────
    PtxRule { pattern: "add.f64",       template: Single { opcode: "DADD", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "add.rn.f64",    template: Single { opcode: "DADD", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "mul.f64",       template: Single { opcode: "DMUL", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "mul.rn.f64",    template: Single { opcode: "DMUL", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "fma.rn.f64",    template: Single { opcode: "DFMA", slots: &[Src(0), Src(1), Src(2), Src(3)] } },

    // ── Math functions (MUFU) ────────────────────────────────────────────
    // b9p13 (phase-3 #11): sin/cos/ex2/lg2 were phase-1 GUESS Singles, never
    // anchor-verified; vendor anchors show them semantically wrong (dropped
    // 1/2pi scale for sin/cos, dropped range scaling for ex2/lg2) -> macros.
    // rcp.rn.f32 / sqrt.rn.f32 / div.rn.f32: vendor lowers via inline fast
    // path + FCHK/guard + CALL.REL.NOINC $__internal slowpath helper (anchors
    // corpus p18/test12 O0+O3) = call-lane (parked, iter40) -> REMOVED the
    // guess Singles so these go fail-closed unsupported instead of silently
    // emitting the approximate fast path. rcp.approx / rsqrt.approx /
    // sqrt.approx Singles stay (unanchored, zero corpus use -- F-note).
    PtxRule { pattern: "rcp.approx",    template: Single { opcode: "MUFU.RCP",  slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "rsqrt.approx",  template: Single { opcode: "MUFU.RSQ",  slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "sqrt.approx",   template: Single { opcode: "MUFU.SQRT", slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "lg2.approx.f32",    template: Lg2Approx },
    PtxRule { pattern: "ex2.approx.f32",    template: Ex2Approx },
    PtxRule { pattern: "sin.approx.f32",    template: SinCos { cos: false } },
    PtxRule { pattern: "cos.approx.f32",    template: SinCos { cos: true } },
    PtxRule { pattern: "tanh.approx.f32", template: Single { opcode: "MUFU.TANH", slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "div.approx.f32",  template: DivApproxF32 },
    // b9p13: abs.f32 -> FADD d, -RZ, |a| (anchors corpus p18/mufu1 O0 0x350
    // + test12 slowpath 0x600; -O3 FOLDS |.| into consumers -- documented).
    PtxRule { pattern: "abs.f32",       template: Single { opcode: "FADD", slots: &[Src(0), NegRZ, AbsSrc(1)] } },

    // ── Moves ────────────────────────────────────────────────────────────
    PtxRule { pattern: "mov.u32",       template: SpecialRegMov },
    PtxRule { pattern: "mov.b32",       template: SpecialRegMov },
    PtxRule { pattern: "mov.s32",       template: SpecialRegMov },
    PtxRule { pattern: "mov.f32",       template: SpecialRegMov },
    PtxRule { pattern: "mov.u64",       template: Mov64 },
    PtxRule { pattern: "mov.b64",       template: Mov64 },

    // ── Comparison ───────────────────────────────────────────────────────
    PtxRule { pattern: "setp.lt.s32",   template: ISetp },
    PtxRule { pattern: "setp.le.s32",   template: ISetp },
    PtxRule { pattern: "setp.eq.s32",   template: ISetp },
    PtxRule { pattern: "setp.ne.s32",   template: ISetp },
    PtxRule { pattern: "setp.gt.s32",   template: ISetp },
    PtxRule { pattern: "setp.ge.s32",   template: ISetp },
    PtxRule { pattern: "setp.lt.u32",   template: ISetp },
    PtxRule { pattern: "setp.le.u32",   template: ISetp },
    PtxRule { pattern: "setp.eq.u32",   template: ISetp },
    PtxRule { pattern: "setp.ne.u32",   template: ISetp },
    PtxRule { pattern: "setp.gt.u32",   template: ISetp },
    PtxRule { pattern: "setp.ge.u32",   template: ISetp },
    PtxRule { pattern: "setp.lo.u32",   template: ISetp },
    PtxRule { pattern: "setp.ls.u32",   template: ISetp },
    PtxRule { pattern: "setp.hi.u32",   template: ISetp },
    PtxRule { pattern: "setp.hs.u32",   template: ISetp },
    PtxRule { pattern: "setp.",          template: ISetp },  // catch-all for setp variants

    // ── Predicate logic (b9 phase-3 P1': census family "pred-logic", 127
    // files / 2,443 ops; forms vendor-anchored, see PredLogic variant docs).
    PtxRule { pattern: "and.pred",      template: PredLogic { lut_a: 0x80, lut_b: 0x08 } },
    PtxRule { pattern: "or.pred",       template: PredLogic { lut_a: 0xf8, lut_b: 0x8f } },
    PtxRule { pattern: "xor.pred",      template: PredLogic { lut_a: 0x28, lut_b: 0x82 } },
    PtxRule { pattern: "not.pred",      template: PredLogic { lut_a: 0x08, lut_b: 0x80 } },
    PtxRule { pattern: "mov.pred",      template: PredLogic { lut_a: 0x80, lut_b: 0x08 } },

    PtxRule { pattern: "selp.s32",      template: Single { opcode: "SEL", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "selp.b32",      template: Single { opcode: "SEL", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "mul.wide.s32",  template: MulWide { unsigned: false } },
    PtxRule { pattern: "mul.wide.u32",  template: MulWide { unsigned: true } },
    PtxRule { pattern: "selp.u32",      template: Single { opcode: "SEL", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "selp.f32",      template: Single { opcode: "SEL", slots: &[Src(0), Src(1), Src(2), Src(3)] } },

    // ── b9 phase-3 #9 (bf16 / ldsm / b16 / s64-misc / cp.async.bulk) ─────────
    // Vendor anchors: work/b9p11/probes (single-op -O0 + -O3 controls) and
    // corpus kernels (p16_bf16, b_ldmatrix, p11, p_ldsm, p12, b_bulk_cp,
    // bench_op06*/bench_pair*/p19_intmisc/tgv_gqa/test44). Parity evidence:
    // results/b9/b9p11_parity/. div.u16 is NOT here on purpose: vendor
    // lowers it via CALL.REL.NOINC $__internal_$__cuda_sm20_div_u16 (helper
    // call lane, out of phase-3 scope) -> stays unsupported (fail-closed
    // until the call lane lands).
    PtxRule { pattern: "add.bf16x2",    template: Single { opcode: "HADD2.BF16_V2", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "mul.bf16x2",    template: Single { opcode: "HMUL2.BF16_V2", slots: &[Src(0), Src(1), Src(2)] } },
    // fma.rn.f16x2 -> HFMA2 (plain suffix-less, anchor t16i 0x270; bench_m9
    // fam-residuum surfaced after sub.s64 landed).
    PtxRule { pattern: "fma.rn.f16x2",  template: Single { opcode: "HFMA2", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "mad.wide.u32",  template: MadWide32 },
    // mul.f16x2 -> HMUL2 (plain 2-src, anchor mulf16 0x1a0; p15_half2 fam).
    PtxRule { pattern: "mul.f16x2",     template: Single { opcode: "HMUL2", slots: &[Src(0), Src(1), Src(2)] } },
    PtxRule { pattern: "ldmatrix.",     template: Ldsm { store: false } },
    PtxRule { pattern: "stmatrix.",     template: Ldsm { store: true } },
    PtxRule { pattern: "and.b16",       template: Single { opcode: "LOP3.LUT", slots: &[Src(0), Src(1), Src(2), RZ, Imm(0xc0), NotPT] } },
    PtxRule { pattern: "or.b16",        template: Single { opcode: "LOP3.LUT", slots: &[Src(0), Src(1), Src(2), RZ, Imm(0xfc), NotPT] } },
    PtxRule { pattern: "xor.b16",       template: Single { opcode: "LOP3.LUT", slots: &[Src(0), Src(1), Src(2), RZ, Imm(0x3c), NotPT] } },
    PtxRule { pattern: "add.s16",       template: Single { opcode: "IADD3", slots: &[Src(0), PT, PT, Src(1), Src(2), RZ] } },
    PtxRule { pattern: "sub.s16",       template: Sub16 },
    PtxRule { pattern: "mul.lo.s16",    template: MulLo16 },
    PtxRule { pattern: "mul.hi.u16",    template: MulHiU16 },
    PtxRule { pattern: "shr.u16",       template: ShrU16 },
    PtxRule { pattern: "selp.b16",      template: Single { opcode: "SEL", slots: &[Src(0), Src(1), Src(2), Src(3)] } },
    PtxRule { pattern: "mov.b16",       template: Single { opcode: "MOV", slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "sub.s64",       template: Sub64 },
    PtxRule { pattern: "min.s64",       template: MinS64 },
    PtxRule { pattern: "clz.b64",       template: Clz64 },
    PtxRule { pattern: "popc.b64",      template: Popc64 },
    PtxRule { pattern: "mul.lo.s64",    template: Mul64 { kind: Mul64Kind::Lo } },
    PtxRule { pattern: "mad.lo.s64",    template: Mul64 { kind: Mul64Kind::Mad } },
    PtxRule { pattern: "mul.hi.u64",    template: Mul64 { kind: Mul64Kind::Hi } },
    PtxRule { pattern: "cp.async.bulk.shared::cluster.global.mbarrier::complete_tx::bytes",
                                          template: CpAsyncBulk },

    // ── Memory ───────────────────────────────────────────────────────────
    PtxRule { pattern: "ld.param.",     template: LoadParam },
    PtxRule { pattern: "ld.global.",    template: LdGlobal },
    // b9p12: ld.volatile.global.b32 -> LDG.E.EF (suffix handled in lower_ld_global)
    PtxRule { pattern: "ld.volatile.global.", template: LdGlobal },
    PtxRule { pattern: "st.global.",    template: StGlobal },
    // b9 phase-3 #12 (b9p14): vector ld.shared./st.shared. MUST dispatch
    // before the plain prefixes (find_rule = first starts_with hit); the
    // bare LDS/STS templates would misrender the width-joined group as a
    // 32-bit op (silent pre-b9p14 flattening, p29 exposure).
    PtxRule { pattern: "ld.shared.v2", template: SharedVec { store: false } },
    PtxRule { pattern: "ld.shared.v4", template: SharedVec { store: false } },
    PtxRule { pattern: "st.shared.v2", template: SharedVec { store: true } },
    PtxRule { pattern: "st.shared.v4", template: SharedVec { store: true } },
    PtxRule { pattern: "ld.shared.",    template: Single { opcode: "LDS", slots: &[Src(0), Src(1)] } },
    PtxRule { pattern: "st.shared.",    template: Single { opcode: "STS", slots: &[Src(0), Src(1)] } },

    // ── Control flow ─────────────────────────────────────────────────────
    PtxRule { pattern: "bra.uni",       template: Single { opcode: "BRA", slots: &[Src(0)] } },
    PtxRule { pattern: "bra",           template: Single { opcode: "BRA", slots: &[Src(0)] } },
    PtxRule { pattern: "ret",           template: Single { opcode: "EXIT", slots: &[] } },
    PtxRule { pattern: "exit",          template: Single { opcode: "EXIT", slots: &[] } },

    // ── Synchronization ──────────────────────────────────────────────────
    // b9 phase-1: vendor canonical for __syncthreads is DEFER_BLOCKING
    // (anchor: k3 ptxas probe).
    // b9 phase-2: vendor keeps id AND thread-count (corpus anchor:
    // "BAR.SYNC.DEFER_BLOCKING 0x2, 0x1a0"); missing args resolve to RZ.
    // b9p12 (phase-3 #10): bar.sync/barrier sync family re-anchored on the
    // full corpus mat (probes work/b9p12/t/bar*.ptx):
    //   bar.sync 0 / barrier.sync[.aligned] 0     -> WARPSYNC.ALL; BAR.SYNC.DEFER_BLOCKING 0x0
    //   bar.sync I,N / barrier.sync.aligned I,N   -> WARPSYNC.ALL; BAR.SYNC.DEFER_BLOCKING I, N (II_II)
    //   barrier.sync I,N (non-aligned, with count)-> collective pack protocol (MOV id; MOV cnt;
    //     MOV -1; WARPSYNC.COLLECTIVE.ALL `(L); SHF.L 0x10; LOP3 0xf8 (cnt<<16|0xf|id);
    //     BAR.SYNC.DEFER_BLOCKING R,R; SHF.R 0x10; ENDCOLLECTIVE; L:)  [anchor p21 0xe0-0x160]
    //   barrier.arrive[.aligned] analogous with BAR.ARV (pack) / BAR.ARV I,N (II_II mg ARV).
    //   reg-form, guard, .cta -> unsupported (fail-closed).
    PtxRule { pattern: "bar.sync",      template: BarSync { aligned: false } },
    PtxRule { pattern: "barrier.sync.aligned", template: BarSync { aligned: true } },
    PtxRule { pattern: "barrier.sync",  template: BarSync { aligned: false } },
    PtxRule { pattern: "barrier.arrive.aligned", template: BarArrive { aligned: true } },
    PtxRule { pattern: "barrier.arrive", template: BarArrive { aligned: false } },
    // bar.red: WARPSYNC.ALL; BAR.RED.{AND,OR}.DEFER_BLOCKING imm, Ps; B2R.RESULT RZ, Pd
    // (anchors corpus v55 O0 0x2b0-0x2d0 AND + 0x4f0-0x510 OR; probe bar.ptx imm-1).
    PtxRule { pattern: "bar.red.and.pred", template: BarRed { or: false } },
    PtxRule { pattern: "bar.red.or.pred",  template: BarRed { or: true } },
    // b9 phase-3 #5: fence/membar family, vendor-anchored (fm1/fm2/fm3).
    // Legacy "MEMBAR.SC.GL" spelling was a silent trap (no encoder key); the
    // vendor form for membar.gl on sm_103a is the SC.GPU glue chain.
    PtxRule { pattern: "membar.cta",    template: Fence { lines: &["MEMBAR.SC.CTA"] } },
    PtxRule { pattern: "membar.gl",     template: Fence { lines: &["MEMBAR.SC.GPU", "ERRBAR", "CGAERRBAR", "CCTL.IVALL"] } },
    PtxRule { pattern: "membar.sys",    template: Fence { lines: &["MEMBAR.SC.SYS", "ERRBAR", "CGAERRBAR", "CCTL.IVALL"] } },
    PtxRule { pattern: "fence.sc.cta",  template: Fence { lines: &["MEMBAR.ALL.CTA"] } },
    PtxRule { pattern: "fence.sc.gpu",  template: Fence { lines: &["MEMBAR.ALL.GPU", "ERRBAR", "CGAERRBAR", "CCTL.IVALL"] } },
    PtxRule { pattern: "fence.sc.sys",  template: Fence { lines: &["MEMBAR.ALL.SYS", "ERRBAR", "CGAERRBAR", "CCTL.IVALL"] } },
    PtxRule { pattern: "fence.acq_rel.cta", template: Fence { lines: &["MEMBAR.ALL.CTA"] } },
    PtxRule { pattern: "fence.acq_rel.gpu", template: Fence { lines: &["MEMBAR.ALL.GPU", "ERRBAR", "CGAERRBAR", "CCTL.IVALL"] } },
    PtxRule { pattern: "fence.acq_rel.sys", template: Fence { lines: &["MEMBAR.ALL.SYS", "ERRBAR", "CGAERRBAR", "CCTL.IVALL"] } },
    // most-specific first: shared::cta before bare async
    PtxRule { pattern: "fence.proxy.async.shared::cta", template: Fence { lines: &["MEMBAR.ALL.CTA", "FENCE.VIEW.ASYNC.S"] } },
    PtxRule { pattern: "fence.proxy.async", template: Fence { lines: &["MEMBAR.ALL.GPU", "FENCE.VIEW.ASYNC.S"] } },

    // b9 phase-3 #6: fence.mbarrier_init = plain NOP (vendor anchor mb3:
    // NOP at +0xf0 between SYNCS.EXCH.64 and the next glue, -O0 and -O3).
    PtxRule { pattern: "fence.mbarrier_init.release.cluster", template: Fence { lines: &["NOP"] } },

    // ── mbarrier (b9 phase-3 #6; exact-name match like Fence) ──────────
    PtxRule { pattern: "mbarrier.init.shared::cta.b64",       template: Mbar { kind: MbarKind::Init } },
    PtxRule { pattern: "mbarrier.init.shared.b64",            template: Mbar { kind: MbarKind::Init } },
    PtxRule { pattern: "mbarrier.arrive.expect_tx.shared::cta.b64", template: Mbar { kind: MbarKind::ArriveExpectTx } },
    PtxRule { pattern: "mbarrier.arrive.shared::cluster.b64", template: Mbar { kind: MbarKind::ArriveCluster } },
    PtxRule { pattern: "mbarrier.arrive.shared::cta.b64",     template: Mbar { kind: MbarKind::Arrive } },
    PtxRule { pattern: "mbarrier.arrive.shared.b64",          template: Mbar { kind: MbarKind::Arrive } },
    PtxRule { pattern: "mbarrier.try_wait.parity.shared::cta.b64", template: Mbar { kind: MbarKind::TryWaitParity } },
    PtxRule { pattern: "mbarrier.try_wait.parity.shared.b64", template: Mbar { kind: MbarKind::TryWaitParity } },
    PtxRule { pattern: "mbarrier.try_wait.shared::cta.b64",   template: Mbar { kind: MbarKind::TryWait } },
    PtxRule { pattern: "mbarrier.try_wait.shared.b64",        template: Mbar { kind: MbarKind::TryWait } },

    // ── barrier.cluster (b9 phase-3 #7; exact-name match like Mbar; ─────
    // ordered most-specific first: plain names are prefixes of the
    // suffixed ones, and find_rule is a linear starts_with search)
    PtxRule { pattern: "barrier.cluster.arrive.relaxed.aligned", template: ClusterBarrier { arrive: true, relaxed: true, aligned: true } },
    PtxRule { pattern: "barrier.cluster.arrive.relaxed",         template: ClusterBarrier { arrive: true, relaxed: true, aligned: false } },
    PtxRule { pattern: "barrier.cluster.arrive.release.aligned", template: ClusterBarrier { arrive: true, relaxed: false, aligned: true } },
    PtxRule { pattern: "barrier.cluster.arrive.release",         template: ClusterBarrier { arrive: true, relaxed: false, aligned: false } },
    PtxRule { pattern: "barrier.cluster.arrive.aligned",         template: ClusterBarrier { arrive: true, relaxed: false, aligned: true } },
    PtxRule { pattern: "barrier.cluster.arrive",                 template: ClusterBarrier { arrive: true, relaxed: false, aligned: false } },
    PtxRule { pattern: "barrier.cluster.wait.acquire.aligned",   template: ClusterBarrier { arrive: false, relaxed: false, aligned: true } },
    PtxRule { pattern: "barrier.cluster.wait.acquire",           template: ClusterBarrier { arrive: false, relaxed: false, aligned: false } },
    PtxRule { pattern: "barrier.cluster.wait.aligned",           template: ClusterBarrier { arrive: false, relaxed: false, aligned: true } },
    PtxRule { pattern: "barrier.cluster.wait",                   template: ClusterBarrier { arrive: false, relaxed: false, aligned: false } },
    PtxRule { pattern: "mapa.shared::cluster.u32",               template: Mapa },

    // ── b9 phase-3 #8: vote/match/bar.warp/elect/nanosleep/griddep ─────
    // (exact-name match like Mbar/ClusterBarrier: the match arm re-checks
    // insn.opcode == rule.pattern so unlisted suffixes stay unsupported)
    PtxRule { pattern: "vote.sync.ballot.b32", template: Vote { ballot: true, all: false } },
    // b9 phase-3 #12 (b9p14): activemask.b32 -> VOTE.ANY Rd, PT, PT
    // (corpus p09 -O0 0x370; the ballot row with both sources tied PT).
    PtxRule { pattern: "activemask.b32", template: Single { opcode: "VOTE.ANY", slots: &[Src(0), PT, PT] } },
    PtxRule { pattern: "vote.sync.any.pred",   template: Vote { ballot: false, all: false } },
    PtxRule { pattern: "vote.sync.all.pred",   template: Vote { ballot: false, all: true } },
    PtxRule { pattern: "match.any.sync.b32",   template: MatchAny },
    PtxRule { pattern: "bar.warp.sync",        template: WarpSyncMask },
    PtxRule { pattern: "elect.sync",           template: ElectSync },
    PtxRule { pattern: "nanosleep.u32",        template: Nanosleep },
    PtxRule { pattern: "griddepcontrol.launch_dependents", template: GridDep { wait: false } },
    PtxRule { pattern: "griddepcontrol.wait",  template: GridDep { wait: true } },
    // cp.async non-bulk: most-specific (L2 hint) first, find_rule is a
    // linear starts_with search.
    PtxRule { pattern: "cp.async.cg.shared.global.L2::128B", template: CpAsync { bypass: true, ltc: Some(128) } },
    PtxRule { pattern: "cp.async.cg.shared.global",          template: CpAsync { bypass: true, ltc: None } },
    PtxRule { pattern: "cp.async.ca.shared.global.L2::256B", template: CpAsync { bypass: false, ltc: Some(256) } },
    PtxRule { pattern: "cp.async.ca.shared.global",          template: CpAsync { bypass: false, ltc: None } },
    PtxRule { pattern: "cp.async.commit_group", template: CpAsyncBar { commit: true, all: false } },
    PtxRule { pattern: "cp.async.wait_group",   template: CpAsyncBar { commit: false, all: false } },
    PtxRule { pattern: "cp.async.wait_all",     template: CpAsyncBar { commit: true, all: true } },
    PtxRule { pattern: "cvta.to.shared.u64",   template: AliasPair },

    // ── Atomics (b9 phase-3 #4; shapes parsed per-op in lower_atomic) ────
    PtxRule { pattern: "atom.",         template: Atom },
    PtxRule { pattern: "red.",          template: Red },

    // ── Warp ops ─────────────────────────────────────────────────────────
    PtxRule { pattern: "shfl.sync.",    template: Shfl },
    // b9 phase-2 P6: removed "redux.sync." -> REDUX.ADD single-op rule. It
    // collapsed MIN/MAX/AND/OR into ADD (wrong op) AND emitted an R-dest form
    // the sm_103a encoder does not have (vendor: REDUX[.op][.type] URd, Ra;
    // REDUX_UR_R table key). The gateway has no UR-domain allocation, so the
    // honest behavior is PTX-level rejection ("unsupported PTX: redux.sync..")
    // until a phase-3 UR path exists.

    // ── Conversions ──────────────────────────────────────────────────────
    PtxRule { pattern: "cvt.",          template: Cvt },
    PtxRule { pattern: "cvta.to.global.u64", template: AliasPair },

    // ── b9p12 (phase-3 #10) misc: trap / setmaxnreg / discard.global.L2 ──
    // trap = BPT.TRAP 0x1 (anchor corpus p32 O0 0x250 == O3 0x80)
    PtxRule { pattern: "trap",          template: Single { opcode: "BPT.TRAP", slots: &[Imm(0x1)] } },
    // setmaxnreg: vendor ELIDES the hint on sm_103a at both -O0 and -O3
    // (anchors corpus p30 both opt levels: zero SASS emitted). Emit nothing.
    PtxRule { pattern: "setmaxnreg.inc.sync.aligned.u32", template: Nop },
    PtxRule { pattern: "setmaxnreg.dec.sync.aligned.u32", template: Nop },
    // discard.global.L2 [a], 128 = CCTL.E.RML2 [pair] (anchor corpus p_cctl O0
    // 0x200); other sizes/scopes fail-closed.
    PtxRule { pattern: "discard.global.L2", template: DiscardL2 },

    // ── MMA ──────────────────────────────────────────────────────────────
    PtxRule { pattern: "mma.sync.",     template: Mma },
];

/// Find the first matching rule for a PTX opcode.
pub fn find_rule(ptx_opcode: &str) -> Option<&'static PtxRule> {
    RULES.iter().find(|r| ptx_opcode.starts_with(r.pattern))
}

/// Comparison operator mapping: PTX name → SASS suffix.
pub fn setp_cmp_suffix(ptx_opcode: &str) -> &'static str {
    let parts: Vec<&str> = ptx_opcode.split('.').collect();
    if parts.len() < 2 { return "EQ"; }
    let cmp = parts[1];
    if cmp.eq_ignore_ascii_case("lt") || cmp.eq_ignore_ascii_case("lo") { "LT" }
    else if cmp.eq_ignore_ascii_case("le") || cmp.eq_ignore_ascii_case("ls") { "LE" }
    else if cmp.eq_ignore_ascii_case("eq") || cmp.eq_ignore_ascii_case("equ") { "EQ" }
    else if cmp.eq_ignore_ascii_case("ne") || cmp.eq_ignore_ascii_case("neu") { "NE" }
    else if cmp.eq_ignore_ascii_case("gt") || cmp.eq_ignore_ascii_case("hi") { "GT" }
    else if cmp.eq_ignore_ascii_case("ge") || cmp.eq_ignore_ascii_case("hs") { "GE" }
    else if cmp.eq_ignore_ascii_case("ltu") { "LT" }
    else if cmp.eq_ignore_ascii_case("leu") { "LE" }
    else if cmp.eq_ignore_ascii_case("gtu") { "GT" }
    else if cmp.eq_ignore_ascii_case("geu") { "GE" }
    else { "EQ" }
}

/// Is this a float setp?
pub fn setp_is_float(ptx_opcode: &str) -> bool {
    ptx_opcode.contains(".f32") || ptx_opcode.contains(".f64") || ptx_opcode.contains(".f16")
}

/// Extract shuffle mode from PTX opcode.
pub fn shfl_mode(ptx_opcode: &str) -> &'static str {
    if ptx_opcode.contains(".up") { "UP" }
    else if ptx_opcode.contains(".down") { "DOWN" }
    else if ptx_opcode.contains(".bfly") { "BFLY" }
    else if ptx_opcode.contains(".idx") { "IDX" }
    else { "BFLY" }
}

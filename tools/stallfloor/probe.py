#!/usr/bin/env python3
"""probe.py - stall-floor probes as a service (sm_120).  One request = one isolated kernel family = one short GPU block.

A REQUEST names a producer form and a consumer form (kind `raw`: from which issue distance does the consumer see the
producer's result?) or a store form and an overwriter form (kind `war`: from which issue distance may an instruction
rewrite a register a BARE store reads?), and what is swept: the distance in issue cycles, the occupancy (warps per SM)
and the memory traffic in front. The tool builds one frozen kernel per point (every control code written out, nothing
is scheduled), launches each `reps` times and classifies EVERY thread of every launch against a checksum computed on
the host from the kernel's arithmetic - the absolute oracle. No reference kernel is the judge (a comparison with a
reference kernel is blind when the reference itself is affected: docs/KNOWN_ISSUES.md A27).

    probe.py gen  <requests.json> --out <batch dir> [--cubit BIN] [--table sm120.json.gz] [--dep-table dep_latency_sm120.json]
                  CPU: kernels (.sass + .cubin), family.json (index + provenance), model.npz (the host-computed
                  checksums of every thread for each failure hypothesis), per request in <batch dir>/<id>/
    probe.py run  <batch dir> [--reps N] [--limit-s S]
                  GPU (device 0 of the container): launches + classification -> <batch dir>/<id>/result.json,
                  <batch dir>/floors.json; prints SUMMARY lines
    probe.py floor <batch dir | result.json ...>
                  the result as log lines: `floor: <pair> = N (conditions) ...`
    probe.py adapt <gate json | dir ...> --out req.json
                  requests written by emu120.gate (`kernels[i].probes`) -> a request file of this tool + the list of pairs
                  the catalogue cannot build yet
    probe.py list     the forms the catalogue knows
    probe.py selftest the host model against an independent scalar interpreter (CPU only)

Request (JSON object; a file holds one object or a list):
    {"id": "sts_d_iadd3", "kind": "raw", "producer": "IADD3", "consumer": "STS.data",
     "occupancy": ["w1", "w8", "w32"], "front": ["none", "sts128x15@9"], "distances": "1-15,20,30",
     "cell": {"producer": "IADD3", "consumer": "STS", "role": "r1"}, "note": "..."}
    {"id": "sts_d_lop3", "kind": "war", "store": "STS.data", "overwriter": "LOP3", "controls": true,
     "occupancy": ["w8", "g32"], "front": ["none", "sts128x15@4"], "distances": "1-15,18-75:3,90,105,150"}
Distance = the sum of the stall counts from the tested producer (store) to the consumer (overwriter): one stall
1..15 on the producer plus fillers of 15 cycles (`"via": "fill"`: stall 1 plus fillers of 1 cycle - the additive model).
Classes of a thread-launch (256 iterations each):
    good      the checksum of the intended values in all 256 iterations
    stale     raw: the consumer took the register's PREVIOUS content in all 256 iterations
    late      war: the store took the OVERWRITTEN register in all 256 iterations
    overtake  war: the read-back load saw the slot before the store in all 256 iterations
    other     a mixture (some iterations wrong) - or a model that does not describe the kernel: the far / control
              kernels of every series must be 100 % good, else the series has NO result (`oracle: FAILED`)
Floor of a series = the smallest swept distance from which every swept distance is 100 % good in every launch; the
binding floor of a request = the largest over its conditions. Floors enter cubit's table only through its gate.

Kind `reuse` (version 20) - the operand-reuse flag: a word reads R6 through one of its three source-register slots with
`.reuse`, R6 is written again, a reader takes R6 through the same slot d issue cycles behind the write. `stale` = the
reader took the OLD content. Variants: bare (the flag), ctl (the same text without it: the write's own floor).
    {"id": "ru_a_clean_w1", "kind": "reuse", "flagged": "IADD3i.A", "writer": "clean", "words": 1,
     "occupancy": ["w1", "w8", "w32", "c2w9s"]}

Version 22 - kind `raw`, pair classes without a table cell: consumers FMUL.r2, FADD.r1, FFMA.r2 (they take a producer
whose result is a finite float or zero: FADD, FMUL, CS2R, MOV.fin), MUFU.RCP.r1 (producer MOV.pow2), IMAD.WIDE.r2,
IMAD.r2, SHF.r3, IADD.r1, IADD.r2; producers MOV.fin, MOV.pow2, IABS; `"result": 1` = the consumer takes the SECOND
register of a pair producer (CS2R, IADD.64, IMAD.WIDE); `"salt": "set"` = the iteration's input is added to the checksum
behind the consumer (a producer of zeros must not leave the checksum of a kernel that never ran).
    {"id": "pd_cs2r_fmul_r2h", "kind": "raw", "producer": "CS2R", "consumer": "FMUL.r2", "result": 1, "salt": "set", "distances": "1-8,11,26"}

Version 23 - kind `ord`, SETS of producers on one write barrier: `forms` takes, beside s | u | d | q, the letters G (LDG.E),
Q (LDG.E.128), B (LDG.E.U8), c (LDC), C (LDC.64), m (MUFU.EX2), h (SHFL.BFLY); such a request has 2 .. 17 producers, its
kernels declare R0-R79 (.regcount 88) and run on grids of at most 744 threads per SM.
    {"id": "gs17_all", "kind": "ord", "forms": "gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gG", "barrier": "all", "yield": "set"}

Version 24 - kind `raw` with a TENSOR consumer (QMMA.r3 | .r3h | .r1 | .r1h | .r2 | .r2h, HMMA.r3 | .r3h: one register of
an operand of a tensor word with uniform fragments; producers CS2R, MOV, FMUL (accumulator), MOV (A), LOP3 (B); "reg" =
which upper register of a quad) and RELATIVE consumers (QMMA.u6 behind UMOV; IMADi.rel, IMAD.rel, IADD.64.rel behind
CS2R, CS2R.32.CgaSize, CS2R.GLOBALTIMERLO: the consumer's result at the swept distance against the same word's result 45
cycles later - the host need not know the content). "control": "stale" = the positive control of a request: the
producer's word behind the consumer, the model still gives the consumer the new content - expect 0 % good.
    {"id": "tq_cs2r_r3h1", "kind": "raw", "producer": "CS2R", "consumer": "QMMA.r3h", "reg": 1, "front": ["none", "mmax1@7"]}
    {"id": "tq_cs2r_r3h1_c", "kind": "raw", "producer": "CS2R", "consumer": "QMMA.r3h", "reg": 1, "control": "stale"}

Version 25 - "control": "stale" for EVERY kind-`raw` pair (an ordinary pair too: the producer's word behind the consumer
and its checksum, a filler in its place; expect 0 % good, the class `stale`); consumers IADD.64rr.r1 | .r1h | .r2 | .r2h
(the register-register IADD.64), PRMT.r3, STG.a0 (the low register of a global store's address pair; producer kind gaddr:
IADD.64); kind `mma`: hold_c_cs2r / sens_c_cs2r ("reg": 0 | 2) and hold_c_prmt / sens_c_prmt - the accumulator's hold with
the vendor's overwriters -, "dest": "a" = the word's result goes to its own A quad; `table_cell` reads `producer_forms`.
    {"id": "pc_mov_iadd_r2h", "kind": "raw", "producer": "MOV", "consumer": "IADD.64rr.r2h"}
    {"id": "pc_mov_iadd_r2h_c", "kind": "raw", "producer": "MOV", "consumer": "IADD.64rr.r2h", "control": "stale"}
    {"id": "hv_cs2r_q", "kind": "mma", "variant": "hold_c_cs2r", "reg": 2, "dest": "a", "distances": "1-10,12"}

Version 25, fifth build - the consumer LEA.r2 (the UNSHIFTED operand of `LEA Rd, Ra, Rb, 2` = (Ra << 2) + Rb); kind `mma`:
hold_u_umov / sens_u_umov - the hold of the UNIFORM operand (the selector) of a QMMA.SF behind the word, RELATIVE: the word
against the same word 60 cycles in front of it, `UMOV UR6, 0x0` d cycles behind it (the control: the UMOV 60 cycles in
front of it); the scale register holds four different bytes that differ from lane to lane.
    {"id": "hu_q", "kind": "mma", "variant": "hold_u_umov", "distances": "1-10,12,15,30,45"}
    {"id": "hu_q_s", "kind": "mma", "variant": "sens_u_umov"}

Version 26 - kind `thr`, a THROUGHPUT probe: the TIME of a synthetic stage loop with tensor words (four QMMA.SF 16 cycles
apart, the vendor's PRMT / LOP3.LUT words in front of them, one LDS.128 on a write barrier, IMAD folds) in which ONE control
field changes per slot; the slot number rides in the distance slot (slot 1 = the base stage, the last slot = the base stage
again). "stage": a (words that wait on a free barrier / on a load in flight; tensor words that arm a read barrier; the
re-arm wait; yield patterns) | e (the empty loop); "repeat": an ODD number of passes of 256 iterations (a thread ends with
repeat x the checksum of one pass). Every slot computes the same checksum and keeps the table's cells and the holds (the
generator's audit refuses a slot that does not). The runner writes the median launch time per slot.
    {"id": "thr_a_full_n255", "kind": "thr", "stage": "a", "repeat": 255, "occupancy": ["w32", "c4w8", "c2w9s"], "reps": 20}

Version 26, second build - kind `gw`, a WAIT CARRIED BY A WORD UNDER A GUARD: a scoreboarded producer (SHFL | LDS) on a write
barrier; the only wait on it stands on `@P4 PRMT ...` two cycles behind the producer; the reader `@!P4 PRMT ...` has no wait
and stands d cycles behind the producer; "guard": bit (P4 false in part of the iterations) | false (in every one); "wait":
guarded | none (no wait at all: the positive control and the floor by distance alone); "yield": "set".
    {"id": "gw_shfl", "kind": "gw", "producer": "SHFL", "wait": "guarded", "guard": "bit"}
    {"id": "gw_shfl_nw", "kind": "gw", "producer": "SHFL", "wait": "none", "guard": "bit"}

Version 26, third build - kind `lb`, the BASE register of a load rewritten by a YOUNGER load of the same pipe: `LDS R6,
[R13+0x4]` (no read barrier), then `LDS R13, [R13+0x3c]` d cycles behind it with no wait between; the new base is another
address of the thread's own line (a late read of the base shows as another word, never as a trap); "control": "front" =
the positive control (the younger load in front of the older one: expect 0 % good, class late); "yield": "set".
    {"id": "lb_lds", "kind": "lb"}
    {"id": "lb_lds_c", "kind": "lb", "control": "front"}

Version 27 - kind `gp`, a GUARDED WAIT UNDER ANOTHER PREDICATE: two `LDC.64` under two different predicates arm ONE write
barrier; the only wait on it stands on a word under the FIRST predicate; the reader reads the second load's pair under the
SECOND predicate d cycles behind its load, no wait of its own. "form": imad | lea (the two pointer groups of the vendor's
MoE kernel's prologue, with their stalls and yield flags; the reader's result is DATA here, folded relative to the prologue's copy of
the constant); "guards": tt | ft | tf | ff | lane | cnt (which side executes: carrier's, reader's); "pset": pro | near
(where the predicates are set); "wait": guarded | end (the positive control: the carrier without its wait bit); form imad:
"share": ldg (the kernel's shape: the barrier is armed again by a guarded global load one cycle in front of the reader) | ldc
| own (the second load on a barrier of its own).
    {"id": "gp_imad_ft", "kind": "gp", "form": "imad", "guards": "ft", "pset": "near"}
    {"id": "gp_imad_ft_ew", "kind": "gp", "form": "imad", "guards": "ft", "pset": "near", "wait": "end"}

Version 28 - kind `ord`, a SET UNDER TWO PREDICATES on one write barrier (the attention kernel's `@P0 LDG.E.128` + `@P0
LDG.E.U8` + `@P1 LDG.E`): the prefix k on a load = under the second predicate (`@P2`; P1 is the loop's); "pguard": two
letters, P0 then P2, of t (true) | f (false) | l (a bit of the lane: all four combinations inside every warp) | c (a bit of
iteration counter x 0x9e3779b1; P0 takes the next bit for every further pair) - both written at the top of every iteration
by ISETP.GE.AND, P0 again 13 cycles in front of every further `@P0 LDG.E.128`; a nullified producer leaves its
destinations' markers. "wait": reader | end (the positive control: the reader's wait bit moved to the first word behind
the reader words - the producers keep their barrier); "rdist": the reader's distance behind the last arming (absent: 2).
    {"id": "e2_tf", "kind": "ord", "forms": "gQ,kG", "barrier": "all", "yield": "set", "pguard": "tf"}
    {"id": "e2_tf_ew", "kind": "ord", "forms": "gQ,kG", "barrier": "all", "yield": "set", "pguard": "tf", "wait": "end"}
Version 28, second build - letter c on a set with more than one `gQ`: the shift of P0's source stands right behind the previous
ISETP (13 cycles or more in front of the ISETP that reads it). The FIRST build put it one cycle in front of that ISETP: not
right by construction (ten requests of the result file `_b55` are void); "pshift": 1 builds that text again, with the hypothesis
`p0old` (every such ISETP read the source's old content) as a third host model.

Version 29 - kind `ord`, the SCALE SET (the letter S): 2 or 3 unguarded `LDS` on ONE write barrier, issued one after another
without a wait (every second one through another base register), each into a block-scale register of two GUARDED tensor
readers: `@P0 QMMA.SF ... Ryoungest, Rnext, URZ` on the ONE wait and, 16 cycles behind it, `@P2 QMMA.SF ... Roldest, Ryoungest,
URZ` with no wait of its own. The loads bring the UE8M0 code of the unit scale in every byte; until its load lands a register
holds the code of x 2 (a stale reader adds another, still exact, amount). "pguard": two letters, P0 (the first reader) then P2
(the second), of t | f | l | c as in version 28 (written at the top of every iteration); "rdist": the first reader's distance
behind the last arming (absent: 2); "wait": reader | end (the positive control: that one wait bit on the first word behind the
reader words). Hypotheses: stale (every reader word that executes took the markers), stale1 / stale2 (only the first / only
the second). The generator COUNTS THE CYCLES of every such body (`sf_audit`): a consumer of a fixed-latency word of the probe's
own text closer than the table's distance, a guard closer than 13 behind its ISETP, a tensor result read closer than 28, a
rewrite closer than 8 behind a tensor word that read the register - refused.
    {"id": "sf2_ft", "kind": "ord", "forms": "S,S", "barrier": "all", "yield": "set", "pguard": "ft", "distances": "1,4"}
    {"id": "sf2_ft_ew", "kind": "ord", "forms": "S,S", "barrier": "all", "yield": "set", "pguard": "ft", "distances": "4", "wait": "end"}
Version 29, second build - the MIXED scale set: the letter D = an unguarded `LDS.64` on the same barrier, its pair read by two
`MOV` words (data); 2 .. 7 loads, 1 .. 4 S and 0 .. 3 D in any order (with one S the readers' other scale operand is a register
of the prologue). "lead": qmma (absent: the tensor readers first, the MOV readers behind them) | mov (the MOV readers first:
the first MOV carries the ONE wait); hypothesis stale3 = only the MOV readers took the markers.
    {"id": "mx7_ft", "kind": "ord", "forms": "S,S,D,D,S,S,D", "barrier": "all", "yield": "set", "pguard": "ft", "distances": "1,4"}
    {"id": "mx5m_cc", "kind": "ord", "forms": "D,D,S,S,D", "barrier": "all", "yield": "set", "pguard": "cc", "lead": "mov", "distances": "1,4"}
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import hashlib
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import time

TOOL = "probe.py 29 (2026-11-12)"
HERE = pathlib.Path(__file__).resolve().parent
SEED = 0x12345
PTR_STANDIN = [0, 0]      # version 28: the scalar interpreter's stand-in for the output pointer R2:R3 (the selftest sets it nonzero: no fold may depend on it)
REPEAT = 256
SMEM = 65536
# occupancy: name -> (CTAs, threads per CTA); the output buffer keeps 1 024 words per CTA (gid = ctaid * 1024 + tid)
GEOM = {"w1": (188, 32), "w2": (188, 64), "w4": (188, 128), "w8": (188, 256), "w16": (188, 512), "w32": (188, 1024),
        "g32": (32, 1024), "g8": (32, 256), "w12": (188, 384), "c2w9": (376, 288), "w9": (188, 288), "c2w9s": (376, 288), "c4w8": (752, 256)}
# shared memory per CTA (bytes) where it is not SMEM. An SM of these cards has 102 400 B (sharedMemPerMultiprocessor): a
# kernel that declares 65 536 B has ONE CTA resident per SM whatever the grid says - `c2w9` (376 CTAs) ran as two waves of
# 188 and was called "2 CTAs per SM" until 2026-11-11. `c2w9s` declares 49 152 B: two CTAs fit an SM, three do not.
SMEM_OF = {"c2w9s": 49152, "c4w8": 24576}      # c4w8: four CTAs fit an SM (98 304 B), five do not
SMEM_PER_SM = 102400
SMEM_PER_CTA_MAX = 101376
OCC = {"w1": "1 warp per SM (188 CTAs x 32)", "w2": "2 warps per SM (188 x 64)", "w4": "4 warps per SM (188 x 128)",
       "w8": "8 warps per SM (188 x 256)", "w16": "16 warps per SM (188 x 512)", "w32": "32 warps per SM (188 x 1 024)",
       "g32": "32 warps on each of 32 SMs (32 x 1 024)", "g8": "8 warps on each of 32 SMs (32 x 256)",
       "w12": "12 warps per SM (188 x 384)",
       "c2w9": "9 warps per SM, ONE CTA resident per SM (376 x 288 in two waves: 65 536 B of shared memory per CTA)",
       "w9": "9 warps per SM (188 x 288)",
       "c2w9s": "2 CTAs of 9 warps per SM (376 x 288; 49 152 B of shared memory per CTA)",
       "c4w8": "4 CTAs of 8 warps per SM (752 x 256; 24 576 B of shared memory per CTA)"}
NGID = 188 * 1024
DEF_CUBIT = str(HERE.parent.parent / "target" / "release" / "cubit")
DEF_TABLE = str(HERE.parent.parent / "tables" / "sm120.json.gz")
DEF_DEP = str(HERE.parent.parent / "tables" / "dep_latency_sm120.json")


def C(s=15, wait="", rb="-", wb="-", y=False):
    """a control code `[B<waits>:R<read barrier>:W<write barrier>:<yield>:S<stall>]`"""
    w = "".join(str(i) if str(i) in wait else "-" for i in range(6))
    return f"[B{w}:R{rb}:W{wb}:{'Y' if y else '-'}:S{s:02d}]"


class Ins:
    """one instruction: control code, text, what it does for the host model, its role in the probe"""
    __slots__ = ("ctl", "text", "sem", "tag", "dst")

    def __init__(self, text, sem, ctl=None, tag=None, dst=()):
        self.ctl, self.text, self.sem, self.tag, self.dst = ctl or C(), text, sem, tag, tuple(dst)

    def line(self):
        return f"{self.ctl} {self.text}"


def PAD():
    return Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",))


def FILL1():
    return Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(1))


class Lbl(Ins):
    """version 20: a label on its own line (no control code; nothing for the host model)"""
    __slots__ = ()

    def __init__(self, name):
        Ins.__init__(self, name, ("nop",), tag="L")

    def line(self):
        return f"{self.text}:"


# ------------------------------------------------------------------------------------------------ the catalogue
def fin(reg, src):
    """a finite float in +-[1, 2) from a random word"""
    return [Ins(f"LOP3.LUT R{reg}, R{src}, 0x807fffff, RZ, 0xc0, !PT ;", ("and", f"R{reg}", f"R{src}", 0x807fffff)),
            Ins(f"LOP3.LUT R{reg}, R{reg}, 0x3f800000, RZ, 0xfc, !PT ;", ("or", f"R{reg}", f"R{reg}", 0x3f800000))]


def data_producer(name, rd):
    """-> (pre, text, sem, table class): R<rd> = f(a, b) of the iteration (a = R4, b = R5)"""
    r = f"R{rd}"
    if name == "IADD3":
        return [], f"IADD3 {r}, PT, PT, R4, R5, RZ ;", ("add", r, "R4", "R5"), "IADD3"
    if name == "IMAD":
        return [], f"IMAD {r}, R4, 0x9, R5 ;", ("mad", r, "R4", 9, "R5"), "IMAD"
    if name == "LOP3":
        return [], f"LOP3.LUT {r}, R4, R5, RZ, 0x3c, !PT ;", ("xor", r, "R4", "R5"), "LOP3"
    if name == "MOV":
        return [], f"MOV {r}, R4 ;", ("mov", r, "R4"), "MOV"
    if name == "SHF":
        return [], f"SHF.R.U32.HI {r}, RZ, 0x3, R4 ;", ("shr", r, "R4", 3), "SHF"
    if name == "FADD":
        return fin(13, 4) + fin(14, 5), f"FADD.FTZ {r}, R13, R14 ;", ("fadd", r, "R13", "R14"), "FADD"
    if name == "FMUL":
        return fin(13, 4) + fin(14, 5), f"FMUL.FTZ {r}, R13, R14 ;", ("fmul", r, "R13", "R14"), "FMUL"
    if name == "SEL":          # P2 = a < b (set long before); SEL Rd, Ra, Rb, !P2 = P2 ? Rb : Ra
        return [P2_LT()], f"SEL {r}, R4, R5, !P2 ;", ("selnot", r, "R4", "R5", "P2"), "SEL"
    if name == "F2FP.SAT":     # both halves from the same finite float: the result does not depend on the order of the halves
        return fin(13, 4), f"F2FP.SATFINITE.BF16.F32.PACK_AB {r}, R13, R13 ;", ("bf16pack2", r, "R13"), "F2FP.PACK"
    if name == "IADD3.neg":
        return [], f"IADD3 {r}, PT, PT, -R4, 0x10, RZ ;", ("rsub", r, "R4", 0x10), "IADD3"
    if name == "PRMT":
        return [], f"PRMT {r}, R4, 0x7632, R5 ;", ("prmt", r, "R4", 0x7632, "R5"), "PRMT"
    if name == "IMAD.SHL":
        return [], f"IMAD.SHL.U32 {r}, R4, 0x10, RZ ;", ("mad", r, "R4", 0x10, "RZ"), "IMAD"
    if name == "IADD.64":      # the pair R(d+1):Rd = R5:R4 + 4
        return [], f"IADD.64 {r}, R4, 0x4 ;", ("add64i", r, "R4", 4), "IADD.64"
    if name == "CS2R":         # the pair form `CS2R Rn, SRZ`: R(d+1):Rd = 0; both registers hold the iteration's inputs until it lands
        return ([Ins(f"MOV {r}, R4 ;", ("mov", r, "R4")), Ins(f"MOV R{rd + 1}, R5 ;", ("mov", f"R{rd + 1}", "R5"))],
                f"CS2R {r}, SRZ ;", ("zero2", r), "CS2R")
    if name == "LEA":          # Ra + (Ra << 2), the form whose arithmetic the LEA consumer ran with
        return [], f"LEA {r}, R4, R4, 0x2 ;", ("mad", r, "R4", 5, "RZ"), "LEA"
    if name == "IMAD.WIDE":    # the pair R(d+1):Rd = R4 * R5
        return [], f"IMAD.WIDE.U32 {r}, R4, R5, RZ ;", ("mulw", r, "R4", "R5"), "IMAD.WIDE"
    if name == "MOV.fin":      # version 22: a register move of a FINITE float (what a float consumer needs)
        return fin(13, 4), f"MOV {r}, R13 ;", ("mov", r, "R13"), "MOV"
    if name == "MOV.pow2":     # version 22: a register move of a power of two, 2^-3 ... 2^4 (its reciprocal is exact)
        return ([Ins("LOP3.LUT R13, R4, 0x3800000, RZ, 0xc0, !PT ;", ("and", "R13", "R4", 0x03800000)),
                 Ins("IADD3 R13, PT, PT, R13, 0x3e000000, RZ ;", ("add", "R13", "R13", 0x3e000000))],
                f"MOV {r}, R13 ;", ("mov", r, "R13"), "MOV")
    if name == "IABS":         # version 22
        return [], f"IABS {r}, R4 ;", ("iabs", r, "R4"), "IABS"
    raise SystemExit(f"unknown data producer {name!r} (probe.py list)")


def P2_LT():
    return Ins("ISETP.LT.U32.AND P2, PT, R4, R5, PT ;", ("ltu", "P2", "R4", "R5"))


DATA_PRODUCERS = ["IADD3", "IMAD", "LOP3", "MOV", "SHF", "FADD", "FMUL", "SEL", "F2FP.SAT", "IADD3.neg", "PRMT", "IMAD.SHL", "IADD.64", "IMAD.WIDE", "CS2R", "LEA", "MOV.fin", "MOV.pow2", "IABS"]
PAIR_PRODUCERS = {"IADD.64", "IMAD.WIDE", "CS2R"}      # they write R(d) and R(d+1)


def uniform_producer(name):
    """-> (pre, text, sem, class): UR6 = a warp-uniform value (the uniform datapath; UR4 / UR5 hold the memory descriptor)"""
    if name == "UMOV":         # an immediate; UR6 holds ANOTHER immediate until it lands
        return [Ins("UMOV UR6, 0x155 ;", ("mov", "UR6", 0x155))], "UMOV UR6, 0x400 ;", ("mov", "UR6", 0x400), "UMOV"
    if name == "UIADD3":       # UR8 counts the iterations
        return ([Ins("UIADD3 UR8, UPT, UPT, UR8, 0x1, URZ ;", ("add", "UR8", "UR8", 1))],
                "UIADD3 UR6, UPT, UPT, UR8, 0x650, URZ ;", ("add", "UR6", "UR8", 0x650), "UIADD3")
    if name == "CS2UR.32":     # version 27, third build: a special register of KNOWN content (zero) into a uniform register; UR6 holds an immediate until it lands
        return [Ins("UMOV UR6, 0x155 ;", ("mov", "UR6", 0x155))], "CS2UR.32 UR6, SRZ ;", ("mov", "UR6", 0), "CS2UR"
    if name == "CS2UR":        # the 64-bit form (the kernel's `CS2UR UR4, SR_GLOBALTIMERLO`): it writes UR6 AND UR7
        return ([Ins("UMOV UR6, 0x155 ;", ("mov", "UR6", 0x155)), Ins("UMOV UR7, 0x2aa ;", ("mov", "UR7", 0x2aa))],
                "CS2UR UR6, SRZ ;", ("zero2u", "UR6", "UR7"), "CS2UR")
    raise SystemExit(f"unknown uniform producer {name!r} (probe.py list)")


UNIFORM_PRODUCERS = ["UMOV", "UIADD3", "CS2UR.32", "CS2UR"]


def addr_producer(name):
    """-> (pre, text, sem, class): R6 = the address of word k = a & 3 of the thread's slot 2 (R9 + 0x20 + 4 k)"""
    k = [Ins("LOP3.LUT R7, R4, 0x3, RZ, 0xc0, !PT ;", ("and", "R7", "R4", 3))]
    k4 = k + [Ins("SHF.L.U32 R7, R7, 0x2, RZ ;", ("shl", "R7", "R7", 2)),
              Ins("IADD3 R7, PT, PT, R7, 0x20, RZ ;", ("add", "R7", "R7", 0x20))]
    if name == "IADD3":
        return k4, "IADD3 R6, PT, PT, R7, R9, RZ ;", ("add", "R6", "R7", "R9"), "IADD3"
    if name == "IMAD":
        return k, "IMAD R6, R7, 0x4, R13 ;", ("mad", "R6", "R7", 4, "R13"), "IMAD"      # R13 = R9 + 0x20 (prologue)
    if name == "LOP3":      # the low 6 bits of R9 are zero: OR adds
        return k4, "LOP3.LUT R6, R7, R9, RZ, 0xfc, !PT ;", ("or", "R6", "R7", "R9"), "LOP3"
    raise SystemExit(f"unknown address producer {name!r} (probe.py list)")


ADDR_PRODUCERS = ["IADD3", "IMAD", "LOP3"]


def gaddr_producer(name):
    """version 25 -> (pre, text, sem, class): the PAIR R7:R6 = the address of the thread's word A (R17:R16). Until it lands
    the pair holds the address of the thread's word B (R19:R18). Both are words of the kernel's own output buffer and the
    runner keeps the buffer inside one 4-GiB window: the two addresses differ in the LOW register only - a store through a
    stale low register goes to word B, and no mixture of the two pairs leaves the buffer. (The HIGH register, role a0h,
    cannot be probed this way: both addresses share it.) The model's stand-ins: R16 = 0 (word A), R18 = 1 (word B)."""
    pre = [Ins("MOV R6, R18 ;", ("mov", "R6", "R18")), Ins("MOV R7, R19 ;", ("mov", "R7", "R19"))]
    if name == "IADD.64":      # the vendor's register-register form; R27:R26 = 0 (the prologue; nothing of this body writes them)
        return pre, "IADD.64 R6, R16, R26 ;", ("mov2", "R6", "R16"), "IADD"
    raise SystemExit(f"unknown global-address producer {name!r} (probe.py list)")


GADDR_PRODUCERS = ["IADD.64"]
FOLD4 = [("IMAD R8, R29, 0x3, R28 ;", ("mad", "R8", "R29", 3, "R28")), ("IMAD R8, R30, 0x5, R8 ;", ("mad", "R8", "R30", 5, "R8")),
         ("IMAD R8, R31, 0x7, R8 ;", ("mad", "R8", "R31", 7, "R8")), ("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"))]


def fold4(wait):
    return [Ins(t, s, ctl=C(wait=wait) if i == 0 else None) for i, (t, s) in enumerate(FOLD4)]


def ADD10(wait=""):
    return Ins("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"), ctl=C(wait=wait))


RAW_CONSUMERS = {
    # name: (what the producer writes: "data" + its register, or "addr"; table consumer class, role; text of the description)
    "STS.data": ("data", 6, "STS", "r1", "the data register of a 32-bit shared store"),
    "STS128.d0": ("data", 24, "STS", "r1", "the FIRST data register of STS.128"),
    "STS128.d3": ("data", 27, "STS", "r1h", "the LAST data register of STS.128"),
    "STG.data": ("data", 6, "STG", "r1", "the data register of a global store"),
    "STS.addr": ("addr", 6, "STS", "a0", "the address register of a shared store"),
    "LDS.addr": ("addr", 6, "LDS", "a1", "the address register of a shared load"),
    "IADD3.r1": ("data", 6, "IADD3", "r1", "the first addend of IADD3"),
    "IADD3.r2": ("data", 6, "IADD3", "r2", "the second addend of IADD3"),
    "IMAD.r1": ("data", 6, "IMAD", "r1", "the multiplicand of IMAD"),
    "IMAD.r3": ("data", 6, "IMAD", "r3", "the addend of IMAD"),
    "LOP3.r1": ("data", 6, "LOP3", "r1", "the first operand of LOP3"),
    "MOV.r1": ("data", 6, "MOV", "r1", "the source of MOV"),
    "SHF.r1": ("data", 6, "SHF", "r1", "the shifted operand of SHF.L.U32"),
    "SEL.r1": ("data", 6, "SEL", "r1", "the first operand of SEL"),
    "PRMT.r1": ("data", 6, "PRMT", "r1", "the first operand of PRMT"),
    "I2FP.r1": ("data", 6, "I2FP", "r1", "the source of I2FP.F32.S32"),
    "IMAD.SHL.r1": ("data", 6, "IMAD", "r1", "the multiplicand of IMAD.SHL.U32"),
    "IADD.64.r1": ("data", 6, "IADD.64", "r1", "the LOW word of the first operand pair of IADD.64"),
    "IADD.64.r1h": ("data", 6, "IADD.64", "r1h", "the HIGH word of the first operand pair of IADD.64 (the producer writes a pair)"),
    "LEA.r1": ("data", 6, "LEA", "r1", "both operands of LEA Rd, Ra, Ra, 2"),
    "LEA.r2": ("data", 6, "LEA", "r2", "the UNSHIFTED operand of LEA Rd, Ra, Rb, 2 = (Ra << 2) + Rb (version 25, fifth build)"),
    "SHF.L.U64.HI.r1": ("data", 6, "SHF", "r1", "the operand PAIR of SHF.L.U64.HI (the producer writes a pair)"),
    "IMAD.WIDE.r3": ("data", 6, "IMAD.WIDE", "r3", "the LOW word of the 64-bit addend of IMAD.WIDE"),
    "IMAD.WIDE.r3h": ("data", 7, "IMAD.WIDE", "r3h", "the HIGH word of the 64-bit addend of IMAD.WIDE"),
    "UIADD3.u1": ("udata", 6, "UIADD3", "u1", "the uniform addend of UIADD3"),
    "MOV.u1": ("udata", 6, "MOV", "u1", "the uniform source of MOV R, UR"),
    "IADD.64.u2": ("udata", 6, "IADD.64", "u2", "the uniform pair of IADD.64 R, -R, UR - the low word of the result (version 27, third build)"),
    "IADD.64.u2h": ("udata", 6, "IADD.64", "u2h", "the uniform pair of IADD.64 R, -R, UR - the high word of the result (version 27, third build)"),
    # version 22 - pair classes the catalogue could not express (CS's seven, EM's table of the default-priced classes)
    "FMUL.r2": ("data", 6, "FMUL", "r2", "the second factor of FMUL.FTZ (the producer brings a finite float or zero)"),
    "FADD.r1": ("data", 6, "FADD", "r1", "the first addend of FADD.FTZ (the producer brings a finite float or zero)"),
    "FFMA.r2": ("data", 6, "FFMA", "r2", "the second factor of FFMA.FTZ Rd, 3.0, R, Rc (the producer brings a finite float or zero; one rounding, exact on the host)"),
    "MUFU.RCP.r1": ("data", 6, "MUFU", "r1", "the source of MUFU.RCP (the producer brings a power of two; the host's reciprocal is exact, the unit's must be - the far kernels say)"),
    "IMAD.WIDE.r2": ("data", 6, "IMAD.WIDE", "r2", "the multiplier REGISTER of IMAD.WIDE.U32 (both words of the product reach the checksum)"),
    "IMAD.r2": ("data", 6, "IMAD", "r2", "the multiplier REGISTER of IMAD Rd, Ra, R, RZ"),
    "SHF.r3": ("data", 6, "SHF", "r3", "the high-word operand of SHF.R.U32.HI Rd, RZ, 3, R"),
    "IADD.r1": ("data", 6, "IADD", "r1", "the first addend of the 32-bit IADD Rd, R, Rb"),
    "IADD.r2": ("data", 6, "IADD", "r2", "the second addend of the 32-bit IADD Rd, Ra, R"),
    # version 24 - tensor consumers (absolute; uniform fragments) and relative consumers
    "QMMA.r3": ("tdata", 28, "QMMA", "r3", "the FIRST accumulator register of QMMA.SF.16832.F32.E4M3.E2M1.E8 (producers CS2R, MOV, FMUL)"),
    "QMMA.r3h": ("tdata", 29, "QMMA", "r3h", "an UPPER accumulator register of the QMMA (\"reg\": 1 | 2 | 3; producers CS2R, MOV, FMUL)"),
    "QMMA.r1": ("tdata", 16, "QMMA", "r1", "the FIRST register of the QMMA's A fragment (producer MOV)"),
    "QMMA.r1h": ("tdata", 17, "QMMA", "r1h", "an UPPER register of the QMMA's A fragment (\"reg\": 1 | 2 | 3; producer MOV)"),
    "QMMA.r2": ("tdata", 12, "QMMA", "r2", "the LOWER register of the QMMA's B fragment (producer LOP3, the vendor's mask form)"),
    "QMMA.r2h": ("tdata", 13, "QMMA", "r2h", "the UPPER register of the QMMA's B fragment (producer LOP3)"),
    "QMMA.u6": ("trel", 6, "QMMA", "u6", "the uniform operand of the QMMA (producer UMOV) - RELATIVE: the result against the same word's 45 cycles later"),
    "HMMA.r3": ("tdata", 28, "HMMA", "r3", "the FIRST accumulator register of HMMA.16816.F32.BF16 (producers FMUL, MOV, CS2R)"),
    "HMMA.r3h": ("tdata", 29, "HMMA", "r3h", "an UPPER accumulator register of the HMMA (\"reg\": 1 | 2 | 3)"),
    "IMADi.rel": ("rel", 6, "IMAD", "r1", "RELATIVE: IMAD R8, R6, -0xa0, RZ (the vendor's word behind CS2R.32) against the same word 45 cycles later"),
    "IMAD.rel": ("rel", 6, "IMAD", "r1", "RELATIVE: IMAD R8, R6, 0x3, R5 against the same word 45 cycles later"),
    "IADD.64.rel": ("rel", 6, "IADD.64", "r1", "RELATIVE: IADD.64 R24, R6, 0x4 (both registers of the pair) against the same word 45 cycles later"),
    # version 25 - the register-register IADD.64 (the vendor's form), the second source of PRMT, the address pair of a global store
    "IADD.64rr.r1": ("data", 6, "IADD", "r1", "the LOW word of the FIRST operand pair of IADD.64 R24, R6, R4 (register-register; the low word of the sum reaches the checksum)"),
    "IADD.64rr.r1h": ("data", 7, "IADD", "r1h", "the HIGH word of the FIRST operand pair of IADD.64 R24, R6, R4 (the high word of the sum reaches the checksum; a pair producer sits on R6)"),
    "IADD.64rr.r2": ("data", 6, "IADD", "r2", "the LOW word of the SECOND operand pair of IADD.64 R24, R4, R6 (the low word of the sum reaches the checksum)"),
    "IADD.64rr.r2h": ("data", 7, "IADD", "r2h", "the HIGH word of the SECOND operand pair of IADD.64 R24, R4, R6 (the high word of the sum reaches the checksum; a pair producer sits on R6)"),
    "PRMT.r3": ("data", 6, "PRMT", "r3", "the SECOND source register of PRMT R8, R5, 0x7632, R (the upper two bytes of the result come from it)"),
    "STG.a0": ("gaddr", 6, "STG", "a0", "the LOW register of the 64-bit address pair of a global store (producer kind gaddr: the pair holds the address of the thread's word B until the address of word A lands)"),
}
RR_CONSUMERS = ("IADD.64rr.r1", "IADD.64rr.r1h", "IADD.64rr.r2", "IADD.64rr.r2h")      # version 25
RR_HIGH = ("IADD.64rr.r1h", "IADD.64rr.r2h")
FLOAT_CONSUMERS = ("FMUL.r2", "FADD.r1", "FFMA.r2")
FLOAT_PRODUCERS = ("FADD", "FMUL", "CS2R", "MOV.fin")
# version 22: consumers whose word names the tested register R6 exactly once - with "result": 1 it becomes R7, the
# second register of a pair producer
RESULT1_CONSUMERS = ("STS.data", "STG.data", "IADD3.r1", "IADD3.r2", "IMAD.r1", "IMAD.r3", "LOP3.r1", "MOV.r1", "SHF.r1", "SEL.r1", "PRMT.r1", "I2FP.r1",
                     "IMAD.SHL.r1", "FMUL.r2", "FADD.r1", "FFMA.r2", "IMAD.WIDE.r2", "IMAD.r2", "SHF.r3", "IADD.r1", "IADD.r2")
R6_TOKEN = r"(?<![A-Za-z0-9])R6(?![0-9])"


def raw_pair_ok(prod, cons):
    if cons in ("IADD.64.u2", "IADD.64.u2h") or prod in ("CS2UR", "CS2UR.32"):      # version 27, third build
        # the reader of a uniform PAIR takes the producer that writes both registers; the 64-bit producer does not stand in front of UIADD3.u1 (that consumer writes UR7 itself)
        return (prod == "CS2UR" and cons in ("IADD.64.u2", "IADD.64.u2h", "MOV.u1")) or (prod == "CS2UR.32" and cons in ("MOV.u1", "UIADD3.u1"))
    """version 22: a float consumer takes a producer whose result is a finite float or zero; MUFU.RCP a power of two"""
    if cons in FLOAT_CONSUMERS:
        return prod in FLOAT_PRODUCERS
    if cons == "MUFU.RCP.r1":
        return prod == "MOV.pow2"
    return True
WAR_STORES = {
    # name: (overwriters, table class, description)
    "STS.data": (["LOP3", "IADD3", "LDS", "LDG"], "STS", "the data register of a bare 32-bit shared store (IADD3: + a constant, so the NUMBER of late iterations per thread is read from the checksum)"),
    "STS128.data": (["LOP3", "LDS128", "LDSM"], "STS", "the data registers of a bare STS.128 (LOP3: the last one)"),
    "STG.data": (["LOP3", "IADD3", "LDG", "LDS"], "STG", "the data register of a bare global store (IADD3: as for STS.data)"),
    "STS.addr": (["IADD3", "LDS"], "STS", "the address register of a bare shared store (LDS: a shared LOAD brings the other address - the vendor's practice)"),
    "STG.addr": (["MOV"], "STG", "the address pair (low register) of a bare global store"),
    # version 25: the UNIFORM operand of a store - the uniform base register of a shared store, rewritten by UMOV behind it.
    # UMOV.front = the positive control (the rewrite IN FRONT of the store, the model ignoring it: expect 0 % good)
    "STS.ubase": (["UMOV", "UMOV.front"], "STS", "the UNIFORM base register of STS [UR6+0x24], R (a read barrier on the store in every variant; a late read of the base stores into another valid word of the CTA)"),
    # version 15 - not stores: a warp shuffle reads its source register of ANOTHER lane (`"read_barrier": "set"` puts the
    # vendor's read barrier on the shuffle in the bare variant too; nobody waits it before the reader)
    "SHFL.BFLY.src": (["LOP3", "IADD3", "IADD3.it"], "SHFL", "the source register of SHFL.BFLY PT, Rd, Rs, 0x1, 0x1f (every lane takes lane ^ 1's register)"),
    "SHFL.IDX.src": (["LOP3", "IADD3", "IADD3.it"], "SHFL", "the source register of SHFL.IDX PT, Rd, Rs, 0x1, 0x1f (every lane takes lane 1's register)"),
    # version 18 - WRITE AFTER WRITE, not stores either: the entry is the FIRST writer of a register (a scoreboarded producer
    # on write barrier 1), the "overwriter" is the SECOND writer d cycles behind it, which does not wait that barrier; the
    # reader waits it. A first write that lands after the second leaves the FIRST writer's value (mode `late`).
    # IADD3 writes (the first writer's value - the constant): the checksum counts the iterations in which the first write
    # came last; IADD3.it writes (that value - (iteration index + 1) x the constant): one such iteration is decoded to its
    # index + 1. A second writer LDS / LDG / SHFL is a scoreboarded producer itself (write barrier 2; the reader waits both).
    # ctl = the second writer WAITS barrier 1 (the vendor's practice: must be good); rb = no first writer at all.
    "LDS.dst": (["IADD3", "IADD3.it", "LDS", "LDG"], "LDS", "the destination of a shared load (it brings the value stored in front of it), written again behind it"),
    "LDG.dst": (["IADD3", "IADD3.it", "LDG", "LDS"], "LDG", "the destination of a global load (it brings the value stored in front of it), written again behind it"),
    "LDC.dst": (["IADD3", "IADD3.it"], "LDC", "the destination of LDC Rd, c[0x0][0x388] (the seed), written again behind it"),
    "S2R.dst": (["IADD3", "IADD3.it"], "S2R", "the destination of S2R Rd, SR_TID.X, written again behind it"),
    "SHFL.dst": (["IADD3", "LDS"], "SHFL", "the destination of SHFL.BFLY PT, Rd, Rs, 0x1, 0x1f, written again behind it"),
    "LDS128.dst": (["SHFL"], "LDS", "the first destination register of LDS.128, written again by a warp shuffle (the one unwaited pair of this kind in vendor text)"),
}
SHFL_STORES = ("SHFL.BFLY.src", "SHFL.IDX.src")
WAW_STORES = ("LDS.dst", "LDG.dst", "LDC.dst", "S2R.dst", "SHFL.dst", "LDS128.dst")
NEG_CONST = (-0x9e3779b1) & 0xFFFFFFFF      # 2^32 - LATE_CONST


def shfl_of(req):
    """the warp shuffle in a request's body: None | "bfly" | "idx" (its model needs the lanes the shuffle reads, too)"""
    if req.get("kind") == "war":
        if req.get("store") == "SHFL.IDX.src":
            return "idx"
        if req.get("store") in ("SHFL.BFLY.src", "SHFL.dst", "LDS128.dst"):
            return "bfly"
    if req.get("kind") == "ord" and req.get("older") == "SHFL":
        return "bfly"
    if req.get("kind") == "gw" and req.get("producer") == "SHFL":      # version 26, second build
        return "bfly"
    if req.get("kind") == "ord" and req.get("forms") and any(t.strip() == "h" for t in str(req["forms"]).split(",")):
        return "bfly"      # version 23: a SHFL.BFLY among the producers of a set
    return None
LATE_CONST = 0x9e3779b1      # odd: (checksum - good) / LATE_CONST = the number of iterations in which the store took the rewritten data
FRONT_RE = re.compile(r"(sts128|sts|stg)x(\d+)@(\d+)")


def front_ins(front, kind_has_b_target):
    """the memory traffic in front of the tested instruction: K stores of the constant quad, stall S each"""
    if front in ("none", "", None):
        return []
    m = FRONT_RE.fullmatch(front)
    if not m:
        raise SystemExit(f"unknown front {front!r}: none | sts128xK@S | stsxK@S | stgxK@S")
    form, k, s = m.group(1), int(m.group(2)), int(m.group(3))
    if not (1 <= s <= 15 and 1 <= k <= 64):
        raise SystemExit(f"front {front!r}: K 1..64, S 1..15")
    out = []
    for i in range(k):
        if form == "sts128":      # slots 0 / 1 of the thread: they hold this quad already
            out.append(Ins(f"STS.128 [R9{'+0x10' if i % 2 else ''}], R20 ;", ("nop",), ctl=C(s)))
        elif form == "sts":
            off = 16 * (i % 2)
            out.append(Ins(f"STS [R9{('+0x%x' % off) if off else ''}], R20 ;", ("nop",), ctl=C(s)))
        else:                      # the thread's word B of the output buffer: it holds R20 already
            if kind_has_b_target:
                raise SystemExit("front stg...: not with STG.addr (word B is the target of a misdirected store there)")
            out.append(Ins("STG.E desc[UR4][R18.64], R20 ;", ("nop",), ctl=C(s)))
    return out


def front_id(front):
    return "f0" if front in ("none", "", None) else front.replace("@", "s")


def split_distance(d, via="stall"):
    """-> (stall of the tested instruction, fillers)"""
    if via == "fill":
        return 1, [FILL1() for _ in range(d - 1)]
    npad = (d - 1) // 15
    return d - 15 * npad, [PAD() for _ in range(npad)]


# ------------------------------------------------------------------------------------------------ version 24
# Kind `raw` with a TENSOR consumer, and RELATIVE consumers.
#   tdata  one register of an operand of a tensor word (QMMA.SF / HMMA with uniform fragments, the model of body_mma):
#          of the A quad (r1 / r1h), of the B pair (r2 / r2h) or of the accumulator quad (r3 / r3h). The register is
#          dirtied 30 cycles in front of the producer. Absolute oracle (operation `tmma`).
#   trel   the uniform operand of the QMMA (u6): the result X at the swept distance against the same word's result Y
#          45 cycles later on a second accumulator - the host need not know what the selector does.
#   rel    a register consumer of a producer whose content the host does not know (a special register): X against Y.
# "control": "stale" = the positive control of a request: the producer's word stands BEHIND the consumer and its
# checksum, the model still gives the consumer the new content - a control that works shows 0 % good.
T24_WHAT = ("tdata", "trel", "rel")
T24_PRODUCERS = {"acc": ("CS2R", "MOV", "FMUL"), "a": ("MOV",), "b": ("LOP3",), "u": ("UMOV",),
                 "rel": ("CS2R", "CS2R.32.CgaSize", "CS2R.GLOBALTIMERLO")}


def is_traw(req):
    """a raw request whose consumer is a tensor word (it takes the prologue of kind mma: no global addresses in R16..R19)"""
    return req.get("kind") == "raw" and RAW_CONSUMERS.get(req.get("consumer"), ("",))[0] in ("tdata", "trel")


def t24_kind(cons):
    what, _rd, _cls, role, _txt = RAW_CONSUMERS[cons]
    return "rel" if what == "rel" else "u" if what == "trel" else {"r3": "acc", "r3h": "acc", "r1": "a", "r1h": "a", "r2": "b", "r2h": "b"}[role]


def t24_reg(req):
    """the index of the tested register inside its operand (0 = the operand's own register)"""
    role = RAW_CONSUMERS[req["consumer"]][3]
    return 0 if role in ("r3", "r1", "r2", "u6") else 1 if role == "r2h" else int(req.get("reg", 1))


def body_rel24(req, d, front):
    """a register consumer X at the swept distance against the SAME word Y 45 cycles later (the content the producer
    brings is not known to the host): checksum += (X ^ Y) + the iteration's input"""
    prod, cons = req["producer"], req["consumer"]
    control = req.get("control") == "stale"
    s, fill = split_distance(d)
    r = "R7" if req.get("result") == 1 else "R6"
    # the pair holds the iteration's inputs until the producer lands
    b = [Ins("MOV R6, R4 ;", ("mov", "R6", "R4")), Ins("MOV R7, R5 ;", ("mov", "R7", "R5")), PAD(), PAD()]
    b += front_ins(front, False)
    # (the model's stand-in for a content the host does not know: any value - X and Y take the same one)
    ptext, psem, dst = {"CS2R": ("CS2R R6, SRZ ;", ("zero2", "R6"), ["R6", "R7"]),
                        "CS2R.32.CgaSize": ("CS2R.32 R6, SR_CgaSize ;", ("mov", "R6", 0x00c0ffee), ["R6"]),
                        "CS2R.GLOBALTIMERLO": ("CS2R R6, SR_GLOBALTIMERLO ;", ("zero2", "R6"), ["R6", "R7"])}[prod]
    b.append(Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;" if control else ptext, psem, ctl=C(s, y=req.get("yield") == "set"), tag="P", dst=dst))
    b += fill
    if cons == "IMADi.rel":
        x, y2 = (f"IMAD R8, {r}, -0xa0, RZ ;", ("mad", "R8", r, -0xa0, "RZ")), (f"IMAD R12, {r}, -0xa0, RZ ;", ("mad", "R12", r, -0xa0, "RZ"))
    elif cons == "IMAD.rel":
        x, y2 = (f"IMAD R8, {r}, 0x3, R5 ;", ("mad", "R8", r, 3, "R5")), (f"IMAD R12, {r}, 0x3, R5 ;", ("mad", "R12", r, 3, "R5"))
    else:      # IADD.64.rel: the pair R7:R6
        x, y2 = ("IADD.64 R24, R6, 0x4 ;", ("add64i", "R24", "R6", 4)), ("IADD.64 R26, R6, 0x4 ;", ("add64i", "R26", "R6", 4))
    b.append(Ins(x[0], x[1], tag="C"))
    if control:      # the real producer: behind X, 60 cycles in front of Y
        b.append(Ins(ptext, ("nop",)))
    b += [PAD(), PAD(), PAD()]
    b.append(Ins(y2[0], y2[1]))
    if cons == "IADD.64.rel":
        b += [Ins("LOP3.LUT R8, R24, R26, RZ, 0x3c, !PT ;", ("xor", "R8", "R24", "R26")), Ins("LOP3.LUT R13, R25, R27, RZ, 0x3c, !PT ;", ("xor", "R13", "R25", "R27")),
              Ins("IMAD R13, R13, 0x3, R8 ;", ("mad", "R13", "R13", 3, "R8"))]
    else:
        b.append(Ins("LOP3.LUT R13, R8, R12, RZ, 0x3c, !PT ;", ("xor", "R13", "R8", "R12")))
    b += [Ins("IADD3 R10, PT, PT, R10, R13, RZ ;", ("add", "R10", "R10", "R13")), Ins("IADD3 R10, PT, PT, R10, R4, RZ ;", ("add", "R10", "R10", "R4"))]
    return b


def body_raw24(req, d, front):
    """ONE tensor word per iteration with uniform fragments (body_mma's model); a fixed-latency producer writes one
    register of one of its operands d issue cycles in front of it. The register is dirtied 30 cycles in front of the
    producer, so a tensor word that takes the previous content gives another, still exact, result."""
    prod, cons = req["producer"], req["consumer"]
    kind = t24_kind(cons)
    if kind == "rel":
        return body_rel24(req, d, front)
    control = req.get("control") == "stale"
    s, fill = split_distance(d)
    fn = req["form"]
    form, sp = MMA_FORMS[fn], MMA_SPEC[fn]
    t = t24_reg(req)
    ur = "UR6" if kind == "u" else "URZ"
    if fn.startswith("QMMA"):
        q = lambda rd: f"{form} {rd}, R16, R12, {rd}, R14, R14, {ur} ;"
    else:
        q = lambda rd: f"{form} {rd}, R16, R12, {rd} ;"
    # the iteration's fragments and accumulators - every one 30 cycles or more in front of the producer
    b = [Ins("LOP3.LUT R0, R11, 0x1, RZ, 0xc0, !PT ;", ("and", "R0", "R11", 1)),
         Ins(f"IMAD R6, R0, 0x{sp['da']:x}, RZ ;", ("mad", "R6", "R0", sp["da"], "RZ")),
         Ins(f"IADD3 R6, PT, PT, R6, 0x{sp['a0']:x}, RZ ;", ("add", "R6", "R6", sp["a0"]))]      # R6 = this iteration's A word (1.0 / 2.0 in every element)
    if kind == "a":
        # (third build) the A classes: the SAME code in every iteration (1.0 in every element), the tested register holds the 2.0 code until the
        # producer lands. The first two builds let the code alternate and dirtied with the other one: a register stale in EVERY iteration moved
        # the checksum by +d in even and -d in odd iterations and the linear checksum cancelled it (block 43: the three A controls 100 % good).
        b = [Ins(f"MOV R6, 0x{sp['a0']:x} ;", ("mov", "R6", sp["a0"])), Ins(f"MOV R7, 0x{sp['a0'] + sp['da']:x} ;", ("mov", "R7", sp["a0"] + sp["da"]))]
    for k in range(4):
        srcr = "R7" if (kind == "a" and k == t) else "R6"
        b.append(Ins(f"MOV R{16 + k}, {srcr} ;", ("mov", f"R{16 + k}", srcr)))
    b += [Ins("LOP3.LUT R28, R4, 0x3fffff, RZ, 0xc0, !PT ;", ("and", "R28", "R4", 0x3fffff)),
          Ins("LOP3.LUT R28, R28, 0x4b000000, RZ, 0xfc, !PT ;", ("or", "R28", "R28", 0x4b000000)),
          Ins("IADD3 R29, PT, PT, R28, 0x1, RZ ;", ("add", "R29", "R28", 1)), Ins("IADD3 R30, PT, PT, R28, 0x2, RZ ;", ("add", "R30", "R28", 2)),
          Ins("IADD3 R31, PT, PT, R28, 0x3, RZ ;", ("add", "R31", "R28", 3))]
    fk, fs = mma_front(front) if MMAFRONT_RE.fullmatch(str(front)) else (0, 0)
    if kind == "u":      # the second accumulator of the relative form: the same four values; the selector 0; a scale register whose bytes differ
        b += [Ins(f"MOV R{24 + k}, R{28 + k} ;", ("mov", f"R{24 + k}", f"R{28 + k}")) for k in range(4)]
        # (second build) the scale register: bytes 0x7f + m, 0x80 + m, 0x7e + m, 0x7d + m with m = lane & 3 - four different scales in
        # every lane and other ones from lane to lane; the model does not read it (X and Y take the same register)
        b += [Ins("UMOV UR6, 0x0 ;", ("mov", "UR6", 0)),
              Ins("LOP3.LUT R14, R1, 0x3, RZ, 0xc0, !PT ;", ("nop",)), Ins("IMAD R14, R14, 0x1010101, RZ ;", ("nop",)),
              Ins("IADD3 R14, PT, PT, R14, 0x7d7e807f, RZ ;", ("nop",))]
    elif fk:             # the accumulator of the tensor traffic in front (not part of the checksum)
        b += [Ins("LOP3.LUT R24, R5, 0x3fffff, RZ, 0xc0, !PT ;", ("and", "R24", "R5", 0x3fffff)),
              Ins("LOP3.LUT R24, R24, 0x4b000000, RZ, 0xfc, !PT ;", ("or", "R24", "R24", 0x4b000000)),
              Ins("IADD3 R25, PT, PT, R24, 0x1, RZ ;", ("add", "R25", "R24", 1)), Ins("IADD3 R26, PT, PT, R24, 0x2, RZ ;", ("add", "R26", "R24", 2)),
              Ins("IADD3 R27, PT, PT, R24, 0x3, RZ ;", ("add", "R27", "R24", 3))]
    tr = f"R{(28 if kind == 'acc' else 16 if kind == 'a' else 12) + t}"      # the tested register
    if kind == "acc" and prod == "CS2R":      # the pair's OTHER register holds zero before and after: only the tested one can be stale
        pb = 28 + (t & ~1)
        other = pb + 1 - (t & 1)
        b.append(Ins(f"MOV R{other}, RZ ;", ("mov", f"R{other}", 0)))
        ptext, psem = f"CS2R R{pb}, SRZ ;", ("zero2", f"R{pb}")
    elif kind == "acc":      # R7 = the new accumulator: another integer-valued float (+ 64)
        b.append(Ins(f"IADD3 R7, PT, PT, {tr}, 0x40, RZ ;", ("add", "R7", tr, 0x40)))
        if prod == "MOV":
            ptext, psem = f"MOV {tr}, R7 ;", ("mov", tr, "R7")
        else:                 # FMUL.FTZ by 1.0: exact
            b.append(Ins("MOV R0, 0x3f800000 ;", ("mov", "R0", 0x3f800000)))
            ptext, psem = f"FMUL.FTZ {tr}, R7, R0 ;", ("fmul", tr, "R7", "R0")
    elif kind == "a":
        ptext, psem = f"MOV {tr}, R6 ;", ("mov", tr, "R6")
    elif kind == "b":        # the vendor's mask form; the tested register holds the 2.0 code until it lands
        b += [Ins(f"MOV {tr}, 0x{sp['b2']:x} ;", ("mov", tr, sp["b2"])), Ins(f"MOV R0, 0x{sp['b1'] | 0x03030303:x} ;", ("mov", "R0", sp["b1"] | 0x03030303))]
        ptext, psem = f"LOP3.LUT {tr}, R0, 0x3c3c3c3c, RZ, 0xc0, !PT ;", ("and", tr, "R0", 0x3c3c3c3c)
    else:                    # u: the selector 0 -> 9
        tr = "UR6"
        ptext, psem = "UMOV UR6, 0x9 ;", ("mov", "UR6", 9)
    b += [PAD(), PAD()]
    if fk:
        b += [Ins(q("R24"), ("nop",), ctl=C(fs), tag="F") for _ in range(fk)]
    else:
        b += front_ins(front, False)
    y = req.get("yield") == "set"
    # (the control: the model's producer in its place under a filler's text, the real word behind the checksum)
    b.append(Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;" if control else ptext, psem, ctl=C(s, y=y), tag="P", dst=[tr]))
    b += fill
    acc4 = ["R28", "R29", "R30", "R31"]
    if kind == "u":
        b.append(Ins(q("R28"), ("qmma", "R28", "R16", "R12", None, fn), tag="C", dst=acc4))
        if control:      # the real producer: behind X, 60 cycles in front of Y
            b.append(Ins(ptext, ("nop",)))
        b += [PAD(), PAD(), PAD()]
        b.append(Ins(q("R24"), ("qmma", "R24", "R16", "R12", None, fn)))
        b += [PAD(), PAD(), PAD()]
        b += [Ins("LOP3.LUT R0, R28, R24, RZ, 0x3c, !PT ;", ("xor", "R0", "R28", "R24")), Ins("LOP3.LUT R7, R29, R25, RZ, 0x3c, !PT ;", ("xor", "R7", "R29", "R25")),
              Ins("IMAD R8, R7, 0x3, R0 ;", ("mad", "R8", "R7", 3, "R0")),
              Ins("LOP3.LUT R0, R30, R26, RZ, 0x3c, !PT ;", ("xor", "R0", "R30", "R26")), Ins("IMAD R8, R0, 0x5, R8 ;", ("mad", "R8", "R0", 5, "R8")),
              Ins("LOP3.LUT R7, R31, R27, RZ, 0x3c, !PT ;", ("xor", "R7", "R31", "R27")), Ins("IMAD R8, R7, 0x7, R8 ;", ("mad", "R8", "R7", 7, "R8")),
              Ins("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8")), Ins("IADD3 R10, PT, PT, R10, R4, RZ ;", ("add", "R10", "R10", "R4"))]
        return b
    b.append(Ins(q("R28"), ("tmma", "R28", "R16", "R12", fn), tag="C", dst=acc4))
    b += [PAD(), PAD(), PAD()]      # a reader of the tensor word's result is 45 cycles behind it
    for tx, sem in (("IMAD R8, R29, 0x3, R28 ;", ("mad", "R8", "R29", 3, "R28")), ("IMAD R8, R30, 0x5, R8 ;", ("mad", "R8", "R30", 5, "R8")),
                    ("IMAD R8, R31, 0x7, R8 ;", ("mad", "R8", "R31", 7, "R8")), ("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"))):
        b.append(Ins(tx, sem))
    if control:
        b.append(Ins(ptext, ("nop",)))
    return b


def norm24(r):
    cons, prod = r["consumer"], r.get("producer")
    kind = t24_kind(cons)
    if prod not in T24_PRODUCERS[kind]:
        raise SystemExit(f"{r['id']}: {cons} takes the producers {', '.join(T24_PRODUCERS[kind])} (version 24), not {prod!r}")
    if r.get("control") not in (None, "stale"):
        raise SystemExit(f"{r['id']}: control is \"stale\" (the positive control: the producer's word behind the consumer) or absent")
    if r.get("via") not in (None, "stall") or r.get("salt") is not None:
        raise SystemExit(f"{r['id']}: a version-24 consumer is swept via stall and has no salt field")
    r["via"] = "stall"
    role = RAW_CONSUMERS[cons][3]
    if kind != "rel":
        r["form"] = "HMMA.BF16" if cons.startswith("HMMA") else "QMMA.SF.E4M3.E2M1"
        if role in ("r3h", "r1h"):
            r.setdefault("reg", 1)
            if r["reg"] not in (1, 2, 3):
                raise SystemExit(f"{r['id']}: reg is 1, 2 or 3 (which upper register of the quad)")
        else:
            if r.get("reg") not in (None, t24_reg({"consumer": cons})):
                raise SystemExit(f"{r['id']}: {cons} names its register itself (no reg field)")
            r["reg"] = t24_reg({"consumer": cons})
        if kind == "acc" and prod == "CS2R":      # the pair sits on the even register: which of its two results feeds the tested register
            if r.get("result") not in (None, r["reg"] & 1):
                raise SystemExit(f"{r['id']}: with CS2R the result register follows from reg ({r['reg'] & 1})")
            r["result"] = r["reg"] & 1
        elif r.get("result") not in (None, 0):
            raise SystemExit(f"{r['id']}: result is for a CS2R producer")
    else:
        if r.get("result") not in (None, 0, 1) or (r.get("result") == 1 and (prod == "CS2R.32.CgaSize" or cons == "IADD.64.rel")) \
                or (cons == "IADD.64.rel" and prod == "CS2R.32.CgaSize"):
            raise SystemExit(f"{r['id']}: result 1 = the second register of a 64-bit CS2R behind IMADi.rel / IMAD.rel; IADD.64.rel takes the pair of a 64-bit CS2R")
    for f in r.get("front", ["none"]):
        if MMAFRONT_RE.fullmatch(str(f)):
            if kind in ("u", "rel"):
                raise SystemExit(f"{r['id']}: no tensor traffic in front of a relative request")
            mma_front(f)
        elif str(f).startswith("stg"):
            raise SystemExit(f"{r['id']}: front stg... is not for a version-24 consumer")
    r.setdefault("distances", "2,7" if r.get("control") else "1-8,11,26" if kind == "rel" else "1-15,18,22,26,29,45")
    if r.get("yield") and max(parse_distances(r["distances"])) > 11:
        raise SystemExit(f"{r['id']}: with the yield flag the swept stall is at most 11")


def text24(r):
    cons, prod, kind = r["consumer"], r["producer"], t24_kind(r["consumer"])
    body = body_raw24(dict(r, control=None), 3, "none")
    p = next(i.text for i in body if i.tag == "P").rstrip(" ;")
    c = next(i.text for i in body if i.tag == "C").rstrip(" ;")
    if kind == "rel":
        s = (f"{prod} -> {cons} [RELATIVE, version 24: `{p}` -> `{c}` at the swept distance against the same consumer word 45 cycles later; "
             "checksum += (X ^ Y) + the iteration's input" + ("; the consumer takes the producer's SECOND result register" if r.get("result") == 1 else "") + "]")
    elif kind == "u":
        s = (f"{prod} -> {cons} [RELATIVE, version 24: `{p}` -> the uniform operand of `{c}` (UR6 holds 0 until it lands; the scale register holds four different bytes, other ones from lane to lane) "
             "against the same word on a second accumulator 45 cycles later]")
    else:
        tr = next(i.dst[0] for i in body if i.tag == "P")
        s = (f"{prod} -> {cons} [TENSOR consumer, version 24: `{p}` -> register {tr} of `{c}`, uniform fragments; until the producer lands {tr} holds "
             + {"acc": "another integer-valued float", "a": "the other A code", "b": "the 2.0 code"}[kind]
             + (("; the pair's other register holds zero before and after; the consumer takes the producer's " + ("SECOND" if r.get("result") == 1 else "FIRST") + " result register")
                if prod == "CS2R" else "") + "]")
    if r.get("control") == "stale":
        s += " [POSITIVE CONTROL: the producer's word stands BEHIND the consumer and its checksum, the model gives the consumer the new content - expect 0 % good]"
    return s


def body_raw(req, d, front):
    prod, cons = req["producer"], req["consumer"]
    what, rd, _cls, _role, _txt = RAW_CONSUMERS[cons]
    if what in T24_WHAT:      # version 24
        return body_raw24(req, d, front)
    s, fill = split_distance(d, req.get("via", "stall"))
    control = req.get("control") == "stale"      # version 25: the positive control of an ordinary pair
    b = []
    if what == "addr":
        pre, ptext, psem, _ = addr_producer(prod)
    elif what == "udata":
        pre, ptext, psem, _ = uniform_producer(prod)
        if cons in ("IADD.64.u2", "IADD.64.u2h"):      # version 27, third build: the subtrahend pair = the iteration's inputs, set long before
            # (the LOW word of the subtrahend is the iteration's SECOND input: with the first one the low result -a and the salt +a would cancel)
            pre = pre + [Ins("MOV R26, R5 ;", ("mov", "R26", "R5")), Ins("MOV R27, R4 ;", ("mov", "R27", "R4"))]
    elif what == "gaddr":      # version 25
        pre, ptext, psem, _ = gaddr_producer(prod)
    else:
        if cons in RR_HIGH and prod in PAIR_PRODUCERS:      # version 25: a pair producer sits on the even register, its SECOND result is the tested high word
            rd = 6
        pre, ptext, psem, _ = data_producer(prod, rd)
    if cons in RR_CONSUMERS and prod not in PAIR_PRODUCERS:      # version 25: the other word of the operand pair R7:R6 is the iteration's own, set long before
        pre = pre + [Ins("MOV R6, R5 ;", ("mov", "R6", "R5")) if cons in RR_HIGH else Ins("MOV R7, R5 ;", ("mov", "R7", "R5"))]
    if cons == "STS128.d3":
        pre = pre + [Ins("MOV R24, R4 ;", ("mov", "R24", "R4")), Ins("MOV R25, R5 ;", ("mov", "R25", "R5")),
                     Ins("LOP3.LUT R26, R4, 0x33cc33cc, RZ, 0x3c, !PT ;", ("xor", "R26", "R4", 0x33cc33cc))]
    if cons == "STS128.d0":
        pre = pre + [Ins("MOV R25, R4 ;", ("mov", "R25", "R4")), Ins("MOV R26, R5 ;", ("mov", "R26", "R5")),
                     Ins("LOP3.LUT R27, R4, 0x33cc33cc, RZ, 0x3c, !PT ;", ("xor", "R27", "R4", 0x33cc33cc))]
    if cons == "SEL.r1" and prod != "SEL":
        pre = pre + [P2_LT()]
    if cons in ("IADD.64.r1h", "SHF.L.U64.HI.r1") and prod not in PAIR_PRODUCERS:
        raise SystemExit(f"{cons}: the producer must write a register pair ({', '.join(sorted(PAIR_PRODUCERS))})")
    if prod == "CS2R" and rd % 2:
        raise SystemExit("CS2R: the pair form is built on an even register only (not the last register of STS.128)")
    if cons.startswith("IMAD.WIDE.r3"):
        if prod in PAIR_PRODUCERS:
            raise SystemExit(f"{cons}: the producer writes ONE word of the addend pair (not {prod})")
        # the other word of the addend pair R7:R6 is the iteration's own, set long before
        pre = pre + [Ins("MOV R6, R5 ;", ("mov", "R6", "R5")) if cons == "IMAD.WIDE.r3h" else Ins("MOV R7, R5 ;", ("mov", "R7", "R5"))]
    if not raw_pair_ok(prod, cons):
        raise SystemExit(f"{cons}: the producer must bring a finite float ({', '.join(FLOAT_PRODUCERS)}; MUFU.RCP.r1: MOV.pow2), not {prod}")
    if cons in FLOAT_CONSUMERS:      # version 22: the other operand is a finite float set long before: R27, from the thread's constant R20
        pre = pre + fin(27, 20)      # (NOT from R4 / R5: with the pair's old content x in both places a stale FFMA gives 4x, +2^24 a time, 2^32 in 256 iterations)
        if cons == "FFMA.r2":        # R26 = 3.0: 3.0 * b + c needs one rounding only, which the host does exactly
            pre = pre + [Ins("MOV R26, 0x40400000 ;", ("mov", "R26", 0x40400000))]
        if prod == "CS2R":           # the pair holds FINITE floats until the CS2R lands (not the raw inputs)
            pre = pre + fin(6, 4) + fin(7, 5)
    b += pre
    b += front_ins(front, what == "gaddr")
    dst = (["UR6", "UR7"] if prod == "CS2UR" else ["UR6"]) if what == "udata" else ["R6", "R7"] if what == "gaddr" else [f"R{rd}", f"R{rd + 1}"] if prod in PAIR_PRODUCERS else [f"R{rd}"]
    # (version 25, the control: the model's producer in its place under a filler's text, the real word behind the consumer and its checksum)
    b.append(Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;" if control else ptext, psem, ctl=C(s, y=req.get("yield") == "set", wb="1" if req.get("pbar") and not control else "-"), tag="P", dst=dst))
    b += fill
    if cons == "STS.data":
        b += [Ins("STS [R9+0x20], R6 ;", ("sts", "R9", 0x20, "R6", 1), ctl=C(rb="2"), tag="C"),
              Ins("LDS R8, [R9+0x20] ;", ("lds", "R8", "R9", 0x20, 1), ctl=C(wb="1")), ADD10("12")]
    elif cons in ("STS128.d0", "STS128.d3"):
        b += [Ins("STS.128 [R9+0x20], R24 ;", ("sts", "R9", 0x20, "R24", 4), ctl=C(rb="2"), tag="C"),
              Ins("LDS.128 R28, [R9+0x20] ;", ("lds", "R28", "R9", 0x20, 4), ctl=C(wb="1"))] + fold4("12")
    elif cons == "STG.data":
        b += [Ins("STG.E desc[UR4][R16.64], R6 ;", ("stg", "R16", "R6"), ctl=C(rb="2"), tag="C"),
              Ins("LDG.E R8, desc[UR4][R16.64] ;", ("ldg", "R8", "R16"), ctl=C(wb="1")), ADD10("12")]
    elif cons == "STS.addr":
        b += [Ins("STS [R6], R4 ;", ("sts", "R6", 0, "R4", 1), ctl=C(rb="2"), tag="C"),
              Ins("LDS.128 R28, [R9+0x20] ;", ("lds", "R28", "R9", 0x20, 4), ctl=C(wb="1"))] + fold4("12")
    elif cons == "LDS.addr":
        b += [Ins("LDS R8, [R6] ;", ("lds", "R8", "R6", 0, 1), ctl=C(wb="1"), tag="C"), ADD10("1")]
    elif cons == "IADD3.r1":
        b += [Ins("IADD3 R8, PT, PT, R6, R5, RZ ;", ("add", "R8", "R6", "R5"), tag="C"), ADD10()]
    elif cons == "IADD3.r2":
        b += [Ins("IADD3 R8, PT, PT, R5, R6, RZ ;", ("add", "R8", "R5", "R6"), tag="C"), ADD10()]
    elif cons == "IMAD.r1":
        b += [Ins("IMAD R8, R6, 0x3, R5 ;", ("mad", "R8", "R6", 3, "R5"), tag="C"), ADD10()]
    elif cons == "IMAD.r3":
        b += [Ins("IMAD R8, R5, 0x3, R6 ;", ("mad", "R8", "R5", 3, "R6"), tag="C"), ADD10()]
    elif cons == "LOP3.r1":
        b += [Ins("LOP3.LUT R8, R6, 0x33cc33cc, RZ, 0x3c, !PT ;", ("xor", "R8", "R6", 0x33cc33cc), tag="C"), ADD10()]
    elif cons == "MOV.r1":
        b += [Ins("MOV R8, R6 ;", ("mov", "R8", "R6"), tag="C"), ADD10()]
    elif cons == "SHF.r1":
        b += [Ins("SHF.L.U32 R8, R6, 0x2, RZ ;", ("shl", "R8", "R6", 2), tag="C"), ADD10()]
    elif cons == "SEL.r1":
        b += [Ins("SEL R8, R6, RZ, P2 ;", ("sel", "R8", "R6", "RZ", "P2"), tag="C"), ADD10()]
    elif cons == "PRMT.r1":
        b += [Ins("PRMT R8, R6, 0x7632, R5 ;", ("prmt", "R8", "R6", 0x7632, "R5"), tag="C"), ADD10()]
    elif cons == "I2FP.r1":
        b += [Ins("I2FP.F32.S32 R8, R6 ;", ("i2f", "R8", "R6"), tag="C"), ADD10()]
    elif cons == "IMAD.SHL.r1":
        b += [Ins("IMAD.SHL.U32 R8, R6, 0x10, RZ ;", ("mad", "R8", "R6", 0x10, "RZ"), tag="C"), ADD10()]
    elif cons in ("IADD.64.r1", "IADD.64.r1h"):      # R25:R24 = R7:R6 + 4; the low word (r1) or the high word (r1h) reaches the checksum
        # (a 64-bit pair sits on an EVEN register: `IADD.64 R13, ...` is "Misaligned Register", Xid 13, at the first launch)
        b += [Ins("IADD.64 R24, R6, 0x4 ;", ("add64i", "R24", "R6", 4), tag="C"),
              Ins("MOV R8, R24 ;" if cons == "IADD.64.r1" else "MOV R8, R25 ;", ("mov", "R8", "R24" if cons == "IADD.64.r1" else "R25")), ADD10()]
    elif cons in ("IMAD.WIDE.r3", "IMAD.WIDE.r3h"):      # R25:R24 = R4 * R5 + R7:R6; the low (r3) or the high (r3h) word reaches the checksum
        b += [Ins("IMAD.WIDE.U32 R24, R4, R5, R6 ;", ("madw", "R24", "R4", "R5", "R6"), tag="C"),
              Ins("MOV R8, R24 ;" if cons == "IMAD.WIDE.r3" else "MOV R8, R25 ;", ("mov", "R8", "R24" if cons == "IMAD.WIDE.r3" else "R25")), ADD10()]
    elif cons == "SHF.L.U64.HI.r1":      # R8 = the high word of (R7:R6) << 3
        b += [Ins("SHF.L.U64.HI R8, R6, 0x3, R7 ;", ("shl64hi", "R8", "R6", 3, "R7"), tag="C"), ADD10()]
    elif cons == "UIADD3.u1":
        b += [Ins("UIADD3 UR7, UPT, UPT, UR6, 0x630, URZ ;", ("add", "UR7", "UR6", 0x630), tag="C"),
              Ins("MOV R8, UR7 ;", ("mov", "R8", "UR7")), ADD10()]
    elif cons == "MOV.u1":
        b += [Ins("MOV R8, UR6 ;", ("mov", "R8", "UR6"), ctl=C(wait="1" if req.get("pbar") else ""), tag="C"), ADD10()]
    elif cons in ("IADD.64.u2", "IADD.64.u2h"):      # version 27, third build: R25:R24 = UR7:UR6 - R27:R26, the kernel's reader of its clock
        b += [Ins("IADD.64 R24, -R26, UR6 ;", ("sub64u", "R24", "UR6", "UR7", "R26"), ctl=C(wait="1" if req.get("pbar") else ""), tag="C"),
              Ins("MOV R8, R24 ;" if cons == "IADD.64.u2" else "MOV R8, R25 ;", ("mov", "R8", "R24" if cons == "IADD.64.u2" else "R25")), ADD10()]
    elif cons == "LEA.r1":
        b += [Ins("LEA R8, R6, R6, 0x2 ;", ("mad", "R8", "R6", 5, "RZ"), tag="C"), ADD10()]
    elif cons == "LEA.r2":      # (version 25, fifth build) R8 = (R5 << 2) + R6: the tested register is the unshifted operand
        b += [Ins("LEA R8, R5, R6, 0x2 ;", ("mad", "R8", "R5", 4, "R6"), tag="C"), ADD10()]
    elif cons == "FMUL.r2":
        b += [Ins("FMUL.FTZ R8, R27, R6 ;", ("fmul", "R8", "R27", "R6"), tag="C"), ADD10()]
    elif cons == "FADD.r1":
        b += [Ins("FADD.FTZ R8, R6, R27 ;", ("fadd", "R8", "R6", "R27"), tag="C"), ADD10()]
    elif cons == "FFMA.r2":      # R8 = 3.0 * R6 + R27 with one rounding
        b += [Ins("FFMA.FTZ R8, R26, R6, R27 ;", ("ffma", "R8", "R26", "R6", "R27"), tag="C"), ADD10()]
    elif cons == "MUFU.RCP.r1":      # MUFU is a scoreboarded producer (the table's variable_latency): its result on write barrier 1, the checksum word waits it
        b += [Ins("MUFU.RCP R8, R6 ;", ("rcp2", "R8", "R6"), ctl=C(wb="1"), tag="C"), ADD10("1")]
    elif cons == "IMAD.WIDE.r2":      # R25:R24 = R5 * R6; both words reach the checksum
        b += [Ins("IMAD.WIDE.U32 R24, R5, R6, RZ ;", ("mulw", "R24", "R5", "R6"), tag="C"),
              Ins("IADD3 R8, PT, PT, R24, R25, RZ ;", ("add", "R8", "R24", "R25")), ADD10()]
    elif cons == "IMAD.r2":
        b += [Ins("IMAD R8, R5, R6, RZ ;", ("mad", "R8", "R5", "R6", "RZ"), tag="C"), ADD10()]
    elif cons == "SHF.r3":
        b += [Ins("SHF.R.U32.HI R8, RZ, 0x3, R6 ;", ("shr", "R8", "R6", 3), tag="C"), ADD10()]
    elif cons == "IADD.r1":
        b += [Ins("IADD R8, R6, R5 ;", ("add", "R8", "R6", "R5"), tag="C"), ADD10()]
    elif cons == "IADD.r2":
        b += [Ins("IADD R8, R5, R6 ;", ("add", "R8", "R5", "R6"), tag="C"), ADD10()]
    elif cons in ("IADD.64rr.r1", "IADD.64rr.r1h"):      # version 25: R25:R24 = R7:R6 + R5:R4 (the vendor's register-register form)
        b += [Ins("IADD.64 R24, R6, R4 ;", ("add64", "R24", "R6", "R4"), tag="C"),
              Ins("MOV R8, R24 ;" if cons == "IADD.64rr.r1" else "MOV R8, R25 ;", ("mov", "R8", "R24" if cons == "IADD.64rr.r1" else "R25")), ADD10()]
    elif cons in ("IADD.64rr.r2", "IADD.64rr.r2h"):      # version 25: R25:R24 = R5:R4 + R7:R6
        b += [Ins("IADD.64 R24, R4, R6 ;", ("add64", "R24", "R4", "R6"), tag="C"),
              Ins("MOV R8, R24 ;" if cons == "IADD.64rr.r2" else "MOV R8, R25 ;", ("mov", "R8", "R24" if cons == "IADD.64rr.r2" else "R25")), ADD10()]
    elif cons == "PRMT.r3":      # version 25: bytes 2, 3 of R5 and bytes 2, 3 of R6
        b += [Ins("PRMT R8, R5, 0x7632, R6 ;", ("prmt", "R8", "R5", 0x7632, "R6"), tag="C"), ADD10()]
    elif cons == "STG.a0":      # version 25: the store goes to word A (the new address) or to word B (a stale low register); both words are read back
        b += [Ins("STG.E desc[UR4][R6.64], R4 ;", ("stg", "R6", "R4"), ctl=C(rb="2"), tag="C"),
              Ins("LDG.E R8, desc[UR4][R16.64] ;", ("ldg", "R8", "R16"), ctl=C(wb="1")),
              Ins("LDG.E R13, desc[UR4][R18.64] ;", ("ldg", "R13", "R18"), ctl=C(wb="3")),
              Ins("IMAD R8, R13, 0x3, R8 ;", ("mad", "R8", "R13", 3, "R8"), ctl=C(wait="123")), ADD10()]
    else:
        raise SystemExit(f"unknown raw consumer {cons!r} (probe.py list)")
    if req.get("salt") == "set":      # version 22: the iteration's input goes into the checksum too (behind the consumer: no distance moves) -
        # a producer of zeros (CS2R) must not leave the checksum 0, which is what a kernel that never ran leaves in the zeroed buffer
        b.append(Ins("IADD3 R10, PT, PT, R10, R4, RZ ;", ("add", "R10", "R10", "R4")))
    if req.get("result") == 1:      # version 22: the consumer takes the pair producer's SECOND register (R7, not R6)
        c = [i for i in b if i.tag == "C"]
        if prod not in PAIR_PRODUCERS or cons not in RESULT1_CONSUMERS or len(c) != 1 or len(re.findall(R6_TOKEN, c[0].text)) != 1 \
                or [x for x in c[0].sem if isinstance(x, str)].count("R6") != 1:
            raise SystemExit(f"{prod} -> {cons}: \"result\": 1 needs a pair producer and a consumer whose word names R6 once")
        c[0].text = re.sub(R6_TOKEN, "R7", c[0].text)
        c[0].sem = tuple("R7" if (isinstance(x, str) and x == "R6") else x for x in c[0].sem)
    if control:      # version 25: the real producer - behind the consumer and its checksum; the model has applied it in its place
        b.append(Ins(ptext, ("nop",)))
    return b


ORD_PAIRS = [("LDS", "LDS"), ("LDS", "LDSM"), ("LDS", "LDG"), ("LDS128", "LDS"), ("LDG", "LDS"), ("LDG", "LDG"), ("LDS", "LDS128"),
             ("LDS", "LDS64"), ("LDS64", "LDS64"), ("LDS64", "LDS"), ("LDSU16", "LDS"), ("LDSU16", "LDS128"),
             # version 18: a YOUNGER producer of another class (with "older_barrier": "same": two producers of different
             # classes on ONE write barrier - does the barrier count them?); older LDC = the constant-bank load of the seed,
             # older SHFL = SHFL.BFLY; younger S2R R8, SR_TID.X / S2UR UR6, SR_CTAID.X / LDC.64 R30, c[0x0][0x380]
             ("LDS", "S2R"), ("LDC", "S2UR"), ("SHFL", "LDC64"), ("LDG", "S2R"), ("LDG", "S2UR"), ("LDG", "LDC64")]


def far_layout(threads):
    """the second region of a CTA's shared memory, behind the threads' 64-byte slots: word k of a thread = FARBASE +
    k * STRIDE + tid * 4, STRIDE >= 1 KB and >= one word per thread. -> (farbase, stride)"""
    stride = max(0x400, (threads * 4 + 0xFF) & ~0xFF)
    return threads * 64, stride


def smem_of(req, occ):
    """the shared memory the kernels of a request declare on a grid"""
    ctas, threads = GEOM[occ]
    smem = SMEM_OF.get(occ, SMEM)
    if req.get("kind") == "ord" and req.get("far") == "off" and threads * 64 + 0x240 > smem:
        raise SystemExit(f"{req['id']}: far = \"off\" does not fit the grid {occ} (the last thread's younger load would leave the {smem} B it declares)")
    if req.get("kind") == "ord" and req.get("nload") and req.get("place") == "far":
        fb, st = far_layout(threads)
        need = fb + int(req["nload"]) * st
        if need > smem:
            if occ in SMEM_OF:
                raise SystemExit(f"{req['id']}: {need} B of shared memory do not fit the grid {occ} ({smem} B per CTA)")
            smem = (need + 0xFFF) & ~0xFFF
    if smem > SMEM_PER_CTA_MAX:
        raise SystemExit(f"{req['id']}: {smem} B of shared memory per CTA (the card allows {SMEM_PER_CTA_MAX})")
    return smem


# version 21 - N loads of MIXED forms. letter: (mnemonic, registers, bytes of the thread's line it takes)
ORDN_FORM = {"s": ("LDS", 1, 4), "u": ("LDS.U16", 1, 4), "d": ("LDS.64", 2, 8), "q": ("LDS.128", 4, 16)}
ORDN_DEST = [24, 25, 26, 27, 28, 29, 30, 31, 16, 17, 18, 19, 14, 7]      # destination registers in this order (temporaries: R6 R8 R12 R13)
# version 23 - SETS of producers on ONE write barrier (the shapes of the served attention kernel): letter: (mnemonic,
# registers). A request with one of these letters is a SET request: its kernels declare R0-R79 (.regcount 88).
SET_FORM = {"G": ("LDG.E", 1), "Q": ("LDG.E.128", 4), "B": ("LDG.E.U8", 1), "c": ("LDC", 1), "C": ("LDC.64", 2),
            "m": ("MUFU.EX2", 1), "h": ("SHFL.BFLY", 1),
            "M": ("LDSM.16.M88.4", 4),      # (second build) only as the set M,s,s: the reader is an HMMA of the LDSM's quad and the two LDS
            "S": ("LDS", 1),                # version 29: only in a scale set: an unguarded LDS into a block-scale register of two guarded QMMA.SF readers
            "D": ("LDS.64", 2)}             # version 29, second build: only in a scale set beside S: an unguarded LDS.64 whose pair is read by MOV words
SET_NAMES = {"s": "LDS", "u": "LDS.U16", "d": "LDS.64", "q": "LDS.128", "G": "LDG.E", "Q": "LDG.E.128", "B": "LDG.E.U8",
             "c": "LDC", "C": "LDC.64", "m": "MUFU.EX2", "h": "SHFL.BFLY",
             "M": "LDSM.16.M88.4 [the A fragment of the reader HMMA.16816.F32.BF16; the two LDS behind it are its B fragment]",
             "S": "LDS [into a block-scale register of the reader QMMA.SF words]",
             "D": "LDS.64 [its pair read by MOV words]"}
SET_REGS = 80            # R0-R79; .regcount SET_REGS + 8
SET_HSRC = 73            # the shuffle's source (written every iteration)
SET_MSRC, SET_MREF = 74, 75      # the MUFU's source and the reference of its result (prologue)
SET_ABASE = 76           # R76:R77 = the address of the first B word of the thread's warp (prologue; never rewritten)
SET_CBASE = 78           # (third build) cold: R78:R79 = the address of this iteration's lines; only R78 (the LOW word) is written in the loop
SET_COLD_OCC = ("w1", "w2", "w4", "w8", "w9", "w12", "w16", "c2w9s")      # >= 256 blocks of 4 096 B in the buffer, a tail of >= 2 048 B behind the threads' words
SET_REL = [24, 25, 26, 27, 28, 29, 30, 31]      # temporaries of the relative readers
SET_OCC = ("w1", "w2", "w4", "w8", "w9", "w12", "w16", "g8", "c2w9s")      # threads per SM x 88 registers <= 65 536, the label true


def is_set(req):
    """version 23: a request of kind ord whose `forms` name a producer that is not a shared load of the thread's line"""
    return bool(req.get("kind") == "ord" and req.get("forms")
                and any(t.strip()[-1:] in SET_FORM for t in str(req["forms"]).split(",")))


def set_nreg(let):
    return SET_FORM[let][1] if let in SET_FORM else ORDN_FORM[let][1]


def set_plan(req):
    """the producers of a SET request, oldest first: [(guard, letter, first destination register, aux)]; aux = the byte
    offset in the thread's line (s u d q), the quad of the warp's B words (Q: 0..7), the byte of the warp's 128 B bytes
    (B), else None. Destinations R32 .. R72: the quads first, then the pairs, then the singles, each in the order of the
    producers."""
    toks = []
    for t in [x.strip() for x in str(req["forms"]).split(",")]:
        g = t[:1] if (t[:1] in ("g", "k") and len(t) > 1) else ""      # version 28: k = under the SECOND predicate (@P2)
        let = t[len(g):]
        if let not in SET_FORM and let not in ORDN_FORM:
            raise SystemExit(f"{req.get('id')}: forms token {t!r}: s | u | d | q | G | Q | B | c | C | m | h with an optional prefix g on a load")
        if g == "k" and not req.get("pguard"):
            raise SystemExit(f"{req.get('id')}: forms token {t!r}: the prefix k (under the second predicate, @P2) needs the field pguard (version 28)")
        if g and let in ("c", "C", "m", "h", "M"):
            raise SystemExit(f"{req.get('id')}: forms token {t!r}: the guard is for a load (s u d q G Q B)")
        toks.append((g, let))
    if any(let == "M" for _g, let in toks) and toks != [("", "M"), ("", "s"), ("", "s")]:
        raise SystemExit(f"{req.get('id')}: LDSM stands only in the tensor set M,s,s (LDSM + LDS + LDS, the reader an HMMA)")
    sd_ = [let for _g, let in toks if let in ("S", "D")]      # version 29 (second build: D)
    if sd_ and (len(sd_) != len(toks) or any(g for g, _l in toks) or not (2 <= len(toks) <= 7) or not (1 <= sd_.count("S") <= 4) or sd_.count("D") > 3):
        raise SystemExit(f"{req.get('id')}: the letters S (an LDS into a block-scale register of the QMMA.SF readers) and D (an LDS.64 read by MOV words) stand only in a scale set: 2 .. 7 loads of S and D alone, 1 .. 4 S, at most 3 D, no guard")
    regof, reg = {}, 32
    for width in (4, 2, 1):
        for k, (_g, let) in enumerate(toks):
            if set_nreg(let) == width:
                regof[k] = reg
                reg += width
    if reg > SET_HSRC:
        raise SystemExit(f"{req.get('id')}: the destinations of the set do not fit R32..R{SET_HSRC - 1}")
    plan, off, nq, nb = [], 0, 0, 0
    for k, (g, let) in enumerate(toks):
        aux = None
        if let in ORDN_FORM:
            nbytes = ORDN_FORM[let][2]
            off = (off + nbytes - 1) // nbytes * nbytes
            if off + nbytes > 64:
                raise SystemExit(f"{req.get('id')}: the shared loads do not fit the thread's 64 bytes")
            aux, off = off, off + nbytes
        elif let == "Q":
            aux, nq = nq % 8, nq + 1
        elif let == "B":
            aux, nb = (17 * nb + 5) % 128, nb + 1
        plan.append((g, let, regof[k], aux))
    return plan


# version 28 - a SET under TWO predicates (the shared write barrier of an attention kernel: `@P0 LDG.E.128` + `@P0
# LDG.E.U8` + `@P1 LDG.E` on one barrier; the tool's P1 is the loop's, the second predicate here is P2). "pguard" = two
# letters, the first for P0 (the producers with prefix g), the second for P2 (prefix k): t = true, f = false, l = a bit of
# the lane (P0: bit 0, P2: bit 1 - true where the bit is 0: all four combinations inside every warp), c = a bit of
# (iteration counter x 0x9e3779b1) (P0: bit 31 for the first pair, the next lower bit for every further pair; P2: bit 20).
# The predicate is (source >= 0): `ISETP.GE.AND Pn, PT, Rsrc, RZ, PT`, the kernel's own word for P0, written at the top of
# every iteration, 60 / 45 cycles in front of the first producer; P0 is written again 13 cycles (the table's default for a
# predicate -> a guard) in front of every further `gQ` - the kernel writes P0 between its pairs.
SET_PG = ("t", "f", "l", "c")
SET_PSRC = ("R7", "R14")      # the sources of P0 / P2: free registers of a set kernel


def set_psrc(letter, which):
    reg = SET_PSRC[which]
    if letter == "t":
        return [Ins(f"MOV {reg}, RZ ;", ("mov", reg, 0))]
    if letter == "f":
        return [Ins(f"MOV {reg}, 0x80000000 ;", ("mov", reg, 0x80000000))]
    if letter == "l":
        return [Ins(f"SHF.L.U32 {reg}, R0, 0x{31 - which:x}, RZ ;", ("shl", reg, "R0", 31 - which))]
    out = [Ins(f"IMAD {reg}, R11, 0x9e3779b1, RZ ;", ("mad", reg, "R11", 0x9e3779b1, "RZ"))]
    if which:
        out.append(Ins(f"SHF.L.U32 {reg}, {reg}, 0xb, RZ ;", ("shl", reg, reg, 11)))
    return out


def set_pshift(stall):
    """the next bit of the counter's hash into the sign of P0's source (tag PS)"""
    return Ins(f"SHF.L.U32 {SET_PSRC[0]}, {SET_PSRC[0]}, 0x1, RZ ;", ("shl", SET_PSRC[0], SET_PSRC[0], 1), ctl=C(stall), tag="PS")


def set_pguard_top(pg, shift_first=False):
    """(second build) shift_first: the bit of the first further pair is shifted in right behind the top's two ISETP - 45 cycles and more in front of the ISETP that reads it"""
    return (set_psrc(pg[0], 0) + set_psrc(pg[1], 1)
            + [Ins(f"ISETP.GE.AND P0, PT, {SET_PSRC[0]}, RZ, PT ;", ("sge0", "P0", SET_PSRC[0])),
               Ins(f"ISETP.GE.AND P2, PT, {SET_PSRC[1]}, RZ, PT ;", ("sge0", "P2", SET_PSRC[1]))]
            + ([set_pshift(15)] if shift_first else []) + [PAD(), PAD()])


def set_pguard_again(pg, more=False, pshift=None):
    """P0 written again in front of a further pair, 13 cycles in front of the pair's first load and right behind the last load in
    front of it. Letter c (second build): the ISETP reads the source as the shift behind the PREVIOUS ISETP left it (13 cycles or
    more before); when a further pair follows (`more`) the next shift stands right behind this ISETP. `pshift` 1 = the FIRST
    build's text: the shift at stall 1 directly in front of the ISETP that reads it - NOT RIGHT BY CONSTRUCTION."""
    isetp = lambda st: Ins(f"ISETP.GE.AND P0, PT, {SET_PSRC[0]}, RZ, PT ;", ("sge0", "P0", SET_PSRC[0]), ctl=C(st))
    if pg[0] != "c":
        return [isetp(13)]
    if pshift == 1:
        return [set_pshift(1), isetp(13)]
    return [isetp(1), set_pshift(12)] if more else [isetp(13)]


def set_rdist(req, y, ys):
    """version 28 -> (the youngest producer's stall, the stalls of the fillers behind it): together the reader's distance behind
    the last arming ("rdist"; absent: younger_stall and no filler). With the yield flag a stall is at most 11."""
    rd = req.get("rdist")
    if rd is None:
        return ys, []
    smax = 11 if y else 15
    if rd <= smax:
        return rd, []
    k, rest = divmod(rd - smax, 15)
    fill = [15] * k + ([rest] if rest else [])
    assert smax + sum(fill) == rd and all(1 <= s <= 15 for s in fill)
    return smax, fill


def set_exec(req, gids):
    """version 28: numpy bool per thread - does at least one producer of the set execute in at least one iteration"""
    import numpy as np
    gids = np.asarray(gids)
    lane = gids % 1024
    pg = req["pguard"]

    def ex(letter, bit):
        if letter in ("t", "c"):
            return np.ones(len(gids), bool)
        if letter == "f":
            return np.zeros(len(gids), bool)
        return ((lane >> bit) & 1) == 0

    out = np.zeros(len(gids), bool)
    for g, _let, _r, _a in set_plan(req):
        out |= ex(pg[0], 0) if g == "g" else ex(pg[1], 1) if g == "k" else np.ones(len(gids), bool)
    return out


def set_pg_text(r):
    w = {"t": "true in every lane and iteration", "f": "FALSE in every lane and iteration (its loads never execute)",
         "l": "a bit of the lane (true where the bit is 0)", "c": "a bit of (iteration counter x 0x9e3779b1) (true where the bit is 0)"}
    pg = r["pguard"]
    return (f" [version 28 - TWO PREDICATES on one write barrier: P0 = {w[pg[0]]}"
            + (" - bit 0" if pg[0] == "l" else " - bit 31 for the first pair, the next lower bit for every further pair" if pg[0] == "c" else "")
            + f"; P2 = {w[pg[1]]}" + (" - bit 1" if pg[1] == "l" else " - bit 20" if pg[1] == "c" else "")
            + "; both are written at the top of every iteration by ISETP.GE.AND, P0 again 13 cycles in front of every further `@P0 LDG.E.128`"
            + f"; the first reader word stands {r['rdist'] if r.get('rdist') else r.get('younger_stall', 2)} cycles behind the last arming"
            + ("; POSITIVE CONTROL (wait end): the same text with the reader's wait bit moved to the first word BEHIND the reader words - expect not good wherever a producer executes"
               if r.get("wait") == "end" else "; the first reader word carries the ONE wait")
            + ("; THE FIRST BUILD'S TEXT (pshift 1): the shift of P0's source stands ONE cycle in front of the ISETP that reads it - NOT RIGHT BY CONSTRUCTION; the hypothesis "
               "p0old = every such ISETP read the source's old content (the previous pair's bit)" if r.get("pshift") == 1
               else "; the next pair's bit is shifted into P0's source right behind the previous ISETP, 13 cycles or more in front of the ISETP that reads it, and that ISETP "
                    "stands right behind the pair's last load" if (pg[0] == "c" and sum(1 for t_ in str(r["forms"]).split(",") if t_.strip() == "gQ") > 1) else "") + "]")


def ordn_plan(req):
    """the loads of a mixed N-load request, oldest first: [(guard, letter, first destination register, byte offset)].
    `forms` = one token per load, comma-separated: s | u | d | q with an optional prefix g (under @P0: true) or f (under
    @P3: false - the load does not happen and its registers keep their markers)."""
    free = [r for r in ORDN_DEST if not (r == 7 and req.get("place") == "base2")]
    toks = []
    for t in [x.strip() for x in str(req["forms"]).split(",")]:
        g = t[:1] if t[:1] in ("g", "f") else ""
        if t[len(g):] not in ORDN_FORM:
            raise SystemExit(f"{req.get('id')}: forms token {t!r}: s | u | d | q with an optional prefix g | f")
        toks.append((g, t[len(g):]))
    used, regof = set(), {}
    for width in (4, 2, 1):      # the wide destinations first: they need aligned registers
        for k, (g, let) in enumerate(toks):
            nreg = ORDN_FORM[let][1]
            if nreg != width:
                continue
            reg = next((r for r in free if r % nreg == 0 and all((r + j) in free and (r + j) not in used for j in range(nreg))), None)
            if reg is None:
                raise SystemExit(f"{req.get('id')}: no destination register left for load {k + 1} ({g}{let}) (14 registers; 13 with place base2)")
            used.update(range(reg, reg + nreg))
            regof[k] = reg
    plan, off = [], 0
    for k, (g, let) in enumerate(toks):
        nbytes = ORDN_FORM[let][2]
        off = (off + nbytes - 1) // nbytes * nbytes      # an access is aligned to its size
        if off + nbytes > 64:
            raise SystemExit(f"{req.get('id')}: the loads do not fit the thread's 64 bytes")
        plan.append((g, let, regof[k], off))
        off += nbytes
    return plan


def ordn_no_gaddr(req):
    """a mixed N-load request whose loads write R16..R19: its prologue leaves the global addresses (and the store through them) out"""
    if is_set(req):      # version 23: the destinations of a set are R32..
        return False
    return bool(req.get("kind") == "ord" and req.get("forms")
                and any(16 <= reg + k <= 19 for _g, let, reg, _o in ordn_plan(req) for k in range(ORDN_FORM[let][1])))


def body_ordn_mixed(req, d, front, variant):
    """N loads of mixed forms of one thread in flight, d issue cycles apart, ONE wait of the reader (`barrier` last | all |
    none, variant ctl as in body_ordn). Every destination register holds a marker that changes each iteration until its
    load lands; the reader takes every register - three a word into four temporaries, then two a word, one issue cycle
    apart, the first on the wait."""
    plan = ordn_plan(req)
    n, place, bar = len(plan), req["place"], req["barrier"]
    ys = int(req.get("younger_stall", 2))
    ctl = variant == "ctl"
    y = req.get("yield") == "set"
    regs = [reg + k for _g, let, reg, _o in plan for k in range(ORDN_FORM[let][1])]
    b = [Ins(f"MOV R{r}, R5 ;", ("mov", f"R{r}", "R5")) for r in regs]
    if place == "base2":
        b.append(Ins("MOV R7, R9 ;", ("mov", "R7", "R9")))
    b += front_ins(front, False)
    for k, (g, let, reg, off) in enumerate(plan):
        last = k == n - 1
        mn, nreg, _nb = ORDN_FORM[let]
        base = "R7" if (place == "base2" and k % 2) else "R9"
        text = f"{'@P0 ' if g == 'g' else '@P3 ' if g == 'f' else ''}{mn} R{reg}, [{base}{('+0x%x' % off) if off else ''}] ;"
        dst = [f"R{reg + j}" for j in range(nreg)]
        if g == "f":
            sem, dst = ("nop",), []
        elif let == "u":
            sem = ("ldsu16", f"R{reg}", "R9", off)
        else:
            sem = ("lds", f"R{reg}", "R9", off, nreg)
        if ctl:
            b.append(Ins(text, sem, ctl=C(1, wb="0", y=y), tag="P", dst=dst))
            b.append(Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(ys if last else d, wait="0")))
        else:
            wb = "1" if (bar != "none" and (last or bar == "all")) else "-"
            b.append(Ins(text, sem, ctl=C(ys if last else d, wb=wb, y=y), tag="P", dst=dst))
    cw = "0" if ctl else "" if bar == "none" else "1"
    tmp = ["R6", "R8", "R12", "R13"]
    words, i = [], 0
    for j in range(4):
        if i < len(regs):
            words.append((tmp[j], None, regs[i:i + 3]))
            i += 3
    j = 0
    while i < len(regs):
        words.append((tmp[j % 4], tmp[j % 4], regs[i:i + 2]))
        i += 2
        j += 1
    for k, (t, acc, grp) in enumerate(words):
        srcs = ([acc] if acc else []) + [f"R{r}" for r in grp]
        ct = C(1, wait=cw) if k == 0 else C(1)
        if len(srcs) == 3:
            b.append(Ins(f"IADD3 {t}, PT, PT, {srcs[0]}, {srcs[1]}, {srcs[2]} ;", ("add3", t, srcs[0], srcs[1], srcs[2]), ctl=ct, tag="C"))
        elif len(srcs) == 2:
            b.append(Ins(f"IADD3 {t}, PT, PT, {srcs[0]}, {srcs[1]}, RZ ;", ("add", t, srcs[0], srcs[1]), ctl=ct, tag="C"))
        else:
            b.append(Ins(f"MOV {t}, {srcs[0]} ;", ("mov", t, srcs[0]), ctl=ct, tag="C"))
    b.append(PAD())
    ut = [t for t in tmp if any(w[0] == t for w in words)]
    b.append(Ins("IMAD R6, R6, 0x3, RZ ;", ("mad", "R6", "R6", 3, "RZ")))
    for j, t in enumerate(ut[1:], 1):
        b.append(Ins(f"IMAD R6, {t}, 0x{2 * j + 3:x}, R6 ;", ("mad", "R6", t, 2 * j + 3, "R6")))
    b.append(Ins("IADD3 R10, PT, PT, R10, R6, RZ ;", ("add", "R10", "R10", "R6")))
    return b


def body_set_mma(req, d, front, variant):
    """version 23 - the tensor set of the served attention kernel (words [733] - [740] of v43c): LDSM.16.M88.4 + LDS + LDS
    on ONE write barrier, and ONE wait on the reader - an HMMA.16816.F32.BF16 whose A fragment is the LDSM's quad and
    whose B fragment is the two LDS registers. Slot 3 and slot 2 of every thread's line hold the code of 1.0 in every
    element (prologue), so both fragments are uniform whatever the matrix layout is; until its producer lands every
    destination holds the code of 2.0 - a stale fragment gives another, still exact, result. Accumulators as in kind mma
    (integer-valued floats: the result is an integer add on the bit pattern)."""
    (_g0, _l0, qa, _a0), (_g1, _l1, bl, _a1), (_g2, _l2, bu, _a2) = set_plan(req)
    assert qa % 4 == 0 and bl % 2 == 0 and bu == bl + 1
    bar = req["barrier"]
    ys = int(req.get("younger_stall", 2))
    ctl = variant == "ctl"
    y = req.get("yield") == "set"
    fn = "HMMA.BF16"
    sp = MMA_SPEC[fn]
    two = sp["a0"] + sp["da"]
    assert two == sp["b2"] and sp["a0"] == sp["b1"]
    b = [Ins("LOP3.LUT R28, R4, 0x3fffff, RZ, 0xc0, !PT ;", ("and", "R28", "R4", 0x3fffff)),
         Ins("LOP3.LUT R28, R28, 0x4b000000, RZ, 0xfc, !PT ;", ("or", "R28", "R28", 0x4b000000)),
         Ins("IADD3 R29, PT, PT, R28, 0x1, RZ ;", ("add", "R29", "R28", 1)), Ins("IADD3 R30, PT, PT, R28, 0x2, RZ ;", ("add", "R30", "R28", 2)),
         Ins("IADD3 R31, PT, PT, R28, 0x3, RZ ;", ("add", "R31", "R28", 3))]
    b += [Ins(f"MOV R{r}, 0x{two:x} ;", ("mov", f"R{r}", two)) for r in (qa, qa + 1, qa + 2, qa + 3, bl, bu)]
    b += front_ins(front, False)
    # (the model's LDSM: four words of the thread's slot 3 - right because every element of every lane's slot 3 is the same code)
    prods = [(f"LDSM.16.M88.4 R{qa}, [R9+0x30] ;", ("lds", f"R{qa}", "R9", 0x30, 4), [f"R{qa + j}" for j in range(4)]),
             (f"LDS R{bl}, [R9+0x20] ;", ("lds", f"R{bl}", "R9", 0x20, 1), [f"R{bl}"]),
             (f"LDS R{bu}, [R9+0x24] ;", ("lds", f"R{bu}", "R9", 0x24, 1), [f"R{bu}"])]
    for k, (text, sem, dst) in enumerate(prods):
        last = k == len(prods) - 1
        if ctl:
            b.append(Ins(text, sem, ctl=C(1, wb="0", y=y), tag="P", dst=dst))
            b.append(Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(ys if last else d, wait="0")))
        else:
            wb = "1" if (bar != "none" and (last or bar == "all")) else "-"
            b.append(Ins(text, sem, ctl=C(ys if last else d, wb=wb, y=y), tag="P", dst=dst))
    cw = "0" if ctl else "" if bar == "none" else "1"
    b.append(Ins(f"{MMA_FORMS[fn]} R28, R{qa}, R{bl}, R28 ;", ("qmma", "R28", f"R{qa}", f"R{bl}", None, fn), ctl=C(wait=cw), tag="C"))
    b += [PAD(), PAD(), PAD()]
    for t, sem in (("IMAD R8, R29, 0x3, R28 ;", ("mad", "R8", "R29", 3, "R28")), ("IMAD R8, R30, 0x5, R8 ;", ("mad", "R8", "R30", 5, "R8")),
                   ("IMAD R8, R31, 0x7, R8 ;", ("mad", "R8", "R31", 7, "R8")), ("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"))):
        b.append(Ins(t, sem))
    return b


# version 29 - the SCALE SET (the shape of the vendor-text MoE kernel's tensor loop once the loop's loads no longer wait): 2 or 3
# unguarded `LDS` on ONE write barrier, issued one after another without a wait, every second one through another base register;
# each brings a block-scale register of the readers. The readers are two GUARDED tensor words: `@P0 QMMA.SF` on the youngest and
# the next register - it carries the ONE wait, also where its guard is false - and, 16 cycles behind it (the table's resource
# row), `@P2 QMMA.SF` on the oldest and the youngest register (with four S: the two oldest) with no wait of its own. What a load brings is the UE8M0 code of
# the unit scale in every byte (prologue: slot 2 of the thread's line); until its load lands a register holds the code of x 2 -
# a reader that took it adds 2 x (4 x with both) its exact amount: still an integer add on the accumulator's bit pattern.
# Second build - the MIXED set: the letter D = an unguarded `LDS.64` on the same barrier (a pair of the thread's constants, slots
# 0 / 1 of its line; until it lands the pair holds the iteration's second input), read by two `MOV` words into temporaries that
# go into the fold. "lead": mov puts the MOV readers first (the first MOV carries the one wait).
SF_FORM = "QMMA.SF.E4M3.E2M1"
SF_UNIT, SF_MARK = 0x7f7f7f7f, 0x80808080      # UE8M0 in every byte: x 1 (what the loads bring) | x 2 (the marker)
SF_A, SF_B1, SF_B2, SF_ACC1, SF_ACC2, SF_BASE2 = 40, 44, 46, 48, 52, 56      # (first build: the layout of a set whose destinations end below R40)
SF_LET = ("S", "D")


def is_sf(req):
    """version 29: a SET request whose producers are the letters S / D (the scale set)"""
    return bool(is_set(req) and any(t.strip() in SF_LET for t in str(req["forms"]).split(",")))


def sf_layout(plan):
    """(second build) the registers of the readers behind the set's destinations (R32 ..): the A quad on the first multiple of
    four that is free and at least R40 (= the first build's layout for S,S and S,S,S), then the two B pairs, the two
    accumulator quads, the second base register, the prologue's unit-scale register, six temporaries of the MOV readers"""
    nd = sum(set_nreg(let) for _g, let, _r, _a in plan)
    a = max(SF_A, (32 + nd + 3) // 4 * 4)
    return {"a": a, "b1": a + 4, "b2": a + 6, "c1": a + 8, "c2": a + 12, "base2": a + 16, "one": a + 17, "tmp": a + 18}


def sf_exec(req, gids):
    """version 29 -> (numpy bool per thread: the first reader word executes in at least one iteration; the second likewise)"""
    import numpy as np
    lane = np.asarray(gids) % 1024
    pg = req["pguard"]

    def ex(letter, bit):
        if letter in ("t", "c"):
            return np.ones(len(lane), bool)
        if letter == "f":
            return np.zeros(len(lane), bool)
        return ((lane >> bit) & 1) == 0

    return ex(pg[0], 0), ex(pg[1], 1)


def sf_text(r):
    w = {"t": "true in every lane and iteration", "f": "FALSE in every lane and iteration (the word never executes)",
         "l": "a bit of the lane (true where the bit is 0)", "c": "a bit of (iteration counter x 0x9e3779b1) (true where the bit is 0)"}
    pg = r["pguard"]
    nd_ = sum(1 for t_ in str(r["forms"]).split(",") if t_.strip() == "D")
    mixed = ("" if not nd_ else
             f"; MIXED (second build): the {nd_} LDS.64 of the set bring pairs that {2 * nd_} unguarded MOV words read - "
             + ("the MOV readers stand FIRST and the first MOV carries the one wait (lead mov)" if r.get("lead") == "mov" else "the MOV readers stand behind the tensor readers"))
    return (" [version 29 - THE SCALE SET: every load is an unguarded LDS into a block-scale register of the readers, every second one through the second base register; "
            "the readers are two GUARDED tensor words - `@P0 QMMA.SF` on the youngest and the next register and, 16 cycles behind it, `@P2 QMMA.SF` on the oldest and the youngest"
            + f"; P0 = {w[pg[0]]}" + (" - bit 0" if pg[0] == "l" else " - bit 31" if pg[0] == "c" else "")
            + f"; P2 = {w[pg[1]]}" + (" - bit 1" if pg[1] == "l" else " - bit 20" if pg[1] == "c" else "")
            + "; both are written at the top of every iteration by ISETP.GE.AND"
            + f"; the first reader stands {r['rdist'] if r.get('rdist') else 2} cycles behind the last arming"
            + ("; POSITIVE CONTROL (wait end): the same text with the readers' ONE wait bit moved to the first word BEHIND the reader words - expect not good wherever a reader executes"
               if r.get("wait") == "end" else "; the first reader word carries the ONE wait (also where its guard is false)") + mixed + "]")


def sf_rw(ins):
    """version 29 -> (guard predicate | None, mnemonic, registers read, registers written, predicate written | None) of a word of the scale set's body"""
    t = ins.text.rstrip(" ;")
    g = None
    m = re.match(r"@!?(P\d) (.*)", t)
    if m:
        g, t = m.group(1), m.group(2)
    op, _, rest = t.partition(" ")
    ops = [o.strip() for o in re.split(r",(?![^\[]*\])", rest)] if rest else []
    regs = lambda o: [int(x) for x in re.findall(r"(?<![UA-Za-z0-9])R(\d+)(?![0-9])", o)]
    if op == "NOP":
        return g, op, set(), [], None
    if op.startswith("ISETP"):
        return g, op, {x for o in ops[1:] for x in regs(o)}, [], ops[0]
    if op.startswith("QMMA"):
        d0, a0, b0, c0 = (regs(o)[0] for o in ops[:4])
        rd = set(range(a0, a0 + 4)) | {b0, b0 + 1} | set(range(c0, c0 + 4)) | {regs(ops[4])[0], regs(ops[5])[0]}
        return g, op, rd, list(range(d0, d0 + 4)), None
    if op in ("MOV", "LOP3.LUT", "IADD3", "IMAD", "SHF.L.U32", "LDS", "LDS.64"):
        wr = regs(ops[0])
        return g, op, {x for o in ops[1:] for x in regs(o)}, wr + ([wr[0] + 1] if op == "LDS.64" else []), None
    raise SystemExit(f"sf_audit: a word the audit does not know: {ins.text}")


def sf_audit(req, body):
    """version 29: COUNT THE CYCLES of the probe's own words (a consumer one cycle behind its fixed-latency producer in a
    predicate word made ten requests of an earlier batch void - the model and the selftest's models cannot see timing). Two
    passes of the iteration (the body, the tail, the loop's compare and branch) in issue order; refused:
      a read of a register closer than 6 cycles behind its last fixed-latency writer (15 when the reader is a tensor word);
      a marker closer than 15 in front of a tensor word (6: a MOV reader) that reads the register behind a load;
      a tensor result read closer than 28; a guard closer than 13 behind the ISETP that wrote its predicate;
      a load's result read by anything but a reader word of the set (they stand behind the wait under test);
      any rewrite of a register closer than 8 behind a tensor word that read it (the operand hold).
    R15 is the fillers' register: nothing reads it into the checksum."""
    seq = list(body) + list(TAIL) + [Ins(f"ISETP.LT.U32.AND P1, PT, R11, 0x{REPEAT:x}, PT ;", ("nop",)), Ins("NOP ;", ("nop",))]
    lastw, lastfixed, lastp, treads, t, bad = {}, {}, {}, [], 0, []
    for _pass in (0, 1):
        for ins in seq:
            g, op, rd, wr, pw = sf_rw(ins)
            tensor, load = op.startswith("QMMA"), op.startswith("LDS")
            if g is not None and g in lastp and t - lastp[g] < 13:
                bad.append(f"`{ins.text}`: its guard {g} {t - lastp[g]} cycles behind the ISETP (13)")
            for r in sorted(rd):
                if r == 15 or r not in lastw:
                    continue
                tw, kind = lastw[r]
                if kind == "lds":
                    if ins.tag not in ("C", "C2", "C3"):
                        bad.append(f"`{ins.text}`: reads R{r} behind a load and is no reader word of the set")
                    elif r in lastfixed and t - lastfixed[r] < (15 if tensor else 6):
                        bad.append(f"`{ins.text}`: the marker of R{r} only {t - lastfixed[r]} cycles in front ({15 if tensor else 6})")
                    continue
                need = 28 if kind == "tensor" else 15 if tensor else 6
                if t - tw < need:
                    bad.append(f"`{ins.text}`: reads R{r} {t - tw} cycles behind its last writer ({need})")
            if pw is not None:
                lastp[pw] = t
            for r in wr:
                if r == 15:
                    continue
                for tt, rr in treads:
                    if r in rr and t - tt < 8:
                        bad.append(f"`{ins.text}`: rewrites R{r} {t - tt} cycles behind a tensor word that read it (8)")
                lastw[r] = (t, "lds" if load else "tensor" if tensor else "fixed")
                if not load and not tensor:
                    lastfixed[r] = t
            if tensor:
                treads.append((t, set(rd)))
            t += int(ins.ctl[-3:-1])
    if bad:
        raise SystemExit(f"{req.get('id')}: sf_audit refuses this body - " + "; ".join(sorted(set(bad))[:6]))


def body_set_sf(req, d, front, variant):
    """version 29 - the scale set: the loads d issue cycles apart on write barrier 1, the first reader `rdist` cycles behind
    the last arming. Every iteration: the markers into the destinations; the A quad (1.0 on even, 2.0 on odd iterations);
    the two accumulator quads (integer-valued floats 2^23 + k from the iteration's two inputs); P0 and P2; the loads; the
    readers; 45 cycles or more behind the second tensor reader the fold of the eight accumulator registers (second build:
    and of the MOV readers' temporaries)."""
    plan = set_plan(req)
    n = len(plan)
    if variant != "bare" or req["barrier"] != "all" or front not in ("none", "", None):
        raise SystemExit(f"{req.get('id')}: the scale set has barrier all, no front, no ctl variant")
    y = req.get("yield") == "set"
    pg = req["pguard"]
    sp, form = MMA_SPEC[SF_FORM], MMA_FORMS[SF_FORM]
    L = sf_layout(plan)
    a, c1, c2 = L["a"], L["c1"], L["c2"]
    sreg = [reg for _g, let, reg, _a in plan if let == "S"]
    dreg = [reg for _g, let, reg, _a in plan if let == "D"]
    b = []
    for _g, let, reg, _a in plan:
        if let == "S":
            b.append(Ins(f"MOV R{reg}, 0x{SF_MARK:x} ;", ("mov", f"R{reg}", SF_MARK)))
        else:
            b += [Ins(f"MOV R{reg + j}, R5 ;", ("mov", f"R{reg + j}", "R5")) for j in (0, 1)]
    b += [Ins("LOP3.LUT R13, R11, 0x1, RZ, 0xc0, !PT ;", ("and", "R13", "R11", 1)),
          Ins(f"IMAD R{a}, R13, 0x{sp['da']:x}, RZ ;", ("mad", f"R{a}", "R13", sp["da"], "RZ")),
          Ins(f"IADD3 R{a}, PT, PT, R{a}, 0x{sp['a0']:x}, RZ ;", ("add", f"R{a}", f"R{a}", sp["a0"]))]
    b += [Ins(f"MOV R{a + k}, R{a} ;", ("mov", f"R{a + k}", f"R{a}")) for k in (1, 2, 3)]
    for c, src in ((c1, "R4"), (c2, "R5")):
        b += [Ins(f"LOP3.LUT R{c}, {src}, 0x3fffff, RZ, 0xc0, !PT ;", ("and", f"R{c}", src, 0x3fffff)),
              Ins(f"LOP3.LUT R{c}, R{c}, 0x4b000000, RZ, 0xfc, !PT ;", ("or", f"R{c}", f"R{c}", 0x4b000000))]
        b += [Ins(f"IADD3 R{c + k}, PT, PT, R{c}, 0x{k:x}, RZ ;", ("add", f"R{c + k}", f"R{c}", k)) for k in (1, 2, 3)]
    b += set_pguard_top(pg)
    slast, rfill = set_rdist(req, y, 2)
    ks = kd = 0
    for k, (_g, let, reg, _a) in enumerate(plan):
        base = f"R{L['base2']}" if k % 2 else "R9"
        if let == "S":
            off, ks = 0x20 + 4 * ks, ks + 1
            text, sem, dst = f"LDS R{reg}, [{base}+0x{off:x}] ;", ("lds", f"R{reg}", "R9", off, 1), [f"R{reg}"]
        else:
            off, kd = 8 * kd, kd + 1
            text, sem, dst = f"LDS.64 R{reg}, [{base}{('+0x%x' % off) if off else ''}] ;", ("lds", f"R{reg}", "R9", off, 2), [f"R{reg}", f"R{reg + 1}"]
        b.append(Ins(text, sem, ctl=C(slast if k == n - 1 else d, wb="1", y=y), tag="P", dst=dst))
    b += [Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(st)) for st in rfill]
    endw = req.get("wait") == "end"      # the positive control: the readers' ONE wait bit stands on the first word BEHIND the reader words
    lead_mov = req.get("lead") == "mov"
    one = L["one"]
    young, nxt, old_ = sreg[-1], (sreg[-2] if len(sreg) > 1 else one), (sreg[0] if len(sreg) > 1 else one)
    r2a, r2b = (sreg[0], sreg[1]) if len(sreg) > 3 else (old_, young)      # (second build) with four S the second reader takes the two oldest: every scale register is read
    acc = lambda c: tuple(f"R{c + k}" for k in range(4))
    q = lambda c, bb, s1, s2: f"{form} R{c}, R{a}, R{bb}, R{c}, R{s1}, R{s2}, URZ ;"
    w1 = "" if (endw or lead_mov) else "1"
    tens = [Ins("@P0 " + q(c1, L["b1"], young, nxt),
                ("g", "P0", 1, acc(c1), ("qmmasf", f"R{c1}", f"R{a}", f"R{L['b1']}", f"R{young}", f"R{nxt}", SF_FORM)),
                ctl=C(1, wait=w1, y=y), tag="C"),
            Ins("NOP ;", ("nop",)),
            Ins("@P2 " + q(c2, L["b2"], r2a, r2b),
                ("g", "P2", 1, acc(c2), ("qmmasf", f"R{c2}", f"R{a}", f"R{L['b2']}", f"R{r2a}", f"R{r2b}", SF_FORM)), tag="C2")]
    movs, tmps = [], []
    for j, reg in enumerate(reversed(dreg)):      # (second build) the MOV readers: the youngest pair first, one issue cycle apart
        for h in (0, 1):
            t_ = L["tmp"] + 2 * j + h
            tmps.append(t_)
            movs.append(Ins(f"MOV R{t_}, R{reg + h} ;", ("mov", f"R{t_}", f"R{reg + h}"),
                            ctl=C(1, wait="1" if (lead_mov and not endw and not movs) else ""), tag="C3"))
    b += (movs + tens) if lead_mov else (tens + movs)
    b.append(Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="1")) if endw else PAD())
    b.append(PAD())
    b.append(Ins(f"IMAD R8, R{c1 + 1}, 0x3, R{c1} ;", ("mad", "R8", f"R{c1 + 1}", 3, f"R{c1}")))
    for reg, wgt in [(c1 + 2, 5), (c1 + 3, 7), (c2, 11), (c2 + 1, 13), (c2 + 2, 17), (c2 + 3, 19)] + list(zip(tmps, (23, 29, 31, 37, 41, 43))):
        b.append(Ins(f"IMAD R8, R{reg}, 0x{wgt:x}, R8 ;", ("mad", "R8", f"R{reg}", wgt, "R8")))
    b.append(Ins("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8")))
    sf_audit(req, b)
    return b


def body_set(req, d, front, variant):
    """version 23 - a SET of producers of one thread in flight, d issue cycles apart, ONE wait of the reader (`barrier`
    all = every producer sets the SAME write barrier, none = the positive control: no barrier and no wait, last = only
    the youngest; variant ctl: every producer on its own barrier with its own wait). Every destination register holds a
    marker that changes each iteration until its producer lands. The reader takes one register of every producer
    first - the youngest producer first, three a word, one issue cycle apart, the first word on the wait - then the
    other registers of the pairs and quads. A register whose content the host cannot know (LDC.64 of the output
    pointer, MUFU.EX2) is read as (register - its reference): 0 when the producer has landed."""
    plan = set_plan(req)
    if any(let == "M" for _g, let, _r, _a in plan):
        return body_set_mma(req, d, front, variant)
    if any(let in ("S", "D") for _g, let, _r, _a in plan):      # version 29
        return body_set_sf(req, d, front, variant)
    n, bar = len(plan), req["barrier"]
    ys = int(req.get("younger_stall", 2))
    ctl = variant == "ctl"
    y = req.get("yield") == "set"
    b = [Ins(f"MOV R{reg + j}, R5 ;", ("mov", f"R{reg + j}", "R5")) for _g, let, reg, _a in plan for j in range(set_nreg(let))]
    cold = req.get("cold") == "set"
    if cold:
        # (third build) the lines of this iteration: the tail (behind the threads' words) of block (b & 0xff) of the output
        # buffer, b = the iteration's second input - another block for every lane and every iteration. R76:R77 = the tail of
        # block 0 (prologue); only the LOW word R78 is written here (R79 = R77 since the prologue): a stale or torn address is
        # still a tail inside the buffer. Quad k at +128 k, byte m at +0x400 + 64 m (+ a byte), the word at +0x600.
        b += [Ins("LOP3.LUT R13, R5, 0xff, RZ, 0xc0, !PT ;", ("and", "R13", "R5", 0xff)),
              Ins("SHF.L.U32 R13, R13, 0xc, RZ ;", ("shl", "R13", "R13", 12)),
              Ins(f"IADD3 R{SET_CBASE}, PT, PT, R13, R{SET_ABASE}, RZ ;", ("nop",))]
    nbyte = 0
    if any(let == "h" for _g, let, _r, _a in plan):
        b.append(Ins(f"IMAD R{SET_HSRC}, R5, 0x3, R4 ;", ("mad", f"R{SET_HSRC}", "R5", 3, "R4")))
    pg = req.get("pguard")      # version 28
    psh = req.get("pshift")     # (second build) 1 = the first build's text for letter c
    again = [k_ for k_, (g_, l_, _r, _a) in enumerate(plan) if g_ == "g" and l_ == "Q" and any(x_[0] == "g" for x_ in plan[:k_])] if pg else []
    if pg:
        b += set_pguard_top(pg, shift_first=(pg[0] == "c" and bool(again) and not psh))
    slast, rfill = set_rdist(req, y, ys)
    b += front_ins(front, False)
    for k, (g, let, reg, aux) in enumerate(plan):
        last = k == n - 1
        gp = "@P2 " if g == "k" else "@P0 " if g else ""
        if k in again:      # version 28: the kernel's form - P0 is written again between the pairs
            b += set_pguard_again(pg, more=(k != again[-1]), pshift=psh)
        nreg = set_nreg(let)
        if let == "u":
            text, sem = f"{gp}LDS.U16 R{reg}, [R9{('+0x%x' % aux) if aux else ''}] ;", ("ldsu16", f"R{reg}", "R9", aux)
        elif let in ORDN_FORM:
            text, sem = f"{gp}{ORDN_FORM[let][0]} R{reg}, [R9{('+0x%x' % aux) if aux else ''}] ;", ("lds", f"R{reg}", "R9", aux, nreg)
        elif let == "G" and cold:
            text, sem = f"{gp}LDG.E R{reg}, desc[UR4][R{SET_CBASE}.64+0x600] ;", ("zeron", f"R{reg}", 1)
        elif let == "Q" and cold:
            text, sem = f"{gp}LDG.E.128 R{reg}, desc[UR4][R{SET_CBASE}.64{('+0x%x' % (128 * aux)) if aux else ''}] ;", ("zeron", f"R{reg}", 4)
        elif let == "B" and cold:
            text, sem = f"{gp}LDG.E.U8 R{reg}, desc[UR4][R{SET_CBASE}.64+0x{0x400 + 64 * nbyte + aux % 64:x}] ;", ("zeron", f"R{reg}", 1)
            nbyte += 1
        elif let == "G":
            text, sem = f"{gp}LDG.E R{reg}, desc[UR4][R18.64] ;", ("ldg", f"R{reg}", "R18")
        elif let == "Q":
            text, sem = f"{gp}LDG.E.128 R{reg}, desc[UR4][R{SET_ABASE}.64{('+0x%x' % (16 * aux)) if aux else ''}] ;", ("ldgq", f"R{reg}", aux)
        elif let == "B":
            text, sem = f"{gp}LDG.E.U8 R{reg}, desc[UR4][R{SET_ABASE}.64+0x{aux:x}] ;", ("ldgb", f"R{reg}", aux)
        elif let == "c":
            text, sem = f"LDC R{reg}, c[0x0][0x388] ;", ("mov", f"R{reg}", SEED)
        elif let == "C":
            text, sem = f"LDC.64 R{reg}, c[0x0][0x380] ;", ("mov2", f"R{reg}", "R2")
        elif let == "m":
            text, sem = f"MUFU.EX2 R{reg}, R{SET_MSRC} ;", ("mov", f"R{reg}", f"R{SET_MREF}")
        else:
            text, sem = f"SHFL.BFLY PT, R{reg}, R{SET_HSRC}, 0x1, 0x1f ;", ("shfl", f"R{reg}", f"R{SET_HSRC}", "bfly", 1)
        dst = [f"R{reg + j}" for j in range(nreg)]
        if pg and g:      # version 28: the model's word under its guard (where it is nullified its destinations keep their markers)
            sem = ("g", "P2" if g == "k" else "P0", 1, tuple(dst), sem)
        if ctl:
            b.append(Ins(text, sem, ctl=C(1, wb="0", y=y), tag="P", dst=dst))
            b.append(Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(ys if last else d, wait="0")))
        else:
            wb = "1" if (bar != "none" and (last or bar == "all")) else "-"
            b.append(Ins(text, sem, ctl=C(slast if last else d, wb=wb, y=y), tag="P", dst=dst))
    b += [Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(st)) for st in rfill]      # version 28: rdist
    endw = req.get("wait") == "end"      # version 28: the positive control - the reader's wait bit stands on the first word BEHIND the reader words
    cw = "0" if ctl else "" if (bar == "none" or endw) else "1"

    def ref(let, j):
        return (2 + j) if let == "C" else SET_MREF if let == "m" else None

    items = [(reg, ref(let, 0)) for _g, let, reg, _a in reversed(plan)]
    items += [(reg + j, ref(let, j)) for _g, let, reg, _a in reversed(plan) for j in range(1, set_nreg(let))]
    tmp = ["R6", "R8", "R12", "R13"]
    words, i, pw, rw = [], 0, 0, 0
    while i < len(items):
        if items[i][1] is not None:      # a relative reader: its own temporary
            words.append((f"R{SET_REL[rw]}", None, [items[i]]))
            rw += 1
            i += 1
            continue
        acc = None if pw < 4 else tmp[pw % 4]
        grp = []
        while i < len(items) and items[i][1] is None and len(grp) < (2 if acc else 3):
            grp.append(items[i])
            i += 1
        words.append((tmp[pw % 4], acc, grp))
        pw += 1
    if not pw:
        raise SystemExit(f"{req.get('id')}: a set needs one producer whose content the host knows")
    for k, (t, acc, grp) in enumerate(words):
        ct = C(1, wait=cw) if k == 0 else C(1)
        if grp[0][1] is not None:
            r, rf = grp[0]
            b.append(Ins(f"IADD3 {t}, PT, PT, R{r}, -R{rf}, RZ ;", ("rsub", t, f"R{rf}", f"R{r}"), ctl=ct, tag="C"))
            continue
        srcs = ([acc] if acc else []) + [f"R{r}" for r, _f in grp]
        if len(srcs) == 3:
            b.append(Ins(f"IADD3 {t}, PT, PT, {srcs[0]}, {srcs[1]}, {srcs[2]} ;", ("add3", t, srcs[0], srcs[1], srcs[2]), ctl=ct, tag="C"))
        elif len(srcs) == 2:
            b.append(Ins(f"IADD3 {t}, PT, PT, {srcs[0]}, {srcs[1]}, RZ ;", ("add", t, srcs[0], srcs[1]), ctl=ct, tag="C"))
        else:
            b.append(Ins(f"MOV {t}, {srcs[0]} ;", ("mov", t, srcs[0]), ctl=ct, tag="C"))
    b.append(Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="1")) if endw else PAD())
    ut = [t for t in tmp if any(w[0] == t for w in words)] + [f"R{SET_REL[j]}" for j in range(rw)]
    b.append(Ins("IMAD R6, R6, 0x3, RZ ;", ("mad", "R6", "R6", 3, "RZ")))
    for j, t in enumerate(ut[1:], 1):
        b.append(Ins(f"IMAD R6, {t}, 0x{2 * j + 3:x}, R6 ;", ("mad", "R6", t, 2 * j + 3, "R6")))
    b.append(Ins("IADD3 R10, PT, PT, R10, R6, RZ ;", ("add", "R10", "R10", "R6")))
    if cold:      # (third build) every load brings zeros: the iteration's input keeps the checksum of a kernel that ran away from 0
        b.append(Ins("IADD3 R10, PT, PT, R10, R4, RZ ;", ("add", "R10", "R10", "R4")))
    return b


def body_ordn(req, d, front, variant):
    """N shared loads of one thread in flight (`nload` 2..8), d issue cycles apart, and ONE wait of the reader:
    `barrier` last = only the youngest load carries the write barrier (the vendor's cover of bare loads), all = every
    load carries the SAME barrier (cubit's allocator records stale reads for eight such loads 1 KB apart at >= 2 CTAs
    per SM). `place` near = words 0..N-1 of the thread's own 64 bytes, one base register; base2 = the same words, every
    second load through another base register (R7 = R9); far = N words STRIDE (>= 1 KB) apart in the second region of
    the CTA's shared memory (the thread's own words, written once in the prologue). Every destination holds a marker
    that changes each iteration until its load lands. From version 13 the reader takes ALL N registers within N / 2
    cycles of its wake-up (pairs summed at stall 1 into R6 / R8 / R12 / R13, weighed afterwards); version 12 read the
    oldest register at the wake-up and each further one 15 cycles later - a tight test of the oldest load only.
    `barrier` none = the POSITIVE CONTROL: no load carries a barrier and the reader does not wait (it must be wrong).
    variant ctl: every load is waited before the next is issued (must be right at every distance)."""
    if req.get("forms"):      # version 21: loads of mixed forms (version 23: a set of producers)
        return body_set(req, d, front, variant) if is_set(req) else body_ordn_mixed(req, d, front, variant)
    n, place, bar = int(req["nload"]), req["place"], req["barrier"]
    ys = int(req.get("younger_stall", 2))
    ctl = variant == "ctl"
    yl = req.get("yield") == "set"      # version 21: the loads carry the yield flag
    _fb, stride = far_layout(int(req.get("_threads", 1024)))
    b = [Ins(f"MOV R{24 + k}, R5 ;", ("mov", f"R{24 + k}", "R5")) for k in range(n)]
    if place == "base2":
        b.append(Ins("MOV R7, R9 ;", ("mov", "R7", "R9")))
    b += front_ins(front, False)
    for k in range(n):
        last = k == n - 1
        if place == "far":
            text, sem = f"LDS R{24 + k}, [R14{('+0x%x' % (k * stride)) if k else ''}] ;", ("ldsf", f"R{24 + k}", k)
        else:
            base = "R7" if (place == "base2" and k % 2) else "R9"
            text, sem = f"LDS R{24 + k}, [{base}{('+0x%x' % (4 * k)) if k else ''}] ;", ("lds", f"R{24 + k}", "R9", 4 * k, 1)
        if ctl:
            b.append(Ins(text, sem, ctl=C(1, wb="0", y=yl), tag="P", dst=[f"R{24 + k}"]))
            b.append(Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(ys if last else d, wait="0")))
        else:
            wb = "1" if (bar != "none" and (last or bar == "all")) else "-"
            b.append(Ins(text, sem, ctl=C(ys if last else d, wb=wb, y=yl), tag="P", dst=[f"R{24 + k}"]))
    cw = "0" if ctl else "" if bar == "none" else "1"
    tmp = ["R6", "R8", "R12", "R13"]
    for j in range((n + 1) // 2):      # the snapshots: one issue cycle apart, the first on the wait
        a, c = 24 + 2 * j, 24 + 2 * j + 1
        ct = C(1, wait=cw) if j == 0 else C(1)
        if c < 24 + n:
            b.append(Ins(f"IADD3 {tmp[j]}, PT, PT, R{a}, R{c}, RZ ;", ("add", tmp[j], f"R{a}", f"R{c}"), ctl=ct, tag="C"))
        else:
            b.append(Ins(f"MOV {tmp[j]}, R{a} ;", ("mov", tmp[j], f"R{a}"), ctl=ct, tag="C"))
    b.append(PAD())
    b.append(Ins(f"IMAD R6, R6, 0x3, RZ ;", ("mad", "R6", "R6", 3, "RZ")))
    for j in range(1, (n + 1) // 2):
        b.append(Ins(f"IMAD R6, {tmp[j]}, 0x{2 * j + 3:x}, R6 ;", ("mad", "R6", tmp[j], 2 * j + 3, "R6")))
    b.append(Ins("IADD3 R10, PT, PT, R10, R6, RZ ;", ("add", "R10", "R10", "R6")))
    return b


def body_ord(req, d, front, variant):
    """an OLDER load without a write barrier, d issue cycles in front of a YOUNGER load that carries one; the reader of the
    older load's result waits only on the younger load's barrier. variant ctl: the older load carries barrier 0 and the
    reader waits on it too (must be right at every distance)."""
    if req.get("nload"):
        return body_ordn(req, d, front, variant)
    older, younger = req["older"], req["younger"]
    if (older, younger) not in ORD_PAIRS:
        raise SystemExit(f"ord: older {older!r} / younger {younger!r} not in the catalogue (probe.py list)")
    s, fill = split_distance(d)
    ys = int(req.get("younger_stall", 2))
    ctl = variant == "ctl"
    # "older_barrier": "same" = the older load carries the SAME write barrier as the younger one (two producers on one
    # scoreboard, one wait): right at every distance if the scoreboard COUNTS its producers, stale like the bare older
    # load if it only follows the last one
    # version 21 - "older_barrier": "recycle" = the older load carries write barrier 1; the YOUNGER load's own word waits
    # barrier 1 (the older load has landed when it issues) and sets barrier 1 again; the reader of the OLDER load's
    # register does not wait at all - it stands `younger_stall` cycles behind the younger load's issue
    recycle = req.get("older_barrier") == "recycle" and not ctl
    yw = "1" if recycle else ""
    wb0 = "0" if ctl else "1" if req.get("older_barrier") in ("same", "recycle") else "-"
    cw = "01" if ctl else "" if recycle else "1"
    b = []
    # "far": the younger SHARED load reads another line of the CTA's shared memory, 1 KB away (another thread's 64 bytes:
    # R14 = R9 ^ 0x400, always inside the 64 KB the kernel declares); what it brings is not used and not modelled
    # "far": "off" (version 14) = the younger shared load on the SAME base register, 0x200 bytes away (another line; inside
    # the declared shared memory: `gen` refuses a grid where the last thread's address would not be)
    far = req.get("far")
    if far and younger not in ("LDS", "LDS128", "LDSM", "LDS64"):
        raise SystemExit("ord: `far` is for a younger SHARED load (LDS, LDS128, LDSM, LDS64)")
    ybase = "R14" if far is True else "R7" if far == "base2" else "R9"      # version 19: "base2" = another base register, the same address
    yoff = 0x230 if far == "off" else 0x30
    # "younger_guard": the younger load under a predicate - true (P0) or false (P3: the load does not happen; what its
    # write barrier then does for the reader's wait is the question)
    yg = {"true": "@P0 ", "false": "@P3 "}.get(req.get("younger_guard"), "")
    if far is True:
        b.append(Ins("LOP3.LUT R14, R9, 0x400, RZ, 0x3c, !PT ;", ("xor", "R14", "R9", 0x400)))
    if far == "base2":      # version 19: the younger shared load through ANOTHER base register on the SAME line
        b.append(Ins("MOV R7, R9 ;", ("mov", "R7", "R9")))
    # version 19 - "older_guard": "true" = the OLDER shared load under a guard that is true (P0, set in the prologue)
    og = "@P0 " if req.get("older_guard") == "true" else ""
    # what the older load brings changes every iteration (a store with read barrier 3, waited by the fold); its destination
    # holds a marker (b) until the load lands
    if older == "LDS":
        b += [Ins("STS [R9+0x20], R4 ;", ("sts", "R9", 0x20, "R4", 1), ctl=C(rb="3")), Ins("MOV R6, R5 ;", ("mov", "R6", "R5"))]
        b += front_ins(front, False)
        b.append(Ins(f"{og}LDS R6, [R9+0x20] ;", ("lds", "R6", "R9", 0x20, 1), ctl=C(s, wb=wb0), tag="P", dst=["R6"]))
    elif older == "LDSU16":      # 16 bits, zero-extended
        b += [Ins("STS [R9+0x20], R4 ;", ("sts", "R9", 0x20, "R4", 1), ctl=C(rb="3")), Ins("MOV R6, R5 ;", ("mov", "R6", "R5"))]
        b += front_ins(front, False)
        b.append(Ins(f"{og}LDS.U16 R6, [R9+0x20] ;", ("ldsu16", "R6", "R9", 0x20), ctl=C(s, wb=wb0), tag="P", dst=["R6"]))
    elif older == "LDS64":
        b += [Ins("MOV R26, R4 ;", ("mov", "R26", "R4")), Ins("MOV R27, R5 ;", ("mov", "R27", "R5")),
              Ins("STS.64 [R9+0x20], R26 ;", ("sts", "R9", 0x20, "R26", 2), ctl=C(rb="3")),
              Ins("MOV R28, R5 ;", ("mov", "R28", "R5")), Ins("MOV R29, R5 ;", ("mov", "R29", "R5"))]
        b += front_ins(front, False)
        b.append(Ins(f"{og}LDS.64 R28, [R9+0x20] ;", ("lds", "R28", "R9", 0x20, 2), ctl=C(s, wb=wb0), tag="P", dst=["R28", "R29"]))
    elif older == "LDS128":
        b += [Ins("MOV R24, R4 ;", ("mov", "R24", "R4")), Ins("MOV R25, R5 ;", ("mov", "R25", "R5")),
              Ins("LOP3.LUT R26, R4, 0x33cc33cc, RZ, 0x3c, !PT ;", ("xor", "R26", "R4", 0x33cc33cc)),
              Ins("IADD3 R27, PT, PT, R4, R5, RZ ;", ("add", "R27", "R4", "R5")),
              Ins("STS.128 [R9+0x20], R24 ;", ("sts", "R9", 0x20, "R24", 4), ctl=C(rb="3")),
              Ins("MOV R28, R5 ;", ("mov", "R28", "R5")), Ins("MOV R29, R5 ;", ("mov", "R29", "R5")),
              Ins("MOV R30, R5 ;", ("mov", "R30", "R5")), Ins("MOV R31, R5 ;", ("mov", "R31", "R5"))]
        b += front_ins(front, False)
        b.append(Ins(f"{og}LDS.128 R28, [R9+0x20] ;", ("lds", "R28", "R9", 0x20, 4), ctl=C(s, wb=wb0), tag="P", dst=["R28", "R29", "R30", "R31"]))
    elif older == "LDC":      # version 18: the constant-bank load of the seed; its destination holds the marker until it lands
        b.append(Ins("MOV R6, R5 ;", ("mov", "R6", "R5")))
        b += front_ins(front, False)
        b.append(Ins("LDC R6, c[0x0][0x388] ;", ("mov", "R6", SEED), ctl=C(s, wb=wb0), tag="P", dst=["R6"]))
    elif older == "SHFL":     # version 18: a warp shuffle (its source differs between the lanes of a pair)
        b += [Ins("IMAD R14, R5, 0x3, R4 ;", ("mad", "R14", "R5", 3, "R4")), Ins("MOV R6, R5 ;", ("mov", "R6", "R5"))]
        b += front_ins(front, False)
        b.append(Ins("SHFL.BFLY PT, R6, R14, 0x1, 0x1f ;", ("shfl", "R6", "R14", "bfly", 1), ctl=C(s, wb=wb0), tag="P", dst=["R6"]))
    else:
        b += [Ins("STG.E desc[UR4][R16.64], R4 ;", ("stg", "R16", "R4"), ctl=C(rb="3")), Ins("MOV R6, R5 ;", ("mov", "R6", "R5"))]
        b += front_ins(front, False)
        b.append(Ins("LDG.E R6, desc[UR4][R16.64] ;", ("ldg", "R6", "R16"), ctl=C(s, wb=wb0), tag="P", dst=["R6"]))
    b += fill
    if younger == "LDS":
        b.append(Ins(f"{yg}LDS R8, [{ybase}+0x{yoff:x}] ;", ("poison", "R8", 1) if (far or yg) else ("lds", "R8", "R9", 0x30, 1), ctl=C(ys, wait=yw, wb="1")))
    elif younger == "LDS128":      # another access width than the older load (only behind an older LDS / LDS.U16: R24-R27 are free there)
        b.append(Ins(f"{yg}LDS.128 R24, [{ybase}+0x{yoff:x}] ;", ("poison", "R24", 4), ctl=C(ys, wait=yw, wb="1")))
    elif younger == "LDS64":       # (R30:R31: free behind every older form that pairs with it)
        b.append(Ins(f"{yg}LDS.64 R30, [{ybase}+0x{yoff:x}] ;", ("poison", "R30", 2), ctl=C(ys, wait=yw, wb="1")))
    elif younger == "LDSM":
        b.append(Ins(f"{yg}LDSM.16.M88.4 R24, [{ybase}+0x{yoff:x}] ;", ("poison", "R24", 4), ctl=C(ys, wait=yw, wb="1")))
    elif younger == "S2R":       # version 18: a younger producer of another class (what it brings is not used)
        b.append(Ins("S2R R8, SR_TID.X ;", ("mov", "R8", "R0"), ctl=C(ys, wait=yw, wb="1")))
    elif younger == "S2UR":      # ... into a uniform register (UR4 is the descriptor's)
        b.append(Ins("S2UR UR6, SR_CTAID.X ;", ("nop",), ctl=C(ys, wait=yw, wb="1")))
    elif younger == "LDC64":     # ... the pair R30:R31 (the output pointer: not modelled)
        b.append(Ins("LDC.64 R30, c[0x0][0x380] ;", ("poison", "R30", 2), ctl=C(ys, wait=yw, wb="1")))
    else:
        b.append(Ins("LDG.E R8, desc[UR4][R18.64] ;", ("ldg", "R8", "R18"), ctl=C(ys, wait=yw, wb="1")))
    if older == "LDS64":
        b.append(Ins("IADD3 R13, PT, PT, R28, R29, RZ ;", ("add", "R13", "R28", "R29"), ctl=C(wait=cw), tag="C"))
    elif older == "LDS128":
        b.append(Ins("IADD3 R13, PT, PT, R28, R31, RZ ;", ("add", "R13", "R28", "R31"), ctl=C(wait=cw), tag="C"))
    else:
        b.append(Ins("MOV R13, R6 ;", ("mov", "R13", "R6"), ctl=C(wait=cw), tag="C"))
    b.append(Ins("IADD3 R10, PT, PT, R10, R13, RZ ;", ("add", "R10", "R10", "R13"), ctl=C(wait="13" if recycle else "3")))
    return b


def body_war(req, d, front, variant):
    """variant: bare (the question), ctl (no overwriter), rb (read barrier on the store, the overwriter waits)"""
    store, over = req["store"], req["overwriter"]
    if store not in WAR_STORES or over not in WAR_STORES[store][0]:
        raise SystemExit(f"war: store {store!r} / overwriter {over!r} not in the catalogue (probe.py list)")
    s, fill = split_distance(d)
    rb = "2" if variant == "rb" else "-"
    ow = "2" if variant == "rb" else ""
    ctl = variant == "ctl"
    b = []
    load_over = over in ("LDS", "LDG", "LDS128", "LDSM") and not ctl
    back_wait = "0" if load_over else ""
    if store == "STS.data":
        b.append(Ins("IADD3 R6, PT, PT, R4, R5, RZ ;", ("add", "R6", "R4", "R5")))
        b += front_ins(front, False)
        b.append(Ins("STS [R9+0x20], R6 ;", ("sts", "R9", 0x20, "R6", 1), ctl=C(s, rb=rb), tag="S"))
        b += fill
        if ctl:
            b.append(PAD())
        elif over == "LOP3":
            b.append(Ins("LOP3.LUT R6, R6, 0x5a5a5a5a, RZ, 0x3c, !PT ;", ("xor", "R6", "R6", 0x5a5a5a5a), ctl=C(wait=ow), tag="O"))
        elif over == "IADD3":
            b.append(Ins(f"IADD3 R6, PT, PT, R6, 0x{LATE_CONST:x}, RZ ;", ("add", "R6", "R6", LATE_CONST), ctl=C(wait=ow), tag="O"))
        elif over == "LDS":
            b.append(Ins("LDS R6, [R9+0x30] ;", ("lds", "R6", "R9", 0x30, 1), ctl=C(wait=ow, wb="0"), tag="O"))
        else:
            b.append(Ins("LDG.E R6, desc[UR4][R18.64] ;", ("ldg", "R6", "R18"), ctl=C(wait=ow, wb="0"), tag="O"))
        b += [Ins("LDS R8, [R9+0x20] ;", ("lds", "R8", "R9", 0x20, 1), ctl=C(wait=back_wait, wb="1"), tag="B"), ADD10("1")]
    elif store == "STS128.data":
        b += [Ins("IADD3 R24, PT, PT, R4, R5, RZ ;", ("add", "R24", "R4", "R5")), Ins("MOV R25, R4 ;", ("mov", "R25", "R4")),
              Ins("MOV R26, R5 ;", ("mov", "R26", "R5")),
              Ins("LOP3.LUT R27, R24, 0x33cc33cc, RZ, 0x3c, !PT ;", ("xor", "R27", "R24", 0x33cc33cc))]
        b += front_ins(front, False)
        b.append(Ins("STS.128 [R9+0x20], R24 ;", ("sts", "R9", 0x20, "R24", 4), ctl=C(s, rb=rb), tag="S"))
        b += fill
        if ctl:
            b.append(PAD())
        elif over == "LOP3":
            b.append(Ins("LOP3.LUT R27, R27, 0x5a5a5a5a, RZ, 0x3c, !PT ;", ("xor", "R27", "R27", 0x5a5a5a5a), ctl=C(wait=ow), tag="O"))
        elif over == "LDS128":
            b.append(Ins("LDS.128 R24, [R9+0x30] ;", ("lds", "R24", "R9", 0x30, 4), ctl=C(wait=ow, wb="0"), tag="O"))
        else:
            b.append(Ins("LDSM.16.M88.4 R24, [R9+0x30] ;", ("poison", "R24", 4), ctl=C(wait=ow, wb="0"), tag="O"))
        b += [Ins("LDS.128 R28, [R9+0x20] ;", ("lds", "R28", "R9", 0x20, 4), ctl=C(wait=back_wait, wb="1"), tag="B")] + fold4("1")
    elif store == "STG.data":
        b.append(Ins("IADD3 R6, PT, PT, R4, R5, RZ ;", ("add", "R6", "R4", "R5")))
        b += front_ins(front, False)
        b.append(Ins("STG.E desc[UR4][R16.64], R6 ;", ("stg", "R16", "R6"), ctl=C(s, rb=rb), tag="S"))
        b += fill
        if ctl:
            b.append(PAD())
        elif over == "LOP3":
            b.append(Ins("LOP3.LUT R6, R6, 0x5a5a5a5a, RZ, 0x3c, !PT ;", ("xor", "R6", "R6", 0x5a5a5a5a), ctl=C(wait=ow), tag="O"))
        elif over == "IADD3":
            b.append(Ins(f"IADD3 R6, PT, PT, R6, 0x{LATE_CONST:x}, RZ ;", ("add", "R6", "R6", LATE_CONST), ctl=C(wait=ow), tag="O"))
        elif over == "LDG":
            b.append(Ins("LDG.E R6, desc[UR4][R18.64] ;", ("ldg", "R6", "R18"), ctl=C(wait=ow, wb="0"), tag="O"))
        else:
            b.append(Ins("LDS R6, [R9+0x30] ;", ("lds", "R6", "R9", 0x30, 1), ctl=C(wait=ow, wb="0"), tag="O"))
        b += [Ins("LDG.E R8, desc[UR4][R16.64] ;", ("ldg", "R8", "R16"), ctl=C(wait=back_wait, wb="1"), tag="B"), ADD10("1")]
    elif store in SHFL_STORES:
        mode = "bfly" if store == "SHFL.BFLY.src" else "idx"
        rbset = req.get("read_barrier") == "set"
        srb = "2" if (variant == "rb" or rbset) else "-"
        behind = req.get("behind") in ("write_waiter", "younger_write", "younger_read", "younger_lds")
        younger = req.get("behind") == "younger_write"
        ycover = req.get("behind") if req.get("behind") in ("younger_read", "younger_lds") else None      # version 21
        if over == "IADD3.it":      # version 16: R7 = (iteration index + 1) * the odd constant (R7 is 0 before the loop)
            b.append(Ins(f"IADD3 R7, PT, PT, R7, 0x{LATE_CONST:x}, RZ ;", ("add", "R7", "R7", LATE_CONST)))
        # the source value must DIFFER between lanes 2k and 2k + 1 (a + b does not: b = gid ^ an odd constant)
        b.append(Ins("IMAD R6, R4, 0x9, R5 ;", ("mad", "R6", "R4", 9, "R5")))
        if younger or ycover == "younger_read":      # version 17: the YOUNGER shuffle's own source (it differs between the lanes of a pair too)
            b.append(Ins("IMAD R14, R5, 0x3, R4 ;", ("mad", "R14", "R5", 3, "R4")))
        b += front_ins(front, False)
        # (behind: the reader waits the WRITE barrier only - with a read barrier on the shuffle that is the shape of a barred
        # shuffle whose overwriter stands behind the write-barrier waiter and does not wait the read barrier)
        rwait = "12" if (srb == "2" and not behind) else "1"
        if younger:
            # version 17: the tested shuffle with NO write barrier, a younger shuffle with one `younger_gap` cycles behind
            # it, the reader that waits the YOUNGER one's barrier and takes both results (at stall s), then the rewrite of
            # the OLDER shuffle's source: the swept distance is waiter -> overwriter
            b.append(Ins(f"SHFL.{mode.upper()} PT, R8, R6, 0x1, 0x1f ;", ("shfl", "R8", "R6", mode, 1),
                         ctl=C(int(req.get("younger_gap", 1)), rb=srb, wb="-"), tag="S"))
            b.append(Ins(f"SHFL.{mode.upper()} PT, R13, R14, 0x1, 0x1f ;", ("shfl", "R13", "R14", mode, 1), ctl=C(wb="1")))
            b.append(Ins("IMAD R8, R13, 0x3, R8 ;", ("mad", "R8", "R13", 3, "R8"), ctl=C(s, wait="1")))
        elif ycover:
            # version 21 - two further covers of the vendor's text. The tested shuffle carries its own write barrier 1 and NO
            # read barrier (variant rb: read barrier 2, waited by the overwriter); `younger_gap` cycles behind it a younger
            # producer of the same unit - a shuffle with READ barrier 4 and write barrier 3 (younger_read) or a shared load
            # with write barrier 3 (younger_lds); a filler WAITS that barrier (4 / 3) at stall s; behind it the rewrite of
            # the tested shuffle's source (the swept distance = waiter -> overwriter); both results are read behind the
            # overwriter, behind a wait on both write barriers
            b.append(Ins(f"SHFL.{mode.upper()} PT, R8, R6, 0x1, 0x1f ;", ("shfl", "R8", "R6", mode, 1),
                         ctl=C(int(req.get("younger_gap", 1)), rb=srb, wb="1"), tag="S"))
            if ycover == "younger_read":
                b.append(Ins(f"SHFL.{mode.upper()} PT, R13, R14, 0x1, 0x1f ;", ("shfl", "R13", "R14", mode, 1), ctl=C(rb="4", wb="3")))
            else:      # slot 3 of the thread holds R20..R23
                b.append(Ins("LDS R13, [R9+0x30] ;", ("lds", "R13", "R9", 0x30, 1), ctl=C(wb="3")))
            b.append(Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(s, wait="4" if ycover == "younger_read" else "3")))
        elif behind:
            # version 16: the shuffle, then the reader of its result (it WAITS the shuffle's write barrier) at stall s, then
            # the rewrite of the source: the swept distance is waiter -> overwriter
            b.append(Ins(f"SHFL.{mode.upper()} PT, R8, R6, 0x1, 0x1f ;", ("shfl", "R8", "R6", mode, 1), ctl=C(rb=srb, wb="1"), tag="S"))
            b.append(Ins("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"), ctl=C(s, wait=rwait)))
        else:
            b.append(Ins(f"SHFL.{mode.upper()} PT, R8, R6, 0x1, 0x1f ;", ("shfl", "R8", "R6", mode, 1), ctl=C(s, rb=srb, wb="1"), tag="S"))
        b += fill
        if ctl:
            b.append(PAD())
        elif over == "LOP3":
            b.append(Ins("LOP3.LUT R6, R6, 0x5a5a5a5a, RZ, 0x3c, !PT ;", ("xor", "R6", "R6", 0x5a5a5a5a), ctl=C(wait=ow), tag="O"))
        elif over == "IADD3.it":
            b.append(Ins("IADD3 R6, PT, PT, R6, R7, RZ ;", ("add", "R6", "R6", "R7"), ctl=C(wait=ow), tag="O"))
        else:
            b.append(Ins(f"IADD3 R6, PT, PT, R6, 0x{LATE_CONST:x}, RZ ;", ("add", "R6", "R6", LATE_CONST), ctl=C(wait=ow), tag="O"))
        if ycover:
            b.append(Ins("IMAD R8, R13, 0x3, R8 ;", ("mad", "R8", "R13", 3, "R8"), ctl=C(wait="13")))
            b.append(ADD10(""))
        elif younger:
            b.append(ADD10(""))
        elif not behind:
            b.append(ADD10(rwait))
    elif store in WAW_STORES:
        # version 18 - write after write. tag S = the FIRST writer (write barrier 1) at stall s, tag O = the SECOND writer
        # d cycles behind it; bare: the second writer does not wait; ctl: it waits barrier 1; rb: no first writer (a filler
        # in its place). The reader of the register waits barrier 1 (+ 3: the read barrier of the store that prepared the
        # first writer's value; + 2: a scoreboarded second writer's own barrier).
        sw = "1" if ctl else ""
        if over == "IADD3.it":      # R7 = -(iteration index + 1) * the constant (R7 is 0 before the loop)
            b.append(Ins(f"IADD3 R7, PT, PT, R7, 0x{NEG_CONST:x}, RZ ;", ("add", "R7", "R7", NEG_CONST)))
        dreg, vreg, rwait = "R6", None, "1"
        if store == "LDS.dst":
            b.append(Ins("STS [R9+0x20], R4 ;", ("sts", "R9", 0x20, "R4", 1), ctl=C(rb="3")))
            vreg, rwait = "R4", "13"
            first = Ins("LDS R6, [R9+0x20] ;", ("lds", "R6", "R9", 0x20, 1), ctl=C(s, wb="1"), tag="S")
        elif store == "LDG.dst":
            b.append(Ins("STG.E desc[UR4][R16.64], R4 ;", ("stg", "R16", "R4"), ctl=C(rb="3")))
            vreg, rwait = "R4", "13"
            first = Ins("LDG.E R6, desc[UR4][R16.64] ;", ("ldg", "R6", "R16"), ctl=C(s, wb="1"), tag="S")
        elif store == "LDC.dst":
            first = Ins("LDC R6, c[0x0][0x388] ;", ("mov", "R6", SEED), ctl=C(s, wb="1"), tag="S")
        elif store == "S2R.dst":
            vreg = "R0"
            first = Ins("S2R R6, SR_TID.X ;", ("mov", "R6", "R0"), ctl=C(s, wb="1"), tag="S")
        elif store == "SHFL.dst":
            b.append(Ins("IMAD R14, R5, 0x3, R4 ;", ("mad", "R14", "R5", 3, "R4")))
            vreg = "R4"
            first = Ins("SHFL.BFLY PT, R6, R14, 0x1, 0x1f ;", ("shfl", "R6", "R14", "bfly", 1), ctl=C(s, wb="1"), tag="S")
        else:                       # LDS128.dst: slot 2 of the thread holds R20..R23 (prologue)
            b.append(Ins("IMAD R14, R5, 0x3, R4 ;", ("mad", "R14", "R5", 3, "R4")))
            dreg = "R24"
            first = Ins("LDS.128 R24, [R9+0x20] ;", ("lds", "R24", "R9", 0x20, 4), ctl=C(s, wb="1"), tag="S")
        b += front_ins(front, False)
        b.append(first if variant != "rb" else Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(s)))
        b += fill
        if over == "IADD3":
            if vreg:
                b.append(Ins(f"IADD3 R6, PT, PT, {vreg}, 0x{NEG_CONST:x}, RZ ;", ("add", "R6", vreg, NEG_CONST), ctl=C(wait=sw), tag="O"))
            else:                   # the seed - the constant, as an immediate
                b.append(Ins(f"IADD3 R6, PT, PT, RZ, 0x{(SEED + NEG_CONST) & 0xFFFFFFFF:x}, RZ ;", ("add", "R6", "RZ", (SEED + NEG_CONST) & 0xFFFFFFFF),
                             ctl=C(wait=sw), tag="O"))
        elif over == "IADD3.it":
            if vreg:
                b.append(Ins(f"IADD3 R6, PT, PT, {vreg}, R7, RZ ;", ("add", "R6", vreg, "R7"), ctl=C(wait=sw), tag="O"))
            else:
                b.append(Ins(f"IADD3 R6, PT, PT, R7, 0x{SEED:x}, RZ ;", ("add", "R6", "R7", SEED), ctl=C(wait=sw), tag="O"))
        elif over == "LDS":         # slot 3 of the thread holds R20..R23
            b.append(Ins("LDS R6, [R9+0x30] ;", ("lds", "R6", "R9", 0x30, 1), ctl=C(wait=sw, wb="2"), tag="O"))
            rwait += "2"
        elif over == "LDG":         # word B of the thread holds R20
            b.append(Ins("LDG.E R6, desc[UR4][R18.64] ;", ("ldg", "R6", "R18"), ctl=C(wait=sw, wb="2"), tag="O"))
            rwait += "2"
        else:                       # SHFL (behind LDS.128)
            b.append(Ins("SHFL.BFLY PT, R24, R14, 0x1, 0x1f ;", ("shfl", "R24", "R14", "bfly", 1), ctl=C(wait=sw, wb="2"), tag="O"))
            rwait += "2"
        b.append(Ins(f"IADD3 R10, PT, PT, R10, {dreg}, RZ ;", ("add", "R10", "R10", dreg), ctl=C(wait=rwait)))
    elif store == "STS.addr":
        b += [Ins("IADD3 R6, PT, PT, R4, R5, RZ ;", ("add", "R6", "R4", "R5")),
              Ins("IADD3 R7, PT, PT, R9, 0x20, RZ ;", ("add", "R7", "R9", 0x20))]
        b += front_ins(front, False)
        b.append(Ins("STS [R7], R6 ;", ("sts", "R7", 0, "R6", 1), ctl=C(s, rb=rb), tag="S"))
        b += fill
        if ctl:
            b.append(PAD())
        elif over == "LDS":      # word 3 of slot 3 holds the address of slot 3 (prologue): the load brings the OTHER address
            b.append(Ins("LDS R7, [R9+0x3c] ;", ("lds", "R7", "R9", 0x3c, 1), ctl=C(wait=ow, wb="3"), tag="O"))
        else:
            b.append(Ins("IADD3 R7, PT, PT, R9, 0x30, RZ ;", ("add", "R7", "R9", 0x30), ctl=C(wait=ow), tag="O"))
        b += [Ins("LDS R8, [R9+0x20] ;", ("lds", "R8", "R9", 0x20, 1), ctl=C(wait="3" if (over == "LDS" and not ctl) else "", wb="0")),
              Ins("LDS R13, [R9+0x30] ;", ("lds", "R13", "R9", 0x30, 1), ctl=C(wb="1"), tag="B"),
              Ins("IMAD R8, R13, 0x3, R8 ;", ("mad", "R8", "R13", 3, "R8"), ctl=C(wait="01")), ADD10()]
    elif store == "STG.addr":
        b += [Ins("IADD3 R14, PT, PT, R4, R5, RZ ;", ("add", "R14", "R4", "R5")),
              Ins("MOV R6, R16 ;", ("mov", "R6", "R16")), Ins("MOV R7, R17 ;", ("mov", "R7", "R17"))]
        b += front_ins(front, True)
        b.append(Ins("STG.E desc[UR4][R6.64], R14 ;", ("stg", "R6", "R14"), ctl=C(s, rb=rb), tag="S"))
        b += fill
        if ctl:
            b += [PAD(), PAD()]
        else:
            b += [Ins("MOV R6, R18 ;", ("mov", "R6", "R18"), ctl=C(wait=ow), tag="O"), Ins("MOV R7, R19 ;", ("mov", "R7", "R19"))]
        b += [Ins("LDG.E R8, desc[UR4][R16.64] ;", ("ldg", "R8", "R16"), ctl=C(wb="0")),
              Ins("LDG.E R13, desc[UR4][R18.64] ;", ("ldg", "R13", "R18"), ctl=C(wb="1"), tag="B"),
              Ins("IMAD R8, R13, 0x3, R8 ;", ("mad", "R8", "R13", 3, "R8"), ctl=C(wait="01")), ADD10()]
    elif store == "STS.ubase":
        # version 25: a shared store through a UNIFORM base register; UMOV rewrites the base d cycles behind it.
        # Every lane of the warp stores the SAME value (R4 - lane = the iteration's input of lane 0) through UR6 = the address of lane 0's
        # line: ONE word per warp (offset 0x24 of that line; its first content is the prologue's constant 0x0f0f0f0f in every thread). The
        # rewritten base is the CTA's offset 0x10: a store that takes it goes to word 0x34 of the CTA - slot 3 of thread 0, which nothing of
        # this body reads. Both places are valid shared memory of the CTA: a late read of the base shows as the warp's word NOT written
        # (the read-back, through a general register, then gives the last iteration's value). The store carries read barrier 2 in every
        # variant (the vendor's shape): bare = the overwriter does not wait it, rb = it does, ctl = no overwriter.
        # The model: the thread's own line stands for lane 0's (the same values in every lane), UR6 = 0 or 0x10.
        b += [Ins("LOP3.LUT R24, R0, 0x1f, RZ, 0xc0, !PT ;", ("and", "R24", "R0", 31)),
              Ins("IADD3 R6, PT, PT, -R24, R4, RZ ;", ("rsub", "R6", "R24", "R4")),
              Ins("IMAD R25, R24, -0x40, R9 ;", ("mov", "R25", "R9")),
              Ins("R2UR UR6, R25 ;", ("mov", "UR6", "R9")), PAD(), PAD()]
        b += front_ins(front, False)
        if over == "UMOV.front" and not ctl:      # the POSITIVE CONTROL: the rewrite 45 cycles IN FRONT of the store, the model ignoring it
            b += [Ins("UMOV UR6, 0x10 ;", ("nop",)), PAD(), PAD()]
        b.append(Ins("STS [UR6+0x24], R6 ;", ("sts", "UR6", 0x24, "R6", 1), ctl=C(s, rb="2"), tag="S"))
        b += fill
        if ctl or over == "UMOV.front":
            b.append(PAD())
        else:
            b.append(Ins("UMOV UR6, 0x10 ;", ("mov", "UR6", 0x10), ctl=C(wait=ow), tag="O"))
        b += [Ins("LDS R8, [R25+0x24] ;", ("lds", "R8", "R9", 0x24, 1), ctl=C(wb="1"), tag="B"), ADD10("12")]
    return b


MMA_FORMS = {"QMMA.SF.E4M3.E2M1": "QMMA.SF.16832.F32.E4M3.E2M1.E8", "HMMA.F16": "HMMA.16816.F32", "HMMA.BF16": "HMMA.16816.F32.BF16"}
# per form: the A fragment word on even iterations and what an odd iteration adds (1.0 -> 2.0 in every element), the B1 / B2
# words (1.0 / 2.0 in every element), the reduction length K (a result element = accumulator + K * a * b), the element
# mask of a fragment word and the value of its codes
MMA_SPEC = {"QMMA.SF.E4M3.E2M1": dict(a0=0x38383838, da=0x08080808, b1=0x08080808, b2=0x10101010, k=32, amask=0xFF, bmask=0xFF,
                                      aval={0x38: 1, 0x40: 2}, bval={0x08: 1, 0x10: 2}),
            "HMMA.F16": dict(a0=0x3c003c00, da=0x04000400, b1=0x3c003c00, b2=0x40004000, k=16, amask=0xFFFF, bmask=0xFFFF,
                             aval={0x3c00: 1, 0x4000: 2}, bval={0x3c00: 1, 0x4000: 2}),
            "HMMA.BF16": dict(a0=0x3f803f80, da=0x00800080, b1=0x3f803f80, b2=0x40004000, k=16, amask=0xFFFF, bmask=0xFFFF,
                              aval={0x3f80: 1, 0x4000: 2}, bval={0x3f80: 1, 0x4000: 2})}
MMA_VARIANTS = {"acc2": "another accumulator, the same A fragment, another B fragment (the served loops)",
                "chain": "the SAME accumulator in both (the accumulate chain)",
                "guard": "both under a guard, two different predicates, both true",
                "gfalse": "the second under a guard that is false (it must change nothing)",
                # the operand HOLD of an MMA: ONE MMA, and d cycles behind it a fixed-latency instruction rewrites a register
                # of its A or B fragment (the MMA must have read it: the result may not change)
                "hold_a_mov": "one MMA; MOV rewrites a register of its A fragment d cycles behind it",
                "hold_a_iadd3": "one MMA; IADD3 rewrites a register of its A fragment d cycles behind it",
                "hold_b_mov": "one MMA; MOV rewrites a register of its B fragment d cycles behind it",
                "hold_b_iadd3": "one MMA; IADD3 rewrites a register of its B fragment d cycles behind it",
                "hold_b_shf": "one MMA; SHF.R.U32.HI rewrites the upper register of its B fragment from the lower one, d cycles behind it",
                "hold_bl_mov": "one MMA; MOV rewrites the LOWER register of its B fragment d cycles behind it",
                # version 23: a LOAD as the overwriter (on write barrier 1, waited before the next iteration; its result lands late)
                "hold_a_lds": "one MMA; LDS rewrites a register of its A fragment d cycles behind it",
                "hold_a_ldsm": "one MMA; LDSM.16.M88.4 rewrites its whole A fragment d cycles behind it",
                "hold_b_lds": "one MMA; LDS rewrites the upper register of its B fragment d cycles behind it",
                "hold_bl_lds": "one MMA; LDS rewrites the LOWER register of its B fragment d cycles behind it",
                "hold_b_ldsm": "one MMA; LDSM.16.M88.4 rewrites the quad that holds its B fragment d cycles behind it",
                # positive controls: the same rewrite 45 cycles IN FRONT of the MMA. The model ignores the rewrite, so `good` here
                # means "the rewritten register is not part of what the MMA reads" - a hold result on that register would be void
                "sens_a_mov": "CONTROL: MOV rewrites the A-fragment register IN FRONT of the MMA (the result must change: expect 0 % good)",
                # version 24, fifth build: the accumulator behind the word - the word's result goes to ANOTHER quad (R24..R27)
                "hold_c_mov": "one MMA whose result goes to another quad; MOV rewrites a register of its ACCUMULATOR d cycles behind it",
                "sens_c_mov": "CONTROL: MOV rewrites the accumulator register IN FRONT of the MMA whose result goes to another quad (expect 0 % good)",
                # version 25: overwriters of an accumulator register that the vendor's own schedules place 8 cycles behind a tensor word
                "hold_c_cs2r": "one MMA whose result goes to another quad; the 64-bit CS2R Rn, SRZ zeroes TWO registers of its ACCUMULATOR d cycles behind it",
                "sens_c_cs2r": "CONTROL: the 64-bit CS2R zeroes the two accumulator registers IN FRONT of the MMA whose result goes to another quad (expect 0 % good)",
                "hold_c_prmt": "one MMA whose result goes to another quad; PRMT rewrites a register of its ACCUMULATOR d cycles behind it",
                "sens_c_prmt": "CONTROL: PRMT rewrites the accumulator register IN FRONT of the MMA whose result goes to another quad (expect 0 % good)",
                # version 25, fifth build: the UNIFORM operand (the selector) of a QMMA.SF behind the word - RELATIVE
                "hold_u_umov": "one QMMA.SF with a uniform selector (UR6 = 9) against the SAME word 60 cycles in front of it; UMOV UR6, 0x0 rewrites the selector d cycles behind it",
                "sens_u_umov": "CONTROL: UMOV UR6, 0x0 rewrites the selector 60 cycles IN FRONT of the QMMA.SF, 60 cycles behind the word it is compared with (expect 0 % good)",
                "sens_b_mov": "CONTROL: MOV rewrites the upper B-fragment register IN FRONT of the MMA (expect 0 % good)",
                "sens_b_shf": "CONTROL: SHF.R.U32.HI rewrites the upper B-fragment register IN FRONT of the MMA (expect 0 % good)",
                "sens_bl_mov": "CONTROL: MOV rewrites the LOWER B-fragment register IN FRONT of the MMA (expect 0 % good)",
                "sens_a_lds": "CONTROL: LDS rewrites the A-fragment register IN FRONT of the MMA and is waited (expect 0 % good)",
                "sens_a_ldsm": "CONTROL: LDSM.16.M88.4 rewrites the A fragment IN FRONT of the MMA and is waited (expect 0 % good)",
                "sens_b_lds": "CONTROL: LDS rewrites the upper B-fragment register IN FRONT of the MMA and is waited (expect 0 % good)",
                "sens_bl_lds": "CONTROL: LDS rewrites the LOWER B-fragment register IN FRONT of the MMA and is waited (expect 0 % good)",
                "sens_b_ldsm": "CONTROL: LDSM.16.M88.4 rewrites the quad of the B fragment IN FRONT of the MMA and is waited (expect 0 % good)"}


C_HOLD_VARIANTS = ("hold_c_mov", "sens_c_mov", "hold_c_cs2r", "sens_c_cs2r", "hold_c_prmt", "sens_c_prmt")      # version 25
U_HOLD_VARIANTS = ("hold_u_umov", "sens_u_umov")      # version 25, fifth build


def mma_load_over(var, tgt, sem=None):
    """version 23: the LOAD that rewrites a fragment register of an MMA (variants ending in _lds / _ldsm), on write barrier
    1: LDS brings word 0 of slot 2 of the thread's line (the thread's constant - not a fragment code), LDSM.16.M88.4 the
    quad of slot 3 into the whole A fragment (R16..R19) or into the quad of the B fragment (R12..R15)."""
    if var.endswith("_ldsm"):
        q0 = "R16" if "_a_" in var else "R12"
        return Ins(f"LDSM.16.M88.4 {q0}, [R9+0x30] ;", sem or ("poison", q0, 4), ctl=C(wb="1"), tag="O")
    return Ins(f"LDS {tgt}, [R9+0x20] ;", sem or ("lds", tgt, "R9", 0x20, 1), ctl=C(wb="1"), tag="O")


def mma_b_restore(sp):
    """version 23: an LDSM into R12..R15 rewrote the whole quad: both B registers and the scale register are set again"""
    return [Ins(f"MOV R12, 0x{sp['b1']:x} ;", ("mov", "R12", sp["b1"])), Ins(f"MOV R13, 0x{sp['b1']:x} ;", ("mov", "R13", sp["b1"])),
            Ins("MOV R14, 0x7f7f7f7f ;", ("mov", "R14", 0x7f7f7f7f))]


MMAFRONT_RE = re.compile(r"mmax(\d+)@(\d+)")


def mma_front(front):
    """the tensor traffic in front of the MMA of a hold request: `mmaxK@S` = K MMAs of the same form on ANOTHER accumulator
    (R24, the same A fragment, the B2 fragment), stall S each - the tested MMA is issued S cycles behind the last of them.
    -> (K, S); (0, 0) for none"""
    if front in ("none", "", None):
        return 0, 0
    m = MMAFRONT_RE.fullmatch(front)
    if not m:
        raise SystemExit(f"unknown front {front!r} for an mma hold request: none | mmaxK@S")
    k, s = int(m.group(1)), int(m.group(2))
    if not (1 <= k <= 16 and 1 <= s <= 15):
        raise SystemExit(f"front {front!r}: K 1..16, S 1..15")
    return k, s


def body_mma(req, d, front="none"):
    """two block-scaled MMAs of one warp, d issue cycles apart. Every element of the A fragment is the same E4M3 code
    (1.0 on even iterations, 2.0 on odd), of the B fragments the same E2M1 code (B1 1.0, B2 2.0), the block scales are 1,
    and the accumulators are integer-valued floats 2^23 + k (k per thread and register): each result is its accumulator
    + 32 * a * b - an INTEGER add on the bit pattern, exact, whatever the fragment layout is."""
    form, var, fn, sp = MMA_FORMS[req["form"]], req["variant"], req["form"], MMA_SPEC[req["form"]]
    if fn.startswith("QMMA"):
        q = lambda rd, rb: f"{form} {rd}, R16, {rb}, {rd}, R14, R14, URZ ;"
    else:
        q = lambda rd, rb: f"{form} {rd}, R16, {rb}, {rd} ;"
    b = [Ins("LOP3.LUT R0, R11, 0x1, RZ, 0xc0, !PT ;", ("and", "R0", "R11", 1)),
         Ins(f"IMAD R16, R0, 0x{sp['da']:x}, RZ ;", ("mad", "R16", "R0", sp["da"], "RZ")),
         Ins(f"IADD3 R16, PT, PT, R16, 0x{sp['a0']:x}, RZ ;", ("add", "R16", "R16", sp["a0"])),
         Ins("MOV R17, R16 ;", ("mov", "R17", "R16")), Ins("MOV R18, R16 ;", ("mov", "R18", "R16")), Ins("MOV R19, R16 ;", ("mov", "R19", "R16")),
         Ins("LOP3.LUT R28, R4, 0x3fffff, RZ, 0xc0, !PT ;", ("and", "R28", "R4", 0x3fffff)),
         Ins("LOP3.LUT R28, R28, 0x4b000000, RZ, 0xfc, !PT ;", ("or", "R28", "R28", 0x4b000000)),
         Ins("IADD3 R29, PT, PT, R28, 0x1, RZ ;", ("add", "R29", "R28", 1)), Ins("IADD3 R30, PT, PT, R28, 0x2, RZ ;", ("add", "R30", "R28", 2)),
         Ins("IADD3 R31, PT, PT, R28, 0x3, RZ ;", ("add", "R31", "R28", 3)),
         Ins("LOP3.LUT R24, R5, 0x3fffff, RZ, 0xc0, !PT ;", ("and", "R24", "R5", 0x3fffff)),
         Ins("LOP3.LUT R24, R24, 0x4b000000, RZ, 0xfc, !PT ;", ("or", "R24", "R24", 0x4b000000)),
         Ins("IADD3 R25, PT, PT, R24, 0x1, RZ ;", ("add", "R25", "R24", 1)), Ins("IADD3 R26, PT, PT, R24, 0x2, RZ ;", ("add", "R26", "R24", 2)),
         Ins("IADD3 R27, PT, PT, R24, 0x3, RZ ;", ("add", "R27", "R24", 3)),
         PAD(), PAD()]
    if var in U_HOLD_VARIANTS:      # (version 25, fifth build) the uniform operand - the selector - of a QMMA.SF behind the word, RELATIVE
        # Y = the word on R24..R27, 45 cycles behind `UMOV UR6, 0x9`; X = the SAME word (the same accumulator values, fragments and
        # scale register) on R28..R31, 60 cycles behind Y; `UMOV UR6, 0x0` - another valid selector - d cycles behind X. The checksum
        # takes fold(X ^ Y) + the iteration's input: the host need not know what a selector does, an X that took the rewritten
        # selector differs from Y. The scale register: bytes 0x7f + m, 0x80 + m, 0x7e + m, 0x7d + m with m = lane & 3 (the u6 body of
        # version 24) - without different scales no selector is seen. CONTROL: the UMOV 60 cycles in front of X and 60 behind Y.
        qu = lambda rd: f"{form} {rd}, R16, R12, {rd}, R14, R14, UR6 ;"
        acc4 = ["R28", "R29", "R30", "R31"]
        b = b[:-2] + [Ins(f"MOV R{24 + k}, R{28 + k} ;", ("mov", f"R{24 + k}", f"R{28 + k}")) for k in range(4)]
        b += [Ins("LOP3.LUT R14, R1, 0x3, RZ, 0xc0, !PT ;", ("nop",)), Ins("IMAD R14, R14, 0x1010101, RZ ;", ("nop",)),
              Ins("IADD3 R14, PT, PT, R14, 0x7d7e807f, RZ ;", ("nop",)),
              Ins("UMOV UR6, 0x9 ;", ("mov", "UR6", 9)), PAD(), PAD(),
              Ins(qu("R24"), ("qmma", "R24", "R16", "R12", None, fn)), PAD(), PAD(), PAD()]
        if var.startswith("sens_"):      # (the model ignores the rewrite: `good` would mean "the selector is not read")
            b += [Ins("UMOV UR6, 0x0 ;", ("nop",)), PAD(), PAD(), PAD(),
                  Ins(qu("R28"), ("qmma", "R28", "R16", "R12", None, fn), tag="P", dst=acc4)]
        else:
            s, fill = split_distance(d)
            b.append(Ins(qu("R28"), ("qmma", "R28", "R16", "R12", None, fn), ctl=C(s, y=req.get("yield") == "set"), tag="P", dst=acc4))
            b += fill
            b.append(Ins("UMOV UR6, 0x0 ;", ("mov", "UR6", 0), tag="O"))
        b += [PAD(), PAD(), PAD()]
        b += [Ins("LOP3.LUT R0, R28, R24, RZ, 0x3c, !PT ;", ("xor", "R0", "R28", "R24")), Ins("LOP3.LUT R7, R29, R25, RZ, 0x3c, !PT ;", ("xor", "R7", "R29", "R25")),
              Ins("IMAD R8, R7, 0x3, R0 ;", ("mad", "R8", "R7", 3, "R0")),
              Ins("LOP3.LUT R0, R30, R26, RZ, 0x3c, !PT ;", ("xor", "R0", "R30", "R26")), Ins("IMAD R8, R0, 0x5, R8 ;", ("mad", "R8", "R0", 5, "R8")),
              Ins("LOP3.LUT R7, R31, R27, RZ, 0x3c, !PT ;", ("xor", "R7", "R31", "R27")), Ins("IMAD R8, R7, 0x7, R8 ;", ("mad", "R8", "R7", 7, "R8")),
              Ins("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8")), Ins("IADD3 R10, PT, PT, R10, R4, RZ ;", ("add", "R10", "R10", "R4"))]
        return b
    if var in C_HOLD_VARIANTS:      # (version 24, fifth build; version 25: the vendor's overwriters, "dest") the accumulator R28..R31 behind a word whose result goes to another quad
        creg = f"R{28 + int(req.get('reg') or 0)}"
        d0 = 16 if req.get("dest") == "a" else 24      # (version 25) "dest": "a" - the result goes to the word's own A quad (a form of the vendor's kernels)
        word = f"{form} R{d0}, R16, R12, R28, R14, R14, URZ ;" if fn.startswith("QMMA") else f"{form} R{d0}, R16, R12, R28 ;"
        wsem = ("tmma", f"R{d0}", "R16", "R12", fn, "R28")
        dq = [f"R{d0 + k}" for k in range(4)]
        foldc = [Ins(f"IMAD R8, {dq[1]}, 0x3, {dq[0]} ;", ("mad", "R8", dq[1], 3, dq[0])), Ins(f"IMAD R8, {dq[2]}, 0x5, R8 ;", ("mad", "R8", dq[2], 5, "R8")),
                 Ins(f"IMAD R8, {dq[3]}, 0x7, R8 ;", ("mad", "R8", dq[3], 7, "R8")), Ins("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"))]
        if var.endswith("_cs2r"):      # the vendor's `CS2R R50, SRZ`: the 64-bit form zeroes the register and the next one
            otext, osem = f"CS2R {creg}, SRZ ;", ("zero2", creg)
        elif var.endswith("_prmt"):    # the vendor's `PRMT R34, R24, 0x5140, R25`: bytes of two other registers (R6, R7 hold the B2 word - not an accumulator's content)
            otext, osem = f"PRMT {creg}, R6, 0x5140, R7 ;", ("prmt", creg, "R6", 0x5140, "R7")
        else:
            otext, osem = f"MOV {creg}, R6 ;", ("mov", creg, "R6")
        if var.startswith("sens_"):      # (the model ignores the rewrite: `good` would mean "the register is not read")
            return b + [Ins(otext, ("nop",)), PAD(), PAD(), PAD(),
                        Ins(word, wsem, tag="P", dst=dq), PAD(), PAD(), PAD()] + foldc
        s, fill = split_distance(d)
        b.append(Ins(word, wsem, ctl=C(s, y=req.get("yield") == "set"), tag="P", dst=dq))
        b += fill
        b.append(Ins(otext, osem, tag="O"))
        return b + [PAD(), PAD(), PAD()] + foldc
    if var.startswith("sens_"):
        if var == "sens_b_ldsm":      # version 23
            b[0:0] = mma_b_restore(sp)
        elif var.startswith("sens_bl"):
            b.insert(0, Ins("MOV R12, R13 ;", ("mov", "R12", "R13")))
        elif var.startswith("sens_b"):
            b.insert(0, Ins("MOV R13, R12 ;", ("mov", "R13", "R12")))
        tgt = "R17" if var.startswith("sens_a") else "R12" if var.startswith("sens_bl") else "R13"
        if var == "sens_a_mov" and req.get("reg") is not None:      # (version 24, fourth build) the rewritten register of the A quad
            tgt = f"R{16 + req['reg']}"
        if var.endswith(("_lds", "_ldsm")):      # version 23: the load, and a word that waits it (the model ignores the rewrite)
            b.append(mma_load_over(var, tgt, ("nop",)))
            b.append(Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="1")))
        else:
            b.append(Ins("SHF.R.U32.HI R13, RZ, 0x5, R12 ;", ("nop",)) if var.endswith("_shf") else Ins(f"MOV {tgt}, R6 ;", ("nop",)))
        b += [PAD(), PAD(), PAD()]
        b.append(Ins(q("R28", "R12"), ("qmma", "R28", "R16", "R12", None, fn), tag="P", dst=["R28", "R29", "R30", "R31"]))
        b += [PAD(), PAD(), PAD()]
        for t, sem in (("IMAD R8, R29, 0x3, R28 ;", ("mad", "R8", "R29", 3, "R28")), ("IMAD R8, R30, 0x5, R8 ;", ("mad", "R8", "R30", 5, "R8")),
                       ("IMAD R8, R31, 0x7, R8 ;", ("mad", "R8", "R31", 7, "R8")), ("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"))):
            b.append(Ins(t, sem))
        return b
    if var.startswith("hold_"):
        if var == "hold_b_ldsm":      # version 23
            b[0:0] = mma_b_restore(sp)
        elif var.startswith("hold_bl"):
            b.insert(0, Ins("MOV R12, R13 ;", ("mov", "R12", "R13")))      # the lower B register of the last iteration's overwrite
        elif var.startswith("hold_b"):
            b.insert(0, Ins("MOV R13, R12 ;", ("mov", "R13", "R12")))      # the B register of the last iteration's overwrite
        s, fill = split_distance(d)
        fk, fs = mma_front(front)
        for _ in range(fk):       # the traffic: K MMAs in front, another accumulator (not part of the checksum)
            b.append(Ins(q("R24", "R6"), ("qmma", "R24", "R16", "R6", None, fn), ctl=C(fs), tag="F"))
        b.append(Ins(q("R28", "R12"), ("qmma", "R28", "R16", "R12", None, fn), ctl=C(s, y=req.get("yield") == "set"), tag="P", dst=["R28", "R29", "R30", "R31"]))
        b += fill
        tgt = "R17" if var.startswith("hold_a") else "R12" if var.startswith("hold_bl") else "R13"
        if var == "hold_a_mov" and req.get("reg") is not None:      # (version 24, fourth build) the rewritten register of the A quad
            tgt = f"R{16 + req['reg']}"
        if var.endswith("_mov"):       # R6 = the B2 word: another finite code in every element
            b.append(Ins(f"MOV {tgt}, R6 ;", ("mov", tgt, "R6"), tag="O"))
        elif var.endswith("_shf"):
            b.append(Ins("SHF.R.U32.HI R13, RZ, 0x5, R12 ;", ("shr", "R13", "R12", 5), tag="O"))
        elif var.endswith(("_lds", "_ldsm")):      # version 23: a LOAD as the overwriter; the next word waits it (the next iteration rewrites the register)
            b.append(mma_load_over(var, tgt))
            b.append(Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="1")))
        else:
            b.append(Ins(f"IADD3 {tgt}, PT, PT, {tgt}, 0x8080808, RZ ;", ("add", tgt, tgt, 0x08080808), tag="O"))
        b += [PAD(), PAD(), PAD()]
        for t, sem in (("IMAD R8, R29, 0x3, R28 ;", ("mad", "R8", "R29", 3, "R28")), ("IMAD R8, R30, 0x5, R8 ;", ("mad", "R8", "R30", 5, "R8")),
                       ("IMAD R8, R31, 0x7, R8 ;", ("mad", "R8", "R31", 7, "R8")), ("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"))):
            b.append(Ins(t, sem))
        return b
    g1 = "@P0 " if var in ("guard", "gfalse") else ""
    g2 = {"guard": "@P2 ", "gfalse": "@P3 "}.get(var, "")
    rd2 = "R28" if var == "chain" else "R24"
    if req.get("via", "stall") == "nop":      # the vendor's shape: the first MMA, a NOP of one cycle, the second
        npad = (d - 2) // 15
        s = d - 1 - 15 * npad
        fill = [Ins("NOP ;", ("nop",), ctl=C(1))] + [PAD() for _ in range(npad)]
    else:
        s, fill = split_distance(d)
    b.append(Ins(g1 + q("R28", "R12"), ("qmma", "R28", "R16", "R12", "P0" if g1 else None, fn), ctl=C(s, y=req.get("yield") == "set"), tag="P",
                 dst=["R28", "R29", "R30", "R31"]))
    b += fill
    b.append(Ins(g2 + q(rd2, "R6"), ("qmma", rd2, "R16", "R6", g2.strip("@ ") or None, fn), tag="C"))
    b += [PAD(), PAD(), PAD()]      # a reader of an MMA result is 45 cycles behind the second (the table's row: 28)
    for t, sem in (("IMAD R8, R29, 0x3, R28 ;", ("mad", "R8", "R29", 3, "R28")), ("IMAD R8, R30, 0x5, R8 ;", ("mad", "R8", "R30", 5, "R8")),
                   ("IMAD R8, R31, 0x7, R8 ;", ("mad", "R8", "R31", 7, "R8")), ("IMAD R8, R24, 0xb, R8 ;", ("mad", "R8", "R24", 11, "R8")),
                   ("IMAD R8, R25, 0xd, R8 ;", ("mad", "R8", "R25", 13, "R8")), ("IMAD R8, R26, 0x11, R8 ;", ("mad", "R8", "R26", 17, "R8")),
                   ("IMAD R8, R27, 0x13, R8 ;", ("mad", "R8", "R27", 19, "R8")), ("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8"))):
        b.append(Ins(t, sem))
    return b




# ------------------------------------------------------------------------------------------------ kind thr (version 26)
# A THROUGHPUT probe. Not "is the result right at distance d" but the TIME of a synthetic stage loop with tensor words in
# which ONE thing changes per slot. The slot number rides in the "distance" slot of the kernel index (the runner groups
# kernels by that integer and writes the median launch time per kernel: `launch_us_median_by_distance`); slot 1 is the
# base stage and the last slot of a stage is the base stage again (the null). Every slot of a stage computes the SAME
# checksum (only control codes differ), and every slot keeps the table's cells and the holds - checked by `thr_audit`
# for every kernel that is written: a slot that breaks one is not a throughput variant, it is a wrong kernel.
#
# The kernel: prologue; L_outer: INIT (the inputs R4 / R5, the counter R11, four accumulator quads); L_loop: the stage
# iteration x 256; POST (the 16 accumulator registers folded into the checksum R10); the outer counter and branch. Every
# pass adds the same amount D to R10 (INIT sets again every register the inner loop carries; R10 is never reset), so a
# thread ends with repeat x D mod 2^32 - repeat is ODD, so nothing of D is lost and a wrong pass anywhere shows.
#
# The stage iteration (stage "a": 100 static issue cycles, 38 words): the A quad R16..R19 toggles between the codes of 1.0
# and 2.0; the B pairs R12:R13 / R6:R7 are made by PRMT + LOP3.LUT (the vendor's words) from a source word that toggles;
# four QMMA.SF words on four accumulator quads, 16 cycles apart (the table's resource row); ONE LDS.128 on write barrier 1
# into a quad whose first register was dirtied in front (a reader that did not wait would take the dirt); five IMAD words
# fold one result register of each quad (of the previous iteration) and the loaded word into R10, weighted by the
# iteration's inputs; the counter tail, ISETP, BRA.
THR_REGS = 48                                  # R0-R47, .regcount 56: 1 024 threads per SM x 56 registers <= 65 536
THR_A0, THR_AX = 0x38383838, 0x78787878        # QMMA.SF E4M3: the code of 1.0 in every element, and what toggles it to 2.0
THR_S0, THR_SX = 0x10100808, 0x18181818        # the source word of the B pairs (bytes 08 08 10 10) and its toggle
THR_QUADS = (28, 24, 32, 36)                   # the accumulator quad of tensor word k
THR_OCC = ("w1", "w2", "w4", "w8", "w9", "w12", "w16", "w32", "c2w9s", "c4w8")
THR_FREE16 = ["G2a", "G2b", "G2c", "G2d", "G3a", "G3b", "G3c", "G3d", "T0", "T1", "T2", "I0", "D0", "A0", "A1", "A2"]
THR_FLY8 = ["G0a", "F1", "G0b", "G1a", "G1b", "G0c", "F2", "G0d"]
THR_RBW = ["G2a", "G2b", "G3a", "G3b", "A0", "A1", "A2", "A3", "G0a", "G0b", "G1a", "G1b"]
THR_X = ["X0", "X1", "X2", "X3"]
# stage -> the slots in order: (name, what changes against the base stage)
THR_STAGES = {
    "a": [("base", "the base stage: the load's reader waits write barrier 1, nothing else waits; the yield flag on every word with a stall <= 11 but the NOP"),
          ("a1_1", "1 word waits on write barrier 1 BEHIND its reader's wait (a FREE barrier)"),
          ("a1_2", "2 words wait on the free barrier 1"),
          ("a1_4", "4 words wait on the free barrier 1"),
          ("a1_8", "8 words wait on the free barrier 1"),
          ("a1_16", "16 words wait on the free barrier 1"),
          ("a1n_16", "the same 16 words wait on barrier 5, which no word of the loop arms"),
          ("a2_1", "1 word between the load and its reader waits on the load's barrier IN FLIGHT"),
          ("a2_2", "2 words between the load and its reader wait on the load in flight"),
          ("a2_4", "4 words between the load and its reader wait on the load in flight"),
          ("a2_8", "8 words between the load and its reader wait on the load in flight"),
          ("a3_r", "each of the 4 tensor words arms READ barrier 2; nothing waits on it"),
          ("a3_w", "each tensor word arms read barrier 2 and the 12 words that rewrite a tensor word's source register wait on it"),
          ("a3_d", "as a3_w, and each tensor word waits on read barrier 2 before it arms it again"),
          ("a4", "the LDS.128 waits on its own write barrier 1 before it arms it again"),
          ("a_all", "a1_16 + a3_d + a4 together (NOT one change: the sum check)"),
          ("b_none", "NO yield flag on any word"),
          ("b_tensor", "the yield flag ONLY on the tensor words (stall <= 11)"),
          ("b_alt", "the yield flag on every second word that may carry it"),
          ("base2", "the base stage again (the null of the series)")],
    "e": [("base", "the EMPTY stage: the counter tail, ISETP and BRA only (the loop's skeleton)")],
}


def thr_words(req):
    """the words of one stage iteration: [(issue cycle, key, text, sem)] and the static cycles of the iteration"""
    fn = req["form"]
    form = MMA_FORMS[fn]
    tail = [("T0", TAIL[0]), ("T1", TAIL[1]), ("T2", TAIL[2])]
    isetp = f"ISETP.LT.U32.AND P1, PT, R11, 0x{REPEAT:x}, PT ;"
    if req["stage"] == "e":
        w = [(0, "T0", tail[0][1].text, tail[0][1].sem), (1, "T1", tail[1][1].text, tail[1][1].sem), (2, "T2", tail[2][1].text, tail[2][1].sem),
             (8, "I0", isetp, ("nop",)), (21, "B0", "@P1 BRA L_loop ;", ("nop",))]
        return w, 25
    q = lambda k, rb: (f"{form} R{THR_QUADS[k]}, R16, {rb}, R{THR_QUADS[k]}, R14, R14, URZ ;", ("qmma", f"R{THR_QUADS[k]}", "R16", rb, None, fn))
    tog = lambda r, c: (f"LOP3.LUT {r}, {r}, 0x{c:x}, RZ, 0x3c, !PT ;", ("xor", r, r, c))
    prm = lambda r, sel: (f"PRMT {r}, R44, 0x{sel:x}, R44 ;", ("prmt", r, "R44", sel, "R44"))
    msk = lambda r: (f"LOP3.LUT {r}, {r}, 0x3c3c3c3c, RZ, 0xc0, !PT ;", ("and", r, r, 0x3c3c3c3c))
    fold = lambda r, x: (f"IMAD R10, {r}, {x}, R10 ;", ("mad", "R10", r, x, "R10"))
    w = [(0, "D0", "LOP3.LUT R40, R4, R5, RZ, 0x3c, !PT ;", ("xor", "R40", "R4", "R5")),
         (1, "A0") + tog("R16", THR_AX), (2, "A1") + tog("R17", THR_AX), (3, "A2") + tog("R18", THR_AX), (4, "A3") + tog("R19", THR_AX),
         (5, "S0") + tog("R44", THR_SX),
         (6, "F0") + fold(f"R{THR_QUADS[0]}", "R4"),
         (8, "L0", "LDS.128 R40, [R9+0x10] ;", ("lds", "R40", "R9", 0x10, 4)),
         (11, "G0a") + prm("R12", 0x1010), (12, "F1") + fold(f"R{THR_QUADS[1] + 1}", "R4"), (13, "G0b") + prm("R13", 0x1010),
         (14, "G1a") + prm("R6", 0x3232), (15, "G1b") + prm("R7", 0x3232),
         (17, "G0c") + msk("R12"), (18, "F2") + fold(f"R{THR_QUADS[2] + 2}", "R5"), (19, "G0d") + msk("R13"),
         (20, "G1c") + msk("R6"), (21, "G1d") + msk("R7"),
         (24, "F3") + fold(f"R{THR_QUADS[3] + 3}", "R5"),
         (26, "X0") + q(0, "R12"),
         (30, "FL") + fold("R40", "R5"),
         (34, "G2a") + prm("R12", 0x1010), (35, "G2b") + prm("R13", 0x1010), (40, "G2c") + msk("R12"), (41, "G2d") + msk("R13"),
         (42, "X1") + q(1, "R6"),
         (50, "G3a") + prm("R6", 0x3232), (51, "G3b") + prm("R7", 0x3232), (56, "G3c") + msk("R6"), (57, "G3d") + msk("R7"),
         (58, "X2") + q(2, "R12"),
         (73, "N0", "NOP ;", ("nop",)),
         (74, "X3") + q(3, "R6"),
         (75, "T0", tail[0][1].text, tail[0][1].sem), (76, "T1", tail[1][1].text, tail[1][1].sem), (77, "T2", tail[2][1].text, tail[2][1].sem),
         (83, "I0", isetp, ("nop",)), (96, "B0", "@P1 BRA L_loop ;", ("nop",))]
    return w, 100


def thr_slot(req, slot):
    """the control fields of slot `slot` (1-based) of the request's stage: (name, waits {key: digits}, read barriers {key: digit},
    write barriers {key: digit}, the yield pattern all | none | tensor | alt)"""
    slots = THR_STAGES[req["stage"]]
    if not 1 <= slot <= len(slots):
        raise SystemExit(f"{req.get('id')}: stage {req['stage']} has the slots 1 .. {len(slots)}")
    name = slots[slot - 1][0]
    if req["stage"] == "e":
        return name, {}, {}, {}, "all"
    waits, rb, wb, yl = {"FL": "1"}, {}, {"L0": "1"}, "all"

    def add(keys, b):
        for k in keys:
            waits[k] = "".join(sorted(set(waits.get(k, "") + b)))
    if name.startswith("a1_") or name == "a_all":
        add(THR_FREE16[:16 if name == "a_all" else int(name.split("_")[1])], "1")
    if name == "a1n_16":
        add(THR_FREE16, "5")
    if name.startswith("a2_"):
        add(THR_FLY8[:int(name.split("_")[1])], "1")
    if name in ("a3_r", "a3_w", "a3_d", "a_all"):
        rb.update({k: "2" for k in THR_X})
    if name in ("a3_w", "a3_d", "a_all"):
        add(THR_RBW, "2")
    if name in ("a3_d", "a_all"):
        add(THR_X, "2")
    if name in ("a4", "a_all"):
        add(["L0"], "1")
    if name.startswith("b_"):
        yl = name[2:]
    return name, waits, rb, wb, yl


def body_thr(req, slot, front="none"):
    """the stage iteration of slot `slot` as instructions (control codes written out); the audit runs on every body"""
    words, total = thr_words(req)
    name, waits, rb, wb, yl = thr_slot(req, slot)
    b, nflag = [], 0
    for j, (t, key, text, sem) in enumerate(words):
        s = (words[j + 1][0] if j + 1 < len(words) else total) - t
        tensor = sem[0] == "qmma"
        may = 1 <= s <= 11 and not text.startswith("NOP")      # (the yield flag has no encoding with a stall of 12 .. 15)
        if yl == "all":
            y = may
        elif yl == "none":
            y = False
        elif yl == "tensor":
            y = may and tensor
        else:      # alt: every second word that may carry it
            y = may and nflag % 2 == 0
            nflag += 1 if may else 0
        b.append(Ins(text, sem, ctl=C(s, wait=waits.get(key, ""), rb=rb.get(key, "-"), wb=wb.get(key, "-"), y=y), tag=key))
    thr_audit(req, b, total, f"{req.get('id')} slot {slot} ({name})")
    return b


def thr_pro(req):
    """behind the tensor prologue: the copy of the first input, the source word of the B pairs, the A quad, the outer counter"""
    return ([Ins("MOV R46, R4 ;", ("mov", "R46", "R4")), Ins(f"MOV R44, 0x{THR_S0:x} ;", ("mov", "R44", THR_S0))]
            + [Ins(f"MOV R{16 + k}, 0x{THR_A0:x} ;", ("mov", f"R{16 + k}", THR_A0)) for k in range(4)]
            + [Ins("MOV R45, RZ ;", ("nop",)), PAD(), PAD()])


def thr_init(req):
    """at the head of every pass: every register the inner loop carries is set again (R10, the checksum, is NOT)"""
    i = [Ins("MOV R4, R46 ;", ("mov", "R4", "R46"), ctl=C(6)),
         Ins("LOP3.LUT R5, R1, 0x5bd1e995, RZ, 0x3c, !PT ;", ("xor", "R5", "R1", 0x5bd1e995), ctl=C(6)),
         Ins("MOV R11, RZ ;", ("mov", "R11", 0), ctl=C(6))]
    for q0, src in zip(THR_QUADS, ("R4", "R5", "R23", "R20")):
        i += [Ins(f"LOP3.LUT R{q0}, {src}, 0x3fffff, RZ, 0xc0, !PT ;", ("and", f"R{q0}", src, 0x3fffff), ctl=C(6)),
              Ins(f"LOP3.LUT R{q0}, R{q0}, 0x4b000000, RZ, 0xfc, !PT ;", ("or", f"R{q0}", f"R{q0}", 0x4b000000), ctl=C(6))]
        i += [Ins(f"IADD3 R{q0 + k}, PT, PT, R{q0}, 0x{k:x}, RZ ;", ("add", f"R{q0 + k}", f"R{q0}", k), ctl=C(6)) for k in (1, 2, 3)]
    return i


def thr_post(req):
    """behind the 256 iterations of a pass: the 16 accumulator registers into the checksum (45 cycles behind the last tensor word)"""
    mul = (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59)
    p = [Ins("NOP ;", ("nop",)), Ins("NOP ;", ("nop",))]
    for n, q0 in enumerate(THR_QUADS):
        p += [Ins(f"IMAD R10, R{q0 + k}, 0x{mul[4 * n + k]:x}, R10 ;", ("mad", "R10", f"R{q0 + k}", mul[4 * n + k], "R10"), ctl=C(6)) for k in range(4)]
    return p


def thr_rw(ins):
    """(registers read, registers written, class alu | tensor | load | none) of a stage word - from its model line"""
    sem, text = ins.sem, ins.text
    quad = lambda r, n: [f"R{int(r[1:]) + k}" for k in range(n)]
    isr = lambda x: isinstance(x, str) and re.fullmatch(r"R\d+", x)
    op = sem[0]
    if op == "qmma":
        return quad(sem[1], 4) + quad(sem[2], 4) + quad(sem[3], 2) + ["R14"], quad(sem[1], 4), "tensor"
    if op == "lds":
        return [sem[2]], quad(sem[1], sem[4]), "load"
    if op in ("xor", "and", "or", "add"):
        return [x for x in sem[2:4] if isr(x)], [sem[1]], "alu"
    if op == "mad":
        return [x for x in sem[2:5] if isr(x)], [sem[1]], "alu"
    if op == "prmt":
        return [x for x in (sem[2], sem[4]) if isr(x)], [sem[1]], "alu"
    if op == "mov":
        return [x for x in sem[2:3] if isr(x)], [sem[1]], "alu"
    if op == "nop":
        if text.startswith("ISETP"):
            return re.findall(r"(?<![UA-Za-z])R\d+", text), ["P1"], "alu"
        if text.startswith("@P1 BRA"):
            return ["P1"], [], "branch"
        if text.startswith("NOP"):
            return [], [], "none"
    raise SystemExit(f"thr: a stage word the audit does not know: {text}")


def thr_audit(req, body, total, what):
    """the table's cells and the holds on the cyclic stage iteration (this iteration and the next); refuses on a violation.
    ALU -> ALU >= 6 (every cell of these words is <= 6 = the data default); ALU -> an operand of a tensor word >= 7 (default
    mma_input); tensor result -> ALU >= 28, -> the accumulate operand of a tensor word >= 29; tensor -> tensor >= 16; a
    fixed-latency rewrite of ANY register a tensor word reads >= 8 behind the word (law (d)); ISETP -> BRA >= 13; a tensor
    word >= 14 in front of the branch; IMAD -> IMAD >= 2; a barrier's first waiter >= 2 behind the word that arms it; the first
    reader of a load's register waits its write barrier and the load stands >= 6 behind an ALU write of a register it writes;
    the yield flag only with a stall 1 .. 11; the stalls sum to the stage's static cycles. -> a summary for the family file"""
    bad = []
    ctl = [re.fullmatch(r"\[B([-\d]{6}):R([-\d]):W([-\d]):([-Y]):S(\d\d)\]", i.ctl) for i in body]
    if not all(ctl):
        raise SystemExit(f"thr audit {what}: a control code the audit cannot read")
    st = [int(c.group(5)) for c in ctl]
    t, acc = [], 0
    for s in st:
        t.append(acc)
        acc += s
    if acc != total:
        bad.append(f"the stalls sum to {acc}, the stage has {total} static cycles")
    n = len(body)
    rw = [thr_rw(i) for i in body]
    for j, c in enumerate(ctl):
        if c.group(4) == "Y" and not 1 <= st[j] <= 11:
            bad.append(f"{body[j].tag}: the yield flag with stall {st[j]}")
    # two iterations in a row: positions j (this) and j + n (the next)
    seq = [(t[j % n] + (total if j >= n else 0), j % n) for j in range(2 * n)]

    def last_writer(pos, reg):
        for p in range(pos - 1, -1, -1):
            if reg in rw[seq[p][1]][1]:
                return p
        return None
    for pos in range(n, 2 * n):
        tj, j = seq[pos]
        rd, _wr, cls = rw[j]
        for reg in rd:
            p = last_writer(pos, reg)
            if p is None:
                continue      # (set in front of the loop only)
            tw, jw = seq[p]
            d, wcls = tj - tw, rw[jw][2]
            if wcls == "load":      # the nearest wait on the load's barrier between the load and this reader (the reader itself counts)
                wbar = ctl[jw].group(3)
                waited = any(wbar in ctl[seq[x][1]].group(1) for x in range(p + 1, pos + 1))
                if not waited:
                    bad.append(f"{body[j].tag} reads {reg} of the load {body[jw].tag} with no wait on barrier {wbar} between them")
                continue
            need = (29 if (cls == "tensor" and reg in rw[j][1]) else 28) if wcls == "tensor" else 7 if cls == "tensor" else 13 if cls == "branch" else 6
            if d < need:
                bad.append(f"{body[jw].tag} -> {body[j].tag} ({reg}): {d} cycles, the rule asks {need}")
    tens = [pos for pos in range(2 * n) if rw[seq[pos][1]][2] == "tensor"]
    for a, b2 in zip(tens, tens[1:]):
        if seq[b2][0] - seq[a][0] < 16:
            bad.append(f"{body[seq[a][1]].tag} -> {body[seq[b2][1]].tag}: tensor words {seq[b2][0] - seq[a][0]} cycles apart (the resource row: 16)")
    for a in [p for p in tens if p < n]:      # law (d): the next fixed-latency writer of every register the word reads
        ta, ja = seq[a]
        for reg in rw[ja][0]:
            for p in range(a + 1, 2 * n):
                jp = seq[p][1]
                if reg in rw[jp][1] and rw[jp][2] in ("alu", "tensor"):
                    if seq[p][0] - ta < 8:
                        bad.append(f"law (d): {body[jp].tag} rewrites {reg} {seq[p][0] - ta} cycles behind {body[ja].tag}")
                    break
        for p in range(a + 1, 2 * n):      # the landing row: a tensor word >= 14 in front of the conditional branch
            if rw[seq[p][1]][2] == "branch":
                if seq[p][0] - ta < 14:
                    bad.append(f"{body[ja].tag} stands {seq[p][0] - ta} cycles in front of the branch (the landing row: 14)")
                break
    imad = [pos for pos in range(2 * n) if body[seq[pos][1]].text.startswith("IMAD")]
    for a, b2 in zip(imad, imad[1:]):
        if seq[b2][0] - seq[a][0] < 2:
            bad.append(f"IMAD -> IMAD {seq[b2][0] - seq[a][0]} cycle apart (the resource row: 2)")
    for pos in range(n):      # a barrier's first waiter behind the word that arms it; a load behind an ALU write of its registers
        tj, j = seq[pos]
        for bar in (ctl[j].group(2), ctl[j].group(3)):
            if bar == "-":
                continue
            for p in range(pos + 1, 2 * n):
                if bar in ctl[seq[p][1]].group(1):
                    if seq[p][0] - tj < 2:
                        bad.append(f"{body[seq[p][1]].tag} waits barrier {bar} {seq[p][0] - tj} cycle behind {body[j].tag}, which arms it (the arming distance: 2)")
                    break
        if rw[j][2] == "load":
            for reg in rw[j][1]:
                p = last_writer(pos + n, reg)
                if p is not None and rw[seq[p][1]][2] == "alu" and seq[pos + n][0] - seq[p][0] < 6:
                    bad.append(f"the load {body[j].tag} stands {seq[pos + n][0] - seq[p][0]} cycles behind the ALU write of {reg} ({body[seq[p][1]].tag})")
    if bad:
        raise SystemExit(f"thr audit {what}: " + "; ".join(bad))
    return {"static_cycles": total, "words": n, "tensor_words": sum(1 for x in rw if x[2] == "tensor"), "loads": sum(1 for x in rw if x[2] == "load"),
            "wait_bits": sum(len(c.group(1).replace("-", "")) for c in ctl), "waiting_words": sum(1 for c in ctl if c.group(1) != "------"),
            "read_barriers": sum(1 for c in ctl if c.group(2) != "-"), "write_barriers": sum(1 for c in ctl if c.group(3) != "-"),
            "yield_flags": sum(1 for c in ctl if c.group(4) == "Y")}


def thr_points(req):
    """the family file's table: slot -> name, what changes, and the audit's counts"""
    words, total = thr_words(req)
    out = []
    for k, (name, text) in enumerate(THR_STAGES[req["stage"]], 1):
        if k not in req["distance_list"]:
            continue
        b = [Ins(i.text, i.sem, ctl=i.ctl, tag=i.tag) for i in body_thr(req, k)]
        out.append(dict({"slot": k, "name": name, "what": text}, **thr_audit(req, b, total, f"{req.get('id')} slot {k}")))
    return {"stage": req["stage"], "repeat": req["repeat"], "iterations_per_pass": REPEAT, "stage_iterations_per_thread": REPEAT * req["repeat"],
            "slots": out}


def thr_text(r):
    n = len(THR_STAGES[r["stage"]])
    return (f"throughput stage `{r['stage']}` (version 26): {r['repeat']} passes x {REPEAT} stage iterations per thread, {n} slot(s) in the distance slot - "
            + "; ".join(f"{k} = {name}" for k, (name, _t) in enumerate(THR_STAGES[r["stage"]], 1))
            + ". What is read is the kernel's TIME (the median launch time per slot); every slot computes the same checksum - only control fields differ - "
              "and keeps the table's cells and the holds (the generator's audit); a slot whose checksum is not right in every thread-launch has no time")


def thr_kernel_text(name, req, ctas, body, smem):
    full = prologue(req, ctas)
    ni = len(thr_init(req))
    common, init = full[:-ni], full[-ni:]
    lines = [f".entry {name}", f"    .reg R0-R{THR_REGS - 1}", f"    .regcount {THR_REGS + 8}", "    .param ptr out", "    .param u32 seed", f"    .shared smem[{smem}]"]
    lines += [f"    {i.line()}" for i in common]
    lines.append("L_outer:")
    lines += [f"    {i.line()}" for i in init]
    lines.append("L_loop:")
    lines += [f"    {i.line()}" for i in body]
    lines += [f"    {i.line()}" for i in thr_post(req)]
    lines += [f"    {C(6)} IADD3 R45, PT, PT, R45, 0x1, RZ ;", f"    {C()} ISETP.LT.U32.AND P1, PT, R45, 0x{int(req['repeat']):x}, PT ;", f"    {C()} @P1 BRA L_outer ;",
              f"    {C()} IMAD.WIDE.U32 R2, R1, 0x4, R2 ;", f"    {C()} STG.E desc[UR4][R2.64], R10 ;", f"    {C()} EXIT ;", ".endentry", ""]
    text = "\n".join(lines)
    bad = misaligned(text)
    if bad:
        raise SystemExit(f"{name}: refusing to write a kernel the card would trap on - {sorted(set(bad))}")
    return text


def thr_passes_scalar(req, gid, passes):
    """the independent check of the outer loop: one thread on Python integers through `passes` whole passes (INIT, 256
    iterations, POST) - its checksum must be passes x (the model's checksum of ONE pass) mod 2^32"""
    R, _get, ex = _machine(gid)
    full = prologue(req, 188)
    ni = len(thr_init(req))
    body = body_thr(req, 1)
    for i in full[:-ni]:
        ex(i.sem)
    for _ in range(passes):
        for i in full[-ni:]:
            ex(i.sem)
        start = {k: R[k] for k in ("R4", "R5", "R11", "R16", "R17", "R18", "R19", "R44") + tuple(f"R{q0 + k}" for q0 in THR_QUADS for k in range(4))}
        if _ == 0:
            first = start
        elif start != first:
            raise AssertionError("thr: a pass does not start in the state of the first pass")
        for _i in range(REPEAT):
            for i in body:
                ex(i.sem)
        for i in thr_post(req):
            ex(i.sem)
    return R["R10"]


# ------------------------------------------------------------------------------------------------ kind gw (version 26, second build)
# A WAIT CARRIED BY A WORD UNDER A GUARD. A scoreboarded producer (SHFL.BFLY | LDS, write barrier 1) writes R6; the ONLY
# wait on that barrier stands on a word under the guard @P4 (`@P4 PRMT R24, R6, 0x3210, R6`), two cycles behind the
# producer; the READER is a word under the opposite guard, `@!P4 PRMT R8, R6, 0x3210, R6`, with NO wait of its own, d issue
# cycles behind the producer. P4 is false in part of the iterations ("guard": "bit" - bit 31 of counter x 0x9e3779b1, the
# same in every lane, not the counter's parity) or in every iteration ("false"): there the word that carries the wait does
# not execute and the reader does. `stale` = the reader took R6's previous content (the iteration's input, written into R6
# far in front) in every iteration in which it executed. "wait": "none" = the same text with no wait at all - the positive
# control, and the floor of producer -> reader by distance alone (its distances start at 1: the reader then stands in front
# of the two words). Both results go into the checksum weighted by the iteration's inputs.
GW_PRODUCERS = {"SHFL": ("SHFL.BFLY PT, R6, R14, 0x1, 0x1f ;", ("shfl", "R6", "R14", "bfly", 1), "SHFL.BFLY PT, R6, R14, 0x1, 0x1f (every lane takes lane ^ 1's R14 = that lane's input)"),
                "LDS": ("LDS R6, [R9+0x20] ;", ("lds", "R6", "R9", 0x20, 1), "LDS R6, [R9+0x20] (the thread's own line: warm)")}


def gw_layout(req, d):
    """-> (the producer's stall, the waiter's stall, PADs behind the waiter, reader in front of the two words?) for the distance
    producer -> reader d; None when the request cannot have it"""
    y = req.get("yield") == "set"
    if d in (1, 2):
        return (d, 1, 0, True) if req["wait"] in ("none", "end") else None
    k = (d - 3) // 15
    s = d - 2 - 15 * k
    if not 1 <= s <= 15 or (y and s > 11):
        return None
    return 1, s, k, False


def body_gw(req, d, front="none"):
    lay = gw_layout(req, d)
    if lay is None:
        raise SystemExit(f"{req.get('id')}: distance {d} cannot be built (a guarded wait: 3 .. ; with the yield flag the waiter's stall is <= 11; 1 and 2 only with wait none)")
    ps, ws, pads, front_reader = lay
    y = req.get("yield") == "set"
    ptext, psem, _t = GW_PRODUCERS[req["producer"]]
    b = []
    if req["guard"] == "bit":
        b += [Ins("IMAD R0, R11, 0x9e3779b1, RZ ;", ("mad", "R0", "R11", 0x9e3779b1, "RZ")), Ins("SHF.R.U32.HI R0, RZ, 0x1f, R0 ;", ("shr", "R0", "R0", 31)),
              Ins("ISETP.NE.U32.AND P4, PT, R0, RZ, PT ;", ("mov", "P4", "R0"))]
    else:
        b += [Ins("ISETP.NE.U32.AND P4, PT, RZ, RZ, PT ;", ("mov", "P4", 0))]
    b += [Ins("MOV R14, R5 ;", ("mov", "R14", "R5")), Ins("MOV R6, R4 ;", ("mov", "R6", "R4")), Ins("MOV R8, R5 ;", ("mov", "R8", "R5")),
          Ins("MOV R24, R4 ;", ("mov", "R24", "R4")), PAD(), PAD()]
    prod = Ins(ptext, psem, ctl=C(ps, wb="1", y=y and ps <= 11), tag="P", dst=["R6"])
    fill = Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(1, y=y))
    waiter = Ins("@P4 PRMT R24, R6, 0x3210, R6 ;", ("gprmt", "R24", "R6", 0x3210, "R6", "P4", 1),
                 ctl=C(ws, wait="1" if req["wait"] == "guarded" else "", y=y and ws <= 11), tag="W")
    reader = Ins("@!P4 PRMT R8, R6, 0x3210, R6 ;", ("gprmt", "R8", "R6", 0x3210, "R6", "P4", 0), ctl=C(1, y=y), tag="C")
    if front_reader:
        b += [prod, reader, fill, waiter]
    else:
        b += [prod, fill, waiter] + [PAD() for _ in range(pads)] + [reader]
    b += [PAD(), PAD(), PAD(),
          Ins("IMAD R10, R8, R5, R10 ;", ("mad", "R10", "R8", "R5", "R10")), Ins("IMAD R10, R24, R4, R10 ;", ("mad", "R10", "R24", "R4", "R10"))]
    if req["wait"] == "end":      # (fourth build) the barrier drained once per iteration, 45 cycles and more behind the reader
        b += [Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="1")), PAD()]
    return b


def gw_text(r):
    return (f"a WAIT carried by a word under a guard (version 26): {GW_PRODUCERS[r['producer']][2]} on write barrier 1; "
            + ("the only wait on that barrier stands on `@P4 PRMT R24, R6, 0x3210, R6`, two cycles behind the producer"
               if r["wait"] == "guarded" else "NO wait between the producer and the reader; ONE wait on that barrier at the END of the iteration, behind the checksum (the barrier is "
               "drained once per iteration): the floor of producer -> reader by distance alone" if r["wait"] == "end"
               else "NO wait on that barrier at all, in any iteration (the positive control of the guarded wait; NOT a floor by distance: the barrier is armed 256 times and never waited)")
            + "; the reader `@!P4 PRMT R8, R6, 0x3210, R6` has no wait of its own - distance = producer -> reader; P4 is "
            + ("bit 31 of (iteration counter x 0x9e3779b1): false in part of the iterations, the same in every lane" if r["guard"] == "bit"
               else "FALSE in every iteration: the word that carries the wait never executes, the reader always does")
            + "; stale = the reader took R6's previous content (the iteration's input) wherever it executed")


# ------------------------------------------------------------------------------------------------ kind lb (version 26, third build)
# THE BASE REGISTER OF A LOAD REWRITTEN BY A YOUNGER LOAD OF THE SAME PIPE. The older load `LDS R6, [R13+0x4]`
# (write barrier 1, NO read barrier) reads word 1 of the thread's own line through the base R13; d issue cycles behind it the
# younger load `LDS R13, [R13+0x3c]` (write barrier 2) brings a NEW base - the address of word 2 of the same line, stored
# there by the prologue - and nobody waits in between. With the old base the older load reads word 1, with the new one
# word 3: a late read of the base shows as the other word (`late`), never as a trap (both addresses are inside the thread's
# 64 bytes). The reader waits both barriers. "control": "front" = the positive control: the younger load stands 45 cycles
# IN FRONT of the older one and is waited - the older load then reads through the new base: expect 0 % good, class `late`.
def body_lb(req, d, front="none"):
    y = req.get("yield") == "set"
    b = [Ins("MOV R13, R9 ;", ("mov", "R13", "R9")), PAD(), PAD()]
    older = lambda s: Ins("LDS R6, [R13+0x4] ;", ("lds", "R6", "R13", 0x4, 1), ctl=C(s, wb="1", y=y and s <= 11), tag="S")
    if req.get("control") == "front":
        # (the model ignores the younger load in front; the word tagged O carries its effect for the hypothesis `late`: the
        # older load executed behind the rewrite - which is what the card does in this control)
        b += [Ins("LDS R13, [R13+0x3c] ;", ("nop",), ctl=C(wb="2")), Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="2")), PAD(), PAD(),
              older(1), Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("add", "R13", "R9", 0x8), tag="O")]
    else:
        s, fill = split_distance(d)
        b += [older(s)] + fill + [Ins("LDS R13, [R13+0x3c] ;", ("lds", "R13", "R13", 0x3c, 1), ctl=C(1 if y else 15, wb="2", y=y), tag="O")]      # (the yield flag has no encoding with a stall of 15)
    b += [PAD(), Ins("IMAD R10, R6, R4, R10 ;", ("mad", "R10", "R6", "R4", "R10"), ctl=C(wait="12" if req.get("control") != "front" else "1")), PAD()]
    return b


def lb_pro(req):
    """word 15 of the thread's line := the address of word 2 of the line (a store with a read barrier, waited): the NEW base"""
    return [Ins("IADD3 R13, PT, PT, R9, 0x8, RZ ;", ("add", "R13", "R9", 0x8)),
            Ins("STS [R9+0x3c], R13 ;", ("sts", "R9", 0x3c, "R13", 1), ctl=C(rb="5")),
            Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="5")), PAD()]


def lb_text(r):
    return ("the BASE register of a load rewritten by a younger load of the same pipe (version 26): `LDS R6, [R13+0x4]` on write barrier 1, no read barrier; "
            + ("the younger `LDS R13, [R13+0x3c]` stands 45 cycles IN FRONT of it and is waited - the POSITIVE CONTROL: the older load reads through the NEW base, expect 0 % good, class late"
               if r.get("control") == "front" else "the younger `LDS R13, [R13+0x3c]` (write barrier 2) brings a new base d issue cycles behind it, nobody waits in between - distance = older -> younger")
            + "; the new base is the address of word 2 of the thread's own line: a late read of the base shows as word 3 of the line instead of word 1 (late), never as a trap; the reader waits both barriers")


# ------------------------------------------------------------------------------------------------ kind gp (version 27)
# A GUARDED WAIT UNDER ANOTHER PREDICATE - the two pointer groups of the prologue of a vendor's MoE kernel as cubit's wait policy
# left them. Two `LDC.64` under two DIFFERENT predicates arm ONE write barrier; the ONLY wait on that barrier stands on a
# word under the FIRST predicate (the carrier, which reads the first load's pair); the READER reads the second load's
# pair under the SECOND predicate, d issue cycles behind its load, with no wait of its own.
#   form imad:  @P0 LDC.64 R24 | @P2 LDC.64 R26 | [wait] @P0 IMAD.WIDE.U32 R24, R13, 0x4, R24 | one word |
#               @P2 IMAD.WIDE.U32 R26, R21, 0x4, R26               (the reader: 8 behind its load in the kernel)
#   form lea:   @!P0 LDC.64 R24 | 8 cycles | @!P2 LDC.64 R26 | 10 cycles | [wait] @!P0 LEA R6, P3, R13, R24, 0x2 |
#               @!P0 LEA.HI.X R7, .. | @!P2 LEA R28, P4, R21, R26, 0x2 (the reader: 17) | one word |
#               @!P2 LEA.HI.X R29, R21, R27, R22, 0x2, P4          (the second reader: 6 behind the first)
# with the kernel's own stalls and yield flags on these words. In the kernel the reader's result is the ADDRESS of a
# global load; here it is DATA: the pair is folded into the checksum relative to the prologue's copy of the same
# constant (R2:R3, the output pointer, which the host does not know) - no address depends on what is tested.
# The loaded constant is c[0x0][0x380]; before the loads the reader's pair holds (R2 + a, R3 + b) - a, b the iteration's
# inputs - so a reader that took the old pair shows as (a, b + ..) instead of (0, ..). The multiplicand / index only
# touches the HIGH word (R21 = (b & 3) << 30, product (b & 3) << 32; index low word 0): no carry depends on the unknown
# low word. Hypotheses: good | stale (the reader took the old pair) | drop2 (form imad: the reader's result was lost -
# the load landed behind the reader's own write).
# "guards": which side EXECUTES - first letter the carrier's side, second the reader's: tt | ft | tf | ff (the same in
# every lane and iteration), lane (bit 0 / bit 1 of the lane: all four combinations inside every warp), cnt (two bits of
# counter x 0x9e3779b1: all four over the iterations, the same in every lane). "pset": pro (both predicates set once, in
# the prologue) | near (set in every iteration by two ISETP.GE.AND 13 and 12 cycles in front of the first load, as in
# the kernel). "wait": guarded (the carrier has the wait bit) | end (the positive control: the SAME text without that
# bit; the fold's own wait drains the barrier behind the reader). The carrier's result is NEVER folded: where the
# carrier executes without its wait it reads without a wait itself, and that must not reach the checksum.
# "share" (form imad; second build): ldg = the kernel's own shape - the reader's barrier is shared with the first LDC.64
# AND armed again, one cycle in front of the reader, by a global load under the FIRST predicate (`@P0 LDG.E.CONSTANT R7,
# desc[UR4][R18.64]` with a read barrier: the kernel's word in that place; here it reads the thread's own word B through an
# address the prologue set) | ldc = shared with the first LDC.64 only (a filler in the load's place) | own = the second
# LDC.64 on a barrier of its own (3), the carrier waits both; the global load stays on barrier 0.
GP_FORMS = {"imad": ("`@P0 LDC.64` + `@P2 LDC.64` on write barrier 0, the wait on `@P0 IMAD.WIDE.U32 R24, R13, 0x4, R24` two cycles behind the second load, "
                     "the reader `@P2 IMAD.WIDE.U32 R26, R21, 0x4, R26`", 0, 1),
            "lea": ("`@!P0 LDC.64` + `@!P2 LDC.64` (8 cycles apart) on write barrier 4, the wait on `@!P0 LEA R6, P3, R13, R24, 0x2` ten cycles behind the second load, "
                    "the readers `@!P2 LEA R28, P4, R21, R26, 0x2` and, 6 cycles behind it, `@!P2 LEA.HI.X R29, R21, R27, R22, 0x2, P4`", 4, 0)}
GP_GUARDS = ("tt", "ft", "tf", "ff", "lane", "cnt")
GP_SHARE = {"ldg": "the reader's barrier is shared with the first LDC.64 and armed again one cycle in front of the reader by `@P0 LDG.E.CONSTANT R7, desc[UR4][R18.64]` (read barrier 1; the thread's own word B) - the kernel's own shape",
            "ldc": "the reader's barrier is shared with the first LDC.64 only (a filler stands in the place of the kernel's global load)",
            "own": "the second LDC.64 has a barrier of its OWN (3) and the carrier waits barriers 0 and 3; `@P0 LDG.E.CONSTANT R7, desc[UR4][R18.64]` (read barrier 1) arms barrier 0 one cycle in front of the reader"}


def gp_layout(req, d):
    """-> (the carrier's stall, the filler behind the carrier?, PADs in front of the reader) for the distance second load -> reader; None when it cannot be built"""
    if req["form"] == "imad":
        if d == 3:      # (no word between the carrier and the reader: only without the kernel's global load)
            return (1, False, 0) if req.get("share") == "ldc" else None
        if d < 4:
            return None
        k = (d - 4) // 15
        return d - 3 - 15 * k, True, k
    if d < 12:
        return None
    k = (d - 12) // 15
    return d - 11 - 15 * k, True, k


def gp_srcs(req):
    """the two predicate sources (R8, R20) as prologue words for the constant layouts and the lane layout; a word executes
    where its predicate is TRUE (form imad) / FALSE (form lea); the predicate is (source >= 0)"""
    g, want = req["guards"], GP_FORMS[req["form"]][2]
    if g == "lane":      # the sign of the source = bit 0 / bit 1 of the lane
        return [Ins("SHF.L.U32 R8, R0, 0x1f, RZ ;", ("shl", "R8", "R0", 31)), Ins("SHF.L.U32 R20, R0, 0x1e, RZ ;", ("shl", "R20", "R0", 30))]
    if g == "cnt":       # (set in every iteration)
        return [Ins("MOV R8, RZ ;", ("mov", "R8", 0)), Ins("MOV R20, RZ ;", ("mov", "R20", 0))]
    out = []
    for reg, ch in (("R8", g[0]), ("R20", g[1])):
        neg = (ch == "t") != bool(want)      # the source is negative where the predicate has to be false
        out.append(Ins(f"MOV {reg}, 0x80000000 ;", ("mov", reg, 0x80000000)) if neg else Ins(f"MOV {reg}, RZ ;", ("mov", reg, 0)))
    return out


def gp_isetp(near):
    return [Ins("ISETP.GE.AND P0, PT, R8, RZ, PT ;", ("sge0", "P0", "R8"), ctl=C(1, y=True) if near else C()),
            Ins("ISETP.GE.AND P2, PT, R20, RZ, PT ;", ("sge0", "P2", "R20"), ctl=C(12) if near else C())]


def gp_pro(req):
    p = [Ins("MOV R6, RZ ;", ("mov", "R6", 0))] + [Ins(f"MOV R{k}, RZ ;", ("mov", f"R{k}", 0)) for k in (21, 22, 23, 28, 29, 30, 31)]
    p += [Ins("ISETP.NE.U32.AND P3, PT, RZ, RZ, PT ;", ("mov", "P3", 0)), Ins("ISETP.NE.U32.AND P4, PT, RZ, RZ, PT ;", ("mov", "P4", 0))]
    p += gp_srcs(req) + [PAD()]
    p += gp_isetp(False) + [PAD()]      # (pset near sets them again in every iteration)
    return p


def body_gp(req, d, front="none"):
    lay = gp_layout(req, d)
    if lay is None:
        raise SystemExit(f"{req.get('id')}: distance {d} cannot be built (form imad: from 3; form lea: from 12)")
    s, filler, pads = lay
    form, near, guarded = req["form"], req["pset"] == "near", req["wait"] == "guarded"
    wbar, want = str(GP_FORMS[form][1]), GP_FORMS[form][2]
    g0 = lambda dst, inner: ("g", "P0", want, tuple(dst), inner)
    g2 = lambda dst, inner: ("g", "P2", want, tuple(dst), inner)
    fl = lambda st, y=True: Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(st, y=y))      # a filler in the place of a word of the kernel, with that word's stall and yield flag
    b = [Ins("IADD3 R24, PT, PT, R2, R5, RZ ;", ("add", "R24", "R2", "R5")), Ins("IADD3 R25, PT, PT, R3, R4, RZ ;", ("add", "R25", "R3", "R4")),
         Ins("IADD3 R26, PT, PT, R2, R4, RZ ;", ("add", "R26", "R2", "R4")), Ins("IADD3 R27, PT, PT, R3, R5, RZ ;", ("add", "R27", "R3", "R5"))]
    share = req.get("share")
    if form == "imad":
        b += [Ins("SHF.L.U32 R13, R4, 0x1e, RZ ;", ("shl", "R13", "R4", 30)), Ins("SHF.L.U32 R21, R5, 0x1e, RZ ;", ("shl", "R21", "R5", 30)),
              Ins("MOV R7, R5 ;", ("mov", "R7", "R5"))]
    else:
        b += [Ins("MOV R13, RZ ;", ("mov", "R13", 0)), Ins("LOP3.LUT R14, R4, 0xff, RZ, 0xc0, !PT ;", ("and", "R14", "R4", 0xff)),
              Ins("MOV R21, RZ ;", ("mov", "R21", 0)), Ins("LOP3.LUT R22, R5, 0xff, RZ, 0xc0, !PT ;", ("and", "R22", "R5", 0xff)),
              Ins("MOV R28, R4 ;", ("mov", "R28", "R4")), Ins("MOV R29, R5 ;", ("mov", "R29", "R5"))]
    if req["guards"] == "cnt":
        b += [Ins("IMAD R23, R11, 0x9e3779b1, RZ ;", ("mad", "R23", "R11", 0x9e3779b1, "RZ")), Ins("MOV R8, R23 ;", ("mov", "R8", "R23")),
              Ins("SHF.L.U32 R20, R23, 0x1, RZ ;", ("shl", "R20", "R23", 1))]
    b += [PAD(), PAD()]
    if near:
        b += gp_isetp(True)
    if form == "imad":
        l1 = Ins("@P0 LDC.64 R24, c[0x0][0x380] ;", g0(("R24", "R25"), ("mov2", "R24", "R2")), ctl=C(8, wb=wbar, y=True))
        wb2 = "3" if share == "own" else wbar
        l2 = Ins("@P2 LDC.64 R26, c[0x0][0x380] ;", g2(("R26", "R27"), ("mov2", "R26", "R2")), ctl=C(2, wb=wb2, y=True), tag="P", dst=["R26", "R27"])
        cw = Ins("@P0 IMAD.WIDE.U32 R24, R13, 0x4, R24 ;", g0(("R24", "R25"), ("madw", "R24", "R13", 4, "R24")),
                 ctl=C(s, wait=(wbar + ("3" if share == "own" else "")) if guarded else ""), tag="W")
        rd = Ins("@P2 IMAD.WIDE.U32 R26, R21, 0x4, R26 ;", g2(("R26", "R27"), ("madw", "R26", "R21", 4, "R26")), ctl=C(5), tag="C", dst=["R26", "R27"])
        ldg = Ins("@P0 LDG.E.CONSTANT R7, desc[UR4][R18.64] ;", g0(("R7",), ("ldg", "R7", "R18")), ctl=C(1, rb="1", wb=wbar, y=True), tag="G")
        b += [l1, l2, cw] + [PAD() for _ in range(pads)] + ([fl(1) if share == "ldc" else ldg] if filler else []) + [rd]
        lo, hi = "R26", "R27"
    else:
        l1 = Ins("@!P0 LDC.64 R24, c[0x0][0x380] ;", g0(("R24", "R25"), ("mov2", "R24", "R2")), ctl=C(1, wb=wbar, y=True))
        l2 = Ins("@!P2 LDC.64 R26, c[0x0][0x380] ;", g2(("R26", "R27"), ("mov2", "R26", "R2")), ctl=C(1, wb=wbar, y=True), tag="P", dst=["R26", "R27"])
        cw = Ins("@!P0 LEA R6, P3, R13, R24, 0x2 ;", g0(("R6", "P3"), ("lea", "R6", "R13", "R24", 2, "P3")), ctl=C(s, wait=wbar if guarded else ""), tag="W")
        ch = Ins("@!P0 LEA.HI.X R7, R13, R25, R14, 0x2, P3 ;", g0(("R7",), ("leahi", "R7", "R13", "R25", "R14", 2, "P3")), ctl=C(1, y=True))
        rd = Ins("@!P2 LEA R28, P4, R21, R26, 0x2 ;", g2(("R28", "P4"), ("lea", "R28", "R21", "R26", 2, "P4")), ctl=C(5), tag="C", dst=["R28", "P4"])
        rh = Ins("@!P2 LEA.HI.X R29, R21, R27, R22, 0x2, P4 ;", g2(("R29",), ("leahi", "R29", "R21", "R27", "R22", 2, "P4")), ctl=C(1, y=True), tag="C", dst=["R29"])
        b += [l1, fl(1), fl(1), fl(1), fl(1), fl(3, False), l2, fl(1), fl(1), fl(5, False), fl(2), cw, ch] + [PAD() for _ in range(pads)] + [rd, fl(1), rh]
        lo, hi = "R28", "R29"
    # the fold, behind a real wait on the barrier (unguarded: it drains the barrier in every iteration), relative to R2:R3
    b += [PAD(), PAD(), PAD(),
          Ins(f"IADD3 R30, PT, PT, {lo}, -R2, RZ ;", ("rsub", "R30", "R2", lo), ctl=C(wait=wbar + ("1" if share in ("ldg", "own") else "") + ("3" if share == "own" else ""))),
          Ins(f"IADD3 R31, PT, PT, {hi}, -R3, RZ ;", ("rsub", "R31", "R3", hi)),
          Ins("IMAD R10, R30, R5, R10 ;", ("mad", "R10", "R30", "R5", "R10")), Ins("IMAD R10, R31, R4, R10 ;", ("mad", "R10", "R31", "R4", "R10")),
          Ins("IADD3 R10, PT, PT, R10, R4, RZ ;", ("add", "R10", "R10", "R4"))]
    if form == "imad":      # (second build) the global load's register: word B where the load executed, the iteration's input elsewhere - read behind the fold's wait
        b.append(Ins("IMAD R10, R7, 0x9e3779b1, R10 ;", ("mad", "R10", "R7", 0x9e3779b1, "R10")))
    return b


def gp_exec(req, gids):
    """numpy bool per thread: does the READER execute in at least one iteration"""
    import numpy as np
    g, want = req["guards"], GP_FORMS[req["form"]][2]
    gids = np.asarray(gids)
    if g == "cnt":
        return np.ones(len(gids), bool)
    if g == "lane":      # the predicate is true where bit 1 of the lane is 0
        return (((gids % 1024) >> 1) & 1 == 0) == bool(want)
    return np.full(len(gids), g[1] == "t")


def gp_text(r):
    g = r["guards"]
    return (f"a guarded wait under ANOTHER predicate (version 27), form {r['form']}: {GP_FORMS[r['form']][0]} - no wait of its own, distance = its load -> the reader; "
            + (f"{GP_SHARE[r['share']]}; " if r["form"] == "imad" else "")
            + ("the wait bit stands on the carrier" if r["wait"] == "guarded"
               else "the POSITIVE CONTROL: the same text WITHOUT the carrier's wait bit (only the fold's own wait, 45 cycles and more behind the reader, drains the barrier)")
            + "; which side executes: "
            + ({"tt": "both, in every lane and iteration", "ft": "the READER's side only - the word that carries the wait never executes", "tf": "the carrier's side only - the reader never executes",
                "ff": "neither"}.get(g) or ("bit 0 of the lane decides the carrier's side and bit 1 the reader's: all four combinations inside every warp" if g == "lane"
                                            else "two bits of (iteration counter x 0x9e3779b1) decide: all four combinations over the iterations, the same in every lane"))
            + ("; both predicates are set ONCE in the prologue" if r["pset"] == "pro" else "; both predicates are set in every iteration by two ISETP.GE.AND 13 and 12 cycles in front of the first load")
            + "; the reader's result is DATA here (folded relative to the prologue's copy of the constant), never an address; stale = the reader took the pair's content from before its load")


# ------------------------------------------------------------------------------------------------ kind reuse (version 20)
# The operand-reuse flag. A 128-bit word has three flag bits - 122 (slot A) / 123 (slot B) / 124 (slot C); a slot IS its
# flag bit (the vendor's census decides it 780 to 0 on the IMAD pair of forms). In the seven forms below - and in most
# forms - the operand of bit 122 / 123 / 124 is the register field at bit 24 / 32 / 64; thirteen forms of the sm_120
# table pair a field with another bit (FADD R, R, R: the field at bit 32 carries bit 124) - none of them is used here.
# In the vendor's four served MoE texts (1 308 flags on 1 076 words, every one on a standard pair) every
# flag is followed by a reader of the SAME register through the SAME slot within 11 words and 11 issue cycles, with no
# write of the register, no label and no branch between, and every word of the window carries the yield flag at a
# stall <= 5: the texts cannot say what the hardware does when the register IS written inside the window.
# name: (slot, the word with {d} = its destination and {r} = the tested operand (R6 or R6.reuse), what it does for the
#        host model, the coefficient of R6 in its result (None: not linear), the vendor's row of that flag and its count)
REUSE_FORMS = {
    "IADD3i.A": ("A", "IADD3 {d}, PT, PT, {r}, 0x630, RZ ;", lambda d: ("add", d, "R6", 0x630), 1, "IADD3_R_P_P_R_II_R operand 4: 10 flags"),
    "IMADi.A": ("A", "IMAD {d}, {r}, 0x3, R5 ;", lambda d: ("mad", d, "R6", 3, "R5"), 3, "IMAD_R_R_II_R operand 2: 27 flags"),
    "PRMT.A": ("A", "PRMT {d}, {r}, 0x7632, R5 ;", lambda d: ("prmt", d, "R6", 0x7632, "R5"), None, "PRMT_R_R_II_R operand 2: 208 flags"),
    "IADD3.B": ("B", "IADD3 {d}, PT, PT, R5, {r}, RZ ;", lambda d: ("add", d, "R5", "R6"), 1, "IADD3_R_P_P_R_R_R operand 5: 86 flags"),
    "MOV.B": ("B", "MOV {d}, {r} ;", lambda d: ("mov", d, "R6"), 1, "MOV_R_R operand 2: 5 flags"),
    "IMADi.C": ("C", "IMAD {d}, R5, 0x3, {r} ;", lambda d: ("mad", d, "R5", 3, "R6"), 1, "IMAD_R_R_II_R operand 4: 10 flags"),
    "PRMT.C": ("C", "PRMT {d}, R5, 0x7632, {r} ;", lambda d: ("prmt", d, "R5", 0x7632, "R6"), None, "PRMT_R_R_II_R operand 4: 226 flags"),
}
REUSE_FIRST = {"A": "IADD3i.A", "B": "IADD3.B", "C": "IMADi.C"}
REUSE_WRITERS = {"none": "NO write of the flagged register: the positive control (the flag may not change a result)",
                 "clean": "the write by a word that does not read through the flagged slot",
                 "other": "the write by a word that reads ANOTHER register through the flagged slot",
                 "self": "a word that reads the flagged register through the flagged slot (no flag) and writes it",
                 "selff": "the flagged word ITSELF writes its flagged register (no other flagged word in front)",
                 "lds": "the write by a shared load on write barrier 1, which the reader waits"}
REUSE_BETWEEN = {None: "", "branch": "a taken BRA directly in front of the reader", "cbranch": "a taken conditional BRA directly in front of the reader",
                 "branch_f": "a taken BRA directly behind the flagged word",
                 "wait_r": "a global load is in flight in front of the flagged word and the READER waits its write barrier (the warp blocks)",
                 "wait_x": "a global load is in flight in front of the flagged word and the word behind the flagged word waits its write barrier (the warp blocks)"}


def reuse_writer(name, slot, flag):
    """-> (text, sem, write barrier): the WRITE of R6. R7 holds B = A + the constant, R14 the constant."""
    r6 = "R6.reuse" if flag else "R6"
    mov = ("MOV R6, R7 ;", ("mov", "R6", "R7"), "-")                                   # reads through slot B only
    addi = ("IADD3 R6, PT, PT, R7, 0x0, RZ ;", ("add", "R6", "R7", 0), "-")              # reads through slot A (and RZ through C)
    if name == "clean":
        return addi if slot == "B" else mov
    if name == "other":
        return addi if slot == "A" else mov if slot == "B" else ("IADD3 R6, PT, PT, RZ, RZ, R7 ;", ("add", "R6", "RZ", "R7"), "-")
    if name in ("self", "selff"):
        if slot == "A":
            return f"IADD3 R6, PT, PT, {r6}, 0x{LATE_CONST:x}, RZ ;", ("add", "R6", "R6", LATE_CONST), "-"
        if slot == "B":
            return f"IADD3 R6, PT, PT, R14, {r6}, RZ ;", ("add", "R6", "R14", "R6"), "-"
        return f"IMAD R6, R14, 0x1, {r6} ;", ("mad", "R6", "R14", 1, "R6"), "-"
    if name == "lds":
        return "LDS R6, [R9+0x20] ;", ("lds", "R6", "R9", 0x20, 1), "1"
    raise SystemExit(f"reuse: unknown writer {name!r}")


def reuse_filler(slot, kind, y, wait=""):
    """a one-cycle word of the window: clean = it does not read through the flagged slot, other = it reads R15 (RZ in slot C)
    through it. MOV reads through slot B only; IADD3 with an immediate through A, and RZ through C."""
    if (slot != "B") == (kind == "clean"):
        return Ins("MOV R15, R15 ;", ("nop",), ctl=C(1, wait=wait, y=y))
    return Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(1, wait=wait, y=y))


def reuse_extra(r):
    """issue cycles between the swept word and the reader that are not the swept word's own stall"""
    return (int(r["words"]) - 1) + (5 if r.get("between") in ("branch", "cbranch") else 0) \
        + (1 if (r.get("between") == "wait_x" and r["writer"] == "none") else 0)


def reuse_late_delta(r):
    """a stale reader of a linear form: checksum = good + (stale iterations) x this"""
    coef = REUSE_FORMS[r["reader"]][3]
    return None if (r["writer"] == "none" or coef is None) else (-coef * LATE_CONST) & 0xFFFFFFFF


def body_reuse(req, d, front, variant):
    """variant bare = the flag(s), ctl = the same text without `.reuse`. Tags: F the flagged word, P the write, C the reader,
    X a word a taken branch skips, L a label. The swept distance d = the stall of the swept word (the write; with
    writer none the flagged word) + the words between it and the reader."""
    flag = variant == "bare"
    slot, writer, k, btw = req["slot"], req["writer"], int(req["words"]), req.get("between")
    y = req.get("window_yield", "set") == "set"
    _fs, ftext, fsem, _fc, _frow = REUSE_FORMS[req["flagged"]]
    _rs, rtext, rsem, _rc, _rrow = REUSE_FORMS[req["reader"]]
    sw = d - reuse_extra(req)
    if not 1 <= sw <= (11 if y else 15):
        raise SystemExit(f"{req['id']}: distance {d} needs a stall of {sw} on the swept word (1..{11 if y else 15})")
    b = [Ins("IADD3 R6, PT, PT, R4, R5, RZ ;", ("add", "R6", "R4", "R5")),                                   # A
         Ins(f"IADD3 R7, PT, PT, R6, 0x{LATE_CONST:x}, RZ ;", ("add", "R7", "R6", LATE_CONST))]              # B = A + the constant
    if writer in ("self", "selff") and slot != "A":
        b.append(Ins(f"MOV R14, 0x{LATE_CONST:x} ;", ("mov", "R14", LATE_CONST)))
    if writer == "lds":      # what the load brings: B, stored with read barrier 3 (waited by the checksum word)
        b.append(Ins("STS [R9+0x20], R7 ;", ("sts", "R9", 0x20, "R7", 1), ctl=C(rb="3")))
    b += front_ins(front, False)
    if btw in ("wait_r", "wait_x"):      # word B of the thread (it holds R20): a global load in flight on write barrier 1
        b.append(Ins("LDG.E R12, desc[UR4][R18.64] ;", ("ldg", "R12", "R18"), ctl=C(2, wb="1")))
    fill = [reuse_filler(slot, req["fill"], y) for _ in range(k - 1)]

    def jump(cond):
        return [Ins(("@P0 " if cond else "") + "BRA L_r ;", ("nop",), ctl=C(5, y=y)),
                Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), tag="X"), Lbl("L_r")]

    if writer == "none":
        b.append(Ins(ftext.format(d="R8", r="R6.reuse" if flag else "R6"), fsem("R8"), ctl=C(sw, y=y), tag="F"))
        if btw == "wait_x":
            b.append(reuse_filler(slot, "clean", y, wait="1"))
        b += fill
    else:
        if writer != "selff":
            b.append(Ins(ftext.format(d="R8", r="R6.reuse" if flag else "R6"), fsem("R8"), ctl=C(int(req["fstall"]), y=y), tag="F"))
        if btw == "branch_f":
            b += jump(False)
        if btw == "wait_x":
            b.append(reuse_filler(slot, "clean", y, wait="1"))
        wtext, wsem, wwb = reuse_writer(writer, slot, flag and writer == "selff")      # (self: the same word WITHOUT the flag)
        b.append(Ins(wtext, wsem, ctl=C(sw, wb=wwb, y=y), tag="P", dst=["R6"]))
        b += fill
    if btw in ("branch", "cbranch"):
        b += jump(btw == "cbranch")
    rwait = "1" if (writer == "lds" or btw == "wait_r") else ""
    b.append(Ins(rtext.format(d="R13", r="R6.reuse" if (flag and req.get("chain")) else "R6"), rsem("R13"), ctl=C(2, wait=rwait, y=y), tag="C"))
    b.append(PAD())
    b.append(Ins("IADD3 R10, PT, PT, R10, R13, RZ ;", ("add", "R10", "R10", "R13"), ctl=C(wait="3" if writer == "lds" else "")))
    if writer != "selff":      # the flagged word's own result (it read A): part of the checksum too
        b.append(Ins("IADD3 R10, PT, PT, R10, R8, RZ ;", ("add", "R10", "R10", "R8")))
    return b


def prologue(req, ctas):
    """the same for every kernel of a request (and, but for the address of word B, of the tool)"""
    half = 1024 * ctas * 4
    p = [Ins("LDCU.64 UR4, c[0x0][0x358] ;", ("nop",), ctl=C(4, wb="0")),
         Ins("S2R R0, SR_TID.X ;", ("nop",), ctl=C(4, wb="1")),
         Ins("S2R R1, SR_CTAID.X ;", ("nop",), ctl=C(4, wb="2")),
         Ins("LDC.64 R2, c[0x0][0x380] ;", ("nop",), ctl=C(4, wb="3")),
         Ins("LDC R4, c[0x0][0x388] ;", ("nop",), ctl=C(8, wb="4")),
         Ins("IMAD R1, R1, 0x400, R0 ;", ("mad", "R1", "R1", 0x400, "R0"), ctl=C(wait="01234")),      # gid
         Ins("MOV R12, R1 ;", ("mov", "R12", "R1")),
         Ins("IADD3 R4, PT, PT, R4, R12, RZ ;", ("add", "R4", "R4", "R12")),                         # a0 = seed + gid
         Ins("LOP3.LUT R5, R12, 0x5bd1e995, RZ, 0x3c, !PT ;", ("xor", "R5", "R12", 0x5bd1e995)),      # b0
         Ins("MOV R10, RZ ;", ("mov", "R10", 0)), Ins("MOV R11, RZ ;", ("mov", "R11", 0)), Ins("MOV R15, RZ ;", ("nop",)),
         Ins("IMAD R9, R0, 0x40, RZ ;", ("base", "R9")),                                             # the thread's 64 bytes
         Ins("LOP3.LUT R20, R12, 0xa5a5a5a5, RZ, 0x3c, !PT ;", ("xor", "R20", "R12", 0xa5a5a5a5)),
         Ins("MOV R21, 0xf0f0f0f ;", ("mov", "R21", 0x0f0f0f0f)), Ins("MOV R22, 0xdeadbeef ;", ("mov", "R22", 0xdeadbeef)),
         Ins("IMAD R23, R12, 0x9e3779b1, RZ ;", ("mad", "R23", "R12", 0x9e3779b1, "RZ")),
         Ins("STS.128 [R9+0x30], R20 ;", ("sts", "R9", 0x30, "R20", 4)), Ins("STS.128 [R9], R20 ;", ("sts", "R9", 0, "R20", 4)),
         Ins("STS.128 [R9+0x10], R20 ;", ("sts", "R9", 0x10, "R20", 4)), Ins("STS.128 [R9+0x20], R20 ;", ("sts", "R9", 0x20, "R20", 4)),
         PAD(), PAD(), PAD(), PAD()]
    if req["kind"] not in ("mma", "thr") and not is_traw(req):
        p += [] if ordn_no_gaddr(req) else [Ins("IMAD.WIDE.U32 R16, R1, 0x4, R2 ;", ("gaddr", "R16", 0)),                          # A = &out[gid]
              Ins(f"MOV R14, 0x{half:x} ;", ("nop",)),
              Ins("IMAD.WIDE.U32 R18, R14, 0x1, R16 ;", ("gaddr", "R18", 1)),                        # B = A + half
              Ins("STG.E desc[UR4][R18.64], R20 ;", ("stg", "R18", "R20")),
              PAD(), PAD()]
    else:
        # uniform fragments: every element of B1 is 1.0 and of B2 is 2.0 (E2M1, one element per byte at bits 5:2), unit
        # block scales (UE8M0 0x7f); R9 and R20..R23 are NOT touched (the bare stores above read them when they are served)
        sp = MMA_SPEC[req["form"]]
        p += [Ins(f"MOV R12, 0x{sp['b1']:x} ;", ("mov", "R12", sp["b1"])), Ins(f"MOV R13, 0x{sp['b1']:x} ;", ("mov", "R13", sp["b1"])),
              Ins(f"MOV R6, 0x{sp['b2']:x} ;", ("mov", "R6", sp["b2"])), Ins("MOV R14, 0x7f7f7f7f ;", ("mov", "R14", 0x7f7f7f7f)),
              Ins("ISETP.EQ.U32.AND P0, PT, RZ, RZ, PT ;", ("mov", "P0", 1)), Ins("ISETP.EQ.U32.AND P2, PT, RZ, RZ, PT ;", ("mov", "P2", 1)),
              Ins("ISETP.NE.U32.AND P3, PT, RZ, RZ, PT ;", ("mov", "P3", 0)),
              Ins(f"MOV R7, 0x{sp['b2']:x} ;", ("mov", "R7", sp["b2"])), Ins("MOV R8, RZ ;", ("mov", "R8", 0)),
              Ins("MOV R24, RZ ;", ("mov", "R24", 0)), Ins("MOV R25, RZ ;", ("mov", "R25", 0)),
              Ins("MOV R26, RZ ;", ("mov", "R26", 0)), Ins("MOV R27, RZ ;", ("mov", "R27", 0))]
        if req["kind"] == "thr":      # version 26: + the stage's constants, + INIT (the head of every pass; the model runs ONE pass)
            p += thr_pro(req) + thr_init(req)
        return p
    p += [Ins("MOV R7, RZ ;", ("mov", "R7", 0)), Ins("MOV R8, RZ ;", ("mov", "R8", 0)),
         Ins("MOV R13, RZ ;", ("mov", "R13", 0)), Ins("MOV R14, RZ ;", ("mov", "R14", 0)),
         Ins("MOV R24, RZ ;", ("mov", "R24", 0)), Ins("MOV R25, RZ ;", ("mov", "R25", 0)),
         Ins("MOV R26, RZ ;", ("mov", "R26", 0)), Ins("MOV R27, RZ ;", ("mov", "R27", 0))]
    addr = req["kind"] == "raw" and RAW_CONSUMERS[req["consumer"]][0] == "addr"
    if req["kind"] == "raw" and RAW_CONSUMERS[req["consumer"]][0] == "udata":
        p += [Ins("UMOV UR6, 0x0 ;", ("mov", "UR6", 0)), Ins("UMOV UR7, 0x0 ;", ("mov", "UR7", 0)), Ins("UMOV UR8, 0x0 ;", ("mov", "UR8", 0))]
        if req["consumer"] in ("IADD.64.u2", "IADD.64.u2h"):      # version 27, third build
            p += [Ins("MOV R24, RZ ;", ("mov", "R24", 0)), Ins("MOV R25, RZ ;", ("mov", "R25", 0)), Ins("MOV R26, RZ ;", ("mov", "R26", 0)), Ins("MOV R27, RZ ;", ("mov", "R27", 0))]
    if req["kind"] == "raw" and (req["producer"] == "SEL" or req["consumer"] == "SEL.r1"):
        p.append(Ins("ISETP.LT.U32.AND P2, PT, RZ, RZ, PT ;", ("mov", "P2", 0)))
    if req["kind"] == "war" and req["store"] == "STS.addr" and req["overwriter"] == "LDS":
        # the address the overwriting load brings: word 3 of slot 3 := the address of slot 3 (a store with a read barrier, waited)
        p += [Ins("IADD3 R13, PT, PT, R9, 0x30, RZ ;", ("add", "R13", "R9", 0x30)),
              Ins("STS [R9+0x3c], R13 ;", ("sts", "R9", 0x3c, "R13", 1), ctl=C(rb="5")),
              Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="5")), PAD()]
    if req["kind"] == "lb":      # version 26, third build
        p += lb_pro(req)
    if req["kind"] == "gp":      # version 27
        p += gp_pro(req)
    if addr:      # a stale ADDRESS must still be an address of the thread's own slot
        p += [Ins("IADD3 R6, PT, PT, R9, 0x20, RZ ;", ("add", "R6", "R9", 0x20)),
              Ins("IADD3 R13, PT, PT, R9, 0x20, RZ ;", ("add", "R13", "R9", 0x20))]
    else:
        p.append(Ins("MOV R6, RZ ;", ("mov", "R6", 0)))
    if (req["kind"] == "ord" and (req.get("younger_guard") or req.get("older_guard") or (req.get("forms") and any(x.strip()[:1] in ("g", "f") for x in str(req["forms"]).split(","))))) \
            or (req["kind"] == "reuse" and req.get("between") == "cbranch"):
        p += [Ins("ISETP.EQ.U32.AND P0, PT, RZ, RZ, PT ;", ("nop",)), Ins("ISETP.NE.U32.AND P3, PT, RZ, RZ, PT ;", ("nop",))]
    if req["kind"] == "ord" and req.get("nload") and req.get("place") == "far":
        # R14 = the thread's word in the second region; word k := a per-thread constant (a store with read barrier 5, waited)
        fb, stride = far_layout(int(req.get("_threads", 1024)))
        p += [Ins("IMAD R14, R0, 0x4, RZ ;", ("nop",)), Ins(f"IADD3 R14, PT, PT, R14, 0x{fb:x}, RZ ;", ("nop",))]
        for k in range(int(req["nload"])):
            c = (0x9e3779b1 * (k + 1)) & 0xFFFFFFFF
            p += [Ins(f"IADD3 R13, PT, PT, R20, 0x{c:x}, RZ ;", ("add", "R13", "R20", c)),
                  Ins(f"STS [R14{('+0x%x' % (k * stride)) if k else ''}], R13 ;", ("stsf", k, "R13"), ctl=C(rb="5")),
                  Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="5"))]
        p += [PAD(), PAD()]
    if is_set(req):      # version 23
        lets = {let for _g, let, _r, _a in set_plan(req)}
        if req.get("cold") == "set":
            # (third build) R76:R77 = out + 4 x threads = the tail of block 0 (the words behind the threads' own, never written:
            # the runner's zeros); R78:R79 = the same until the loop writes R78
            thr = int(req.get("_threads", 512))
            p += [Ins(f"MOV R13, 0x{4 * thr:x} ;", ("nop",)),
                  Ins(f"IMAD.WIDE.U32 R{SET_ABASE}, R13, 0x1, R2 ;", ("nop",)),
                  Ins(f"MOV R{SET_CBASE}, R{SET_ABASE} ;", ("nop",)), Ins(f"MOV R{SET_CBASE + 1}, R{SET_ABASE + 1} ;", ("nop",)),
                  Ins("MOV R13, RZ ;", ("mov", "R13", 0)), PAD(), PAD()]
        elif lets & {"Q", "B"}:
            # R76:R77 = the address of the first B word of the thread's WARP: A of lane 0 (out + 4 * (gid & ~31)) + half. The
            # 32 B words of the warp were stored above by ONE instruction of the warp (every lane its own word, R20).
            p += [Ins("LOP3.LUT R13, R1, 0xffffffe0, RZ, 0xc0, !PT ;", ("nop",)),
                  Ins(f"MOV R14, 0x{half:x} ;", ("nop",)),
                  Ins(f"IMAD.WIDE.U32 R{SET_ABASE}, R13, 0x4, R2 ;", ("nop",)),
                  Ins(f"IMAD.WIDE.U32 R{SET_ABASE}, R14, 0x1, R{SET_ABASE} ;", ("nop",)),
                  Ins("MOV R13, RZ ;", ("mov", "R13", 0)), Ins("MOV R14, RZ ;", ("mov", "R14", 0)), PAD(), PAD()]
        if "m" in lets:
            # R74 = a finite float of the thread's constant; R75 = MUFU.EX2 of it, taken once behind its own wait (the
            # model's stand-in is a constant: the reader only ever takes the difference register - R75)
            p += fin(SET_MSRC, 20)
            p += [Ins(f"MUFU.EX2 R{SET_MREF}, R{SET_MSRC} ;", ("mov", f"R{SET_MREF}", 0x3fc00000), ctl=C(4, wb="5")),
                  Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="5")), PAD()]
        if "M" in lets:
            # the tensor set: slot 3 (the LDSM's 16 bytes) and slot 2 (the two LDS words) of every thread's line := the code of
            # 1.0 in every element - stores with a read barrier, waited; behind the prologue's bare stores of the same slots
            one = MMA_SPEC["HMMA.BF16"]["a0"]
            p += [Ins(f"MOV R{r}, 0x{one:x} ;", ("mov", f"R{r}", one)) for r in (28, 29, 30, 31)]
            p += [Ins("STS.128 [R9+0x30], R28 ;", ("sts", "R9", 0x30, "R28", 4), ctl=C(rb="5")),
                  Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="5")),
                  Ins("STS.128 [R9+0x20], R28 ;", ("sts", "R9", 0x20, "R28", 4), ctl=C(rb="5")),
                  Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="5")), PAD(), PAD()]
        if lets & set(SF_LET):
            # version 29 - the scale set: slot 2 of every thread's line (the words the LDS take) := the UE8M0 code of the unit
            # scale in every byte - a store with a read barrier, waited, behind the prologue's bare stores of the same slot; the
            # B fragments of the two readers (every element 1.0 | 2.0); the second base register; (second build) with ONE S
            # the readers' other scale operand, the unit scale
            sf_, sl_ = MMA_SPEC[SF_FORM], sf_layout(set_plan(req))
            p += [Ins(f"MOV R{r}, 0x{SF_UNIT:x} ;", ("mov", f"R{r}", SF_UNIT)) for r in (28, 29, 30, 31)]
            p += [Ins("STS.128 [R9+0x20], R28 ;", ("sts", "R9", 0x20, "R28", 4), ctl=C(rb="5")),
                  Ins("IADD3 R15, PT, PT, R15, 0x1, RZ ;", ("nop",), ctl=C(wait="5")),
                  Ins(f"MOV R{sl_['b1']}, 0x{sf_['b1']:x} ;", ("mov", f"R{sl_['b1']}", sf_["b1"])), Ins(f"MOV R{sl_['b1'] + 1}, 0x{sf_['b1']:x} ;", ("mov", f"R{sl_['b1'] + 1}", sf_["b1"])),
                  Ins(f"MOV R{sl_['b2']}, 0x{sf_['b2']:x} ;", ("mov", f"R{sl_['b2']}", sf_["b2"])), Ins(f"MOV R{sl_['b2'] + 1}, 0x{sf_['b2']:x} ;", ("mov", f"R{sl_['b2'] + 1}", sf_["b2"])),
                  Ins(f"MOV R{sl_['base2']}, R9 ;", ("mov", f"R{sl_['base2']}", "R9"))]
            if sum(1 for _g, l_, _r, _a in set_plan(req) if l_ == "S") == 1:
                p.append(Ins(f"MOV R{sl_['one']}, 0x{SF_UNIT:x} ;", ("mov", f"R{sl_['one']}", SF_UNIT)))
            p += [PAD(), PAD()]
    return p


TAIL = [Ins("IADD3 R4, PT, PT, R4, 0x9e3779b9, RZ ;", ("add", "R4", "R4", 0x9e3779b9)),
        Ins("IADD3 R5, PT, PT, R5, 0x7f4a7c15, RZ ;", ("add", "R5", "R5", 0x7f4a7c15)),
        Ins("IADD3 R11, PT, PT, R11, 0x1, RZ ;", ("add", "R11", "R11", 1))]


def misaligned(text):
    """operands the card refuses at the first launch although the assembler takes them: a 64-bit register pair on an odd
    register, a 128-bit operand (or a tensor instruction's result / A fragment) off a multiple of four. -> list of problems"""
    bad = []
    for line in text.splitlines():
        m = re.match(r"\s*\[B[^\]]*\]\s+(?:@!?U?P[\dT]\s+)?(\S+)\s+(.*?)\s*;", line)
        if not m:
            continue
        op, rest = m.group(1), m.group(2)
        ops = [o.strip() for o in re.split(r",(?![^\[]*\])", rest)]
        regs = lambda o: [int(x) for x in re.findall(r"(?<![UA-Za-z])R(\d+)\b", o)]
        for n in re.findall(r"(?<![UA-Za-z])R(\d+)\.64", rest):
            if int(n) % 2:
                bad.append(f"{op}: a 64-bit address pair on R{n}")
        if op.startswith(("IADD.64", "CS2R", "LDC.64", "MOV.64", "IMAD.WIDE")):
            pair = ops[:1] if op.startswith(("CS2R", "LDC.64", "IMAD.WIDE")) else [o for o in ops if re.fullmatch(r"-?R\d+", o)]
            if op.startswith("IMAD.WIDE") and len(ops) >= 4 and re.fullmatch(r"R\d+", ops[-1]):
                pair = pair + [ops[-1]]
            for o in pair:
                for n in regs(o):
                    if n % 2:
                        bad.append(f"{op}: a 64-bit pair on R{n}")
        if op.startswith(("LDS.64", "STS.64", "LDG.E.64", "STG.E.64")):
            for o in ops:
                if "[" not in o:
                    for n in regs(o):
                        if n % 2:
                            bad.append(f"{op}: a 64-bit data pair on R{n}")
        if ".128" in op or op.startswith("LDSM"):
            for o in ops:
                if "[" not in o:
                    for n in regs(o):
                        if n % 4:
                            bad.append(f"{op}: a 128-bit operand on R{n}")
        if re.match(r"[A-Z]MMA", op):
            for k, o in enumerate(ops[:4]):
                for n in regs(o):
                    if n % (2 if k == 2 else 4):
                        bad.append(f"{op}: operand {k} on R{n}")
    return bad


def kernel_text(name, req, ctas, body, smem=SMEM):
    if req["kind"] == "thr":      # version 26: the outer loop, R0-R47
        return thr_kernel_text(name, req, ctas, body, smem)
    lines = [f".entry {name}", "    .reg R0-R31", "    .regcount 40", "    .param ptr out", "    .param u32 seed", f"    .shared smem[{smem}]"]
    if is_set(req):      # version 23: the destinations of a set are R32..R72 (a register above the declared count traps)
        lines[1:3] = [f"    .reg R0-R{SET_REGS - 1}", f"    .regcount {SET_REGS + 8}"]
    lines += [f"    {i.line()}" for i in prologue(req, ctas)]
    lines.append("L_loop:")
    lines += [f"    {i.line()}" for i in body]
    lines += [f"    {i.line()}" for i in TAIL]
    lines += [f"    {C()} ISETP.LT.U32.AND P1, PT, R11, 0x{REPEAT:x}, PT ;", f"    {C()} @P1 BRA L_loop ;",
              f"    {C()} IMAD.WIDE.U32 R2, R1, 0x4, R2 ;", f"    {C()} STG.E desc[UR4][R2.64], R10 ;", f"    {C()} EXIT ;", ".endentry", ""]
    text = "\n".join(lines)
    bad = misaligned(text)
    if bad:
        raise SystemExit(f"{name}: refusing to write a kernel the card would trap on - {sorted(set(bad))}")
    return text


# ------------------------------------------------------------------------------------------------ the host model
class Poison(Exception):
    pass


def model(req, mode, gids=None, scalar=False):
    """the checksum (R10) every thread must end with, per failure hypothesis `mode`:
    good | stale (raw) | late, overtake (war). numpy over all gids, or (scalar=True) plain Python integers - the
    independent check of the vectorised code."""
    import numpy as np
    if gids is None:
        gids = np.arange(NGID, dtype=np.int64)
    if shfl_of(req) and not scalar:      # (version 18: also write-after-write with a shuffle, and an older shuffle of kind ord)
        gids = np.asarray(gids, dtype=np.int64)
        need = np.union1d(gids, (gids ^ 1) if shfl_of(req) == "bfly" else ((gids & ~31) | 1))
        if len(need) != len(gids):      # a shuffle reads another lane: model the closed set, return the threads asked for
            return model(req, mode, gids=need)[np.searchsorted(need, gids)]
    if req["kind"] == "war":
        body = body_war(req, 15, "none", "bare")
    elif req["kind"] == "ord":
        body = body_ord(req, 15, "none", "bare")
    elif req["kind"] == "mma":
        body = body_mma(dict(req, via="stall"), 15, req.get("_model_front", "none"))
    elif req["kind"] == "reuse":
        body = body_reuse(req, max(req["distance_list"]), "none", "bare")
    elif req["kind"] == "thr":      # version 26: every slot has the base stage's arithmetic
        body = body_thr(req, 1, "none")
    elif req["kind"] == "gw":       # version 26, second build
        body = body_gw(req, max(req["distance_list"]), "none")
    elif req["kind"] == "lb":       # version 26, third build
        body = body_lb(req, 15, "none")
    elif req["kind"] == "gp":       # version 27
        body = body_gp(req, max(req["distance_list"]), "none")
    else:
        body = body_raw(dict(req, via="stall"), 15, "none")
    if mode in ("drop1", "drop2"):      # mma: the first / the second MMA changed nothing in any iteration
        body = [i for i in body if i.tag != ("P" if mode == "drop1" else "C")]
        mode = "good"
    if mode == "p0old":      # version 28, second build: every ISETP directly behind the shift of its source read the source's OLD content, in every iteration
        b2, k_ = [], 0
        while k_ < len(body):
            if body[k_].tag == "PS" and k_ + 1 < len(body) and body[k_ + 1].sem[0] == "sge0":
                b2 += [body[k_ + 1], body[k_]]
                k_ += 2
            else:
                b2.append(body[k_])
                k_ += 1
        body, mode = b2, "good"
    pro = prologue(req, 188)
    if scalar and req["kind"] == "thr":      # version 26: one pass (the stage carries its own tail), the fold, x repeat
        return [(_scalar(int(g), pro, body, mode, tail=[], post=thr_post(req)) * int(req["repeat"])) & 0xFFFFFFFF for g in gids]
    if scalar:
        return [_scalar(int(g), pro, body, mode) for g in gids]
    n = len(gids)
    U = np.uint32
    R = {"R0": (gids % 1024).astype(U), "R1": (gids // 1024).astype(U), "R4": np.full(n, SEED, U),
         "R17": np.zeros(n, U), "R19": np.zeros(n, U), "RZ": np.zeros(n, U),
         "R2": np.zeros(n, U), "R3": np.zeros(n, U)}      # (version 23: the model's stand-in for the output pointer)
    mem = np.zeros((n, 16), U)
    farmem = np.zeros((n, 16), U)
    G = np.zeros((n, 2), U)
    rows = np.arange(n)
    consts = {}

    def get(x):
        if isinstance(x, int):
            if x not in consts:
                consts[x] = np.full(n, x & 0xFFFFFFFF, U)
            return consts[x]
        v = R.get(x)
        if v is None:
            raise Poison(x)
        return v

    def reg(r, k):
        return f"R{int(r[1:]) + k}"

    def ex(sem):
        op = sem[0]
        if op == "nop":
            return
        if op == "mov":
            R[sem[1]] = get(sem[2])
        elif op == "add":
            R[sem[1]] = get(sem[2]) + get(sem[3])
        elif op == "add3":
            R[sem[1]] = get(sem[2]) + get(sem[3]) + get(sem[4])
        elif op == "xor":
            R[sem[1]] = get(sem[2]) ^ get(sem[3])
        elif op == "and":
            R[sem[1]] = get(sem[2]) & get(sem[3])
        elif op == "or":
            R[sem[1]] = get(sem[2]) | get(sem[3])
        elif op == "mad":
            R[sem[1]] = get(sem[2]) * get(sem[3]) + get(sem[4])
        elif op == "shl":
            R[sem[1]] = get(sem[2]) << U(sem[3])
        elif op == "shr":
            R[sem[1]] = get(sem[2]) >> U(sem[3])
        elif op in ("fadd", "fmul"):
            a, b = get(sem[2]).view(np.float32), get(sem[3]).view(np.float32)
            R[sem[1]] = ((a + b) if op == "fadd" else (a * b)).astype(np.float32).view(U)
        elif op == "ltu":
            R[sem[1]] = (get(sem[2]) < get(sem[3])).astype(U)
        elif op == "sel":           # P ? a : b
            R[sem[1]] = np.where(get(sem[4]) != 0, get(sem[2]), get(sem[3]))
        elif op == "selnot":        # !P ? a : b
            R[sem[1]] = np.where(get(sem[4]) != 0, get(sem[3]), get(sem[2]))
        elif op == "rsub":
            R[sem[1]] = get(sem[3]) - get(sem[2])
        elif op == "prmt":          # byte i of the result = byte (nibble i of the selector) of the 8 bytes Rb:Ra
            pool = get(sem[2]).astype(np.uint64) | (get(sem[4]).astype(np.uint64) << np.uint64(32))
            out = np.zeros(n, np.uint64)
            for k in range(4):
                nib = (sem[3] >> (4 * k)) & 7
                out |= ((pool >> np.uint64(8 * nib)) & np.uint64(0xFF)) << np.uint64(8 * k)
            R[sem[1]] = out.astype(U)
        elif op == "gprmt":         # version 26, second build: a PRMT under a guard - done where (predicate != 0) == sem[6]
            pool = get(sem[2]).astype(np.uint64) | (get(sem[4]).astype(np.uint64) << np.uint64(32))
            out = np.zeros(n, np.uint64)
            for k in range(4):
                nib = (sem[3] >> (4 * k)) & 7
                out |= ((pool >> np.uint64(8 * nib)) & np.uint64(0xFF)) << np.uint64(8 * k)
            R[sem[1]] = np.where((get(sem[5]) != 0) == bool(sem[6]), out.astype(U), get(sem[1])).astype(U)
        elif op == "zero2u":        # version 27, third build: two uniform registers := 0 (a 64-bit CS2UR of SRZ)
            R[sem[1]], R[sem[2]] = np.zeros(n, U), np.zeros(n, U)
        elif op == "sub64u":        # version 27, third build: the pair R(d+1):Rd = (UR hi : UR lo) - R(c+1):Rc (mod 2^64)
            v = ((get(sem[2]).astype(np.uint64) | (get(sem[3]).astype(np.uint64) << np.uint64(32)))
                 - (get(sem[4]).astype(np.uint64) | (get(reg(sem[4], 1)).astype(np.uint64) << np.uint64(32))))
            R[sem[1]] = (v & np.uint64(0xFFFFFFFF)).astype(U)
            R[reg(sem[1], 1)] = (v >> np.uint64(32)).astype(U)
        elif op == "g":             # version 27: a word under a guard - done where (predicate != 0) == sem[2]; elsewhere its destinations keep their content
            m = (get(sem[1]) != 0) == bool(sem[2])
            keep = {r_: get(r_) for r_ in sem[3]}
            ex(sem[4])
            for r_, v_ in keep.items():
                R[r_] = np.where(m, get(r_), v_).astype(U)
        elif op == "sge0":          # version 27: ISETP.GE against zero - the register as a signed 32-bit integer >= 0
            R[sem[1]] = (get(sem[2]) < U(0x80000000)).astype(U)
        elif op == "lea":           # version 27: Rd = Rb + (Ra << k); the predicate = the carry out of bit 31
            v = get(sem[3]).astype(np.uint64) + ((get(sem[2]).astype(np.uint64) << np.uint64(sem[4])) & np.uint64(0xFFFFFFFF))
            R[sem[1]] = (v & np.uint64(0xFFFFFFFF)).astype(U)
            R[sem[5]] = (v >> np.uint64(32)).astype(U)
        elif op == "leahi":         # version 27: Rd = Rb + the high word of ((Rc:Ra) << k) + the carry predicate
            hi = ((get(sem[4]).astype(np.uint64) << np.uint64(sem[5])) | (get(sem[2]).astype(np.uint64) >> np.uint64(32 - sem[5]))) & np.uint64(0xFFFFFFFF)
            R[sem[1]] = ((get(sem[3]).astype(np.uint64) + hi + (get(sem[6]) != 0).astype(np.uint64)) & np.uint64(0xFFFFFFFF)).astype(U)
        elif op == "bf16pack2":     # round to nearest even at bit 16, the same bf16 in both halves
            x = get(sem[2])
            h = ((x.astype(np.uint64) + np.uint64(0x7FFF) + ((x >> U(16)) & U(1)).astype(np.uint64)) >> np.uint64(16)) & np.uint64(0xFFFF)
            R[sem[1]] = ((h << np.uint64(16)) | h).astype(U)
        elif op == "i2f":
            R[sem[1]] = get(sem[2]).view(np.int32).astype(np.float32).view(U)
        elif op == "add64i":        # the pair R(d+1):Rd = R(a+1):Ra + imm
            v = (get(sem[2]).astype(np.uint64) | (get(reg(sem[2], 1)).astype(np.uint64) << np.uint64(32))) + np.uint64(sem[3])
            R[sem[1]] = (v & np.uint64(0xFFFFFFFF)).astype(U)
            R[reg(sem[1], 1)] = (v >> np.uint64(32)).astype(U)
        elif op == "add64":         # version 25: the pair R(d+1):Rd = R(a+1):Ra + R(b+1):Rb (mod 2^64)
            v = ((get(sem[2]).astype(np.uint64) | (get(reg(sem[2], 1)).astype(np.uint64) << np.uint64(32)))
                 + (get(sem[3]).astype(np.uint64) | (get(reg(sem[3], 1)).astype(np.uint64) << np.uint64(32))))
            R[sem[1]] = (v & np.uint64(0xFFFFFFFF)).astype(U)
            R[reg(sem[1], 1)] = (v >> np.uint64(32)).astype(U)
        elif op == "qmma":          # every element of the result = its accumulator + 32 * a * b (integer-valued, exact)
            if sem[4] is not None and not int(get(sem[4])[0]):
                return
            sp = MMA_SPEC[sem[5]]
            av, bv = int(get(sem[2])[0]) & sp["amask"], int(get(sem[3])[0]) & sp["bmask"]
            if (get(sem[2]) != get(sem[2])[0]).any() or av not in sp["aval"] or bv not in sp["bval"]:
                raise RuntimeError(f"model: an MMA fragment the model does not know ({sem})")
            for k in range(4):
                R[reg(sem[1], k)] = get(reg(sem[1], k)) + U(sp["k"] * sp["aval"][av] * sp["bval"][bv])
        elif op == "qmmasf":        # version 29: a QMMA.SF with uniform fragments whose two block-scale registers hold, in every byte, the UE8M0 code of x 1 or of x 2 (per thread): result = accumulator + 32 a b x the two scales
            sp = MMA_SPEC[sem[6]]
            av, bv = int(get(sem[2])[0]) & sp["amask"], int(get(sem[3])[0]) & sp["bmask"]
            if (get(sem[2]) != get(sem[2])[0]).any() or (get(sem[3]) != get(sem[3])[0]).any() or av not in sp["aval"] or bv not in sp["bval"]:
                raise RuntimeError(f"model: an MMA fragment the model does not know ({sem})")
            sh = np.zeros(n, U)
            for s_ in (sem[4], sem[5]):
                v_ = get(s_)
                if ((v_ != U(SF_UNIT)) & (v_ != U(SF_MARK))).any():
                    raise RuntimeError(f"model: a block scale the model does not know ({sem})")
                sh = sh + (v_ == U(SF_MARK)).astype(U)
            add = (np.full(n, sp["k"] * sp["aval"][av] * sp["bval"][bv], U) << sh).astype(U)
            for k in range(4):
                R[reg(sem[1], k)] = get(reg(sem[1], k)) + add
        elif op == "tmma":          # version 24: a tensor word with uniform fragments - result k = accumulator k + K a b (a ZERO accumulator: float(K a b))
            sp = MMA_SPEC[sem[4]]
            fa, fb = [get(reg(sem[2], k)) for k in range(4)], [get(reg(sem[3], k)) for k in range(2)]
            if any((x != fa[0]).any() for x in fa[1:]) or (fb[1] != fb[0]).any():
                raise Poison("tmma: the registers of a fragment differ - the result depends on the fragment layout")
            av, bv = int(fa[0][0]) & sp["amask"], int(fb[0][0]) & sp["bmask"]
            if (fa[0] != fa[0][0]).any() or (fb[0] != fb[0][0]).any() or av not in sp["aval"] or bv not in sp["bval"]:
                raise RuntimeError(f"model: an MMA fragment the model does not know ({sem})")
            add = sp["k"] * sp["aval"][av] * sp["bval"][bv]
            fz = U(int(np.array([add], np.float32).view(U)[0]))
            for k in range(4):
                acc = get(reg(sem[5] if len(sem) > 5 else sem[1], k))      # (fifth build: the accumulator quad may be another one than the destination)
                isz = acc == U(0)
                if (~isz & ((acc >> U(23)) != U(0x96))).any():
                    raise RuntimeError(f"model: an accumulator the model does not know ({sem})")
                R[reg(sem[1], k)] = np.where(isz, fz, acc + U(add)).astype(U)
        elif op == "ffma":          # version 22: a * b + c with ONE rounding - exact in float64 for the catalogue's operands (a = 3.0)
            fa, fb, fc = (get(x).view(np.float32).astype(np.float64) for x in sem[2:5])
            R[sem[1]] = (fa * fb + fc).astype(np.float32).view(U)
        elif op == "rcp2":          # version 22: the reciprocal of a power of two (positive, zero mantissa); of +0.0: +inf
            x = get(sem[2])
            R[sem[1]] = np.where(x == U(0), U(0x7F800000), U(0x7F000000) - x).astype(U)
        elif op == "iabs":          # version 22: |x| of a 32-bit integer (0x80000000 stays)
            x = get(sem[2])
            R[sem[1]] = np.where(x >= U(0x80000000), (x ^ U(0xFFFFFFFF)) + U(1), x).astype(U)
        elif op == "zero2":
            R[sem[1]] = np.zeros(n, U)
            R[reg(sem[1], 1)] = np.zeros(n, U)
        elif op == "shl64hi":       # the high word of (hi:lo) << k
            R[sem[1]] = (get(sem[4]) << U(sem[3])) | (get(sem[2]) >> U(32 - sem[3]))
        elif op == "mulw":
            v = get(sem[2]).astype(np.uint64) * get(sem[3]).astype(np.uint64)
            R[sem[1]] = (v & np.uint64(0xFFFFFFFF)).astype(U)
            R[reg(sem[1], 1)] = (v >> np.uint64(32)).astype(U)
        elif op == "madw":          # the pair R(d+1):Rd = Ra * Rb + R(c+1):Rc (mod 2^64)
            v = (get(sem[2]).astype(np.uint64) * get(sem[3]).astype(np.uint64)
                 + (get(sem[4]).astype(np.uint64) | (get(reg(sem[4], 1)).astype(np.uint64) << np.uint64(32))))
            R[sem[1]] = (v & np.uint64(0xFFFFFFFF)).astype(U)
            R[reg(sem[1], 1)] = (v >> np.uint64(32)).astype(U)
        elif op == "base":
            R[sem[1]] = np.zeros(n, U)
        elif op == "gaddr":
            R[sem[1]] = np.full(n, sem[2], U)
        elif op == "sts":
            a = get(sem[1]) + U(sem[2])
            if (a & U(3)).any() or (a > U(64 - 4 * sem[4])).any():
                raise RuntimeError(f"model: a shared store outside the thread's 64 bytes ({sem})")
            w = (a >> U(2)).astype(np.int64)
            for k in range(sem[4]):
                mem[rows, w + k] = get(reg(sem[3], k))
        elif op == "lds":
            a = get(sem[2]) + U(sem[3])
            if (a & U(3)).any() or (a > U(64 - 4 * sem[4])).any():
                raise RuntimeError(f"model: a shared load outside the thread's 64 bytes ({sem})")
            w = (a >> U(2)).astype(np.int64)
            for k in range(sem[4]):
                R[reg(sem[1], k)] = mem[rows, w + k]
        elif op == "ldsu16":        # 16 bits of the thread's slot, zero-extended
            a = get(sem[2]) + U(sem[3])
            R[sem[1]] = mem[rows, (a >> U(2)).astype(np.int64)] & U(0xFFFF)
        elif op == "poison":
            for k in range(sem[2]):
                R[reg(sem[1], k)] = None
        elif op == "stsf":          # word k of the thread's far region
            farmem[rows, sem[1]] = get(sem[2])
        elif op == "ldsf":
            R[sem[1]] = farmem[rows, sem[2]].copy()
        elif op == "stg":
            G[rows, get(sem[1]).astype(np.int64)] = get(sem[2])
        elif op == "ldg":
            R[sem[1]] = G[rows, get(sem[2]).astype(np.int64)]
        elif op == "ldgq":          # version 23: quad k of the B words of the thread's warp (R1 = gid; word B of gid g = g ^ 0xa5a5a5a5)
            for k in range(4):
                R[reg(sem[1], k)] = ((get("R1") & U(0xFFFFFFE0)) + U(4 * sem[2] + k)) ^ U(0xA5A5A5A5)
        elif op == "ldgb":          # version 23: byte i of those 128 bytes, zero-extended
            R[sem[1]] = ((((get("R1") & U(0xFFFFFFE0)) + U(sem[2] // 4)) ^ U(0xA5A5A5A5)) >> U(8 * (sem[2] % 4))) & U(0xFF)
        elif op == "mov2":          # version 23: a pair
            R[sem[1]], R[reg(sem[1], 1)] = get(sem[2]), get(reg(sem[2], 1))
        elif op == "zeron":         # version 23 (third build): n registers of zeros (a cold load of the buffer's never-written words)
            for k in range(sem[2]):
                R[reg(sem[1], k)] = np.zeros(n, U)
        elif op == "shfl":          # every lane takes the register of another lane of its warp: lane ^ k (bfly) or lane k (idx)
            src = (gids ^ sem[4]) if sem[3] == "bfly" else ((gids & ~31) | sem[4])
            pos = np.minimum(np.searchsorted(gids, src), n - 1)
            if (gids[pos] != src).any():
                raise RuntimeError("model: a shuffle needs its source lanes among the modelled threads")
            R[sem[1]] = get(sem[2])[pos]
        else:
            raise RuntimeError(f"model: unknown op {sem}")

    for i in pro:
        ex(i.sem)
    last_b = max((k for k, i in enumerate(body) if i.tag == "B"), default=-1)
    for _ in range(REPEAT):
        old, deferred = {}, None
        for k, i in enumerate(body):
            if mode in ("stale", "stale1", "stale2", "stale3") and i.tag == "P":      # (version 29: stale1 / stale2 / stale3)
                old.update({r: R[r] for r in i.dst if r in R})      # (several producers in front of one reader: all stale)
                ex(i.sem)
            elif (mode == "stale" and i.tag in ("C", "C2", "C3")) or (mode == "stale1" and i.tag == "C") or (mode == "stale2" and i.tag == "C2") or (mode == "stale3" and i.tag == "C3"):      # (version 29: the scale set's second tensor reader has the tag C2, its MOV readers C3)
                cur = {r: R[r] for r in old}
                R.update(old)
                ex(i.sem)
                R.update({r: v for r, v in cur.items() if r not in i.dst})      # (version 24: a consumer that writes the tested register keeps its result)
            elif mode in ("late", "overtake") and i.tag == "S":
                deferred = i
            elif mode == "late" and i.tag == "O":
                ex(i.sem)
                ex(deferred.sem)
                deferred = None
            elif mode == "overtake" and k == last_b:
                ex(i.sem)
                ex(deferred.sem)
                deferred = None
            else:
                ex(i.sem)
        if deferred is not None:
            raise RuntimeError(f"model: mode {mode} found no place for the deferred store")
        for i in ([] if req["kind"] == "thr" else TAIL):
            ex(i.sem)
    if req["kind"] == "thr":      # version 26: the fold behind the 256 iterations of ONE pass; every pass adds the same amount
        for i in thr_post(req):
            ex(i.sem)
        return (R["R10"] * U(int(req["repeat"]))).astype(U)
    return R["R10"].copy()


def _machine(gid):
    """one thread on Python integers -> (its registers, get, ex)"""
    M = 0xFFFFFFFF
    R = {"R0": gid % 1024, "R1": gid // 1024, "R4": SEED, "R17": 0, "R19": 0, "RZ": 0, "R2": PTR_STANDIN[0], "R3": PTR_STANDIN[1]}
    mem, farmem, G = [0] * 16, [0] * 16, [0, 0]

    def get(x):
        if isinstance(x, int):
            return x & M
        v = R.get(x)
        if v is None:
            raise Poison(x)
        return v

    def reg(r, k):
        return f"R{int(r[1:]) + k}"

    def ex(sem):
        import struct
        op = sem[0]
        if op == "nop":
            return
        if op == "mov":
            R[sem[1]] = get(sem[2])
        elif op == "add":
            R[sem[1]] = (get(sem[2]) + get(sem[3])) & M
        elif op == "add3":
            R[sem[1]] = (get(sem[2]) + get(sem[3]) + get(sem[4])) & M
        elif op == "xor":
            R[sem[1]] = get(sem[2]) ^ get(sem[3])
        elif op == "and":
            R[sem[1]] = get(sem[2]) & get(sem[3])
        elif op == "or":
            R[sem[1]] = get(sem[2]) | get(sem[3])
        elif op == "mad":
            R[sem[1]] = (get(sem[2]) * get(sem[3]) + get(sem[4])) & M
        elif op == "shl":
            R[sem[1]] = (get(sem[2]) << sem[3]) & M
        elif op == "shr":
            R[sem[1]] = get(sem[2]) >> sem[3]
        elif op in ("fadd", "fmul"):
            a = struct.unpack("<f", struct.pack("<I", get(sem[2])))[0]
            b = struct.unpack("<f", struct.pack("<I", get(sem[3])))[0]
            R[sem[1]] = struct.unpack("<I", struct.pack("<f", a + b if op == "fadd" else a * b))[0]
        elif op == "ltu":
            R[sem[1]] = 1 if get(sem[2]) < get(sem[3]) else 0
        elif op == "sel":
            R[sem[1]] = get(sem[2]) if get(sem[4]) else get(sem[3])
        elif op == "selnot":
            R[sem[1]] = get(sem[3]) if get(sem[4]) else get(sem[2])
        elif op == "rsub":
            R[sem[1]] = (get(sem[3]) - get(sem[2])) & M
        elif op == "prmt":
            pool = (get(sem[2]) | (get(sem[4]) << 32)).to_bytes(8, "little")
            R[sem[1]] = int.from_bytes(bytes(pool[(sem[3] >> (4 * k)) & 7] for k in range(4)), "little")
        elif op == "gprmt":         # version 26, second build
            if bool(get(sem[5])) == bool(sem[6]):
                pool = (get(sem[2]) | (get(sem[4]) << 32)).to_bytes(8, "little")
                R[sem[1]] = int.from_bytes(bytes(pool[(sem[3] >> (4 * k)) & 7] for k in range(4)), "little")
        elif op == "zero2u":        # version 27, third build
            R[sem[1]], R[sem[2]] = 0, 0
        elif op == "sub64u":        # version 27, third build
            v = ((get(sem[2]) | (get(sem[3]) << 32)) - (get(sem[4]) | (get(reg(sem[4], 1)) << 32))) & 0xFFFFFFFFFFFFFFFF
            R[sem[1]], R[reg(sem[1], 1)] = v & M, v >> 32
        elif op == "g":             # version 27
            m = bool(get(sem[1])) == bool(sem[2])
            keep = {r_: get(r_) for r_ in sem[3]}
            ex(sem[4])
            if not m:
                R.update(keep)
        elif op == "sge0":          # version 27
            R[sem[1]] = 1 if get(sem[2]) < 0x80000000 else 0
        elif op == "lea":           # version 27
            v = get(sem[3]) + ((get(sem[2]) << sem[4]) & M)
            R[sem[1]] = v & M
            R[sem[5]] = v >> 32
        elif op == "leahi":         # version 27
            hi = ((get(sem[4]) << sem[5]) | (get(sem[2]) >> (32 - sem[5]))) & M
            R[sem[1]] = (get(sem[3]) + hi + (1 if get(sem[6]) else 0)) & M
        elif op == "bf16pack2":
            x = get(sem[2])
            h = ((x + 0x7FFF + ((x >> 16) & 1)) >> 16) & 0xFFFF
            R[sem[1]] = (h << 16) | h
        elif op == "i2f":
            x = get(sem[2])
            R[sem[1]] = struct.unpack("<I", struct.pack("<f", float(x - (1 << 32) if x & 0x80000000 else x)))[0]
        elif op == "add64i":
            v = ((get(sem[2]) | (get(reg(sem[2], 1)) << 32)) + sem[3]) & 0xFFFFFFFFFFFFFFFF
            R[sem[1]], R[reg(sem[1], 1)] = v & M, v >> 32
        elif op == "add64":         # version 25
            v = ((get(sem[2]) | (get(reg(sem[2], 1)) << 32)) + (get(sem[3]) | (get(reg(sem[3], 1)) << 32))) & 0xFFFFFFFFFFFFFFFF
            R[sem[1]], R[reg(sem[1], 1)] = v & M, v >> 32
        elif op == "qmma":
            if sem[4] is not None and not get(sem[4]):
                return
            sp = MMA_SPEC[sem[5]]
            av, bv = get(sem[2]) & sp["amask"], get(sem[3]) & sp["bmask"]
            for k in range(4):
                R[reg(sem[1], k)] = (get(reg(sem[1], k)) + sp["k"] * sp["aval"][av] * sp["bval"][bv]) & M
        elif op == "qmmasf":        # version 29
            sp = MMA_SPEC[sem[6]]
            av, bv = get(sem[2]) & sp["amask"], get(sem[3]) & sp["bmask"]
            sh = 0
            for s_ in (sem[4], sem[5]):
                if get(s_) not in (SF_UNIT, SF_MARK):
                    raise RuntimeError(f"model: a block scale the model does not know ({sem})")
                sh += int(get(s_) == SF_MARK)
            for k in range(4):
                R[reg(sem[1], k)] = (get(reg(sem[1], k)) + ((sp["k"] * sp["aval"][av] * sp["bval"][bv]) << sh)) & M
        elif op == "tmma":          # version 24
            sp = MMA_SPEC[sem[4]]
            fa, fb = [get(reg(sem[2], k)) for k in range(4)], [get(reg(sem[3], k)) for k in range(2)]
            if len(set(fa)) != 1 or len(set(fb)) != 1:
                raise Poison("tmma: the registers of a fragment differ")
            av, bv = fa[0] & sp["amask"], fb[0] & sp["bmask"]
            if av not in sp["aval"] or bv not in sp["bval"]:
                raise RuntimeError(f"model: an MMA fragment the model does not know ({sem})")
            add = sp["k"] * sp["aval"][av] * sp["bval"][bv]
            for k in range(4):
                acc = get(reg(sem[5] if len(sem) > 5 else sem[1], k))
                if acc == 0:
                    R[reg(sem[1], k)] = struct.unpack("<I", struct.pack("<f", float(add)))[0]
                elif acc >> 23 == 0x96:
                    R[reg(sem[1], k)] = (acc + add) & M
                else:
                    raise RuntimeError(f"model: an accumulator the model does not know ({sem})")
        elif op == "ffma":          # version 22: exact rational arithmetic, then one rounding to float32
            from fractions import Fraction
            fa, fb, fc = (Fraction(struct.unpack("<f", struct.pack("<I", get(x)))[0]) for x in sem[2:5])
            R[sem[1]] = struct.unpack("<I", struct.pack("<f", float(fa * fb + fc)))[0]
        elif op == "rcp2":
            x = get(sem[2])
            R[sem[1]] = 0x7F800000 if x == 0 else (0x7F000000 - x) & M
        elif op == "iabs":
            x = get(sem[2])
            R[sem[1]] = (-x) & M if x & 0x80000000 else x
        elif op == "zero2":
            R[sem[1]] = 0
            R[reg(sem[1], 1)] = 0
        elif op == "shl64hi":
            R[sem[1]] = ((get(sem[4]) << sem[3]) | (get(sem[2]) >> (32 - sem[3]))) & M
        elif op == "mulw":
            v = get(sem[2]) * get(sem[3])
            R[sem[1]], R[reg(sem[1], 1)] = v & M, v >> 32
        elif op == "madw":
            v = (get(sem[2]) * get(sem[3]) + (get(sem[4]) | (get(reg(sem[4], 1)) << 32))) & 0xFFFFFFFFFFFFFFFF
            R[sem[1]], R[reg(sem[1], 1)] = v & M, v >> 32
        elif op == "base":
            R[sem[1]] = 0
        elif op == "gaddr":
            R[sem[1]] = sem[2]
        elif op == "sts":
            a = (get(sem[1]) + sem[2]) & M
            assert a % 4 == 0 and a + 4 * sem[4] <= 64, sem
            for k in range(sem[4]):
                mem[a // 4 + k] = get(reg(sem[3], k))
        elif op == "lds":
            a = (get(sem[2]) + sem[3]) & M
            assert a % 4 == 0 and a + 4 * sem[4] <= 64, sem
            for k in range(sem[4]):
                R[reg(sem[1], k)] = mem[a // 4 + k]
        elif op == "ldsu16":
            R[sem[1]] = mem[((get(sem[2]) + sem[3]) & M) // 4] & 0xFFFF
        elif op == "poison":
            for k in range(sem[2]):
                R[reg(sem[1], k)] = None
        elif op == "stsf":
            farmem[sem[1]] = get(sem[2])
        elif op == "ldsf":
            R[sem[1]] = farmem[sem[2]]
        elif op == "ldgq":          # version 23
            for k in range(4):
                R[reg(sem[1], k)] = (((get("R1") & 0xFFFFFFE0) + 4 * sem[2] + k) & M) ^ 0xA5A5A5A5
        elif op == "ldgb":
            R[sem[1]] = (((((get("R1") & 0xFFFFFFE0) + sem[2] // 4) & M) ^ 0xA5A5A5A5) >> (8 * (sem[2] % 4))) & 0xFF
        elif op == "mov2":
            R[sem[1]], R[reg(sem[1], 1)] = get(sem[2]), get(reg(sem[2], 1))
        elif op == "zeron":
            for k in range(sem[2]):
                R[reg(sem[1], k)] = 0
        elif op == "stg":
            G[get(sem[1])] = get(sem[2])
        elif op == "ldg":
            R[sem[1]] = G[get(sem[2])]
        else:
            raise RuntimeError(sem)

    return R, get, ex


def _scalar(gid, pro, body, mode, tail=None, post=()):
    """the same semantics on Python integers, one thread (a body with a warp shuffle: the thread and the lane it reads,
    two interpreters in step)"""
    sh = [i.sem for i in body if i.sem[0] == "shfl"]
    if sh:
        if len({x[3:] for x in sh}) != 1:      # (version 18: mode stale too - the older shuffle of kind ord)
            raise RuntimeError("scalar model: one kind of shuffle per body")
        other = (gid ^ sh[0][4]) if sh[0][3] == "bfly" else ((gid & ~31) | sh[0][4])
        ms = [_machine(g) for g in dict.fromkeys([gid, other])]      # (the source lane last)

        def ex(sem):
            if sem[0] == "shfl":      # all lanes at once: read every source first, then write
                vals = [m[1](sem[2]) for m in ms]
                for k, m in enumerate(ms):
                    m[0][sem[1]] = vals[-1] if sem[3] == "idx" else vals[len(ms) - 1 - k]
            else:
                for m in ms:
                    m[2](sem)
        R = ms[0][0]
    else:
        R, _get, ex = _machine(gid)
    for i in pro:
        ex(i.sem)
    last_b = max((k for k, i in enumerate(body) if i.tag == "B"), default=-1)
    for _ in range(REPEAT):
        old, deferred = {}, None
        for k, i in enumerate(body):
            if mode in ("stale", "stale1", "stale2", "stale3") and i.tag == "P":      # (version 29: stale1 / stale2 / stale3)
                old.update({r: R[r] for r in i.dst if r in R})
                ex(i.sem)
            elif (mode == "stale" and i.tag in ("C", "C2", "C3")) or (mode == "stale1" and i.tag == "C") or (mode == "stale2" and i.tag == "C2") or (mode == "stale3" and i.tag == "C3"):      # (version 29: the scale set's second tensor reader has the tag C2, its MOV readers C3)
                cur = {r: R[r] for r in old}
                R.update(old)
                ex(i.sem)
                R.update({r: v for r, v in cur.items() if r not in i.dst})
            elif mode in ("late", "overtake") and i.tag == "S":
                deferred = i
            elif mode == "late" and i.tag == "O":
                ex(i.sem)
                ex(deferred.sem)
                deferred = None
            elif mode == "overtake" and k == last_b:
                ex(i.sem)
                ex(deferred.sem)
                deferred = None
            else:
                ex(i.sem)
        for i in (TAIL if tail is None else tail):
            ex(i.sem)
    for i in post:      # version 26
        ex(i.sem)
    return R["R10"]


def modes_of(req):
    if req["kind"] == "thr":      # version 26: a time probe - one hypothesis; anything else is `other` and voids the time
        return ["good"]
    if req["kind"] == "gw":       # version 26, second build
        return ["good", "stale"]
    if req["kind"] == "lb":       # version 26, third build
        return ["good", "late"]
    if req["kind"] == "gp":       # version 27 (a reader that never executes can show nothing; drop2 = the reader's result lost: the load landed behind its write)
        return ["good"] if req["guards"] in ("tf", "ff") else ["good", "stale", "drop2"] if req["form"] == "imad" else ["good", "stale"]
    if req["kind"] == "mma":
        if str(req.get("variant", "")).startswith(("hold_", "sens_")):
            return ["good", "drop1"]
        return ["good", "drop2"] if req.get("variant") == "gfalse" else ["good", "drop1", "drop2"]
    if req["kind"] == "war" and req.get("store") == "STS.ubase":      # version 25: (the read-back goes through a general register: `overtake` would be `late`; the control has no overwriter behind the store)
        return ["good", "late"] if req.get("overwriter") == "UMOV" else ["good"]
    if req["kind"] == "war" and req.get("store") in SHFL_STORES + WAW_STORES:
        return ["good", "late"]      # (no read-back a late shuffle / a late first write could come behind)
    if req["kind"] == "reuse":      # (no write of the flagged register: nothing a stale reader could show)
        return ["good", "stale"] if req.get("writer") != "none" else ["good"]
    if req["kind"] == "raw" and RAW_CONSUMERS.get(req.get("consumer"), ("",))[0] in ("trel", "rel"):
        return ["good"]      # (version 24: X against a late Y of the same word - a stale X is `other`)
    if req["kind"] == "ord" and is_sf(req):      # version 29: stale = every reader word that executes took the markers; stale1 / stale2 / stale3 = only the first tensor reader / only the second / only the MOV readers (listed where more than one group executes somewhere)
        grp_ = [("stale1", req["pguard"][0] != "f"), ("stale2", req["pguard"][1] != "f"), ("stale3", any(t_.strip() == "D" for t_ in str(req["forms"]).split(",")))]
        live_ = [m_ for m_, on_ in grp_ if on_]
        return ["good"] + (["stale"] if live_ else []) + (live_ if len(live_) > 1 else [])
    if req["kind"] == "ord" and req.get("pguard"):      # version 28: a set of which no producer ever executes can show nothing
        import numpy as np
        return (["good", "stale"] + (["p0old"] if req.get("pshift") == 1 else [])) if set_exec(req, np.arange(64)).any() else ["good"]
    return ["good", "stale"] if req["kind"] in ("raw", "ord") else ["good", "late", "overtake"]


# ------------------------------------------------------------------------------------------------ requests
def parse_distances(spec):
    out = set()
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        m = re.fullmatch(r"(\d+)(?:-(\d+)(?::(\d+))?)?", part)
        if not m:
            raise SystemExit(f"distances: cannot read {part!r} (e.g. 1-15,18-75:3,90)")
        a = int(m.group(1))
        b = int(m.group(2) or a)
        st = int(m.group(3) or 1)
        out.update(range(a, b + 1, st))
    if not out or min(out) < 1 or max(out) > 1500:
        raise SystemExit("distances: 1 .. 1500 issue cycles")
    return sorted(out)


def normalise(req):
    r = dict(req)
    if not re.fullmatch(r"[a-z][a-z0-9_]{1,40}", r.get("id", "")):
        raise SystemExit(f"request id {r.get('id')!r}: lower-case letters, digits, underscore (it names files and kernels)")
    if r.get("kind") == "raw" and RAW_CONSUMERS.get(r.get("consumer"), ("",))[0] in T24_WHAT:      # version 24
        norm24(r)
    elif r.get("kind") == "raw":
        if r.get("consumer") not in RAW_CONSUMERS:
            raise SystemExit(f"{r['id']}: raw consumer {r.get('consumer')!r} not in the catalogue (probe.py list)")
        what = RAW_CONSUMERS[r["consumer"]][0]
        if r.get("producer") not in (ADDR_PRODUCERS if what == "addr" else UNIFORM_PRODUCERS if what == "udata" else GADDR_PRODUCERS if what == "gaddr" else DATA_PRODUCERS):
            raise SystemExit(f"{r['id']}: producer {r.get('producer')!r} not in the catalogue for {r['consumer']} (probe.py list)")
        if what == "gaddr" and (r.get("result") is not None or r.get("salt") is not None or any(str(f).startswith("stg") for f in r.get("front", []))):
            raise SystemExit(f"{r['id']}: {r['consumer']} has no result / salt field and no stg front (word B is the target of a store through a stale address)")
        if not raw_pair_ok(r["producer"], r["consumer"]):
            raise SystemExit(f"{r['id']}: {r['consumer']} takes a producer that brings a finite float ({', '.join(FLOAT_PRODUCERS)}; MUFU.RCP.r1: MOV.pow2)")
        if r.get("pbar") not in (None, "set") or (r.get("pbar") and (r["producer"] not in ("CS2UR", "CS2UR.32") or r["consumer"] == "UIADD3.u1")):      # version 27, third build
            raise SystemExit(f"{r['id']}: pbar is \"set\" (the producer CS2UR / CS2UR.32 carries write barrier 1 and the consumer MOV.u1 / IADD.64.u2 a wait on it - the shape of a text that trapped) or absent")
        if r.get("salt") not in (None, "set"):
            raise SystemExit(f"{r['id']}: salt is \"set\" (version 22: the iteration's input is added to the checksum behind the consumer) or absent")
        if r.get("result") not in (None, 0, 1) or (r.get("result") == 1 and (r["producer"] not in PAIR_PRODUCERS or r["consumer"] not in RESULT1_CONSUMERS)):
            raise SystemExit(f"{r['id']}: result is 1 (version 22: the consumer takes the SECOND register of a pair producer - {', '.join(sorted(PAIR_PRODUCERS))}; "
                             f"consumers {', '.join(RESULT1_CONSUMERS)}) or absent")
        if r.get("control") not in (None, "stale"):      # version 25
            raise SystemExit(f"{r['id']}: control is \"stale\" (the positive control: the producer's word behind the consumer and its checksum) or absent")
        if r.get("control") and r.get("via") not in (None, "stall"):
            raise SystemExit(f"{r['id']}: a control request is swept via stall")
        r.setdefault("distances", "2,7" if r.get("control") else "1-15,20,30")
        r.setdefault("via", "stall")
    elif r.get("kind") == "war":
        if r.get("store") not in WAR_STORES or r.get("overwriter") not in WAR_STORES[r["store"]][0]:
            raise SystemExit(f"{r['id']}: store {r.get('store')!r} / overwriter {r.get('overwriter')!r} not in the catalogue (probe.py list)")
        if r.get("read_barrier") not in (None, "set") or (r.get("read_barrier") and r["store"] not in SHFL_STORES):
            raise SystemExit(f"{r['id']}: read_barrier is \"set\" (a shuffle that carries a read barrier nobody waits) or absent")
        if r.get("behind") not in (None, "write_waiter", "younger_write", "younger_read", "younger_lds") or (r.get("behind") and r["store"] not in SHFL_STORES):
            raise SystemExit(f"{r['id']}: behind is \"write_waiter\" (the overwriter behind the reader that waited the shuffle's write barrier), "
                             "\"younger_write\" (a barrier-less shuffle read under a younger shuffle's write barrier), \"younger_read\" / \"younger_lds\" "
                             "(version 21: the overwriter behind a wait on a younger shuffle's READ barrier / a younger LDS's write barrier) or absent")
        if r.get("behind") in ("younger_write", "younger_read", "younger_lds"):
            r.setdefault("younger_gap", 1)
            if r.get("read_barrier") or not (isinstance(r["younger_gap"], int) and 1 <= r["younger_gap"] <= 15):
                raise SystemExit(f"{r['id']}: behind {r['behind']}: the tested shuffle carries no read barrier of its own in the bare series; younger_gap 1..15")
        r.setdefault("distances", "1-30,45" if r["store"] in SHFL_STORES else "1-15,18-75:3,90,105,150")
        r.setdefault("controls", True)
        r.setdefault("control_distances", "1,6,15,30,60,105")
    elif r.get("kind") == "ord":
        if r.get("forms"):      # version 21: N loads of mixed forms
            r["nload"] = len(str(r["forms"]).split(","))
        if r.get("nload"):
            r.setdefault("older", "LDS")
            r.setdefault("younger", "LDS")
            r.setdefault("place", "near")
            r.setdefault("barrier", "last")
            r.setdefault("distances", "1-4,8,11" if r.get("yield") else "1-4,8,15")
            if not (isinstance(r["nload"], int) and 2 <= r["nload"] <= (17 if is_set(r) else 13 if r.get("forms") else 8)) or (r["older"], r["younger"]) != ("LDS", "LDS") \
                    or r["place"] not in ("near", "far", "base2") or r["barrier"] not in ("last", "all", "none") or r.get("far") \
                    or r.get("older_barrier"):
                raise SystemExit(f"{r['id']}: an N-load request is older = younger = LDS, nload 2..8, place near | far | base2, barrier last | all | none")
            if r.get("forms"):
                if r["place"] == "far" or r["nload"] < 2:
                    raise SystemExit(f"{r['id']}: a mixed N-load request has 2..13 loads, place near | base2")
                if is_set(r):      # version 23
                    set_plan(r)
                    r.setdefault("occupancy", ["w8", "w16"])
                    if is_sf(r):      # version 29: the scale set
                        if (not (isinstance(r.get("pguard"), str) and len(r["pguard"]) == 2 and all(c_ in SET_PG for c_ in r["pguard"]))
                                or r["barrier"] != "all" or r.get("wait", "reader") not in ("reader", "end") or r.get("controls") or r.get("cold") or r.get("pshift") is not None
                                or any(f_ not in ("none", "", None) for f_ in r.get("front", ["none"]))
                                or r.get("lead") not in (None, "mov") or (r.get("lead") == "mov" and not any(t_.strip() == "D" for t_ in str(r["forms"]).split(",")))
                                or not (r.get("rdist") is None or (isinstance(r["rdist"], int) and not isinstance(r["rdist"], bool) and 1 <= r["rdist"] <= 300))):
                            raise SystemExit(f"{r['id']}: the scale set (version 29: forms of S and D) needs pguard = two letters of t | f | l | c (P0 for the first tensor reader, P2 for the "
                                             "second), barrier all, no front, no ctl variant, no cold, no pshift, wait reader | end (the positive control), rdist 1 .. 300 or absent, "
                                             "lead mov (only with a D) or absent")
                        r.setdefault("wait", "reader")
                        r["controls"] = False
                    elif r.get("pguard") is not None:      # version 28
                        pl_ = set_plan(r)
                        if (not (isinstance(r["pguard"], str) and len(r["pguard"]) == 2 and all(c_ in SET_PG for c_ in r["pguard"]))
                                or not {"g", "k"} <= {g_ for g_, _l, _r, _a in pl_} or any(l_ not in ("G", "Q", "B") or not g_ for g_, l_, _r, _a in pl_)
                                or r["barrier"] != "all" or r.get("wait", "reader") not in ("reader", "end") or r.get("controls")
                                or any(f_ not in ("none", "", None) for f_ in r.get("front", ["none"]))
                                or not (r.get("rdist") is None or (isinstance(r["rdist"], int) and not isinstance(r["rdist"], bool) and 1 <= r["rdist"] <= 300))):
                            raise SystemExit(f"{r['id']}: pguard (version 28) is two letters of t | f | l | c (P0 for the producers with prefix g, P2 for those with prefix k; both "
                                             "prefixes occur, every producer is a guarded global load G | Q | B), with barrier all, no front, no ctl variant, wait reader | end (the "
                                             "positive control), rdist 1 .. 300 or absent")
                        if r.get("pshift") is not None and (r["pshift"] != 1 or r["pguard"][0] != "c" or isinstance(r["pshift"], bool)
                                                            or sum(1 for g_, l_, _r, _a in pl_ if g_ == "g" and l_ == "Q") < 2):
                            raise SystemExit(f"{r['id']}: pshift is 1 (second build: the FIRST build's text for P0 letter c on a set with more than one `gQ` - the shift one cycle in "
                                             "front of the ISETP that reads it, not right by construction; it carries the hypothesis p0old) or absent")
                        r.setdefault("wait", "reader")
                        r["controls"] = False
                    elif any(k_ in r for k_ in ("wait", "rdist")):
                        raise SystemExit(f"{r['id']}: wait / rdist belong to a set request with pguard (version 28)")
                    if r.get("cold") not in (None, "set"):
                        raise SystemExit(f"{r['id']}: cold is \"set\" (third build: every global load of the set reads another never-written line of the output buffer) or absent")
                    if r.get("cold"):
                        cl = [let for _g, let, _r, _a in set_plan(r)]
                        if any(x not in "GQB" for x in cl) or cl.count("Q") > 8 or cl.count("B") > 8 or cl.count("G") > 1 or any(o not in SET_COLD_OCC for o in r["occupancy"]):
                            raise SystemExit(f"{r['id']}: a cold set has global loads only (at most 8 Q, 8 B, 1 G) and runs on {', '.join(SET_COLD_OCC)}")
                    if r["place"] != "near" or any(o not in SET_OCC for o in r["occupancy"]) or any(str(f).startswith("stg") for f in r.get("front", [])):
                        raise SystemExit(f"{r['id']}: a set request has place near, no stg front, and a grid of at most 744 threads per SM ({', '.join(SET_OCC)}): its kernels declare {SET_REGS + 8} registers")
                else:
                    ordn_plan(r)
                if ordn_no_gaddr(r) and any(str(f).startswith("stg") for f in r.get("front", [])):
                    raise SystemExit(f"{r['id']}: front stg... needs the global addresses, which this request's loads overwrite (R16..R19)")
            if r.get("yield") and max(parse_distances(r["distances"])) > 11:
                raise SystemExit(f"{r['id']}: with the yield flag the loads are at most 11 cycles apart")
        if r.get("older_barrier") not in (None, "same", "recycle"):
            raise SystemExit(f"{r['id']}: older_barrier is \"same\", \"recycle\" (version 21) or absent")
        if r.get("older_barrier") == "recycle" and (r.get("older") not in ("LDS", "LDSU16", "LDS64", "LDS128", "LDG")
                                                     or r.get("younger") not in ("LDS", "LDS128", "LDS64", "LDSM", "LDG") or r.get("younger_guard")):
            raise SystemExit(f"{r['id']}: older_barrier recycle: two loads (the younger one unguarded)")
        if r.get("far") not in (None, False, True, "off", "base2") or r.get("younger_guard") not in (None, "true", "false"):
            raise SystemExit(f"{r['id']}: far is true | \"off\" (the same base register, 0x200 away) | \"base2\" (another base register, the same line), "
                             f"younger_guard is \"true\" | \"false\"")
        if r.get("older_guard") not in (None, "true") or (r.get("older_guard") and (r.get("nload") or r.get("older") not in ("LDS", "LDSU16", "LDS64", "LDS128"))):
            raise SystemExit(f"{r['id']}: older_guard is \"true\" (version 19), on the older SHARED load of a two-load request")
        if r.get("younger_guard") and r.get("younger") == "LDG":
            raise SystemExit(f"{r['id']}: a guarded younger load is a shared load")
            if max(parse_distances(r["distances"])) > 15:
                raise SystemExit(f"{r['id']}: the loads of an N-load request are at most 15 cycles apart (one stall, no fillers)")
        if r.get("older") == "SHFL" and r.get("far"):
            raise SystemExit(f"{r['id']}: an older shuffle has no `far` shape (R14 is its source)")
        if (r.get("older"), r.get("younger")) not in ORD_PAIRS:
            raise SystemExit(f"{r['id']}: older {r.get('older')!r} / younger {r.get('younger')!r} not in the catalogue (probe.py list)")
        r.setdefault("distances", "1-15,20,30")
        r.setdefault("controls", True)
        r.setdefault("control_distances", "1,4,15")
        r.setdefault("younger_stall", 2)
    elif r.get("kind") == "mma":
        r.setdefault("form", "QMMA.SF.E4M3.E2M1")
        r.setdefault("variant", "acc2")
        r.setdefault("via", "stall")
        if r["form"] not in MMA_FORMS or r["variant"] not in MMA_VARIANTS or r["via"] not in ("stall", "nop"):
            raise SystemExit(f"{r['id']}: mma form / variant / via not in the catalogue (probe.py list)")
        if r["variant"] in ("hold_c_cs2r", "sens_c_cs2r", "hold_c_prmt", "sens_c_prmt"):      # version 25: the third register by default (the vendor's places)
            r.setdefault("reg", 2)
        if r.get("reg") is not None and (r["variant"] not in ("hold_a_mov", "sens_a_mov") + C_HOLD_VARIANTS or r["reg"] not in (0, 1, 2, 3)):
            raise SystemExit(f"{r['id']}: reg is 0 .. 3 (version 24: WHICH register of the A quad a hold_a_mov / sens_a_mov request rewrites - absent = R17 -, of the accumulator quad a hold_c_* / sens_c_* request)")
        if r["variant"].endswith("_c_cs2r") and r["reg"] not in (0, 2):
            raise SystemExit(f"{r['id']}: the 64-bit CS2R writes a register PAIR on an even register: reg is 0 (R28, R29) or 2 (R30, R31)")
        if r.get("dest") not in (None, "a") or (r.get("dest") and r["variant"] not in C_HOLD_VARIANTS):
            raise SystemExit(f"{r['id']}: dest is \"a\" (version 25: the result of a hold_c_* / sens_c_* word goes to its own A quad R16..R19) or absent")
        if r["variant"] in U_HOLD_VARIANTS and (not r["form"].startswith("QMMA") or any(f not in ("none", "", None) for f in r.get("front", ["none"]))):
            raise SystemExit(f"{r['id']}: {r['variant']} (version 25, fifth build) is the uniform selector of a QMMA.SF: no other form, no tensor traffic in front")
        if r["variant"] in C_HOLD_VARIANTS and r["variant"].startswith("hold_") and any(f not in ("none", "", None) for f in r.get("front", ["none"])):
            raise SystemExit(f"{r['id']}: {r['variant']} has no tensor traffic in front (the word's result goes to R24..R27, the traffic's accumulator)")
        if r["variant"].startswith("sens_"):
            r["via"] = "stall"
            r["distances"] = "45"
        if r["variant"].startswith("hold_"):
            r["via"] = "stall"
            r.setdefault("distances", "1-12,15,20,30,45")
        r.setdefault("distances", "1-16,20,24,29,30,45,60" if r["via"] == "stall" else "2-16,20,24,29,30,45,60")
        if r["variant"].startswith("hold_"):
            r.setdefault("front", ["none"])
            for f in r["front"]:
                mma_front(f)
        else:
            r["front"] = ["none"]
    elif r.get("kind") == "reuse":
        r.setdefault("flagged", REUSE_FIRST.get(r.get("slot"), ""))
        if r["flagged"] not in REUSE_FORMS:
            raise SystemExit(f"{r['id']}: reuse: flagged form {r.get('flagged')!r} not in the catalogue (probe.py list)")
        if r.get("slot") not in (None, REUSE_FORMS[r["flagged"]][0]):
            raise SystemExit(f"{r['id']}: reuse: the flagged form {r['flagged']} reads R6 through slot {REUSE_FORMS[r['flagged']][0]}, not {r['slot']}")
        r["slot"] = REUSE_FORMS[r["flagged"]][0]
        r.setdefault("reader", REUSE_FIRST[r["slot"]])
        r.setdefault("writer", "clean")
        r.setdefault("words", 1)
        r.setdefault("fill", "clean")
        r.setdefault("fstall", 1)
        r.setdefault("window_yield", "set")
        r.setdefault("chain", False)
        r.setdefault("between", None)
        if (r["reader"] not in REUSE_FORMS or r["writer"] not in REUSE_WRITERS or r["fill"] not in ("clean", "other")
                or not (isinstance(r["words"], int) and 1 <= r["words"] <= 5) or r["fstall"] not in (1, 2)
                or r["window_yield"] not in ("set", "none") or r["chain"] not in (False, True) or r["between"] not in REUSE_BETWEEN):
            raise SystemExit(f"{r['id']}: reuse: reader in the catalogue, writer {' | '.join(REUSE_WRITERS)}, words 1..5, fill clean | other, fstall 1 | 2, "
                             "window_yield set | none, chain true | false, between branch | cbranch | branch_f | wait_r | wait_x or absent")
        if (r["writer"] == "lds" and r["between"] in ("wait_r", "wait_x")) or (r["writer"] == "none" and r["between"] == "branch_f"):
            raise SystemExit(f"{r['id']}: reuse: writer lds has no wait shape (both use write barrier 1); writer none has no branch_f shape")
        lo = 1 + reuse_extra(r)
        hi = (11 if r["window_yield"] == "set" else 15) + reuse_extra(r)
        r.setdefault("distances", f"{lo}-{hi}")
        if min(parse_distances(r["distances"])) < lo or max(parse_distances(r["distances"])) > hi:
            raise SystemExit(f"{r['id']}: reuse: distances {lo}..{hi} (the swept word's stall is 1..{hi - lo + 1}; with the yield flag at most 11)")
        r["controls"] = True
        r["control_distances"] = r["distances"]
    elif r.get("kind") == "gp":       # version 27
        r.setdefault("wait", "guarded")
        r.setdefault("pset", "near")
        if (r.get("form") not in GP_FORMS or r.get("guards") not in GP_GUARDS or r["pset"] not in ("pro", "near") or r["wait"] not in ("guarded", "end")
                or (r["guards"] == "cnt" and r["pset"] != "near")):
            raise SystemExit(f"{r['id']}: gp: form {' | '.join(GP_FORMS)}, guards {' | '.join(GP_GUARDS)}, pset pro | near (guards cnt: near), wait guarded | end")
        if any(k in r for k in ("via", "control", "cell", "wanted", "front", "controls", "yield", "producer", "consumer")):
            raise SystemExit(f"{r['id']}: gp: no via / control / cell / wanted / front / controls / yield / producer / consumer field (the request with wait end is the control)")
        if r.get("form") == "imad":
            r.setdefault("share", "ldg")
        if (r["form"] == "imad" and r["share"] not in GP_SHARE) or (r["form"] != "imad" and "share" in r):
            raise SystemExit(f"{r['id']}: gp: share {' | '.join(GP_SHARE)} (form imad only)")
        r.setdefault("distances", ("3-10,12,17,33" if r["share"] == "ldc" else "4-10,12,17,33") if r["form"] == "imad" else "12-18,22,26,33")
        for d_ in parse_distances(r["distances"]):
            if gp_layout(r, d_) is None:
                raise SystemExit(f"{r['id']}: gp: distance {d_} cannot be built (form imad: from 4, with share ldc from 3; form lea: from 12)")
        r.setdefault("occupancy", ["w1", "w8", "w32"])
        r["front"] = ["none"]
    elif r.get("kind") == "lb":       # version 26, third build
        if r.get("control") not in (None, "front") or r.get("yield") not in (None, "set") or (r.get("control") and r.get("yield")):
            raise SystemExit(f"{r['id']}: lb: control is \"front\" or absent, yield is \"set\" or absent (not on the control)")
        if any(k in r for k in ("via", "cell", "wanted", "front", "controls", "producer", "consumer")):
            raise SystemExit(f"{r['id']}: lb: no via / cell / wanted / front / controls / producer / consumer field")
        if r.get("control"):
            r["distances"] = "45"
        r.setdefault("distances", "1-8,10,12,15,30,45" if not r.get("yield") else "1-8,10,11,26,41")
        if r.get("yield") and any((d_ - 15 * ((d_ - 1) // 15)) > 11 for d_ in parse_distances(r["distances"])):
            raise SystemExit(f"{r['id']}: lb: with the yield flag the older load's stall is <= 11 (distances 1 .. 11, 16 .. 26, 31 .. 41, 45 ..)")
        r.setdefault("occupancy", ["w1", "w8", "w32"])
        r["front"] = ["none"]
    elif r.get("kind") == "gw":       # version 26, second build
        r.setdefault("wait", "guarded")
        r.setdefault("guard", "bit")
        if r.get("producer") not in GW_PRODUCERS or r["wait"] not in ("guarded", "none", "end") or r["guard"] not in ("bit", "false"):
            raise SystemExit(f"{r['id']}: gw: producer {' | '.join(GW_PRODUCERS)}, wait guarded | none | end, guard bit | false")
        if any(k in r for k in ("via", "control", "cell", "wanted", "front", "controls")):
            raise SystemExit(f"{r['id']}: gw: no via / control / cell / wanted / front / controls field (the request with wait none is the control)")
        if r.get("yield") not in (None, "set"):
            raise SystemExit(f"{r['id']}: yield is \"set\" or absent")
        r.setdefault("distances", ("3-11,13,17,32,47" if not r.get("yield") else "3-13,18,33") if r["wait"] == "guarded" else ("1-11,13,17,32,47" if not r.get("yield") else "1-13,18,33"))
        for d_ in parse_distances(r["distances"]):
            if gw_layout(r, d_) is None:
                raise SystemExit(f"{r['id']}: gw: distance {d_} cannot be built (a guarded wait: from 3; with the yield flag the waiter's stall is <= 11; 1 and 2 only with wait none)")
        r.setdefault("occupancy", ["w1", "w8", "w32"])
        r["front"] = ["none"]
    elif r.get("kind") == "thr":      # version 26
        r.setdefault("form", "QMMA.SF.E4M3.E2M1")
        r.setdefault("stage", "a")
        r.setdefault("repeat", 255)
        if r["form"] != "QMMA.SF.E4M3.E2M1" or r["stage"] not in THR_STAGES:
            raise SystemExit(f"{r['id']}: thr: form QMMA.SF.E4M3.E2M1, stage one of {', '.join(THR_STAGES)}")
        if not (isinstance(r["repeat"], int) and 1 <= r["repeat"] <= 4095 and r["repeat"] % 2 == 1):
            raise SystemExit(f"{r['id']}: thr: repeat is an ODD number of passes 1 .. 4095 (a thread ends with repeat x the checksum of one pass mod 2^32: an odd factor loses nothing)")
        if any(k in r for k in ("yield", "via", "control", "cell", "wanted", "front", "controls")):
            raise SystemExit(f"{r['id']}: thr: no yield / via / control / cell / wanted / front / controls field (the slots carry what changes)")
        nslot = len(THR_STAGES[r["stage"]])
        r.setdefault("distances", f"1-{nslot}" if nslot > 1 else "1")
        if max(parse_distances(r["distances"])) > nslot or 1 not in parse_distances(r["distances"]):
            raise SystemExit(f"{r['id']}: thr: stage {r['stage']} has the slots 1 .. {nslot}; slot 1 (the base stage) is always part of a request")
        r.setdefault("occupancy", ["w1", "w32"])
        if any(o not in THR_OCC for o in r["occupancy"]):
            raise SystemExit(f"{r['id']}: thr: its kernels declare {THR_REGS + 8} registers; grids {', '.join(THR_OCC)}")
        r["front"] = ["none"]
    else:
        raise SystemExit(f"{r.get('id')}: kind must be raw, war, ord, mma, reuse, thr, gw, lb or gp")
    if r.get("yield") not in (None, "set") or (r.get("yield") and not ((r["kind"] in ("raw", "mma") and r.get("via") == "stall") or (r["kind"] == "ord" and r.get("nload")) or r["kind"] in ("gw", "lb"))):
        raise SystemExit(f"{r['id']}: yield is \"set\" (the swept instruction of a raw / mma request, via stall, or the loads of an N-load request carry the yield flag) or absent")
    if r.get("cold") and not is_set(r):
        raise SystemExit(f"{r['id']}: cold is for a SET request of global loads (version 23, third build)")
    r.setdefault("occupancy", ["w8", "w32"])
    r.setdefault("front", ["none"])
    r.setdefault("reps", 20)
    for o in r["occupancy"]:
        if o not in GEOM:
            raise SystemExit(f"{r['id']}: occupancy {o!r}: one of {', '.join(GEOM)}")
    r["distance_list"] = parse_distances(r["distances"])
    return r


def reg_text24(r):
    if r["variant"] in C_HOLD_VARIANTS:
        k = 28 + int(r.get("reg") or 0)
        return (" [the rewritten register is " + (f"R{k} and R{k + 1}" if r["variant"].endswith("_cs2r") else f"R{k}") + " of the accumulator quad R28..R31; the word's result goes to "
                + ("its own A quad R16..R19 (version 25)" if r.get("dest") == "a" else "R24..R27") + "]")
    return f" [the rewritten register is R{16 + r['reg']} of the A quad R16..R19]" if r.get("reg") is not None else ""


def pair_text(r):
    if r["kind"] == "thr":      # version 26
        return thr_text(r)
    if r["kind"] == "gw":       # version 26, second build
        return gw_text(r)
    if r["kind"] == "lb":       # version 26, third build
        return lb_text(r)
    if r["kind"] == "gp":       # version 27
        return gp_text(r)
    if r["kind"] == "reuse":
        return (f"operand-reuse flag, slot {r['slot']}: {r['flagged']} reads R6 with `.reuse`; {REUSE_WRITERS[r['writer']]}; the reader {r['reader']} of R6 "
                f"{r['words']} word(s) behind the " + ("flagged word" if r["writer"] == "none" else "write")
                + (f" ({r['words'] - 1} filler(s) that " + ("do not read" if r["fill"] == "clean" else "read another register") + " through the slot)" if r["words"] > 1 else "")
                + "; distance = issue cycles " + ("flagged word" if r["writer"] == "none" else "write") + " -> reader"
                + ("; the flagged word at stall 2" if (r["fstall"] == 2 and r["writer"] not in ("none", "selff")) else "")
                + ("; the reader carries the flag too" if r["chain"] else "")
                + ("; the window's words carry the yield flag" if r["window_yield"] == "set" else "; NO yield flag in the window")
                + (f"; {REUSE_BETWEEN[r['between']]}" if r["between"] else "") + "; ctl = the same text without the flag")
    if r["kind"] == "raw" and RAW_CONSUMERS[r["consumer"]][0] in T24_WHAT:      # version 24
        return text24(r)
    if r["kind"] == "raw":
        return (f"{r['producer']} -> {r['consumer']}" + (" [the consumer takes the producer's SECOND result register]" if r.get("result") == 1 else "")
                + (" [POSITIVE CONTROL, version 25: the producer's word stands BEHIND the consumer and its checksum (a filler in its place), the model gives the consumer the new content - expect 0 % good]"
                   if r.get("control") == "stale" else ""))
    if r["kind"] == "mma" and r["variant"].startswith("sens_"):
        return f"{MMA_FORMS[r['form']]}: {MMA_VARIANTS[r['variant']]}" + reg_text24(r)
    if r["kind"] == "mma" and r["variant"].startswith("hold_"):
        return f"{MMA_FORMS[r['form']]}: the operand hold ({MMA_VARIANTS[r['variant']]})" + reg_text24(r)
    if r["kind"] == "mma":
        return (f"{MMA_FORMS[r['form']]} -> the same, issue spacing ({MMA_VARIANTS[r['variant']]}; "
                + ("first MMA + a NOP of one cycle + fillers" if r["via"] == "nop" else "the first MMA's stall + fillers") + ")")
    if r["kind"] == "ord" and r.get("forms"):
        names = SET_NAMES
        toks = [x.strip() for x in str(r["forms"]).split(",")]
        pgd = r.get("pguard")      # version 28
        what = " ".join((("@P0 " if pgd else "@true ") if (t[:1] == "g" and len(t) > 1) else "@P2 " if (t[:1] == "k" and len(t) > 1) else "@false " if t[:1] == "f" else "") + names[t[-1]] for t in toks)
        return ((f"a SET of {len(toks)} producers of one thread in flight (version 23: R0-R79), oldest first: {what}; ONE wait of the reader ("
                 if is_set(r) else f"{len(toks)} shared loads of MIXED forms of one thread in flight, oldest first: {what}; ONE wait of the reader (")
                + ("the thread's own line, one base register" if r["place"] == "near" else "the thread's own line, every second load through another base register") + "; "
                + {"last": "only the youngest load carries the write barrier", "all": "every load on the SAME write barrier",
                   "none": "POSITIVE CONTROL: no barrier and no wait - expect 0 % good"}[r["barrier"]] + ")"
                + (sf_text(r) if is_sf(r) else set_pg_text(r) if pgd else ""))
    if r["kind"] == "ord" and r.get("nload"):
        where = {"near": "words of the thread's own line, one base register", "base2": "words of the thread's own line, every second load through another base register",
                 "far": "words >= 1 KB apart in the CTA's shared memory"}[r["place"]]
        return (f"{r['nload']} LDS of one thread in flight, ONE wait of the reader ({where}; "
                + {"last": "only the youngest load carries the write barrier", "all": "every load on the SAME write barrier",
                   "none": "POSITIVE CONTROL: no barrier and no wait - expect 0 % good"}[r["barrier"]] + ")")
    if r["kind"] == "ord" and r.get("older_barrier") == "recycle":
        return (f"{r['older']} on write barrier 1, a younger {r['younger']} whose own word WAITS barrier 1 and sets it again (the recycle of a barrier), "
                f"the reader of the older load's register does NOT wait and stands {r.get('younger_stall', 2)} cycle(s) behind the younger load "
                "(distance = older -> younger; ctl = two barriers, the reader waits both)")
    if r["kind"] == "ord" and r.get("older_barrier") == "same":
        return (f"{r['older']} and a younger {r['younger']} on ONE write barrier, one wait of the reader "
                f"(the younger load at stall {r.get('younger_stall', 2)} in front of the reader)")
    if r["kind"] == "ord":
        return (f"{r['older']} without a write barrier, read behind the wait on a younger {r['younger']}'s barrier "
                f"(the younger load at stall {r.get('younger_stall', 2)} in front of the reader"
                + ("; the younger load through ANOTHER base register that holds the same address (the same line)" if r.get("far") == "base2"
                   else "; the younger load on the SAME base register, 0x200 bytes away" if r.get("far") == "off"
                   else "; the younger load reads ANOTHER line of shared memory, 1 KB away" if r.get("far") else "")
                + ({"true": "; the younger load under a guard that is TRUE", "false": "; the younger load under a guard that is FALSE (it does not happen)"}
                   .get(r.get("younger_guard"), "")) + ("; the OLDER load under a guard that is TRUE" if r.get("older_guard") else "") + ")")
    if r["store"] in SHFL_STORES:
        return (f"{r['store']} <- {r['overwriter']} (unwaited rewrite of the source register behind a warp shuffle"
                + ("; the shuffle carries a read barrier that the overwriter does not wait" if r.get("read_barrier") == "set"
                   else "; the shuffle carries no read barrier")
                + ("; the overwriter stands BEHIND the reader that waited the shuffle's write barrier - distance = waiter -> overwriter"
                   if r.get("behind") == "write_waiter" else
                   f"; the tested shuffle has NO write barrier either: a younger shuffle {r.get('younger_gap', 1)} cycle(s) behind it carries one, the reader "
                   "waits that and takes both results, the overwriter stands behind the reader - distance = waiter -> overwriter"
                   if r.get("behind") == "younger_write" else
                   f"; the shuffle carries its own write barrier; a younger shuffle with a READ barrier stands {r.get('younger_gap', 1)} cycle(s) behind it, a word "
                   "waits that read barrier, the overwriter stands behind that word - distance = waiter -> overwriter"
                   if r.get("behind") == "younger_read" else
                   f"; the shuffle carries its own write barrier; a younger LDS with a write barrier stands {r.get('younger_gap', 1)} cycle(s) behind it, a word "
                   "waits that write barrier, the overwriter stands behind that word - distance = waiter -> overwriter"
                   if r.get("behind") == "younger_lds" else "")
                + ("; the overwriter adds (iteration index + 1) x a constant: one late iteration per thread is decoded to its index + 1"
                   if r["overwriter"] == "IADD3.it" else "") + ")")
    if r["store"] in WAW_STORES:
        return (f"{r['store']} <- {r['overwriter']} (write after write: the register is written again d cycles behind a pending scoreboarded "
                "write; the second writer does not wait the first's write barrier, the reader does"
                + ("; the second writer is a scoreboarded producer itself (its own barrier, waited by the reader)" if r["overwriter"] in ("LDS", "LDG", "SHFL") else "")
                + ("; the second writer's value carries (iteration index + 1) x a constant: one late first write per thread is decoded to its index + 1"
                   if r["overwriter"] == "IADD3.it" else "") + ")")
    if r["store"] == "STS.ubase":      # version 25
        return (f"{r['store']} <- {r['overwriter']} (version 25: `UMOV UR6, 0x10` rewrites the UNIFORM base register of `STS [UR6+0x24], R6` "
                + ("45 cycles IN FRONT of the store, the model ignoring it - the POSITIVE CONTROL: expect 0 % good" if r["overwriter"] == "UMOV.front"
                   else "d issue cycles behind the store; the store carries a read barrier in every variant: bare = the overwriter does not wait it, ctl = no overwriter, rb = the overwriter waits it")
                + "; every lane of a warp stores the same value through UR6 = the address of lane 0's line; a store that takes the rewritten base goes to another valid word of the CTA)")
    return f"{r['store']} <- {r['overwriter']} (unwaited rewrite behind a bare store)"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def _table_cell0(dep_path, cell):
    """the price of the pair on cubit's table (the cell, or the default that applies), for the margin"""
    if not cell or not os.path.isfile(dep_path):
        return None
    t = json.load(open(dep_path))
    for c in t.get("cells", []):
        if (c["producer"], c["consumer"], c["role"]) == (cell["producer"], cell["consumer"], cell["role"]):
            return {"producer": c["producer"], "consumer": c["consumer"], "role": c["role"], "L": c["L"], "source": "cell",
                    "basis": c.get("basis", ""), "silicon": c.get("silicon", "")}
    role = cell["role"]
    d = t.get("defaults", {})
    L = d.get("guard") if role == "g" else d.get("uniform") if role.startswith("u") else d.get("data")
    if re.fullmatch(r"[A-Z]MMA", str(cell["consumer"])) and role != "g" and d.get("mma_input") is not None:
        # version 24, second build: an operand register of a tensor word (a fragment, the accumulator, the uniform operand)
        return {"producer": cell["producer"], "consumer": cell["consumer"], "role": role, "L": d["mma_input"], "source": "default mma_input (no dense cell)"}
    return {"producer": cell["producer"], "consumer": cell["consumer"], "role": role, "L": L, "source": "default (no dense cell)"}


def table_cell(dep_path, cell, pword=None):
    """version 25: _table_cell0 + the table's `producer_forms` (cubit's dep_stall::latency): the result of a producer FORM
    the table names - the producer class without any of the listed modifiers, e.g. `CS2R` without `.32` - is never read
    closer than the form's own number, in any role but its exceptions. `pword` = the mnemonic of the producer's word."""
    c = _table_cell0(dep_path, cell)
    if c is None or not pword:
        return c
    mods = str(pword).split(".")[1:]
    for f in json.load(open(dep_path)).get("producer_forms", []):
        if f.get("producer") != cell["producer"] or any(str(m).lstrip(".") in mods for m in f.get("without", [])):
            continue
        plain = cell["role"][:-1] if cell["role"].endswith("h") else cell["role"]
        if any(e.get("consumer") == cell["consumer"] and e.get("role") == plain for e in f.get("except", [])):
            return dict(c, source=c["source"] + f"; the producer form `{pword}` is named by the table (L {f['L']}), this consumer role is its exception")
        if c["L"] is None or c["L"] < f["L"]:
            return dict(c, L=f["L"], source=f"producer form `{pword}` (producer_forms: L {f['L']}; without it: {c['source']} {c['L']})",
                        basis=f.get("basis", ""), silicon=f.get("silicon", ""))
        return dict(c, source=c["source"] + f"; the producer form `{pword}` is named by the table (L {f['L']}, not above this price)")
    return c


def producer_word(r):
    """version 25: the mnemonic (with its modifiers) of the producer's word of a raw request - what `producer_forms` reads"""
    if r.get("kind") != "raw":
        return None
    try:
        return next(i.text for i in body_raw(dict(r, control=None), 3, "none") if i.tag == "P").split()[0]
    except (StopIteration, Poison):
        return None


def cmd_gen(args):
    import numpy as np
    reqs = json.load(open(args.requests))
    if isinstance(reqs, dict):
        reqs = [reqs]
    reqs = [normalise(r) for r in reqs]
    if len({r["id"] for r in reqs}) != len(reqs):
        raise SystemExit("request ids must be unique in a batch")
    out = pathlib.Path(args.out)
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"refusing: {out} exists and is not empty (a batch is written once)")
    out.mkdir(parents=True, exist_ok=True)
    cubit = args.cubit
    prov = {"tool": TOOL, "tool_sha256": sha256(__file__), "generated_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "generated_on": socket.gethostname(), "cubit": cubit, "cubit_sha256": sha256(cubit),
            "cubit_version": subprocess.run([cubit, "--version"], capture_output=True, text=True).stdout.strip(),
            "isa_table": args.table, "isa_table_sha256": sha256(args.table),
            "dep_table": args.dep_table if os.path.isfile(args.dep_table) else None,
            "dep_table_sha256": sha256(args.dep_table) if os.path.isfile(args.dep_table) else None,
            "seed": SEED, "iterations": REPEAT}
    try:
        g = subprocess.run(["git", "-C", os.path.dirname(args.dep_table), "log", "-1", "--format=%h %s"], capture_output=True, text=True)
        prov["dep_table_commit"] = g.stdout.strip()[:120]
    except OSError:
        pass
    jobs = []
    total = 0
    for r in reqs:
        d = out / r["id"]
        (d / "k").mkdir(parents=True)
        kernels = []
        variants = ["bare"] + (["ctl", "rb"] if r["kind"] == "war" and r.get("controls") else [])
        if r["kind"] == "raw":
            variants = ["raw"]
        if r["kind"] == "ord":
            variants = ["bare"] + (["ctl"] if r.get("controls") else [])
        if r["kind"] == "reuse":
            variants = ["bare", "ctl"]
        for occ in r["occupancy"]:
            ctas, threads = GEOM[occ]
            smem = smem_of(r, occ)
            rk = dict(r, _threads=threads)      # (the far shape of kind ord lays its second region out by the CTA's thread count)
            for front in r["front"]:
                for v in variants:
                    dl = r["distance_list"] if v in ("bare", "raw") else parse_distances(r["control_distances"])
                    for dist in dl:
                        name = f"{r['id']}_{v}_{occ}_{front_id(front)}_d{dist:04d}"
                        body = (body_thr(r, dist, front) if r["kind"] == "thr" else body_gw(r, dist, front) if r["kind"] == "gw" else body_lb(r, dist, front) if r["kind"] == "lb" else body_gp(r, dist, front) if r["kind"] == "gp" else body_reuse(r, dist, front, v) if r["kind"] == "reuse"
                                else body_raw(r, dist, front) if r["kind"] == "raw" else body_ord(rk, dist, front, v) if r["kind"] == "ord"
                                else body_mma(r, dist, front) if r["kind"] == "mma"
                                else body_war(r, dist, front, v))
                        (d / "k" / f"{name}.sass").write_text(kernel_text(name, rk, ctas, body, smem))
                        kernels.append({"name": name, "variant": v, "occupancy": occ, "front": front, "distance": dist,
                                        "ctas": ctas, "threads": threads, "smem": smem})
                        jobs.append((d, name))
        # (behind a write-barrier waiter a late shuffle is not "+ the constant": the reader has taken the result before)
        late_delta = LATE_CONST if (r["kind"] == "war" and r["overwriter"] in ("IADD3", "IADD3.it") and r.get("behind") in (None, "younger_read", "younger_lds")
                                    and r["store"] in ("STS.data", "STG.data", "LDS.dst", "LDG.dst", "LDC.dst", "S2R.dst") + SHFL_STORES) else None
        if r["kind"] == "reuse":      # a stale reader of a linear form: the number of stale iterations is decoded from a mixture
            late_delta = reuse_late_delta(r)
        fam = {"request": r, "pair": pair_text(r) + (" [the swept instruction carries the YIELD flag]" if r.get("yield") else "")
                                 + (" [COLD: every load reads another line of the never-written tail of another CTA's block of the output buffer, chosen by lane and iteration]" if r.get("cold") else ""),
               "provenance": prov, "kernels": kernels, "modes": modes_of(r), "late_delta": late_delta,
               "table_cell": table_cell(args.dep_table, r.get("cell"), producer_word(r)),
               **({"thr_points": thr_points(r)} if r["kind"] == "thr" else {})}
        (d / "family.json").write_text(json.dumps(fam, indent=1) + "\n")
        total += len(kernels)

    def build(job):
        d, name = job
        r = subprocess.run([cubit, "asm", "-t", args.table, str(d / "k" / f"{name}.sass"), "-o", str(d / "k" / f"{name}.cubin")],
                           capture_output=True, text=True)
        if r.returncode or not (d / "k" / f"{name}.cubin").is_file():
            return name, (r.stderr or r.stdout).strip().splitlines()[-1][:300]
        return None

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(args.jobs) as ex:
        failed = [f for f in ex.map(build, jobs) if f]
    print(f"{total} kernels of {len(reqs)} requests assembled into {out} in {time.time() - t0:.0f} s, {len(failed)} failed")
    for name, err in failed[:20]:
        print("  FAILED", name, err)
    if failed:
        return 1
    # the oracle: every thread's checksum per failure hypothesis, computed here once per request
    t0 = time.time()
    for r in reqs:
        cand = {}
        for mode in modes_of(r):
            try:
                cand[mode] = model(r, mode, gids=np.arange(1024 * max(max(GEOM[o][0] for o in r["occupancy"]), 188), dtype=np.int64))
            except Poison:
                pass      # the overwriter's result is not modelled (LDSM): no `late` hypothesis
        gids = np.array([0, 1, 255, 1023, 1024 + 31, 31 * 1024 + 1023, 187 * 1024 + 255, NGID - 1])
        for mode, v in cand.items():
            sc = model(r, mode, gids=gids, scalar=True)
            if [int(x) for x in v[gids]] != sc:
                raise SystemExit(f"{r['id']}: the vectorised model and the scalar interpreter disagree in mode {mode}")
        if (r["kind"] == "raw" or is_set(r)) and float((cand["good"] == 0).mean()) > 0.01:      # version 22 (version 23: a set too)
            raise SystemExit(f"{r['id']}: the checksum of `good` is 0 in {100 * float((cand['good'] == 0).mean()):.0f} % of the threads - a kernel that never ran would pass; give the request the field salt = set")
        if r["kind"] == "gp":       # version 27
            ex_ = gp_exec(r, np.arange(len(cand["good"])))
            for m_ in cand:
                if m_ != "good" and not np.array_equal(cand["good"] != cand[m_], ex_):
                    raise SystemExit(f"{r['id']}: hypothesis {m_} does not differ from `good` in exactly the threads whose reader executes - the probe could not see it there")
            if float((cand["good"] == 0).mean()) > 0.01:
                raise SystemExit(f"{r['id']}: the checksum of `good` is 0 in too many threads - a kernel that never ran would pass")
        if r["kind"] == "ord" and r.get("pshift") == 1 and not (cand["good"] != cand["p0old"]).all():      # version 28, second build
            raise SystemExit(f"{r['id']}: the hypothesis p0old gives the checksum of `good` in some thread - the request could not prove the reading there")
        if r["kind"] == "ord" and is_sf(r):      # version 29
            e1_, e2_ = sf_exec(r, np.arange(len(cand["good"])))
            e3_ = np.full(len(cand["good"]), any(t_.strip() == "D" for t_ in str(r["forms"]).split(",")), bool)
            for m_, ex_ in (("stale", e1_ | e2_ | e3_), ("stale1", e1_), ("stale2", e2_), ("stale3", e3_)):
                if m_ in cand and not np.array_equal(cand["good"] != cand[m_], ex_):
                    raise SystemExit(f"{r['id']}: the hypothesis {m_} does not differ from `good` in exactly the threads in which its reader word executes - the probe could not see it there")
        if r["kind"] == "ord" and r.get("pguard") and not is_sf(r) and "stale" in cand:      # version 28
            if not np.array_equal(cand["good"] != cand["stale"], set_exec(r, np.arange(len(cand["good"])))):
                raise SystemExit(f"{r['id']}: the hypothesis stale does not differ from `good` in exactly the threads in which a producer of the set executes - the probe could not see it there")
        if r["kind"] == "lb" and not (cand["good"] != cand["late"]).all():       # version 26, third build
            raise SystemExit(f"{r['id']}: a late read of the base gives the checksum of `good` in some thread - the probe could not see it there")
        if r["kind"] == "gw" and not (cand["good"] != cand["stale"]).all():      # version 26, second build
            raise SystemExit(f"{r['id']}: a stale reader gives the checksum of `good` in some thread - the probe could not see it there")
        if r["kind"] == "thr" and (cand["good"] == 0).any():      # version 26
            raise SystemExit(f"{r['id']}: the checksum of `good` is 0 in some thread - a thread that never ran would pass there")
        if any(np.array_equal(cand["good"], v) for m, v in cand.items() if m != "good") and r["kind"] != "mma":
            raise SystemExit(f"{r['id']}: a failure hypothesis gives the checksums of `good` - the probe could not see it")
        if r["kind"] == "raw" and r.get("control") == "stale" and "stale" in cand and not (cand["good"] != cand["stale"]).all():      # version 25
            raise SystemExit(f"{r['id']}: a consumer that is stale in every iteration gives the checksum of `good` in some thread - this control could not show it there")
        if r["kind"] == "reuse" and "stale" in cand and not (cand["good"] != cand["stale"]).all():
            raise SystemExit(f"{r['id']}: a stale reader gives the checksum of `good` in some thread - the probe could not see it there")
        np.savez_compressed(out / r["id"] / "model.npz", **cand)
    print(f"host models of {len(reqs)} requests written in {time.time() - t0:.0f} s (each checked against the scalar interpreter on 8 threads)")
    (out / "batch.json").write_text(json.dumps({"requests": [r["id"] for r in reqs], "kernels": total, "provenance": prov}, indent=1) + "\n")
    return 0


# ------------------------------------------------------------------------------------------------ the GPU side
def smi(q):
    try:
        return subprocess.run(["nvidia-smi", f"--query-gpu={q}", "--format=csv,noheader", "-i", "0"], capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception as e:      # noqa: BLE001
        return f"? ({e})"


def series_floor(by):
    """by: {distance: {class: count}} -> (floor | None, last not-good distance | None, sorted distances)"""
    ds = sorted(by)
    bad = [d for d in ds if set(by[d]) != {"good"}]
    if not bad:
        return ds[0], None, ds
    if bad[-1] == ds[-1]:
        return None, bad[-1], ds
    return min(d for d in ds if d > bad[-1]), bad[-1], ds


def show(t):
    n = sum(v for v in t.values() if isinstance(v, int)) or 1
    return " ".join(f"{k} {100.0 * v / n:.2f}%" if isinstance(v, int) else f"{k} {v}"
                    for k, v in sorted(t.items(), key=lambda kv: -kv[1] if isinstance(kv[1], int) else 0))


class _FakeDriver:
    def __init__(self, owner):
        self.o = owner

    def cuModuleLoad(self, _mod, _path):
        return 0

    def cuModuleGetFunction(self, _fn, _mod, _name):
        return 0

    def cuModuleUnload(self, _mod):
        return 0


class FakeCuda:
    """PROBE_FAKE=1 - the runner's own logic on a CPU, no card and no nvidia-smi: every kernel "computes" the host model's
    `good` checksums, except the tested variants below distance 4, which give the first failure hypothesis."""

    def __init__(self):
        self.cu = _FakeDriver(self)
        self.now = None      # (kernel entry, candidates, order) of the kernel being launched

    def alloc(self, _nbytes):
        import ctypes
        return ctypes.c_uint64(0x10000)

    def free(self, _d):
        pass

    def memset32(self, *_a):
        pass

    def launch(self, *_a, **_k):
        pass

    def synchronize(self):
        pass

    def from_device(self, _d, nbytes, dtype=None):
        import numpy as np
        e, cand, order = self.now
        n = nbytes // 4
        own = (np.arange(n) % 1024) < e["threads"]
        m = order[1] if (e["variant"] in ("bare", "raw") and e["distance"] < 4 and len(order) > 1) else order[0]
        out = np.zeros(n, np.uint32)
        out[own] = cand[m][:n][own]
        return out

    def close(self):
        pass


def cmd_run(args):
    import ctypes
    import numpy as np
    sys.path.insert(0, str(HERE))
    fake_env = os.environ.get("PROBE_FAKE", "")
    fake = fake_env == "1" or (fake_env == "2" and (args.child or args.no_isolate))
    if not fake_env and not os.path.exists("/.dockerenv") and os.environ.get("PROBE_ALLOW_HOST") != "1":
        raise SystemExit("probe.py run: refusing - not inside a container: it would open a CUDA context on device 0 of this host "
                         "(PROBE_FAKE=1 | 2 = a CPU rehearsal; PROBE_ALLOW_HOST=1 only on a machine whose device 0 is yours to use)")
    if fake:
        def CK(rc, what=""):
            assert not rc, what
    else:
        from culaunch import Cuda, CK
    batch = pathlib.Path(args.batch)
    ids = json.load(open(batch / "batch.json"))["requests"]
    if args.only:
        ids = [i for i in ids if re.search(args.only, i)]
    if not fake and not args.child and not args.no_isolate:      # (PROBE_FAKE=2: the same path without a card - children run fake)
        return run_isolated(args, batch, ids)
    t0 = time.time()
    clock_csv = batch / "clock.csv"
    if args.child:
        mon = None
    elif fake:
        clock_csv.write_text("")
        mon = None
    else:
        mon = subprocess.Popen(["nvidia-smi", "--query-gpu=clocks.sm,power.draw,utilization.gpu,temperature.gpu", "--format=csv,noheader,nounits",
                                "-i", "0", "-lms", "500"], stdout=open(clock_csv, "w"), stderr=subprocess.DEVNULL)
    q = (lambda _x: "FAKE (no card)") if fake else smi
    cond = {"gpu": q("name"), "driver": q("driver_version"), "clocks_max_sm": q("clocks.max.sm"), "power_limit": q("power.limit"),
            "host": socket.gethostname(), "image": os.environ.get("PROBE_IMAGE", ""), "block": os.environ.get("PROBE_BLOCK", ""),
            "runner_sha256": sha256(__file__), "in_container": os.path.exists("/.dockerenv"),
            "start_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    print(f"[probe] start {cond['start_utc']} {cond['gpu']} max {cond['clocks_max_sm']} limit {cond['power_limit']}; {len(ids)} requests", flush=True)
    cu = FakeCuda() if fake else Cuda(0)
    bufs = {}

    def buffer(ctas):
        if ctas not in bufs:
            nbytes = 1024 * ctas * 4 * 2
            keep = []
            for _ in range(8):      # a torn 64-bit address (new low word, old high word) must stay inside the buffer
                d = cu.alloc(nbytes)
                if (d.value & 0xFFFFFFFF) + nbytes < 2 ** 32:
                    break
                keep.append(d)
            else:
                raise RuntimeError("no output buffer inside one 4-GiB window")
            for k in keep:
                cu.free(k)
            bufs[ctas] = d
        return bufs[ctas]

    floors, skipped_total, dead, nkern = [], 0, 0, 0
    for rid in ids:
        fam = json.load(open(batch / rid / "family.json"))
        req = fam["request"]
        reps = args.reps or req.get("reps", 20)
        cand = dict(np.load(batch / rid / "model.npz"))
        order = [m for m in fam["modes"] if m in cand]
        late_inv = np.uint32(pow(int(fam["late_delta"]), -1, 2 ** 32)) if fam.get("late_delta") else None
        latek = {}
        results, errors, skipped = {}, [], 0
        eqfar, far_raw, ref_name, ltime = {}, {}, {}, {}
        tr = time.time()

        def run_kernel(e, nrep, far=None):
            """-> (classes per thread-launch, thread-launches equal to the reference kernel's output, the first output)"""
            ctas, threads = e["ctas"], e["threads"]
            n = 1024 * ctas
            own = (np.arange(n) % 1024) < threads
            d_out = buffer(ctas)
            tot, eq, first = {}, 0, None
            lt = []
            if fake:
                cu.now = (e, cand, order)
            mod = ctypes.c_void_p()
            try:
                CK(cu.cu.cuModuleLoad(ctypes.byref(mod), str(batch / rid / "k" / f"{e['name']}.cubin").encode()), "cuModuleLoad")
                fn = ctypes.c_void_p()
                CK(cu.cu.cuModuleGetFunction(ctypes.byref(fn), mod, e["name"].encode()), "cuModuleGetFunction")
                for _ in range(nrep):
                    cu.memset32(d_out, 0, 2 * n)
                    t1 = time.perf_counter()
                    cu.launch(fn, grid=(ctas, 1, 1), block=(threads, 1, 1), args=[d_out, ctypes.c_uint32(SEED)])
                    cu.synchronize()
                    lt.append(time.perf_counter() - t1)
                    o = cu.from_device(d_out, n * 4, dtype=np.uint32)
                    if first is None:
                        first = o
                    if far is not None:
                        eq += int(np.count_nonzero(own & (o == far)))
                    left = own.copy()
                    for m in order:
                        hit = left & (o == cand[m][:n])
                        c = int(np.count_nonzero(hit))
                        if c:
                            tot[m] = tot.get(m, 0) + c
                            left &= ~hit
                    c = int(np.count_nonzero(left))
                    if c:
                        tot["other"] = tot.get("other", 0) + c
                        if late_inv is not None:      # other = a mixture: how many of the 256 iterations were late, per thread
                            k = ((o[left] - cand["good"][:n][left]) * late_inv).astype(np.int64)
                            ok = (k >= 1) & (k <= 255)
                            st = latek.setdefault((e["variant"], e["occupancy"], e["front"], e["distance"]),
                                                  {"threads_decoded": 0, "threads_not_decoded": 0, "late_iterations": 0, "threads_with_one": 0, "max": 0})
                            st["threads_decoded"] += int(np.count_nonzero(ok))
                            st["threads_not_decoded"] += int(np.count_nonzero(~ok))
                            if ok.any():
                                st["late_iterations"] += int(k[ok].sum())
                                st["threads_with_one"] += int(np.count_nonzero(k[ok] == 1))
                                st["max"] = max(st["max"], int(k[ok].max()))
                    c = int(np.count_nonzero(~own & (o != 0)))
                    if c:
                        tot["STRAY_WORDS"] = tot.get("STRAY_WORDS", 0) + c
            finally:
                if mod:
                    cu.cu.cuModuleUnload(mod)
            if lt and nrep > 1:      # launch -> synchronize on the host's clock, the median over the launches (microseconds)
                ltime.setdefault((e["variant"], e["occupancy"], e["front"]), {})[e["distance"]] = round(1e6 * sorted(lt)[len(lt) // 2], 1)
            return tot, eq, first

        # the kernels of a request by condition (occupancy, front); the reference kernel of a condition runs first, once:
        # the control at its largest distance (war, ord) or the largest distance of the sweep (raw). Its output is NOT the
        # oracle - the host model is; it is kept so that every kernel also has its count of threads equal to it, and saved
        # when the model does not describe it (then the model can be repaired on the CPU and the counts still be read).
        groups = {}
        for e in fam["kernels"]:
            groups.setdefault((e["occupancy"], e["front"]), []).append(e)
        ref_v = "raw" if req["kind"] == "raw" else ("ctl" if any(e["variant"] == "ctl" for e in fam["kernels"]) else "bare")
        for gkey, ks in groups.items():
            refs = [e for e in ks if e["variant"] == ref_v]
            far = None
            if refs and not (time.time() - t0 > args.limit_s or dead >= 3):
                ref = max(refs, key=lambda e: e["distance"])
                try:
                    _t, _e, far = run_kernel(ref, 1)
                    far_raw[gkey], ref_name[gkey] = far, ref["name"]
                except Exception as ex:      # noqa: BLE001
                    errors.append(f"{ref['name']} (reference): {str(ex)[:120]}")
                    print(f"FAIL {ref['name']} (reference): {str(ex)[:160]}", flush=True)
                    dead += 1
            for e in ks:
                if time.time() - t0 > args.limit_s or dead >= 3:      # the time limit, or three kernels in a row failed to launch (a dead context)
                    skipped += 1
                    continue
                try:
                    tot, eq, _f = run_kernel(e, reps, far)
                    dead = 0
                except Exception as ex:      # noqa: BLE001
                    tot, eq = {"ERROR": str(ex)[:120]}, 0
                    errors.append(f"{e['name']}: {str(ex)[:120]}")
                    print(f"FAIL {e['name']}: {str(ex)[:160]}", flush=True)
                    dead += 1
                results.setdefault((e["variant"], e["occupancy"], e["front"]), {})[e["distance"]] = tot
                eqfar.setdefault((e["variant"], e["occupancy"], e["front"]), {})[e["distance"]] = eq
        skipped_total += skipped
        nkern += len(fam["kernels"]) - skipped
        # ---- per series
        series = []
        for (v, occ, front), by in sorted(results.items()):
            fl, last_bad, ds = series_floor(by)
            ctas, threads = GEOM[occ]
            tl = ctas * threads * reps
            # the oracle of a series: its own largest distance (raw) / its control kernels (war) must be 100 % good
            entry = {"variant": v, "occupancy": occ, "occupancy_text": OCC[occ], "front": front, "thread_launches_per_kernel": tl,
                     "iterations_per_thread": REPEAT, "distances": ds, "by_distance": {str(d): by[d] for d in ds},
                     "floor": fl, "last_not_good": last_bad,
                     "events_clean_at_floor": (tl * REPEAT) if fl is not None else 0,
                     "reference_kernel": ref_name.get((occ, front), ""),
                     "late_iterations_in_mixtures": {str(d): latek[(v, occ, front, d)] for d in ds if (v, occ, front, d) in latek},
                     "equal_to_reference_by_distance": {str(d): eqfar.get((v, occ, front), {}).get(d, 0) for d in ds},
                     "launch_us_median_by_distance": {str(d): ltime.get((v, occ, front), {}).get(d) for d in ds},
                     "smem_per_cta": next((e.get("smem", SMEM) for e in fam["kernels"] if e["occupancy"] == occ), SMEM)}
            series.append(entry)
        def find(v, occ, front):
            return next((s for s in series if (s["variant"], s["occupancy"], s["front"]) == (v, occ, front)), None)
        main_v = "raw" if req["kind"] == "raw" else "bare"
        per_cond, oracle_bad, bad_groups = {}, [], []
        for s in series:
            if s["variant"] != main_v:
                continue
            key = f"{s['occupancy']}/{s['front']}"
            if req["kind"] in ("war", "ord"):
                ctl = find("ctl", s["occupancy"], s["front"])
                if ctl is not None and ctl["last_not_good"] is not None:
                    oracle_bad.append(f"{key}: the control is not good ({show(ctl['by_distance'][str(ctl['last_not_good'])])})")
                    s["oracle"] = "FAILED"
                    bad_groups.append((s["occupancy"], s["front"]))
                    continue
                s["oracle"] = "ok (control: good in every thread)" if ctl is not None else "no control series"
                rbs = find("rb", s["occupancy"], s["front"])
                if rbs is not None:
                    s["read_barrier_control"] = "good at every distance" if rbs["last_not_good"] is None else f"NOT good to {rbs['last_not_good']}"
            else:
                far = s["by_distance"][str(s["distances"][-1])]
                if set(far) != {"good"}:
                    oracle_bad.append(f"{key}: the largest distance ({s['distances'][-1]}) is not good ({show(far)})")
                    s["oracle"] = "FAILED"
                    bad_groups.append((s["occupancy"], s["front"]))
                    continue
                s["oracle"] = f"ok (distance {s['distances'][-1]}: good in every thread)"
            per_cond[key] = s["floor"]
        vals = [v for v in per_cond.values()]
        binding = None if (not vals or any(v is None for v in vals)) else max(vals)
        incomplete = skipped > 0 or bool(errors)      # a series cut by the time limit or by a launch error has no floor
        if incomplete:
            oracle_bad.append(f"INCOMPLETE: {skipped} kernels not launched (time limit / dead context), {len(errors)} launch errors")
            binding = None
        cell = fam.get("table_cell")
        verdict, margin = "", None
        if req["kind"] == "raw" and cell and cell.get("L") is not None:
            if oracle_bad or not vals:
                verdict = "NO RESULT (oracle)"
            elif binding is None:
                verdict = f"TOO LOW: not clean up to the largest distance swept (table {cell['L']})"
            else:
                margin = cell["L"] - binding
                verdict = (f"holds: floor {binding} <= table {cell['L']} ({cell['source']}), margin {margin}" if margin >= 0
                           else f"TOO LOW: floor {binding} > table {cell['L']} ({cell['source']})")
        wanted = req.get("wanted")
        covers = None
        if wanted is not None and not oracle_bad and vals:
            covers = binding is not None and binding <= int(wanted)
            verdict += ("; " if verdict else "") + (f"wanted distance {wanted}: COVERED (floor {binding})" if covers
                                                    else f"wanted distance {wanted}: NOT covered (floor {'none' if binding is None else binding})")
        res = {"tool": TOOL, "request": req, "pair": fam["pair"], "provenance": fam["provenance"], "conditions": dict(cond, reps=reps),
               "table_cell": cell, "series": series, "floor": {"binding": binding, "per_condition": per_cond, "margin_vs_table": margin,
                                                              "wanted": wanted, "covers_wanted": covers,
                                                              "verdict": verdict, "oracle_failures": oracle_bad},
               "errors": errors, "skipped_kernels": skipped, "seconds": round(time.time() - tr, 1)}
        (batch / rid / "result.json").write_text(json.dumps(res, indent=1) + "\n")
        if bad_groups:      # what the reference kernels really produced, for the repair of the model on the CPU
            np.savez_compressed(batch / rid / "reference_raw.npz", **{f"{o}__{front_id(f)}": far_raw[(o, f)] for o, f in bad_groups if (o, f) in far_raw})
        floors.append({"id": rid, "pair": fam["pair"], "kind": req["kind"], "binding": binding, "per_condition": per_cond,
                       "verdict": verdict, "oracle_failures": oracle_bad, "errors": len(errors), "skipped": skipped})
        b = "none up to the largest distance swept" if binding is None and vals else binding
        print(f"RESULT {rid} [{fam['pair']}]: floor {b}; " + ", ".join(f"{k} {'NONE' if v is None else v}" for k, v in sorted(per_cond.items()))
              + (f"; {verdict}" if verdict else "") + (f"; ORACLE FAILED: {'; '.join(oracle_bad)[:300]}" if oracle_bad else "")
              + (f"; ERRORS {len(errors)}" if errors else "") + (f"; skipped {skipped}" if skipped else ""), flush=True)
        for s in series:
            if s["variant"] == main_v and s["last_not_good"] is not None:
                bd = s["by_distance"]
                pts = [d for d in s["distances"] if set(bd[str(d)]) != {"good"}]
                prof = " | ".join(f"d{d}: {show(bd[str(d)])}" for d in pts[:3] + pts[-2:])
                print(f"DETAIL {rid} {s['occupancy']}/{s['front']}: not good at {len(pts)} of {len(s['distances'])} distances, last {s['last_not_good']} || {prof}"[:700], flush=True)
    if args.child:      # one request in its own process: its row goes to the parent, which owns the clock and the summary
        for f in floors:
            (batch / f["id"] / "floor_row.json").write_text(json.dumps(dict(f, nkern=nkern, dead=dead)) + "\n")
        cu.close()
        return 0
    if mon is not None:
        mon.terminate()
    return finish(batch, ids, floors, cond, t0, nkern, skipped_total, dead, clock_csv, cu)


def run_isolated(args, batch, ids):
    """the default on a card: ONE PROCESS PER REQUEST. A kernel that traps kills its context - and with it only the rest of
    its own request; the next request starts in a fresh process with a fresh context."""
    t0 = time.time()
    clock_csv = batch / "clock.csv"
    fake2 = os.environ.get("PROBE_FAKE") == "2"
    if fake2:
        clock_csv.write_text("")
        mon = None
    else:
        mon = subprocess.Popen(["nvidia-smi", "--query-gpu=clocks.sm,power.draw,utilization.gpu,temperature.gpu", "--format=csv,noheader,nounits",
                                "-i", "0", "-lms", "500"], stdout=open(clock_csv, "w"), stderr=subprocess.DEVNULL)
    q = (lambda _x: "FAKE (no card)") if fake2 else smi
    cond = {"gpu": q("name"), "driver": q("driver_version"), "clocks_max_sm": q("clocks.max.sm"), "power_limit": q("power.limit"),
            "host": socket.gethostname(), "image": os.environ.get("PROBE_IMAGE", ""), "block": os.environ.get("PROBE_BLOCK", ""),
            "runner_sha256": sha256(__file__), "one_process_per_request": True,
            "start_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    print(f"[probe] start {cond['start_utc']} {cond['gpu']} max {cond['clocks_max_sm']} limit {cond['power_limit']}; {len(ids)} requests, one process each", flush=True)
    floors, nkern, skipped_total = [], 0, 0
    for rid in ids:
        fam = json.load(open(batch / rid / "family.json"))
        row_p = batch / rid / "floor_row.json"
        if row_p.exists():
            row_p.unlink()
        left = args.limit_s - (time.time() - t0)
        rc = None
        if left > 5:
            cmd = [sys.executable, os.path.abspath(__file__), "run", str(batch), "--only", f"^{re.escape(rid)}$", "--child", "--limit-s", str(left)]
            rc = subprocess.run(cmd + (["--reps", str(args.reps)] if args.reps else []),
                                env=dict(os.environ, PROBE_FAKE="1") if fake2 else None).returncode
        if row_p.exists():
            row = json.load(open(row_p))
            nkern += row.pop("nkern", 0)
            row.pop("dead", None)
            skipped_total += row.get("skipped", 0)
            floors.append(row)
        else:
            why = "NOT RUN: the block's time limit" if rc is None else f"PROCESS FAILED (exit {rc}): no result"
            print(f"FAIL {rid}: {why}", flush=True)
            skipped_total += len(fam["kernels"])
            floors.append({"id": rid, "pair": fam["pair"], "kind": fam["request"]["kind"], "binding": None, "per_condition": {}, "verdict": "",
                           "oracle_failures": [why], "errors": 0 if rc is None else 1, "skipped": len(fam["kernels"])})
    if mon is not None:
        mon.terminate()
    return finish(batch, ids, floors, cond, t0, nkern, skipped_total, 0, clock_csv, None)


def finish(batch, ids, floors, cond, t0, nkern, skipped_total, dead, clock_csv, cu):
    # ---- conditions: the clock while busy
    busy = []
    pmax = 0.0
    for line in open(clock_csv):
        f = [x.strip() for x in line.split(",")]
        try:
            clk, pw, ut = float(f[0]), float(f[1]), float(f[2])
        except (ValueError, IndexError):
            continue
        pmax = max(pmax, pw)
        if ut >= 20:
            busy.append(clk)
    cond.update({"end_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "seconds": round(time.time() - t0, 1),
                 "clock_busy_mean_mhz": round(sum(busy) / len(busy)) if busy else None, "clock_busy_max_mhz": max(busy) if busy else None,
                 "power_max_w": pmax, "busy_samples": len(busy)})
    for rid in ids:
        p = batch / rid / "result.json"
        if not p.exists():
            continue
        r = json.load(open(p))
        r["conditions"].update(cond)
        p.write_text(json.dumps(r, indent=1) + "\n")
    (batch / "floors.json").write_text(json.dumps({"tool": TOOL, "conditions": cond, "floors": floors}, indent=1) + "\n")
    nor = sum(1 for f in floors if f["oracle_failures"])
    low = [f["id"] for f in floors if f["verdict"].startswith("TOO LOW")]
    print(f"SUMMARY probe batch {batch.name}: {len(ids)} requests, {nkern} kernels launched, {time.time() - t0:.0f} s of the card; oracle failures {nor}, "
          f"requests with launch errors {sum(1 for f in floors if f['errors'])}, kernels skipped {skipped_total}{' (ABORTED: three kernels in a row failed to launch)' if dead >= 3 else ''}; "
          f"clock while busy mean {cond['clock_busy_mean_mhz']} / max {cond['clock_busy_max_mhz']} MHz, power max {pmax:.0f} W", flush=True)
    def fl(f):
        return "NONE" if f["binding"] is None else str(f["binding"])
    raw = " ".join(f"{f['id']}={fl(f)}" for f in floors if f["kind"] == "raw" and not f["oracle_failures"])
    war = " ".join(f"{f['id']}={fl(f)}" for f in floors if f["kind"] == "war" and not f["oracle_failures"])
    print(f"SUMMARY raw floors (binding over the conditions): {raw}"[:290], flush=True)
    print(f"SUMMARY war floors (smallest distance from which an unwaited rewrite never reached the store; NONE = not up to the largest swept): {war}"[:290], flush=True)
    mmal = " ".join(f"{f['id']}={fl(f)}" for f in floors if f["kind"] == "mma" and not f["oracle_failures"])
    if mmal:
        print(f"SUMMARY mma floors (two MMAs of one warp: smallest issue distance from which both results were always right): {mmal}"[:290], flush=True)
    ordl = " ".join(f"{f['id']}={fl(f)}" for f in floors if f["kind"] == "ord" and not f["oracle_failures"])
    if ordl:
        print(f"SUMMARY ord floors (older load without a barrier -> younger load whose barrier the reader waits on; smallest distance from which the reader was always right): {ordl}"[:290], flush=True)
    print(f"SUMMARY table cells too low: {len(low)} {' '.join(low)}"[:290], flush=True)
    if cu is not None:
        cu.close()
    return 0


def cmd_floor(args):
    paths = []
    for p in args.paths:
        p = pathlib.Path(p)
        paths += sorted(p.glob("*/result.json")) if p.is_dir() else [p]
    for p in paths:
        r = json.load(open(p))
        req, fl, c = r["request"], r["floor"], r["conditions"]
        occ = ", ".join(sorted({s["occupancy"] for s in r["series"]}))
        fronts = ", ".join(sorted({s["front"] for s in r["series"]}))
        b = fl["binding"]
        n = "NONE up to %d" % max(req["distance_list"]) if b is None else str(b)
        per = ", ".join(f"{k} {'NONE' if v is None else v}" for k, v in sorted(fl["per_condition"].items()))
        cell = r.get("table_cell")
        tab = f"; table {cell['L']} ({cell['source']}): {fl['verdict']}" if cell and fl.get("verdict") else ""
        print(f"floor: {r['pair']} = {n} ({c.get('gpu', '?')}, clock {c.get('clock_busy_mean_mhz')} MHz busy, occupancy {occ}; front {fronts}; "
              f"{c.get('reps')} launches x 256 iterations per thread; per condition: {per}{tab}"
              + (f"; ORACLE FAILED {fl['oracle_failures'][:2]}" if fl.get("oracle_failures") else "") + f") [{p}]")
    return 0

# ------------------------------------------------------------------------------------------------ requests written by other tools
# The offline gate of the schedule search (emu120.gate) writes, per candidate, `kernels[i].probes`: one object per pair that nobody measured
#   {kind: "producer -> consumer (read after write)" | "reader -> overwriter (write after read)" | ..., first: {form, text, is},
#    second: {form, text, is}, operand_role, distance_wanted, distance_in_seed, sweep: {distance: [lo, hi], occupancy_warps_per_sm}, sites, kernel}
# `probe.py adapt` turns such files into a request file of this tool (one request per distinct pair, `wanted` = the smallest
# distance any site asks for) and lists what the catalogue cannot build yet - the work list of the catalogue.
ADAPT_PROD = {"IADD3": "IADD3", "IMAD": "IMAD", "LOP3.LUT": "LOP3", "MOV": "MOV", "SHF.R.U32.HI": "SHF", "SHF.L.U32": "SHF",
              "FADD": "FADD", "FADD.FTZ": "FADD", "FMUL": "FMUL", "FMUL.FTZ": "FMUL", "SEL": "SEL",
              "F2FP.SATFINITE.BF16.F32.PACK_AB": "F2FP.SAT", "PRMT": "PRMT", "IMAD.SHL.U32": "IMAD.SHL", "IADD.64": "IADD.64",
              "IMAD.WIDE.U32": "IMAD.WIDE", "IMAD.WIDE": "IMAD.WIDE"}
ADAPT_CONS = {("STS", "r1"): "STS.data", ("STS", "a0"): "STS.addr", ("STS.128", "r1"): "STS128.d0", ("STS.128", "r1h"): "STS128.d3",
              ("STG.E", "r1"): "STG.data", ("STG", "r1"): "STG.data", ("LDS", "a1"): "LDS.addr", ("LDS", "a0"): "LDS.addr",
              ("IADD3", "r1"): "IADD3.r1", ("IADD3", "r2"): "IADD3.r2", ("IMAD", "r1"): "IMAD.r1", ("IMAD", "r3"): "IMAD.r3",
              ("LOP3.LUT", "r1"): "LOP3.r1", ("MOV", "r1"): "MOV.r1", ("SHF.L.U32", "r1"): "SHF.r1", ("SEL", "r1"): "SEL.r1",
              ("PRMT", "r1"): "PRMT.r1", ("I2FP.F32.S32", "r1"): "I2FP.r1", ("IMAD.SHL.U32", "r1"): "IMAD.SHL.r1",
              ("IADD.64", "r1"): "IADD.64.r1", ("IADD.64", "r1h"): "IADD.64.r1h", ("LEA", "r1"): "LEA.r1", ("LEA", "r2"): "LEA.r2"}
ADAPT_STORE = {("STS", "r1"): "STS.data", ("STS", "a0"): "STS.addr", ("STS.128", "r1"): "STS128.data", ("STS.128", "r1h"): "STS128.data",
               ("STG.E", "r1"): "STG.data", ("STG.E", "a0"): "STG.addr", ("STG.E", "a1"): "STG.addr"}
ADAPT_OVER = {"LOP3.LUT": "LOP3", "IADD3": "IADD3", "MOV": "MOV", "LDS": "LDS", "LDS.128": "LDS128", "LDSM.16.M88.4": "LDSM", "LDG.E": "LDG"}


def cmd_adapt(args):
    files = []
    for p in args.paths:
        p = pathlib.Path(p)
        files += sorted(p.rglob("*.json")) if p.is_dir() else [p]
    got, missing, nprobe = {}, {}, 0
    for f in files:
        try:
            doc = json.load(open(f))
        except (OSError, ValueError):
            continue
        for k in (doc.get("kernels") or []) if isinstance(doc, dict) else []:
            for pr in k.get("probes") or []:
                nprobe += 1
                kind = str(pr.get("kind", ""))
                a, b = pr.get("first") or {}, pr.get("second") or {}
                fa, fb = str(a.get("form", "")), str(b.get("form", ""))
                oa, ob = (fa.split() or [""])[0], (fb.split() or [""])[0]
                role = str(pr.get("operand_role", ""))
                sites = len(pr.get("sites") or [None])
                want = pr.get("distance_wanted")
                req = None
                if kind.startswith("producer -> consumer"):
                    cons = ADAPT_CONS.get((ob, role))
                    prod = ADAPT_PROD.get(oa)
                    if prod == "IADD3" and "-R" in str(a.get("text", "")):
                        prod = "IADD3.neg"
                    if cons and prod and prod in (ADDR_PRODUCERS if RAW_CONSUMERS[cons][0] == "addr" else DATA_PRODUCERS) \
                            and not (cons == "IADD.64.r1h" and prod not in PAIR_PRODUCERS):
                        mem = RAW_CONSUMERS[cons][2] in ("STS", "STG", "LDS")
                        req = {"kind": "raw", "producer": prod, "consumer": cons,
                               "front": ["none", "stgx15@4" if RAW_CONSUMERS[cons][2] == "STG" else "sts128x15@4"] if mem else ["none"],
                               "cell": {"producer": oa.replace(".LUT", ""), "consumer": RAW_CONSUMERS[cons][2], "role": role}}
                elif kind.startswith("reader -> overwriter"):
                    st, ov = ADAPT_STORE.get((oa, role)), ADAPT_OVER.get(ob)
                    if st and ov and ov in WAR_STORES[st][0]:
                        req = {"kind": "war", "store": st, "overwriter": ov, "front": ["none", "sts128x15@4"], "controls": True}
                if req is None:
                    m = missing.setdefault((kind, fa, fb, role), {"kind": kind, "first": fa, "second": fb, "operand_role": role, "sites": 0,
                                                                  "distance_wanted": want, "example": [a.get("text", ""), b.get("text", "")], "files": []})
                    m["sites"] += sites
                    if want is not None and (m["distance_wanted"] is None or want < m["distance_wanted"]):
                        m["distance_wanted"] = want
                    if str(f) not in m["files"]:
                        m["files"].append(str(f))
                    continue
                key = (req["kind"], req.get("producer") or req.get("store"), req.get("consumer") or req.get("overwriter"))
                hi = int((pr.get("sweep") or {}).get("distance", [1, 30])[1])
                r = got.setdefault(key, dict(req, occupancy=["w1", "w8", "w32"], sites=0, wanted=want, hi=hi, forms=[fa, fb]))
                r["sites"] += sites
                r["hi"] = max(r["hi"], hi)
                if want is not None and (r["wanted"] is None or want < r["wanted"]):
                    r["wanted"] = want
    out = []
    for (kind, x, y), r in sorted(got.items()):
        hi = min(max(r.pop("hi"), 30), 150)
        r["distances"] = "1-15" + (f",18-{hi}:3" if hi > 18 else "") + ("" if kind == "raw" else ",105,150")
        r["id"] = re.sub(r"[^a-z0-9]+", "_", f"g_{x}_{y}".lower())[:40].strip("_")
        r["note"] = f"from {nprobe} gate requests: {r.pop('sites')} site(s), forms {r.pop('forms')}"
        if r["wanted"] is None:
            r.pop("wanted")
        out.append(normalise(r) and r)
    outp = pathlib.Path(args.out)
    outp.write_text(json.dumps(out, indent=1) + "\n")
    miss = sorted(missing.values(), key=lambda m: -m["sites"])
    pathlib.Path(str(outp) + ".not_in_catalogue.json").write_text(json.dumps(miss, indent=1) + "\n")
    print(f"{nprobe} gate requests in {len(files)} files -> {len(out)} requests of this tool in {outp}; {len(miss)} distinct pairs ({sum(m['sites'] for m in miss)} sites) "
          f"are not in the catalogue: {outp}.not_in_catalogue.json")
    for m in miss[:12]:
        print(f"  not in the catalogue x{m['sites']}: {m['kind'][:24]} | {m['first']} -> {m['second']} ({m['operand_role']})")
    return 0


def cmd_list(_args):
    print("kind raw - producer -> consumer:")
    print("  data producers:", ", ".join(DATA_PRODUCERS), "| address producers:", ", ".join(ADDR_PRODUCERS), "| uniform producers:", ", ".join(UNIFORM_PRODUCERS))
    for k, v in RAW_CONSUMERS.items():
        print(f"  consumer {k:10s} {v[4]} (table class {v[2]}, role {v[3]}; producer kind: {v[0]})")
    print("  version 22: consumers " + ", ".join(FLOAT_CONSUMERS) + " take a producer of " + ", ".join(FLOAT_PRODUCERS) + "; MUFU.RCP.r1 takes MOV.pow2; "
          "\"result\": 1 = the consumer takes the SECOND register of a pair producer (" + ", ".join(sorted(PAIR_PRODUCERS)) + "): " + ", ".join(RESULT1_CONSUMERS)
          + "; \"salt\": \"set\" = the iteration's input is added to the checksum behind the consumer")
    print("  version 24: TENSOR consumers QMMA.r3 | .r3h | .r1 | .r1h | .r2 | .r2h, HMMA.r3 | .r3h (one register of an operand of a tensor word with uniform fragments; \"reg\": 1 | 2 | 3 = "
          "which upper register) take " + "; ".join(f"{k}: {', '.join(v)}" for k, v in T24_PRODUCERS.items() if k in ("acc", "a", "b")) + "; RELATIVE consumers QMMA.u6 (UMOV), IMADi.rel, "
          "IMAD.rel, IADD.64.rel (" + ", ".join(T24_PRODUCERS["rel"]) + "): the result at the swept distance against the same word's 45 cycles later; \"control\": \"stale\" = the positive "
          "control (the producer's word behind the consumer - expect 0 % good); fronts none | mmaxK@S | sts128xK@S | stsxK@S")
    print("  version 25: \"control\": \"stale\" on EVERY raw request (an ordinary pair: the producer's word behind the consumer and its checksum - expect 0 % good, class stale); consumers "
          + ", ".join(RR_CONSUMERS) + " (the register-register IADD.64), PRMT.r3, STG.a0 (global-address producers: " + ", ".join(GADDR_PRODUCERS) + "); kind mma: hold_c_cs2r / sens_c_cs2r "
          "(\"reg\": 0 | 2), hold_c_prmt / sens_c_prmt, \"dest\": \"a\" = the result of a hold_c_* / sens_c_* word goes to its own A quad; table_cell reads the table's producer_forms")
    print("  version 25, fifth build: the consumer LEA.r2 (the unshifted operand); kind mma: hold_u_umov / sens_u_umov (the uniform selector of a QMMA.SF behind the word, RELATIVE)")
    print("kind war - a register of a BARE store rewritten behind it:")
    for k, v in WAR_STORES.items():
        print(f"  store {k:12s} overwriters {', '.join(v[0])}: {v[2]}")
    print("  a shuffle's source register: \"read_barrier\": \"set\" = the shuffle carries a read barrier in the bare variant too (the overwriter does not wait it)")
    print("  a shuffle's source register: overwriter IADD3.it adds (iteration index + 1) x the constant (which iteration is the late one); \"behind\": \"write_waiter\" = the overwriter behind the reader that waited the shuffle's WRITE barrier (distance = waiter -> overwriter); \"behind\": \"younger_write\" (+ \"younger_gap\": 1..15) = a barrier-less shuffle read under a YOUNGER shuffle's write barrier")
    print("  write after write (version 18): stores LDS.dst / LDG.dst / LDC.dst / S2R.dst / SHFL.dst / LDS128.dst = the FIRST writer of a register on write barrier 1, the overwriter = the second writer d cycles behind it (IADD3 / IADD3.it: the first writer's value - the constant, so late first writes are counted / decoded; LDS / LDG / SHFL: a scoreboarded second writer); ctl = the second writer waits barrier 1, rb = no first writer")
    print("  mixed producer classes (version 18): ord pairs with a younger S2R / S2UR / LDC64 and an older LDC / SHFL (\"older_barrier\": \"same\" = both on ONE write barrier); \"yield\": \"set\" on a raw / mma request = its swept instruction carries the yield flag")
    print("kind mma - two tensor instructions of one warp, d issue cycles apart (form; variant; via stall | nop):")
    print("  forms: " + ", ".join(f"{k} = {v}" for k, v in MMA_FORMS.items()))
    for k, v in MMA_VARIANTS.items():
        print(f"  variant {k:7s} {v}")
    print("kind ord - an OLDER load without a write barrier, read behind the wait on a YOUNGER load's barrier (older, younger):")
    print("  " + ", ".join(f"({a}, {b})" for a, b in ORD_PAIRS) + "; distance = older -> younger; `younger_stall` (default 2) = younger -> reader")
    print("  version 21: \"older_barrier\": \"recycle\" = the younger load's own word waits the older load's write barrier and sets it again, the reader of the older load does not wait; "
          "N loads: \"yield\": \"set\" = the loads carry the yield flag; \"forms\": \"s,d,gq,...\" = N loads of mixed forms (s LDS, u LDS.U16, d LDS.64, q LDS.128; prefix g = under a true guard, f = under a false guard), up to 13")
    print("  version 23, SETS of producers on one write barrier: \"forms\" also takes " + ", ".join(f"{k} = {v[0]}" for k, v in SET_FORM.items())
          + " (prefix g on a load); 2 .. 17 producers; R0-R79 (.regcount 88); grids " + " ".join(SET_OCC)
          + "; LDC.64 and MUFU.EX2 are read relative to a reference (the host does not know their content)")
    print("  version 21, a shuffle's source: \"behind\": \"younger_read\" = the overwriter behind a word that waited a YOUNGER shuffle's READ barrier; \"younger_lds\" = ... a younger LDS's write barrier (+ \"younger_gap\")")
    print("  version 19, two-load requests: \"far\": \"base2\" = the younger shared load through ANOTHER base register that holds the same address (the same line); \"older_guard\": \"true\" = the older shared load under a guard that is true")
    print("  N loads in flight and ONE wait: \"nload\": 2..8, \"place\": near | base2 | far (>= 1 KB apart), \"barrier\": last (the older loads bare) | all (one shared barrier) | none (positive control: no wait); distance = load -> load, 1..15")
    print("  two loads on ONE write barrier: \"older_barrier\": \"same\" (does the scoreboard count its producers?)")
    print("kind reuse (version 20) - the operand-reuse flag: a word reads R6 through slot A / B / C (flag bit 122 / 123 / 124 - a slot is its flag bit; in the seven forms below its operand is the register field at bit 24 / 32 / 64) with `.reuse`, R6 is written again, a reader takes R6 through the slot d cycles behind the write:")
    for k, v in REUSE_FORMS.items():
        print(f"  flagged / reader form {k:9s} slot {v[0]}: {v[1].format(d='Rd', r='R6.reuse')}  (the vendor's row: {v[4]})")
    for k, v in REUSE_WRITERS.items():
        print(f"  writer {k:6s} {v}")
    print("  \"words\": 1..5 = the reader k words behind the write (fillers \"fill\": clean | other); \"fstall\": 1 | 2; \"chain\": true = the reader flagged too; \"window_yield\": set | none; "
          "\"between\": " + " | ".join(f"{k} ({v})" for k, v in REUSE_BETWEEN.items() if k) + "; variants bare (the flag) and ctl (no flag)")
    print("kind gp (version 27) - a guarded wait under ANOTHER predicate (two LDC.64 under two predicates on one barrier; the wait on a word under the first, the reader under the second): "
          "\"form\": " + " | ".join(GP_FORMS) + "; \"guards\": " + " | ".join(GP_GUARDS) + "; \"pset\": pro | near; \"wait\": guarded | end (the control); form imad \"share\": " + " | ".join(GP_SHARE))
    print("kind lb (version 26, third build) - the BASE register of a load rewritten by a younger load of the same pipe (LDS R6, [R13+0x4] <- LDS R13, [R13+0x3c]); \"control\": \"front\"; \"yield\": \"set\"")
    print("kind gw (version 26, second build) - a WAIT carried by a word under a guard: producer " + " | ".join(GW_PRODUCERS) + "; \"wait\": guarded | none | end (fourth build: one wait at the end of the iteration - the floor by distance alone); \"guard\": bit | false; \"yield\": \"set\"")
    print("kind thr (version 26) - a THROUGHPUT probe: the time of a synthetic stage loop with tensor words; \"stage\", \"repeat\" (odd); the slot in the distance slot:")
    for st_, sl_ in THR_STAGES.items():
        for k_, (nm_, tx_) in enumerate(sl_, 1):
            print(f"  stage {st_} slot {k_:2d} {nm_:9s} {tx_}")
    print("kind ord (version 29) - the SCALE SET: \"forms\" of S (an unguarded LDS into a block-scale register of two guarded QMMA.SF readers) and D (second build: an unguarded LDS.64 read by MOV words), "
          "2 .. 7 loads on one write barrier; \"pguard\": two letters of t | f | l | c (P0 the first tensor reader, P2 the second); \"rdist\"; \"lead\": mov; \"wait\": reader | end (the control); "
          "hypotheses stale, stale1, stale2, stale3; sf_audit counts the cycles")
    print("occupancy:", "; ".join(f"{k} = {v}" for k, v in OCC.items()))
    print("front: none | sts128xK@S | stsxK@S | stgxK@S  (K stores of a constant at stall S in front of the tested instruction)")
    return 0


def cmd_selftest(_args):
    import numpy as np
    gids = np.array([0, 5, 1023, 1024, 40000, NGID - 1])
    n = 0
    n25 = 0
    for cons in RAW_CONSUMERS:
        what = RAW_CONSUMERS[cons][0]
        if what in T24_WHAT:      # version 24: their own part below
            continue
        for prod in (ADDR_PRODUCERS if what == "addr" else UNIFORM_PRODUCERS if what == "udata" else GADDR_PRODUCERS if what == "gaddr" else DATA_PRODUCERS):
            if cons in ("IADD.64.r1h", "SHF.L.U64.HI.r1") and prod not in PAIR_PRODUCERS:
                continue
            if prod == "CS2R" and RAW_CONSUMERS[cons][1] % 2:
                continue
            if cons.startswith("IMAD.WIDE.r3") and prod in PAIR_PRODUCERS:
                continue
            if not raw_pair_ok(prod, cons):
                continue
            r = normalise({"id": "selftest", "kind": "raw", "producer": prod, "consumer": cons})
            for mode in modes_of(r):
                v = model(r, mode, gids=gids)
                assert [int(x) for x in v] == model(r, mode, gids=gids, scalar=True), (prod, cons, mode)
                n += 1
            assert not np.array_equal(model(r, "good", gids=gids), model(r, "stale", gids=gids)), (prod, cons)
            # version 25: the positive control of an ordinary pair - the request's model, the producer's word behind the consumer and its checksum
            rc = normalise({"id": "selftest", "kind": "raw", "producer": prod, "consumer": cons, "control": "stale"})
            g_, st_ = model(r, "good", gids=gids), model(r, "stale", gids=gids)
            assert np.array_equal(g_, model(rc, "good", gids=gids)) and np.array_equal(st_, model(rc, "stale", gids=gids)), (prod, cons, "the control's model is the request's")
            assert [int(x) for x in st_] == model(rc, "stale", gids=gids, scalar=True), (prod, cons)
            # a consumer stale in EVERY iteration must change the checksum in EVERY thread (address consumers of the thread's four words: in most)
            assert (g_ != st_).all() or what == "addr", (prod, cons, "a stale consumer must change every thread's checksum")
            for dd in (1, 7, 16):
                b_, bc_ = body_raw(r, dd, "none"), body_raw(rc, dd, "none")
                pt_, pc_ = next(a for a in b_ if a.tag == "P"), next(a for a in bc_ if a.tag == "P")
                assert len(bc_) == len(b_) + 1 and [a.line() for a in bc_[:-1] if a.tag != "P"] == [a.line() for a in b_ if a.tag != "P"], (prod, cons, dd)
                assert pc_.text == "IADD3 R15, PT, PT, R15, 0x1, RZ ;" and pc_.sem == pt_.sem and pc_.ctl == pt_.ctl and pc_.dst == pt_.dst, (prod, cons, dd)
                assert bc_[-1].text == pt_.text and bc_[-1].sem == ("nop",) and bc_[-1].tag is None and bc_.index(pc_) < next(k for k, a in enumerate(bc_) if a.tag == "C"), (prod, cons, dd)
                # (a pair the card would refuse - a 64-bit producer on an odd register - is refused by kernel_text for the request and for its control alike)
                assert misaligned("\n".join(i.line() for i in bc_)) == misaligned("\n".join(i.line() for i in b_)), (prod, cons, dd)
            n25 += 1
    # version 22: the pair's SECOND result register - the consumer's word differs in R6 -> R7 and in nothing else
    for prod in sorted(PAIR_PRODUCERS):
        for cons in RESULT1_CONSUMERS:
            if not raw_pair_ok(prod, cons):
                continue
            r0, r1 = (normalise(dict({"id": "selftest", "kind": "raw", "producer": prod, "consumer": cons}, **x)) for x in ({}, {"result": 1}))
            b0, b1 = body_raw(r0, 3, "none"), body_raw(r1, 3, "none")
            dd = [(a, c) for a, c in zip(b0, b1) if a.line() != c.line()]
            assert len(b0) == len(b1) and len(dd) == 1 and dd[0][0].tag == "C" and dd[0][0].ctl == dd[0][1].ctl, (prod, cons)
            assert re.sub(R6_TOKEN, "R7", dd[0][0].text) == dd[0][1].text and "R7" not in dd[0][0].text and not re.search(R6_TOKEN, dd[0][1].text), (prod, cons)
            for mode in modes_of(r1):
                v = model(r1, mode, gids=gids)
                assert [int(x) for x in v] == model(r1, mode, gids=gids, scalar=True), (prod, cons, mode)
                n += 1
            assert not np.array_equal(model(r1, "good", gids=gids), model(r1, "stale", gids=gids)), (prod, cons)
            assert not np.array_equal(model(r1, "stale", gids=gids), model(r0, "stale", gids=gids)), (prod, cons)
    for bad in ({"producer": "IADD3", "consumer": "FMUL.r2"}, {"producer": "MOV", "consumer": "FFMA.r2"}, {"producer": "MOV.fin", "consumer": "MUFU.RCP.r1"},
                {"producer": "MOV", "consumer": "LOP3.r1", "result": 1}, {"producer": "CS2R", "consumer": "LEA.r1", "result": 1},
                {"producer": "CS2R", "consumer": "IMAD.WIDE.r3", "result": 1}, {"producer": "CS2R", "consumer": "LOP3.r1", "result": 2}):
        try:
            normalise(dict({"id": "selftest", "kind": "raw"}, **bad))
        except SystemExit:
            n += 1
        else:
            raise AssertionError(f"version 22: {bad} must be refused")
    for prod, cons, extra in (("CS2R", "MOV.r1", {"result": 1}), ("CS2R", "FMUL.r2", {}), ("CS2R", "SHF.r3", {"result": 1}), ("MOV", "IADD.r1", {})):      # the salt
        r0, r1 = (normalise(dict({"id": "selftest", "kind": "raw", "producer": prod, "consumer": cons}, **extra, **x)) for x in ({}, {"salt": "set"}))
        b0, b1 = body_raw(r0, 3, "none"), body_raw(r1, 3, "none")
        assert len(b1) == len(b0) + 1 and [a.line() for a in b1[:-1]] == [a.line() for a in b0] and b1[-1].text == "IADD3 R10, PT, PT, R10, R4, RZ ;" and b1[-1].tag is None, (prod, cons)
        big = np.arange(0, NGID, 97, dtype=np.int64)
        g0, g1 = model(r0, "good", gids=big), model(r1, "good", gids=big)
        assert float((g1 == 0).mean()) < 0.01 and (prod != "CS2R" or float((g0 == 0).mean()) > 0.4), (prod, cons, float((g0 == 0).mean()), float((g1 == 0).mean()))
        for mode in modes_of(r1):
            assert [int(x) for x in model(r1, mode, gids=gids)] == model(r1, mode, gids=gids, scalar=True), (prod, cons, mode)
            n += 1
        assert not np.array_equal(model(r1, "good", gids=gids), model(r1, "stale", gids=gids)), (prod, cons)
    import struct as _st      # the three new operations against plain arithmetic
    R_, _get, ex_ = _machine(0)
    for e in range(124, 132):
        R_["R6"] = e << 23
        ex_(("rcp2", "R8", "R6"))
        assert _st.unpack("<f", _st.pack("<I", R_["R8"]))[0] == 1.0 / _st.unpack("<f", _st.pack("<I", e << 23))[0], e
    for x, y in ((5, 5), (0xFFFFFFFB, 5), (0x80000000, 0x80000000), (0, 0), (0x7FFFFFFF, 0x7FFFFFFF)):
        R_["R6"] = x
        ex_(("iabs", "R8", "R6"))
        assert R_["R8"] == y, x
    for fa, fb, fc, want in ((3.0, 1.25, -1.75, 2.0), (3.0, 0.0, 1.5, 1.5), (3.0, -0.5, 1.5, 0.0), (3.0, 1.0000001192092896, 1.0, 4.000000476837158)):
        R_["R1"], R_["R2"], R_["R3"] = (_st.unpack("<I", _st.pack("<f", q))[0] for q in (fa, fb, fc))
        ex_(("ffma", "R8", "R1", "R2", "R3"))
        assert _st.unpack("<f", _st.pack("<I", R_["R8"]))[0] == want, (fa, fb, fc, _st.unpack("<f", _st.pack("<I", R_["R8"]))[0])
    pw = normalise({"id": "selftest", "kind": "raw", "producer": "MOV.pow2", "consumer": "MUFU.RCP.r1"})
    pv = [i for i in body_raw(pw, 3, "none") if i.tag == "P"]
    assert len(pv) == 1 and pv[0].text == "MOV R6, R13 ;"
    mu = body_raw(pw, 3, "none")
    ic = next(k for k, i in enumerate(mu) if i.tag == "C")
    assert mu[ic].line() == "[B------:R-:W1:-:S15] MUFU.RCP R8, R6 ;" and mu[ic + 1].line() == "[B-1----:R-:W-:-:S15] IADD3 R10, PT, PT, R10, R8, RZ ;"
    n += 3
    for st, (overs, _c, _t) in WAR_STORES.items():
        for ov in overs:
            r = normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": ov})
            got = {}
            for mode in modes_of(r):
                try:
                    v = model(r, mode, gids=gids)
                except Poison:
                    continue
                assert [int(x) for x in v] == model(r, mode, gids=gids, scalar=True), (st, ov, mode)
                got[mode] = v
                n += 1
            # (behind a load overwriter `overtake` is `late`: a store served after the read-back was served after the overwriter too)
            assert all(not np.array_equal(got["good"], v) for m, v in got.items() if m != "good"), (st, ov)
    for var, form in [(v, f) for f in MMA_FORMS for v in MMA_VARIANTS if not (v in U_HOLD_VARIANTS and not f.startswith("QMMA"))]:
        r = normalise({"id": "selftest", "kind": "mma", "variant": var, "form": form})
        got = {m: model(r, m, gids=gids) for m in modes_of(r)}
        for m, v in got.items():
            assert [int(x) for x in v] == model(r, m, gids=gids, scalar=True), (var, m)
            n += 1
        assert var == "gfalse" or all(not np.array_equal(got["good"], v) for m, v in got.items() if m != "good"), var
        if var.startswith("hold_"):      # the tensor traffic in front writes another accumulator: the checksum may not move
            for fr in ("mmax1@7", "mmax8@1"):
                rf = dict(r, _model_front=fr)
                assert np.array_equal(model(rf, "good", gids=gids), got["good"]), (var, fr)
                assert [int(x) for x in got["good"]] == model(rf, "good", gids=gids, scalar=True), (var, fr)
                n += 1
    for older, younger, far in [(o, y, False) for o, y in ORD_PAIRS] + [("LDS", "LDS", True), ("LDS", "LDS128", True), ("LDS", "LDSM", True)]:
        r = normalise({"id": "selftest", "kind": "ord", "older": older, "younger": younger, "far": far})
        g, st = model(r, "good", gids=gids), model(r, "stale", gids=gids)
        assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and [int(x) for x in st] == model(r, "stale", gids=gids, scalar=True)
        assert not np.array_equal(g, st), (older, younger)
        n += 2
    for older, younger, extra in [("LDS", "LDS64", {"far": "off"}), ("LDS64", "LDS64", {"far": "off"}), ("LDS", "LDS128", {"younger_guard": "true", "far": True}),
                                  ("LDS", "LDS128", {"younger_guard": "false", "far": True}), ("LDSU16", "LDS", {"far": True}), ("LDS64", "LDS", {}),
                                  ("LDS", "LDS64", {"far": "base2"}), ("LDS64", "LDS64", {"far": "base2"}), ("LDSU16", "LDS", {"far": "base2"}),
                                  ("LDS", "LDS128", {"far": "base2"}), ("LDS", "LDS128", {"far": "base2", "younger_guard": "true"}),
                                  ("LDS", "LDS", {"older_guard": "true"}), ("LDS", "LDS", {"older_guard": "true", "far": True}),
                                  ("LDS64", "LDS64", {"older_guard": "true", "far": "base2"}), ("LDS128", "LDS", {"older_guard": "true"})]:
        r = normalise(dict({"id": "selftest", "kind": "ord", "older": older, "younger": younger}, **extra))
        g, st = model(r, "good", gids=gids), model(r, "stale", gids=gids)
        assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and [int(x) for x in st] == model(r, "stale", gids=gids, scalar=True)
        assert not np.array_equal(g, st), (older, younger, extra)
        n += 2
    assert misaligned("    [B------:R-:W-:-:S15] LDS.64 R29, [R9+0x20] ;") and not misaligned("    [B------:R-:W-:-:S15] LDS.64 R28, [R9+0x20] ;")
    for st in SHFL_STORES:      # a shuffle moves data between lanes: lanes 0 / 1 (and 2 / 3) of a warp must not end alike
        r = normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": "IADD3", "read_barrier": "set"})
        w = np.arange(64, dtype=np.int64)
        g, lt = model(r, "good", gids=w), model(r, "late", gids=w)
        assert not np.array_equal(g, lt), st
        if st == "SHFL.IDX.src":      # every lane of a warp ends with lane 1's sum; two warps, two sums
            assert len(set(int(x) for x in g[:32])) == 1 and len(set(int(x) for x in g)) == 2, st
        else:                          # lanes 0 and 1 swap their sums
            assert len(set(int(x) for x in g)) == 64 and int(g[0]) != int(g[1]), st
        assert [int(x) for x in g] == model(r, "good", gids=w, scalar=True) and [int(x) for x in lt] == model(r, "late", gids=w, scalar=True), st
        # every late iteration adds the overwriter's constant once, in every thread
        assert all(int(x) == (REPEAT * LATE_CONST) & 0xFFFFFFFF for x in (lt - g)), st
        n += 2
        # IADD3.it: late iteration i adds (i + 1) constants; the good checksum is the plain one's
        ri = normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": "IADD3.it"})
        gi, li = model(ri, "good", gids=w), model(ri, "late", gids=w)
        assert np.array_equal(gi, g) and all(int(x) == (LATE_CONST * REPEAT * (REPEAT + 1) // 2) & 0xFFFFFFFF for x in (li - gi)), st
        # behind a write-barrier waiter: the same good checksum (the order of two instructions that do not depend on each
        # other changed), and a late shuffle is another checksum
        for ov in ("LOP3", "IADD3"):
            rb_ = normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": ov, "behind": "write_waiter"})
            gb, lb = model(rb_, "good", gids=w), model(rb_, "late", gids=w)
            assert np.array_equal(gb, g) and not np.array_equal(gb, lb), (st, ov)
            assert [int(x) for x in gb] == model(rb_, "good", gids=w, scalar=True) and [int(x) for x in lb] == model(rb_, "late", gids=w, scalar=True), (st, ov)
            n += 2
            # a barrier-less shuffle under a younger shuffle's barrier: the checksum takes BOTH results (another one than
            # the plain shape's), a late older shuffle is another checksum again, and the gap does not enter the model
            ry = normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": ov, "behind": "younger_write", "younger_gap": 4})
            gy, ly = model(ry, "good", gids=w), model(ry, "late", gids=w)
            assert not np.array_equal(gy, g) and not np.array_equal(gy, ly), (st, ov)
            assert [int(x) for x in gy] == model(ry, "good", gids=w, scalar=True) and [int(x) for x in ly] == model(ry, "late", gids=w, scalar=True), (st, ov)
            n += 2
    for st in WAW_STORES:      # version 18 - write after write: `late` = the FIRST writer's value in every iteration
        for ov in WAR_STORES[st][0]:
            r = normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": ov})
            w = np.arange(64, dtype=np.int64)
            g, lt = model(r, "good", gids=w), model(r, "late", gids=w)
            assert modes_of(r) == ["good", "late"] and not np.array_equal(g, lt), (st, ov)
            assert [int(x) for x in g] == model(r, "good", gids=w, scalar=True) and [int(x) for x in lt] == model(r, "late", gids=w, scalar=True), (st, ov)
            if ov == "IADD3" and st != "SHFL.dst":       # every late first write adds the constant once
                assert all(int(x) == (REPEAT * LATE_CONST) & 0xFFFFFFFF for x in (lt - g)), (st, ov)
            if ov == "IADD3.it":                         # late first write of iteration i adds (i + 1) constants
                assert all(int(x) == (LATE_CONST * REPEAT * (REPEAT + 1) // 2) & 0xFFFFFFFF for x in (lt - g)), (st, ov)
            # the controls: ctl differs from bare in ONE control code (the second writer waits barrier 1), rb in ONE
            # instruction (a filler with the same stall in the first writer's place)
            bare, ctl_, rb_ = (body_war(r, 7, "none", v) for v in ("bare", "ctl", "rb"))
            dc = [(a, c) for a, c in zip(bare, ctl_) if a.line() != c.line()]
            dr = [(a, c) for a, c in zip(bare, rb_) if a.line() != c.line()]
            assert len(bare) == len(ctl_) == len(rb_) and len(dc) == 1 and len(dr) == 1, (st, ov)
            assert dc[0][0].tag == "O" and dc[0][0].text == dc[0][1].text and dc[0][0].ctl[1:8] == "B------" and dc[0][1].ctl[1:8] == "B-1----", (st, ov)
            assert dr[0][0].tag == "S" and dr[0][1].sem == ("nop",) and dr[0][0].ctl[-4:] == dr[0][1].ctl[-4:] == "S07]", (st, ov)
            n += 2
    for prod, cons in (("IADD3", "STS.data"), ("IMAD", "IADD3.r1")):      # version 18 - the yield flag sits on the swept instruction only
        ry = normalise({"id": "selftest", "kind": "raw", "producer": prod, "consumer": cons, "yield": "set"})
        rn = normalise({"id": "selftest", "kind": "raw", "producer": prod, "consumer": cons})
        by, bn = body_raw(ry, 3, "none"), body_raw(rn, 3, "none")
        dy = [(a.line(), c.line()) for a, c in zip(by, bn) if a.line() != c.line()]
        assert len(by) == len(bn) and len(dy) == 1 and ":Y:S03]" in dy[0][0] and ":-:S03]" in dy[0][1], (prod, cons, dy)
        assert np.array_equal(model(ry, "good", gids=gids), model(rn, "good", gids=gids))
        n += 1
    for var in ("acc2", "hold_a_mov", "hold_b_mov"):
        ry = normalise({"id": "selftest", "kind": "mma", "variant": var, "yield": "set"})
        rn = normalise({"id": "selftest", "kind": "mma", "variant": var})
        by, bn = body_mma(ry, 2, "none"), body_mma(rn, 2, "none")
        dy = [(a.line(), c.line()) for a, c in zip(by, bn) if a.line() != c.line()]
        assert len(by) == len(bn) and len(dy) == 1 and ":Y:S02]" in dy[0][0] and "QMMA" in dy[0][0], (var, dy)
        n += 1
    for older, younger in ORD_PAIRS:
        r = normalise({"id": "selftest", "kind": "ord", "older": older, "younger": younger, "older_barrier": "same"})
        g, st = model(r, "good", gids=gids), model(r, "stale", gids=gids)
        assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and not np.array_equal(g, st), (older, younger, "same")
        n += 1
    for nl in (2, 3, 4, 5, 8):
        for place in ("near", "base2", "far"):
            for bar in ("last", "all", "none"):
                r = normalise({"id": "selftest", "kind": "ord", "nload": nl, "place": place, "barrier": bar})
                g, st = model(r, "good", gids=gids), model(r, "stale", gids=gids)
                assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and [int(x) for x in st] == model(r, "stale", gids=gids, scalar=True)
                assert not np.array_equal(g, st), (nl, place, bar)
                # one stale register alone must move the checksum too: the weights of the fold are distinct and odd
                n += 2
    w = np.arange(64, dtype=np.int64)      # version 21 - the two further covers of a shuffle's source, the recycle, mixed N loads
    for st in SHFL_STORES:
        plain = model(normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": "IADD3"}), "good", gids=w)
        for bh in ("younger_read", "younger_lds"):
            for ov in ("LOP3", "IADD3", "IADD3.it"):
                r = normalise({"id": "selftest", "kind": "war", "store": st, "overwriter": ov, "behind": bh, "younger_gap": 4})
                g, lt = model(r, "good", gids=w), model(r, "late", gids=w)
                assert modes_of(r) == ["good", "late"] and not np.array_equal(g, lt) and not np.array_equal(g, plain), (st, bh, ov)
                assert [int(x) for x in g] == model(r, "good", gids=w, scalar=True) and [int(x) for x in lt] == model(r, "late", gids=w, scalar=True), (st, bh, ov)
                if ov == "IADD3":       # every late iteration adds the constant once
                    assert all(int(x) == (REPEAT * LATE_CONST) & 0xFFFFFFFF for x in (lt - g)), (st, bh)
                if ov == "IADD3.it":    # late iteration i adds (i + 1) constants
                    assert all(int(x) == (LATE_CONST * REPEAT * (REPEAT + 1) // 2) & 0xFFFFFFFF for x in (lt - g)), (st, bh)
                bare, ctl_, rb_ = (body_war(r, 7, "none", v) for v in ("bare", "ctl", "rb"))
                # ctl = no overwriter (a filler in its place); rb = the tested shuffle carries read barrier 2 and the overwriter waits it
                assert len(bare) == len(ctl_) == len(rb_), (st, bh, ov)
                dc = [(a, c) for a, c in zip(bare, ctl_) if a.line() != c.line()]
                dr = [(a, c) for a, c in zip(bare, rb_) if a.line() != c.line()]
                assert len(dc) == 1 and dc[0][0].tag == "O" and dc[0][1].sem == ("nop",), (st, bh, ov)
                assert len(dr) == 2 and dr[0][0].tag == "S" and ":R2:" in dr[0][1].ctl and dr[1][0].tag == "O" and dr[1][1].ctl[1:8] == "B--2---", (st, bh, ov)
                # the waiter waits the younger producer's barrier only (4 = the younger shuffle's read barrier, 3 = the load's write barrier)
                wt = [a for a in bare if a.sem == ("nop",) and a.ctl[1:8] != "B------"]
                assert len(wt) == 1 and wt[0].ctl[1:8] == ("B----4-" if bh == "younger_read" else "B---3--") and wt[0].ctl[-4:] == "S07]", (st, bh, ov)
                assert bare[[a.tag for a in bare].index("S")].ctl[9:16] == "R-:W1:-", (st, bh)
                n += 2
    for older, younger in (("LDS", "LDS"), ("LDS", "LDS128"), ("LDS64", "LDS64"), ("LDG", "LDG"), ("LDS128", "LDS")):
        r = normalise({"id": "selftest", "kind": "ord", "older": older, "younger": younger, "older_barrier": "recycle", "younger_stall": 1})
        g, st_ = model(r, "good", gids=gids), model(r, "stale", gids=gids)
        assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and [int(x) for x in st_] == model(r, "stale", gids=gids, scalar=True)
        assert not np.array_equal(g, st_), (older, younger, "recycle")
        bare = body_ord(r, 3, "none", "bare")
        yi = next(k for k, a in enumerate(bare) if a.ctl[1:8] == "B-1----" and ":W1:" in a.ctl)      # the younger load: waits 1, sets 1
        assert bare[yi].ctl[-4:] == "S01]" and bare[yi + 1].tag == "C" and bare[yi + 1].ctl[1:8] == "B------" and bare[yi + 2].ctl[1:8] == "B-1-3--", (older, younger)
        assert [a for a in bare if a.tag == "P"][0].ctl[9:14] == "R-:W1" and [a for a in bare if a.tag == "P"][0].ctl[-4:] == "S03]", (older, younger)
        n += 2
    for forms, place, bar in (("s,s,s", "near", "last"), ("s,d,s,gq,s", "near", "last"), ("s,s,s,s,s,s,s,s,s,s,s,s,s", "near", "last"),
                              ("s,s,s,s,s,s,s,s,s,s,s,s,s", "base2", "last"), ("s,d,s,s,d,s,s,s,s,s,d", "near", "last"), ("u,s,d,s,s,s,s,fq", "base2", "last"),
                              ("gs,s,gs,s,s,s,s,s,s,q", "base2", "last"), ("d,d,d,q", "near", "all"), ("s,u,d,q,s", "near", "none"), ("s,s,d,s,s,s,s,s,s,s,s,d", "near", "all")):
        for extra in ({}, {"yield": "set"}):
            r = normalise(dict({"id": "selftest", "kind": "ord", "forms": forms, "place": place, "barrier": bar}, **extra))
            g, st_ = model(r, "good", gids=gids), model(r, "stale", gids=gids)
            assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and [int(x) for x in st_] == model(r, "stale", gids=gids, scalar=True), forms
            assert not np.array_equal(g, st_), forms
            plan = ordn_plan(r)
            regs = [reg + k for _g, let, reg, _o in plan for k in range(ORDN_FORM[let][1])]
            assert len(set(regs)) == len(regs) and not (set(regs) & {6, 8, 12, 13, 9, 10, 11, 15}) and all(16 <= x <= 31 or x in (7, 14) for x in regs), forms
            assert all(reg % ORDN_FORM[let][1] == 0 and off % ORDN_FORM[let][2] == 0 and off + ORDN_FORM[let][2] <= 64 for _g, let, reg, off in plan), forms
            bare = body_ord(r, 4, "none", "bare")
            loads = [a for a in bare if a.tag == "P"]
            assert len(loads) == r["nload"] == len(plan), forms
            # the barrier: the youngest load only (last), every load (all), none; the swept stall on every load but the youngest
            assert [a.ctl[12:14] for a in loads] == {"last": ["W-"] * (len(loads) - 1) + ["W1"], "all": ["W1"] * len(loads), "none": ["W-"] * len(loads)}[bar], forms
            assert all(a.ctl[-4:] == "S04]" for a in loads[:-1]) and loads[-1].ctl[-4:] == "S02]", forms
            assert all((":Y:S" in a.ctl) == bool(extra) for a in loads), forms
            # every destination register is read by exactly one snapshot word, the first of which carries the wait
            snaps = [a for a in bare if a.tag == "C"]
            read = [x for a in snaps for x in a.sem[2:] if x in [f"R{q}" for q in regs]]
            assert sorted(read) == sorted(f"R{q}" for q in regs) and snaps[0].ctl[1:8] == ("B------" if bar == "none" else "B-1----"), forms
            assert all(a.ctl[1:8] == "B------" and a.ctl[-4:] == "S01]" for a in snaps[1:]), forms
            assert misaligned("\n".join("    " + a.line() for a in bare)) == [], forms
            # one stale register alone moves the checksum: (checked on the model) the loads' values differ from the markers
            n += 2
    # version 23 - sets of producers on one write barrier
    for forms in ("gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gG", "gQ,gB,gQ,gB,gQ,gB,gQ,gB,gB", "gQ,gQ,gB", "c,C", "m,s,s,s,s", "m,h",
                  "gQ,gG", "gQ,gB", "Q,Q,Q", "c,C,c", "c,Q", "G,Q,B,c,C,m,h,s,d,gq,u"):
        for bar in ("all", "none", "last"):
            for extra in ({}, {"yield": "set"}):
                r = normalise(dict({"id": "selftest", "kind": "ord", "forms": forms, "barrier": bar}, **extra))
                assert is_set(r) and not ordn_no_gaddr(r) and r["occupancy"] == ["w8", "w16"], forms
                g, st_ = model(r, "good", gids=gids), model(r, "stale", gids=gids)
                assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and [int(x) for x in st_] == model(r, "stale", gids=gids, scalar=True), forms
                assert (g != st_).all() and (g != 0).all(), forms
                plan = set_plan(r)
                regs = [reg + k for _g, let, reg, _a in plan for k in range(set_nreg(let))]
                assert len(set(regs)) == len(regs) and all(32 <= x <= 72 for x in regs) and all(reg % set_nreg(let) == 0 for _g, let, reg, _a in plan), forms
                for v in ("bare", "ctl"):
                    body = body_ord(r, 4, "none", v)
                    prods = [a for a in body if a.tag == "P"]
                    assert len(prods) == r["nload"] == len(plan), forms
                    if v == "bare":
                        assert [a.ctl[12:14] for a in prods] == {"last": ["W-"] * (len(prods) - 1) + ["W1"], "all": ["W1"] * len(prods), "none": ["W-"] * len(prods)}[bar], forms
                        assert all(a.ctl[-4:] == "S04]" for a in prods[:-1]) and prods[-1].ctl[-4:] == "S02]" and all(a.ctl[1:8] == "B------" for a in prods), forms
                    else:
                        assert all(a.ctl[12:14] == "W0" and a.ctl[-4:] == "S01]" for a in prods), forms
                        assert all(body[k + 1].ctl[1:8] == "B0-----" for k, a in enumerate(body) if a.tag == "P"), forms
                    assert all((":Y:S" in a.ctl) == bool(extra) for a in prods), forms
                    # every destination register is read by exactly one reader word; the first carries the wait; the first
                    # len(plan) registers read are one of every producer, the youngest producer first
                    snaps = [a for a in body if a.tag == "C"]
                    read = [x for a in snaps for x in (a.sem[3:] if a.sem[0] == "rsub" else a.sem[2:]) if x in [f"R{q}" for q in regs]]
                    assert sorted(read) == sorted(f"R{q}" for q in regs), forms
                    assert read[:len(plan)] == [f"R{reg}" for _g, _l, reg, _a in reversed(plan)], forms
                    assert snaps[0].ctl[1:8] == ("B0-----" if v == "ctl" else "B------" if bar == "none" else "B-1----"), forms
                    assert all(a.ctl[1:8] == "B------" and a.ctl[-4:] == "S01]" for a in snaps[1:]), forms
                    # nothing writes R9, R20..R23, the address registers or a reference inside the loop
                    wr = set()
                    for a in body:
                        m_ = re.match(r"(?:@P0 )?\S+ (?:PT, )?R(\d+)", a.text)
                        if m_ and not a.text.startswith(("STS", "STG")):
                            wr.add(int(m_.group(1)))
                    assert not (wr & {1, 2, 3, 9, 16, 17, 18, 19, 20, 21, 22, 23, SET_MSRC, SET_MREF, SET_ABASE, SET_ABASE + 1}), (forms, sorted(wr))
                    text = kernel_text("selftest_x", dict(r, _threads=256), 188, body, 65536)
                    assert misaligned(text) == [] and "    .reg R0-R79\n    .regcount 88\n" in text, forms
                    assert max(int(x) for x in re.findall(r"(?<![UA-Za-z])R(\d+)", text.split(".shared")[1])) <= SET_REGS - 1, forms
                n += 2
    for bad in ({"forms": "Q,Q", "occupancy": ["w32"]}, {"forms": "Q,Q", "occupancy": ["c4w8"]}, {"forms": "Q,Q", "place": "base2"}, {"forms": "gc,Q"},
                {"forms": "Q,Q,Q,Q,Q,Q,Q,Q,Q,Q,Q"}, {"forms": "m,C"}, {"forms": "Q,Q", "front": ["stgx4@4"]}):
        try:
            rb = normalise(dict({"id": "selftest", "kind": "ord", "barrier": "all"}, **bad))
            body_ord(rb, 4, "none", "bare")
            raise AssertionError(f"a set request that must be refused was taken: {bad}")
        except SystemExit:
            pass
    for forms in ("gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gG", "gQ,gB,gQ,gB,gQ,gB,gQ,gB,gB", "Q,Q,Q", "gB,G"):      # (third build) the cold variant
        for bar in ("all", "none"):
            r = normalise({"id": "selftest", "kind": "ord", "forms": forms, "barrier": bar, "cold": "set", "yield": "set", "occupancy": ["w16", "c2w9s"]})
            g, st_ = model(r, "good", gids=gids), model(r, "stale", gids=gids)
            assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and [int(x) for x in st_] == model(r, "stale", gids=gids, scalar=True), forms
            assert (g != st_).all() and (g != 0).all(), forms
            warm = normalise({"id": "selftest", "kind": "ord", "forms": forms, "barrier": bar, "yield": "set"})
            for v in ("bare", "ctl"):
                body, wbody = body_ord(r, 4, "none", v), body_ord(warm, 4, "none", v)
                prods, wprods = [a for a in body if a.tag == "P"], [a for a in wbody if a.tag == "P"]
                # the cold body = the warm body + three address words in front of the loads + the salt; the loads differ in their address only
                assert len(body) == len(wbody) + 4 and [a.ctl for a in prods] == [a.ctl for a in wprods] and [a.dst for a in prods] == [a.dst for a in wprods], forms
                assert all(a.text.split(", desc[")[0] == w.text.split(", desc[")[0] and f"desc[UR4][R{SET_CBASE}.64" in a.text for a, w in zip(prods, wprods)), forms
                offs = [int(a.text.split(".64+")[1].split("]")[0], 16) if ".64+" in a.text else 0 for a in prods]
                assert all(o + (16 if ".128" in a.text else 4 if "LDG.E R" in a.text else 1) <= 2048 for o, a in zip(offs, prods)) and len({o // 64 for o in offs}) == len(offs), (forms, offs)
                assert all(o % 16 == 0 for o, a in zip(offs, prods) if ".128" in a.text) and all(o % 4 == 0 for o, a in zip(offs, prods) if "LDG.E R" in a.text), forms
                wr = [a.text for a in body if re.match(rf"(?:@P0 )?\S+ (?:PT, )?R({SET_ABASE}|{SET_ABASE + 1}|{SET_CBASE}|{SET_CBASE + 1}),", a.text)]
                assert wr == [f"IADD3 R{SET_CBASE}, PT, PT, R13, R{SET_ABASE}, RZ ;"], (forms, wr)
                i0 = next(k for k, a in enumerate(body) if a.text.startswith(f"IADD3 R{SET_CBASE},"))
                assert [a.text for a in body[i0 - 2:i0]] == ["LOP3.LUT R13, R5, 0xff, RZ, 0xc0, !PT ;", "SHF.L.U32 R13, R13, 0xc, RZ ;"] and i0 < body.index(prods[0]), forms
                assert body[-1].text == "IADD3 R10, PT, PT, R10, R4, RZ ;", forms
                for thr in (32, 512):
                    text = kernel_text("selftest_x", dict(r, _threads=thr), 188, body, 65536)
                    assert misaligned(text) == [] and f"MOV R13, 0x{4 * thr:x} ;" in text and f"IMAD.WIDE.U32 R{SET_ABASE}, R13, 0x1, R2 ;" in text and f"MOV R{SET_CBASE + 1}, R{SET_ABASE + 1} ;" in text, forms
                    assert "0xffffffe0" not in text and max(int(x) for x in re.findall(r"(?<![UA-Za-z])R(\d+)", text.split(".shared")[1])) <= SET_REGS - 1, forms
            n += 2
    for bad in ({"forms": "Q,s", "cold": "set"}, {"forms": "Q,Q", "cold": "set", "occupancy": ["g8"]}, {"forms": "c,Q", "cold": "set"}, {"forms": "Q,Q", "cold": "yes"},
                {"forms": "B,B,B,B,B,B,B,B,B", "cold": "set"}):
        try:
            normalise(dict({"id": "selftest", "kind": "ord", "barrier": "all"}, **bad))
            raise AssertionError(f"a cold set that must be refused was taken: {bad}")
        except SystemExit:
            pass
    for bar in ("all", "none", "last"):      # (second build) the tensor set M,s,s
        for extra in ({}, {"yield": "set"}):
            r = normalise(dict({"id": "selftest", "kind": "ord", "forms": "M,s,s", "barrier": bar}, **extra))
            g, st_ = model(r, "good", gids=gids), model(r, "stale", gids=gids)
            assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and [int(x) for x in st_] == model(r, "stale", gids=gids, scalar=True), bar
            assert (g != st_).all() and (g != 0).all() and set_plan(r) == [("", "M", 32, None), ("", "s", 36, 0), ("", "s", 37, 4)], bar
            for v in ("bare", "ctl"):
                body = body_ord(r, 4, "none", v)
                prods = [a for a in body if a.tag == "P"]
                assert [a.text for a in prods] == ["LDSM.16.M88.4 R32, [R9+0x30] ;", "LDS R36, [R9+0x20] ;", "LDS R37, [R9+0x24] ;"], bar
                if v == "bare":
                    assert [a.ctl[12:14] for a in prods] == {"last": ["W-", "W-", "W1"], "all": ["W1"] * 3, "none": ["W-"] * 3}[bar], bar
                    assert [a.ctl[-4:] for a in prods] == ["S04]", "S04]", "S02]"], bar
                rd = [a for a in body if a.tag == "C"]
                assert len(rd) == 1 and rd[0].text == "HMMA.16816.F32.BF16 R28, R32, R36, R28 ;", bar
                assert rd[0].ctl[1:8] == ("B0-----" if v == "ctl" else "B------" if bar == "none" else "B-1----") and body[body.index(rd[0]) - 1].tag == ("P" if v == "bare" else None), bar
                assert all((":Y:S" in a.ctl) == bool(extra) for a in prods), bar
                text = kernel_text("selftest_x", dict(r, _threads=256), 188, body, 65536)
                assert misaligned(text) == [] and "    .reg R0-R79\n    .regcount 88\n" in text and text.count("STS.128 [R9+0x30], R28 ;") == 1, bar
            n += 2
    for bad in ({"forms": "M,s"}, {"forms": "s,M,s"}, {"forms": "gM,s,s"}, {"forms": "M,s,s,s"}, {"forms": "M,gs,s"}):
        try:
            normalise(dict({"id": "selftest", "kind": "ord", "barrier": "all"}, **bad))
            raise AssertionError(f"a tensor set that must be refused was taken: {bad}")
        except SystemExit:
            pass
    for var in ("hold_a_lds", "hold_a_ldsm", "hold_b_lds", "hold_bl_lds", "hold_b_ldsm", "sens_a_lds", "sens_a_ldsm", "sens_b_lds", "sens_bl_lds", "sens_b_ldsm"):
        for form in ("HMMA.BF16", "HMMA.F16", "QMMA.SF.E4M3.E2M1"):      # (second build) a LOAD as the overwriter of an MMA's fragment register
            r = normalise({"id": "selftest", "kind": "mma", "form": form, "variant": var})
            g, dr = model(r, "good", gids=gids), model(r, "drop1", gids=gids)
            assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and [int(x) for x in dr] == model(r, "drop1", gids=gids, scalar=True), (var, form)
            assert (g != dr).all() and modes_of(r) == ["good", "drop1"], (var, form)
            # the model's result does not depend on the overwriter: the same checksums as the MOV variant of the same register
            twin = normalise({"id": "selftest", "kind": "mma", "form": form, "variant": var.rsplit("_", 1)[0] + "_mov"}) if not var.endswith("b_ldsm") and not var.endswith("a_ldsm") else None
            if twin is not None and var.startswith("hold_"):
                assert np.array_equal(g, model(twin, "good", gids=gids)), (var, form)
            body = body_mma(r, 3, "none")
            ld = [k for k, a in enumerate(body) if a.text.startswith(("LDS ", "LDSM"))]
            pm = next(k for k, a in enumerate(body) if a.tag == "P")
            assert len(ld) == 1 and body[ld[0]].ctl[9:14] == "R-:W1" and body[ld[0] + 1].ctl[1:8] == "B-1----" and body[ld[0] + 1].sem == ("nop",), (var, form)
            want = {"a_lds": "LDS R17, [R9+0x20] ;", "a_ldsm": "LDSM.16.M88.4 R16, [R9+0x30] ;", "b_lds": "LDS R13, [R9+0x20] ;", "bl_lds": "LDS R12, [R9+0x20] ;",
                    "b_ldsm": "LDSM.16.M88.4 R12, [R9+0x30] ;"}[var.split("_", 1)[1]]
            assert body[ld[0]].text == want, (var, form, body[ld[0]].text)
            if var.startswith("hold_"):      # the swept distance = the stalls from the MMA to the load
                assert ld[0] > pm and sum(int(a.ctl[-3:-1]) for a in body[pm:ld[0]]) == 3 and body[pm].ctl[-4:] == "S03]", (var, form)
            else:                            # the control: the load, its wait and 45 cycles in front of the MMA
                assert ld[0] < pm and sum(int(a.ctl[-3:-1]) for a in body[ld[0] + 1:pm]) >= 45, (var, form)
            if var.endswith("b_ldsm"):
                assert [a.text for a in body[:3]] == [f"MOV R12, 0x{MMA_SPEC[form]['b1']:x} ;", f"MOV R13, 0x{MMA_SPEC[form]['b1']:x} ;", "MOV R14, 0x7f7f7f7f ;"], (var, form)
            assert misaligned(kernel_text("selftest_x", r, 188, body, 65536)) == [], (var, form)
            n += 2
    assert not is_set(normalise({"id": "xx", "kind": "ord", "forms": "s,d,gq,u"})) and ".regcount 40" in kernel_text("x", normalise({"id": "xx", "kind": "ord", "forms": "s,d,gq,u"}), 188, [], 65536)
    assert ordn_no_gaddr(normalise({"id": "xx", "kind": "ord", "forms": "s,s,s,s,s,s,s,s,s"})) and not ordn_no_gaddr(normalise({"id": "xx", "kind": "ord", "forms": "s,s,s,s,d,d"}))
    assert not any("R16" in a.text or "R18" in a.text for a in prologue(normalise({"id": "xx", "kind": "ord", "forms": "s,s,s,s,s,s,s,s,s"}), 188))
    for nl in (2, 8):      # (C) the yield flag on the loads of the plain N-load family: one flag per load, nothing else moves
        ry, rn = (normalise(dict({"id": "selftest", "kind": "ord", "nload": nl, "barrier": "all"}, **x)) for x in ({"yield": "set"}, {}))
        by, bn = body_ord(ry, 4, "none", "bare"), body_ord(rn, 4, "none", "bare")
        dy = [(a.line(), c.line()) for a, c in zip(by, bn) if a.line() != c.line()]
        assert len(by) == len(bn) and len(dy) == nl and all(":Y:S" in a and ":-:S" in c and a.replace(":Y:S", ":-:S") == c for a, c in dy), nl
        assert np.array_equal(model(ry, "good", gids=gids), model(rn, "good", gids=gids))
        n += 1
    w = np.arange(64, dtype=np.int64)      # version 20 - kind reuse
    for form in REUSE_FORMS:
        for writer in REUSE_WRITERS:
            for btw in REUSE_BETWEEN:
                if (writer == "lds" and btw in ("wait_r", "wait_x")) or (writer == "none" and btw == "branch_f"):
                    continue
                for extra in ({"words": 1}, {"words": 3, "fill": "other", "chain": True, "fstall": 2}, {"words": 5, "window_yield": "none"}):
                    r = normalise(dict({"id": "selftest", "kind": "reuse", "flagged": form, "writer": writer, "between": btw}, **extra))
                    g = model(r, "good", gids=w)
                    assert [int(x) for x in g] == model(r, "good", gids=w, scalar=True), (form, writer, btw, extra)
                    n += 1
                    if writer == "none":
                        assert modes_of(r) == ["good"] and reuse_late_delta(r) is None, (form, writer)
                    else:
                        st = model(r, "stale", gids=w)
                        assert [int(x) for x in st] == model(r, "stale", gids=w, scalar=True) and (g != st).all(), (form, writer, btw, extra)
                        n += 1
                        rc = REUSE_FORMS[r["reader"]][3]      # every stale iteration moves the checksum by the reader's coefficient x the constant
                        assert rc is not None and all(int(x) == (-REPEAT * rc * LATE_CONST) & 0xFFFFFFFF for x in (st - g)), (form, writer, btw)
                        assert reuse_late_delta(r) == (-rc * LATE_CONST) & 0xFFFFFFFF and reuse_late_delta(r) % 2 == 1
                    for dd in (r["distance_list"][0], r["distance_list"][-1]):
                        bare, ctl_ = body_reuse(r, dd, "none", "bare"), body_reuse(r, dd, "none", "ctl")
                        # the control differs from the tested kernel in the flags and in nothing else
                        assert len(bare) == len(ctl_) and all(a.ctl == c.ctl and a.sem == c.sem and a.tag == c.tag for a, c in zip(bare, ctl_)), (form, writer, btw)
                        diff = [(a.text, c.text) for a, c in zip(bare, ctl_) if a.text != c.text]
                        assert len(diff) == (2 if r["chain"] else 1) and all(a.replace(".reuse", "") == c for a, c in diff), (form, writer, btw, diff)
                        assert not any(".reuse" in c.text for c in ctl_) and sum(a.text.count(".reuse") for a in bare) == len(diff), (form, writer, btw)
                        # the swept distance = the stalls from the swept word to the reader (a skipped word and a label do not count)
                        run = [a for a in bare if a.tag not in ("X", "L")]
                        i0 = next(k for k, a in enumerate(run) if a.tag == ("F" if writer == "none" else "P"))
                        i1 = next(k for k, a in enumerate(run) if a.tag == "C")
                        assert sum(int(a.ctl[-3:-1]) for a in run[i0:i1]) == dd, (form, writer, btw, dd)
                        # the vendor's window: the yield flag on every word from the flagged one to the word in front of the reader
                        if r["window_yield"] == "set" and writer != "selff":
                            j0 = next(k for k, a in enumerate(run) if a.tag == "F")
                            assert all(":Y:S" in a.ctl for a in run[j0:i1]), (form, writer, btw)
    # version 24: tensor consumers and relative consumers
    def dist24(b):
        i0 = next(k for k, a in enumerate(b) if a.tag == "P")
        i1 = next(k for k, a in enumerate(b) if a.tag == "C")
        return sum(int(a.ctl[-3:-1]) for a in b[i0:i1])
    n24 = 0
    for cons in [c for c in RAW_CONSUMERS if RAW_CONSUMERS[c][0] in T24_WHAT]:
        kind = t24_kind(cons)
        for prod in T24_PRODUCERS[kind]:
            for reg_ in ((1, 2, 3) if RAW_CONSUMERS[cons][3] in ("r3h", "r1h") else (None,)):
                for res in ((None, 1) if (kind == "rel" and prod != "CS2R.32.CgaSize" and cons != "IADD.64.rel") else (None,)):
                    if cons == "IADD.64.rel" and prod == "CS2R.32.CgaSize":
                        continue
                    q0 = {"id": "selftest", "kind": "raw", "producer": prod, "consumer": cons}
                    if reg_:
                        q0["reg"] = reg_
                    if res:
                        q0["result"] = res
                    r, rc = normalise(q0), normalise(dict(q0, control="stale"))
                    g = model(r, "good", gids=gids)
                    assert [int(x) for x in g] == model(r, "good", gids=gids, scalar=True) and (g != 0).all(), (prod, cons, reg_, res)
                    assert np.array_equal(g, model(rc, "good", gids=gids)), (prod, cons, "the control's model is the request's")
                    n += 1
                    n24 += 1
                    if kind == "acc":
                        assert modes_of(r) == ["good", "stale"]
                        st = model(r, "stale", gids=gids)
                        assert [int(x) for x in st] == model(r, "stale", gids=gids, scalar=True) and (g != st).all(), (prod, cons, reg_)
                        assert np.array_equal(st, model(rc, "stale", gids=gids)), (prod, cons, reg_)
                        n += 1
                    elif kind in ("a", "b"):
                        for sc in (False, True):
                            try:
                                model(r, "stale", gids=gids, scalar=sc)
                            except Poison:
                                continue
                            raise AssertionError((prod, cons, reg_, "a stale fragment register must give no hypothesis"))
                    else:
                        assert modes_of(r) == ["good"], (prod, cons)
                        # the checksum of `good` is the sum of the salts: the iteration's first input, 256 times
                        a0 = (SEED + gids) & 0xFFFFFFFF
                        assert [int(x) for x in g] == [int((REPEAT * int(a) + 0x9e3779b9 * (REPEAT * (REPEAT - 1) // 2)) & 0xFFFFFFFF) for a in a0], (prod, cons)
                    for dd in (1, 2, 7, 11, 16, 45):
                        b, bc = body_raw(r, dd, "none"), body_raw(rc, dd, "none")
                        assert dist24(b) == dd and dist24(bc) == dd, (prod, cons, dd)
                        # the control: the same words, the producer's text moved behind the consumer (and, absolute, behind the checksum)
                        pt = next(a for a in b if a.tag == "P")
                        assert [a.sem for a in b] == [a.sem for a in bc if a.text != pt.text or a.sem != ("nop",)], (prod, cons, dd)
                        assert next(a for a in bc if a.tag == "P").text == "IADD3 R15, PT, PT, R15, 0x1, RZ ;" and sum(a.text == pt.text for a in bc) == 1
                        k_c, k_p = next(k for k, a in enumerate(bc) if a.tag == "C"), next(k for k, a in enumerate(bc) if a.text == pt.text)
                        assert k_p > k_c and bc[k_p].sem == ("nop",), (prod, cons, dd)
                        assert not misaligned(kernel_text("x", r, 188, b)) and not misaligned(kernel_text("x", rc, 188, bc))
                    if kind in ("acc", "a", "b"):      # tensor traffic in front: the same model, the tested distance unchanged
                        rf = normalise(dict(q0, front=["mmax2@4"]))
                        bf = body_raw(rf, 5, "mmax2@4")
                        assert dist24(bf) == 5 and sum(a.tag == "F" for a in bf) == 2 and all(a.sem == ("nop",) for a in bf if a.tag == "F")
                        assert ".reg R0-R31" in kernel_text("x", rf, 188, bf)
    for bad in ({"producer": "LOP3", "consumer": "QMMA.r1"}, {"producer": "MOV", "consumer": "QMMA.r2"}, {"producer": "CS2R", "consumer": "QMMA.r3", "reg": 1},
                {"producer": "CS2R", "consumer": "QMMA.r3h", "reg": 4}, {"producer": "CS2R", "consumer": "QMMA.r3h", "reg": 1, "result": 0},
                {"producer": "UMOV", "consumer": "QMMA.u6", "front": ["mmax1@7"]}, {"producer": "CS2R.32.CgaSize", "consumer": "IMADi.rel", "result": 1},
                {"producer": "CS2R.32.CgaSize", "consumer": "IADD.64.rel"}, {"producer": "MOV", "consumer": "QMMA.r1", "yield": "set"},
                {"producer": "MOV", "consumer": "QMMA.r1", "control": "yes"}, {"producer": "IADD3", "consumer": "IMAD.rel"}):
        try:
            normalise(dict({"id": "selftest", "kind": "raw"}, **bad))
        except SystemExit:
            continue
        raise AssertionError(("version 24 must refuse", bad))
    assert normalise({"id": "xx", "kind": "raw", "producer": "MOV", "consumer": "QMMA.r1", "yield": "set", "distances": "1-8,11"})["distance_list"][-1] == 11
    assert normalise({"id": "xx", "kind": "raw", "producer": "CS2R", "consumer": "QMMA.r3h", "reg": 3})["result"] == 1 and normalise({"id": "xx", "kind": "raw", "producer": "CS2R", "consumer": "QMMA.r3h", "reg": 2})["result"] == 0
    assert n24 >= 30, n24
    # second build: the price of a tensor operand is the table's mma_input; the u6 body's scale register
    if os.path.isfile(DEF_DEP):
        tc = table_cell(DEF_DEP, {"producer": "MOV", "consumer": "QMMA", "role": "r1h"})
        assert tc["L"] == json.load(open(DEF_DEP))["defaults"]["mma_input"] and "mma_input" in tc["source"], tc
        assert table_cell(DEF_DEP, {"producer": "UMOV", "consumer": "QMMA", "role": "u6"})["L"] == tc["L"] and table_cell(DEF_DEP, {"producer": "FMUL", "consumer": "HMMA", "role": "r3"})["L"] == tc["L"]
        assert table_cell(DEF_DEP, {"producer": "IABS", "consumer": "ISETP", "role": "r0"})["source"] == "default (no dense cell)"
    bu = body_raw(normalise({"id": "xx", "kind": "raw", "producer": "UMOV", "consumer": "QMMA.u6"}), 4, "none")
    assert [a.text for a in bu if "R14" in a.text and "QMMA" not in a.text] == ["LOP3.LUT R14, R1, 0x3, RZ, 0xc0, !PT ;", "IMAD R14, R14, 0x1010101, RZ ;", "IADD3 R14, PT, PT, R14, 0x7d7e807f, RZ ;"]
    assert all(((0x7d7e807f + m * 0x01010101) >> (8 * k)) & 0xFF == (0x7f, 0x80, 0x7e, 0x7d)[k] + m for m in range(4) for k in range(4))
    # third build: a tensor word that takes the dirty content in EVERY iteration must change the checksum in every thread - for every
    # absolute tensor class (the first two builds failed this for the A classes: the deviations of even and odd iterations cancelled)
    for cons, prod in (("QMMA.r1", "MOV"), ("QMMA.r1h", "MOV"), ("QMMA.r2", "LOP3"), ("QMMA.r2h", "LOP3"), ("QMMA.r3", "CS2R"), ("QMMA.r3h", "MOV"), ("HMMA.r3", "FMUL")):
        r = normalise({"id": "xx", "kind": "raw", "producer": prod, "consumer": cons})
        g = model(r, "good", gids=gids)
        if t24_kind(cons) == "a":      # the whole A fragment dirty (one dirty register has no model): every A register takes R7
            b = body_raw(r, 15, "none")
            for a in b:
                if a.sem[0] == "mov" and a.sem[1] in ("R16", "R17", "R18", "R19"):
                    a.sem = ("mov", a.sem[1], "R7")
            st = [_scalar(int(x), prologue(r, 188), b, "good") for x in gids]
        elif t24_kind(cons) == "b":    # the whole B pair dirty: both registers keep the 2.0 code
            b = body_raw(r, 15, "none")
            sp_ = MMA_SPEC[r["form"]]
            b = [Ins(f"MOV R12, 0x{sp_['b2']:x} ;", ("mov", "R12", sp_["b2"])), Ins(f"MOV R13, 0x{sp_['b2']:x} ;", ("mov", "R13", sp_["b2"]))] + [a for a in b if a.tag != "P" and not (a.sem[0] == "mov" and a.sem[1] in ("R12", "R13"))]
            st = [_scalar(int(x), prologue(r, 188), b, "good") for x in gids]
        else:
            st = [int(x) for x in model(r, "stale", gids=gids)]
        assert all(int(x) != y for x, y in zip(g, st)), (cons, prod, "a consumer that is stale in every iteration gives the checksum of `good`")
    ba = body_raw(normalise({"id": "xx", "kind": "raw", "producer": "MOV", "consumer": "QMMA.r1h", "reg": 2}), 3, "none")
    assert [a.text for a in ba[:6]] == ["MOV R6, 0x38383838 ;", "MOV R7, 0x40404040 ;", "MOV R16, R6 ;", "MOV R17, R6 ;", "MOV R18, R7 ;", "MOV R19, R6 ;"]
    # fourth build: the hold of EVERY register of the A quad (kind mma, hold_a_mov / sens_a_mov with "reg")
    for form in ("QMMA.SF.E4M3.E2M1", "HMMA.BF16"):
        b1 = body_mma(normalise({"id": "xx", "kind": "mma", "form": form, "variant": "hold_a_mov"}), 3)
        for reg_ in (0, 1, 2, 3):
            r = normalise({"id": "xx", "kind": "mma", "form": form, "variant": "hold_a_mov", "reg": reg_})
            b = body_mma(r, 3)
            o = [a for a in b if a.tag == "O"]
            assert len(o) == 1 and o[0].text == f"MOV R{16 + reg_}, R6 ;" and o[0].sem == ("mov", f"R{16 + reg_}", "R6"), (form, reg_)
            assert [a.line() for a in b if a.tag != "O"] == [a.line() for a in b1 if a.tag != "O"] and (reg_ != 1 or [a.line() for a in b] == [a.line() for a in b1])
            for mode in modes_of(r):
                v = model(r, mode, gids=gids)
                assert [int(x) for x in v] == model(r, mode, gids=gids, scalar=True), (form, reg_, mode)
                n += 1
            s_ = body_mma(normalise({"id": "xx", "kind": "mma", "form": form, "variant": "sens_a_mov", "reg": reg_}), 45)
            assert sum(a.text == f"MOV R{16 + reg_}, R6 ;" and a.sem == ("nop",) for a in s_) == 1, (form, reg_)
    for bad in ({"variant": "hold_b_mov", "reg": 1}, {"variant": "hold_a_mov", "reg": 4}, {"variant": "hold_a_lds", "reg": 0}):
        try:
            normalise(dict({"id": "xx", "kind": "mma"}, **bad))
        except SystemExit:
            continue
        raise AssertionError(("the fourth build must refuse", bad))
    # fifth build: the hold of each ACCUMULATOR register behind a word whose result goes to another quad
    for form in ("QMMA.SF.E4M3.E2M1", "HMMA.BF16"):
        for reg_ in (0, 1, 2, 3):
            r = normalise({"id": "xx", "kind": "mma", "form": form, "variant": "hold_c_mov", "reg": reg_})
            b = body_mma(r, 3)
            w, o = [a for a in b if a.tag == "P"], [a for a in b if a.tag == "O"]
            assert len(w) == 1 and w[0].text.split()[1:5] == ["R24,", "R16,", "R12,", "R28" + ("," if form.startswith("QMMA") else "")] and w[0].sem[5] == "R28", (form, reg_)
            assert len(o) == 1 and o[0].text == f"MOV R{28 + reg_}, R6 ;" and b.index(o[0]) > b.index(w[0]) and not misaligned(kernel_text("x", r, 188, b))
            assert sum(int(a.ctl[-3:-1]) for a in b[b.index(w[0]):b.index(o[0])]) == 3
            for mode in modes_of(r):
                v = model(r, mode, gids=gids)
                assert [int(x) for x in v] == model(r, mode, gids=gids, scalar=True), (form, reg_, mode)
                n += 1
            g = model(r, "good", gids=gids)
            assert (g != model(r, "drop1", gids=gids)).all()
            # the word taking the REWRITTEN accumulator register gives another checksum in every thread (what the control must show)
            bs = body_mma(normalise({"id": "xx", "kind": "mma", "form": form, "variant": "sens_c_mov", "reg": reg_}), 45)
            k_m, k_w = next(k for k, a in enumerate(bs) if a.text == f"MOV R{28 + reg_}, R6 ;"), next(k for k, a in enumerate(bs) if a.tag == "P")
            assert k_m < k_w and bs[k_m].sem == ("nop",)
            bs[k_m].sem = ("mov", f"R{28 + reg_}", 0)      # (the model has no float of the code word: a ZERO accumulator stands for "another content")
            assert all(_scalar(int(x), prologue(r, 188), bs, "good") != int(y) for x, y in zip(gids, g)), (form, reg_)
    for bad in ({"variant": "hold_c_mov", "reg": 4}, {"variant": "hold_c_mov", "reg": 0, "front": ["mmax1@7"]}):
        try:
            normalise(dict({"id": "xx", "kind": "mma"}, **bad))
        except SystemExit:
            continue
        raise AssertionError(("the fifth build must refuse", bad))
    # ---- version 25
    assert n25 >= 300, n25
    R_, _get, ex_ = _machine(0)      # add64 against plain arithmetic
    for a_, b_ in ((0xFFFFFFFF_FFFFFFFF, 1), (0x00000001_FFFFFFFF, 0x00000002_00000001), (0x12345678_9ABCDEF0, 0x0FEDCBA9_87654321), (0, 0)):
        R_["R6"], R_["R7"], R_["R4"], R_["R5"] = a_ & 0xFFFFFFFF, a_ >> 32, b_ & 0xFFFFFFFF, b_ >> 32
        ex_(("add64", "R24", "R6", "R4"))
        assert (R_["R25"] << 32) | R_["R24"] == (a_ + b_) & 0xFFFFFFFFFFFFFFFF, (a_, b_)
    # the words of the new consumers, the tested register and the pair's other word
    for cons, prod, cw, pw, other in (("IADD.64rr.r1", "MOV", "IADD.64 R24, R6, R4 ;", "MOV R6, R4 ;", "MOV R7, R5 ;"), ("IADD.64rr.r1h", "MOV", "IADD.64 R24, R6, R4 ;", "MOV R7, R4 ;", "MOV R6, R5 ;"),
                                      ("IADD.64rr.r2", "MOV", "IADD.64 R24, R4, R6 ;", "MOV R6, R4 ;", "MOV R7, R5 ;"), ("IADD.64rr.r2h", "MOV", "IADD.64 R24, R4, R6 ;", "MOV R7, R4 ;", "MOV R6, R5 ;"),
                                      ("IADD.64rr.r1", "IMAD.WIDE", "IADD.64 R24, R6, R4 ;", "IMAD.WIDE.U32 R6, R4, R5, RZ ;", None),
                                      ("IADD.64rr.r1h", "IMAD.WIDE", "IADD.64 R24, R6, R4 ;", "IMAD.WIDE.U32 R6, R4, R5, RZ ;", None),
                                      ("PRMT.r3", "SEL", "PRMT R8, R5, 0x7632, R6 ;", "SEL R6, R4, R5, !P2 ;", None)):
        bb = body_raw(normalise({"id": "xx", "kind": "raw", "producer": prod, "consumer": cons}), 5, "none")
        assert next(a.text for a in bb if a.tag == "C") == cw and next(a.text for a in bb if a.tag == "P") == pw, (cons, prod)
        assert (other is None and not any(a.text in ("MOV R7, R5 ;", "MOV R6, R5 ;") for a in bb)) or sum(a.text == other for a in bb) == 1, (cons, prod)
        assert next(a.dst for a in bb if a.tag == "P") == (("R6", "R7") if prod == "IMAD.WIDE" else (pw.split()[1].rstrip(","),)), (cons, prod)
        assert sum(int(a.ctl[-3:-1]) for a in bb[next(k for k, a in enumerate(bb) if a.tag == "P"):next(k for k, a in enumerate(bb) if a.tag == "C")]) == 5
    # STG.a0: every address the kernel can form is word A or word B of the thread; a stale low register stores to word B
    for ctl_ in (None, "stale"):
        rg = normalise(dict({"id": "xx", "kind": "raw", "producer": "IADD.64", "consumer": "STG.a0"}, **({"control": ctl_} if ctl_ else {})))
        bg = body_raw(rg, 4, "sts128x15@4")
        assert [a.text for a in bg[:2]] == ["MOV R6, R18 ;", "MOV R7, R19 ;"] and sum(a.text == "IADD.64 R6, R16, R26 ;" for a in bg) == 1
        assert all(a.text.split(None, 1)[1].split(",")[0].strip() not in ("R6", "R7") or a.text in ("MOV R6, R18 ;", "MOV R7, R19 ;", "IADD.64 R6, R16, R26 ;") for a in bg), "another writer of the address pair"
        assert not any(re.match(r"\S+\s+R2[67]\b", a.text) for a in bg) and not any("R26" in i.text or "R27" in i.text for i in prologue(rg, 188) if not i.text.startswith(("MOV R26, RZ", "MOV R27, RZ")))
        assert [a.text for a in bg if a.tag == "C"] == ["STG.E desc[UR4][R6.64], R4 ;"] and not misaligned(kernel_text("x", rg, 188, bg))
        g_, st_ = model(rg, "good", gids=gids), model(rg, "stale", gids=gids)
        assert (g_ != st_).all() and [int(x) for x in g_] == model(rg, "good", gids=gids, scalar=True) and [int(x) for x in st_] == model(rg, "stale", gids=gids, scalar=True)
        n += 2
    for bad in ({"producer": "MOV", "consumer": "STG.a0"}, {"producer": "IADD.64", "consumer": "STG.a0", "front": ["stgx4@4"]}, {"producer": "IADD.64", "consumer": "STG.a0", "result": 1},
                {"producer": "MOV", "consumer": "IADD.64rr.r1", "control": "yes"}, {"producer": "MOV", "consumer": "IADD.64rr.r1", "control": "stale", "via": "fill"}):
        try:
            normalise(dict({"id": "xx", "kind": "raw"}, **bad))
        except SystemExit:
            continue
        raise AssertionError(("version 25 must refuse", bad))
    assert normalise({"id": "xx", "kind": "raw", "producer": "MOV", "consumer": "IADD.64rr.r1", "control": "stale"})["distance_list"] == [2, 7]
    assert "POSITIVE CONTROL" in pair_text(normalise({"id": "xx", "kind": "raw", "producer": "MOV", "consumer": "IADD.r1", "control": "stale"}))
    assert "POSITIVE CONTROL" not in pair_text(normalise({"id": "xx", "kind": "raw", "producer": "MOV", "consumer": "IADD.r1"}))
    # the accumulator's hold with the vendor's overwriters; "dest": "a"
    for form in ("QMMA.SF.E4M3.E2M1", "HMMA.BF16"):
        for var_, reg_, dest_ in (("cs2r", 0, None), ("cs2r", 2, None), ("cs2r", 2, "a"), ("prmt", 0, None), ("prmt", 1, None), ("prmt", 2, None), ("prmt", 3, None), ("prmt", 2, "a"), ("mov", 2, "a"), ("mov", 3, "a")):
            q_ = {"id": "xx", "kind": "mma", "form": form, "variant": f"hold_c_{var_}", "reg": reg_}
            if dest_:
                q_["dest"] = dest_
            r = normalise(q_)
            ot = {"cs2r": f"CS2R R{28 + reg_}, SRZ ;", "prmt": f"PRMT R{28 + reg_}, R6, 0x5140, R7 ;", "mov": f"MOV R{28 + reg_}, R6 ;"}[var_]
            d0 = "R16" if dest_ else "R24"
            for dd in (1, 7, 8, 12):
                b = body_mma(r, dd)
                w, o = [a for a in b if a.tag == "P"], [a for a in b if a.tag == "O"]
                assert len(w) == 1 and w[0].text.split()[1:5] == [d0 + ",", "R16,", "R12,", "R28" + ("," if form.startswith("QMMA") else "")] and w[0].sem[5] == "R28" and w[0].sem[1] == d0, (form, var_, reg_)
                assert len(o) == 1 and o[0].text == ot and b.index(o[0]) > b.index(w[0]) and not misaligned(kernel_text("x", r, 188, b)), (form, var_, reg_)
                assert sum(int(a.ctl[-3:-1]) for a in b[b.index(w[0]):b.index(o[0])]) == dd
                assert [a.text.split()[2].rstrip(",") for a in b[-4:-1]] == [f"R{int(d0[1:]) + k}" for k in (1, 2, 3)], (form, var_, dest_)
            for mode in modes_of(r):
                v = model(r, mode, gids=gids)
                assert [int(x) for x in v] == model(r, mode, gids=gids, scalar=True), (form, var_, reg_, mode)
                n += 1
            g = model(r, "good", gids=gids)
            assert (g != model(r, "drop1", gids=gids)).all()
            # the control's kernel: the overwriter 45 cycles in front, the model ignoring it; the word taking the REWRITTEN register(s) gives another checksum in every thread
            bs = body_mma(normalise(dict(q_, variant=f"sens_c_{var_}")), 45)
            k_m, k_w = next(k for k, a in enumerate(bs) if a.text == ot), next(k for k, a in enumerate(bs) if a.tag == "P")
            assert k_m < k_w and bs[k_m].sem == ("nop",) and sum(int(a.ctl[-3:-1]) for a in bs[k_m:k_w]) == 60 and sum(a.text == ot for a in bs) == 1
            bs[k_m].sem = ("zero2", f"R{28 + reg_}") if var_ == "cs2r" else ("mov", f"R{28 + reg_}", 0)      # (PRMT / MOV: a ZERO accumulator stands for "another content")
            assert all(_scalar(int(x), prologue(r, 188), bs, "good") != int(y) for x, y in zip(gids, g)), (form, var_, reg_)
    # the bodies of the fifth build's hold_c_mov / sens_c_mov without "dest" are unchanged in text (checked against the fifth build by s10/cmp25.py)
    for bad in ({"variant": "hold_c_cs2r", "reg": 1}, {"variant": "sens_c_cs2r", "reg": 3}, {"variant": "hold_c_prmt", "reg": 4}, {"variant": "hold_a_mov", "dest": "a"},
                {"variant": "hold_c_mov", "dest": "b"}, {"variant": "hold_c_prmt", "front": ["mmax1@7"]}):
        try:
            normalise(dict({"id": "xx", "kind": "mma"}, **bad))
        except SystemExit:
            continue
        raise AssertionError(("version 25 must refuse", bad))
    assert normalise({"id": "xx", "kind": "mma", "variant": "hold_c_cs2r"})["reg"] == 2 and normalise({"id": "xx", "kind": "mma", "variant": "sens_c_prmt"})["reg"] == 2
    assert "R30 and R31" in pair_text(normalise({"id": "xx", "kind": "mma", "variant": "hold_c_cs2r"})) and "its own A quad" in pair_text(normalise({"id": "xx", "kind": "mma", "variant": "hold_c_prmt", "dest": "a"}))
    assert pair_text(normalise({"id": "xx", "kind": "mma", "variant": "hold_c_mov", "reg": 3})).endswith("[the rewritten register is R31 of the accumulator quad R28..R31; the word's result goes to R24..R27]")
    # table_cell reads producer_forms (a table that has the section)
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump({"defaults": {"data": 6, "mma_input": 7, "guard": 13, "uniform": 13},
                   "cells": [{"producer": "CS2R", "consumer": "LOP3", "role": "r1", "L": 5}, {"producer": "CS2R", "consumer": "STS", "role": "r1", "L": 4}, {"producer": "CS2R", "consumer": "SHF", "role": "r1", "L": 9}],
                   "producer_forms": [{"producer": "CS2R", "without": [".32"], "L": 7, "except": [{"consumer": "STS", "role": "r1"}]}]}, tf)
    try:
        tcf = lambda c, r_, w: table_cell(tf.name, {"producer": "CS2R", "consumer": c, "role": r_}, w)      # noqa: E731
        assert tcf("IMAD", "r1", "CS2R")["L"] == 7 and tcf("IMAD", "r1", "CS2R")["source"].startswith("producer form")
        assert tcf("IMAD", "r1", "CS2R.32")["L"] == 6 and tcf("IMAD", "r1", None)["L"] == 6 and tcf("IMAD", "r1", "CS2R.32")["source"] == "default (no dense cell)"
        assert tcf("LOP3", "r1", "CS2R")["L"] == 7 and tcf("LOP3", "r1", "CS2R.32")["L"] == 5 and tcf("LOP3", "r1h", "CS2R")["L"] == 7
        assert tcf("STS", "r1", "CS2R")["L"] == 4 and "exception" in tcf("STS", "r1", "CS2R")["source"] and tcf("STS", "r1h", "CS2R")["L"] == 6
        assert tcf("SHF", "r1", "CS2R")["L"] == 9 and "not above" in tcf("SHF", "r1", "CS2R")["source"]
        assert tcf("QMMA", "r3", "CS2R")["L"] == 7 and table_cell(tf.name, {"producer": "MOV", "consumer": "IADD", "role": "r1"}, "MOV")["L"] == 6
    finally:
        os.unlink(tf.name)
    # third build: the uniform base register of a shared store (kind war, STS.ubase)
    rw = normalise({"id": "xx", "kind": "war", "store": "STS.ubase", "overwriter": "UMOV"})
    rwc = normalise({"id": "xx", "kind": "war", "store": "STS.ubase", "overwriter": "UMOV.front", "controls": False})
    assert modes_of(rw) == ["good", "late"] and modes_of(rwc) == ["good"]
    gw, lw = model(rw, "good", gids=gids), model(rw, "late", gids=gids)
    assert (gw != lw).all() and [int(x) for x in gw] == model(rw, "good", gids=gids, scalar=True) and [int(x) for x in lw] == model(rw, "late", gids=gids, scalar=True)
    assert np.array_equal(gw, model(rwc, "good", gids=gids)), "the control's model is the request's"
    # the warp's value: R4 - lane is the same number in every lane of a warp (gids 0 and 5 are lanes of one warp)
    assert int(gw[0]) == int(gw[1]) and int(lw[0]) == int(lw[1])
    n += 3
    for dd in (1, 6, 12):
        for var_ in ("bare", "ctl", "rb"):
            bw = body_war(rw, dd, "sts128x15@4", var_)
            ks, um = next(k for k, a in enumerate(bw) if a.tag == "S"), [k for k, a in enumerate(bw) if a.text == "UMOV UR6, 0x10 ;"]
            assert bw[ks].line() == f"[B------:R2:W-:-:S{dd:02d}] STS [UR6+0x24], R6 ;" and sum(a.text.startswith("R2UR UR6, R25") for a in bw[:ks]) == 1, (dd, var_)
            assert sum(int(a.ctl[-3:-1]) for a in bw[next(k for k, a in enumerate(bw) if a.text.startswith("R2UR")):ks]) >= 45
            assert (um == [] if var_ == "ctl" else (len(um) == 1 and um[0] > ks and sum(int(a.ctl[-3:-1]) for a in bw[ks:um[0]]) == dd
                                                     and bw[um[0]].ctl.startswith("[B--2---" if var_ == "rb" else "[B------"))), (dd, var_)
            assert [a.line() for a in bw[-2:]] == ["[B------:R-:W1:-:S15] LDS R8, [R25+0x24] ;", "[B-12---:R-:W-:-:S15] IADD3 R10, PT, PT, R10, R8, RZ ;"]
            # nothing but the tested store writes shared memory through a uniform register, and no other word of the body reads slot 3 of a line
            assert sum("[UR" in a.text for a in bw) == 1 and not any("+0x3" in a.text for a in bw), (dd, var_)
        bc = body_war(rwc, dd, "none", "bare")
        ks, um = next(k for k, a in enumerate(bc) if a.tag == "S"), [k for k, a in enumerate(bc) if a.text == "UMOV UR6, 0x10 ;"]
        assert len(um) == 1 and um[0] < ks and bc[um[0]].sem == ("nop",) and sum(int(a.ctl[-3:-1]) for a in bc[um[0]:ks]) == 45 and not any(a.tag == "O" for a in bc)
        assert um[0] > next(k for k, a in enumerate(bc) if a.text.startswith("R2UR")), "the control's rewrite stands behind the R2UR of the iteration"
        bc[um[0]].sem = ("mov", "UR6", 0x10)      # the control's kernel as the card runs it: the store takes the rewritten base - another checksum in every thread
        assert all(_scalar(int(x), prologue(rwc, 188), bc, "good") != int(y) for x, y in zip(gids, gw)), dd
    # fifth build: the hold of the UNIFORM selector of a QMMA.SF behind the word (kind mma, hold_u_umov / sens_u_umov); the consumer LEA.r2
    st_ = lambda bb, i, j: sum(int(a.ctl[-3:-1]) for a in bb[i:j])
    ru, rs = (normalise({"id": "xx", "kind": "mma", "variant": v_}) for v_ in ("hold_u_umov", "sens_u_umov"))
    assert modes_of(ru) == ["good", "drop1"] and modes_of(rs) == ["good", "drop1"] and rs["distances"] == "45" and ru["form"].startswith("QMMA")
    for dd in (1, 2, 8, 17, 45):
        b = body_mma(ru, dd)
        qs = [k for k, a in enumerate(b) if a.text.startswith("QMMA.SF")]
        um = [k for k, a in enumerate(b) if a.text.startswith("UMOV UR6")]
        assert len(qs) == 2 and all(b[k].text.endswith("R14, R14, UR6 ;") for k in qs) and b[qs[0]].text.split()[1] == "R24," and b[qs[1]].text.split()[1] == "R28,", dd
        assert b[qs[1]].tag == "P" and b[qs[0]].tag is None and b[qs[0]].text.replace("R24", "R28") == b[qs[1]].text, dd
        assert [b[k].text for k in um] == ["UMOV UR6, 0x9 ;", "UMOV UR6, 0x0 ;"] and b[um[1]].tag == "O" and b[um[1]].sem == ("mov", "UR6", 0) and um[0] < qs[0] < qs[1] < um[1], dd
        assert st_(b, qs[1], um[1]) == dd and st_(b, um[0], qs[0]) == 45 and st_(b, qs[0], qs[1]) == 60, dd
        fx = next(k for k, a in enumerate(b) if a.text.startswith("LOP3.LUT R0, R28, R24"))
        assert st_(b, um[1], fx) == 60 and b[-1].text == "IADD3 R10, PT, PT, R10, R4, RZ ;" and not misaligned(kernel_text("x", ru, 188, b)), dd
        assert sum(a.text.startswith("IADD3 R14, PT, PT, R14, 0x7d7e807f") for a in b[:qs[0]]) == 1 and [a.text for a in b if a.text.startswith("MOV R2")] == [f"MOV R{24 + k}, R{28 + k} ;" for k in range(4)], dd
    bs = body_mma(rs, 45)
    qs, um = [k for k, a in enumerate(bs) if a.text.startswith("QMMA.SF")], [k for k, a in enumerate(bs) if a.text.startswith("UMOV UR6")]
    assert len(qs) == 2 and [bs[k].text for k in um] == ["UMOV UR6, 0x9 ;", "UMOV UR6, 0x0 ;"] and um[0] < qs[0] < um[1] < qs[1] and bs[um[1]].sem == ("nop",) and bs[qs[1]].tag == "P"
    assert st_(bs, qs[0], um[1]) == 60 and st_(bs, um[1], qs[1]) == 60 and not any(a.tag == "O" for a in bs) and st_(bs, qs[1], next(k for k, a in enumerate(bs) if a.text.startswith("LOP3.LUT R0, R28, R24"))) == 60
    assert not misaligned(kernel_text("x", rs, 188, bs))
    for r_ in (ru, rs):
        g, dr = model(r_, "good", gids=gids), model(r_, "drop1", gids=gids)
        assert [int(x) for x in g] == model(r_, "good", gids=gids, scalar=True) and [int(x) for x in dr] == model(r_, "drop1", gids=gids, scalar=True) and (g != dr).all(), r_["variant"]
        n += 2
    # (the model of X ^ Y is 0 in every iteration: the checksum of the hold body and of its control are the same sum of the iteration inputs)
    assert np.array_equal(model(ru, "good", gids=gids), model(rs, "good", gids=gids))
    for bad in ({"variant": "hold_u_umov", "form": "HMMA.BF16"}, {"variant": "sens_u_umov", "form": "HMMA.F16"}, {"variant": "hold_u_umov", "front": ["mmax1@7"]},
                {"variant": "hold_u_umov", "reg": 0}, {"variant": "hold_u_umov", "dest": "a"}):
        try:
            normalise(dict({"id": "xx", "kind": "mma"}, **bad))
            raise AssertionError(bad)
        except SystemExit:
            pass
    assert "the operand hold (one QMMA.SF with a uniform selector" in pair_text(ru) and pair_text(rs).split(": ", 1)[1].startswith("CONTROL: UMOV UR6, 0x0")
    rl, rlc = (normalise(dict({"id": "xx", "kind": "raw", "producer": "IADD3", "consumer": "LEA.r2"}, **x_)) for x_ in ({}, {"control": "stale"}))
    bl = body_raw(rl, 3, "none")
    cl = [a for a in bl if a.tag == "C"]
    assert len(cl) == 1 and cl[0].text == "LEA R8, R5, R6, 0x2 ;" and cl[0].sem == ("mad", "R8", "R5", 4, "R6") and RAW_CONSUMERS["LEA.r2"][2:4] == ("LEA", "r2")
    for r_ in (rl, rlc):
        g, sl = model(r_, "good", gids=gids), model(r_, "stale", gids=gids)
        assert [int(x) for x in g] == model(r_, "good", gids=gids, scalar=True) and [int(x) for x in sl] == model(r_, "stale", gids=gids, scalar=True) and (g != sl).all()
        n += 2
    assert producer_word(normalise({"id": "xx", "kind": "raw", "producer": "CS2R", "consumer": "IMAD.r1", "salt": "set"})) == "CS2R"
    assert producer_word(normalise({"id": "xx", "kind": "raw", "producer": "CS2R.32.CgaSize", "consumer": "IMADi.rel"})) == "CS2R.32"
    assert producer_word(normalise({"id": "xx", "kind": "raw", "producer": "MOV", "consumer": "IADD.r1", "control": "stale"})) == "MOV"
    assert smem_of({"id": "x", "kind": "ord", "nload": 8, "place": "far"}, "c2w9s") == 49152 and smem_of({"id": "x", "kind": "ord", "nload": 8, "place": "far"}, "w32") == 98304
    assert smem_of({"id": "x", "kind": "ord", "nload": 8, "place": "far"}, "c4w8") == 24576
    assert far_layout(288) == (18432, 1280) and far_layout(1024) == (65536, 4096) and far_layout(32) == (2048, 1024)
    # version 27 - kind gp: the shape of the body at every distance (the kernel's stalls at its own distance), every hypothesis against the scalar interpreter, refusals
    for form_ in GP_FORMS:
        wb_, want_ = str(GP_FORMS[form_][1]), GP_FORMS[form_][2]
        for gd_ in GP_GUARDS:
            for ps_ in ("pro", "near"):
                if gd_ == "cnt" and ps_ == "pro":
                    continue
                for wt_, sh_ in [(w_, x_) for w_ in ("guarded", "end") for x_ in ((None,) if form_ == "lea" else tuple(GP_SHARE))]:
                    rp_ = normalise(dict({"id": "xx", "kind": "gp", "form": form_, "guards": gd_, "pset": ps_, "wait": wt_}, **({"share": sh_} if sh_ else {})))
                    wb2_ = "3" if sh_ == "own" else wb_
                    for dd in rp_["distance_list"]:
                        bp_ = body_gp(rp_, dd)
                        ip, iw = next(k for k, a in enumerate(bp_) if a.tag == "P"), next(k for k, a in enumerate(bp_) if a.tag == "W")
                        ics = [k for k, a in enumerate(bp_) if a.tag == "C"]
                        assert st_(bp_, ip, ics[0]) == dd and ip < iw < ics[0] and len(ics) == (1 if form_ == "imad" else 2), (form_, gd_, ps_, wt_, dd)
                        assert st_(bp_, ip, iw) == (2 if form_ == "imad" else 10) and (form_ == "imad" or st_(bp_, ics[0], ics[1]) == 6)
                        assert (("B" + "-" * int(wb_) + wb_) in bp_[iw].ctl) == (wt_ == "guarded") and f"W{wb2_}" in bp_[ip].ctl and f"W{wb_}" in bp_[ip - (1 if form_ == "imad" else 6)].ctl
                        assert sh_ != "own" or bp_[iw].ctl.startswith("[B0--3--" if wt_ == "guarded" else "[B------")
                        igs = [k for k, a in enumerate(bp_) if a.tag == "G"]
                        assert all("B------" in bp_[k].ctl for k in ics) and all(":W-:" in a.ctl for k, a in enumerate(bp_) if k > ip and k not in igs)
                        if sh_ in ("ldg", "own"):      # the kernel's global load: under the FIRST predicate, read barrier 1, write barrier 0, ONE cycle in front of the reader, a safe address
                            assert igs == [ics[0] - 1] and bp_[igs[0]].text == "@P0 LDG.E.CONSTANT R7, desc[UR4][R18.64] ;" and bp_[igs[0]].ctl == "[B------:R1:W0:Y:S01]"
                        else:
                            assert not igs and not any("LDG" in a.text for a in bp_)
                        guard_ = "@P" if want_ else "@!P"
                        assert bp_[iw].text.startswith(guard_ + "0 ") and all(bp_[k].text.startswith(guard_ + "2 ") for k in ics + [ip]) and bp_[ip].text.split()[1] == "LDC.64"
                        drains = [k for k, a in enumerate(bp_) if ("B" + "-" * int(wb_) + wb_) in a.ctl and a.tag is None]
                        assert len(drains) == 1 and drains[0] > ics[-1] and st_(bp_, ics[-1], drains[0]) >= 46 and bp_[drains[0]].text.startswith("IADD3 R30") and not bp_[drains[0]].text.startswith("@")
                        assert bp_[drains[0]].ctl[:9] == {None: "[B----4-:", "ldc": "[B0-----:", "ldg": "[B01----:", "own": "[B01-3--:"}[sh_]
                        assert all(("Y" in a.ctl.split(":")[3]) <= (int(a.ctl[-3:-1]) <= 11) for a in bp_) and not misaligned(kernel_text("x", rp_, 188, bp_))
                        assert not any(("R24" in a.text or "R25" in a.text or (form_ == "lea" and ("R6," in a.text or "R7," in a.text))) and k > ics[-1]
                                       for k, a in enumerate(bp_) if a.tag is None), "the carrier's result is never folded"
                        if dd == (8 if form_ == "imad" else 17):      # the kernel's own control fields at the kernel's distance
                            ctl_ = [a.ctl for a in bp_[ip - (1 if form_ == "imad" else 6):ics[-1] + 1]]
                            kern_ = (["[B------:R-:W0:Y:S08]", f"[B------:R-:W{wb2_}:Y:S02]", "[B0--3--:R-:W-:-:S05]" if sh_ == "own" else "[B0-----:R-:W-:-:S05]",
                                      "[B------:R-:W-:Y:S01]" if sh_ == "ldc" else "[B------:R1:W0:Y:S01]", "[B------:R-:W-:-:S05]"] if form_ == "imad" else
                                     ["[B------:R-:W4:Y:S01]", "[B------:R-:W-:Y:S01]", "[B------:R-:W-:Y:S01]", "[B------:R-:W-:Y:S01]", "[B------:R-:W-:Y:S01]", "[B------:R-:W-:-:S03]",
                                      "[B------:R-:W4:Y:S01]", "[B------:R-:W-:Y:S01]", "[B------:R-:W-:Y:S01]", "[B------:R-:W-:-:S05]", "[B------:R-:W-:Y:S02]", "[B----4-:R-:W-:-:S06]",
                                      "[B------:R-:W-:Y:S01]", "[B------:R-:W-:-:S05]", "[B------:R-:W-:Y:S01]", "[B------:R-:W-:Y:S01]"])
                            if wt_ == "end":
                                kern_ = [c_.replace("[B0-----", "[B------").replace("[B0--3--", "[B------").replace("[B----4-", "[B------") for c_ in kern_]
                            assert ctl_ == kern_, (form_, wt_, ctl_)
                        if ps_ == "near":
                            assert bp_[ip - (3 if form_ == "imad" else 8)].text.startswith("ISETP.GE.AND P0") and bp_[ip - (2 if form_ == "imad" else 7)].text.startswith("ISETP.GE.AND P2")
                            assert bp_[ip - (3 if form_ == "imad" else 8)].ctl.endswith("Y:S01]") and bp_[ip - (2 if form_ == "imad" else 7)].ctl.endswith("-:S12]")
                        else:
                            assert not any(a.text.startswith("ISETP") for a in bp_)
                    assert modes_of(rp_) == (["good"] if gd_ in ("tf", "ff") else ["good", "stale", "drop2"] if form_ == "imad" else ["good", "stale"])
                    ex_ = gp_exec(rp_, gids)
                    mg_ = model(rp_, "good", gids=gids)
                    assert [int(x) for x in mg_] == model(rp_, "good", gids=gids, scalar=True) and (mg_ != 0).all(), (form_, gd_, ps_, wt_)
                    n += 1
                    for m_ in modes_of(rp_)[1:]:
                        mv_ = model(rp_, m_, gids=gids)
                        assert [int(x) for x in mv_] == model(rp_, m_, gids=gids, scalar=True) and np.array_equal(mg_ != mv_, ex_), (form_, gd_, ps_, wt_, m_)
                        n += 1
                    # the control computes what the guarded text computes (the wait bit is not part of the model); own == ldg (the barrier is not part of it either)
                    assert np.array_equal(mg_, model(normalise(dict({"id": "xx", "kind": "gp", "form": form_, "guards": gd_, "pset": ps_}, **({"share": "ldg" if sh_ == "own" else sh_} if sh_ else {}))), "good", gids=gids))
            # where the predicates are set does not change what is computed
            if gd_ != "cnt":
                assert np.array_equal(model(normalise({"id": "xx", "kind": "gp", "form": form_, "guards": gd_, "pset": "pro"}), "good", gids=gids),
                                      model(normalise({"id": "xx", "kind": "gp", "form": form_, "guards": gd_, "pset": "near"}), "good", gids=gids))
        # neither side executes: every pair keeps what the front wrote; both sides execute in every thread with tt
        assert gp_exec(normalise({"id": "xx", "kind": "gp", "form": form_, "guards": "tt"}), gids).all() and not gp_exec(normalise({"id": "xx", "kind": "gp", "form": form_, "guards": "tf"}), gids).any()
        assert 0 < int(gp_exec(normalise({"id": "xx", "kind": "gp", "form": form_, "guards": "lane"}), np.arange(64)).sum()) == 32
    for bad in ({"form": "x", "guards": "tt"}, {"form": "imad", "guards": "t"}, {"form": "imad", "guards": "cnt", "pset": "pro"}, {"form": "imad", "guards": "tt", "wait": "none"},
                {"form": "imad", "guards": "tt", "distances": "2"}, {"form": "lea", "guards": "tt", "distances": "8"}, {"form": "lea", "guards": "tt", "yield": "set"},
                {"form": "imad", "guards": "tt", "distances": "3"}, {"form": "imad", "guards": "tt", "share": "x"}, {"form": "lea", "guards": "tt", "share": "ldc"}):
        try:
            normalise(dict({"id": "xx", "kind": "gp"}, **bad))
            raise AssertionError(bad)
        except SystemExit:
            pass
    # version 26, third build - kind lb: the distance older -> younger, the control's shape, both hypotheses against the scalar interpreter
    for extra in ({}, {"yield": "set"}, {"control": "front"}):
        rl_ = normalise(dict({"id": "xx", "kind": "lb"}, **extra))
        for dd in rl_["distance_list"]:
            bl_ = body_lb(rl_, dd)
            io, iy = next(k for k, a in enumerate(bl_) if a.tag == "S"), next(k for k, a in enumerate(bl_) if a.tag == "O")
            assert all(("Y" in a.ctl.split(":")[3]) <= (int(a.ctl[-3:-1]) <= 11) for a in bl_)
            assert bl_[io].text == "LDS R6, [R13+0x4] ;" and "W1" in bl_[io].ctl and ":R-:" in bl_[io].ctl and io < iy and not misaligned(kernel_text("x", rl_, 188, bl_))
            if extra.get("control"):
                iyf = next(k for k, a in enumerate(bl_) if a.text.startswith("LDS R13"))
                assert iyf < io and bl_[iyf].sem == ("nop",) and st_(bl_, iyf, io) == 60 and bl_[iy].text.startswith("IADD3 R15") and sum(a.text.startswith("LDS R13") for a in bl_) == 1
            else:
                assert st_(bl_, io, iy) == dd and bl_[iy].text == "LDS R13, [R13+0x3c] ;" and "W2" in bl_[iy].ctl and "B------" in bl_[iy].ctl
                assert not any("B" + w_ in a.ctl for a in bl_[io:iy + 1] for w_ in ("-1", "--2", "-12"))
        assert any(a.text == "STS [R9+0x3c], R13 ;" for a in prologue(rl_, 188))
        g, lt_ = model(rl_, "good", gids=gids), model(rl_, "late", gids=gids)
        assert [int(x) for x in g] == model(rl_, "good", gids=gids, scalar=True) and [int(x) for x in lt_] == model(rl_, "late", gids=gids, scalar=True) and (g != lt_).all(), extra
        n += 2
    assert np.array_equal(model(normalise({"id": "xx", "kind": "lb"}), "good", gids=gids), model(normalise({"id": "xx", "kind": "lb", "control": "front"}), "good", gids=gids))
    assert np.array_equal(model(normalise({"id": "xx", "kind": "lb"}), "late", gids=gids), model(normalise({"id": "xx", "kind": "lb", "control": "front"}), "late", gids=gids))
    for bad in ({"control": "x"}, {"control": "front", "yield": "set"}, {"yield": "set", "distances": "12-14"}, {"producer": "LDS"}):
        try:
            normalise(dict({"id": "xx", "kind": "lb"}, **bad))
            raise AssertionError(bad)
        except SystemExit:
            pass
    # version 26, second build - kind gw: the shape of the body at every distance, both hypotheses against the scalar interpreter, refusals
    for prod_ in GW_PRODUCERS:
        for extra in ({}, {"guard": "false"}, {"wait": "none"}, {"wait": "none", "guard": "false"}, {"yield": "set"}, {"wait": "none", "yield": "set"},
                      {"wait": "end"}, {"wait": "end", "guard": "false", "yield": "set"}):
            rg = normalise(dict({"id": "xx", "kind": "gw", "producer": prod_}, **extra))
            for dd in rg["distance_list"]:
                bg = body_gw(rg, dd)
                ip, iw, ic = (next(k for k, a in enumerate(bg) if a.tag == t_) for t_ in ("P", "W", "C"))
                assert st_(bg, ip, ic) == dd and sum(1 for a in bg if a.tag in ("P", "W", "C")) == 3, (prod_, extra, dd)
                assert ("B-1----" in bg[iw].ctl) == (rg["wait"] == "guarded") and "W1" in bg[ip].ctl and "B------" in bg[ic].ctl and bg[ic].text.startswith("@!P4 ") and bg[iw].text.startswith("@P4 ")
                assert (iw < ic and st_(bg, ip, iw) == 2) or (dd <= 2 and rg["wait"] != "guarded" and ic < iw), (prod_, extra, dd)
                ends = [k for k, a in enumerate(bg) if "B-1----" in a.ctl and a.tag is None]
                assert (len(ends) == 1 and ends[0] > ic and st_(bg, ic, ends[0]) >= 45 and bg[ends[0]].sem == ("nop",)) if rg["wait"] == "end" else not ends, (prod_, extra, dd)
                assert all(("Y" in a.ctl.split(":")[3]) <= (int(a.ctl[-3:-1]) <= 11) for a in bg) and not misaligned(kernel_text("x", rg, 188, bg))
            g, sl_ = model(rg, "good", gids=gids), model(rg, "stale", gids=gids)
            assert [int(x) for x in g] == model(rg, "good", gids=gids, scalar=True) and [int(x) for x in sl_] == model(rg, "stale", gids=gids, scalar=True) and (g != sl_).all(), (prod_, extra)
            n += 2
        assert np.array_equal(model(normalise({"id": "xx", "kind": "gw", "producer": prod_}), "good", gids=gids),
                              model(normalise({"id": "xx", "kind": "gw", "producer": prod_, "wait": "none"}), "good", gids=gids))
    for bad in ({"producer": "LDG"}, {"producer": "SHFL", "wait": "x"}, {"producer": "SHFL", "guard": "true"}, {"producer": "SHFL", "distances": "1-5"},
                {"producer": "LDS", "yield": "set", "distances": "14-16"}, {"producer": "LDS", "front": ["none"]}):
        try:
            normalise(dict({"id": "xx", "kind": "gw"}, **bad))
            raise AssertionError(bad)
        except SystemExit:
            pass
    # version 26 - kind thr: every slot of every stage passes the audit with the stage's static cycles, differs from the base
    # stage in control fields only, assembles to a text the alignment check takes; the model of ONE pass x repeat equals the
    # scalar interpreter; three whole passes on Python integers give 3 x the checksum of one pass; refusals
    for stg, slots in THR_STAGES.items():
        rt = normalise({"id": "xx", "kind": "thr", "stage": stg, "repeat": 3, "occupancy": ["w1", "w32", "c4w8", "c2w9s"]})
        base = body_thr(rt, 1)
        tot = thr_words(rt)[1]
        pts = thr_points(rt)["slots"]
        assert [p_["slot"] for p_ in pts] == list(range(1, len(slots) + 1)) and all(p_["static_cycles"] == tot for p_ in pts), stg
        for k in range(1, len(slots) + 1):
            bk = body_thr(rt, k)
            assert [(a.text, a.sem, a.tag) for a in bk] == [(a.text, a.sem, a.tag) for a in base], (stg, k)
            assert [a.ctl[-4:] for a in bk] == [a.ctl[-4:] for a in base], (stg, k)      # the same stalls
            assert not misaligned(kernel_text("x", rt, 188, bk)), (stg, k)
        if stg == "a":
            assert [a.ctl for a in body_thr(rt, len(slots))] == [a.ctl for a in base]      # the null slot IS the base stage
            by = {p_["name"]: p_ for p_ in pts}
            assert (by["base"]["wait_bits"], by["base"]["read_barriers"], by["base"]["write_barriers"], by["base"]["tensor_words"], by["base"]["loads"]) == (1, 0, 1, 4, 1)
            assert [by[f"a1_{m}"]["wait_bits"] for m in (1, 2, 4, 8, 16)] == [2, 3, 5, 9, 17] and by["a1n_16"]["wait_bits"] == 17
            assert [by[f"a2_{m}"]["wait_bits"] for m in (1, 2, 4, 8)] == [2, 3, 5, 9]
            assert (by["a3_r"]["read_barriers"], by["a3_r"]["wait_bits"]) == (4, 1) and (by["a3_w"]["read_barriers"], by["a3_w"]["wait_bits"]) == (4, 13)
            assert (by["a3_d"]["read_barriers"], by["a3_d"]["wait_bits"]) == (4, 17) and by["a4"]["wait_bits"] == 2
            assert by["b_none"]["yield_flags"] == 0 and by["b_tensor"]["yield_flags"] == 3 and by["b_alt"]["yield_flags"] * 2 in (by["base"]["yield_flags"], by["base"]["yield_flags"] + 1)
        g = model(rt, "good", gids=gids)
        assert [int(x) for x in g] == model(rt, "good", gids=gids, scalar=True) and (g != 0).all(), stg
        one = model(dict(rt, repeat=1), "good", gids=gids, scalar=True)
        for gi, d1 in zip(gids, one):
            assert thr_passes_scalar(rt, int(gi), 3) == (3 * d1) & 0xFFFFFFFF, (stg, int(gi))
        n += 1
    for bad in ({"repeat": 2}, {"repeat": 0}, {"stage": "zz"}, {"distances": "2-5"}, {"distances": "1-99"}, {"occupancy": ["g32"]}, {"yield": "set"}, {"form": "HMMA.BF16"}):
        try:
            normalise(dict({"id": "xx", "kind": "thr"}, **bad))
            raise AssertionError(bad)
        except SystemExit:
            pass
    # a stage that breaks a rule is refused by the audit: a rewrite of a B register 7 cycles behind its tensor word; a reader of the load that does not wait
    rt = normalise({"id": "xx", "kind": "thr", "stage": "a", "repeat": 3})
    for mut in ("hold", "nowait", "cycles"):
        b_ = body_thr(rt, 1)
        tot = thr_words(rt)[1]
        ix = {a.tag: k for k, a in enumerate(b_)}
        if mut == "hold":      # X0 one cycle later, FL one cycle earlier in stall: G2a then stands 7 behind X0
            b_[ix["F3"]] = Ins(b_[ix["F3"]].text, b_[ix["F3"]].sem, ctl=b_[ix["F3"]].ctl[:-3] + "03]", tag="F3")
            b_[ix["X0"]] = Ins(b_[ix["X0"]].text, b_[ix["X0"]].sem, ctl=b_[ix["X0"]].ctl[:-3] + "03]", tag="X0")
        elif mut == "nowait":
            b_[ix["FL"]] = Ins(b_[ix["FL"]].text, b_[ix["FL"]].sem, ctl=C(4, y=True), tag="FL")
        else:
            b_[ix["B0"]] = Ins(b_[ix["B0"]].text, b_[ix["B0"]].sem, ctl=C(5, y=True), tag="B0")
        try:
            thr_audit(rt, b_, tot, mut)
            raise AssertionError(mut)
        except SystemExit:
            pass
    # version 28 - a set under two predicates
    s17_ = "gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,gQ,gB,kG"
    for forms in ("gQ,kG", s17_, "gQ,gB,gQ,gB,gQ,gB,gQ,gB,kG", "gB,kG", "gQ,kG,gQ,gB,kG"):
        toks_ = forms.split(",")
        nagain = sum(1 for k_, t_ in enumerate(toks_) if t_ == "gQ" and any(x_[:1] == "g" for x_ in toks_[:k_]))
        for pg_ in ("tt", "tf", "ft", "ff", "ll", "cc", "lt", "fl", "tc"):
            for cold_ in ((None, "set") if forms.count("G") == 1 else (None,)):
                base_ = dict({"id": "xx", "kind": "ord", "forms": forms, "barrier": "all", "yield": "set", "pguard": pg_, "occupancy": ["w8", "c2w9s"]}, **({"cold": cold_} if cold_ else {}))
                rq = normalise(base_)
                assert is_set(rq) and rq["controls"] is False and rq["wait"] == "reader", (forms, pg_)
                ex_ = set_exec(rq, gids)
                assert modes_of(rq) == (["good"] if pg_ == "ff" else ["good", "stale"]), (forms, pg_)
                g = model(rq, "good", gids=gids)
                assert [int(x) for x in g] == model(rq, "good", gids=gids, scalar=True) and (g != 0).all(), (forms, pg_, cold_)
                PTR_STANDIN[:] = [0x1234567, 0x89abcde]      # (no term of a fold may be the pointer the host model does not know)
                try:
                    assert [int(x) for x in g] == model(rq, "good", gids=gids, scalar=True), (forms, pg_, cold_)
                finally:
                    PTR_STANDIN[:] = [0, 0]
                n += 1
                if pg_ != "ff":
                    st_ = model(rq, "stale", gids=gids)
                    assert [int(x) for x in st_] == model(rq, "stale", gids=gids, scalar=True) and np.array_equal(g != st_, ex_), (forms, pg_, cold_)
                    n += 1
                else:
                    assert not ex_.any()
                if pg_ == "tt":      # the anchor: both predicates true = the same set under ONE true guard (version 23)
                    old_ = normalise(dict({"id": "xx", "kind": "ord", "forms": forms.replace("k", "g"), "barrier": "all", "yield": "set", "occupancy": ["w8", "c2w9s"]},
                                          **({"cold": cold_} if cold_ else {})))
                    assert np.array_equal(g, model(old_, "good", gids=gids)), (forms, cold_)
                ref_ = None
                for wt_, rd_ in (("reader", None), ("end", None), ("reader", 4), ("reader", 12), ("reader", 129), ("end", 129)):
                    rv = normalise(dict(base_, wait=wt_, **({"rdist": rd_} if rd_ else {})))
                    for d_ in (1, 4):
                        body = body_ord(rv, d_, "none", "bare")
                        prods, snaps = [a for a in body if a.tag == "P"], [a for a in body if a.tag == "C"]
                        assert len(prods) == len(toks_) and all(a.ctl[12:14] == "W1" and ":Y:S" in a.ctl and a.ctl[1:8] == "B------" for a in prods), (forms, pg_)
                        assert all(a.text.startswith("@P0 " if t_[0] == "g" else "@P2 ") and a.sem[0] == "g" and a.sem[1] == ("P0" if t_[0] == "g" else "P2") and a.sem[2] == 1
                                   and list(a.sem[3]) == list(a.dst) for a, t_ in zip(prods, toks_)), (forms, pg_)
                        assert all(a.ctl[-4:] == f"S{d_:02d}]" for a in prods[:-1]), (forms, pg_)
                        # the reader's distance behind the last arming = the last producer's stall + the fillers up to the first reader word
                        i0, i1 = body.index(prods[-1]), body.index(snaps[0])
                        assert all(a.sem == ("nop",) and a.ctl[1:8] == "B------" for a in body[i0 + 1:i1]), (forms, pg_)
                        assert sum(int(a.ctl[-3:-1]) for a in body[i0:i1]) == (rd_ or 2) and int(prods[-1].ctl[-3:-1]) <= 11, (forms, pg_, rd_)
                        # ONE wait in the whole body: on the first reader word, or (the control) on the first word behind the reader words
                        waits = [k_ for k_, a in enumerate(body) if a.ctl[1:8] != "B------"]
                        ilast = body.index(snaps[-1])
                        assert waits == [i1 if wt_ == "reader" else ilast + 1] and body[waits[0]].ctl[1:8] == "B-1----", (forms, pg_, wt_, waits)
                        assert wt_ == "reader" or (body[ilast + 1].sem == ("nop",) and body[ilast + 1].text.startswith("IADD3 R15,")), (forms, pg_)
                        assert all(a.ctl[-4:] == "S01]" for a in snaps), (forms, pg_)
                        # the predicates: P2 once, P0 once and again in front of every further gQ; each guarded load >= 13 cycles behind the ISETP of its predicate
                        ip0 = [k_ for k_, a in enumerate(body) if a.text.startswith("ISETP.GE.AND P0,")]
                        ip2 = [k_ for k_, a in enumerate(body) if a.text.startswith("ISETP.GE.AND P2,")]
                        assert len(ip0) == 1 + nagain and len(ip2) == 1 and ip0[0] < ip2[0] < body.index(prods[0]), (forms, pg_)
                        # (second build) every ISETP stands >= 6 issue cycles behind the last writer of its source register - the check the first build lacked
                        lastw, now_ = {}, 0
                        for a in body:
                            ms_ = re.match(r"ISETP\.GE\.AND P[02], PT, (R\d+), RZ, PT ;", a.text)
                            if ms_:
                                assert ms_.group(1) in lastw and now_ - lastw[ms_.group(1)] >= 6, (forms, pg_, a.text, now_ - lastw.get(ms_.group(1), -999))
                            mw_ = re.match(r"(?:MOV|SHF\.L\.U32|IMAD) (R7|R14),", a.text)
                            if mw_:
                                lastw[mw_.group(1)] = now_
                            now_ += int(a.ctl[-3:-1])
                        # (second build) between the pairs P0 is written right behind the last load in front of it (the kernel's place) and 13 cycles in front of the next load
                        for k_ in ip0[1:]:
                            assert body[k_ - 1].tag == "P" and sum(int(x.ctl[-3:-1]) for x in body[k_:next(q_ for q_ in range(k_, len(body)) if body[q_].tag == "P")]) == 13, (forms, pg_)
                        for a, t_ in zip(prods, toks_):
                            ia = body.index(a)
                            isrc = max(k_ for k_ in (ip0 if t_[0] == "g" else ip2) if k_ < ia)
                            assert sum(int(x.ctl[-3:-1]) for x in body[isrc:ia]) >= 13, (forms, pg_, t_)
                        # nothing but the predicate words touches R7 / R14; nothing writes an address register, a reference or the loop's registers
                        for a in body:
                            if re.search(r"(?<![UA-Za-z0-9])R(7|14)(?![0-9])", a.text):
                                assert a.text.startswith(("MOV R7, ", "MOV R14, ", "SHF.L.U32 R7, ", "SHF.L.U32 R14, ", "IMAD R7, R11, ", "IMAD R14, R11, ", "ISETP.GE.AND P")), a.text
                        wr = set()
                        for a in body:
                            m_ = re.match(r"(?:@P[02] )?\S+ (?:PT, )?R(\d+)", a.text)
                            if m_ and not a.text.startswith(("STS", "STG", "ISETP")):
                                wr.add(int(m_.group(1)))
                        assert not (wr & {0, 1, 2, 3, 4, 5, 9, 11, 16, 17, 18, 19, 20, 21, 22, 23, SET_MSRC, SET_MREF, SET_ABASE, SET_ABASE + 1, SET_CBASE + 1}), (forms, sorted(wr))
                        text = kernel_text("selftest_x", dict(rv, _threads=256), 188, body, 49152)
                        assert misaligned(text) == [] and "    .reg R0-R79\n    .regcount 88\n" in text, forms
                        assert max(int(x) for x in re.findall(r"(?<![UA-Za-z])R(\d+)", text.split(".shared")[1])) <= SET_REGS - 1, forms
                        if (wt_, rd_) == ("reader", None):
                            ref_ = ref_ or {}
                            ref_[d_] = body
                        elif (wt_, rd_) == ("end", None):      # the control = the test but for two control codes: the reader's wait bit and the word behind the reader words
                            rb_ = ref_[d_]
                            assert len(rb_) == len(body) and all(a.text == c.text and a.sem == c.sem for a, c in zip(rb_, body)), (forms, pg_)
                            assert [k_ for k_, (a, c) in enumerate(zip(rb_, body)) if a.ctl != c.ctl] == [i1, ilast + 1], (forms, pg_)
    for bad in ({"forms": "gQ,kG"}, {"forms": "gQ,gG", "pguard": "tt"}, {"forms": "gQ,kG", "pguard": "tx"}, {"forms": "gQ,kG", "pguard": "t"}, {"forms": "gQ,kG", "pguard": "tt", "barrier": "none"},
                {"forms": "gQ,kG", "pguard": "tt", "wait": "none"}, {"forms": "gQ,kG", "pguard": "tt", "controls": True}, {"forms": "gQ,kG", "pguard": "tt", "rdist": 0},
                {"forms": "gQ,kG", "pguard": "tt", "rdist": 301}, {"forms": "gQ,gG", "wait": "end"}, {"forms": "gQ,gG", "rdist": 4}, {"forms": "gQ,kc", "pguard": "tt"},
                {"forms": "gQ,kG,Q", "pguard": "tt"}, {"forms": "gQ,kG", "pguard": "tt", "front": ["sts128x15@4"]}, {"forms": "gQ,kG,kG", "pguard": "tt", "cold": "set"}):
        try:
            normalise(dict({"id": "xx", "kind": "ord", "barrier": "all", "yield": "set"}, **bad))
            raise AssertionError(f"a request that must be refused was taken: {bad}")
        except SystemExit:
            pass
    # (second build) "pshift": 1 = the first build's text and the hypothesis p0old
    for forms in (s17_, "gQ,kG,gQ,gB,kG"):
        rx = normalise({"id": "xx", "kind": "ord", "forms": forms, "barrier": "all", "yield": "set", "pguard": "cc", "pshift": 1, "occupancy": ["w8", "c2w9s"]})
        rf = normalise({"id": "xx", "kind": "ord", "forms": forms, "barrier": "all", "yield": "set", "pguard": "cc", "occupancy": ["w8", "c2w9s"]})
        assert modes_of(rx) == ["good", "stale", "p0old"] and modes_of(rf) == ["good", "stale"], forms
        bx, bf = body_ord(rx, 4, "none", "bare"), body_ord(rf, 4, "none", "bare")
        ps_ = [k_ for k_, a in enumerate(bx) if a.tag == "PS"]
        assert ps_ and all(bx[k_].ctl[-4:] == "S01]" and bx[k_ + 1].text.startswith("ISETP.GE.AND P0,") and bx[k_ + 1].ctl[-4:] == "S13]" for k_ in ps_), forms
        pf_ = [k_ for k_, a in enumerate(bf) if a.tag == "PS"]
        assert len(pf_) == len(ps_) and bf[pf_[0]].ctl[-4:] == "S15]" and all(bf[k_].ctl[-4:] == "S12]" and bf[k_ - 1].text.startswith("ISETP.GE.AND P0,") and bf[k_ - 1].ctl[-4:] == "S01]" for k_ in pf_[1:]), forms
        # the model does not see timing: both texts have the same `good`; p0old differs from it in every thread
        g, o_ = model(rx, "good", gids=gids), model(rx, "p0old", gids=gids)
        assert np.array_equal(g, model(rf, "good", gids=gids)) and [int(x) for x in o_] == model(rx, "p0old", gids=gids, scalar=True) and (g != o_).all(), forms
        assert np.array_equal(model(rx, "stale", gids=gids), model(rf, "stale", gids=gids)), forms
        n += 1
    for bad in ({"forms": "gQ,kG", "pguard": "cc", "pshift": 1}, {"forms": s17_, "pguard": "tc", "pshift": 1}, {"forms": s17_, "pguard": "cc", "pshift": 2}, {"forms": s17_, "pshift": 1}):
        try:
            normalise(dict({"id": "xx", "kind": "ord", "barrier": "all", "yield": "set"}, **bad))
            raise AssertionError(f"a request that must be refused was taken: {bad}")
        except SystemExit:
            pass
    assert set_rdist({"rdist": 129}, True, 2) == (11, [15] * 7 + [13]) and set_rdist({"rdist": 129}, False, 2) == (15, [15] * 7 + [9]) and set_rdist({}, True, 2) == (2, [])
    assert set_rdist({"rdist": 12}, True, 2) == (11, [1]) and set_rdist({"rdist": 11}, True, 2) == (11, []) and set_rdist({"rdist": 26}, True, 2) == (11, [15])
    # version 29 - the scale set: unguarded LDS (second build: and LDS.64) on one write barrier, two guarded QMMA.SF readers (and MOV readers)
    for forms, lead_ in (("S,S", None), ("S,S,S", None), ("S,S,D,D,S,S,D", None), ("S,D,D,S,S,D", None), ("D,D,S,S,D", "mov"), ("S,D,D,S,D", None), ("D,D,S,D", "mov"), ("D,D,S,D", None), ("S,D", "mov")):
        toks_ = forms.split(",")
        ns_, nd_ = toks_.count("S"), toks_.count("D")
        for pg_ in (("tt", "tf", "ft", "ff", "ll", "cc", "lt", "cf") if not nd_ else ("tf", "ft", "ff", "cc")):
            base_ = dict({"id": "xx", "kind": "ord", "forms": forms, "barrier": "all", "yield": "set", "pguard": pg_, "distances": "1,4", "occupancy": ["w8", "c2w9s"]}, **({"lead": lead_} if lead_ else {}))
            rq = normalise(dict(base_))
            assert is_set(rq) and is_sf(rq) and rq["controls"] is False and rq["wait"] == "reader" and rq["nload"] == ns_ + nd_, (forms, pg_)
            e1_, e2_ = sf_exec(rq, gids)
            e3_ = np.full(len(gids), bool(nd_), bool)
            live_ = [m_ for m_, on_ in (("stale1", pg_[0] != "f"), ("stale2", pg_[1] != "f"), ("stale3", bool(nd_))) if on_]
            want_ = ["good"] + (["stale"] if live_ else []) + (live_ if len(live_) > 1 else [])
            assert modes_of(rq) == want_, (forms, pg_, modes_of(rq))
            g = model(rq, "good", gids=gids)
            assert [int(x) for x in g] == model(rq, "good", gids=gids, scalar=True) and (g != 0).all(), (forms, pg_)
            PTR_STANDIN[:] = [0x1234567, 0x89abcde]      # (no term of a fold may be the pointer the host model does not know)
            try:
                assert [int(x) for x in g] == model(rq, "good", gids=gids, scalar=True), (forms, pg_)
            finally:
                PTR_STANDIN[:] = [0, 0]
            n += 1
            got_ = {}
            for m_, ex_ in (("stale", e1_ | e2_ | e3_), ("stale1", e1_), ("stale2", e2_), ("stale3", e3_)):
                if m_ in want_:
                    got_[m_] = model(rq, m_, gids=gids)
                    assert [int(x) for x in got_[m_]] == model(rq, m_, gids=gids, scalar=True) and np.array_equal(g != got_[m_], ex_), (forms, pg_, m_)
                    n += 1
            if {"stale1", "stale2"} <= set(got_):      # where both tensor readers execute the hypotheses are different checksums
                both_ = e1_ & e2_
                assert both_.any() and (got_["stale"][both_] != got_["stale1"][both_]).all() and (got_["stale"][both_] != got_["stale2"][both_]).all() \
                    and (got_["stale1"][both_] != got_["stale2"][both_]).all(), (forms, pg_)
            if "stale3" in got_:
                assert (got_["stale3"] != got_["stale"]).any() and all((got_["stale3"] != got_[m_]).any() for m_ in ("stale1", "stale2") if m_ in got_), (forms, pg_)
            ref_ = None
            for wt_, rd_ in (("reader", None), ("end", None), ("reader", 34), ("end", 34), ("reader", 12)):
                rv = normalise(dict(base_, wait=wt_, **({"rdist": rd_} if rd_ else {})))
                for d_ in (1, 4):
                    body = body_ord(rv, d_, "none", "bare")
                    lay_ = sf_layout(set_plan(rv))
                    prods, r1_, r2_, r3_ = [a for a in body if a.tag == "P"], [a for a in body if a.tag == "C"], [a for a in body if a.tag == "C2"], [a for a in body if a.tag == "C3"]
                    assert len(prods) == ns_ + nd_ and len(r1_) == 1 and len(r2_) == 1 and len(r3_) == 2 * nd_, (forms, pg_)
                    assert all(a.ctl[12:14] == "W1" and ":Y:S" in a.ctl and a.ctl[1:8] == "B------" and a.sem[0] == "lds" for a in prods), (forms, pg_)
                    # the loads: every second one through the second base register; S = a word of slot 2, D = a pair of slots 0 / 1; pairs on even registers
                    ks_ = kd_ = 0
                    sregs_, dregs_ = [], []
                    for k_, (a, t_) in enumerate(zip(prods, toks_)):
                        bs_ = f"R{lay_['base2']}" if k_ % 2 else "R9"
                        if t_ == "S":
                            m_ = re.match(r"LDS R(\d+), ", a.text)
                            assert m_ and a.text == f"LDS R{m_.group(1)}, [{bs_}+0x{0x20 + 4 * ks_:x}] ;" and list(a.dst) == [f"R{m_.group(1)}"], a.text
                            sregs_.append(int(m_.group(1)))
                            ks_ += 1
                        else:
                            m_ = re.match(r"LDS\.64 R(\d+), ", a.text)
                            assert m_ and a.text == f"LDS.64 R{m_.group(1)}, [{bs_}{('+0x%x' % (8 * kd_)) if kd_ else ''}] ;" and list(a.dst) == [f"R{m_.group(1)}", f"R{int(m_.group(1)) + 1}"], a.text
                            dregs_.append(int(m_.group(1)))
                            kd_ += 1
                    assert all(x % 2 == 0 for x in dregs_) and len(set(sregs_ + dregs_ + [x + 1 for x in dregs_])) == ns_ + 2 * nd_ and max(sregs_ + [x + 1 for x in dregs_]) < lay_["a"], (forms, sregs_, dregs_)
                    if not nd_:
                        assert lay_["a"] == 40 and [a.text for a in prods] == [f"LDS R{32 + k_}, [{'R56' if k_ % 2 else 'R9'}+0x{0x20 + 4 * k_:x}] ;" for k_ in range(ns_)], (forms, [a.text for a in prods])
                    assert all(a.ctl[-4:] == f"S{d_:02d}]" for a in prods[:-1]), (forms, pg_)
                    readers = sorted(body.index(x) for x in r1_ + r2_ + r3_)
                    i0, i1, i2 = body.index(prods[-1]), body.index(r1_[0]), body.index(r2_[0])
                    ifirst, ilast = readers[0], readers[-1]
                    assert all(a.sem == ("nop",) and a.ctl[1:8] == "B------" for a in body[i0 + 1:ifirst]), (forms, pg_)
                    assert sum(int(a.ctl[-3:-1]) for a in body[i0:ifirst]) == (rd_ or 2) and int(prods[-1].ctl[-3:-1]) <= 11, (forms, pg_, rd_)
                    # the tensor readers: the kernel's word under P0 / P2, 16 cycles apart, the scale operands youngest + next | oldest + youngest (with one S: the prologue's unit scale)
                    y_ = sregs_[-1]
                    x_, o_ = (sregs_[-2], sregs_[0]) if ns_ > 1 else (lay_["one"], lay_["one"])
                    p_, q_ = (sregs_[0], sregs_[1]) if ns_ > 3 else (o_, y_)      # with four S the second reader takes the two oldest
                    assert r1_[0].text == f"@P0 QMMA.SF.16832.F32.E4M3.E2M1.E8 R{lay_['c1']}, R{lay_['a']}, R{lay_['b1']}, R{lay_['c1']}, R{y_}, R{x_}, URZ ;" and r1_[0].ctl[-6:] == "Y:S01]", r1_[0].line()
                    assert r2_[0].text == f"@P2 QMMA.SF.16832.F32.E4M3.E2M1.E8 R{lay_['c2']}, R{lay_['a']}, R{lay_['b2']}, R{lay_['c2']}, R{p_}, R{q_}, URZ ;" and r2_[0].ctl == C(), r2_[0].line()
                    assert i2 == i1 + 2 and body[i1 + 1].text == "NOP ;" and body[i1 + 1].ctl == C(), (forms, pg_)
                    assert r1_[0].sem[:3] == ("g", "P0", 1) and r2_[0].sem[:3] == ("g", "P2", 1) and r1_[0].sem[4][0] == "qmmasf" and r2_[0].sem[4][0] == "qmmasf", (forms, pg_)
                    # the MOV readers: both registers of every pair, the youngest pair first, one cycle apart, in front of the tensor readers (lead mov) or behind them
                    assert [a.text for a in r3_] == [f"MOV R{lay_['tmp'] + 2 * j_ + h_}, R{rg_ + h_} ;" for j_, rg_ in enumerate(reversed(dregs_)) for h_ in (0, 1)], (forms, [a.text for a in r3_])
                    assert all(a.ctl[-4:] == "S01]" and ":-:S" in a.ctl for a in r3_) and (not r3_ or (body.index(r3_[0]) < i1) == (lead_ == "mov")), (forms, pg_)
                    assert not r3_ or [body.index(x) for x in r3_] == list(range(body.index(r3_[0]), body.index(r3_[0]) + len(r3_))), (forms, pg_)
                    # ONE wait in the whole body: on the first reader word, or (the control) on the first word behind the reader words
                    waits = [k_ for k_, a in enumerate(body) if a.ctl[1:8] != "B------"]
                    assert waits == [ifirst if wt_ == "reader" else ilast + 1] and body[waits[0]].ctl[1:8] == "B-1----", (forms, pg_, wt_, waits)
                    assert wt_ == "reader" or (body[ilast + 1].sem == ("nop",) and body[ilast + 1].text.startswith("IADD3 R15,")), (forms, pg_)
                    # the fold stands 45 cycles or more behind the second tensor reader; the predicates are written once each, in front of the loads
                    ifold = next(k_ for k_, a in enumerate(body) if a.text.startswith(f"IMAD R8, R{lay_['c1'] + 1},"))
                    assert sum(int(a.ctl[-3:-1]) for a in body[i2:ifold]) == 45 + (len(r3_) if lead_ != "mov" else 0), (forms, pg_)
                    ip0 = [k_ for k_, a in enumerate(body) if a.text.startswith("ISETP.GE.AND P0,")]
                    ip2 = [k_ for k_, a in enumerate(body) if a.text.startswith("ISETP.GE.AND P2,")]
                    assert len(ip0) == 1 and len(ip2) == 1 and ip0[0] < ip2[0] < body.index(prods[0]), (forms, pg_)
                    # nothing writes an address register, the loop's registers, the B fragments, the second base or the unit scale
                    wr = set()
                    for a in body:
                        wr.update(sf_rw(a)[3])
                    assert not (wr & {0, 1, 2, 3, 4, 5, 9, 11, 16, 17, 18, 19, 20, 21, 22, 23, lay_["b1"], lay_["b1"] + 1, lay_["b2"], lay_["b2"] + 1, lay_["base2"], lay_["one"]}), (forms, sorted(wr))
                    sf_audit(rv, body)
                    text = kernel_text("selftest_x", dict(rv, _threads=256), 188, body, 49152)
                    assert misaligned(text) == [] and "    .reg R0-R79\n    .regcount 88\n" in text, forms
                    assert max(int(x) for x in re.findall(r"(?<![UA-Za-z])R(\d+)", text.split(".shared")[1])) <= SET_REGS - 1, forms
                    assert (f"MOV R{lay_['one']}, 0x7f7f7f7f ;" in text) == (ns_ == 1), forms
                    if (wt_, rd_) == ("reader", None):
                        ref_ = ref_ or {}
                        ref_[d_] = body
                    elif (wt_, rd_) == ("end", None):      # the control = the test but for two control codes: the first reader's wait bit and the word behind the reader words
                        rb_ = ref_[d_]
                        assert len(rb_) == len(body) and all(a.text == c.text and a.sem == c.sem for a, c in zip(rb_, body)), (forms, pg_)
                        assert [k_ for k_, (a, c) in enumerate(zip(rb_, body)) if a.ctl != c.ctl] == [ifirst, ilast + 1], (forms, pg_)
    # the audit has teeth: six bodies it must refuse
    rq = normalise({"id": "xx", "kind": "ord", "forms": "S,S", "barrier": "all", "yield": "set", "pguard": "cc", "distances": "1,4", "occupancy": ["w8"]})
    b0_ = body_ord(rq, 4, "none", "bare")
    re_ = lambda a, st: Ins(a.text, a.sem, ctl=a.ctl[:-3] + f"{st:02d}]", tag=a.tag, dst=a.dst)
    ix_ = lambda pre: next(k_ for k_, a in enumerate(b0_) if a.text.startswith(pre))
    k14, kp0, kp2, kr2 = ix_("IMAD R14, R11,"), ix_("ISETP.GE.AND P0,"), ix_("ISETP.GE.AND P2,"), ix_("@P2 QMMA")
    assert b0_[k14 + 1].text.startswith("SHF.L.U32 R14, R14,") and kp2 == kp0 + 1 and all(a.sem == ("nop",) for a in b0_[kp2 + 1:kp2 + 3]) and all(a.sem == ("nop",) for a in b0_[kr2 + 1:kr2 + 3])
    muts_ = {"a consumer one cycle behind its fixed-latency producer": b0_[:k14] + [re_(b0_[k14], 1)] + b0_[k14 + 1:],
             "a guard 8 cycles behind its ISETP": b0_[:kp0] + [re_(b0_[kp0], 1), re_(b0_[kp2], 1)] + b0_[kp2 + 3:],
             "a rewrite one cycle behind a tensor word": b0_[:kr2] + [re_(b0_[kr2], 1), Ins(f"MOV R32, 0x{SF_MARK:x} ;", ("mov", "R32", SF_MARK))] + b0_[kr2 + 1:],
             "a tensor result read 17 cycles behind its word": b0_[:kr2] + [re_(b0_[kr2], 1)] + b0_[kr2 + 3:],
             "a load's result read by a word that is no reader": b0_[:kr2 + 1] + [Ins("IADD3 R13, PT, PT, R32, 0x1, RZ ;", ("nop",))] + b0_[kr2 + 1:]}
    rm_ = normalise({"id": "xx", "kind": "ord", "forms": "D,D,S,D", "barrier": "all", "yield": "set", "pguard": "cc", "lead": "mov", "distances": "1,4", "occupancy": ["w8"]})
    bm0_ = body_ord(rm_, 4, "none", "bare")
    km_ = max(k_ for k_, a in enumerate(bm0_) if a.tag == "C3")
    tm_ = sf_layout(set_plan(rm_))["tmp"]
    kf_ = next(k_ for k_, a in enumerate(bm0_) if a.text.startswith(f"IMAD R8, R{tm_},"))
    assert bm0_[km_ + 1].tag == "C" and kf_ > km_
    sf_audit(rm_, bm0_)
    for why_, (rr_, bm_) in dict({k_: (rq, v_) for k_, v_ in muts_.items()},
                                 **{"a MOV temporary rewritten one cycle in front of the fold's read": (rm_, bm0_[:kf_] + [Ins(f"MOV R{tm_}, R5 ;", ("nop",), ctl=C(1))] + bm0_[kf_:])}).items():
        try:
            sf_audit(rr_, bm_)
            raise AssertionError(f"sf_audit took a body it must refuse: {why_}")
        except SystemExit:
            pass
    for bad in ({"forms": "S,S"}, {"forms": "S,s", "pguard": "tt"}, {"forms": "gS,S", "pguard": "tt"}, {"forms": "S,S,S,S,S", "pguard": "tt"}, {"forms": "S", "pguard": "tt"},
                {"forms": "S,S", "pguard": "tx"}, {"forms": "S,S", "pguard": "tt", "barrier": "last"}, {"forms": "S,S", "pguard": "tt", "wait": "none"},
                {"forms": "S,S", "pguard": "tt", "cold": "set"}, {"forms": "S,S", "pguard": "tt", "rdist": 0}, {"forms": "S,S", "pguard": "tt", "rdist": 301},
                {"forms": "S,S", "pguard": "tt", "front": ["sts128x15@4"]}, {"forms": "S,S", "pguard": "tt", "controls": True}, {"forms": "S,S", "pguard": "cc", "pshift": 1},
                {"forms": "S,G", "pguard": "tt"}, {"forms": "S,S", "pguard": "tt", "occupancy": ["w32"]}, {"forms": "D,D", "pguard": "tt"}, {"forms": "S,D,D,D,D", "pguard": "tt"},
                {"forms": "S,S", "pguard": "tt", "lead": "mov"}, {"forms": "S,D", "pguard": "tt", "lead": "qmma"}, {"forms": "S,d", "pguard": "tt"}, {"forms": "S,S,S,S,D,D,D,S", "pguard": "tt"}):
        try:
            normalise(dict({"id": "xx", "kind": "ord", "barrier": "all", "yield": "set"}, **bad))
            raise AssertionError(f"a request that must be refused was taken: {bad}")
        except SystemExit:
            pass
    print(f"selftest: {n} (pair, hypothesis) models equal the scalar interpreter on {len(gids)} threads; `good` differs from every failure hypothesis")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen")
    g.add_argument("requests")
    g.add_argument("--out", required=True)
    g.add_argument("--cubit", default=DEF_CUBIT)
    g.add_argument("--table", default=DEF_TABLE)
    g.add_argument("--dep-table", default=DEF_DEP)
    g.add_argument("--jobs", type=int, default=12)
    r = sub.add_parser("run")
    r.add_argument("batch")
    r.add_argument("--reps", type=int, default=0)
    r.add_argument("--limit-s", type=float, default=600)
    r.add_argument("--only", default="")
    r.add_argument("--child", action="store_true", help="(internal) one request in its own process")
    r.add_argument("--no-isolate", action="store_true", help="all requests in ONE process (a trapped kernel then ends the batch)")
    f = sub.add_parser("floor")
    f.add_argument("paths", nargs="+")
    ad = sub.add_parser("adapt")
    ad.add_argument("paths", nargs="+")
    ad.add_argument("--out", required=True)
    sub.add_parser("list")
    sub.add_parser("selftest")
    a = ap.parse_args()
    return {"gen": cmd_gen, "run": cmd_run, "floor": cmd_floor, "list": cmd_list, "selftest": cmd_selftest, "adapt": cmd_adapt}[a.cmd](a)


if __name__ == "__main__":
    raise SystemExit(main())

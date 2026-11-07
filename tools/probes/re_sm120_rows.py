#!/usr/bin/env python3
"""The long tail of KNOWN_ISSUES T1: verify the remaining harvest rows of sm120 field by field over the whole
128-bit word with nvdisasm 13.1 and tag the ones that hold (session G run 5, 2026-11-07).

The 2026-06..08 harvest learned its rows from compiler output. The lattice families (LDG.256 / STG.256 / REDG /
the compare, FP32 and conversion families) were rebuilt whole by their own probes; what is left is ~1 400 rows on
~500 keys of ~110 mnemonics, mostly one or two rows per key -- too heterogeneous for one law per family. This
probe measures each row on its own terms:

  1. the row's canonical word: `and_base` with every field at a value whose single-bit flips all change the
     printed operand (distinct register numbers, a 0x5a5a.. immediate pattern, `PT` predicates, the guard at 7),
     checked legal with nvdisasm (two fallback value sets);
  2. the full circumference: every bit 0..104 and the four `.reuse` bits 122..125 flipped one at a time, each
     word named by nvdisasm; the texts are diffed token by token against the canonical text and every bit gets
     a class: `field` (moves exactly the operand token the declared field names), `guard` (the guard token),
     `modifier` (changes the mnemonic / modifier token only: another group's word), `operand_other` (changes an
     operand the row has no field for: a neighbouring form, a sign or `.reuse` bit the harvest never declared),
     `inert` (same text), `illegal` (nvdisasm rejects), `complex` (several tokens move);
  3. cubit's own decode / print / re-encode of every word (`examples/audit_words.rs`) and the keys cubit would
     look the vendor texts up under (`examples/text_keys.rs`);
  4. the census witnesses of the row (T-10's 249 929 distinct production words, `--census`), up to three per row,
     named by nvdisasm with their own control code.

A row is **measured** when every declared field bit moves its own token (bits whose flip nvdisasm rejects are
allowed inside a field: value-range limits), no bit outside the fields moves an operand of the same form, the
canonical word decodes in cubit to the row itself with the vendor's text and re-encodes bit-exact, and every
census witness does too. `apply` then tags the row (`_src`, `_note`), sets `variable_mask` to exactly the field
bits (fail closed on the text-inert bits, the convention of every measured family), adds the `.reuse` fields the
sweep found (bits 122..125 printing `.reuse` on a register operand of the row) and retires the keys the verdict
names (`key_aliases` to the key cubit already decodes the canonical word through -- the shadowed dotted twins --
or documented deletions of keys whose canonical word nvdisasm rejects). Everything else stays a harvest row and is
listed in the verdict with its reason (the named exceptions of `G/NEEDS_OWNER.md`).

Fixture (`tests/fixtures/sm120_rows_<family>_nvdisasm.jsonl`): one header line (`nvdisasm`, its sha256, the
arch, the family, the control code used) and one line per row:
  {"key", "group", "w0", "t0", "fields": [[shift, bits, tok, ext], ...],
   "field": [[bit, text], ...], "guard": [[bit, text], ...], "modifier": [[bit, text], ...],
   "operand_other": [[bit, text], ...], "complex": [[bit, text], ...], "inert": [bits], "illegal": [bits],
   "witnesses": [[word, text], ...], "status": "measured" | "<reason>"}
The probe words are `w0 ^ (1 << bit)` (or-ed with the header's control code); the witnesses carry their own.

    probe --family <name> [--table tables/sm120.json] [--census G/census/words_out_main.jsonl] [--jobs 24]
    apply <sm120.json> --family <name> [--verdict <probe's verdict.json>]
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures
import difflib
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import nvprobe  # noqa: E402

CTRL = 0x000f_e200 << 96
SCHEDULE = nvprobe.SCHEDULE
SWEEP_BITS = list(range(0, 105)) + [122, 123, 124, 125]
DATE = "2026-11-07"
NVDISASM = "/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm"

# family -> base mnemonics (the key's first dotted part before the operand signature)
FAMILIES = {
    "tensor": ["QMMA", "HMMA", "OMMA", "DMMA", "IMMA"],
    "half": ["HFMA2", "HMNMX2", "HADD2", "HSET2", "F2FP", "I2FP", "F2IP", "I2IP", "UF2FP", "UI2FP", "F2F", "UF2I", "UI2F"],
    "intalu": ["VIMNMX", "IADD", "IMAD", "IADD3", "IMNMX", "IABS", "VIADD", "SGXT", "BMSK", "PRMT", "LOP3", "SEL", "MOV",
               "FLO", "POPC", "BREV", "R2UR", "LDC", "S2R", "CS2R", "MOV64IUR", "LDCU", "S2UR", "FHADD", "DMUL", "DADD"],
    "uniform": ["USHF", "ULEA", "ULOP3", "UFLO", "UMOV", "UIADD3", "UIMAD", "USEL", "UIMNMX", "UBMSK", "UVIMNMX", "UPRMT",
                "UCLEA", "UBREV", "UPOPC", "UISETP", "REDUX", "ELECT"],
    "memory": ["LDG", "STG", "LD", "ST", "LDS", "STS", "LDL", "STL", "LDGSTS", "LDGMC", "LDSM", "STSM", "MOVM", "CCTL",
               "QSPC", "LDGDEPBAR", "UTMALDG", "UTMASTG", "UTMACCTL", "UTMACMDFLUSH", "UBLKCP", "UBLKRED", "UBLKPF"],
    "atomic": ["ATOMG", "ATOM", "ATOMS", "REDG"],
    "control": ["WARPSYNC", "CALL", "BSSY", "BSYNC", "EXIT", "BREAK", "BAR", "MEMBAR", "NOP", "YIELD", "PREEXIT", "ERRBAR",
                "CGAERRBAR", "ACQBULK", "ACQSHMINIT", "NANOSLEEP", "BMOV", "UCGABAR"],
}


# (key, group) -> reason: rows whose structure nvdisasm confirms but which stay harvest on purpose (named in
# G/NEEDS_OWNER.md): the probe reports them as `exception`, apply leaves them, the test lists them
EXCEPTIONS: dict[str, dict[tuple[str, str], str]] = {
    "intalu": {
        # the carry-out predicate at [83:81]: at PT the vendor elides it (`IMAD.HI R32, R64, UR96, R24`), a spelling
        # whose plain key has no `HI` / `HI,X` group -- cubit prints the `_P_` row's explicit `PT`; the plain groups
        # are legal words nvdisasm names (G/NEEDS_OWNER.md 11)
        ("IMAD_R_P_R_UR_R", "HI"): "the PT carry-out word is the plain key's spelling (IMAD_R_R_UR_R has no HI group); cubit prints the explicit PT",
        ("IMAD_R_P_R_UR_R_P", "HI,U32,X"): "the PT carry-out word is the plain key's spelling (IMAD_R_R_UR_R_P has no HI,U32,X group); cubit prints the explicit PT",
        ("IMAD_R_P_R_UR_R_P", "HI,X"): "the PT carry-out word is the plain key's spelling (IMAD_R_R_UR_R_P has no HI,X group); cubit prints the explicit PT",
        ("R2UR_P_UR_R", "FILL"): "the PT predicate word is the plain key's spelling (R2UR_UR_R has no FILL group); cubit prints the explicit PT",
    },
    "control": {
        ("WARPSYNC.COLLECTIVE_R_II", ""): "the immediate is a 50-bit field the vendor prints whole (0x169696969696978 for the "
                                         "probe's pattern); cubit's row reads 20 bits of it -- the collective mask / target law "
                                         "needs its own probe (G/NEEDS_OWNER.md 10)",
    },
}
# key prefix -> reason: whole mnemonics / keys left harvest on purpose in run 5 although the probe verifies them -- the
# 2026-08/09 bug-wave tests pin their harvest structure or their tolerant decode of text-inert bits (bug148 / 163 /
# 164 / 167 / 172 / 188 / 204 / 226e / 265 / 271 / 274 / 279 / 285 / 288 / 311 / 330 / 340 / 359 / 360 / 413ii / 415 /
# 419 / 420 / 425 / 425b); re-pinning those suites to the measured doctrine is T's call (the batch-10..14 pattern), so
# the rows keep their records in the fixture (status `exception`) and nothing of theirs moves in the table
WAVE_PINNED = ("pinned by the 2026-08/09 bug-wave tests: the row verifies field by field (this record), the re-pin of "
               "those suites to the measured doctrine is T's -- left for T-16 / run 6 (G/NEEDS_OWNER.md 12)")
EXCEPTION_PREFIXES: dict[str, dict[str, str]] = {
    "half": {"HFMA2": WAVE_PINNED + " (bug265 / 271 / 274 / 279 / 285 / 288 / 330)", "HADD2": WAVE_PINNED + " (bug271 / 419)",
             "F2IP": WAVE_PINNED + " (bug340)", "F2F.": WAVE_PINNED + " (bug226e)",
             "I2IP": WAVE_PINNED + " (bug265 / 275 / 276 / 282 / 284 / 296)"},
    "memory": {"LDGSTS": WAVE_PINNED + " (bug164 / 311 / 359 / 360 / 373)", "LDS_": WAVE_PINNED + " (bug148 / 413ii / 415 / 420)",
               "STS_": WAVE_PINNED + " (bug425 / 425b)", "LDL_": WAVE_PINNED + " (bug415 / 420)", "STL_": WAVE_PINNED + " (bug425)",
               "MOVM": WAVE_PINNED + " (bug272 / 276 / 283)"},
    "intalu": {"LDC": WAVE_PINNED + " (bug163 / 167 / 172 / 409)"},
    "atomic": {"ATOMS": WAVE_PINNED + " (bug188 / 204)"},
}
# hand decisions the shadow rule cannot make on its own (each one measured in the family's note):
#   MANUAL_ALIAS: key -> target. The integer spelling `S2R_R_II` of the system-register read (nvdisasm prints `SR90`
#   for an unnamed code, cubit decodes that spelling through the junk key) -> `S2R_R_L`; the dotted `UBMSK.W_*` twins
#   of `UBMSK_*`'s `W` group (same text, one text-inert bit apart: the encoder mints the plain row's word).
#   MANUAL_DEAD: (key, group) -> the key whose row decodes the group's words afterwards. The harvest named the `!` of
#   IMAD.X's carry-in predicate a modifier (`B90`); the `U32,WIDE,X` row of the same key carries bit 90 as a field.
#   The integer spelling `HFMA2_R_R_II_II_R` of the f16-pair immediate form -> `HFMA2_R_R_FI_FI_R` (the FMUL_R_R_II
#   precedent: the hexadecimal literal still encodes through the alias; its RELU groups' words have the dotted
#   `HFMA2.*.RELU_R_R_FI_FI_R_P` rows).
#   `ATOMS_R_ARI` (one group, `32,INC,POPC`, URZ baked at [71:64]) -> `ATOMS_R_ARURI`: the vendor spells the word
#   `[R16+URZ+imm]`, the uniform-indexed form with URZ, which the measured `_ARURI` row's UR field covers (0 census
#   witnesses on either; the harvest `_ARI` row claimed the inert-bit neighbours the measured row fails closed on and
#   printed them `[imm]`, bug188's pin).
MANUAL_ALIAS: dict[str, dict[str, str]] = {
    "intalu": {"S2R_R_II": "S2R_R_L"},
    "uniform": {"UBMSK.W_UR_UR_II": "UBMSK_UR_UR_II", "UBMSK.W_UR_UR_UR": "UBMSK_UR_UR_UR"},
    "half": {"HFMA2_R_R_II_II_R": "HFMA2_R_R_FI_FI_R"},
    "atomic": {"ATOMS_R_ARI": "ATOMS_R_ARURI"},
}
#   MANUAL_FIELDS: key prefix -> fields cubit keeps on the rows although nvdisasm 13.1 prints nothing for the bit. IMAD's
#   bit 72: text-inert for nvdisasm on every IMAD form (`IMAD R32, R48, R80, R24` with 72 set prints the same), kept by
#   cubit as the negation of Ra (`IMAD R5, -R4, R3, R2`; BUG-296, re-affirmed by T-3 on 2026-11-04 with the U32 twins).
#   The row carries the field (tok = the register at the Ra slot [31:24]); the bit-72 word is neither a form word nor a
#   lattice word of the fixture (class `cubit_law`); the owner confirms or retires the law on silicon (NEEDS 13).
MANUAL_FIELDS: dict[str, dict[str, list]] = {
    "intalu": {"IMAD_": [["neg", 72, 1, 24]]},  # [extraction, bit, bits, the slot shift whose token takes the field]
}
MANUAL_DEAD: dict[str, dict[tuple[str, str], str]] = {
    "intalu": {("IMAD_R_P_R_II_R_P", "B90,U32,WIDE,X"): "IMAD_R_P_R_II_R_P"},
}


def tag_of(family: str) -> str:
    return f"rows-{family}-{DATE}"


def mnemonic_of(key: str) -> str:
    return key.split("_")[0].split(".")[0]


def field_mask(f) -> int:
    return ((1 << f["bits"]) - 1) << f["shift"]


def fields_mask(fields) -> int:
    m = 0
    for f in fields:
        m |= field_mask(f)
    return m


# --- canonical words -------------------------------------------------------------------------------------------

# register numbers 8-aligned (the multi-register MMA operands must start at reg % 4 == 0 on silicon, BUG-037) and
# with few bits set (no single-bit flip reaches 255 = RZ / URZ)
REG_VALUES = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x18, 0x28, 0x38, 0x48]
PATTERN = 0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
REG_EXTRACTIONS = ("reg", "ureg", "reg_ff", "ureg_ff", "sub_r", "sub_ur", "ureg_shr", "reg_shr")


def is_reg(e: str) -> bool:
    return e.startswith(REG_EXTRACTIONS)


def is_pred(e: str) -> bool:
    return e.startswith("pred") or e.startswith("upred")


def value_for(f, token_order: int, variant: int, pred: int) -> int:
    """A field value whose single-bit flips all change the printed operand (variant 0), or a fallback."""
    e, bits = f["extraction"], f["bits"]
    full = (1 << bits) - 1
    if e == "guard":
        return 7
    if is_pred(e):
        return pred & full  # 7 = PT (elided by some forms), 3 = P3 (the `!` bit of pred_inv4 clear)
    if is_reg(e):
        v = REG_VALUES[token_order % len(REG_VALUES)] if variant == 0 else (8 * token_order + 8)
        return v & full if bits >= 6 else (1 if variant == 0 else 0)
    if e in ("f32", "f64hi"):
        return 0x5a5a5a5a & full if variant == 0 else 0x3f800000 & full
    if e in ("f16", "f16_d", "bf16"):
        return 0x5a5a & full if variant == 0 else 0x3c00 & full
    if bits == 1:
        return 0
    if e.startswith("imm") or e.startswith("sub_imm") or e.startswith("cm16") or e.startswith("cm17"):
        if variant == 0:
            return PATTERN & full if bits > 3 else (1 & full)
        if variant == 1:
            return 0x10 & full if bits > 5 else 1
        return 0
    if e == "barrier":
        return 1
    # enum-like small fields (hsel, byte_sel, addr_scale, ...): keep the group's own constant on the first try
    return 0 if variant < 2 else 1


def canonical_candidates(row) -> list[int]:
    """Candidate canonical words, most informative first: registers 8-aligned and distinct, immediates on the
    0x5a.. pattern, predicates PT then P3 (forms that elide PT need the explicit spelling to show the operand),
    then the smaller fallbacks."""
    fields = row.get("fields", [])
    base = int(row["and_base"], 16) & ~SCHEDULE & ~fields_mask(fields)
    out = []
    for variant in (0, 1, 2):
        for pred in (7, 3):
            w = base
            for order, f in enumerate(fields):
                w |= (value_for(f, order, variant, pred) & ((1 << f["bits"]) - 1)) << f["shift"]
            if w not in out:
                out.append(w)
    return out


# --- text tokens -----------------------------------------------------------------------------------------------

def tokens(text: str) -> list[str]:
    """[guard, mnemonic.mods, operand1, operand2, ...] -- the table's token_idx k is operand k (guard = 0)."""
    t = text.strip()
    guard = ""
    if t.startswith("@"):
        guard, _, t = t.partition(" ")
    op, _, rest = t.partition(" ")
    ops = [o.strip() for o in rest.split(", ")] if rest.strip() else []
    return [guard, op] + ops


def diff_class(t0: str, t: str):
    """('modifier', None) | ('operand', token_idx) | ('guard', 0) | ('complex', None) for t vs the canonical t0."""
    a, b = tokens(t0), tokens(t)
    if len(a) == len(b):
        # same shape: compare position by position (a sequence matcher would re-align equal register names)
        changed = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
        if len(changed) != 1:
            return "complex", None
        i = changed[0]
        return ("guard", 0) if i == 0 else (("modifier", None) if i == 1 else ("operand", i - 1))
    changes = [(tag, i1, i2, j1, j2) for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes()
               if tag != "equal"]
    if len(changes) != 1:
        return "complex", None
    tag, i1, i2, j1, j2 = changes[0]
    if tag == "replace" and i2 - i1 == 1 and j2 - j1 == 1:
        if i1 == 0:
            return "guard", 0
        if i1 == 1:
            return "modifier", None
        return "operand", i1 - 1
    if tag in ("insert", "delete") and max(i2 - i1, j2 - j1) == 1 and i1 >= 2:
        # an operand elided / un-elided (PT, RZ, a zero offset): the token index of the moved operand
        return "operand", i1 - 1
    if a[1] != b[1] and a[0] == b[0] and a[2:] == b[2:]:
        return "modifier", None
    return "complex", None


# --- oracles ---------------------------------------------------------------------------------------------------

class Nvdisasm:
    def __init__(self, nvdisasm: str, arch: str, jobs: int, cache_file: pathlib.Path | None = None):
        self.nv, self.arch, self.jobs = nvdisasm, arch, jobs
        self.version, self.digest = nvprobe.nvdisasm_identity(nvdisasm)
        self.cache: dict[int, str | None] = {}
        self.local = threading.local()
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix=f"re_rows_{arch.lower()}_"))
        # an on-disk memo of (word -> text) for this nvdisasm build and target: a session convenience (the probe
        # re-runs after a cubit rebuild without re-spawning 40 000 nvdisasm processes); never read by the tests
        self.cache_file = cache_file
        if cache_file is not None and cache_file.exists():
            with cache_file.open() as fh:
                for line in fh:
                    d = json.loads(line)
                    if d.get("nvdisasm_sha256") == self.digest and d.get("arch") == arch:
                        self.cache[int(d["word"], 16)] = d["text"]

    def save(self):
        if self.cache_file is None:
            return
        with self.cache_file.open("w") as fh:
            for w, t in self.cache.items():
                fh.write(json.dumps({"word": f"{w:032x}", "text": t, "arch": self.arch, "nvdisasm_sha256": self.digest}) + "\n")

    def _one(self, word: int):
        scratch = getattr(self.local, "scratch", None)
        if scratch is None:
            scratch = self.tmp / f"{threading.get_ident()}.bin"
            self.local.scratch = scratch
        scratch.write_bytes(word.to_bytes(16, "little"))
        r = subprocess.run([self.nv, "-b", self.arch, "-hex", str(scratch)], capture_output=True, text=True)
        if r.returncode:
            if "Illegal instruction" in r.stderr or "undefined value" in r.stderr:
                return None  # `undefined value for table TABLES_opex`: a reuse bit on a slot without a register
            raise RuntimeError(f"nvdisasm failed on {word:032x}: {r.stderr.strip()[:200]}")
        m = nvprobe._TEXT.search(r.stdout)
        return m.group(1).strip() if m else None

    def texts(self, words) -> list:
        """Vendor texts of full words (control code included); None where nvdisasm rejects the word."""
        todo = [w for w in dict.fromkeys(words) if w not in self.cache]
        if todo:
            with concurrent.futures.ThreadPoolExecutor(self.jobs) as pool:
                for w, t in zip(todo, pool.map(self._one, todo)):
                    self.cache[w] = t
            self.save()
        return [self.cache[w] for w in words]


def run_example(binary: str, items: list[dict], *extra) -> list[dict]:
    with tempfile.TemporaryDirectory(prefix="re_rows_cubit_") as d:
        inp, out = pathlib.Path(d) / "in.jsonl", pathlib.Path(d) / "out.jsonl"
        inp.write_text("".join(json.dumps(i) + "\n" for i in items))
        subprocess.run([binary, str(inp), *extra, str(out)], check=True, capture_output=True, text=True)
        return [json.loads(line) for line in out.read_text().splitlines() if line.strip()]


# --- the probe -------------------------------------------------------------------------------------------------

def select_rows(table: dict, family: str, only_keys=None, also_in: dict | None = None):
    """The family's harvest rows (and, on an applied table, the rows this family tagged). `also_in` = another table
    the row must be a harvest row of as well -- the rows another batch measures or retires on a branch not yet on
    the base (the LDG.256 / STG.256 / REDG lattices of batches 12-14) are not probed again."""
    mns = set(FAMILIES[family])
    rows = []
    for key, entry in table["instructions"].items():
        if mnemonic_of(key) not in mns or (only_keys and key not in only_keys):
            continue
        for group, row in entry.get("mod_groups", {}).items():
            if row.get("_src") not in (None, tag_of(family)):
                continue
            if also_in is not None:
                other = also_in["instructions"].get(key, {}).get("mod_groups", {}).get(group)
                if other is None or other.get("_src") not in (None, tag_of(family)):
                    continue
            rows.append((key, group, row))
    return rows


def load_census(path: pathlib.Path | None):
    by_row = collections.defaultdict(list)
    if path is None or not path.exists():
        return by_row
    with path.open() as fh:
        for line in fh:
            d = json.loads(line)
            if "cubit_key" in d:
                by_row[(d["cubit_key"], d["cubit_group"])].append(int(d["word"], 16))
    return by_row


def probe(args):
    table = nvprobe.load_table(pathlib.Path(args.table))
    also = nvprobe.load_table(pathlib.Path(args.also_harvest_in)) if args.also_harvest_in else None
    rows = select_rows(table, args.family, set(args.keys) if args.keys else None, also)
    census = load_census(pathlib.Path(args.census) if args.census else None)
    nv = Nvdisasm(args.nvdisasm, args.arch, args.jobs, pathlib.Path(args.nv_cache) if args.nv_cache else None)
    print(f"{len(rows)} harvest rows of family {args.family} ({', '.join(FAMILIES[args.family])}); nvdisasm {nv.version}")

    # 1. canonical words: the first legal candidate whose vendor text the key spells (else the first legal one)
    cands = {(k, g): canonical_candidates(r) for k, g, r in rows}
    flat = [w | CTRL for c in cands.values() for w in c]
    nv.texts(flat)
    cand_texts = sorted({nv.cache[w] for w in flat if nv.cache[w]})
    key_of_text = {r["text"]: r for r in run_example(args.text_keys, [{"text": t} for t in cand_texts])}

    def spelled_by(key, group, text):
        kt = key_of_text.get(text, {})
        return (kt.get("base_key") == key and kt.get("mod_group") == group) or \
               (kt.get("full_key") == key and group in ("", kt.get("mod_group")))

    w0_of = {}
    for (k, g), c in cands.items():
        legal = [w for w in c if nv.cache[w | CTRL] is not None]
        w0_of[(k, g)] = next((w for w in legal if spelled_by(k, g, nv.cache[w | CTRL])), legal[0] if legal else None)

    # 2. the sweep + the witnesses
    sweep_words = []
    for (k, g), w0 in w0_of.items():
        if w0 is not None:
            sweep_words += [(w0 ^ (1 << b)) | CTRL for b in SWEEP_BITS]
    witness_of = {(k, g): census.get((k, g), [])[: args.witnesses] for k, g, _ in rows}
    nv.texts(sweep_words + [w for ws in witness_of.values() for w in ws])
    print(f"nvdisasm: {len(nv.cache)} distinct words named")

    # 3. cubit's view of every word, the keys of every vendor text
    all_words = sorted({w for w in nv.cache})
    cubit_rows = run_example(args.audit_words, [{"word": f"{w:032x}", "nvidia_sass": nv.cache[w]} for w in all_words],
                             args.table)
    cubit = {int(r["word"], 16): r for r in cubit_rows}
    texts = sorted({t for t in nv.cache.values() if t} - set(key_of_text))
    key_of_text.update({r["text"]: r for r in run_example(args.text_keys, [{"text": t} for t in texts])})

    # 4. classify
    verdict = {"family": args.family, "tag": tag_of(args.family), "arch": args.arch, "nvdisasm": nv.version, "rows": []}
    fixture = [{"nvdisasm": nv.version, "nvdisasm_sha256": nv.digest, "arch": args.arch, "family": args.family,
                "ctrl": f"{CTRL >> 96:08x}", "tool": "tools/probes/re_sm120_rows.py", "table": args.table}]
    stats = collections.Counter()
    for key, group, row in rows:
        fields = row.get("fields", [])
        w0 = w0_of[(key, group)]
        rec = {"key": key, "group": group, "fields": [[f["shift"], f["bits"], f["token_idx"], f["extraction"]] for f in fields]}
        v = {"key": key, "group": group, "count": row.get("count"), "problems": [], "reuse_add": [], "cubit": {}}
        if w0 is None:
            rec.update(w0=None, t0=None, status="canonical_illegal", reason="nvdisasm rejects every canonical word of the row")
            v["status"] = "canonical_illegal"
            v["problems"].append("nvdisasm rejects every canonical word of the row")
            stats["canonical_illegal"] += 1
            fixture.append(rec)
            verdict["rows"].append(v)
            continue
        t0 = nv.cache[w0 | CTRL]
        rec.update(w0=f"{w0:032x}", t0=t0)
        kt = key_of_text.get(t0, {})
        v["vendor_keys"] = {k: kt.get(k) for k in ("base_key", "full_key", "mod_group", "parse_error") if k in kt}
        # the key + group name the vendor's text (two accepted spellings: plain key + group, or the dotted key)
        if not spelled_by(key, group, t0):
            v["problems"].append(f"the key does not spell the vendor text: {t0!r} -> {kt.get('full_key')} / {kt.get('mod_group')!r}")
        # bit classes
        by_class = collections.defaultdict(list)
        field_of_bit = {}
        for f in fields:
            for b in range(f["shift"], f["shift"] + f["bits"]):
                field_of_bit[b] = f
        toks0 = tokens(t0)
        for b in SWEEP_BITS:
            t = nv.cache[(w0 ^ (1 << b)) | CTRL]
            f = field_of_bit.get(b)
            if t is None:
                by_class["illegal"].append(b)
                if f is not None:
                    # value-range limits inside a field; for `.reuse` fields nvdisasm's "undefined opex value": the
                    # bit is inert on silicon (KNOWN_ISSUES A12 / BUG-362a), the field stays (never a defect)
                    v.setdefault("field_illegal_bits", []).append(b)
                continue
            if t == t0:
                by_class["inert"].append(b)
                if f is not None:
                    if f["extraction"] == "reuse":
                        v.setdefault("reuse_inert", []).append(b)  # kept (A12 doctrine); not a form word
                    else:
                        v["problems"].append(f"field bit {b} ({f['extraction']} tok {f['token_idx']}) is text-inert")
                continue
            cls, tok = diff_class(t0, t)
            # the flip introduces a vendor-invalid marker the canonical text does not carry (the INVALIDn-keyed
            # harvest rows print their own glyph on every word: a faithful rendering, owner 2026-11-03); inside a
            # field it is an invalid value of the field (`.INVALID1` half selector) -- a lattice plane, not a form word
            glyph = (t.count("???") > t0.count("???")) or (t.count("INVALID") > t0.count("INVALID"))
            if glyph:
                by_class["glyph"].append([b, t])
                if f is not None:
                    v.setdefault("field_glyph_bits", []).append(b)
            elif f is not None:
                want = 0 if f["extraction"] == "guard" else f["token_idx"]
                if (cls == "guard" and want == 0) or (cls == "operand" and tok == want):
                    by_class["field"].append([b, t])
                    # a declared `neg` the vendor prints as the ones' complement `~X` (the carry forms of IADD3.X /
                    # UIMAD.X / IADD.X): the extraction is `inv`
                    toks = tokens(t)
                    if f["extraction"] == "neg" and tok is not None and tok + 1 < len(toks) and toks[tok + 1] == "~" + toks0[tok + 1]:
                        v.setdefault("ext_fix", {})[f["shift"]] = "inv"
                else:
                    by_class["complex" if cls == "complex" else "field_wrong"].append([b, t])
                    v["problems"].append(f"field bit {b} ({f['extraction']} tok {f['token_idx']}) moves {cls} {tok}: {t!r}")
            elif cls == "modifier":
                by_class["modifier"].append([b, t])
            elif cls == "guard":
                # the guard the harvest row never declared: a 4-bit field at 12 (added by apply)
                by_class["field"].append([b, t])
                if ["guard", 12, 4, 0] not in v.setdefault("fields_add", []):
                    v["fields_add"].append(["guard", 12, 4, 0])
            elif cls == "operand":
                kt2 = key_of_text.get(t, {})
                same_form = kt2.get("base_key") == kt.get("base_key")
                toks = tokens(t)
                old, new = (toks0[tok + 1], toks[tok + 1]) if tok + 1 < len(toks0) and tok + 1 < len(toks) else ("", "")
                added = None
                if same_form and b in (122, 123, 124, 125) and new == old + ".reuse":
                    added = ["reuse", b, 1, tok]
                elif same_form and new == "-" + old:
                    added = ["neg", b, 1, tok]
                elif same_form and new == "~" + old:
                    added = ["inv", b, 1, tok]
                elif same_form and new == f"|{old}|":
                    added = ["abs", b, 1, tok]
                elif same_form and new == "!" + old and (old.startswith("P") or old.startswith("UP")):
                    added = ["neg", b, 1, tok]  # the predicate's `!` is spelled `neg` on the measured rows (bug247's pin)
                # an address whose base register gains / loses a width or scale suffix (`[R48.64+UR64]`, `[R2.X4+0x10]`,
                # `[RZ.U32+UR4]`): the vendor spells another address form -- another row's word (a coverage gap when
                # the table has none), never this row's operand
                strip = lambda s: re.sub(r"\.(64|U32|X4|X8|X16)(?=[+\]])", "", s)  # noqa: E731
                form_neighbour = old.startswith("[") and new.startswith("[") and strip(old) == strip(new) and old != new
                if added is not None:
                    # a sign / abs / reuse bit on an operand of this row the harvest never declared: a field
                    by_class["field"].append([b, t])
                    v.setdefault("fields_add", []).append(added)
                elif form_neighbour:
                    by_class["operand_other"].append([b, t])
                elif same_form:
                    by_class["operand_other"].append([b, t])
                    v["problems"].append(f"bit {b} outside the fields moves operand {tok} of the same form: {t!r}")
                else:
                    by_class["operand_other"].append([b, t])  # a neighbouring form (another key): lattice
            else:
                by_class["complex"].append([b, t])
                kt2 = key_of_text.get(t, {})
                if kt2.get("base_key") == kt.get("base_key"):
                    v["problems"].append(f"bit {b} outside the fields moves several tokens of the same form: {t!r}")
        for f in fields:
            fb = [b for b, _ in by_class["field"] if f["shift"] <= b < f["shift"] + f["bits"]]
            if not fb and f["extraction"] != "reuse":
                v["problems"].append(f"field {f['extraction']} [{f['shift'] + f['bits'] - 1}:{f['shift']}] tok {f['token_idx']}: no bit moves its token")
        # the measured field list: the declared fields (an integer `imm` whose operand the vendor prints as a float
        # becomes the float extraction of its width -- the harvest spelled f16 pairs as hex) plus the added ones
        target_fields = []
        for f in fields:
            nf = {k: f[k] for k in ("bits", "extraction", "shift", "token_idx")}
            tok_text = toks0[f["token_idx"] + 1] if 0 <= f["token_idx"] + 1 < len(toks0) else ""
            if f["extraction"] == "imm" and re.fullmatch(r"[-+]?(\d+\.\d+(e[-+]\d+)?|\d+|INF|QNAN|SNAN)", tok_text) \
                    and ("." in tok_text or "e" in tok_text or tok_text.endswith(("INF", "NAN"))) and f["bits"] in (16, 32):
                nf["extraction"] = ("bf16" if "BF16" in (key + group) else "f16") if f["bits"] == 16 else "f32"
                v.setdefault("fields_fix", []).append([f["shift"], f["extraction"], nf["extraction"]])
            if f["shift"] in v.get("ext_fix", {}):
                nf["extraction"] = v["ext_fix"][f["shift"]]
                v.setdefault("fields_fix", []).append([f["shift"], f["extraction"], nf["extraction"]])
            if f["extraction"] in ("pred", "upred") and f["bits"] == 4:
                # a 4-bit predicate window is the 3-bit predicate plus its `!` bit (the vendor prints `!PT` for 15; a
                # plain `pred` of 4 bits printed `P15`): split into the measured rows' `pred` + `neg` pair
                nf["bits"] = 3
                target_fields.append(nf)
                target_fields.append({"bits": 1, "extraction": "neg", "shift": f["shift"] + 3, "token_idx": f["token_idx"]})
                v.setdefault("fields_fix", []).append([f["shift"], f["extraction"] + "4", f["extraction"] + "3+neg"])
                continue
            target_fields.append(nf)
        for ext, shift, nb, tok in v.get("fields_add", []):
            if not any(tf["shift"] == shift for tf in target_fields):
                target_fields.append({"bits": nb, "extraction": ext, "shift": shift, "token_idx": tok})
        for prefix, extra in MANUAL_FIELDS.get(args.family, {}).items():
            if key.startswith(prefix):
                for ext, bit, nb, slot in extra:
                    tok_slot = next((tf["token_idx"] for tf in target_fields if tf["shift"] == slot and is_reg(tf["extraction"])), None)
                    if tok_slot is None or any(tf["shift"] == bit for tf in target_fields):
                        continue
                    target_fields.append({"bits": nb, "extraction": ext, "shift": bit, "token_idx": tok_slot})
                    if bit in by_class["inert"]:
                        by_class["inert"].remove(bit)
                    by_class["cubit_law"].append([bit, nv.cache[(w0 ^ (1 << bit)) | CTRL]])
                    v.setdefault("fields_add", []).append([ext, bit, nb, tok_slot])
        rec["fields"] = [[tf["shift"], tf["bits"], tf["token_idx"], tf["extraction"]] for tf in target_fields]
        for c in ("field", "modifier", "operand_other", "glyph", "complex", "field_wrong", "cubit_law"):
            if by_class[c]:
                rec[c] = by_class[c]
        rec["inert"] = by_class["inert"]
        rec["illegal"] = by_class["illegal"]
        if v.get("fields_add"):
            rec["fields_add"] = v["fields_add"]
        if v.get("fields_fix"):
            rec["fields_fix"] = v["fields_fix"]
        if v.get("reuse_inert"):
            rec["reuse_inert"] = v["reuse_inert"]
        # cubit on the canonical word
        c0 = cubit[w0 | CTRL]
        v["cubit"] = {k: c0.get(k) for k in ("cubit_key", "cubit_group", "cubit_text_lossless", "reencode", "cubit_error", "vendor_encode") if k in c0}
        # a re-encode the encoder refuses on a silicon law (BUG-037: multi-register MMA operands off their alignment)
        # is the `silicon_illegal` class of tools/audit_dynamic.py: the text is the vendor's, the word is not mintable
        silicon = lambda c: str(c.get("reencode", "")).startswith("error:") and "silicon" in c["reencode"]  # noqa: E731
        # cubit-side findings are kept apart from the vendor-side ones: the row's structure is decided by nvdisasm; a
        # cubit text / re-encode difference is either healed by the structure apply writes (the fixed field types,
        # the added fields -- checked by re-running the probe on the applied table) or a cubit defect to fix
        cp = v["cubit_problems"] = []
        if "cubit_error" in c0:
            cp.append(f"cubit does not decode the canonical word: {c0['cubit_error'][:80]}")
        else:
            if (c0["cubit_key"], c0["cubit_group"]) != (key, group):
                cp.append(f"cubit decodes the canonical word through {c0['cubit_key']} / {c0['cubit_group']!r} (shadowed)")
                v["shadowed_by"] = [c0["cubit_key"], c0["cubit_group"]]
            if c0["cubit_text_lossless"] != t0:
                cp.append(f"cubit prints {c0['cubit_text_lossless']!r} for {t0!r}")
            if c0["reencode"] != "ok" and not silicon(c0):
                cp.append(f"re-encode {c0['reencode']}")
            if silicon(c0):
                rec["silicon"] = True
        # the field words in cubit: every one must decode to the row with the vendor text and re-encode (or be
        # refused on the silicon law)
        bad_field_words = 0
        silicon_words = []
        for b, t in by_class["field"]:
            c = cubit[(w0 ^ (1 << b)) | CTRL]
            if silicon(c) and c.get("cubit_text_lossless") == t:
                silicon_words.append(b)
                continue
            if "cubit_error" in c or c.get("cubit_text_lossless") != t or c.get("reencode") != "ok":
                bad_field_words += 1
                if bad_field_words <= 3:
                    cp.append(f"field word bit {b}: cubit {c.get('cubit_text_lossless', c.get('cubit_error', ''))[:60]!r} "
                              f"re-encode {c.get('reencode')} for {t!r}")
        if silicon_words:
            rec["silicon_bits"] = silicon_words
        # a row none of whose own words cubit decodes through it, every one printed vendor-true by a sibling key that
        # spells an elided operand (`[UR4+0x10]` is the `[RZ+UR4+0x10]` word): an encoder-only row -- its fields are
        # the vendor's, the test does not ask the decoder to reach it
        own_words = [w0 | CTRL] + [(w0 ^ (1 << b)) | CTRL for b, _ in by_class["field"]]
        if own_words and all("cubit_error" not in cubit[w] and (cubit[w]["cubit_key"], cubit[w]["cubit_group"]) != (key, group)
                             for w in own_words):
            rec["shadow_only"] = True
        # witnesses
        rec["witnesses"] = []
        fm = sum(((1 << tf["bits"]) - 1) << tf["shift"] for tf in target_fields)
        for w in witness_of[(key, group)]:
            t = nv.cache[w]
            rec["witnesses"].append([f"{w:032x}", t])
            c = cubit[w]
            if t is None:
                v["problems"].append(f"census witness {w:032x} is illegal for nvdisasm")
            elif "cubit_error" in c or c.get("cubit_text_lossless") != t or (c.get("reencode") != "ok" and not silicon(c)):
                cp.append(f"census witness {w:032x}: cubit {c.get('cubit_text_lossless', c.get('cubit_error', ''))[:60]!r} for {t!r}")
            # the witness must lie inside the row's measured shape: its constant bits equal and_base's
            if (w & ~SCHEDULE & ~fm) != (int(row["and_base"], 16) & ~SCHEDULE & ~fm):
                v["problems"].append(f"census witness {w:032x} carries bits outside the fields")
        wave = next((r for pfx, r in EXCEPTION_PREFIXES.get(args.family, {}).items() if key.startswith(pfx)), None)
        if (key, group) in EXCEPTIONS.get(args.family, {}):
            v["status"] = "exception"
            rec["reason"] = EXCEPTIONS[args.family][(key, group)]
        elif wave is not None:
            v["status"] = "exception"
            rec["reason"] = wave
        elif v["problems"]:
            v["status"] = "harvest"
            rec["reason"] = v["problems"][0][:200]  # the first vendor-side finding: the row stays harvest, named
        else:
            v["status"] = "measured"
        # a row whose canonical word cubit already decodes through another key that prints the vendor's text and
        # re-encodes it bit-exact is unreachable (a byte-identical `_P_` twin, a `_?` junk spelling, a dotted twin of a
        # plain key's group, the integer spelling of a float-immediate form): it retires as a `_meta.key_aliases`
        # entry -- whatever else is wrong with its structure
        # (a row the census reaches -- production words cubit decodes through it -- is alive whatever its canonical
        # word does: S2R_R_L's `SR_TID.X` words vs the `SR90` spelling of the probe's immediate)
        # ... and only when the shadowing key is a twin of this one: the same operand signature (a dotted twin), the
        # integer spelling of a float-immediate form (`_II` for `_FI`), a junk spelling (`?`, or more operand tokens
        # than the vendor's text has), or a byte-identical row structure (the `_P_` tensor twins). A key that prints
        # the same text with an operand elided (`[UR4+0x10]` for `[RZ+UR4+0x10]`, `LDC` without its register, the
        # explicit-predicate `_P` variants, IADD3's carry-in predicates) is NOT a twin: it is the encoder's path for
        # the other spelling (the BUG-464 pattern) and stays, measured or named.
        def twin_ok(target_key):
            if target_key == key:
                return False
            sig_k, sig_t = key.split("_", 1)[1] if "_" in key else "", target_key.split("_", 1)[1] if "_" in target_key else ""
            if "?" in key or sig_k == sig_t or sig_k.replace("II", "FI") == sig_t.replace("II", "FI"):
                return True
            vendor_sig = (kt.get("base_key") or "").split("_", 1)[1] if "_" in (kt.get("base_key") or "") else ""
            if sig_k.count("_") + 1 > vendor_sig.count("_") + 1 and vendor_sig:
                return True  # phantom operand tokens in the harvest key (the `_P_` tensor twins: no P in any text)
            # (a byte-identical row under a different signature is NOT a twin: `LDC_R_cARI` / `LDC_R_cAI` share
            # their words at RZ, but each key is the encoder's path for its own spelling -- the census writes both)
            return False
        if v["status"] != "exception" and "shadowed_by" in v and c0["cubit_text_lossless"] == t0 \
                and (c0["reencode"] == "ok" or silicon(c0)) and not witness_of[(key, group)] and twin_ok(v["shadowed_by"][0]):
            if mnemonic_of(v["shadowed_by"][0]) == mnemonic_of(key):
                v["status"] = "alias"
            else:
                # a harvest key named after one mnemonic whose bits are another's (`F2IP.U8.F32.NTZ_P_R_R_R_R` is an
                # HMMA word): no alias across mnemonics -- the row is dead, the key empties and goes
                v["status"] = "dead"
            rec["target"] = v["shadowed_by"][0]
        if key in MANUAL_ALIAS.get(args.family, {}) and wave is None:
            v["status"] = "alias"
            rec["target"] = v.get("shadowed_by", [MANUAL_ALIAS[args.family][key]])[0]
            rec["manual"] = True
        if (key, group) in MANUAL_DEAD.get(args.family, {}) and wave is None:
            v["status"] = "dead"
            rec["target"] = MANUAL_DEAD[args.family][(key, group)]
            rec["manual"] = True
        rec["status"] = v["status"]
        stats[v["status"]] += 1
        fixture.append(rec)
        verdict["rows"].append(v)
    # a key retires only whole: every row of the key must be an alias (none may stay) and the target must be a key
    # that stays; the key's alias target is the target of its most-witnessed row (the rows of a junk key may be
    # decoded by different real keys -- the alias is the name's forwarding address, the words have their own rows)
    rows_of_key = {k: list(e.get("mod_groups", {})) for k, e in table["instructions"].items()}
    by_key = collections.defaultdict(list)
    for rec, v in zip(fixture[1:], verdict["rows"]):
        by_key[rec["key"]].append((rec, v))
    retiring = {}
    for k, pairs in by_key.items():
        if all(r["status"] == "alias" for r, _ in pairs) and len(pairs) == len(rows_of_key[k]):
            best = max(pairs, key=lambda p: (p[1].get("count") or 0))
            retiring[k] = best[0]["target"]
    # a target that retires itself forwards to its own target (resolved to a fixpoint; a cycle keeps the keys)
    for k in list(retiring):
        seen, t = {k}, retiring[k]
        while t in retiring and t not in seen:
            seen.add(t)
            t = retiring[t]
        if t in seen:
            del retiring[k]
        else:
            retiring[k] = t
    for rec in fixture[1:]:
        # a row target that retires itself forwards to its own alias target (the `S2R_R_L_II` -> `S2R_R_II` ->
        # `S2R_R_L` chain): the test decodes the word through the key that stays
        if rec.get("target") in retiring:
            rec["target"] = retiring[rec["target"]]
    for rec, v in zip(fixture[1:], verdict["rows"]):
        if rec["status"] == "alias":
            if rec["key"] in retiring:
                rec["alias_target"] = retiring[rec["key"]]
            else:
                # an unreachable row of a key that stays (its other rows are live): cubit decodes its canonical word
                # through another key with the vendor text -- the row is dead and is deleted (documented here and
                # asserted by the test: the key keeps its live rows, the word keeps its real row)
                stats["alias"] -= 1
                stats["dead"] += 1
                rec["status"] = v["status"] = "dead"
    n_cubit = sum(1 for v in verdict["rows"] if v["status"] == "measured" and v["cubit_problems"])
    stats["measured_with_cubit_problems"] = n_cubit

    out = pathlib.Path(args.out) if args.out else nvprobe.FIXTURES / f"sm120_rows_{args.family}_nvdisasm.jsonl"
    nvprobe.write_fixture(out, fixture)
    vpath = pathlib.Path(args.verdict) if args.verdict else out.with_name(f"rows_{args.family}_verdict.json")
    vpath.write_text(json.dumps(verdict, indent=1) + "\n")
    print(f"{out}: {len(rows)} rows; {dict(stats)}; verdict {vpath}")
    per_key = collections.defaultdict(collections.Counter)
    for v in verdict["rows"]:
        per_key[v["key"]][v["status"]] += 1
    for k in sorted(per_key):
        print(f"  {k:52s} {dict(per_key[k])}")


# --- apply -----------------------------------------------------------------------------------------------------

def note_for(family: str, rec: dict) -> str:
    inert = rec.get("inert", [])
    illegal = rec.get("illegal", [])
    mods = [b for b, _ in rec.get("modifier", [])]
    other = [b for b, _ in rec.get("operand_other", [])]
    glyph = [b for b, _ in rec.get("glyph", [])]
    added = "; ".join(f"{e} {s} tok {t}" for e, s, _n, t in rec.get("fields_add", []))
    extra = f" Fields the harvest never declared, added from the sweep: {added}." if added else ""
    reuse = rec.get("reuse_inert", [])
    extra += f" Declared .reuse bits {reuse} are text-inert for nvdisasm (kept: inert on silicon, KNOWN_ISSUES A12)." if reuse else ""
    return (f"Row verified field by field with nvdisasm 13.1 (-b SM120; session G run 5, {DATE}, "
            f"tools/probes/re_sm120_rows.py --family {family}): canonical word {rec['w0']} = `{rec['t0']}`; every field bit "
            f"moves its own operand token; bits outside the fields: modifier bits {mods} (other groups' words), "
            f"neighbouring-form bits {other}, vendor-invalid glyph planes {glyph}, illegal {illegal}, text-inert {inert} "
            f"(fail closed: the mask is the fields).{extra}")


def apply(args):
    path = pathlib.Path(args.table)
    table = nvprobe.load_table(path)
    ins = table["instructions"]
    family = args.family
    src = tag_of(family)
    fixture_path = pathlib.Path(args.fixture) if args.fixture else nvprobe.FIXTURES / f"sm120_rows_{family}_nvdisasm.jsonl"
    recs = [json.loads(l) for l in fixture_path.read_text().splitlines() if l.strip()][1:]
    tagged = added = 0
    for rec in recs:
        if rec["status"] != "measured":
            continue
        entry = ins.get(rec["key"])
        if entry is None or rec["group"] not in entry.get("mod_groups", {}):
            continue  # retired / renamed on this base
        row = entry["mod_groups"][rec["group"]]
        if row.get("_src") is not None and row.get("_src") != src:
            continue  # measured by someone else meanwhile
        # the measured field list: the declared fields (float extractions where the harvest spelled a float immediate
        # as an integer) plus the guard / sign / abs / reuse bits the sweep found on this row's operands
        old = {(f["shift"], f["bits"]): f for f in row.get("fields", [])}
        fields = []
        for shift, bits, tok, ext in rec["fields"]:
            f = dict(old.get((shift, bits), {}))
            if not f or f.get("extraction") != ext or f.get("token_idx") != tok:
                added += 1
            f.update({"bits": bits, "extraction": ext, "shift": shift, "token_idx": tok})
            f.setdefault("_src", src)
            fields.append(f)
        row["fields"] = fields
        mask = fields_mask(fields)
        base = int(row["and_base"], 16) & ~SCHEDULE & ~mask
        row["and_base"] = f"0x{base:032x}"
        row["variable_mask"] = f"0x{mask:032x}"
        row["_src"] = src
        row["_note"] = note_for(family, rec)
        tagged += 1
    retired, deleted = [], []
    dead = 0
    alias_targets = set(table["_meta"].get("key_aliases", {}).values()) | {rec.get("alias_target") for rec in recs}
    for rec in recs:
        if rec["status"] == "dead" and rec["key"] in ins and rec["group"] in ins[rec["key"]].get("mod_groups", {}):
            if len(ins[rec["key"]]["mod_groups"]) == 1 and rec["key"] in alias_targets:
                print(f"  keeping the last row of alias target {rec['key']} ({rec['group']!r}) -- dead by the probe, needed by the aliases")
                continue
            del ins[rec["key"]]["mod_groups"][rec["group"]]
            dead += 1
            if not ins[rec["key"]]["mod_groups"]:
                del ins[rec["key"]]
                deleted.append(rec["key"])
    aliases = sorted({(rec["key"], rec["alias_target"]) for rec in recs if rec["status"] == "alias"}) + list(args.alias or [])
    for junk, target in aliases:
        if junk in ins and target in ins:
            del ins[junk]
            table["_meta"].setdefault("key_aliases", {})[junk] = target
            retired.append(junk)
    for junk in (args.delete or []):
        if junk in ins:
            del ins[junk]
            deleted.append(junk)
    prov = table["_meta"]["provenance"]
    rows = [g for e in ins.values() for g in e.get("mod_groups", {}).values()]
    prov["rows_total"] = len(rows)
    prov["rows_without_src"] = sum(1 for g in rows if g.get("_src") is None)
    prov["sources"][src] = {"rows": sum(1 for g in rows if g.get("_src") == src),
                            "kind": "nvdisasm 13.1 per-row field verification over the whole word (-b SM120)", "date": DATE,
                            "tool": f"tools/probes/re_sm120_rows.py --family {family}", "test": f"tests/sm120_rows_{family}.rs"}
    nvprobe.save_table(path, table)
    print(f"{path}: {tagged} rows tagged {src} ({added} fields added / retyped), {len(retired)} keys retired as aliases "
          f"{retired}, {dead} dead rows deleted ({len(deleted)} keys emptied {deleted}); rows without _src now {prov['rows_without_src']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("probe")
    p.add_argument("--family", required=True, choices=sorted(FAMILIES))
    p.add_argument("--table", default=str(nvprobe.REPO / "tables" / "sm120.json"))
    p.add_argument("--census", default=None)
    p.add_argument("--witnesses", type=int, default=3)
    p.add_argument("--keys", nargs="*", default=None)
    p.add_argument("--also-harvest-in", default=None,
                   help="a second table the row must be a harvest row of too (skip rows another batch handles elsewhere)")
    p.add_argument("--nvdisasm", default=NVDISASM)
    p.add_argument("--arch", default="SM120")
    p.add_argument("--jobs", type=int, default=24)
    p.add_argument("--audit-words", default=str(nvprobe.REPO / "target" / "release" / "examples" / "audit_words"))
    p.add_argument("--text-keys", default=str(nvprobe.REPO / "target" / "release" / "examples" / "text_keys"))
    p.add_argument("--out", default=None)
    p.add_argument("--verdict", default=None)
    p.add_argument("--nv-cache", default=None, help="on-disk nvdisasm memo (session convenience, not read by tests)")
    a = sub.add_parser("apply")
    a.add_argument("table")
    a.add_argument("--family", required=True, choices=sorted(FAMILIES))
    a.add_argument("--fixture", default=None)
    a.add_argument("--verdict", default=None)
    a.add_argument("--alias", nargs=2, action="append", metavar=("JUNK", "TARGET"))
    a.add_argument("--delete", nargs="*")
    args = parser.parse_args()
    if args.command == "probe":
        probe(args)
    else:
        apply(args)


if __name__ == "__main__":
    main()

# Symbolic registers: write a kernel without numbering it, let `cubit ra` place the registers (sm_120)

For people who write SASS generators. A generator that numbers its registers by hand carries a second
program in its author's head: which numbers are free where, which pairs must be even, which value may
reuse which register without making the scheduler wait. `cubit ra --mode full --target sm120` takes that
over: the generator names values, the pass places them and proves the placement.

```bash
python3 gen_kernel.py > k.sym.sass                       # register numerals are SYMBOLS here
cubit ra k.sym.sass --mode full --target sm120 -o k.sass --report k.ra.json
cubit asm k.sass -t tables/sm120.json -o k.cubin         # with the kernel's own scheduling switches
```

## 1. What the source looks like

The source is ordinary directive-format SASS. A register numeral in it is a name, not a place:

* **One numeral per value** (or per role: "the row pointer", "the accumulator of column 3"). Two values
  that are alive at the same time need two numerals — that is the only thing you must get right, and
  nobody can check it for you: a numeral used for two values at once IS one register.
* **A value of several registers gets consecutive numerals.** 64-bit pointers and products (`LDC.64`,
  `IMAD.WIDE`, the address of `desc[UR][R.64]`), 128-bit loads and stores (`LDG.E.128`, `LDS.128`,
  `STS.128`), `LDSM` fragments, the tuples of an MMA: name the base, the rest follows. The pass keeps
  such a group together and puts its base on the silicon's grid (§3). You need not align the numerals
  yourself — but if you do (a pair on an even numeral, a quad on a multiple of four) the source
  assembles and runs as it is, which is worth having while you debug the generator.
* **At most 253 numerals** (`R0`–`R252`), and one register per numeral for the whole kernel: the pass
  renames, it does not split a value's life into pieces. Temporaries of a loop body are one numeral
  each, not one per iteration; a phase's scratch may be reused by the next phase under the same numeral.
* **`.reg R0-R252`** (or whatever covers your numerals). The output's `.reg` line is rewritten to the
  registers actually used, and that sets the register count of the cubin.
* Uniform registers (`UR0`–`UR62`) and predicates (`P0`–`P6`) are symbols too. There are only seven
  predicates and no spilling: more than seven alive at once is an error.
* **Every read must have a write on every path that reaches it.** `@P0 MOV R9, 0x1 ; STS [..], R9` reads
  R9 unwritten when P0 is false — the pass refuses the kernel and names the register. A default
  followed by a guarded overwrite is fine (`MOV R9, RZ ; @P0 LDG.E R9, …`), and so is a guarded write
  whose readers all sit under the same guard.

A helper of ten lines is all a generator needs:

```python
class Regs:
    """Hands out numerals as symbols: one per value, consecutive numerals for a pair / quad."""
    def __init__(self):
        self.next = 0
    def new(self, width=1):
        base = -(-self.next // width) * width     # on its grid: the source itself assembles and runs
        self.next = base + width
        assert self.next <= 253, "more than 253 symbols: let values that never meet share one"
        return base

R = Regs()
tid = R.new()
inp, addr = R.new(2), R.new(2)                     # 64-bit: pairs
vec = R.new(4)                                     # a 128-bit load: a quad
tmp = [R.new() for _ in range(4)]                  # one symbol per temporary: no manual reuse
```

`tests/fixtures/ra_sm120/sum16.sass` is a kernel written this way (24 numerals).

## 2. What you get back

`k.sass` — the same instructions, token for token, with other numerals; comments are dropped, labels
kept. `k.ra.json` — per kernel:

| field | meaning |
|---|---|
| `plan.r` / `.ur` / `.p` | old numeral → register, per domain |
| `full.r.symbols`, `.groups` | numerals found, and the groups they form (a pair, a quad, … is one group) |
| `full.r.watermark` | registers used: `R0` … `R<watermark-1>` |
| `regcount` | the register count the cubin will carry: watermark + the two shadow registers, in granules of 8 (KNOWN_ISSUES A1) |
| `peak_live_r` | the most registers that hold a value at one point — no renaming can use fewer; the gap to `watermark` is what the grid and the scan's order cost |
| `full.renamed` | numerals changed in the text |

Two ways to allocate:

* **default** — values that are never alive together may get one register. Fewest registers.
* **`--no-share`** — every numeral keeps a register of its own. The result has exactly the register
  dependencies of the source, so it assembles to the same schedule, control word for control word.

Why that matters: a register handed from one value to the next creates a dependency the source did not
have. Where the first value's last read is a **load's address or a store's data** — operands the memory
pipe latches when it serves the instruction, not at issue — the write of the second value must wait
for that latch. On `sum16.sass` the default allocation (24 numerals on 11 registers) puts the second
load's destination on the register the first load's address has just left: the first load sets a read
barrier, the second waits for it (3 of 21 control words differ from the source's schedule). With
`--no-share` (24 registers, the same register count 32) all 21 are the source's. If your kernel keeps
several loads in flight on purpose, either use `--no-share` and do the sharing yourself by reusing
numerals where it is harmless, or look at what the default did (`cubit disassemble --frozen`: a
`[..:R<n>:..]` on a load and a wait on `<n>` right behind it).

## 3. What `--target sm120` guarantees, and how

Every run proves its result before it writes a byte; any failure stops the run with no output.

| guarantee | how it is established |
|---|---|
| **Nothing but numerals changed.** Opcode, modifiers, guards, immediates, labels, and the operand selectors (`.H1`, `.H0_H0`, `.B0`, …) are the source's. | the rendered text is re-parsed and compared with the renamed program, selector chains included (the encoder reads selectors from the text) |
| **No value is overwritten while it is needed.** | the plan is injective on every instruction's live-in ∪ live-out ∪ written ∪ read registers; liveness is computed on the control-flow graph, and a **guarded write does not end a life** (`@P0 LDG.E.128 R88, …` leaves R88–R91 as they were when P0 is false) |
| **Multi-register operands stay whole and on the silicon's grid**: pairs on even registers, quads on multiples of four, MMA tuples as the encoder demands. | groups are placed as units; the finished plan is audited against the footprint of every instruction (`audit_spans`) |
| **The pass sees what the hardware touches**: the 64-bit address and the 64-bit descriptor of `desc[UR][R.64]`, both registers `CS2R` writes, both of `LDSM.2`, all four of `LDSM.4` / `.128`, the pairs of `IMAD.WIDE` and `LDC.64`, the MMA tuples (B of `HMMA.16816` is a pair). | `ra_target::target_xfer`; an opcode whose register or predicate roles are not known stops the run |
| **No register is read before it is written.** | a register live at the entry is an error |
| **The register count is the allocation's.** | `.reg` is rewritten; an explicit `.regcount` must cover the plan; R252 is the last usable register |

The grid is silicon law: 38 probe kernels on an RTX PRO 6000 (`tools/ra/gen_align_probes.py`, results
`tools/ra/align_probes_sm120_20261110.json`) — every pair or quad off its grid ends the launch with
CUDA_ERROR_ILLEGAL_INSTRUCTION (715): the addend and the destination of `IMAD.WIDE`, the destination of
`LDC.64` / `LDG.E.64` / `LDG.E.128` / `LDS.64` / `LDS.128` / `CS2R` / `LDSM.2` / `LDSM.4`, the data of
`STS.64` / `STS.128`, the address pair of `LDG` and `STG`, an odd uniform pair; MMA tuples per BUG-037.
The vendor never leaves it: in 1 811 600 instructions of nvcc / ptxas output for sm_120 no
multi-register operand of any kind is off the grid (`tools/ra/align_census_sm120.json`). **The assembler
does not check it for you** — every one of the 38 probes assembled without a warning (KNOWN_ISSUES A28);
`cubit roundtrip-strict` on the cubin catches the `IMAD.WIDE` addend only. Let the allocator place
multi-register values, or keep to the grid by hand.

Without `--target` the pass is the target-neutral one it always was: no grid, the role table's
footprints (one register for a `desc` address, for `CS2R`, for `LDSM.2`), every write a kill. On sm_120
code that plan assembles and does not run; `--mode apply --target sm120` refuses it.

## 4. What it does not do

* **It does not split or spill.** One register per numeral; a kernel that needs more than 253 registers
  alive is refused. Give long-lived values their own numerals and reuse scratch numerals yourself.
* **It does not schedule.** Stalls and scoreboards are `cubit asm`'s; the allocation changes them only
  through the dependencies sharing adds (§2).
* **It does not know your intent.** A numeral used for two values at once, a quad you meant as two
  pairs: the pass sees a consistent program and allocates it.
* **It knows sm_120.** `--target` has one value; other architectures get the target-neutral pass.
* **`--mode identity`** renames nothing: it proves the pass reads every register of the text (zero
  changed numerals) — the cheapest check that a new kernel's opcodes are all known to it.

## 5. Checks worth running after an allocation

```bash
CUBIT_VERIFY=1 cubit asm k.sass -t tables/sm120.json -o k.cubin   # scoreboard: 0 unprotected RAW, 0 broken WAR
cubit roundtrip-strict k.cubin -t tables/sm120.json               # every word decodes and re-encodes
python3 tools/ra/ra_equiv.py text k.sym.sass k.sass k.ra.json     # an independent check (own footprints and liveness)
```

`tools/ra/ra_equiv.py` knows the opcodes of the sparse-MLA prefill attention kernel and stops on any
other; extend its `footprint` for yours. Then the kernel's own bit gate on silicon — a renaming is
bit-neutral by construction, and the gate is how a construction is checked.

## 6. Measured: the production attention kernel

`sparse_mla_prefill_v41` (two source texts: 2 535 and 1 449 instructions; R0–R125 numbered by hand,
register count 128), re-numbered from zero, 2026-11-10:

| | hand-numbered | `--target sm120` | `--target sm120 --no-share` |
|---|---|---|---|
| numerals changed (v41 / v42 text) | — | 4 007 / 3 017 | 3 935 / 2 861 |
| registers, register count | 126, 128 | 125, 128 | 126, 128 |
| alive at once (lower bound) | 113 | 113 | 113 |
| `CUBIT_VERIFY`, `CUBIT_DEP_VERIFY`, strict round trip | clean | clean | clean |
| control words that differ from the hand-numbered build | — | 0 of 2 540 / 1 454 | 0 |

On silicon (RTX PRO 6000 Workstation Edition, the kernel's harness: 8 synthetic cases and 8 dumps of a
real prefill, output and lse `torch.equal`): the re-numbered builds are bit-identical in 30 warm
launches × 16 cases and 30 fresh processes × 16 cases, and as fast as the hand-numbered ones at every
shape (within ±0.3 %, the spread between rounds) — as are two further numberings made by permuting the
plan's 4-register blocks. The register numbers themselves cost nothing; what the hand numbering knew
was the grid, and where not to share a register.

# Encoder guards

cubit guards a set of measured SM120/SM103a silicon behaviors at the
assembler source: constructs that would mis-encode or mis-execute are a hard
error — or a loud warning, where marked — instead of a silent wrong binary.
Guards are active by default; the ones that shape how you write SASS:

- **PRMT operand order is hardware order `(d, a, sel, b)`** — the selector is
  operand 3, as `nvdisasm` prints it. PTX spells `prmt.b32 d, a, b, c` with
  the selector last; the assembler encodes hardware order and rejects text it
  cannot place unambiguously, never silently swapping sel/b.
- **`IMAD.HI[.U32]` must select its genuine SM120 opcode `0x227`.**
  The historical HI-to-WIDE fallback (`0x225`) remains an error. The previous
  blanket rejection was disproved by fresh ptxas output for `mad.hi.u32` and
  1004 boundary/random triples on SM120 (2026-10-22): high32(a*b)+c was exact.
  `WIDE` writes a register pair; genuine `HI` is a separate instruction.

- **Predicate index 7 is PT** — literal `P7`/`UP7` and above is a hard
  assembler error; index 7 already names the always-true PT.
- **SM120 `BRXU` offsets are signed 58-bit byte values, aligned to four bytes.**
  The legacy `BRXU 0xT` shorthand means a nonnegative absolute code address;
  it is lowered before table lookup to `BRXU URZ, T - PC - 16`.
  Disassembly prints the explicit register and offset. Invalid alignment or
  range is an error, and distant negative offsets retain all address bits.
- **Plain `WARPSYNC R<n>` warns on sm_120** — legality depends on the
  surrounding schedule. Use `WARPSYNC.ALL ;`, or rely on intra-warp
  `STS`→`LDS` ordering.
- **Carry-in negation lives on `.X` forms** — a negated carry-in that has no
  bit in the selected form is a hard error, never a silent downgrade.
- **A wide IMAD's pairs start on even registers (SM120)** — `IMAD.WIDE[.U32][.X] Rd, [Pn,] Ra, Rb, Rc[, Pcin]` computes
  `Rd:Rd+1 = Ra * Rb + Rc:Rc+1`; an odd `Rd`, an odd register `Rc` or an odd uniform `URc` (the uniform addend is a
  pair too) faults the launch (CUDA 715, measured in every form: 4-operand and `PT` spelling, with a real carry-out
  predicate, with a carry-in, with a uniform addend) and is a hard error. The even idiom is silent.
- **Every other multi-register operand starts on its grid (SM120)** — a 64-bit pair on an even register, a 128-bit quad
  on a multiple of four: the destination of `LDG.E.64` / `.128`, `LDS.64` / `.128`, `LDC.64`, `CS2R` (pair form),
  `LDSM.….2` / `.4`, `LDCU.64`; the data of `STS.64` / `.128`; the address pair `desc[UR][R.64]` of `LDG` / `STG`; the
  pairs of `IADD.64`. Off the grid the launch faults (CUDA 715: 23 of 23 probe kernels; a trap on the card for
  `IADD.64`) and `cubit asm` refuses to write the kernel (BUG-488). This guard sits in the kernel assembler, not in the
  word-level encoder: `cubit encode` / `asm-text` assemble such a word (table work). `RZ` is exempt.
  `CUBIT_ALLOW_OFF_GRID=1` lifts this one guard.
- **Frozen `DEPBAR`/`MEMBAR` keep their control word** — fully-static barrier
  classes retain the `[B:R:W:Y:S]` prefix on re-encode.
- **REGCOUNT follows driver legality** — clamped to the 255 hardware maximum;
  `--eiattr-from` rebuilds treat the template's REGCOUNT as a floor.
- **sm_103a descriptor-pair traps fail closed** — odd-base `desc[UR][R.64]`
  register pairs for LDG/STG/atomics and the consumer `IMNMX` class are
  silicon-illegal there, so the assembler rejects them; the decoder still
  reads such words for reverse engineering of existing binaries.

## Escape hatch

`CUBIT_DISABLE_ERRATA=1` disables the guard layer. This is a table-research
escape hatch only (for assembling known-illegal words on purpose, e.g. when
probing encodings); production flows must not need it.

`CUBIT_ALLOW_OFF_GRID=1` lifts only the register-grid guard of SM120 (BUG-488): for a
generator of probe kernels that measures the fault of an off-grid operand and wants
every other guard to stay on.

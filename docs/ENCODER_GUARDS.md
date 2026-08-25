# Encoder guards

cubit guards a set of measured SM120/SM103a silicon behaviors at the
assembler source: constructs that would mis-encode or mis-execute are a hard
error — or a loud warning, where marked — instead of a silent wrong binary.
Guards are active by default; the ones that shape how you write SASS:

- **PRMT operand order is hardware order `(d, a, sel, b)`** — the selector is
  operand 3, as `nvdisasm` prints it. PTX spells `prmt.b32 d, a, b, c` with
  the selector last; the assembler encodes hardware order and rejects text it
  cannot place unambiguously, never silently swapping sel/b.
- **`IMAD.HI[.U32]` is not encodable on sm_120** — silicon executes harvested
  "HI" words as `IMAD.WIDE.U32` (`Rd` = LOW half, `Rd+1` clobbered), so the
  assembler rejects the form. Use `IMAD.WIDE[.U32] Rd, Ra, Rb, RZ` and read
  the high half from `Rd+1`, or the 5-operand pout form.
- **Predicate index 7 is PT** — literal `P7`/`UP7` and above is a hard
  assembler error; index 7 already names the always-true PT.
- **Plain `WARPSYNC R<n>` warns on sm_120** — legality depends on the
  surrounding schedule. Use `WARPSYNC.ALL ;`, or rely on intra-warp
  `STS`→`LDS` ordering.
- **Carry-in negation lives on `.X` forms** — a negated carry-in that has no
  bit in the selected form is a hard error, never a silent downgrade.
- **4-operand `IMAD.WIDE*` with `c != RZ` warns** — the c accumulator is the
  64-bit pair `(Rc, Rc+1)`; canonical spellings are the 5-operand pout form
  or `c = RZ`.
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

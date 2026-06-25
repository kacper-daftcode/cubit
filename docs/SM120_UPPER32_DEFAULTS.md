# SM120 Upper32 Defaults per Instruction Class

These values go in hi64[63:32] (upper 32 bits of control word) and are
required by the SM120 hardware for instruction decode. They are NOT in
sm120.json `and_base` — they come from the scheduling/ctrl word system.

Without these, nvdisasm reports "Unrecognized operation for functional unit 'uC'"
and the GPU raises illegal instruction errors.

## Default Values

| Upper32 | Stall | Yield | WBar | RBar | Wait | Usage |
|---------|-------|-------|------|------|------|-------|
| 0x000fc000 | 0 | Y | 0 | 0 | 0x38 | QMMA, IMAD.WIDE (tensor/long-latency producers) |
| 0x000fc200 | 0 | Y | 0 | 2 | 0x38 | Most ALU: IADD3, IMAD, MOV, SHF, LOP3, SEL |
| 0x000fc600 | 0 | Y | 0 | 6 | 0x38 | (unused in current MCCodeEmitter) |
| 0x000fca00 | 0 | Y | 0 | 2 | 0x39 | BRA (branches) |
| 0x000fce00 | 0 | Y | 0 | 6 | 0x39 | (unused) |
| 0x000fda00 | 0 | Y | 0 | 2 | 0x3B | ISETP, FSETP (predicate writers) |
| 0x000fe200 | 0 | Y | 0 | 2 | 0x3C | LDG, STG, LDCU, LDC, LDSM, S2R (memory/IO) |

## Common Bits

All values have upper32[31:17] = 0x0007E (bits 19:17 = 0b111).
These are required hardware mode bits — setting them to 0 causes decode failure.

## Per-Opcode Mapping

From tungsten MCCodeEmitter:

| Instruction | Upper32 Default |
|-------------|----------------|
| IADD3, IADD3.X | 0x000fc200 |
| IMAD, IMAD.WIDE | 0x000fc000 |
| MOV, MOV_IMM | 0x000fc200 |
| SHF.L, SHF.R | 0x000fc200 |
| LOP3 | 0x000fc200 |
| SEL | 0x000fc200 |
| FMUL, FADD, FFMA | 0x000fc000 |
| ISETP, FSETP, DSETP | 0x000fda00 |
| MUFU | 0x000fc200 (+ func code in lo32[15:8]) |
| S2R | 0x000fc200 (+ SR code in lo32[15:8]) |
| LDG, LDG.E | 0x000fe200 (+ discriminator in lo32) |
| STG, STG.E | 0x000fe200 (+ discriminator in lo32) |
| LDCU | 0x000fe200 (+ 0x08000a00 in lo32) |
| LDC | 0x000fc200 (+ type in lo32) |
| LDSM | 0x000fe200 (+ mode in lo32) |
| BRA, @P BRA | 0x000fca00 |
| EXIT | 0x000fc200 |
| BAR.SYNC | 0x000fc200 |
| BSSY, BSYNC | 0x000fc200 |
| QMMA | 0x000fc000 (MUST be exactly this — no barriers!) |
| NOP | 0x000fc000 |

## Implementation

cubit encoder should:
1. After field-based encoding (from and_base + fields), check upper32
2. If upper32 == 0 (no mode bits from and_base), apply default from this table
3. Then inject stall/yield on top (bits[4:0])
4. Barrier/wait bits: only if scheduling pass explicitly sets them

This ensures all instructions have valid upper32 mode bits while preserving
the instruction-specific lo32 from and_base.

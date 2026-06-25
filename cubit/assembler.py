"""SM120 SASS assembler with full scheduling control.

High-level assembler wrapping cubit's native encode()/decode() with
per-instruction control over scheduling bits (stall, barriers, yield).

SM120 control code: 17 bits packed into ctrl_word[57:41].

    packed[3:0]   stall       4 bits (0-15 cycles before issue)
    packed[4]     !yield      1 bit  (inverted: 0=yield, 1=no yield)
    packed[7:5]   write_bar   3 bits (0-5=slot, 7=none)
    packed[10:8]  read_bar    3 bits (0-5=slot, 7=none)
    packed[16:11] wait_mask   6 bits (one per barrier 0-5)

Usage::

    from cubit.assembler import Assembler

    asm = Assembler()
    inst = asm.assemble("IADD3 R5, PT, PT, R5, R6, RZ", stall=1)
    inst = asm.assemble("S2R R9, SR_CLOCKLO", stall=15, write_bar=2)
    inst = asm.nop(stall=15, wait_mask=0x04)  # wait barrier 2
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from . import encode as _encode


# ── Control code layout ──────────────────────────────────────

CC_POS = 41
CC_BITS = 17
CC_MASK_UNSHIFTED = (1 << CC_BITS) - 1
CC_MASK = CC_MASK_UNSHIFTED << CC_POS
MOD_MASK = (1 << CC_POS) - 1  # bits [40:0] — opcode modifier/operand bits


def build_ctrl(
    stall: int = 1,
    yield_hint: bool = True,
    wait_mask: int = 0,
    read_bar: int = 7,
    write_bar: int = 7,
) -> int:
    """Build scheduling bits for ctrl_word[57:41].

    Args:
        stall:      cycles to wait before issue (0-15)
        yield_hint: hint warp scheduler to switch
        wait_mask:  6-bit mask — wait for barrier slots to clear
        read_bar:   read barrier slot (0-5, 7=none)
        write_bar:  write barrier slot (0-5, 7=none)
    """
    c_yield = 0 if yield_hint else 1
    packed = (
        (stall & 0xF) |
        (c_yield << 4) |
        ((write_bar & 0x7) << 5) |
        ((read_bar & 0x7) << 8) |
        ((wait_mask & 0x3F) << 11)
    )
    return packed << CC_POS


def merge_ctrl(cubit_hi: int, sched: int) -> int:
    """Merge cubit's opcode bits [40:0] with scheduling bits [57:41]."""
    return (cubit_hi & ~CC_MASK) | (sched & CC_MASK)


def decode_ctrl(hi: int) -> dict:
    """Decode scheduling fields from a ctrl word."""
    packed = (hi >> CC_POS) & CC_MASK_UNSHIFTED
    return {
        "stall": packed & 0xF,
        "yield_flag": (packed >> 4) & 1 == 0,
        "write_bar": (packed >> 5) & 7,
        "read_bar": (packed >> 8) & 7,
        "wait_mask": (packed >> 11) & 0x3F,
    }


# ── Instruction data type ────────────────────────────────────

@dataclass
class Instruction:
    """One assembled SM120 SASS instruction (128 bits)."""
    offset: int
    instr_word: int    # lo64: opcode + operands
    ctrl_word: int     # hi64: scheduling + opcode modifiers
    text: str

    def to_bytes(self) -> bytes:
        return struct.pack("<QQ", self.instr_word, self.ctrl_word)

    @property
    def stall(self) -> int:
        return (self.ctrl_word >> CC_POS) & 0xF

    @property
    def write_bar(self) -> int:
        return (self.ctrl_word >> (CC_POS + 5)) & 0x7

    @property
    def read_bar(self) -> int:
        return (self.ctrl_word >> (CC_POS + 8)) & 0x7

    @property
    def wait_mask(self) -> int:
        return (self.ctrl_word >> (CC_POS + 11)) & 0x3F


# ── Assembler ────────────────────────────────────────────────

class Assembler:
    """SM120 SASS assembler with per-instruction scheduling control.

    Every method returns ``Instruction`` with fully-specified control
    words.  No manual bit patching needed.
    """

    def assemble(
        self,
        sass: str,
        offset: int = 0,
        stall: int = 1,
        yield_hint: bool = True,
        wait_mask: int = 0,
        read_bar: int = 7,
        write_bar: int = 7,
    ) -> Instruction:
        """Assemble one SASS instruction with explicit scheduling.

        Args:
            sass:        SASS text, e.g. "IADD3 R5, PT, PT, R5, R6, RZ"
            offset:      byte offset (for BRA target encoding)
            stall:       cycles before issue (0-15)
            yield_hint:  yield warp after this instruction
            wait_mask:   6-bit barrier wait mask
            read_bar:    read barrier slot (0-5, 7=none)
            write_bar:   write barrier slot (0-5, 7=none)
        """
        text = sass.strip()
        if not text.endswith(";"):
            text += " ;"

        lo, hi = _encode(text, addr=offset)
        sched = build_ctrl(stall, yield_hint, wait_mask, read_bar, write_bar)
        final_hi = merge_ctrl(hi, sched)

        return Instruction(offset, lo, final_hi, text)

    def nop(self, offset: int = 0, **kwargs) -> Instruction:
        """Assemble a NOP with given scheduling."""
        return self.assemble("NOP", offset=offset, **kwargs)

    def assemble_block(
        self,
        lines: list[str],
        base_offset: int = 0,
        **kwargs,
    ) -> list[Instruction]:
        """Assemble a list of SASS instructions with uniform scheduling."""
        result = []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("//") or line.startswith("#"):
                continue
            offset = base_offset + len(result) * 16
            result.append(self.assemble(line, offset=offset, **kwargs))
        return result

    def block_to_bytes(self, instructions: list[Instruction]) -> bytes:
        """Convert instructions to raw bytes."""
        return b"".join(i.to_bytes() for i in instructions)

    def pad_to_alignment(
        self,
        instructions: list[Instruction],
        alignment: int = 128,
    ) -> list[Instruction]:
        """Pad with NOPs to next multiple of alignment bytes."""
        while (len(instructions) * 16) % alignment != 0:
            instructions.append(self.nop(offset=len(instructions) * 16))
        return instructions

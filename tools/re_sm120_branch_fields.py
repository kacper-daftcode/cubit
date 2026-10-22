#!/usr/bin/env python3
"""Repair SM120 BRA.DIV's measured REL16 layout in the canonical ISA.

NVIDIA r15 v3 anchors: at0xa30, lowword0x0000001e04247947 targets0x26d0;
at0x1290 lowword0x0000001604287947 targets0x2740. Both have UR4.
Target-addr-16 in 4-byte units: low8@[23:16], signed high48@[81:34].
Single-bit probes additionally verify +4/+8 targets and upper sign bits.
The old 19-bit field overlapped UR@[31:24] and an artifact BRA.U row.
Run on the canonical blackwell-isa checkout, then vendor with sync_table.py.
"""
import argparse, copy, json
from pathlib import Path

def repair(data):
 ins=data['instructions']
 fields=[dict(bits=4,extraction='guard',shift=12,token_idx=0),dict(bits=8,extraction='ureg',shift=24,token_idx=1),dict(bits=8,extraction='imm_shr2',shift=16,token_idx=2),dict(bits=48,extraction='imm_shr10',shift=34,token_idx=2)]
 mask=sum(((1<<f['bits'])-1)<<f['shift'] for f in fields)
 row=dict(and_base=f'0x{((0xb800000<<64)|(2<<32)|0x947):032x}',count=150,fields=fields,variable_mask=f'0x{mask:032x}')
 ins['BRA.DIV_UR_II']['mod_groups']['']=copy.deepcopy(row)
 ins['BRA_UR_II']['mod_groups']['DIV']=copy.deepcopy(row)
 # This harvested artifact claims BRA.DIV target bits as uniform predicates.
 ins['BRA.U_?_II']['encode_only']=True
 return data

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('canonical_table',type=Path);a=p.parse_args()
 d=json.loads(a.canonical_table.read_text());repair(d)
 tmp=a.canonical_table.with_suffix('.json.branch-tmp');tmp.write_text(json.dumps(d,indent=1,ensure_ascii=False)+'\n');tmp.replace(a.canonical_table)

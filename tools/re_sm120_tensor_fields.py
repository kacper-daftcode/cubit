#!/usr/bin/env python3
"""Repair SM120 semantic tensor, election and scalar/vector ALU fields.

This writes ordinary named ISA fields, never per-word payloads or residues.
The laws were independently measured with NVIDIA nvdisasm on 2026-10-22:
5,796 single-bit/operand/mode probe records plus sparse-selector enumeration.
Use --verify-oracle to rerun representative independent NVIDIA word checks.
The patch reads the current table and atomically updates only these families.
"""
import argparse
import copy
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

SOURCE = "re_sm120_tensor_fields.py: NVIDIA SM120 bit/field/mode probes 2026-10-22"


def f(shift, bits, extraction, token):
    return dict(shift=shift, bits=bits, extraction=extraction, token_idx=token)


def mask(fields):
    value = 0
    for field in fields:
        value |= ((1 << field['bits']) - 1) << field['shift']
    return value


def group(base, fields):
    variable = mask(fields)
    return dict(and_base=f"0x{base & ~variable:032x}", variable_mask=f"0x{variable:032x}", fields=copy.deepcopy(fields), count=1, _source=SOURCE)


def entry(prototype, base_op, signature, groups):
    out = copy.deepcopy(prototype)
    out.update(base_op=base_op, operand_sig=signature, mod_groups=groups, _semantic_re=SOURCE)
    out.pop('encode_only', None)
    out.pop('_discovery', None)
    return out


def canonicalize(db):
    ins = db['instructions']
    # ELECT's UR destination is [23:16], its predicate destination [83:81].
    ep = copy.deepcopy(ins['ELECT_P_UR_P'])
    for k in list(ins):
        if k.startswith('ELECT'): ins[k]['encode_only'] = True
    fields = [f(12,4,'guard',0), f(81,3,'pred',1), f(16,8,'ureg',2), f(87,3,'pred',3), f(90,1,'neg',3)]
    ins['ELECT_P_UR_P'] = entry(ep,'ELECT','P_UR_P', {
        '': group(0x82f, fields), 'IGNOREKILL': group(0x82f | (1<<85), fields)})

    # FSETP comparison [79:76], boolean combine [75:74], FTZ[80].
    # Legacy broad rows masked combine bits and even inferred false register
    # operands. Keep those spellings encode-only; canonical rows own decode.
    fp = copy.deepcopy(ins['FSETP_P_P_R_R_P'])
    for k in list(ins):
        if k.startswith('FSETP'): ins[k]['encode_only'] = True
    compares = ['F','LT','EQ','LE','GT','NE','GE','NUM','NAN','LTU','EQU','LEU','GTU','NEU','GEU','T']
    for kind, opbits, ext in [('R',0x20b,'reg'), ('FI',0x80b,'f32'), ('II',0x80b,'f32'), ('UR',0xc0b | (1<<91),'ureg')]:
        fields = [f(12,4,'guard',0), f(81,3,'pred',1), f(84,3,'pred',2), f(24,8,'reg',3),
                  f(72,1,'neg',3),f(73,1,'abs',3),f(122,1,'reuse',3),f(87,3,'pred',5),f(90,1,'inv',5)]
        if kind == 'R': fields += [f(32,8,'reg',4),f(62,1,'abs',4),f(63,1,'neg',4),f(123,1,'reuse',4)]
        elif kind == 'UR': fields += [f(32,8,'ureg',4),f(62,1,'abs',4),f(63,1,'neg',4)]
        else: fields += [f(32,32,ext,4)]
        groups = {}
        for cmp, compare in enumerate(compares):
            for boolcode, boolean in enumerate(['AND','OR','XOR']):
                for ftz in [False,True]:
                    mods = [compare,boolean] + (['FTZ'] if ftz else [])
                    groups[','.join(sorted(mods))] = group(opbits|(cmp<<76)|(boolcode<<74)|(int(ftz)<<80),fields)
        key = f'FSETP_P_P_R_{kind}_P'
        ins[key] = entry(fp,'FSETP',f'P_P_R_{kind}_P',groups)
        if kind == 'II': ins[key]['encode_only'] = True
        # Existing dotted aliases must encode these same semantic fields.
        # A wrong fully-qualified alias otherwise wins before the base row.
        suffix=f'_P_P_R_{kind}_P'
        for oldkey in list(ins):
            if oldkey.startswith('FSETP.') and oldkey.endswith(suffix):
                opcode=oldkey[:-len(suffix)]; mods=','.join(sorted(opcode.split('.')[1:]))
                if mods in groups:
                    ins[oldkey]=entry(fp,opcode,f'P_P_R_{kind}_P',{'':groups[mods]})
                    ins[oldkey]['encode_only']=True

    # FMNMX modes are independent named modifiers FTZ[80], NAN[81], XORSIGN[82].
    mp = copy.deepcopy(ins['FMNMX_R_R_R_P'])
    for k in list(ins):
        if k.startswith('FMNMX'): ins[k]['encode_only'] = True
    for kind, opbits, ext in [('R',0x209,'reg'),('FI',0x809,'f32'),('II',0x809,'f32'),('UR',0xc09 | (1<<91),'ureg')]:
        fields=[f(12,4,'guard',0),f(16,8,'reg',1),f(24,8,'reg',2),f(72,1,'neg',2),f(73,1,'abs',2),
                f(122,1,'reuse',2),f(87,3,'pred',4),f(90,1,'neg',4)]
        if kind=='R': fields += [f(32,8,'reg',3),f(62,1,'abs',3),f(63,1,'neg',3),f(123,1,'reuse',3)]
        elif kind=='UR': fields += [f(32,8,'ureg',3),f(62,1,'abs',3),f(63,1,'neg',3)]
        else: fields += [f(32,32,ext,3)]
        groups={}
        for mode in range(8):
            mods=[name for bit,name in enumerate(['FTZ','NAN','XORSIGN']) if mode&(1<<bit)]
            groups[','.join(sorted(mods))]=group(opbits|(mode<<80),fields)
        key=f'FMNMX_R_R_{kind}_P'
        ins[key]=entry(mp,'FMNMX',f'R_R_{kind}_P',groups)
        if kind=='II': ins[key]['encode_only']=True

    # Tensor scale-selector UR is a split eight-bit field, with the regular
    # 0xff URZ sentinel. Bit63 belongs to neg(B), not to that selector.
    # Operand types A/B have separate [78,82,83] / [79,84,85] bit triples.
    qp=copy.deepcopy(next(v for k,v in ins.items() if k.startswith('QMMA.SF.16832.')))
    op=copy.deepcopy(next(v for k,v in ins.items() if k.startswith('OMMA.SF.16864.')))
    for k in list(ins):
        if k.startswith(('QMMA.SF.','OMMA.SF.')): ins[k]['encode_only']=True
    types={'E4M3':0,'E5M2':1,'E3M2':3,'E2M3':4,'E2M1':5}
    def tensor(opcode, prototype, base, sparse=False, predicate=False):
        tail=['R','R','UR'] + (['II'] if sparse else [])
        signature='_'.join(['R']*4 + (['UP'] if predicate else []) + tail)
        off=1 if predicate else 0
        fields=[f(12,4,'guard',0),f(16,8,'reg',1),f(24,8,'reg',2),f(32,8,'reg',3),f(64,8,'reg',4),
                f(72,1,'neg',2),f(63,1,'neg',3),f(123,1,'reuse',3),
                f(40,8,'reg',5+off),f(52,8,'reg',6+off),f(51,1,'reuse',6+off),
                f(60,3,'ureg',7+off),f(73,5,'ureg_shr3',7+off)]
        if sparse: fields.append(f(48,2,'imm',8+off))
        if predicate: fields.append(f(87,4,'pred_inv4',5))
        key=opcode+'_'+signature
        ins[key]=entry(prototype,opcode,signature,{'':group(base,fields)})
    for a,ac in types.items():
        for b,bc in types.items():
            bits=sum(((ac>>i)&1)<<s for i,s in enumerate([78,82,83]))|sum(((bc>>i)&1)<<s for i,s in enumerate([79,84,85]))
            for sparse in [False,True]:
                opcode=f'QMMA.SF.{"SP.16864" if sparse else "16832"}.F32.{a}.{b}.E8'
                for predicate in [False,True]:tensor(opcode,qp,0x47a|bits|(int(sparse)<<80),sparse,predicate)
    for scale,scale_bits in [('E8',1<<83),('E8.4X',0),('UE4M3',(1<<82)|(1<<83)),('UE4M3.4X',1<<82)]:
        for sparse in [False,True]:
            opcode=f'OMMA.SF.{"SP.168128" if sparse else "16864"}.F32.E2M1.E2M1.{scale}'
            for predicate in [False,True]:tensor(opcode,op,0x47f|scale_bits|(int(sparse)<<80),sparse,predicate)
    return db


def canonicalize_smallalu(db):
    ins = db['instructions']
    common = [f(12,4,'guard',0),f(16,8,'reg',1)]
    # SGXT's immediate is the complete 32-bit value in [63:32].
    prototype=copy.deepcopy(ins['SGXT_R_R_II'])
    fields=common+[f(24,8,'reg',2),f(122,1,'reuse',2),f(32,32,'imm',3)]
    groups={}
    for signed in [False,True]:
        for wide in [False,True]:
            mods=([] if signed else ['U32'])+(['W'] if wide else [])
            groups[','.join(sorted(mods))]=group(0x81a|(int(signed)<<73)|(int(wide)<<75),fields)
    ins['SGXT_R_R_II']=entry(prototype,'SGXT','R_R_II',groups)

    # The U16 source lane is H1[60], signedness[74], round-mode[79:78].
    fields=common+[f(32,8,'reg',2),f(60,1,'opmod:H1',2)]
    for signed in [False,True]:
        for rounding,mode in [('',0),('RM',1),('RP',2),('RZ',3)]:
            mods=['S16' if signed else 'U16']+([rounding] if rounding else [])
            ins['I2F_R_R']['mod_groups'][','.join(sorted(mods))]=group(0x306|(0x101000<<64)|(int(signed)<<74)|(mode<<78),fields)

    # FRND F32 rounding 0/1/2/3 = nearest/floor/ceil/truncate, FTZ[80].
    prototype=copy.deepcopy(ins['FRND_R_R'])
    fields=common+[f(32,8,'reg',2),f(62,1,'abs',2),f(63,1,'neg',2),f(123,1,'reuse',2)]
    groups={}
    for rounding,mode in [('',0),('FLOOR',1),('CEIL',2),('TRUNC',3)]:
        for ftz in [False,True]:
            mods=([rounding] if rounding else [])+(['FTZ'] if ftz else [])
            groups[','.join(sorted(mods))]=group(0x307|(0x201000<<64)|(mode<<78)|(int(ftz)<<80),fields)
    for k in ['FRND.CEIL_R_R','FRND.FLOOR_R_R','FRND.TRUNC_R_R']:
        if k in ins:ins[k]['encode_only']=True
    ins['FRND_R_R']=entry(prototype,'FRND','R_R',groups)

    # UIMAD.HI has its own 0x2a6 opcode; it is not UIMAD.WIDE's 0x2a5.
    fields=[f(12,4,'guard',0),f(16,8,'ureg',1),f(24,8,'ureg',2),f(32,8,'ureg',3),f(64,8,'ureg',4),f(75,1,'neg',4)]
    for signed in [False,True]:
        mods=['HI']+([] if signed else ['U32'])
        ins['UIMAD_UR_UR_UR_UR']['mod_groups'][','.join(sorted(mods))]=group(0x2a6|(0xf8e0000<<64)|(int(signed)<<73),fields)

    # IABS with a uniform source: replace the old field-less placeholder.
    prototype=copy.deepcopy(ins['IABS_R_UR'])
    prototype['ctrl_class']='alu_simple'
    ins['IABS_R_UR']=entry(prototype,'IABS','R_UR',{'':group(0xc13|(0x08000000<<64),common+[f(32,8,'ureg',2)])})

    # R2UR broadcast is a mode bit [87], retaining the usual source reuse.
    fields=[f(12,4,'guard',0),f(16,8,'ureg',1),f(24,8,'reg',2),f(122,1,'reuse',2)]
    ins['R2UR_UR_R']['mod_groups']['BROADCAST']=group(0x2ca|(0x008e0000<<64),fields)
    fields=[f(12,4,'guard',0),f(81,3,'pred',1),f(16,8,'ureg',2),f(24,8,'reg',3),f(122,1,'reuse',3)]
    if 'R2UR_P_UR_R' not in ins: ins['R2UR_P_UR_R']=entry(ins['R2UR_UR_R'],'R2UR','P_UR_R',{})
    ins['R2UR_P_UR_R']['mod_groups']['BROADCAST']=group(0x2ca|(0x00800000<<64),fields)

    # HMNMX's sign bits are operand bits 72/63. The legacy row also
    # declared source-negation at schedule bit109 (yield), causing thousands
    # of fake negative operands. A schedule bit is never an operand field.
    prototype=copy.deepcopy(ins['HMNMX2_R_R_R_P'])
    fields=common+[f(24,8,'reg',2),f(72,1,'neg',2),f(73,1,'abs',2),f(74,2,'hsel',2),f(122,1,'reuse',2),
                   f(32,8,'reg',3),f(62,1,'abs',3),f(63,1,'neg',3),f(60,2,'hsel',3),f(123,1,'reuse',3),
                   f(87,3,'pred',4),f(90,1,'neg',4)]
    groups={}
    for bf16 in [False,True]:
        for mode in range(8):
            mods=(['BF16_V2'] if bf16 else [])+[name for bit,name in enumerate(['FTZ','NAN','XORSIGN']) if mode&(1<<bit)]
            groups[','.join(sorted(mods))]=group(0x240|(int(bf16)<<85)|(mode<<80),fields)
    ins['HMNMX2_R_R_R_P']=entry(prototype,'HMNMX2','R_R_R_P',groups)

    # MUFU's function enum is [77:74]. Do not let the learned variable
    # mask absorb a SQRT8 word into the TANH9 variant. Neg/abs are 63/62.
    prototype=copy.deepcopy(ins['MUFU_R_R'])
    fields=common+[f(32,8,'reg',2),f(62,1,'abs',2),f(63,1,'neg',2)]
    groups={name:group(0x308|(mode<<74),fields) for mode,name in enumerate(['COS','SIN','EX2','LG2','RCP','RSQ','RCP64H','RSQ64H','SQRT','TANH'])}
    for dtype,bit in [('F16',72),('BF16',73)]:
        groups[','.join(sorted(['EX2',dtype]))]=group(0x308|(2<<74)|(1<<bit),fields)
    ins['MUFU_R_R']=entry(prototype,'MUFU','R_R',groups)
    return db


def canonicalize_floatalu(db):
    ins=db['instructions']
    prototype=copy.deepcopy(ins['FFMA_R_R_R_R'])
    shapes=[('R_R_R_R',0x223),('R_R_FI_R',0x823),('R_R_II_R',0x823),('R_R_R_FI',0x423),('R_R_R_II',0x423)]
    for signature,opbits in shapes:
        fields=[f(12,4,'guard',0),f(16,8,'reg',1),f(24,8,'reg',2),f(72,1,'neg',2),f(73,1,'abs',2),f(122,1,'reuse',2)]
        if signature=='R_R_R_R':
            fields += [f(32,8,'reg',3),f(62,1,'abs',3),f(63,1,'neg',3),f(123,1,'reuse',3),
                       f(64,8,'reg',4),f(74,1,'abs',4),f(75,1,'neg',4),f(124,1,'reuse',4)]
        elif signature.endswith('_R'):
            fields += [f(32,32,'f32',3),f(64,8,'reg',4),f(74,1,'abs',4),f(75,1,'neg',4),f(124,1,'reuse',4)]
        else:
            fields += [f(64,8,'reg',3),f(74,1,'abs',3),f(75,1,'neg',3),f(123,1,'reuse',3),f(32,32,'f32',4)]
        groups={}
        for flushing,bits in [('',0),('FMZ',1<<76),('FTZ',1<<80)]:
            for saturate in [False,True]:
                for rounding,mode in [('',0),('RM',1),('RP',2),('RZ',3)]:
                    mods=([flushing] if flushing else [])+(['SAT'] if saturate else [])+([rounding] if rounding else [])
                    groups[','.join(sorted(mods))]=group(opbits|bits|(int(saturate)<<77)|(mode<<78),fields)
        key='FFMA_'+signature
        ins[key]=entry(prototype,'FFMA',signature,groups)
        if 'II' in signature:ins[key]['encode_only']=True
        for oldkey in list(ins):
            if oldkey.startswith('FFMA.')and oldkey.endswith('_'+signature):ins[oldkey]['encode_only']=True

    # The uniform FADD packet is 0xe21 with the UR-identity bit91 set.
    # A's neg/abs are 72/73; B's are 63/62, independently of FTZ80.
    prototype=copy.deepcopy(ins['FADD_R_R_UR'])
    fields=[f(12,4,'guard',0),f(16,8,'reg',1),f(24,8,'reg',2),f(72,1,'neg',2),f(73,1,'abs',2),f(122,1,'reuse',2),
            f(32,8,'ureg',3),f(62,1,'abs',3),f(63,1,'neg',3)]
    groups={}
    for ftz in [False,True]:
        for saturate in [False,True]:
            for rounding,mode in [('',0),('RM',1),('RP',2),('RZ',3)]:
                mods=(['FTZ'] if ftz else [])+(['SAT'] if saturate else [])+([rounding] if rounding else [])
                groups[','.join(sorted(mods))]=group(0xe21|(1<<91)|(int(ftz)<<80)|(int(saturate)<<77)|(mode<<78),fields)
    ins['FADD_R_R_UR']=entry(prototype,'FADD','R_R_UR',groups)
    # The ordinary immediate packet is 0x421 and owns all 32 literal bits;
    # the old L row printed baked 1.0 as 0x0 and shadowed the FI row.
    fields=[f(12,4,'guard',0),f(16,8,'reg',1),f(24,8,'reg',2),f(72,1,'neg',2),f(73,1,'abs',2),f(122,1,'reuse',2),f(32,32,'f32',3)]
    groups={}
    for ftz in [False,True]:
        for saturate in [False,True]:
            for rounding,mode in [('',0),('RM',1),('RP',2),('RZ',3)]:
                mods=(['FTZ'] if ftz else [])+(['SAT'] if saturate else [])+([rounding] if rounding else [])
                groups[','.join(sorted(mods))]=group(0x421|(int(ftz)<<80)|(int(saturate)<<77)|(mode<<78),fields)
    for key in ['FADD_R_R_L','FADD_R_R_II','FADD_R_R_FI']:
        if key in ins:ins[key]['encode_only']=True
    ins['FADD_R_R_FI']=entry(prototype,'FADD','R_R_FI',groups)
    ins['FADD_R_R_II']=entry(prototype,'FADD','R_R_II',groups)
    ins['FADD_R_R_II']['encode_only']=True
    return db


def canonicalize_compare2(db):
    ins=db['instructions']
    # DSETP shares the float compare fields; enum endpoints are MIN/MAX.
    prototype=copy.deepcopy(ins['DSETP_P_P_R_R_P'])
    fields=[f(12,4,'guard',0),f(81,3,'pred',1),f(84,3,'pred',2),f(24,8,'reg',3),f(72,1,'neg',3),f(73,1,'abs',3),f(122,1,'reuse',3),
            f(32,8,'reg',4),f(62,1,'abs',4),f(63,1,'neg',4),f(123,1,'reuse',4),f(87,3,'pred',5),f(90,1,'neg',5)]
    groups={}
    for cmp,name in enumerate(['MIN','LT','EQ','LE','GT','NE','GE','NUM','NAN','LTU','EQU','LEU','GTU','NEU','GEU','MAX']):
        for combine,boolean in enumerate(['AND','OR','XOR']):
            groups[','.join(sorted([name,boolean]))]=group(0x22a|(cmp<<76)|(combine<<74),fields)
    ins['DSETP_P_P_R_R_P']=entry(prototype,'DSETP','P_P_R_R_P',groups)

    # UISETP has width64[80] (opposite the normal ISETP packet),
    # signedness[73], compare[78:76], combine[75:74], EX[72].
    prototype=copy.deepcopy(ins['UISETP_UP_UP_UR_UR_UP'])
    legacy=copy.deepcopy(prototype['mod_groups'].get(''))
    for extended in [False,True]:
        signature='UP_UP_UR_UR_UP'+('_UP' if extended else '')
        fields=[f(12,4,'guard',0),f(81,3,'upred',1),f(84,3,'upred',2),f(24,8,'ureg',3),f(32,8,'ureg',4),f(87,3,'upred',5),f(90,1,'inv',5)]
        if extended:fields += [f(68,3,'upred',6),f(71,1,'inv',6)]
        groups={}
        for wide in [False,True]:
            for signed in [False,True]:
                dtype=('S64' if signed else 'U64') if wide else ('' if signed else 'U32')
                for cmp,name in enumerate(['F','LT','EQ','LE','GT','NE','GE','T']):
                    for combine,boolean in enumerate(['AND','OR','XOR']):
                        mods=[name,boolean]+([dtype] if dtype else [])+(['EX'] if extended else [])
                        base=0x28c|(0x08000070<<64)|(int(wide)<<80)|(int(signed)<<73)|(cmp<<76)|(combine<<74)|(int(extended)<<72)
                        groups[','.join(sorted(mods))]=group(base,fields)
        if legacy and not extended:
            legacy['encode_only']=True;groups['']=legacy
        ins['UISETP_'+signature]=entry(prototype,'UISETP',signature,groups)
    return db


def canonicalize_iadd(db):
    ins=db['instructions']
    prototype=copy.deepcopy(ins['IADD_R_R_R'])
    # IADD has separate reg, literal32 and uniform packets (235/835/c35).
    # X[74] changes the meanings of source flags 72/63 from negation to
    # bitwise inversion and enables the input-carry predicate [90:87].
    for key in list(ins):
        if key.startswith('IADD_') or key.startswith('IADD.'):
            ins[key]['encode_only']=True
    for extended in [False,True]:
        for carryout in [False,True]:
            for kind,packet in [('R',0x235),('II',0x835),('UR',0xc35|(1<<91))]:
                signature='R_'+('P_' if carryout else '')+'R_'+kind+('_P' if extended else '')
                a=3 if carryout else 2;b=a+1
                fields=[f(12,4,'guard',0),f(16,8,'reg',1),f(24,8,'reg',a),
                        f(72,1,'inv' if extended else 'neg',a),f(122,1,'reuse',a)]
                if carryout:fields.append(f(81,3,'pred',2))
                if kind=='II':fields.append(f(32,32,'imm',b))
                else:
                    fields += [f(32,8,'ureg' if kind=='UR' else 'reg',b),f(63,1,'inv' if extended else 'neg',b)]
                    if kind=='R':fields.append(f(123,1,'reuse',b))
                if extended:fields += [f(87,3,'pred',b+1),f(90,1,'inv',b+1)]
                base=packet|(int(extended)<<74)
                if not carryout:base|=7<<81
                # NVIDIA's canonical no-X packet stores the unused input
                # carry as !PT; no operand or raw-bit escape represents it.
                if not extended:base|=15<<87
                groups={}
                for wide in [False,True]:
                    mods=(['64'] if wide else [])+(['X'] if extended else [])
                    groups[','.join(sorted(mods))]=group(base|(int(wide)<<73),fields)
                ins['IADD_'+signature]=entry(prototype,'IADD',signature,groups)
    return db


def canonicalize_uniform_integer(db):
    ins=db['instructions']
    prototype=copy.deepcopy(ins['UIADD3_UR_UP_UP_UR_UR_UR'])
    # 32-bit UIADD3's three sources are complete eight-bit UR fields at
    # 24/32/64. X is bit74, not a different compact register layout. The
    # 64-bit packet (opcode297/897) is owned by its separate canonical row.
    for key in list(ins):
        if key.startswith('UIADD3_'):ins[key]['encode_only']=True
    for extended in [False,True]:
        for kind,packet in [('UR',0x290),('II',0x890)]:
            signature='UR_UP_UP_UR_'+kind+'_UR'+('_UP_UP' if extended else '')
            fields=[f(12,4,'guard',0),f(16,8,'ureg',1),f(81,3,'upred',2),f(84,3,'upred',3),
                    f(24,8,'ureg',4),f(72,1,'inv' if extended else 'neg',4),
                    f(64,8,'ureg',6),f(75,1,'inv' if extended else 'neg',6)]
            if kind=='II':fields.append(f(32,32,'imm',5))
            else:fields += [f(32,8,'ureg',5),f(63,1,'inv' if extended else 'neg',5)]
            base=packet|(1<<91)|(int(extended)<<74)
            if extended:fields += [f(87,3,'upred',7),f(90,1,'inv',7),f(77,3,'upred',8),f(80,1,'inv',8)]
            else:base|=(15<<87)|(15<<77)
            ins['UIADD3_'+signature]=entry(prototype,'UIADD3',signature,{'X' if extended else '':group(base,fields)})
    # UPOPC is uniform destination16/source32, with source inversion63.
    prototype=copy.deepcopy(ins['UPOPC_UR_UR'])
    fields=[f(12,4,'guard',0),f(16,8,'ureg',1),f(32,8,'ureg',2),f(63,1,'inv',2)]
    ins['UPOPC_UR_UR']=entry(prototype,'UPOPC','UR_UR',{'':group(0x2bf|(1<<91),fields)})
    return db


def canonicalize_alu_tail(db):
    ins=db['instructions']
    # DSETP's float-immediate and uniform packets have the same named
    # comparison/boolean layout as its register packet. The literal is the
    # high dword of a double, while the UR packet is 0xe2a plus identity91.
    prototype=copy.deepcopy(ins['DSETP_P_P_R_R_P'])
    ins.pop('DSETP_P_P_R_II_P',None)
    for kind,packet,extraction in [('FI',0x42a,'f64hi'),('UR',0xe2a|(1<<91),'ureg')]:
        fields=[f(12,4,'guard',0),f(81,3,'pred',1),f(84,3,'pred',2),f(24,8,'reg',3),
                f(72,1,'neg',3),f(73,1,'abs',3),f(122,1,'reuse',3),
                f(32,8 if kind=='UR' else 32,extraction,4),f(87,3,'pred',5),f(90,1,'inv',5)]
        if kind=='UR':fields += [f(62,1,'abs',4),f(63,1,'neg',4)]
        groups={}
        for cmp,name in enumerate(['MIN','LT','EQ','LE','GT','NE','GE','NUM','NAN','LTU','EQU','LEU','GTU','NEU','GEU','MAX']):
            for combine,boolean in enumerate(['AND','OR','XOR']):
                groups[','.join(sorted([name,boolean]))]=group(packet|(cmp<<76)|(combine<<74),fields)
        key=f'DSETP_P_P_R_{kind}_P';ins[key]=entry(prototype,'DSETP',f'P_P_R_{kind}_P',groups)

    # I2F U8/S8 signedness74 is independent of the source byte selector.
    fields=[f(12,4,'guard',0),f(16,8,'reg',1),f(32,8,'reg',2),f(60,2,'byte_sel',2)]
    for signed in [False,True]:
        for rounding,mode in [('',0),('RM',1),('RP',2),('RZ',3)]:
            mods=['S8' if signed else 'U8']+([rounding] if rounding else [])
            ins['I2F_R_R']['mod_groups'][','.join(sorted(mods))]=group(0x306|(0x1000<<64)|(int(signed)<<74)|(mode<<78),fields)

    # UFLO.SH is bit74; signedness73 suppresses the explicit U32 suffix.
    prototype=copy.deepcopy(ins['UFLO_UR_UR'])
    for carryout in [False,True]:
        signature='UR_UP_UR' if carryout else 'UR_UR';src=3 if carryout else 2
        fields=[f(12,4,'guard',0),f(16,8,'ureg',1),f(32,8,'ureg',src),f(63,1,'inv',src)]
        if carryout:fields.append(f(81,3,'upred',2))
        groups={}
        for signed in [False,True]:
            for shift in [False,True]:
                mods=([] if signed else ['U32'])+(['SH'] if shift else [])
                base=0x2bd|(1<<91)|(int(signed)<<73)|(int(shift)<<74)|(0 if carryout else 7<<81)
                groups[','.join(sorted(mods))]=group(base,fields)
        ins['UFLO_'+signature]=entry(prototype,'UFLO',signature,groups)

    # I2FP's uniform source is a UR at32, rather than a baked register.
    prototype=copy.deepcopy(ins['I2FP_R_UR'])
    fields=[f(12,4,'guard',0),f(16,8,'reg',1),f(32,8,'ureg',2)]
    groups={}
    for signed in [False,True]:
        groups['F32,'+('S32' if signed else 'U32')]=group(0xc45|(0x08201000<<64)|(int(signed)<<74),fields)
    ins['I2FP_R_UR']=entry(prototype,'I2FP','R_UR',groups)
    ins['I2FP.F32.S32_R_UR']=entry(prototype,'I2FP.F32.S32','R_UR',{'':groups['F32,S32']})
    ins['I2FP.F32.S32_R_UR']['encode_only']=True

    # UFSEL literal32 is an ordinary float with independent A signs and
    # uniform selector predicate87/90. The old placeholder had no fields.
    prototype=copy.deepcopy(ins['UFSEL_UR_UR_II_UP'])
    for key in list(ins):
        if key.startswith('UFSEL_')and '_UR_UR_UR_' not in key:ins[key]['encode_only']=True
    fields=[f(12,4,'guard',0),f(16,8,'ureg',1),f(24,8,'ureg',2),f(72,1,'neg',2),f(73,1,'abs',2),
            f(32,32,'f32',3),f(87,3,'upred',4),f(90,1,'inv',4)]
    groups={mods:group(0x851|(1<<91)|(int(bool(mods))<<80),fields)for mods in ['', 'FTZ']}
    ins['UFSEL_UR_UR_FI_UP']=entry(prototype,'UFSEL','UR_UR_FI_UP',groups)
    ins['UFSEL_UR_UR_II_UP']=entry(prototype,'UFSEL','UR_UR_II_UP',groups)
    ins['UFSEL_UR_UR_II_UP']['encode_only']=True

    # VIMNMX type is a real enum [74:72], not abs/neg source flags.
    prototype=copy.deepcopy(ins['VIMNMX_R_R_R_P'])
    for key in list(ins):
        if key.startswith('VIMNMX'):ins[key]['encode_only']=True
    for kind,packet in [('R',0x248),('II',0x848),('UR',0xc48|(1<<91))]:
        fields=[f(12,4,'guard',0),f(16,8,'reg',1),f(24,8,'reg',2),f(122,1,'reuse',2),
                f(32,32 if kind=='II' else 8,'imm' if kind=='II' else 'ureg' if kind=='UR' else 'reg',3),
                f(87,3,'pred',4),f(90,1,'inv',4)]
        if kind=='R':fields.append(f(123,1,'reuse',3))
        groups={}
        for code,dtype in enumerate(['U32','S32','U16x2','S16x2','U8x4','S8x4']):
            for relu in [False,True]:
                mods=[dtype]+(['RELU'] if relu else [])
                groups[','.join(sorted(mods))]=group(packet|(0x7e<<80)|(code<<72)|(int(relu)<<76),fields)
        ins[f'VIMNMX_R_R_{kind}_P']=entry(prototype,'VIMNMX',f'R_R_{kind}_P',groups)
    return db


def canonicalize_alu64(db):
    ins=db['instructions']
    # The HI integer-MAD packet optionally writes UP[83:81]. X[74] adds
    # its input-carry UP[90:87], using the ordinary eight-bit UR operands.
    prototype=copy.deepcopy(ins['UIMAD_UR_UR_UR_UR'])
    for carryout in [False,True]:
        for extended in [False,True]:
            signature='UR_'+('UP_' if carryout else '')+'UR_UR_UR'+('_UP' if extended else '')
            a=3 if carryout else 2
            fields=[f(12,4,'guard',0),f(16,8,'ureg',1),f(24,8,'ureg',a),f(32,8,'ureg',a+1),
                    f(64,8,'ureg',a+2),f(75,1,'neg',a+2)]
            if carryout:fields.append(f(81,3,'upred',2))
            if extended:fields += [f(87,3,'upred',a+3),f(90,1,'inv',a+3)]
            groups=copy.deepcopy(ins.get('UIMAD_'+signature,{}).get('mod_groups',{}))
            for signed in [False,True]:
                mods=['HI']+([] if signed else ['U32'])+(['X'] if extended else [])
                base=0x2a6|(1<<91)|(int(signed)<<73)|(int(extended)<<74)
                if not carryout:base|=7<<81
                if not extended:base|=15<<87
                groups[','.join(sorted(mods))]=group(base,fields)
            ins['UIMAD_'+signature]=entry(prototype,'UIMAD',signature,groups)

    # 64-bit min/max predicates surround ordinary complete-byte registers.
    # The two input predicates have distinct inversion bits90 and80.
    for uniform in [False,True]:
        base='UIMNMX' if uniform else 'IMNMX'
        prototype=copy.deepcopy(next(v for k,v in ins.items() if k.startswith(base+'.S64_')))
        for key in list(ins):
            if key.startswith(base+'.S64_')or key.startswith(base+'.U64_'):ins[key]['encode_only']=True
        p='UP' if uniform else 'P';r='UR' if uniform else 'R';kind='UR'
        signature=f'{p}_{p}_{r}_{r}_{kind}_{p}_{p}'
        fields=[f(12,4,'guard',0),f(81,3,'upred' if uniform else 'pred',1),f(84,3,'upred' if uniform else 'pred',2),
                f(16,8,'ureg' if uniform else 'reg',3),f(24,8,'ureg' if uniform else 'reg',4),f(32,8,'ureg',5),
                f(87,3,'upred' if uniform else 'pred',6),f(90,1,'inv',6),
                f(77,3,'upred' if uniform else 'pred',7),f(80,1,'inv',7)]
        if not uniform:fields.append(f(122,1,'reuse',4))
        packet=(0x285 if uniform else 0xc17)|(1<<91)|(1<<74)
        groups={dtype:group(packet|(int(dtype=='S64')<<73),fields)for dtype in ['U64','S64']}
        ins[base+'_'+signature]=entry(prototype,base,signature,groups)
        # Fully-qualified historical aliases must use the same fields when
        # authored, but only the generic typed row participates in decode.
        for dtype in ['U64','S64']:
            key=base+'.'+dtype+'_'+signature
            ins[key]=entry(prototype,base+'.'+dtype,signature,{'':groups[dtype]});ins[key]['encode_only']=True

    # SHF's literal-last packet (0x419) stores its middle register at64 and
    # all32 literal bits at32. Type[74:73], W75, R76 and HI80 are independent.
    prototype=copy.deepcopy(ins['SHF_R_R_R_II'])
    fields=[f(12,4,'guard',0),f(16,8,'reg',1),f(24,8,'reg',2),f(122,1,'reuse',2),
            f(64,8,'reg',3),f(123,1,'reuse',3),f(32,32,'imm',4)]
    groups={}
    for dtype,typebits in [('S64',0),('U64',1),('S32',2),('U32',3)]:
        for right in [False,True]:
            for wrap in [False,True]:
                for high in [False,True]:
                    mods=[dtype,'R' if right else 'L']+(['W'] if wrap else [])+(['HI'] if high else [])
                    groups[','.join(sorted(mods))]=group(0x419|(typebits<<73)|(int(right)<<76)|(int(wrap)<<75)|(int(high)<<80),fields)
    ins['SHF_R_R_R_II']=entry(prototype,'SHF','R_R_R_II',groups)
    return db


def canonicalize_alu_tail2(db):
    ins=db['instructions'];common=[f(12,4,'guard',0),f(16,8,'reg',1)]
    # F64 integer conversion has a distinct 0x312 packet. Width84/85,
    # signedness74 and rounding78/79 retain the measured conversion enums.
    for width,code in [(8,0),(16,1),(32,2),(64,3)]:
        fields=common+[f(32,8,'reg',2)]
        if width==8:fields.append(f(60,2,'byte_sel',2))
        if width==16:fields.append(f(60,1,'opmod:H1',2))
        for signed in [False,True]:
            for rounding,mode in [('',0),('RM',1),('RP',2),('RZ',3)]:
                mods=['F64']+([] if signed and width==32 else [('S' if signed else 'U')+str(width)])+([rounding] if rounding else [])
                row=group(0x312|(0x1800<<64)|(code<<84)|(int(signed)<<74)|(mode<<78),fields)
                ins['I2F_R_R']['mod_groups'][','.join(sorted(mods))]=row
                if signed and width==32:
                    alias=copy.deepcopy(row);alias['encode_only']=True
                    ins['I2F_R_R']['mod_groups'][','.join(sorted(mods+['S32']))]=alias
    for signed in [False,True]:
        for rounding,mode in [('',0),('RM',1),('RP',2),('RZ',3)]:
            mods=['BF16']+([] if signed else ['U32'])+([rounding] if rounding else [])
            ins['I2F_R_R']['mod_groups'][','.join(sorted(mods))]=group(0x306|(0x202000<<64)|(int(signed)<<74)|(mode<<78),common+[f(32,8,'reg',2)])

    fields=common+[f(32,8,'reg',2),f(62,1,'abs',2),f(63,1,'neg',2)]
    for rounding,mode in [('',0),('FLOOR',1),('CEIL',2),('TRUNC',3)]:
        for ftz in [False,True]:
            mods=['F64']+([rounding] if rounding else [])+(['FTZ'] if ftz else [])
            ins['FRND_R_R']['mod_groups'][','.join(sorted(mods))]=group(0x313|(0x301800<<64)|(mode<<78)|(int(ftz)<<80),fields)

    prototype=copy.deepcopy(ins['SGXT_R_R_II']);fields=common+[f(24,8,'reg',2),f(32,8,'reg',3)]
    groups={}
    for signed in [False,True]:
        for wide in [False,True]:
            mods=([] if signed else ['U32'])+(['W'] if wide else [])
            groups[','.join(sorted(mods))]=group(0x21a|(int(signed)<<73)|(int(wide)<<75),fields)
    ins['SGXT_R_R_R']=entry(prototype,'SGXT','R_R_R',groups)

    prototype=copy.deepcopy(ins['USHF_UR_UR_UR_UR'])
    fields=[f(12,4,'guard',0),f(16,8,'ureg',1),f(24,8,'ureg',2),f(32,8,'ureg',3),f(64,8,'ureg',4)]
    groups={}
    for dtype,typebits in [('S64',0),('U64',1),('S32',2),('U32',3)]:
        for right in [False,True]:
            for wrap in [False,True]:
                for high in [False,True]:
                    mods=[dtype,'R' if right else 'L']+(['W'] if wrap else [])+(['HI'] if high else [])
                    groups[','.join(sorted(mods))]=group(0x299|(1<<91)|(typebits<<73)|(int(right)<<76)|(int(wrap)<<75)|(int(high)<<80),fields)
    ins['USHF_UR_UR_UR_UR']=entry(prototype,'USHF','UR_UR_UR_UR',groups)

    prototype=copy.deepcopy(ins['UFSEL_UR_UR_UR_UP'])
    fields=[f(12,4,'guard',0),f(16,8,'ureg',1),f(24,8,'ureg',2),f(72,1,'neg',2),f(73,1,'abs',2),
            f(32,8,'ureg',3),f(62,1,'abs',3),f(63,1,'neg',3),f(87,3,'upred',4),f(90,1,'inv',4)]
    ins['UFSEL_UR_UR_UR_UP']=entry(prototype,'UFSEL','UR_UR_UR_UP',{mods:group(0x251|(1<<91)|(int(bool(mods))<<80),fields)for mods in ['', 'FTZ']})

    prototype=copy.deepcopy(ins['PRMT_R_R_R_R'])
    fields=common+[f(24,8,'reg',2),f(64,8,'reg',3),f(32,8,'ureg',4)]
    # PRMT's selector-UR packet places its final printed selector at32,
    # while the middle printed R is at64. Enumerated legal mode values.
    modes={'':0,'F4E':1,'B4E':2,'RC8':3,'ECL':4,'ECR':5,'RC16':6}
    ins['PRMT_R_R_R_UR']=entry(prototype,'PRMT','R_R_R_UR',{name:group(0xe16|(1<<91)|(mode<<72),fields)for name,mode in modes.items()})

    prototype=copy.deepcopy(ins['ULOP3_UP_UR_UR_UR_UR_II_UP'])
    fields=[f(12,4,'guard',0),f(81,3,'upred',1),f(16,8,'ureg',2),f(24,8,'ureg',3),f(32,8,'ureg',4),
            f(64,8,'ureg',5),f(72,8,'imm',6),f(87,3,'upred',7),f(90,1,'inv',7)]
    ins['ULOP3_UP_UR_UR_UR_UR_II_UP']=entry(prototype,'ULOP3','UP_UR_UR_UR_UR_II_UP',{'LUT':group(0x292|(1<<91),fields),'LUT,PAND':group(0x292|(1<<91)|(1<<80),fields)})

    prototype=copy.deepcopy(ins['UFSETP_UP_UP_UR_UR_UP'])
    for key in list(ins):
        if key.startswith('UFSETP'):ins[key]['encode_only']=True
    for kind,packet in [('UR',0x253),('FI',0x853),('II',0x853)]:
        fields=[f(12,4,'guard',0),f(81,3,'upred',1),f(84,3,'upred',2),f(24,8,'ureg',3),f(72,1,'neg',3),f(73,1,'abs',3),
                f(32,8 if kind=='UR' else 32,'ureg' if kind=='UR' else 'f32',4),f(87,3,'upred',5),f(90,1,'inv',5)]
        if kind=='UR':fields += [f(62,1,'abs',4),f(63,1,'neg',4)]
        groups={}
        for cmp,name in enumerate(['F','LT','EQ','LE','GT','NE','GE','NUM','NAN','LTU','EQU','LEU','GTU','NEU','GEU','T']):
            for combine,boolean in enumerate(['AND','OR','XOR']):
                for ftz in [False,True]:
                    mods=[name,boolean]+(['FTZ'] if ftz else [])
                    groups[','.join(sorted(mods))]=group(packet|(1<<91)|(cmp<<76)|(combine<<74)|(int(ftz)<<80),fields)
        key=f'UFSETP_UP_UP_UR_{kind}_UP';ins[key]=entry(prototype,'UFSETP',f'UP_UP_UR_{kind}_UP',groups)
        if kind=='II':ins[key]['encode_only']=True

    # UISETP immediate32 differs from UR only in its source packet and
    # source field width. Its independent type/compare/EX laws were probed.
    for extended in [False,True]:
        old='UISETP_UP_UP_UR_UR_UP'+('_UP' if extended else '')
        signature='UP_UP_UR_II_UP'+('_UP' if extended else '')
        groups={}
        for mods,row in ins[old]['mod_groups'].items():
            if not mods:continue
            fields=copy.deepcopy(row['fields'])
            for field in fields:
                if field['token_idx']==4 and field['extraction']=='ureg':field.update(bits=32,extraction='imm')
            base=int(row['and_base'],16);base=(base&~0xfff)|0x88c
            groups[mods]=group(base,fields)
        ins['UISETP_'+signature]=entry(ins[old],'UISETP',signature,groups)

    prototype=copy.deepcopy(ins['USEL_UR_UR_II_UP'])
    groups={}
    for wide in [False,True]:
        fields=[f(12,4,'guard',0),f(16,8,'ureg',1),f(24,8,'ureg',2),f(32,33 if wide else 32,'imm',3),f(87,3,'upred',4),f(90,1,'inv',4)]
        groups['64' if wide else '']=group((0x487 if wide else 0x887)|(1<<91),fields)
    for key in ['USEL_UR_UR_II_?','USEL_UR_UR_II_II']:
        if key in ins:ins[key]['encode_only']=True
    ins['USEL_UR_UR_II_UP']=entry(prototype,'USEL','UR_UR_II_UP',groups)
    ins['USEL.64_UR_UR_II_UP']=entry(prototype,'USEL.64','UR_UR_II_UP',{'':groups['64']});ins['USEL.64_UR_UR_II_UP']['encode_only']=True

    prototype=copy.deepcopy(ins['UPRMT_UR_UR_II_UR'])
    fields=[f(12,4,'guard',0),f(16,8,'ureg',1),f(24,8,'ureg',2),f(32,32,'imm',3),f(64,8,'ureg',4)]
    ins['UPRMT_UR_UR_II_UR']=entry(prototype,'UPRMT','UR_UR_II_UR',{'':group(0x896|(1<<91),fields)})
    return db


def canonicalize_fast3_alu(db):
    ins=db['instructions']
    # Register IMNMX64 uses the same two predicate-input windows as the
    # uniform-source packet, and ordinary byte registers at16/24/32.
    prototype=copy.deepcopy(ins['IMNMX_P_P_R_R_R_P_P'])
    fields=[f(12,4,'guard',0),f(81,3,'pred',1),f(84,3,'pred',2),f(16,8,'reg',3),
            f(24,8,'reg',4),f(122,1,'reuse',4),f(32,8,'reg',5),f(123,1,'reuse',5),
            f(87,3,'pred',6),f(90,1,'inv',6),f(77,3,'pred',7),f(80,1,'inv',7)]
    groups={dtype:group(0x217|(1<<74)|(int(dtype=='S64')<<73),fields)for dtype in ['S64','U64']}
    ins['IMNMX_P_P_R_R_R_P_P']=entry(prototype,'IMNMX','P_P_R_R_R_P_P',groups)
    for dtype in ['S64','U64']:
        key=f'IMNMX.{dtype}_P_P_R_R_R_P_P'
        if key in ins:
            ins[key]=entry(prototype,'IMNMX.'+dtype,'P_P_R_R_R_P_P',{'':groups[dtype]});ins[key]['encode_only']=True

    # IMAD.HI's IRF-B packet has an optional ordinary output predicate81.
    prototype=copy.deepcopy(ins['IMAD_R_P_R_UR_R'])
    for extended in [False,True]:
        signature='R_P_R_UR_R'+('_P' if extended else '')
        fields=[f(12,4,'guard',0),f(16,8,'reg',1),f(81,3,'pred',2),f(24,8,'reg',3),f(122,1,'reuse',3),
                f(32,8,'ureg',4),f(64,8,'reg',5),f(75,1,'inv' if extended else 'neg',5),f(124,1,'reuse',5)]
        if extended:fields += [f(87,3,'pred',6),f(90,1,'inv',6)]
        groups=copy.deepcopy(ins.get('IMAD_'+signature,{}).get('mod_groups',{}))
        for signed in [False,True]:
            mods=['HI']+([] if signed else ['U32'])+(['X'] if extended else [])
            base=0xc27|(1<<91)|(int(signed)<<73)|(int(extended)<<74)
            if not extended:base|=15<<87
            groups[','.join(sorted(mods))]=group(base,fields)
        ins['IMAD_'+signature]=entry(prototype,'IMAD',signature,groups)

    prototype=copy.deepcopy(ins['UBMSK_UR_UR_II'])
    fields=[f(12,4,'guard',0),f(16,8,'ureg',1),f(24,8,'ureg',2),f(32,32,'imm',3)]
    ins['UBMSK_UR_UR_II']=entry(prototype,'UBMSK','UR_UR_II',{'':group(0x89b|(1<<91),fields),'W':group(0x89b|(1<<91)|(1<<75),fields)})

    # R2UR explicitly reports the participating-lane predicate when it is
    # other than PT; the nonbroadcast packet retains exactly that layout.
    fields=[f(12,4,'guard',0),f(81,3,'pred',1),f(16,8,'ureg',2),f(24,8,'reg',3),f(122,1,'reuse',3)]
    for mods,bits in [('',0),('OR',1<<84),('FILL',1<<86),('BROADCAST',1<<87)]:
        ins['R2UR_P_UR_R']['mod_groups'][mods]=group(0x2ca|bits,fields)
    return db



def canonicalize_oracle_semantics(db):
    ins = db['instructions']
    # BMSK has no signed operands. In particular global109 belongs only to
    # the explicit control code; the old neg@109 field conflated yield with
    # arithmetic semantics and could still produce a misleading exact inverse.
    prototype = copy.deepcopy(ins['BMSK_R_R_R'])
    fields = [f(12,4,'guard',0), f(16,8,'reg',1), f(24,8,'reg',2),
              f(32,8,'reg',3), f(122,1,'reuse',2), f(123,1,'reuse',3)]
    groups = {'':group(0x21b,fields), 'W':group(0x21b|(1<<75),fields)}
    ins['BMSK_R_R_R'] = entry(prototype,'BMSK','R_R_R',groups)
    ins['BMSK.W_R_R_R'] = entry(prototype,'BMSK.W','R_R_R',{'':groups['W']})
    ins['BMSK.W_R_R_R']['encode_only'] = True

    # UF2I's native UR destination is the complete byte[23:16], and its
    # source is byte[39:32]. A shifted4-bit destination plus a baked bit16
    # was invertible but represented the wrong register. Native sweeps cover
    # all eight selector bits, URZ, source neg/abs, and uniform guards.
    key = 'UF2I.FTZ.U32.TRUNC.NTZ_UR_UR'
    prototype = copy.deepcopy(ins[key])
    fields = [f(12,4,'guard',0), f(16,8,'ureg',1), f(32,8,'ureg',2),
              f(62,1,'abs',2), f(63,1,'neg',2)]
    ins[key] = entry(prototype,'UF2I.FTZ.U32.TRUNC.NTZ','UR_UR',{
        '':group(0x000000000821f000000000000000025c,fields)})
    # FCHK output is P[83:81], independent of the full byte Ra[31:24].
    # The old immediate row's extra pred@27 overwrote Ra bit3 while still
    # decoding it from the original word. All packet layouts are measured.
    prototype = copy.deepcopy(ins['FCHK_P_R_R'])
    for kind, packet, ext in [('R',0x302,'reg'), ('UR',0xd02|(1<<91),'ureg'),
                              ('FI',0x902,'f32cast'), ('II',0x902,'f32cast')]:
        fields = [f(12,4,'guard',0), f(81,3,'pred',1), f(24,8,'reg',2),
                  f(72,1,'neg',2), f(73,1,'abs',2), f(32,32 if kind in ['FI','II'] else 8,ext,3)]
        if kind in ['R','UR']:
            fields += [f(62,1,'abs',3), f(63,1,'neg',3)]
        key = 'FCHK_P_R_' + kind
        ins[key] = entry(prototype,'FCHK','P_R_'+kind,{'':group(packet,fields)})
        if kind == 'II': ins[key]['encode_only'] = True
    return db


def canonicalize_capture_tail_alu(db):
    ins = db['instructions']
    # All96 native RR32 selector combinations are directly NVIDIA-verified.
    # Preserve the independently repaired64-bit groups and all R/UR groups.
    for extended in [False, True]:
        key = 'ISETP_P_P_R_R_P' + ('_P' if extended else '')
        groups = ins[key]['mod_groups']
        measured64 = [(name, copy.deepcopy(g)) for name,g in groups.items()
                      if {'S64','U64'} & set(name.split(','))]
        for name,g in measured64:
            modifiers = ['U32' if m == 'U64' else m for m in name.split(',') if m != 'S64']
            groups[','.join(sorted(modifiers))] = group(int(g['and_base'],16)&~(1<<80),g['fields'])

    # The dedicated IMAD.HI immediate packet is827, with full literal32@32,
    # Rc8@64, output predicate81 (PT elides), carry-in87/90 for .X.
    # Rc75 means arithmetic negation on non-X and bitwise inverse on .X.
    prototype = copy.deepcopy(ins['IMAD_R_R_II_R'])
    for output_predicate in [False,True]:
        for extended in [False,True]:
            signature = ('R_P_R_II_R' if output_predicate else 'R_R_II_R')+('_P'if extended else '')
            ra,imm,rc = (3,4,5) if output_predicate else (2,3,4)
            fields = [f(12,4,'guard',0),f(16,8,'reg',1),f(24,8,'reg',ra),f(122,1,'reuse',ra),
                      f(32,32,'imm',imm),f(64,8,'reg',rc),f(75,1,'inv'if extended else 'neg',rc),f(124,1,'reuse',rc)]
            if output_predicate:fields += [f(81,3,'pred',2)]
            if extended:fields += [f(87,3,'pred',rc+1),f(90,1,'inv',rc+1)]
            groups = copy.deepcopy(ins.get('IMAD_'+signature,{}).get('mod_groups',{}))
            for signed in [False,True]:
                mods = ['HI']+([]if signed else ['U32'])+(['X']if extended else [])
                base = 0x827|(int(signed)<<73)|(int(extended)<<74)
                if not output_predicate:base |= 7<<81
                if not extended:base |= 15<<87
                groups[','.join(sorted(mods))] = group(base,fields)
            ins['IMAD_'+signature] = entry(prototype,'IMAD',signature,groups)
    return db

ORACLE_ANCHORS = [
    (0x000fda00038000000000000000ff782f,'ELECT P0, URZ, PT'),
    (0x000fe4000382000000000000004f782f,'ELECT P1, UR79, PT'),
    (0x000fe200037234000000004f3600720b,'FSETP.LE.OR P1, PT, R54, R79, P6'),
    (0x0c0fe20003f042000000000f0c00720b,'FSETP.GT.AND P0, PT, |R12|.reuse, R15.reuse, PT'),
    (0x000fe2000781000040000011ff177209,'FMNMX.FTZ R23, RZ, |R17|, !PT'),
    (0x000fca00038200004120000006067809,'FMNMX.NAN R6, R6, 10, PT'),
    (0x000fe2000384020043e0000005057809,'FMNMX.XORSIGN R5, |R5|, 448, PT'),
    (0x020fe2000020be2074e045422820747a,'QMMA.SF.16832.F32.E4M3.E2M1.E8 R32, R40, R66, R32, R69, R78, URZ'),
    (0x008ff600000800106000000c0808747f,'OMMA.SF.16864.F32.E2M1.E2M1.E8 R8, R8, R12, R16, R0, R0, UR6'),
    (0x000fe200000e0400d555555505097835,'IADD.X R9, R5, -0x2aaaaaab, P0'),
    (0x000fe200080e05008000000405097c35,'IADD.X R9, ~R5, ~UR4, P0'),
    (0x000fe200087fe4ff80000027ff057290,'UIADD3.X UR5, UPT, UPT, URZ, ~UR39, URZ, UP0, !UPT'),
    (0x000fc8000800000080000004000472bf,'UPOPC UR4, ~UR4'),
    (0x001e1e000070e600200000000400742a,'DSETP.GEU.OR P0, PT, |R4|, 1.4916681462400413487e-154, P0'),
    (0x000e24000bf2b0000000000402007e2a,'DSETP.LEU.AND P1, PT, R2, UR4, PT'),
    (0x000e6200000010002000003000007306,'I2F.U8 R0, R48.B2'),
    (0x000fcc00080e04000000000b000b72bd,'UFLO.U32.SH UR11, UR11'),
    (0x000fe200082014000000000700067c45,'I2FP.F32.S32 R6, UR7'),
    (0x000fe2000c8000003f80000007077851,'UFSEL UR7, UR7, 1, !UP1'),
    (0x0c0fe20003fe02000000000e120f7248,'VIMNMX.U16x2 R15, R18.reuse, R14.reuse, PT'),
    (0x060fe40003ffe6000000000204067217,'IMNMX.S64 PT, PT, R6, R4.reuse, R2, PT, !PT'),
    (0x000fc8000f800006000000040d067c27,'IMAD.HI.U32 R6, P0, R13, UR4, R6'),
    (0x000fe2000800000000000004ff06789b,'UBMSK UR6, URZ, 0x4'),
    (0x000fc80000000000000000000fff72ca,'R2UR P0, URZ, R15'),
    (0x000fe200000001ff00007fffff1f7431,'HFMA2 R31, -RZ, RZ, 0, +QNAN'),
    (0x000fe4000000000000000006090d721b,'BMSK R13, R9, R6'),
    (0x000fe4000000080000000006090d721b,'BMSK.W R13, R9, R6'),
    (0x000fcc000821f000000000040005725c,'UF2I.FTZ.U32.TRUNC.NTZ UR5, UR4'),
    (0x000e220000000000402df85418007902,'FCHK P0, R24, 2.7182817459106445312'),
    (0x000e2200000000000000000618007302,'FCHK P0, R24, R6'),
    (0x000e2200080000000000000d18007d02,'FCHK P0, R24, UR13'),
    (0x000fe20004765a700000001a1200720c,'ISETP.NE.XOR P3, PT, R18, R26, !P0'),
    (0x000fca00000e041effffffff2d1f7827,'IMAD.HI.U32.X R31, R45, -0x1, R30, P0'),
    (0x000fc8000f800c06000000040d067c27,'IMAD.HI.U32.X R6, P0, R13, UR4, ~R6, !PT'),
]


def verify_oracle(binary):
    for word,expected in ORACLE_ANCHORS:
        with tempfile.NamedTemporaryFile(suffix='.bin') as source:
            source.write(word.to_bytes(16,'little'));source.flush()
            p=subprocess.run([binary,'-raw','-ndf','-b','SM120',source.name],capture_output=True,text=True,check=True)
        m=re.search(r'/\*0000\*/\s*(.*?)\s*;',p.stdout)
        if m is None or m.group(1)!=expected:raise RuntimeError(f'NVIDIA oracle mismatch {word:032x}: {p.stdout}')
    print(f'NVIDIA oracle: {len(ORACLE_ANCHORS)} independent anchors verified')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--table',type=Path,required=True,help='Canonical ISA JSON; sync vendored tables separately with the normal pinned workflow')
    parser.add_argument('--verify-oracle',metavar='NVDISASM')
    args=parser.parse_args()
    if args.verify_oracle:verify_oracle(args.verify_oracle)
    guard = open(args.table.parent / '.sm120-edit.lock', 'a')
    fcntl.flock(guard, fcntl.LOCK_EX)
    before=args.table.read_bytes();db=json.loads(before)
    for repair in [canonicalize,canonicalize_smallalu,canonicalize_floatalu,canonicalize_compare2,
                   canonicalize_iadd,canonicalize_uniform_integer,canonicalize_alu_tail,
                   canonicalize_alu64,canonicalize_alu_tail2,canonicalize_fast3_alu,canonicalize_oracle_semantics,canonicalize_capture_tail_alu]:
        db=repair(db)
    indent = next((len(line)-len(line.lstrip()) for line in before.decode().splitlines() if line.lstrip().startswith(chr(34))), 2)
    after=(json.dumps(db,indent=indent,ensure_ascii=True)+'\n').encode()
    if after==before:print('Canonical fields already current');return
    with tempfile.NamedTemporaryFile(dir=args.table.parent,prefix=args.table.name+'.',delete=False)as target:
        target.write(after);name=target.name
    os.replace(name,args.table)
    print(f'Updated canonical fields in {args.table}')


if __name__=='__main__':main()

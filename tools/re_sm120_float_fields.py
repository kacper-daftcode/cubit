#!/usr/bin/env python3
"""Recover native SM120 float packets using named, independently probed fields.

Run --verify-oracle EVIDENCE.json to check every new mode and declared operand
field against NVIDIA nvdisasm. --table explicitly names the canonical database.
No original-word/residue field is authored.
"""
import argparse,copy,json,re,struct,subprocess,tempfile
from pathlib import Path
from re_sm120_memory_fields import split_operands
NV=Path('/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm')
SOURCE='SM120 float RE 2026-10-22: NVIDIA mode grids and independent operand fields'
def f(s,n,e,t):return dict(shift=s,bits=n,extraction=e,token_idx=t)
def group(base,fields):
 mask=0
 for q in fields:mask|=((1<<q['bits'])-1)<<q['shift']
 return dict(and_base=f'0x{base&~mask:032x}',variable_mask=f'0x{mask:032x}',fields=fields,count=1,_source=SOURCE)
def shapes():
 g=[f(12,4,'guard',0)]
 a=[f(16,8,'reg',1),f(24,8,'reg',2),f(72,1,'neg',2),f(73,1,'abs',2)]
 b=[f(32,8,'reg',3),f(62,1,'abs',3),f(63,1,'neg',3)]
 ua=[f(16,8,'ureg',1),f(24,8,'ureg',2),f(72,1,'neg',2),f(73,1,'abs',2)]
 fi=[f(32,32,'f32',3)]
 for name,sig,base,fields,rounds,flushes,saturation,scales in [
  ('FMUL','R_R_R',0x220,g+a+b+[f(122,1,'reuse',2),f(123,1,'reuse',3)],True,[('',0),('FMZ',1<<76),('FTZ',1<<80)],True,True),
  ('DMUL','R_R_R',0x228,g+a+b,True,[('',0)],False,False),
  ('FHADD','R_R_R',0x221|(1<<81),g+a+b+[f(83,1,'opmod:H1',2)],True,[('',0),('BF16',1<<82)],True,False),
  ('UFMUL','UR_UR_FI',0x856|(1<<91),g+ua+fi,True,[('',0),('FTZ',1<<80)],True,True),
  ('UFFMA','UR_UR_FI_UR',0x855|(1<<91),g+ua+fi+[f(64,8,'ureg',4),f(74,1,'abs',4),f(75,1,'neg',4)],True,[('',0),('FMZ',1<<76),('FTZ',1<<80)],True,False),
  ('FFMA','R_R_UR_R',0xc23|(1<<91),g+a+[f(32,8,'ureg',3),f(62,1,'abs',3),f(63,1,'neg',3),f(64,8,'reg',4),f(74,1,'abs',4),f(75,1,'neg',4),f(122,1,'reuse',2),f(124,1,'reuse',4)],True,[('',0),('FMZ',1<<76),('FTZ',1<<80)],True,False),
  ('FFMA','R_R_R_UR',0xe23|(1<<91),g+a+[f(64,8,'reg',3),f(74,1,'abs',3),f(75,1,'neg',3),f(32,8,'ureg',4),f(62,1,'abs',4),f(63,1,'neg',4),f(122,1,'reuse',2),f(123,1,'reuse',3)],True,[('',0),('FMZ',1<<76),('FTZ',1<<80)],True,False),
 ]:
  groups={}
  for flush,fb in flushes:
   for sat in ([False,True] if saturation else [False]):
    for rnd,rv in [('',0),('RM',1),('RP',2),('RZ',3)]:
     for scale,sv in ([('D8',1),('D4',2),('D2',3),('',4),('M2',5),('M4',6),('M8',7)] if scales else [('',0)]):
      mods=[s for s in (flush,'SAT' if sat else '',rnd,scale) if s]
      groups[','.join(sorted(mods))]=group(base|fb|(int(sat)<<77)|(rv<<78)|(sv<<84),fields)
  yield name+'_'+sig,name,sig,groups
 # Packed comparison's bool selector is 70:69; 75:74 and 61:60 are
 # independent half selectors, and BF16_V2 is bit65.
 for uniform in [False,True]:
  fields=g+[f(81,3,'pred',1),f(84,3,'pred',2),f(24,8,'reg',3),f(72,1,'neg',3),f(73,1,'abs',3),f(74,2,'hsel',3),
   f(32,8,'ureg' if uniform else 'reg',4),f(62,1,'abs',4),f(63,1,'neg',4),f(60,2,'hsel',4),f(87,3,'pred',5),f(90,1,'neg',5),f(122,1,'reuse',3)]
  if not uniform:fields.append(f(124,1,'reuse',4))
  groups={}
  compares=['F','LT','EQ','LE','GT','NE','GE','NUM','NAN','LTU','EQU','LEU','GTU','NEU','GEU','T']
  for cmp,compare in enumerate(compares):
   for bc,boolean in enumerate(['AND','OR','XOR']):
    for bf16 in [False,True]:
     for ftz in [False,True]:
      for horizontal in [False,True]:
       mods=[compare,boolean]+(['BF16_V2'] if bf16 else [])+(['FTZ'] if ftz else [])+(['H_AND'] if horizontal else [])
       base=(0xe34|(1<<91)) if uniform else 0x234
       groups[','.join(sorted(mods))]=group(base|(cmp<<76)|(bc<<69)|(int(bf16)<<65)|(int(ftz)<<80)|(int(horizontal)<<71),fields)
  sig='P_P_R_UR_P' if uniform else 'P_P_R_R_P'
  yield 'HSETP2_'+sig,'HSETP2',sig,groups
 # The uniform-source packed min/max has the same independent source half
 # selectors, with BF16_V2 at85 and min/max predicate at87/90. IS_A at65
 # changes the arity and is deliberately outside this four-operand form.
 fields=g+a+[f(74,2,'hsel',2),f(32,8,'ureg',3),f(62,1,'abs',3),f(63,1,'neg',3),f(60,2,'hsel',3),f(87,3,'pred',4),f(90,1,'neg',4),f(122,1,'reuse',2)]
 groups={}
 for bits in range(16):
  mods=[];base=0xc40|(1<<91)
  for bit,(name,shift) in enumerate([('BF16_V2',85),('FTZ',80),('NAN',81),('XORSIGN',82)]):
   if bits&(1<<bit):mods.append(name);base|=1<<shift
  groups[','.join(sorted(mods))]=group(base,fields)
 yield 'HMNMX2_R_R_UR_P','HMNMX2','R_R_UR_P',groups
 # Native FSET's boolean combine lives at75:74, separately from its
 # comparison at79:76. Its scalar sources have the ordinary independent
 # sign/absolute and reuse fields. This packet always displays BF.
 fields=g+a+b+[f(87,3,'pred',4),f(90,1,'neg',4),f(122,1,'reuse',2),f(123,1,'reuse',3)]
 groups={}
 for cmp,compare in enumerate(['F','LT','EQ','LE','GT','NE','GE','NUM','NAN','LTU','EQU','LEU','GTU','NEU','GEU','T']):
  for bc,boolean in enumerate(['AND','OR','XOR']):
   for ftz in [False,True]:
    mods=['BF',compare,boolean]+(['FTZ'] if ftz else [])
    groups[','.join(sorted(mods))]=group(0x20a|(cmp<<76)|(bc<<74)|(int(ftz)<<80),fields)
 yield 'FSET_R_R_R_P','FSET','R_R_R_P',groups
 # I2FP has source R@32 (not24) and its only legal scalar F32 rounding
 # selectors are RN=0 (elided) and RZ=3;1/2 are NVIDIA INVALID1/2.
 fields=g+[f(16,8,'reg',1),f(32,8,'reg',2),f(123,1,'reuse',2)]
 groups={}
 for signed in [False,True]:
  for rounding,value in [('',0),('RZ',3)]:
   mods=['F32','S32' if signed else 'U32']+([rounding] if rounding else [])
   groups[','.join(sorted(mods))]=group(0x245|(2<<75)|(2<<84)|(int(signed)<<74)|(value<<78),fields)
 yield 'I2FP_R_R','I2FP','R_R',groups

def oracle(words):
 if not words:return []
 with tempfile.TemporaryDirectory() as d:
  p=Path(d)/'probe.bin';p.write_bytes(b''.join(w.to_bytes(16,'little') for w in words))
  r=subprocess.run([str(NV),'-b','SM120',str(p)],capture_output=True,text=True,timeout=30)
 if r.returncode:
  if len(words)==1:return [dict(sass='',status='invalid',error=r.stderr,returncode=r.returncode)]
  half=len(words)//2;return oracle(words[:half])+oracle(words[half:])
 rows={int(m[1],16)//16:m[2].strip() for l in r.stdout.splitlines() if (m:=re.search(r'/\*([0-9a-fA-F]+)\*/\s+(.*?)\s*;',l))}
 return [dict(sass=rows.get(i,''),status='decoded' if rows.get(i) and 'INVALID' not in rows[i] and '???' not in rows[i] else 'invalid') for i in range(len(words))]

def verify_value(word,field,sass):
 e=field['extraction'];v=(word>>field['shift'])&((1<<field['bits'])-1)
 if e=='guard':
  m=re.match(r'^@(!?)(?:UP|P)([0-6]|T)\s',sass)
  actual=7 if not m else (7 if m[2]=='T' else int(m[2]))+(8 if m[1] else 0)
 else:
  _,ops=split_operands(sass);t=ops[field['token_idx']-1]
  if e in ('reg','ureg','pred'):
   m=re.search(r'(?:UR|UP|R|P)(Z|T|\d+)',t);assert m,(e,t)
   actual={'Z':255,'T':7}.get(m[1],int(m[1]) if m[1].isdigit() else -1)
  elif e=='f32':actual=int.from_bytes(struct.pack('<f',float(t)),'little')
  elif e=='neg':actual=int(t.startswith(('-','!')))
  elif e=='abs':actual=int('|' in t)
  elif e=='reuse':actual=int('.reuse' in t)
  elif e=='hsel':actual=3 if '.H1_H1' in t else 2 if '.H0_H0' in t else 1 if '.H0_H1' in t else 0
  elif e.startswith('opmod:'):actual=int('.'+e.split(':')[1] in t)
  else:raise ValueError(e)
 assert actual==v,(e,field,hex(word),v,actual,sass)

def verify(path):
 specs=list(shapes());probes=[]
 for key,op,sig,groups in specs:
  fields=next(iter(groups.values()))['fields']
  for mg,row in groups.items():
   # Every declared mode is independently checked with nontrivial operands.
   word=int(row['and_base'],16)|(7<<12)|(0xfe2<<104)
   for q in fields:
    if q['extraction'] in ('reg','ureg'):word|=6<<q['shift']
    elif q['extraction']=='pred':word|=7<<q['shift']
    elif q['extraction']=='hsel':word|=2<<q['shift']
    elif q['extraction']=='f32':word|=0x3f800000<<q['shift']
   probes.append((key,op,mg,fields,word,'mode'))
  mg=next(iter(groups));base=int(groups[mg]['and_base'],16)|(7<<12)|(0xfe2<<104)
  for q in fields:
   if q['extraction']=='pred':base|=7<<q['shift']
   if q['extraction']=='hsel':base|=2<<q['shift']
   if q['extraction']=='f32':base|=0x3f800000<<q['shift']
  for q in fields:
   e=q['extraction'];values=([0,1,7,31,63,127,254,255] if e in ('reg','ureg') else [0,1,6,7,8,14,15] if e=='guard' else [0,1,6,7] if e=='pred' else [0,2,3] if e=='hsel' else [0,0x3f800000,0xc02df854,0x3fffffff,0x80000000] if e=='f32' else [0,1])
   for v in values:
    w=(base&~(((1<<q['bits'])-1)<<q['shift']))|(v<<q['shift'])
    probes.append((key,op,mg,fields,w,e))
 results=oracle([p[4] for p in probes]);records=[]
 for (key,op,mg,fields,w,kind),result in zip(probes,results):
  if result['status']=='decoded':
   actual_op=split_operands(result['sass'])[0];tokens=actual_op.split('.')
   assert tokens[0]==op and ','.join(sorted(tokens[1:]))==mg,(key,mg,result)
   for q in fields:verify_value(w,q,result['sass'])
   result['status']='verified'
  elif kind=='mode':raise ValueError(('invalid authored mode',key,mg,result))
  records.append(dict(key=key,mods=mg,word=f'{w:032x}',probe=kind,**result))
 path.write_text(json.dumps(dict(oracle=str(NV),source=SOURCE,probes=records,verified=sum(r['status']=='verified' for r in records),invalid=sum(r['status']=='invalid' for r in records)),indent=2)+'\n')
 print(f"verified {sum(r['status']=='verified' for r in records)}; NVIDIA invalid {sum(r['status']=='invalid' for r in records)}")

def apply(db):
 ins=db['instructions']
 for key,op,sig,groups in shapes():
  proto=copy.deepcopy(ins.get(key) or ins['FADD_R_R_R'])
  proto.update(base_op=op,operand_sig=sig,ctrl_class='alu_simple' if op!='FFMA' else 'alu_iadd3',mod_groups=groups,_semantic_re=SOURCE)
  proto.pop('encode_only',None)
  if key not in ins:proto.pop('scheduling',None) # no invented hardware latency for newly named packets
  ins[key]=proto
  for alias in list(ins):
   if alias.startswith(op+'.') and alias.endswith('_'+sig):
    mods=','.join(sorted(alias[:-len('_'+sig)].split('.')[1:]))
    if mods in groups:
     ins[alias]=copy.deepcopy(proto);ins[alias].update(base_op=alias[:-len('_'+sig)],mod_groups={'':groups[mods]},encode_only=True)
 return db

def main():
 p=argparse.ArgumentParser();p.add_argument('--table',type=Path);p.add_argument('--verify-oracle',type=Path);a=p.parse_args()
 if a.verify_oracle:verify(a.verify_oracle)
 if a.table:
  db=apply(json.loads(a.table.read_bytes()));tmp=a.table.with_suffix('.json.float-tmp');tmp.write_text(json.dumps(db,indent=1,ensure_ascii=True)+'\n');tmp.replace(a.table)
 if not a.table and not a.verify_oracle:p.error('specify --table or --verify-oracle')
if __name__=='__main__':main()

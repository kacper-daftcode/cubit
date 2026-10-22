#!/usr/bin/env python3
"""SM120 memory-row recovery from NVIDIA decoded production witnesses.

The instruction words supply mode/opcode constants only. All addresses,
registers and guards are declared independent fields and verified by bit
perturbations through NVIDIA nvdisasm. No instruction/residue passthrough.
"""
import argparse,copy,json,re,subprocess,tempfile
from pathlib import Path
NV=Path('/usr/local/lib/python3.12/dist-packages/triton/backends/nvidia/bin/nvdisasm')

def f(bits,extraction,shift,token_idx):return dict(bits=bits,extraction=extraction,shift=shift,token_idx=token_idx)
G=f(4,'guard',12,0)
def row(code,fields):
 mask=0
 for q in fields:mask|=((1<<q['bits'])-1)<<q['shift']
 return dict(and_base=f'0x{code&~mask&((1<<96)-1):032x}',fields=fields,variable_mask=f'0x{mask:032x}',count=1)
def oracle(words):
 if not words:return []
 with tempfile.TemporaryDirectory() as d:
  p=Path(d)/'probe.bin';p.write_bytes(b''.join(w.to_bytes(16,'little') for w in words))
  q=subprocess.run([str(NV),'-b','SM120',str(p)],capture_output=True,text=True,timeout=60)
  if q.returncode:
   if 'Illegal instruction found' not in q.stderr:raise RuntimeError(f'NVIDIA oracle failed: {q.stderr}')
   # NVIDIA sometimes aborts a whole raw stream at an illegal instruction.
   # Bisect that stream so every remaining legal instruction still gets its
   # own oracle evidence, and rejected words stay explicitly INVALID.
   if len(words)==1:return ['INVALID (NVIDIA rejected the instruction)']
   mid=len(words)//2;return oracle(words[:mid])+oracle(words[mid:])
  out={}
  for l in q.stdout.splitlines():
   m=re.search(r'/\*([0-9a-fA-F]+)\*/\s+(.*?)\s*;',l)
   if m:out[int(m[1],16)//16]=m[2].strip()
  return [out.get(i,'') for i in range(len(words))]

def collect(failures):
 words=set()
 for path in failures:
  for line in Path(path).read_text().splitlines():
   try:
    record=json.loads(line);r=record.get('failure',record)
   except json.JSONDecodeError:continue
   if r.get('stage','decode') not in ('decode','mismatch','encode') or not r.get('expected'):continue
   w=int(r['expected'],16)
   if w&0xfff in (0x9a4,0x9a5,0x9b9,0x5b4,0x980,0x985,0x385,0x986,0x981,0x983,0x387,0x7ac,0x98c,0x3a9,0x38b,0x9a8,0x3aa,0x3ba,0x3b5,0x98e,0xfae,0x98f):words.add(w)
 return sorted(words)
def geometry(sass):
 clean=re.sub(r'^@\S+\s+','',sass);op=clean.split()[0];mods=op.split('.')[1:];base=op.split('.')[0]
 if base in ('ATOM','ATOMG') and 'CAS' in mods:return (base+'_P_R_ARI_R_R','P_R_ARI_R_R',mods,[G,f(3,'pred',81,1),f(8,'reg',16,2),f(8,'sub_r0',24,3),f(24,'sub_imm1',40,3),f(8,'reg',32,4),f(8,'reg',64,5)])
 if base=='ATOMG' and 'desc[' in clean:return ('ATOMG_P_R_dARI_R','P_R_dARI_R',mods,[G,f(3,'pred',81,1),f(8,'reg',16,2),f(8,'sub_ur0',64,3),f(8,'sub_r1',24,3),f(23,'sub_imm2',40,3),f(8,'reg',32,4)])
 if base=='QSPC':return ('QSPC_P_R_ARI','P_R_ARI',mods,[G,f(3,'pred',81,1),f(8,'reg',16,2),f(8,'sub_r0',24,3),f(24,'sub_imm1',40,3)])
 if base=='UBLKCP':return ('UBLKCP_AURI_AURI_UR','AURI_AURI_UR',mods,[G,f(8,'sub_ur0',32,1),f(8,'sub_ur0',24,2),f(8,'ureg',64,3)])
 if base=='UTMASTG':return ('UTMASTG_AURI_AURI','AURI_AURI',mods,[G,f(8,'sub_ur0',32,1),f(8,'sub_ur0',24,2)])
 if base=='REDG' and 'desc[' in clean:return ('REDG_dARI_R','dARI_R',mods,[G,f(8,'sub_ur0',64,1),f(8,'sub_r1',24,1),f(24,'sub_imm2',40,1),f(8,'reg',32,2)])
 if base=='LDGSTS':
  src=split_operands(clean)[1][1]
  if 'UR' not in src:return ('LDGSTS_ARI_ARI_P','ARI_ARI_P',mods,[G,f(8,'sub_r0',16,1),f(20,'sub_imm1',44,1),f(8,'sub_r0',24,2),f(12,'sub_imm1',32,2),f(4,'pred',87,3)])
  return ('LDGSTS_ARI_ARURI_P','ARI_ARURI_P',mods,[G,f(8,'sub_r0',16,1),f(20,'sub_imm1',44,1),f(8,'sub_r0',24,2),f(8,'sub_ur1',64,2),f(12,'sub_imm2',32,2),f(4,'pred',87,3)])
 if base=='CCTL':return ('CCTL_ARI','ARI',mods,[G,f(8,'sub_r0',24,1),f(32,'sub_imm1',32,1)])
 if base in ('ST','STG') and 'desc[' not in clean and ('+UR' in clean or re.search(r'\[UR',clean)):
  sig='ARURI_R'
  return (base+'_'+sig,sig,mods,[G,f(8,'sub_r0',24,1),f(8,'sub_ur1',64,1),f(24,'sub_imm2',40,1),f(8,'reg',32,2)])
 if base=='ST' and 'desc[' not in clean:return ('ST_ARI_R','ARI_R',mods,[G,f(8,'sub_r0',24,1),f(32,'sub_imm1',32,1),f(8,'reg',64,2)])
 if base=='LDG' and 'desc[' not in clean and '+UR' in clean:
  key=op+'_R_ARURI' if '.U32' in clean and set(mods) in ({'E'},{'E','GPU','STRONG'}) else 'LDG_R_ARURI'
  return (key,'R_ARURI',mods,[G,f(8,'reg',16,1),f(8,'sub_r0',24,2),f(8,'sub_ur1',32,2),f(24,'sub_imm2',40,2)])
 if base=='LDCU':return ('LDCU_UR_cAI','UR_cAI',mods,[G,f(8,'ureg',16,1),f(8,'sub_ur1',24,2),f(22,'cm17_off',37,2)])
 if base=='ATOMS':return ('ATOMS_R_ARURI_R','R_ARURI_R',mods,[G,f(8,'reg',16,1),f(8,'sub_r0',24,2),f(8,'sub_ur1',64,2),f(24,'sub_imm2',40,2),f(8,'reg',32,3)])
 if base=='LDGMC':return ('LDGMC_R_ARURI','R_ARURI',mods,[G,f(8,'reg',16,1),f(8,'sub_r0',24,2),f(24,'sub_imm2',40,2),f(8,'sub_ur1',64,2)])
 if base=='UTMACCTL':return ('UTMACCTL_AURI','AURI',mods,[G,f(8,'sub_ur0',24,1)])
 if base=='UTMALDG' and 'desc[' in clean:return ('UTMALDG_AURI_AURI_II','AURI_AURI_II',mods,[G,f(8,'sub_ur0',32,1),f(8,'sub_ur0',24,2),f(8,'desc_ur',40,3)])
 if base in ('LD','LDG') and 'desc[' in clean:return (base+'_R_dARI','R_dARI',mods,[G,f(8,'reg',16,1),f(8,'sub_r1',24,2),f(8,'sub_ur0',32,2),f(24,'sub_imm2',40,2)])
 if base=='ST' and 'desc[' in clean:return ('ST_dARI_R','dARI_R',mods,[G,f(8,'sub_r1',24,1),f(8,'sub_ur0',64,1),f(24,'sub_imm2',40,1),f(8,'reg',32,2)])
 if base=='LDL':return ('LDL_R_ARI','R_ARI',mods,[G,f(8,'reg',16,1),f(8,'sub_r0',24,2),f(24,'sub_imm1',40,2)])
 if base=='STL':return ('STL_ARI_R','ARI_R',mods,[G,f(8,'sub_r0',24,1),f(24,'sub_imm1',40,1),f(8,'reg',32,2)])
 return None


def split_operands(sass):
 """Split commas only outside bracketed operands; preserve descriptor groups."""
 clean=re.sub(r'^@\S+\s+','',sass.strip().rstrip(';').strip())
 parts=clean.split(None,1)
 if not parts:raise ValueError('missing opcode')
 if len(parts)==1:return parts[0],[]
 operands=[];start=0;stack=[];pairs={']':'[',')':'(','}':'{'}
 for i,c in enumerate(parts[1]):
  if c in '[({':stack.append(c)
  elif c in '])}':
   if not stack or stack.pop()!=pairs[c]:raise ValueError(f'unbalanced operand brackets: {sass}')
  elif c==',' and not stack:
   token=parts[1][start:i].strip()
   if not token:raise ValueError(f'empty operand: {sass}')
   operands.append(token);start=i+1
 if stack:raise ValueError(f'unbalanced operand brackets: {sass}')
 tail=parts[1][start:].strip()
 if not tail:raise ValueError(f'empty operand: {sass}')
 operands.append(tail)
 return parts[0],operands


def register_atom(atom):
 m=re.fullmatch(r'(UR|R)(Z|\d+)(?:\.[A-Za-z0-9_]+)*',atom.strip())
 if not m:raise ValueError(f'not a register atom: {atom}')
 return ('ur' if m[1]=='UR' else 'r'),(255 if m[2]=='Z' else int(m[2]))


def address_atoms(token):
 """Return ordered descriptor/base/index/immediate atoms from NV memory syntax.

 NVIDIA prints a signed negative displacement as ``R0+-0x1``. Normalize only
 that additive spelling; do not discard unknown operands or reorder atoms.
 """
 groups=re.findall(r'\[([^\[\]]*)\]',token)
 if not groups:raise ValueError(f'address brackets absent: {token}')
 outside=re.sub(r'\[[^\[\]]*\]','',token).strip()
 if outside not in ('','desc','c'):raise ValueError(f'unknown address prefix/suffix: {token}')
 atoms=[]
 for body in groups:
  body=body.replace('+-','-')
  pieces=[p.strip() for p in re.split(r'(?=[+-])',body) if p.strip()]
  if not pieces:raise ValueError(f'empty bracketed address: {token}')
  for atom in pieces:
   atom=atom[1:].strip() if atom.startswith('+') else atom
   if not atom:raise ValueError(f'empty address atom: {token}')
   if re.match(r'^(?:UR|R)',atom):atoms.append(register_atom(atom))
   else:
    try:atoms.append(('imm',int(atom,0)))
    except ValueError as e:raise ValueError(f'unknown address atom: {atom}') from e
 return atoms


def decoded_field(sass,field):
 extraction=field['extraction'];index=field['token_idx']
 if extraction=='guard':
  m=re.match(r'^@(!?)(?:UP|P)(T|[0-7])\s+',sass.strip())
  return 7 if m is None else (7 if m[2]=='T' else int(m[2]))+(8 if m[1] else 0)
 op,operands=split_operands(sass)
 if extraction=='pred' and index==3 and len(operands)==2 and op.split('.')[0]=='LDGSTS':return 7
 if not 1<=index<=len(operands):raise ValueError(f'operand {index} absent: {sass}')
 token=operands[index-1]
 if extraction=='pred':
  m=re.fullmatch(r'(!?)P(T|[0-7])',token)
  if not m:raise ValueError(f'expected P predicate: {token}')
  return (7 if m[2]=='T' else int(m[2]))+(8 if m[1] else 0)
 if extraction in ('reg','ureg'):
  kind,value=register_atom(token);expected_kind='r' if extraction=='reg' else 'ur'
  if kind!=expected_kind:raise ValueError(f'expected direct {expected_kind} register: {token}')
  return value
 if extraction=='cm17_off':
  atoms=address_atoms(token)
  if len(atoms) not in (2,3) or atoms[0][0]!='imm' or atoms[1][0] not in ('ur','imm') or (len(atoms)==3 and (atoms[1][0]!='ur' or atoms[2][0]!='imm')):
   raise ValueError(f'expected c[bank][UR+signed17] address: {token}')
  bank=atoms[0][1];offset=atoms[-1][1] if atoms[-1][0]=='imm' else 0
  if not 0<=bank<32 or not -(1<<16)<=offset<(1<<16):raise ValueError(f'constant-memory bank/offset out of range: {token}')
  return (bank<<17)|(offset&0x1ffff)
 if extraction=='desc_ur':
  m=re.fullmatch(r'desc\[\s*(UR(?:Z|\d+))\s*\]',token)
  if not m:raise ValueError(f'expected descriptor UR operand: {token}')
  return register_atom(m[1])[1]
 m=re.fullmatch(r'sub_(r|ur|imm)(\d+)',extraction)
 if not m:raise ValueError(f'unimplemented field extraction: {extraction}')
 atoms=address_atoms(token);sub=int(m[2])
 # ATOMS elides only the architecturally zero RZ base. Its uniform address
 # still has the logical R,UR,offset slots even when NV spells [URn+off].
 if split_operands(sass)[0].split('.')[0] in ('ATOMS','ST','STG') and token.startswith('[') and atoms[0][0]=='ur':atoms.insert(0,('r',255))
 # LDCU prints c[bank][offset] when a nonzero displacement accompanies
 # URZ; the same zero-index word at offset zero prints c[bank][URZ].
 if extraction=='sub_ur1' and token.startswith('c[') and len(atoms)==2 and atoms[1][0]=='imm':return 255
 base=split_operands(sass)[0].split('.')[0]
 if token.startswith('[') and atoms[0][0]=='imm' and base in ('ATOM','ATOMG','QSPC','CCTL','LDGSTS','ST'):atoms.insert(0,('r',255))
 if base=='LDGSTS' and index==2 and (extraction in ('sub_ur1','sub_imm2')) and (len(atoms)==1 or atoms[1][0]!='ur'):atoms.insert(1,('ur',255))
 # NVIDIA elides precisely the final zero offset. A missing register/index is
 # never treated as zero, nor is an omitted interior field synthesized.
 if sub==len(atoms) and m[1]=='imm':return 0
 if sub>=len(atoms):raise ValueError(f'address atom {sub} absent: {token}')
 kind,value=atoms[sub]
 if kind!=m[1]:raise ValueError(f'{extraction} selected {kind}, expected {m[1]}: {token}')
 return value


def expected_field(word,field):
 value=(word>>field['shift'])&((1<<field['bits'])-1)
 if field['extraction'].startswith('sub_imm') and value&(1<<(field['bits']-1)):
  value-=1<<field['bits']
 return value


def verify_instruction(key,mods,fields,word,sass):
 """Fail closed if a legal NV mutant disagrees with any authored field/mode."""
 if not sass or any(s in sass for s in ('INVALID','???')):
  return dict(status='invalid',reason='NVIDIA rejected the mutated instruction')
 decoded=geometry(sass)
 predicate=re.match(r'^@!?((?:UP|P))(?:T|[0-7])\s+',sass.strip())
 expected_kind='UP' if key.startswith(('UTMALDG_','UTMACCTL_','LDCU_','UTMASTG_','UBLKCP_')) else 'P'
 if predicate is not None and predicate[1]!=expected_kind:raise ValueError(f'predicate kind changed for {key}: {sass}')
 ldgsts_shapes={'LDGSTS_ARI_ARI_P','LDGSTS_ARI_ARURI_P','LDGSTS_ARI_ARI','LDGSTS_ARI_ARURI'}
 same_shape=decoded is not None and (decoded[0]==key or (decoded[0] in ldgsts_shapes and key in ldgsts_shapes))
 if not same_shape or ','.join(sorted(decoded[2]))!=mods:
  raise ValueError(f'mode changed for {key}/{mods}: {sass}')
 checks=[]
 for field in fields:
  expected=expected_field(word,field);actual=decoded_field(sass,field)
  if actual!=expected:
   raise ValueError(f"{key}/{mods} {field['extraction']} token {field['token_idx']} "
                    f"bits [{field['shift']}:{field['shift']+field['bits']}] "
                    f'authored {expected}, NVIDIA decoded {actual}: {sass}')
  checks.append(dict(extraction=field['extraction'],token_idx=field['token_idx'],expected=expected,actual=actual))
 return dict(status='verified',fields=checks)


def probe_values(field):
 if field['extraction']=='guard':return (0,1,6,7,8,14,15)
 if field['extraction']=='cm17_off':
  return tuple(sorted({0,1,0xffff,0x10000,0x1fffe,0x1ffff,0x20000,0x3e0000,0x3fffff,*[1<<i for i in range(22)]}))
 if field['extraction'].startswith('sub_imm'):
  if not 1<=field['bits']<=32:raise ValueError('unsupported signed memory displacement width')
  # Exercise every offset bit, zero elision, and both sides of the sign edge.
  return tuple(sorted(v for v in {0,1,7,31,63,127,255,*[1<<i for i in range(field['bits'])],(1<<(field['bits']-1))-1,1<<(field['bits']-1),(1<<field['bits'])-2,(1<<field['bits'])-1} if v<(1<<field['bits'])))
 return tuple(v for v in (0,1,7,31,63,127,254,255) if v<(1<<field['bits']))

def main():
 a=argparse.ArgumentParser();a.add_argument('canonical',type=Path);a.add_argument('--failures',nargs='+',required=True);a.add_argument('--evidence',type=Path,required=True);a.add_argument('--apply',action='store_true');o=a.parse_args()
 words=collect(o.failures)
 if not words:raise RuntimeError('no supported memory witness words in the supplied failure files')
 kinds={}
 for path in o.failures:
  for line in Path(path).read_text().splitlines():
   try:record=json.loads(line);record=record.get('failure',record)
   except (json.JSONDecodeError,AttributeError):continue
   if record.get('expected') and record.get('source_kind'):kinds[int(record['expected'],16)]=record['source_kind']
 texts=oracle(words);rows={};evidence=[]
 for w,t in zip(words,texts):
  if not t or any(x in t for x in ('INVALID','???')):continue
  geo=geometry(t)
  if geo is None:continue
  key,sig,mods,fields=geo;mg=','.join(sorted(mods));r=row(w,fields)
  if key=='LDG_R_ARURI' or (key.startswith('LDG.') and key.endswith('_R_ARURI')) or key in ('ST_ARURI64_R','STG_ARURI64_R','ST_ARURI_R','STG_ARURI_R'):r['addr_width']='U32' if '.U32' in t else '64'
  # Every declared source/destination byte must vary independently. The
  # full oracle sweep is retained for review; an illegal mutant is not used
  # as an instruction-row witness.
  k=(key,mg)
  if k in rows:
   if rows[k]['and_base']!=r['and_base']:raise RuntimeError(f'unexplained constant bits for {k}: {t}')
  else:rows[k]=r
  validation=verify_instruction(key,mg,fields,w,t)
  if validation['status']!='verified':raise RuntimeError(f'invalid original witness: {t}')
  evidence.append(dict(word=f'{w:032x}',sass=t,key=key,mods=mg,verified_fields=True,source_kind=kinds.get(w,'input_failure_witness')))
 if not rows:raise RuntimeError('no legal supported memory rows were recovered')
 # PT and URZ are architecturally fixed elisions in the shorter text.
 # Derive the missing short signature from the declared predicate field;
 # validate its independent word and every remaining field through NVIDIA.
 derived=[]
 for (key,mg),r in list(rows.items()):
  if key!='LDGSTS_ARI_ARI_P':continue
  pred=next(fld for fld in r['fields'] if fld['extraction']=='pred')
  fields=[fld for fld in r['fields'] if fld is not pred]
  w=int(r['and_base'],16)|(7<<pred['shift'])|(7<<12)|(0xfe2<<104)
  short_key='LDGSTS_ARI_ARI';sass=oracle([w])[0]
  verify_instruction(short_key,mg,fields,w,sass)
  rows[(short_key,mg)]=row(w,fields)
  derived.append(dict(key=short_key,mods=mg,word=f'{w:032x}',sass=sass,source='independent NVIDIA PT/URZ-elision probe; not a runtime witness'))
 # Probe each representative field at independent values. This is evidence,
 # not a bypass: no probed words are encoder inputs in the strict roundtrip.
 probes=[]
 for (key,mg),r in rows.items():
  base=int(r['and_base'],16)|(0x7<<12)|(0xfe2<<104)
  for field in r['fields']:
   for v in probe_values(field):
    mask=((1<<field['bits'])-1)<<field['shift'];probes.append((key,mg,field,v,(base&~mask)|(v<<field['shift'])))
 decoded=oracle([p[-1] for p in probes])
 records=[];verified_by_field={}
 for p,t in zip(probes,decoded):
  verification=verify_instruction(p[0],p[1],rows[(p[0],p[1])]['fields'],p[-1],t)
  if verification['status']=='verified':
   identity=(p[0],p[1],p[2]['extraction'],p[2]['token_idx'])
   verified_by_field.setdefault(identity,set()).add(p[3])
  records.append(dict(key=p[0],mods=p[1],field=p[2],value=p[3],word=f'{p[-1]:032x}',sass=t,verification=verification))
 # An invalid mutant is retained explicitly, never counted as verification.
 # Every declared field must have independent legal evidence before --apply.
 for (key,mg),r in rows.items():
  for field in r['fields']:
   identity=(key,mg,field['extraction'],field['token_idx'])
   if len(verified_by_field.get(identity,set()))<2:raise RuntimeError(f'insufficient legal independent probes for {identity}')
 retire=[]
 if ('LDG_R_dARI','128,E,LTC128B') in rows:
  # The former encode-only era scout steals genuine NVIDIA text and
  # emits opcode 0x980; native semantics must own this exact spelling.
  retire.append(dict(key='LDG.E.LTC128B.128_R_dARI',mod_group='128,E,LTC128B'))
 if any(k=='LDCU_UR_cAI' for k,_ in rows):
  retire.extend(dict(key=k,mod_group='') for k in ('LDCU.64_UR_cAI_II','LDCU.64_UR_cAI_II_?','LDCU.64_UR_cAI_II_II_?'))
 if ('ATOMS_R_ARURI_R','ADD') in rows:
  # These learned rows mistake the address UR byte for a fourth R operand;
  # their fixed-bit specificity would otherwise steal the genuine row.
  retire.extend(dict(key='ATOMS_R_ARI_R_R',mod_group=mg) for mg in ('ADD','MAX,S32'))
 if ('LDG_R_ARURI','E') in rows:
  retire.append(dict(key='LDG.E_R_ARURI',mod_group='E'))
 if ('LDG_R_ARURI','64,E') in rows:
  # The old full-opcode donor hardcodes b92=1, but every observed native
  # witness has b92=0. NVIDIA renders both identically, so do not invent a
  # semantic field to preserve the unsupported donor's reserved-bit value.
  retire.append(dict(key='LDG.E.64_R_ARURI',mod_group='64,E'))
 result=dict(witnesses=evidence,derived_elision_rows=derived,probes=records,rows=len(rows),verified_probes=sum(r['verification']['status']=='verified' for r in records),invalid_probes=sum(r['verification']['status']=='invalid' for r in records),all_legal_probes_verified=True,retire_rows=retire,candidate_rows={key:dict(mod_groups={mg:r for (k,mg),r in rows.items() if k==key}) for key,_ in rows})
 o.evidence.write_text(json.dumps(result,indent=2)+'\n')
 if o.apply:
  data=json.loads(o.canonical.read_text());ins=data['instructions']
  for retired in retire:
   key=retired['key']
   if key in ins:
    ins[key]['mod_groups'].pop(retired['mod_group'],None)
    if not ins[key]['mod_groups']:del ins[key]
  for (key,mg),r in rows.items():
   entry=ins.setdefault(key,dict(base_op=key.split('_')[0],operand_sig=key.split('_',1)[1],ctrl_class='ld_generic' if key.startswith('LD') else 'alu_simple',scheduling=dict(def_latency=0,is_variable_latency=True,pipe_class=0,pipe_name='UNKNOWN'),mod_groups={}))
   entry['mod_groups'][mg]=r
  tmp=o.canonical.with_suffix('.json.memory-tmp');tmp.write_text(json.dumps(data,indent=1,ensure_ascii=True)+'\n');tmp.replace(o.canonical)
 print(json.dumps(dict(rows=len(rows),witnesses=len(evidence),probes=len(probes),verified_probes=result['verified_probes'],invalid_probes=result['invalid_probes'])))
if __name__=='__main__':main()

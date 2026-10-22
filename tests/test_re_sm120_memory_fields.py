"""Independent address/field checks for the NVIDIA-backed memory recovery tool."""
import importlib.util
from pathlib import Path
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/'tools'/'re_sm120_memory_fields.py'
SPEC=importlib.util.spec_from_file_location('re_sm120_memory_fields',SCRIPT)
MEM=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(MEM)

class MemoryFieldParsing(unittest.TestCase):
 def test_operand_split_preserves_bracketed_commas(self):
  op,operands=MEM.split_operands('@!P2 UTMALDG.2D [UR1, UR2], [UR3], desc[UR4];')
  self.assertEqual(op,'UTMALDG.2D')
  self.assertEqual(operands,['[UR1, UR2]','[UR3]','desc[UR4]'])
  with self.assertRaises(ValueError):MEM.split_operands('LD R0, desc[UR2][R4')

 def test_descriptor_register_positions_are_distinct(self):
  text='LDG.E.STRONG.SYS R7, desc[UR11][R29.64+-0x2]'
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'reg',16,1)),7)
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'sub_ur0',32,2)),11)
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'sub_r1',24,2)),29)
  self.assertEqual(MEM.decoded_field(text,MEM.f(24,'sub_imm2',40,2)),-2)

 def test_ldgmc_uniform_index_is_second_address_atom(self):
  text='LDGMC.E.ADD.32.STRONG.SYS R13, [R23.64+UR41+0x123]'
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'sub_r0',24,2)),23)
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'sub_ur1',64,2)),41)
  with self.assertRaises(ValueError):MEM.decoded_field(text,MEM.f(8,'sub_ur0',64,2))

 def test_only_final_zero_offset_can_be_elided(self):
  text='LDL.U16 RZ, [RZ]'
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'reg',16,1)),255)
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'sub_r0',24,2)),255)
  self.assertEqual(MEM.decoded_field(text,MEM.f(24,'sub_imm1',40,2)),0)
  with self.assertRaises(ValueError):MEM.decoded_field(text,MEM.f(8,'sub_ur1',64,2))
  with self.assertRaises(ValueError):MEM.decoded_field(text,MEM.f(24,'sub_imm2',40,2))

 def test_uniform_sentinel_and_descriptor(self):
  text='UTMALDG.2D [UR31], [URZ], desc[UR255]'
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'sub_ur0',32,1)),31)
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'sub_ur0',24,2)),255)
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'desc_ur',40,3)),255)

 def test_signed24_boundaries_and_nv_negative_spelling(self):
  field=MEM.f(24,'sub_imm2',40,2)
  for raw,expected,spelling in [(0,0,''),(0x7fffff,8388607,'+0x7fffff'),(0x800000,-8388608,'+-0x800000'),(0xfffffe,-2,'+-0x2'),(0xffffff,-1,'+-0x1')]:
   with self.subTest(raw=raw):
    self.assertEqual(MEM.expected_field(raw<<40,field),expected)
    self.assertEqual(MEM.decoded_field(f'LD R0, desc[UR0][R0.64{spelling}]',field),expected)
  values=MEM.probe_values(field)
  self.assertTrue({0x7fffff,0x800000,0xfffffe,0xffffff}.issubset(values))
  self.assertTrue(all((1<<i) in values for i in range(24)))

 def test_guard_predication(self):
  for spelling,expected in [('LDL R0, [R0]',7),('@P0 LDL R0, [R0]',0),('@!P6 LDL R0, [R0]',14),('@!PT LDL R0, [R0]',15),('@UP0 UTMACCTL.PF [UR0]',0),('@!UPT UTMACCTL.PF [UR0]',15)]:
   self.assertEqual(MEM.decoded_field(spelling,MEM.G),expected)

 def test_ldcu_signed_constant_window_and_uniform_index(self):
  for address,expected_index,expected_cm in [('c[0xf][UR14+-0x1]',14,(15<<17)|0x1ffff),('c[0xf][-0x1]',255,(15<<17)|0x1ffff),('c[0x4][URZ]',255,4<<17),('c[0x1f][UR0+0xffff]',0,(31<<17)|0xffff)]:
   text=f'LDCU.64 UR3, {address}'
   self.assertEqual(MEM.decoded_field(text,MEM.f(8,'ureg',16,1)),3)
   self.assertEqual(MEM.decoded_field(text,MEM.f(8,'sub_ur1',24,2)),expected_index)
   self.assertEqual(MEM.decoded_field(text,MEM.f(22,'cm17_off',37,2)),expected_cm)

 def test_atoms_elided_base_stays_distinct_from_uniform_index(self):
  text='ATOMS.ADD RZ, [UR4+0x5], R20'
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'sub_r0',24,2)),255)
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'sub_ur1',64,2)),4)
  self.assertEqual(MEM.decoded_field(text,MEM.f(24,'sub_imm2',40,2)),5)
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'reg',32,3)),20)

class MemoryFieldVerification(unittest.TestCase):
 def setUp(self):
  self.text='LDGMC.E.ADD.32.STRONG.SYS R0, [R0.64+UR0]'
  self.key,_,mods,self.fields=MEM.geometry(self.text)
  self.mods=','.join(sorted(mods))
  self.base=0x000fe2000803410000000000000079a4

 def test_field_mismatch_and_unmodified_field_change_fail(self):
  word=self.base|(31<<16)
  good='LDGMC.E.ADD.32.STRONG.SYS R31, [R0.64+UR0]'
  self.assertEqual(MEM.verify_instruction(self.key,self.mods,self.fields,word,good)['status'],'verified')
  for bad in [good.replace('R31,','R30,'),good.replace('+UR0]','+UR1]')]:
   with self.assertRaises(ValueError):MEM.verify_instruction(self.key,self.mods,self.fields,word,bad)

 def test_mode_change_fails_even_when_registers_match(self):
  with self.assertRaisesRegex(ValueError,'mode changed'):
   MEM.verify_instruction(self.key,self.mods,self.fields,self.base,self.text.replace('.32.','.64.'))

 def test_uniform_predicate_kind_cannot_replace_warp_guard(self):
  with self.assertRaisesRegex(ValueError,'predicate kind changed'):
   MEM.verify_instruction(self.key,self.mods,self.fields,self.base&~(15<<12),'@UP0 '+self.text)

 def test_invalid_mutant_never_counts_as_verified(self):
  result=MEM.verify_instruction(self.key,self.mods,self.fields,self.base,'LDGMC.E.ADD.32.STRONG.SYS R0, [???255.64+UR0]')
  self.assertEqual(result['status'],'invalid')

 def test_old_ldgmc_shift32_offset_geometry_is_rejected(self):
  wrong=[MEM.f(32,'sub_imm2',32,2)]
  with self.assertRaisesRegex(ValueError,'authored 31, NVIDIA decoded 0'):
   MEM.verify_instruction(self.key,self.mods,wrong,31<<32,self.text)

 def test_distinct_signed_offset_widths_are_verified(self):
  for width in (12,20,23,24,32):
   field=MEM.f(width,'sub_imm1',40,1)
   self.assertEqual(MEM.expected_field((1<<(width-1))<<40,field),-(1<<(width-1)))
   values=MEM.probe_values(field)
   self.assertTrue({(1<<(width-1))-1,1<<(width-1),(1<<width)-1}.issubset(values))
   self.assertTrue(all(0<=v<(1<<width) for v in values))

 def test_ldgsts_elides_only_true_predicate_and_zero_uniform_index(self):
  text='LDGSTS.E.BYPASS.LTC128B.128 [R0], [R0.64]'
  self.assertEqual(MEM.decoded_field(text,MEM.f(4,'pred',87,3)),7)
  self.assertEqual(MEM.decoded_field(text,MEM.f(8,'sub_ur1',64,2)),255)
  self.assertEqual(MEM.decoded_field(text,MEM.f(12,'sub_imm2',32,2)),0)
  self.assertEqual(MEM.decoded_field(text+', !PT',MEM.f(4,'pred',87,3)),15)

 @unittest.skipUnless(MEM.NV.is_file(),'NVIDIA nvdisasm unavailable')
 def test_illegal_nv_instruction_does_not_hide_legal_neighbors(self):
  good=0x004ea200081ef30c800000190e1c29a8
  texts=MEM.oracle([good,good^(1<<63),good])
  self.assertEqual(len(texts),3)
  self.assertEqual(texts[0],texts[2])
  self.assertIn('INVALID',texts[1])
  self.assertTrue(texts[0].startswith('@P2 ATOMG.E.ADD.S32.STRONG.GPU'))

 @unittest.skipUnless(MEM.NV.is_file(),'NVIDIA nvdisasm unavailable')
 def test_new_memory_families_and_combined_sentinel_boundaries(self):
  words=[0x000ea20008000a0000008a00260477ac,0x000ee60008000a0001000000ff1c77ac,0x000fe20008000a0003ffffe0ff0377ac,0x000fe20008000a0003ffffe00e0377ac,0x0001e8000800000400000014ffff798c,0x000fe20008000009000005070b02798c,0x000fe200080000ff000000070b02798c,0x000f28000c1eb5000000020e102c7981]
  for word,text in zip(words,MEM.oracle(words)):
   with self.subTest(word=f'{word:032x}',text=text):
    key,_,mods,fields=MEM.geometry(text)
    self.assertEqual(MEM.verify_instruction(key,','.join(sorted(mods)),fields,word,text)['status'],'verified')

 @unittest.skipUnless(MEM.NV.is_file(),'NVIDIA nvdisasm unavailable')
 def test_nv_disassembly_agrees_at_positive_negative_signed24_edges(self):
  samples=[]
  for raw in [0,0x7fffff,0x800000,0xfffffe,0xffffff]:samples.append(self.base|(raw<<40))
  for word,text in zip(samples,MEM.oracle(samples)):
   with self.subTest(word=f'{word:032x}'):
    self.assertEqual(MEM.verify_instruction(self.key,self.mods,self.fields,word,text)['status'],'verified')

class CapturedMemoryRegressions(unittest.TestCase):
 @unittest.skipUnless(MEM.NV.is_file(),'NVIDIA nvdisasm unavailable')
 def test_raw_ldg_u32_and_64_keep_distinct_owner_rows(self):
  words=[0x004ea800081e090000000008ff030981,0x000ea8000c1e09000000800c0c0a7981]
  expected=['LDG.E_R_ARURI','LDG_R_ARURI']
  texts=MEM.oracle(words)
  for word,text,key in zip(words,texts,expected):
   geo=MEM.geometry(text);self.assertEqual(geo[0],key)
   self.assertEqual(MEM.verify_instruction(key,','.join(sorted(geo[2])),geo[3],word,text)['status'],'verified')
  geo=MEM.geometry(texts[0])
  with self.assertRaisesRegex(ValueError,'mode changed'):
   MEM.verify_instruction(geo[0],','.join(sorted(geo[2])),geo[3],words[0],texts[0].replace('.U32','.64'))

 @unittest.skipUnless(MEM.NV.is_file(),'NVIDIA nvdisasm unavailable')
 def test_plain_store_offset_uses_32_bit_window(self):
  word=0x000fe2000010011100000010b8009385;text=MEM.oracle([word])[0]
  key,_,mods,fields=MEM.geometry(text)
  offset=next(f for f in fields if f['extraction']=='sub_imm1')
  self.assertEqual((offset['shift'],offset['bits']),(32,32))
  self.assertEqual(MEM.verify_instruction(key,','.join(sorted(mods)),fields,word,text)['status'],'verified')
  with self.assertRaisesRegex(ValueError,'authored 16, NVIDIA decoded 17'):
   MEM.verify_instruction(key,','.join(sorted(mods)),fields,word,text.replace('+0x10','+0x11'))

 @unittest.skipUnless(MEM.NV.is_file(),'NVIDIA nvdisasm unavailable')
 def test_ldgsts_elided_uniform_zero_is_not_a_live_index(self):
  word=0x0005e200099a02ff0c08c00cd2077fae;text=MEM.oracle([word])[0]
  key,_,mods,fields=MEM.geometry(text)
  self.assertEqual(key,'LDGSTS_ARI_ARI_P')
  self.assertEqual(MEM.verify_instruction(key,','.join(sorted(mods)),fields,word,text)['status'],'verified')
  generic=MEM.geometry(text.replace('[R210.64+0xc]','[R210.64+UR18+0xc]'))
  with self.assertRaisesRegex(ValueError,'authored 255, NVIDIA decoded 18'):
   MEM.verify_instruction(generic[0],','.join(sorted(mods)),generic[3],word,text.replace('[R210.64+0xc]','[R210.64+UR18+0xc]'))

if __name__=='__main__':unittest.main()

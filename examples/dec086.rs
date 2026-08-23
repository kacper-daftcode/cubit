use cubit::table::IsaTable;
use cubit::decoder::DecodeIndex;
fn main() {
    let t = IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap();
    let idx = DecodeIndex::build(&t);
    let code: u128 = 0x000fe40001743070000000070500780c;
    // replicate candidate filter for the target mg
    let cc = code & !(0xFFFF_FFFFu128 << 96);
    let mg = t.get("ISETP_P_P_R_II_P","AND,LE,U32").unwrap();
    let mut fm: u128 = 0;
    for f in &mg.fields { fm |= ((1u128<<f.bits)-1) << f.shift; }
    let mm = !mg.variable_mask & !fm;
    let gm = 0xF000u128;
    println!("strict: {}", (cc & mm & !gm) == (mg.and_base & mm & !gm));
    let d = (cc ^ mg.and_base) & mm & !gm;
    println!("diff bits: {:?}", (0..128).filter(|b| (d>>b)&1==1).collect::<Vec<_>>());
    println!("ab lo12: {:03x}", mg.and_base & 0xfff);
    let d2 = idx.decode(code, 0, &t).unwrap();
    println!("winner: {} :: {}", d2.key, d2.mod_group);
}

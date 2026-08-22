use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;
fn main() {
    let t = IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap();
    let t120 = IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
    for (txt, tt) in [
        ("LDS R10, [R26+0xc]", &t),
        ("STS [R26+0xc], R10", &t),
        ("LDG.E R12, [R26+0xc]", &t),
        ("STG.E [R26+0xc], R12", &t),
        ("LDS R10, [R26+0xc]", &t120),
        ("STS [R26+0xc], R10", &t120),
        ("LDS R10, [R26-0x4]", &t),
    ] {
        let insn = parse_sass(&format!("{txt} ;"), 0).unwrap();
        let w = encode_instruction(&insn, tt).unwrap();
        println!("{txt:28} -> 0x{w:032x}");
    }
}

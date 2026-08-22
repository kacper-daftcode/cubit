use cubit::encoder::encode_instruction;
use cubit::parser::parse_sass;
use cubit::table::IsaTable;
fn main(){
    let t120=IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
    let t103=IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap();
    for txt in ["ULEA UR11, UR11, UR7, 0x1", "ULEA.HI.SX32 UR6, UR4, 0x1, 0x2",
                "ULEA.HI.X.SX32 UR6, UR8, UR6, 0x1, UP0", "@UP2 ULEA UR7, UP0, UR4, UR8, 0x1",
                "ULEA.HI UR4, UR4, UR4, URZ, 0x1", "ULEA.HI UR23, UP0, UR28, UR23, URZ, 0x1"] {
        let insn = parse_sass(&format!("{txt} ;"), 0).unwrap();
        let a = encode_instruction(&insn, &t120).map(|w| format!("{w:032x}")).unwrap_or_else(|e| format!("ERR {e}"));
        let b = encode_instruction(&insn, &t103).map(|w| format!("{w:032x}")).unwrap_or_else(|e| format!("ERR {e}"));
        println!("{txt}\n  120 {a}\n  103 {b}");
    }
}

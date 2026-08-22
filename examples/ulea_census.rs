use cubit::decoder::DecodeIndex;
use cubit::table::IsaTable;
use std::io::Write;
fn dec(idx:&DecodeIndex, w:u128, t:&IsaTable)->String{
    match idx.decode(w,0,t){Ok(d)=>format!("{d}").trim_end_matches([' ',';']).to_string(),Err(_)=>"__raw__".into()}
}
fn main(){
    let raw: Vec<(String,String)> = serde_json::from_str(&std::fs::read_to_string("/tmp/ulea_all.json").unwrap()).unwrap();
    let t120=IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
    let t103=IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap();
    let i120=DecodeIndex::build(&t120); let i103=DecodeIndex::build(&t103);
    let mut out=std::io::BufWriter::new(std::fs::File::create("/tmp/ulea_census_out.jsonl").unwrap());
    for (ws,v) in &raw {
        let w=u128::from_str_radix(ws,16).unwrap();
        let r120=dec(&i120,w,&t120); let r103=dec(&i103,w,&t103);
        writeln!(out, "{}", serde_json::json!({"w":ws,"vendor":v,"r120":r120,"r103":r103})).unwrap();
    }
}

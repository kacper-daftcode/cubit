use cubit::decoder::DecodeIndex;
use cubit::table::IsaTable;
fn dec(t:&IsaTable, w:u128)->String{
    let idx=DecodeIndex::build(t);
    match idx.decode(w,0,t){Ok(d)=>format!("{d}").trim_end_matches([' ',';']).to_string(),Err(e)=>format!("__err__ {e}")}
}
fn main(){
    let raw: Vec<(String,String)> = serde_json::from_str(&std::fs::read_to_string("/tmp/words_plain.json").unwrap()).unwrap();
    let t120=IsaTable::load(std::path::Path::new("tables/sm120.json")).unwrap();
    let t103=IsaTable::load(std::path::Path::new("tables/sm103a.json")).unwrap();
    for (ws,v) in &raw {
        let w = u128::from_str_radix(ws,16).unwrap();
        println!("{}\n  VENDOR : {}\n  sm120  : {}\n  sm103a : {}", ws, v, dec(&t120,w), dec(&t103,w));
    }
}

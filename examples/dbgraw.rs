fn main() {
    let path = std::env::args().nth(1).unwrap();
    let text = std::fs::read_to_string(path).unwrap();
    let sf = cubit::sass_file::parse_sass_file_str(&text).unwrap();
    for def in &sf.kernels {
        for ins in &def.instructions {
            if ins.raw_text.contains("LDC") || ins.raw_text.contains("STG") {
                println!("lane {:2} | raw={:?}", ins.addr / 16, ins.raw_text);
            }
        }
    }
}

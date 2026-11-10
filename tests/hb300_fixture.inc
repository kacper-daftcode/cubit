// Shared by the `hidden_b300_*.rs` tests (`include!("hb300_fixture.inc");`).
//
// The nvdisasm fixtures of the B300 measurement lane keep every probe record whole -- the 128-bit word, the command,
// nvdisasm's complete stdout / stderr and return code, the input's SHA-256, the record's kind and generation -- which
// makes them 1-4 MB per architecture and form. They are vendored gzip-compressed (`tests/fixtures/<name>.jsonl.gz`,
// single member, mtime 0: the decompressed bytes are the lane's file, digest in `tests/fixtures/hidden_b300.sha256`),
// and read through this helper instead of `include_str!`.

/// The decompressed text of `tests/fixtures/<name>.gz`, read once per process.
#[allow(dead_code)]
fn hb300_fixture(name: &str) -> &'static str {
    use std::io::Read;
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, &'static str>>> =
        std::sync::OnceLock::new();
    let mut cache = CACHE.get_or_init(Default::default).lock().unwrap();
    if let Some(text) = cache.get(name) {
        return text;
    }
    let path = format!("tests/fixtures/{name}.gz");
    let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut text = String::new();
    flate2::read::GzDecoder::new(file)
        .read_to_string(&mut text)
        .unwrap_or_else(|e| panic!("{path}: {e}"));
    let text: &'static str = Box::leak(text.into_boxed_str());
    cache.insert(name.to_string(), text);
    text
}

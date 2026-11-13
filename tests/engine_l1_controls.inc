// E2 consolidation: previously separate measured controls retained by the
// common row. A synthetic-key prohibition becomes a real rendering check:
// this common family must preserve vendor text, not merely accept a key.
fn e2_consolidated_control(row: &Value, expected_key: &str, decoded_key: &str) -> bool {
    if decoded_key != expected_key {
        return false;
    }
    let Some(text) = row["nvidia_sass"].as_str() else { return false };
    let mnemonic = expected_key.split('_').next().unwrap_or("");
    text.split_whitespace().any(|token| token.split('.').next() == Some(mnemonic))
}

//! KNOWN_ISSUES A23 (NEEDS_OWNER 43; the owner's decision of 2026-11-10: the frozen path carries the vendor's degenerate
//! glyphs). A word nvdisasm prints with a degenerate glyph -- `LDG.E.LTC128B R4, [???255.64+UR6+0x10]`: base register
//! 255 under the `.64` width -- is printed text-faithfully, and that text cannot be assembled (there is no `???255`
//! operand). The frozen path does not need it to be: `disassemble --frozen` re-assembles every non-branch line before it
//! writes it and writes the word as `__raw__0x<128 bits>` when that fails (the fallback of 2026-07-31), so `asm -T` of
//! the frozen listing reproduces the cubin byte for byte. Session T-26 found the fallback in place when it came to add
//! it; this test pins it on the four words of `tests/sm120_audit_t11.rs` (nvdisasm 13.1's texts).
use std::process::Command;

const WORDS: [(u128, &str); 4] = [
    (0x0000_0000_0c1e_0d20_0000_1006_ff04_7981, "LDG.E.LTC128B.128 R4, [???255.64+UR6+0x10]"),
    (0x0000_0000_0c1e_0b20_0000_1006_ff04_7981, "LDG.E.LTC128B.64 R4, [???255.64+UR6+0x10]"),
    (0x0000_0000_0c1e_0920_0000_1006_ff04_7981, "LDG.E.LTC128B R4, [???255.64+UR6+0x10]"),
    (0x0000_0000_0c10_0d05_0000_1006_ff00_7986, "STG.E.128 [???255.64+UR5+0x10], R6"),
];

fn cubit(args: &[&str]) -> (String, String) {
    let res = Command::new(env!("CARGO_BIN_EXE_cubit")).args(args).output().unwrap();
    let (out, err) = (String::from_utf8_lossy(&res.stdout).into_owned(), String::from_utf8_lossy(&res.stderr).into_owned());
    assert!(res.status.success(), "cubit {args:?}:\n{out}\n{err}");
    (out, err)
}

#[test]
fn a_cubin_with_degenerate_glyph_words_round_trips_through_the_frozen_path() {
    let dir = std::env::temp_dir().join(format!("a23_glyph_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = |name: &str| dir.join(name).to_str().unwrap().to_string();
    let mut sass = String::from(".entry glyph_kern\n    .param u64 output\n    MOV R4, R5 ;\n");
    for (word, _) in WORDS {
        sass.push_str(&format!("    __raw__0x{word:032x} ;\n"));
    }
    sass.push_str("    EXIT ;\n.endentry\n");
    std::fs::write(p("k.sass"), &sass).unwrap();
    cubit(&["asm", "-t", "tables/sm120.json", &p("k.sass"), "-o", &p("k.cubin")]);

    // the plain listing: the vendor's text, glyph and all
    let (listing, _) = cubit(&["disassemble", "-t", "tables/sm120.json", &p("k.cubin")]);
    for (_, text) in WORDS {
        assert!(listing.contains(text), "the plain listing prints the vendor's text: {text}\n{listing}");
    }

    // the frozen listing: no glyph, the four words verbatim
    let (_, warn) = cubit(&["disassemble", "--frozen", "-t", "tables/sm120.json", &p("k.cubin"), "-o", &p("frozen.sass")]);
    let frozen = std::fs::read_to_string(p("frozen.sass")).unwrap();
    assert!(!frozen.contains("???"), "{frozen}");
    for (word, text) in WORDS {
        assert!(frozen.contains(&format!("__raw__0x{word:032x} ;")), "{word:032x} is carried verbatim:\n{frozen}");
        assert!(warn.contains(text), "the fallback names the text it could not re-assemble: {text}\n{warn}");
    }
    assert_eq!(frozen.matches("__raw__0x").count(), WORDS.len(), "{frozen}");

    // and back: byte for byte
    cubit(&["asm", "-T", &p("k.cubin"), "-t", "tables/sm120.json", &p("frozen.sass"), "-o", &p("k2.cubin")]);
    assert_eq!(std::fs::read(p("k.cubin")).unwrap(), std::fs::read(p("k2.cubin")).unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

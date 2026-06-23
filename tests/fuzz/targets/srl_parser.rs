#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_rules::parse_rule_file;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // SRL parsing should never panic — fuzz the public entry point.
        let _ = parse_rule_file(text);
    }
});
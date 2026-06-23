#![no_main]

use libfuzzer_sys::fuzz_target;
use sentinel_rules::import_secrule_conf;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // CRS importer should never panic on arbitrary input.
        let _ = sentinel_rules::import_secrule_conf(text);
    }
});
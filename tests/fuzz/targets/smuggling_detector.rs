#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // Build a HeaderMap with random header names and values from the fuzz input.
        let mut headers = http::HeaderMap::new();
        // Split input by newlines into header lines, each line is "name: value"
        for line in text.lines().take(50) {
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                let value = value.trim();
                if !name.is_empty() {
                    if let (Ok(n), Ok(v)) = (
                        http::header::HeaderName::from_bytes(name.as_bytes()),
                        http::header::HeaderValue::from_bytes(value.as_bytes()),
                    ) {
                        headers.append(n, v);
                    }
                }
            }
        }
        // Smuggling detection must never panic.
        let _ = sentinel_modules::detect_smuggling(&headers);
    }
});
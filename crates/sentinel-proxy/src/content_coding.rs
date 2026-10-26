//! Request bodies sent with a `Content-Encoding`, decoded for inspection.
//!
//! The rules and the classifiers read the body as text. A body sent
//! `Content-Encoding: gzip` (or `br`, `deflate`, `zstd`) reached them as the
//! compressed bytes, which match nothing — so an attack compressed by the
//! client passed uninspected to an origin that decompresses request bodies
//! (as many frameworks do). CRS's answer, 920450 on a restricted
//! `Content-Encoding` header, scores 5, below the blocking threshold of 10, and
//! the product does not seed that list anyway.
//!
//! So the body is decoded here, the way the origin would decode it, and the
//! decoded text is what is inspected; the origin still receives the bytes as
//! sent. Decoding is bounded by the site's body limit, which therefore holds
//! for what is inspected as well as for what arrived: a few kilobytes that
//! inflate to gigabytes are refused, not inflated.
//!
//! A body that cannot be decoded — a coding this does not know (`compress`,
//! anything new), a corrupt stream, or one that inflates past the limit — was
//! not inspected as the origin will read it, and is handled as a body past the
//! limit is: refused in blocking mode, forwarded and recorded as a would-block
//! in learning mode. A corrupt stream is most likely not encoded at all, so it
//! is inspected as it arrived first: an attack sent under a Content-Encoding it
//! does not have is still answered, and logged, as an attack.

use std::fmt;
use std::io::Read;

use bytes::Bytes;
use http::HeaderMap;

/// The decoded size allowed when the site sets no body limit: decoding is
/// never unbounded, whatever the site allows to arrive.
pub(crate) const UNLIMITED_SITE_CAP: usize = 64 << 20;

/// Why a body could not be decoded for inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Undecodable {
    /// A coding no decoder here knows.
    Unsupported(String),
    /// The stream is not valid in the coding it names.
    Corrupt(String),
    /// Decoded, it is longer than the limit.
    TooLarge(usize),
}

impl Undecodable {
    /// The status a refusal answers with, and its body.
    pub(crate) fn status(&self) -> (http::StatusCode, &'static str) {
        match self {
            // RFC 9110 §15.5.16: an unsupported content coding is 415.
            Self::Unsupported(_) => (
                http::StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "Unsupported Media Type",
            ),
            Self::Corrupt(_) => (http::StatusCode::BAD_REQUEST, "Bad Request"),
            Self::TooLarge(_) => (
                http::StatusCode::PAYLOAD_TOO_LARGE,
                "Request Entity Too Large",
            ),
        }
    }
}

impl fmt::Display for Undecodable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(c) => write!(
                f,
                "request body in a Content-Encoding that cannot be inspected ({c})"
            ),
            Self::Corrupt(c) => write!(f, "request body is not valid {c} and cannot be inspected"),
            Self::TooLarge(limit) => write!(
                f,
                "request body decodes to more than the {limit}-byte limit (decompression bomb)"
            ),
        }
    }
}

/// The codings applied to the body, in the order they were applied, without
/// `identity`; empty when there are none. Every `Content-Encoding` field, each
/// a comma-separated list, lower-cased.
pub(crate) fn codings(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(http::header::CONTENT_ENCODING)
        .iter()
        .flat_map(|v| {
            String::from_utf8_lossy(v.as_bytes())
                .split(',')
                .map(|c| c.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .filter(|c| !c.is_empty() && c != "identity")
        .collect()
}

/// `body` with `codings` undone, last applied first, each step bounded by
/// `limit` decoded bytes.
pub(crate) fn decode(codings: &[String], body: &[u8], limit: usize) -> Result<Bytes, Undecodable> {
    let mut current = body.to_vec();
    for coding in codings.iter().rev() {
        current = decode_one(coding, &current, limit)?;
    }
    Ok(Bytes::from(current))
}

fn decode_one(coding: &str, body: &[u8], limit: usize) -> Result<Vec<u8>, Undecodable> {
    let corrupt = || Undecodable::Corrupt(coding.to_owned());
    match coding {
        "gzip" | "x-gzip" => bounded(flate2::read::MultiGzDecoder::new(body), limit, coding),
        // RFC 9110 `deflate` is the zlib format; some clients send raw deflate,
        // which the origin's decoder may well accept, so that is tried too.
        "deflate" => {
            bounded(flate2::read::ZlibDecoder::new(body), limit, coding).or_else(|e| match e {
                Undecodable::Corrupt(_) => {
                    bounded(flate2::read::DeflateDecoder::new(body), limit, coding)
                }
                other => Err(other),
            })
        }
        "br" => bounded(
            brotli_decompressor::Decompressor::new(body, 4096),
            limit,
            coding,
        ),
        "zstd" => {
            let decoder = zstd::stream::read::Decoder::new(body).map_err(|_| corrupt())?;
            bounded(decoder, limit, coding)
        }
        other => Err(Undecodable::Unsupported(other.to_owned())),
    }
}

/// Read `decoder` to the end, refusing once it yields more than `limit` bytes.
fn bounded(decoder: impl Read, limit: usize, coding: &str) -> Result<Vec<u8>, Undecodable> {
    let mut out = Vec::new();
    decoder
        .take(limit as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| Undecodable::Corrupt(coding.to_owned()))?;
    if out.len() > limit {
        return Err(Undecodable::TooLarge(limit));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SQLI: &[u8] = b"q=1' UNION SELECT password FROM users--";

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn headers(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(http::header::CONTENT_ENCODING, value.parse().unwrap());
        h
    }

    #[test]
    fn every_coding_decodes_to_the_text_sent() {
        let mut zlib = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        zlib.write_all(SQLI).unwrap();
        let mut raw =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        raw.write_all(SQLI).unwrap();
        let br = brotli_uncompressed(SQLI);
        // The same text from the reference encoder (Python `brotli`, quality 11).
        let br_ref =
            hex("1b2600f88d942e6f0a654b4c5c9df480430ed8ffd53cd0fa0c4d76e2c99f2633e770e1be5406");
        let zstd = zstd::stream::encode_all(SQLI, 3).unwrap();
        for (coding, body) in [
            ("gzip", gzip(SQLI)),
            ("x-gzip", gzip(SQLI)),
            ("deflate", zlib.finish().unwrap()),
            ("deflate", raw.finish().unwrap()),
            ("br", br),
            ("br", br_ref),
            ("zstd", zstd),
        ] {
            let got = decode(&codings(&headers(coding)), &body, 1 << 20).unwrap();
            assert_eq!(&got[..], SQLI, "{coding}");
        }
    }

    /// A brotli stream holding `data` (≤ 65,536 bytes) in one uncompressed
    /// meta-block (RFC 7932 §9.2), then an empty last meta-block: the crate
    /// decodes only, and the format lets a stream be built by hand.
    fn brotli_uncompressed(data: &[u8]) -> Vec<u8> {
        assert!(!data.is_empty() && data.len() <= 1 << 16);
        let mut bits = BitWriter::default();
        bits.put(0, 1); // WBITS = 16
        bits.put(0, 1); // ISLAST = 0
        bits.put(0, 2); // MNIBBLES = 4
        bits.put((data.len() - 1) as u64, 16); // MLEN - 1
        bits.put(1, 1); // ISUNCOMPRESSED
        bits.align();
        let mut out = bits.bytes;
        out.extend_from_slice(data);
        let mut tail = BitWriter::default();
        tail.put(1, 1); // ISLAST
        tail.put(1, 1); // ISLASTEMPTY
        tail.align();
        out.extend_from_slice(&tail.bytes);
        out
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[derive(Default)]
    struct BitWriter {
        bytes: Vec<u8>,
        used: u32,
    }

    impl BitWriter {
        fn put(&mut self, value: u64, n: u32) {
            for i in 0..n {
                if self.used % 8 == 0 {
                    self.bytes.push(0);
                }
                let bit = ((value >> i) & 1) as u8;
                *self.bytes.last_mut().unwrap() |= bit << (self.used % 8);
                self.used += 1;
            }
        }
        fn align(&mut self) {
            self.used = self.used.div_ceil(8) * 8;
        }
    }

    #[test]
    fn stacked_codings_are_undone_last_first() {
        let twice = gzip(&gzip(SQLI));
        let got = decode(&codings(&headers("gzip, x-gzip")), &twice, 1 << 20).unwrap();
        assert_eq!(&got[..], SQLI);
    }

    #[test]
    fn identity_and_no_header_mean_nothing_to_decode() {
        assert!(codings(&HeaderMap::new()).is_empty());
        assert!(codings(&headers("identity")).is_empty());
        assert_eq!(codings(&headers(" GZIP , identity")), vec!["gzip"]);
    }

    /// 10 MiB of zeros is 10 KiB of gzip: decoded past the limit, it is refused
    /// after `limit + 1` bytes, not inflated whole.
    #[test]
    fn a_decompression_bomb_is_refused_at_the_limit() {
        let bomb = gzip(&vec![0u8; 10 << 20]);
        assert!(bomb.len() < 64 << 10);
        assert_eq!(
            decode(&codings(&headers("gzip")), &bomb, 1 << 20),
            Err(Undecodable::TooLarge(1 << 20))
        );
    }

    #[test]
    fn what_cannot_be_decoded_says_why() {
        assert_eq!(
            decode(&codings(&headers("compress")), b"x", 100),
            Err(Undecodable::Unsupported("compress".into()))
        );
        assert_eq!(
            decode(&codings(&headers("gzip")), b"not gzip at all", 100),
            Err(Undecodable::Corrupt("gzip".into()))
        );
        assert_eq!(
            Undecodable::Unsupported("x".into()).status().0,
            http::StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }
}

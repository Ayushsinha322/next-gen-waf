//! On-disk spool for history rows ClickHouse could not accept.
//!
//! # Why this exists
//!
//! The history writer used to be lossy by construction in three separate places:
//! rows were not buffered at all while disconnected, a drained batch was
//! discarded while disconnected, and a batch whose INSERT failed was dropped.
//! Each was individually defensible — they all kept memory bounded — but the
//! combined effect was that a node which could not reach ClickHouse recorded
//! nothing at all, silently, while still enforcing perfectly.
//!
//! Measured on the 2-VM active/passive pair (2026-07-29): nine attacks were
//! blocked with 403 while the passive node held the VIP and ClickHouse recorded
//! zero of them. Enforcement was never in question; the audit trail was simply
//! absent for exactly the window an operator would most want to inspect.
//!
//! # Design
//!
//! Rows go to disk as NDJSON segments and are replayed when the sink returns.
//! Three properties matter, in this order:
//!
//! 1. **Never harm the request path.** Spooling happens in the flusher task, not
//!    in `record_event`. The hot path only ever pushes to a capped in-memory
//!    buffer, exactly as before.
//! 2. **Bounded disk.** An unreachable sink must not fill the filesystem and
//!    take down the WAF — that trades a missing log for an outage, which is a
//!    strictly worse deal. Over the cap, the OLDEST segments are dropped and the
//!    loss is logged with a row count. Never silently.
//! 3. **Survive a restart.** The spool lives on the `sentinel-state` volume
//!    ("per-node data-plane state that must outlive the container"), so a reboot
//!    or `--force-recreate` mid-outage does not lose the window. This is the
//!    whole reason it is disk rather than a bigger memory buffer.
//!
//! # Delivery semantics: at-least-once
//!
//! A segment is deleted only after its INSERT succeeds. Crash in that window and
//! the segment is replayed, so a row can appear twice. That is deliberate:
//! duplicate-and-know beats lose-and-not-know for an audit trail, and every row
//! carries `request_id` so a reader can de-duplicate. Do not describe this as
//! exactly-once.
//!
//! # Ordering
//!
//! Segment names are `{kind}-{millis:013}-{seq:06}.ndjson`, all fixed width, so a
//! plain lexicographic sort is chronological within a kind. Replay is oldest
//! first, which keeps ClickHouse's `ts` ordering close to natural insert order.

use serde::{de::DeserializeOwned, Serialize};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Default spool ceiling. Chosen to be large enough to ride out a multi-hour
/// ClickHouse outage on a busy node (waf_events only stores *notable* requests,
/// so the rate is attack-driven, not traffic-driven) while staying small enough
/// that it cannot plausibly fill the `sentinel-state` volume.
pub const DEFAULT_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// Segment file suffix. Anything else in the directory is ignored, so an
/// operator can drop notes there and a stray `.tmp` from a killed process is
/// never mistaken for data.
const SEGMENT_EXT: &str = "ndjson";

/// Disambiguates segments created within the same millisecond.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// A bounded, crash-safe, replayable disk spool.
#[derive(Debug, Clone)]
pub struct Spool {
    dir: PathBuf,
    max_bytes: u64,
}

/// What a cap enforcement pass discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Dropped {
    pub segments: usize,
    pub bytes: u64,
}

impl Spool {
    /// Open (creating if needed) a spool directory.
    pub fn open(dir: impl Into<PathBuf>, max_bytes: u64) -> io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, max_bytes })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Write `rows` as one segment. Atomic: the batch is written to a
    /// per-process temp name, fsynced, then renamed into place, so a reader (or
    /// a replay after a crash) never observes a half-written segment. Mirrors
    /// `write_cached_sites` in the proxy, which learned the same lesson.
    ///
    /// Returns the number of bytes written. An empty batch writes nothing.
    pub fn append<T: Serialize>(&self, kind: &str, rows: &[T]) -> io::Result<u64> {
        if rows.is_empty() {
            return Ok(0);
        }
        let body = encode(rows)?;
        write_atomic(&self.dir.join(Self::segment_name(kind)), &body, None)?;
        Ok(body.len() as u64)
    }

    /// Replace the segment at `path` with `rows`: what is left of it after a
    /// replay that got part-way. Without this, the rows ClickHouse had already
    /// accepted were sent again on every retry. The name is kept, so the segment
    /// keeps its place in the replay order, and so is the mtime, so it keeps its
    /// place in the cap's oldest-first order. Atomic like `append`; empty `rows`
    /// removes the segment.
    pub fn rewrite<T: Serialize>(path: &Path, rows: &[T]) -> io::Result<u64> {
        if rows.is_empty() {
            Self::remove(path);
            return Ok(0);
        }
        let body = encode(rows)?;
        let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
        write_atomic(path, &body, mtime)?;
        Ok(body.len() as u64)
    }

    /// Segments for `kind`, oldest first.
    pub fn segments(&self, kind: &str) -> Vec<PathBuf> {
        let prefix = format!("{kind}-");
        let mut v: Vec<PathBuf> = match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| is_segment(p) && file_name(p).is_some_and(|n| n.starts_with(&prefix)))
                .collect(),
            Err(_) => Vec::new(),
        };
        // Fixed-width millis+seq means lexicographic == chronological.
        v.sort();
        v
    }

    /// Total bytes held across every kind. Used for cap accounting, so it counts
    /// whole segments regardless of which stream produced them — the disk budget
    /// is shared.
    pub fn bytes(&self) -> u64 {
        match std::fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .filter_map(Result::ok)
                .filter(|e| is_segment(&e.path()))
                .filter_map(|e| e.metadata().ok())
                .map(|m| m.len())
                .sum(),
            Err(_) => 0,
        }
    }

    /// Read one segment. Tolerant per line: a single unparseable line costs that
    /// row, not the whole segment, which matters because the alternative is
    /// discarding thousands of good events over one bad byte. Returns the rows
    /// and the number of lines skipped.
    pub fn load<T: DeserializeOwned>(path: &Path) -> io::Result<(Vec<T>, usize)> {
        let data = std::fs::read(path)?;
        let mut rows = Vec::new();
        let mut skipped = 0usize;
        for line in data.split(|b| *b == b'\n') {
            if line.is_empty() || line.iter().all(|b| b.is_ascii_whitespace()) {
                continue;
            }
            match serde_json::from_slice::<T>(line) {
                Ok(r) => rows.push(r),
                Err(_) => skipped += 1,
            }
        }
        Ok((rows, skipped))
    }

    /// Delete a replayed segment. Best-effort: a failure here means the segment
    /// is replayed again later (duplicates, not loss), which is the safe side.
    pub fn remove(path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    /// Drop oldest segments until the spool is under its cap.
    ///
    /// Oldest-first is the standard ring choice and keeps the most recent window,
    /// which is what an operator reaches for after an incident. The caller is
    /// expected to LOG whatever this returns — a spool that silently discards is
    /// indistinguishable from the bug this module exists to fix.
    pub fn enforce_cap(&self) -> Dropped {
        let mut total = self.bytes();
        if total <= self.max_bytes {
            return Dropped::default();
        }
        // Sort by mtime rather than name: the cap spans every kind, and names
        // are only chronological *within* a kind (they start with the kind).
        let mut entries: Vec<(std::time::SystemTime, u64, PathBuf)> =
            match std::fs::read_dir(&self.dir) {
                Ok(rd) => rd
                    .filter_map(Result::ok)
                    .filter(|e| is_segment(&e.path()))
                    .filter_map(|e| {
                        let md = e.metadata().ok()?;
                        Some((
                            md.modified().unwrap_or(std::time::UNIX_EPOCH),
                            md.len(),
                            e.path(),
                        ))
                    })
                    .collect(),
                Err(_) => return Dropped::default(),
            };
        entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.2.cmp(&b.2)));

        let mut dropped = Dropped::default();
        for (_, len, path) in entries {
            if total <= self.max_bytes {
                break;
            }
            if std::fs::remove_file(&path).is_ok() {
                total = total.saturating_sub(len);
                dropped.segments += 1;
                dropped.bytes += len;
            }
        }
        dropped
    }

    fn segment_name(kind: &str) -> String {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed) % 1_000_000;
        format!("{kind}-{millis:013}-{seq:06}.{SEGMENT_EXT}")
    }
}

/// Rows as NDJSON.
fn encode<T: Serialize>(rows: &[T]) -> io::Result<Vec<u8>> {
    let mut body: Vec<u8> = Vec::with_capacity(rows.len() * 256);
    for r in rows {
        serde_json::to_writer(&mut body, r).map_err(to_io)?;
        body.push(b'\n');
    }
    Ok(body)
}

/// Write `body` to a temp name beside `final_path`, fsync, then rename it into
/// place, so a reader never observes a half-written segment.
fn write_atomic(
    final_path: &Path,
    body: &[u8],
    mtime: Option<std::time::SystemTime>,
) -> io::Result<()> {
    use std::io::Write as _;
    // Temp name is per-process for the same reason the config cache's is:
    // two nodes pointed at one directory must not truncate each other's
    // in-flight temp file and then rename the partial result into place.
    let mut tmp_name = final_path.as_os_str().to_owned();
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = PathBuf::from(tmp_name);

    let res = (|| -> io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body)?;
        if let Some(t) = mtime {
            f.set_modified(t)?;
        }
        f.sync_all()?;
        std::fs::rename(&tmp, final_path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

fn is_segment(p: &Path) -> bool {
    p.extension().and_then(|s| s.to_str()) == Some(SEGMENT_EXT)
}

fn file_name(p: &Path) -> Option<&str> {
    p.file_name().and_then(|s| s.to_str())
}

fn to_io(e: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Row {
        n: u32,
        s: String,
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "sentinel-spool-test-{}-{}-{:?}",
            tag,
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn rows(n: u32) -> Vec<Row> {
        (0..n)
            .map(|i| Row {
                n: i,
                s: format!("row-{i}"),
            })
            .collect()
    }

    #[test]
    fn append_then_load_round_trips() {
        let dir = tmpdir("roundtrip");
        let sp = Spool::open(&dir, DEFAULT_MAX_BYTES).unwrap();
        let want = rows(3);
        let bytes = sp.append("events", &want).unwrap();
        assert!(bytes > 0);

        let segs = sp.segments("events");
        assert_eq!(segs.len(), 1);
        let (got, skipped) = Spool::load::<Row>(&segs[0]).unwrap();
        assert_eq!(got, want);
        assert_eq!(skipped, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_batch_writes_no_segment() {
        let dir = tmpdir("empty");
        let sp = Spool::open(&dir, DEFAULT_MAX_BYTES).unwrap();
        assert_eq!(sp.append::<Row>("events", &[]).unwrap(), 0);
        assert!(sp.segments("events").is_empty());
        assert_eq!(sp.bytes(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn kinds_are_isolated() {
        let dir = tmpdir("kinds");
        let sp = Spool::open(&dir, DEFAULT_MAX_BYTES).unwrap();
        sp.append("events", &rows(1)).unwrap();
        sp.append("traffic", &rows(2)).unwrap();
        assert_eq!(sp.segments("events").len(), 1);
        assert_eq!(sp.segments("traffic").len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn segments_are_returned_oldest_first() {
        let dir = tmpdir("order");
        let sp = Spool::open(&dir, DEFAULT_MAX_BYTES).unwrap();
        for i in 0..5u32 {
            sp.append(
                "events",
                &[Row {
                    n: i,
                    s: "x".into(),
                }],
            )
            .unwrap();
        }
        let segs = sp.segments("events");
        assert_eq!(segs.len(), 5);
        // The first row of each segment must come back in write order — this is
        // what makes replay chronological.
        let firsts: Vec<u32> = segs
            .iter()
            .map(|p| Spool::load::<Row>(p).unwrap().0[0].n)
            .collect();
        assert_eq!(firsts, vec![0, 1, 2, 3, 4]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_corrupt_line_costs_only_that_row() {
        let dir = tmpdir("corrupt");
        let sp = Spool::open(&dir, DEFAULT_MAX_BYTES).unwrap();
        let seg = dir.join("events-0000000000001-000000.ndjson");
        std::fs::write(
            &seg,
            b"{\"n\":1,\"s\":\"a\"}\nthis is not json\n{\"n\":2,\"s\":\"b\"}\n",
        )
        .unwrap();
        // A hand-written segment must still be discovered like any other.
        assert_eq!(sp.segments("events"), vec![seg.clone()]);
        let (got, skipped) = Spool::load::<Row>(&seg).unwrap();
        assert_eq!(skipped, 1);
        assert_eq!(
            got,
            vec![
                Row {
                    n: 1,
                    s: "a".into()
                },
                Row {
                    n: 2,
                    s: "b".into()
                }
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cap_drops_oldest_and_reports_what_it_lost() {
        let dir = tmpdir("cap");
        // Cap deliberately tiny so a handful of small segments exceeds it. Each
        // segment here is ~30 bytes, so 6 of them (~180) must clear 100.
        let sp = Spool::open(&dir, 100).unwrap();
        for i in 0..6u32 {
            sp.append(
                "events",
                &[Row {
                    n: i,
                    s: "padding-padding".into(),
                }],
            )
            .unwrap();
            // Distinct mtimes so oldest-first is unambiguous on coarse-grained
            // filesystem timestamps.
            std::thread::sleep(std::time::Duration::from_millis(12));
        }
        let before = sp.bytes();
        assert!(before > 100, "expected to exceed cap, got {before}");

        let dropped = sp.enforce_cap();
        assert!(dropped.segments > 0);
        assert!(dropped.bytes > 0);
        assert!(sp.bytes() <= 100, "still over cap: {}", sp.bytes());

        // The survivors must be the NEWEST rows — that is the whole point of
        // dropping oldest.
        let surviving: Vec<u32> = sp
            .segments("events")
            .iter()
            .flat_map(|p| Spool::load::<Row>(p).unwrap().0)
            .map(|r| r.n)
            .collect();
        assert!(
            surviving.iter().all(|n| *n >= 6 - surviving.len() as u32),
            "kept the wrong end: {surviving:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cap_is_a_no_op_under_the_limit() {
        let dir = tmpdir("undercap");
        let sp = Spool::open(&dir, DEFAULT_MAX_BYTES).unwrap();
        sp.append("events", &rows(2)).unwrap();
        assert_eq!(sp.enforce_cap(), Dropped::default());
        assert_eq!(sp.segments("events").len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_deletes_a_replayed_segment() {
        let dir = tmpdir("remove");
        let sp = Spool::open(&dir, DEFAULT_MAX_BYTES).unwrap();
        sp.append("events", &rows(1)).unwrap();
        let segs = sp.segments("events");
        Spool::remove(&segs[0]);
        assert!(sp.segments("events").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn non_segment_files_are_ignored() {
        let dir = tmpdir("ignore");
        let sp = Spool::open(&dir, DEFAULT_MAX_BYTES).unwrap();
        std::fs::write(dir.join("README.txt"), b"operator note").unwrap();
        std::fs::write(
            dir.join("events-0000000000001-000000.ndjson.tmp.999"),
            b"partial",
        )
        .unwrap();
        sp.append("events", &rows(1)).unwrap();
        assert_eq!(
            sp.segments("events").len(),
            1,
            "a stray .tmp or note must not be replayed as data"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn real_history_rows_round_trip() {
        // The generic tests above prove the mechanism; this proves it against the
        // ACTUAL types the flusher spools. Those rows carry several
        // `#[serde(default)]` fields added over time, so a spool that round-trips
        // a toy struct could still silently mangle a real event.
        let dir = tmpdir("realrows");
        let sp = Spool::open(&dir, DEFAULT_MAX_BYTES).unwrap();

        let ev = crate::WafEventRow {
            ts: 1_785_305_612,
            ip: "203.0.113.7".into(),
            country: "IN".into(),
            site: "juice-shop".into(),
            tenant: "acme".into(),
            method: "GET".into(),
            path: "/".into(),
            query: "id=1'+OR+1=1--".into(),
            referer: "https://juice.example/#/search".into(),
            matched: "1' OR 1=1--".into(),
            rule: "942100".into(),
            attack: "SQL Injection".into(),
            action: "BLOCK".into(),
            severity: "CRITICAL".into(),
            score: 15,
            status: 403,
            protocol: "h1".into(),
            request_id: "5769fa66-c1d3-4144-a0fd-8304003169cb".into(),
            target: "ARGS:id".into(),
            mode: "blocking".into(),
            threshold: 10,
            explanation: "blocked: anomaly score 15 >= threshold 10".into(),
            ja4: String::new(),
            rules: String::new(),
            headers: String::new(),
            ua: String::new(),
        };
        let tr = crate::TrafficRow {
            ts: 1_785_305_612,
            tenant: "acme".into(),
            site_id: "juice-shop".into(),
            reqs: 1_234,
            blocked: 9,
            p99_ms: 8.5,
        };

        sp.append("events", std::slice::from_ref(&ev)).unwrap();
        sp.append("traffic", std::slice::from_ref(&tr)).unwrap();

        let (evs, s1) = Spool::load::<crate::WafEventRow>(&sp.segments("events")[0]).unwrap();
        let (trs, s2) = Spool::load::<crate::TrafficRow>(&sp.segments("traffic")[0]).unwrap();
        assert_eq!(s1, 0);
        assert_eq!(s2, 0);
        assert_eq!(evs, vec![ev]);
        assert_eq!(trs, vec![tr]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A partly replayed segment keeps only what is left, in its old place in
    /// both orders (replay by name, cap by mtime).
    #[test]
    fn rewrite_keeps_the_rest_in_place() {
        let dir = tmpdir("rewrite");
        let sp = Spool::open(&dir, DEFAULT_MAX_BYTES).unwrap();
        sp.append("events", &rows(5)).unwrap();
        let path = sp.segments("events").remove(0);
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();

        Spool::rewrite(&path, &rows(5)[3..]).unwrap();
        assert_eq!(sp.segments("events"), vec![path.clone()]);
        assert_eq!(Spool::load::<Row>(&path).unwrap().0, rows(5)[3..].to_vec());
        assert_eq!(std::fs::metadata(&path).unwrap().modified().unwrap(), old);
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "no temp file left"
        );

        Spool::rewrite::<Row>(&path, &[]).unwrap();
        assert!(sp.segments("events").is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reopening_an_existing_dir_sees_prior_segments() {
        // This is the restart-recovery property: the spool is only useful if a
        // fresh process finds what the dead one left behind.
        let dir = tmpdir("reopen");
        {
            let sp = Spool::open(&dir, DEFAULT_MAX_BYTES).unwrap();
            sp.append("events", &rows(4)).unwrap();
        }
        let sp2 = Spool::open(&dir, DEFAULT_MAX_BYTES).unwrap();
        let segs = sp2.segments("events");
        assert_eq!(segs.len(), 1);
        assert_eq!(Spool::load::<Row>(&segs[0]).unwrap().0.len(), 4);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

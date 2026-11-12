//! File discovery and multi-pattern binary scanning (std only).
//! Also the shared machinery for raw devices and process memory: `count_stream`.
//!
//! How the search works: checking all 80 signatures at every byte of every file
//! would be slow, so `Matcher` first groups the signatures by their first two
//! bytes. While scanning, each pair of neighbouring bytes in the file is used
//! as a table index; for almost every position the bucket is empty and the
//! position is skipped at once. Only when the first two bytes agree is the full
//! pattern compared. One pass over the file therefore finds all signatures.

use crate::signatures::{Confidence, Signature, SIGNATURES};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::io::Read;
use std::{fs, io};

/// One signature found in one file.
pub struct Finding {
    pub sig: &'static Signature,
    pub count: u64,          // how many times the pattern occurs in the file
    pub first_offset: usize, // byte position of the first occurrence
}

/// All findings for one file (only files with at least one finding get a report).
pub struct FileReport {
    pub path: PathBuf,
    pub size: u64,
    pub kind: &'static str, // file type guessed by `detect_kind`
    pub findings: Vec<Finding>,
}

/// Counters for the whole run, shown in the report header.
#[derive(Default)]
pub struct ScanStats {
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub skipped_large: u64, // files over the size limit
    pub errors: u64,        // files or directories that could not be read
}

/// Signatures indexed by their first two bytes: `index[key]` lists the positions
/// in `SIGNATURES` of every pattern starting with those two bytes (65536 buckets).
pub struct Matcher {
    index: Vec<Vec<usize>>,
}

/// Two bytes combined into one number 0..65535, e.g. [0x63, 0x7c] -> 0x637c.
fn key(b: &[u8]) -> usize {
    (b[0] as usize) << 8 | b[1] as usize
}

impl Matcher {
    /// Builds the index. Signatures below `min` confidence are left out,
    /// so they can never be reported.
    pub fn new(min: Confidence) -> Self {
        let index = SIGNATURES
            .iter()
            .enumerate()
            .filter(|(_, s)| s.confidence >= min)
            // start from 65536 empty buckets and drop each signature into its bucket
            .fold(vec![Vec::new(); 65536], |mut index, (i, s)| {
                index[key(s.pattern)].push(i);
                index
            });
        Matcher { index }
    }

    /// Step 1 - candidates: for every pair of neighbouring bytes, the signatures
    /// starting with that pair (usually none), as (signature index, offset).
    fn candidates<'a>(&'a self, data: &'a [u8]) -> impl Iterator<Item = Hit> + 'a {
        data.windows(2).enumerate().flat_map(|(offset, pair)| self.index[key(pair)].iter().map(move |&si| (si, offset)))
    }

    /// Every signature found in `data`, in database order.
    pub fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let matches = self.candidates(data).filter(|&hit| is_match(data, hit));
        to_findings(count_hits(Counts::new(), matches))
    }

    /// Like `scan`, but for data too large to load at once (a raw device, the
    /// memory of a process): reads `reader` in chunks of `CHUNK` bytes and adds
    /// the matches to `counts`. `base` is the address of the first byte, added to
    /// every offset. Returns the updated counts and the number of bytes read;
    /// a read error ends the stream early.
    ///
    /// A pattern may straddle two chunks, so the last `longest pattern - 1` bytes
    /// of each chunk (`tail`) are put in front of the next one. Matches lying
    /// entirely inside the tail were already counted, so they are filtered out.
    pub fn count_stream(&self, mut reader: impl Read, base: usize, counts: Counts) -> (Counts, u64) {
        let keep = SIGNATURES.iter().map(|s| s.pattern.len()).max().unwrap_or(1) - 1;
        let (mut counts, mut tail, mut pos) = (counts, Vec::new(), 0);
        loop {
            let mut chunk = Vec::new();
            let _ = reader.by_ref().take(CHUNK).read_to_end(&mut chunk); // on error keep what was read
            if chunk.is_empty() {
                return (counts, pos as u64);
            }
            let (old, start) = (tail.len(), base + pos - tail.len());
            let data = [tail, chunk].concat();
            let new = self
                .candidates(&data)
                .filter(|&hit| is_match(&data, hit))
                .filter(|&(si, offset)| offset + SIGNATURES[si].pattern.len() > old)
                .map(|(si, offset)| (si, start + offset));
            counts = count_hits(counts, new);
            pos += data.len() - old;
            tail = data[data.len().saturating_sub(keep)..].to_vec();
        }
    }
}

/// How much of a stream is held in memory at a time (4 MB).
const CHUNK: u64 = 4 << 20;

/// A place where a signature may be (or is) present: (index in `SIGNATURES`, offset).
type Hit = (usize, usize);

/// Matches grouped by signature: index in `SIGNATURES` -> (count, first offset).
pub type Counts = BTreeMap<usize, (u64, usize)>;

/// Step 2 - verify: is the whole pattern really present at the candidate's offset?
fn is_match(data: &[u8], (si, offset): Hit) -> bool {
    data[offset..].starts_with(SIGNATURES[si].pattern)
}

/// Step 3 - group: adds the hits to `counts`.
/// Hits arrive in ascending offset order, so the offset stored on first insert
/// is the first occurrence. A `BTreeMap` iterates in key order = database order.
fn count_hits(counts: Counts, hits: impl Iterator<Item = Hit>) -> Counts {
    hits.fold(counts, |mut counts, (si, offset)| {
        counts.entry(si).or_insert((0, offset)).0 += 1;
        counts
    })
}

/// Step 4 - convert the grouped entries into the `Finding`s shown in the report.
fn to_findings(counts: Counts) -> Vec<Finding> {
    counts.into_iter().map(|(si, (count, first_offset))| Finding { sig: &SIGNATURES[si], count, first_offset }).collect()
}

/// Rough file type from the "magic bytes" at the start of the file (context for
/// the report). Without a known magic, the file is "Text" if its first 512 bytes
/// are all printable ASCII, otherwise "Binary/data".
pub fn detect_kind(data: &[u8]) -> &'static str {
    const MACH_O: &str = "Mach-O / Java class";
    const MAGIC: [(&[u8], &str); 9] = [
        (b"\x7fELF", "ELF executable/library"),
        (b"MZ", "Windows PE (exe/dll)"),
        (b"\xcf\xfa\xed\xfe", MACH_O),
        (b"\xce\xfa\xed\xfe", MACH_O),
        (b"\xfe\xed\xfa\xce", MACH_O),
        (b"\xfe\xed\xfa\xcf", MACH_O),
        (b"\xca\xfe\xba\xbe", MACH_O),
        (b"PK\x03\x04", "ZIP/JAR/APK archive"),
        (b"#!", "Script"),
    ];
    let is_text = |b: &u8| matches!(b, b'\n' | b'\r' | b'\t' | 0x20..=0x7e);
    MAGIC
        .iter()
        .find(|(magic, _)| data.starts_with(magic))
        .map(|&(_, kind)| kind)
        .unwrap_or(if data.iter().take(512).all(is_text) { "Text" } else { "Binary/data" })
}

/// All regular files under `path` with their sizes, found recursively.
/// Anything unreadable becomes an `Err` item instead of stopping the walk, so
/// the caller can count errors. Symlinks are neither file nor dir for
/// `symlink_metadata`, so they are skipped (this also prevents endless loops).
fn walk(path: PathBuf) -> Vec<io::Result<(PathBuf, u64)>> {
    let failed = |err| vec![Err(err)];
    let contents = |md: fs::Metadata| match (md.is_file(), md.is_dir()) {
        (true, _) => Ok(vec![Ok((path.clone(), md.len()))]), // a file: just itself
        // a directory: walk every entry and join the results into one list
        (_, true) => fs::read_dir(&path).map(|dir| dir.flat_map(|e| e.map_or_else(failed, |e| walk(e.path()))).collect()),
        _ => Ok(vec![]), // symlink, device, ...: nothing
    };
    fs::symlink_metadata(&path).and_then(contents).unwrap_or_else(failed)
}

/// What happened to one scanned object (a file, a device or a process).
pub enum Outcome {
    Error,                            // could not be read
    TooLarge,                         // over the size limit, not read
    Scanned(u64, Option<FileReport>), // bytes read; a report only if something was found
}

/// Outcome of a stream scan (`Matcher::count_stream`): `name` and `kind` label
/// the scanned object in the report.
pub fn stream_outcome(name: String, kind: &'static str, (counts, size): (Counts, u64)) -> Outcome {
    let findings = to_findings(counts);
    Outcome::Scanned(size, (!findings.is_empty()).then(|| FileReport { path: name.into(), size, kind, findings }))
}

/// Scans a raw device or image (disk, partition, ROM / firmware dump) as one
/// stream, without a size limit. The large buffer makes every read from the
/// device a whole number of sectors, which raw devices on Windows require.
pub fn scan_device(path: &Path, matcher: &Matcher) -> Outcome {
    let scan = |file| matcher.count_stream(io::BufReader::with_capacity(2 * CHUNK as usize, file), 0, Counts::new());
    match fs::File::open(path).map(scan) {
        Ok(result) if result.1 > 0 => stream_outcome(path.display().to_string(), "Raw device/image", result),
        _ => Outcome::Error, // could not open, or not a single byte could be read
    }
}

/// Reads and scans one file. The size check uses the size from `walk`, so
/// oversized files are never loaded into memory.
fn scan_file(entry: io::Result<(PathBuf, u64)>, matcher: &Matcher, max_size: u64) -> Outcome {
    match entry {
        Err(_) => Outcome::Error,
        Ok((_, size)) if size > max_size => Outcome::TooLarge,
        Ok((path, _)) => fs::read(&path).map_or(Outcome::Error, |data| {
            let (size, findings) = (data.len() as u64, matcher.scan(&data));
            let report = (!findings.is_empty()).then(|| FileReport { kind: detect_kind(&data), path, size, findings });
            Outcome::Scanned(size, report)
        }),
    }
}

/// The running result of a scan: the reports so far and the counters.
type Totals = (Vec<FileReport>, ScanStats);

/// Adds one outcome to the totals. Each case returns new stats with one
/// counter changed; `..stats` copies the others.
fn add_outcome((mut reports, stats): Totals, outcome: Outcome) -> Totals {
    match outcome {
        Outcome::Error => (reports, ScanStats { errors: stats.errors + 1, ..stats }),
        Outcome::TooLarge => (reports, ScanStats { skipped_large: stats.skipped_large + 1, ..stats }),
        Outcome::Scanned(size, report) => {
            reports.extend(report); // adds the report if there is one
            let (files_scanned, bytes_scanned) = (stats.files_scanned + 1, stats.bytes_scanned + size);
            (reports, ScanStats { files_scanned, bytes_scanned, ..stats })
        }
    }
}

/// What a scan is working on right now; `main` decides how (and whether) to show it.
pub type Progress<'a> = &'a dyn Fn(&str);

/// Scans every file under `root`: list of files -> one `Outcome` per file.
/// `progress` is told the path of each file before it is read.
pub fn scan_files(root: &Path, matcher: &Matcher, max_size: u64, progress: Progress) -> Vec<Outcome> {
    let announce = |entry: &io::Result<(PathBuf, u64)>| entry.iter().for_each(|(path, _)| progress(&path.display().to_string()));
    walk(root.to_path_buf()).into_iter().inspect(announce).map(|entry| scan_file(entry, matcher, max_size)).collect()
}

/// Sums outcomes (from files, devices and processes alike) into the final
/// result; reports are sorted by path.
pub fn total(outcomes: impl Iterator<Item = Outcome>) -> Totals {
    let (mut reports, stats) = outcomes.fold((Vec::new(), ScanStats::default()), add_outcome);
    reports.sort_by(|a, b| a.path.cmp(&b.path));
    (reports, stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    const AES_SBOX: [u8; 16] = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76];

    #[test]
    fn finds_aes_sbox() {
        let mut data = vec![0u8; 100];
        data.extend_from_slice(&AES_SBOX);
        let f = Matcher::new(Confidence::Medium).scan(&data);
        assert!(f.iter().any(|x| x.sig.algorithm == "AES" && x.first_offset == 100));
    }

    #[test]
    fn counts_repeats_and_keeps_first_offset() {
        let data = [&[0u8; 3][..], &AES_SBOX, &AES_SBOX].concat();
        let f = Matcher::new(Confidence::High).scan(&data);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].count, f[0].first_offset), (2, 3));
    }

    #[test]
    fn finds_rsa_pem() {
        let f = Matcher::new(Confidence::High).scan(b"junk -----BEGIN RSA PRIVATE KEY----- junk");
        assert!(f.iter().any(|x| x.sig.algorithm == "RSA"));
    }

    #[test]
    fn clean_or_tiny_data_has_no_findings() {
        let m = Matcher::new(Confidence::Low);
        assert!(m.scan(&[0xAA; 4096]).is_empty());
        assert!(m.scan(&[]).is_empty());
        assert!(m.scan(&[0x66]).is_empty());
    }

    #[test]
    fn min_confidence_filters_low() {
        let data = [0x66, 0x0f, 0x38, 0xdc, 0x00];
        assert!(Matcher::new(Confidence::Medium).scan(&data).is_empty());
        assert!(!Matcher::new(Confidence::Low).scan(&data).is_empty());
    }

    #[test]
    fn every_signature_matches_itself() {
        let m = Matcher::new(Confidence::Low);
        for s in SIGNATURES {
            assert!(s.pattern.len() >= 2, "{} is too short to index", s.description);
            assert!(m.scan(s.pattern).iter().any(|f| std::ptr::eq(f.sig, s)), "{} not found", s.description);
        }
    }

    /// Feeds the data one byte per `read` call, so chunk handling cannot rely on full reads.
    struct Trickle<'a>(&'a [u8]);
    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.0.len().min(buf.len()).min(1);
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    #[test]
    fn stream_scan_equals_whole_scan_across_chunk_borders() {
        let chunk = CHUNK as usize;
        let pem = b"-----BEGIN RSA PRIVATE KEY-----";
        // one S-box cut in half by the first chunk border, a PEM header ending exactly
        // on the second border, and an S-box right after the third border
        let mut data = vec![0u8; 3 * chunk + 100];
        data[chunk - 8..chunk + 8].copy_from_slice(&AES_SBOX);
        data[2 * chunk - pem.len()..2 * chunk].copy_from_slice(pem);
        data[3 * chunk..3 * chunk + 16].copy_from_slice(&AES_SBOX);

        let m = Matcher::new(Confidence::High);
        let whole: Vec<_> = m.scan(&data).iter().map(|f| (f.sig.description, f.count, f.first_offset)).collect();
        let (counts, bytes) = m.count_stream(&data[..], 0, Counts::new());
        let stream: Vec<_> = to_findings(counts).iter().map(|f| (f.sig.description, f.count, f.first_offset)).collect();

        assert_eq!(bytes, data.len() as u64);
        assert_eq!(whole, vec![("S-box table", 2, chunk - 8), ("PEM header: RSA PRIVATE KEY", 1, 2 * chunk - pem.len())]);
        assert_eq!(stream, whole);
    }

    #[test]
    fn stream_scan_handles_short_reads_and_base_address() {
        let data = [&[0u8; 5][..], &AES_SBOX, &AES_SBOX].concat();
        let (counts, bytes) = Matcher::new(Confidence::High).count_stream(Trickle(&data), 0x1000, Counts::new());
        let f = to_findings(counts);
        assert_eq!(bytes, 37);
        assert_eq!((f.len(), f[0].count, f[0].first_offset), (1, 2, 0x1005));
    }

    #[test]
    fn scans_image_as_device() {
        let image = std::env::temp_dir().join(format!("crypto_scanner_image_{}", std::process::id()));
        fs::write(&image, [&[0u8; 9][..], &AES_SBOX].concat()).unwrap();
        let outcome = scan_device(&image, &Matcher::new(Confidence::High));
        fs::remove_file(&image).unwrap();

        let Outcome::Scanned(25, Some(report)) = outcome else { panic!("image was not scanned") };
        assert_eq!((report.kind, report.findings[0].first_offset), ("Raw device/image", 9));
        assert!(matches!(scan_device(Path::new("no/such/device"), &Matcher::new(Confidence::High)), Outcome::Error));
    }

    #[test]
    fn detects_file_kinds() {
        assert_eq!(detect_kind(b"\x7fELF\x02\x01"), "ELF executable/library");
        assert_eq!(detect_kind(b"MZ\x90\x00"), "Windows PE (exe/dll)");
        assert_eq!(detect_kind(b"PK\x03\x04rest"), "ZIP/JAR/APK archive");
        assert_eq!(detect_kind(b"#!/bin/sh\n"), "Script");
        assert_eq!(detect_kind(b"plain text\n"), "Text");
        assert_eq!(detect_kind(&[0x00, 0xff, 0x10]), "Binary/data");
    }

    #[test]
    fn scans_directory_tree() {
        let dir = std::env::temp_dir().join(format!("crypto_scanner_test_{}", std::process::id()));
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub").join("key.pem"), "-----BEGIN RSA PRIVATE KEY-----\n").unwrap();
        fs::write(dir.join("clean.txt"), "nothing here").unwrap();
        fs::write(dir.join("big.bin"), [0u8; 64]).unwrap();

        let (reports, stats) = total(scan_files(&dir, &Matcher::new(Confidence::Medium), 40, &|_| ()).into_iter());
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!((stats.files_scanned, stats.skipped_large, stats.errors), (2, 1, 0));
        assert_eq!(reports.len(), 1);
        assert!(reports[0].path.ends_with("key.pem"));
        assert_eq!(reports[0].kind, "Text");
    }
}

//! File discovery and multi-pattern binary scanning (std only).

use crate::signatures::{Confidence, Signature, SIGNATURES};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::{fs, io};

pub struct Finding {
    pub sig: &'static Signature,
    pub count: u64,
    pub first_offset: usize,
}

pub struct FileReport {
    pub path: PathBuf,
    pub size: u64,
    pub kind: &'static str,
    pub findings: Vec<Finding>,
}

#[derive(Default)]
pub struct ScanStats {
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub skipped_large: u64,
    pub errors: u64,
}

/// Signatures indexed by their first two bytes (65536 buckets).
pub struct Matcher {
    index: Vec<Vec<usize>>,
}

fn key(b: &[u8]) -> usize {
    (b[0] as usize) << 8 | b[1] as usize
}

impl Matcher {
    /// Signatures below `min` confidence are left out of the index.
    pub fn new(min: Confidence) -> Self {
        let index = SIGNATURES
            .iter()
            .enumerate()
            .filter(|(_, s)| s.confidence >= min && s.pattern.len() >= 2)
            .fold(vec![Vec::new(); 65536], |mut index, (i, s)| {
                index[key(s.pattern)].push(i);
                index
            });
        Matcher { index }
    }

    /// Every signature found in `data`, in database order.
    pub fn scan(&self, data: &[u8]) -> Vec<Finding> {
        data.windows(2)
            .enumerate()
            .flat_map(|(offset, w)| self.index[key(w)].iter().map(move |&si| (si, offset)))
            .filter(|&(si, offset)| data[offset..].starts_with(SIGNATURES[si].pattern))
            .fold(BTreeMap::new(), |mut hits, (si, offset)| {
                hits.entry(si).or_insert((0, offset)).0 += 1;
                hits
            })
            .into_iter()
            .map(|(si, (count, first_offset))| Finding { sig: &SIGNATURES[si], count, first_offset })
            .collect()
    }
}

/// Rough file type from magic bytes (context for the report).
pub fn detect_kind(data: &[u8]) -> &'static str {
    const MAGIC: [(&[u8], &str); 9] = [
        (b"\x7fELF", "ELF executable/library"),
        (b"MZ", "Windows PE (exe/dll)"),
        (b"\xcf\xfa\xed\xfe", "Mach-O / Java class"),
        (b"\xce\xfa\xed\xfe", "Mach-O / Java class"),
        (b"\xfe\xed\xfa\xce", "Mach-O / Java class"),
        (b"\xfe\xed\xfa\xcf", "Mach-O / Java class"),
        (b"\xca\xfe\xba\xbe", "Mach-O / Java class"),
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

/// All regular files under `path` with their sizes; unreadable entries become `Err`.
/// Symlinks are neither file nor dir for `symlink_metadata`, so they are skipped.
fn walk(path: PathBuf) -> Vec<io::Result<(PathBuf, u64)>> {
    match fs::symlink_metadata(&path) {
        Ok(md) if md.is_file() => vec![Ok((path, md.len()))],
        Ok(md) if md.is_dir() => match fs::read_dir(&path) {
            Ok(entries) => entries.flat_map(|e| e.map_or_else(|err| vec![Err(err)], |e| walk(e.path()))).collect(),
            Err(err) => vec![Err(err)],
        },
        Ok(_) => vec![],
        Err(err) => vec![Err(err)],
    }
}

enum Outcome {
    Error,
    TooLarge,
    Scanned(u64, Option<FileReport>),
}

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

/// Scans every file under `root`; reports are sorted by path.
pub fn scan_path(root: &Path, matcher: &Matcher, max_size: u64) -> (Vec<FileReport>, ScanStats) {
    let (mut reports, stats) = walk(root.to_path_buf())
        .into_iter()
        .map(|entry| scan_file(entry, matcher, max_size))
        .fold((Vec::new(), ScanStats::default()), |(mut reports, stats), outcome| match outcome {
            Outcome::Error => (reports, ScanStats { errors: stats.errors + 1, ..stats }),
            Outcome::TooLarge => (reports, ScanStats { skipped_large: stats.skipped_large + 1, ..stats }),
            Outcome::Scanned(size, report) => {
                reports.extend(report);
                let (files_scanned, bytes_scanned) = (stats.files_scanned + 1, stats.bytes_scanned + size);
                (reports, ScanStats { files_scanned, bytes_scanned, ..stats })
            }
        });
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

        let (reports, stats) = scan_path(&dir, &Matcher::new(Confidence::Medium), 40);
        fs::remove_dir_all(&dir).unwrap();

        assert_eq!((stats.files_scanned, stats.skipped_large, stats.errors), (2, 1, 0));
        assert_eq!(reports.len(), 1);
        assert!(reports[0].path.ends_with("key.pem"));
        assert_eq!(reports[0].kind, "Text");
    }
}

//! File discovery and multi-pattern binary scanning (std only).

use crate::signatures::{Confidence, Signature, SIGNATURES};
use std::fs;
use std::path::{Path, PathBuf};

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

/// Index of signatures keyed by their first two bytes (65536 buckets).
pub struct Matcher {
    index: Vec<Vec<usize>>,
    min: Confidence,
}

impl Matcher {
    pub fn new(min: Confidence) -> Self {
        let mut index: Vec<Vec<usize>> = vec![Vec::new(); 65536];
        for (i, s) in SIGNATURES.iter().enumerate() {
            if s.confidence < min || s.pattern.len() < 2 {
                continue;
            }
            let key = ((s.pattern[0] as usize) << 8) | s.pattern[1] as usize;
            index[key].push(i);
        }
        Matcher { index, min }
    }

    pub fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let n = SIGNATURES.len();
        let mut counts = vec![0u64; n];
        let mut first = vec![usize::MAX; n];
        if data.len() >= 2 {
            for i in 0..data.len() - 1 {
                let key = ((data[i] as usize) << 8) | data[i + 1] as usize;
                let cands = &self.index[key];
                if cands.is_empty() {
                    continue;
                }
                for &si in cands {
                    if data[i..].starts_with(SIGNATURES[si].pattern) {
                        counts[si] += 1;
                        if first[si] == usize::MAX {
                            first[si] = i;
                        }
                    }
                }
            }
        }
        let mut out = Vec::new();
        for i in 0..n {
            if counts[i] > 0 && SIGNATURES[i].confidence >= self.min {
                out.push(Finding { sig: &SIGNATURES[i], count: counts[i], first_offset: first[i] });
            }
        }
        out
    }
}

/// Rough file type from magic bytes (context for the report).
pub fn detect_kind(data: &[u8]) -> &'static str {
    if data.starts_with(&[0x7f, b'E', b'L', b'F']) {
        "ELF executable/library"
    } else if data.starts_with(b"MZ") {
        "Windows PE (exe/dll)"
    } else if data.starts_with(&[0xcf, 0xfa, 0xed, 0xfe])
        || data.starts_with(&[0xce, 0xfa, 0xed, 0xfe])
        || data.starts_with(&[0xfe, 0xed, 0xfa, 0xce])
        || data.starts_with(&[0xfe, 0xed, 0xfa, 0xcf])
        || data.starts_with(&[0xca, 0xfe, 0xba, 0xbe])
    {
        "Mach-O / Java class"
    } else if data.starts_with(b"PK\x03\x04") {
        "ZIP/JAR/APK archive"
    } else if data.starts_with(b"#!") {
        "Script"
    } else if data.iter().take(512).all(|&b| b == b'\n' || b == b'\r' || b == b'\t' || (0x20..0x7f).contains(&b)) {
        "Text"
    } else {
        "Binary/data"
    }
}

/// Recursively collect regular files (symlinks are not followed).
pub fn collect_files(root: &Path, stats: &mut ScanStats) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(p) = stack.pop() {
        let md = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => {
                stats.errors += 1;
                continue;
            }
        };
        let ft = md.file_type();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            match fs::read_dir(&p) {
                Ok(rd) => {
                    for e in rd {
                        match e {
                            Ok(e) => stack.push(e.path()),
                            Err(_) => stats.errors += 1,
                        }
                    }
                }
                Err(_) => stats.errors += 1,
            }
        } else if ft.is_file() {
            out.push(p);
        }
    }
    out.sort();
    out
}

pub fn scan_path(root: &Path, matcher: &Matcher, max_size: u64) -> (Vec<FileReport>, ScanStats) {
    let mut stats = ScanStats::default();
    let files = collect_files(root, &mut stats);
    let mut reports = Vec::new();
    for path in files {
        let size = match fs::metadata(&path) {
            Ok(m) => m.len(),
            Err(_) => {
                stats.errors += 1;
                continue;
            }
        };
        if size > max_size {
            stats.skipped_large += 1;
            continue;
        }
        let data = match fs::read(&path) {
            Ok(d) => d,
            Err(_) => {
                stats.errors += 1;
                continue;
            }
        };
        stats.files_scanned += 1;
        stats.bytes_scanned += size;
        let findings = matcher.scan(&data);
        if !findings.is_empty() {
            reports.push(FileReport { kind: detect_kind(&data), path, size, findings });
        }
    }
    (reports, stats)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_aes_sbox() {
        let mut data = vec![0u8; 100];
        data.extend_from_slice(&[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]);
        let m = Matcher::new(Confidence::Medium);
        let f = m.scan(&data);
        assert!(f.iter().any(|x| x.sig.algorithm == "AES" && x.first_offset == 100));
    }

    #[test]
    fn finds_rsa_pem() {
        let data = b"junk -----BEGIN RSA PRIVATE KEY----- junk".to_vec();
        let m = Matcher::new(Confidence::High);
        let f = m.scan(&data);
        assert!(f.iter().any(|x| x.sig.algorithm == "RSA"));
    }

    #[test]
    fn clean_data_has_no_findings() {
        let data = vec![0xAAu8; 4096];
        assert!(Matcher::new(Confidence::Low).scan(&data).is_empty());
    }

    #[test]
    fn min_confidence_filters_low() {
        let data = vec![0x66, 0x0f, 0x38, 0xdc, 0x00];
        assert!(Matcher::new(Confidence::Medium).scan(&data).is_empty());
        assert!(!Matcher::new(Confidence::Low).scan(&data).is_empty());
    }
}

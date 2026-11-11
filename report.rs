//! Console, JSON and CSV output.

use crate::scanner::{FileReport, ScanStats};
use crate::signatures::{quantum_status, Confidence};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

pub fn print_text(reports: &[FileReport], stats: &ScanStats) {
    println!("=== Crypto scanner report ===");
    println!(
        "Files scanned: {} ({:.1} MB) | skipped (too large): {} | errors: {}",
        stats.files_scanned,
        stats.bytes_scanned as f64 / 1_048_576.0,
        stats.skipped_large,
        stats.errors
    );
    println!("Files with crypto indicators: {}\n", reports.len());

    let mut summary: BTreeMap<&str, (usize, Confidence)> = BTreeMap::new();
    for r in reports {
        println!("{}  [{}, {} bytes]", r.path.display(), r.kind, r.size);
        let mut seen: BTreeMap<&str, Confidence> = BTreeMap::new();
        for f in &r.findings {
            println!(
                "    [{:<6}] {:<17} {} @0x{:x} (x{})",
                f.sig.confidence.label(),
                f.sig.algorithm,
                f.sig.description,
                f.first_offset,
                f.count
            );
            let e = seen.entry(f.sig.algorithm).or_insert(f.sig.confidence);
            if f.sig.confidence > *e {
                *e = f.sig.confidence;
            }
        }
        for (alg, conf) in seen {
            let e = summary.entry(alg).or_insert((0, conf));
            e.0 += 1;
            if conf > e.1 {
                e.1 = conf;
            }
        }
        println!();
    }

    println!("=== Summary by algorithm ===");
    println!("{:<18} {:>5}  {:<7} {}", "Algorithm", "Files", "Conf.", "Quantum status");
    for (alg, (files, conf)) in &summary {
        println!("{:<18} {:>5}  {:<7} {}", alg, files, conf.label(), quantum_status(alg));
    }
}

fn json_esc(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o
}

pub fn write_json(path: &Path, reports: &[FileReport], stats: &ScanStats) -> io::Result<()> {
    let mut s = String::new();
    s.push_str(&format!(
        "{{\n  \"files_scanned\": {},\n  \"skipped_large\": {},\n  \"errors\": {},\n  \"files\": [\n",
        stats.files_scanned, stats.skipped_large, stats.errors
    ));
    for (i, r) in reports.iter().enumerate() {
        s.push_str(&format!(
            "    {{\"path\": \"{}\", \"type\": \"{}\", \"size\": {}, \"findings\": [\n",
            json_esc(&r.path.display().to_string()),
            json_esc(r.kind),
            r.size
        ));
        for (j, f) in r.findings.iter().enumerate() {
            s.push_str(&format!(
                "      {{\"algorithm\": \"{}\", \"description\": \"{}\", \"confidence\": \"{}\", \"offset\": {}, \"count\": {}, \"quantum_status\": \"{}\"}}{}\n",
                json_esc(f.sig.algorithm),
                json_esc(f.sig.description),
                f.sig.confidence.label(),
                f.first_offset,
                f.count,
                json_esc(quantum_status(f.sig.algorithm)),
                if j + 1 < r.findings.len() { "," } else { "" }
            ));
        }
        s.push_str(&format!("    ]}}{}\n", if i + 1 < reports.len() { "," } else { "" }));
    }
    s.push_str("  ]\n}\n");
    fs::write(path, s)
}

fn csv_esc(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

pub fn write_csv(path: &Path, reports: &[FileReport]) -> io::Result<()> {
    let mut s = String::from("path,file_type,algorithm,description,confidence,offset_hex,count,quantum_status\n");
    for r in reports {
        for f in &r.findings {
            s.push_str(&format!(
                "{},{},{},{},{},0x{:x},{},{}\n",
                csv_esc(&r.path.display().to_string()),
                csv_esc(r.kind),
                csv_esc(f.sig.algorithm),
                csv_esc(f.sig.description),
                f.sig.confidence.label(),
                f.first_offset,
                f.count,
                csv_esc(quantum_status(f.sig.algorithm))
            ));
        }
    }
    fs::write(path, s)
}

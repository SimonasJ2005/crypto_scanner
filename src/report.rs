//! Console, JSON and CSV reports as pure functions returning text.

use crate::scanner::{FileReport, ScanStats};
use crate::signatures::{quantum_status, Confidence};
use std::collections::BTreeMap;

/// algorithm -> (number of files it appears in, highest confidence seen)
fn summarize(reports: &[FileReport]) -> BTreeMap<&'static str, (usize, Confidence)> {
    let best_in_file = |r: &FileReport| {
        r.findings.iter().fold(BTreeMap::new(), |mut best, f| {
            let c = best.entry(f.sig.algorithm).or_insert(f.sig.confidence);
            *c = f.sig.confidence.max(*c);
            best
        })
    };
    reports.iter().flat_map(best_in_file).fold(BTreeMap::new(), |mut sum, (alg, conf)| {
        let e = sum.entry(alg).or_insert((0, conf));
        *e = (e.0 + 1, conf.max(e.1));
        sum
    })
}

fn file_text(r: &FileReport) -> String {
    let findings: String = r
        .findings
        .iter()
        .map(|f| {
            let s = f.sig;
            format!("    [{:<6}] {:<17} {} @0x{:x} (x{})\n", s.confidence.label(), s.algorithm, s.description, f.first_offset, f.count)
        })
        .collect();
    format!("{}  [{}, {} bytes]\n{findings}\n", r.path.display(), r.kind, r.size)
}

pub fn to_text(reports: &[FileReport], stats: &ScanStats) -> String {
    let files: String = reports.iter().map(file_text).collect();
    let summary: String = summarize(reports)
        .iter()
        .map(|(alg, (n, conf))| format!("{alg:<18} {n:>5}  {:<7} {}\n", conf.label(), quantum_status(alg)))
        .collect();
    format!(
        "=== Crypto scanner report ===\n\
         Files scanned: {} ({:.1} MB) | skipped (too large): {} | errors: {}\n\
         Files with crypto indicators: {}\n\n\
         {files}\
         === Summary by algorithm ===\n\
         {:<18} {:>5}  {:<7} Quantum status\n\
         {summary}",
        stats.files_scanned,
        stats.bytes_scanned as f64 / 1_048_576.0,
        stats.skipped_large,
        stats.errors,
        reports.len(),
        "Algorithm",
        "Files",
        "Conf."
    )
}

fn json_esc(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '"' => "\\\"".to_string(),
            '\\' => "\\\\".to_string(),
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32),
            c => c.to_string(),
        })
        .collect()
}

fn file_json(r: &FileReport) -> String {
    let findings: Vec<String> = r
        .findings
        .iter()
        .map(|f| {
            format!(
                r#"      {{"algorithm": "{}", "description": "{}", "confidence": "{}", "offset": {}, "count": {}, "quantum_status": "{}"}}"#,
                json_esc(f.sig.algorithm),
                json_esc(f.sig.description),
                f.sig.confidence.label(),
                f.first_offset,
                f.count,
                json_esc(quantum_status(f.sig.algorithm))
            )
        })
        .collect();
    format!(
        "    {{\"path\": \"{}\", \"type\": \"{}\", \"size\": {}, \"findings\": [\n{}\n    ]}}",
        json_esc(&r.path.display().to_string()),
        json_esc(r.kind),
        r.size,
        findings.join(",\n")
    )
}

pub fn to_json(reports: &[FileReport], stats: &ScanStats) -> String {
    let files: Vec<String> = reports.iter().map(file_json).collect();
    format!(
        "{{\n  \"files_scanned\": {},\n  \"skipped_large\": {},\n  \"errors\": {},\n  \"files\": [\n{}\n  ]\n}}\n",
        stats.files_scanned,
        stats.skipped_large,
        stats.errors,
        files.join(",\n")
    )
}

fn csv_esc(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

pub fn to_csv(reports: &[FileReport]) -> String {
    let header = "path,file_type,algorithm,description,confidence,offset_hex,count,quantum_status\n".to_string();
    let rows = reports.iter().flat_map(|r| {
        r.findings.iter().map(move |f| {
            format!(
                "{},{},{},{},{},0x{:x},{},{}\n",
                csv_esc(&r.path.display().to_string()),
                csv_esc(r.kind),
                csv_esc(f.sig.algorithm),
                csv_esc(f.sig.description),
                f.sig.confidence.label(),
                f.first_offset,
                f.count,
                csv_esc(quantum_status(f.sig.algorithm))
            )
        })
    });
    std::iter::once(header).chain(rows).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::Matcher;

    fn sample() -> Vec<FileReport> {
        let findings = Matcher::new(Confidence::High).scan(b"-----BEGIN RSA PRIVATE KEY-----");
        vec![FileReport { path: "dir\\a \"b\".pem".into(), size: 31, kind: "Text", findings }]
    }

    #[test]
    fn summary_counts_files_and_keeps_best_confidence() {
        let report = |data: &[u8]| FileReport { path: "f".into(), size: 0, kind: "Text", findings: Matcher::new(Confidence::Low).scan(data) };
        // file 1: RSA at HIGH and MEDIUM; file 2: RSA at MEDIUM only
        let reports = [report(b"-----BEGIN RSA PRIVATE KEY----- ssh-rsa ssh-rsa"), report(b"ssh-rsa")];
        let summary = summarize(&reports);
        assert_eq!(summary.len(), 1);
        assert_eq!(summary["RSA"], (2, Confidence::High));
    }

    #[test]
    fn text_report() {
        let text = to_text(&sample(), &ScanStats { files_scanned: 1, ..Default::default() });
        assert!(text.starts_with("=== Crypto scanner report ===\nFiles scanned: 1 (0.0 MB)"));
        assert!(text.contains("    [HIGH  ] RSA               PEM header: RSA PRIVATE KEY @0x0 (x1)\n"));
        assert!(text.contains("RSA                    1  HIGH    BROKEN by Shor"));
    }

    #[test]
    fn escapes() {
        assert_eq!(json_esc("a\"b\\c\n\u{1}"), "a\\\"b\\\\c\\n\\u0001");
        assert_eq!(csv_esc("a\"b,c"), "\"a\"\"b,c\"");
    }

    #[test]
    fn json_report() {
        let stats = ScanStats { files_scanned: 1, ..Default::default() };
        let json = to_json(&sample(), &stats);
        assert!(json.contains(r#""files_scanned": 1"#));
        assert!(json.contains(r#""path": "dir\\a \"b\".pem""#));
        assert!(json.contains(r#""algorithm": "RSA""#));
        assert!(json.contains(r#""offset": 0, "count": 1"#));
        assert!(!json.contains(",\n    ]") && !json.contains(",\n  ]"), "trailing comma");

        let empty = to_json(&[], &ScanStats::default());
        assert!(empty.contains("\"files\": [\n\n  ]"));
    }

    #[test]
    fn csv_report() {
        let csv = to_csv(&sample());
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].starts_with("\"dir\\a \"\"b\"\".pem\",\"Text\",\"RSA\","));
        assert!(lines[1].contains(",HIGH,0x0,1,"));
    }
}

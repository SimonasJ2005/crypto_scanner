mod report;
mod scanner;
mod signatures;

use signatures::Confidence;
use std::env;
use std::path::PathBuf;
use std::process;

struct Options {
    root: PathBuf,
    json: Option<PathBuf>,
    csv: Option<PathBuf>,
    max_size: u64,
    min_conf: Confidence,
}

const USAGE: &str = "Usage: crypto_scanner <directory-or-file> [options]
  --json <file>             write JSON report
  --csv <file>              write CSV report
  --min-confidence <level>  low | medium (default) | high
  --max-size-mb <n>         skip files larger than n MB (default 200)";

fn parse_args() -> Result<Options, String> {
    let mut args = env::args().skip(1);
    let mut root: Option<PathBuf> = None;
    let mut opts = Options { root: PathBuf::new(), json: None, csv: None, max_size: 200 * 1024 * 1024, min_conf: Confidence::Medium };
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => return Err(String::new()),
            "--json" => opts.json = Some(PathBuf::from(args.next().ok_or("--json needs a file name")?)),
            "--csv" => opts.csv = Some(PathBuf::from(args.next().ok_or("--csv needs a file name")?)),
            "--min-confidence" => {
                let v = args.next().ok_or("--min-confidence needs a value")?;
                opts.min_conf = Confidence::parse(&v).ok_or("confidence must be low, medium or high")?;
            }
            "--max-size-mb" => {
                let v = args.next().ok_or("--max-size-mb needs a number")?;
                let mb: u64 = v.parse().map_err(|_| "invalid number for --max-size-mb".to_string())?;
                opts.max_size = mb * 1024 * 1024;
            }
            s if s.starts_with("--") => return Err(format!("unknown option {}", s)),
            _ => root = Some(PathBuf::from(a)),
        }
    }
    opts.root = root.ok_or("missing directory to scan")?;
    Ok(opts)
}

fn main() {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("error: {}\n", e);
            }
            eprintln!("{}", USAGE);
            process::exit(if e.is_empty() { 0 } else { 2 });
        }
    };
    if !opts.root.exists() {
        eprintln!("error: path {} does not exist", opts.root.display());
        process::exit(2);
    }

    let matcher = scanner::Matcher::new(opts.min_conf);
    let (reports, stats) = scanner::scan_path(&opts.root, &matcher, opts.max_size);
    report::print_text(&reports, &stats);

    if let Some(p) = &opts.json {
        match report::write_json(p, &reports, &stats) {
            Ok(_) => println!("\nJSON report written to {}", p.display()),
            Err(e) => eprintln!("could not write JSON: {}", e),
        }
    }
    if let Some(p) = &opts.csv {
        match report::write_csv(p, &reports) {
            Ok(_) => println!("CSV report written to {}", p.display()),
            Err(e) => eprintln!("could not write CSV: {}", e),
        }
    }
}

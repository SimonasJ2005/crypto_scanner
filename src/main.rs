//! Command-line entry point. All side effects live here (reading arguments,
//! printing, writing report files, exit codes); the other modules only compute:
//!
//!   signatures  - the database: which byte patterns reveal which algorithm
//!   scanner     - walks the directory and searches every file for the patterns;
//!                 also scans raw devices / ROM images as a stream
//!   memory      - scans the memory (RAM) of running processes
//!   report      - turns the findings into text / JSON / CSV strings
//!
//! Flow: arguments -> Options -> Matcher -> outcomes of every target -> reports -> output.

mod memory;
mod report;
mod scanner;
mod signatures;

use signatures::Confidence;
use std::path::{Path, PathBuf};
use std::{env, fs, process};

/// Everything the user can set on the command line.
struct Options {
    root: Option<PathBuf>,   // file or directory to scan
    device: Option<PathBuf>, // raw device or ROM image to scan as one stream
    ram: bool,               // scan the memory of all running processes
    pid: Option<u32>,        // scan the memory of this process only
    json: Option<PathBuf>,   // where to write the JSON report, if requested
    csv: Option<PathBuf>,    // where to write the CSV report, if requested
    max_size: u64,           // files larger than this many bytes are skipped
    min_conf: Confidence,    // signatures below this confidence are ignored
}

/// Defaults: nothing to scan, 200 MB size limit (200 << 20 bytes), medium confidence.
impl Default for Options {
    fn default() -> Self {
        let (max_size, min_conf) = (200 << 20, Confidence::Medium);
        Options { root: None, device: None, ram: false, pid: None, json: None, csv: None, max_size, min_conf }
    }
}

const USAGE: &str = "Usage: crypto_scanner [<directory-or-file>] [options]
At least one target is required: a path, --device, --ram or --pid.
  --device <path>           scan a raw device or ROM/firmware image as a stream
                            (Linux: /dev/sda, Windows: \\\\.\\PhysicalDrive0)
  --ram                     scan the memory of all running processes
  --pid <n>                 scan the memory of one process
  --json <file>             write JSON report
  --csv <file>              write CSV report
  --min-confidence <level>  low | medium (default) | high
  --max-size-mb <n>         skip files larger than n MB (default 200)
Devices and other users' processes need administrator / root rights.";

/// Parses the arguments recursively: each step matches the front of the list,
/// builds a new `Options` with one field replaced (`..o` copies the rest) and
/// calls itself on the remaining arguments. Nothing is mutated.
/// An empty error string means "show help".
fn parse_args(args: &[&str], o: Options) -> Result<Options, String> {
    match args {
        // end of the list: valid only if some target was given
        [] if o.root.is_none() && o.device.is_none() && !o.ram && o.pid.is_none() => Err("nothing to scan".into()),
        [] => Ok(o),
        ["-h" | "--help", ..] => Err(String::new()),
        ["--ram", rest @ ..] => parse_args(rest, Options { ram: true, ..o }),
        // options that take a value consume two arguments
        ["--device", path, rest @ ..] => parse_args(rest, Options { device: Some(path.into()), ..o }),
        ["--pid", n, rest @ ..] => {
            let pid = n.parse().map_err(|_| "invalid number for --pid")?;
            parse_args(rest, Options { pid: Some(pid), ..o })
        }
        ["--json", file, rest @ ..] => parse_args(rest, Options { json: Some(file.into()), ..o }),
        ["--csv", file, rest @ ..] => parse_args(rest, Options { csv: Some(file.into()), ..o }),
        ["--min-confidence", level, rest @ ..] => {
            let min_conf = Confidence::parse(level).ok_or("confidence must be low, medium or high")?;
            parse_args(rest, Options { min_conf, ..o })
        }
        ["--max-size-mb", n, rest @ ..] => {
            let mb: u64 = n.parse().map_err(|_| "invalid number for --max-size-mb")?;
            parse_args(rest, Options { max_size: mb.saturating_mul(1 << 20), ..o })
        }
        // anything else starting with '-' is unknown, or a known option with its value missing
        [flag, ..] if flag.starts_with('-') => Err(format!("unknown option or missing value: {flag}")),
        // a plain argument is the path to scan
        [path, rest @ ..] => parse_args(rest, Options { root: Some(path.into()), ..o }),
    }
}

/// Prints an error and stops the program (exit code 2 = bad usage, 1 = I/O failure).
fn fail(msg: String, code: i32) -> ! {
    eprintln!("error: {msg}");
    process::exit(code)
}

/// Writes one finished report to disk.
fn save(kind: &str, path: &Path, content: String) {
    fs::write(path, content).unwrap_or_else(|e| fail(format!("could not write {kind} report: {e}"), 1));
    println!("{kind} report written to {}", path.display());
}

fn main() {
    // skip(1) drops the program name; &str slices allow matching on literals in parse_args
    let args: Vec<String> = env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let opts = match parse_args(&args, Options::default()) {
        Ok(o) => o,
        Err(e) if e.is_empty() => return println!("{USAGE}"),
        Err(e) => fail(format!("{e}\n\n{USAGE}"), 2),
    };
    if let Some(root) = opts.root.iter().find(|r| !r.exists()) {
        fail(format!("path {} does not exist", root.display()), 2);
    }

    // build the signature index once; every requested target yields a list of
    // outcomes, and all of them are summed into one report
    let matcher = scanner::Matcher::new(opts.min_conf);
    let files = opts.root.iter().flat_map(|root| scanner::scan_files(root, &matcher, opts.max_size));
    let device = opts.device.iter().map(|path| scanner::scan_device(path, &matcher));
    let ram = if opts.ram || opts.pid.is_some() { memory::scan_processes(&matcher, opts.pid) } else { Vec::new() };
    let (reports, stats) = scanner::total(files.chain(device).chain(ram));
    println!("{}", report::to_text(&reports, &stats));

    // optional machine-readable reports
    if let Some(p) = &opts.json {
        save("JSON", p, report::to_json(&reports, &stats));
    }
    if let Some(p) = &opts.csv {
        save("CSV", p, report::to_csv(&reports));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Options, String> {
        parse_args(args, Options::default())
    }

    #[test]
    fn parses_all_options() {
        let o = parse(&["dir", "--json", "r.json", "--csv", "r.csv", "--min-confidence", "HIGH", "--max-size-mb", "5"]).ok().unwrap();
        assert_eq!(o.root, Some(PathBuf::from("dir")));
        assert_eq!(o.json, Some(PathBuf::from("r.json")));
        assert_eq!(o.csv, Some(PathBuf::from("r.csv")));
        assert_eq!(o.min_conf, Confidence::High);
        assert_eq!(o.max_size, 5 << 20);
    }

    #[test]
    fn defaults() {
        let o = parse(&["dir"]).ok().unwrap();
        assert_eq!((o.max_size, o.min_conf), (200 << 20, Confidence::Medium));
        assert!(o.json.is_none() && o.csv.is_none());
    }

    #[test]
    fn memory_and_device_targets_need_no_path() {
        let o = parse(&["--ram"]).ok().unwrap();
        assert!(o.ram && o.root.is_none());
        assert_eq!(parse(&["--pid", "42"]).ok().unwrap().pid, Some(42));
        assert_eq!(parse(&["--device", "/dev/sda"]).ok().unwrap().device, Some(PathBuf::from("/dev/sda")));
        assert!(parse(&["--pid", "x"]).is_err());
    }

    #[test]
    fn rejects_bad_input() {
        assert_eq!(parse(&[]).err().unwrap(), "nothing to scan");
        assert_eq!(parse(&["--json", "r.json"]).err().unwrap(), "nothing to scan");
        assert_eq!(parse(&["dir", "--json"]).err().unwrap(), "unknown option or missing value: --json");
        assert_eq!(parse(&["dir", "--bogus"]).err().unwrap(), "unknown option or missing value: --bogus");
        assert!(parse(&["dir", "--min-confidence", "huge"]).is_err());
        assert!(parse(&["dir", "--max-size-mb", "abc"]).is_err());
        assert_eq!(parse(&["--help"]).err(), Some(String::new()));
    }
}

//! Bonus: scanning the memory (RAM) of running processes.
//!
//! A program that uses cryptography keeps its tables, constants and often its
//! keys in memory while it runs, even if the file on disk is packed or encrypted.
//! So the same signatures are searched in the memory of every process:
//!
//!   1. list the process ids;
//!   2. for each process, list its readable memory regions (start address, length);
//!   3. read every region in chunks and feed it to `Matcher::count_stream`;
//!   4. report the process like a file: "pid 1234 (name)", offsets = addresses.
//!
//! Steps 1-2 and the reading itself differ per operating system and live in the
//! `os` module below: Linux uses the `/proc` file system, Windows the Win32 API.
//! Reading other users' or system processes needs administrator / root rights;
//! processes that cannot be opened are counted as errors.

use crate::scanner::{stream_outcome, Counts, Matcher, Outcome};

/// Scans one process (`only`) or all of them. The scanner itself is skipped:
/// its own memory holds every signature.
pub fn scan_processes(matcher: &Matcher, only: Option<u32>) -> Vec<Outcome> {
    let pids = only.map_or_else(os::process_ids, |pid| vec![pid]);
    pids.into_iter().filter(|&pid| pid != std::process::id()).map(|pid| scan_process(pid, matcher)).collect()
}

/// Scans all readable regions of one process. The counts are carried from
/// region to region, so the result is one set of findings per process.
fn scan_process(pid: u32, matcher: &Matcher) -> Outcome {
    let Ok(process) = os::Process::open(pid) else { return Outcome::Error };
    let scanned = process.regions().into_iter().fold((Counts::new(), 0), |(counts, bytes), (start, len)| {
        let (counts, read) = matcher.count_stream(process.reader(start, len), start, counts);
        (counts, bytes + read)
    });
    stream_outcome(format!("pid {pid} ({})", process.name()), "Process memory", scanned)
}

/// One line of `/proc/<pid>/maps`, e.g.
/// `7f1c2a000000-7f1c2a021000 r-xp 00000000 08:01 1234  /usr/lib/libcrypto.so`
/// -> (start address, length) if the region is readable. The kernel's special
/// `[vvar]` / `[vsyscall]` regions are skipped: they cannot be read this way.
#[cfg(any(target_os = "linux", test))]
fn parse_maps_line(line: &str) -> Option<(usize, usize)> {
    let mut fields = line.split_whitespace();
    let (range, perms) = (fields.next()?, fields.next()?);
    let name = fields.nth(3).unwrap_or("");
    let (start, end) = range.split_once('-')?;
    let (start, end) = (usize::from_str_radix(start, 16).ok()?, usize::from_str_radix(end, 16).ok()?);
    (perms.starts_with('r') && !name.starts_with("[v")).then_some((start, end.checked_sub(start)?))
}

/// Linux: everything is a file under `/proc`. `/proc/<pid>/maps` lists the
/// regions as text and `/proc/<pid>/mem` is the process memory itself, readable
/// at the same addresses.
#[cfg(target_os = "linux")]
mod os {
    use std::fs::{self, File};
    use std::io::{self, Read, Seek, SeekFrom};

    /// The numeric directory names in `/proc` are the running process ids.
    pub fn process_ids() -> Vec<u32> {
        let names = fs::read_dir("/proc").into_iter().flatten().flatten().map(|e| e.file_name());
        let mut pids: Vec<u32> = names.filter_map(|n| n.to_str()?.parse().ok()).collect();
        pids.sort();
        pids
    }

    pub struct Process {
        pid: u32,
        maps: String,
        mem: File,
    }

    impl Process {
        pub fn open(pid: u32) -> io::Result<Self> {
            Ok(Process { pid, maps: fs::read_to_string(format!("/proc/{pid}/maps"))?, mem: File::open(format!("/proc/{pid}/mem"))? })
        }

        pub fn name(&self) -> String {
            fs::read_to_string(format!("/proc/{}/comm", self.pid)).map_or_else(|_| "?".into(), |s| s.trim().into())
        }

        pub fn regions(&self) -> Vec<(usize, usize)> {
            self.maps.lines().filter_map(super::parse_maps_line).collect()
        }

        /// Reader over `len` bytes starting at address `start`. If the seek
        /// fails the length is set to 0, so nothing is read from a wrong place.
        pub fn reader(&self, start: usize, len: usize) -> impl Read + '_ {
            let ok = (&self.mem).seek(SeekFrom::Start(start as u64)).is_ok();
            (&self.mem).take(if ok { len as u64 } else { 0 })
        }
    }
}

/// Windows: the Win32 API, declared by hand to stay free of external crates.
/// `unsafe` is needed only to call these C functions; each block passes
/// pointers to local variables or to a buffer of the stated size.
#[cfg(windows)]
mod os {
    use std::ffi::c_void;
    use std::io::{self, Read};
    use std::mem::{size_of, zeroed};

    type Handle = *mut c_void;

    /// MEMORY_BASIC_INFORMATION: description of one memory region.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct MemInfo {
        base: *mut c_void,
        allocation_base: *mut c_void,
        allocation_protect: u32,
        #[cfg(target_pointer_width = "64")]
        _alignment: u32,
        size: usize,
        state: u32,
        protect: u32,
        kind: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn K32EnumProcesses(pids: *mut u32, bytes: u32, bytes_returned: *mut u32) -> i32;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
        fn VirtualQueryEx(process: Handle, address: *const c_void, info: *mut MemInfo, len: usize) -> usize;
        fn ReadProcessMemory(process: Handle, address: *const c_void, buf: *mut u8, size: usize, read: *mut usize) -> i32;
        fn QueryFullProcessImageNameW(process: Handle, flags: u32, name: *mut u16, size: *mut u32) -> i32;
    }

    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
    const MEM_COMMIT: u32 = 0x1000; // the region is backed by real memory
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_GUARD: u32 = 0x100; // touching it raises an exception in the target

    pub fn process_ids() -> Vec<u32> {
        let mut pids = vec![0u32; 16384];
        let mut bytes = 0u32;
        let ok = unsafe { K32EnumProcesses(pids.as_mut_ptr(), (pids.len() * 4) as u32, &mut bytes) } != 0;
        pids.truncate(if ok { bytes as usize / 4 } else { 0 });
        pids.retain(|&pid| pid != 0); // pid 0 is the idle pseudo-process
        pids
    }

    pub struct Process(Handle);

    impl Drop for Process {
        fn drop(&mut self) {
            unsafe { CloseHandle(self.0) };
        }
    }

    impl Process {
        pub fn open(pid: u32) -> io::Result<Self> {
            let handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) };
            if handle.is_null() { Err(io::Error::last_os_error()) } else { Ok(Process(handle)) }
        }

        /// File name of the executable, e.g. "notepad.exe".
        pub fn name(&self) -> String {
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = unsafe { QueryFullProcessImageNameW(self.0, 0, buf.as_mut_ptr(), &mut len) } != 0;
            let path = String::from_utf16_lossy(&buf[..if ok { len as usize } else { 0 }]);
            path.rsplit('\\').next().filter(|n| !n.is_empty()).unwrap_or("?").to_string()
        }

        /// Walks the address space: each query describes the region at `address`
        /// and the next query starts right after it, until the query fails at the
        /// end of the address space. Only committed, accessible regions are kept.
        pub fn regions(&self) -> Vec<(usize, usize)> {
            let query = |address: usize| {
                let mut info: MemInfo = unsafe { zeroed() };
                let written = unsafe { VirtualQueryEx(self.0, address as *const c_void, &mut info, size_of::<MemInfo>()) };
                (written != 0).then_some(info)
            };
            let readable = |i: &MemInfo| i.state == MEM_COMMIT && i.protect != 0 && i.protect & (PAGE_NOACCESS | PAGE_GUARD) == 0;
            std::iter::successors(query(0), |i| (i.base as usize).checked_add(i.size).and_then(query))
                .filter(readable)
                .map(|i| (i.base as usize, i.size))
                .collect()
        }

        pub fn reader(&self, start: usize, len: usize) -> impl Read + '_ {
            Region { process: self, address: start, left: len }
        }
    }

    /// `Read` over one memory region of another process.
    struct Region<'a> {
        process: &'a Process,
        address: usize,
        left: usize,
    }

    impl Read for Region<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let (want, mut got) = (buf.len().min(self.left), 0);
            if want == 0 {
                return Ok(0);
            }
            let ok = unsafe { ReadProcessMemory(self.process.0, self.address as *const c_void, buf.as_mut_ptr(), want, &mut got) } != 0;
            if !ok || got == 0 {
                return Err(io::Error::last_os_error());
            }
            self.address += got;
            self.left -= got;
            Ok(got)
        }
    }
}

/// Other systems (e.g. macOS): memory scanning is not implemented, so no
/// process can be opened and each requested one is reported as an error.
#[cfg(not(any(target_os = "linux", windows)))]
mod os {
    use std::io::{self, Read};

    pub fn process_ids() -> Vec<u32> {
        Vec::new()
    }

    pub struct Process;

    impl Process {
        pub fn open(_pid: u32) -> io::Result<Self> {
            Err(io::ErrorKind::Unsupported.into())
        }
        pub fn name(&self) -> String {
            String::new()
        }
        pub fn regions(&self) -> Vec<(usize, usize)> {
            Vec::new()
        }
        pub fn reader(&self, _start: usize, _len: usize) -> impl Read + '_ {
            io::empty()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signatures::Confidence;

    #[test]
    fn parses_maps_lines() {
        let line = "7f1c2a000000-7f1c2a021000 r-xp 00000000 08:01 1234  /usr/lib/libcrypto.so.3";
        assert_eq!(parse_maps_line(line), Some((0x7f1c2a000000, 0x21000)));
        assert_eq!(parse_maps_line("00400000-00401000 rw-p 00000000 00:00 0"), Some((0x400000, 0x1000)));
        assert_eq!(parse_maps_line("00400000-00401000 ---p 00000000 00:00 0"), None); // not readable
        assert_eq!(parse_maps_line("7ffd1000-7ffd3000 r--p 00000000 00:00 0  [vvar]"), None);
        assert_eq!(parse_maps_line("garbage"), None);
    }

    /// End-to-end on the real OS: start a child process (`sort` exists on both
    /// Windows and Linux and keeps its input in memory until the input ends),
    /// send it a signature, then find that signature in the child's memory.
    #[cfg(any(target_os = "linux", windows))]
    #[test]
    fn finds_signature_in_child_process_memory() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child = Command::new("sort").stdin(Stdio::piped()).stdout(Stdio::null()).spawn().unwrap();
        child.stdin.as_mut().unwrap().write_all(b"-----BEGIN RSA PRIVATE KEY-----\n").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(500));
        let outcomes = scan_processes(&Matcher::new(Confidence::High), Some(child.id()));
        child.kill().unwrap();
        child.wait().unwrap();

        let [Outcome::Scanned(bytes, Some(report))] = &outcomes[..] else { panic!("child process was not scanned") };
        assert!(*bytes > 0 && report.kind == "Process memory");
        assert!(report.path.to_string_lossy().starts_with(&format!("pid {} (", child.id())));
        assert!(report.findings.iter().any(|f| f.sig.description == "PEM header: RSA PRIVATE KEY"));
    }

    #[test]
    fn skips_itself_and_reports_unopenable_process() {
        let m = Matcher::new(Confidence::High);
        assert!(scan_processes(&m, Some(std::process::id())).is_empty());
        assert!(matches!(scan_processes(&m, Some(u32::MAX - 7))[..], [Outcome::Error]));
    }
}

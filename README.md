# Crypto scanner (Lab 2)

Scans every file in a directory at binary level and reports which cryptographic algorithms
it appears to use, by searching for known byte signatures. Each finding has a confidence
level and a quantum-computing status. Written in Rust with no external dependencies;
works on Windows and Linux.

Bonus part: the same search also runs over **RAM** (the memory of running processes) and
**ROM / raw storage** (firmware images, whole disks or partitions).

Detected: AES (and AES-128/192/256 when the key size is named), RSA, ECC, Ed25519, DH/DSA,
DES/3DES, Blowfish, ChaCha20/Salsa20, SHA-1/256/512, MD5, stored key material (PEM, SSH, PGP)
and common crypto libraries (OpenSSL, mbedTLS, wolfSSL, libsodium, Windows CNG/CryptoAPI,
Apple CommonCrypto).

## Build and run

Requires a recent stable [Rust](https://rustup.rs) toolchain (developed and tested with 1.99).

    cargo build --release
    cargo run --release -- /path/to/scan --json report.json --csv report.csv
    cargo test

| Argument | Meaning |
|---|---|
| `<directory-or-file>` | files to scan; directories are scanned recursively |
| `--device <path>` | scan a raw device or ROM/firmware image as one stream, without a size limit |
| `--ram` | scan the memory of all running processes |
| `--pid <n>` | scan the memory of one process |
| `--json <file>` | also write a JSON report |
| `--csv <file>` | also write a CSV report (one row per finding) |
| `--min-confidence <level>` | `low`, `medium` (default) or `high` |
| `--max-size-mb <n>` | skip files larger than n MB (default 200) |
| `-h`, `--help` | show usage |

At least one target is required (a path, `--device`, `--ram` or `--pid`); they can be combined
in one run. Exit codes: `0` success, `1` a report file could not be written, `2` bad arguments
or path.

### RAM and ROM (bonus)

    # Linux (root is needed for devices and for other users' processes)
    sudo ./target/release/crypto_scanner --ram --min-confidence high
    sudo ./target/release/crypto_scanner --pid 1234
    sudo ./target/release/crypto_scanner --device /dev/sda
    sudo ./target/release/crypto_scanner --device /sys/firmware/acpi/tables/DSDT

    # Windows (run the terminal as Administrator)
    crypto_scanner.exe --ram --min-confidence high
    crypto_scanner.exe --pid 1234
    crypto_scanner.exe --device \\.\PhysicalDrive0
    crypto_scanner.exe --device firmware_dump.bin

Without administrator rights the scan still runs, but only over the processes of the current
user; the rest are counted under `errors`. A process is reported like a file, as
`pid 1234 (name)  [Process memory, N bytes]`, and the offsets are memory addresses.
A full RAM scan reads tens of gigabytes and takes minutes (about 200 MB/s).

## Example output

    === Crypto scanner report ===
    Objects scanned: 1 (0.2 MB) | skipped (too large): 0 | errors: 0
    Objects with crypto indicators: 1

    C:/Windows/System32/bcrypt.dll  [Windows PE (exe/dll), 195128 bytes]
        [HIGH  ] RSA               ASN.1 OID rsaEncryption @0x2a816 (x10)
        [MEDIUM] RSA               ASN.1 OID sha256WithRSAEncryption @0x2a703 (x20)
        [MEDIUM] RSA               DER public exponent 65537 @0x2a931 (x10)
        [MEDIUM] Crypto library    Windows CNG (BCryptEncrypt) @0x22281 (x1)

    === Summary by algorithm ===
    Algorithm          Files  Conf.   Quantum status
    Crypto library         1  MEDIUM  n/a (inspect manually)
    RSA                    1  HIGH    BROKEN by Shor - migrate to post-quantum (ML-KEM / ML-DSA)

`@0x2a816` is the offset of the first match in the file, `(x10)` the number of matches.

## How it works

**1. Signatures.** Crypto code cannot work without certain fixed data, and that data stays
visible inside the compiled file:

| Kind of signature | Example | Confidence |
|---|---|---|
| Lookup tables and constants | AES S-box, SHA-256 round constants, MD5 sine table | high |
| ASN.1 OIDs in keys and certificates | `rsaEncryption`, curve P-256 | high / medium |
| PEM headers, SSH key prefixes | `-----BEGIN RSA PRIVATE KEY-----`, `ssh-ed25519` | high / medium |
| API and library names | `EVP_aes_`, `BCryptEncrypt`, `OpenSSL` | medium |
| Text markers | `AES-256`, `RSA-PSS` | medium / low |
| CPU instructions | AES-NI `aesenc` | low |

Multi-byte constants are stored in both byte orders (big- and little-endian), because the
order in the file depends on the CPU and compiler. The database holds 80 signatures.

**2. Search.** Comparing 80 patterns at every byte of every file would be slow. Instead the
signatures are indexed once by their first two bytes (a table with 65536 buckets). The scanner
then slides over the file two bytes at a time and looks the pair up in the table. For almost
every position the bucket is empty and the position is skipped immediately; only when the first
two bytes agree is the whole pattern compared. All signatures are found in a single pass
(about 170 MB in under a second in a release build).

**3. Files.** The directory is walked recursively. Symbolic links are not followed, files over
the size limit are skipped, and unreadable files are counted as errors instead of stopping the
scan. The file type (ELF, PE, Mach-O, ZIP, script, text, binary) is guessed from the first
bytes and shown for context.

**4. Report.** Findings are grouped by file, then summarised per algorithm: the number of files
it occurs in, the highest confidence seen, and the quantum status:

| Status | Algorithms | Reason |
|---|---|---|
| Broken | RSA, ECC, Ed25519, DH/DSA | Shor's algorithm solves factoring and discrete logarithms |
| Weakened | AES-128 | Grover's algorithm halves the effective key length (to ~64 bits) |
| Quantum-safe | AES-192/256, SHA-256/512, ChaCha20 | still strong enough after halving |
| Already weak | DES/3DES, MD5, SHA-1, Blowfish | should be replaced regardless of quantum computers |

**5. Streams (ROM, raw devices, RAM).** A disk or the memory of a process is too large to load
at once, so it is read in 4 MB chunks. A signature may be cut in two by a chunk border, so the
last bytes of each chunk (the longest signature minus one byte) are placed in front of the next
chunk; matches lying entirely in that overlap were already counted and are skipped.

**6. Process memory (RAM).** A running program holds its crypto tables and keys in memory even
when the file on disk is packed or encrypted. For every process the scanner lists the readable
memory regions and scans each as a stream:

| | Linux | Windows |
|---|---|---|
| List processes | numeric directories in `/proc` | `K32EnumProcesses` |
| List memory regions | `/proc/<pid>/maps` | `VirtualQueryEx` |
| Read memory | `/proc/<pid>/mem` | `ReadProcessMemory` |

The Windows functions are declared by hand (`extern "system"`), so no external crate is needed.
The scanner skips its own process, whose memory contains every signature.

## Code layout

The code is written in a functional style: data flows through iterator pipelines
(`map` / `filter` / `fold`), values are not mutated, and input/output happens only in `main.rs`.

| File | Content |
|---|---|
| `src/signatures.rs` | signature database, confidence levels, quantum status |
| `src/scanner.rs` | directory walk, two-byte index matcher, chunked stream scan, file type detection |
| `src/memory.rs` | process memory scan; one small `os` module each for Linux and Windows |
| `src/report.rs` | console / JSON / CSV reports as pure functions returning text |
| `src/main.rs` | command-line parsing, output, exit codes |

Tests live at the bottom of each file (`cargo test` runs all 23). To add a signature, add one
`sg(algorithm, description, confidence, pattern)` line to `SIGNATURES` in `src/signatures.rs`;
a test checks that every signature can be found by the matcher.

## Limits

- Signature matching gives indicators, not proof. A text marker can come from documentation,
  and short patterns can occur by chance; use `--min-confidence high` for the most reliable hits.
- Obfuscated, packed or encrypted binaries may hide their tables, and archives (ZIP, JAR) are
  not unpacked, so compressed content is not seen.
- Table constants prove AES but not its key size; AES-128/192/256 is reported only when the
  file names it.
- Each file is read into memory whole, which is why large files are skipped by default
  (`--device <file>` scans a file of any size as a stream).
- Many processes load the same system libraries, so a RAM scan reports the same algorithms for
  most of them. Text held as UTF-16 in memory (usual on Windows) is not matched by the ASCII
  text markers.
- A read error on a device or memory region ends that stream early; what was read is still
  reported.
- Memory scanning is implemented for Linux and Windows only. On other systems (macOS) the file
  and device scans work, and `--ram` / `--pid` report errors.
- Tested on Windows. The Linux code is compiled and lint-checked but has not been run on a
  Linux machine; raw devices have been tested only through image files, not real disks.
- Scanning the project directory itself reports the scanner's own signatures inside `target/`.

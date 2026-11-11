# Crypto scanner (Lab 2)

Scans every file in a directory at binary level and reports cryptographic algorithms
(AES-128/192/256, RSA, ECC, DES/3DES, Blowfish, ChaCha20, SHA-1/256/512, MD5, crypto libraries)
by matching known signatures: lookup tables, round constants, ASN.1 OIDs, PEM headers, API names.
Each finding has a confidence level and a quantum-computing status.

## Build and run
    cargo build --release
    cargo run --release -- /path/to/scan --json report.json --csv report.csv
    cargo test

Options: `--min-confidence low|medium|high` (default medium), `--max-size-mb N` (default 200).

## Layout (suggested split for 5 people)
| File | Content |
|---|---|
| src/signatures.rs | signature database + quantum status (research part, 2 people: symmetric/hash vs public-key/libraries) |
| src/scanner.rs | file walking, multi-pattern matcher, file type detection |
| src/report.rs | console / JSON / CSV output |
| src/main.rs + tests | CLI parsing, test fixtures, README, demo |

## Limits
Signature matching gives indicators, not proof. Statically linked or obfuscated code may hide
tables, and text markers can appear in documentation. AES key size is only known when the
file mentions it; table constants prove AES but not 128/192/256.

//! Signature database: byte patterns that reveal cryptographic algorithms.

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::Low => "LOW",
            Confidence::Medium => "MEDIUM",
            Confidence::High => "HIGH",
        }
    }
    pub fn parse(s: &str) -> Option<Confidence> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Confidence::Low),
            "medium" => Some(Confidence::Medium),
            "high" => Some(Confidence::High),
            _ => None,
        }
    }
}

pub struct Signature {
    pub algorithm: &'static str,
    pub description: &'static str,
    pub confidence: Confidence,
    pub pattern: &'static [u8],
}

const fn sg(
    algorithm: &'static str,
    description: &'static str,
    confidence: Confidence,
    pattern: &'static [u8],
) -> Signature {
    Signature { algorithm, description, confidence, pattern }
}

use Confidence::{High, Low, Medium};

pub static SIGNATURES: &[Signature] = &[
    // ---------------- AES ----------------
    sg("AES", "S-box table", High, &[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76]),
    sg("AES", "Inverse S-box table", High, &[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb]),
    sg("AES", "Te0 table (big-endian)", High, &[0xc6, 0x63, 0x63, 0xa5, 0xf8, 0x7c, 0x7c, 0x84]),
    sg("AES", "Te0 table (little-endian)", High, &[0xa5, 0x63, 0x63, 0xc6, 0x84, 0x7c, 0x7c, 0xf8]),
    sg("AES", "Td0 table (big-endian)", High, &[0x51, 0xf4, 0xa7, 0x50, 0x7e, 0x41, 0x65, 0x53]),
    sg("AES", "Td0 table (little-endian)", High, &[0x50, 0xa7, 0xf4, 0x51, 0x53, 0x65, 0x41, 0x7e]),
    sg("AES", "Key schedule round constants (Rcon)", Medium, &[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]),
    sg("AES", "AES-NI aesenc instruction", Low, &[0x66, 0x0f, 0x38, 0xdc]),
    sg("AES", "AES-NI aesenclast instruction", Low, &[0x66, 0x0f, 0x38, 0xdd]),
    sg("AES", "AES API name (AES_set_encrypt_key)", Medium, b"AES_set_encrypt_key"),
    sg("AES", "AES API name (EVP_aes_)", Medium, b"EVP_aes_"),
    sg("AES", "AES API name (mbedtls_aes)", Medium, b"mbedtls_aes"),
    sg("AES-128", "Text marker AES-128", Medium, b"AES-128"),
    sg("AES-128", "Text marker aes-128", Medium, b"aes-128"),
    sg("AES-128", "Text marker aes128", Low, b"aes128"),
    sg("AES-128", "Text marker AES128", Low, b"AES128"),
    sg("AES-192", "Text marker AES-192", Medium, b"AES-192"),
    sg("AES-192", "Text marker aes-192", Medium, b"aes-192"),
    sg("AES-192", "Text marker aes192", Low, b"aes192"),
    sg("AES-192", "Text marker AES192", Low, b"AES192"),
    sg("AES-256", "Text marker AES-256", Medium, b"AES-256"),
    sg("AES-256", "Text marker aes-256", Medium, b"aes-256"),
    sg("AES-256", "Text marker aes256", Low, b"aes256"),
    sg("AES-256", "Text marker AES256", Low, b"AES256"),
    // ---------------- RSA ----------------
    sg("RSA", "PEM header: RSA PRIVATE KEY", High, b"-----BEGIN RSA PRIVATE KEY-----"),
    sg("RSA", "PEM header: RSA PUBLIC KEY", High, b"-----BEGIN RSA PUBLIC KEY-----"),
    sg("RSA", "ASN.1 OID rsaEncryption", High, &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]),
    sg("RSA", "ASN.1 OID sha256WithRSAEncryption", Medium, &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]),
    sg("RSA", "DER public exponent 65537", Medium, &[0x02, 0x03, 0x01, 0x00, 0x01]),
    sg("RSA", "SSH public key prefix ssh-rsa", Medium, b"ssh-rsa"),
    sg("RSA", "API name RSA_public_encrypt", Medium, b"RSA_public_encrypt"),
    sg("RSA", "API name RSA_private_decrypt", Medium, b"RSA_private_decrypt"),
    sg("RSA", "API name RSA_generate_key", Medium, b"RSA_generate_key"),
    sg("RSA", "API name EVP_PKEY_RSA", Medium, b"EVP_PKEY_RSA"),
    sg("RSA", "Text marker rsa-sha2-", Medium, b"rsa-sha2-"),
    sg("RSA", "Text marker RSA-PSS", Medium, b"RSA-PSS"),
    sg("RSA", "Text marker RSA-OAEP", Medium, b"RSA-OAEP"),
    // ---------------- Elliptic curves / other public-key ----------------
    sg("ECC", "PEM header: EC PRIVATE KEY", High, b"-----BEGIN EC PRIVATE KEY-----"),
    sg("ECC", "ASN.1 OID id-ecPublicKey", High, &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
    sg("ECC", "ASN.1 OID prime256v1 (P-256)", High, &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
    sg("ECC", "ASN.1 OID secp384r1 (P-384)", High, &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22]),
    sg("ECC", "SSH key prefix ecdsa-sha2-nistp", Medium, b"ecdsa-sha2-nistp"),
    sg("ECC", "Curve name secp256k1", Medium, b"secp256k1"),
    sg("ECC", "API name EC_KEY_new", Medium, b"EC_KEY_new"),
    sg("Ed25519", "ASN.1 OID Ed25519", Medium, &[0x06, 0x03, 0x2b, 0x65, 0x70]),
    sg("Ed25519", "SSH key prefix ssh-ed25519", Medium, b"ssh-ed25519"),
    sg("DH/DSA", "PEM header: DH PARAMETERS", High, b"-----BEGIN DH PARAMETERS-----"),
    sg("DH/DSA", "PEM header: DSA PRIVATE KEY", High, b"-----BEGIN DSA PRIVATE KEY-----"),
    // ---------------- Key / certificate containers (algorithm unknown) ----------------
    sg("Key material", "PEM header: PRIVATE KEY (PKCS#8)", Medium, b"-----BEGIN PRIVATE KEY-----"),
    sg("Key material", "PEM header: ENCRYPTED PRIVATE KEY", Medium, b"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    sg("Key material", "PEM header: OPENSSH PRIVATE KEY", Medium, b"-----BEGIN OPENSSH PRIVATE KEY-----"),
    sg("Key material", "PEM header: PUBLIC KEY", Medium, b"-----BEGIN PUBLIC KEY-----"),
    sg("Key material", "PEM header: CERTIFICATE", Medium, b"-----BEGIN CERTIFICATE-----"),
    sg("Key material", "PEM header: PGP", Medium, b"-----BEGIN PGP"),
    // ---------------- Other ciphers ----------------
    sg("ChaCha20/Salsa20", "Constant 'expand 32-byte k'", High, b"expand 32-byte k"),
    sg("ChaCha20/Salsa20", "Constant 'expand 16-byte k'", Medium, b"expand 16-byte k"),
    sg("DES/3DES", "Initial permutation table", Medium, &[0x3a, 0x32, 0x2a, 0x22, 0x1a, 0x12, 0x0a, 0x02, 0x3c, 0x34, 0x2c, 0x24, 0x1c, 0x14, 0x0c, 0x04]),
    sg("Blowfish", "P-array initial values (big-endian)", High, &[0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3, 0x13, 0x19, 0x8a, 0x2e]),
    sg("Blowfish", "P-array initial values (little-endian)", High, &[0x88, 0x6a, 0x3f, 0x24, 0xd3, 0x08, 0xa3, 0x85, 0x2e, 0x8a, 0x19, 0x13]),
    // ---------------- Hash functions ----------------
    sg("SHA-256", "Round constants K (big-endian)", High, &[0x42, 0x8a, 0x2f, 0x98, 0x71, 0x37, 0x44, 0x91, 0xb5, 0xc0, 0xfb, 0xcf, 0xe9, 0xb5, 0xdb, 0xa5]),
    sg("SHA-256", "Round constants K (little-endian)", High, &[0x98, 0x2f, 0x8a, 0x42, 0x91, 0x44, 0x37, 0x71, 0xcf, 0xfb, 0xc0, 0xb5, 0xa5, 0xdb, 0xb5, 0xe9]),
    sg("SHA-256", "Initial hash values (big-endian)", Medium, &[0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85]),
    sg("SHA-256", "Initial hash values (little-endian)", Medium, &[0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb]),
    sg("SHA-512", "Round constants K (big-endian)", High, &[0x42, 0x8a, 0x2f, 0x98, 0xd7, 0x28, 0xae, 0x22, 0x71, 0x37, 0x44, 0x91, 0x23, 0xef, 0x65, 0xcd]),
    sg("SHA-512", "Round constants K (little-endian)", High, &[0x22, 0xae, 0x28, 0xd7, 0x98, 0x2f, 0x8a, 0x42, 0xcd, 0x65, 0xef, 0x23, 0x91, 0x44, 0x37, 0x71]),
    sg("SHA-1", "Round constants (big-endian)", High, &[0x5a, 0x82, 0x79, 0x99, 0x6e, 0xd9, 0xeb, 0xa1, 0x8f, 0x1b, 0xbc, 0xdc, 0xca, 0x62, 0xc1, 0xd6]),
    sg("SHA-1", "Round constants (little-endian)", High, &[0x99, 0x79, 0x82, 0x5a, 0xa1, 0xeb, 0xd9, 0x6e, 0xdc, 0xbc, 0x1b, 0x8f, 0xd6, 0xc1, 0x62, 0xca]),
    sg("MD5", "Sine-table constants (little-endian)", High, &[0x78, 0xa4, 0x6a, 0xd7, 0x56, 0xb7, 0xc7, 0xe8, 0xdb, 0x70, 0x20, 0x24]),
    sg("MD5", "Sine-table constants (big-endian)", High, &[0xd7, 0x6a, 0xa4, 0x78, 0xe8, 0xc7, 0xb7, 0x56, 0x24, 0x20, 0x70, 0xdb]),
    sg("MD5/SHA-1", "Initial state (big-endian)", Medium, &[0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76]),
    sg("MD5/SHA-1", "Initial state (little-endian)", Medium, &[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]),
    // ---------------- Crypto libraries ----------------
    sg("Crypto library", "OpenSSL", Medium, b"OpenSSL"),
    sg("Crypto library", "libcrypto", Medium, b"libcrypto"),
    sg("Crypto library", "mbedTLS", Medium, b"mbedtls_"),
    sg("Crypto library", "wolfSSL", Medium, b"wolfSSL"),
    sg("Crypto library", "libsodium", Medium, b"sodium_init"),
    sg("Crypto library", "Windows CNG (BCryptEncrypt)", Medium, b"BCryptEncrypt"),
    sg("Crypto library", "Windows CryptoAPI", Medium, b"CryptAcquireContext"),
    sg("Crypto library", "Apple CommonCrypto", Medium, b"CCCrypt"),
];

/// Quantum-computing status of an algorithm (used in the report).
pub fn quantum_status(algorithm: &str) -> &'static str {
    match algorithm {
        "RSA" | "ECC" | "Ed25519" | "DH/DSA" => "BROKEN by Shor - migrate to post-quantum (ML-KEM / ML-DSA)",
        "AES-128" => "Weakened by Grover (~64-bit) - use AES-256",
        "AES" => "Check key size - AES-256 is quantum-safe",
        "AES-192" | "AES-256" | "SHA-256" | "SHA-512" | "ChaCha20/Salsa20" => "Considered quantum-safe",
        "DES/3DES" | "MD5" | "SHA-1" | "MD5/SHA-1" | "Blowfish" => "Already weak classically - replace",
        _ => "n/a (inspect manually)",
    }
}

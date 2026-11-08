use std::fs; // failu skaitymui ir rasymui
use walkdir::WalkDir; // pereina per aplanka ir visus jo poaplankius
use memchr::memmem; // iesko baitu sekos kitoje baitu sekoje
use std::env; // argumentu skaitymui (root aplanko location)

struct Signature {
    algorithm: String, // Sifravimo algoritmo pavadinimas
    name: String, // Pagal ka atpazintas algoritmas
    bytes: Vec<u8> // Baitu seka, kurios ieskome failo viduje
}

/// Grąžina visų žinomų kriptografinių signatūrų sąrašą.
///
/// Kiekviena signatūra – tai baitų seka, būdinga konkrečiam
/// algoritmui (pvz. AES S-box lentelė, RSA OID). Jei tokia seka
/// randama faile, failas tikėtinai naudoja tą algoritmą.
fn get_signatures() -> Vec<Signature> {

    let mut list: Vec<Signature> = Vec::new();

    // ---------- AES ----------
    list.push(Signature {
        algorithm: String::from("AES"),
        name: String::from("S-box"),
        bytes: vec![
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
            0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        ],
    });

    list.push(Signature {
        algorithm: String::from("AES"),
        name: String::from("atvirkštinė S-box"),
        bytes: vec![
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38,
            0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        ],
    });

    // ---------- SHA ----------
    list.push(Signature {
        algorithm: String::from("SHA-256"),
        name: String::from("pradinės reikšmės"),
        bytes: vec![0x67, 0xE6, 0x09, 0x6A, 0x85, 0xAE, 0x67, 0xBB],
    });

    list.push(Signature {
        algorithm: String::from("SHA-1"),
        name: String::from("pradinės reikšmės"),
        bytes: vec![
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC,
            0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xF0, 0xE1, 0xD2, 0xC3,
        ],
    });

    // ---------- DES ----------
    list.push(Signature {
        algorithm: String::from("DES"),
        name: String::from("S-box"),
        bytes: vec![
            0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08,
            0x03, 0x0A, 0x06, 0x0C, 0x05, 0x09, 0x00, 0x07,
        ],
    });

    // ---------- RSA ----------
    list.push(Signature {
        algorithm: String::from("RSA"),
        name: String::from("OID rsaEncryption"),
        bytes: vec![0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01],
    });

    list.push(Signature {
        algorithm: String::from("RSA"),
        name: String::from("PEM privatus raktas"),
        bytes: b"-----BEGIN RSA PRIVATE KEY-----".to_vec(),
    });

    // ---------- ECC ----------
    list.push(Signature {
        algorithm: String::from("ECC"),
        name: String::from("OID P-256 kreivė"),
        bytes: vec![0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    });

    return list;
}

fn main() {
    println!("Hello Giovanni!")
}
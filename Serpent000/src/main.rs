
use anyhow::{anyhow, Context, Result};
use block_padding::Pkcs7;
use cbc::{Decryptor, Encryptor};
use cbc::cipher::{generic_array::GenericArray, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use rand::RngCore;
use rand_core::OsRng;
use serpent_crate::Serpent;
use sha2::Sha256;
use std::env;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

// HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

// File format: [ MAGIC(4) | VERSION(1) | SALT(32) | IV(16) | CIPHERTEXT(..) | TAG(32) ]
const MAGIC: &[u8; 4] = b"SRP1";
const VERSION: u8 = 1;

const SALT_SIZE: usize = 32;
const IV_SIZE: usize = 16; // Serpent block size
const TAG_SIZE: usize = 32;

struct DerivedKeys {
    enc_key: [u8; 32],
    mac_key: [u8; 32],
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.enc_key.zeroize();
        self.mac_key.zeroize();
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 || !(args[1] == "E" || args[1] == "D") {
        eprintln!("Usage: {} [E|D] <filename>", args[0]);
        std::process::exit(1);
    }

    let encrypt = args[1] == "E";
    let path = Path::new(&args[2]);

    // Read 32-byte master key
    let mut key_bytes = fs::read("key.key").context("Failed to read key.key")?;
    if key_bytes.len() != 32 {
        anyhow::bail!("key.key must be exactly 32 bytes");
    }

    let data = fs::read(path).with_context(|| format!("Reading file: {:?}", path))?;

    let out = if encrypt {
        encrypt_file(&data, &key_bytes)?
    } else {
        decrypt_file(&data, &key_bytes)?
    };

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &out).context("Writing temp file")?;
    fs::rename(&tmp_path, path).context("Replacing original file")?;

    // wipe master key
    key_bytes.zeroize();

    println!(
        "{}ion successful: {:?}",
        if encrypt { "Encrypt" } else { "Decrypt" },
        path
    );
    Ok(())
}

fn hkdf_derive(master_key: &[u8], salt: &[u8]) -> Result<DerivedKeys> {
    // HKDF-SHA256 with explicit context labels for key separation
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    hk.expand(b"serpent-tool enc key v1", &mut enc_key)
        .map_err(|_| anyhow!("HKDF expand enc key failed"))?;
    hk.expand(b"serpent-tool mac key v1", &mut mac_key)
        .map_err(|_| anyhow!("HKDF expand mac key failed"))?;
    Ok(DerivedKeys { enc_key, mac_key })
}

fn encrypt_file(plaintext: &[u8], master_key: &[u8]) -> Result<Vec<u8>> {
    // Random salt + IV
    let mut salt = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let mut iv = [0u8; IV_SIZE];
    OsRng.fill_bytes(&mut iv);

    // Derive separate keys
    let keys = hkdf_derive(master_key, &salt)?;

    // Prepare key/iv as GenericArray references
    let ga_key = GenericArray::from_slice(&keys.enc_key);
    let ga_iv = GenericArray::from_slice(&iv);

    // Encrypt (CBC + PKCS7) in-place
    let enc = Encryptor::<Serpent>::new(ga_key, ga_iv);
    let mut buf = Vec::with_capacity(plaintext.len() + IV_SIZE);
    buf.extend_from_slice(plaintext);
    let ct_len = {
        let ct_slice = enc
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext.len())
            .map_err(|_| anyhow!("Encryption/PKCS7 padding failed"))?;
        ct_slice.len()
    };
    buf.truncate(ct_len); // ciphertext now in `buf`

    // Compute HMAC over header + salt + iv + ciphertext (EtM)
    let mut mac =
        <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&keys.mac_key).context("HMAC init")?;
    mac.update(MAGIC);
    mac.update(&[VERSION]);
    mac.update(&salt);
    mac.update(&iv);
    mac.update(&buf);
    let tag = mac.finalize().into_bytes();

    // Assemble output
    let mut out = Vec::with_capacity(4 + 1 + SALT_SIZE + IV_SIZE + buf.len() + TAG_SIZE);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&iv);
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);

    Ok(out)
}

fn decrypt_file(data: &[u8], master_key: &[u8]) -> Result<Vec<u8>> {
    // Minimum structure: magic + version + salt + iv + tag
    let min_len = 4 + 1 + SALT_SIZE + IV_SIZE + TAG_SIZE;
    if data.len() < min_len {
        anyhow::bail!("Data too short");
    }

    // Parse header
    let (magic, rest) = data.split_at(4);
    if magic != MAGIC {
        anyhow::bail!("Bad magic");
    }
    let (&version, rest) = rest.split_first().ok_or_else(|| anyhow!("Missing version"))?;
    if version != VERSION {
        anyhow::bail!("Unsupported version");
    }

    let (salt, rest) = rest.split_at(SALT_SIZE);
    let (iv, rest) = rest.split_at(IV_SIZE);
    if rest.len() < TAG_SIZE {
        anyhow::bail!("Data too short for tag");
    }
    let (ct, tag) = rest.split_at(rest.len() - TAG_SIZE);

    // Derive keys
    let keys = hkdf_derive(master_key, salt)?;
    let ga_key = GenericArray::from_slice(&keys.enc_key);
    let ga_iv = GenericArray::from_slice(iv);

    // Verify HMAC first (EtM)
    let mut mac =
        <HmacSha256 as hmac::digest::KeyInit>::new_from_slice(&keys.mac_key).context("HMAC init")?;
    mac.update(MAGIC);
    mac.update(&[VERSION]);
    mac.update(salt);
    mac.update(iv);
    mac.update(ct);
    mac.verify_slice(tag).context("HMAC verification failed")?;

    // Decrypt in-place
    let dec = Decryptor::<Serpent>::new(ga_key, ga_iv);
    let mut buf = Vec::from(ct);
    let pt_len = {
        let pt_slice = dec
            .decrypt_padded_mut::<Pkcs7>(&mut buf)
            .map_err(|_| anyhow!("Decrypt/PKCS7 failed"))?;
        pt_slice.len()
    };
    buf.truncate(pt_len);

    Ok(buf)
}

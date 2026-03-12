use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha384, Sha512};
use std::path::Path;

// ── ASN.1 minimal parser ────────────────────────────────────────────

#[derive(Debug)]
struct Asn1<'a> {
    tag: u8,
    data: &'a [u8],
}

/// Read one ASN.1 TLV, returning the item and remaining bytes.
fn read_asn1(input: &[u8]) -> Result<(Asn1<'_>, &[u8])> {
    if input.len() < 2 {
        bail!("ASN.1: insufficient data");
    }
    let tag = input[0];
    let (len, hdr) = if input[1] & 0x80 == 0 {
        (input[1] as usize, 2)
    } else {
        let n = (input[1] & 0x7f) as usize;
        if input.len() < 2 + n {
            bail!("ASN.1: truncated length");
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | input[2 + i] as usize;
        }
        (len, 2 + n)
    };
    if input.len() < hdr + len {
        bail!(
            "ASN.1: data truncated (need {}, have {})",
            hdr + len,
            input.len()
        );
    }
    Ok((
        Asn1 {
            tag,
            data: &input[hdr..hdr + len],
        },
        &input[hdr + len..],
    ))
}

fn expect_tag<'a>(input: &'a [u8], expected: u8) -> Result<(Asn1<'a>, &'a [u8])> {
    let (item, rest) = read_asn1(input)?;
    if item.tag != expected {
        bail!(
            "ASN.1: expected tag 0x{expected:02x}, got 0x{:02x}",
            item.tag
        );
    }
    Ok((item, rest))
}

fn read_sequence(input: &[u8]) -> Result<(Asn1<'_>, &[u8])> {
    expect_tag(input, 0x30)
}

fn read_octet_string(input: &[u8]) -> Result<(Asn1<'_>, &[u8])> {
    expect_tag(input, 0x04)
}

fn read_oid(input: &[u8]) -> Result<(Asn1<'_>, &[u8])> {
    expect_tag(input, 0x06)
}

fn read_integer_value(input: &[u8]) -> Result<(u32, &[u8])> {
    let (item, rest) = expect_tag(input, 0x02)?;
    let mut val = 0u32;
    for &b in item.data {
        val = (val << 8) | b as u32;
    }
    Ok((val, rest))
}

// ── OID constants (DER-encoded values) ──────────────────────────────

const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
const OID_PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];
const OID_DES_EDE3_CBC: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x03, 0x07];
const OID_PBE_SHA1_3DES: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x05, 0x01, 0x03,
];

// ── Crypto primitives ───────────────────────────────────────────────

fn decrypt_3des_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use cbc::Decryptor;
    use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use des::TdesEde3;

    type Dec = Decryptor<TdesEde3>;

    let mut buf = data.to_vec();
    let pt = Dec::new_from_slices(key, iv)
        .map_err(|e| anyhow!("3DES init: {e}"))?
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| anyhow!("3DES decrypt/unpad failed"))?;
    Ok(pt.to_vec())
}

fn decrypt_aes256_cbc(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    use aes::Aes256;
    use cbc::Decryptor;
    use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};

    type Dec = Decryptor<Aes256>;

    let mut buf = data.to_vec();
    let pt = Dec::new_from_slices(key, iv)
        .map_err(|e| anyhow!("AES-256 init: {e}"))?
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| anyhow!("AES-256 decrypt/unpad failed"))?;
    Ok(pt.to_vec())
}

type HmacSha1 = Hmac<Sha1>;

fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// ── Mozilla-specific key derivation ─────────────────────────────────

/// Mozilla's custom key derivation for older PBE (SHA-1 + 3DES) entries.
fn moz_3des_decrypt(
    global_salt: &[u8],
    password: &[u8],
    entry_salt: &[u8],
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    let hp = {
        let mut h = Sha1::new();
        h.update(global_salt);
        h.update(password);
        h.finalize().to_vec()
    };

    let mut pes = entry_salt.to_vec();
    pes.resize(20, 0);

    let chp = {
        let mut h = Sha1::new();
        h.update(&hp);
        h.update(entry_salt);
        h.finalize().to_vec()
    };

    let mut pes_salt = pes.clone();
    pes_salt.extend_from_slice(entry_salt);
    let k1 = hmac_sha1(&chp, &pes_salt);

    let tk = hmac_sha1(&chp, &pes);
    let mut tk_salt = tk;
    tk_salt.extend_from_slice(entry_salt);
    let k2 = hmac_sha1(&chp, &tk_salt);

    let mut k = k1;
    k.extend_from_slice(&k2);

    let key = &k[..24];
    let iv = &k[k.len() - 8..];

    decrypt_3des_cbc(key, iv, encrypted)
}

/// Hash globalSalt + password using the algorithm NSS selects based on salt length.
/// See `sftkdb_passwordToKey()` in NSS `sftkpwd.c`.
fn password_to_key(global_salt: &[u8], password: &[u8]) -> Vec<u8> {
    match global_salt.len() {
        32 => {
            let mut h = Sha256::new();
            h.update(global_salt);
            h.update(password);
            h.finalize().to_vec()
        }
        48 => {
            let mut h = Sha384::new();
            h.update(global_salt);
            h.update(password);
            h.finalize().to_vec()
        }
        64 => {
            let mut h = Sha512::new();
            h.update(global_salt);
            h.update(password);
            h.finalize().to_vec()
        }
        _ => {
            let mut h = Sha1::new();
            h.update(global_salt);
            h.update(password);
            h.finalize().to_vec()
        }
    }
}

/// PBES2 decryption (PBKDF2-HMAC-SHA256 + AES-256-CBC).
/// Firefox first hashes the password with the globalSalt before feeding to PBKDF2.
fn pbes2_decrypt(
    global_salt: &[u8],
    password: &[u8],
    entry_salt: &[u8],
    iterations: u32,
    key_len: usize,
    iv: &[u8],
    encrypted: &[u8],
) -> Result<Vec<u8>> {
    let k = password_to_key(global_salt, password);

    let mut key = vec![0u8; key_len];
    pbkdf2::pbkdf2_hmac::<Sha256>(&k, entry_salt, iterations, &mut key);

    decrypt_aes256_cbc(&key, iv, encrypted)
}

// ── ASN.1 structure parsers ─────────────────────────────────────────

/// Decrypt an ASN.1-wrapped encrypted blob from key4.db (item2 or a11).
fn decrypt_encoded_item(
    global_salt: &[u8],
    password: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    let (outer, _) = read_sequence(data)?;
    let (algo_id, enc_rest) = read_sequence(outer.data)?;
    let (encrypted, _) = read_octet_string(enc_rest)?;

    let (oid, params_rest) = read_oid(algo_id.data)?;

    if oid.data == OID_PBES2 {
        // PBES2: parse PBKDF2 + AES-256-CBC params
        let (pbes2_params, _) = read_sequence(params_rest)?;

        // Key derivation function
        let (kdf, enc_scheme_rest) = read_sequence(pbes2_params.data)?;
        let (kdf_oid, kdf_params_rest) = read_oid(kdf.data)?;
        if kdf_oid.data != OID_PBKDF2 {
            bail!("expected PBKDF2 OID in KDF");
        }
        let (pbkdf2_params, _) = read_sequence(kdf_params_rest)?;
        let (salt, r) = read_octet_string(pbkdf2_params.data)?;
        let (iterations, r) = read_integer_value(r)?;

        // keyLength is optional in PBKDF2-params; peek at next tag
        let key_len = if !r.is_empty() && r[0] == 0x02 {
            let (kl, _) = read_integer_value(r)?;
            kl as usize
        } else {
            32 // default for AES-256
        };

        // Encryption scheme
        let (enc_scheme, _) = read_sequence(enc_scheme_rest)?;
        let (enc_oid, iv_rest) = read_oid(enc_scheme.data)?;
        if enc_oid.data != OID_AES256_CBC {
            bail!("expected AES-256-CBC OID");
        }
        // Read the IV OCTET STRING. If the value is already 16 bytes, use it
        // directly. If it's 14 bytes (older Firefox quirk), use the raw TLV
        // bytes (tag + length + 14 = 16 bytes) as the IV.
        let (iv_item, _) = read_octet_string(iv_rest)?;
        let iv = if iv_item.data.len() == 16 {
            iv_item.data
        } else {
            iv_rest
        };

        pbes2_decrypt(
            global_salt,
            password,
            salt.data,
            iterations,
            key_len,
            iv,
            encrypted.data,
        )
    } else if oid.data == OID_PBE_SHA1_3DES {
        // Older PBE: SHA-1 + 3DES
        let (pbe_params, _) = read_sequence(params_rest)?;
        let (entry_salt, _) = read_octet_string(pbe_params.data)?;

        moz_3des_decrypt(global_salt, password, entry_salt.data, encrypted.data)
    } else {
        bail!("unsupported encryption OID: {:02x?}", oid.data);
    }
}

// ── High-level API ──────────────────────────────────────────────────

/// Holds decrypted keys from nssPrivate (potentially both 3DES and AES keys).
pub struct MasterKeys {
    keys: Vec<(Vec<u8>, Vec<u8>)>, // (key_bytes, key_id)
}

impl MasterKeys {
    /// Find the right key for a given algorithm: 24 bytes for 3DES, 32 bytes for AES-256.
    fn key_for_len(&self, len: usize) -> Result<&[u8]> {
        self.keys
            .iter()
            .find(|(k, _)| k.len() == len)
            .map(|(k, _)| k.as_slice())
            .with_context(|| format!("no {len}-byte key available"))
    }
}

/// Read key4.db and extract the master decryption keys.
pub fn get_master_keys(profile_dir: &Path, password: &[u8]) -> Result<MasterKeys> {
    let db_path = profile_dir.join("key4.db");
    if !db_path.exists() {
        bail!("key4.db not found in {}", profile_dir.display());
    }

    let conn = rusqlite::Connection::open_with_flags(
        &db_path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .context("failed to open key4.db")?;

    // Read global salt and encrypted password-check from metadata table
    let (global_salt, item2): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT item1, item2 FROM metadata WHERE id = 'password'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .context("failed to read metadata from key4.db")?;

    // Verify master password by decrypting the check value
    let check = decrypt_encoded_item(&global_salt, password, &item2)
        .context("failed to decrypt password check (wrong master password?)")?;

    // After PKCS7 unpadding, the check value should start with "password-check"
    if !check.starts_with(b"password-check") {
        bail!(
            "incorrect master password (check value: {:?})",
            String::from_utf8_lossy(&check)
        );
    }

    // Read all encrypted keys from nssPrivate
    let mut stmt = conn
        .prepare("SELECT a11, a102 FROM nssPrivate")
        .context("failed to prepare nssPrivate query")?;

    let rows: Vec<(Vec<u8>, Vec<u8>)> = stmt
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .filter_map(|r| r.ok())
        .collect();

    let mut keys = Vec::new();
    for (a11, a102) in &rows {
        if let Ok(key) = decrypt_encoded_item(&global_salt, password, a11) {
            keys.push((key, a102.clone()));
        }
    }

    if keys.is_empty() {
        bail!("no keys could be decrypted from nssPrivate");
    }

    Ok(MasterKeys { keys })
}

/// Decrypt a single login field (base64-encoded encrypted username or password).
pub fn decrypt_login_field(keys: &MasterKeys, encrypted_b64: &str) -> Result<String> {
    use base64::Engine;
    let der = base64::engine::general_purpose::STANDARD
        .decode(encrypted_b64)
        .context("base64 decode failed")?;

    let (outer, _) = read_sequence(&der)?;

    // SEQUENCE { OCTET STRING (keyId), SEQUENCE { OID, OCTET STRING (IV) }, OCTET STRING (data) }
    let (_key_id, rest) = read_octet_string(outer.data)?;
    let (algo, rest) = read_sequence(rest)?;
    let (oid, iv_rest) = read_oid(algo.data)?;
    let (encrypted, _) = read_octet_string(rest)?;

    let plaintext = if oid.data == OID_DES_EDE3_CBC {
        let (iv, _) = read_octet_string(iv_rest)?;
        let key = keys.key_for_len(24)?;
        decrypt_3des_cbc(key, iv.data, encrypted.data)?
    } else if oid.data == OID_AES256_CBC {
        let (iv, _) = read_octet_string(iv_rest)?;
        let key = keys.key_for_len(32)?;
        decrypt_aes256_cbc(key, iv.data, encrypted.data)?
    } else {
        bail!("login field uses unsupported algorithm: {:02x?}", oid.data);
    };

    String::from_utf8(plaintext).context("decrypted field is not valid UTF-8")
}

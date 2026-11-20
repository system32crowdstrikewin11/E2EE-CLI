use aes_gcm::{
    aead::{
        consts::{U12, U14, U16},
        Aead, KeyInit, Payload,
    },
    aes::{Aes128, Aes192, Aes256},
    AesGcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use std::io::{self, Read, Write};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop};

type Aes128Gcm96 = AesGcm<Aes128, U12, U12>;
type Aes192Gcm112 = AesGcm<Aes192, U12, U14>;
type Aes256Gcm128 = AesGcm<Aes256, U12, U16>;

pub const DISCORD_CONTENT_LIMIT: usize = 2000;
pub const PREFIX: &str = "\u{00A7}"; // '§'

const VERSION_MESSAGE: u8 = 2;
const VERSION_FILE: u8 = 3;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const MASTER_LEN: usize = 32;
const FILE_CHUNK: usize = 64 * 1024;
const FILE_PREFIX_LEN: usize = 7;

const ARGON_PASSES: u32 = 3;
const ARGON_MEMORY_KIB: u32 = 64 * 1024;
const USER_KEY_SALT: &[u8] = b"dcenc2|user-key|v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    Aes128,
    Aes192,
    Aes256,
}

impl Preset {
    pub const fn index(self) -> u8 {
        match self {
            Preset::Aes128 => 0,
            Preset::Aes192 => 1,
            Preset::Aes256 => 2,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Preset::Aes128 => "AES-128-GCM",
            Preset::Aes192 => "AES-192-GCM",
            Preset::Aes256 => "AES-256-GCM",
        }
    }

    pub const fn key_bytes(self) -> usize {
        match self {
            Preset::Aes128 => 16,
            Preset::Aes192 => 24,
            Preset::Aes256 => 32,
        }
    }

    pub const fn tag_bytes(self) -> usize {
        match self {
            Preset::Aes128 => 12,
            Preset::Aes192 => 14,
            Preset::Aes256 => 16,
        }
    }

    pub const fn pad_block(self) -> usize {
        match self {
            Preset::Aes128 => 16,
            Preset::Aes192 => 32,
            Preset::Aes256 => 64,
        }
    }

    pub const fn from_index(i: u8) -> Option<Self> {
        match i {
            0 => Some(Preset::Aes128),
            1 => Some(Preset::Aes192),
            2 => Some(Preset::Aes256),
            _ => None,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "0" | "128" | "aes128" | "aes-128" | "aes-128-gcm" => Some(Preset::Aes128),
            "1" | "192" | "aes192" | "aes-192" | "aes-192-gcm" => Some(Preset::Aes192),
            "2" | "256" | "aes256" | "aes-256" | "aes-256-gcm" => Some(Preset::Aes256),
            _ => None,
        }
    }
}

/// 256-bit master key held strictly in RAM and automatically zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; MASTER_LEN]);

impl MasterKey {
    pub fn as_bytes(&self) -> &[u8; MASTER_LEN] {
        &self.0
    }
}

/// Built-in forced channel password lookup matching ForcedKeys.java.
pub fn forced_channel_password(channel_id: &str) -> Option<&'static str> {
    match channel_id {
        "1562876012675465326" => Some("mojoen"),
        _ => None,
    }
}

pub fn looks_encrypted(s: &str) -> bool {
    s.starts_with(PREFIX)
}

pub fn derive_user_key(password: &str) -> Result<MasterKey, String> {
    derive_with_salt(password, USER_KEY_SALT)
}

pub fn derive_context_key(password: &str, context: &str) -> Result<MasterKey, String> {
    let salt = format!("dcenc2|ctx|{}", context);
    derive_with_salt(password, salt.as_bytes())
}

fn derive_with_salt(password: &str, salt: &[u8]) -> Result<MasterKey, String> {
    if password.is_empty() {
        return Err("Password cannot be empty".into());
    }
    let mut normalized: String = password.nfkc().collect();
    let params = Params::new(ARGON_MEMORY_KIB, ARGON_PASSES, 1, Some(MASTER_LEN))
        .map_err(|e| format!("Argon2id parameter error: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut master = [0u8; MASTER_LEN];
    let res = argon2.hash_password_into(normalized.as_bytes(), salt, &mut master);
    normalized.zeroize();

    res.map_err(|e| format!("Argon2id derivation failed: {e}"))?;
    Ok(MasterKey(master))
}

fn max_raw_bytes_for_chars(chars: usize) -> usize {
    let mut n = chars * 3 / 4 + 1;
    while (4 * n + 2) / 3 > chars {
        n -= 1;
    }
    n
}

pub fn max_plaintext_bytes(preset: Preset) -> usize {
    // PREFIX is 1 UTF-16 char in Java (PREFIX.length() == 1).
    let raw = max_raw_bytes_for_chars(DISCORD_CONTENT_LIMIT - 1);
    let payload_cap = raw - 1 - SALT_LEN - preset.tag_bytes();
    (payload_cap / preset.pad_block()) * preset.pad_block() - 1
}

pub fn encrypt_message(
    plaintext: &str,
    master: &MasterKey,
    preset: Preset,
    channel_id: &str,
    sender_id: &str,
) -> Result<String, String> {
    let data = plaintext.as_bytes();
    let max_bytes = max_plaintext_bytes(preset);
    if data.len() > max_bytes {
        return Err(format!(
            "Plaintext is {} bytes, exceeding {} limit of {} bytes",
            data.len(),
            preset.label(),
            max_bytes
        ));
    }

    let pad_block = preset.pad_block();
    let padded_len = (data.len() + 1).div_ceil(pad_block) * pad_block;
    let mut payload = vec![0u8; padded_len];
    payload[..data.len()].copy_from_slice(data);
    payload[data.len()] = 0x80;

    let header = (VERSION_MESSAGE << 4) | preset.index();
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let info = build_info("msg", preset, channel_id, sender_id)?;
    let mut okm = hkdf_derive(master, &salt, &info, preset.key_bytes() + NONCE_LEN)?;
    let aad = build_aad(header, &salt, &info);

    let ct_res = gcm_encrypt(
        preset,
        &okm[..preset.key_bytes()],
        &okm[preset.key_bytes()..],
        &aad,
        &payload,
    );
    payload.zeroize();
    okm.zeroize();
    let ct = ct_res?;

    let mut wire = Vec::with_capacity(1 + SALT_LEN + ct.len());
    wire.push(header);
    wire.extend_from_slice(&salt);
    wire.extend_from_slice(&ct);

    Ok(format!("{}{}", PREFIX, STANDARD_NO_PAD.encode(&wire)))
}

pub fn decrypt_message(
    wire_str: &str,
    master: &MasterKey,
    channel_id: &str,
    sender_id: &str,
) -> Result<(String, Preset), String> {
    let trimmed = wire_str.trim();
    let b64_part = trimmed
        .strip_prefix(PREFIX)
        .ok_or_else(|| "Ciphertext does not start with '§' prefix".to_string())?;

    // Match Android Base64.NO_WRAP leniency on trailing '=' padding or stray whitespace.
    let cleaned: String = b64_part
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let raw = STANDARD_NO_PAD
        .decode(cleaned.trim_end_matches('='))
        .map_err(|e| format!("Invalid Base64: {e}"))?;

    if raw.len() < 1 + SALT_LEN + 1 {
        return Err("Ciphertext too short".into());
    }
    let header = raw[0];
    if (header >> 4) != VERSION_MESSAGE {
        return Err(format!("Unsupported message version: {}", header >> 4));
    }
    let preset = Preset::from_index(header & 0x0F)
        .ok_or_else(|| format!("Unknown preset index: {}", header & 0x0F))?;

    let ct_len = raw.len() - 1 - SALT_LEN;
    if ct_len < preset.tag_bytes() + preset.pad_block()
        || !(ct_len - preset.tag_bytes()).is_multiple_of(preset.pad_block())
    {
        return Err("Invalid ciphertext length for preset".into());
    }

    let salt = &raw[1..1 + SALT_LEN];
    let info = build_info("msg", preset, channel_id, sender_id)?;
    let mut okm = hkdf_derive(master, salt, &info, preset.key_bytes() + NONCE_LEN)?;
    let aad = build_aad(header, salt, &info);

    let pt_res = gcm_decrypt(
        preset,
        &okm[..preset.key_bytes()],
        &okm[preset.key_bytes()..],
        &aad,
        &raw[1 + SALT_LEN..],
    );
    okm.zeroize();
    let mut payload = pt_res?;

    let mut end = payload.len();
    while end > 0 && payload[end - 1] == 0 {
        end -= 1;
    }
    if end == 0 || payload[end - 1] != 0x80 {
        payload.zeroize();
        return Err("Invalid padding".into());
    }

    let out = String::from_utf8(payload[..end - 1].to_vec())
        .map_err(|e| format!("Decrypted bytes are not valid UTF-8: {e}"));
    payload.zeroize();
    out.map(|s| (s, preset))
}

/// Streams plaintext in 64 KiB authenticated chunks (Aegires file format v3).
pub fn encrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    master: &MasterKey,
    preset: Preset,
    channel_id: &str,
    sender_id: &str,
) -> Result<u64, String> {
    let header = (VERSION_FILE << 4) | preset.index();
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let info = build_info("file", preset, channel_id, sender_id)?;
    let mut okm = hkdf_derive(master, &salt, &info, preset.key_bytes() + FILE_PREFIX_LEN)?;
    let aad = build_aad(header, &salt, &info);

    let mut key = okm[..preset.key_bytes()].to_vec();
    let mut nonce_prefix = [0u8; FILE_PREFIX_LEN];
    nonce_prefix.copy_from_slice(&okm[preset.key_bytes()..]);
    okm.zeroize();

    let result = (|| -> Result<u64, String> {
        writer
            .write_all(&[header])
            .map_err(|e| format!("Write error: {e}"))?;
        writer
            .write_all(&salt)
            .map_err(|e| format!("Write error: {e}"))?;

        let mut cur = vec![0u8; FILE_CHUNK];
        let mut next = vec![0u8; FILE_CHUNK];
        let mut cur_len = read_fully(reader, &mut cur).map_err(|e| format!("Read error: {e}"))?;
        let mut total_in: u64 = 0;
        let mut counter: u32 = 0;

        loop {
            let next_len = if cur_len == FILE_CHUNK {
                read_fully(reader, &mut next).map_err(|e| format!("Read error: {e}"))?
            } else {
                0
            };
            let last = next_len == 0;
            let nonce = chunk_nonce(&nonce_prefix, counter, last);
            let ct = gcm_encrypt(preset, &key, &nonce, &aad, &cur[..cur_len])?;
            writer
                .write_all(&ct)
                .map_err(|e| format!("Write error: {e}"))?;
            total_in += cur_len as u64;

            if last {
                break;
            }
            std::mem::swap(&mut cur, &mut next);
            cur_len = next_len;
            if counter >= u32::MAX - 1 {
                return Err("File too large: chunk counter overflow".into());
            }
            counter += 1;
        }
        writer.flush().map_err(|e| format!("Flush error: {e}"))?;
        cur.zeroize();
        next.zeroize();
        Ok(total_in)
    })();

    key.zeroize();
    nonce_prefix.zeroize();
    result
}

/// Streams and authenticates 64 KiB ciphertext chunks (Aegires file format v3).
pub fn decrypt_stream<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    master: &MasterKey,
    channel_id: &str,
    sender_id: &str,
) -> Result<(u64, Preset), String> {
    let mut hdr = [0u8; 1];
    if read_fully(reader, &mut hdr).map_err(|e| format!("Read error: {e}"))? != 1 {
        return Err("Empty or unreadable file".into());
    }
    let header = hdr[0];
    if (header >> 4) != VERSION_FILE {
        return Err(format!("Unsupported file version: {}", header >> 4));
    }
    let preset = Preset::from_index(header & 0x0F)
        .ok_or_else(|| format!("Unknown preset index: {}", header & 0x0F))?;

    let mut salt = [0u8; SALT_LEN];
    if read_fully(reader, &mut salt).map_err(|e| format!("Read error: {e}"))? != SALT_LEN {
        return Err("Truncated file header".into());
    }

    let info = build_info("file", preset, channel_id, sender_id)?;
    let mut okm = hkdf_derive(master, &salt, &info, preset.key_bytes() + FILE_PREFIX_LEN)?;
    let aad = build_aad(header, &salt, &info);

    let mut key = okm[..preset.key_bytes()].to_vec();
    let mut nonce_prefix = [0u8; FILE_PREFIX_LEN];
    nonce_prefix.copy_from_slice(&okm[preset.key_bytes()..]);
    okm.zeroize();

    let result = (|| -> Result<u64, String> {
        let chunk_ct = FILE_CHUNK + preset.tag_bytes();
        let mut cur = vec![0u8; chunk_ct];
        let mut next = vec![0u8; chunk_ct];
        let mut cur_len = read_fully(reader, &mut cur).map_err(|e| format!("Read error: {e}"))?;
        if cur_len < preset.tag_bytes() {
            return Err("Truncated ciphertext".into());
        }

        let mut total_out: u64 = 0;
        let mut counter: u32 = 0;

        loop {
            let next_len = if cur_len == chunk_ct {
                read_fully(reader, &mut next).map_err(|e| format!("Read error: {e}"))?
            } else {
                0
            };
            let last = next_len == 0;
            let nonce = chunk_nonce(&nonce_prefix, counter, last);
            let mut pt = gcm_decrypt(preset, &key, &nonce, &aad, &cur[..cur_len])?;
            writer
                .write_all(&pt)
                .map_err(|e| format!("Write error: {e}"))?;
            total_out += pt.len() as u64;
            pt.zeroize();

            if last {
                break;
            }
            std::mem::swap(&mut cur, &mut next);
            cur_len = next_len;
            if counter >= u32::MAX - 1 {
                return Err("File too large: chunk counter overflow".into());
            }
            counter += 1;
        }
        writer.flush().map_err(|e| format!("Flush error: {e}"))?;
        Ok(total_out)
    })();

    key.zeroize();
    nonce_prefix.zeroize();
    result.map(|bytes| (bytes, preset))
}

fn chunk_nonce(prefix: &[u8; FILE_PREFIX_LEN], counter: u32, last: bool) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[..FILE_PREFIX_LEN].copy_from_slice(prefix);
    n[7..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = if last { 1 } else { 0 };
    n
}

fn read_fully<R: Read>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

fn build_info(
    kind: &str,
    preset: Preset,
    channel_id: &str,
    sender_id: &str,
) -> Result<Vec<u8>, String> {
    let ch = channel_id.as_bytes();
    let se = sender_id.as_bytes();
    if ch.len() > u16::MAX as usize || se.len() > u16::MAX as usize {
        return Err("channel_id or sender_id exceeds 65535 bytes".into());
    }
    let label = format!("dcenc2/{}", kind);
    let mut out = Vec::with_capacity(label.len() + 1 + 2 + ch.len() + 2 + se.len());
    out.extend_from_slice(label.as_bytes());
    out.push(preset.index());
    out.extend_from_slice(&(ch.len() as u16).to_be_bytes());
    out.extend_from_slice(ch);
    out.extend_from_slice(&(se.len() as u16).to_be_bytes());
    out.extend_from_slice(se);
    Ok(out)
}

fn build_aad(header: u8, salt: &[u8], info: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(1 + salt.len() + info.len());
    aad.push(header);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(info);
    aad
}

fn hkdf_derive(
    master: &MasterKey,
    salt: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Vec<u8>, String> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master.as_bytes());
    let mut okm = vec![0u8; len];
    hk.expand(info, &mut okm)
        .map_err(|_| "HKDF expand failed".to_string())?;
    Ok(okm)
}

fn gcm_encrypt(
    preset: Preset,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let n = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let res = match preset {
        Preset::Aes128 => Aes128Gcm96::new_from_slice(key)
            .map_err(|_| "Invalid AES-128 key")?
            .encrypt(n, payload),
        Preset::Aes192 => Aes192Gcm112::new_from_slice(key)
            .map_err(|_| "Invalid AES-192 key")?
            .encrypt(n, payload),
        Preset::Aes256 => Aes256Gcm128::new_from_slice(key)
            .map_err(|_| "Invalid AES-256 key")?
            .encrypt(n, payload),
    };
    res.map_err(|_| "AES-GCM encryption failed".to_string())
}

fn gcm_decrypt(
    preset: Preset,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let n = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let res = match preset {
        Preset::Aes128 => Aes128Gcm96::new_from_slice(key)
            .map_err(|_| "Invalid AES-128 key")?
            .decrypt(n, payload),
        Preset::Aes192 => Aes192Gcm112::new_from_slice(key)
            .map_err(|_| "Invalid AES-192 key")?
            .decrypt(n, payload),
        Preset::Aes256 => Aes256Gcm128::new_from_slice(key)
            .map_err(|_| "Invalid AES-256 key")?
            .decrypt(n, payload),
    };
    res.map_err(|_| "Authentication failed (wrong key, channel, sender, or tampered data)".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn roundtrip_all_presets_messages() {
        let key = derive_user_key("test-passphrase-123").unwrap();
        let ch = "123456789012345678";
        let sender = "987654321098765432";

        for preset in [Preset::Aes128, Preset::Aes192, Preset::Aes256] {
            for msg in ["", "Hello Aegires!", "Unicode: नमस्ते 🚀"] {
                let wire = encrypt_message(msg, &key, preset, ch, sender).unwrap();
                assert!(looks_encrypted(&wire));
                assert!(wire.chars().count() <= DISCORD_CONTENT_LIMIT);
                let (pt, detected) = decrypt_message(&wire, &key, ch, sender).unwrap();
                assert_eq!(pt, msg);
                assert_eq!(detected, preset);
                // Wrong sender or channel must fail authentication.
                assert!(decrypt_message(&wire, &key, ch, "111111").is_err());
                assert!(decrypt_message(&wire, &key, "222222", sender).is_err());
            }
        }
    }

    #[test]
    fn roundtrip_streaming_file_boundaries() {
        let key = derive_context_key("mojoen", "forced|1562876012675465326").unwrap();
        let ch = "1562876012675465326";
        let sender = "4242424242";

        // Test 0 bytes, small, exact 64 KiB chunk, and multi-chunk files.
        for size in [0usize, 13, 65536, 65537, 150_000] {
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            for preset in [Preset::Aes128, Preset::Aes192, Preset::Aes256] {
                let mut enc = Vec::new();
                encrypt_stream(&mut Cursor::new(&data), &mut enc, &key, preset, ch, sender)
                    .unwrap();

                let mut dec = Vec::new();
                let (n, detected) =
                    decrypt_stream(&mut Cursor::new(&enc), &mut dec, &key, ch, sender).unwrap();
                assert_eq!(n as usize, size);
                assert_eq!(detected, preset);
                assert_eq!(dec, data);
            }
        }
    }
}

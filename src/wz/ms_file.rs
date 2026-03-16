//! MS file parsing — `.ms` archive format introduced in MapleStory v220+.
//!
//! Ported from MapleLib's `WzMsFile.cs` (Credits: Elem8100 / MapleNecrocer).
//! `.ms` files add a Snow2 stream cipher layer over standard WZ/IMG data.
//! Once decrypted, contents are standard WZ images using BMS keys (IV `[0,0,0,0]`).
//!
//! File layout:
//! ```text
//! [random bytes]              len = sum(filename chars) % 312 + 30
//! [hashedSaltLen: i32]        low byte XOR'd with randBytes[0] → actual salt length
//! [salt bytes]                saltLen × 2 bytes (UTF-16LE, only low byte carries XOR'd char)
//! [Snow2-encrypted header]    9 bytes: hash:i32 + version:u8 + entryCount:i32
//! [padding]                   len = sum(filename chars × 3) % 212 + 33
//! [Snow2-encrypted entries]   per entry: nameLen:i32 + name:utf16le + 7×i32 + entryKey:16
//! [alignment padding]         pad to next 1024-byte boundary
//! [encrypted data blocks]     each entry's data is 1024-aligned
//! ```
//!
//! Each data block uses double Snow2 encryption on its first 1024 bytes
//! to provide extra protection for the WZ image header.

use crate::crypto::snow2::Snow2;

use super::error::{WzError, WzResult};

// ── Constants ────────────────────────────────────────────────────────

const SUPPORTED_VERSION: u8 = 2; // only known MS format version
const SNOW_KEY_LEN: usize = 16;
const BLOCK_ALIGNMENT: usize = 1024;
const DOUBLE_ENCRYPT_BYTES: usize = 1024;
// Standard FNV-1a parameters (used in per-entry image key derivation)
const FNV_OFFSET_BASIS: u32 = 0x811C_9DC5;
const FNV_PRIME: u32 = 0x0100_0193;

// ── Public types ─────────────────────────────────────────────────────

pub struct MsParsedFile {
    pub salt: String,
    pub file_name_with_salt: String,
    pub entries: Vec<MsEntry>,
    pub data_start_pos: usize,
}

pub struct MsEntry {
    pub name: String, // e.g. "Mob/0100000.img"
    pub size: usize,
    /// Absolute byte offset in the .ms file (converted from block index during parsing)
    pub start_pos: usize,
    pub entry_key: [u8; 16], // random per-entry key, used to derive Snow2 image key
}

// ── Key derivation ───────────────────────────────────────────────────

/// Snow2 key from filename+salt — two derivation modes:
/// - Header key (`!is_entry_key`): `key[i] = char[i % len] + i`
/// - Entry-table key (`is_entry_key`): `key[i] = i + (i%3+2) * char[len-1 - i%len]`
///
/// C# uses `char` (UTF-16 code units); we use `encode_utf16()` to match exactly.
fn derive_snow_key(file_name_with_salt: &str, is_entry_key: bool) -> [u8; SNOW_KEY_LEN] {
    let chars: Vec<u16> = file_name_with_salt.encode_utf16().collect();
    let len = chars.len();
    let mut key = [0u8; SNOW_KEY_LEN];

    if !is_entry_key {
        // Header key: char + index
        for i in 0..SNOW_KEY_LEN {
            key[i] = (chars[i % len] as u8).wrapping_add(i as u8);
        }
    } else {
        // Entry key: index + multiplier * reversed char
        for i in 0..SNOW_KEY_LEN {
            let char_idx = len - 1 - (i % len);
            let multiplier = (i % 3 + 2) as u8;
            key[i] = (i as u8).wrapping_add(multiplier.wrapping_mul(chars[char_idx] as u8));
        }
    }
    key
}

/// Per-entry Snow2 key: FNV-1a(salt) → decimal digit array, then mixed with
/// entry name (UTF-16 code units) and the entry's random 16-byte key.
///
/// `key[i] = i + nameChar * (digits[i]%2 + entryKey[...] + (digits[i+1]+i)%5)`
fn derive_img_key(salt: &str, entry_name: &str, entry_key: &[u8; 16]) -> [u8; SNOW_KEY_LEN] {
    // FNV-1a hash of salt → u32, then convert to decimal digit array
    let mut key_hash: u32 = FNV_OFFSET_BASIS;
    for c in salt.bytes() {
        key_hash = (key_hash ^ c as u32).wrapping_mul(FNV_PRIME);
    }

    let hash_str = key_hash.to_string();
    let digits: Vec<u8> = hash_str.bytes().map(|b| b - b'0').collect();
    let dlen = digits.len();

    // UTF-16 code units to match C# `char` indexing
    let name_u16: Vec<u16> = entry_name.encode_utf16().collect();
    let nlen = name_u16.len();

    let mut img_key = [0u8; SNOW_KEY_LEN];
    for i in 0..SNOW_KEY_LEN {
        let digit_idx = i % dlen;
        let ek_idx = ((digits[(i + 2) % dlen] as usize) + i) % entry_key.len();
        let name_char = name_u16[i % nlen] as u32;
        let factor = (digits[digit_idx] % 2) as u32
            + entry_key[ek_idx] as u32
            + ((digits[(i + 1) % dlen] as u32 + i as u32) % 5);
        img_key[i] = (i as u32).wrapping_add(name_char.wrapping_mul(factor)) as u8;
    }
    img_key
}

// ── Parsing ──────────────────────────────────────────────────────────

fn read_i32_le(buf: &[u8], pos: usize) -> WzResult<i32> {
    if pos + 4 > buf.len() {
        return Err(WzError::UnexpectedEof);
    }
    Ok(i32::from_le_bytes([
        buf[pos],
        buf[pos + 1],
        buf[pos + 2],
        buf[pos + 3],
    ]))
}

// `file_name` is lowercased internally to match C# behavior.
pub fn parse_ms_file(data: &[u8], file_name: &str) -> WzResult<MsParsedFile> {
    let file_name_lower = file_name.to_lowercase();

    // ── Random-byte prefix (obfuscation, length derived from filename) ──
    let char_sum: u32 = file_name_lower.bytes().map(|b| b as u32).sum();
    let rand_byte_count = (char_sum % 312 + 30) as usize;

    if data.len() < rand_byte_count + 4 {
        return Err(WzError::Custom("MS file too small for header".into()));
    }

    let rand_bytes = &data[..rand_byte_count];
    let mut pos = rand_byte_count;

    // ── Salt recovery ────────────────────────────────────────────
    // Salt length is hidden: low byte of hashedSaltLen XOR'd with first random byte.
    // Salt chars are stored as UTF-16LE pairs but only the low byte carries data
    // (XOR'd with corresponding random byte); high byte is zero-padding.
    let hashed_salt_len = read_i32_le(data, pos)?;
    pos += 4;

    let salt_len = ((hashed_salt_len as u8) ^ rand_bytes[0]) as usize;
    if pos + salt_len * 2 > data.len() {
        return Err(WzError::Custom("MS file too small for salt".into()));
    }
    let salt_bytes = &data[pos..pos + salt_len * 2];
    pos += salt_len * 2;

    let salt_str: String = (0..salt_len)
        .map(|i| (rand_bytes[i] ^ salt_bytes[i * 2]) as char)
        .collect();

    let file_name_with_salt = format!("{}{}", file_name_lower, salt_str);

    // ── Encrypted header (9 bytes: hash:i32 + version:u8 + count:i32) ─
    let header_start = pos;
    // Snow2 operates on 4-byte blocks, so read 12 bytes (9 rounded up)
    let header_read_len = 12;
    if header_start + header_read_len > data.len() {
        return Err(WzError::Custom(
            "MS file too small for encrypted header".into(),
        ));
    }

    let mut header_buf = [0u8; 12];
    header_buf.copy_from_slice(&data[header_start..header_start + 12]);

    let header_key = derive_snow_key(&file_name_with_salt, false);
    Snow2::new(&header_key, &[], false).process(&mut header_buf);

    let hash = i32::from_le_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]]);
    let version = header_buf[4];
    let entry_count =
        i32::from_le_bytes([header_buf[5], header_buf[6], header_buf[7], header_buf[8]]);

    if version != SUPPORTED_VERSION {
        return Err(WzError::Custom(format!(
            "Unsupported MS version: expected {}, got {}",
            SUPPORTED_VERSION, version
        )));
    }

    // Integrity check: hash = hashedSaltLen + version + entryCount + sum(salt as u16[])
    let salt_u16_sum: i32 = (0..salt_len)
        .map(|i| u16::from_le_bytes([salt_bytes[i * 2], salt_bytes[i * 2 + 1]]) as i32)
        .sum();
    let expected_hash = hashed_salt_len + version as i32 + entry_count + salt_u16_sum;
    if hash != expected_hash {
        return Err(WzError::Custom(format!(
            "MS header hash mismatch: expected {}, got {}",
            expected_hash, hash
        )));
    }

    // ── Entry section ────────────────────────────────────────────
    // Filename-derived padding between header and entry table
    let pad_amount = {
        let s: u32 = file_name_lower.bytes().map(|b| b as u32 * 3).sum();
        (s % 212 + 33) as usize
    };
    let entry_start = header_start + 9 + pad_amount; // 9 = header payload size

    if entry_start >= data.len() {
        return Err(WzError::Custom("MS file too small for entries".into()));
    }

    // Decrypt entry section
    let mut entry_buf = data[entry_start..].to_vec();
    let entry_key = derive_snow_key(&file_name_with_salt, true);
    Snow2::new(&entry_key, &[], false).process(&mut entry_buf);

    // Parse entries from decrypted buffer
    let entry_count = entry_count as usize;
    let mut entries = Vec::with_capacity(entry_count);
    let mut epos = 0usize;

    for _ in 0..entry_count {
        // Name length (i32, count of UTF-16 code units)
        let name_len = read_i32_le(&entry_buf, epos)? as usize;
        epos += 4;

        // Name as UTF-16LE
        let name_byte_len = name_len * 2;
        if epos + name_byte_len > entry_buf.len() {
            return Err(WzError::UnexpectedEof);
        }
        let utf16: Vec<u16> = (0..name_len)
            .map(|i| {
                u16::from_le_bytes([entry_buf[epos + i * 2], entry_buf[epos + i * 2 + 1]])
            })
            .collect();
        let name = String::from_utf16_lossy(&utf16);
        epos += name_byte_len;

        // Entry metadata: 7 × i32 fields + 16-byte random key = 44 bytes
        // Fields: checksum, flags, startPos (block index), size, sizeAligned, unk1, unk2
        // checksum = flags + startPos + size + sizeAligned + unk1 + sum(entryKey)
        if epos + 44 > entry_buf.len() {
            return Err(WzError::UnexpectedEof);
        }

        let _checksum = read_i32_le(&entry_buf, epos)?;
        epos += 4;
        let _flags = read_i32_le(&entry_buf, epos)?;
        epos += 4;
        let start_pos_raw = read_i32_le(&entry_buf, epos)? as usize; // block index, not byte offset
        epos += 4;
        let size = read_i32_le(&entry_buf, epos)? as usize;
        epos += 4;
        let _size_aligned = read_i32_le(&entry_buf, epos)?; // size rounded up to 1024
        epos += 4;
        let _unk1 = read_i32_le(&entry_buf, epos)?;
        epos += 4;
        let _unk2 = read_i32_le(&entry_buf, epos)?;
        epos += 4;

        let mut ek = [0u8; 16];
        ek.copy_from_slice(&entry_buf[epos..epos + 16]);
        epos += 16;

        entries.push(MsEntry {
            name,
            size,
            start_pos: start_pos_raw,
            entry_key: ek,
        });
    }

    // C# CryptoStream reads in 4-byte blocks, so the stream position after reading entries
    // is rounded up to a 4-byte boundary. The data section then starts at the next 1024-byte page.
    let raw_bytes_consumed = (epos + 3) & !3;
    let data_start_pos = (entry_start + raw_bytes_consumed + 0x3FF) & !0x3FF;

    // Convert block indices → absolute byte offsets
    for entry in &mut entries {
        entry.start_pos = data_start_pos + entry.start_pos * BLOCK_ALIGNMENT;
    }

    Ok(MsParsedFile {
        salt: salt_str,
        file_name_with_salt,
        entries,
        data_start_pos,
    })
}

// Returns raw WZ image bytes using BMS keys (IV `[0,0,0,0]`).
pub fn decrypt_entry_data(
    data: &[u8],
    file: &MsParsedFile,
    entry_index: usize,
) -> WzResult<Vec<u8>> {
    let entry = file.entries.get(entry_index).ok_or_else(|| {
        WzError::Custom(format!(
            "MS entry index {} out of range (count {})",
            entry_index,
            file.entries.len()
        ))
    })?;

    if entry.start_pos + entry.size > data.len() {
        return Err(WzError::Custom(format!(
            "MS entry '{}' extends past end of file (offset 0x{:X}, size {})",
            entry.name, entry.start_pos, entry.size
        )));
    }

    let img_key = derive_img_key(&file.salt, &entry.name, &entry.entry_key);

    let mut buffer = data[entry.start_pos..entry.start_pos + entry.size].to_vec();

    // Decryption is the reverse of encryption (inner-then-outer):
    // 1. Outer Snow2 pass over entire buffer
    Snow2::new(&img_key, &[], false).process(&mut buffer);
    // 2. Inner Snow2 pass over first 1024 bytes (double-encrypted to protect WZ image header)
    let double_len = buffer.len().min(DOUBLE_ENCRYPT_BYTES);
    Snow2::new(&img_key, &[], false).process(&mut buffer[..double_len]);

    Ok(buffer)
}

// ── Writing ─────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct MsSaveEntry {
    pub name: String,
    pub image_data: Vec<u8>,
    pub entry_key: [u8; 16],
}

/// Reverse of `decrypt_entry_data()`.
pub fn encrypt_entry_data(
    data: &[u8],
    salt: &str,
    entry_name: &str,
    entry_key: &[u8; 16],
) -> Vec<u8> {
    let img_key = derive_img_key(salt, entry_name, entry_key);

    let aligned_size = (data.len() + BLOCK_ALIGNMENT - 1) & !(BLOCK_ALIGNMENT - 1);
    let mut buffer = vec![0u8; aligned_size];
    buffer[..data.len()].copy_from_slice(data);

    // Encrypt: inner first 1024 bytes, then outer entire buffer
    let double_len = buffer.len().min(DOUBLE_ENCRYPT_BYTES);
    Snow2::new(&img_key, &[], true).process(&mut buffer[..double_len]);
    Snow2::new(&img_key, &[], true).process(&mut buffer);

    buffer
}

fn write_i32_le(buf: &mut Vec<u8>, val: i32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

pub fn save_ms_file(
    file_name: &str,
    salt: &str,
    entries: &[MsSaveEntry],
) -> WzResult<Vec<u8>> {
    let file_name_lower = file_name.to_lowercase();
    let mut output = Vec::new();

    let char_sum: u32 = file_name_lower.bytes().map(|b| b as u32).sum();
    let rand_byte_count = (char_sum % 312 + 30) as usize;

    // Deterministic "random" bytes (seeded from filename for reproducibility)
    let mut rand_bytes = vec![0u8; rand_byte_count];
    for (i, b) in rand_bytes.iter_mut().enumerate() {
        *b = ((i as u32).wrapping_mul(0x41C64E6D).wrapping_add(0x3039) >> 16) as u8;
    }
    output.extend_from_slice(&rand_bytes);

    let salt_len = salt.len();
    let hashed_salt_len = (salt_len as u8 ^ rand_bytes[0]) as i32;
    write_i32_le(&mut output, hashed_salt_len);

    // Salt as UTF-16LE pairs: low byte = salt_char XOR rand_byte, high byte = 0
    let mut salt_u16_values = Vec::with_capacity(salt_len);
    for i in 0..salt_len {
        let lo = salt.as_bytes()[i] ^ rand_bytes[i];
        output.push(lo);
        output.push(0);
        salt_u16_values.push(u16::from_le_bytes([lo, 0]));
    }

    let file_name_with_salt = format!("{}{}", file_name_lower, salt);

    let salt_u16_sum: i32 = salt_u16_values.iter().map(|&v| v as i32).sum();
    let hash = hashed_salt_len + SUPPORTED_VERSION as i32 + entries.len() as i32 + salt_u16_sum;

    let mut header_buf = [0u8; 12];
    header_buf[0..4].copy_from_slice(&hash.to_le_bytes());
    header_buf[4] = SUPPORTED_VERSION;
    header_buf[5..9].copy_from_slice(&(entries.len() as i32).to_le_bytes());

    let header_key = derive_snow_key(&file_name_with_salt, false);
    Snow2::new(&header_key, &[], true).process(&mut header_buf);
    // Only write the 9 meaningful bytes (not the 3 padding bytes)
    output.extend_from_slice(&header_buf[..9]);

    let pad_amount = {
        let s: u32 = file_name_lower.bytes().map(|b| b as u32 * 3).sum();
        (s % 212 + 33) as usize
    };
    output.extend(std::iter::repeat(0u8).take(pad_amount));

    let mut entry_buf = Vec::new();
    let mut block_offset: usize = 0;

    for entry in entries {
        let name_u16: Vec<u16> = entry.name.encode_utf16().collect();
        write_i32_le(&mut entry_buf, name_u16.len() as i32);
        for &ch in &name_u16 {
            entry_buf.extend_from_slice(&ch.to_le_bytes());
        }

        let aligned_size = (entry.image_data.len() + BLOCK_ALIGNMENT - 1) & !(BLOCK_ALIGNMENT - 1);
        let ek_sum: i32 = entry.entry_key.iter().map(|&b| b as i32).sum();
        let flags: i32 = 0;
        let unk1: i32 = 0;
        let unk2: i32 = 0;
        let checksum = flags + (block_offset / BLOCK_ALIGNMENT) as i32
            + entry.image_data.len() as i32
            + aligned_size as i32
            + unk1
            + ek_sum;

        write_i32_le(&mut entry_buf, checksum);
        write_i32_le(&mut entry_buf, flags);
        write_i32_le(&mut entry_buf, (block_offset / BLOCK_ALIGNMENT) as i32); // start block index
        write_i32_le(&mut entry_buf, entry.image_data.len() as i32);
        write_i32_le(&mut entry_buf, aligned_size as i32);
        write_i32_le(&mut entry_buf, unk1);
        write_i32_le(&mut entry_buf, unk2);
        entry_buf.extend_from_slice(&entry.entry_key);

        block_offset += aligned_size;
    }

    // Encrypt the entry table
    let entry_key = derive_snow_key(&file_name_with_salt, true);
    // Pad to 4-byte boundary for Snow2
    while entry_buf.len() % 4 != 0 {
        entry_buf.push(0);
    }
    Snow2::new(&entry_key, &[], true).process(&mut entry_buf);
    output.extend_from_slice(&entry_buf);

    let remainder = output.len() % BLOCK_ALIGNMENT;
    if remainder != 0 {
        output.extend(std::iter::repeat(0u8).take(BLOCK_ALIGNMENT - remainder));
    }

    for entry in entries {
        let encrypted = encrypt_entry_data(
            &entry.image_data,
            salt,
            &entry.name,
            &entry.entry_key,
        );
        output.extend_from_slice(&encrypted);
    }

    Ok(output)
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_snow_key_header() {
        let key = derive_snow_key("test.ms_salt", false);
        assert_eq!(key.len(), 16);
        // First byte: 't' (0x74) + 0 = 0x74
        assert_eq!(key[0], b't');
        // Second byte: 'e' (0x65) + 1 = 0x66
        assert_eq!(key[1], b'e' + 1);
    }

    #[test]
    fn test_derive_snow_key_entry() {
        let key = derive_snow_key("test.ms_salt", true);
        assert_eq!(key.len(), 16);
        // Entry key uses reversed indexing and multiplier
        // i=0: char_idx = len-1-0 = 11 ('t'), multiplier = 0%3+2 = 2
        // key[0] = 0 + 2 * 't'(0x74) = 0xE8
        assert_eq!(key[0], 2u8.wrapping_mul(b't'));
    }

    #[test]
    fn test_derive_img_key_deterministic() {
        let ek = [1u8; 16];
        let k1 = derive_img_key("salt", "Mob/test.img", &ek);
        let k2 = derive_img_key("salt", "Mob/test.img", &ek);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_img_key_differs_by_salt() {
        let ek = [0u8; 16];
        let k1 = derive_img_key("aaa", "Mob/test.img", &ek);
        let k2 = derive_img_key("bbb", "Mob/test.img", &ek);
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_snow2_double_decrypt_roundtrip() {
        // Simulate the double-encryption scheme: inner then outer
        let key = [0x42u8; 16];
        let original = vec![0xABu8; 2048];
        let mut encrypted = original.clone();

        // Encrypt: inner first 1024, then outer all
        Snow2::new(&key, &[], true).process(&mut encrypted[..1024]);
        Snow2::new(&key, &[], true).process(&mut encrypted);

        // Decrypt: outer all, then inner first 1024
        Snow2::new(&key, &[], false).process(&mut encrypted);
        Snow2::new(&key, &[], false).process(&mut encrypted[..1024]);

        assert_eq!(encrypted, original);
    }

    #[test]
    fn test_parse_ms_file_too_small() {
        let result = parse_ms_file(&[0u8; 10], "test.ms");
        assert!(result.is_err());
    }

    // ── encrypt/decrypt roundtrip ────────────────────────────────

    #[test]
    fn test_encrypt_decrypt_entry_roundtrip() {
        let original = vec![0x73u8; 2048]; // fake WZ image data
        let salt = "testsalt";
        let name = "Mob/test.img";
        let entry_key = [0x42u8; 16];

        let encrypted = encrypt_entry_data(&original, salt, name, &entry_key);
        assert_ne!(&encrypted[..original.len()], &original[..]);

        // Decrypt
        let img_key = derive_img_key(salt, name, &entry_key);
        let mut decrypted = encrypted;
        Snow2::new(&img_key, &[], false).process(&mut decrypted);
        let double_len = decrypted.len().min(DOUBLE_ENCRYPT_BYTES);
        Snow2::new(&img_key, &[], false).process(&mut decrypted[..double_len]);

        assert_eq!(&decrypted[..original.len()], &original[..]);
    }

    // ── save/parse roundtrip ─────────────────────────────────────

    #[test]
    fn test_save_parse_ms_roundtrip() {
        let file_name = "test_data.ms";
        let salt = "abc";
        let image_data = vec![0x73u8, 0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let entry_key = [0x11u8; 16];

        let entries = vec![MsSaveEntry {
            name: "Mob/0100.img".into(),
            image_data: image_data.clone(),
            entry_key,
        }];

        let saved = save_ms_file(file_name, salt, &entries).unwrap();
        let parsed = parse_ms_file(&saved, file_name).unwrap();

        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "Mob/0100.img");
        assert_eq!(parsed.entries[0].size, image_data.len());

        // Decrypt and verify the image data
        let decrypted = decrypt_entry_data(&saved, &parsed, 0).unwrap();
        assert_eq!(&decrypted[..image_data.len()], &image_data[..]);
    }

    #[test]
    fn test_save_parse_ms_multiple_entries() {
        let file_name = "multi.ms";
        let salt = "xyz";

        let entries = vec![
            MsSaveEntry {
                name: "Map/town.img".into(),
                image_data: vec![0x73; 500],
                entry_key: [0x22; 16],
            },
            MsSaveEntry {
                name: "Npc/shop.img".into(),
                image_data: vec![0x73; 1500],
                entry_key: [0x33; 16],
            },
        ];

        let saved = save_ms_file(file_name, salt, &entries).unwrap();
        let parsed = parse_ms_file(&saved, file_name).unwrap();

        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].name, "Map/town.img");
        assert_eq!(parsed.entries[1].name, "Npc/shop.img");

        for i in 0..2 {
            let decrypted = decrypt_entry_data(&saved, &parsed, i).unwrap();
            assert_eq!(
                &decrypted[..entries[i].image_data.len()],
                &entries[i].image_data[..]
            );
        }
    }
}

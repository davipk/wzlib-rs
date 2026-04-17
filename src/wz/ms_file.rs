//! MS file parsing — `.ms` archive format introduced in MapleStory v220+.
//!
//! Ported from WzComparerR2's `Ms_File.cs` / `Ms_FileV2.cs` (Credits: Elem8100).
//! `.ms` files add a cipher layer over standard WZ/IMG data.
//! Once decrypted, contents are standard WZ images using BMS keys (IV `[0,0,0,0]`).
//!
//! Two format versions exist:
//!
//! **V1 (version byte = 2):** Snow2 stream cipher.
//! ```text
//! [random bytes]              len = sum(filename chars) % 312 + 30
//! [hashedSaltLen: i32]        low byte XOR'd with randBytes[0] → actual salt length
//! [salt bytes]                saltLen × 2 bytes (UTF-16LE, XOR'd with rand bytes)
//! [Snow2-encrypted header]    9 bytes: hash:i32 + version:u8 + entryCount:i32
//! [padding]                   len = sum(filename chars × 3) % 212 + 33
//! [Snow2-encrypted entries]   per entry: nameLen:i32 + name:utf16le + 7×i32 + entryKey:16
//! [alignment padding]         pad to next 1024-byte boundary
//! [encrypted data blocks]     each entry's data is 1024-aligned
//! ```
//! Each data block uses double Snow2 encryption on its first 1024 bytes.
//!
//! **V2 (version byte = 4):** ChaCha20 stream cipher.
//! ```text
//! [random bytes]              same length formula, then arithmetic-right-shifted by 1
//! [version ^ randBytes[0]]    1 byte (must decode to 4)
//! [hashedSaltLen: i32]        same as v1
//! [salt bytes]                same length, but decoded with extra transform
//! [ChaCha20-encrypted header] 8 bytes: hash:i32 + entryCount:i32
//! [padding]                   len = sum(filename chars × 3) % 212 + 64
//! [ChaCha20-encrypted entries] per entry: same as v1 + unk3:i32 + unk4:i32
//! [alignment padding]         pad to next 1024-byte boundary
//! [encrypted data blocks]     only first 1024 bytes encrypted per entry
//! ```

use crate::crypto::chacha20::ChaCha20;
use crate::crypto::snow2::Snow2;

use super::error::{WzError, WzResult};

// ── Constants ────────────────────────────────────────────────────────

const MS_VERSION_V1: u8 = 2;
const MS_VERSION_V2: u8 = 4;
const SNOW_KEY_LEN: usize = 16;
const CHACHA_KEY_LEN: usize = 32;
const CHACHA_NONCE_LEN: usize = 12;
const CHACHA_BLOCK_SIZE: usize = 64;
const BLOCK_ALIGNMENT: usize = 1024;
const DOUBLE_ENCRYPT_BYTES: usize = 1024;
const FNV_OFFSET_BASIS: u32 = 0x811C_9DC5;
const FNV_PRIME: u32 = 0x0100_0193;

/// XOR mask applied to all ChaCha20 keys in v2
const CHACHA20_KEY_OBSCURE: [u8; 32] = [
    0x7B, 0x2F, 0x35, 0x48, 0x43, 0x95, 0x02, 0xB9, 0xAE, 0x91, 0xA6, 0xE1, 0xD8, 0xD6, 0x24, 0xB4,
    0x33, 0x10, 0x1D, 0x3D, 0xC1, 0xBB, 0xC6, 0xF4, 0xA5, 0xFE, 0xB3, 0x69, 0x6B, 0x56, 0xE4, 0x75,
];

// ── Public types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsVersion {
    V1, // Snow2, version byte = 2
    V2, // ChaCha20, version byte = 4
}

impl From<u8> for MsVersion {
    fn from(v: u8) -> Self {
        match v {
            2 => MsVersion::V2,
            _ => MsVersion::V1,
        }
    }
}

pub struct MsParsedFile {
    pub version: MsVersion,
    pub salt: String,
    pub file_name_with_salt: String,
    pub entries: Vec<MsEntry>,
    pub data_start_pos: usize,
}

pub struct MsEntry {
    pub name: String, // e.g. "Mob/0100000.img"
    pub size: usize,
    pub size_aligned: usize,
    /// Absolute byte offset in the .ms file (converted from block index during parsing)
    pub start_pos: usize,
    pub entry_key: [u8; 16],
}

// ── Shared helpers ───────────────────────────────────────────────────

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

fn write_i32_le(buf: &mut Vec<u8>, val: i32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

/// FNV-1a hash over UTF-16 code units of the salt string (matches C# `foreach (var c in salt)`).
fn fnv1a_u16(salt: &str) -> u32 {
    let mut h: u32 = FNV_OFFSET_BASIS;
    for c in salt.encode_utf16() {
        h = (h ^ c as u32).wrapping_mul(FNV_PRIME);
    }
    h
}

fn rand_byte_count(file_name: &str) -> usize {
    let char_sum: u32 = file_name.bytes().map(|b| b as u32).sum();
    (char_sum % 312 + 30) as usize
}

fn entry_pad_amount(file_name: &str) -> usize {
    let s: u32 = file_name.bytes().map(|b| b as u32 * 3).sum();
    (s % 212) as usize
}

fn align_to_block(size: usize) -> usize {
    (size + BLOCK_ALIGNMENT - 1) & !(BLOCK_ALIGNMENT - 1)
}

/// Deterministic pseudo-random bytes seeded from position index (reproducible across builds).
fn generate_rand_bytes(count: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; count];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = ((i as u32).wrapping_mul(0x41C64E6D).wrapping_add(0x3039) >> 16) as u8;
    }
    bytes
}

// ── Key derivation (shared core) ─────────────────────────────────────

/// Header: `key[i] = char[i % len] + i` — Entry: `key[i] = i + (i%3+2) * char[len-1 - i%len]`
fn derive_key_core(file_name_with_salt: &str, is_entry_key: bool, out: &mut [u8]) {
    let chars: Vec<u16> = file_name_with_salt.encode_utf16().collect();
    let len = chars.len();

    if !is_entry_key {
        for i in 0..out.len() {
            out[i] = (chars[i % len] as u8).wrapping_add(i as u8);
        }
    } else {
        for i in 0..out.len() {
            let char_idx = len - 1 - (i % len);
            let multiplier = (i % 3 + 2) as u8;
            out[i] = (i as u8).wrapping_add(multiplier.wrapping_mul(chars[char_idx] as u8));
        }
    }
}

fn derive_img_key_core(salt: &str, entry_name: &str, entry_key: &[u8; 16], out: &mut [u8]) {
    let key_hash = fnv1a_u16(salt);
    let hash_str = key_hash.to_string();
    let digits: Vec<u8> = hash_str.bytes().map(|b| b - b'0').collect();
    let dlen = digits.len();

    let name_u16: Vec<u16> = entry_name.encode_utf16().collect();
    let nlen = name_u16.len();

    for i in 0..out.len() {
        let digit_idx = i % dlen;
        let ek_idx = ((digits[(i + 2) % dlen] as usize) + i) % entry_key.len();
        let name_char = name_u16[i % nlen] as u32;
        let factor = (digits[digit_idx] % 2) as u32
            + entry_key[ek_idx] as u32
            + ((digits[(i + 1) % dlen] as u32 + i as u32) % 5);
        out[i] = (i as u32).wrapping_add(name_char.wrapping_mul(factor)) as u8;
    }
}

fn xor_with_obscure(key: &mut [u8]) {
    for (k, &o) in key.iter_mut().zip(CHACHA20_KEY_OBSCURE.iter()) {
        *k ^= o;
    }
}

// ── V1 key derivation (Snow2) ────────────────────────────────────────

fn derive_snow_key(file_name_with_salt: &str, is_entry_key: bool) -> [u8; SNOW_KEY_LEN] {
    let mut key = [0u8; SNOW_KEY_LEN];
    derive_key_core(file_name_with_salt, is_entry_key, &mut key);
    key
}

fn derive_img_key_v1(salt: &str, entry_name: &str, entry_key: &[u8; 16]) -> [u8; SNOW_KEY_LEN] {
    let mut key = [0u8; SNOW_KEY_LEN];
    derive_img_key_core(salt, entry_name, entry_key, &mut key);
    key
}

// ── V2 key derivation (ChaCha20) ────────────────────────────────────

fn derive_chacha_key(file_name_with_salt: &str, is_entry_key: bool) -> [u8; CHACHA_KEY_LEN] {
    let mut key = [0u8; CHACHA_KEY_LEN];
    derive_key_core(file_name_with_salt, is_entry_key, &mut key);
    xor_with_obscure(&mut key);
    key
}

fn derive_img_key_v2(salt: &str, entry_name: &str, entry_key: &[u8; 16]) -> [u8; CHACHA_KEY_LEN] {
    let mut key = [0u8; CHACHA_KEY_LEN];
    derive_img_key_core(salt, entry_name, entry_key, &mut key);
    xor_with_obscure(&mut key);
    key
}

fn derive_img_nonce_counter(salt: &str) -> ([u8; CHACHA_NONCE_LEN], u32) {
    let key_hash = fnv1a_u16(salt);
    let key_hash2 = key_hash >> 1;
    let key_hash3 = key_hash2 ^ 0x6C;

    let mut kh_data = [0u8; 12];
    kh_data[0..4].copy_from_slice(&key_hash.to_le_bytes());
    kh_data[4..8].copy_from_slice(&key_hash2.to_le_bytes());
    kh_data[8..12].copy_from_slice(&key_hash3.to_le_bytes());

    // Matches C# mixing loop exactly
    let (mut a, mut b, mut c, mut d): (i32, i32, i32, i32) = (0, 0, 90, 0);
    for i in 0..12u32 {
        let mix = (d as u32)
            .wrapping_add(11u32.wrapping_mul(i / 11))
            .wrapping_add((c as u32) ^ (i >> 2))
            .wrapping_add((a as u32) ^ (b as u32));
        kh_data[i as usize] ^= mix as u8;
        d -= 1;
        a += 8;
        b += 17;
        c += 43;
    }

    // nonce[0..4] = 0, nonce[4..12] = keyHashData[0..8]
    let mut nonce = [0u8; CHACHA_NONCE_LEN];
    nonce[4..12].copy_from_slice(&kh_data[0..8]);

    let counter = u32::from_le_bytes([kh_data[8], kh_data[9], kh_data[10], kh_data[11]]);

    (nonce, counter)
}

// ── ChaCha20 stream reader (for v2 entry table) ─────────────────────
//
// Matches C#'s `Ms_FileV2.ChaCha20Reader`: reads 64-byte blocks from
// the source, decrypts each via ChaCha20, and resets the counter when
// a ReadBytes call finishes with the internal 64-byte buffer exhausted.

struct ChaCha20StreamReader<'a> {
    data: &'a [u8],
    pos: usize, // position in source data
    buffer: [u8; CHACHA_BLOCK_SIZE],
    buf_pos: usize, // position within decrypted buffer (0..64)
    cipher: ChaCha20,
}

impl<'a> ChaCha20StreamReader<'a> {
    fn new(data: &'a [u8], key: &[u8; CHACHA_KEY_LEN], nonce: &[u8; CHACHA_NONCE_LEN]) -> Self {
        Self {
            data,
            pos: 0,
            buffer: [0u8; CHACHA_BLOCK_SIZE],
            buf_pos: CHACHA_BLOCK_SIZE, // starts "empty" — first read triggers a block fetch
            cipher: ChaCha20::new(key, nonce, 0),
        }
    }

    fn read_bytes_into(&mut self, out: &mut [u8]) -> WzResult<()> {
        let mut remaining = 0usize;
        let total = out.len();

        while remaining < total {
            if self.buf_pos >= CHACHA_BLOCK_SIZE {
                if self.pos + CHACHA_BLOCK_SIZE > self.data.len() {
                    return Err(WzError::UnexpectedEof);
                }
                self.buffer
                    .copy_from_slice(&self.data[self.pos..self.pos + CHACHA_BLOCK_SIZE]);
                self.cipher.process(&mut self.buffer);
                self.pos += CHACHA_BLOCK_SIZE;
                self.buf_pos = 0;
            }

            let avail = CHACHA_BLOCK_SIZE - self.buf_pos;
            let need = total - remaining;
            let n = need.min(avail);
            out[remaining..remaining + n]
                .copy_from_slice(&self.buffer[self.buf_pos..self.buf_pos + n]);
            self.buf_pos += n;
            remaining += n;
        }

        // C# resets the counter when a ReadBytes call ends with buffer exhausted
        if self.buf_pos >= CHACHA_BLOCK_SIZE {
            self.cipher.reset_counter();
        }
        Ok(())
    }

    fn read_bytes(&mut self, count: usize) -> WzResult<Vec<u8>> {
        let mut buf = vec![0u8; count];
        self.read_bytes_into(&mut buf)?;
        Ok(buf)
    }

    fn read_i32(&mut self) -> WzResult<i32> {
        let mut buf = [0u8; 4];
        self.read_bytes_into(&mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }

    /// Read a length-prefixed UTF-16LE string (matches C#'s `ChaCha20Reader.ReadString`).
    fn read_string(&mut self) -> WzResult<String> {
        let len = self.read_i32()? as usize;
        let byte_len = len * 2;
        let bytes = self.read_bytes(byte_len)?;
        let utf16: Vec<u16> = (0..len)
            .map(|i| u16::from_le_bytes([bytes[i * 2], bytes[i * 2 + 1]]))
            .collect();
        Ok(String::from_utf16_lossy(&utf16))
    }

    /// How many bytes have been consumed from the source data (always a multiple of 64).
    fn bytes_consumed(&self) -> usize {
        self.pos
    }
}

// ── Parsing (auto-detect v1/v2) ──────────────────────────────────────

pub fn parse_ms_file(data: &[u8], file_name: &str) -> WzResult<MsParsedFile> {
    let file_name_lower = file_name.to_lowercase();
    let rbc = rand_byte_count(&file_name_lower);

    if data.len() < rbc + 5 {
        return Err(WzError::Custom("MS file too small for header".into()));
    }

    // Try v2 first: arithmetic-right-shift the random prefix, XOR to recover version byte
    let mut shifted = data[..rbc].to_vec();
    for b in shifted.iter_mut() {
        *b = ((*b as i8) >> 1) as u8;
    }
    let version_byte = data[rbc] ^ shifted[0];

    if version_byte == MS_VERSION_V2 {
        match parse_ms_file_v2(data, &file_name_lower, &shifted, rbc) {
            Ok(result) => return Ok(result),
            Err(_) => {} // v2 detection was a false positive, try v1
        }
    }

    parse_ms_file_v1(data, &file_name_lower, rbc)
}

// ── V1 parsing ───────────────────────────────────────────────────────

fn parse_ms_file_v1(data: &[u8], file_name: &str, rbc: usize) -> WzResult<MsParsedFile> {
    let rand_bytes = &data[..rbc];
    let mut pos = rbc;

    // ── Salt recovery ──
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

    let file_name_with_salt = format!("{}{}", file_name, salt_str);

    // ── Encrypted header (9 bytes: hash:i32 + version:u8 + count:i32) ──
    let header_start = pos;
    if header_start + 12 > data.len() {
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

    if version != MS_VERSION_V1 {
        return Err(WzError::Custom(format!(
            "Unsupported MS version: expected {}, got {}",
            MS_VERSION_V1, version
        )));
    }

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

    // ── Entry section ──
    let pad = entry_pad_amount(file_name) + 33;
    let entry_start = header_start + 9 + pad;

    if entry_start >= data.len() {
        return Err(WzError::Custom("MS file too small for entries".into()));
    }

    let mut entry_buf = data[entry_start..].to_vec();
    let entry_key = derive_snow_key(&file_name_with_salt, true);
    Snow2::new(&entry_key, &[], false).process(&mut entry_buf);

    let entry_count = entry_count as usize;
    let mut entries = Vec::with_capacity(entry_count);
    let mut epos = 0usize;

    for _ in 0..entry_count {
        let name_len = read_i32_le(&entry_buf, epos)? as usize;
        epos += 4;

        let name_byte_len = name_len * 2;
        if epos + name_byte_len > entry_buf.len() {
            return Err(WzError::UnexpectedEof);
        }
        let utf16: Vec<u16> = (0..name_len)
            .map(|i| u16::from_le_bytes([entry_buf[epos + i * 2], entry_buf[epos + i * 2 + 1]]))
            .collect();
        let name = String::from_utf16_lossy(&utf16);
        epos += name_byte_len;

        if epos + 44 > entry_buf.len() {
            return Err(WzError::UnexpectedEof);
        }

        let _checksum = read_i32_le(&entry_buf, epos)?;
        epos += 4;
        let _flags = read_i32_le(&entry_buf, epos)?;
        epos += 4;
        let start_pos_raw = read_i32_le(&entry_buf, epos)? as usize;
        epos += 4;
        let size = read_i32_le(&entry_buf, epos)? as usize;
        epos += 4;
        let size_aligned = read_i32_le(&entry_buf, epos)? as usize;
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
            size_aligned,
            start_pos: start_pos_raw,
            entry_key: ek,
        });
    }

    // Snow2 reads in 4-byte blocks → round up, then align to 1024
    let raw_bytes_consumed = (epos + 3) & !3;
    let entry_table_end = entry_start + raw_bytes_consumed;
    let data_start_pos = (entry_table_end + 0x3FF) & !0x3FF;

    for entry in &mut entries {
        entry.start_pos = data_start_pos + entry.start_pos * BLOCK_ALIGNMENT;
    }

    Ok(MsParsedFile {
        version: MsVersion::V1,
        salt: salt_str,
        file_name_with_salt,
        entries,
        data_start_pos,
    })
}

// ── V2 parsing ───────────────────────────────────────────────────────

fn parse_ms_file_v2(
    data: &[u8],
    file_name: &str,
    shifted_rand: &[u8],
    rbc: usize,
) -> WzResult<MsParsedFile> {
    // Version byte already verified by caller; skip past it
    let mut pos = rbc + 1;

    // ── Salt recovery (v2 transform) ──
    let hashed_salt_len = read_i32_le(data, pos)?;
    pos += 4;

    let salt_len = ((hashed_salt_len as u8) ^ shifted_rand[0]) as usize;
    if pos + salt_len * 2 > data.len() {
        return Err(WzError::Custom("MS v2 file too small for salt".into()));
    }
    let salt_bytes = &data[pos..pos + salt_len * 2];
    pos += salt_len * 2;

    // V2 salt derivation: extra (a | 0x4B) << 1 - a - 75 transform
    let salt_str: String = (0..salt_len)
        .map(|i| {
            let a = (shifted_rand[i] ^ salt_bytes[i * 2]) as i32;
            let b = ((a | 0x4B) << 1) - a - 75;
            char::from(b as u8)
        })
        .collect();

    let file_name_with_salt = format!("{}{}", file_name, salt_str);

    // ── Encrypted header (8 bytes via ChaCha20: hash:i32 + entryCount:i32) ──
    let header_start = pos;
    // ChaCha20 processes 64-byte blocks; we need at least one block
    if header_start + CHACHA_BLOCK_SIZE > data.len() {
        return Err(WzError::Custom(
            "MS v2 file too small for encrypted header".into(),
        ));
    }

    let header_key = derive_chacha_key(&file_name_with_salt, false);
    let empty_nonce = [0u8; CHACHA_NONCE_LEN];
    let mut header_block = [0u8; CHACHA_BLOCK_SIZE];
    header_block.copy_from_slice(&data[header_start..header_start + CHACHA_BLOCK_SIZE]);
    ChaCha20::new(&header_key, &empty_nonce, 0).process(&mut header_block);

    let _header_hash = i32::from_le_bytes([
        header_block[0],
        header_block[1],
        header_block[2],
        header_block[3],
    ]);
    let entry_count = i32::from_le_bytes([
        header_block[4],
        header_block[5],
        header_block[6],
        header_block[7],
    ]);

    if entry_count < 0 || entry_count > 100_000 {
        return Err(WzError::Custom(format!(
            "MS v2 entry count out of range: {}",
            entry_count
        )));
    }

    // ── Entry section ──
    let pad = entry_pad_amount(file_name) + 64; // v2 uses +64 instead of +33
    let entry_start = header_start + 8 + pad;

    if entry_start + CHACHA_BLOCK_SIZE > data.len() {
        return Err(WzError::Custom("MS v2 file too small for entries".into()));
    }

    let entry_key = derive_chacha_key(&file_name_with_salt, true);
    let mut reader = ChaCha20StreamReader::new(&data[entry_start..], &entry_key, &empty_nonce);

    let entry_count = entry_count as usize;
    let mut entries = Vec::with_capacity(entry_count);

    for _ in 0..entry_count {
        let name = reader.read_string()?;
        let _checksum = reader.read_i32()?;
        let _flags = reader.read_i32()?;
        let start_pos_raw = reader.read_i32()? as usize;
        let size = reader.read_i32()? as usize;
        let size_aligned = reader.read_i32()? as usize;
        let _unk1 = reader.read_i32()?;
        let _unk2 = reader.read_i32()?;
        let ek_vec = reader.read_bytes(16)?;
        let _unk3 = reader.read_i32()?;
        let _unk4 = reader.read_i32()?;

        let mut ek = [0u8; 16];
        ek.copy_from_slice(&ek_vec);

        entries.push(MsEntry {
            name,
            size,
            size_aligned,
            start_pos: start_pos_raw,
            entry_key: ek,
        });
    }

    // ChaCha20StreamReader reads in 64-byte blocks → round up, then align to 1024
    let raw_bytes_consumed = reader.bytes_consumed();
    let entry_table_end = entry_start + raw_bytes_consumed;
    let data_start_pos = (entry_table_end + 0x3FF) & !0x3FF;

    for entry in &mut entries {
        entry.start_pos = data_start_pos + entry.start_pos * BLOCK_ALIGNMENT;
    }

    Ok(MsParsedFile {
        version: MsVersion::V2,
        salt: salt_str,
        file_name_with_salt,
        entries,
        data_start_pos,
    })
}

// ── Decryption ───────────────────────────────────────────────────────

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

    match file.version {
        MsVersion::V1 => decrypt_entry_v1(data, &file.salt, entry),
        MsVersion::V2 => decrypt_entry_v2(data, &file.salt, entry),
    }
}

fn decrypt_entry_v1(data: &[u8], salt: &str, entry: &MsEntry) -> WzResult<Vec<u8>> {
    let img_key = derive_img_key_v1(salt, &entry.name, &entry.entry_key);
    let mut buffer = data[entry.start_pos..entry.start_pos + entry.size].to_vec();

    // Decrypt order: outer pass first, then inner pass (reverse of encrypt)
    Snow2::new(&img_key, &[], false).process(&mut buffer);
    let double_len = buffer.len().min(DOUBLE_ENCRYPT_BYTES);
    Snow2::new(&img_key, &[], false).process(&mut buffer[..double_len]);

    Ok(buffer)
}

fn decrypt_entry_v2(data: &[u8], salt: &str, entry: &MsEntry) -> WzResult<Vec<u8>> {
    let img_key = derive_img_key_v2(salt, &entry.name, &entry.entry_key);
    let (nonce, counter) = derive_img_nonce_counter(salt);

    // V2 only encrypts the first min(size, 1024) bytes; the rest is plaintext
    let crypted_size = entry.size.min(DOUBLE_ENCRYPT_BYTES);
    // ChaCha20 processes 64-byte blocks — round up
    let decrypt_len = (crypted_size + CHACHA_BLOCK_SIZE - 1) & !(CHACHA_BLOCK_SIZE - 1);

    if entry.start_pos + decrypt_len > data.len() {
        return Err(WzError::Custom(format!(
            "MS v2 entry '{}' encrypted region extends past end of file",
            entry.name
        )));
    }

    let mut encrypted = data[entry.start_pos..entry.start_pos + decrypt_len].to_vec();
    ChaCha20::new(&img_key, &nonce, counter).process(&mut encrypted);

    let mut result = encrypted[..crypted_size].to_vec();

    if entry.size > DOUBLE_ENCRYPT_BYTES {
        let plain_start = entry.start_pos + DOUBLE_ENCRYPT_BYTES;
        let plain_end = entry.start_pos + entry.size;
        if plain_end > data.len() {
            return Err(WzError::Custom(format!(
                "MS v2 entry '{}' plaintext region extends past end of file",
                entry.name
            )));
        }
        result.extend_from_slice(&data[plain_start..plain_end]);
    }

    Ok(result)
}

// ── Writing ─────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
pub struct MsSaveEntry {
    pub name: String,
    pub image_data: Vec<u8>,
    pub entry_key: [u8; 16],
    /// Original entry data size from parsing. When set, alignment is computed
    /// from `max(image_data.len(), original_size)` so that re-serialized data
    /// that shrinks slightly doesn't cross a 1024-byte block boundary.
    #[serde(default)]
    pub original_size: Option<usize>,
}

impl MsSaveEntry {
    fn aligned_size(&self) -> usize {
        let effective = match self.original_size {
            Some(orig) if orig > self.image_data.len() => orig,
            _ => self.image_data.len(),
        };
        align_to_block(effective)
    }
}

pub fn encrypt_entry_data(
    data: &[u8],
    salt: &str,
    entry_name: &str,
    entry_key: &[u8; 16],
    version: MsVersion,
) -> Vec<u8> {
    match version {
        MsVersion::V1 => encrypt_entry_data_v1(data, salt, entry_name, entry_key, None),
        MsVersion::V2 => encrypt_entry_data_v2(data, salt, entry_name, entry_key, None),
    }
}

fn encrypt_entry_data_v1(
    data: &[u8],
    salt: &str,
    entry_name: &str,
    entry_key: &[u8; 16],
    size_aligned: Option<usize>,
) -> Vec<u8> {
    let img_key = derive_img_key_v1(salt, entry_name, entry_key);

    let aligned_size = size_aligned.unwrap_or_else(|| align_to_block(data.len()));
    let mut buffer = vec![0u8; aligned_size];
    buffer[..data.len()].copy_from_slice(data);

    // Encrypt: inner first 1024 bytes, then outer entire buffer
    let double_len = buffer.len().min(DOUBLE_ENCRYPT_BYTES);
    Snow2::new(&img_key, &[], true).process(&mut buffer[..double_len]);
    Snow2::new(&img_key, &[], true).process(&mut buffer);

    buffer
}

fn build_ms_file_v1(file_name: &str, salt: &str, entries: &[MsSaveEntry]) -> WzResult<Vec<u8>> {
    let file_name_lower = file_name.to_lowercase();
    let mut output = Vec::new();

    let rand_bytes = generate_rand_bytes(rand_byte_count(&file_name_lower));
    output.extend_from_slice(&rand_bytes);

    let salt_len = salt.len();
    let hashed_salt_len = (salt_len as u8 ^ rand_bytes[0]) as i32;
    write_i32_le(&mut output, hashed_salt_len);

    let mut salt_u16_values = Vec::with_capacity(salt_len);
    for i in 0..salt_len {
        let lo = salt.as_bytes()[i] ^ rand_bytes[i];
        output.push(lo);
        output.push(0);
        salt_u16_values.push(u16::from_le_bytes([lo, 0]));
    }

    let file_name_with_salt = format!("{}{}", file_name_lower, salt);

    let salt_u16_sum: i32 = salt_u16_values.iter().map(|&v| v as i32).sum();
    let hash = hashed_salt_len + MS_VERSION_V1 as i32 + entries.len() as i32 + salt_u16_sum;

    let mut header_buf = [0u8; 12];
    header_buf[0..4].copy_from_slice(&hash.to_le_bytes());
    header_buf[4] = MS_VERSION_V1;
    header_buf[5..9].copy_from_slice(&(entries.len() as i32).to_le_bytes());

    let header_key = derive_snow_key(&file_name_with_salt, false);
    Snow2::new(&header_key, &[], true).process(&mut header_buf);
    output.extend_from_slice(&header_buf[..9]);

    let pad = entry_pad_amount(&file_name_lower) + 33;
    output.extend(std::iter::repeat(0u8).take(pad));

    let mut entry_buf = Vec::new();
    let mut block_offset: usize = 0;

    for entry in entries {
        let name_u16: Vec<u16> = entry.name.encode_utf16().collect();
        write_i32_le(&mut entry_buf, name_u16.len() as i32);
        for &ch in &name_u16 {
            entry_buf.extend_from_slice(&ch.to_le_bytes());
        }

        let aligned_size = entry.aligned_size();
        let ek_sum: i32 = entry.entry_key.iter().map(|&b| b as i32).sum();
        let flags: i32 = 0;
        let unk1: i32 = 0;
        let unk2: i32 = 0;
        let checksum = flags
            + (block_offset / BLOCK_ALIGNMENT) as i32
            + entry.image_data.len() as i32
            + aligned_size as i32
            + unk1
            + ek_sum;

        write_i32_le(&mut entry_buf, checksum);
        write_i32_le(&mut entry_buf, flags);
        write_i32_le(&mut entry_buf, (block_offset / BLOCK_ALIGNMENT) as i32);
        write_i32_le(&mut entry_buf, entry.image_data.len() as i32);
        write_i32_le(&mut entry_buf, aligned_size as i32);
        write_i32_le(&mut entry_buf, unk1);
        write_i32_le(&mut entry_buf, unk2);
        entry_buf.extend_from_slice(&entry.entry_key);

        block_offset += aligned_size;
    }

    let entry_key = derive_snow_key(&file_name_with_salt, true);
    while entry_buf.len() % 4 != 0 {
        entry_buf.push(0);
    }
    Snow2::new(&entry_key, &[], true).process(&mut entry_buf);
    output.extend_from_slice(&entry_buf);

    let padded_len = align_to_block(output.len());
    output.resize(padded_len, 0);

    for entry in entries {
        let encrypted = encrypt_entry_data_v1(
            &entry.image_data,
            salt,
            &entry.name,
            &entry.entry_key,
            Some(entry.aligned_size()),
        );
        output.extend_from_slice(&encrypted);
    }

    Ok(output)
}

// ── ChaCha20 stream writer (for v2 entry table encryption) ──────────
//
// Exact mirror of `ChaCha20StreamReader`: encrypts in 64-byte blocks,
// resets the counter when a write_bytes call ends with the buffer just flushed.

struct ChaCha20StreamWriter {
    output: Vec<u8>,
    buffer: [u8; CHACHA_BLOCK_SIZE],
    buf_pos: usize,
    cipher: ChaCha20,
}

impl ChaCha20StreamWriter {
    fn new(key: &[u8; CHACHA_KEY_LEN], nonce: &[u8; CHACHA_NONCE_LEN]) -> Self {
        Self {
            output: Vec::new(),
            buffer: [0u8; CHACHA_BLOCK_SIZE],
            buf_pos: 0,
            cipher: ChaCha20::new(key, nonce, 0),
        }
    }

    fn write_bytes(&mut self, data: &[u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let space = CHACHA_BLOCK_SIZE - self.buf_pos;
            let n = (data.len() - offset).min(space);
            self.buffer[self.buf_pos..self.buf_pos + n].copy_from_slice(&data[offset..offset + n]);
            self.buf_pos += n;
            offset += n;

            if self.buf_pos >= CHACHA_BLOCK_SIZE {
                self.cipher.process(&mut self.buffer);
                self.output.extend_from_slice(&self.buffer);
                self.buffer = [0u8; CHACHA_BLOCK_SIZE];
                self.buf_pos = 0;
            }
        }

        // Mirror ChaCha20StreamReader: reset counter when write ends with buffer just flushed
        if self.buf_pos == 0 && !data.is_empty() {
            self.cipher.reset_counter();
        }
    }

    fn write_i32(&mut self, val: i32) {
        self.write_bytes(&val.to_le_bytes());
    }

    /// Write a length-prefixed UTF-16LE string (mirrors `ChaCha20StreamReader::read_string`)
    fn write_string(&mut self, s: &str) {
        let utf16: Vec<u16> = s.encode_utf16().collect();
        self.write_i32(utf16.len() as i32);
        let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        self.write_bytes(&bytes);
    }

    /// Flush any partial block (pad with zeros, encrypt, append) and return the output.
    fn finish(mut self) -> Vec<u8> {
        if self.buf_pos > 0 {
            self.cipher.process(&mut self.buffer);
            self.output.extend_from_slice(&self.buffer);
        }
        self.output
    }
}

// ── V2 entry data encryption ────────────────────────────────────────

fn encrypt_entry_data_v2(
    data: &[u8],
    salt: &str,
    entry_name: &str,
    entry_key: &[u8; 16],
    size_aligned: Option<usize>,
) -> Vec<u8> {
    let img_key = derive_img_key_v2(salt, entry_name, entry_key);
    let (nonce, counter) = derive_img_nonce_counter(salt);

    let aligned_size = size_aligned.unwrap_or_else(|| align_to_block(data.len()));
    let mut buffer = vec![0u8; aligned_size];
    buffer[..data.len()].copy_from_slice(data);

    // Only encrypt first min(size, 1024) bytes, rounded up to ChaCha20 block boundary
    let crypted_size = data.len().min(DOUBLE_ENCRYPT_BYTES);
    let encrypt_len = (crypted_size + CHACHA_BLOCK_SIZE - 1) & !(CHACHA_BLOCK_SIZE - 1);
    let encrypt_len = encrypt_len.min(buffer.len());
    ChaCha20::new(&img_key, &nonce, counter).process(&mut buffer[..encrypt_len]);

    buffer
}

// ── V2 salt encoding ────────────────────────────────────────────────

/// Reverse of the v2 salt decode transform.
/// Given a desired salt character, find a value `a` such that
/// `((a | 0x4B) << 1) - a - 75` truncated to u8 equals `c`.
fn v2_encode_salt_value(c: u8) -> u8 {
    for a in 0u16..=255 {
        let a8 = a as u8;
        let val = (((a8 as i32 | 0x4B) << 1) - a8 as i32 - 75) as u8;
        if val == c {
            return a8;
        }
    }
    c
}

fn v2_encode_salt(salt: &str, shifted_rand: &[u8]) -> (Vec<u8>, i32, i32) {
    let salt_len = salt.len();
    let hashed_salt_len = (salt_len as u8 ^ shifted_rand[0]) as i32;

    let mut raw_salt_bytes = Vec::with_capacity(salt_len * 2);
    let mut salt_u16_sum: i32 = 0;

    for (i, c) in salt.bytes().enumerate() {
        let a = v2_encode_salt_value(c);
        let lo = a ^ shifted_rand[i];
        // High byte is sign extension of lo (matches original MapleStory encoder)
        let hi = if (lo as i8) < 0 { 0xFFu8 } else { 0x00u8 };
        raw_salt_bytes.push(lo);
        raw_salt_bytes.push(hi);
        salt_u16_sum += u16::from_le_bytes([lo, hi]) as i32;
    }

    (raw_salt_bytes, hashed_salt_len, salt_u16_sum)
}

// ── V2 from-scratch file builder ────────────────────────────────────

fn build_ms_file_v2(file_name: &str, salt: &str, entries: &[MsSaveEntry]) -> WzResult<Vec<u8>> {
    let file_name_lower = file_name.to_lowercase();
    let mut output = Vec::new();

    let rand_bytes = generate_rand_bytes(rand_byte_count(&file_name_lower));
    let shifted_rand: Vec<u8> = rand_bytes.iter().map(|&b| ((b as i8) >> 1) as u8).collect();

    output.extend_from_slice(&rand_bytes);

    let raw_version_byte = MS_VERSION_V2 ^ shifted_rand[0];
    output.push(raw_version_byte);

    let (raw_salt_bytes, hashed_salt_len, salt_u16_sum) = v2_encode_salt(salt, &shifted_rand);
    write_i32_le(&mut output, hashed_salt_len);
    output.extend_from_slice(&raw_salt_bytes);

    let file_name_with_salt = format!("{}{}", file_name_lower, salt);

    let header_hash = hashed_salt_len
        + raw_version_byte as i32
        + MS_VERSION_V2 as i32
        + entries.len() as i32
        + salt_u16_sum;

    let mut header_block = [0u8; CHACHA_BLOCK_SIZE];
    header_block[0..4].copy_from_slice(&header_hash.to_le_bytes());
    header_block[4..8].copy_from_slice(&(entries.len() as i32).to_le_bytes());
    let header_key = derive_chacha_key(&file_name_with_salt, false);
    let empty_nonce = [0u8; CHACHA_NONCE_LEN];
    ChaCha20::new(&header_key, &empty_nonce, 0).process(&mut header_block);
    output.extend_from_slice(&header_block);

    // entry_start = header_pos + 8 + pad + 64 (block), so inter-pad = 8 + pad
    let epa = entry_pad_amount(&file_name_lower);
    let inter_pad_len = 8 + epa;
    output.extend(std::iter::repeat(0u8).take(inter_pad_len));

    let entry_key_chacha = derive_chacha_key(&file_name_with_salt, true);
    let mut writer = ChaCha20StreamWriter::new(&entry_key_chacha, &empty_nonce);
    let mut block_offset: usize = 0;

    for entry in entries {
        let aligned_size = entry.aligned_size();
        let block_idx = block_offset / BLOCK_ALIGNMENT;
        let ek_sum: i32 = entry.entry_key.iter().map(|&b| b as i32).sum();
        let flags: i32 = 0;
        let unk1: i32 = 0;
        let unk2: i32 = 0;
        let checksum = flags
            + block_idx as i32
            + entry.image_data.len() as i32
            + aligned_size as i32
            + unk1
            + ek_sum;

        writer.write_string(&entry.name);
        writer.write_i32(checksum);
        writer.write_i32(flags);
        writer.write_i32(block_idx as i32);
        writer.write_i32(entry.image_data.len() as i32);
        writer.write_i32(aligned_size as i32);
        writer.write_i32(unk1);
        writer.write_i32(unk2);
        writer.write_bytes(&entry.entry_key);
        writer.write_i32(0); // unk3
        writer.write_i32(0); // unk4

        block_offset += aligned_size;
    }
    let encrypted_entries = writer.finish();
    output.extend_from_slice(&encrypted_entries);

    let padded_len = align_to_block(output.len());
    output.resize(padded_len, 0);

    for entry in entries {
        let encrypted = encrypt_entry_data_v2(
            &entry.image_data,
            salt,
            &entry.name,
            &entry.entry_key,
            Some(entry.aligned_size()),
        );
        output.extend_from_slice(&encrypted);
    }

    Ok(output)
}

// ── Unified public builder ───────────────────────────────────────────

pub fn build_ms_file(
    file_name: &str,
    salt: &str,
    entries: &[MsSaveEntry],
    version: MsVersion,
) -> WzResult<Vec<u8>> {
    match version {
        MsVersion::V1 => build_ms_file_v1(file_name, salt, entries),
        MsVersion::V2 => build_ms_file_v2(file_name, salt, entries),
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── V1 key derivation tests ─────────────────────────────────

    #[test]
    fn test_derive_snow_key_header() {
        let key = derive_snow_key("test.ms_salt", false);
        assert_eq!(key.len(), 16);
        assert_eq!(key[0], b't');
        assert_eq!(key[1], b'e' + 1);
    }

    #[test]
    fn test_derive_snow_key_entry() {
        let key = derive_snow_key("test.ms_salt", true);
        assert_eq!(key.len(), 16);
        assert_eq!(key[0], 2u8.wrapping_mul(b't'));
    }

    #[test]
    fn test_derive_img_key_v1_deterministic() {
        let ek = [1u8; 16];
        let k1 = derive_img_key_v1("salt", "Mob/test.img", &ek);
        let k2 = derive_img_key_v1("salt", "Mob/test.img", &ek);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_img_key_v1_differs_by_salt() {
        let ek = [0u8; 16];
        let k1 = derive_img_key_v1("aaa", "Mob/test.img", &ek);
        let k2 = derive_img_key_v1("bbb", "Mob/test.img", &ek);
        assert_ne!(k1, k2);
    }

    // ── V2 key derivation tests ─────────────────────────────────

    #[test]
    fn test_derive_chacha_key_has_obscure_xor() {
        let key = derive_chacha_key("test.ms_salt", false);
        assert_eq!(key.len(), 32);
        // Without obscure: key[0] = 't' + 0 = 0x74. With obscure: 0x74 ^ 0x7B = 0x0F
        assert_eq!(key[0], b't' ^ CHACHA20_KEY_OBSCURE[0]);
    }

    #[test]
    fn test_derive_img_key_v2_is_32_bytes() {
        let ek = [1u8; 16];
        let key = derive_img_key_v2("salt", "Mob/test.img", &ek);
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_derive_img_nonce_counter_deterministic() {
        let (n1, c1) = derive_img_nonce_counter("salt_a");
        let (n2, c2) = derive_img_nonce_counter("salt_a");
        assert_eq!(n1, n2);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_derive_img_nonce_counter_differs_by_salt() {
        let (n1, c1) = derive_img_nonce_counter("salt_a");
        let (n2, c2) = derive_img_nonce_counter("salt_b");
        assert!(n1 != n2 || c1 != c2);
    }

    // ── ChaCha20 stream reader tests ────────────────────────────

    #[test]
    fn test_chacha20_stream_reader_basic() {
        let key = [0x42u8; CHACHA_KEY_LEN];
        let nonce = [0u8; CHACHA_NONCE_LEN];

        // Create 128 bytes of "encrypted" data (2 blocks)
        let mut raw_data = vec![0xABu8; 128];

        // Encrypt it the same way the reader will decrypt
        let mut cipher = ChaCha20::new(&key, &nonce, 0);
        cipher.process(&mut raw_data[..64]);
        cipher.reset_counter();
        cipher.process(&mut raw_data[64..128]);

        let mut reader = ChaCha20StreamReader::new(&raw_data, &key, &nonce);

        // Read 64 bytes — should all be 0xAB
        let result = reader.read_bytes(64).unwrap();
        assert!(result.iter().all(|&b| b == 0xAB));

        // Second block
        let result2 = reader.read_bytes(64).unwrap();
        assert!(result2.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_chacha20_stream_reader_i32() {
        let key = [0u8; CHACHA_KEY_LEN];
        let nonce = [0u8; CHACHA_NONCE_LEN];

        // Encrypt the value 42 as i32 LE, padded to 64 bytes
        let mut block = [0u8; 64];
        block[0..4].copy_from_slice(&42i32.to_le_bytes());
        ChaCha20::new(&key, &nonce, 0).process(&mut block);

        let mut reader = ChaCha20StreamReader::new(&block, &key, &nonce);
        assert_eq!(reader.read_i32().unwrap(), 42);
    }

    // ── V1 Snow2 double-decrypt roundtrip ───────────────────────

    #[test]
    fn test_snow2_double_decrypt_roundtrip() {
        let key = [0x42u8; 16];
        let original = vec![0xABu8; 2048];
        let mut encrypted = original.clone();

        Snow2::new(&key, &[], true).process(&mut encrypted[..1024]);
        Snow2::new(&key, &[], true).process(&mut encrypted);

        Snow2::new(&key, &[], false).process(&mut encrypted);
        Snow2::new(&key, &[], false).process(&mut encrypted[..1024]);

        assert_eq!(encrypted, original);
    }

    #[test]
    fn test_parse_ms_file_too_small() {
        let result = parse_ms_file(&[0u8; 10], "test.ms");
        assert!(result.is_err());
    }

    // ── V1 encrypt/decrypt roundtrip ────────────────────────────

    #[test]
    fn test_encrypt_decrypt_entry_roundtrip() {
        let original = vec![0x73u8; 2048];
        let salt = "testsalt";
        let name = "Mob/test.img";
        let entry_key = [0x42u8; 16];

        let encrypted = encrypt_entry_data(&original, salt, name, &entry_key, MsVersion::V1);
        assert_ne!(&encrypted[..original.len()], &original[..]);

        let img_key = derive_img_key_v1(salt, name, &entry_key);
        let mut decrypted = encrypted;
        Snow2::new(&img_key, &[], false).process(&mut decrypted);
        let double_len = decrypted.len().min(DOUBLE_ENCRYPT_BYTES);
        Snow2::new(&img_key, &[], false).process(&mut decrypted[..double_len]);

        assert_eq!(&decrypted[..original.len()], &original[..]);
    }

    // ── V1 save/parse roundtrip ─────────────────────────────────

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
            original_size: None,
        }];

        let saved = build_ms_file(file_name, salt, &entries, MsVersion::V1).unwrap();
        let parsed = parse_ms_file(&saved, file_name).unwrap();

        assert_eq!(parsed.version, MsVersion::V1);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "Mob/0100.img");
        assert_eq!(parsed.entries[0].size, image_data.len());

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
                original_size: None,
            },
            MsSaveEntry {
                name: "Npc/shop.img".into(),
                image_data: vec![0x73; 1500],
                entry_key: [0x33; 16],
                original_size: None,
            },
        ];

        let saved = build_ms_file(file_name, salt, &entries, MsVersion::V1).unwrap();
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

    // ── V2 entry decryption roundtrip ───────────────────────────

    #[test]
    fn test_v2_decrypt_entry_roundtrip() {
        let salt = "test_v2_salt";
        let entry_name = "Mob/test.img";
        let entry_key = [0x55u8; 16];
        let original = vec![0x73u8; 200];

        // Encrypt like v2: only first min(size, 1024) bytes via ChaCha20
        let img_key = derive_img_key_v2(salt, entry_name, &entry_key);
        let (nonce, counter) = derive_img_nonce_counter(salt);
        let crypted_size = original.len().min(DOUBLE_ENCRYPT_BYTES);
        let decrypt_len = (crypted_size + CHACHA_BLOCK_SIZE - 1) & !(CHACHA_BLOCK_SIZE - 1);

        let mut encrypted = vec![0u8; decrypt_len];
        encrypted[..original.len()].copy_from_slice(&original);
        ChaCha20::new(&img_key, &nonce, counter).process(&mut encrypted);

        // Simulate file structure: just the encrypted data at offset 0
        let file = MsParsedFile {
            version: MsVersion::V2,
            salt: salt.into(),
            file_name_with_salt: String::new(),
            entries: vec![MsEntry {
                name: entry_name.into(),
                size: original.len(),
                size_aligned: decrypt_len,
                start_pos: 0,
                entry_key,
            }],
            data_start_pos: 0,
        };

        let decrypted = decrypt_entry_data(&encrypted, &file, 0).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_v2_decrypt_entry_large_plaintext_tail() {
        let salt = "big_salt";
        let entry_name = "Map/large.img";
        let entry_key = [0xAA; 16];
        let original = vec![0x42u8; 2048]; // > 1024 bytes

        let img_key = derive_img_key_v2(salt, entry_name, &entry_key);
        let (nonce, counter) = derive_img_nonce_counter(salt);

        // Only first 1024 bytes are encrypted; rest is plaintext
        let mut data_block = original.clone();
        // Pad first 1024 to 64-byte boundary (already aligned)
        ChaCha20::new(&img_key, &nonce, counter).process(&mut data_block[..DOUBLE_ENCRYPT_BYTES]);

        let file = MsParsedFile {
            version: MsVersion::V2,
            salt: salt.into(),
            file_name_with_salt: String::new(),
            entries: vec![MsEntry {
                name: entry_name.into(),
                size: original.len(),
                size_aligned: align_to_block(original.len()),
                start_pos: 0,
                entry_key,
            }],
            data_start_pos: 0,
        };

        let decrypted = decrypt_entry_data(&data_block, &file, 0).unwrap();
        assert_eq!(decrypted, original);
    }

    // ── FNV-1a test ─────────────────────────────────────────────

    #[test]
    fn test_fnv1a_u16_ascii() {
        // For ASCII-only strings, FNV over UTF-16 code units = FNV over bytes
        let h = fnv1a_u16("hello");
        let mut expected: u32 = FNV_OFFSET_BASIS;
        for &b in b"hello" {
            expected = (expected ^ b as u32).wrapping_mul(FNV_PRIME);
        }
        assert_eq!(h, expected);
    }

    // ── V2 encrypt/decrypt entry roundtrip ────────────────────

    #[test]
    fn test_v2_encrypt_decrypt_entry_roundtrip() {
        let salt = "test_salt";
        let entry_name = "Mob/test.img";
        let entry_key = [0x55u8; 16];
        let original = vec![0x73u8; 200];

        let encrypted = encrypt_entry_data_v2(&original, salt, entry_name, &entry_key, None);
        assert_ne!(&encrypted[..original.len()], &original[..]);

        let file = MsParsedFile {
            version: MsVersion::V2,
            salt: salt.into(),
            file_name_with_salt: String::new(),
            entries: vec![MsEntry {
                name: entry_name.into(),
                size: original.len(),
                size_aligned: encrypted.len(),
                start_pos: 0,
                entry_key,
            }],
            data_start_pos: 0,
        };

        let decrypted = decrypt_entry_data(&encrypted, &file, 0).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_v2_encrypt_decrypt_large_entry() {
        let salt = "big_salt";
        let entry_name = "Map/large.img";
        let entry_key = [0xAA; 16];
        let original = vec![0x42u8; 2048];

        let encrypted = encrypt_entry_data_v2(&original, salt, entry_name, &entry_key, None);

        let file = MsParsedFile {
            version: MsVersion::V2,
            salt: salt.into(),
            file_name_with_salt: String::new(),
            entries: vec![MsEntry {
                name: entry_name.into(),
                size: original.len(),
                size_aligned: encrypted.len(),
                start_pos: 0,
                entry_key,
            }],
            data_start_pos: 0,
        };

        let decrypted = decrypt_entry_data(&encrypted, &file, 0).unwrap();
        assert_eq!(decrypted, original);
    }

    // ── ChaCha20 stream writer roundtrip ──────────────────────

    #[test]
    fn test_chacha20_stream_writer_reader_roundtrip() {
        let key = [0x42u8; CHACHA_KEY_LEN];
        let nonce = [0u8; CHACHA_NONCE_LEN];

        let mut writer = ChaCha20StreamWriter::new(&key, &nonce);
        writer.write_string("Mob/0100000.img");
        writer.write_i32(42);
        writer.write_i32(0);
        writer.write_bytes(&[0xAB; 16]);
        writer.write_i32(99);
        writer.write_i32(100);
        let encrypted = writer.finish();

        let mut reader = ChaCha20StreamReader::new(&encrypted, &key, &nonce);
        assert_eq!(reader.read_string().unwrap(), "Mob/0100000.img");
        assert_eq!(reader.read_i32().unwrap(), 42);
        assert_eq!(reader.read_i32().unwrap(), 0);
        let bytes = reader.read_bytes(16).unwrap();
        assert!(bytes.iter().all(|&b| b == 0xAB));
        assert_eq!(reader.read_i32().unwrap(), 99);
        assert_eq!(reader.read_i32().unwrap(), 100);
    }

    // ── V2 from-scratch build + parse roundtrip ──────────────

    #[test]
    fn test_build_ms_file_v2_roundtrip() {
        let file_name = "test_v2.ms";
        let salt = "abcdef";
        let image_data = vec![0x73u8, 0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04];
        let entry_key = [0x11u8; 16];

        let entries = vec![MsSaveEntry {
            name: "Mob/0100.img".into(),
            image_data: image_data.clone(),
            entry_key,
            original_size: None,
        }];

        let saved = build_ms_file(file_name, salt, &entries, MsVersion::V2).unwrap();
        let parsed = parse_ms_file(&saved, file_name).unwrap();

        assert_eq!(parsed.version, MsVersion::V2);
        assert_eq!(parsed.entries.len(), 1);
        assert_eq!(parsed.entries[0].name, "Mob/0100.img");
        assert_eq!(parsed.entries[0].size, image_data.len());

        let decrypted = decrypt_entry_data(&saved, &parsed, 0).unwrap();
        assert_eq!(&decrypted[..image_data.len()], &image_data[..]);
    }

    #[test]
    fn test_build_ms_file_v2_multiple_entries() {
        let file_name = "multi_v2.ms";
        let salt = "xyz123";

        let entries = vec![
            MsSaveEntry {
                name: "Map/town.img".into(),
                image_data: vec![0x73; 500],
                entry_key: [0x22; 16],
                original_size: None,
            },
            MsSaveEntry {
                name: "Npc/shop.img".into(),
                image_data: vec![0x73; 1500],
                entry_key: [0x33; 16],
                original_size: None,
            },
            MsSaveEntry {
                name: "Mob/boss.img".into(),
                image_data: vec![0x42; 3000],
                entry_key: [0x44; 16],
                original_size: None,
            },
        ];

        let saved = build_ms_file(file_name, salt, &entries, MsVersion::V2).unwrap();
        let parsed = parse_ms_file(&saved, file_name).unwrap();

        assert_eq!(parsed.version, MsVersion::V2);
        assert_eq!(parsed.entries.len(), 3);

        for i in 0..3 {
            assert_eq!(parsed.entries[i].name, entries[i].name);
            assert_eq!(parsed.entries[i].size, entries[i].image_data.len());
            let decrypted = decrypt_entry_data(&saved, &parsed, i).unwrap();
            assert_eq!(
                &decrypted[..entries[i].image_data.len()],
                &entries[i].image_data[..]
            );
        }
    }

    // ── V2 salt encoding roundtrip ────────────────────────

    #[test]
    fn test_v2_salt_encode_decode_roundtrip() {
        let salt = "hello_world_test";
        let shifted_rand: Vec<u8> = (0..salt.len())
            .map(|i| ((i as u32 * 37 + 13) & 0xFF) as u8)
            .collect();

        let (raw_salt_bytes, _, _) = v2_encode_salt(salt, &shifted_rand);

        // Decode using the same transform as parse_ms_file_v2
        let decoded: String = (0..salt.len())
            .map(|i| {
                let a = (shifted_rand[i] ^ raw_salt_bytes[i * 2]) as i32;
                let b = ((a | 0x4B) << 1) - a - 75;
                char::from(b as u8)
            })
            .collect();

        assert_eq!(decoded, salt);
    }

    #[test]
    fn test_v2_salt_encode_all_printable_ascii() {
        // Verify encoding works for all printable ASCII chars
        for c in 32u8..=126 {
            let a = v2_encode_salt_value(c);
            let val = (((a as i32 | 0x4B) << 1) - a as i32 - 75) as u8;
            assert_eq!(val, c, "Failed to encode ASCII {}", c);
        }
    }
}

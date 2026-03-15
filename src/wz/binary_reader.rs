//! WZ binary reader — reads encrypted strings, compressed ints, and offsets.
//!
//! Ported from MapleLib's `WzBinaryReader.cs`.

use std::io::{Read, Seek, SeekFrom};

use super::error::{WzError, WzResult};
use super::header::WzHeader;
use super::keys::WzKey;
use crate::crypto::constants::WZ_OFFSET_CONSTANT;

pub struct WzBinaryReader<R: Read + Seek> {
    reader: R,
    pub wz_key: WzKey,
    pub hash: u32,
    pub header: WzHeader,
    pub start_offset: u64,
}

impl<R: Read + Seek> WzBinaryReader<R> {
    pub fn new(reader: R, iv: [u8; 4], header: WzHeader, start_offset: u64) -> Self {
        WzBinaryReader {
            reader,
            wz_key: WzKey::new(iv),
            hash: 0,
            header,
            start_offset,
        }
    }

    pub fn position(&mut self) -> WzResult<u64> {
        Ok(self.reader.stream_position()?)
    }

    pub fn seek(&mut self, pos: u64) -> WzResult<()> {
        self.reader.seek(SeekFrom::Start(pos))?;
        Ok(())
    }

    pub fn available(&mut self) -> WzResult<u64> {
        let pos = self.position()?;
        let end = self.header.data_start as u64 + self.header.file_size;
        Ok(end.saturating_sub(pos))
    }

    // ── Primitive reads ──────────────────────────────────────────────

    pub fn read_u8(&mut self) -> WzResult<u8> {
        let mut buf = [0u8; 1];
        self.reader.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    pub fn read_i8(&mut self) -> WzResult<i8> {
        Ok(self.read_u8()? as i8)
    }

    pub fn read_u16(&mut self) -> WzResult<u16> {
        let mut buf = [0u8; 2];
        self.reader.read_exact(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    pub fn read_i16(&mut self) -> WzResult<i16> {
        let mut buf = [0u8; 2];
        self.reader.read_exact(&mut buf)?;
        Ok(i16::from_le_bytes(buf))
    }

    pub fn read_u32(&mut self) -> WzResult<u32> {
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    pub fn read_i32(&mut self) -> WzResult<i32> {
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }

    pub fn read_i64(&mut self) -> WzResult<i64> {
        let mut buf = [0u8; 8];
        self.reader.read_exact(&mut buf)?;
        Ok(i64::from_le_bytes(buf))
    }

    pub fn read_f32(&mut self) -> WzResult<f32> {
        let mut buf = [0u8; 4];
        self.reader.read_exact(&mut buf)?;
        Ok(f32::from_le_bytes(buf))
    }

    pub fn read_f64(&mut self) -> WzResult<f64> {
        let mut buf = [0u8; 8];
        self.reader.read_exact(&mut buf)?;
        Ok(f64::from_le_bytes(buf))
    }

    pub fn read_bytes(&mut self, len: usize) -> WzResult<Vec<u8>> {
        // Prevent OOM panics (which become WASM `unreachable` traps) from
        // corrupted size values. No single WZ property should exceed 256 MB.
        const MAX_READ: usize = 256 * 1024 * 1024;
        if len > MAX_READ {
            return Err(WzError::Custom(format!(
                "Read request too large: {} bytes (max {})",
                len, MAX_READ
            )));
        }
        let mut buf = vec![0u8; len];
        self.reader.read_exact(&mut buf)?;
        Ok(buf)
    }

    // ── WZ-specific compressed reads ─────────────────────────────────

    pub fn read_compressed_int(&mut self) -> WzResult<i32> {
        let indicator = self.read_i8()?;
        if indicator == -128 {
            self.read_i32()
        } else {
            Ok(indicator as i32)
        }
    }

    pub fn read_compressed_long(&mut self) -> WzResult<i64> {
        let indicator = self.read_i8()?;
        if indicator == -128 {
            self.read_i64()
        } else {
            Ok(indicator as i64)
        }
    }

    // ── WZ encrypted string reads ────────────────────────────────────

    pub fn read_wz_string(&mut self) -> WzResult<String> {
        let indicator = self.read_i8()?;

        if indicator >= 0 {
            // Unicode string
            self.read_wz_unicode_string(indicator)
        } else {
            // ASCII string
            self.read_wz_ascii_string(indicator)
        }
    }

    fn read_wz_unicode_string(&mut self, indicator: i8) -> WzResult<String> {
        const MAX_STRING_LEN: usize = 1024 * 1024; // prevent OOM from corrupted data

        let length = if indicator == 127 {
            let len = self.read_i32()?;
            if len <= 0 {
                return Ok(String::new());
            }
            len as usize
        } else {
            indicator as usize
        };

        if length == 0 {
            return Ok(String::new());
        }

        if length > MAX_STRING_LEN {
            return Err(WzError::Custom(format!(
                "Unicode string length too large: {}",
                length
            )));
        }

        self.wz_key.ensure_size(length * 2);

        let mut chars = Vec::with_capacity(length);
        let mut mask: u16 = 0xAAAA;

        for i in 0..length {
            let encrypted = self.read_u16()?;
            let key_lo = self.wz_key[i * 2] as u16;
            let key_hi = self.wz_key[i * 2 + 1] as u16;
            let key_word = key_lo | (key_hi << 8);

            let decrypted = encrypted ^ mask ^ key_word;
            mask = mask.wrapping_add(1);
            chars.push(decrypted);
        }

        Ok(String::from_utf16_lossy(&chars))
    }

    fn read_wz_ascii_string(&mut self, indicator: i8) -> WzResult<String> {
        const MAX_STRING_LEN: usize = 1024 * 1024;

        let length = if indicator == -128 {
            let len = self.read_i32()?;
            if len <= 0 {
                return Ok(String::new());
            }
            len as usize
        } else {
            -(indicator as i32) as usize
        };

        if length == 0 {
            return Ok(String::new());
        }

        if length > MAX_STRING_LEN {
            return Err(WzError::Custom(format!(
                "ASCII string length too large: {}",
                length
            )));
        }

        self.wz_key.ensure_size(length);

        let mut bytes = self.read_bytes(length)?;
        let mut mask: u8 = 0xAA;

        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte ^= mask;
            *byte ^= self.wz_key[i];
            mask = mask.wrapping_add(1);
        }

        Ok(String::from_utf8_lossy(&bytes).to_string())
    }

    // C#'s `ReadStringAtOffset()`: adjusts by start_offset for embedded sub-files.
    pub fn read_string_at_offset(&mut self, offset: u64) -> WzResult<String> {
        let saved = self.position()?;
        self.seek(offset - self.start_offset)?;
        let s = self.read_wz_string()?;
        self.seek(saved)?;
        Ok(s)
    }

    // Type byte: 0x00|0x73 = inline string, 0x01|0x1B = string at offset, else empty
    pub fn read_string_block(&mut self, offset: u64) -> WzResult<String> {
        let type_byte = self.read_u8()?;
        match type_byte {
            0x00 | 0x73 => self.read_wz_string(),
            0x01 | 0x1B => {
                let str_offset = self.read_i32()?;
                self.read_string_at_offset(offset.wrapping_add(str_offset as i64 as u64))
            }
            _ => Ok(String::new()),
        }
    }

    // ── WZ offset decryption ─────────────────────────────────────────

    pub fn read_wz_offset(&mut self) -> WzResult<u64> {
        let cur_pos = self.position()? as u32;
        let fstart = self.header.data_start;

        let mut offset = (cur_pos.wrapping_sub(fstart)) ^ 0xFFFF_FFFF;
        offset = offset.wrapping_mul(self.hash);
        offset = offset.wrapping_sub(WZ_OFFSET_CONSTANT);
        offset = offset.rotate_left(offset & 0x1F);

        let encrypted = self.read_u32()?;
        offset ^= encrypted;
        offset = offset.wrapping_add(fstart.wrapping_mul(2));

        Ok(offset as u64 + self.start_offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_reader(data: Vec<u8>) -> WzBinaryReader<Cursor<Vec<u8>>> {
        let header = WzHeader {
            ident: "PKG1".to_string(),
            file_size: data.len() as u64,
            data_start: 0,
            copyright: String::new(),
        };
        WzBinaryReader::new(Cursor::new(data), [0; 4], header, 0)
    }

    fn make_reader_with_header(
        data: Vec<u8>,
        data_start: u32,
        file_size: u64,
    ) -> WzBinaryReader<Cursor<Vec<u8>>> {
        let header = WzHeader {
            ident: "PKG1".to_string(),
            file_size,
            data_start,
            copyright: String::new(),
        };
        WzBinaryReader::new(Cursor::new(data), [0; 4], header, 0)
    }

    /// Encode an ASCII string as WZ would store it with BMS zero-key IV.
    /// Returns bytes: [indicator_byte, ...encrypted_bytes]
    fn encode_wz_ascii(s: &str) -> Vec<u8> {
        let len = s.len();
        assert!(len > 0 && len < 128);
        let indicator = -(len as i8);
        let mut out = vec![indicator as u8];
        let mut mask: u8 = 0xAA;
        for b in s.bytes() {
            out.push(b ^ mask); // key[i] = 0 for BMS IV
            mask = mask.wrapping_add(1);
        }
        out
    }

    /// Encode a Unicode string as WZ would store it with BMS zero-key IV.
    /// Returns bytes: [indicator_byte, ...encrypted_u16_le_pairs]
    fn encode_wz_unicode(s: &str) -> Vec<u8> {
        let chars: Vec<u16> = s.encode_utf16().collect();
        let len = chars.len();
        assert!(len > 0 && len < 127);
        let mut out = vec![len as u8]; // positive indicator = unicode
        let mut mask: u16 = 0xAAAA;
        for ch in &chars {
            let encrypted = ch ^ mask; // key_word = 0 for BMS IV
            out.extend_from_slice(&encrypted.to_le_bytes());
            mask = mask.wrapping_add(1);
        }
        out
    }

    // ── Compressed int (existing) ──────────────────────────────────

    #[test]
    fn test_read_compressed_int_small() {
        let mut reader = make_reader(vec![42]); // indicator = 42
        assert_eq!(reader.read_compressed_int().unwrap(), 42);
    }

    #[test]
    fn test_read_compressed_int_large() {
        let mut data = vec![0x80u8]; // indicator = -128 → read i32
        data.extend_from_slice(&1000i32.to_le_bytes());
        let mut reader = make_reader(data);
        assert_eq!(reader.read_compressed_int().unwrap(), 1000);
    }

    #[test]
    fn test_read_compressed_int_negative() {
        let mut reader = make_reader(vec![0xFE]); // -2 as i8
        assert_eq!(reader.read_compressed_int().unwrap(), -2);
    }

    // ── Compressed long ────────────────────────────────────────────

    #[test]
    fn test_read_compressed_long_small() {
        let mut reader = make_reader(vec![42]);
        assert_eq!(reader.read_compressed_long().unwrap(), 42i64);
    }

    #[test]
    fn test_read_compressed_long_large() {
        let mut data = vec![0x80u8]; // indicator = -128 → read i64
        data.extend_from_slice(&999_999_999i64.to_le_bytes());
        let mut reader = make_reader(data);
        assert_eq!(reader.read_compressed_long().unwrap(), 999_999_999);
    }

    #[test]
    fn test_read_compressed_long_negative() {
        let mut reader = make_reader(vec![0xFDu8]); // -3 as i8
        assert_eq!(reader.read_compressed_long().unwrap(), -3i64);
    }

    // ── ASCII string (BMS zero-key) ────────────────────────────────

    #[test]
    fn test_read_wz_string_ascii_short() {
        // Encode "Hi" with BMS zero-key
        let data = encode_wz_ascii("Hi");
        let mut reader = make_reader(data);
        assert_eq!(reader.read_wz_string().unwrap(), "Hi");
    }

    #[test]
    fn test_read_wz_string_ascii_property() {
        let data = encode_wz_ascii("Property");
        let mut reader = make_reader(data);
        assert_eq!(reader.read_wz_string().unwrap(), "Property");
    }

    #[test]
    fn test_read_wz_string_ascii_long_indicator() {
        // indicator = -128 (0x80), then i32 length, then encrypted bytes
        let s = "TestLongString";
        let len = s.len() as i32;
        let mut data = vec![0x80u8];
        data.extend_from_slice(&len.to_le_bytes());
        let mut mask: u8 = 0xAA;
        for b in s.bytes() {
            data.push(b ^ mask);
            mask = mask.wrapping_add(1);
        }
        let mut reader = make_reader(data);
        assert_eq!(reader.read_wz_string().unwrap(), s);
    }

    // ── Unicode string (BMS zero-key) ──────────────────────────────

    #[test]
    fn test_read_wz_string_unicode_short() {
        let data = encode_wz_unicode("AB");
        let mut reader = make_reader(data);
        assert_eq!(reader.read_wz_string().unwrap(), "AB");
    }

    #[test]
    fn test_read_wz_string_unicode_single_char() {
        let data = encode_wz_unicode("X");
        let mut reader = make_reader(data);
        assert_eq!(reader.read_wz_string().unwrap(), "X");
    }

    // ── String block ───────────────────────────────────────────────

    #[test]
    fn test_read_string_block_inline_0x73() {
        // type=0x73 → inline WZ string
        let mut data = vec![0x73u8];
        data.extend_from_slice(&encode_wz_ascii("Hello"));
        let mut reader = make_reader(data);
        assert_eq!(reader.read_string_block(0).unwrap(), "Hello");
    }

    #[test]
    fn test_read_string_block_inline_0x00() {
        let mut data = vec![0x00u8];
        data.extend_from_slice(&encode_wz_ascii("Test"));
        let mut reader = make_reader(data);
        assert_eq!(reader.read_string_block(0).unwrap(), "Test");
    }

    #[test]
    fn test_read_string_block_unknown_type_returns_empty() {
        let data = vec![0xFFu8];
        let mut reader = make_reader(data);
        assert_eq!(reader.read_string_block(0).unwrap(), "");
    }

    #[test]
    fn test_read_string_block_offset_0x01() {
        // Layout: [type=0x01 at pos 0] [offset i32 at pos 1..5] [...padding...] [string at pos 10]
        // We set base_offset=0, and the i32 offset value = 10
        // So it reads string at position (0 + 10) - start_offset(0) = 10
        let target_str = encode_wz_ascii("AtOffset");
        let mut data = vec![0x01u8];
        data.extend_from_slice(&10i32.to_le_bytes()); // offset = 10
        // Pad to position 10
        while data.len() < 10 {
            data.push(0x00);
        }
        data.extend_from_slice(&target_str);
        let mut reader = make_reader(data);
        assert_eq!(reader.read_string_block(0).unwrap(), "AtOffset");
    }

    // ── Position / seek / available ────────────────────────────────

    #[test]
    fn test_position_starts_at_zero() {
        let mut reader = make_reader(vec![0; 10]);
        assert_eq!(reader.position().unwrap(), 0);
    }

    #[test]
    fn test_seek_and_position_roundtrip() {
        let mut reader = make_reader(vec![0; 100]);
        reader.seek(42).unwrap();
        assert_eq!(reader.position().unwrap(), 42);
        reader.seek(0).unwrap();
        assert_eq!(reader.position().unwrap(), 0);
    }

    #[test]
    fn test_available_full() {
        // file_size=100, data_start=0, pos=0 → available = 0+100-0 = 100
        let mut reader = make_reader_with_header(vec![0; 100], 0, 100);
        assert_eq!(reader.available().unwrap(), 100);
    }

    #[test]
    fn test_available_after_read() {
        let mut reader = make_reader_with_header(vec![0; 100], 0, 100);
        reader.read_u8().unwrap(); // consume 1 byte
        assert_eq!(reader.available().unwrap(), 99);
    }

    #[test]
    fn test_available_with_data_start() {
        // file_size=50, data_start=10, pos=0 → end = 10+50=60, available = 60-0=60
        let mut reader = make_reader_with_header(vec![0; 100], 10, 50);
        assert_eq!(reader.available().unwrap(), 60);
    }

    // ── WZ offset decryption ───────────────────────────────────────

    #[test]
    fn test_read_wz_offset_deterministic() {
        // Set up: data_start=60, hash=713421, position at byte 60
        // We need 4 bytes of encrypted offset data at position 60
        let fstart: u32 = 60;
        let hash: u32 = 713421;

        // Calculate expected intermediate values:
        // cur_pos = 60, offset = (60-60) ^ 0xFFFFFFFF = 0xFFFFFFFF
        // offset *= 713421 (wrapping) → some value
        // offset -= WZ_OFFSET_CONSTANT → some value
        // offset = rotate_left(offset, offset & 0x1F)
        // Then we pick encrypted=0 so offset ^= 0 is unchanged
        // offset += fstart * 2 = 120

        let mut offset: u32 = (fstart.wrapping_sub(fstart)) ^ 0xFFFF_FFFF;
        offset = offset.wrapping_mul(hash);
        offset = offset.wrapping_sub(WZ_OFFSET_CONSTANT);
        offset = offset.rotate_left(offset & 0x1F);
        let pre_xor = offset;
        // If encrypted_u32 = 0, final = pre_xor + fstart*2
        let expected = pre_xor.wrapping_add(fstart.wrapping_mul(2)) as u64;

        // Build data: 60 bytes of padding + 4 bytes of encrypted offset (0)
        let data = vec![0u8; 64];
        // encrypted u32 = 0 (already zero)

        let mut reader = make_reader_with_header(data.clone(), fstart, data.len() as u64);
        reader.hash = hash;
        reader.seek(fstart as u64).unwrap();
        let result = reader.read_wz_offset().unwrap();
        assert_eq!(result, expected);
    }
}

//! WZ binary writer — writes encrypted strings, compressed ints, and offsets.
//!
//! Ported from MapleLib's `WzBinaryWriter.cs`.

use std::collections::HashMap;
use std::io::{Seek, SeekFrom, Write};

use super::error::WzResult;
use super::header::WzHeader;
use super::keys::WzKey;
use crate::crypto::constants::WZ_OFFSET_CONSTANT;

pub struct WzBinaryWriter<W: Write + Seek> {
    pub(crate) writer: W,
    pub wz_key: WzKey,
    pub hash: u32,
    pub header: WzHeader,
    pub string_cache: HashMap<String, u32>,
}

impl<W: Write + Seek> WzBinaryWriter<W> {
    pub fn new(writer: W, iv: [u8; 4], header: WzHeader) -> Self {
        WzBinaryWriter {
            writer,
            wz_key: WzKey::new(iv),
            hash: 0,
            header,
            string_cache: HashMap::new(),
        }
    }

    pub fn position(&mut self) -> WzResult<u64> {
        Ok(self.writer.stream_position()?)
    }

    pub fn seek(&mut self, pos: u64) -> WzResult<()> {
        self.writer.seek(SeekFrom::Start(pos))?;
        Ok(())
    }

    // ── Primitive writes ─────────────────────────────────────────────

    pub fn write_u8(&mut self, val: u8) -> WzResult<()> {
        self.writer.write_all(&[val])?;
        Ok(())
    }

    pub fn write_i16(&mut self, val: i16) -> WzResult<()> {
        self.writer.write_all(&val.to_le_bytes())?;
        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> WzResult<()> {
        self.writer.write_all(&val.to_le_bytes())?;
        Ok(())
    }

    pub fn write_i32(&mut self, val: i32) -> WzResult<()> {
        self.writer.write_all(&val.to_le_bytes())?;
        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> WzResult<()> {
        self.writer.write_all(&val.to_le_bytes())?;
        Ok(())
    }

    pub fn write_i64(&mut self, val: i64) -> WzResult<()> {
        self.writer.write_all(&val.to_le_bytes())?;
        Ok(())
    }

    pub fn write_f32(&mut self, val: f32) -> WzResult<()> {
        self.writer.write_all(&val.to_le_bytes())?;
        Ok(())
    }

    pub fn write_f64(&mut self, val: f64) -> WzResult<()> {
        self.writer.write_all(&val.to_le_bytes())?;
        Ok(())
    }

    pub fn write_bytes(&mut self, data: &[u8]) -> WzResult<()> {
        self.writer.write_all(data)?;
        Ok(())
    }

    // ── Compressed writes ────────────────────────────────────────────

    pub fn write_compressed_int(&mut self, val: i32) -> WzResult<()> {
        if (-127..=127).contains(&val) && val != -128 {
            self.write_u8(val as u8)
        } else {
            self.write_u8(0x80)?; // -128 as i8
            self.write_i32(val)
        }
    }

    pub fn write_compressed_long(&mut self, val: i64) -> WzResult<()> {
        if (-127..=127).contains(&val) && val != -128 {
            self.write_u8(val as u8)
        } else {
            self.write_u8(0x80)?;
            self.write_i64(val)
        }
    }

    // ── Encrypted string writes ──────────────────────────────────────

    pub fn write_wz_string(&mut self, s: &str) -> WzResult<()> {
        if s.is_ascii() {
            self.write_wz_ascii_string(s)
        } else {
            self.write_wz_unicode_string(s)
        }
    }

    fn write_wz_unicode_string(&mut self, s: &str) -> WzResult<()> {
        let chars: Vec<u16> = s.encode_utf16().collect();
        let length = chars.len();

        if length >= 127 {
            self.write_u8(127)?; // sbyte.MaxValue
            self.write_i32(length as i32)?;
        } else {
            self.write_u8(length as u8)?;
        }

        self.wz_key.ensure_size(length * 2);
        let mut mask: u16 = 0xAAAA;

        for (i, &ch) in chars.iter().enumerate() {
            let key_lo = self.wz_key[i * 2] as u16;
            let key_hi = self.wz_key[i * 2 + 1] as u16;
            let key_word = key_lo | (key_hi << 8);

            let encrypted = ch ^ key_word ^ mask;
            mask = mask.wrapping_add(1);
            self.write_u16(encrypted)?;
        }

        Ok(())
    }

    fn write_wz_ascii_string(&mut self, s: &str) -> WzResult<()> {
        let bytes = s.as_bytes();
        let length = bytes.len();

        if length > 127 {
            self.write_u8(0x80)?; // -128 as i8
            self.write_i32(length as i32)?;
        } else {
            self.write_u8((-(length as i32)) as u8)?;
        }

        self.wz_key.ensure_size(length);
        let mut mask: u8 = 0xAA;

        for (i, &byte) in bytes.iter().enumerate() {
            let encrypted = byte ^ self.wz_key[i] ^ mask;
            mask = mask.wrapping_add(1);
            self.write_u8(encrypted)?;
        }

        Ok(())
    }

    // ── String caching writes ──────────────────────────────────────────

    /// Property names: `without_offset=0x00, with_offset=0x01`.
    /// Type strings:   `without_offset=0x73, with_offset=0x1B`.
    pub fn write_string_value(
        &mut self,
        s: &str,
        without_offset: u8,
        with_offset: u8,
    ) -> WzResult<()> {
        if s.len() > 4 {
            if let Some(&cached_offset) = self.string_cache.get(s) {
                self.write_u8(with_offset)?;
                return self.write_i32(cached_offset as i32);
            }
        }

        self.write_u8(without_offset)?;
        let str_offset = self.position()? as u32;
        self.write_wz_string(s)?;

        if !self.string_cache.contains_key(s) {
            self.string_cache.insert(s.to_string(), str_offset);
        }
        Ok(())
    }

    /// `entry_type`: 3 = directory, 4 = image.
    pub fn write_wz_object_value(&mut self, name: &str, entry_type: u8) -> WzResult<()> {
        let cache_key = format!("{}_{}", entry_type, name);

        if let Some(&cached_offset) = self.string_cache.get(&cache_key) {
            self.write_u8(0x02)?; // RetrieveStringFromOffset
            return self.write_i32(cached_offset as i32);
        }

        let str_offset = (self.position()? as u32).wrapping_sub(self.header.data_start);
        self.write_u8(entry_type)?;
        self.write_wz_string(name)?;
        self.string_cache.insert(cache_key, str_offset);
        Ok(())
    }

    pub fn write_null_terminated_string(&mut self, s: &str) -> WzResult<()> {
        self.write_bytes(s.as_bytes())?;
        self.write_u8(0)
    }

    // ── Offset encryption ────────────────────────────────────────────

    pub fn write_wz_offset(&mut self, value: u32) -> WzResult<()> {
        let cur_pos = self.position()? as u32;
        let fstart = self.header.data_start;

        let mut enc = (cur_pos.wrapping_sub(fstart)) ^ 0xFFFF_FFFF;
        enc = enc.wrapping_mul(self.hash);
        enc = enc.wrapping_sub(WZ_OFFSET_CONSTANT);
        enc = enc.rotate_left(enc & 0x1F);

        let write_val = enc ^ (value.wrapping_sub(fstart.wrapping_mul(2)));
        self.write_u32(write_val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wz::test_utils::{dummy_header, make_reader};
    use std::io::Cursor;

    fn make_writer() -> WzBinaryWriter<Cursor<Vec<u8>>> {
        WzBinaryWriter::new(Cursor::new(Vec::new()), [0; 4], dummy_header(0))
    }

    fn finish_writer(writer: WzBinaryWriter<Cursor<Vec<u8>>>) -> Vec<u8> {
        writer.writer.into_inner()
    }

    // ── write_string_value roundtrip ─────────────────────────────────

    #[test]
    fn test_write_string_value_inline() {
        let mut writer = make_writer();
        writer.write_string_value("Property", 0x73, 0x1B).unwrap();
        let data = finish_writer(writer);

        let mut reader = make_reader(data);
        // read_string_block at offset 0: type 0x73 → inline string
        let s = reader.read_string_block(0).unwrap();
        assert_eq!(s, "Property");
    }

    #[test]
    fn test_write_string_value_cached() {
        let mut writer = make_writer();
        // First write — inline (0x73)
        writer.write_string_value("Property", 0x73, 0x1B).unwrap();
        let first_end = writer.position().unwrap();
        // Second write — should use cache (0x1B + offset)
        writer.write_string_value("Property", 0x73, 0x1B).unwrap();
        let data = finish_writer(writer);

        let mut reader = make_reader(data);
        // First: inline
        let s1 = reader.read_string_block(0).unwrap();
        assert_eq!(s1, "Property");
        // Second: offset-based
        reader.seek(first_end).unwrap();
        let s2 = reader.read_string_block(0).unwrap();
        assert_eq!(s2, "Property");
    }

    #[test]
    fn test_write_string_value_short_string_no_cache() {
        let mut writer = make_writer();
        // Short strings (<= 4 bytes) are never cached
        writer.write_string_value("ab", 0x00, 0x01).unwrap();
        writer.write_string_value("ab", 0x00, 0x01).unwrap();
        let data = finish_writer(writer);

        let mut reader = make_reader(data);
        let s1 = reader.read_string_block(0).unwrap();
        assert_eq!(s1, "ab");
        let s2 = reader.read_string_block(0).unwrap();
        assert_eq!(s2, "ab");
    }

    // ── write_wz_object_value ────────────────────────────────────────

    #[test]
    fn test_write_wz_object_value_inline() {
        let mut writer = make_writer();
        writer.write_wz_object_value("test.img", 4).unwrap();
        let data = finish_writer(writer);

        // First byte should be the entry_type (4)
        assert_eq!(data[0], 4);
        // Rest is the encrypted WZ string for "test.img"
    }

    #[test]
    fn test_write_wz_object_value_cached() {
        let mut writer = make_writer();
        writer.write_wz_object_value("test.img", 4).unwrap();
        let pos_after_first = writer.position().unwrap();
        writer.write_wz_object_value("test.img", 4).unwrap();
        let data = finish_writer(writer);

        // Second entry should start with 0x02 (RetrieveStringFromOffset)
        assert_eq!(data[pos_after_first as usize], 0x02);
    }

    // ── write_null_terminated_string ─────────────────────────────────

    #[test]
    fn test_write_null_terminated_string() {
        let mut writer = make_writer();
        writer.write_null_terminated_string("hello").unwrap();
        let data = finish_writer(writer);
        assert_eq!(&data, &[b'h', b'e', b'l', b'l', b'o', 0]);
    }

    #[test]
    fn test_write_null_terminated_string_empty() {
        let mut writer = make_writer();
        writer.write_null_terminated_string("").unwrap();
        let data = finish_writer(writer);
        assert_eq!(&data, &[0]);
    }
}

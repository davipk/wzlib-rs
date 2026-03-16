//! Shared test utilities for WZ module tests.
//!
//! Consolidates duplicated helpers (make_reader, encode_wz_ascii, etc.)
//! that were previously copy-pasted across binary_reader, binary_writer,
//! directory, image, and image_writer test modules.

use std::io::Cursor;

use super::binary_reader::WzBinaryReader;
use super::header::WzHeader;

pub fn dummy_header(file_size: u64) -> WzHeader {
    WzHeader::dummy(file_size)
}

pub fn make_reader(data: Vec<u8>) -> WzBinaryReader<Cursor<Vec<u8>>> {
    let header = dummy_header(data.len() as u64);
    WzBinaryReader::new(Cursor::new(data), [0; 4], header, 0)
}

pub fn make_reader_with_header(
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
pub fn encode_wz_ascii(s: &str) -> Vec<u8> {
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
pub fn encode_wz_unicode(s: &str) -> Vec<u8> {
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

/// Compute the 4 encrypted LE bytes so `read_wz_offset` returns `desired`.
/// Assumes data_start=0, hash=0, start_offset=0.
pub fn encode_wz_offset(cur_pos: u32, desired: u32) -> [u8; 4] {
    use crate::crypto::constants::WZ_OFFSET_CONSTANT;
    let mut v = cur_pos ^ 0xFFFF_FFFF;
    v = v.wrapping_mul(0); // hash = 0
    v = v.wrapping_sub(WZ_OFFSET_CONSTANT);
    v = v.rotate_left(v & 0x1F);
    (v ^ desired).to_le_bytes()
}

/// Build a string block (type 0x73 + inline WZ ASCII string).
pub fn string_block(s: &str) -> Vec<u8> {
    let mut out = vec![0x73u8]; // inline type
    out.extend_from_slice(&encode_wz_ascii(s));
    out
}

/// Build a complete 0x73 "Property" image header (header_byte + "Property" string + u16(0)).
pub fn property_image_header() -> Vec<u8> {
    let mut out = vec![0x73u8]; // header byte
    out.extend_from_slice(&encode_wz_ascii("Property"));
    out.extend_from_slice(&0u16.to_le_bytes()); // val = 0
    out
}

/// Build a property image with a single property of the given name and raw value bytes.
pub fn build_image_with_property(name: &str, value_bytes: &[u8]) -> Vec<u8> {
    let mut data = property_image_header();
    data.push(1); // count = 1 (compressed int)
    data.extend_from_slice(&string_block(name)); // property name
    data.extend_from_slice(value_bytes); // type marker + value
    data
}

/// Build an extended property value: marker 0x09 + block_size + inner bytes.
pub fn build_extended_property(type_name: &str, inner_after_type: &[u8]) -> Vec<u8> {
    let mut inner = vec![0x73u8]; // inline type name
    inner.extend_from_slice(&encode_wz_ascii(type_name));
    inner.extend_from_slice(inner_after_type);

    let mut value = vec![0x09u8];
    value.extend_from_slice(&(inner.len() as u32).to_le_bytes()); // block_size
    value.extend_from_slice(&inner);
    value
}

//! List.wz parser — pre-Big Bang path index.
//!
//! List.wz uses a different format from standard WZ files: entries are stored
//! as `[i32 length][u16 chars × length][u16 null]` sequences. Each string is
//! XOR-encrypted with the WZ key but without the incremental mask used in
//! standard WZ string encoding.

use std::io::{Cursor, Read};

use super::error::WzResult;
use super::keys::WzKey;
use super::types::WzMapleVersion;

pub fn parse_list_file(data: &[u8], maple_version: WzMapleVersion) -> WzResult<Vec<String>> {
    parse_list_file_with_iv(data, maple_version.iv())
}

pub fn parse_list_file_with_iv(data: &[u8], iv: [u8; 4]) -> WzResult<Vec<String>> {
    parse_list_file_with_iv_and_user_key(data, iv, None)
}

pub fn parse_list_file_with_iv_and_user_key(
    data: &[u8],
    iv: [u8; 4],
    user_key: Option<[u8; 128]>,
) -> WzResult<Vec<String>> {
    let mut cursor = Cursor::new(data);
    let mut wz_key = match user_key {
        Some(uk) => WzKey::with_user_key(iv, uk),
        None => WzKey::new(iv),
    };
    let mut entries = Vec::new();
    let data_len = data.len() as u64;

    while cursor.position() + 4 <= data_len {
        let mut len_buf = [0u8; 4];
        cursor.read_exact(&mut len_buf)?;
        let len = i32::from_le_bytes(len_buf);

        if len <= 0 {
            break;
        }
        let len = len as usize;

        // Each char is 2 bytes + 2 bytes for the encrypted null terminator
        if cursor.position() + (len as u64 * 2 + 2) > data_len {
            break;
        }

        let mut chars = Vec::with_capacity(len);
        for _ in 0..len {
            let mut buf = [0u8; 2];
            cursor.read_exact(&mut buf)?;
            chars.push(u16::from_le_bytes(buf));
        }
        // Skip encrypted null terminator
        cursor.read_exact(&mut [0u8; 2])?;

        // Decrypt: XOR each char with key word (no incremental mask)
        wz_key.ensure_size(len * 2);
        for i in 0..len {
            let key_lo = wz_key[i * 2] as u16;
            let key_hi = wz_key[i * 2 + 1] as u16;
            chars[i] ^= key_lo | (key_hi << 8);
        }

        entries.push(String::from_utf16_lossy(&chars));
    }

    // C# replaces the last char of the last entry: '/' → 'g'
    if let Some(last) = entries.last_mut() {
        if last.ends_with('/') {
            last.pop();
            last.push('g');
        }
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_list_entry(text: &str, wz_key: &mut WzKey) -> Vec<u8> {
        let chars: Vec<u16> = text.encode_utf16().collect();
        let len = chars.len();
        wz_key.ensure_size(len * 2);

        let mut data = Vec::new();
        data.extend_from_slice(&(len as i32).to_le_bytes());
        for i in 0..len {
            let key_lo = wz_key[i * 2] as u16;
            let key_hi = wz_key[i * 2 + 1] as u16;
            let encrypted = chars[i] ^ (key_lo | (key_hi << 8));
            data.extend_from_slice(&encrypted.to_le_bytes());
        }
        data.extend_from_slice(&0u16.to_le_bytes()); // null terminator
        data
    }

    #[test]
    fn test_parse_single_entry() {
        let iv = [0u8; 4];
        let mut key = WzKey::new(iv);
        let data = build_list_entry("Character/00002000.img", &mut key);
        let entries = parse_list_file_with_iv(&data, iv).unwrap();
        assert_eq!(entries, vec!["Character/00002000.img"]);
    }

    #[test]
    fn test_parse_multiple_entries() {
        let iv = [0u8; 4];
        let mut key = WzKey::new(iv);
        let mut data = Vec::new();
        data.extend(build_list_entry("Character/00002000.img", &mut key));
        data.extend(build_list_entry("String/Eqp.img", &mut key));
        let entries = parse_list_file_with_iv(&data, iv).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], "Character/00002000.img");
        assert_eq!(entries[1], "String/Eqp.img");
    }

    #[test]
    fn test_last_entry_slash_replaced_with_g() {
        let iv = [0u8; 4];
        let mut key = WzKey::new(iv);
        let data = build_list_entry("path/file.im/", &mut key);
        let entries = parse_list_file_with_iv(&data, iv).unwrap();
        assert_eq!(entries[0], "path/file.img");
    }

    #[test]
    fn test_empty_data() {
        let entries = parse_list_file_with_iv(&[], [0; 4]).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_gms_iv() {
        let iv = [0x4D, 0x23, 0xC7, 0x2B];
        let mut key = WzKey::new(iv);
        let data = build_list_entry("Test/File.img", &mut key);
        let entries = parse_list_file_with_iv(&data, iv).unwrap();
        assert_eq!(entries[0], "Test/File.img");
    }

    #[test]
    fn test_ems_iv() {
        let iv = [0xB9, 0x7D, 0x63, 0xE9];
        let mut key = WzKey::new(iv);
        let data = build_list_entry("Map/Map0/000010000.img", &mut key);
        let entries = parse_list_file_with_iv(&data, iv).unwrap();
        assert_eq!(entries[0], "Map/Map0/000010000.img");
    }

    #[test]
    fn test_no_slash_replacement_when_not_trailing() {
        let iv = [0u8; 4];
        let mut key = WzKey::new(iv);
        let data = build_list_entry("no/slash/ending.img", &mut key);
        let entries = parse_list_file_with_iv(&data, iv).unwrap();
        assert_eq!(entries[0], "no/slash/ending.img");
    }
}

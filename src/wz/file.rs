//! WZ file — top-level entry point for parsing `.wz` files.
//!
//! Ported from MapleLib's `WzFile.cs`.

use std::io::{Cursor, Read, Seek};

use super::binary_reader::WzBinaryReader;
use super::directory::WzDirectoryEntry;
use super::error::{WzError, WzResult};
use super::header::WzHeader;
use super::image::parse_image;
use super::properties::WzProperty;
use super::types::WzMapleVersion;

const WZ_VERSION_HEADER_64BIT_START: u16 = 770;
const WZ_HEADER_MAGIC: [u8; 4] = *b"PKG1";
const WZ_IMAGE_HEADER_BYTE: u8 = 0x73;

// ── File type detection ─────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WzFileType {
    /// Standard WZ file with PKG1 header
    Standard,
    /// Hotfix Data.wz — starts with 0x73 (WzImage header byte), no PKG1 header
    HotfixDataWz,
    /// List.wz — pre-Big Bang path index, header is NOT PKG1
    ListFile,
}

pub fn detect_file_type(data: &[u8]) -> WzFileType {
    if data.len() >= 4 && data[0..4] == WZ_HEADER_MAGIC {
        WzFileType::Standard
    } else if !data.is_empty() && data[0] == WZ_IMAGE_HEADER_BYTE {
        WzFileType::HotfixDataWz
    } else {
        WzFileType::ListFile
    }
}

// ── Hotfix Data.wz parsing ──────────────────────────────────────────

/// Parses a hotfix Data.wz file (the entire file is a single WzImage, no PKG1 header).
pub fn parse_hotfix_data_wz(
    data: &[u8],
    maple_version: WzMapleVersion,
) -> WzResult<Vec<(String, WzProperty)>> {
    let iv = maple_version.iv();
    let header = WzHeader {
        ident: String::new(),
        file_size: data.len() as u64,
        data_start: 0,
        copyright: String::new(),
    };
    let cursor = Cursor::new(data);
    let mut reader = WzBinaryReader::new(cursor, iv, header, 0);
    parse_image(&mut reader)
}

pub struct WzFile {
    pub header: WzHeader,
    pub version: i16,
    pub version_hash: u32,
    pub maple_version: WzMapleVersion,
    pub is_64bit: bool,
    pub directory: WzDirectoryEntry,
}

impl WzFile {
    pub fn parse(
        data: &[u8],
        maple_version: WzMapleVersion,
        expected_version: Option<i16>,
    ) -> WzResult<Self> {
        let mut cursor = Cursor::new(data);
        let header = WzHeader::parse(&mut cursor)?;
        let iv = maple_version.iv();
        let mut reader = WzBinaryReader::new(cursor, iv, header.clone(), 0);
        let is_64bit = check_64bit_client(&mut reader)?;
        reader.seek(header.data_start as u64)?;

        let wz_version_header = if is_64bit {
            WZ_VERSION_HEADER_64BIT_START
        } else {
            reader.read_u16()?
        };

        if let Some(ver) = expected_version {
            let hash = check_and_get_version_hash(wz_version_header, ver);
            if hash != 0 {
                reader.hash = hash;
                let dir = WzDirectoryEntry::parse(&mut reader)?;
                return Ok(WzFile {
                    header: reader.header,
                    version: ver,
                    version_hash: hash,
                    maple_version,
                    is_64bit,
                    directory: dir,
                });
            }
        }

        if is_64bit {
            for ver in WZ_VERSION_HEADER_64BIT_START..WZ_VERSION_HEADER_64BIT_START + 10 {
                if let Some(result) = try_decode(
                    &mut reader,
                    wz_version_header,
                    ver as i16,
                    is_64bit,
                    maple_version,
                )? {
                    return Ok(result);
                }
            }
        }

        for ver in 0..2000i16 {
            if let Some(result) = try_decode(
                &mut reader,
                wz_version_header,
                ver,
                is_64bit,
                maple_version,
            )? {
                return Ok(result);
            }
        }

        Err(WzError::InvalidVersion(
            "Could not detect WZ version after trying 0..2000".into(),
        ))
    }

}

fn check_64bit_client<R: Read + Seek>(
    reader: &mut WzBinaryReader<R>,
) -> WzResult<bool> {
    let fstart = reader.header.data_start as u64;

    if reader.header.file_size < 2 {
        return Ok(true); // Only 1 byte of data → no encVer
    }

    reader.seek(fstart)?;
    let encver = reader.read_u16()?;

    let is_64bit = if encver > 0xFF {
        // encVer is always 0..255; >255 means this is directory data, not a version header
        true
    } else if encver == 0x80 {
        // 0x80 could be a compressed int marker — check if it looks like an entry count
        if reader.header.file_size >= 5 {
            reader.seek(fstart)?;
            let prop_count = reader.read_i32()?;
            prop_count > 0 && (prop_count & 0xFF) == 0 && prop_count <= 0xFFFF
        } else {
            false
        }
    } else {
        false
    };

    reader.seek(fstart)?;
    Ok(is_64bit)
}

fn try_decode<R: Read + Seek>(
    reader: &mut WzBinaryReader<R>,
    wz_version_header: u16,
    patch_version: i16,
    is_64bit: bool,
    maple_version: WzMapleVersion,
) -> WzResult<Option<WzFile>> {
    let hash = check_and_get_version_hash(wz_version_header, patch_version);
    if hash == 0 {
        return Ok(None);
    }

    reader.hash = hash;

    let data_pos = if is_64bit {
        reader.header.data_start as u64
    } else {
        reader.header.data_start as u64 + 2 // skip 2-byte encVer
    };
    reader.seek(data_pos)?;

    let dir = match WzDirectoryEntry::parse(reader) {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };

    let first_image = dir.images.first()
        .or_else(|| dir.subdirectories.iter()
            .flat_map(|d| d.images.iter())
            .next());

    if let Some(img) = first_image {
        let saved_pos = reader.position()?;
        reader.seek(img.offset)?;
        match reader.read_u8() {
            // 0x73 = inline Property string, 0x1B = offset-based
            Ok(0x73) | Ok(0x1B) => {
                reader.seek(saved_pos)?;
            }
            _ => {
                reader.seek(saved_pos)?;
                return Ok(None);
            }
        }
    } else if is_64bit {
        // Empty directory is OK for 64-bit files, but reject version 113
        // to avoid a known hash collision (MSEA v194 Map001.wz falsely matches).
        if patch_version == 113 {
            return Ok(None);
        }
    } else {
        return Ok(None);
    }

    Ok(Some(WzFile {
        header: reader.header.clone(),
        version: patch_version,
        version_hash: hash,
        maple_version,
        is_64bit,
        directory: dir,
    }))
}

pub fn compute_version_hash(version: i16) -> u32 {
    let version_str = version.to_string();
    let mut hash: u32 = 0;
    for c in version_str.bytes() {
        hash = hash.wrapping_mul(32).wrapping_add(c as u32).wrapping_add(1);
    }
    hash
}

pub fn compute_enc_version(hash: u32) -> u8 {
    let b0 = (hash >> 24) & 0xFF;
    let b1 = (hash >> 16) & 0xFF;
    let b2 = (hash >> 8) & 0xFF;
    let b3 = hash & 0xFF;
    !(b0 ^ b1 ^ b2 ^ b3) as u8
}

fn check_and_get_version_hash(wz_version_header: u16, patch_version: i16) -> u32 {
    let hash = compute_version_hash(patch_version);

    if wz_version_header == WZ_VERSION_HEADER_64BIT_START {
        return hash;
    }

    // Validate: the XOR of all 4 hash bytes, inverted, should match the header
    let enc_byte = compute_enc_version(hash);
    if wz_version_header == enc_byte as u16 {
        hash
    } else {
        0 // Invalid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── detect_file_type ──────────────────────────────────────────

    #[test]
    fn test_detect_standard_wz() {
        assert_eq!(detect_file_type(b"PKG1\x00\x00\x00\x00"), WzFileType::Standard);
    }

    #[test]
    fn test_detect_hotfix_data_wz() {
        assert_eq!(detect_file_type(&[0x73, 0x00, 0x00, 0x00]), WzFileType::HotfixDataWz);
    }

    #[test]
    fn test_detect_list_file() {
        // i32 length = 25, first byte 0x19 — not PKG1 and not 0x73
        assert_eq!(detect_file_type(&[0x19, 0x00, 0x00, 0x00]), WzFileType::ListFile);
    }

    #[test]
    fn test_detect_empty_data() {
        assert_eq!(detect_file_type(&[]), WzFileType::ListFile);
    }

    #[test]
    fn test_detect_short_data() {
        assert_eq!(detect_file_type(&[0x50]), WzFileType::ListFile);
    }

    // ── parse_hotfix_data_wz ──────────────────────────────────────

    fn encode_ascii_bms(s: &str) -> Vec<u8> {
        let len = s.len();
        assert!(len > 0 && len < 128);
        let indicator = -(len as i8);
        let mut out = vec![indicator as u8];
        let mut mask: u8 = 0xAA;
        for b in s.bytes() {
            out.push(b ^ mask);
            mask = mask.wrapping_add(1);
        }
        out
    }

    #[test]
    fn test_parse_hotfix_data_wz_basic() {
        // Build a minimal 0x73 "Property" image with one Null property (BMS zero-key)
        let mut data = vec![0x73u8];
        data.extend_from_slice(&encode_ascii_bms("Property"));
        data.extend_from_slice(&0u16.to_le_bytes());
        data.push(1); // count = 1
        data.push(0x73); // string block: inline
        data.extend_from_slice(&encode_ascii_bms("test"));
        data.push(0x00); // Null property type

        let props = parse_hotfix_data_wz(&data, WzMapleVersion::Bms).unwrap();
        assert_eq!(props.len(), 1);
        assert_eq!(props[0].0, "test");
        assert!(matches!(props[0].1, WzProperty::Null));
    }

    #[test]
    fn test_parse_hotfix_data_wz_multiple_props() {
        let mut data = vec![0x73u8];
        data.extend_from_slice(&encode_ascii_bms("Property"));
        data.extend_from_slice(&0u16.to_le_bytes());
        data.push(2); // count = 2
        // Property 1: "a" = Null
        data.push(0x73);
        data.extend_from_slice(&encode_ascii_bms("a"));
        data.push(0x00);
        // Property 2: "b" = Short(42)
        data.push(0x73);
        data.extend_from_slice(&encode_ascii_bms("b"));
        data.push(0x02);
        data.extend_from_slice(&42i16.to_le_bytes());

        let props = parse_hotfix_data_wz(&data, WzMapleVersion::Bms).unwrap();
        assert_eq!(props.len(), 2);
        assert_eq!(props[0].0, "a");
        assert!(matches!(props[0].1, WzProperty::Null));
        assert_eq!(props[1].0, "b");
        assert_eq!(props[1].1.as_int(), Some(42));
    }

    // ── version hash ──────────────────────────────────────────────

    #[test]
    fn test_version_hash_83() {
        let hash = compute_version_hash(83);
        assert_ne!(hash, 0);
    }

    #[test]
    fn test_version_hash_deterministic() {
        let h1 = compute_version_hash(176);
        let h2 = compute_version_hash(176);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_enc_version_roundtrip() {
        for ver in [40, 55, 83, 95, 113, 176, 200, 250] {
            let hash = compute_version_hash(ver);
            let enc = compute_enc_version(hash);
            // Verify the hash validates against the enc byte
            let result = check_and_get_version_hash(enc as u16, ver);
            assert_ne!(result, 0, "Version {} should validate", ver);
        }
    }

    #[test]
    fn test_64bit_hash_always_valid() {
        for ver in 770..780i16 {
            let hash = check_and_get_version_hash(WZ_VERSION_HEADER_64BIT_START, ver);
            assert_ne!(hash, 0);
        }
    }
}

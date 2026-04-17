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
pub fn parse_hotfix_data_wz(data: &[u8], iv: [u8; 4]) -> WzResult<Vec<(String, WzProperty)>> {
    parse_hotfix_data_wz_with_user_key(data, iv, None)
}

/// Parses a hotfix Data.wz file with an optional custom user key.
pub fn parse_hotfix_data_wz_with_user_key(
    data: &[u8],
    iv: [u8; 4],
    user_key: Option<[u8; 128]>,
) -> WzResult<Vec<(String, WzProperty)>> {
    let header = WzHeader {
        ident: String::new(),
        file_size: data.len() as u64,
        data_start: 0,
        copyright: String::new(),
    };
    let cursor = Cursor::new(data);
    let mut reader = WzBinaryReader::new(cursor, iv, header, 0);
    if let Some(uk) = user_key {
        reader.wz_key = super::keys::WzKey::with_user_key(iv, uk);
    }
    parse_image(&mut reader)
}

pub struct WzFile {
    pub header: WzHeader,
    pub version: i16,
    pub version_hash: u32,
    pub maple_version: WzMapleVersion,
    /// The actual 4-byte IV used for encryption. Stored explicitly so that
    /// `save()` re-uses the same key that was active during parsing, even
    /// when the version enum is `Custom` or a hybrid key was detected.
    pub iv: [u8; 4],
    /// Optional custom 128-byte user key for AES key generation.
    /// When set, this key is used instead of the standard `UserKey`.
    pub user_key: Option<[u8; 128]>,
    pub is_64bit: bool,
    pub directory: WzDirectoryEntry,
}

impl WzFile {
    pub fn parse(
        data: &[u8],
        maple_version: WzMapleVersion,
        expected_version: Option<i16>,
    ) -> WzResult<Self> {
        Self::parse_with_iv(data, maple_version, maple_version.iv(), expected_version)
    }

    pub fn parse_with_iv(
        data: &[u8],
        maple_version: WzMapleVersion,
        iv: [u8; 4],
        expected_version: Option<i16>,
    ) -> WzResult<Self> {
        Self::parse_with_iv_and_user_key(data, maple_version, iv, expected_version, None)
    }

    pub fn parse_with_iv_and_user_key(
        data: &[u8],
        maple_version: WzMapleVersion,
        iv: [u8; 4],
        expected_version: Option<i16>,
        user_key: Option<[u8; 128]>,
    ) -> WzResult<Self> {
        let mut cursor = Cursor::new(data);
        let header = WzHeader::parse(&mut cursor)?;
        let mut reader = WzBinaryReader::new(cursor, iv, header.clone(), 0);
        if let Some(uk) = user_key {
            reader.wz_key = super::keys::WzKey::with_user_key(iv, uk);
        }
        let is_64bit = check_64bit_client(&mut reader)?;
        reader.seek(header.data_start as u64)?;

        let wz_version_header = if is_64bit {
            WZ_VERSION_HEADER_64BIT_START
        } else {
            reader.read_u16()?
        };

        // KMST1125+ stub WZ files have valid PKG1 headers but zero entries —
        // skip the 0..2000 brute-force, which can't validate a hash with no image.
        let entry_count_pos = reader.position()?;
        let entry_count = reader.read_compressed_int()?;
        if entry_count == 0 {
            return Ok(WzFile {
                header: reader.header,
                version: 0,
                version_hash: 0,
                maple_version,
                iv,
                user_key,
                is_64bit,
                directory: WzDirectoryEntry::root(),
            });
        }
        reader.seek(entry_count_pos)?;

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
                    iv,
                    user_key,
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
                    iv,
                    user_key,
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
                iv,
                user_key,
            )? {
                return Ok(result);
            }
        }

        Err(WzError::InvalidVersion(
            "Could not detect WZ version after trying 0..2000".into(),
        ))
    }

    pub fn save(&mut self) -> WzResult<Vec<u8>> {
        let mut image_data_buf = Vec::new();
        self.directory
            .generate_data(self.iv, self.user_key, &mut image_data_buf)?;
        self.save_with_image_data(&[&image_data_buf])
    }

    /// Phases 2–3: compute offsets and write the final WZ file.
    /// `image_data` slices must be in depth-first traversal order matching the directory,
    /// and each image's `size`/`checksum` must be set.
    pub fn save_with_image_data(&mut self, image_data: &[&[u8]]) -> WzResult<Vec<u8>> {
        let iv = self.iv;

        // Phase 2: Compute offsets
        self.directory.compute_all_offset_sizes();
        let enc_ver_size = if self.is_64bit { 0u32 } else { 2 };
        let dir_start = self.header.data_start + enc_ver_size;
        let after_dir = self.directory.get_offsets(dir_start);
        let total_len = self.directory.get_img_offsets(after_dir);

        // Update file size in header (file_size = data portion size, per MapleLib)
        self.header.file_size = (total_len - self.header.data_start) as u64;

        // Phase 3: Write into a single buffer so the writer sees correct absolute
        // positions (required for offset encryption).
        let mut output = Vec::new();
        output.try_reserve(total_len as usize).map_err(|_| {
            WzError::Custom(format!(
                "Cannot allocate {} bytes for output — file too large for available memory",
                total_len
            ))
        })?;
        output.resize(total_len as usize, 0);
        let mut header_cursor = Cursor::new(&mut output[..]);
        self.header.write(&mut header_cursor)?;

        let mut writer = super::binary_writer::WzBinaryWriter::new(
            Cursor::new(&mut output[..]),
            iv,
            self.header.clone(),
        );
        if let Some(uk) = self.user_key {
            writer.wz_key = super::keys::WzKey::with_user_key(iv, uk);
        }
        writer.hash = self.version_hash;
        writer.seek(self.header.data_start as u64)?;

        if !self.is_64bit {
            let enc_ver = compute_enc_version(self.version_hash) as u16;
            writer.write_u16(enc_ver)?;
        }

        self.directory.save_directory(&mut writer)?;
        writer.string_cache.clear();

        let img_start = after_dir as u64;
        writer.seek(img_start)?;
        for chunk in image_data {
            writer.write_bytes(chunk)?;
        }

        Ok(output)
    }
}

pub fn save_hotfix_data_wz(properties: &[(String, WzProperty)], iv: [u8; 4]) -> WzResult<Vec<u8>> {
    save_hotfix_data_wz_with_user_key(properties, iv, None)
}

/// Save a hotfix Data.wz file with an optional custom user key.
pub fn save_hotfix_data_wz_with_user_key(
    properties: &[(String, WzProperty)],
    iv: [u8; 4],
    user_key: Option<[u8; 128]>,
) -> WzResult<Vec<u8>> {
    let header = WzHeader {
        ident: String::new(),
        file_size: 0,
        data_start: 0,
        copyright: String::new(),
    };
    let mut writer = super::binary_writer::WzBinaryWriter::new(Cursor::new(Vec::new()), iv, header);
    if let Some(uk) = user_key {
        writer.wz_key = super::keys::WzKey::with_user_key(iv, uk);
    }
    super::image_writer::write_image(&mut writer, properties)?;
    Ok(writer.writer.into_inner())
}

fn check_64bit_client<R: Read + Seek>(reader: &mut WzBinaryReader<R>) -> WzResult<bool> {
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
    iv: [u8; 4],
    user_key: Option<[u8; 128]>,
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

    let first_image = dir.images.first().or_else(|| {
        dir.subdirectories
            .iter()
            .flat_map(|d| d.images.iter())
            .next()
    });

    if let Some(img) = first_image {
        let saved_pos = reader.position()?;
        reader.seek(img.offset)?;
        match reader.read_u8() {
            // 0x73 = inline Property string, 0x1B = offset-based, 0x01 = .lua image
            Ok(0x73) | Ok(0x1B) | Ok(0x01) => {
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
        iv,
        user_key,
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
        assert_eq!(
            detect_file_type(b"PKG1\x00\x00\x00\x00"),
            WzFileType::Standard
        );
    }

    #[test]
    fn test_detect_hotfix_data_wz() {
        assert_eq!(
            detect_file_type(&[0x73, 0x00, 0x00, 0x00]),
            WzFileType::HotfixDataWz
        );
    }

    #[test]
    fn test_detect_list_file() {
        // i32 length = 25, first byte 0x19 — not PKG1 and not 0x73
        assert_eq!(
            detect_file_type(&[0x19, 0x00, 0x00, 0x00]),
            WzFileType::ListFile
        );
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

        let props = parse_hotfix_data_wz(&data, WzMapleVersion::Bms.iv()).unwrap();
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

        let props = parse_hotfix_data_wz(&data, WzMapleVersion::Bms.iv()).unwrap();
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

    // ── save_hotfix_data_wz roundtrip ────────────────────────────────

    #[test]
    fn test_save_hotfix_roundtrip() {
        let props = vec![
            ("name".into(), WzProperty::String("mob".into())),
            ("hp".into(), WzProperty::Int(100)),
        ];
        let iv = WzMapleVersion::Bms.iv();
        let saved = save_hotfix_data_wz(&props, iv).unwrap();
        let parsed = parse_hotfix_data_wz(&saved, iv).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, "name");
        assert_eq!(parsed[0].1.as_str(), Some("mob"));
        assert_eq!(parsed[1].0, "hp");
        assert_eq!(parsed[1].1.as_int(), Some(100));
    }

    // ── empty-stub WZ files ──────────────────────────────────────────

    /// Layout: PKG1 | file_size u64 | data_start u32=16 | body
    fn build_pkg1_stub(body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"PKG1");
        out.extend_from_slice(&(body.len() as u64).to_le_bytes());
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn test_parse_empty_stub_returns_empty_directory() {
        let data = build_pkg1_stub(&[0x34, 0x00, 0x00]); // encVer=0x34, count=0

        let wz = WzFile::parse_with_iv_and_user_key(
            &data,
            WzMapleVersion::Bms,
            WzMapleVersion::Bms.iv(),
            None,
            None,
        )
        .expect("empty stub should parse");

        assert_eq!(wz.version, 0);
        assert_eq!(wz.version_hash, 0);
        assert!(wz.directory.subdirectories.is_empty());
        assert!(wz.directory.images.is_empty());
    }

    #[test]
    fn test_parse_empty_stub_ignores_encver_mismatch() {
        let data = build_pkg1_stub(&[0x00, 0x00, 0x00]); // encVer=0x00, count=0

        let result = WzFile::parse_with_iv_and_user_key(
            &data,
            WzMapleVersion::Bms,
            WzMapleVersion::Bms.iv(),
            None,
            None,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_nonempty_unparseable_still_errors() {
        let data = build_pkg1_stub(&[0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]); // count=1 + junk

        let result = WzFile::parse_with_iv_and_user_key(
            &data,
            WzMapleVersion::Bms,
            WzMapleVersion::Bms.iv(),
            None,
            None,
        );

        match result {
            Err(WzError::InvalidVersion(_)) => {}
            Err(other) => panic!("expected InvalidVersion, got {other:?}"),
            Ok(_) => panic!("expected error, got success"),
        }
    }

    // ── WzFile::save roundtrip ───────────────────────────────────────

    #[test]
    fn test_wz_file_save_roundtrip() {
        use crate::wz::directory::{WzDirectoryEntry, WzImageEntry};
        use crate::wz::types::WzDirectoryType;

        // Build image properties
        let img_props = vec![
            ("x".into(), WzProperty::Int(42)),
            ("y".into(), WzProperty::Short(7)),
        ];

        let mut dir = WzDirectoryEntry::new(String::new(), WzDirectoryType::Directory as u8);
        dir.images.push(WzImageEntry {
            name: "test.img".into(),
            size: 0,
            checksum: 0,
            offset: 0,
            properties: Some(img_props),
            iv: None,
        });

        let version = 83i16;
        let hash = compute_version_hash(version);

        let mut wz_file = WzFile {
            header: WzHeader {
                ident: "PKG1".into(),
                file_size: 0,
                data_start: 60,
                copyright: "Test".into(),
            },
            version,
            version_hash: hash,
            maple_version: WzMapleVersion::Bms,
            iv: WzMapleVersion::Bms.iv(),
            user_key: None,
            is_64bit: false,
            directory: dir,
        };

        let saved = wz_file.save().unwrap();

        // Parse it back
        let parsed = WzFile::parse(&saved, WzMapleVersion::Bms, Some(83)).unwrap();
        assert_eq!(parsed.version, 83);
        assert_eq!(parsed.directory.images.len(), 1);
        assert_eq!(parsed.directory.images[0].name, "test.img");

        // Parse the image data
        let img = &parsed.directory.images[0];
        let iv = WzMapleVersion::Bms.iv();
        let header = parsed.header.clone();
        let mut reader =
            crate::wz::binary_reader::WzBinaryReader::new(Cursor::new(&saved), iv, header, 0);
        reader.seek(img.offset).unwrap();
        let props = crate::wz::image::parse_image(&mut reader).unwrap();
        assert_eq!(props.len(), 2);
        assert_eq!(props[0].0, "x");
        assert_eq!(props[0].1.as_int(), Some(42));
        assert_eq!(props[1].0, "y");
        assert_eq!(props[1].1.as_int(), Some(7));
    }

    // ── Save with duplicate image names across subdirectories ─────

    #[test]
    fn test_wz_file_save_duplicate_names_no_gap() {
        use crate::wz::directory::{WzDirectoryEntry, WzImageEntry};
        use crate::wz::types::WzDirectoryType;

        // Two subdirectories with identically-named images — triggers
        // string caching in write_wz_object_value. Before the fix,
        // measure_entry_table_size didn't account for caching, producing
        // a gap of zero bytes between directory tables and image data.
        let make_img = |name: &str, props: Vec<(String, WzProperty)>| WzImageEntry {
            name: name.into(),
            size: 0,
            checksum: 0,
            offset: 0,
            properties: Some(props),
            iv: None,
        };

        let mut sub_a = WzDirectoryEntry::new("skillA".into(), WzDirectoryType::Directory as u8);
        sub_a
            .images
            .push(make_img("0.img", vec![("x".into(), WzProperty::Int(1))]));
        sub_a
            .images
            .push(make_img("1.img", vec![("y".into(), WzProperty::Int(2))]));

        let mut sub_b = WzDirectoryEntry::new("skillB".into(), WzDirectoryType::Directory as u8);
        sub_b
            .images
            .push(make_img("0.img", vec![("x".into(), WzProperty::Int(3))]));
        sub_b
            .images
            .push(make_img("1.img", vec![("y".into(), WzProperty::Int(4))]));

        let mut dir = WzDirectoryEntry::new(String::new(), WzDirectoryType::Directory as u8);
        dir.subdirectories.push(sub_a);
        dir.subdirectories.push(sub_b);

        let version = 83i16;
        let hash = compute_version_hash(version);

        let mut wz_file = WzFile {
            header: WzHeader {
                ident: "PKG1".into(),
                file_size: 0,
                data_start: 60,
                copyright: String::new(),
            },
            version,
            version_hash: hash,
            maple_version: WzMapleVersion::Bms,
            iv: WzMapleVersion::Bms.iv(),
            user_key: None,
            is_64bit: false,
            directory: dir,
        };

        let saved = wz_file.save().unwrap();

        // Parse back and verify all 4 images are readable
        let parsed = WzFile::parse(&saved, WzMapleVersion::Bms, Some(83)).unwrap();
        assert_eq!(parsed.directory.subdirectories.len(), 2);
        assert_eq!(parsed.directory.subdirectories[0].images.len(), 2);
        assert_eq!(parsed.directory.subdirectories[1].images.len(), 2);

        let iv = WzMapleVersion::Bms.iv();
        for sub in &parsed.directory.subdirectories {
            for img in &sub.images {
                let mut reader = crate::wz::binary_reader::WzBinaryReader::new(
                    Cursor::new(&saved),
                    iv,
                    parsed.header.clone(),
                    0,
                );
                reader.seek(img.offset).unwrap();
                let props = crate::wz::image::parse_image(&mut reader).unwrap();
                assert_eq!(props.len(), 1);
            }
        }

        // Verify no zero-byte gap: the first image should start immediately
        // after the directory tables. Re-save to confirm identical output.
        let mut wz2 = parsed;
        // Re-parse all images so we have properties
        for sub in &mut wz2.directory.subdirectories {
            for img in &mut sub.images {
                let mut reader = crate::wz::binary_reader::WzBinaryReader::new(
                    Cursor::new(&saved),
                    iv,
                    wz2.header.clone(),
                    0,
                );
                reader.seek(img.offset).unwrap();
                img.properties = Some(crate::wz::image::parse_image(&mut reader).unwrap());
            }
        }
        let saved2 = wz2.save().unwrap();
        assert_eq!(
            saved.len(),
            saved2.len(),
            "Re-save should produce identical size"
        );
    }

    // ── Hybrid IV preservation ───────────────────────────────────────

    #[test]
    fn test_hybrid_iv_save_roundtrip() {
        use crate::crypto::{WZ_BMSCLASSIC_IV, WZ_GMSIV};
        use crate::wz::directory::{WzDirectoryEntry, WzImageEntry};
        use crate::wz::types::WzDirectoryType;

        // Image A: uses GMS key (different from directory BMS key)
        let props_a = vec![("a".into(), WzProperty::Int(1))];
        // Image B: uses directory key (BMS, iv=None falls back)
        let props_b = vec![("b".into(), WzProperty::Int(2))];

        let mut dir = WzDirectoryEntry::new(String::new(), WzDirectoryType::Directory as u8);
        dir.images.push(WzImageEntry {
            name: "gms.img".into(),
            size: 0,
            checksum: 0,
            offset: 0,
            properties: Some(props_a),
            iv: Some(WZ_GMSIV),
        });
        dir.images.push(WzImageEntry {
            name: "bms.img".into(),
            size: 0,
            checksum: 0,
            offset: 0,
            properties: Some(props_b),
            iv: None, // falls back to directory IV (BMS)
        });

        let version = 83i16;
        let hash = compute_version_hash(version);

        let mut wz_file = WzFile {
            header: WzHeader {
                ident: "PKG1".into(),
                file_size: 0,
                data_start: 60,
                copyright: String::new(),
            },
            version,
            version_hash: hash,
            maple_version: WzMapleVersion::Bms,
            iv: WZ_BMSCLASSIC_IV,
            user_key: None,
            is_64bit: false,
            directory: dir,
        };

        let saved = wz_file.save().unwrap();
        let parsed = WzFile::parse(&saved, WzMapleVersion::Bms, Some(83)).unwrap();

        // Verify both images survived
        assert_eq!(parsed.directory.images.len(), 2);

        // Image A (GMS-encrypted) should be readable via IV fallback
        let img_a = &parsed.directory.images[0];
        let header = parsed.header.clone();
        let mut reader = crate::wz::binary_reader::WzBinaryReader::new(
            Cursor::new(&saved),
            WZ_BMSCLASSIC_IV,
            header.clone(),
            0,
        );
        reader.hash = parsed.version_hash;
        reader.seek(img_a.offset).unwrap();
        let props = crate::wz::image::parse_image(&mut reader).unwrap();
        assert_eq!(props[0].0, "a");
        assert_eq!(props[0].1.as_int(), Some(1));
        // Confirm the reader switched to GMS key
        assert_eq!(reader.wz_key.iv(), WZ_GMSIV);

        // Image B (BMS-encrypted) should be readable directly
        let img_b = &parsed.directory.images[1];
        let mut reader = crate::wz::binary_reader::WzBinaryReader::new(
            Cursor::new(&saved),
            WZ_BMSCLASSIC_IV,
            header,
            0,
        );
        reader.hash = parsed.version_hash;
        reader.seek(img_b.offset).unwrap();
        let props = crate::wz::image::parse_image(&mut reader).unwrap();
        assert_eq!(props[0].0, "b");
        assert_eq!(props[0].1.as_int(), Some(2));
        // Reader stayed on BMS key
        assert_eq!(reader.wz_key.iv(), WZ_BMSCLASSIC_IV);
    }
}

//! WZ directory and image entry structures.
//!
//! A WZ file contains a tree of directories and images.
//! Each directory entry has a type (1-4), name, size, checksum, and offset.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::binary_reader::WzBinaryReader;
use super::error::{WzError, WzResult};
use super::properties::WzProperty;
use super::types::WzDirectoryType;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WzDirectoryEntry {
    pub name: String,
    pub size: i32,
    pub checksum: i32,
    pub offset: u64,
    pub entry_type: u8,
    #[serde(skip)]
    pub offset_size: u32,
    pub subdirectories: Vec<WzDirectoryEntry>,
    pub images: Vec<WzImageEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WzImageEntry {
    pub name: String,
    pub size: i32,
    pub checksum: i32,
    pub offset: u64,
    #[serde(skip)]
    pub properties: Option<Vec<(String, WzProperty)>>,
    /// Per-image IV detected during parsing (hybrid WZ files may encrypt
    /// different images with different keys). Falls back to the directory
    /// IV when `None`.
    #[serde(skip)]
    pub iv: Option<[u8; 4]>,
}

impl WzDirectoryEntry {
    pub fn new(name: String, entry_type: u8) -> Self {
        WzDirectoryEntry {
            name,
            size: 0,
            checksum: 0,
            offset: 0,
            entry_type,
            offset_size: 0,
            subdirectories: Vec::new(),
            images: Vec::new(),
        }
    }

    pub fn parse<R: std::io::Read + std::io::Seek>(
        reader: &mut WzBinaryReader<R>,
    ) -> WzResult<Self> {
        let entry_count = reader.read_compressed_int()?;

        // Sanity check — garbled data from wrong version hash will produce huge counts
        if !(0..=super::MAX_DIRECTORY_ENTRIES).contains(&entry_count) {
            return Err(WzError::Custom(format!(
                "Invalid entry count {} — likely wrong version hash",
                entry_count
            )));
        }

        let mut dir = WzDirectoryEntry::new(String::new(), WzDirectoryType::Directory as u8);

        struct RawEntry {
            entry_type: u8,
            name: String,
            size: i32,
            checksum: i32,
            offset: u64,
        }
        let mut raw_entries = Vec::with_capacity(entry_count as usize);

        for _ in 0..entry_count {
            let mut entry_type = reader.read_u8()?;
            let dir_type = WzDirectoryType::try_from(entry_type);

            let (name, remember_pos) = match dir_type {
                Ok(WzDirectoryType::UnknownType) => {
                    let _unknown = reader.read_i32()?;
                    let _unknown2 = reader.read_i16()?;
                    let _offset = reader.read_wz_offset()?;
                    continue;
                }
                Ok(WzDirectoryType::RetrieveStringFromOffset) => {
                    let string_offset = reader.read_i32()?;
                    let remember_pos = reader.position()?;

                    let fstart = reader.header.data_start as u64;
                    reader.seek(fstart + string_offset as u64)?;
                    entry_type = reader.read_u8()?;
                    let name = reader.read_wz_string()?;

                    (name, remember_pos)
                }
                Ok(WzDirectoryType::Directory) | Ok(WzDirectoryType::Image) => {
                    let name = reader.read_wz_string()?;
                    let remember_pos = reader.position()?;
                    (name, remember_pos)
                }
                Err(unknown) => {
                    return Err(WzError::UnknownDirectoryType(unknown));
                }
            };

            reader.seek(remember_pos)?;
            let size = reader.read_compressed_int()?;
            let checksum = reader.read_compressed_int()?;
            let offset = reader.read_wz_offset()?;

            raw_entries.push(RawEntry {
                entry_type,
                name,
                size,
                checksum,
                offset,
            });
        }

        let mut subdirs_with_offset: Vec<(WzDirectoryEntry, u64)> = Vec::new();

        for entry in raw_entries {
            if entry.entry_type == WzDirectoryType::Directory as u8 {
                let mut subdir = WzDirectoryEntry::new(
                    entry.name,
                    WzDirectoryType::Directory as u8,
                );
                subdir.size = entry.size;
                subdir.checksum = entry.checksum;
                subdir.offset = entry.offset;
                subdirs_with_offset.push((subdir, entry.offset));
            } else {
                // Types 2 (resolved) and 4 → image
                let img = WzImageEntry {
                    name: entry.name,
                    size: entry.size,
                    checksum: entry.checksum,
                    offset: entry.offset,
                    properties: None,
                    iv: None,
                };
                dir.images.push(img);
            }
        }

        for (mut subdir, offset) in subdirs_with_offset {
            reader.seek(offset)?;
            match WzDirectoryEntry::parse(reader) {
                Ok(parsed) => {
                    subdir.subdirectories = parsed.subdirectories;
                    subdir.images = parsed.images;
                    dir.subdirectories.push(subdir);
                }
                Err(_) => {
                    // If subdirectory parse fails, still include it (empty)
                    dir.subdirectories.push(subdir);
                }
            }
        }

        Ok(dir)
    }

    // ── Writing ──────────────────────────────────────────────────────

    // Phase 1 of three-phase save (see WzFile::save)
    pub fn generate_data(
        &mut self,
        iv: [u8; 4],
        user_key: Option<[u8; 128]>,
        image_data_buf: &mut Vec<u8>,
    ) -> WzResult<()> {
        for img in &mut self.images {
            if let Some(props) = img.properties.take() {
                let image_iv = img.iv.unwrap_or(iv);
                let header = super::header::WzHeader::dummy(0);
                let mut img_writer =
                    super::binary_writer::WzBinaryWriter::new(std::io::Cursor::new(Vec::new()), image_iv, header);
                if let Some(uk) = user_key {
                    img_writer.wz_key = super::keys::WzKey::with_user_key(image_iv, uk);
                }
                super::image_writer::write_image(&mut img_writer, &props)?;
                drop(props); // free parsed data before appending serialized
                let serialized = img_writer.writer.into_inner();

                img.checksum = compute_image_checksum(&serialized);
                img.size = serialized.len() as i32;
                image_data_buf.extend_from_slice(&serialized);
            }
            // If properties is None, image retains its existing size/checksum
        }

        for subdir in &mut self.subdirectories {
            subdir.generate_data(iv, user_key, image_data_buf)?;
        }

        Ok(())
    }

    fn measure_entry_table_size(&self, string_cache: &mut HashSet<String>) -> u32 {
        let entry_count = self.images.len() + self.subdirectories.len();
        let mut size = compressed_int_size(entry_count as i32);

        for img in &self.images {
            let cache_key = format!("{}_{}", WzDirectoryType::Image as u8, img.name);
            let name_size = if string_cache.contains(&cache_key) {
                // 0x02 (RetrieveStringFromOffset) + i32 offset
                5
            } else {
                string_cache.insert(cache_key);
                // entry_type(1) + wz_string(name)
                1 + wz_string_size(&img.name)
            };
            size += name_size + compressed_int_size(img.size)
                + compressed_int_size(img.checksum) + 4;
        }
        for dir in &self.subdirectories {
            let cache_key = format!("{}_{}", WzDirectoryType::Directory as u8, dir.name);
            let name_size = if string_cache.contains(&cache_key) {
                5
            } else {
                string_cache.insert(cache_key);
                1 + wz_string_size(&dir.name)
            };
            size += name_size + compressed_int_size(dir.size)
                + compressed_int_size(dir.checksum) + 4;
        }
        size as u32
    }

    /// Computes `offset_size` for every directory in the tree, simulating
    /// the same string-caching order as `save_directory()`.
    pub fn compute_all_offset_sizes(&mut self) {
        let mut cache = HashSet::new();
        self.compute_offset_sizes_recursive(&mut cache);
    }

    fn compute_offset_sizes_recursive(&mut self, cache: &mut HashSet<String>) {
        self.offset_size = self.measure_entry_table_size(cache);
        for subdir in &mut self.subdirectories {
            subdir.compute_offset_sizes_recursive(cache);
        }
    }

    // Phase 2a of three-phase save
    pub fn get_offsets(&mut self, cur_offset: u32) -> u32 {
        self.offset = cur_offset as u64;
        let mut next = cur_offset + self.offset_size;
        for subdir in &mut self.subdirectories {
            next = subdir.get_offsets(next);
        }
        next
    }

    // Phase 2b of three-phase save
    pub fn get_img_offsets(&mut self, cur_offset: u32) -> u32 {
        let mut next = cur_offset;
        for img in &mut self.images {
            img.offset = next as u64;
            next += img.size as u32;
        }
        for subdir in &mut self.subdirectories {
            next = subdir.get_img_offsets(next);
        }
        next
    }

    // Phase 3 of three-phase save
    pub fn save_directory<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut super::binary_writer::WzBinaryWriter<W>,
    ) -> WzResult<()> {
        let entry_count = self.images.len() + self.subdirectories.len();
        writer.write_compressed_int(entry_count as i32)?;

        for img in &self.images {
            writer.write_wz_object_value(&img.name, WzDirectoryType::Image as u8)?;
            writer.write_compressed_int(img.size)?;
            writer.write_compressed_int(img.checksum)?;
            writer.write_wz_offset(img.offset as u32)?;
        }

        for dir in &self.subdirectories {
            writer.write_wz_object_value(&dir.name, WzDirectoryType::Directory as u8)?;
            writer.write_compressed_int(dir.size)?;
            writer.write_compressed_int(dir.checksum)?;
            writer.write_wz_offset(dir.offset as u32)?;
        }

        for subdir in &self.subdirectories {
            subdir.save_directory(writer)?;
        }

        Ok(())
    }

    // Expects blobs in depth-first order: images first, then subdirectories.
    pub fn attach_image_data(&mut self, blobs: &[&[u8]]) -> WzResult<usize> {
        let mut consumed = 0;
        for img in &mut self.images {
            if consumed >= blobs.len() {
                return Err(super::error::WzError::Custom(
                    "Not enough image blobs for directory tree".into(),
                ));
            }
            img.checksum = compute_image_checksum(blobs[consumed]);
            img.size = blobs[consumed].len() as i32;
            consumed += 1;
        }
        for subdir in &mut self.subdirectories {
            consumed += subdir.attach_image_data(&blobs[consumed..])?;
        }
        Ok(consumed)
    }
}

pub fn compute_image_checksum(data: &[u8]) -> i32 {
    let mut checksum: i32 = 0;
    for &b in data {
        checksum = checksum.wrapping_add(b as i32);
    }
    checksum
}

// ── Size estimation helpers ──────────────────────────────────────────

fn compressed_int_size(val: i32) -> usize {
    if (-127..=127).contains(&val) && val != -128 {
        1
    } else {
        5
    }
}

fn wz_string_size(s: &str) -> usize {
    if s.is_ascii() {
        let len = s.len();
        let prefix = if len > 127 { 5 } else { 1 };
        prefix + len
    } else {
        let chars: Vec<u16> = s.encode_utf16().collect();
        let len = chars.len();
        let prefix = if len >= 127 { 5 } else { 1 };
        prefix + len * 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wz::test_utils::*;

    // ── Constructor ─────────────────────────────────────────────────

    #[test]
    fn test_new_defaults() {
        let e = WzDirectoryEntry::new("mob".to_string(), 3);
        assert_eq!(e.name, "mob");
        assert_eq!(e.entry_type, 3);
        assert_eq!(e.size, 0);
        assert_eq!(e.checksum, 0);
        assert_eq!(e.offset, 0);
        assert!(e.subdirectories.is_empty());
        assert!(e.images.is_empty());
    }

    // ── Entry count validation ──────────────────────────────────────

    #[test]
    fn test_parse_empty_directory() {
        let mut reader = make_reader(vec![0x00]);
        let dir = WzDirectoryEntry::parse(&mut reader).unwrap();
        assert!(dir.subdirectories.is_empty());
        assert!(dir.images.is_empty());
    }

    #[test]
    fn test_parse_negative_entry_count() {
        let mut reader = make_reader(vec![0xFF]); // -1 as compressed int
        assert!(WzDirectoryEntry::parse(&mut reader).is_err());
    }

    #[test]
    fn test_parse_too_large_entry_count() {
        let mut data = vec![0x80u8]; // large compressed int indicator
        data.extend_from_slice(&100_001i32.to_le_bytes());
        let mut reader = make_reader(data);
        assert!(WzDirectoryEntry::parse(&mut reader).is_err());
    }

    // ── Single image (type 4) ───────────────────────────────────────

    #[test]
    fn test_parse_single_image() {
        let mut data = Vec::new();
        data.push(0x01); // entry_count = 1
        data.push(WzDirectoryType::Image as u8);
        data.extend_from_slice(&encode_wz_ascii("test.img"));
        data.push(10); // size
        data.push(5);  // checksum
        let pos = data.len() as u32;
        data.extend_from_slice(&encode_wz_offset(pos, 200));

        let mut reader = make_reader(data);
        let dir = WzDirectoryEntry::parse(&mut reader).unwrap();

        assert!(dir.subdirectories.is_empty());
        assert_eq!(dir.images.len(), 1);
        assert_eq!(dir.images[0].name, "test.img");
        assert_eq!(dir.images[0].size, 10);
        assert_eq!(dir.images[0].checksum, 5);
        assert_eq!(dir.images[0].offset, 200);
    }

    // ── Single subdirectory (type 3) with empty contents ────────────

    #[test]
    fn test_parse_directory_with_empty_subdir() {
        let mut data = Vec::new();
        data.push(0x01);
        data.push(WzDirectoryType::Directory as u8);
        data.extend_from_slice(&encode_wz_ascii("mob"));
        data.push(0); // size
        data.push(0); // checksum
        let offset_pos = data.len() as u32;
        let subdir_pos = offset_pos + 4; // right after the 4-byte wz_offset
        data.extend_from_slice(&encode_wz_offset(offset_pos, subdir_pos));
        data.push(0x00); // subdirectory: entry_count = 0

        let mut reader = make_reader(data);
        let dir = WzDirectoryEntry::parse(&mut reader).unwrap();

        assert_eq!(dir.subdirectories.len(), 1);
        assert_eq!(dir.subdirectories[0].name, "mob");
        assert_eq!(dir.subdirectories[0].entry_type, WzDirectoryType::Directory as u8);
        assert!(dir.subdirectories[0].subdirectories.is_empty());
        assert!(dir.subdirectories[0].images.is_empty());
        assert!(dir.images.is_empty());
    }

    // ── Mixed directories and images ────────────────────────────────

    #[test]
    fn test_parse_mixed_entries() {
        let mut data = Vec::new();
        data.push(0x02); // entry_count = 2

        // Entry 1: Directory
        data.push(WzDirectoryType::Directory as u8);
        data.extend_from_slice(&encode_wz_ascii("dir"));
        data.push(0);
        data.push(0);
        let dir_offset_pos = data.len() as u32;
        // placeholder — we'll patch after knowing the subdir data position
        data.extend_from_slice(&[0; 4]);

        // Entry 2: Image
        data.push(WzDirectoryType::Image as u8);
        data.extend_from_slice(&encode_wz_ascii("x.img"));
        data.push(30);
        data.push(7);
        let img_offset_pos = data.len() as u32;
        data.extend_from_slice(&encode_wz_offset(img_offset_pos, 500));

        // Subdirectory data
        let subdir_data_pos = data.len() as u32;
        data.push(0x00); // empty subdir

        // Patch the directory's wz_offset
        let enc = encode_wz_offset(dir_offset_pos, subdir_data_pos);
        let p = dir_offset_pos as usize;
        data[p..p + 4].copy_from_slice(&enc);

        let mut reader = make_reader(data);
        let dir = WzDirectoryEntry::parse(&mut reader).unwrap();

        assert_eq!(dir.subdirectories.len(), 1);
        assert_eq!(dir.subdirectories[0].name, "dir");
        assert_eq!(dir.images.len(), 1);
        assert_eq!(dir.images[0].name, "x.img");
        assert_eq!(dir.images[0].offset, 500);
    }

    // ── Type 1 (UnknownType) is skipped ─────────────────────────────

    #[test]
    fn test_parse_type1_skipped() {
        let mut data = Vec::new();
        data.push(0x02); // 2 entries

        // Entry 1: UnknownType (type 1) — skipped
        data.push(WzDirectoryType::UnknownType as u8);
        data.extend_from_slice(&0i32.to_le_bytes()); // _unknown
        data.extend_from_slice(&0i16.to_le_bytes()); // _unknown2
        let skip_pos = data.len() as u32;
        data.extend_from_slice(&encode_wz_offset(skip_pos, 0)); // _offset

        // Entry 2: Image
        data.push(WzDirectoryType::Image as u8);
        data.extend_from_slice(&encode_wz_ascii("real.img"));
        data.push(30);
        data.push(7);
        let p = data.len() as u32;
        data.extend_from_slice(&encode_wz_offset(p, 300));

        let mut reader = make_reader(data);
        let dir = WzDirectoryEntry::parse(&mut reader).unwrap();

        assert_eq!(dir.images.len(), 1);
        assert_eq!(dir.images[0].name, "real.img");
        assert!(dir.subdirectories.is_empty());
    }

    // ── Type 2 (RetrieveStringFromOffset) ───────────────────────────

    #[test]
    fn test_parse_type2_resolves_to_image() {
        let mut data = Vec::new();
        data.push(0x01);
        data.push(WzDirectoryType::RetrieveStringFromOffset as u8);

        // String lives at position 12 (data_start + string_offset = 0 + 12)
        data.extend_from_slice(&12i32.to_le_bytes());
        // remember_pos = 6

        data.push(20); // size (at pos 6)
        data.push(3);  // checksum (at pos 7)
        let offset_pos = data.len() as u32; // pos 8
        data.extend_from_slice(&encode_wz_offset(offset_pos, 400));

        // At position 12: type byte + wz_string
        data.push(WzDirectoryType::Image as u8);
        data.extend_from_slice(&encode_wz_ascii("ref.img"));

        let mut reader = make_reader(data);
        let dir = WzDirectoryEntry::parse(&mut reader).unwrap();

        assert_eq!(dir.images.len(), 1);
        assert_eq!(dir.images[0].name, "ref.img");
        assert_eq!(dir.images[0].size, 20);
        assert_eq!(dir.images[0].offset, 400);
    }

    // ── Invalid entry type → error ──────────────────────────────────

    #[test]
    fn test_parse_invalid_entry_type() {
        let mut data = Vec::new();
        data.push(0x01);
        data.push(0x05); // invalid type
        let mut reader = make_reader(data);
        assert!(WzDirectoryEntry::parse(&mut reader).is_err());
    }

    // ── compute_all_offset_sizes with string caching ──────────────

    #[test]
    fn test_offset_sizes_account_for_string_caching() {
        use crate::wz::binary_writer::WzBinaryWriter;
        use crate::wz::header::WzHeader;
        use std::io::Cursor;

        // Two subdirectories each containing an image named "0.img".
        // The second occurrence should be cached (5 bytes) instead of inline (1 + 1 + 5 = 7 bytes).
        let mut root = WzDirectoryEntry::new(String::new(), WzDirectoryType::Directory as u8);

        let mut sub_a = WzDirectoryEntry::new("a".into(), WzDirectoryType::Directory as u8);
        sub_a.images.push(WzImageEntry {
            name: "0.img".into(), size: 100, checksum: 10, offset: 0, properties: None, iv: None,
        });

        let mut sub_b = WzDirectoryEntry::new("b".into(), WzDirectoryType::Directory as u8);
        sub_b.images.push(WzImageEntry {
            name: "0.img".into(), size: 200, checksum: 20, offset: 0, properties: None, iv: None,
        });

        root.subdirectories.push(sub_a);
        root.subdirectories.push(sub_b);

        root.compute_all_offset_sizes();

        // Verify by doing an actual write and comparing sizes
        let header = WzHeader { ident: String::new(), file_size: 0, data_start: 0, copyright: String::new() };
        let mut writer = WzBinaryWriter::new(Cursor::new(Vec::new()), [0; 4], header);

        // Set dummy offsets so write_wz_offset doesn't panic
        root.offset = 0;
        root.subdirectories[0].offset = root.offset_size as u64;
        root.subdirectories[1].offset = root.subdirectories[0].offset
            + root.subdirectories[0].offset_size as u64;

        for img in &mut root.subdirectories[0].images { img.offset = 1000; }
        for img in &mut root.subdirectories[1].images { img.offset = 2000; }

        root.save_directory(&mut writer).unwrap();
        let actual_size = writer.position().unwrap() as u32;

        let expected = root.offset_size
            + root.subdirectories[0].offset_size
            + root.subdirectories[1].offset_size;
        assert_eq!(actual_size, expected,
            "Measured size ({}) must match actual written size ({})", expected, actual_size);
    }

    // ── Failed subdirectory parse still includes the entry ──────────

    #[test]
    fn test_parse_subdir_failure_keeps_entry() {
        let mut data = Vec::new();
        data.push(0x01);
        data.push(WzDirectoryType::Directory as u8);
        data.extend_from_slice(&encode_wz_ascii("bad"));
        data.push(0);
        data.push(0);
        let offset_pos = data.len() as u32;
        let bad_pos = offset_pos + 4;
        data.extend_from_slice(&encode_wz_offset(offset_pos, bad_pos));
        data.push(0xFF); // compressed_int = -1, fails entry count validation

        let mut reader = make_reader(data);
        let dir = WzDirectoryEntry::parse(&mut reader).unwrap();

        // Subdirectory still present, just empty
        assert_eq!(dir.subdirectories.len(), 1);
        assert_eq!(dir.subdirectories[0].name, "bad");
        assert!(dir.subdirectories[0].subdirectories.is_empty());
        assert!(dir.subdirectories[0].images.is_empty());
    }
}

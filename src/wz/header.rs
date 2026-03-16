//! WZ file header parsing.
//!
//! The WZ header is the first structure in every .wz file:
//! - 4 bytes: "PKG1" identifier
//! - 8 bytes: file size (u64)
//! - 4 bytes: data start offset (u32, typically 0x3C / 60)
//! - Variable: copyright string (null-terminated)

use std::io::{Read, Seek, SeekFrom};

use super::error::{WzError, WzResult};

#[derive(Debug, Clone)]
pub struct WzHeader {
    pub ident: String,
    pub file_size: u64,
    pub data_start: u32,
    pub copyright: String,
}

impl WzHeader {
    pub fn dummy(file_size: u64) -> Self {
        WzHeader {
            ident: String::new(),
            file_size,
            data_start: 0,
            copyright: String::new(),
        }
    }

    pub fn parse<R: Read + Seek>(reader: &mut R) -> WzResult<Self> {
        reader.seek(SeekFrom::Start(0))?;

        let mut ident_buf = [0u8; 4];
        reader.read_exact(&mut ident_buf)?;
        let ident = String::from_utf8_lossy(&ident_buf).to_string();

        if ident != "PKG1" {
            return Err(WzError::InvalidHeader(ident));
        }

        let mut size_buf = [0u8; 8];
        reader.read_exact(&mut size_buf)?;
        let file_size = u64::from_le_bytes(size_buf);

        let mut start_buf = [0u8; 4];
        reader.read_exact(&mut start_buf)?;
        let data_start = u32::from_le_bytes(start_buf);

        let current_pos = reader.stream_position()? as u32;
        let copyright_len = data_start.saturating_sub(current_pos);
        let mut copyright_buf = vec![0u8; copyright_len as usize];
        reader.read_exact(&mut copyright_buf)?;

        let copyright = String::from_utf8_lossy(
            &copyright_buf[..copyright_buf
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(copyright_buf.len())],
        )
        .to_string();

        Ok(WzHeader {
            ident,
            file_size,
            data_start,
            copyright,
        })
    }

    pub fn write<W: std::io::Write>(&self, writer: &mut W) -> WzResult<()> {
        writer.write_all(b"PKG1")?;
        writer.write_all(&self.file_size.to_le_bytes())?;
        writer.write_all(&self.data_start.to_le_bytes())?;
        writer.write_all(self.copyright.as_bytes())?;

        let written = 4 + 8 + 4 + self.copyright.len() as u32;
        let padding = self.data_start.saturating_sub(written);
        for _ in 0..padding {
            writer.write_all(&[0])?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_parse_header() {
        let mut data = Vec::new();
        data.extend_from_slice(b"PKG1"); // ident
        data.extend_from_slice(&100u64.to_le_bytes()); // file_size
        data.extend_from_slice(&60u32.to_le_bytes()); // data_start = 0x3C
        // Copyright string to fill up to offset 60
        let copyright = b"Package file v1.0 Copyright 2009";
        data.extend_from_slice(copyright);
        // Pad to offset 60
        while data.len() < 60 {
            data.push(0);
        }

        let mut cursor = Cursor::new(data);
        let header = WzHeader::parse(&mut cursor).unwrap();

        assert_eq!(header.ident, "PKG1");
        assert_eq!(header.file_size, 100);
        assert_eq!(header.data_start, 60);
        assert!(header.copyright.starts_with("Package file"));
    }

    #[test]
    fn test_write_then_parse_roundtrip() {
        let original = WzHeader {
            ident: "PKG1".to_string(),
            file_size: 12345,
            data_start: 60,
            copyright: "Test Copyright".to_string(),
        };

        let mut buf = Vec::new();
        original.write(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let parsed = WzHeader::parse(&mut cursor).unwrap();

        assert_eq!(parsed.ident, "PKG1");
        assert_eq!(parsed.file_size, 12345);
        assert_eq!(parsed.data_start, 60);
        assert_eq!(parsed.copyright, "Test Copyright");
    }

    #[test]
    fn test_write_then_parse_empty_copyright() {
        let original = WzHeader {
            ident: "PKG1".to_string(),
            file_size: 500,
            data_start: 16, // minimum: 4 + 8 + 4 = 16
            copyright: String::new(),
        };

        let mut buf = Vec::new();
        original.write(&mut buf).unwrap();

        let mut cursor = Cursor::new(buf);
        let parsed = WzHeader::parse(&mut cursor).unwrap();

        assert_eq!(parsed.file_size, 500);
        assert_eq!(parsed.copyright, "");
    }

    #[test]
    fn test_parse_invalid_ident() {
        let mut data = Vec::new();
        data.extend_from_slice(b"BAD!"); // wrong ident
        data.extend_from_slice(&100u64.to_le_bytes());
        data.extend_from_slice(&16u32.to_le_bytes());

        let mut cursor = Cursor::new(data);
        let err = WzHeader::parse(&mut cursor).unwrap_err();
        matches!(err, WzError::InvalidHeader(_));
    }
}

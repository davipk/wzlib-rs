//! Enums and type definitions for WZ structures.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WzMapleVersion {
    Gms,
    Ems,
    Bms,
    Custom,
}

impl WzMapleVersion {
    pub fn iv(&self) -> [u8; 4] {
        match self {
            WzMapleVersion::Gms => crate::crypto::WZ_GMSIV,
            WzMapleVersion::Ems => crate::crypto::WZ_MSEAIV,
            WzMapleVersion::Bms => crate::crypto::WZ_BMSCLASSIC_IV,
            WzMapleVersion::Custom => [0; 4], // Caller must provide
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WzDirectoryType {
    UnknownType = 1,
    RetrieveStringFromOffset = 2,
    Directory = 3,
    Image = 4,
}

impl TryFrom<u8> for WzDirectoryType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(WzDirectoryType::UnknownType),
            2 => Ok(WzDirectoryType::RetrieveStringFromOffset),
            3 => Ok(WzDirectoryType::Directory),
            4 => Ok(WzDirectoryType::Image),
            _ => Err(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WzPngFormat {
    Bgra4444,      //    1 — 16-bit, 4 bits per channel
    Bgra8888,      //    2 — 32-bit, full color + alpha
    Dxt3Grayscale, //    3 — DXT3 black/white thumbnails
    Argb1555,      //  257 — 16-bit, 1-bit binary alpha
    Rgb565,        //  513 — 16-bit, no alpha
    Rgb565Block,   //  517 — RGB565 with 16×16 block compression
    R16,           //  769 — 16-bit single red channel
    Dxt3,          // 1026 — DXT3/BC2 colored
    Dxt5,          // 2050 — DXT5/BC3 smooth alpha gradients
    A8,            // 2304 — 8-bit alpha only
    Rgba1010102,   // 2562 — 10-bit RGB + 2-bit alpha
    Dxt1,          // 4097 — DXT1/BC1, 8 bytes per 4×4 block
    Bc7,           // 4098 — BC7 high-quality RGBA
    Rgba32Float,   // 4100 — 32-bit float per channel (HDR)
    Unknown(u32),  //    ? — raw combined value preserved for diagnostics
}

impl WzPngFormat {
    pub fn from_raw(format_low: i32, format_high: i32) -> Self {
        let combined = (format_low + (format_high << 8)) as u32;
        Self::from_combined(combined)
    }

    pub fn from_combined(value: u32) -> Self {
        match value {
            1 => WzPngFormat::Bgra4444,
            2 => WzPngFormat::Bgra8888,
            3 => WzPngFormat::Dxt3Grayscale,
            257 => WzPngFormat::Argb1555,
            513 => WzPngFormat::Rgb565,
            517 => WzPngFormat::Rgb565Block,
            769 => WzPngFormat::R16,
            1026 => WzPngFormat::Dxt3,
            2050 => WzPngFormat::Dxt5,
            2304 => WzPngFormat::A8,
            2562 => WzPngFormat::Rgba1010102,
            4097 => WzPngFormat::Dxt1,
            4098 => WzPngFormat::Bc7,
            4100 => WzPngFormat::Rgba32Float,
            _ => WzPngFormat::Unknown(value),
        }
    }

    pub fn format_id(&self) -> u32 {
        match self {
            WzPngFormat::Bgra4444 => 1,
            WzPngFormat::Bgra8888 => 2,
            WzPngFormat::Dxt3Grayscale => 3,
            WzPngFormat::Argb1555 => 257,
            WzPngFormat::Rgb565 => 513,
            WzPngFormat::Rgb565Block => 517,
            WzPngFormat::R16 => 769,
            WzPngFormat::Dxt3 => 1026,
            WzPngFormat::Dxt5 => 2050,
            WzPngFormat::A8 => 2304,
            WzPngFormat::Rgba1010102 => 2562,
            WzPngFormat::Dxt1 => 4097,
            WzPngFormat::Bc7 => 4098,
            WzPngFormat::Rgba32Float => 4100,
            WzPngFormat::Unknown(id) => *id,
        }
    }

    pub fn format_low(&self) -> i32 {
        (self.format_id() & 0xFF) as i32
    }

    pub fn format_high(&self) -> i32 {
        (self.format_id() >> 8) as i32
    }

    pub fn raw_data_size(&self, width: u32, height: u32) -> usize {
        let pixels = (width * height) as usize;
        let blocks_4x4 = || {
            let bw = (width as usize).div_ceil(4);
            let bh = (height as usize).div_ceil(4);
            bw * bh
        };

        match self {
            // Per-pixel formats (sorted by ID)
            WzPngFormat::Bgra4444
            | WzPngFormat::Argb1555
            | WzPngFormat::Rgb565
            | WzPngFormat::R16 => pixels * 2,
            WzPngFormat::Bgra8888 | WzPngFormat::Rgba1010102 => pixels * 4,
            WzPngFormat::Dxt3Grayscale => pixels * 4, // C# allocates w*h*4
            WzPngFormat::A8 => pixels,
            WzPngFormat::Rgba32Float => pixels * 16,
            WzPngFormat::Rgb565Block => pixels / 128, // 16×16 blocks, 2 bytes each

            // 4×4 block-compressed formats
            WzPngFormat::Dxt1 => blocks_4x4() * 8, //  8 bytes/block
            WzPngFormat::Dxt3 | WzPngFormat::Dxt5 | WzPngFormat::Bc7 => blocks_4x4() * 16, // 16 bytes/block

            WzPngFormat::Unknown(_) => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── WzPngFormat from_combined / format_id roundtrip ────────────

    #[test]
    fn test_png_format_roundtrip_all_known() {
        let ids: &[(u32, WzPngFormat)] = &[
            (1, WzPngFormat::Bgra4444),
            (2, WzPngFormat::Bgra8888),
            (3, WzPngFormat::Dxt3Grayscale),
            (257, WzPngFormat::Argb1555),
            (513, WzPngFormat::Rgb565),
            (517, WzPngFormat::Rgb565Block),
            (769, WzPngFormat::R16),
            (1026, WzPngFormat::Dxt3),
            (2050, WzPngFormat::Dxt5),
            (2304, WzPngFormat::A8),
            (2562, WzPngFormat::Rgba1010102),
            (4097, WzPngFormat::Dxt1),
            (4098, WzPngFormat::Bc7),
            (4100, WzPngFormat::Rgba32Float),
        ];
        for &(id, expected) in ids {
            let parsed = WzPngFormat::from_combined(id);
            assert_eq!(parsed, expected, "from_combined({}) mismatch", id);
            assert_eq!(
                parsed.format_id(),
                id,
                "format_id() mismatch for {:?}",
                expected
            );
        }
    }

    #[test]
    fn test_png_format_unknown_roundtrip() {
        let fmt = WzPngFormat::from_combined(999);
        assert_eq!(fmt, WzPngFormat::Unknown(999));
        assert_eq!(fmt.format_id(), 999);
    }

    #[test]
    fn test_png_format_from_raw() {
        // Argb1555 = 257 = 1 + (1 << 8)
        assert_eq!(WzPngFormat::from_raw(1, 1), WzPngFormat::Argb1555);
        // Rgb565 = 513 = 1 + (2 << 8)
        assert_eq!(WzPngFormat::from_raw(1, 2), WzPngFormat::Rgb565);
        // Bgra4444 = 1 = 1 + (0 << 8)
        assert_eq!(WzPngFormat::from_raw(1, 0), WzPngFormat::Bgra4444);
        // Dxt3 = 1026 = 2 + (4 << 8)
        assert_eq!(WzPngFormat::from_raw(2, 4), WzPngFormat::Dxt3);
        // Dxt5 = 2050 = 2 + (8 << 8)
        assert_eq!(WzPngFormat::from_raw(2, 8), WzPngFormat::Dxt5);
    }

    // ── raw_data_size ──────────────────────────────────────────────

    #[test]
    fn test_raw_data_size_per_pixel_formats() {
        // 4×4 = 16 pixels
        assert_eq!(WzPngFormat::Bgra4444.raw_data_size(4, 4), 32); // 16 * 2
        assert_eq!(WzPngFormat::Bgra8888.raw_data_size(4, 4), 64); // 16 * 4
        assert_eq!(WzPngFormat::Argb1555.raw_data_size(4, 4), 32); // 16 * 2
        assert_eq!(WzPngFormat::Rgb565.raw_data_size(4, 4), 32); // 16 * 2
        assert_eq!(WzPngFormat::R16.raw_data_size(4, 4), 32); // 16 * 2
        assert_eq!(WzPngFormat::A8.raw_data_size(4, 4), 16); // 16 * 1
        assert_eq!(WzPngFormat::Rgba1010102.raw_data_size(4, 4), 64); // 16 * 4
        assert_eq!(WzPngFormat::Rgba32Float.raw_data_size(4, 4), 256); // 16 * 16
    }

    #[test]
    fn test_raw_data_size_block_formats() {
        // 4×4 = 1 block
        assert_eq!(WzPngFormat::Dxt1.raw_data_size(4, 4), 8); // 1 block * 8
        assert_eq!(WzPngFormat::Dxt3.raw_data_size(4, 4), 16); // 1 block * 16
        assert_eq!(WzPngFormat::Dxt5.raw_data_size(4, 4), 16); // 1 block * 16
        assert_eq!(WzPngFormat::Bc7.raw_data_size(4, 4), 16); // 1 block * 16

        // 8×8 = 4 blocks (2×2)
        assert_eq!(WzPngFormat::Dxt1.raw_data_size(8, 8), 32); // 4 * 8
        assert_eq!(WzPngFormat::Dxt3.raw_data_size(8, 8), 64); // 4 * 16

        // Non-multiple of 4: 5×5 → ceil(5/4)=2 → 2×2=4 blocks
        assert_eq!(WzPngFormat::Dxt1.raw_data_size(5, 5), 32); // 4 * 8
    }

    #[test]
    fn test_raw_data_size_unknown_returns_zero() {
        assert_eq!(WzPngFormat::Unknown(999).raw_data_size(100, 100), 0);
    }

    // ── WzDirectoryType TryFrom ────────────────────────────────────

    #[test]
    fn test_directory_type_valid() {
        assert_eq!(
            WzDirectoryType::try_from(1u8),
            Ok(WzDirectoryType::UnknownType)
        );
        assert_eq!(
            WzDirectoryType::try_from(2u8),
            Ok(WzDirectoryType::RetrieveStringFromOffset)
        );
        assert_eq!(
            WzDirectoryType::try_from(3u8),
            Ok(WzDirectoryType::Directory)
        );
        assert_eq!(WzDirectoryType::try_from(4u8), Ok(WzDirectoryType::Image));
    }

    #[test]
    fn test_directory_type_invalid() {
        assert_eq!(WzDirectoryType::try_from(0u8), Err(0));
        assert_eq!(WzDirectoryType::try_from(5u8), Err(5));
        assert_eq!(WzDirectoryType::try_from(255u8), Err(255));
    }

    // ── WzMapleVersion IV ──────────────────────────────────────────

    #[test]
    fn test_maple_version_iv() {
        assert_eq!(WzMapleVersion::Gms.iv(), [0x4D, 0x23, 0xC7, 0x2B]);
        assert_eq!(WzMapleVersion::Ems.iv(), [0xB9, 0x7D, 0x63, 0xE9]);
        assert_eq!(WzMapleVersion::Bms.iv(), [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(WzMapleVersion::Custom.iv(), [0x00, 0x00, 0x00, 0x00]);
    }
}

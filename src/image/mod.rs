//! Image decoding and encoding — pixel format conversion, DXT decompression, zlib compression.
//!
//! Ported from MapleLib's `PngUtility.cs` and `WzPngProperty.cs`.
//! Decoders output RGBA8888; encoders accept RGBA8888 and produce WZ-native formats.

pub mod dxt;
pub mod encode;
pub mod pixel;

use crate::wz::error::{WzError, WzResult};
use crate::wz::types::WzPngFormat;

// Tolerates short data by zero-padding (matches C# pre-allocated buffer behavior).
pub fn decode_pixels(
    raw: &[u8],
    width: u32,
    height: u32,
    format: WzPngFormat,
) -> WzResult<Vec<u8>> {
    use std::borrow::Cow;

    let expected = format.raw_data_size(width, height);

    let data: Cow<[u8]> = if expected > 0 && raw.len() < expected {
        let mut padded = raw.to_vec();
        padded.resize(expected, 0);
        Cow::Owned(padded)
    } else {
        Cow::Borrowed(raw)
    };

    let pixel_count = (width * height) as usize;
    match format {
        //   1 — BGRA4444
        WzPngFormat::Bgra4444 => pixel::bgra4444_to_rgba(&data, pixel_count),
        //   2 — BGRA8888
        WzPngFormat::Bgra8888 => pixel::bgra8888_to_rgba(&data, pixel_count),
        //   3 — DXT3 grayscale  /  1026 — DXT3 colored
        WzPngFormat::Dxt3Grayscale | WzPngFormat::Dxt3 => {
            dxt::decompress_dxt3(&data, width, height)
        }
        // 257 — ARGB1555
        WzPngFormat::Argb1555 => pixel::argb1555_to_rgba(&data, pixel_count),
        // 513 — RGB565
        WzPngFormat::Rgb565 => pixel::rgb565_to_rgba(&data, pixel_count),
        // 517 — RGB565 block
        WzPngFormat::Rgb565Block => pixel::rgb565_block_to_rgba(&data, width, height),
        // 769 — R16
        WzPngFormat::R16 => pixel::r16_to_rgba(&data, pixel_count),
        // 2050 — DXT5
        WzPngFormat::Dxt5 => dxt::decompress_dxt5(&data, width, height),
        // 2304 — A8
        WzPngFormat::A8 => pixel::a8_to_rgba(&data, pixel_count),
        // 2562 — RGBA1010102
        WzPngFormat::Rgba1010102 => pixel::rgba1010102_to_rgba(&data, pixel_count),
        // 4097 — DXT1/BC1
        WzPngFormat::Dxt1 => dxt::decompress_dxt1(&data, width, height),
        // 4098 — BC7
        WzPngFormat::Bc7 => dxt::decompress_bc7(&data, width, height),
        // 4100 — RGBA32Float
        WzPngFormat::Rgba32Float => pixel::rgba32float_to_rgba(&data, pixel_count),

        WzPngFormat::Unknown(id) => Err(WzError::UnsupportedPngFormat(id)),
    }
}

pub fn decompress_png_data(compressed: &[u8], wz_key: Option<&[u8]>) -> WzResult<Vec<u8>> {
    use flate2::read::{DeflateDecoder, ZlibDecoder};
    use std::io::{Cursor, Read};

    if compressed.len() < 2 {
        return Err(WzError::DecompressionFailed("Data too short".into()));
    }

    let is_zlib = matches!(
        (compressed[0], compressed[1]),
        (0x78, 0x9C) | (0x78, 0xDA) | (0x78, 0x01) | (0x78, 0x5E)
    );

    let mut output = Vec::new();

    if is_zlib {
        let mut decoder = ZlibDecoder::new(compressed);
        decoder
            .read_to_end(&mut output)
            .map_err(|e| WzError::DecompressionFailed(e.to_string()))?;
    } else if let Some(key) = wz_key {
        // list.wz encrypted block format: [blocksize:i32][XOR'd bytes]... → zlib after decrypt
        let mut cursor = Cursor::new(compressed);
        let mut decrypted = Vec::new();
        let end = compressed.len() as u64;

        while cursor.position() < end {
            let mut size_buf = [0u8; 4];
            std::io::Read::read_exact(&mut cursor, &mut size_buf)
                .map_err(|e| WzError::DecompressionFailed(e.to_string()))?;
            let block_size = i32::from_le_bytes(size_buf) as usize;

            let mut block = vec![0u8; block_size];
            std::io::Read::read_exact(&mut cursor, &mut block)
                .map_err(|e| WzError::DecompressionFailed(e.to_string()))?;

            for i in 0..block_size {
                if i < key.len() {
                    block[i] ^= key[i];
                }
            }
            decrypted.extend_from_slice(&block);
        }

        if decrypted.len() < 2 {
            return Err(WzError::DecompressionFailed(
                "Decrypted list.wz data too short".into(),
            ));
        }
        let mut decoder = DeflateDecoder::new(&decrypted[2..]); // skip 2-byte zlib header
        decoder
            .read_to_end(&mut output)
            .map_err(|e| WzError::DecompressionFailed(e.to_string()))?;
    } else {
        let mut decoder = DeflateDecoder::new(compressed);
        decoder
            .read_to_end(&mut output)
            .map_err(|e| WzError::DecompressionFailed(e.to_string()))?;
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    // ── decode_pixels ──────────────────────────────────────────────

    #[test]
    fn test_decode_pixels_bgra8888_white() {
        // 2×2 BGRA8888 all-white: B=FF, G=FF, R=FF, A=FF per pixel
        let raw = vec![0xFF; 2 * 2 * 4]; // 16 bytes
        let result = decode_pixels(&raw, 2, 2, WzPngFormat::Bgra8888).unwrap();
        assert_eq!(result.len(), 16); // 2*2*4
                                      // After BGRA→RGBA swap, still all 0xFF
        assert!(result.iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_decode_pixels_a8() {
        // 2×2 A8: alpha values [0, 128, 255, 64]
        let raw = vec![0, 128, 255, 64];
        let result = decode_pixels(&raw, 2, 2, WzPngFormat::A8).unwrap();
        assert_eq!(result.len(), 16);
        // Pixel 0: R=255, G=255, B=255, A=0
        assert_eq!(&result[0..4], &[255, 255, 255, 0]);
        // Pixel 2: R=255, G=255, B=255, A=255
        assert_eq!(&result[8..12], &[255, 255, 255, 255]);
    }

    #[test]
    fn test_decode_pixels_unknown_format_error() {
        let raw = vec![0; 16];
        let err = decode_pixels(&raw, 2, 2, WzPngFormat::Unknown(999)).unwrap_err();
        matches!(err, WzError::UnsupportedPngFormat(999));
    }

    #[test]
    fn test_decode_pixels_short_data_zero_padded() {
        // BGRA8888 2×2 expects 16 bytes, provide only 8 → zero-padded
        let raw = vec![0xFF; 8]; // only half the data
        let result = decode_pixels(&raw, 2, 2, WzPngFormat::Bgra8888).unwrap();
        assert_eq!(result.len(), 16);
        // First 2 pixels have data, last 2 are zero-padded
        // Pixel 0: B=FF,G=FF,R=FF,A=FF → R=FF,G=FF,B=FF,A=FF
        assert_eq!(&result[0..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
        // Pixel 2 (padded zeros): B=0,G=0,R=0,A=0 → R=0,G=0,B=0,A=0
        assert_eq!(&result[8..12], &[0, 0, 0, 0]);
    }

    // ── decompress_png_data ────────────────────────────────────────

    #[test]
    fn test_decompress_png_data_zlib() {
        // Compress known data with zlib, then decompress
        let original = b"Hello, WZ world!";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let compressed = encoder.finish().unwrap();

        let result = decompress_png_data(&compressed, None).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_decompress_png_data_too_short() {
        let err = decompress_png_data(&[0x78], None).unwrap_err();
        matches!(err, WzError::DecompressionFailed(_));
    }

    #[test]
    fn test_decompress_png_data_encrypted_blocks() {
        // Build encrypted block format: [block_size:i32][encrypted_bytes:block_size]
        // With zero-key, XOR with key is a no-op, so we just need valid zlib after the 2-byte skip
        let original = b"test data for blocks";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original).unwrap();
        let zlib_data = encoder.finish().unwrap();

        // key = all zeros (BMS), so encrypted = plaintext.
        // Format: i32(block_size) + block_bytes
        let block_size = zlib_data.len() as i32;
        let mut compressed = Vec::new();
        compressed.extend_from_slice(&block_size.to_le_bytes());
        compressed.extend_from_slice(&zlib_data);

        let key = vec![0u8; zlib_data.len()]; // zero key
        let result = decompress_png_data(&compressed, Some(&key)).unwrap();
        assert_eq!(result, original);
    }
}

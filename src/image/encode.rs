//! Pixel format encoding and PNG data compression — the reverse of the decode path.
//!
//! `encode_pixels` converts RGBA8888 → target WZ pixel format.
//! `compress_png_data` zlib-compresses raw pixel data for storage in WZ Canvas nodes.

use crate::wz::error::{WzError, WzResult};
use crate::wz::types::WzPngFormat;

// DXT/BC block-compressed formats are not supported for encoding —
// use Bgra8888 as a lossless default for imported images.
pub fn encode_pixels(
    rgba: &[u8],
    width: u32,
    height: u32,
    format: WzPngFormat,
) -> WzResult<Vec<u8>> {
    let pixel_count = (width * height) as usize;
    if rgba.len() < pixel_count * 4 {
        return Err(WzError::Custom(format!(
            "RGBA data too short: need {} bytes, got {}",
            pixel_count * 4,
            rgba.len()
        )));
    }

    match format {
        WzPngFormat::Bgra4444 => Ok(rgba_to_bgra4444(rgba, pixel_count)),
        WzPngFormat::Bgra8888 => Ok(rgba_to_bgra8888(rgba, pixel_count)),
        WzPngFormat::Argb1555 => Ok(rgba_to_argb1555(rgba, pixel_count)),
        WzPngFormat::Rgb565 => Ok(rgba_to_rgb565(rgba, pixel_count)),
        WzPngFormat::R16 => Ok(rgba_to_r16(rgba, pixel_count)),
        WzPngFormat::A8 => Ok(rgba_to_a8(rgba, pixel_count)),
        WzPngFormat::Rgba1010102 => Ok(rgba_to_rgba1010102(rgba, pixel_count)),
        WzPngFormat::Rgba32Float => Ok(rgba_to_rgba32float(rgba, pixel_count)),
        _ => Err(WzError::Custom(format!(
            "Encoding not supported for format {:?} — use Bgra8888 instead",
            format
        ))),
    }
}

pub fn compress_png_data(raw: &[u8]) -> WzResult<Vec<u8>> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(raw)
        .map_err(|e| WzError::Custom(format!("Zlib compression failed: {}", e)))?;
    encoder
        .finish()
        .map_err(|e| WzError::Custom(format!("Zlib compression finish failed: {}", e)))
}

// ── Per-format encoders ─────────────────────────────────────────────

fn rgba_to_bgra4444(rgba: &[u8], pixel_count: usize) -> Vec<u8> {
    let mut out = vec![0u8; pixel_count * 2];
    for i in 0..pixel_count {
        let (r, g, b, a) = (
            rgba[i * 4],
            rgba[i * 4 + 1],
            rgba[i * 4 + 2],
            rgba[i * 4 + 3],
        );
        let r4 = r >> 4;
        let g4 = g >> 4;
        let b4 = b >> 4;
        let a4 = a >> 4;
        // lo = [B3..B0 | G3..G0], hi = [R3..R0 | A3..A0]
        out[i * 2] = b4 | (g4 << 4);
        out[i * 2 + 1] = r4 | (a4 << 4);
    }
    out
}

fn rgba_to_bgra8888(rgba: &[u8], pixel_count: usize) -> Vec<u8> {
    let mut out = vec![0u8; pixel_count * 4];
    for i in 0..pixel_count {
        out[i * 4] = rgba[i * 4 + 2]; // B
        out[i * 4 + 1] = rgba[i * 4 + 1]; // G
        out[i * 4 + 2] = rgba[i * 4]; // R
        out[i * 4 + 3] = rgba[i * 4 + 3]; // A
    }
    out
}

fn rgba_to_argb1555(rgba: &[u8], pixel_count: usize) -> Vec<u8> {
    let mut out = vec![0u8; pixel_count * 2];
    for i in 0..pixel_count {
        let (r, g, b, a) = (
            rgba[i * 4],
            rgba[i * 4 + 1],
            rgba[i * 4 + 2],
            rgba[i * 4 + 3],
        );
        let r5 = (r as u16 >> 3) & 0x1F;
        let g5 = (g as u16 >> 3) & 0x1F;
        let b5 = (b as u16 >> 3) & 0x1F;
        let a1: u16 = if a >= 128 { 1 } else { 0 };
        let val = (a1 << 15) | (r5 << 10) | (g5 << 5) | b5;
        out[i * 2..i * 2 + 2].copy_from_slice(&val.to_le_bytes());
    }
    out
}

fn rgba_to_rgb565(rgba: &[u8], pixel_count: usize) -> Vec<u8> {
    let mut out = vec![0u8; pixel_count * 2];
    for i in 0..pixel_count {
        let (r, g, b) = (rgba[i * 4], rgba[i * 4 + 1], rgba[i * 4 + 2]);
        let r5 = (r as u16 >> 3) & 0x1F;
        let g6 = (g as u16 >> 2) & 0x3F;
        let b5 = (b as u16 >> 3) & 0x1F;
        let val = (r5 << 11) | (g6 << 5) | b5;
        out[i * 2..i * 2 + 2].copy_from_slice(&val.to_le_bytes());
    }
    out
}

fn rgba_to_r16(rgba: &[u8], pixel_count: usize) -> Vec<u8> {
    let mut out = vec![0u8; pixel_count * 2];
    for i in 0..pixel_count {
        let r = rgba[i * 4];
        // High byte = red channel, low byte = 0
        out[i * 2] = 0;
        out[i * 2 + 1] = r;
    }
    out
}

fn rgba_to_a8(rgba: &[u8], pixel_count: usize) -> Vec<u8> {
    let mut out = vec![0u8; pixel_count];
    for i in 0..pixel_count {
        out[i] = rgba[i * 4 + 3]; // alpha channel
    }
    out
}

fn rgba_to_rgba1010102(rgba: &[u8], pixel_count: usize) -> Vec<u8> {
    let mut out = vec![0u8; pixel_count * 4];
    for i in 0..pixel_count {
        let (r, g, b, a) = (
            rgba[i * 4],
            rgba[i * 4 + 1],
            rgba[i * 4 + 2],
            rgba[i * 4 + 3],
        );
        // 8-bit → 10-bit: (val << 2) | (val >> 6)
        let r10 = ((r as u32) << 2) | ((r as u32) >> 6);
        let g10 = ((g as u32) << 2) | ((g as u32) >> 6);
        let b10 = ((b as u32) << 2) | ((b as u32) >> 6);
        // 8-bit → 2-bit: val / 85
        let a2 = (a as u32) / 85;
        let val = r10 | (g10 << 10) | (b10 << 20) | (a2 << 30);
        out[i * 4..i * 4 + 4].copy_from_slice(&val.to_le_bytes());
    }
    out
}

fn rgba_to_rgba32float(rgba: &[u8], pixel_count: usize) -> Vec<u8> {
    let mut out = vec![0u8; pixel_count * 16];
    for i in 0..pixel_count {
        let r = rgba[i * 4] as f32 / 255.0;
        let g = rgba[i * 4 + 1] as f32 / 255.0;
        let b = rgba[i * 4 + 2] as f32 / 255.0;
        let a = rgba[i * 4 + 3] as f32 / 255.0;
        out[i * 16..i * 16 + 4].copy_from_slice(&r.to_le_bytes());
        out[i * 16 + 4..i * 16 + 8].copy_from_slice(&g.to_le_bytes());
        out[i * 16 + 8..i * 16 + 12].copy_from_slice(&b.to_le_bytes());
        out[i * 16 + 12..i * 16 + 16].copy_from_slice(&a.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::{decode_pixels, decompress_png_data};

    // ── Roundtrip: encode → decode should recover original RGBA ──────

    #[test]
    fn test_bgra8888_roundtrip() {
        let rgba = vec![0xFF, 0x80, 0x00, 0xC0, 0x10, 0x20, 0x30, 0x40];
        let encoded = encode_pixels(&rgba, 2, 1, WzPngFormat::Bgra8888).unwrap();
        let decoded = decode_pixels(&encoded, 2, 1, WzPngFormat::Bgra8888).unwrap();
        assert_eq!(decoded, rgba);
    }

    #[test]
    fn test_bgra4444_roundtrip_lossy() {
        // 4-bit quantization is lossy — high nibble should survive
        let rgba = vec![0xF0, 0x80, 0x30, 0xA0];
        let encoded = encode_pixels(&rgba, 1, 1, WzPngFormat::Bgra4444).unwrap();
        let decoded = decode_pixels(&encoded, 1, 1, WzPngFormat::Bgra4444).unwrap();
        // Each channel: val >> 4 then (nibble << 4) | nibble
        assert_eq!(decoded[0], 0xFF); // 0xF0 >> 4 = 0xF → 0xFF
        assert_eq!(decoded[1], 0x88); // 0x80 >> 4 = 0x8 → 0x88
        assert_eq!(decoded[2], 0x33); // 0x30 >> 4 = 0x3 → 0x33
        assert_eq!(decoded[3], 0xAA); // 0xA0 >> 4 = 0xA → 0xAA
    }

    #[test]
    fn test_argb1555_roundtrip_lossy() {
        // 5-bit quantization + 1-bit alpha
        let rgba = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let encoded = encode_pixels(&rgba, 1, 1, WzPngFormat::Argb1555).unwrap();
        let decoded = decode_pixels(&encoded, 1, 1, WzPngFormat::Argb1555).unwrap();
        assert_eq!(decoded, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_rgb565_roundtrip_lossy() {
        let rgba = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let encoded = encode_pixels(&rgba, 1, 1, WzPngFormat::Rgb565).unwrap();
        let decoded = decode_pixels(&encoded, 1, 1, WzPngFormat::Rgb565).unwrap();
        assert_eq!(decoded, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_a8_roundtrip() {
        let rgba = vec![0xFF, 0xFF, 0xFF, 0x80];
        let encoded = encode_pixels(&rgba, 1, 1, WzPngFormat::A8).unwrap();
        assert_eq!(encoded, vec![0x80]);
        let decoded = decode_pixels(&encoded, 1, 1, WzPngFormat::A8).unwrap();
        assert_eq!(decoded[3], 0x80);
    }

    #[test]
    fn test_r16_roundtrip() {
        let rgba = vec![0xAB, 0x00, 0x00, 0xFF];
        let encoded = encode_pixels(&rgba, 1, 1, WzPngFormat::R16).unwrap();
        let decoded = decode_pixels(&encoded, 1, 1, WzPngFormat::R16).unwrap();
        assert_eq!(decoded[0], 0xAB);
    }

    #[test]
    fn test_rgba1010102_roundtrip_lossy() {
        let rgba = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let encoded = encode_pixels(&rgba, 1, 1, WzPngFormat::Rgba1010102).unwrap();
        let decoded = decode_pixels(&encoded, 1, 1, WzPngFormat::Rgba1010102).unwrap();
        assert_eq!(decoded, vec![0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_dxt_encoding_unsupported() {
        let rgba = vec![0; 64]; // 4x4
        assert!(encode_pixels(&rgba, 4, 4, WzPngFormat::Dxt3).is_err());
        assert!(encode_pixels(&rgba, 4, 4, WzPngFormat::Dxt5).is_err());
        assert!(encode_pixels(&rgba, 4, 4, WzPngFormat::Bc7).is_err());
    }

    #[test]
    fn test_short_input_rejected() {
        assert!(encode_pixels(&[0; 3], 1, 1, WzPngFormat::Bgra8888).is_err());
    }

    // ── compress → decompress roundtrip ──────────────────────────────

    #[test]
    fn test_compress_decompress_roundtrip() {
        let raw = vec![0xAA; 1024];
        let compressed = compress_png_data(&raw).unwrap();
        let decompressed = decompress_png_data(&compressed, None).unwrap();
        assert_eq!(decompressed, raw);
    }

    #[test]
    fn test_compress_actually_compresses() {
        // Repetitive data should compress significantly
        let raw = vec![0x42; 4096];
        let compressed = compress_png_data(&raw).unwrap();
        assert!(compressed.len() < raw.len() / 2);
    }
}

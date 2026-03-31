//! Block compression decompression: DXT1/BC1, DXT3/BC2, DXT5/BC3, BC7.
//!
//! DXT1 blocks are 8 bytes per 4x4 tile; DXT3/DXT5/BC7 are 16 bytes.
//! Output is always RGBA8888.

use super::pixel::rgb565_decode;
use crate::wz::error::{WzError, WzResult};

/// Shared DXT3/DXT5 block decompression — only the alpha expansion differs.
fn decompress_dxt_block(
    data: &[u8],
    width: u32,
    height: u32,
    format_name: &str,
    expand_alpha: fn(&[u8]) -> [u8; 16],
) -> WzResult<Vec<u8>> {
    let pixel_count = (width * height) as usize;
    let mut rgba = vec![0u8; pixel_count * 4];

    let blocks_x = width.div_ceil(4) as usize;
    let blocks_y = height.div_ceil(4) as usize;

    let block_count = blocks_x * blocks_y;
    if data.len() < block_count * 16 {
        return Err(WzError::DecompressionFailed(
            format!("{} data too short", format_name),
        ));
    }

    for by in 0..blocks_y {
        for bx in 0..blocks_x {
            let block_idx = (by * blocks_x + bx) * 16;
            let block = &data[block_idx..block_idx + 16];

            let alpha = expand_alpha(&block[0..8]);
            let colors = expand_color_table(block[8], block[9], block[10], block[11]);
            let indices = expand_color_indices(&block[12..16]);

            for py in 0..4u32 {
                for px in 0..4u32 {
                    let img_x = bx as u32 * 4 + px;
                    let img_y = by as u32 * 4 + py;
                    if img_x >= width || img_y >= height {
                        continue;
                    }

                    let pixel_idx = (py * 4 + px) as usize;
                    let color_idx = indices[pixel_idx] as usize;
                    let (r, g, b) = colors[color_idx];
                    let a = alpha[pixel_idx];

                    let out_idx = (img_y * width + img_x) as usize * 4;
                    rgba[out_idx] = r;
                    rgba[out_idx + 1] = g;
                    rgba[out_idx + 2] = b;
                    rgba[out_idx + 3] = a;
                }
            }
        }
    }

    Ok(rgba)
}

pub fn decompress_dxt3(data: &[u8], width: u32, height: u32) -> WzResult<Vec<u8>> {
    decompress_dxt_block(data, width, height, "DXT3", expand_alpha_dxt3)
}

pub fn decompress_dxt5(data: &[u8], width: u32, height: u32) -> WzResult<Vec<u8>> {
    decompress_dxt_block(data, width, height, "DXT5", expand_alpha_dxt5)
}

type Texture2dDecodeFn = fn(&[u8], usize, usize, &mut [u32]) -> Result<(), &'static str>;

/// Shared wrapper for texture2ddecoder-based formats (DXT1/BC1, BC7).
fn decode_via_texture2d(
    data: &[u8],
    width: u32,
    height: u32,
    decode_fn: Texture2dDecodeFn,
) -> WzResult<Vec<u8>> {
    let w = width as usize;
    let h = height as usize;
    let pixel_count = w * h;
    let mut buf = vec![0u32; pixel_count];

    decode_fn(data, w, h, &mut buf)
        .map_err(|e| WzError::DecompressionFailed(e.into()))?;

    let mut rgba = Vec::with_capacity(pixel_count * 4);
    for &pixel in &buf {
        rgba.extend_from_slice(&pixel.to_le_bytes());
    }
    Ok(rgba)
}

pub fn decompress_dxt1(data: &[u8], width: u32, height: u32) -> WzResult<Vec<u8>> {
    decode_via_texture2d(data, width, height, texture2ddecoder::decode_bc1)
}

pub fn decompress_bc7(data: &[u8], width: u32, height: u32) -> WzResult<Vec<u8>> {
    decode_via_texture2d(data, width, height, texture2ddecoder::decode_bc7)
}

fn expand_alpha_dxt3(data: &[u8]) -> [u8; 16] {
    let mut alpha = [0u8; 16];
    for i in 0..8 {
        let lo = data[i] & 0x0F;
        let hi = (data[i] >> 4) & 0x0F;
        alpha[i * 2] = lo | (lo << 4);
        alpha[i * 2 + 1] = hi | (hi << 4);
    }
    alpha
}

fn expand_alpha_dxt5(data: &[u8]) -> [u8; 16] {
    let a0 = data[0] as u16;
    let a1 = data[1] as u16;

    // Build 8-entry alpha lookup table
    let mut table = [0u8; 8];
    table[0] = a0 as u8;
    table[1] = a1 as u8;

    if a0 > a1 {
        // 7-value codebook
        for i in 2..8u16 {
            table[i as usize] = (((8 - i) * a0 + (i - 1) * a1 + 3) / 7) as u8;
        }
    } else {
        // 5-value codebook + 0 and 255
        for i in 2..6u16 {
            table[i as usize] = (((6 - i) * a0 + (i - 1) * a1 + 2) / 5) as u8;
        }
        table[6] = 0;
        table[7] = 255;
    }

    // Unpack 3-bit indices from 6 bytes (48 bits for 16 pixels)
    let mut alpha = [0u8; 16];

    // First 8 pixels from bytes 2-4
    let bits_lo = data[2] as u32 | ((data[3] as u32) << 8) | ((data[4] as u32) << 16);
    for (i, a) in alpha[..8].iter_mut().enumerate() {
        let idx = ((bits_lo >> (i * 3)) & 0x07) as usize;
        *a = table[idx];
    }

    // Next 8 pixels from bytes 5-7
    let bits_hi = data[5] as u32 | ((data[6] as u32) << 8) | ((data[7] as u32) << 16);
    for (i, a) in alpha[8..16].iter_mut().enumerate() {
        let idx = ((bits_hi >> (i * 3)) & 0x07) as usize;
        *a = table[idx];
    }

    alpha
}

// Always 4-color interpolation — the 3-color mode with transparent black
// (when c0 <= c1) is DXT1-only; DXT3/DXT5 store alpha separately.
fn expand_color_table(c0_lo: u8, c0_hi: u8, c1_lo: u8, c1_hi: u8) -> [(u8, u8, u8); 4] {
    let c0_raw = u16::from_le_bytes([c0_lo, c0_hi]);
    let c1_raw = u16::from_le_bytes([c1_lo, c1_hi]);

    let (r0, g0, b0) = rgb565_decode(c0_raw);
    let (r1, g1, b1) = rgb565_decode(c1_raw);

    [
        (r0, g0, b0),
        (r1, g1, b1),
        (
            ((r0 as u16 * 2 + r1 as u16 + 1) / 3) as u8,
            ((g0 as u16 * 2 + g1 as u16 + 1) / 3) as u8,
            ((b0 as u16 * 2 + b1 as u16 + 1) / 3) as u8,
        ),
        (
            ((r0 as u16 + r1 as u16 * 2 + 1) / 3) as u8,
            ((g0 as u16 + g1 as u16 * 2 + 1) / 3) as u8,
            ((b0 as u16 + b1 as u16 * 2 + 1) / 3) as u8,
        ),
    ]
}

fn expand_color_indices(data: &[u8]) -> [u8; 16] {
    let mut indices = [0u8; 16];
    for i in 0..4 {
        indices[i * 4] = data[i] & 0x03;
        indices[i * 4 + 1] = (data[i] >> 2) & 0x03;
        indices[i * 4 + 2] = (data[i] >> 4) & 0x03;
        indices[i * 4 + 3] = (data[i] >> 6) & 0x03;
    }
    indices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_alpha_dxt3() {
        let data = [0x0F, 0xF0, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00];
        let alpha = expand_alpha_dxt3(&data);
        // First byte 0x0F: lo=0xF→0xFF, hi=0x0→0x00
        assert_eq!(alpha[0], 0xFF);
        assert_eq!(alpha[1], 0x00);
        // Second byte 0xF0: lo=0x0→0x00, hi=0xF→0xFF
        assert_eq!(alpha[2], 0x00);
        assert_eq!(alpha[3], 0xFF);
    }

    #[test]
    fn test_expand_color_indices() {
        let data = [0b11_10_01_00, 0, 0, 0];
        let indices = expand_color_indices(&data);
        assert_eq!(indices[0], 0);
        assert_eq!(indices[1], 1);
        assert_eq!(indices[2], 2);
        assert_eq!(indices[3], 3);
    }

    #[test]
    fn test_decompress_dxt3_minimal() {
        // 4x4 block = exactly 1 DXT3 block = 16 bytes
        let mut block = [0u8; 16];
        // All alpha = full
        block[0..8].fill(0xFF);
        // Color 0 = white (0xFFFF), Color 1 = black (0x0000)
        block[8] = 0xFF;
        block[9] = 0xFF;
        block[10] = 0x00;
        block[11] = 0x00;
        // All pixels use color index 0 (white)
        block[12..16].fill(0x00);

        let result = decompress_dxt3(&block, 4, 4).unwrap();
        assert_eq!(result.len(), 64); // 4*4*4 = 64 bytes
        // First pixel should be white with full alpha
        assert_eq!(result[0], 0xFF); // R
        assert_eq!(result[1], 0xFF); // G
        assert_eq!(result[2], 0xFF); // B
        assert_eq!(result[3], 0xFF); // A
    }

    // ── expand_alpha_dxt5 ──────────────────────────────────────────

    #[test]
    fn test_expand_alpha_dxt5_endpoints_max_min() {
        // a0=255, a1=0 → 7-value codebook since a0 > a1
        // All indices = 0 → all pixels get a0=255
        let mut data = [0u8; 8];
        data[0] = 255; // a0
        data[1] = 0;   // a1
        // indices all zero (bytes 2-7 = 0)
        let alpha = expand_alpha_dxt5(&data);
        assert_eq!(alpha[0], 255);
        assert_eq!(alpha[15], 255);
    }

    #[test]
    fn test_expand_alpha_dxt5_all_index_1() {
        // a0=255, a1=0 → 7-value codebook
        // All indices = 1 → all pixels get a1=0
        let mut data = [0u8; 8];
        data[0] = 255; // a0
        data[1] = 0;   // a1
        // Pack index=1 (binary 001) for first 8 pixels in bytes 2-4
        // 001_001_001_001_001_001_001_001 = 0x249249 (24 bits)
        data[2] = 0x49; // 0100_1001
        data[3] = 0x92; // 1001_0010
        data[4] = 0x24; // 0010_0100
        // Same for next 8 pixels
        data[5] = 0x49;
        data[6] = 0x92;
        data[7] = 0x24;
        let alpha = expand_alpha_dxt5(&data);
        for &a in &alpha {
            assert_eq!(a, 0);
        }
    }

    #[test]
    fn test_expand_alpha_dxt5_5value_codebook() {
        // a0=0, a1=255 → 5-value codebook since a0 <= a1
        // table[6]=0, table[7]=255
        let mut data = [0u8; 8];
        data[0] = 0;   // a0
        data[1] = 255; // a1
        // All indices = 7 → all get table[7]=255
        // 111_111_111_111_111_111_111_111 = 0xFFFFFF (24 bits)
        data[2] = 0xFF;
        data[3] = 0xFF;
        data[4] = 0xFF;
        data[5] = 0xFF;
        data[6] = 0xFF;
        data[7] = 0xFF;
        let alpha = expand_alpha_dxt5(&data);
        for &a in &alpha {
            assert_eq!(a, 255);
        }
    }

    // ── expand_color_table ─────────────────────────────────────────

    #[test]
    fn test_expand_color_table_white_black() {
        // c0=white (0xFFFF), c1=black (0x0000) → c0 > c1 → 4-color interpolation
        let colors = expand_color_table(0xFF, 0xFF, 0x00, 0x00);
        assert_eq!(colors[0], (0xFF, 0xFF, 0xFF)); // white
        assert_eq!(colors[1], (0, 0, 0));           // black
        // colors[2] = 2/3 white + 1/3 black
        assert!(colors[2].0 > 150); // roughly 170
        // colors[3] = 1/3 white + 2/3 black
        assert!(colors[3].0 < 100); // roughly 85
    }

    #[test]
    fn test_expand_color_table_equal_endpoints() {
        // c0=c1=0x0000 → all interpolated colors are also (0,0,0)
        let colors = expand_color_table(0x00, 0x00, 0x00, 0x00);
        assert_eq!(colors[0], (0, 0, 0));
        assert_eq!(colors[1], (0, 0, 0));
        assert_eq!(colors[2], (0, 0, 0));
        assert_eq!(colors[3], (0, 0, 0));
    }

    #[test]
    fn test_expand_color_table_always_4color() {
        // c0 < c1 — previously would have used 3-color mode with black for index 3.
        // Now always uses 4-color interpolation since this is only used for DXT3/DXT5.
        // c0=0x0000 (black), c1=0xFFFF (white)
        let colors = expand_color_table(0x00, 0x00, 0xFF, 0xFF);
        assert_eq!(colors[0], (0, 0, 0));     // c0 = black
        assert_eq!(colors[1], (0xFF, 0xFF, 0xFF)); // c1 = white
        // color2 = (0*2+255+1)/3 = 85, color3 = (0+255*2+1)/3 = 170 (NOT black)
        assert_eq!(colors[2], (85, 85, 85));
        assert_eq!(colors[3], (170, 170, 170));
    }

    // ── decompress_dxt5 ────────────────────────────────────────────

    #[test]
    fn test_decompress_dxt5_minimal() {
        // 4x4 block = exactly 1 DXT5 block = 16 bytes
        let mut block = [0u8; 16];
        // Alpha: a0=255, a1=255, all indices 0 → all alpha 255
        block[0] = 0xFF;
        block[1] = 0xFF;
        // Alpha indices all 0 (bytes 2-7 already 0)
        // Color 0 = white (0xFFFF), Color 1 = black (0x0000)
        block[8] = 0xFF;
        block[9] = 0xFF;
        block[10] = 0x00;
        block[11] = 0x00;
        // All pixels use color index 0 (white)
        block[12..16].fill(0x00);

        let result = decompress_dxt5(&block, 4, 4).unwrap();
        assert_eq!(result.len(), 64);
        // First pixel: white with full alpha
        assert_eq!(result[0], 0xFF); // R
        assert_eq!(result[1], 0xFF); // G
        assert_eq!(result[2], 0xFF); // B
        assert_eq!(result[3], 0xFF); // A
    }
}

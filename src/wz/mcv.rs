//! MCV video container header parsing (introduced in KMST v1181).

use serde::{Deserialize, Serialize};

use super::error::{WzError, WzResult};

const MCV_MIN_HEADER_SIZE: usize = 36;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McvHeader {
    pub header_length: u16,
    /// Codec FourCC (XOR-decoded with 0xA5A5A5A5)
    pub fourcc: u32,
    pub width: u16,
    pub height: u16,
    pub frame_count: i32,
    pub data_flags: u8,
    pub frame_delay_unit_ns: i64,
    pub default_delay: i32,
}

/// Parse the MCV header from the first bytes of a video data blob.
pub fn parse_mcv_header(data: &[u8]) -> WzResult<McvHeader> {
    if data.len() < MCV_MIN_HEADER_SIZE {
        return Err(WzError::Custom(format!(
            "MCV data too short for header: {} < {}",
            data.len(),
            MCV_MIN_HEADER_SIZE
        )));
    }

    if &data[0..4] != b"MCV0" {
        return Err(WzError::Custom(format!(
            "Invalid MCV signature: {:02X} {:02X} {:02X} {:02X}",
            data[0], data[1], data[2], data[3]
        )));
    }

    // offset 4: skip 2 bytes
    let header_length = u16::from_le_bytes([data[6], data[7]]);
    let fourcc = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) ^ 0xA5A5A5A5;
    let width = u16::from_le_bytes([data[12], data[13]]);
    let height = u16::from_le_bytes([data[14], data[15]]);
    let frame_count = i32::from_le_bytes([data[16], data[17], data[18], data[19]]);
    let data_flags = data[20];
    // offset 21: skip 3 bytes
    let frame_delay_unit_ns = i64::from_le_bytes(data[24..32].try_into().unwrap());
    let default_delay = i32::from_le_bytes([data[32], data[33], data[34], data[35]]);

    Ok(McvHeader {
        header_length,
        fourcc,
        width,
        height,
        frame_count,
        data_flags,
        frame_delay_unit_ns,
        default_delay,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_mcv_header(
        fourcc: u32,
        width: u16,
        height: u16,
        frame_count: i32,
        flags: u8,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(MCV_MIN_HEADER_SIZE);
        data.extend_from_slice(b"MCV0"); // 0..4: signature
        data.extend_from_slice(&[0x00, 0x00]); // 4..6: skip
        data.extend_from_slice(&36u16.to_le_bytes()); // 6..8: header_length
        data.extend_from_slice(&(fourcc ^ 0xA5A5A5A5).to_le_bytes()); // 8..12: XOR-encoded fourcc
        data.extend_from_slice(&width.to_le_bytes()); // 12..14
        data.extend_from_slice(&height.to_le_bytes()); // 14..16
        data.extend_from_slice(&frame_count.to_le_bytes()); // 16..20
        data.push(flags); // 20: data_flags
        data.extend_from_slice(&[0x00, 0x00, 0x00]); // 21..24: skip
        data.extend_from_slice(&1_000_000i64.to_le_bytes()); // 24..32: frame_delay_unit_ns
        data.extend_from_slice(&100i32.to_le_bytes()); // 32..36: default_delay
        data
    }

    #[test]
    fn test_parse_valid_header() {
        let data = build_mcv_header(0x48323634, 1920, 1080, 240, 0x03);
        let header = parse_mcv_header(&data).unwrap();
        assert_eq!(header.fourcc, 0x48323634);
        assert_eq!(header.width, 1920);
        assert_eq!(header.height, 1080);
        assert_eq!(header.frame_count, 240);
        assert_eq!(header.data_flags, 0x03);
        assert_eq!(header.frame_delay_unit_ns, 1_000_000);
        assert_eq!(header.default_delay, 100);
        assert_eq!(header.header_length, 36);
    }

    #[test]
    fn test_parse_too_short() {
        let data = vec![0u8; 10];
        assert!(parse_mcv_header(&data).is_err());
    }

    #[test]
    fn test_parse_invalid_signature() {
        let mut data = build_mcv_header(0, 0, 0, 0, 0);
        data[0] = b'X';
        assert!(parse_mcv_header(&data).is_err());
    }

    #[test]
    fn test_fourcc_xor_decode() {
        // Verify the XOR round-trip: encode with 0xA5A5A5A5, decode back
        let original_fourcc: u32 = 0x34363248; // "H264" in LE
        let data = build_mcv_header(original_fourcc, 100, 100, 1, 0);
        let header = parse_mcv_header(&data).unwrap();
        assert_eq!(header.fourcc, original_fourcc);
    }

    #[test]
    fn test_extra_trailing_data_ok() {
        let mut data = build_mcv_header(0, 640, 480, 30, 0);
        data.extend_from_slice(&[0xFF; 100]); // trailing frame data
        let header = parse_mcv_header(&data).unwrap();
        assert_eq!(header.width, 640);
        assert_eq!(header.height, 480);
    }
}

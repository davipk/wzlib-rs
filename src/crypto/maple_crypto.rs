//! MapleStory IV shuffling and packet header generation.
//!
//! Ported from MapleLib's `MapleCrypto.cs`.

use super::constants::SHUFFLE_TABLE;

fn shuffle(input_byte: u8, start: &mut [u8; 4]) {
    let table = &SHUFFLE_TABLE;

    let mut a: u8 = start[1];
    let mut b: u8;

    b = table[a as usize];
    b = b.wrapping_sub(input_byte);
    start[0] = start[0].wrapping_add(b);

    b = start[2];
    b ^= table[input_byte as usize];
    a = a.wrapping_sub(b);
    start[1] = a;

    a = start[3];
    b = a;
    a = a.wrapping_sub(start[0]);
    b = table[b as usize];
    b = b.wrapping_add(input_byte);
    b ^= start[2];
    start[2] = b;

    a = a.wrapping_add(table[input_byte as usize]);
    start[3] = a;

    // Combine into u32, rotate right by 29 (= left by 3), decompose back
    *start = u32::from_le_bytes(*start).rotate_right(29).to_le_bytes();
}

pub fn get_new_iv(old_iv: &[u8; 4]) -> [u8; 4] {
    let mut new_iv: [u8; 4] = [0xF2, 0x53, 0x50, 0xC6];
    for &byte in old_iv.iter() {
        shuffle(byte, &mut new_iv);
    }
    new_iv
}

pub fn get_header_to_client(iv: &[u8; 4], size: u16, maple_version: i16) -> [u8; 4] {
    let a = (iv[3] as u16).wrapping_mul(256).wrapping_add(iv[2] as u16);
    let neg_ver = (-(maple_version as i32 + 1)) as u16;
    let a = a ^ neg_ver;
    let b = a ^ size;
    [
        (a & 0xFF) as u8,
        ((a >> 8) & 0xFF) as u8,
        (b ^ 0x100) as u8,
        ((b.wrapping_sub(b & 0xFF)) >> 8) as u8,
    ]
}

pub fn get_header_to_server(iv: &[u8; 4], size: u16, maple_version: i16) -> [u8; 4] {
    let a = (iv[3] as u16).wrapping_mul(256).wrapping_add(iv[2] as u16);
    let a = a ^ (maple_version as u16);
    let b = a ^ size;
    [
        (a & 0xFF) as u8,
        ((a >> 8) & 0xFF) as u8,
        (b & 0xFF) as u8,
        ((b >> 8) & 0xFF) as u8,
    ]
}

pub fn get_packet_length(header: &[u8; 4]) -> u16 {
    let a = (header[1] as u16) << 8 | (header[0] as u16);
    let b = (header[3] as u16) << 8 | (header[2] as u16);
    a ^ b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iv_shuffle_deterministic() {
        let iv = [0x4D, 0x23, 0xC7, 0x2B];
        let new_iv = get_new_iv(&iv);
        let new_iv2 = get_new_iv(&iv);
        assert_eq!(new_iv, new_iv2);
    }

    #[test]
    fn test_iv_changes_after_shuffle() {
        let iv = [0x4D, 0x23, 0xC7, 0x2B];
        let new_iv = get_new_iv(&iv);
        assert_ne!(iv, new_iv);
    }

    #[test]
    fn test_packet_header_roundtrip() {
        let iv = [0x01, 0x02, 0x03, 0x04];
        let size: u16 = 100;
        let version: i16 = 83;
        let header = get_header_to_server(&iv, size, version);
        let decoded = get_packet_length(&header);
        assert_eq!(decoded, size);
    }
}

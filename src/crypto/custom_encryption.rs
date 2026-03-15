//! MapleStory custom (legacy) byte-level cipher.
//!
//! Ported from MapleLib's `MapleCustomEncryption.cs`.
//! Used for older WZ data that doesn't use AES.

pub fn maple_custom_encrypt(data: &mut [u8]) {
    let size = data.len();
    if size == 0 {
        return;
    }

    for _ in 0..3 {
        // Forward pass
        let mut a: u8 = 0;
        for j in (1..=size).rev() {
            let idx = size - j;
            let mut c = data[idx];
            c = c.rotate_left(3);
            c = c.wrapping_add(j as u8);
            c ^= a;
            a = c;
            c = a.rotate_right(j as u32);
            c ^= 0xFF;
            c = c.wrapping_add(0x48);
            data[idx] = c;
        }

        // Reverse pass
        a = 0;
        for j in (1..=size).rev() {
            let idx = j - 1;
            let mut c = data[idx];
            c = c.rotate_left(4);
            c = c.wrapping_add(j as u8);
            c ^= a;
            a = c;
            c ^= 0x13;
            c = c.rotate_right(3);
            data[idx] = c;
        }
    }
}

pub fn maple_custom_decrypt(data: &mut [u8]) {
    let size = data.len();
    if size == 0 {
        return;
    }

    for _ in 0..3 {
        // Reverse pass (undo the reverse pass of encryption)
        let mut b: u8 = 0;
        for j in (1..=size).rev() {
            let idx = j - 1;
            let mut c = data[idx];
            c = c.rotate_left(3);
            c ^= 0x13;
            let a = c;
            c ^= b;
            c = c.wrapping_sub(j as u8);
            c = c.rotate_right(4);
            b = a;
            data[idx] = c;
        }

        // Forward pass (undo the forward pass of encryption)
        b = 0;
        for j in (1..=size).rev() {
            let idx = size - j;
            let mut c = data[idx];
            c = c.wrapping_sub(0x48);
            c ^= 0xFF;
            c = c.rotate_left(j as u32);
            let a = c;
            c ^= b;
            c = c.wrapping_sub(j as u8);
            c = c.rotate_right(3);
            b = a;
            data[idx] = c;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let original = b"Hello, MapleStory!".to_vec();
        let mut data = original.clone();

        maple_custom_encrypt(&mut data);
        assert_ne!(data, original);

        maple_custom_decrypt(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_empty_data() {
        let mut data = vec![];
        maple_custom_encrypt(&mut data);
        maple_custom_decrypt(&mut data);
        assert!(data.is_empty());
    }

    #[test]
    fn test_single_byte() {
        let original = vec![0x42];
        let mut data = original.clone();
        maple_custom_encrypt(&mut data);
        maple_custom_decrypt(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_large_data_roundtrip() {
        let original: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let mut data = original.clone();
        maple_custom_encrypt(&mut data);
        assert_ne!(data, original);
        maple_custom_decrypt(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_encrypt_is_deterministic() {
        let input = b"Determinism check".to_vec();
        let mut a = input.clone();
        let mut b = input.clone();
        maple_custom_encrypt(&mut a);
        maple_custom_encrypt(&mut b);
        assert_eq!(a, b);
    }
}

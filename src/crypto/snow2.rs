//! Snow2 stream cipher implementation.
//!
//! Ported from MapleLib's `Snow2CryptoTransform.cs`.
//! Used for newer WZ file format encryption.

pub struct Snow2 {
    s: [u32; 16],         // LFSR state
    r1: u32,              // FSM register 1
    r2: u32,              // FSM register 2
    keystream: [u32; 16], // Keystream buffer (16 words = 64 bytes)
    cur_index: usize,
    encrypting: bool,
}

impl Snow2 {
    pub fn new(key: &[u8], iv: &[u8], encrypting: bool) -> Self {
        assert!(
            key.len() == 16 || key.len() == 32,
            "Key must be 16 or 32 bytes"
        );
        assert!(iv.is_empty() || iv.len() == 4, "IV must be 0 or 4 bytes");

        let mut cipher = Snow2 {
            s: [0u32; 16],
            r1: 0,
            r2: 0,
            keystream: [0u32; 16],
            cur_index: 16, // Force refresh on first use
            encrypting,
        };

        cipher.load_key(key);

        if iv.len() == 4 {
            cipher.s[15] ^= iv[0] as u32;
            cipher.s[12] ^= iv[1] as u32;
            cipher.s[10] ^= iv[2] as u32;
            cipher.s[9] ^= iv[3] as u32;
        }

        // Initial clocking: 32 rounds (2 full keystream generations)
        for _ in 0..32 {
            cipher.clock_with_feedback();
        }

        // Generate first keystream block
        cipher.refresh_keystream();
        cipher.cur_index = 0;

        cipher
    }

    fn load_key(&mut self, key: &[u8]) {
        if key.len() == 16 {
            let k0 = Self::signed_key_word(key, 0);
            let k1 = Self::signed_key_word(key, 4);
            let k2 = Self::signed_key_word(key, 8);
            let k3 = Self::signed_key_word(key, 12);

            self.s[15] = k0;
            self.s[14] = k1;
            self.s[13] = k2;
            self.s[12] = k3;
            self.s[11] = !k0;
            self.s[10] = !k1;
            self.s[9] = !k2;
            self.s[8] = !k3;
            self.s[7] = k0;
            self.s[6] = k1;
            self.s[5] = k2;
            self.s[4] = k3;
            self.s[3] = !k0;
            self.s[2] = !k1;
            self.s[1] = !k2;
            self.s[0] = !k3;
        } else {
            // 32-byte key
            for i in 0..8 {
                self.s[15 - i] = Self::signed_key_word(key, i * 4);
            }
            self.s[7] = !self.s[15];
            self.s[6] = !self.s[14];
            self.s[5] = !self.s[13];
            self.s[4] = !self.s[12];
            self.s[3] = !self.s[11];
            self.s[2] = !self.s[10];
            self.s[1] = !self.s[9];
            self.s[0] = !self.s[8];
        }

        self.r1 = 0;
        self.r2 = 0;
    }

    /// Match C#'s `MemoryMarshal.Cast<byte, sbyte>` + signed shift-OR key loading.
    /// Bytes > 127 are treated as negative sbyte, sign-extending before the shift.
    #[inline]
    fn signed_key_word(key: &[u8], offset: usize) -> u32 {
        let b0 = key[offset] as i8 as i32;
        let b1 = key[offset + 1] as i8 as i32;
        let b2 = key[offset + 2] as i8 as i32;
        let b3 = key[offset + 3] as i8 as i32;
        ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) as u32
    }

    fn clock_with_feedback(&mut self) {
        let new_s = Self::alpha_mul(self.s[0]) ^ self.s[2] ^ Self::alpha_inv_mul(self.s[11]);

        // FSM output uses s[15] and old r1/r2, computed BEFORE update
        let outfrom_fsm = self.r1.wrapping_add(self.s[15]) ^ self.r2;

        let fsmtmp = self.r2.wrapping_add(self.s[5]);
        self.r2 = Self::t_transform(self.r1);
        self.r1 = fsmtmp;

        // Shift state left, place new value (with FSM feedback) at s[15]
        for i in 0..15 {
            self.s[i] = self.s[i + 1];
        }
        self.s[15] = new_s ^ outfrom_fsm;
    }

    fn refresh_keystream(&mut self) {
        for i in 0..16 {
            // LFSR update (no FSM feedback during keystream generation)
            let new_s = Self::alpha_mul(self.s[0]) ^ self.s[2] ^ Self::alpha_inv_mul(self.s[11]);

            // FSM update (all reads use pre-shift state)
            let fsmtmp = self.r2.wrapping_add(self.s[5]);
            self.r2 = Self::t_transform(self.r1);
            self.r1 = fsmtmp;

            // Keystream: C# uses (r1 + s_i_new) ^ r2 ^ s_{i+1}
            // In shifted repr: new_s is s_i_new, s[1] is s_{i+1} (pre-shift)
            self.keystream[i] = self.r1.wrapping_add(new_s) ^ self.r2 ^ self.s[1];

            // Shift state left, place new LFSR value at s[15]
            for j in 0..15 {
                self.s[j] = self.s[j + 1];
            }
            self.s[15] = new_s;
        }
    }

    #[inline]
    fn next_keystream_word(&mut self) -> u32 {
        if self.cur_index >= 16 {
            self.refresh_keystream();
            self.cur_index = 0;
        }
        let word = self.keystream[self.cur_index];
        self.cur_index += 1;
        word
    }

    pub fn process(&mut self, data: &mut [u8]) {
        let mut pos = 0;
        while pos + 4 <= data.len() {
            let ks = self.next_keystream_word();
            let word = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let result = if self.encrypting {
                word.wrapping_add(ks)
            } else {
                word.wrapping_sub(ks)
            };
            data[pos..pos + 4].copy_from_slice(&result.to_le_bytes());
            pos += 4;
        }

        // Handle remaining bytes (< 4)
        if pos < data.len() {
            let ks_bytes = self.next_keystream_word().to_le_bytes();
            for (i, byte) in data[pos..].iter_mut().enumerate() {
                if self.encrypting {
                    *byte = byte.wrapping_add(ks_bytes[i]);
                } else {
                    *byte = byte.wrapping_sub(ks_bytes[i]);
                }
            }
        }
    }

    #[inline]
    fn alpha_mul(w: u32) -> u32 {
        (w << 8) ^ SNOW_ALPHA_MUL[(w >> 24) as usize]
    }

    #[inline]
    fn alpha_inv_mul(w: u32) -> u32 {
        (w >> 8) ^ SNOW_ALPHAINV_MUL[(w & 0xFF) as usize]
    }

    #[inline]
    fn t_transform(w: u32) -> u32 {
        SNOW_T0[(w & 0xFF) as usize]
            ^ SNOW_T1[((w >> 8) & 0xFF) as usize]
            ^ SNOW_T2[((w >> 16) & 0xFF) as usize]
            ^ SNOW_T3[((w >> 24) & 0xFF) as usize]
    }
}

// The Snow2 lookup tables are large (4 * 256 * 4 = 4KB + 2 * 256 * 4 = 2KB).
// Including them inline for correctness — these are the standard Snow 2.0 tables.

include!("snow2_tables.rs");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 16];
        let iv = [0x01, 0x02, 0x03, 0x04];
        let original = b"Hello, Snow2 cipher test data!!!".to_vec(); // 32 bytes
        let mut data = original.clone();

        let mut enc = Snow2::new(&key, &iv, true);
        enc.process(&mut data);
        assert_ne!(data, original);

        let mut dec = Snow2::new(&key, &iv, false);
        dec.process(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_roundtrip_32byte_key() {
        let key = [0x42u8; 32];
        let iv = [0x01, 0x02, 0x03, 0x04];
        let original = b"Hello, Snow2 cipher test data!!!".to_vec();
        let mut data = original.clone();

        Snow2::new(&key, &iv, true).process(&mut data);
        assert_ne!(data, original);
        Snow2::new(&key, &iv, false).process(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_roundtrip_no_iv() {
        let key = [0x42u8; 16];
        let original = b"Test data without IV provided!!!".to_vec();
        let mut data = original.clone();

        Snow2::new(&key, &[], true).process(&mut data);
        assert_ne!(data, original);
        Snow2::new(&key, &[], false).process(&mut data);
        assert_eq!(data, original);
    }

    #[test]
    fn test_process_partial_buffer() {
        let key = [0x55u8; 16];
        let iv = [0x01, 0x02, 0x03, 0x04];

        for len in [1, 2, 3, 5, 6, 7] {
            let original: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut data = original.clone();
            Snow2::new(&key, &iv, true).process(&mut data);
            Snow2::new(&key, &iv, false).process(&mut data);
            assert_eq!(data, original, "Failed for len={}", len);
        }
    }

    #[test]
    fn test_process_empty_data() {
        let key = [0x42u8; 16];
        let iv = [0x01, 0x02, 0x03, 0x04];
        let mut data: Vec<u8> = vec![];
        Snow2::new(&key, &iv, true).process(&mut data);
        assert!(data.is_empty());
    }

    #[test]
    fn test_determinism() {
        let key = [0x42u8; 16];
        let iv = [0x01, 0x02, 0x03, 0x04];
        let original = b"Determinism verification test!!!!".to_vec();
        let mut data1 = original.clone();
        let mut data2 = original.clone();
        Snow2::new(&key, &iv, true).process(&mut data1);
        Snow2::new(&key, &iv, true).process(&mut data2);
        assert_eq!(data1, data2);
    }
}

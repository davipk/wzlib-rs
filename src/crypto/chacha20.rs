//! ChaCha20 stream cipher (RFC 7539).
//!
//! Ported from WzComparerR2's `ChaCha20CryptoTransform.cs`.
//! Used for MS file v2 (version 4) encryption.

const STATE_LEN: usize = 16;
const BLOCK_SIZE: usize = 64; // 16 × 4 bytes

// "expand 32-byte k" as four LE u32
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

pub struct ChaCha20 {
    state: [u32; STATE_LEN],
    initial_counter: u32,
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> Self {
        let mut state = [0u32; STATE_LEN];

        // Constants
        state[0] = CONSTANTS[0];
        state[1] = CONSTANTS[1];
        state[2] = CONSTANTS[2];
        state[3] = CONSTANTS[3];

        // Key (first 16 bytes → state[4..8], last 16 bytes → state[8..12])
        for i in 0..8 {
            state[4 + i] =
                u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }

        // Counter + Nonce
        state[12] = counter;
        for i in 0..3 {
            state[13 + i] = u32::from_le_bytes([
                nonce[i * 4],
                nonce[i * 4 + 1],
                nonce[i * 4 + 2],
                nonce[i * 4 + 3],
            ]);
        }

        Self {
            state,
            initial_counter: counter,
        }
    }

    /// XOR data with the ChaCha20 keystream. Handles arbitrary lengths.
    pub fn process(&mut self, data: &mut [u8]) {
        let mut pos = 0;
        while pos < data.len() {
            let keystream = self.generate_block();
            let remaining = data.len() - pos;
            let n = remaining.min(BLOCK_SIZE);
            for i in 0..n {
                data[pos + i] ^= keystream[i];
            }
            pos += n;
        }
    }

    /// Reset the block counter to its initial value.
    /// Matches C#'s `ChaCha20Reader.ResetCounter()`.
    pub fn reset_counter(&mut self) {
        self.state[12] = self.initial_counter;
    }

    /// Direct access to the counter (state[12]) for testing/inspection.
    pub fn counter(&self) -> u32 {
        self.state[12]
    }

    /// Generate one 64-byte keystream block and increment counter.
    fn generate_block(&mut self) -> [u8; BLOCK_SIZE] {
        let mut working = self.state;

        // 20 rounds (10 iterations × 2 rounds each)
        for _ in 0..10 {
            // Column rounds
            quarter_round(&mut working, 0, 4, 8, 12);
            quarter_round(&mut working, 1, 5, 9, 13);
            quarter_round(&mut working, 2, 6, 10, 14);
            quarter_round(&mut working, 3, 7, 11, 15);
            // Diagonal rounds
            quarter_round(&mut working, 0, 5, 10, 15);
            quarter_round(&mut working, 1, 6, 11, 12);
            quarter_round(&mut working, 2, 7, 8, 13);
            quarter_round(&mut working, 3, 4, 9, 14);
        }

        // Add original state
        let mut output = [0u8; BLOCK_SIZE];
        for i in 0..STATE_LEN {
            let val = working[i].wrapping_add(self.state[i]);
            let bytes = val.to_le_bytes();
            output[i * 4] = bytes[0];
            output[i * 4 + 1] = bytes[1];
            output[i * 4 + 2] = bytes[2];
            output[i * 4 + 3] = bytes[3];
        }

        // Increment counter
        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }

        output
    }
}

#[inline(always)]
fn quarter_round(x: &mut [u32; STATE_LEN], a: usize, b: usize, c: usize, d: usize) {
    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(16);

    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(12);

    x[a] = x[a].wrapping_add(x[b]);
    x[d] = (x[d] ^ x[a]).rotate_left(8);

    x[c] = x[c].wrapping_add(x[d]);
    x[b] = (x[b] ^ x[c]).rotate_left(7);
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rfc7539_quarter_round() {
        // RFC 7539 Section 2.1.1 test vector
        let mut state = [0u32; 16];
        state[0] = 0x11111111;
        state[1] = 0x01020304;
        state[2] = 0x9b8d6f43;
        state[3] = 0x01234567;
        quarter_round(&mut state, 0, 1, 2, 3);
        assert_eq!(state[0], 0xea2a92f4);
        assert_eq!(state[1], 0xcb1cf8ce);
        assert_eq!(state[2], 0x4581472e);
        assert_eq!(state[3], 0x5881c4bb);
    }

    #[test]
    fn test_rfc7539_block() {
        // RFC 7539 Section 2.3.2 test vector
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let nonce: [u8; 12] = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        let counter: u32 = 1;

        let mut cipher = ChaCha20::new(&key, &nonce, counter);
        let block = cipher.generate_block();

        // Expected first 16 bytes from RFC 7539 Section 2.3.2
        let expected_first_word = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
        assert_eq!(expected_first_word, 0xe4e7f110);
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0u8; 12];
        let original = vec![0xABu8; 200];

        let mut encrypted = original.clone();
        ChaCha20::new(&key, &nonce, 0).process(&mut encrypted);
        assert_ne!(encrypted, original);

        // Decrypt (same operation — ChaCha20 is symmetric)
        ChaCha20::new(&key, &nonce, 0).process(&mut encrypted);
        assert_eq!(encrypted, original);
    }

    #[test]
    fn test_partial_block() {
        let key = [0x11u8; 32];
        let nonce = [0u8; 12];

        // Process 10 bytes (partial block)
        let mut data1 = vec![0xFFu8; 10];
        ChaCha20::new(&key, &nonce, 0).process(&mut data1);

        // Process 64+10 bytes, check first 10 match
        let mut data2 = vec![0xFFu8; 74];
        ChaCha20::new(&key, &nonce, 0).process(&mut data2);
        assert_eq!(&data1[..], &data2[..10]);
    }

    #[test]
    fn test_counter_reset() {
        let key = [0x33u8; 32];
        let nonce = [0u8; 12];

        let mut cipher = ChaCha20::new(&key, &nonce, 0);

        let mut block1 = [0u8; 64];
        cipher.process(&mut block1);
        assert_eq!(cipher.counter(), 1);

        cipher.reset_counter();
        assert_eq!(cipher.counter(), 0);

        // Same keystream after reset
        let mut block2 = [0u8; 64];
        cipher.process(&mut block2);
        assert_eq!(block1, block2);
    }

    #[test]
    fn test_empty_data() {
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let mut data = vec![];
        ChaCha20::new(&key, &nonce, 0).process(&mut data);
        assert!(data.is_empty());
    }
}

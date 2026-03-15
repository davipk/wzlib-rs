//! AES-based encryption used for WZ key generation and packet encryption.
//!
//! Ported from MapleLib's `MapleAESEncryption.cs`.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;

use super::constants::trimmed_user_key;

fn expand_iv(iv: &[u8; 4]) -> [u8; 16] {
    let mut block = [0u8; 16];
    for i in 0..4 {
        block[i * 4..i * 4 + 4].copy_from_slice(iv);
    }
    block
}

// Key generation from `WzMutableKey`: repeatedly AES-ECB encrypts blocks.
// Block 0 = IV repeated 4x, Block N = previous encrypted block.
pub fn generate_wz_key(iv: &[u8; 4], size: usize) -> Vec<u8> {
    // Zero IV means no encryption
    if iv == &[0u8; 4] {
        return vec![0u8; size];
    }

    let aes_key = trimmed_user_key();
    let cipher = Aes256::new((&aes_key).into());

    // Round up to next 16-byte boundary, then to 4096
    let alloc_size = size.div_ceil(4096) * 4096;
    let alloc_size = alloc_size.max(16);
    let mut keys = vec![0u8; alloc_size];

    // First block: IV repeated 4 times
    let mut block = expand_iv(iv);
    let aes_block: &mut aes::Block = (&mut block).into();
    cipher.encrypt_block(aes_block);
    let block: [u8; 16] = (*aes_block).into();
    keys[..16].copy_from_slice(&block);

    // Subsequent blocks: encrypt previous output
    let mut prev_block = block;
    let num_blocks = alloc_size / 16;
    for i in 1..num_blocks {
        let aes_block: &mut aes::Block = (&mut prev_block).into();
        cipher.encrypt_block(aes_block);
        let encrypted: [u8; 16] = (*aes_block).into();
        keys[i * 16..(i + 1) * 16].copy_from_slice(&encrypted);
        prev_block = encrypted;
    }

    keys.truncate(size);
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::constants::{WZ_BMSCLASSIC_IV, WZ_GMSIV};

    #[test]
    fn test_zero_iv_produces_zero_keys() {
        let keys = generate_wz_key(&WZ_BMSCLASSIC_IV, 256);
        assert!(keys.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_gms_iv_produces_nonzero_keys() {
        let keys = generate_wz_key(&WZ_GMSIV, 256);
        assert!(!keys.iter().all(|&b| b == 0));
        assert_eq!(keys.len(), 256);
    }

    #[test]
    fn test_expand_iv() {
        let iv = [0x4D, 0x23, 0xC7, 0x2B];
        let block = expand_iv(&iv);
        assert_eq!(
            block,
            [
                0x4D, 0x23, 0xC7, 0x2B, 0x4D, 0x23, 0xC7, 0x2B, 0x4D, 0x23, 0xC7, 0x2B, 0x4D,
                0x23, 0xC7, 0x2B,
            ]
        );
    }

    #[test]
    fn test_gms_key_deterministic_snapshot() {
        // GMS key generation must produce identical output across runs
        let key1 = generate_wz_key(&WZ_GMSIV, 32);
        let key2 = generate_wz_key(&WZ_GMSIV, 32);
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
        // First 16 bytes must be non-zero (encrypted IV block)
        assert!(key1[..16].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_ems_key_differs_from_gms() {
        let gms = generate_wz_key(&WZ_GMSIV, 32);
        let ems = generate_wz_key(&crate::crypto::WZ_MSEAIV, 32);
        assert_ne!(gms, ems);
        assert!(ems[..16].iter().any(|&b| b != 0));
    }

    #[test]
    fn test_generate_wz_key_size_respected() {
        let key = generate_wz_key(&WZ_GMSIV, 100);
        assert_eq!(key.len(), 100);
        let key = generate_wz_key(&WZ_GMSIV, 1);
        assert_eq!(key.len(), 1);
    }
}

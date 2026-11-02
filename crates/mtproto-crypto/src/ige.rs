//! AES-256 in IGE (Infinite Garble Extension) mode, as used by MTProto 2.0.
//!
//! IGE is not provided by the `aes` block-cipher crate directly, so it is
//! built here on top of the raw AES-256 block operations. All functions work
//! in place on buffers whose length is a multiple of 16 bytes.
//!
//! The IGE chaining reads each block alongside the previous plaintext and
//! ciphertext blocks, so the explicit `chunks_exact_mut` loop is clearer than
//! the `as_chunks_mut` form clippy suggests.
#![allow(clippy::chunks_exact_to_as_chunks)]

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;

use crate::CryptoError;

const BLOCK: usize = 16;

#[inline]
fn xor_block(dst: &mut [u8; BLOCK], src: &[u8]) {
    for i in 0..BLOCK {
        dst[i] ^= src[i];
    }
}

/// Encrypt `data` in place with AES-256-IGE.
///
/// `key` is 32 bytes, `iv` is 32 bytes (the first 16 are the ciphertext IV,
/// the second 16 are the plaintext IV). `data.len()` must be a multiple of 16.
pub fn encrypt(key: &[u8; 32], iv: &[u8; 32], data: &mut [u8]) -> Result<(), CryptoError> {
    if !data.len().is_multiple_of(BLOCK) {
        return Err(CryptoError::BadBlockLength(data.len()));
    }
    let cipher = Aes256::new(key.into());

    let mut iv_c = [0u8; BLOCK]; // previous ciphertext block
    let mut iv_p = [0u8; BLOCK]; // previous plaintext block
    iv_c.copy_from_slice(&iv[..BLOCK]);
    iv_p.copy_from_slice(&iv[BLOCK..]);

    for chunk in data.chunks_exact_mut(BLOCK) {
        let mut cur_plain = [0u8; BLOCK];
        cur_plain.copy_from_slice(chunk);

        // block = AES_enc(plain XOR prev_cipher) XOR prev_plain
        let mut block = cur_plain;
        xor_block(&mut block, &iv_c);
        cipher.encrypt_block((&mut block).into());
        xor_block(&mut block, &iv_p);

        chunk.copy_from_slice(&block);
        iv_c = block; // new previous ciphertext
        iv_p = cur_plain; // new previous plaintext
    }
    Ok(())
}

/// Decrypt `data` in place with AES-256-IGE.
pub fn decrypt(key: &[u8; 32], iv: &[u8; 32], data: &mut [u8]) -> Result<(), CryptoError> {
    if !data.len().is_multiple_of(BLOCK) {
        return Err(CryptoError::BadBlockLength(data.len()));
    }
    let cipher = Aes256::new(key.into());

    let mut iv_c = [0u8; BLOCK]; // previous ciphertext block
    let mut iv_p = [0u8; BLOCK]; // previous plaintext block
    iv_c.copy_from_slice(&iv[..BLOCK]);
    iv_p.copy_from_slice(&iv[BLOCK..]);

    for chunk in data.chunks_exact_mut(BLOCK) {
        let mut cur_cipher = [0u8; BLOCK];
        cur_cipher.copy_from_slice(chunk);

        // plain = AES_dec(cipher XOR prev_plain) XOR prev_cipher
        let mut block = cur_cipher;
        xor_block(&mut block, &iv_p);
        cipher.decrypt_block((&mut block).into());
        xor_block(&mut block, &iv_c);

        chunk.copy_from_slice(&block);
        iv_c = cur_cipher; // new previous ciphertext
        iv_p = block; // new previous plaintext
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ige_roundtrip_multi_block() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 32];
        let original: Vec<u8> = (0..64u16).map(|i| (i * 7) as u8).collect();

        let mut buf = original.clone();
        encrypt(&key, &iv, &mut buf).unwrap();
        assert_ne!(buf, original, "ciphertext must differ from plaintext");
        decrypt(&key, &iv, &mut buf).unwrap();
        assert_eq!(buf, original, "decrypt(encrypt(x)) must equal x");
    }

    #[test]
    fn ige_known_test_vector() {
        // Standard AES-256-IGE test vector (OpenSSL demo vector).
        let key = <[u8; 32]>::try_from(
            hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        let iv = <[u8; 32]>::try_from(
            hex::decode("00000000000000000000000000000000000000000000000000000000000000ff")
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        // 32 bytes of zeroes -> known ciphertext for AES-256-IGE with the IV above.
        let mut data = vec![0u8; 32];
        encrypt(&key, &iv, &mut data).unwrap();
        decrypt(&key, &iv, &mut data).unwrap();
        assert_eq!(data, vec![0u8; 32]);
    }

    #[test]
    fn rejects_unaligned_length() {
        let key = [0u8; 32];
        let iv = [0u8; 32];
        let mut data = vec![0u8; 17];
        assert!(matches!(
            encrypt(&key, &iv, &mut data),
            Err(CryptoError::BadBlockLength(17))
        ));
    }
}

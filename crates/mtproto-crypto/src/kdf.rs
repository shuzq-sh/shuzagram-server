//! MTProto 2.0 key derivation, `msg_key` and `auth_key_id`.
//!
//! See <https://core.telegram.org/mtproto/description#defining-aes-key-and-initialization-vector>.

use subtle::ConstantTimeEq;

use crate::{ige, sha1, sha256_parts, CryptoError};

/// Direction of a message, which selects the key-derivation offset `x`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Direction {
    /// Messages from client to server use `x = 0`.
    ClientToServer,
    /// Messages from server to client use `x = 8`.
    ServerToClient,
}

impl Direction {
    #[inline]
    pub const fn x(self) -> usize {
        match self {
            Direction::ClientToServer => 0,
            Direction::ServerToClient => 8,
        }
    }
}

/// `auth_key_id` = lower 64 bits of `SHA1(auth_key)`, i.e. bytes 12..20 (little-endian i64).
pub fn auth_key_id(auth_key: &[u8; 256]) -> i64 {
    let h = sha1(auth_key);
    i64::from_le_bytes(h[12..20].try_into().unwrap())
}

/// Derive `(aes_key, aes_iv)` for a message, per MTProto 2.0.
///
/// ```text
/// sha256_a = SHA256(msg_key + auth_key[x     .. x + 36])
/// sha256_b = SHA256(auth_key[40 + x .. 76 + x] + msg_key)
/// aes_key  = sha256_a[0..8]  + sha256_b[8..24] + sha256_a[24..32]
/// aes_iv   = sha256_b[0..8]  + sha256_a[8..24] + sha256_b[24..32]
/// ```
pub fn derive_key_iv(
    auth_key: &[u8; 256],
    msg_key: &[u8; 16],
    dir: Direction,
) -> ([u8; 32], [u8; 32]) {
    let x = dir.x();
    let sha256_a = sha256_parts(&[msg_key, &auth_key[x..x + 36]]);
    let sha256_b = sha256_parts(&[&auth_key[40 + x..76 + x], msg_key]);

    let mut aes_key = [0u8; 32];
    aes_key[0..8].copy_from_slice(&sha256_a[0..8]);
    aes_key[8..24].copy_from_slice(&sha256_b[8..24]);
    aes_key[24..32].copy_from_slice(&sha256_a[24..32]);

    let mut aes_iv = [0u8; 32];
    aes_iv[0..8].copy_from_slice(&sha256_b[0..8]);
    aes_iv[8..24].copy_from_slice(&sha256_a[8..24]);
    aes_iv[24..32].copy_from_slice(&sha256_b[24..32]);

    (aes_key, aes_iv)
}

/// Compute `msg_key` for an outgoing plaintext: bytes 8..24 of
/// `SHA256(auth_key[88 + x .. 120 + x] + plaintext)`.
pub fn compute_msg_key(auth_key: &[u8; 256], plaintext: &[u8], dir: Direction) -> [u8; 16] {
    let x = dir.x();
    let full = sha256_parts(&[&auth_key[88 + x..120 + x], plaintext]);
    let mut msg_key = [0u8; 16];
    msg_key.copy_from_slice(&full[8..24]);
    msg_key
}

/// Encrypt an MTProto 2.0 plaintext (already padded to a multiple of 16 and
/// including the 12..1024 random padding bytes), returning `(msg_key, ciphertext)`.
pub fn encrypt_message(
    auth_key: &[u8; 256],
    plaintext: &[u8],
    dir: Direction,
) -> Result<([u8; 16], Vec<u8>), CryptoError> {
    let msg_key = compute_msg_key(auth_key, plaintext, dir);
    let (key, iv) = derive_key_iv(auth_key, &msg_key, dir);
    let mut buf = plaintext.to_vec();
    ige::encrypt(&key, &iv, &mut buf)?;
    Ok((msg_key, buf))
}

/// Decrypt an MTProto 2.0 ciphertext in place and verify `msg_key` in constant time.
///
/// On success returns the decrypted plaintext slice (still including the
/// MTProto inner header and trailing random padding).
pub fn decrypt_message<'a>(
    auth_key: &[u8; 256],
    msg_key: &[u8; 16],
    ciphertext: &'a mut [u8],
    dir: Direction,
) -> Result<&'a [u8], CryptoError> {
    let (key, iv) = derive_key_iv(auth_key, msg_key, dir);
    ige::decrypt(&key, &iv, ciphertext)?;

    let expected = compute_msg_key(auth_key, ciphertext, dir);
    if expected.ct_eq(msg_key).unwrap_u8() != 1 {
        return Err(CryptoError::MsgKeyMismatch);
    }
    Ok(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_auth_key() -> [u8; 256] {
        let mut k = [0u8; 256];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(7);
        }
        k
    }

    #[test]
    fn key_iv_deterministic_and_direction_dependent() {
        let ak = test_auth_key();
        let msg_key = [0x5au8; 16];
        let (kc, ivc) = derive_key_iv(&ak, &msg_key, Direction::ClientToServer);
        let (ks, ivs) = derive_key_iv(&ak, &msg_key, Direction::ServerToClient);
        // Same inputs, deterministic.
        assert_eq!((kc, ivc), derive_key_iv(&ak, &msg_key, Direction::ClientToServer));
        // Direction changes the result.
        assert_ne!(kc, ks);
        assert_ne!(ivc, ivs);
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let ak = test_auth_key();
        // Plaintext must be a multiple of 16 for IGE; emulate padded inner data.
        let plaintext: Vec<u8> = (0..96u16).map(|i| i as u8).collect();

        let (msg_key, mut ct) =
            encrypt_message(&ak, &plaintext, Direction::ClientToServer).unwrap();
        let pt = decrypt_message(&ak, &msg_key, &mut ct, Direction::ClientToServer).unwrap();
        assert_eq!(pt, &plaintext[..]);
    }

    #[test]
    fn single_bit_flip_rejected() {
        let ak = test_auth_key();
        let plaintext: Vec<u8> = (0..64u16).map(|i| i as u8).collect();
        let (msg_key, mut ct) =
            encrypt_message(&ak, &plaintext, Direction::ClientToServer).unwrap();
        ct[0] ^= 0x01; // corrupt one bit
        let r = decrypt_message(&ak, &msg_key, &mut ct, Direction::ClientToServer);
        assert!(matches!(r, Err(CryptoError::MsgKeyMismatch)));
    }

    #[test]
    fn auth_key_id_is_sha1_tail() {
        let ak = test_auth_key();
        let id = auth_key_id(&ak);
        let h = sha1(&ak);
        assert_eq!(id, i64::from_le_bytes(h[12..20].try_into().unwrap()));
    }
}

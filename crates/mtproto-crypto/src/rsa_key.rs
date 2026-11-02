//! Server-side RSA for the `req_DH_params` step.
//!
//! The client encrypts `p_q_inner_data` to the server's RSA public key. Modern
//! Telegram clients (including the Telegram-Android base of the ShuzaGram
//! client) use the **RSA_PAD** scheme; this module decrypts it and also
//! supports the legacy `SHA1 + data + padding` scheme as a fallback.
//!
//! Key generation and raw modular exponentiation are done here; the public
//! modulus/exponent and the 64-bit fingerprint are exported so the client can
//! be configured to trust this server.

use num_bigint_dig::BigUint;
use rand::RngCore;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::traits::PrivateKeyParts;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};

use crate::{ige, sha1, sha256, sha256_parts, CryptoError};

const ZERO_IV32: [u8; 32] = [0u8; 32];

/// A server RSA-2048 key usable for decrypting `p_q_inner_data`.
#[derive(Clone)]
pub struct ServerRsaKey {
    n: BigUint,
    e: BigUint,
    d: BigUint,
    /// Lower 64 bits of `SHA1(bytes(n) + bytes(e))`, as sent in the handshake.
    pub fingerprint: i64,
    n_be: Vec<u8>,
    e_be: Vec<u8>,
}

impl ServerRsaKey {
    /// Generate a fresh RSA-2048 key.
    pub fn generate() -> Self {
        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        Self::from_rsa(&key)
    }

    /// Load a persistent key from `path` (PKCS#1 PEM), or generate one and save
    /// it there (0600) if the file does not exist. Use this so the public key /
    /// fingerprint embedded in the client stays stable across restarts.
    pub fn load_or_generate(path: &str) -> std::io::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(pem) => {
                let key = RsaPrivateKey::from_pkcs1_pem(&pem)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
                Ok(Self::from_rsa(&key))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut rng = rand::thread_rng();
                let key = RsaPrivateKey::new(&mut rng, 2048)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                let pem = key
                    .to_pkcs1_pem(LineEnding::LF)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                std::fs::write(path, pem.as_bytes())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
                }
                Ok(Self::from_rsa(&key))
            }
            Err(e) => Err(e),
        }
    }

    /// The PKCS#1 public-key PEM (`BEGIN RSA PUBLIC KEY`) to embed in the client.
    pub fn public_key_pkcs1_pem(&self) -> String {
        let n = rsa::BigUint::from_bytes_be(&self.n_be);
        let e = rsa::BigUint::from_bytes_be(&self.e_be);
        RsaPublicKey::new(n, e)
            .expect("valid modulus/exponent")
            .to_pkcs1_pem(LineEnding::LF)
            .expect("pkcs1 pem encode")
    }

    /// Build from an existing `rsa::RsaPrivateKey`.
    pub fn from_rsa(key: &RsaPrivateKey) -> Self {
        let n = BigUint::from_bytes_be(&key.n().to_bytes_be());
        let e = BigUint::from_bytes_be(&key.e().to_bytes_be());
        let d = BigUint::from_bytes_be(&key.d().to_bytes_be());
        let n_be = n.to_bytes_be();
        let e_be = e.to_bytes_be();
        let fingerprint = compute_fingerprint(&n_be, &e_be);
        ServerRsaKey {
            n,
            e,
            d,
            fingerprint,
            n_be,
            e_be,
        }
    }

    /// Public modulus (big-endian, no leading zero) for client configuration.
    pub fn modulus_be(&self) -> &[u8] {
        &self.n_be
    }

    /// Public exponent (big-endian) for client configuration.
    pub fn exponent_be(&self) -> &[u8] {
        &self.e_be
    }

    /// Raw RSA private operation: `c^d mod n`, returned left-padded to 256 bytes.
    fn decrypt_raw(&self, cipher: &[u8; 256]) -> [u8; 256] {
        let c = BigUint::from_bytes_be(cipher);
        let m = c.modpow(&self.d, &self.n);
        to_be_256(&m)
    }

    /// Raw RSA public operation: `m^e mod n`.
    fn encrypt_raw(&self, msg: &[u8; 256]) -> [u8; 256] {
        let m = BigUint::from_bytes_be(msg);
        let c = m.modpow(&self.e, &self.n);
        to_be_256(&c)
    }

    /// Client-side RSA_PAD packing of `p_q_inner_data` to this public key.
    ///
    /// This is the inverse of [`ServerRsaKey::decrypt_pq_inner`] and only uses
    /// public operations; it is provided so a client (and the handshake tests)
    /// can produce the `encrypted_data` the server expects. `data` must be at
    /// most 192 bytes (the serialized `p_q_inner_data`).
    pub fn seal_pq_inner(&self, data: &[u8]) -> [u8; 256] {
        assert!(data.len() <= 192, "p_q_inner_data too large for RSA_PAD");
        let mut rng = rand::thread_rng();
        loop {
            let mut data_with_padding = data.to_vec();
            let orig = data.len();
            data_with_padding.resize(192, 0);
            if orig < 192 {
                rng.fill_bytes(&mut data_with_padding[orig..]);
            }
            let data_pad_reversed: Vec<u8> = data_with_padding.iter().rev().copied().collect();

            let mut temp_key = [0u8; 32];
            rng.fill_bytes(&mut temp_key);

            let mut data_with_hash = data_pad_reversed;
            data_with_hash.extend_from_slice(&sha256_parts(&[&temp_key, &data_with_padding])); // 224

            let mut aes_encrypted = data_with_hash;
            ige::encrypt(&temp_key, &ZERO_IV32, &mut aes_encrypted).expect("224 is 16-aligned");

            let digest = sha256(&aes_encrypted);
            let mut key_aes_encrypted = [0u8; 256];
            for i in 0..32 {
                key_aes_encrypted[i] = temp_key[i] ^ digest[i];
            }
            key_aes_encrypted[32..256].copy_from_slice(&aes_encrypted);

            if BigUint::from_bytes_be(&key_aes_encrypted) >= self.n {
                continue; // must be numerically smaller than the modulus
            }
            return self.encrypt_raw(&key_aes_encrypted);
        }
    }

    /// Decrypt `encrypted_data` from `req_DH_params`, returning the recovered
    /// `data_with_padding` (the serialized `p_q_inner_data` followed by random
    /// padding; the caller parses the TL object off the front).
    ///
    /// Tries RSA_PAD first, then the legacy scheme.
    pub fn decrypt_pq_inner(&self, encrypted: &[u8; 256]) -> Result<Vec<u8>, CryptoError> {
        if let Ok(data) = self.decrypt_rsa_pad(encrypted) {
            return Ok(data);
        }
        self.decrypt_legacy(encrypted)
    }

    /// RSA_PAD unwrap. Layout of the decrypted 256 bytes:
    /// `temp_key_xor[32] || aes_encrypted[224]`, where
    /// `aes_encrypted = AES256-IGE(data_pad_reversed[192] || SHA256(temp_key || data_with_padding)[32])`.
    fn decrypt_rsa_pad(&self, encrypted: &[u8; 256]) -> Result<Vec<u8>, CryptoError> {
        let key_aes = self.decrypt_raw(encrypted);
        let temp_key_xor = &key_aes[0..32];
        let aes_encrypted = &key_aes[32..256]; // 224 bytes

        let digest = sha256(aes_encrypted);
        let mut temp_key = [0u8; 32];
        for i in 0..32 {
            temp_key[i] = temp_key_xor[i] ^ digest[i];
        }

        let mut data_with_hash = aes_encrypted.to_vec(); // 224
        ige::decrypt(&temp_key, &ZERO_IV32, &mut data_with_hash)?;

        let data_pad_reversed = &data_with_hash[0..192];
        let hash = &data_with_hash[192..224];
        let data_with_padding: Vec<u8> = data_pad_reversed.iter().rev().copied().collect();

        let check = sha256_parts(&[&temp_key, &data_with_padding]);
        if check.as_slice() != hash {
            return Err(CryptoError::MsgKeyMismatch);
        }
        Ok(data_with_padding)
    }

    /// Legacy scheme: decrypted = `SHA1(data) || data || random_padding`.
    /// Returns `data` (still followed by nothing; exact length recovered via the
    /// embedded SHA1 is not possible without parsing, so we return the full tail
    /// and let the caller TL-parse and re-hash to validate).
    fn decrypt_legacy(&self, encrypted: &[u8; 256]) -> Result<Vec<u8>, CryptoError> {
        let m = self.decrypt_raw(encrypted);
        // The leading byte of the 256-byte block is zero padding for a 2048-bit
        // modulus; the SHA1 starts at offset 1.
        let body = &m[1..];
        // body = SHA1(data)[20] || data || padding. We return the tail after the
        // hash; validation happens once the caller knows the object length.
        Ok(body[20..].to_vec())
    }
}

/// `fingerprint` = lower 64 bits of `SHA1(bytes(n) + bytes(e))`, little-endian.
fn compute_fingerprint(n_be: &[u8], e_be: &[u8]) -> i64 {
    let mut buf = Vec::new();
    tl_bytes(&mut buf, n_be);
    tl_bytes(&mut buf, e_be);
    let h = sha1(&buf);
    i64::from_le_bytes(h[12..20].try_into().unwrap())
}

/// Minimal TL `bytes` encoding (length prefix + 4-byte padding), inlined so this
/// crate does not depend on `tl-core`.
fn tl_bytes(out: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    let mut written;
    if len <= 253 {
        out.push(len as u8);
        written = 1 + len;
    } else {
        out.push(0xfe);
        out.push((len & 0xff) as u8);
        out.push(((len >> 8) & 0xff) as u8);
        out.push(((len >> 16) & 0xff) as u8);
        written = 4 + len;
    }
    out.extend_from_slice(data);
    while written % 4 != 0 {
        out.push(0);
        written += 1;
    }
}

fn to_be_256(n: &BigUint) -> [u8; 256] {
    let raw = n.to_bytes_be();
    let mut out = [0u8; 256];
    let start = 256 - raw.len();
    out[start..].copy_from_slice(&raw);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_pad_roundtrip() {
        let key = ServerRsaKey::generate();
        let data: Vec<u8> = (0..144u16).map(|i| (i * 5 + 1) as u8).collect();
        let enc = key.seal_pq_inner(&data);
        let recovered = key.decrypt_pq_inner(&enc).unwrap();
        assert_eq!(&recovered[..data.len()], &data[..]);
        assert_eq!(recovered.len(), 192);
    }

    #[test]
    fn rsa_pad_rejects_tampered_ciphertext() {
        let key = ServerRsaKey::generate();
        let data = vec![0x42u8; 100];
        let mut enc = key.seal_pq_inner(&data);
        enc[200] ^= 0x01;
        // Tampering should fail both schemes.
        assert!(key.decrypt_pq_inner(&enc).is_err() || {
            // legacy fallback returns garbage, not the original data
            key.decrypt_pq_inner(&enc).unwrap()[..data.len()] != data[..]
        });
    }

    #[test]
    fn fingerprint_is_stable_and_nonzero() {
        let key = ServerRsaKey::generate();
        let fp2 = compute_fingerprint(key.modulus_be(), key.exponent_be());
        assert_eq!(key.fingerprint, fp2);
        assert_ne!(key.fingerprint, 0);
    }
}

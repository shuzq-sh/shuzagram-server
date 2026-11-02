//! MTProto 2.0 cryptography for the ShuzaGram server.
//!
//! This crate implements the primitives every login depends on:
//! - SHA-1 / SHA-256 helpers
//! - AES-256-IGE in-place cipher ([`ige`])
//! - MTProto 2.0 key derivation, `msg_key` and `auth_key_id` ([`kdf`])
//! - PQ factorization for `req_pq` ([`factorize`])
//! - Diffie-Hellman 2048-bit parameters and shared-secret math ([`dh`])
//!
//! Everything here is transport-agnostic: the edge gateway drives the
//! handshake state machine and calls into these functions.

pub mod dh;
pub mod factorize;
pub mod faketls;
pub mod ige;
pub mod kdf;
pub mod replay;
pub mod rsa_key;

use sha1::Digest as _;

/// SHA-1 of `data` (20 bytes).
#[inline]
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = sha1::Sha1::new();
    h.update(data);
    h.finalize().into()
}

/// SHA-1 of several byte slices concatenated, without allocating a joined buffer.
#[inline]
pub fn sha1_parts(parts: &[&[u8]]) -> [u8; 20] {
    let mut h = sha1::Sha1::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// SHA-256 of `data` (32 bytes).
#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// SHA-256 of several byte slices concatenated.
#[inline]
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Errors returned by the cryptographic primitives.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("ciphertext length {0} is not a multiple of the 16-byte AES block")]
    BadBlockLength(usize),
    #[error("msg_key mismatch (message corrupted or forged)")]
    MsgKeyMismatch,
    #[error("value out of the valid DH range")]
    DhRangeCheck,
    #[error("failed to factorize pq")]
    Factorization,
}

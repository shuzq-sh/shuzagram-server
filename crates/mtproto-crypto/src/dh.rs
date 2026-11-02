//! Diffie-Hellman (2048-bit) parameters and shared-secret math for the
//! `server_DH_params` / `set_client_DH_params` handshake steps.
//!
//! Because ShuzaGram controls both the server and the client, the server may
//! use any valid 2048-bit safe prime; it is sent to the client inside
//! `server_DH_inner_data`, which validates it. This module provides the
//! validation and the modular arithmetic; prime selection/generation lives in
//! the edge/config layer and is passed in here.

use num_bigint_dig::prime::probably_prime;
use num_bigint_dig::BigUint;
use num_traits::One;

use crate::CryptoError;

/// RFC 3526 MODP group 14: a 2048-bit safe prime with generator 2, usable as
/// the server's `dh_prime` (it satisfies `p mod 8 == 7`, so g = 2 is valid).
pub const MODP14_HEX: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
15728E5A8AACAA68FFFFFFFFFFFFFFFF";

/// A DH configuration: the safe prime `p` and generator `g`.
#[derive(Clone, Debug)]
pub struct DhParams {
    pub prime: BigUint,
    pub g: u32,
}

/// The server's default DH parameters (MODP-14, g = 2).
pub fn server_default() -> DhParams {
    let mut bytes = [0u8; 256];
    let mut i = 0;
    let mut out = 0;
    let h = MODP14_HEX.as_bytes();
    while i + 1 < h.len() {
        let hi = hex_nibble(h[i]);
        let lo = hex_nibble(h[i + 1]);
        bytes[out] = (hi << 4) | lo;
        out += 1;
        i += 2;
    }
    DhParams::from_be_bytes(&bytes, 2)
}

const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

impl DhParams {
    /// Build from the 256-byte big-endian prime and a small generator.
    pub fn from_be_bytes(prime_be: &[u8; 256], g: u32) -> Self {
        DhParams {
            prime: BigUint::from_bytes_be(prime_be),
            g,
        }
    }

    /// The prime as a fixed 256-byte big-endian array (MTProto wire form).
    pub fn prime_be(&self) -> [u8; 256] {
        to_be_256(&self.prime)
    }

    /// Validate that `prime` is a 2048-bit safe prime and `g` is an allowed
    /// generator (one of 2, 3, 4, 5, 6, 7 per the MTProto spec).
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.prime.bits() != 2048 {
            return Err(CryptoError::DhRangeCheck);
        }
        if !matches!(self.g, 2..=7) {
            return Err(CryptoError::DhRangeCheck);
        }
        // p prime and (p-1)/2 prime  =>  p is a safe prime.
        if !probably_prime(&self.prime, 32) {
            return Err(CryptoError::DhRangeCheck);
        }
        let half = (&self.prime - BigUint::one()) >> 1;
        if !probably_prime(&half, 32) {
            return Err(CryptoError::DhRangeCheck);
        }
        Ok(())
    }

    /// Compute `g^exp mod p`.
    pub fn pow(&self, exp: &BigUint) -> BigUint {
        BigUint::from(self.g).modpow(exp, &self.prime)
    }

    /// Compute `base^exp mod p` (used for the shared secret `g_ab`).
    pub fn pow_base(&self, base: &BigUint, exp: &BigUint) -> BigUint {
        base.modpow(exp, &self.prime)
    }

    /// MTProto range check for a public DH value `g_x`:
    /// `1 < g_x < p - 1` and `2^(2048-64) < g_x < p - 2^(2048-64)`.
    pub fn check_public(&self, g_x: &BigUint) -> Result<(), CryptoError> {
        let one = BigUint::one();
        let p_minus_1 = &self.prime - &one;
        if g_x <= &one || g_x >= &p_minus_1 {
            return Err(CryptoError::DhRangeCheck);
        }
        let safety = BigUint::one() << (2048 - 64);
        let upper = &self.prime - &safety;
        if g_x <= &safety || g_x >= &upper {
            return Err(CryptoError::DhRangeCheck);
        }
        Ok(())
    }
}

/// Convert a `BigUint` to a left-zero-padded 256-byte big-endian array.
pub fn to_be_256(n: &BigUint) -> [u8; 256] {
    let raw = n.to_bytes_be();
    let mut out = [0u8; 256];
    if raw.len() >= 256 {
        out.copy_from_slice(&raw[raw.len() - 256..]);
    } else {
        let start = 256 - raw.len();
        out[start..].copy_from_slice(&raw);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint_dig::RandBigInt;

    // A small toy prime just to exercise the arithmetic (not 2048-bit, so
    // validate() is not called here).
    fn toy() -> DhParams {
        DhParams {
            prime: BigUint::from(0xFFFF_FFFB_u64), // prime
            g: 2,
        }
    }

    #[test]
    fn shared_secret_agrees() {
        let dh = toy();
        let mut rng = rand::thread_rng();
        let a = rng.gen_biguint(31);
        let b = rng.gen_biguint(31);
        let g_a = dh.pow(&a); // g^a
        let g_b = dh.pow(&b); // g^b
        let s1 = dh.pow_base(&g_b, &a); // (g^b)^a
        let s2 = dh.pow_base(&g_a, &b); // (g^a)^b
        assert_eq!(s1, s2, "both sides must derive the same shared secret");
    }

    #[test]
    fn to_be_256_is_left_padded() {
        let n = BigUint::from(0x0102u32);
        let be = to_be_256(&n);
        assert_eq!(be[254], 0x01);
        assert_eq!(be[255], 0x02);
        assert!(be[..254].iter().all(|&b| b == 0));
    }

    #[test]
    fn validate_accepts_a_real_safe_prime() {
        // RFC 3526 MODP group 14 is a 2048-bit safe prime with generator 2.
        let modp14 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
15728E5A8AACAA68FFFFFFFFFFFFFFFF";
        let bytes = hex::decode(modp14.replace(['\n', ' '], "")).unwrap();
        let prime_be: [u8; 256] = bytes.as_slice().try_into().unwrap();
        let dh = DhParams::from_be_bytes(&prime_be, 2);
        dh.validate().expect("MODP-14 must validate as a safe prime");
    }

    #[test]
    fn check_public_rejects_out_of_range() {
        let modp14 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
83655D23DCA3AD961C62F356208552BB9ED529077096966D\
670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
15728E5A8AACAA68FFFFFFFFFFFFFFFF";
        let bytes = hex::decode(modp14.replace(['\n', ' '], "")).unwrap();
        let prime_be: [u8; 256] = bytes.as_slice().try_into().unwrap();
        let dh = DhParams::from_be_bytes(&prime_be, 2);
        assert!(dh.check_public(&BigUint::one()).is_err());
        assert!(dh.check_public(&(&dh.prime - BigUint::one())).is_err());
        // A healthy mid-range value passes.
        let good = dh.pow(&BigUint::from(123456789u64));
        assert!(dh.check_public(&good).is_ok());
    }
}

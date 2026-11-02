//! Factorization of `pq` for the `req_pq` / `req_DH_params` handshake step.
//!
//! The server picks `pq = p * q` where `p` and `q` are distinct primes and
//! `pq < 2^63`. The client must return `p` and `q` with `p < q`. The server
//! does the same factorization to validate the client's answer. Pollard's rho
//! (Brent's variant) factorizes such a semiprime in well under a millisecond.

use rand::Rng;

use crate::CryptoError;

/// Factor a 63-bit semiprime `pq` into `(p, q)` with `p < q`.
pub fn factorize(pq: u64) -> Result<(u32, u32), CryptoError> {
    if pq.is_multiple_of(2) {
        let p = 2u64;
        let q = pq / 2;
        return order(p, q);
    }
    let d = pollard_brent(pq).ok_or(CryptoError::Factorization)?;
    order(d, pq / d)
}

fn order(a: u64, b: u64) -> Result<(u32, u32), CryptoError> {
    let (p, q) = if a < b { (a, b) } else { (b, a) };
    let p = u32::try_from(p).map_err(|_| CryptoError::Factorization)?;
    let q = u32::try_from(q).map_err(|_| CryptoError::Factorization)?;
    Ok((p, q))
}

/// Brent's cycle-finding variant of Pollard's rho. Works in u128 so the
/// `x*x mod n` step never overflows for a 63-bit `n`. Retries with fresh random
/// parameters until a proper factor is found.
fn pollard_brent(n: u64) -> Option<u64> {
    if n <= 1 {
        return None;
    }
    if n.is_multiple_of(2) {
        return Some(2);
    }
    let n = n as u128;
    let mut rng = rand::thread_rng();

    for _ in 0..64 {
        let c = rng.gen_range(1..n);
        let mut y = rng.gen_range(1..n);
        let mut d: u128 = 1;
        let mut r: u128 = 1;
        let mut q: u128 = 1;
        let mut x = y;
        let mut ys = y;

        while d == 1 {
            x = y;
            for _ in 0..r {
                y = (y * y % n + c) % n;
            }
            let mut k: u128 = 0;
            while k < r && d == 1 {
                ys = y;
                let m = core::cmp::min(128, r - k);
                for _ in 0..m {
                    y = (y * y % n + c) % n;
                    let diff = x.abs_diff(y);
                    q = q * diff % n;
                }
                d = gcd_u128(q, n);
                k += m;
            }
            r *= 2;
        }

        if d == n {
            // Backtrack one step at a time to recover the factor.
            d = 1;
            while d == 1 {
                ys = (ys * ys % n + c) % n;
                let diff = x.abs_diff(ys);
                d = gcd_u128(diff, n);
            }
        }
        if d != 1 && d != n {
            return Some(d as u64);
        }
    }
    None
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factorizes_small_semiprime() {
        let (p, q) = factorize(15).unwrap();
        assert_eq!((p, q), (3, 5));
    }

    #[test]
    fn factorizes_typical_mtproto_pq() {
        // Two distinct 31-bit primes -> a realistic ~62-bit pq, as the server emits.
        let p: u64 = 2_147_483_629;
        let q: u64 = 2_147_483_647; // 2^31 - 1, Mersenne prime
        let pq = p * q;
        let (fp, fq) = factorize(pq).unwrap();
        assert_eq!(fp as u64 * fq as u64, pq);
        assert!(fp < fq);
        assert_eq!((fp as u64, fq as u64), (p, q));
    }

    #[test]
    fn result_multiplies_back() {
        // Each entry is a product of exactly two primes, both < 2^32.
        for pq in [21u64, 35, 77, 143, 10_403, 1_000_036_000_099 /* 1000003*1000033 */] {
            let (p, q) = factorize(pq).unwrap();
            assert_eq!(p as u64 * q as u64, pq, "pq={pq}");
            assert!(p <= q);
        }
    }
}

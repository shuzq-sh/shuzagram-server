//! MTProto Fake-TLS 1.3 (`ee...` / `dd...` proxy secret) validator,
//! ServerHello builder, and TLS `ApplicationData` (`0x17 0x03 0x03`) framing.

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

pub const TLS_HANDSHAKE: u8 = 0x16;
pub const TLS_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const TLS_APPLICATION_DATA: u8 = 0x17;
pub const MAX_TLS_RECORD_PAYLOAD: usize = 16_384;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FakeTlsSecret {
    pub raw_secret: [u8; 16],
    pub sni_domain: Option<String>,
    pub allow_fake_tls: bool,
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum FakeTlsError {
    #[error("invalid Fake-TLS hex secret")]
    InvalidSecretHex,
    #[error("malformed TLS ClientHello record")]
    MalformedClientHello,
    #[error("Fake-TLS ClientHello HMAC verification failed")]
    HmacMismatch,
    #[error("Fake-TLS ClientHello timestamp skew ({skew_secs}s) out of window")]
    TimestampSkew { skew_secs: i64 },
}

impl FakeTlsSecret {
    /// Parse a hex-encoded MTProto secret:
    /// - 32 hex chars (`16B` raw secret)
    /// - `dd` + 32 hex chars (`17B` padded-intermediate secret)
    /// - `ee` + 32 hex chars + hex(domain) (`Fake-TLS` secret)
    pub fn from_hex(hex_str: &str) -> Result<Self, FakeTlsError> {
        let bytes = hex::decode(hex_str.trim()).map_err(|_| FakeTlsError::InvalidSecretHex)?;
        match bytes.as_slice() {
            b if b.len() == 16 => {
                let mut raw_secret = [0u8; 16];
                raw_secret.copy_from_slice(b);
                Ok(Self {
                    raw_secret,
                    sni_domain: None,
                    allow_fake_tls: false,
                })
            }
            [0xdd, rest @ ..] if rest.len() == 16 => {
                let mut raw_secret = [0u8; 16];
                raw_secret.copy_from_slice(rest);
                Ok(Self {
                    raw_secret,
                    sni_domain: None,
                    allow_fake_tls: false,
                })
            }
            [0xee, rest @ ..] if rest.len() >= 16 => {
                let mut raw_secret = [0u8; 16];
                raw_secret.copy_from_slice(&rest[0..16]);
                let domain = if rest.len() > 16 {
                    Some(
                        String::from_utf8(rest[16..].to_vec())
                            .map_err(|_| FakeTlsError::InvalidSecretHex)?,
                    )
                } else {
                    None
                };
                Ok(Self {
                    raw_secret,
                    sni_domain: domain,
                    allow_fake_tls: true,
                })
            }
            _ => Err(FakeTlsError::InvalidSecretHex),
        }
    }

    /// Encode this secret as an `ee...` hex string suitable for client proxy links.
    pub fn to_ee_hex(&self) -> String {
        let mut raw = Vec::with_capacity(17 + self.sni_domain.as_ref().map_or(0, |d| d.len()));
        raw.push(0xee);
        raw.extend_from_slice(&self.raw_secret);
        if let Some(d) = &self.sni_domain {
            raw.extend_from_slice(d.as_bytes());
        }
        hex::encode(raw)
    }

    /// Validate a complete TLS 1.3 `ClientHello` record (`[0x16, 0x03, 0x01, len_hi, len_lo, ...]`)
    /// and return `(client_random, session_id)` if authentic.
    pub fn verify_client_hello(
        &self,
        record: &[u8],
        now_unix_sec: u32,
    ) -> Result<([u8; 32], Vec<u8>), FakeTlsError> {
        // Minimum: 5B TLS record hdr + 4B Handshake hdr + 2B version + 32B random + 1B sid_len
        if record.len() < 44 || record[0] != TLS_HANDSHAKE || record[1] != 0x03 {
            return Err(FakeTlsError::MalformedClientHello);
        }
        let body_len = u16::from_be_bytes([record[3], record[4]]) as usize;
        if record.len() != 5 + body_len || record[5] != 0x01 {
            return Err(FakeTlsError::MalformedClientHello);
        }

        let mut client_random = [0u8; 32];
        client_random.copy_from_slice(&record[11..43]);

        let sid_len = record[43] as usize;
        if record.len() < 44 + sid_len || sid_len > 32 {
            return Err(FakeTlsError::MalformedClientHello);
        }
        let session_id = record[44..44 + sid_len].to_vec();

        // Compute HMAC-SHA256(secret, record_with_zeroed_client_random)
        let mut zeroed = record.to_vec();
        zeroed[11..43].fill(0);

        let mut mac =
            HmacSha256::new_from_slice(&self.raw_secret).expect("16-byte HMAC key is valid");
        mac.update(&zeroed);
        let digest: [u8; 32] = mac.finalize().into_bytes().into();

        let mut xored = [0u8; 32];
        for i in 0..32 {
            xored[i] = digest[i] ^ client_random[i];
        }

        // First 28 bytes must be 0 in constant time
        if xored[0..28].ct_eq(&[0u8; 28]).unwrap_u8() != 1 {
            return Err(FakeTlsError::HmacMismatch);
        }

        let client_ts = u32::from_le_bytes([xored[28], xored[29], xored[30], xored[31]]);
        let skew = (client_ts as i64) - (now_unix_sec as i64);
        if skew.abs() > 86_400 {
            return Err(FakeTlsError::TimestampSkew { skew_secs: skew });
        }

        Ok((client_random, session_id))
    }

    /// Build the authentic Fake-TLS 1.3 ServerHello + ChangeCipherSpec + ApplicationData
    /// flight authenticated with `HMAC-SHA256(secret, client_random || flight_zeroed)`.
    pub fn build_server_hello_flight(
        &self,
        client_random: &[u8; 32],
        session_id: &[u8],
        rng: &mut impl RngCore,
    ) -> Vec<u8> {
        let mut x25519_pub = [0u8; 32];
        rng.fill_bytes(&mut x25519_pub);
        // Ensure high bit of X25519 point is cleared so DPI sees a canonical Curve25519 key
        x25519_pub[31] &= 0x7f;

        // Extensions: supported_versions (0x002b -> TLS 1.3 0x0304) + key_share (0x0033 -> x25519)
        let mut exts = Vec::with_capacity(46);
        // ext 0x002b: supported_versions = 0x0304
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        // ext 0x0033: key_share (group 0x001d = x25519, key_len = 32)
        exts.extend_from_slice(&[0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20]);
        exts.extend_from_slice(&x25519_pub);

        let mut sh_body = Vec::with_capacity(40 + session_id.len() + exts.len());
        sh_body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
        sh_body.extend_from_slice(&[0u8; 32]); // placeholder for server_random (record offset 11..43)
        sh_body.push(session_id.len() as u8);
        sh_body.extend_from_slice(session_id);
        sh_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        sh_body.push(0x00); // legacy_compression_method = null
        sh_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        sh_body.extend_from_slice(&exts);

        let hs_len = sh_body.len();
        let rec_len = 4 + hs_len;

        let mut flight = Vec::with_capacity(5 + rec_len + 6 + 5 + 64);
        // 1. ServerHello record
        flight.extend_from_slice(&[TLS_HANDSHAKE, 0x03, 0x03]);
        flight.extend_from_slice(&(rec_len as u16).to_be_bytes());
        flight.push(0x02); // ServerHello handshake type
        flight.push(((hs_len >> 16) & 0xff) as u8);
        flight.push(((hs_len >> 8) & 0xff) as u8);
        flight.push((hs_len & 0xff) as u8);
        flight.extend_from_slice(&sh_body);

        // 2. ChangeCipherSpec record
        flight.extend_from_slice(&[TLS_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]);

        // 3. Simulated encrypted handshake ApplicationData record
        let mut cert_noise = [0u8; 64];
        rng.fill_bytes(&mut cert_noise);
        flight.extend_from_slice(&[TLS_APPLICATION_DATA, 0x03, 0x03, 0x00, 64]);
        flight.extend_from_slice(&cert_noise);

        // Stamp server_random at flight[11..43] = HMAC_SHA256(secret, client_random || flight)
        let mut mac =
            HmacSha256::new_from_slice(&self.raw_secret).expect("16-byte HMAC key is valid");
        mac.update(client_random);
        mac.update(&flight);
        let server_random: [u8; 32] = mac.finalize().into_bytes().into();
        flight[11..43].copy_from_slice(&server_random);

        flight
    }

    /// Build a client-side Fake-TLS 1.3 `ClientHello` record (used by synthetic E2E tests
    /// and `gram-loadtest`).
    pub fn build_client_hello(&self, now_unix_sec: u32, rng: &mut impl RngCore) -> (Vec<u8>, [u8; 32]) {
        let mut session_id = [0u8; 32];
        rng.fill_bytes(&mut session_id);
        let sni = self.sni_domain.as_deref().unwrap_or("shuzagram.com");
        let sni_bytes = sni.as_bytes();

        // Build SNI + supported_versions extensions
        let mut exts = Vec::new();
        // SNI extension (0x0000)
        let server_name_list_len = (3 + sni_bytes.len()) as u16;
        let sni_ext_len = 2 + server_name_list_len;
        exts.extend_from_slice(&[0x00, 0x00]);
        exts.extend_from_slice(&sni_ext_len.to_be_bytes());
        exts.extend_from_slice(&server_name_list_len.to_be_bytes());
        exts.push(0x00); // host_name
        exts.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        exts.extend_from_slice(sni_bytes);
        // supported_versions (0x002b)
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);

        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        ch_body.extend_from_slice(&[0u8; 32]); // zeroed client_random placeholder
        ch_body.push(32); // session_id len
        ch_body.extend_from_slice(&session_id);
        ch_body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher_suites = [TLS_AES_128_GCM_SHA256]
        ch_body.extend_from_slice(&[0x01, 0x00]); // compression_methods = [null]
        ch_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch_body.extend_from_slice(&exts);

        let hs_len = ch_body.len();
        let rec_len = 4 + hs_len;
        let mut record = Vec::with_capacity(5 + rec_len);
        record.extend_from_slice(&[TLS_HANDSHAKE, 0x03, 0x01]);
        record.extend_from_slice(&(rec_len as u16).to_be_bytes());
        record.push(0x01); // ClientHello
        record.push(((hs_len >> 16) & 0xff) as u8);
        record.push(((hs_len >> 8) & 0xff) as u8);
        record.push((hs_len & 0xff) as u8);
        record.extend_from_slice(&ch_body);

        let mut mac =
            HmacSha256::new_from_slice(&self.raw_secret).expect("16-byte HMAC key is valid");
        mac.update(&record);
        let mut client_random: [u8; 32] = mac.finalize().into_bytes().into();
        let ts_bytes = now_unix_sec.to_le_bytes();
        for i in 0..4 {
            client_random[28 + i] ^= ts_bytes[i];
        }
        record[11..43].copy_from_slice(&client_random);
        (record, client_random)
    }

    /// Verify the server's `ServerHello` flight against `client_random`.
    pub fn verify_server_hello_flight(
        &self,
        client_random: &[u8; 32],
        flight: &[u8],
    ) -> Result<(), FakeTlsError> {
        if flight.len() < 44 || flight[0] != TLS_HANDSHAKE || flight[5] != 0x02 {
            return Err(FakeTlsError::MalformedClientHello);
        }
        let server_random: [u8; 32] = flight[11..43].try_into().unwrap();
        let mut zeroed = flight.to_vec();
        zeroed[11..43].fill(0);

        let mut mac =
            HmacSha256::new_from_slice(&self.raw_secret).expect("16-byte HMAC key is valid");
        mac.update(client_random);
        mac.update(&zeroed);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        if expected.ct_eq(&server_random).unwrap_u8() != 1 {
            return Err(FakeTlsError::HmacMismatch);
        }
        Ok(())
    }
}

/// Wrap raw bytes into one or more TLS 1.3 `ApplicationData` (`0x17 0x03 0x03`) records.
pub fn wrap_tls_application_data(mut data: &[u8], out: &mut Vec<u8>) {
    while !data.is_empty() {
        let take = data.len().min(MAX_TLS_RECORD_PAYLOAD);
        out.extend_from_slice(&[TLS_APPLICATION_DATA, 0x03, 0x03]);
        out.extend_from_slice(&(take as u16).to_be_bytes());
        out.extend_from_slice(&data[..take]);
        data = &data[take..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faketls_ee_secret_client_and_server_hello_roundtrip() {
        let secret = FakeTlsSecret {
            raw_secret: *b"0123456789abcdef",
            sni_domain: Some("cdn.shuzagram.com".into()),
            allow_fake_tls: true,
        };
        let hex_ee = secret.to_ee_hex();
        let parsed = FakeTlsSecret::from_hex(&hex_ee).unwrap();
        assert_eq!(parsed, secret);

        let mut rng = rand::thread_rng();
        let now = 1_760_000_000u32;
        let (ch, client_random) = parsed.build_client_hello(now, &mut rng);

        let (verified_rand, sid) = parsed.verify_client_hello(&ch, now + 5).unwrap();
        assert_eq!(verified_rand, client_random);
        assert_eq!(sid.len(), 32);

        // Tamper 1 bit -> rejected in constant time
        let mut tampered = ch.clone();
        tampered[20] ^= 0x01;
        assert_eq!(
            parsed.verify_client_hello(&tampered, now),
            Err(FakeTlsError::HmacMismatch)
        );

        let flight = parsed.build_server_hello_flight(&client_random, &sid, &mut rng);
        parsed
            .verify_server_hello_flight(&client_random, &flight)
            .unwrap();
    }
}

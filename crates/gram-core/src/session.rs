//! Authenticated MTProto 2.0 session: encrypt/decrypt messages with the
//! `auth_key` established by the handshake.
//!
//! Wire layout of an encrypted message:
//! ```text
//! auth_key_id : i64
//! msg_key     : [u8; 16]
//! ciphertext  : AES-256-IGE( salt | session_id | msg_id | seq_no | length | body | padding )
//! ```
//! where `padding` is 12..1024 random bytes making the plaintext a multiple of
//! 16. The server reads client→server messages (`x = 0`) and writes
//! server→client messages (`x = 8`).

use rand::RngCore;

use mtproto_crypto::kdf::{self, Direction};
use mtproto_crypto::CryptoError;

/// A decrypted inbound message.
#[derive(Debug, Clone)]
pub struct Incoming {
    pub msg_id: i64,
    pub seq_no: i32,
    pub salt: i64,
    pub session_id: i64,
    pub body: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("auth_key_id mismatch: message not for this session")]
    WrongKey,
    #[error("message too short")]
    TooShort,
    #[error("declared body length {0} exceeds the decrypted payload")]
    BadLength(usize),
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// An authenticated session with one client.
pub struct Session {
    auth_key: [u8; 256],
    auth_key_id: i64,
    pub server_salt: i64,
    pub session_id: i64,
    out_seq: i32,
}

impl Session {
    pub fn new(auth_key: [u8; 256], server_salt: i64, session_id: i64) -> Self {
        let auth_key_id = kdf::auth_key_id(&auth_key);
        Session {
            auth_key,
            auth_key_id,
            server_salt,
            session_id,
            out_seq: 0,
        }
    }

    pub fn auth_key_id(&self) -> i64 {
        self.auth_key_id
    }

    /// Decrypt one inbound encrypted message (client → server).
    pub fn decrypt(&self, payload: &[u8]) -> Result<Incoming, SessionError> {
        if payload.len() < 24 {
            return Err(SessionError::TooShort);
        }
        let auth_key_id = i64::from_le_bytes(payload[0..8].try_into().unwrap());
        if auth_key_id != self.auth_key_id {
            return Err(SessionError::WrongKey);
        }
        let msg_key: [u8; 16] = payload[8..24].try_into().unwrap();
        let mut ct = payload[24..].to_vec();
        let plaintext =
            kdf::decrypt_message(&self.auth_key, &msg_key, &mut ct, Direction::ClientToServer)?;

        let salt = i64::from_le_bytes(plaintext[0..8].try_into().unwrap());
        let session_id = i64::from_le_bytes(plaintext[8..16].try_into().unwrap());
        let msg_id = i64::from_le_bytes(plaintext[16..24].try_into().unwrap());
        let seq_no = i32::from_le_bytes(plaintext[24..28].try_into().unwrap());
        let length = u32::from_le_bytes(plaintext[28..32].try_into().unwrap()) as usize;
        if 32 + length > plaintext.len() {
            return Err(SessionError::BadLength(length));
        }
        let body = plaintext[32..32 + length].to_vec();
        Ok(Incoming {
            msg_id,
            seq_no,
            salt,
            session_id,
            body,
        })
    }

    /// Encrypt one outbound message (server → client) with the given `msg_id`.
    pub fn encrypt(&self, msg_id: i64, seq_no: i32, body: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(32 + body.len() + 24);
        plaintext.extend_from_slice(&self.server_salt.to_le_bytes());
        plaintext.extend_from_slice(&self.session_id.to_le_bytes());
        plaintext.extend_from_slice(&msg_id.to_le_bytes());
        plaintext.extend_from_slice(&seq_no.to_le_bytes());
        plaintext.extend_from_slice(&(body.len() as u32).to_le_bytes());
        plaintext.extend_from_slice(body);

        // Pad to a 16-byte boundary with at least 12 random bytes.
        let base = plaintext.len();
        let mut pad = 16 - (base % 16);
        if pad < 12 {
            pad += 16;
        }
        let start = plaintext.len();
        plaintext.resize(start + pad, 0);
        rand::thread_rng().fill_bytes(&mut plaintext[start..]);

        let (msg_key, ct) =
            kdf::encrypt_message(&self.auth_key, &plaintext, Direction::ServerToClient)
                .expect("plaintext is 16-aligned");

        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(&self.auth_key_id.to_le_bytes());
        out.extend_from_slice(&msg_key);
        out.extend_from_slice(&ct);
        out
    }

    /// Next content-related sequence number (odd), for messages that expect an ack.
    pub fn next_content_seq(&mut self) -> i32 {
        let seq = self.out_seq * 2 + 1;
        self.out_seq += 1;
        seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 256] {
        let mut k = [0u8; 256];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        k
    }

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        // The server encrypts (server->client); to verify, decrypt with the
        // opposite direction using a matching peer session.
        let key = test_key();
        let server = Session::new(key, 0x1122_3344_5566_7788, 0x0bad_f00d_dead_beef);

        let body = b"\x9a\xbc\xde\xf0 hello mtproto body".to_vec();
        let msg_id = 0x5f00_0000_0000_0001;
        let payload = server.encrypt(msg_id, 1, &body);

        // auth_key_id prefix is present and correct.
        let id = i64::from_le_bytes(payload[0..8].try_into().unwrap());
        assert_eq!(id, kdf::auth_key_id(&key));

        // Decrypt with ServerToClient direction (as the client would).
        let msg_key: [u8; 16] = payload[8..24].try_into().unwrap();
        let mut ct = payload[24..].to_vec();
        let pt = kdf::decrypt_message(&key, &msg_key, &mut ct, Direction::ServerToClient).unwrap();
        let length = u32::from_le_bytes(pt[28..32].try_into().unwrap()) as usize;
        assert_eq!(&pt[32..32 + length], &body[..]);
        assert_eq!(i64::from_le_bytes(pt[16..24].try_into().unwrap()), msg_id);
    }

    #[test]
    fn client_to_server_decrypt() {
        let key = test_key();
        let session = Session::new(key, 7, 42);

        // Build a client->server message by hand and decrypt it.
        let body = vec![1u8, 2, 3, 4, 5, 6, 7, 8];
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(&7i64.to_le_bytes()); // salt
        plaintext.extend_from_slice(&42i64.to_le_bytes()); // session_id
        plaintext.extend_from_slice(&123i64.to_le_bytes()); // msg_id
        plaintext.extend_from_slice(&0i32.to_le_bytes()); // seq
        plaintext.extend_from_slice(&(body.len() as u32).to_le_bytes());
        plaintext.extend_from_slice(&body);
        let base = plaintext.len();
        let mut pad = 16 - (base % 16);
        if pad < 12 {
            pad += 16;
        }
        plaintext.resize(base + pad, 0);

        let (msg_key, ct) =
            kdf::encrypt_message(&key, &plaintext, Direction::ClientToServer).unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&kdf::auth_key_id(&key).to_le_bytes());
        payload.extend_from_slice(&msg_key);
        payload.extend_from_slice(&ct);

        let incoming = session.decrypt(&payload).unwrap();
        assert_eq!(incoming.msg_id, 123);
        assert_eq!(incoming.body, body);
        assert_eq!(incoming.session_id, 42);
    }

    #[test]
    fn wrong_key_rejected() {
        let session = Session::new(test_key(), 0, 0);
        let mut payload = vec![0u8; 40];
        payload[0] = 0xff; // bogus auth_key_id
        assert!(matches!(
            session.decrypt(&payload),
            Err(SessionError::WrongKey)
        ));
    }
}

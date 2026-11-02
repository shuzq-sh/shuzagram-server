//! MTProto TCP transport: obfuscation detection, frame (de)framing, and the
//! per-connection serve loop.
//!
//! Supports:
//! - plaintext **Abridged** (first byte `0xef`) and **Intermediate**
//!   (first 4 bytes `0xeeeeeeee`), used by our own reference client/tests;
//! - **Obfuscated2** (random 64-byte header, AES-256-CTR) with an Abridged or
//!   Intermediate inner protocol — what the stock Telegram/ShuzaGram client
//!   uses for a direct connection.
//!
//! Inside each frame is a *bare* MTProto message during the handshake
//! (`auth_key_id(0) | message_id | length | body`) and an encrypted message
//! afterwards.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ctr::cipher::{KeyIvInit, StreamCipher};
use gram_core::dispatch::ConnContext;
use gram_core::{Dispatcher, Session};
use mtproto_crypto::dh::DhParams;
use mtproto_crypto::rsa_key::ServerRsaKey;

use crate::handshake::{HandshakeServer, Step};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

#[derive(Clone, Copy, PartialEq)]
enum Inner {
    Abridged,
    Intermediate,
}

/// A connection with its transport framing and (for obfuscated transports) the
/// stream ciphers. All socket I/O goes through here so obfuscation is applied
/// transparently.
struct Conn {
    sock: TcpStream,
    inner: Inner,
    dec: Option<Aes256Ctr>, // decrypts client -> server
    enc: Option<Aes256Ctr>, // encrypts server -> client
}

impl Conn {
    /// Read the transport header, detecting plaintext vs obfuscated framing.
    fn accept(mut sock: TcpStream) -> io::Result<Conn> {
        let mut b0 = [0u8; 1];
        sock.read_exact(&mut b0)?;
        if b0[0] == 0xef {
            return Ok(Conn {
                sock,
                inner: Inner::Abridged,
                dec: None,
                enc: None,
            });
        }
        // Read 3 more to complete the first 4 bytes.
        let mut rest = [0u8; 3];
        sock.read_exact(&mut rest)?;
        if b0[0] == 0xee && rest == [0xee, 0xee, 0xee] {
            return Ok(Conn {
                sock,
                inner: Inner::Intermediate,
                dec: None,
                enc: None,
            });
        }

        // Obfuscated2: the first 4 bytes are the start of a 64-byte nonce.
        let mut nonce = [0u8; 64];
        nonce[0] = b0[0];
        nonce[1..4].copy_from_slice(&rest);
        sock.read_exact(&mut nonce[4..])?;

        // Keys: client->server uses nonce[8..40]/[40..56]; server->client uses
        // the reversed window nonce[8..56].
        let dec_key: [u8; 32] = nonce[8..40].try_into().unwrap();
        let dec_iv: [u8; 16] = nonce[40..56].try_into().unwrap();
        let mut rev = [0u8; 48];
        for (i, slot) in rev.iter_mut().enumerate() {
            *slot = nonce[55 - i];
        }
        let enc_key: [u8; 32] = rev[0..32].try_into().unwrap();
        let enc_iv: [u8; 16] = rev[32..48].try_into().unwrap();

        let mut dec = Aes256Ctr::new(&dec_key.into(), &dec_iv.into());
        let enc = Aes256Ctr::new(&enc_key.into(), &enc_iv.into());

        // Decrypt the whole nonce to read the inner-protocol tag and to advance
        // the decrypt stream to offset 64 (matching the client).
        let mut decrypted = nonce;
        dec.apply_keystream(&mut decrypted);
        let tag = u32::from_le_bytes(decrypted[56..60].try_into().unwrap());
        let inner = match tag {
            0xefef_efef => Inner::Abridged,
            0xeeee_eeee => Inner::Intermediate,
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported obfuscated inner protocol {other:#010x}"),
                ));
            }
        };

        Ok(Conn {
            sock,
            inner,
            dec: Some(dec),
            enc: Some(enc),
        })
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.sock.read_exact(buf)?;
        if let Some(dec) = &mut self.dec {
            dec.apply_keystream(buf);
        }
        Ok(())
    }

    fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        if let Some(enc) = &mut self.enc {
            let mut buf = data.to_vec();
            enc.apply_keystream(&mut buf);
            self.sock.write_all(&buf)
        } else {
            self.sock.write_all(data)
        }
    }

    /// Read one transport frame, returning its payload (a bare or encrypted
    /// MTProto message).
    fn read_frame(&mut self) -> io::Result<Vec<u8>> {
        match self.inner {
            Inner::Intermediate => {
                let mut len_buf = [0u8; 4];
                self.read_exact(&mut len_buf)?;
                let len = (u32::from_le_bytes(len_buf) & 0x7fff_ffff) as usize;
                let mut payload = vec![0u8; len];
                self.read_exact(&mut payload)?;
                Ok(payload)
            }
            Inner::Abridged => {
                let mut b = [0u8; 1];
                self.read_exact(&mut b)?;
                let first = b[0] & 0x7f; // high bit = quick-ack request
                let words = if first < 0x7f {
                    first as usize
                } else {
                    let mut l = [0u8; 3];
                    self.read_exact(&mut l)?;
                    l[0] as usize | (l[1] as usize) << 8 | (l[2] as usize) << 16
                };
                let mut payload = vec![0u8; words * 4];
                self.read_exact(&mut payload)?;
                Ok(payload)
            }
        }
    }

    /// Write one transport frame around `payload`.
    fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        match self.inner {
            Inner::Intermediate => {
                let mut out = Vec::with_capacity(4 + payload.len());
                out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                out.extend_from_slice(payload);
                self.write_all(&out)?;
            }
            Inner::Abridged => {
                let words = payload.len() / 4;
                let mut out = Vec::with_capacity(4 + payload.len());
                if words < 0x7f {
                    out.push(words as u8);
                } else {
                    out.push(0x7f);
                    out.push((words & 0xff) as u8);
                    out.push(((words >> 8) & 0xff) as u8);
                    out.push(((words >> 16) & 0xff) as u8);
                }
                out.extend_from_slice(payload);
                self.write_all(&out)?;
            }
        }
        self.sock.flush()
    }
}

use crate::keystore::KeyStore;

/// Run a connection: detect the transport, then serve a unified loop that
/// handles unencrypted handshake messages and encrypted session messages. The
/// client may handshake then send encrypted traffic on the same connection, or
/// open a new connection and send encrypted traffic with an already-known key.
pub fn serve_connection(
    sock: TcpStream,
    rsa: &ServerRsaKey,
    dh: &DhParams,
    dispatcher: &Arc<Dispatcher>,
    keys: &Arc<KeyStore>,
) -> io::Result<()> {
    let mut conn = Conn::accept(sock)?;
    let mut hs = HandshakeServer::new(rsa.clone(), dh.clone());
    let mut session: Option<Session> = None;
    let mut ctx = ConnContext::default();

    loop {
        let payload = match conn.read_frame() {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        if payload.len() < 8 {
            continue;
        }
        let auth_key_id = i64::from_le_bytes(payload[0..8].try_into().unwrap());

        if auth_key_id == 0 {
            // Unencrypted handshake message.
            let Some(body) = parse_bare(&payload) else {
                continue;
            };
            if body.len() >= 4 {
                let cons = u32::from_le_bytes(body[0..4].try_into().unwrap());
                if cons == 0x62d6_b459 /* msgs_ack */ || cons == 0x7abe_77ec /* ping */ {
                    continue;
                }
            }
            match hs.handle(body) {
                Ok(Step::Reply(reply)) => conn.write_frame(&build_bare(&reply))?,
                Ok(Step::Done {
                    reply,
                    auth_key,
                    auth_key_id,
                    server_salt,
                }) => {
                    conn.write_frame(&build_bare(&reply))?;
                    eprintln!("[edge]   established auth_key id={auth_key_id:#018x}");
                    keys.insert(auth_key_id, *auth_key, server_salt);
                    session = Some(Session::new(*auth_key, server_salt, 0));
                }
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
            }
            continue;
        }

        // Encrypted message: ensure we have a session for this key.
        if session.as_ref().map(|s| s.auth_key_id()) != Some(auth_key_id) {
            let found = keys.get(auth_key_id);
            match found {
                Some((key, salt)) => session = Some(Session::new(key, salt, 0)),
                None => {
                    // Unknown key (handshake not seen yet): drop this connection.
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("encrypted message for unknown auth_key_id {auth_key_id:#018x}"),
                    ));
                }
            }
        }
        let s = session.as_mut().unwrap();
        let incoming = match s.decrypt(&payload) {
            Ok(m) => m,
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
        };
        if s.session_id == 0 {
            s.session_id = incoming.session_id;
        }
        for reply in dispatcher.handle_message(&mut ctx, incoming.msg_id, &incoming.body) {
            let seq = s.next_content_seq();
            let enc = s.encrypt(next_message_id(), seq, &reply);
            conn.write_frame(&enc)?;
        }
    }
}

/// Parse a bare (unencrypted) message, returning its body. Requires
/// `auth_key_id == 0`.
fn parse_bare(payload: &[u8]) -> Option<&[u8]> {
    if payload.len() < 20 {
        return None;
    }
    let auth_key_id = i64::from_le_bytes(payload[0..8].try_into().unwrap());
    if auth_key_id != 0 {
        return None;
    }
    let len = u32::from_le_bytes(payload[16..20].try_into().unwrap()) as usize;
    payload.get(20..20 + len)
}

/// Wrap a body in a bare message with a fresh server `message_id`.
fn build_bare(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + body.len());
    out.extend_from_slice(&0i64.to_le_bytes()); // auth_key_id = 0
    out.extend_from_slice(&next_message_id().to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Monotonic server message id: `unix_time << 32` with low bits so that
/// `msg_id mod 4 == 1` (server-originated), strictly increasing.
fn next_message_id() -> i64 {
    use std::sync::atomic::{AtomicI64, Ordering};
    static LAST: AtomicI64 = AtomicI64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let mut candidate = (now << 32) | 1;
    loop {
        let last = LAST.load(Ordering::SeqCst);
        if candidate <= last {
            candidate = last + 4;
        }
        if LAST
            .compare_exchange(last, candidate, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            return candidate;
        }
    }
}

//! MTProto TCP transport: obfuscation detection, frame (de)framing, and the
//! per-connection serve loop.
//!
//! Supports:
//! - plaintext **Abridged** (`0xef`), **Intermediate** (`0xeeeeeeee`), and
//!   **Padded Intermediate** (`0xdddddddd`);
//! - **Obfuscated2** (random 64-byte header, AES-256-CTR) with an Abridged
//!   (`0xefefefef`), Intermediate (`0xeeeeeeee`), or Padded Intermediate
//!   (`0xdddddddd`) inner protocol — what the ShuzaGram Android client uses.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ctr::cipher::{KeyIvInit, StreamCipher};
use gram_core::dispatch::{ConnContext, OutboundKind};
use gram_core::{Dispatcher, Session};
use mtproto_crypto::dh::DhParams;
use mtproto_crypto::rsa_key::ServerRsaKey;

use crate::handshake::{HandshakeServer, Step};
use crate::keystore::KeyStore;

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

/// MTProto transport-level error frame `-404` (`auth_key_id` not found), which
/// instructs `tgnet` (`ConnectionsManager.cpp`) to drop the stale cached key
/// and start a fresh DH handshake instead of reconnecting in an infinite loop.
const TRANSPORT_ERR_UNKNOWN_KEY: i32 = -404;

/// Idle read timeout so half-open mobile sockets never leak OS threads.
const SOCKET_READ_TIMEOUT: Duration = Duration::from_secs(300);
const SOCKET_WRITE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, PartialEq)]
enum Inner {
    Abridged,
    Intermediate,
    PaddedIntermediate,
    FullTcp,
}

/// A connection with its transport framing and (for obfuscated transports) the
/// stream ciphers. All socket I/O goes through here so obfuscation is applied
/// transparently.
struct Conn {
    sock: TcpStream,
    inner: Inner,
    dec: Option<Aes256Ctr>, // decrypts client -> server
    enc: Option<Aes256Ctr>, // encrypts server -> client
    first_full_header: Option<[u8; 4]>,
    full_out_seq: u32,
}

impl Conn {
    /// Read the transport header, detecting plaintext vs obfuscated framing.
    fn accept(mut sock: TcpStream) -> io::Result<Conn> {
        let _ = sock.set_nodelay(true);
        let _ = sock.set_read_timeout(Some(SOCKET_READ_TIMEOUT));
        let _ = sock.set_write_timeout(Some(SOCKET_WRITE_TIMEOUT));

        let mut b0 = [0u8; 1];
        sock.read_exact(&mut b0)?;
        if b0[0] == 0xef {
            return Ok(Conn {
                sock,
                inner: Inner::Abridged,
                dec: None,
                enc: None,
                first_full_header: None,
                full_out_seq: 0,
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
                first_full_header: None,
                full_out_seq: 0,
            });
        }
        if b0[0] == 0xdd && rest == [0xdd, 0xdd, 0xdd] {
            return Ok(Conn {
                sock,
                inner: Inner::PaddedIntermediate,
                dec: None,
                enc: None,
                first_full_header: None,
                full_out_seq: 0,
            });
        }

        // Peek next 4 bytes to distinguish Full TCP (`seq_no == 0` and reasonable
        // frame length `>= 12`) from 64-byte Obfuscated2 (which never has `bytes[4..8] == 0`).
        let mut next4 = [0u8; 4];
        sock.read_exact(&mut next4)?;
        let first4 = [b0[0], rest[0], rest[1], rest[2]];
        let cand_len = u32::from_le_bytes(first4);
        let cand_seq = u32::from_le_bytes(next4);
        if cand_seq == 0 && (12..=4 * 1024 * 1024).contains(&cand_len) && cand_len.is_multiple_of(4) {
            return Ok(Conn {
                sock,
                inner: Inner::FullTcp,
                dec: None,
                enc: None,
                first_full_header: Some(first4),
                full_out_seq: 0,
            });
        }

        // Obfuscated2: the first 8 bytes are the start of a 64-byte nonce.
        let mut nonce = [0u8; 64];
        nonce[0..4].copy_from_slice(&first4);
        nonce[4..8].copy_from_slice(&next4);
        sock.read_exact(&mut nonce[8..])?;

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
            0xdddd_dddd => Inner::PaddedIntermediate,
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
            first_full_header: None,
            full_out_seq: 0,
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

    /// Read one transport frame, returning `(payload, quick_ack_requested)`.
    fn read_frame(&mut self) -> io::Result<(Vec<u8>, bool)> {
        match self.inner {
            Inner::Intermediate | Inner::PaddedIntermediate => {
                let mut len_buf = [0u8; 4];
                self.read_exact(&mut len_buf)?;
                let raw_len = u32::from_le_bytes(len_buf);
                let quick_ack = (raw_len & 0x8000_0000) != 0;
                let len = (raw_len & 0x7fff_ffff) as usize;
                if len > 4 * 1024 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("oversized frame {len}"),
                    ));
                }
                let mut payload = vec![0u8; len];
                self.read_exact(&mut payload)?;
                Ok((payload, quick_ack))
            }
            Inner::Abridged => {
                let mut b = [0u8; 1];
                self.read_exact(&mut b)?;
                let quick_ack = (b[0] & 0x80) != 0;
                let first = b[0] & 0x7f; // high bit = quick-ack request
                let words = if first < 0x7f {
                    first as usize
                } else {
                    let mut l = [0u8; 3];
                    self.read_exact(&mut l)?;
                    l[0] as usize | (l[1] as usize) << 8 | (l[2] as usize) << 16
                };
                if words > 1024 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("oversized abridged frame {words} words"),
                    ));
                }
                let mut payload = vec![0u8; words * 4];
                self.read_exact(&mut payload)?;
                Ok((payload, quick_ack))
            }
            Inner::FullTcp => {
                let (len_bytes, seq_bytes) = if let Some(first_len) = self.first_full_header.take() {
                    // For the very first Full TCP packet, seq_no (0) was already consumed in accept().
                    (first_len, 0u32.to_le_bytes())
                } else {
                    let mut hdr = [0u8; 8];
                    self.read_exact(&mut hdr)?;
                    (hdr[0..4].try_into().unwrap(), hdr[4..8].try_into().unwrap())
                };
                let total_len = u32::from_le_bytes(len_bytes) as usize;
                if !(12..=4 * 1024 * 1024).contains(&total_len) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid full tcp frame length {total_len}"),
                    ));
                }
                let body_len = total_len - 12;
                let mut payload = vec![0u8; body_len];
                self.read_exact(&mut payload)?;
                let mut crc_bytes = [0u8; 4];
                self.read_exact(&mut crc_bytes)?;
                let expected_crc = u32::from_le_bytes(crc_bytes);
                let mut hasher = crc32fast::Hasher::new();
                hasher.update(&len_bytes);
                hasher.update(&seq_bytes);
                hasher.update(&payload);
                if hasher.finalize() != expected_crc {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "full tcp crc32 mismatch",
                    ));
                }
                Ok((payload, false))
            }
        }
    }

    /// Emit a 4-byte MTProto Quick-Ack token derived from `msg_key` when requested.
    fn write_quick_ack(&mut self, msg_key: &[u8; 16]) -> io::Result<()> {
        let token = u32::from_le_bytes(msg_key[0..4].try_into().unwrap()) | 0x8000_0000;
        let bytes = match self.inner {
            Inner::Abridged => token.swap_bytes().to_le_bytes(),
            Inner::Intermediate | Inner::PaddedIntermediate => token.to_le_bytes(),
            Inner::FullTcp => return Ok(()),
        };
        self.write_all(&bytes)?;
        self.sock.flush()
    }

    /// Write one transport frame around `payload` (`payload.len()` is always a
    /// multiple of 4, including the 4-byte `-404` transport error code).
    fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        match self.inner {
            Inner::Intermediate | Inner::PaddedIntermediate => {
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
            Inner::FullTcp => {
                let total_len = (12 + payload.len()) as u32;
                let seq = self.full_out_seq;
                self.full_out_seq = self.full_out_seq.wrapping_add(1);
                let len_b = total_len.to_le_bytes();
                let seq_b = seq.to_le_bytes();
                let mut hasher = crc32fast::Hasher::new();
                hasher.update(&len_b);
                hasher.update(&seq_b);
                hasher.update(payload);
                let crc = hasher.finalize().to_le_bytes();
                let mut out = Vec::with_capacity(total_len as usize);
                out.extend_from_slice(&len_b);
                out.extend_from_slice(&seq_b);
                out.extend_from_slice(payload);
                out.extend_from_slice(&crc);
                self.write_all(&out)?;
            }
        }
        self.sock.flush()
    }
}

/// Run a connection: detect the transport, then serve a unified loop that
/// handles unencrypted handshake messages and encrypted session messages.
pub fn serve_connection(
    sock: TcpStream,
    rsa: &ServerRsaKey,
    dh: &DhParams,
    dispatcher: &Arc<Dispatcher>,
    keys: &Arc<KeyStore>,
) -> io::Result<()> {
    let peer = sock
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "?".into());
    let mut conn = Conn::accept(sock)?;
    let mut hs = HandshakeServer::new(rsa.clone(), dh.clone());
    let mut session: Option<Session> = None;
    let mut ctx = ConnContext::default();

    loop {
        let (payload, quick_ack) = match conn.read_frame() {
            Ok(p) => p,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(());
            }
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
                    eprintln!("[edge] {peer}: established auth_key id={auth_key_id:#018x}");
                    keys.insert(auth_key_id, *auth_key, server_salt);
                    session = Some(Session::new(*auth_key, server_salt, 0));
                    ctx.auth_key_id = auth_key_id;
                    ctx.server_salt = server_salt;
                }
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
            }
            continue;
        }

        // Encrypted message: ensure we have a session for this key.
        if session.as_ref().map(|s| s.auth_key_id()) != Some(auth_key_id) {
            match keys.get(auth_key_id) {
                Some((key, salt)) => {
                    session = Some(Session::new(key, salt, 0));
                    ctx.auth_key_id = auth_key_id;
                    ctx.server_salt = salt;
                    ctx.user = None; // re-hydrated in dispatcher via perm_key binding
                }
                None => {
                    // Send MTProto -404 transport error frame so the client
                    // drops the stale key and triggers a fresh DH handshake!
                    eprintln!(
                        "[edge] {peer}: unknown auth_key_id {auth_key_id:#018x} -> sending -404"
                    );
                    conn.write_frame(&TRANSPORT_ERR_UNKNOWN_KEY.to_le_bytes())?;
                    continue;
                }
            }
        }
        let s = session.as_mut().unwrap();
        let incoming = match s.decrypt(&payload) {
            Ok(m) => m,
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
        };
        if quick_ack && payload.len() >= 24 {
            let msg_key: [u8; 16] = payload[8..24].try_into().unwrap();
            conn.write_quick_ack(&msg_key)?;
        }
        if s.session_id != incoming.session_id {
            s.session_id = incoming.session_id;
        }
        ctx.auth_key_id = auth_key_id;
        ctx.server_salt = s.server_salt;
        ctx.session_id = incoming.session_id;

        for out in dispatcher.handle_message_ex(&mut ctx, incoming.msg_id, &incoming.body) {
            let seq = match out.kind {
                OutboundKind::Content => s.next_content_seq(),
                OutboundKind::Service => s.current_service_seq(),
            };
            let enc = s.encrypt(next_message_id(), seq, &out.body);
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

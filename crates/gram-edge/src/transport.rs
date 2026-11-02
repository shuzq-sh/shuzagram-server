//! MTProto TCP transport framing and the per-connection serve loop.
//!
//! Supports the two simplest TCP transports a client may select:
//! - **Abridged** (first byte `0xef`)
//! - **Intermediate** (first 4 bytes `0xeeeeeeee`)
//!
//! Inside each frame is a *bare* (unencrypted) MTProto message during the
//! handshake: `auth_key_id(0) | message_id | length | body`.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use gram_core::{Dispatcher, Session};
use mtproto_crypto::dh::DhParams;
use mtproto_crypto::rsa_key::ServerRsaKey;

use crate::handshake::{HandshakeServer, Step};

#[derive(Clone, Copy)]
enum Transport {
    Abridged,
    Intermediate,
}

/// Run a connection: detect the transport, then drive the handshake to
/// completion. The established key material is logged (session handling comes
/// with `gram-core`).
pub fn serve_connection(
    mut sock: TcpStream,
    rsa: &ServerRsaKey,
    dh: &DhParams,
    dispatcher: &Arc<Dispatcher>,
) -> io::Result<()> {
    let transport = detect_transport(&mut sock)?;
    let mut hs = HandshakeServer::new(rsa.clone(), dh.clone());

    // Phase 1: unencrypted DH handshake.
    let (auth_key, server_salt) = loop {
        let payload = read_frame(&mut sock, transport)?;
        let body = parse_bare(&payload)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad bare message"))?;

        match hs.handle(body) {
            Ok(Step::Reply(reply)) => {
                write_frame(&mut sock, transport, &build_bare(&reply))?;
            }
            Ok(Step::Done {
                reply,
                auth_key,
                auth_key_id,
                server_salt,
            }) => {
                write_frame(&mut sock, transport, &build_bare(&reply))?;
                eprintln!("[edge]   established auth_key id={auth_key_id:#018x}");
                break (*auth_key, server_salt);
            }
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
        }
    };

    // Phase 2: authenticated session — handle encrypted RPCs (auth.sendCode,
    // auth.signIn, ping, …) until the client disconnects.
    let mut session = Session::new(auth_key, server_salt, 0);
    loop {
        let payload = match read_frame(&mut sock, transport) {
            Ok(p) => p,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let incoming = session
            .decrypt(&payload)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        // Adopt the client's session id so replies are addressed correctly.
        if session.session_id == 0 {
            session.session_id = incoming.session_id;
        }
        for reply in dispatcher.handle_message(incoming.msg_id, &incoming.body) {
            let seq = session.next_content_seq();
            let enc = session.encrypt(next_message_id(), seq, &reply);
            write_frame(&mut sock, transport, &enc)?;
        }
    }
}

fn detect_transport(sock: &mut TcpStream) -> io::Result<Transport> {
    let mut first = [0u8; 1];
    sock.read_exact(&mut first)?;
    if first[0] == 0xef {
        return Ok(Transport::Abridged);
    }
    // Intermediate begins with 0xeeeeeeee; we already consumed one 0xee.
    let mut rest = [0u8; 3];
    sock.read_exact(&mut rest)?;
    if first[0] == 0xee && rest == [0xee, 0xee, 0xee] {
        return Ok(Transport::Intermediate);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "unsupported transport (only abridged/intermediate)",
    ))
}

fn read_frame(sock: &mut TcpStream, transport: Transport) -> io::Result<Vec<u8>> {
    match transport {
        Transport::Intermediate => {
            let mut len_buf = [0u8; 4];
            sock.read_exact(&mut len_buf)?;
            let len = u32::from_le_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            sock.read_exact(&mut payload)?;
            Ok(payload)
        }
        Transport::Abridged => {
            let mut b = [0u8; 1];
            sock.read_exact(&mut b)?;
            let len = if b[0] < 0x7f {
                b[0] as usize * 4
            } else {
                let mut l = [0u8; 3];
                sock.read_exact(&mut l)?;
                (l[0] as usize | (l[1] as usize) << 8 | (l[2] as usize) << 16) * 4
            };
            let mut payload = vec![0u8; len];
            sock.read_exact(&mut payload)?;
            Ok(payload)
        }
    }
}

fn write_frame(sock: &mut TcpStream, transport: Transport, payload: &[u8]) -> io::Result<()> {
    match transport {
        Transport::Intermediate => {
            sock.write_all(&(payload.len() as u32).to_le_bytes())?;
            sock.write_all(payload)?;
        }
        Transport::Abridged => {
            let words = payload.len() / 4;
            if words < 0x7f {
                sock.write_all(&[words as u8])?;
            } else {
                sock.write_all(&[0x7f])?;
                sock.write_all(&[
                    (words & 0xff) as u8,
                    ((words >> 8) & 0xff) as u8,
                    ((words >> 16) & 0xff) as u8,
                ])?;
            }
            sock.write_all(payload)?;
        }
    }
    sock.flush()
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
    let body = payload.get(20..20 + len)?;
    Some(body)
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

/// Monotonic server message id: `unix_time << 32`, with the low bits set so that
/// `msg_id mod 4 == 1` (server-originated), and strictly increasing.
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

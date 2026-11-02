//! Async `tokio` Zero-Copy MTProto 2.0 Edge Gateway (`gram-edge`).
//!
//! Supports all 6 MTProto transport encodings over both raw TCP and WebSocket:
//! 1. **Abridged** (`0xef`)
//! 2. **Intermediate** (`0xeeeeeeee`)
//! 3. **Padded Intermediate** (`0xdddddddd`)
//! 4. **Full TCP** (`length + seq_no + payload + CRC32`)
//! 5. **Obfuscated2** (64-byte AES-256-CTR header, both unkeyed and secret-keyed)
//! 6. **Fake-TLS 1.3** (`0x16 0x03 0x01` HMAC-authenticated ClientHello + `0x17 0x03 0x03` records)
//!
//! Plus bidirectional real-time `Updates` push from [`gram_core::SessionHub`],
//! 128-slot `ReplayWindow` deduplication, `new_session_created#9ec20908`, and
//! `-404` unknown-key recovery.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Buf, BytesMut};
use ctr::cipher::{KeyIvInit, StreamCipher};
use futures_util::{Sink, Stream};
use gram_core::dispatch::{ConnContext, Outbound, OutboundKind};
use gram_core::egress::EgressCommand;
use gram_core::{Dispatcher, KeyStore, Session};
use mtproto_crypto::dh::DhParams;
use mtproto_crypto::faketls::{
    wrap_tls_application_data, FakeTlsSecret, TLS_APPLICATION_DATA, TLS_CHANGE_CIPHER_SPEC,
    TLS_HANDSHAKE,
};
use mtproto_crypto::replay::{MsgIdVerdict, ReplayWindow};
use mtproto_crypto::rsa_key::ServerRsaKey;
use mtproto_crypto::sha256_parts;
use rand::RngCore;
use tl_core::Writer;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response as WsResponse};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use crate::handshake::{HandshakeServer, Step};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

const TRANSPORT_ERR_UNKNOWN_KEY: i32 = -404;
const NEW_SESSION_CREATED: u32 = 0x9ec2_0908;
const BAD_MSG_NOTIFICATION: u32 = 0xa7ef_f811;
const IDLE_READ_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct EdgeConfig {
    pub rsa: Arc<ServerRsaKey>,
    pub dh: DhParams,
    pub dispatcher: Arc<Dispatcher>,
    pub keys: Arc<KeyStore>,
    pub fake_tls: Option<FakeTlsSecret>,
    pub enforce_clock_window: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Inner {
    Abridged,
    Intermediate,
    PaddedIntermediate,
    FullTcp,
}

/// Adapter turning a `tokio_tungstenite::WebSocketStream` into `AsyncRead + AsyncWrite`
/// so all MTProto framing (Abridged / Intermediate / Obfuscated2) works identically over WS.
pub struct WsByteStream<S> {
    ws: tokio_tungstenite::WebSocketStream<S>,
    read_buf: BytesMut,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsByteStream<S> {
    pub fn new(ws: tokio_tungstenite::WebSocketStream<S>) -> Self {
        Self {
            ws,
            read_buf: BytesMut::with_capacity(8192),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsByteStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let n = buf.remaining().min(self.read_buf.len());
                buf.put_slice(&self.read_buf.split_to(n));
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.ws).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Ok(WsMessage::Binary(b)))) => {
                    if !b.is_empty() {
                        self.read_buf.extend_from_slice(&b);
                    }
                }
                Poll::Ready(Some(Ok(WsMessage::Close(_)))) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionAborted, e)))
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsByteStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.ws).poll_ready(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)))
            }
            Poll::Ready(Ok(())) => {
                if let Err(e) = Pin::new(&mut self.ws).start_send(WsMessage::Binary(buf.to_vec())) {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
                }
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws)
            .poll_flush(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.ws)
            .poll_close(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, e))
    }
}

/// Async stream reader/writer supporting optional Fake-TLS `0x17 0x03 0x03` framing
/// and optional Obfuscated2 AES-256-CTR stream cipher.
struct AsyncConn<S> {
    io: S,
    is_fake_tls: bool,
    tls_plain_buf: BytesMut,
    prefix_buf: BytesMut,
    inner: Inner,
    dec: Option<Aes256Ctr>,
    enc: Option<Aes256Ctr>,
    first_full_header: Option<[u8; 4]>,
    full_out_seq: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncConn<S> {
    async fn accept(mut io: S, fake_tls_cfg: Option<&FakeTlsSecret>) -> io::Result<Self> {
        let mut first3 = [0u8; 3];
        io.read_exact(&mut first3).await?;

        let mut is_fake_tls = false;
        let mut prefix_buf = BytesMut::new();

        if first3[0] == TLS_HANDSHAKE && first3[1] == 0x03 && (first3[2] == 0x01 || first3[2] == 0x03)
        {
            let Some(secret) = fake_tls_cfg.filter(|s| s.allow_fake_tls) else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Fake-TLS handshake received but Fake-TLS secret is not configured",
                ));
            };
            let mut len_b = [0u8; 2];
            io.read_exact(&mut len_b).await?;
            let body_len = u16::from_be_bytes(len_b) as usize;
            if body_len > 4096 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Fake-TLS ClientHello too large",
                ));
            }
            let mut record = Vec::with_capacity(5 + body_len);
            record.extend_from_slice(&first3);
            record.extend_from_slice(&len_b);
            record.resize(5 + body_len, 0);
            io.read_exact(&mut record[5..]).await?;

            let now = now_unix_u32();
            let (client_random, session_id) = secret
                .verify_client_hello(&record, now)
                .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e.to_string()))?;

            let flight = {
                let mut rng = rand::thread_rng();
                secret.build_server_hello_flight(&client_random, &session_id, &mut rng)
            };
            io.write_all(&flight).await?;
            io.flush().await?;
            is_fake_tls = true;
        } else {
            prefix_buf.extend_from_slice(&first3);
        }

        let mut conn = Self {
            io,
            is_fake_tls,
            tls_plain_buf: BytesMut::with_capacity(16_384),
            prefix_buf,
            inner: Inner::Abridged,
            dec: None,
            enc: None,
            first_full_header: None,
            full_out_seq: 0,
        };

        // Detect inner MTProto transport
        let mut b0 = [0u8; 1];
        conn.read_transport_raw(&mut b0).await?;
        if b0[0] == 0xef {
            conn.inner = Inner::Abridged;
            return Ok(conn);
        }

        let mut rest = [0u8; 3];
        conn.read_transport_raw(&mut rest).await?;
        if b0[0] == 0xee && rest == [0xee, 0xee, 0xee] {
            conn.inner = Inner::Intermediate;
            return Ok(conn);
        }
        if b0[0] == 0xdd && rest == [0xdd, 0xdd, 0xdd] {
            conn.inner = Inner::PaddedIntermediate;
            return Ok(conn);
        }

        let mut next4 = [0u8; 4];
        conn.read_transport_raw(&mut next4).await?;
        let first4 = [b0[0], rest[0], rest[1], rest[2]];
        let cand_len = u32::from_le_bytes(first4);
        let cand_seq = u32::from_le_bytes(next4);
        if cand_seq == 0 && (12..=4 * 1024 * 1024).contains(&cand_len) && cand_len.is_multiple_of(4)
        {
            conn.inner = Inner::FullTcp;
            conn.first_full_header = Some(first4);
            return Ok(conn);
        }

        // 64-byte Obfuscated2 header
        let mut nonce = [0u8; 64];
        nonce[0..4].copy_from_slice(&first4);
        nonce[4..8].copy_from_slice(&next4);
        conn.read_transport_raw(&mut nonce[8..]).await?;

        let raw_dec_key: [u8; 32] = nonce[8..40].try_into().unwrap();
        let dec_iv: [u8; 16] = nonce[40..56].try_into().unwrap();
        let mut rev = [0u8; 48];
        for (i, slot) in rev.iter_mut().enumerate() {
            *slot = nonce[55 - i];
        }
        let raw_enc_key: [u8; 32] = rev[0..32].try_into().unwrap();
        let enc_iv: [u8; 16] = rev[32..48].try_into().unwrap();

        // Try secret-keyed Obfuscated2 first if a proxy secret is configured,
        // falling back to standard unkeyed Obfuscated2 so both client modes work!
        let mut chosen: Option<(Inner, Aes256Ctr, Aes256Ctr)> = None;
        if let Some(sec) = fake_tls_cfg {
            let keyed_dec = sha256_parts(&[&raw_dec_key, &sec.raw_secret]);
            let keyed_enc = sha256_parts(&[&raw_enc_key, &sec.raw_secret]);
            let mut dec = Aes256Ctr::new(&keyed_dec.into(), &dec_iv.into());
            let mut probe = nonce;
            dec.apply_keystream(&mut probe);
            let tag = u32::from_le_bytes(probe[56..60].try_into().unwrap());
            if let Some(inner) = decode_obf_tag(tag) {
                let enc = Aes256Ctr::new(&keyed_enc.into(), &enc_iv.into());
                chosen = Some((inner, dec, enc));
            }
        }
        if chosen.is_none() {
            let mut dec = Aes256Ctr::new(&raw_dec_key.into(), &dec_iv.into());
            let mut probe = nonce;
            dec.apply_keystream(&mut probe);
            let tag = u32::from_le_bytes(probe[56..60].try_into().unwrap());
            let Some(inner) = decode_obf_tag(tag) else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported obfuscated inner protocol {tag:#010x}"),
                ));
            };
            let enc = Aes256Ctr::new(&raw_enc_key.into(), &enc_iv.into());
            chosen = Some((inner, dec, enc));
        }

        let (inner, dec, enc) = chosen.unwrap();
        conn.inner = inner;
        conn.dec = Some(dec);
        conn.enc = Some(enc);
        Ok(conn)
    }

    async fn read_transport_raw(&mut self, mut out: &mut [u8]) -> io::Result<()> {
        while !out.is_empty() {
            if !self.prefix_buf.is_empty() {
                let n = out.len().min(self.prefix_buf.len());
                out[..n].copy_from_slice(&self.prefix_buf[..n]);
                self.prefix_buf.advance(n);
                out = &mut out[n..];
                continue;
            }
            if self.is_fake_tls {
                while self.tls_plain_buf.is_empty() {
                    let mut hdr = [0u8; 5];
                    self.io.read_exact(&mut hdr).await?;
                    let rec_type = hdr[0];
                    let rec_len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
                    if rec_len > 16_640 {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "TLS record exceeds maximum length",
                        ));
                    }
                    let start = self.tls_plain_buf.len();
                    self.tls_plain_buf.resize(start + rec_len, 0);
                    self.io
                        .read_exact(&mut self.tls_plain_buf[start..start + rec_len])
                        .await?;
                    if rec_type == TLS_CHANGE_CIPHER_SPEC {
                        self.tls_plain_buf.clear();
                        continue;
                    }
                    if rec_type != TLS_APPLICATION_DATA {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("unexpected TLS record type {rec_type:#04x}"),
                        ));
                    }
                }
                let n = out.len().min(self.tls_plain_buf.len());
                out[..n].copy_from_slice(&self.tls_plain_buf[..n]);
                self.tls_plain_buf.advance(n);
                out = &mut out[n..];
            } else {
                self.io.read_exact(out).await?;
                break;
            }
        }
        Ok(())
    }

    async fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.read_transport_raw(buf).await?;
        if let Some(dec) = &mut self.dec {
            dec.apply_keystream(buf);
        }
        Ok(())
    }

    async fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        let mut cipher_buf: Vec<u8>;
        let wire_bytes: &[u8] = if let Some(enc) = &mut self.enc {
            cipher_buf = data.to_vec();
            enc.apply_keystream(&mut cipher_buf);
            &cipher_buf
        } else {
            data
        };

        if self.is_fake_tls {
            let mut tls_out = Vec::with_capacity(wire_bytes.len() + 16);
            wrap_tls_application_data(wire_bytes, &mut tls_out);
            self.io.write_all(&tls_out).await?;
        } else {
            self.io.write_all(wire_bytes).await?;
        }
        self.io.flush().await
    }

    async fn read_frame(&mut self) -> io::Result<(Vec<u8>, bool)> {
        match self.inner {
            Inner::Intermediate | Inner::PaddedIntermediate => {
                let mut len_b = [0u8; 4];
                self.read_exact(&mut len_b).await?;
                let raw_len = u32::from_le_bytes(len_b);
                let quick_ack = (raw_len & 0x8000_0000) != 0;
                let len = (raw_len & 0x7fff_ffff) as usize;
                if len > 4 * 1024 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("frame too large: {len}"),
                    ));
                }
                let mut buf = vec![0u8; len];
                self.read_exact(&mut buf).await?;
                Ok((buf, quick_ack))
            }
            Inner::Abridged => {
                let mut h = [0u8; 1];
                self.read_exact(&mut h).await?;
                let quick_ack = (h[0] & 0x80) != 0;
                let tag = h[0] & 0x7f;
                let words = if tag < 0x7f {
                    tag as usize
                } else {
                    let mut len_b = [0u8; 3];
                    self.read_exact(&mut len_b).await?;
                    (len_b[0] as usize)
                        | ((len_b[1] as usize) << 8)
                        | ((len_b[2] as usize) << 16)
                };
                let len = words * 4;
                if len > 4 * 1024 * 1024 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("frame too large: {len}"),
                    ));
                }
                let mut buf = vec![0u8; len];
                self.read_exact(&mut buf).await?;
                Ok((buf, quick_ack))
            }
            Inner::FullTcp => {
                let (len_b, seq_b) = if let Some(first4) = self.first_full_header.take() {
                    (first4, 0u32.to_le_bytes())
                } else {
                    let mut hdr = [0u8; 8];
                    self.read_exact(&mut hdr).await?;
                    (hdr[0..4].try_into().unwrap(), hdr[4..8].try_into().unwrap())
                };
                let total_len = u32::from_le_bytes(len_b) as usize;
                if !(12..=4 * 1024 * 1024).contains(&total_len) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid full tcp frame length: {total_len}"),
                    ));
                }
                let payload_len = total_len - 12;
                let mut payload = vec![0u8; payload_len];
                self.read_exact(&mut payload).await?;
                let mut crc_b = [0u8; 4];
                self.read_exact(&mut crc_b).await?;
                let expected_crc = u32::from_le_bytes(crc_b);
                let mut hasher = crc32fast::Hasher::new();
                hasher.update(&len_b);
                hasher.update(&seq_b);
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

    async fn write_quick_ack(&mut self, msg_key: &[u8; 16]) -> io::Result<()> {
        let token = u32::from_le_bytes(msg_key[0..4].try_into().unwrap()) | 0x8000_0000;
        let bytes = match self.inner {
            Inner::Abridged => token.swap_bytes().to_le_bytes(),
            Inner::Intermediate | Inner::PaddedIntermediate => token.to_le_bytes(),
            Inner::FullTcp => return Ok(()),
        };
        self.write_all(&bytes).await
    }

    async fn write_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        match self.inner {
            Inner::Intermediate | Inner::PaddedIntermediate => {
                let mut out = Vec::with_capacity(4 + payload.len());
                out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                out.extend_from_slice(payload);
                self.write_all(&out).await
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
                self.write_all(&out).await
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
                self.write_all(&out).await
            }
        }
    }
}

fn decode_obf_tag(tag: u32) -> Option<Inner> {
    match tag {
        0xefef_efef => Some(Inner::Abridged),
        0xeeee_eeee => Some(Inner::Intermediate),
        0xdddd_dddd => Some(Inner::PaddedIntermediate),
        _ => None,
    }
}

struct SessionGuard<'a> {
    hub: &'a gram_core::SessionHub,
    conn_id: u64,
}

impl Drop for SessionGuard<'_> {
    fn drop(&mut self) {
        self.hub.unregister_connection(self.conn_id);
    }
}

/// Serve a single async byte stream (TCP, Fake-TLS TCP, or WebSocket) through
/// DH-2048 handshake, encrypted MTProto 2.0 session, and real-time `SessionHub` push.
pub async fn serve_async_stream<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    peer: String,
    cfg: EdgeConfig,
) -> io::Result<()> {
    let hub = cfg.dispatcher.hub();
    let dc_id = cfg.dispatcher.dc().dc_id;
    let (conn_id, mut egress_rx) = hub.register_connection(peer.clone(), dc_id);
    let _guard = SessionGuard { hub, conn_id };

    let mut conn = match tokio::time::timeout(
        Duration::from_secs(30),
        AsyncConn::accept(stream, cfg.fake_tls.as_ref()),
    )
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) if is_benign_close(&e) => return Ok(()),
        Ok(Err(e)) => return Err(e),
        Err(_) => return Ok(()),
    };

    let mut hs = HandshakeServer::new((*cfg.rsa).clone(), cfg.dh.clone());
    let mut session: Option<Session> = None;
    let mut replay = ReplayWindow::new();
    let mut announced_session_id: i64 = 0;
    let mut ctx = ConnContext {
        conn_id,
        ..Default::default()
    };

    loop {
        tokio::select! {
            biased;

            Some(cmd) = egress_rx.recv(), if session.is_some() => {
                match cmd {
                    EgressCommand::ForceDisconnect => {
                        eprintln!("[edge] {peer}: force-disconnecting conn_id={conn_id}");
                        return Ok(());
                    }
                    EgressCommand::Send(out) => {
                        let s = session.as_mut().unwrap();
                        if s.session_id != 0 {
                            send_encrypted_outbound(&mut conn, s, out).await?;
                        }
                    }
                }
            }

            frame_res = tokio::time::timeout(IDLE_READ_TIMEOUT, conn.read_frame()) => {
                let (payload, quick_ack) = match frame_res {
                    Err(_) => return Ok(()), // Idle timeout
                    Ok(Err(e)) if is_benign_close(&e) => return Ok(()),
                    Ok(Err(e)) => return Err(e),
                    Ok(Ok(p)) => p,
                };
                if payload.len() < 8 {
                    continue;
                }
                let auth_key_id = i64::from_le_bytes(payload[0..8].try_into().unwrap());

                if auth_key_id == 0 {
                    let Some(body) = parse_bare(&payload) else {
                        continue;
                    };
                    if body.len() >= 4 {
                        let cons = u32::from_le_bytes(body[0..4].try_into().unwrap());
                        if cons == 0x62d6_b459 || cons == 0x7abe_77ec {
                            continue;
                        }
                    }
                    match hs.handle(body) {
                        Ok(Step::Reply(reply)) => conn.write_frame(&build_bare(&reply)).await?,
                        Ok(Step::Done {
                            reply,
                            auth_key,
                            auth_key_id,
                            server_salt,
                        }) => {
                            conn.write_frame(&build_bare(&reply)).await?;
                            eprintln!("[edge] {peer}: established auth_key id={auth_key_id:#018x}");
                            cfg.keys.insert(auth_key_id, *auth_key, server_salt);
                            session = Some(Session::new(*auth_key, server_salt, 0));
                            replay.reset();
                            ctx.auth_key_id = auth_key_id;
                            ctx.server_salt = server_salt;
                        }
                        Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
                    }
                    continue;
                }

                if session.as_ref().map(|s| s.auth_key_id()) != Some(auth_key_id) {
                    match cfg.keys.get(auth_key_id) {
                        Some((key, salt)) => {
                            session = Some(Session::new(key, salt, 0));
                            replay.reset();
                            announced_session_id = 0;
                            ctx.auth_key_id = auth_key_id;
                            ctx.server_salt = salt;
                            ctx.user = None;
                        }
                        None => {
                            eprintln!(
                                "[edge] {peer}: unknown auth_key_id {auth_key_id:#018x} -> sending -404"
                            );
                            conn.write_frame(&TRANSPORT_ERR_UNKNOWN_KEY.to_le_bytes()).await?;
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
                    conn.write_quick_ack(&msg_key).await?;
                }
                if s.session_id != incoming.session_id {
                    s.session_id = incoming.session_id;
                    replay.reset();
                }

                // Replay & optional clock-skew check
                let now_check = if cfg.enforce_clock_window {
                    Some(now_unix_u32() as i64)
                } else {
                    None
                };
                match replay.check_and_record(incoming.msg_id, now_check) {
                    MsgIdVerdict::Accept => {}
                    MsgIdVerdict::DuplicateReplay => continue,
                    verdict => {
                        if let Some(code) = verdict.bad_msg_error_code() {
                            if cfg.enforce_clock_window {
                                let notice = build_bad_msg_notification(incoming.msg_id, incoming.seq_no, code);
                                send_encrypted_outbound(&mut conn, s, Outbound::service(notice)).await?;
                                continue;
                            }
                        }
                    }
                }

                ctx.auth_key_id = auth_key_id;
                ctx.server_salt = s.server_salt;
                ctx.session_id = incoming.session_id;
                let prev_device = ctx.device_model.is_empty();

                let replies = cfg.dispatcher.handle_message_ex(&mut ctx, incoming.msg_id, &incoming.body);
                for out in replies {
                    send_encrypted_outbound(&mut conn, s, out).await?;
                }

                // When a real client initializes a session (`initConnection` populates device_model),
                // emit `new_session_created#9ec20908` once per session_id so `tgnet` updates its salt
                // and runs `onSessionCreated` / `updates.getDifference`.
                if prev_device
                    && !ctx.device_model.is_empty()
                    && incoming.session_id != 0
                    && announced_session_id != incoming.session_id
                {
                    announced_session_id = incoming.session_id;
                    let unique_id = {
                        let mut rng = rand::thread_rng();
                        let mut uid_b = [0u8; 8];
                        rng.fill_bytes(&mut uid_b);
                        i64::from_le_bytes(uid_b)
                    };
                    let nsc = build_new_session_created(incoming.msg_id, unique_id, s.server_salt);
                    send_encrypted_outbound(&mut conn, s, Outbound::content(nsc)).await?;
                }
            }
        }
    }
}

async fn send_encrypted_outbound<S: AsyncRead + AsyncWrite + Unpin>(
    conn: &mut AsyncConn<S>,
    session: &mut Session,
    out: Outbound,
) -> io::Result<()> {
    let seq = match out.kind {
        OutboundKind::Content => session.next_content_seq(),
        OutboundKind::Service => session.current_service_seq(),
    };
    let enc = session.encrypt(next_message_id(), seq, &out.body);
    conn.write_frame(&enc).await
}

/// Accept loop for async TCP connections (supports Plaintext, Obfuscated2, Full TCP, and Fake-TLS).
pub async fn serve_tcp_listener(listener: TcpListener, cfg: EdgeConfig) -> io::Result<()> {
    loop {
        let (sock, peer_addr) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let peer = peer_addr.to_string();
            if let Err(e) = serve_async_stream(sock, peer.clone(), cfg).await {
                eprintln!("[edge] {peer}: {e}");
            }
        });
    }
}

/// Accept loop for WebSocket MTProto connections (`Sec-WebSocket-Protocol: binary`).
pub async fn serve_ws_listener(listener: TcpListener, cfg: EdgeConfig) -> io::Result<()> {
    loop {
        let (sock, peer_addr) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let peer = format!("ws://{peer_addr}");
            #[allow(clippy::result_large_err)]
            fn negotiate_binary_subproto(
                req: &Request,
                mut resp: WsResponse,
            ) -> Result<WsResponse, tokio_tungstenite::tungstenite::handshake::server::ErrorResponse>
            {
                if let Some(proto) = req.headers().get("Sec-WebSocket-Protocol") {
                    if proto
                        .to_str()
                        .unwrap_or("")
                        .split(',')
                        .any(|p| p.trim() == "binary")
                    {
                        resp.headers_mut().insert(
                            "Sec-WebSocket-Protocol",
                            HeaderValue::from_static("binary"),
                        );
                    }
                }
                Ok(resp)
            }
            let ws_res = tokio_tungstenite::accept_hdr_async(sock, negotiate_binary_subproto).await;
            match ws_res {
                Ok(ws) => {
                    let stream = WsByteStream::new(ws);
                    if let Err(e) = serve_async_stream(stream, peer.clone(), cfg).await {
                        eprintln!("[edge] {peer}: {e}");
                    }
                }
                Err(e) => eprintln!("[edge] {peer} ws handshake error: {e}"),
            }
        });
    }
}

/// Helper to spawn an ephemeral async TCP edge server on `127.0.0.1:0` for integration tests.
pub async fn spawn_test_tcp_edge(cfg: EdgeConfig) -> io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = serve_tcp_listener(listener, cfg).await;
    });
    Ok(addr)
}

/// Helper to spawn an ephemeral async WebSocket edge server on `127.0.0.1:0` for integration tests.
pub async fn spawn_test_ws_edge(cfg: EdgeConfig) -> io::Result<std::net::SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = serve_ws_listener(listener, cfg).await;
    });
    Ok(addr)
}

fn is_benign_close(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::TimedOut
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
    )
}

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

fn build_bare(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + body.len());
    out.extend_from_slice(&0i64.to_le_bytes());
    out.extend_from_slice(&next_message_id().to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    let pad = (4 - out.len() % 4) % 4;
    out.resize(out.len() + pad, 0);
    out
}

fn build_new_session_created(first_msg_id: i64, unique_id: i64, server_salt: i64) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(NEW_SESSION_CREATED);
    w.write_i64(first_msg_id);
    w.write_i64(unique_id);
    w.write_i64(server_salt);
    w.into_vec()
}

fn build_bad_msg_notification(bad_msg_id: i64, bad_seq_no: i32, error_code: i32) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(BAD_MSG_NOTIFICATION);
    w.write_i64(bad_msg_id);
    w.write_i32(bad_seq_no);
    w.write_i32(error_code);
    w.into_vec()
}

fn next_message_id() -> i64 {
    static SEQ: AtomicI64 = AtomicI64::new(0);
    let secs = now_unix_u32() as i64;
    let base = (secs << 32) | 1;
    let prev = SEQ.load(Ordering::Relaxed);
    let next = if base > prev { base } else { prev + 4 };
    SEQ.store(next, Ordering::Relaxed);
    next
}

fn now_unix_u32() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[allow(dead_code)]
fn _assert_tcp_send(_: TcpStream) {}

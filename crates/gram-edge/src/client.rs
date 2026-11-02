//! A reference MTProto client over TCP using the **obfuscated2 + abridged**
//! transport — the same framing the stock Telegram/ShuzaGram client uses for a
//! direct connection. It performs the full DH handshake and then sends
//! encrypted RPCs, so it exercises the server exactly like the real app.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

use ctr::cipher::{KeyIvInit, StreamCipher};
use num_bigint_dig::BigUint;
use rand::RngCore;

use mtproto_crypto::dh::{self, DhParams};
use mtproto_crypto::kdf::{self, Direction};
use mtproto_crypto::rsa_key::ServerRsaKey;
use mtproto_crypto::{ige, sha1};
use tl_core::{Reader, Writer};

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

const REQ_PQ_MULTI: u32 = 0xbe7e_8ef1;
const RES_PQ: u32 = 0x0516_2463;
const P_Q_INNER_DATA_DC: u32 = 0xa9f5_5f95;
const REQ_DH_PARAMS: u32 = 0xd712_e4be;
const SERVER_DH_PARAMS_OK: u32 = 0xd0e8_075c;
const SERVER_DH_INNER_DATA: u32 = 0xb589_0dba;
const CLIENT_DH_INNER_DATA: u32 = 0x6643_b654;
const SET_CLIENT_DH_PARAMS: u32 = 0xf504_5f1f;
const DH_GEN_OK: u32 = 0x3bcb_f734;

/// A connected client that has completed the handshake.
pub struct Client {
    sock: TcpStream,
    enc: Aes256Ctr,
    dec: Aes256Ctr,
    auth_key: [u8; 256],
    salt: i64,
    session_id: i64,
    msg_seq: i64,
}

impl Client {
    /// Connect, run the handshake against `rsa` (the server's key), return a
    /// ready client.
    pub fn connect_and_handshake<A: ToSocketAddrs>(addr: A, rsa: &ServerRsaKey) -> io::Result<Self> {
        let mut sock = TcpStream::connect(addr)?;
        let (enc, dec) = obf_init(&mut sock)?;
        let mut sid = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut sid);
        let mut c = Client {
            sock,
            enc,
            dec,
            auth_key: [0u8; 256],
            salt: 0,
            session_id: i64::from_le_bytes(sid),
            msg_seq: 0,
        };
        c.handshake(rsa)?;
        Ok(c)
    }

    fn handshake(&mut self, rsa: &ServerRsaKey) -> io::Result<()> {
        let mut nonce = [0u8; 16];
        let mut new_nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        rand::thread_rng().fill_bytes(&mut new_nonce);

        // Step 1: req_pq_multi -> resPQ.
        let mut w = Writer::new();
        w.write_u32(REQ_PQ_MULTI);
        w.write_i128(&nonce);
        self.send_bare(&w.into_vec())?;

        let res_pq = self.recv_bare()?;
        let mut r = Reader::new(&res_pq);
        expect(&mut r, RES_PQ)?;
        let _n = r.read_i128().map_err(inval)?;
        let server_nonce = r.read_i128().map_err(inval)?;
        let pq = be_to_u64(r.read_bytes().map_err(inval)?);
        let _fps = r.read_long_vector().map_err(inval)?;

        let (p, q) = mtproto_crypto::factorize::factorize(pq).map_err(inval)?;

        // Step 2: req_DH_params -> server_DH_params_ok.
        let mut inner = Writer::new();
        inner.write_u32(P_Q_INNER_DATA_DC);
        inner.write_bytes(&pq.to_be_bytes());
        inner.write_bytes(&p.to_be_bytes());
        inner.write_bytes(&q.to_be_bytes());
        inner.write_i128(&nonce);
        inner.write_i128(&server_nonce);
        inner.write_i256(&new_nonce);
        inner.write_i32(0);
        let enc = rsa.seal_pq_inner(&inner.into_vec());

        let mut w = Writer::new();
        w.write_u32(REQ_DH_PARAMS);
        w.write_i128(&nonce);
        w.write_i128(&server_nonce);
        w.write_bytes(&p.to_be_bytes());
        w.write_bytes(&q.to_be_bytes());
        w.write_i64(rsa.fingerprint);
        w.write_bytes(&enc);
        self.send_bare(&w.into_vec())?;

        let dh_params = self.recv_bare()?;
        let mut r = Reader::new(&dh_params);
        expect(&mut r, SERVER_DH_PARAMS_OK)?;
        let _n = r.read_i128().map_err(inval)?;
        let _sn = r.read_i128().map_err(inval)?;
        let enc_answer = r.read_bytes().map_err(inval)?.to_vec();

        let (tmp_key, tmp_iv) = crate::handshake::tmp_aes(&new_nonce, &server_nonce);
        let mut answer = enc_answer;
        ige::decrypt(&tmp_key, &tmp_iv, &mut answer).map_err(inval)?;

        let mut ar = Reader::new(&answer[20..]);
        expect(&mut ar, SERVER_DH_INNER_DATA)?;
        let _n = ar.read_i128().map_err(inval)?;
        let _sn = ar.read_i128().map_err(inval)?;
        let g = ar.read_i32().map_err(inval)? as u32;
        let dh_prime = ar.read_bytes().map_err(inval)?;
        let g_a = BigUint::from_bytes_be(ar.read_bytes().map_err(inval)?);
        let prime_be: [u8; 256] = dh_prime.try_into().map_err(|_| inval_str("dh_prime"))?;
        let dh = DhParams::from_be_bytes(&prime_be, g);
        dh.validate().map_err(inval)?;

        // Step 3: set_client_DH_params -> dh_gen_ok.
        let mut b_bytes = [0u8; 256];
        rand::thread_rng().fill_bytes(&mut b_bytes);
        let b = BigUint::from_bytes_be(&b_bytes) % (&dh.prime - 1u32);
        let g_b = dh.pow(&b);

        let mut cinner = Writer::new();
        cinner.write_u32(CLIENT_DH_INNER_DATA);
        cinner.write_i128(&nonce);
        cinner.write_i128(&server_nonce);
        cinner.write_i64(0);
        cinner.write_bytes(&dh::to_be_256(&g_b));
        let cinner = cinner.into_vec();

        let mut data = Vec::new();
        data.extend_from_slice(&sha1(&cinner));
        data.extend_from_slice(&cinner);
        let pad = (16 - data.len() % 16) % 16;
        let newlen = data.len() + pad;
        data.resize(newlen, 0);
        ige::encrypt(&tmp_key, &tmp_iv, &mut data).map_err(inval)?;

        let mut w = Writer::new();
        w.write_u32(SET_CLIENT_DH_PARAMS);
        w.write_i128(&nonce);
        w.write_i128(&server_nonce);
        w.write_bytes(&data);
        self.send_bare(&w.into_vec())?;

        let gen = self.recv_bare()?;
        expect(&mut Reader::new(&gen), DH_GEN_OK)?;

        self.auth_key = dh::to_be_256(&dh.pow_base(&g_a, &b));
        let mut salt = [0u8; 8];
        for (i, s) in salt.iter_mut().enumerate() {
            *s = new_nonce[i] ^ server_nonce[i];
        }
        self.salt = i64::from_le_bytes(salt);
        Ok(())
    }

    fn next_msg_id(&mut self) -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0) as i64;
        self.msg_seq += 4;
        (t << 32) | self.msg_seq
    }

    /// Send an encrypted query and return the first reply's decrypted body.
    pub fn invoke(&mut self, query: &[u8]) -> io::Result<(i64, Vec<u8>)> {
        let msg_id = self.next_msg_id();
        let enc = self.encrypt(msg_id, query);
        self.send_frame(&enc)?;
        let payload = self.recv_frame()?;
        let body = self.decrypt_session(&payload);
        Ok((msg_id, body))
    }

    fn encrypt(&self, msg_id: i64, body: &[u8]) -> Vec<u8> {
        let mut pt = Vec::new();
        pt.extend_from_slice(&self.salt.to_le_bytes());
        pt.extend_from_slice(&self.session_id.to_le_bytes());
        pt.extend_from_slice(&msg_id.to_le_bytes());
        pt.extend_from_slice(&0i32.to_le_bytes());
        pt.extend_from_slice(&(body.len() as u32).to_le_bytes());
        pt.extend_from_slice(body);
        let base = pt.len();
        let mut pad = 16 - (base % 16);
        if pad < 12 {
            pad += 16;
        }
        pt.resize(base + pad, 0);
        let (msg_key, ct) =
            kdf::encrypt_message(&self.auth_key, &pt, Direction::ClientToServer).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&kdf::auth_key_id(&self.auth_key).to_le_bytes());
        out.extend_from_slice(&msg_key);
        out.extend_from_slice(&ct);
        out
    }

    fn decrypt_session(&self, payload: &[u8]) -> Vec<u8> {
        let msg_key: [u8; 16] = payload[8..24].try_into().unwrap();
        let mut ct = payload[24..].to_vec();
        let pt = kdf::decrypt_message(&self.auth_key, &msg_key, &mut ct, Direction::ServerToClient)
            .unwrap();
        let length = u32::from_le_bytes(pt[28..32].try_into().unwrap()) as usize;
        pt[32..32 + length].to_vec()
    }

    // --- obfuscated + abridged framing -------------------------------------

    fn send_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        let words = payload.len() / 4;
        let mut buf = Vec::with_capacity(4 + payload.len());
        if words < 0x7f {
            buf.push(words as u8);
        } else {
            buf.push(0x7f);
            buf.push((words & 0xff) as u8);
            buf.push(((words >> 8) & 0xff) as u8);
            buf.push(((words >> 16) & 0xff) as u8);
        }
        buf.extend_from_slice(payload);
        self.enc.apply_keystream(&mut buf);
        self.sock.write_all(&buf)?;
        self.sock.flush()
    }

    fn recv_frame(&mut self) -> io::Result<Vec<u8>> {
        let mut b = [0u8; 1];
        self.sock.read_exact(&mut b)?;
        self.dec.apply_keystream(&mut b);
        let words = if b[0] < 0x7f {
            b[0] as usize
        } else {
            let mut l = [0u8; 3];
            self.sock.read_exact(&mut l)?;
            self.dec.apply_keystream(&mut l);
            l[0] as usize | (l[1] as usize) << 8 | (l[2] as usize) << 16
        };
        let mut payload = vec![0u8; words * 4];
        self.sock.read_exact(&mut payload)?;
        self.dec.apply_keystream(&mut payload);
        Ok(payload)
    }

    fn send_bare(&mut self, body: &[u8]) -> io::Result<()> {
        let mut p = Vec::new();
        p.extend_from_slice(&0i64.to_le_bytes());
        p.extend_from_slice(&0i64.to_le_bytes());
        p.extend_from_slice(&(body.len() as u32).to_le_bytes());
        p.extend_from_slice(body);
        self.send_frame(&p)
    }

    fn recv_bare(&mut self) -> io::Result<Vec<u8>> {
        let payload = self.recv_frame()?;
        let len = u32::from_le_bytes(payload[16..20].try_into().unwrap()) as usize;
        Ok(payload[20..20 + len].to_vec())
    }
}

/// Perform the obfuscated2 handshake (abridged inner), returning the stream
/// ciphers `(enc for client->server, dec for server->client)`.
fn obf_init(sock: &mut TcpStream) -> io::Result<(Aes256Ctr, Aes256Ctr)> {
    let forbidden = [
        0x4441_4548u32,
        0x5453_4f50,
        0x2054_4547,
        0x4954_504f,
        0xeeee_eeee,
        0xdddd_dddd,
        0x0201_0316,
    ];
    let mut nonce = [0u8; 64];
    loop {
        rand::thread_rng().fill_bytes(&mut nonce);
        let v = u32::from_le_bytes(nonce[0..4].try_into().unwrap());
        let v2 = u32::from_le_bytes(nonce[4..8].try_into().unwrap());
        if nonce[0] != 0xef && !forbidden.contains(&v) && v2 != 0 {
            break;
        }
    }
    // Abridged inner protocol tag.
    nonce[56] = 0xef;
    nonce[57] = 0xef;
    nonce[58] = 0xef;
    nonce[59] = 0xef;

    let enc_key: [u8; 32] = nonce[8..40].try_into().unwrap();
    let enc_iv: [u8; 16] = nonce[40..56].try_into().unwrap();
    let mut rev = [0u8; 48];
    for (i, slot) in rev.iter_mut().enumerate() {
        *slot = nonce[55 - i];
    }
    let dec_key: [u8; 32] = rev[0..32].try_into().unwrap();
    let dec_iv: [u8; 16] = rev[32..48].try_into().unwrap();

    let mut enc = Aes256Ctr::new(&enc_key.into(), &enc_iv.into());
    let dec = Aes256Ctr::new(&dec_key.into(), &dec_iv.into());

    // Send nonce[0..56] in the clear, then the encrypted tag bytes [56..64].
    let mut tmp = nonce;
    enc.apply_keystream(&mut tmp);
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&nonce[0..56]);
    out.extend_from_slice(&tmp[56..64]);
    sock.write_all(&out)?;

    Ok((enc, dec))
}

fn expect(r: &mut Reader, id: u32) -> io::Result<()> {
    let got = r.read_u32().map_err(inval)?;
    if got != id {
        return Err(inval_str("unexpected constructor"));
    }
    Ok(())
}

fn be_to_u64(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for &x in b {
        v = (v << 8) | x as u64;
    }
    v
}

fn inval<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

fn inval_str(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s.to_string())
}

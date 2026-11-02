//! A reference MTProto client over TCP (Intermediate transport).
//!
//! It performs the full DH handshake and then sends encrypted RPCs. It exists
//! to exercise the server end to end (integration tests, and later the
//! load-test harness), and doubles as executable documentation of the client
//! side of login.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};

use num_bigint_dig::BigUint;
use rand::RngCore;

use mtproto_crypto::dh::{self, DhParams};
use mtproto_crypto::kdf::{self, Direction};
use mtproto_crypto::rsa_key::ServerRsaKey;
use mtproto_crypto::{ige, sha1};
use tl_core::{Reader, Writer};

// Handshake + envelope constructor ids (client side).
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
    auth_key: [u8; 256],
    salt: i64,
    session_id: i64,
    msg_seq: i64,
}

impl Client {
    /// Connect, run the handshake against `rsa` (the server's key), and return a
    /// ready client. `rsa` stands in for the public key a real client embeds.
    pub fn connect_and_handshake<A: ToSocketAddrs>(addr: A, rsa: &ServerRsaKey) -> io::Result<Self> {
        let mut sock = TcpStream::connect(addr)?;
        sock.write_all(&[0xee, 0xee, 0xee, 0xee])?; // Intermediate transport

        let mut nonce = [0u8; 16];
        let mut new_nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        rand::thread_rng().fill_bytes(&mut new_nonce);

        // Step 1: req_pq_multi -> resPQ.
        let mut w = Writer::new();
        w.write_u32(REQ_PQ_MULTI);
        w.write_i128(&nonce);
        send_bare(&mut sock, &w.into_vec())?;

        let res_pq = recv_bare(&mut sock)?;
        let mut r = Reader::new(&res_pq);
        expect(&mut r, RES_PQ)?;
        let _n = rd_i128(&mut r)?;
        let server_nonce = rd_i128(&mut r)?;
        let pq = be_to_u64(r.read_bytes().map_err(inval)?);
        let _fps = r.read_long_vector().map_err(inval)?;

        let (p, q) = mtproto_crypto::factorize::factorize(pq).map_err(inval)?;

        // Step 2: req_DH_params (with RSA_PAD-sealed p_q_inner_data) -> server_DH_params_ok.
        let mut inner = Writer::new();
        inner.write_u32(P_Q_INNER_DATA_DC);
        inner.write_bytes(&pq.to_be_bytes());
        inner.write_bytes(&p.to_be_bytes());
        inner.write_bytes(&q.to_be_bytes());
        inner.write_i128(&nonce);
        inner.write_i128(&server_nonce);
        inner.write_i256(&new_nonce);
        inner.write_i32(0); // dc
        let enc = rsa.seal_pq_inner(&inner.into_vec());

        let mut w = Writer::new();
        w.write_u32(REQ_DH_PARAMS);
        w.write_i128(&nonce);
        w.write_i128(&server_nonce);
        w.write_bytes(&p.to_be_bytes());
        w.write_bytes(&q.to_be_bytes());
        w.write_i64(rsa.fingerprint);
        w.write_bytes(&enc);
        send_bare(&mut sock, &w.into_vec())?;

        let dh_params = recv_bare(&mut sock)?;
        let mut r = Reader::new(&dh_params);
        expect(&mut r, SERVER_DH_PARAMS_OK)?;
        let _n = rd_i128(&mut r)?;
        let _sn = rd_i128(&mut r)?;
        let enc_answer = r.read_bytes().map_err(inval)?.to_vec();

        let (tmp_key, tmp_iv) = crate::handshake::tmp_aes(&new_nonce, &server_nonce);
        let mut answer = enc_answer;
        ige::decrypt(&tmp_key, &tmp_iv, &mut answer).map_err(inval)?;

        let mut ar = Reader::new(&answer[20..]);
        expect(&mut ar, SERVER_DH_INNER_DATA)?;
        let _n = rd_i128(&mut ar)?;
        let _sn = rd_i128(&mut ar)?;
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
        cinner.write_i64(0); // retry_id
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
        send_bare(&mut sock, &w.into_vec())?;

        let gen = recv_bare(&mut sock)?;
        let mut r = Reader::new(&gen);
        expect(&mut r, DH_GEN_OK)?;

        // Shared key and salt.
        let auth_key = dh::to_be_256(&dh.pow_base(&g_a, &b));
        let mut salt = [0u8; 8];
        for (i, s) in salt.iter_mut().enumerate() {
            *s = new_nonce[i] ^ server_nonce[i];
        }
        let salt = i64::from_le_bytes(salt);

        let mut sid = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut sid);

        Ok(Client {
            sock,
            auth_key,
            salt,
            session_id: i64::from_le_bytes(sid),
            msg_seq: 0,
        })
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
        send_frame(&mut self.sock, &enc)?;
        let payload = recv_frame(&mut self.sock)?;
        let body = self.decrypt(&payload);
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

    fn decrypt(&self, payload: &[u8]) -> Vec<u8> {
        let msg_key: [u8; 16] = payload[8..24].try_into().unwrap();
        let mut ct = payload[24..].to_vec();
        let pt = kdf::decrypt_message(&self.auth_key, &msg_key, &mut ct, Direction::ServerToClient)
            .unwrap();
        let length = u32::from_le_bytes(pt[28..32].try_into().unwrap()) as usize;
        pt[32..32 + length].to_vec()
    }
}

// --- framing helpers --------------------------------------------------------

fn send_frame(sock: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    sock.write_all(&(payload.len() as u32).to_le_bytes())?;
    sock.write_all(payload)?;
    sock.flush()
}

fn recv_frame(sock: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    sock.read_exact(&mut len)?;
    let mut payload = vec![0u8; u32::from_le_bytes(len) as usize];
    sock.read_exact(&mut payload)?;
    Ok(payload)
}

fn send_bare(sock: &mut TcpStream, body: &[u8]) -> io::Result<()> {
    let mut p = Vec::new();
    p.extend_from_slice(&0i64.to_le_bytes());
    p.extend_from_slice(&0i64.to_le_bytes());
    p.extend_from_slice(&(body.len() as u32).to_le_bytes());
    p.extend_from_slice(body);
    send_frame(sock, &p)
}

fn recv_bare(sock: &mut TcpStream) -> io::Result<Vec<u8>> {
    let payload = recv_frame(sock)?;
    let len = u32::from_le_bytes(payload[16..20].try_into().unwrap()) as usize;
    Ok(payload[20..20 + len].to_vec())
}

// --- small decode helpers ---------------------------------------------------

fn expect(r: &mut Reader, id: u32) -> io::Result<()> {
    let got = r.read_u32().map_err(inval)?;
    if got != id {
        return Err(inval_str("unexpected constructor"));
    }
    Ok(())
}

fn rd_i128(r: &mut Reader) -> io::Result<[u8; 16]> {
    r.read_i128().map_err(inval)
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

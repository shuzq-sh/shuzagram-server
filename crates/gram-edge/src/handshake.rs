//! Server side of the MTProto 2.0 unencrypted DH handshake.
//!
//! Drives the three-step exchange that establishes a shared 2048-bit
//! `auth_key` with a client:
//!
//! 1. `req_pq_multi`      → `resPQ`
//! 2. `req_DH_params`     → `server_DH_params_ok`
//! 3. `set_client_DH_params` → `dh_gen_ok`
//!
//! Each `handle` call takes the decoded *body* of one inbound bare message and
//! returns the body to send back, or the completed key material.

use num_bigint_dig::prime::probably_prime;
use num_bigint_dig::BigUint;
use rand::RngCore;

use mtproto_crypto::dh::{self, DhParams};
use mtproto_crypto::rsa_key::ServerRsaKey;
use mtproto_crypto::{ige, kdf, sha1, sha1_parts};
use tl_core::{Reader, TlError, Writer};

// --- constructor ids --------------------------------------------------------
const REQ_PQ_MULTI: u32 = 0xbe7e_8ef1;
const RES_PQ: u32 = 0x0516_2463;
const P_Q_INNER_DATA: u32 = 0x83c9_5aec;
const P_Q_INNER_DATA_DC: u32 = 0xa9f5_5f95;
const REQ_DH_PARAMS: u32 = 0xd712_e4be;
const SERVER_DH_PARAMS_OK: u32 = 0xd0e8_075c;
const SERVER_DH_INNER_DATA: u32 = 0xb589_0dba;
const CLIENT_DH_INNER_DATA: u32 = 0x6643_b654;
const SET_CLIENT_DH_PARAMS: u32 = 0xf504_5f1f;
const DH_GEN_OK: u32 = 0x3bcb_f734;

/// Errors during the handshake.
#[derive(Debug, thiserror::Error)]
pub enum HandshakeError {
    #[error("tl decode error: {0}")]
    Tl(#[from] TlError),
    #[error("crypto error: {0}")]
    Crypto(#[from] mtproto_crypto::CryptoError),
    #[error("unexpected constructor {0:#010x} for the current handshake stage")]
    UnexpectedConstructor(u32),
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("unknown rsa key fingerprint {0:#018x}")]
    UnknownFingerprint(i64),
    #[error("client pq {0:#x} did not match server-issued pq")]
    PqMismatch(u64),
    #[error("dh value out of range")]
    DhRange,
    #[error("sha1 integrity check failed")]
    IntegrityCheck,
}

/// Result of feeding one inbound message to the handshake.
pub enum Step {
    /// Send this body back and keep going.
    Reply(Vec<u8>),
    /// Handshake complete: send `reply`, then switch to the encrypted session.
    Done {
        reply: Vec<u8>,
        auth_key: Box<[u8; 256]>,
        auth_key_id: i64,
        server_salt: i64,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum Stage {
    AwaitReqPq,
    AwaitReqDh,
    AwaitSetClientDh,
    Finished,
}

/// Per-connection handshake state machine.
pub struct HandshakeServer {
    rsa: ServerRsaKey,
    dh: DhParams,
    stage: Stage,
    nonce: [u8; 16],
    server_nonce: [u8; 16],
    new_nonce: [u8; 32],
    pq: u64,
    p: u32,
    q: u32,
    a: BigUint,
    tmp_key: [u8; 32],
    tmp_iv: [u8; 32],
}

impl HandshakeServer {
    pub fn new(rsa: ServerRsaKey, dh: DhParams) -> Self {
        HandshakeServer {
            rsa,
            dh,
            stage: Stage::AwaitReqPq,
            nonce: [0; 16],
            server_nonce: [0; 16],
            new_nonce: [0; 32],
            pq: 0,
            p: 0,
            q: 0,
            a: BigUint::from(0u32),
            tmp_key: [0; 32],
            tmp_iv: [0; 32],
        }
    }

    /// Feed the body of one inbound bare message.
    pub fn handle(&mut self, body: &[u8]) -> Result<Step, HandshakeError> {
        let mut r = Reader::new(body);
        let id = r.read_u32()?;
        match (self.stage, id) {
            (Stage::AwaitReqPq, REQ_PQ_MULTI) => self.on_req_pq(&mut r),
            (Stage::AwaitReqDh, REQ_DH_PARAMS) => self.on_req_dh(&mut r),
            (Stage::AwaitSetClientDh, SET_CLIENT_DH_PARAMS) => self.on_set_client_dh(&mut r),
            (_, other) => Err(HandshakeError::UnexpectedConstructor(other)),
        }
    }

    fn on_req_pq(&mut self, r: &mut Reader) -> Result<Step, HandshakeError> {
        self.nonce = r.read_i128()?;
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut self.server_nonce);

        let (p, q) = gen_pq(&mut rng);
        self.p = p;
        self.q = q;
        self.pq = p as u64 * q as u64;

        let mut w = Writer::new();
        w.write_u32(RES_PQ);
        w.write_i128(&self.nonce);
        w.write_i128(&self.server_nonce);
        w.write_bytes(&self.pq.to_be_bytes());
        w.write_long_vector(&[self.rsa.fingerprint]);

        self.stage = Stage::AwaitReqDh;
        Ok(Step::Reply(w.into_vec()))
    }

    fn on_req_dh(&mut self, r: &mut Reader) -> Result<Step, HandshakeError> {
        let nonce = r.read_i128()?;
        let server_nonce = r.read_i128()?;
        if nonce != self.nonce || server_nonce != self.server_nonce {
            return Err(HandshakeError::NonceMismatch);
        }
        let _p = r.read_bytes()?;
        let _q = r.read_bytes()?;
        let fingerprint = r.read_i64()?;
        if fingerprint != self.rsa.fingerprint {
            return Err(HandshakeError::UnknownFingerprint(fingerprint));
        }
        let enc = r.read_bytes()?;
        let enc: [u8; 256] = enc
            .try_into()
            .map_err(|_| HandshakeError::DhRange)?;

        let data = self.rsa.decrypt_pq_inner(&enc)?;
        self.parse_pq_inner(&data)?;

        // Generate the server DH secret and public value.
        let mut rng = rand::thread_rng();
        let mut a_bytes = [0u8; 256];
        rng.fill_bytes(&mut a_bytes);
        self.a = BigUint::from_bytes_be(&a_bytes) % (&self.dh.prime - 1u32);
        let g_a = self.dh.pow(&self.a);
        self.dh.check_public(&g_a).map_err(|_| HandshakeError::DhRange)?;

        // server_DH_inner_data.
        let mut inner = Writer::new();
        inner.write_u32(SERVER_DH_INNER_DATA);
        inner.write_i128(&self.nonce);
        inner.write_i128(&self.server_nonce);
        inner.write_i32(self.dh.g as i32);
        inner.write_bytes(&self.dh.prime_be());
        inner.write_bytes(&dh::to_be_256(&g_a));
        inner.write_i32(now_unix() as i32);
        let inner = inner.into_vec();

        // answer = SHA1(inner) || inner || random padding (to a 16-byte boundary).
        let mut answer = Vec::with_capacity(20 + inner.len() + 16);
        answer.extend_from_slice(&sha1(&inner));
        answer.extend_from_slice(&inner);
        let pad = (16 - answer.len() % 16) % 16;
        let mut padding = vec![0u8; pad];
        rng.fill_bytes(&mut padding);
        answer.extend_from_slice(&padding);

        (self.tmp_key, self.tmp_iv) = tmp_aes(&self.new_nonce, &self.server_nonce);
        ige::encrypt(&self.tmp_key, &self.tmp_iv, &mut answer)?;

        let mut w = Writer::new();
        w.write_u32(SERVER_DH_PARAMS_OK);
        w.write_i128(&self.nonce);
        w.write_i128(&self.server_nonce);
        w.write_bytes(&answer);

        self.stage = Stage::AwaitSetClientDh;
        Ok(Step::Reply(w.into_vec()))
    }

    fn parse_pq_inner(&mut self, data: &[u8]) -> Result<(), HandshakeError> {
        let mut r = Reader::new(data);
        let id = r.read_u32()?;
        if id != P_Q_INNER_DATA && id != P_Q_INNER_DATA_DC {
            return Err(HandshakeError::UnexpectedConstructor(id));
        }
        let pq = be_bytes_to_u64(r.read_bytes()?);
        let _p = r.read_bytes()?;
        let _q = r.read_bytes()?;
        let nonce = r.read_i128()?;
        let server_nonce = r.read_i128()?;
        let new_nonce = r.read_i256()?;
        if nonce != self.nonce || server_nonce != self.server_nonce {
            return Err(HandshakeError::NonceMismatch);
        }
        if pq != self.pq {
            return Err(HandshakeError::PqMismatch(pq));
        }
        self.new_nonce = new_nonce;
        Ok(())
    }

    fn on_set_client_dh(&mut self, r: &mut Reader) -> Result<Step, HandshakeError> {
        let nonce = r.read_i128()?;
        let server_nonce = r.read_i128()?;
        if nonce != self.nonce || server_nonce != self.server_nonce {
            return Err(HandshakeError::NonceMismatch);
        }
        let enc = r.read_bytes()?;
        let mut buf = enc.to_vec();
        ige::decrypt(&self.tmp_key, &self.tmp_iv, &mut buf)?;

        // buf = SHA1(client_DH_inner_data) || client_DH_inner_data || padding
        let embedded_sha: [u8; 20] = buf[0..20].try_into().unwrap();
        let mut cr = Reader::new(&buf[20..]);
        let id = cr.read_u32()?;
        if id != CLIENT_DH_INNER_DATA {
            return Err(HandshakeError::UnexpectedConstructor(id));
        }
        let c_nonce = cr.read_i128()?;
        let c_server_nonce = cr.read_i128()?;
        let _retry_id = cr.read_i64()?;
        let g_b = cr.read_bytes()?.to_vec();
        if c_nonce != self.nonce || c_server_nonce != self.server_nonce {
            return Err(HandshakeError::NonceMismatch);
        }
        let obj_len = cr.position();
        if sha1(&buf[20..20 + obj_len]) != embedded_sha {
            return Err(HandshakeError::IntegrityCheck);
        }

        let g_b_num = BigUint::from_bytes_be(&g_b);
        self.dh
            .check_public(&g_b_num)
            .map_err(|_| HandshakeError::DhRange)?;

        let auth_key_num = self.dh.pow_base(&g_b_num, &self.a);
        let auth_key = dh::to_be_256(&auth_key_num);
        let auth_key_id = kdf::auth_key_id(&auth_key);

        // server_salt = new_nonce[0..8] XOR server_nonce[0..8]
        let mut salt = [0u8; 8];
        for (i, s) in salt.iter_mut().enumerate() {
            *s = self.new_nonce[i] ^ self.server_nonce[i];
        }
        let server_salt = i64::from_le_bytes(salt);

        // new_nonce_hash1 = SHA1(new_nonce || 0x01 || SHA1(auth_key)[0..8])[4..20]
        let aux = &sha1(&auth_key)[0..8];
        let nn_hash = sha1_parts(&[&self.new_nonce, &[1u8], aux]);
        let mut new_nonce_hash1 = [0u8; 16];
        new_nonce_hash1.copy_from_slice(&nn_hash[4..20]);

        let mut w = Writer::new();
        w.write_u32(DH_GEN_OK);
        w.write_i128(&self.nonce);
        w.write_i128(&self.server_nonce);
        w.write_i128(&new_nonce_hash1);

        self.stage = Stage::Finished;
        Ok(Step::Done {
            reply: w.into_vec(),
            auth_key: Box::new(auth_key),
            auth_key_id,
            server_salt,
        })
    }
}

/// Derive the temporary AES key/iv for the `server_DH_params` step:
/// ```text
/// key = SHA1(new_nonce + server_nonce) + SHA1(server_nonce + new_nonce)[0..12]
/// iv  = SHA1(server_nonce + new_nonce)[12..20] + SHA1(new_nonce + new_nonce) + new_nonce[0..4]
/// ```
pub fn tmp_aes(new_nonce: &[u8; 32], server_nonce: &[u8; 16]) -> ([u8; 32], [u8; 32]) {
    let ns = sha1_parts(&[new_nonce, server_nonce]);
    let sn = sha1_parts(&[server_nonce, new_nonce]);
    let nn = sha1_parts(&[new_nonce, new_nonce]);

    let mut key = [0u8; 32];
    key[0..20].copy_from_slice(&ns);
    key[20..32].copy_from_slice(&sn[0..12]);

    let mut iv = [0u8; 32];
    iv[0..8].copy_from_slice(&sn[12..20]);
    iv[8..28].copy_from_slice(&nn);
    iv[28..32].copy_from_slice(&new_nonce[0..4]);

    (key, iv)
}

fn gen_pq(rng: &mut impl RngCore) -> (u32, u32) {
    let p = gen_prime31(rng);
    let mut q = gen_prime31(rng);
    while q == p {
        q = gen_prime31(rng);
    }
    if p < q {
        (p, q)
    } else {
        (q, p)
    }
}

fn gen_prime31(rng: &mut impl RngCore) -> u32 {
    loop {
        // 31-bit odd candidate so p*q < 2^63.
        let c = (rng.next_u32() | 0x4000_0001) & 0x7fff_ffff;
        if probably_prime(&BigUint::from(c), 20) {
            return c;
        }
    }
}

fn be_bytes_to_u64(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for &byte in b {
        v = (v << 8) | byte as u64;
    }
    v
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal in-process client that performs the full handshake against the
    /// server state machine, so we can assert both derive the same auth_key.
    struct TestClient {
        nonce: [u8; 16],
        server_nonce: [u8; 16],
        new_nonce: [u8; 32],
        dh: Option<DhParams>,
        b: BigUint,
        tmp_key: [u8; 32],
        tmp_iv: [u8; 32],
    }

    impl TestClient {
        fn new() -> Self {
            let mut rng = rand::thread_rng();
            let mut nonce = [0u8; 16];
            let mut new_nonce = [0u8; 32];
            rng.fill_bytes(&mut nonce);
            rng.fill_bytes(&mut new_nonce);
            TestClient {
                nonce,
                server_nonce: [0; 16],
                new_nonce,
                dh: None,
                b: BigUint::from(0u32),
                tmp_key: [0; 32],
                tmp_iv: [0; 32],
            }
        }

        fn req_pq(&self) -> Vec<u8> {
            let mut w = Writer::new();
            w.write_u32(REQ_PQ_MULTI);
            w.write_i128(&self.nonce);
            w.into_vec()
        }

        fn on_res_pq(&mut self, body: &[u8], rsa: &ServerRsaKey) -> Vec<u8> {
            let mut r = Reader::new(body);
            assert_eq!(r.read_u32().unwrap(), RES_PQ);
            let _nonce = r.read_i128().unwrap();
            self.server_nonce = r.read_i128().unwrap();
            let pq = be_bytes_to_u64(r.read_bytes().unwrap());
            let fps = r.read_long_vector().unwrap();
            assert_eq!(fps[0], rsa.fingerprint);

            let (p, q) = mtproto_crypto::factorize::factorize(pq).unwrap();

            // p_q_inner_data_dc
            let mut inner = Writer::new();
            inner.write_u32(P_Q_INNER_DATA_DC);
            inner.write_bytes(&pq.to_be_bytes());
            inner.write_bytes(&p.to_be_bytes());
            inner.write_bytes(&q.to_be_bytes());
            inner.write_i128(&self.nonce);
            inner.write_i128(&self.server_nonce);
            inner.write_i256(&self.new_nonce);
            inner.write_i32(0); // dc
            let data = inner.into_vec();

            let enc = rsa.seal_pq_inner(&data);

            let mut w = Writer::new();
            w.write_u32(REQ_DH_PARAMS);
            w.write_i128(&self.nonce);
            w.write_i128(&self.server_nonce);
            w.write_bytes(&p.to_be_bytes());
            w.write_bytes(&q.to_be_bytes());
            w.write_i64(rsa.fingerprint);
            w.write_bytes(&enc);
            w.into_vec()
        }

        fn on_server_dh(&mut self, body: &[u8]) -> Vec<u8> {
            let mut r = Reader::new(body);
            assert_eq!(r.read_u32().unwrap(), SERVER_DH_PARAMS_OK);
            let _nonce = r.read_i128().unwrap();
            let _server_nonce = r.read_i128().unwrap();
            let enc = r.read_bytes().unwrap().to_vec();

            (self.tmp_key, self.tmp_iv) = tmp_aes(&self.new_nonce, &self.server_nonce);
            let mut answer = enc;
            ige::decrypt(&self.tmp_key, &self.tmp_iv, &mut answer).unwrap();

            let mut ar = Reader::new(&answer[20..]);
            assert_eq!(ar.read_u32().unwrap(), SERVER_DH_INNER_DATA);
            let _n = ar.read_i128().unwrap();
            let _sn = ar.read_i128().unwrap();
            let g = ar.read_i32().unwrap() as u32;
            let dh_prime = ar.read_bytes().unwrap();
            let g_a = BigUint::from_bytes_be(ar.read_bytes().unwrap());
            let _server_time = ar.read_i32().unwrap();

            let prime_be: [u8; 256] = dh_prime.try_into().unwrap();
            let dh = DhParams::from_be_bytes(&prime_be, g);
            // A real client validates the safe prime here.
            dh.validate().expect("server prime must validate");

            let mut rng = rand::thread_rng();
            let mut b_bytes = [0u8; 256];
            rng.fill_bytes(&mut b_bytes);
            self.b = BigUint::from_bytes_be(&b_bytes) % (&dh.prime - 1u32);
            let g_b = dh.pow(&self.b);
            let _ = g_a; // client would also compute the shared key from g_a below

            // client_DH_inner_data
            let mut inner = Writer::new();
            inner.write_u32(CLIENT_DH_INNER_DATA);
            inner.write_i128(&self.nonce);
            inner.write_i128(&self.server_nonce);
            inner.write_i64(0); // retry_id
            inner.write_bytes(&dh::to_be_256(&g_b));
            let inner = inner.into_vec();

            let mut data = Vec::new();
            data.extend_from_slice(&sha1(&inner));
            data.extend_from_slice(&inner);
            let pad = (16 - data.len() % 16) % 16;
            let newlen = data.len() + pad;
            data.resize(newlen, 0);
            ige::encrypt(&self.tmp_key, &self.tmp_iv, &mut data).unwrap();

            self.dh = Some(dh);

            let mut w = Writer::new();
            w.write_u32(SET_CLIENT_DH_PARAMS);
            w.write_i128(&self.nonce);
            w.write_i128(&self.server_nonce);
            w.write_bytes(&data);
            w.into_vec()
        }

        fn auth_key(&self, server_g_a: &BigUint) -> [u8; 256] {
            let dh = self.dh.as_ref().unwrap();
            dh::to_be_256(&dh.pow_base(server_g_a, &self.b))
        }
    }

    #[test]
    fn full_handshake_derives_matching_auth_key() {
        let rsa = ServerRsaKey::generate();
        let rsa_for_client = rsa.clone();
        let dh = dh::server_default();
        let mut server = HandshakeServer::new(rsa, dh);

        let mut client = TestClient::new();

        // Step 1.
        let m1 = client.req_pq();
        let r1 = match server.handle(&m1).unwrap() {
            Step::Reply(b) => b,
            _ => panic!("expected reply"),
        };
        // Step 2.
        let m2 = client.on_res_pq(&r1, &rsa_for_client);
        let r2 = match server.handle(&m2).unwrap() {
            Step::Reply(b) => b,
            _ => panic!("expected reply"),
        };
        // Step 3.
        let m3 = client.on_server_dh(&r2);
        let (reply, server_auth_key) = match server.handle(&m3).unwrap() {
            Step::Done {
                reply, auth_key, ..
            } => (reply, *auth_key),
            _ => panic!("expected done"),
        };

        // dh_gen_ok
        let mut rr = Reader::new(&reply);
        assert_eq!(rr.read_u32().unwrap(), DH_GEN_OK);

        // Client derives the shared key from the server's g_a.
        let server_g_a = server.dh.pow(&server.a);
        let client_auth_key = client.auth_key(&server_g_a);

        assert_eq!(
            client_auth_key, server_auth_key,
            "client and server must derive the same auth_key"
        );
    }
}

//! Phase 2 Acceptance Suite (`transport_and_dh_suite`):
//! Verifies all 6 MTProto transport modes (Abridged, Intermediate,
//! PaddedIntermediate, Full TCP CRC32, Obfuscated2, Fake-TLS 1.3 + Obfuscated2),
//! WebSocket MTProto binary transport, and real-time `SessionHub` server push.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use ctr::cipher::{KeyIvInit, StreamCipher};
use gram_core::{Dispatcher, KeyStore, SessionHub, Store};
use gram_edge::async_edge::{
    spawn_test_tcp_edge, spawn_test_ws_edge, EdgeConfig, WsByteStream,
};
use mtproto_crypto::dh;
use mtproto_crypto::faketls::{
    wrap_tls_application_data, FakeTlsSecret, TLS_APPLICATION_DATA, TLS_CHANGE_CIPHER_SPEC,
};
use mtproto_crypto::kdf::{self, Direction};
use mtproto_crypto::rsa_key::ServerRsaKey;
use mtproto_crypto::sha256_parts;
use rand::RngCore;
use tl_core::{Reader, Writer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

type Aes256Ctr = ctr::Ctr128BE<aes::Aes256>;

const REQ_PQ_MULTI: u32 = 0xbe7e_8ef1;
const RES_PQ: u32 = 0x0516_2463;
const PING: u32 = 0x7abe_77ec;
const PONG: u32 = 0x3477_73c5;
const GET_FUTURE_SALTS: u32 = 0xb921_bd04;
const FUTURE_SALTS: u32 = 0xae50_0895;

fn make_req_pq_bare(nonce: [u8; 16]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(REQ_PQ_MULTI);
    w.write_i128(&nonce);
    let body = w.into_vec();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let msg_id = now << 32;
    let mut bare = Vec::new();
    bare.extend_from_slice(&0i64.to_le_bytes());
    bare.extend_from_slice(&msg_id.to_le_bytes());
    bare.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bare.extend_from_slice(&body);
    bare
}

fn assert_respq_nonce(bare_reply: &[u8], expected_nonce: &[u8; 16]) {
    assert!(bare_reply.len() >= 20);
    assert_eq!(i64::from_le_bytes(bare_reply[0..8].try_into().unwrap()), 0);
    let len = u32::from_le_bytes(bare_reply[16..20].try_into().unwrap()) as usize;
    let mut r = Reader::new(&bare_reply[20..20 + len]);
    assert_eq!(r.read_u32().unwrap(), RES_PQ);
    assert_eq!(&r.read_i128().unwrap(), expected_nonce);
}

fn client_encrypt(key: &[u8; 256], salt: i64, session_id: i64, msg_id: i64, body: &[u8]) -> Vec<u8> {
    let mut pt = Vec::new();
    pt.extend_from_slice(&salt.to_le_bytes());
    pt.extend_from_slice(&session_id.to_le_bytes());
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
    let (msg_key, ct) = kdf::encrypt_message(key, &pt, Direction::ClientToServer).unwrap();
    let mut out = Vec::new();
    out.extend_from_slice(&kdf::auth_key_id(key).to_le_bytes());
    out.extend_from_slice(&msg_key);
    out.extend_from_slice(&ct);
    out
}

fn client_decrypt(key: &[u8; 256], payload: &[u8]) -> Vec<u8> {
    let msg_key: [u8; 16] = payload[8..24].try_into().unwrap();
    let mut ct = payload[24..].to_vec();
    let pt = kdf::decrypt_message(key, &msg_key, &mut ct, Direction::ServerToClient).unwrap();
    let length = u32::from_le_bytes(pt[28..32].try_into().unwrap()) as usize;
    pt[32..32 + length].to_vec()
}

#[tokio::test]
async fn all_six_tcp_transports_ws_and_realtime_push_work() {
    let rsa = Arc::new(ServerRsaKey::generate());
    let dh = dh::server_default();
    let keys = Arc::new(KeyStore::load(None));
    let hub = Arc::new(SessionHub::new());
    let store = Arc::new(Store::with_test_code(Some("12345".into())));

    // Pre-provision a known encrypted auth_key + user for steady-state ping/salts/push tests
    let mut auth_key = [0u8; 256];
    for (i, b) in auth_key.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(17).wrapping_add(3);
    }
    let auth_key_id = kdf::auth_key_id(&auth_key);
    let salt = 0x1122_3344_5566_7788i64;
    keys.insert(auth_key_id, auth_key, salt);
    let alice = store.sign_up("88888888888", "h1", "Alice", "").unwrap();
    store.bind_key_user(auth_key_id, alice.id);

    let fake_tls = FakeTlsSecret {
        raw_secret: *b"shuzagram_secret",
        sni_domain: Some("cdn.shuzagram.com".into()),
        allow_fake_tls: true,
    };

    let dispatcher = Arc::new(
        Dispatcher::new(Arc::clone(&store))
            .with_keys(Arc::clone(&keys))
            .with_hub(Arc::clone(&hub)),
    );

    let cfg = EdgeConfig {
        rsa,
        dh,
        dispatcher,
        keys,
        fake_tls: Some(fake_tls.clone()),
        enforce_clock_window: false,
    };

    let tcp_addr = spawn_test_tcp_edge(cfg.clone()).await.unwrap();
    let ws_addr = spawn_test_ws_edge(cfg).await.unwrap();

    // 1. Transport #1: Plaintext Abridged (0xef)
    {
        let mut s = TcpStream::connect(tcp_addr).await.unwrap();
        s.write_all(&[0xef]).await.unwrap();
        let bare = make_req_pq_bare([1u8; 16]);
        let mut frame = vec![(bare.len() / 4) as u8];
        frame.extend_from_slice(&bare);
        s.write_all(&frame).await.unwrap();
        let mut len_b = [0u8; 1];
        s.read_exact(&mut len_b).await.unwrap();
        let mut reply = vec![0u8; (len_b[0] as usize) * 4];
        s.read_exact(&mut reply).await.unwrap();
        assert_respq_nonce(&reply, &[1u8; 16]);
    }

    // 2. Transport #2: Plaintext Intermediate (0xeeeeeeee)
    {
        let mut s = TcpStream::connect(tcp_addr).await.unwrap();
        s.write_all(&0xeeee_eeeeu32.to_le_bytes()).await.unwrap();
        let bare = make_req_pq_bare([2u8; 16]);
        s.write_all(&(bare.len() as u32).to_le_bytes()).await.unwrap();
        s.write_all(&bare).await.unwrap();
        let mut len_b = [0u8; 4];
        s.read_exact(&mut len_b).await.unwrap();
        let mut reply = vec![0u8; u32::from_le_bytes(len_b) as usize];
        s.read_exact(&mut reply).await.unwrap();
        assert_respq_nonce(&reply, &[2u8; 16]);
    }

    // 3. Transport #3: Padded Intermediate (0xdddddddd) + Encrypted Ping & FutureSalts + Real-time Push!
    {
        let mut s = TcpStream::connect(tcp_addr).await.unwrap();
        s.write_all(&0xdddd_ddddu32.to_le_bytes()).await.unwrap();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
        let msg_id_1 = now << 32;
        let mut pw = Writer::new();
        pw.write_u32(PING);
        pw.write_i64(0xCAFE_BABE);
        let enc_ping = client_encrypt(&auth_key, salt, 0x9999, msg_id_1, &pw.into_vec());
        s.write_all(&(enc_ping.len() as u32).to_le_bytes()).await.unwrap();
        s.write_all(&enc_ping).await.unwrap();

        let mut len_b = [0u8; 4];
        s.read_exact(&mut len_b).await.unwrap();
        let mut reply = vec![0u8; u32::from_le_bytes(len_b) as usize];
        s.read_exact(&mut reply).await.unwrap();
        let dec = client_decrypt(&auth_key, &reply);
        let mut r = Reader::new(&dec);
        assert_eq!(r.read_u32().unwrap(), PONG);
        assert_eq!(r.read_i64().unwrap(), msg_id_1);
        assert_eq!(r.read_i64().unwrap(), 0xCAFE_BABE);

        // get_future_salts
        let msg_id_2 = msg_id_1 + 4;
        let mut sw = Writer::new();
        sw.write_u32(GET_FUTURE_SALTS);
        sw.write_i32(4);
        let enc_salts = client_encrypt(&auth_key, salt, 0x9999, msg_id_2, &sw.into_vec());
        s.write_all(&(enc_salts.len() as u32).to_le_bytes()).await.unwrap();
        s.write_all(&enc_salts).await.unwrap();

        s.read_exact(&mut len_b).await.unwrap();
        let mut s_reply = vec![0u8; u32::from_le_bytes(len_b) as usize];
        s.read_exact(&mut s_reply).await.unwrap();
        let dec_salts = client_decrypt(&auth_key, &s_reply);
        let mut sr = Reader::new(&dec_salts);
        assert_eq!(sr.read_u32().unwrap(), FUTURE_SALTS);
        assert_eq!(sr.read_i64().unwrap(), msg_id_2);

        // Register push session (`0x637ea878` tgnet registerDevice) so hub binds Alice's user_id!
        let msg_id_3 = msg_id_1 + 8;
        let mut rw = Writer::new();
        rw.write_u32(0x637e_a878);
        rw.write_i32(7);
        rw.write_string("9999");
        let enc_reg = client_encrypt(&auth_key, salt, 0x9999, msg_id_3, &rw.into_vec());
        s.write_all(&(enc_reg.len() as u32).to_le_bytes()).await.unwrap();
        s.write_all(&enc_reg).await.unwrap();
        s.read_exact(&mut len_b).await.unwrap();
        let mut reg_reply = vec![0u8; u32::from_le_bytes(len_b) as usize];
        s.read_exact(&mut reg_reply).await.unwrap();

        // Push a real-time Updates frame from SessionHub without client polling!
        let mut push_w = Writer::new();
        push_w.write_u32(0xe317_af7e); // updatesTooLong
        let pushed_count = hub.push_to_user(alice.id, None, push_w.into_vec());
        assert_eq!(pushed_count, 1);

        s.read_exact(&mut len_b).await.unwrap();
        let mut pushed_enc = vec![0u8; u32::from_le_bytes(len_b) as usize];
        s.read_exact(&mut pushed_enc).await.unwrap();
        let pushed_dec = client_decrypt(&auth_key, &pushed_enc);
        assert_eq!(
            u32::from_le_bytes(pushed_dec[0..4].try_into().unwrap()),
            0xe317_af7e
        );
    }

    // 4. Transport #4: Full TCP (seq_no + CRC32)
    {
        let mut s = TcpStream::connect(tcp_addr).await.unwrap();
        let bare = make_req_pq_bare([4u8; 16]);
        let total_len = (12 + bare.len()) as u32;
        let len_b = total_len.to_le_bytes();
        let seq_b = 0u32.to_le_bytes();
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&len_b);
        hasher.update(&seq_b);
        hasher.update(&bare);
        let crc_b = hasher.finalize().to_le_bytes();

        s.write_all(&len_b).await.unwrap();
        s.write_all(&seq_b).await.unwrap();
        s.write_all(&bare).await.unwrap();
        s.write_all(&crc_b).await.unwrap();

        let mut hdr = [0u8; 8];
        s.read_exact(&mut hdr).await.unwrap();
        let rlen = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as usize;
        let mut body = vec![0u8; rlen - 12];
        s.read_exact(&mut body).await.unwrap();
        let mut rcrc = [0u8; 4];
        s.read_exact(&mut rcrc).await.unwrap();
        assert_respq_nonce(&body, &[4u8; 16]);
    }

    // 5. Transport #5 + #6: Fake-TLS 1.3 (`ee...` secret) + Keyed Obfuscated2 + PaddedIntermediate
    {
        let mut s = TcpStream::connect(tcp_addr).await.unwrap();
        let now_u32 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as u32;
        let (ch, client_random) = {
            let mut rng = rand::thread_rng();
            fake_tls.build_client_hello(now_u32, &mut rng)
        };
        s.write_all(&ch).await.unwrap();

        // Read ServerHello + ChangeCipherSpec + AppData flight
        let mut sh_hdr = [0u8; 5];
        s.read_exact(&mut sh_hdr).await.unwrap();
        let sh_len = u16::from_be_bytes([sh_hdr[3], sh_hdr[4]]) as usize;
        let mut sh_body = vec![0u8; sh_len];
        s.read_exact(&mut sh_body).await.unwrap();

        let mut ccs = [0u8; 6];
        s.read_exact(&mut ccs).await.unwrap();
        assert_eq!(ccs[0], TLS_CHANGE_CIPHER_SPEC);

        let mut ad_hdr = [0u8; 5];
        s.read_exact(&mut ad_hdr).await.unwrap();
        assert_eq!(ad_hdr[0], TLS_APPLICATION_DATA);
        let ad_len = u16::from_be_bytes([ad_hdr[3], ad_hdr[4]]) as usize;
        let mut ad_body = vec![0u8; ad_len];
        s.read_exact(&mut ad_body).await.unwrap();

        let mut full_flight = Vec::new();
        full_flight.extend_from_slice(&sh_hdr);
        full_flight.extend_from_slice(&sh_body);
        full_flight.extend_from_slice(&ccs);
        full_flight.extend_from_slice(&ad_hdr);
        full_flight.extend_from_slice(&ad_body);
        fake_tls
            .verify_server_hello_flight(&client_random, &full_flight)
            .unwrap();

        // Build keyed Obfuscated2 64-byte header inside TLS ApplicationData
        let (mut obf_hdr, mut obf_enc, mut obf_dec) = {
            let mut rng = rand::thread_rng();
            let mut h = [0u8; 64];
            loop {
                rng.fill_bytes(&mut h);
                let f4 = u32::from_le_bytes(h[0..4].try_into().unwrap());
                let s4 = u32::from_le_bytes(h[4..8].try_into().unwrap());
                if h[0] != 0xef
                    && f4 != 0xeeee_eeee
                    && f4 != 0xdddd_dddd
                    && s4 != 0
                    && h[0] != 0x16
                {
                    break;
                }
            }
            h[56..60].copy_from_slice(&0xdddd_ddddu32.to_le_bytes());

            let raw_enc: [u8; 32] = h[8..40].try_into().unwrap();
            let enc_iv: [u8; 16] = h[40..56].try_into().unwrap();
            let mut rev = [0u8; 48];
            for i in 0..48 {
                rev[i] = h[55 - i];
            }
            let raw_dec: [u8; 32] = rev[0..32].try_into().unwrap();
            let dec_iv: [u8; 16] = rev[32..48].try_into().unwrap();

            let keyed_enc = sha256_parts(&[&raw_enc, &fake_tls.raw_secret]);
            let keyed_dec = sha256_parts(&[&raw_dec, &fake_tls.raw_secret]);

            let mut enc = Aes256Ctr::new(&keyed_enc.into(), &enc_iv.into());
            let dec = Aes256Ctr::new(&keyed_dec.into(), &dec_iv.into());

            let mut enc_copy = h;
            enc.apply_keystream(&mut enc_copy);
            h[56..64].copy_from_slice(&enc_copy[56..64]);
            (h, enc, dec)
        };

        let bare = make_req_pq_bare([6u8; 16]);
        let mut inner_wire = Vec::new();
        inner_wire.extend_from_slice(&(bare.len() as u32).to_le_bytes());
        inner_wire.extend_from_slice(&bare);
        obf_enc.apply_keystream(&mut inner_wire);

        let mut combined = Vec::new();
        combined.extend_from_slice(&obf_hdr);
        combined.extend_from_slice(&inner_wire);
        let _ = &mut obf_hdr;

        let mut tls_out = Vec::new();
        // Also prepend client ChangeCipherSpec to verify transparent skipping!
        tls_out.extend_from_slice(&[TLS_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01]);
        wrap_tls_application_data(&combined, &mut tls_out);
        s.write_all(&tls_out).await.unwrap();

        let mut r_hdr = [0u8; 5];
        s.read_exact(&mut r_hdr).await.unwrap();
        assert_eq!(r_hdr[0], TLS_APPLICATION_DATA);
        let r_len = u16::from_be_bytes([r_hdr[3], r_hdr[4]]) as usize;
        let mut r_cipher = vec![0u8; r_len];
        s.read_exact(&mut r_cipher).await.unwrap();
        obf_dec.apply_keystream(&mut r_cipher);
        let frame_len = u32::from_le_bytes(r_cipher[0..4].try_into().unwrap()) as usize;
        assert_respq_nonce(&r_cipher[4..4 + frame_len], &[6u8; 16]);
    }

    // 6. WebSocket MTProto (`Sec-WebSocket-Protocol: binary`)
    {
        let mut req = format!("ws://{ws_addr}/apiws").into_client_request().unwrap();
        req.headers_mut()
            .insert("Sec-WebSocket-Protocol", "binary".parse().unwrap());
        let (ws_stream, resp) = tokio_tungstenite::connect_async(req).await.unwrap();
        assert_eq!(
            resp.headers()
                .get("Sec-WebSocket-Protocol")
                .and_then(|v| v.to_str().ok()),
            Some("binary")
        );
        let mut ws_io = WsByteStream::new(ws_stream);
        ws_io.write_all(&0xeeee_eeeeu32.to_le_bytes()).await.unwrap();
        let bare = make_req_pq_bare([7u8; 16]);
        ws_io.write_all(&(bare.len() as u32).to_le_bytes()).await.unwrap();
        ws_io.write_all(&bare).await.unwrap();
        ws_io.flush().await.unwrap();

        let mut len_b = [0u8; 4];
        ws_io.read_exact(&mut len_b).await.unwrap();
        let mut reply = vec![0u8; u32::from_le_bytes(len_b) as usize];
        ws_io.read_exact(&mut reply).await.unwrap();
        assert_respq_nonce(&reply, &[7u8; 16]);
    }
}

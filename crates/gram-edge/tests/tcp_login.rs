//! Full login over a real TCP socket: DH handshake, then encrypted
//! `auth.sendCode` and `auth.signIn`, ending in an `auth.authorization`.

use std::sync::Arc;

use gram_core::{Dispatcher, Store};
use gram_edge::{client::Client, transport};
use mtproto_crypto::{dh, rsa_key::ServerRsaKey};
use tl_core::{Reader, Writer};

const AUTH_SEND_CODE: u32 = 0xa677_244f;
const AUTH_SIGN_IN: u32 = 0x8d52_a951;
const AUTH_SENT_CODE: u32 = 0x5e00_2502;
const AUTH_AUTHORIZATION: u32 = 0x2ea2_c0d4;
const USER: u32 = 0xb1b8_cc83;
const HELP_GET_CONFIG: u32 = 0xc4f9_186b;
const CONFIG: u32 = 0xcc1a_241e;
const RPC_RESULT: u32 = 0xf35c_6d01;
const INVOKE_WITH_LAYER: u32 = 0xda9b_0d0d;
const INIT_CONNECTION: u32 = 0xc1cd_5ea9;

fn wrap(query: &[u8]) -> Vec<u8> {
    let mut inner = Writer::new();
    inner.write_u32(INIT_CONNECTION);
    inner.write_i32(0);
    inner.write_i32(12345);
    for s in ["Pixel", "Android 14", "1.0", "en", "", "en"] {
        inner.write_string(s);
    }
    inner.write_raw(query);
    let mut w = Writer::new();
    w.write_u32(INVOKE_WITH_LAYER);
    w.write_i32(232);
    w.write_raw(&inner.into_vec());
    w.into_vec()
}

fn unwrap_result(bytes: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(bytes);
    assert_eq!(r.read_u32().unwrap(), RPC_RESULT);
    let _req = r.read_i64().unwrap();
    r.read_raw(r.remaining()).unwrap().to_vec()
}

#[test]
fn full_login_over_tcp() {
    // Shared RSA key: the server uses it, the client trusts it (as a real
    // client embeds the server's public key).
    let rsa = ServerRsaKey::generate();
    let rsa_server = rsa.clone();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let dh = dh::server_default();
        let dispatcher = Arc::new(Dispatcher::new(Arc::new(Store::new())));
        let keys = Arc::new(gram_edge::keystore::KeyStore::load(None));
        let _ = transport::serve_connection(sock, &rsa_server, &dh, &dispatcher, &keys);
    });

    let mut client = Client::connect_and_handshake(addr, &rsa).expect("handshake");

    // help.getConfig (what the client calls first) — must parse as a config.
    let mut gc = Writer::new();
    gc.write_u32(HELP_GET_CONFIG);
    let (_id, reply) = client.invoke(&wrap(&gc.into_vec())).unwrap();
    let result = unwrap_result(&reply);
    assert_eq!(
        Reader::new(&result).read_u32().unwrap(),
        CONFIG,
        "expected config"
    );

    // auth.sendCode
    let mut sc = Writer::new();
    sc.write_u32(AUTH_SEND_CODE);
    sc.write_string("+99900099999");
    sc.write_i32(12345);
    sc.write_string("apihash");
    let (_id, reply) = client.invoke(&wrap(&sc.into_vec())).unwrap();
    let result = unwrap_result(&reply);

    let mut r = Reader::new(&result);
    assert_eq!(r.read_u32().unwrap(), AUTH_SENT_CODE, "expected auth.sentCode");
    let _flags = r.read_i32().unwrap();
    let _type_id = r.read_u32().unwrap();
    let _len = r.read_i32().unwrap();
    let phone_code_hash = r.read_string().unwrap().to_string();
    assert!(!phone_code_hash.is_empty());

    // auth.signIn with the fixed test code
    let mut si = Writer::new();
    si.write_u32(AUTH_SIGN_IN);
    si.write_i32(1); // flags: phone_code present
    si.write_string("+99900099999");
    si.write_string(&phone_code_hash);
    si.write_string("22222");
    let (_id, reply) = client.invoke(&wrap(&si.into_vec())).unwrap();
    let result = unwrap_result(&reply);

    let mut r = Reader::new(&result);
    assert_eq!(
        r.read_u32().unwrap(),
        AUTH_AUTHORIZATION,
        "expected auth.authorization (logged in)"
    );
    // Parse the embedded TL_user as the client would (flags 0,1,4).
    let _auth_flags = r.read_i32().unwrap();
    assert_eq!(r.read_u32().unwrap(), USER);
    let uflags = r.read_i32().unwrap();
    let _uflags2 = r.read_i32().unwrap();
    let id = r.read_i64().unwrap();
    assert!(uflags & (1 << 0) != 0);
    let _access_hash = r.read_i64().unwrap();
    let first_name = r.read_string().unwrap().to_string();
    let phone = r.read_string().unwrap().to_string();
    assert!(id >= 1000);
    assert_eq!(phone, "+99900099999");
    assert_eq!(first_name, "ShuzaGram");
}

#[test]
fn unknown_auth_key_returns_minus_404_on_padded_intermediate() {
    use std::io::{Read, Write};

    let rsa = ServerRsaKey::generate();
    let rsa_server = rsa.clone();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let dh = dh::server_default();
        let store = Arc::new(Store::new());
        let keys = Arc::new(gram_edge::keystore::KeyStore::load(None));
        let dispatcher = Arc::new(Dispatcher::new(store).with_keys(Arc::clone(&keys)));
        let _ = transport::serve_connection(sock, &rsa_server, &dh, &dispatcher, &keys);
    });

    let mut sock = std::net::TcpStream::connect(addr).unwrap();
    // PaddedIntermediate (0xdddddddd) transport header.
    sock.write_all(&0xdddd_ddddu32.to_le_bytes()).unwrap();
    // Send a 75-byte bogus encrypted packet (with 3 random padding bytes) for unknown key_id.
    let mut bogus = vec![0x11u8; 75];
    bogus[0..8].copy_from_slice(&0x2e9b_192a_1658_1256i64.to_le_bytes());
    sock.write_all(&(bogus.len() as u32).to_le_bytes()).unwrap();
    sock.write_all(&bogus).unwrap();
    sock.flush().unwrap();

    // Server must reply with a 4-byte frame containing -404 (0xfffffe6c) instead of EOF!
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).unwrap();
    assert_eq!(u32::from_le_bytes(len_buf), 4);
    let mut code_buf = [0u8; 4];
    sock.read_exact(&mut code_buf).unwrap();
    assert_eq!(i32::from_le_bytes(code_buf), -404);
}

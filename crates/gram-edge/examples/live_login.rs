//! Ad-hoc end-to-end check against a running server.
//! Usage: SHUZA_RSA_KEY=... SHUZA_TEST_CODE=... ADDR=ip:port cargo run --example live_login

use gram_edge::client::Client;
use mtproto_crypto::rsa_key::ServerRsaKey;
use tl_core::{Reader, Writer};

const AUTH_SEND_CODE: u32 = 0xa677_244f;
const AUTH_SIGN_IN: u32 = 0x8d52_a951;
const AUTH_AUTHORIZATION: u32 = 0x2ea2_c0d4;
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
    for s in ["Rust", "Linux", "1.0", "en", "", "en"] {
        inner.write_string(s);
    }
    inner.write_raw(query);
    let mut w = Writer::new();
    w.write_u32(INVOKE_WITH_LAYER);
    w.write_i32(232);
    w.write_raw(&inner.into_vec());
    w.into_vec()
}

fn result_of(bytes: &[u8]) -> Vec<u8> {
    let mut r = Reader::new(bytes);
    assert_eq!(r.read_u32().unwrap(), RPC_RESULT);
    let _ = r.read_i64().unwrap();
    r.read_raw(r.remaining()).unwrap().to_vec()
}

fn main() {
    let addr = std::env::var("ADDR").unwrap_or_else(|_| "149.56.212.222:8443".into());
    let key_path = std::env::var("SHUZA_RSA_KEY").expect("SHUZA_RSA_KEY");
    let code = std::env::var("SHUZA_TEST_CODE").expect("SHUZA_TEST_CODE");
    let phone = std::env::var("PHONE").unwrap_or_else(|_| "+15550001234".into());

    let rsa = ServerRsaKey::load_or_generate(&key_path).expect("load key");
    println!("connecting to {addr} (fp {:#018x})", rsa.fingerprint as u64);
    let mut c = Client::connect_and_handshake(&addr, &rsa).expect("handshake");
    println!("handshake OK");

    let mut gc = Writer::new();
    gc.write_u32(HELP_GET_CONFIG);
    let (_i, reply) = c.invoke(&wrap(&gc.into_vec())).unwrap();
    assert_eq!(Reader::new(&result_of(&reply)).read_u32().unwrap(), CONFIG);
    println!("help.getConfig OK");

    let mut sc = Writer::new();
    sc.write_u32(AUTH_SEND_CODE);
    sc.write_string(&phone);
    sc.write_i32(12345);
    sc.write_string("apihash");
    let (_i, reply) = c.invoke(&wrap(&sc.into_vec())).unwrap();
    let sent = result_of(&reply);
    let mut r = Reader::new(&sent);
    let _ = r.read_u32();
    let _ = r.read_i32();
    let _ = r.read_u32();
    let _ = r.read_i32();
    let hash = r.read_string().unwrap().to_string();
    println!("auth.sendCode OK (phone {phone})");

    let mut si = Writer::new();
    si.write_u32(AUTH_SIGN_IN);
    si.write_i32(1);
    si.write_string(&phone);
    si.write_string(&hash);
    si.write_string(&code);
    let (_i, reply) = c.invoke(&wrap(&si.into_vec())).unwrap();
    let res = result_of(&reply);
    let id = Reader::new(&res).read_u32().unwrap();
    if id == AUTH_AUTHORIZATION {
        println!("auth.signIn OK -> LOGGED IN as {phone}");
    } else {
        println!("auth.signIn returned {id:#010x} (not authorization)");
        std::process::exit(1);
    }
}

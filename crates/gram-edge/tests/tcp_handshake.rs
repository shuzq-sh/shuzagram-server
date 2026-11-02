//! Over-the-wire smoke test: a real TCP client speaks the Intermediate
//! transport and completes step 1 of the handshake (`req_pq_multi` → `resPQ`).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use std::sync::Arc;

use gram_core::{Dispatcher, Store};
use gram_edge::transport;
use mtproto_crypto::{dh, rsa_key::ServerRsaKey};

const REQ_PQ_MULTI: u32 = 0xbe7e_8ef1;
const RES_PQ: u32 = 0x0516_2463;

fn build_bare(body: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    o.extend_from_slice(&0i64.to_le_bytes()); // auth_key_id = 0
    o.extend_from_slice(&0i64.to_le_bytes()); // message_id (irrelevant for a bare request)
    o.extend_from_slice(&(body.len() as u32).to_le_bytes());
    o.extend_from_slice(body);
    o
}

#[test]
fn tcp_req_pq_returns_respq() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    std::thread::spawn(move || {
        let (sock, _) = listener.accept().unwrap();
        let rsa = ServerRsaKey::generate();
        let dh = dh::server_default();
        let dispatcher = Arc::new(Dispatcher::new(Arc::new(Store::new())));
        let keys = Arc::new(gram_edge::keystore::KeyStore::load(None));
        let _ = transport::serve_connection(sock, &rsa, &dh, &dispatcher, &keys);
    });

    let mut c = TcpStream::connect(addr).unwrap();
    // Intermediate transport tag.
    c.write_all(&[0xee, 0xee, 0xee, 0xee]).unwrap();

    // req_pq_multi { nonce }
    let nonce = [7u8; 16];
    let mut body = Vec::new();
    body.extend_from_slice(&REQ_PQ_MULTI.to_le_bytes());
    body.extend_from_slice(&nonce);
    let bare = build_bare(&body);
    c.write_all(&(bare.len() as u32).to_le_bytes()).unwrap();
    c.write_all(&bare).unwrap();

    // Read the response frame.
    let mut lenb = [0u8; 4];
    c.read_exact(&mut lenb).unwrap();
    let len = u32::from_le_bytes(lenb) as usize;
    let mut payload = vec![0u8; len];
    c.read_exact(&mut payload).unwrap();

    // Skip the 20-byte bare header; the body is resPQ.
    let respq = &payload[20..];
    let id = u32::from_le_bytes(respq[0..4].try_into().unwrap());
    assert_eq!(id, RES_PQ, "expected resPQ");
    assert_eq!(&respq[4..20], &nonce, "server must echo the client nonce");
}

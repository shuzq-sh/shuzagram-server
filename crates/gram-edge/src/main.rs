//! ShuzaGram edge gateway.

use std::net::TcpListener;
use std::sync::Arc;

use gram_core::dispatch::DcEndpoint;
use gram_core::{Dispatcher, Store};
use gram_edge::keystore::KeyStore;
use gram_edge::transport;
use mtproto_crypto::dh;
use mtproto_crypto::rsa_key::ServerRsaKey;

fn main() {
    let addr = std::env::var("EDGE_ADDR").unwrap_or_else(|_| "0.0.0.0:8443".to_string());

    // Persistent key if SHUZA_RSA_KEY points to a file; else an ephemeral key.
    let rsa = match std::env::var("SHUZA_RSA_KEY").ok().filter(|s| !s.is_empty()) {
        Some(path) => {
            eprintln!("[edge] loading server RSA-2048 key from {path}");
            match ServerRsaKey::load_or_generate(&path) {
                Ok(k) => Arc::new(k),
                Err(e) => {
                    eprintln!("[edge] cannot load/create key at {path}: {e}");
                    std::process::exit(1);
                }
            }
        }
        None => {
            eprintln!("[edge] generating an ephemeral server RSA-2048 key (set SHUZA_RSA_KEY to persist)");
            Arc::new(ServerRsaKey::generate())
        }
    };
    let dh = dh::server_default();

    // If asked, print the public key to embed in the client, then exit.
    if std::env::args().any(|a| a == "--print-pubkey") {
        println!("fingerprint (u64): {:#018x}", rsa.fingerprint as u64);
        println!("{}", rsa.public_key_pkcs1_pem());
        return;
    }

    // Test-server master code: read from the environment only, never hardcoded.
    // When set, any phone number registers with this code.
    let test_code = std::env::var("SHUZA_TEST_CODE").ok().filter(|s| !s.is_empty());
    let store = Arc::new(Store::with_test_code(test_code));
    if store.is_test_server() {
        eprintln!("[edge] TEST SERVER mode: any number registers with the configured test code");
    }
    // Address advertised to clients in help.getConfig. Defaults match the
    // listener; override with SHUZA_DC_IP / SHUZA_DC_PORT / SHUZA_DC_ID.
    let dc = DcEndpoint {
        dc_id: std::env::var("SHUZA_DC_ID").ok().and_then(|v| v.parse().ok()).unwrap_or(2),
        ip: std::env::var("SHUZA_DC_IP").unwrap_or_else(|_| "127.0.0.1".to_string()),
        port: std::env::var("SHUZA_DC_PORT").ok().and_then(|v| v.parse().ok()).unwrap_or(8443),
    };
    eprintln!("[edge] advertising dc{} at {}:{}", dc.dc_id, dc.ip, dc.port);
    let dispatcher = Arc::new(Dispatcher::new(store).with_dc(dc));
    // Persist established auth keys next to the RSA key (or SHUZA_AUTHKEYS), so
    // a client's cached key survives server restarts.
    let keys_path = std::env::var("SHUZA_AUTHKEYS").ok().or_else(|| {
        std::env::var("SHUZA_RSA_KEY").ok().map(|p| {
            let dir = std::path::Path::new(&p).parent().map(|d| d.to_path_buf()).unwrap_or_default();
            dir.join("authkeys.bin").to_string_lossy().into_owned()
        })
    });
    let keys = Arc::new(KeyStore::load(keys_path));
    eprintln!(
        "[edge] rsa fingerprint = {:#018x}  (configure the client with this key)",
        rsa.fingerprint
    );

    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[edge] cannot bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("[edge] listening on {addr}");

    for stream in listener.incoming() {
        match stream {
            Ok(sock) => {
                let rsa = Arc::clone(&rsa);
                let dh = dh.clone();
                let dispatcher = Arc::clone(&dispatcher);
                let keys = Arc::clone(&keys);
                std::thread::spawn(move || {
                    let peer = sock
                        .peer_addr()
                        .map(|a| a.to_string())
                        .unwrap_or_else(|_| "?".into());
                    match transport::serve_connection(sock, &rsa, &dh, &dispatcher, &keys) {
                        Ok(()) => eprintln!("[edge] {peer}: session closed"),
                        Err(e) => eprintln!("[edge] {peer}: {e}"),
                    }
                });
            }
            Err(e) => eprintln!("[edge] accept error: {e}"),
        }
    }
}

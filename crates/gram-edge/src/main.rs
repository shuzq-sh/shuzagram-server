//! ShuzaGram async edge gateway (`gram-edge`).

use std::sync::Arc;

use gram_core::dispatch::DcEndpoint;
use gram_core::{Dispatcher, SessionHub, Store};
use gram_edge::async_edge::{serve_tcp_listener, serve_ws_listener, EdgeConfig};
use gram_edge::keystore::KeyStore;
use mtproto_crypto::dh;
use mtproto_crypto::faketls::FakeTlsSecret;
use mtproto_crypto::rsa_key::ServerRsaKey;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() {
    let addr = std::env::var("EDGE_ADDR").unwrap_or_else(|_| "0.0.0.0:8443".to_string());
    let ws_addr = std::env::var("EDGE_WS_ADDR").ok().filter(|s| !s.is_empty());

    let rsa_path = std::env::var("SHUZA_RSA_KEY").ok().filter(|s| !s.is_empty());
    let rsa = match &rsa_path {
        Some(path) => {
            eprintln!("[edge] loading server RSA-2048 key from {path}");
            match ServerRsaKey::load_or_generate(path) {
                Ok(k) => Arc::new(k),
                Err(e) => {
                    eprintln!("[edge] cannot load/create key at {path}: {e}");
                    std::process::exit(1);
                }
            }
        }
        None => {
            eprintln!(
                "[edge] generating an ephemeral server RSA-2048 key (set SHUZA_RSA_KEY to persist)"
            );
            Arc::new(ServerRsaKey::generate())
        }
    };
    let dh = dh::server_default();

    if std::env::args().any(|a| a == "--print-pubkey") {
        println!("fingerprint (u64): {:#018x}", rsa.fingerprint as u64);
        println!("{}", rsa.public_key_pkcs1_pem());
        return;
    }

    let data_dir = rsa_path.as_ref().map(|p| {
        std::path::Path::new(p)
            .parent()
            .map(|d| d.to_path_buf())
            .unwrap_or_default()
    });
    let keys_path = std::env::var("SHUZA_AUTHKEYS").ok().or_else(|| {
        data_dir
            .as_ref()
            .map(|d| d.join("authkeys.bin").to_string_lossy().into_owned())
    });
    let users_path = std::env::var("SHUZA_USERS").ok().or_else(|| {
        data_dir
            .as_ref()
            .map(|d| d.join("users.tsv").to_string_lossy().into_owned())
    });

    let keys = Arc::new(KeyStore::load(keys_path));
    let hub = Arc::new(SessionHub::new());

    let test_code = std::env::var("SHUZA_TEST_CODE").ok().filter(|s| !s.is_empty());
    let store = Arc::new(Store::with_persistence(test_code, users_path));
    if store.is_test_server() {
        eprintln!("[edge] TEST SERVER mode: any number registers with the configured test code");
    }

    let dc = DcEndpoint {
        dc_id: std::env::var("SHUZA_DC_ID")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2),
        ip: std::env::var("SHUZA_DC_IP").unwrap_or_else(|_| "127.0.0.1".to_string()),
        port: std::env::var("SHUZA_DC_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8443),
    };
    eprintln!("[edge] advertising dc{} at {}:{}", dc.dc_id, dc.ip, dc.port);

    let fake_tls = std::env::var("SHUZA_FAKETLS_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|hex_sec| match FakeTlsSecret::from_hex(&hex_sec) {
            Ok(s) => {
                eprintln!("[edge] Fake-TLS / proxy secret enabled");
                Some(s)
            }
            Err(e) => {
                eprintln!("[edge] invalid SHUZA_FAKETLS_SECRET ignored: {e}");
                None
            }
        });

    let dispatcher = Arc::new(
        Dispatcher::new(store)
            .with_keys(Arc::clone(&keys))
            .with_hub(Arc::clone(&hub))
            .with_dc(dc),
    );
    eprintln!(
        "[edge] rsa fingerprint = {:#018x}  (configure the client with this key)",
        rsa.fingerprint
    );

    let cfg = EdgeConfig {
        rsa,
        dh,
        dispatcher,
        keys,
        fake_tls,
        enforce_clock_window: false,
    };

    if let Some(ws_bind) = ws_addr {
        match TcpListener::bind(&ws_bind).await {
            Ok(ws_listener) => {
                eprintln!("[edge] listening WebSocket MTProto on ws://{ws_bind}");
                let ws_cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = serve_ws_listener(ws_listener, ws_cfg).await {
                        eprintln!("[edge] ws listener error: {e}");
                    }
                });
            }
            Err(e) => eprintln!("[edge] cannot bind WS {ws_bind}: {e}"),
        }
    }

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[edge] cannot bind {addr}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("[edge] listening on {addr}");

    if let Err(e) = serve_tcp_listener(listener, cfg).await {
        eprintln!("[edge] fatal listener error: {e}");
    }
}

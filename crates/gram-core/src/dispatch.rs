//! RPC envelope unwrapping and request routing.
//!
//! Service/envelope constructors (`msg_container`, `invokeWithLayer`,
//! `initConnection`, `rpc_result`, `rpc_error`, `ping`/`pong`) use the
//! canonical MTProto ids and are handled exactly.
//!
//! The high-level auth constructors (`auth.sendCode`, `auth.signIn`,
//! `auth.sentCode`, `auth.authorization`, `user`) are encoded here with a
//! minimal, self-consistent layout sufficient to prove the login flow. Their
//! exact Layer-232 wire format must be reconciled with the canonical schema
//! before the stock client can parse them (tracked as step 4b).

use std::sync::Arc;

use tl_core::{Reader, TlError, Writer};

use crate::store::{Store, User};

// --- service / envelope ids (canonical) -------------------------------------
const MSG_CONTAINER: u32 = 0x73f1_f8dc;
const INVOKE_WITH_LAYER: u32 = 0xda9b_0d0d;
const INIT_CONNECTION: u32 = 0xc1cd_5ea9;
const PING: u32 = 0x7abe_77ec;
const PONG: u32 = 0x3477_73c5;
const RPC_RESULT: u32 = 0xf35c_6d01;
const RPC_ERROR: u32 = 0x2144_ca19;

// --- auth ids (service-level ids are canonical; bodies are minimal) ---------
const AUTH_SEND_CODE: u32 = 0xa677_244f;
const AUTH_SIGN_IN: u32 = 0x8d52_a951;
const HELP_GET_CONFIG: u32 = 0xc4f9_186b;
const AUTH_SENT_CODE: u32 = 0x5e00_2502;
const AUTH_SENT_CODE_TYPE_APP: u32 = 0x3dbb_5986;
const AUTH_AUTHORIZATION: u32 = 0x2ea2_c0d4;
/// Minimal `user`-like constructor used by this server's own encoding.
const USER_MIN: u32 = 0x5307_2a01;

/// One object to send back to the client; the caller encrypts it.
pub type Response = Vec<u8>;

/// Routes decrypted requests to handlers.
pub struct Dispatcher {
    store: Arc<Store>,
}

impl Dispatcher {
    pub fn new(store: Arc<Store>) -> Self {
        Dispatcher { store }
    }

    /// Handle one decrypted inbound message body, returning zero or more reply
    /// objects (each already in the form the client expects: a `pong`, or an
    /// `rpc_result` wrapping the query's result).
    pub fn handle_message(&self, msg_id: i64, body: &[u8]) -> Vec<Response> {
        let mut r = Reader::new(body);
        let Ok(id) = r.read_u32() else {
            return vec![];
        };

        if id == MSG_CONTAINER {
            return self.handle_container(&mut r);
        }

        // Unwrap invokeWithLayer / initConnection down to the real query.
        let query = match peel_wrappers(id, &mut r) {
            Ok(q) => q,
            Err(_) => return vec![rpc_result(msg_id, &rpc_error(400, "QUERY_MALFORMED"))],
        };

        let mut qr = Reader::new(&query);
        let Ok(qid) = qr.read_u32() else {
            return vec![rpc_result(msg_id, &rpc_error(400, "QUERY_EMPTY"))];
        };

        if qid == PING {
            let ping_id = qr.read_i64().unwrap_or(0);
            return vec![pong(msg_id, ping_id)];
        }

        let result = self.dispatch_query(qid, &mut qr);
        vec![rpc_result(msg_id, &result)]
    }

    fn handle_container(&self, r: &mut Reader) -> Vec<Response> {
        let Ok(count) = r.read_u32() else {
            return vec![];
        };
        let mut out = Vec::new();
        for _ in 0..count {
            // Each inner message: msg_id:long seq_no:int length:int body.
            let (Ok(inner_msg_id), Ok(_seq), Ok(len)) =
                (r.read_i64(), r.read_i32(), r.read_i32())
            else {
                break;
            };
            let Ok(inner_body) = r.read_raw(len as usize) else {
                break;
            };
            out.extend(self.handle_message(inner_msg_id, inner_body));
        }
        out
    }

    /// Dispatch a single query, returning the result object (a success object or
    /// an `rpc_error`), to be wrapped in `rpc_result` by the caller.
    fn dispatch_query(&self, qid: u32, r: &mut Reader) -> Vec<u8> {
        match qid {
            AUTH_SEND_CODE => self.auth_send_code(r),
            AUTH_SIGN_IN => self.auth_sign_in(r),
            HELP_GET_CONFIG => rpc_error(501, "HELP_GET_CONFIG_NOT_IMPLEMENTED"),
            other => rpc_error(400, &format!("UNKNOWN_METHOD_{other:#010x}")),
        }
    }

    // auth.sendCode phone_number:string api_id:int api_hash:string settings:CodeSettings
    fn auth_send_code(&self, r: &mut Reader) -> Vec<u8> {
        let Ok(phone) = r.read_string() else {
            return rpc_error(400, "PHONE_NUMBER_INVALID");
        };
        // api_id / api_hash follow; we don't need them for the stub flow.
        let _ = r.read_i32();
        let _ = r.read_string();

        let (hash, code) = self.store.start_login(phone);
        eprintln!("[core] sendCode phone={phone} -> code={code} (dev)");

        // auth.sentCode flags:# type:auth.SentCodeType phone_code_hash:string
        let mut w = Writer::new();
        w.write_u32(AUTH_SENT_CODE);
        w.write_i32(0); // flags
        w.write_u32(AUTH_SENT_CODE_TYPE_APP); // type
        w.write_i32(5); // code length
        w.write_string(&hash);
        w.into_vec()
    }

    // auth.signIn flags:# phone_number:string phone_code_hash:string phone_code:flags.0?string
    fn auth_sign_in(&self, r: &mut Reader) -> Vec<u8> {
        let Ok(flags) = r.read_i32() else {
            return rpc_error(400, "SIGN_IN_MALFORMED");
        };
        let (Ok(_phone), Ok(hash)) = (r.read_string(), r.read_string()) else {
            return rpc_error(400, "SIGN_IN_MALFORMED");
        };
        let code = if flags & 1 != 0 {
            r.read_string().unwrap_or("")
        } else {
            return rpc_error(400, "PHONE_CODE_EMPTY");
        };

        match self.store.check_code(hash, code) {
            Some(user) => authorization(&user),
            None => rpc_error(400, "PHONE_CODE_INVALID"),
        }
    }
}

/// Peel `invokeWithLayer` / `initConnection` wrappers, returning the inner query
/// bytes (including its constructor id). `id` is the already-read first id and
/// `r` is positioned just after it.
fn peel_wrappers(mut id: u32, r: &mut Reader) -> Result<Vec<u8>, TlError> {
    loop {
        match id {
            INVOKE_WITH_LAYER => {
                let _layer = r.read_i32()?;
            }
            INIT_CONNECTION => {
                let flags = r.read_i32()?;
                let _api_id = r.read_i32()?;
                for _ in 0..6 {
                    let _ = r.read_string()?; // device_model..lang_code
                }
                if flags & 1 != 0 {
                    // proxy:InputClientProxy — unsupported in this minimal path.
                    return Err(TlError::UnknownConstructor {
                        id: 0,
                        context: "initConnection.proxy",
                    });
                }
                if flags & 2 != 0 {
                    return Err(TlError::UnknownConstructor {
                        id: 0,
                        context: "initConnection.params",
                    });
                }
            }
            _ => {
                // Not a wrapper: reconstruct the query bytes (id + remainder).
                let rest = r.read_raw(r.remaining())?;
                let mut q = Vec::with_capacity(4 + rest.len());
                q.extend_from_slice(&id.to_le_bytes());
                q.extend_from_slice(rest);
                return Ok(q);
            }
        }
        id = r.read_u32()?;
    }
}

/// `rpc_result req_msg_id:long result:Object`.
pub fn rpc_result(req_msg_id: i64, result: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(RPC_RESULT);
    w.write_i64(req_msg_id);
    w.write_raw(result);
    w.into_vec()
}

/// `rpc_error error_code:int error_message:string`.
pub fn rpc_error(code: i32, message: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(RPC_ERROR);
    w.write_i32(code);
    w.write_string(message);
    w.into_vec()
}

/// `pong msg_id:long ping_id:long`.
fn pong(msg_id: i64, ping_id: i64) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(PONG);
    w.write_i64(msg_id);
    w.write_i64(ping_id);
    w.into_vec()
}

/// `auth.authorization flags:# user:User` (minimal: flags = 0).
fn authorization(user: &User) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(AUTH_AUTHORIZATION);
    w.write_i32(0); // flags
    w.write_raw(&encode_user(user));
    w.into_vec()
}

/// Minimal user encoding for this server's own schema.
fn encode_user(user: &User) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(USER_MIN);
    w.write_i64(user.id);
    w.write_i64(user.access_hash);
    w.write_string(&user.first_name);
    w.write_string(&user.last_name);
    w.write_string(&user.phone);
    w.into_vec()
}

#[cfg(test)]
mod decode_helpers {
    use super::*;

    /// Decode the minimal auth.sentCode -> phone_code_hash (test helper).
    pub fn decode_sent_code(result: &[u8]) -> String {
        let mut r = Reader::new(result);
        assert_eq!(r.read_u32().unwrap(), AUTH_SENT_CODE);
        let _flags = r.read_i32().unwrap();
        assert_eq!(r.read_u32().unwrap(), AUTH_SENT_CODE_TYPE_APP);
        let _len = r.read_i32().unwrap();
        r.read_string().unwrap().to_string()
    }

    /// Decode the minimal auth.authorization -> User (test helper).
    pub fn decode_authorization(result: &[u8]) -> User {
        let mut r = Reader::new(result);
        assert_eq!(r.read_u32().unwrap(), AUTH_AUTHORIZATION);
        let _flags = r.read_i32().unwrap();
        assert_eq!(r.read_u32().unwrap(), USER_MIN);
        let id = r.read_i64().unwrap();
        let access_hash = r.read_i64().unwrap();
        let first_name = r.read_string().unwrap().to_string();
        let last_name = r.read_string().unwrap().to_string();
        let phone = r.read_string().unwrap().to_string();
        User {
            id,
            phone,
            first_name,
            last_name,
            access_hash,
        }
    }

    pub fn is_rpc_error(result: &[u8]) -> Option<(i32, String)> {
        let mut r = Reader::new(result);
        if r.read_u32().ok()? != RPC_ERROR {
            return None;
        }
        let code = r.read_i32().ok()?;
        let msg = r.read_string().ok()?.to_string();
        Some((code, msg))
    }

    /// Unwrap rpc_result -> (req_msg_id, result bytes).
    pub fn unwrap_rpc_result(bytes: &[u8]) -> (i64, Vec<u8>) {
        let mut r = Reader::new(bytes);
        assert_eq!(r.read_u32().unwrap(), RPC_RESULT);
        let req = r.read_i64().unwrap();
        let rest = r.read_raw(r.remaining()).unwrap().to_vec();
        (req, rest)
    }
}

#[cfg(test)]
mod tests {
    use super::decode_helpers::*;
    use super::*;

    fn invoke_with_layer(query: &[u8]) -> Vec<u8> {
        // invokeWithLayer(232, initConnection(flags=0, ... , query))
        let mut inner = Writer::new();
        inner.write_u32(INIT_CONNECTION);
        inner.write_i32(0); // flags
        inner.write_i32(12345); // api_id
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

    #[test]
    fn ping_returns_pong_through_wrappers() {
        let store = Arc::new(Store::new());
        let d = Dispatcher::new(store);

        let mut q = Writer::new();
        q.write_u32(PING);
        q.write_i64(0x1234);
        let msg = invoke_with_layer(&q.into_vec());

        let out = d.handle_message(777, &msg);
        assert_eq!(out.len(), 1);
        let mut r = Reader::new(&out[0]);
        assert_eq!(r.read_u32().unwrap(), PONG);
        assert_eq!(r.read_i64().unwrap(), 777); // pong.msg_id = request msg_id
        assert_eq!(r.read_i64().unwrap(), 0x1234); // ping_id echoed
    }

    #[test]
    fn full_login_flow() {
        let store = Arc::new(Store::new());
        let d = Dispatcher::new(store);

        // 1) auth.sendCode
        let mut sc = Writer::new();
        sc.write_u32(AUTH_SEND_CODE);
        sc.write_string("+99900099999");
        sc.write_i32(12345);
        sc.write_string("apihash");
        let out = d.handle_message(10, &invoke_with_layer(&sc.into_vec()));
        let (req, result) = unwrap_rpc_result(&out[0]);
        assert_eq!(req, 10);
        let hash = decode_sent_code(&result);
        assert!(!hash.is_empty());

        // 2a) auth.signIn with the wrong code -> PHONE_CODE_INVALID
        let bad = build_sign_in("+99900099999", &hash, "00000");
        let out = d.handle_message(11, &invoke_with_layer(&bad));
        let (_, result) = unwrap_rpc_result(&out[0]);
        assert_eq!(is_rpc_error(&result).unwrap().1, "PHONE_CODE_INVALID");

        // 2b) auth.signIn with the correct code -> authorization + user
        let ok = build_sign_in("+99900099999", &hash, "22222");
        let out = d.handle_message(12, &invoke_with_layer(&ok));
        let (_, result) = unwrap_rpc_result(&out[0]);
        let user = decode_authorization(&result);
        assert_eq!(user.phone, "+99900099999");
        assert!(user.id >= 1000);
    }

    fn build_sign_in(phone: &str, hash: &str, code: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(AUTH_SIGN_IN);
        w.write_i32(1); // flags: has phone_code
        w.write_string(phone);
        w.write_string(hash);
        w.write_string(code);
        w.into_vec()
    }

    // --- end to end over the encrypted session ------------------------------
    use crate::session::Session;
    use mtproto_crypto::kdf::{self, Direction};

    fn test_auth_key() -> [u8; 256] {
        let mut k = [0u8; 256];
        for (i, b) in k.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11).wrapping_add(5);
        }
        k
    }

    /// Client-side encrypt of a request body (client -> server, x = 0).
    fn client_encrypt(key: &[u8; 256], salt: i64, session_id: i64, msg_id: i64, body: &[u8]) -> Vec<u8> {
        let mut pt = Vec::new();
        pt.extend_from_slice(&salt.to_le_bytes());
        pt.extend_from_slice(&session_id.to_le_bytes());
        pt.extend_from_slice(&msg_id.to_le_bytes());
        pt.extend_from_slice(&0i32.to_le_bytes()); // seq_no
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

    /// Client-side decrypt of a server reply (server -> client, x = 8) -> body.
    fn client_decrypt(key: &[u8; 256], payload: &[u8]) -> Vec<u8> {
        let msg_key: [u8; 16] = payload[8..24].try_into().unwrap();
        let mut ct = payload[24..].to_vec();
        let pt = kdf::decrypt_message(key, &msg_key, &mut ct, Direction::ServerToClient).unwrap();
        let length = u32::from_le_bytes(pt[28..32].try_into().unwrap()) as usize;
        pt[32..32 + length].to_vec()
    }

    #[test]
    fn encrypted_login_roundtrip() {
        let key = test_auth_key();
        let salt = 0x0102_0304_0506_0708;
        let session_id = 0x1111_2222_3333_4444;

        let store = Arc::new(Store::new());
        let dispatcher = Dispatcher::new(store);
        let mut server = Session::new(key, salt, session_id);

        // --- client sends an encrypted auth.sendCode ---
        let mut sc = Writer::new();
        sc.write_u32(AUTH_SEND_CODE);
        sc.write_string("+99900099999");
        sc.write_i32(12345);
        sc.write_string("apihash");
        let request_body = invoke_with_layer(&sc.into_vec());
        let client_msg_id = 0x6000_0000_0000_0004;
        let enc = client_encrypt(&key, salt, session_id, client_msg_id, &request_body);

        // --- server decrypts, dispatches, encrypts the reply ---
        let incoming = server.decrypt(&enc).unwrap();
        assert_eq!(incoming.msg_id, client_msg_id);
        let replies = dispatcher.handle_message(incoming.msg_id, &incoming.body);
        assert_eq!(replies.len(), 1);
        let seq = server.next_content_seq();
        let reply_enc = server.encrypt(0x7000_0000_0000_0001, seq, &replies[0]);

        // --- client decrypts the reply and reads the phone_code_hash ---
        let reply_body = client_decrypt(&key, &reply_enc);
        let (req, result) = unwrap_rpc_result(&reply_body);
        assert_eq!(req, client_msg_id);
        let hash = decode_sent_code(&result);
        assert!(!hash.is_empty(), "got a phone_code_hash over the encrypted session");
    }
}

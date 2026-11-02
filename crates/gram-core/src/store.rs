//! In-memory user / login-code store.
//!
//! A first, non-persistent backing for the auth flow. The partitioned
//! PostgreSQL store from the master plan replaces this later behind the same
//! interface.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

use rand::RngCore;

/// A registered user (minimal fields needed for login).
#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub phone: String,
    pub first_name: String,
    pub last_name: String,
    pub access_hash: i64,
}

/// A pending login code awaiting confirmation.
#[derive(Debug, Clone)]
struct PendingCode {
    phone: String,
    code: String,
}

/// Thread-safe in-memory store.
#[derive(Default)]
pub struct Store {
    users_by_phone: Mutex<HashMap<String, User>>,
    pending: Mutex<HashMap<String, PendingCode>>, // keyed by phone_code_hash
    next_user_id: AtomicI64,
}

impl Store {
    pub fn new() -> Self {
        Store {
            users_by_phone: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            next_user_id: AtomicI64::new(1_000),
        }
    }

    /// Start a login: generate a `phone_code_hash` and the (test) code to send.
    /// Returns `(phone_code_hash, code)`.
    pub fn start_login(&self, phone: &str) -> (String, String) {
        let hash = random_hex(16);
        // A real deployment sends this out of band (SMS / app). For now it is
        // deterministic for known test numbers and random otherwise.
        let code = if phone.ends_with("99999") {
            "22222".to_string()
        } else {
            format!("{:05}", rand::thread_rng().next_u32() % 100_000)
        };
        self.pending.lock().unwrap().insert(
            hash.clone(),
            PendingCode {
                phone: phone.to_string(),
                code: code.clone(),
            },
        );
        (hash, code)
    }

    /// Check a submitted code. On success returns the (existing or newly
    /// created) user; on failure returns `None`.
    pub fn check_code(&self, phone_code_hash: &str, code: &str) -> Option<User> {
        let pending = {
            let mut p = self.pending.lock().unwrap();
            let entry = p.get(phone_code_hash)?.clone();
            if entry.code != code {
                return None;
            }
            p.remove(phone_code_hash);
            entry
        };
        Some(self.get_or_create_user(&pending.phone))
    }

    fn get_or_create_user(&self, phone: &str) -> User {
        let mut users = self.users_by_phone.lock().unwrap();
        if let Some(u) = users.get(phone) {
            return u.clone();
        }
        let id = self.next_user_id.fetch_add(1, Ordering::SeqCst);
        let user = User {
            id,
            phone: phone.to_string(),
            first_name: "ShuzaGram".to_string(),
            last_name: "User".to_string(),
            access_hash: id.wrapping_mul(0x9E37_79B9_7F4A_7C15u64 as i64),
        };
        users.insert(phone.to_string(), user.clone());
        user
    }

    pub fn user_by_phone(&self, phone: &str) -> Option<User> {
        self.users_by_phone.lock().unwrap().get(phone).cloned()
    }
}

fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn login_flow_creates_user_and_rejects_bad_code() {
        let store = Store::new();
        let (hash, code) = store.start_login("+99900099999");
        assert_eq!(code, "22222", "test number has a fixed code");

        assert!(store.check_code(&hash, "00000").is_none(), "wrong code");
        // The pending entry is consumed only on success, so retry still works
        // after a wrong attempt.
        let user = store.check_code(&hash, &code).expect("correct code");
        assert_eq!(user.phone, "+99900099999");
        assert!(user.id >= 1000);

        // Same phone logs in again -> same user id.
        let (h2, c2) = store.start_login("+99900099999");
        let user2 = store.check_code(&h2, &c2).unwrap();
        assert_eq!(user.id, user2.id);
    }
}

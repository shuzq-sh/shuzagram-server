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
    /// Test-server override: when set, any pending login accepts this code, so
    /// any phone number can register. Supplied at runtime (never stored in the
    /// repo); `None` means normal per-number codes only.
    test_code: Option<String>,
}

impl Store {
    pub fn new() -> Self {
        Self::with_test_code(None)
    }

    /// Build a store, optionally enabling the test-server master code.
    pub fn with_test_code(test_code: Option<String>) -> Self {
        Store {
            users_by_phone: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            next_user_id: AtomicI64::new(1_000),
            test_code,
        }
    }

    /// Whether the test-server master code is enabled.
    pub fn is_test_server(&self) -> bool {
        self.test_code.is_some()
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
            // On a test server the configured master code is accepted for any
            // number; otherwise the per-number code must match.
            let ok = entry.code == code
                || self.test_code.as_deref().is_some_and(|m| m == code);
            if !ok {
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

    #[test]
    fn test_server_master_code_accepts_any_number() {
        let store = Store::with_test_code(Some("00000MASTER".to_string()));
        assert!(store.is_test_server());

        // An arbitrary number, with the master code, registers.
        let (hash, _code) = store.start_login("+15551234567");
        assert!(store.check_code(&hash, "99999").is_none(), "wrong code still fails");
        let user = store.check_code(&hash, "00000MASTER").expect("master code works");
        assert_eq!(user.phone, "+15551234567");

        // Without a test code, only the per-number code works.
        let plain = Store::new();
        assert!(!plain.is_test_server());
        let (h, c) = plain.start_login("+15550000000");
        assert!(plain.check_code(&h, "00000MASTER").is_none());
        assert!(plain.check_code(&h, &c).is_some());
    }
}

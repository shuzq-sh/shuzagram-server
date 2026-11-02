//! User, pending login-code, and `auth_key_id -> user_id` binding store.
//!
//! Supports optional file-backed persistence (`users.tsv`) so registered
//! accounts and authenticated key bindings survive server restarts and work
//! across parallel MTProto connections (`Generic`, `Push`, `Download`, `Upload`).

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Mutex;

use rand::RngCore;

/// A registered user (minimal fields needed for login and profile).
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
    verified: bool,
}

/// Thread-safe user and session-binding store.
#[derive(Default)]
pub struct Store {
    path: Option<String>,
    users_by_phone: Mutex<HashMap<String, User>>,
    users_by_id: Mutex<HashMap<i64, User>>,
    key_users: Mutex<HashMap<i64, i64>>, // auth_key_id -> user_id
    pending: Mutex<HashMap<String, PendingCode>>, // phone_code_hash -> PendingCode
    next_user_id: AtomicI64,
    /// Test-server override: when set, any pending login accepts this code, so
    /// any phone number can register. Supplied at runtime (never stored in the
    /// repo or persisted to disk); `None` means normal per-number codes only.
    test_code: Option<String>,
}

impl Store {
    pub fn new() -> Self {
        Self::with_test_code(None)
    }

    /// Build a store, optionally enabling the test-server master code.
    pub fn with_test_code(test_code: Option<String>) -> Self {
        Self::with_persistence(test_code, None)
    }

    /// Build a store with optional TSV persistence for users and key bindings.
    pub fn with_persistence(test_code: Option<String>, path: Option<String>) -> Self {
        let mut users_by_phone = HashMap::new();
        let mut users_by_id = HashMap::new();
        let mut key_users = HashMap::new();
        let mut max_id = 999i64;

        if let Some(p) = &path {
            if let Ok(text) = std::fs::read_to_string(p) {
                for line in text.lines() {
                    let parts: Vec<&str> = line.split('\t').collect();
                    match parts.first().copied() {
                        Some("U") if parts.len() >= 6 => {
                            if let (Ok(id), Ok(access_hash)) =
                                (parts[1].parse::<i64>(), parts[5].parse::<i64>())
                            {
                                let user = User {
                                    id,
                                    phone: parts[2].to_string(),
                                    first_name: parts[3].to_string(),
                                    last_name: parts[4].to_string(),
                                    access_hash,
                                };
                                if id > max_id {
                                    max_id = id;
                                }
                                users_by_phone.insert(user.phone.clone(), user.clone());
                                users_by_id.insert(id, user);
                            }
                        }
                        Some("K") if parts.len() >= 3 => {
                            if let (Ok(kid), Ok(uid)) =
                                (parts[1].parse::<i64>(), parts[2].parse::<i64>())
                            {
                                key_users.insert(kid, uid);
                            }
                        }
                        Some("X") if parts.len() >= 2 => {
                            if let Ok(kid) = parts[1].parse::<i64>() {
                                key_users.remove(&kid);
                            }
                        }
                        _ => {}
                    }
                }
                eprintln!(
                    "[core] loaded {} user(s) and {} key binding(s) from {p}",
                    users_by_id.len(),
                    key_users.len()
                );
            }
        }

        Store {
            path,
            users_by_phone: Mutex::new(users_by_phone),
            users_by_id: Mutex::new(users_by_id),
            key_users: Mutex::new(key_users),
            pending: Mutex::new(HashMap::new()),
            next_user_id: AtomicI64::new(max_id + 1),
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
        let normalized = normalize_phone(phone);
        let hash = random_hex(16);
        let code = if normalized.ends_with("99999") {
            "22222".to_string()
        } else {
            format!("{:05}", rand::thread_rng().next_u32() % 100_000)
        };
        self.pending.lock().unwrap().insert(
            hash.clone(),
            PendingCode {
                phone: normalized,
                code: code.clone(),
                verified: false,
            },
        );
        (hash, code)
    }

    /// Resend a pending code (keeps `phone_code_hash` valid if still present, or
    /// starts a fresh login for `phone`).
    pub fn resend_code(&self, phone: &str, phone_code_hash: &str) -> String {
        if self.pending.lock().unwrap().contains_key(phone_code_hash) {
            return phone_code_hash.to_string();
        }
        self.start_login(phone).0
    }

    /// Cancel a pending login code.
    pub fn cancel_code(&self, phone_code_hash: &str) {
        self.pending.lock().unwrap().remove(phone_code_hash);
    }

    /// Check a submitted code. On success returns the (existing or newly
    /// created) user; on failure returns `None`.
    pub fn check_code(&self, phone_code_hash: &str, code: &str) -> Option<User> {
        let phone = {
            let mut p = self.pending.lock().unwrap();
            let entry = p.get_mut(phone_code_hash)?;
            let ok = entry.code == code
                || self.test_code.as_deref().is_some_and(|m| m == code);
            if !ok {
                return None;
            }
            entry.verified = true;
            let phone = entry.phone.clone();
            p.remove(phone_code_hash);
            phone
        };
        Some(self.get_or_create_user(&phone, None, None))
    }

    /// Complete explicit registration (`auth.signUp`), setting `first_name` /
    /// `last_name` on the account.
    pub fn sign_up(
        &self,
        phone: &str,
        phone_code_hash: &str,
        first_name: &str,
        last_name: &str,
    ) -> Option<User> {
        let normalized = normalize_phone(phone);
        let allowed = {
            let mut p = self.pending.lock().unwrap();
            if let Some(entry) = p.remove(phone_code_hash) {
                normalize_phone(&entry.phone) == normalized || entry.verified || self.is_test_server()
            } else {
                self.is_test_server() || self.users_by_phone.lock().unwrap().contains_key(&normalized)
            }
        };
        if !allowed {
            return None;
        }
        let fname = if first_name.trim().is_empty() {
            "ShuzaGram"
        } else {
            first_name.trim()
        };
        Some(self.get_or_create_user(&normalized, Some(fname), Some(last_name.trim())))
    }

    fn get_or_create_user(
        &self,
        phone: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
    ) -> User {
        let normalized = normalize_phone(phone);
        let mut by_phone = self.users_by_phone.lock().unwrap();
        let mut by_id = self.users_by_id.lock().unwrap();

        if let Some(existing) = by_phone.get_mut(&normalized) {
            let mut changed = false;
            if let Some(f) = first_name {
                if !f.is_empty() && existing.first_name != f {
                    existing.first_name = sanitize_tsv(f);
                    changed = true;
                }
            }
            if let Some(l) = last_name {
                if existing.last_name != l {
                    existing.last_name = sanitize_tsv(l);
                    changed = true;
                }
            }
            let u = existing.clone();
            by_id.insert(u.id, u.clone());
            drop(by_id);
            drop(by_phone);
            if changed {
                self.append_user_record(&u);
            }
            return u;
        }

        let id = self.next_user_id.fetch_add(1, Ordering::SeqCst);
        let user = User {
            id,
            phone: sanitize_tsv(&normalized),
            first_name: sanitize_tsv(first_name.unwrap_or("ShuzaGram")),
            last_name: sanitize_tsv(last_name.unwrap_or("User")),
            access_hash: id.wrapping_mul(0x9E37_79B9_7F4A_7C15u64 as i64),
        };
        by_phone.insert(normalized, user.clone());
        by_id.insert(id, user.clone());
        drop(by_id);
        drop(by_phone);
        self.append_user_record(&user);
        user
    }

    /// Bind an `auth_key_id` (permanent or temporary) to a logged-in `user_id`.
    pub fn bind_key_user(&self, auth_key_id: i64, user_id: i64) {
        if auth_key_id == 0 {
            return;
        }
        {
            let mut ku = self.key_users.lock().unwrap();
            if ku.get(&auth_key_id) == Some(&user_id) {
                return;
            }
            ku.insert(auth_key_id, user_id);
        }
        self.append_line(&format!("K\t{auth_key_id}\t{user_id}\n"));
    }

    /// Unbind an `auth_key_id` on `auth.logOut`.
    pub fn unbind_key(&self, auth_key_id: i64) {
        if auth_key_id == 0 {
            return;
        }
        if self.key_users.lock().unwrap().remove(&auth_key_id).is_some() {
            self.append_line(&format!("X\t{auth_key_id}\n"));
        }
    }

    /// Look up the logged-in user bound to `auth_key_id`, if any.
    pub fn user_for_key(&self, auth_key_id: i64) -> Option<User> {
        let uid = *self.key_users.lock().unwrap().get(&auth_key_id)?;
        self.users_by_id.lock().unwrap().get(&uid).cloned()
    }

    pub fn user_by_phone(&self, phone: &str) -> Option<User> {
        let normalized = normalize_phone(phone);
        self.users_by_phone.lock().unwrap().get(&normalized).cloned()
    }

    pub fn user_by_id(&self, id: i64) -> Option<User> {
        self.users_by_id.lock().unwrap().get(&id).cloned()
    }

    fn append_user_record(&self, u: &User) {
        self.append_line(&format!(
            "U\t{}\t{}\t{}\t{}\t{}\n",
            u.id, u.phone, u.first_name, u.last_name, u.access_hash
        ));
    }

    fn append_line(&self, line: &str) {
        if let Some(p) = &self.path {
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
                let _ = f.write_all(line.as_bytes());
            }
        }
    }
}

fn normalize_phone(phone: &str) -> String {
    let trimmed = phone.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    if trimmed.starts_with('+') && !digits.is_empty() {
        format!("+{digits}")
    } else if !digits.is_empty() {
        digits
    } else {
        trimmed.to_string()
    }
}

fn sanitize_tsv(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\t' | '\n' | '\r' => ' ',
            other => other,
        })
        .collect()
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

    #[test]
    fn key_user_binding_roundtrip() {
        let store = Store::new();
        let (h, c) = store.start_login("+99900099999");
        let u = store.check_code(&h, &c).unwrap();
        store.bind_key_user(0x1234_5678, u.id);
        assert_eq!(store.user_for_key(0x1234_5678).unwrap().id, u.id);
        store.unbind_key(0x1234_5678);
        assert!(store.user_for_key(0x1234_5678).is_none());
    }
}

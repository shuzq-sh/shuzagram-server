//! User, pending login-code, and `auth_key_id -> user_id` binding store,
//! backed by [`gram_store::AcidStore`] (SQLite WAL ACID engine) with seamless
//! legacy `users.tsv` auto-migration and append compatibility.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use gram_store::{AcidStore, UserRow};
use rand::RngCore;

/// A registered ShuzaGram user hydrated from [`AcidStore`].
#[derive(Debug, Clone, Default)]
pub struct User {
    pub id: i64,
    pub home_dc_id: i32,
    pub phone: String,
    pub username: Option<String>,
    pub first_name: String,
    pub last_name: String,
    pub bio: String,
    pub flags_bitmask: i64,
    pub photo_id: Option<i64>,
    pub photo_dc_id: Option<i32>,
    pub access_hash: i64,
}

impl From<UserRow> for User {
    fn from(r: UserRow) -> Self {
        Self {
            id: r.user_id,
            home_dc_id: r.home_dc_id,
            phone: r.phone,
            username: r.username,
            first_name: r.first_name,
            last_name: r.last_name,
            bio: r.bio,
            flags_bitmask: r.flags_bitmask,
            photo_id: r.photo_id,
            photo_dc_id: r.photo_dc_id,
            access_hash: r.access_hash,
        }
    }
}

/// A pending login code awaiting confirmation.
#[derive(Debug, Clone)]
struct PendingCode {
    phone: String,
    code: String,
    verified: bool,
}

/// Thread-safe user, session-binding, and ACID messaging store.
pub struct Store {
    tsv_path: Option<String>,
    acid: Arc<AcidStore>,
    pending: Mutex<HashMap<String, PendingCode>>, // phone_code_hash -> PendingCode
    /// Test-server override: when set, any pending login accepts this code, so
    /// any phone number can register. Supplied at runtime (never stored in the
    /// repo or persisted to disk); `None` means normal per-number codes only.
    test_code: Option<String>,
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

impl Store {
    pub fn new() -> Self {
        Self::with_test_code(None)
    }

    /// Build an in-memory ACID store, optionally enabling the test-server master code.
    pub fn with_test_code(test_code: Option<String>) -> Self {
        let acid = Arc::new(
            AcidStore::open_in_memory(2).expect("failed to initialize in-memory AcidStore"),
        );
        Self::with_acid(test_code, acid)
    }

    /// Build a store sharing an explicit [`AcidStore`] (used in Multi-DC federation tests
    /// and shared edge + admin deployments).
    pub fn with_acid(test_code: Option<String>, acid: Arc<AcidStore>) -> Self {
        Store {
            tsv_path: None,
            acid,
            pending: Mutex::new(HashMap::new()),
            test_code,
        }
    }

    /// Build a store with persistent SQLite WAL storage (`shuzagram.db`) and
    /// automatic idempotent import of any existing `users.tsv`.
    pub fn with_persistence(test_code: Option<String>, path: Option<String>) -> Self {
        let default_dc: i32 = std::env::var("SHUZA_DC_ID")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(2);

        let acid = match &path {
            Some(tsv_str) => {
                let db_path = std::env::var("SHUZA_DB")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| {
                        let p = Path::new(tsv_str);
                        match p.parent() {
                            Some(dir) if !dir.as_os_str().is_empty() => {
                                dir.join("shuzagram.db").to_string_lossy().into_owned()
                            }
                            _ => "shuzagram.db".to_string(),
                        }
                    });
                let engine = AcidStore::open_path(&db_path, default_dc)
                    .unwrap_or_else(|e| panic!("failed to open AcidStore at {db_path}: {e}"));
                match engine.import_legacy_tsv(tsv_str) {
                    Ok(n) if n > 0 => {
                        eprintln!(
                            "[core] migrated/synced {n} legacy record(s) from {tsv_str} into {db_path} (total users={})",
                            engine.user_count()
                        );
                    }
                    Ok(_) => {
                        eprintln!(
                            "[core] opened AcidStore at {db_path} (total users={})",
                            engine.user_count()
                        );
                    }
                    Err(e) => {
                        eprintln!("[core] warning: legacy TSV import error from {tsv_str}: {e}");
                    }
                }
                Arc::new(engine)
            }
            None => Arc::new(
                AcidStore::open_in_memory(default_dc)
                    .expect("failed to initialize in-memory AcidStore"),
            ),
        };

        Store {
            tsv_path: path,
            acid,
            pending: Mutex::new(HashMap::new()),
            test_code,
        }
    }

    /// Access the underlying [`AcidStore`] for messaging, contacts, channels,
    /// media blobs, Stars economy, and admin operations.
    pub fn acid(&self) -> &Arc<AcidStore> {
        &self.acid
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
            let ok =
                entry.code == code || self.test_code.as_deref().is_some_and(|m| m == code);
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
                normalize_phone(&entry.phone) == normalized
                    || entry.verified
                    || self.is_test_server()
            } else {
                self.is_test_server() || self.acid.user_by_phone(&normalized).is_some()
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

    pub fn get_or_create_user(
        &self,
        phone: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
    ) -> User {
        let normalized = normalize_phone(phone);
        let clean_first = first_name.map(sanitize_tsv);
        let clean_last = last_name.map(sanitize_tsv);
        let row = self
            .acid
            .get_or_create_user(
                &normalized,
                clean_first.as_deref(),
                clean_last.as_deref(),
            )
            .expect("AcidStore::get_or_create_user failed");
        let u = User::from(row);
        self.append_user_record(&u);
        u
    }

    /// Bind an `auth_key_id` (permanent or temporary) to a logged-in `user_id`.
    pub fn bind_key_user(&self, auth_key_id: i64, user_id: i64) {
        if auth_key_id == 0 {
            return;
        }
        let home_dc = self
            .acid
            .user_by_id(user_id)
            .map(|u| u.home_dc_id)
            .unwrap_or(2);
        let _ = self.acid.bind_key_user(auth_key_id, user_id, home_dc, 1);
        self.append_line(&format!("K\t{auth_key_id}\t{user_id}\n"));
    }

    /// Bind a federated proxy/guest `auth_key_id` (`binding_mode = 2`) to `user_id`.
    pub fn bind_proxy_key_user(&self, auth_key_id: i64, user_id: i64, home_dc_id: i32) {
        if auth_key_id == 0 {
            return;
        }
        let _ = self.acid.bind_key_user(auth_key_id, user_id, home_dc_id, 2);
    }

    /// Unbind an `auth_key_id` on `auth.logOut`.
    pub fn unbind_key(&self, auth_key_id: i64) {
        if auth_key_id == 0 {
            return;
        }
        let _ = self.acid.unbind_key(auth_key_id);
        self.append_line(&format!("X\t{auth_key_id}\n"));
    }

    /// Look up the logged-in user bound to `auth_key_id`, if any.
    pub fn user_for_key(&self, auth_key_id: i64) -> Option<User> {
        let (row, _hdc, _mode) = self.acid.key_binding(auth_key_id)?;
        Some(User::from(row))
    }

    pub fn user_by_phone(&self, phone: &str) -> Option<User> {
        let normalized = normalize_phone(phone);
        self.acid.user_by_phone(&normalized).map(User::from)
    }

    pub fn user_by_id(&self, id: i64) -> Option<User> {
        self.acid.user_by_id(id).map(User::from)
    }

    pub fn user_by_username(&self, username: &str) -> Option<User> {
        self.acid.user_by_username(username).map(User::from)
    }

    fn append_user_record(&self, u: &User) {
        self.append_line(&format!(
            "U\t{}\t{}\t{}\t{}\t{}\n",
            u.id,
            sanitize_tsv(&u.phone),
            sanitize_tsv(&u.first_name),
            sanitize_tsv(&u.last_name),
            u.access_hash
        ));
    }

    fn append_line(&self, line: &str) {
        if let Some(p) = &self.tsv_path {
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
                let _ = f.write_all(line.as_bytes());
            }
        }
    }
}

pub fn normalize_phone(phone: &str) -> String {
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
        let user = store.check_code(&hash, &code).expect("correct code");
        assert_eq!(user.phone, "+99900099999");
        assert!(user.id >= 1000);

        let (h2, c2) = store.start_login("+99900099999");
        let user2 = store.check_code(&h2, &c2).unwrap();
        assert_eq!(user.id, user2.id);
    }

    #[test]
    fn test_server_master_code_accepts_any_number() {
        let store = Store::with_test_code(Some("00000MASTER".to_string()));
        assert!(store.is_test_server());

        let (hash, _code) = store.start_login("+15551234567");
        assert!(
            store.check_code(&hash, "99999").is_none(),
            "wrong code still fails"
        );
        let user = store
            .check_code(&hash, "00000MASTER")
            .expect("master code works");
        assert_eq!(user.phone, "+15551234567");

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

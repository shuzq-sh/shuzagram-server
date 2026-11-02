//! Persistent store of established auth keys and PFS temp-key bindings.
//!
//! On-disk format:
//! - `<path>`: flat sequence of fixed 272-byte records
//!   `auth_key_id (i64 LE) | auth_key (256) | server_salt (i64 LE)`.
//! - `<path>.links`: flat sequence of fixed 16-byte records
//!   `temp_auth_key_id (i64 LE) | perm_auth_key_id (i64 LE)`.

#![allow(clippy::chunks_exact_to_as_chunks)]

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

const RECORD: usize = 8 + 256 + 8;
const LINK_RECORD: usize = 8 + 8;

/// A thread-safe, optionally file-backed auth-key registry.
pub struct KeyStore {
    path: Option<String>,
    map: Mutex<HashMap<i64, ([u8; 256], i64)>>,
    temp_to_perm: Mutex<HashMap<i64, i64>>,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self::load(None)
    }
}

impl KeyStore {
    /// Load the store from `path` (if given and present); otherwise start empty.
    pub fn load(path: Option<String>) -> Self {
        let mut map = HashMap::new();
        let mut temp_to_perm = HashMap::new();
        if let Some(p) = &path {
            if let Ok(bytes) = std::fs::read(p) {
                for rec in bytes.chunks_exact(RECORD) {
                    let id = i64::from_le_bytes(rec[0..8].try_into().unwrap());
                    let key: [u8; 256] = rec[8..264].try_into().unwrap();
                    let salt = i64::from_le_bytes(rec[264..272].try_into().unwrap());
                    map.insert(id, (key, salt));
                }
                eprintln!("[edge] loaded {} auth key(s) from {p}", map.len());
            }
            let links_path = format!("{p}.links");
            if let Ok(bytes) = std::fs::read(&links_path) {
                for rec in bytes.chunks_exact(LINK_RECORD) {
                    let temp_id = i64::from_le_bytes(rec[0..8].try_into().unwrap());
                    let perm_id = i64::from_le_bytes(rec[8..16].try_into().unwrap());
                    temp_to_perm.insert(temp_id, perm_id);
                }
                eprintln!(
                    "[edge] loaded {} temp->perm key binding(s) from {links_path}",
                    temp_to_perm.len()
                );
            }
        }
        KeyStore {
            path,
            map: Mutex::new(map),
            temp_to_perm: Mutex::new(temp_to_perm),
        }
    }

    pub fn get(&self, id: i64) -> Option<([u8; 256], i64)> {
        self.map.lock().unwrap().get(&id).copied()
    }

    /// Record a newly established key (in memory and, if configured, on disk).
    pub fn insert(&self, id: i64, key: [u8; 256], salt: i64) {
        self.map.lock().unwrap().insert(id, (key, salt));
        if let Some(p) = &self.path {
            let mut rec = Vec::with_capacity(RECORD);
            rec.extend_from_slice(&id.to_le_bytes());
            rec.extend_from_slice(&key);
            rec.extend_from_slice(&salt.to_le_bytes());
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(p) {
                let _ = f.write_all(&rec);
            }
        }
    }

    /// Link a PFS `temp_auth_key_id` to its `perm_auth_key_id`.
    pub fn bind_temp(&self, temp_id: i64, perm_id: i64) {
        self.temp_to_perm.lock().unwrap().insert(temp_id, perm_id);
        if let Some(p) = &self.path {
            let links_path = format!("{p}.links");
            let mut rec = [0u8; LINK_RECORD];
            rec[0..8].copy_from_slice(&temp_id.to_le_bytes());
            rec[8..16].copy_from_slice(&perm_id.to_le_bytes());
            if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(links_path) {
                let _ = f.write_all(&rec);
            }
        }
    }

    /// Resolve a `temp_auth_key_id` to its bound `perm_auth_key_id`, or return
    /// `id` unchanged if `id` is itself a permanent key (or not yet bound).
    pub fn resolve_perm(&self, id: i64) -> i64 {
        self.temp_to_perm
            .lock()
            .unwrap()
            .get(&id)
            .copied()
            .unwrap_or(id)
    }

    /// Drop temp keys bound to the same permanent key except those in `keep`.
    pub fn drop_temp_keys_except(&self, current_key_id: i64, keep: &[i64]) {
        let perm_id = self.resolve_perm(current_key_id);
        let mut links = self.temp_to_perm.lock().unwrap();
        let to_remove: Vec<i64> = links
            .iter()
            .filter(|(&temp, &perm)| {
                perm == perm_id && temp != current_key_id && !keep.contains(&temp)
            })
            .map(|(&temp, _)| temp)
            .collect();
        if to_remove.is_empty() {
            return;
        }
        let mut map = self.map.lock().unwrap();
        for temp in to_remove {
            links.remove(&temp);
            map.remove(&temp);
        }
    }
}

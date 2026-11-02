//! Persistent store of established auth keys, so a client's key survives
//! server restarts (otherwise the client, which caches its permanent key, would
//! keep sending a key the server no longer recognizes).
//!
//! On-disk format: a flat sequence of fixed 272-byte records
//! `auth_key_id (i64 LE) | auth_key (256) | server_salt (i64 LE)`, appended as
//! keys are created and read back fully at startup.

#![allow(clippy::chunks_exact_to_as_chunks)]

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;

const RECORD: usize = 8 + 256 + 8;

/// A thread-safe, optionally file-backed auth-key registry.
pub struct KeyStore {
    path: Option<String>,
    map: Mutex<HashMap<i64, ([u8; 256], i64)>>,
}

impl KeyStore {
    /// Load the store from `path` (if given and present); otherwise start empty.
    pub fn load(path: Option<String>) -> Self {
        let mut map = HashMap::new();
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
        }
        KeyStore {
            path,
            map: Mutex::new(map),
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
}

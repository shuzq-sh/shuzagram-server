//! TL serializer over a growable byte buffer.

use crate::{BOOL_FALSE_ID, BOOL_TRUE_ID, VECTOR_ID};

/// Appends TL-encoded values to an owned buffer.
#[derive(Default, Clone)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { out: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Writer {
            out: Vec::with_capacity(cap),
        }
    }

    pub fn len(&self) -> usize {
        self.out.len()
    }

    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.out
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.out
    }

    /// Write raw bytes verbatim (no length prefix, no padding).
    pub fn write_raw(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }

    pub fn write_u32(&mut self, v: u32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_i32(&mut self, v: i32) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_i64(&mut self, v: i64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_u64(&mut self, v: u64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    pub fn write_f64(&mut self, v: f64) {
        self.out.extend_from_slice(&v.to_le_bytes());
    }

    /// `int128` (16 bytes, e.g. nonce) written verbatim.
    pub fn write_i128(&mut self, v: &[u8; 16]) {
        self.out.extend_from_slice(v);
    }

    /// `int256` (32 bytes, e.g. new_nonce) written verbatim.
    pub fn write_i256(&mut self, v: &[u8; 32]) {
        self.out.extend_from_slice(v);
    }

    pub fn write_bool(&mut self, v: bool) {
        self.write_u32(if v { BOOL_TRUE_ID } else { BOOL_FALSE_ID });
    }

    /// TL `bytes`: length prefix then data then zero padding to a 4-byte boundary.
    pub fn write_bytes(&mut self, data: &[u8]) {
        let len = data.len();
        let mut written;
        if len <= 253 {
            self.out.push(len as u8);
            written = 1 + len;
        } else {
            self.out.push(0xfe);
            self.out.push((len & 0xff) as u8);
            self.out.push(((len >> 8) & 0xff) as u8);
            self.out.push(((len >> 16) & 0xff) as u8);
            written = 4 + len;
        }
        self.out.extend_from_slice(data);
        while !written.is_multiple_of(4) {
            self.out.push(0);
            written += 1;
        }
    }

    /// TL `string` (same wire encoding as `bytes`).
    pub fn write_string(&mut self, s: &str) {
        self.write_bytes(s.as_bytes());
    }

    /// Write the `Vector<t>` header (`0x1cb5c415` + element count).
    pub fn write_vector_header(&mut self, count: usize) {
        self.write_u32(VECTOR_ID);
        self.write_u32(count as u32);
    }

    /// Write a `Vector<long>` from an iterator of i64.
    pub fn write_long_vector(&mut self, items: &[i64]) {
        self.write_vector_header(items.len());
        for &v in items {
            self.write_i64(v);
        }
    }
}

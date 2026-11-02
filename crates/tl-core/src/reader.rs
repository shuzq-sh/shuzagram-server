//! TL deserializer over a borrowed byte slice.

use crate::{TlError, BOOL_FALSE_ID, BOOL_TRUE_ID, VECTOR_ID};

/// A cursor over a TL-encoded buffer.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    #[inline]
    fn take(&mut self, n: usize) -> Result<&'a [u8], TlError> {
        if self.remaining() < n {
            return Err(TlError::UnexpectedEof {
                needed: n,
                remaining: self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Read `n` raw bytes verbatim.
    pub fn read_raw(&mut self, n: usize) -> Result<&'a [u8], TlError> {
        self.take(n)
    }

    pub fn read_u32(&mut self) -> Result<u32, TlError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn read_i32(&mut self) -> Result<i32, TlError> {
        Ok(i32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn read_i64(&mut self) -> Result<i64, TlError> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn read_u64(&mut self) -> Result<u64, TlError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn read_f64(&mut self) -> Result<f64, TlError> {
        Ok(f64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn read_i128(&mut self) -> Result<[u8; 16], TlError> {
        Ok(self.take(16)?.try_into().unwrap())
    }

    pub fn read_i256(&mut self) -> Result<[u8; 32], TlError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    pub fn read_bool(&mut self) -> Result<bool, TlError> {
        let id = self.read_u32()?;
        match id {
            BOOL_TRUE_ID => Ok(true),
            BOOL_FALSE_ID => Ok(false),
            _ => Err(TlError::UnknownConstructor {
                id,
                context: "Bool",
            }),
        }
    }

    /// Read TL `bytes`, consuming the length prefix and trailing padding.
    pub fn read_bytes(&mut self) -> Result<&'a [u8], TlError> {
        let first = self.take(1)?[0] as usize;
        let (len, header) = if first <= 253 {
            (first, 1)
        } else if first == 254 {
            let b = self.take(3)?;
            let len = b[0] as usize | (b[1] as usize) << 8 | (b[2] as usize) << 16;
            (len, 4)
        } else {
            // 0xff is not a valid length prefix in TL.
            return Err(TlError::InvalidPadding);
        };
        let data = self.take(len)?;
        let pad = (4 - (header + len) % 4) % 4;
        let padding = self.take(pad)?;
        if padding.iter().any(|&b| b != 0) {
            return Err(TlError::InvalidPadding);
        }
        Ok(data)
    }

    /// Read a TL `string` as `&str`.
    pub fn read_string(&mut self) -> Result<&'a str, TlError> {
        let b = self.read_bytes()?;
        core::str::from_utf8(b).map_err(|_| TlError::InvalidUtf8)
    }

    /// Read and validate a `Vector<t>` header, returning the element count.
    pub fn read_vector_header(&mut self) -> Result<u32, TlError> {
        let id = self.read_u32()?;
        if id != VECTOR_ID {
            return Err(TlError::UnknownConstructor {
                id,
                context: "Vector",
            });
        }
        let count = self.read_u32()?;
        // Guard against absurd allocations driven by a forged count.
        if count as usize > self.remaining() / 4 + 1 {
            return Err(TlError::VectorLengthOverflow { count });
        }
        Ok(count)
    }

    /// Read a `Vector<long>`.
    pub fn read_long_vector(&mut self) -> Result<Vec<i64>, TlError> {
        let count = self.read_vector_header()?;
        let mut out = Vec::with_capacity(count as usize);
        for _ in 0..count {
            out.push(self.read_i64()?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Writer;

    #[test]
    fn primitive_roundtrips() {
        let mut w = Writer::new();
        w.write_i32(-42);
        w.write_i64(0x0102_0304_0506_0708);
        w.write_u32(0xdead_beef);
        w.write_f64(3.5);
        w.write_bool(true);
        w.write_bool(false);
        let i128v = [7u8; 16];
        let i256v = [9u8; 32];
        w.write_i128(&i128v);
        w.write_i256(&i256v);
        let buf = w.into_vec();

        let mut r = Reader::new(&buf);
        assert_eq!(r.read_i32().unwrap(), -42);
        assert_eq!(r.read_i64().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(r.read_u32().unwrap(), 0xdead_beef);
        assert_eq!(r.read_f64().unwrap(), 3.5);
        assert!(r.read_bool().unwrap());
        assert!(!r.read_bool().unwrap());
        assert_eq!(r.read_i128().unwrap(), i128v);
        assert_eq!(r.read_i256().unwrap(), i256v);
        assert!(r.is_empty());
    }

    #[test]
    fn bytes_padding_all_lengths() {
        for len in [0usize, 1, 2, 3, 4, 5, 100, 253, 254, 255, 1000] {
            let data: Vec<u8> = (0..len).map(|i| (i * 13 + 1) as u8).collect();
            let mut w = Writer::new();
            w.write_bytes(&data);
            let buf = w.into_vec();
            // Total written must be a multiple of 4.
            assert_eq!(buf.len() % 4, 0, "len={len} not 4-aligned");
            let mut r = Reader::new(&buf);
            assert_eq!(r.read_bytes().unwrap(), &data[..], "roundtrip len={len}");
            assert!(r.is_empty(), "leftover bytes for len={len}");
        }
    }

    #[test]
    fn string_roundtrip_unicode() {
        let mut w = Writer::new();
        w.write_string("привет 👋 mtproto");
        let buf = w.into_vec();
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_string().unwrap(), "привет 👋 mtproto");
    }

    #[test]
    fn long_vector_roundtrip() {
        let fps = vec![1i64, -2, 0x7fff_ffff_ffff_ffff, i64::MIN];
        let mut w = Writer::new();
        w.write_long_vector(&fps);
        let buf = w.into_vec();
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_long_vector().unwrap(), fps);
    }

    #[test]
    fn eof_is_reported() {
        let buf = [1u8, 2, 3];
        let mut r = Reader::new(&buf);
        assert!(matches!(
            r.read_i32(),
            Err(TlError::UnexpectedEof {
                needed: 4,
                remaining: 3
            })
        ));
    }

    #[test]
    fn large_length_byte_form() {
        // len 254 uses the 0xfe long form.
        let data = vec![0xabu8; 254];
        let mut w = Writer::new();
        w.write_bytes(&data);
        let buf = w.into_vec();
        assert_eq!(buf[0], 0xfe);
        assert_eq!(buf[1], 254);
        let mut r = Reader::new(&buf);
        assert_eq!(r.read_bytes().unwrap(), &data[..]);
    }
}

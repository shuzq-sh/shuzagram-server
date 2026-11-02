//! Zero-copy borrowed TL (Type Language) reader/writer traits and views.
//!
//! Operates directly over `&'a [u8]` and [`bytes::BytesMut`] with zero heap
//! allocations on hot steady-state paths.

use bytes::{BufMut, BytesMut};

use crate::{TlError, BOOL_FALSE_ID, BOOL_TRUE_ID, VECTOR_ID};

const MAX_VECTOR_LEN: u32 = 1 << 20;

/// Zero-copy borrowed deserialization from a TL byte slice.
pub trait TlRead<'a>: Sized {
    fn tl_read(buf: &mut &'a [u8]) -> Result<Self, TlError>;
}

/// Zero-allocation serialization into a [`BytesMut`] slab.
pub trait TlWrite {
    fn tl_serialized_len(&self) -> usize;
    fn tl_write(&self, out: &mut BytesMut);
}

/// Zero-copy TL byte slice (`bytes`: 1-byte len < 254, or `0xfe` + 3-byte LE len, 4-byte padded).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TlBytes<'a>(pub &'a [u8]);

/// Zero-copy UTF-8 TL string (`string` in TL).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TlStr<'a>(pub &'a str);

/// Zero-copy lazy TL `Vector<T>` iterator that validates header `0x1cb5c415` + element count
/// and decodes elements on demand without allocating a `Vec<T>` on the heap.
#[derive(Copy, Clone, Debug)]
pub struct TlSliceIter<'a, T> {
    remaining_items: u32,
    buf: &'a [u8],
    _marker: core::marker::PhantomData<T>,
}

impl<'a, T: TlRead<'a>> TlSliceIter<'a, T> {
    /// Read `Vector<T>` header (`0x1cb5c415` + `count`) and return a lazy iterator,
    /// advancing the outer cursor past the header; call [`Self::finish`] or consume
    /// all items to advance past elements.
    pub fn from_slice(buf: &mut &'a [u8]) -> Result<Self, TlError> {
        let ctor = u32::tl_read(buf)?;
        if ctor != VECTOR_ID {
            return Err(TlError::UnknownConstructor {
                id: ctor,
                context: "Vector<T>",
            });
        }
        let count = u32::tl_read(buf)?;
        if count > MAX_VECTOR_LEN {
            return Err(TlError::VectorLengthOverflow { count });
        }
        Ok(Self {
            remaining_items: count,
            buf: *buf,
            _marker: core::marker::PhantomData,
        })
    }

    pub const fn len(&self) -> usize {
        self.remaining_items as usize
    }

    pub const fn is_empty(&self) -> bool {
        self.remaining_items == 0
    }

    pub const fn remaining_bytes(&self) -> &'a [u8] {
        self.buf
    }
}

impl<'a, T: TlRead<'a>> Iterator for TlSliceIter<'a, T> {
    type Item = Result<T, TlError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining_items == 0 {
            return None;
        }
        self.remaining_items -= 1;
        Some(T::tl_read(&mut self.buf))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.remaining_items as usize;
        (rem, Some(rem))
    }
}

#[inline]
fn take<'a>(buf: &mut &'a [u8], n: usize) -> Result<&'a [u8], TlError> {
    if buf.len() < n {
        return Err(TlError::UnexpectedEof {
            needed: n,
            remaining: buf.len(),
        });
    }
    let (head, tail) = buf.split_at(n);
    *buf = tail;
    Ok(head)
}

impl<'a> TlRead<'a> for u32 {
    #[inline]
    fn tl_read(buf: &mut &'a [u8]) -> Result<Self, TlError> {
        let b = take(buf, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

impl TlWrite for u32 {
    #[inline]
    fn tl_serialized_len(&self) -> usize {
        4
    }
    #[inline]
    fn tl_write(&self, out: &mut BytesMut) {
        out.put_u32_le(*self);
    }
}

impl<'a> TlRead<'a> for i32 {
    #[inline]
    fn tl_read(buf: &mut &'a [u8]) -> Result<Self, TlError> {
        let b = take(buf, 4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
}

impl TlWrite for i32 {
    #[inline]
    fn tl_serialized_len(&self) -> usize {
        4
    }
    #[inline]
    fn tl_write(&self, out: &mut BytesMut) {
        out.put_i32_le(*self);
    }
}

impl<'a> TlRead<'a> for i64 {
    #[inline]
    fn tl_read(buf: &mut &'a [u8]) -> Result<Self, TlError> {
        let b = take(buf, 8)?;
        Ok(i64::from_le_bytes(b.try_into().unwrap()))
    }
}

impl TlWrite for i64 {
    #[inline]
    fn tl_serialized_len(&self) -> usize {
        8
    }
    #[inline]
    fn tl_write(&self, out: &mut BytesMut) {
        out.put_i64_le(*self);
    }
}

impl<'a> TlRead<'a> for bool {
    #[inline]
    fn tl_read(buf: &mut &'a [u8]) -> Result<Self, TlError> {
        match u32::tl_read(buf)? {
            BOOL_TRUE_ID => Ok(true),
            BOOL_FALSE_ID => Ok(false),
            id => Err(TlError::UnknownConstructor { id, context: "Bool" }),
        }
    }
}

impl TlWrite for bool {
    #[inline]
    fn tl_serialized_len(&self) -> usize {
        4
    }
    #[inline]
    fn tl_write(&self, out: &mut BytesMut) {
        out.put_u32_le(if *self { BOOL_TRUE_ID } else { BOOL_FALSE_ID });
    }
}

impl<'a> TlRead<'a> for TlBytes<'a> {
    fn tl_read(buf: &mut &'a [u8]) -> Result<Self, TlError> {
        let first = take(buf, 1)?[0];
        let (len, header_len) = if first < 254 {
            (first as usize, 1usize)
        } else if first == 254 {
            let b = take(buf, 3)?;
            let l = (b[0] as usize) | ((b[1] as usize) << 8) | ((b[2] as usize) << 16);
            (l, 4usize)
        } else {
            return Err(TlError::InvalidPadding);
        };
        let data = take(buf, len)?;
        let pad = (4 - ((header_len + len) % 4)) % 4;
        let _ = take(buf, pad)?;
        Ok(TlBytes(data))
    }
}

impl<'a> TlWrite for TlBytes<'a> {
    fn tl_serialized_len(&self) -> usize {
        let len = self.0.len();
        let header = if len < 254 { 1 } else { 4 };
        let total = header + len;
        total + ((4 - (total % 4)) % 4)
    }

    fn tl_write(&self, out: &mut BytesMut) {
        let len = self.0.len();
        let header = if len < 254 {
            out.put_u8(len as u8);
            1usize
        } else {
            out.put_u8(254);
            out.put_u8((len & 0xff) as u8);
            out.put_u8(((len >> 8) & 0xff) as u8);
            out.put_u8(((len >> 16) & 0xff) as u8);
            4usize
        };
        out.extend_from_slice(self.0);
        let pad = (4 - ((header + len) % 4)) % 4;
        for _ in 0..pad {
            out.put_u8(0);
        }
    }
}

impl<'a> TlRead<'a> for TlStr<'a> {
    fn tl_read(buf: &mut &'a [u8]) -> Result<Self, TlError> {
        let b = TlBytes::tl_read(buf)?;
        let s = core::str::from_utf8(b.0).map_err(|_| TlError::InvalidUtf8)?;
        Ok(TlStr(s))
    }
}

impl<'a> TlWrite for TlStr<'a> {
    #[inline]
    fn tl_serialized_len(&self) -> usize {
        TlBytes(self.0.as_bytes()).tl_serialized_len()
    }

    #[inline]
    fn tl_write(&self, out: &mut BytesMut) {
        TlBytes(self.0.as_bytes()).tl_write(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_copy_str_and_slice_iter_roundtrip() {
        let mut buf = BytesMut::with_capacity(64);
        VECTOR_ID.tl_write(&mut buf);
        3u32.tl_write(&mut buf);
        TlStr("alpha").tl_write(&mut buf);
        TlStr("бета").tl_write(&mut buf);
        TlStr("gamma").tl_write(&mut buf);

        let frozen = buf.freeze();
        let mut slice: &[u8] = &frozen;
        let iter = TlSliceIter::<TlStr<'_>>::from_slice(&mut slice).unwrap();
        assert_eq!(iter.len(), 3);
        let collected: Vec<&str> = iter.map(|r| r.unwrap().0).collect();
        assert_eq!(collected, vec!["alpha", "бета", "gamma"]);
    }
}

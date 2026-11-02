//! MTProto TL (Type Language) wire (de)serialization.
//!
//! This is a hand-written, correctness-first implementation of the TL binary
//! encoding that the MTProto handshake and the early auth RPCs need:
//!
//! - fixed-width `int`/`long`/`double`/`int128`/`int256`
//! - `bytes` and `string` with the 1-byte / `0xfe`+3-byte length prefix and
//!   4-byte padding
//! - `Vector t` with the `0x1cb5c415` header
//! - boxed constructors identified by a 32-bit CRC id
//!
//! Numbers are little-endian, matching the wire format.

mod reader;
mod writer;
pub mod zerocopy_tl;

pub use reader::Reader;
pub use writer::Writer;
pub use zerocopy_tl::{TlBytes, TlRead, TlSliceIter, TlStr, TlWrite};

/// `Vector<t>` boxed constructor id.
pub const VECTOR_ID: u32 = 0x1cb5_c415;
/// `boolTrue` constructor id.
pub const BOOL_TRUE_ID: u32 = 0x9972_75b5;
/// `boolFalse` constructor id.
pub const BOOL_FALSE_ID: u32 = 0xbc79_9737;

/// Errors produced while reading TL from a buffer.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
pub enum TlError {
    #[error("unexpected end of buffer: needed {needed} more bytes, {remaining} remaining")]
    UnexpectedEof { needed: usize, remaining: usize },
    #[error("unknown constructor id {id:#010x} in {context}")]
    UnknownConstructor { id: u32, context: &'static str },
    #[error("invalid UTF-8 in TL string")]
    InvalidUtf8,
    #[error("invalid TL padding")]
    InvalidPadding,
    #[error("vector length {count} overflows a reasonable bound")]
    VectorLengthOverflow { count: u32 },
    #[error("invoke wrapper nesting depth exceeded maximum {max_depth}")]
    WrapperDepthExceeded { max_depth: u8 },
}

/// A TL object with a boxed constructor id, able to round-trip through the wire.
pub trait TlObject: Sized {
    /// The 32-bit constructor id (CRC32 of the TL definition line).
    const CONSTRUCTOR: u32;

    /// Serialize the body (constructor id is written by [`TlObject::serialize_boxed`]).
    fn serialize_bare(&self, w: &mut Writer);

    /// Deserialize the body, assuming the constructor id has already been read.
    fn deserialize_bare(r: &mut Reader) -> Result<Self, TlError>;

    /// Serialize with the leading constructor id (boxed form).
    fn serialize_boxed(&self, w: &mut Writer) {
        w.write_u32(Self::CONSTRUCTOR);
        self.serialize_bare(w);
    }

    /// Deserialize the boxed form, checking the constructor id.
    fn deserialize_boxed(r: &mut Reader) -> Result<Self, TlError> {
        let id = r.read_u32()?;
        if id != Self::CONSTRUCTOR {
            return Err(TlError::UnknownConstructor {
                id,
                context: core::any::type_name::<Self>(),
            });
        }
        Self::deserialize_bare(r)
    }

    /// Convenience: serialize to a fresh `Vec<u8>` in boxed form.
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.serialize_boxed(&mut w);
        w.into_vec()
    }
}

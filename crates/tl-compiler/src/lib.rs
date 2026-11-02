//! TL (Type Language) compiler, IEEE CRC32 constructor calculator, and
//! Multi-Layer Compatibility Registry (`LayerAdapterRegistry`).
//!
//! Internally `shuzagram-server` executes strictly on **Canonical Layer 232**,
//! while translating older client layers (`185`, `200`, `220`, `227`, etc.)
//! and client-platform quirks (`Desktop`, `Android`, `Ios`, `Web`) at the edge.

use std::collections::HashMap;

use bytes::{BufMut, BytesMut};
use tl_core::TlError;

pub const CANONICAL_LAYER: u16 = 232;

/// Embedded MTProto 2.0 transport schema (`schemas/mtproto_transport.tl`).
pub const MTPROTO_TRANSPORT_SCHEMA: &str =
    include_str!("../../../schemas/mtproto_transport.tl");

/// Embedded Canonical Layer-232 schema (`schemas/canonical_layer_232.tl`).
pub const CANONICAL_LAYER_232_SCHEMA: &str =
    include_str!("../../../schemas/canonical_layer_232.tl");

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SectionKind {
    Types,
    Functions,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TlField {
    pub name: String,
    pub flag_bit: Option<u8>,
    pub ty: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TlCombinator {
    pub section: SectionKind,
    pub name: String,
    pub constructor_id: u32,
    pub fields: Vec<TlField>,
    pub result_type: String,
}

#[derive(Debug, Clone, Default)]
pub struct TlSchema {
    pub combinators: Vec<TlCombinator>,
    by_id: HashMap<u32, usize>,
}

#[derive(Debug, thiserror::Error)]
pub enum SchemaError {
    #[error("malformed TL combinator at line {line}: {detail}")]
    MalformedLine { line: usize, detail: String },
    #[error("duplicate constructor id {id:#010x} ({first} vs {second})")]
    DuplicateConstructor {
        id: u32,
        first: String,
        second: String,
    },
}

/// Compute the official Telegram IEEE CRC32 constructor ID for a canonical TL
/// combinator line (e.g. `"ping ping_id:long = Pong;"` -> `0x7abe77ec`,
/// `"invokeWithLayer {X:Type} layer:int query:!X = X;"` -> `0xda9b0d0d`).
pub fn compute_tl_crc32(definition: &str) -> u32 {
    let trimmed = definition.trim().trim_end_matches(';').trim();
    let mut exact_tokens: Vec<String> = Vec::new();
    for (idx, raw_tok) in trimmed.split_whitespace().enumerate() {
        if idx == 0 {
            let base = raw_tok.split('#').next().unwrap_or(raw_tok);
            exact_tokens.push(base.to_string());
        } else {
            let cleaned: String = raw_tok
                .chars()
                .filter(|&c| c != '{' && c != '}' && c != '(' && c != ')')
                .collect();
            if !cleaned.is_empty() {
                exact_tokens.push(cleaned);
            }
        }
    }
    let normalized = exact_tokens.join(" ");
    crc32fast::hash(normalized.as_bytes())
}

impl TlSchema {
    /// Parse a `.tl` schema file into typed combinators indexed by 32-bit constructor ID.
    pub fn parse(src: &str) -> Result<Self, SchemaError> {
        let mut section = SectionKind::Types;
        let mut combinators = Vec::new();
        let mut by_id: HashMap<u32, usize> = HashMap::new();

        for (line_idx, raw_line) in src.lines().enumerate() {
            let line_no = line_idx + 1;
            let without_comment = raw_line.split("//").next().unwrap_or("").trim();
            if without_comment.is_empty() {
                continue;
            }
            if without_comment == "---types---" {
                section = SectionKind::Types;
                continue;
            }
            if without_comment == "---functions---" {
                section = SectionKind::Functions;
                continue;
            }
            let stmt = without_comment.trim_end_matches(';').trim();
            let Some((lhs, rhs)) = stmt.split_once('=') else {
                return Err(SchemaError::MalformedLine {
                    line: line_no,
                    detail: "missing '=' separator".into(),
                });
            };
            let result_type = rhs.trim().to_string();
            let mut parts = lhs.split_whitespace();
            let head = parts.next().ok_or_else(|| SchemaError::MalformedLine {
                line: line_no,
                detail: "empty combinator name".into(),
            })?;

            let (name, constructor_id) = if let Some((n, hex_id)) = head.split_once('#') {
                let id = u32::from_str_radix(hex_id, 16).map_err(|_| SchemaError::MalformedLine {
                    line: line_no,
                    detail: format!("invalid hex constructor id '{hex_id}'"),
                })?;
                (n.to_string(), id)
            } else {
                (head.to_string(), compute_tl_crc32(stmt))
            };

            let mut fields = Vec::new();
            for tok in parts {
                if tok.starts_with('{') && tok.ends_with('}') {
                    continue;
                }
                let Some((fname, ftype)) = tok.split_once(':') else {
                    return Err(SchemaError::MalformedLine {
                        line: line_no,
                        detail: format!("invalid field '{tok}'"),
                    });
                };
                let (flag_bit, clean_ty) = if let Some((flag_spec, inner_ty)) = ftype.split_once('?')
                {
                    let bit = flag_spec
                        .rsplit('.')
                        .next()
                        .and_then(|b| b.parse::<u8>().ok());
                    (bit, inner_ty.to_string())
                } else {
                    (None, ftype.to_string())
                };
                fields.push(TlField {
                    name: fname.to_string(),
                    flag_bit,
                    ty: clean_ty,
                });
            }

            if let Some(&prev_idx) = by_id.get(&constructor_id) {
                let prev: &TlCombinator = &combinators[prev_idx];
                return Err(SchemaError::DuplicateConstructor {
                    id: constructor_id,
                    first: prev.name.clone(),
                    second: name,
                });
            }

            let idx = combinators.len();
            combinators.push(TlCombinator {
                section,
                name,
                constructor_id,
                fields,
                result_type,
            });
            by_id.insert(constructor_id, idx);
        }

        Ok(Self {
            combinators,
            by_id,
        })
    }

    pub fn lookup(&self, constructor_id: u32) -> Option<&TlCombinator> {
        self.by_id.get(&constructor_id).map(|&i| &self.combinators[i])
    }
}

/// Client platform quirk profile detected from `initConnection`.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ClientQuirkProfile {
    Desktop,
    Android,
    Ios,
    Web,
}

impl ClientQuirkProfile {
    pub fn detect(device_model: &str, system_version: &str, app_version: &str) -> Self {
        let lower_sys = system_version.to_ascii_lowercase();
        let lower_dev = device_model.to_ascii_lowercase();
        let lower_app = app_version.to_ascii_lowercase();
        if lower_sys.contains("android") || lower_sys.starts_with("sdk ") {
            Self::Android
        } else if lower_sys.contains("ios") || lower_dev.contains("iphone") || lower_dev.contains("ipad") {
            Self::Ios
        } else if lower_app.contains("web") || lower_dev.contains("mozilla") || lower_dev.contains("chrome") {
            Self::Web
        } else {
            Self::Desktop
        }
    }
}

/// Multi-layer ingress/egress translation registry (`Layers 185, 200, 220, 232`).
#[derive(Debug, Clone)]
pub struct LayerAdapterRegistry {
    transport: TlSchema,
    canonical: TlSchema,
    legacy_to_canonical_rpc: HashMap<u32, (u16, u32)>,
}

impl Default for LayerAdapterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LayerAdapterRegistry {
    pub fn new() -> Self {
        let transport =
            TlSchema::parse(MTPROTO_TRANSPORT_SCHEMA).expect("valid mtproto_transport.tl");
        let canonical =
            TlSchema::parse(CANONICAL_LAYER_232_SCHEMA).expect("valid canonical_layer_232.tl");

        let mut legacy = HashMap::new();
        // Native tgnet C++ push registration (Layer 185+) -> canonical account.registerDevice
        legacy.insert(0x637e_a878, (185, 0xec86_017a));
        // Layer 185 messages.sendMessage#280d096f -> Layer 232 messages.sendMessage#983f9745
        legacy.insert(0x280d_096f, (185, 0x983f_9745));
        // Layer 200 updates.getDifference#25939651 -> Layer 232 updates.getDifference#19c2f763
        legacy.insert(0x2593_9651, (200, 0x19c2_f763));
        // Layer 220 contacts.resolveUsername#f93ccba3 -> Layer 232 contacts.resolveUsername#725afbbc
        legacy.insert(0xf93c_cba3, (220, 0x725a_fbbc));

        Self {
            transport,
            canonical,
            legacy_to_canonical_rpc: legacy,
        }
    }

    /// Resolve a human-readable method or constructor name for diagnostics and the live RPC sniffer.
    pub fn method_name(&self, constructor_id: u32) -> Option<&str> {
        if let Some(c) = self.canonical.lookup(constructor_id) {
            return Some(&c.name);
        }
        if let Some(c) = self.transport.lookup(constructor_id) {
            return Some(&c.name);
        }
        if let Some(&(_, canon_id)) = self.legacy_to_canonical_rpc.get(&constructor_id) {
            return self.canonical.lookup(canon_id).map(|c| c.name.as_str());
        }
        match constructor_id {
            0x637e_a878 => Some("account.registerDevice_tgnet"),
            0x8cef_c662 => Some("help.getAppUpdate"),
            0x3dc0_f114 => Some("help.getInviteText"),
            0xa4a9_5186 => Some("help.getSupport"),
            0x9cdf_08cd => Some("help.getTermsOfServiceUpdate"),
            0x20bb_fa2e => Some("help.getPromoData"),
            0x9da5_4231 => Some("help.getPremiumPromo"),
            0xc8d7_493e => Some("help.getPeerColors"),
            0xabc9_e4d8 => Some("help.getPeerProfileColors"),
            0x30ef_b928 => Some("langpack.getLanguages"),
            0xf2f2_330a => Some("langpack.getStrings"),
            0xefea_3803 => Some("langpack.getDifference"),
            0xcd98_4aa5 => Some("langpack.getLangPack"),
            _ => None,
        }
    }

    /// Translate an older-layer RPC payload into Canonical Layer 232 bytes when needed.
    pub fn upgrade_ingress_rpc<'a>(
        &self,
        _negotiated_layer: u16,
        buf: &'a [u8],
    ) -> Result<std::borrow::Cow<'a, [u8]>, TlError> {
        if buf.len() < 4 {
            return Err(TlError::UnexpectedEof {
                needed: 4,
                remaining: buf.len(),
            });
        }
        let ctor = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
        match ctor {
            // contacts.resolveUsername#f93ccba3 username:string -> Layer 232 #725afbbc flags:0 username:string
            0xf93c_cba3 => {
                let mut out = BytesMut::with_capacity(8 + buf.len());
                out.put_u32_le(0x725a_fbbc);
                out.put_i32_le(0); // flags = 0 (no referer)
                out.extend_from_slice(&buf[4..]);
                Ok(std::borrow::Cow::Owned(out.to_vec()))
            }
            // updates.getDifference#25939651 (Layer 200) -> #19c2f763 (same wire body)
            0x2593_9651 => {
                let mut out = Vec::with_capacity(buf.len());
                out.extend_from_slice(&0x19c2_f763u32.to_le_bytes());
                out.extend_from_slice(&buf[4..]);
                Ok(std::borrow::Cow::Owned(out))
            }
            _ => Ok(std::borrow::Cow::Borrowed(buf)),
        }
    }

    /// Adapt a Canonical Layer-232 `TL_user#b1b8cc83` constructor ID if an older
    /// client layer (`<= 227` or `<= 216`) requires an older `TL_user` header.
    pub fn adapt_user_constructor_for_layer(layer: u16, _quirk: ClientQuirkProfile) -> u32 {
        if layer < 217 {
            0x020b_1422 // TL_user_layer216
        } else if layer < 228 {
            0x3177_4388 // TL_user_layer227
        } else {
            0xb1b8_cc83 // Canonical Layer 232 TL_user
        }
    }

    pub const fn canonical_schema(&self) -> &TlSchema {
        &self.canonical
    }

    pub const fn transport_schema(&self) -> &TlSchema {
        &self.transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tl_crc32_matches_official_mtproto_vectors() {
        assert_eq!(compute_tl_crc32("ping ping_id:long = Pong;"), 0x7abe_77ec);
        assert_eq!(
            compute_tl_crc32("pong msg_id:long ping_id:long = Pong;"),
            0x3477_73c5
        );
        assert_eq!(compute_tl_crc32("boolTrue = Bool;"), 0x9972_75b5);
        assert_eq!(compute_tl_crc32("boolFalse = Bool;"), 0xbc79_9737);
        assert_eq!(
            compute_tl_crc32("req_pq_multi nonce:int128 = ResPQ;"),
            0xbe7e_8ef1
        );
        assert_eq!(
            compute_tl_crc32(
                "invokeWithLayer {X:Type} layer:int query:!X = X;"
            ),
            0xda9b_0d0d
        );
    }

    #[test]
    fn schemas_parse_without_duplicate_ids_and_resolve_methods() {
        let reg = LayerAdapterRegistry::new();
        assert!(reg.canonical_schema().combinators.len() >= 35);
        assert!(reg.transport_schema().combinators.len() >= 18);
        assert_eq!(reg.method_name(0xc4f9_186b), Some("help.getConfig"));
        assert_eq!(reg.method_name(0x983f_9745), Some("messages.sendMessage"));
        assert_eq!(reg.method_name(0x637e_a878), Some("account.registerDevice"));
    }

    #[test]
    fn layer_220_resolve_username_upgrades_to_layer_232() {
        let reg = LayerAdapterRegistry::new();
        let mut legacy = BytesMut::new();
        legacy.put_u32_le(0xf93c_cba3);
        legacy.extend_from_slice(&[5, b'a', b'l', b'i', b'c', b'e', 0, 0]);
        let upgraded = reg.upgrade_ingress_rpc(220, &legacy).unwrap();
        assert_eq!(
            u32::from_le_bytes(upgraded[0..4].try_into().unwrap()),
            0x725a_fbbc
        );
        assert_eq!(i32::from_le_bytes(upgraded[4..8].try_into().unwrap()), 0);
        assert_eq!(&upgraded[8..], &[5, b'a', b'l', b'i', b'c', b'e', 0, 0]);
    }
}

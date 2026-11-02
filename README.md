# ShuzaGram Server

A from-scratch MTProto 2.0 server (Rust), the backend counterpart to the
ShuzaGram Android client. Private, work in progress.

> Full design: [`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) · [`docs/MINDMAP.md`](docs/MINDMAP.md)

## Status

Phase 1 in progress — cryptographic foundation that account login is built on.

| Crate | What it does | State |
| :-- | :-- | :-- |
| `mtproto-crypto` | AES-256-IGE, MTProto 2.0 KDF, `auth_key_id`/`msg_key`, PQ factorization, DH-2048 | ✅ implemented + tested |
| `tl-core` | Zero-copy TL (de)serialization, Layer 232 types | ⏳ next |
| `gram-edge` | TCP/WS transport + unencrypted DH handshake (`req_pq` → `set_client_DH_params`) | ⏳ next |
| `gram-core` | `auth.sendCode` / `auth.signIn` / `auth.signUp`, session store | ⏳ next |

### The road to "login works"

1. ✅ **Crypto core** — the math the handshake and the encrypted session rely on.
2. **TL serialization** — encode/decode the handshake and API constructors.
3. **Edge + DH handshake** — a client negotiates an `auth_key` with the server.
4. **auth.sendCode / signIn** — a phone number logs in and gets a session.

## Build

```bash
cargo test -p mtproto-crypto          # run the crypto test suite
cargo clippy --workspace -- -D warnings
```

## License

GPL-2.0-only.

# ShuzaGram Server

A from-scratch MTProto 2.0 server (Rust), the backend counterpart to the
ShuzaGram Android client. Private, work in progress.

> Full design: [`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) · [`docs/MINDMAP.md`](docs/MINDMAP.md)

## Status

The DH handshake works end to end: a client and the server negotiate the same
2048-bit `auth_key` over a real TCP socket.

| Crate | What it does | State |
| :-- | :-- | :-- |
| `mtproto-crypto` | AES-256-IGE, MTProto 2.0 KDF, `auth_key_id`/`msg_key`, PQ factorization, DH-2048, RSA_PAD | ✅ implemented + tested |
| `tl-core` | TL wire (de)serialization (int/long/int128/int256/bytes/string/vector) | ✅ implemented + tested |
| `gram-edge` | TCP transport (abridged/intermediate) + unencrypted DH handshake (`req_pq` → `dh_gen_ok`) | ✅ implemented + tested |
| `gram-core` | `auth.sendCode` / `auth.signIn` / `auth.signUp`, encrypted session store | ⏳ next |

### The road to "login works"

1. ✅ **Crypto core** — the math the handshake and the encrypted session rely on.
2. ✅ **TL serialization** — encode/decode the handshake and API constructors.
3. ✅ **Edge + DH handshake** — client and server negotiate a shared `auth_key`.
4. ⏳ **auth.sendCode / signIn** — a phone number logs in and gets a session.

Run the gateway: `EDGE_ADDR=0.0.0.0:8443 cargo run --release -p gram-edge`.
It prints the RSA fingerprint the client must be configured to trust.

## Build

```bash
cargo test -p mtproto-crypto          # run the crypto test suite
cargo clippy --workspace -- -D warnings
```

## License

GPL-2.0-only.

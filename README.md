# ShuzaGram Server

A from-scratch MTProto 2.0 server (Rust), the backend counterpart to the
ShuzaGram Android client. Private, work in progress.

> Full design: [`docs/MASTER_PLAN.md`](docs/MASTER_PLAN.md) · [`docs/MINDMAP.md`](docs/MINDMAP.md)

## Status

**A phone number logs in over a real TCP socket.** The reference client runs
the DH handshake, then sends an encrypted `auth.sendCode` and `auth.signIn`,
and the server replies with `auth.authorization`. Proven end to end by
`tests/tcp_login.rs`.

| Crate | What it does | State |
| :-- | :-- | :-- |
| `mtproto-crypto` | AES-256-IGE, MTProto 2.0 KDF, `auth_key_id`/`msg_key`, PQ factorization, DH-2048, RSA_PAD | ✅ implemented + tested |
| `tl-core` | TL wire (de)serialization (int/long/int128/int256/bytes/string/vector) | ✅ implemented + tested |
| `gram-edge` | TCP transport + DH handshake + authenticated session loop + reference client | ✅ implemented + tested |
| `gram-core` | encrypted session, RPC routing, `auth.sendCode` / `auth.signIn`, in-memory user store | ✅ implemented + tested |

### The road to "login works"

1. ✅ **Crypto core** — the math the handshake and the encrypted session rely on.
2. ✅ **TL serialization** — encode/decode the handshake and API constructors.
3. ✅ **Edge + DH handshake** — client and server negotiate a shared `auth_key`.
4. ✅ **auth.sendCode / signIn** — a phone number logs in and gets a user.

Run the gateway: `EDGE_ADDR=0.0.0.0:8443 cargo run --release -p gram-edge`.
It prints the RSA fingerprint the client must be configured to trust.

> **Next (step 4b): stock-client interop.** The service/envelope layer
> (handshake, encrypted messages, `msg_container`, `rpc_result`, `ping`) uses
> the canonical MTProto ids. The high-level `auth.*` / `user` *bodies* are
> currently a minimal self-consistent encoding; their exact Layer-232 wire
> layout, plus `help.getConfig`, must be reconciled with the canonical schema
> (and the ShuzaGram client pointed at this server's address + RSA key) before
> the stock app can log in.

## Build

```bash
cargo test -p mtproto-crypto          # run the crypto test suite
cargo clippy --workspace -- -D warnings
```

## License

GPL-2.0-only.

# shuzagram-server (Multi-DC MTProto 2.0 Rust Server & Control Plane)

## 1. Core Workspace & Toolchain
### 1.1 Rust Workspace (`Edition 2024`)
#### 1.1.1 Protocol & Crypto Crates
##### `crates/mtproto-crypto`
- In-place AES-256-IGE (`aesni` / `neon` register pipeline)
- MTProto 2.0 KDF (`Direction::ClientToServer x=0`, `ServerToClient x=8`)
- RSA-2048 OAEP & legacy PKCS padding + SHA1 key fingerprint
- Diffie-Hellman 2048-bit safe prime `p`, generator `g`, bounds `2^1984 < g_b < p - 2^1984`
- Obfuscated2 64-byte header (`AES-256-CTR` rx/tx key derivation)
- Fake-TLS (`ee`/`dd` secret HMAC-SHA256 ClientHello + SNI verification)
##### `crates/tl-compiler`
- Build-time `.tl` lexer & AST parser (`canonical_layer_232.tl` + `mtproto_transport.tl`)
- CRC32 constructor ID validator & bitmask flag layout calculator
- Per-layer delta profile codegen (`schemas/profiles/layer_170..231.json`)
##### `crates/tl-core`
- Zero-copy traits (`TlRead<'a>`, `TlWrite`, `TlBytes<'a>`, `TlStr<'a>`, `TlSliceIter<'a, T>`)
- Canonical Layer 232 domain-mapped TL types (`#[repr(C)]` fixed headers)
- `LayerAdapterRegistry` ingress/egress translator + client quirk profiles (`Desktop`, `Android`, `Ios`, `Web`)
- Recursive RPC wrapper unwrapping (`invokeWithLayer`, `initConnection`, `invokeAfterMsg`, max depth 8)
##### `crates/gram-proto`
- `tonic` + `prost` mTLS gRPC stubs from `proto/federation.proto`
- NATS JetStream subject router & binary envelope codecs
#### 1.1.2 Runtime & Service Crates
##### `crates/gram-edge` (Stateless MTProto Gateway)
- `monoio` (`io_uring` thread-per-core) & `tokio` listeners
- 6 transports: Abridged (`0xef`), Intermediate (`0xeeeeeeee`), Padded (`0xdddddddd`), Full TCP (`CRC32`), HTTP, WebSocket (`/apiws`)
- Unencrypted DH handshake (`req_pq_multi` -> `req_DH_params` -> `set_client_DH_params`)
- Session multiplexing, `msg_container`, `gzip_packed`, `ping_delay_disconnect`, `get_future_salts`
- L1 DashMap + L2 Redis `server_salt` 3-slot window & 128-bit `msg_id` replay bitmap
- Per-IP and per-AuthKey admission byte & inflight RPC budgets
##### `crates/gram-core` (Stateful DC Router & Domain Workers)
- Home-DC enforcement (`PHONE_MIGRATE_X`, `USER_MIGRATE_X`, `FILE_MIGRATE_X` 303 errors)
- Cross-DC `auth.exportAuthorization` & `auth.importAuthorization` HMAC ticket engine
- 49 modular domain services migrated from `gramsrv`
##### `crates/gram-egress` (Real-Time Update & Push Dispatcher)
- Session `seq` tracker & layer-aware `Updates` serializer
- Fast-path `updates.getDifference` & `updates.getChannelDifference`
- Background push adapters (FCM, APNs, UnifiedPush, WebPush)
##### `crates/gram-media` (Distributed Multi-DC File Vault)
- `upload.saveFilePart`, `upload.saveBigFilePart`, `upload.getFile`, `upload.getCdnFile`
- 28-byte HMAC-SHA256 `file_reference` verifier (`storage_dc_id` + 24h freshness)
- S3/MinIO multi-DC buckets (`gram-vault-dc1..5`) + local NVMe read-through tier
##### `crates/gram-sfu` (Voice, Video & Group Calls)
- `webrtc-rs` SFU media router + embedded STUN/TURN (`12399`/`12400` UDP)
- 1:1 E2EE call signaling (`phone.requestCall`, `acceptCall`, `confirmCall`) & `groupCalls` / RTMP livestreams
##### `crates/gram-botapi` (HTTP Bot API Server)
- Port `8081` JSON/multipart HTTP gateway bridged to `gram-core` bot sessions
##### `crates/gram-admin` & `crates/gram-loadtest`
- `axum` Control Plane API (`2599`), RBAC, Argon2id auth, WebSocket telemetry & lock-free RPC sniffer
- Synthetic 100k-connection Multi-DC load & migration chaos harness
### 1.2 Frontend Workspace (`web/admin-ui`)
#### Next.js 15 App Router + TypeScript + TailwindCSS + shadcn/ui
- Single-source navigation & permission registry (`src/config/nav.ts`)
- Interactive Multi-DC cluster graph (`React Flow`)
- Real-time WebSocket charts & live TL packet stream table
- Tri-lingual localization (`en`, `ru`, `zh`)

## 2. Multi-DC Topology & Federation (`DC-1` .. `DC-5+`)
### 2.1 Data Center Roles
#### `DC-1` — Americas / Bootstrap Entry (Users Shard 1, Channels Shard 1, Vault 1)
#### `DC-2` — Europe / CIS Primary (Users Shard 2, Channels Shard 2, Vault 2)
#### `DC-3` — Dedicated High-Throughput Media & Collectible Assets Vault
#### `DC-4` — Europe West High-Density Shard (Users Shard 4, Supergroups Shard 4)
#### `DC-5` — APAC / Singapore Shard (Users Shard 5, Channels Shard 5, Vault 5)
#### `DC-203+` — Stateless Edge CDN Nodes (`cdn = true`)
### 2.2 Federation gRPC Services (`proto/federation.proto`)
#### `CrossDcRelay`
- `DeliverDirectMessage` (idempotent cross-DC outbox -> remote inbox + `pts`)
- `DeliverMessageEdit` & `DeliverMessageDelete`
- `DeliverReadHistory` & `DeliverTypingAction`
- `ResolvePeerProfile` (`EntityMinSnapshot` + canonical TL bytes)
#### `AuthFederation`
- `VerifyExportedAuth` (76-byte `SignedTicketBytes` verification)
- `NotifyRemoteSessionTerminated` (global AuthKey revocation)
- `MigrateUserHomeDc` (`zstd` atomic bundle transfer + `dc_epoch` bump)
#### `ChannelFederation`
- `PublishChannelMessage` (routes to channel's `origin_dc_id`)
- `FetchChannelDifference`
- `MutateChannelMembership` + NATS `fed.channel.{id}.updates` fan-out
#### `MediaRouter` & `AdminControl`
- `StreamFileChunk`, `VerifyMediaReference`
- `GetNodeHealth`, `PushClusterConfig`, `SetRpcSnifferFilter`, `ForceDisconnectAuthKey`
### 2.3 State Synchronization Invariants
#### Account `pts` — Scoped `(home_dc_id, user_id)`, contiguous via `alloc_pts_and_append.lua` + 2,048-entry Redis ZSET ring
#### Secret Chat `qts` — Scoped `(home_dc_id, user_id)`, acknowledged via `messages.receivedQueue`
#### Channel `channel_pts` — Scoped `(origin_dc_id, channel_id)`, $O(1)$ write + NATS per-DC subscriber fan-out
#### Session `seq` — Scoped `(edge_dc_id, auth_key_id, session_id)` for ordered container delivery

## 3. Partitioned Storage Layer
### 3.1 PostgreSQL 17 (`PARTITION BY LIST (dc_id)`)
#### Cluster & Crypto (`0001`)
- `dc_clusters` (`dc_id`, `status`, `endpoints_json`)
- `rsa_keys` (`fingerprint`, `public_pem`, `private_pem_enc`, `status`)
- `dh_configs` (`version`, `prime_p`, `generator_g`, `is_current`)
#### Routing & Users (`0002`)
- `global_directory_routing` (`lookup_kind`, `lookup_key`, `entity_id`, `home_dc_id`, `dc_epoch`)
- `users` (`dc_id`, `user_id`, `flags_bitmask`, `password_srp_json`, `pts`, `qts`)
#### AuthKeys & Authorizations (`0003`)
- `auth_keys` (`dc_id`, `auth_key_id`, `auth_key_bytes`, `bound_user_id`, `user_home_dc_id`, `binding_mode`)
- `user_authorizations` (`dc_id`, `user_id`, `session_hash`, `client_layer`, `ip_address`, `edge_node_id`)
#### Dialogs, Messages & Updates (`0004`)
- `dialogs` (`dc_id`, `user_id`, `peer_kind`, `peer_id`, `top_message_id`, `unread_count`, `pts_checkpoint`)
- `messages` (`dc_id`, `owner_user_id`, `msg_id`, `random_id`, `message_text`, `media_tl`, `ttl_period`)
- `pts_updates` (`dc_id`, `user_id`, `pts`, `pts_count`, `update_tl`)
#### Channels & Media (`0005`–`0006`)
- `channels` (`origin_dc_id`, `channel_id`, `flags_bitmask`, `channel_pts`)
- `channel_pts_updates` (`origin_dc_id`, `channel_id`, `pts`, `update_tl`)
- `media_blobs` (`storage_dc_id`, `file_id`, `volume_id`, `s3_bucket`, `s3_object_key`, `sha256_digest`)
#### Economy & Admin (`0007`–`0008`)
- `stars_wallets` & `stars_ledger` (ACID double-checked subunit balances & idempotency keys)
- `gifts_catalog` & `user_gifts` (limited supply, serials, upgrade models/backdrops/symbols, marketplace)
- `virtual_numbers` (`+888` anonymous numbers bound to `assigned_dc_id`)
- `admin_operators` & `admin_audit_log`
### 3.2 Redis / Dragonfly Atomic State
#### `validate_salt_and_msgid.lua` — Salt window + 128-bit replay bitmap
#### `alloc_pts_and_append.lua` — Atomic `INCRBY` + bounded ZSET delta ring
#### `alloc_channel_pts.lua` — Atomic channel `pts` + NATS publish trigger
#### `consume_export_auth.lua` — Idempotent cross-DC ticket verification & AuthKey binding

## 4. Domain & TL Handler Groups (49 Modules in `gram-core`)
### 4.1 Identity, Auth & Security
#### `auth` & `authdiagnostics` — `sendCode`, `signIn`, `signUp`, `logOut`, `export/importAuthorization`, QR login
#### `passkey` & `telegramlogin` — WebAuthn passkeys & OIDC widget login
#### `account` & `privacy` — 2FA SRP-6a, sessions, TTL self-destruct, privacy rules, global notifications
#### `users`, `userprojection`, `contacts`, `usernames` — Profiles, contact sync, collectible `@usernames`
#### `verification`, `botverification`, `rating`, `systemidentity` — Verified badges, account trust rating, official system peer
### 4.2 Messaging, Social & Real-Time
#### `dialogs`, `chatlists`, `peerview`, `readmodel` — Folders, pinned dialogs, unread counters, read-model projections
#### `messages`, `ephemeral`, `welcomemessages` — Rich text entities, albums, replies, forwards, View-Once/TTL, business welcome
#### `updates` — `getState`, `getDifference`, `getChannelDifference`, gap recovery
#### `channels`, `broadcast`, `communities` — Megagroups, forum topics, broadcast channels, linked discussion groups
#### `secretchat` — E2EE DH chat negotiation & `qts` encrypted queue
#### `polls`, `stories`, `themes`, `langpack`, `help` — Polls/quizzes, 24h stories, cloud themes, localization packs, dynamic `DcOption` config
### 4.3 Media, Voice/Video & Bots
#### `files` — Multi-DC upload/download, photo sizes, documents, stickers, GIFs
#### `phone`, `groupcalls`, `livestream` — 1:1 calls, group voice/video rooms, RTMP ingest
#### `bots`, `autosubscribe`, `clienttelemetry`, `maintenance`, `moderation` — Inline/callback bots, Mini-Apps, anti-abuse, maintenance mode
#### `ai`, `transcription`, `translation` — Optional remote webhook adapters (strictly offloaded to external AI nodes, disabled locally)
### 4.4 Economy, Stars & Collectibles
#### `stars`, `wallet`, `donations`, `premium` — Stars subunit ledger, invoices, subscriptions, creator tips
#### `stargifts` & `giftpack` — Official & custom Collectible Gifts, `.tgs` animations, rarity upgrades, profile pinning, transfers

## 5. Control Plane (`gram-admin` + `web/admin-ui`)
### 5.1 Cluster & Multi-DC Topology (`/topology/*`)
#### `/topology/map` (`topology.read` / `topology.drain`) — Live React Flow DC graph, CPU/RAM, session counts, inter-DC RTT
#### `/topology/dc-config` (`topology.write`) — Dynamic `DcOption` editor + live `updateConfig` broadcast
#### `/topology/crypto` (`crypto.read` / `crypto.rotate`) — RSA-2048 key ring, DH prime rotation, FakeTLS secrets
### 5.2 Accounts, Sessions & Moderation (`/accounts/*`)
#### `/accounts/directory` (`accounts.read` / `accounts.moderate` / `accounts.badges`) — Search & badge/restriction controls
#### `/accounts/sessions` (`sessions.read` / `sessions.terminate`) — Active AuthKey explorer & instant Edge disconnect
#### `/accounts/migrations` (`accounts.migrate_dc`) — Live one-click `DC-X -> DC-Y` user state migration
### 5.3 Economy, Stars & Collectibles (`/economy/*`)
#### `/economy/stars` (`economy.stars.read` / `economy.stars.mint`) — Mint/burn Stars, commission config, ledger explorer, giveaway box
#### `/economy/gifts` (`economy.gifts.read` / `economy.gifts.write`) — Collectible NFT Gifts studio, `.tgs` uploader, upgrade pools, withdrawal queue
#### `/economy/registry` (`economy.registry.read` / `economy.registry.assign`) — `+888` anonymous numbers & collectible `@usernames`
### 5.4 Protocol Debugger & Audit (`/debug/*`, `/system/*`)
#### `/debug/sniffer` (`debug.sniffer.read` / `debug.sniffer.capture`) — Lock-free WebSocket live TL RPC inspector
#### `/debug/layers` (`debug.layers.read` / `debug.layers.write`) — Connected client layer histogram & downgrade rules
#### `/system/operators` (`system.audit.read` / `system.operators.manage`) — Operator RBAC matrix & immutable diff audit log

## 6. Six-Phase Execution Roadmap
### Phase 1 — Workspace, `mtproto-crypto` (SIMD AES-IGE, DH-2048, FakeTLS) & `tl-compiler`/`tl-core` (Layer 232)
### Phase 2 — `gram-edge` Zero-Copy Multi-Transport Gateway & Auth Handshake
### Phase 3 — `gram-store` (PG17 Partitioned DDL + Redis Lua) & Single-DC `gram-core` + `gram-egress` MVP
### Phase 4 — Multi-DC Federation (`DC-1..DC-5+`, `*_MIGRATE_X`, `export/importAuthorization`, `tonic` + NATS)
### Phase 5 — `gram-media` S3 Vault, `gram-sfu` Calls, `gram-botapi`, Stars & Collectible Gifts Engine
### Phase 6 — `gram-admin` + Next.js 15 Control Panel, Live DC Migration & 100k-Session Load Gate

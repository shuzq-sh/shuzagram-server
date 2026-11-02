//! `gram-store`: Storage engine for ShuzaGram Server.
//!
//! Exports:
//! - Canonical PostgreSQL 17 partitioned DDL migrations (`MIGRATIONS`: `0001..0008.up.sql`)
//! - Atomic Redis Lua scripts (`ALLOC_PTS_AND_APPEND_LUA`, `CONSUME_EXPORT_AUTH_LUA`)
//! - Self-contained ACID SQLite WAL engine ([`AcidStore`]) that runs with zero
//!   external daemons (ideal for standalone VPS nodes like `149.56.212.222` as
//!   well as multi-DC tests) while enforcing strict `pts` monotonicity, random_id
//!   idempotency, Stars double-entry invariants, and Collectible Gift supply caps.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

/// Canonical PostgreSQL 17 partitioned DDL migrations (`migrations/0001..0008.up.sql`).
pub const MIGRATIONS: &[(&str, &str)] = &[
    (
        "0001_cluster_and_crypto.up.sql",
        include_str!("../../../migrations/0001_cluster_and_crypto.up.sql"),
    ),
    (
        "0002_users_and_routing.up.sql",
        include_str!("../../../migrations/0002_users_and_routing.up.sql"),
    ),
    (
        "0003_auth_keys_and_sessions.up.sql",
        include_str!("../../../migrations/0003_auth_keys_and_sessions.up.sql"),
    ),
    (
        "0004_dialogs_messages_updates.up.sql",
        include_str!("../../../migrations/0004_dialogs_messages_updates.up.sql"),
    ),
    (
        "0005_channels_and_forums.up.sql",
        include_str!("../../../migrations/0005_channels_and_forums.up.sql"),
    ),
    (
        "0006_media_volumes.up.sql",
        include_str!("../../../migrations/0006_media_volumes.up.sql"),
    ),
    (
        "0007_economy_stars_gifts.up.sql",
        include_str!("../../../migrations/0007_economy_stars_gifts.up.sql"),
    ),
    (
        "0008_admin_rbac_audit.up.sql",
        include_str!("../../../migrations/0008_admin_rbac_audit.up.sql"),
    ),
];

/// Atomic Redis Lua script allocating `pts` and appending to `pts:ring:{dc}:{uid}` ZSET.
pub const ALLOC_PTS_AND_APPEND_LUA: &str =
    include_str!("../../../lua/alloc_pts_and_append.lua");

/// Atomic Redis Lua script consuming single-use cross-DC exported auth tickets.
pub const CONSUME_EXPORT_AUTH_LUA: &str =
    include_str!("../../../lua/consume_export_auth.lua");

pub const PEER_USER: i32 = 1;
pub const PEER_CHAT: i32 = 2;
pub const PEER_CHANNEL: i32 = 3;

/// `pts_updates.update_kind` discriminants.
pub const PTS_KIND_NEW_MESSAGE: i32 = 1;
pub const PTS_KIND_EDIT_MESSAGE: i32 = 2;
pub const PTS_KIND_DELETE_MESSAGES: i32 = 3;
pub const PTS_KIND_READ_INBOX: i32 = 4;
pub const PTS_KIND_READ_OUTBOX: i32 = 5;

/// User badge bitmask constants (`users.flags_bitmask`).
pub const USER_FLAG_VERIFIED: i64 = 1 << 0;
pub const USER_FLAG_PREMIUM: i64 = 1 << 1;
pub const USER_FLAG_SCAM: i64 = 1 << 2;
pub const USER_FLAG_FAKE: i64 = 1 << 3;
pub const USER_FLAG_BOT: i64 = 1 << 4;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("username invalid")]
    UsernameInvalid,
    #[error("username occupied")]
    UsernameOccupied,
    #[error("entity not found")]
    NotFound,
    #[error("permission denied")]
    PermissionDenied,
    #[error("insufficient stars balance")]
    InsufficientBalance,
    #[error("gift sold out")]
    SoldOut,
}

#[derive(Debug, Clone)]
pub struct UserRow {
    pub user_id: i64,
    pub home_dc_id: i32,
    pub dc_epoch: i64,
    pub access_hash: i64,
    pub phone: String,
    pub username: Option<String>,
    pub first_name: String,
    pub last_name: String,
    pub bio: String,
    pub flags_bitmask: i64,
    pub pts: i32,
    pub qts: i32,
    pub photo_id: Option<i64>,
    pub photo_dc_id: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct DialogRow {
    pub user_id: i64,
    pub peer_kind: i32,
    pub peer_id: i64,
    pub top_message_id: i32,
    pub read_inbox_max_id: i32,
    pub read_outbox_max_id: i32,
    pub unread_count: i32,
    pub pinned: bool,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct MessageRow {
    pub owner_user_id: i64,
    pub msg_id: i32,
    pub peer_kind: i32,
    pub peer_id: i64,
    pub sender_user_id: i64,
    pub random_id: i64,
    pub is_out: bool,
    pub date_unix: i32,
    pub edit_date_unix: Option<i32>,
    pub reply_to_msg_id: Option<i32>,
    pub message_text: String,
    pub media_tl: Option<Vec<u8>>,
    pub entities_tl: Option<Vec<u8>>,
    pub ttl_period: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct DirectDeliveryOutcome {
    pub deduplicated: bool,
    pub sender_msg: MessageRow,
    pub sender_pts: i32,
    pub recipient_msg: Option<(MessageRow, i32)>,
}

#[derive(Debug, Clone)]
pub struct GroupDeliveryOutcome {
    pub chat: ChatRow,
    pub sender_msg: MessageRow,
    pub sender_pts: i32,
    pub member_deliveries: Vec<(i64, MessageRow, i32)>,
}

#[derive(Debug, Clone)]
pub struct PtsEventRow {
    pub pts: i32,
    pub pts_count: i32,
    pub date_unix: i32,
    pub update_kind: i32,
    pub msg_id: i32,
    pub peer_kind: i32,
    pub peer_id: i64,
    pub extra_i32: i32,
}

#[derive(Debug, Clone)]
pub struct ChatRow {
    pub chat_id: i64,
    pub creator_id: i64,
    pub title: String,
    pub date_unix: i32,
    pub version: i32,
    pub participants_count: i32,
}

#[derive(Debug, Clone)]
pub struct ChannelRow {
    pub channel_id: i64,
    pub origin_dc_id: i32,
    pub creator_id: i64,
    pub access_hash: i64,
    pub title: String,
    pub username: Option<String>,
    pub about: String,
    pub is_broadcast: bool,
    pub is_megagroup: bool,
    pub is_forum: bool,
    pub participants_count: i32,
    pub channel_pts: i32,
    pub date_unix: i32,
}

#[derive(Debug, Clone)]
pub struct ChannelMessageDelivery {
    pub channel: ChannelRow,
    pub msg: MessageRow,
    pub channel_pts: i32,
    pub subscriber_ids: Vec<i64>,
}

#[derive(Debug, Clone)]
pub struct MediaBlobRow {
    pub file_id: i64,
    pub storage_dc_id: i32,
    pub access_hash: i64,
    pub owner_user_id: i64,
    pub mime_type: String,
    pub file_name: String,
    pub byte_size: i64,
    pub sha256_hex: String,
    pub data_bytes: Vec<u8>,
    pub created_at: i32,
}

#[derive(Debug, Clone)]
pub struct StarsWalletRow {
    pub user_id: i64,
    pub balance_units: i64,
    pub lifetime_minted: i64,
    pub lifetime_spent: i64,
}

#[derive(Debug, Clone)]
pub struct StarsTxRow {
    pub tx_id: String,
    pub user_id: i64,
    pub counterparty_id: Option<i64>,
    pub tx_kind: String,
    pub delta_units: i64,
    pub balance_after: i64,
    pub title: String,
    pub created_at: i32,
}

#[derive(Debug, Clone)]
pub struct GiftCatalogRow {
    pub gift_id: i64,
    pub slug_prefix: String,
    pub title: String,
    pub star_price_units: i64,
    pub upgrade_price_units: i64,
    pub convert_units: i64,
    pub total_supply: Option<i32>,
    pub minted_count: i32,
    pub is_limited: bool,
    pub is_upgradeable: bool,
}

#[derive(Debug, Clone)]
pub struct UserGiftRow {
    pub instance_id: i64,
    pub gift_id: i64,
    pub owner_user_id: i64,
    pub sender_user_id: Option<i64>,
    pub serial_number: Option<i32>,
    pub collectible_slug: Option<String>,
    pub is_upgraded: bool,
    pub message: String,
    pub minted_at: i32,
}

#[derive(Debug, Clone)]
pub struct VirtualNumberRow {
    pub phone_digits: String,
    pub owner_user_id: Option<i64>,
    pub assigned_dc_id: i32,
    pub price_units: i64,
    pub is_locked: bool,
    pub issued_at: i32,
}

#[derive(Debug, Clone)]
pub struct EditMessageOutcome {
    pub actor_msg: MessageRow,
    pub actor_pts: i32,
    pub peer_updated: Option<(MessageRow, i32)>,
}

#[derive(Debug, Clone)]
pub struct PeerDeleteBatch {
    pub user_id: i64,
    pub msg_ids: Vec<i32>,
    pub pts: i32,
}

#[derive(Debug, Clone)]
pub struct DeleteMessagesOutcome {
    pub actor_pts: i32,
    pub deleted_count: i32,
    pub peer_batches: Vec<PeerDeleteBatch>,
}

#[derive(Debug, Clone)]
pub struct ReadHistoryOutcome {
    pub reader_pts: i32,
    pub outbox_peer: Option<(i64, i32, i32)>,
}

#[derive(Debug, Clone)]
pub struct AuditLogRow {
    pub audit_id: i64,
    pub operator_name: String,
    pub action_code: String,
    pub target_entity: String,
    pub detail_json: String,
    pub created_at: i32,
}

/// Embedded ACID SQLite WAL store backing `gram-core`, `gram-media`, and `gram-admin`.
pub struct AcidStore {
    conn: Mutex<Connection>,
    default_dc_id: i32,
}

impl AcidStore {
    /// Open an in-memory ACID SQLite database (for unit and integration tests).
    pub fn open_in_memory(default_dc_id: i32) -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let s = Self {
            conn: Mutex::new(conn),
            default_dc_id,
        };
        s.init_schema()?;
        Ok(s)
    }

    /// Open a persistent ACID SQLite WAL database on disk.
    pub fn open_path(path: impl AsRef<Path>, default_dc_id: i32) -> Result<Self, StoreError> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let conn = Connection::open(path)?;
        let s = Self {
            conn: Mutex::new(conn),
            default_dc_id,
        };
        s.init_schema()?;
        Ok(s)
    }

    fn init_schema(&self) -> Result<(), StoreError> {
        let db = self.conn.lock().unwrap();
        db.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS users (
                user_id         INTEGER PRIMARY KEY,
                home_dc_id      INTEGER NOT NULL DEFAULT 2,
                dc_epoch        INTEGER NOT NULL DEFAULT 1,
                access_hash     INTEGER NOT NULL,
                phone           TEXT NOT NULL UNIQUE,
                username        TEXT,
                username_lower  TEXT UNIQUE,
                first_name      TEXT NOT NULL DEFAULT '',
                last_name       TEXT NOT NULL DEFAULT '',
                bio             TEXT NOT NULL DEFAULT '',
                flags_bitmask   INTEGER NOT NULL DEFAULT 0,
                pts             INTEGER NOT NULL DEFAULT 1,
                qts             INTEGER NOT NULL DEFAULT 0,
                next_msg_id     INTEGER NOT NULL DEFAULT 1,
                photo_id        INTEGER,
                photo_dc_id     INTEGER,
                created_at      INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS key_bindings (
                auth_key_id     INTEGER PRIMARY KEY,
                user_id         INTEGER NOT NULL,
                home_dc_id      INTEGER NOT NULL DEFAULT 2,
                binding_mode    INTEGER NOT NULL DEFAULT 1,
                dc_epoch        INTEGER NOT NULL DEFAULT 1,
                updated_at      INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS contacts (
                owner_user_id   INTEGER NOT NULL,
                contact_user_id INTEGER NOT NULL,
                first_name      TEXT NOT NULL DEFAULT '',
                last_name       TEXT NOT NULL DEFAULT '',
                phone           TEXT NOT NULL DEFAULT '',
                created_at      INTEGER NOT NULL,
                PRIMARY KEY (owner_user_id, contact_user_id)
            );

            CREATE TABLE IF NOT EXISTS dialogs (
                user_id             INTEGER NOT NULL,
                peer_kind           INTEGER NOT NULL,
                peer_id             INTEGER NOT NULL,
                top_message_id      INTEGER NOT NULL DEFAULT 0,
                read_inbox_max_id   INTEGER NOT NULL DEFAULT 0,
                read_outbox_max_id  INTEGER NOT NULL DEFAULT 0,
                unread_count        INTEGER NOT NULL DEFAULT 0,
                pinned              INTEGER NOT NULL DEFAULT 0,
                updated_at          INTEGER NOT NULL,
                PRIMARY KEY (user_id, peer_kind, peer_id)
            );

            CREATE TABLE IF NOT EXISTS messages (
                owner_user_id   INTEGER NOT NULL,
                msg_id          INTEGER NOT NULL,
                peer_kind       INTEGER NOT NULL,
                peer_id         INTEGER NOT NULL,
                sender_user_id  INTEGER NOT NULL,
                random_id       INTEGER NOT NULL DEFAULT 0,
                counterpart_uid INTEGER,
                counterpart_mid INTEGER,
                is_out          INTEGER NOT NULL,
                date_unix       INTEGER NOT NULL,
                edit_date_unix  INTEGER,
                reply_to_msg_id INTEGER,
                message_text    TEXT NOT NULL DEFAULT '',
                media_tl        BLOB,
                entities_tl     BLOB,
                ttl_period      INTEGER,
                deleted         INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (owner_user_id, msg_id)
            );
            CREATE INDEX IF NOT EXISTS idx_msg_peer ON messages (owner_user_id, peer_kind, peer_id, msg_id DESC);
            CREATE INDEX IF NOT EXISTS idx_msg_rnd  ON messages (owner_user_id, random_id) WHERE random_id != 0;

            CREATE TABLE IF NOT EXISTS pts_updates (
                user_id         INTEGER NOT NULL,
                pts             INTEGER NOT NULL,
                pts_count       INTEGER NOT NULL DEFAULT 1,
                date_unix       INTEGER NOT NULL,
                update_kind     INTEGER NOT NULL,
                msg_id          INTEGER NOT NULL DEFAULT 0,
                peer_kind       INTEGER NOT NULL DEFAULT 0,
                peer_id         INTEGER NOT NULL DEFAULT 0,
                extra_i32       INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, pts)
            );

            CREATE TABLE IF NOT EXISTS chats (
                chat_id         INTEGER PRIMARY KEY,
                creator_id      INTEGER NOT NULL,
                title           TEXT NOT NULL,
                date_unix       INTEGER NOT NULL,
                version         INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS chat_members (
                chat_id         INTEGER NOT NULL,
                user_id         INTEGER NOT NULL,
                joined_at       INTEGER NOT NULL,
                PRIMARY KEY (chat_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS channels (
                channel_id          INTEGER PRIMARY KEY,
                origin_dc_id        INTEGER NOT NULL DEFAULT 2,
                creator_id          INTEGER NOT NULL,
                access_hash         INTEGER NOT NULL,
                title               TEXT NOT NULL,
                username            TEXT,
                username_lower      TEXT UNIQUE,
                about               TEXT NOT NULL DEFAULT '',
                is_broadcast        INTEGER NOT NULL DEFAULT 0,
                is_megagroup        INTEGER NOT NULL DEFAULT 1,
                is_forum            INTEGER NOT NULL DEFAULT 0,
                participants_count  INTEGER NOT NULL DEFAULT 1,
                channel_pts         INTEGER NOT NULL DEFAULT 1,
                next_msg_id         INTEGER NOT NULL DEFAULT 1,
                date_unix           INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS channel_members (
                channel_id      INTEGER NOT NULL,
                user_id         INTEGER NOT NULL,
                is_admin        INTEGER NOT NULL DEFAULT 0,
                read_max_id     INTEGER NOT NULL DEFAULT 0,
                joined_at       INTEGER NOT NULL,
                PRIMARY KEY (channel_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS channel_messages (
                channel_id      INTEGER NOT NULL,
                msg_id          INTEGER NOT NULL,
                sender_user_id  INTEGER NOT NULL,
                random_id       INTEGER NOT NULL DEFAULT 0,
                date_unix       INTEGER NOT NULL,
                edit_date_unix  INTEGER,
                reply_to_msg_id INTEGER,
                message_text    TEXT NOT NULL DEFAULT '',
                media_tl        BLOB,
                entities_tl     BLOB,
                pts             INTEGER NOT NULL,
                deleted         INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (channel_id, msg_id)
            );

            CREATE TABLE IF NOT EXISTS media_blobs (
                file_id         INTEGER PRIMARY KEY,
                storage_dc_id   INTEGER NOT NULL,
                access_hash     INTEGER NOT NULL,
                owner_user_id   INTEGER NOT NULL,
                mime_type       TEXT NOT NULL,
                file_name       TEXT NOT NULL DEFAULT '',
                byte_size       INTEGER NOT NULL,
                sha256_hex      TEXT NOT NULL,
                data_bytes      BLOB NOT NULL,
                created_at      INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS stars_wallets (
                user_id         INTEGER PRIMARY KEY,
                balance_units   INTEGER NOT NULL DEFAULT 0 CHECK (balance_units >= 0),
                lifetime_minted INTEGER NOT NULL DEFAULT 0,
                lifetime_spent  INTEGER NOT NULL DEFAULT 0,
                updated_at      INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS stars_ledger (
                tx_id           TEXT PRIMARY KEY,
                idempotency_key TEXT NOT NULL UNIQUE,
                user_id         INTEGER NOT NULL,
                counterparty_id INTEGER,
                tx_kind         TEXT NOT NULL,
                delta_units     INTEGER NOT NULL,
                balance_after   INTEGER NOT NULL,
                title           TEXT NOT NULL DEFAULT '',
                created_at      INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS gifts_catalog (
                gift_id             INTEGER PRIMARY KEY,
                slug_prefix         TEXT NOT NULL UNIQUE,
                title               TEXT NOT NULL,
                star_price_units    INTEGER NOT NULL,
                upgrade_price_units INTEGER NOT NULL DEFAULT 25,
                convert_units       INTEGER NOT NULL DEFAULT 0,
                total_supply        INTEGER,
                minted_count        INTEGER NOT NULL DEFAULT 0,
                is_limited          INTEGER NOT NULL DEFAULT 0,
                is_upgradeable      INTEGER NOT NULL DEFAULT 1,
                active              INTEGER NOT NULL DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS user_gifts (
                instance_id         INTEGER PRIMARY KEY AUTOINCREMENT,
                gift_id             INTEGER NOT NULL,
                owner_user_id       INTEGER NOT NULL,
                sender_user_id      INTEGER,
                serial_number       INTEGER,
                collectible_slug    TEXT UNIQUE,
                is_upgraded         INTEGER NOT NULL DEFAULT 0,
                message             TEXT NOT NULL DEFAULT '',
                minted_at           INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS virtual_numbers (
                phone_digits    TEXT PRIMARY KEY,
                owner_user_id   INTEGER,
                assigned_dc_id  INTEGER NOT NULL DEFAULT 2,
                price_units     INTEGER NOT NULL DEFAULT 0,
                is_locked       INTEGER NOT NULL DEFAULT 0,
                issued_at       INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS admin_audit_log (
                audit_id        INTEGER PRIMARY KEY AUTOINCREMENT,
                operator_name   TEXT NOT NULL,
                action_code     TEXT NOT NULL,
                target_entity   TEXT NOT NULL,
                detail_json     TEXT NOT NULL DEFAULT '{}',
                created_at      INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS message_views (
                peer_kind       INTEGER NOT NULL,
                peer_id         INTEGER NOT NULL,
                msg_id          INTEGER NOT NULL,
                views           INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (peer_kind, peer_id, msg_id)
            );

            CREATE TABLE IF NOT EXISTS file_parts (
                file_id         INTEGER NOT NULL,
                file_part       INTEGER NOT NULL,
                bytes           BLOB NOT NULL,
                PRIMARY KEY (file_id, file_part)
            );

            CREATE TABLE IF NOT EXISTS server_settings (
                setting_key   TEXT PRIMARY KEY,
                setting_val   TEXT NOT NULL,
                updated_at    INTEGER NOT NULL
            );
            ",
        )?;

        // Seed default Collectible Star Gifts catalog if empty!
        let catalog_count: i64 =
            db.query_row("SELECT COUNT(*) FROM gifts_catalog", [], |r| r.get(0))?;
        if catalog_count == 0 {
            db.execute(
                "INSERT INTO gifts_catalog (gift_id, slug_prefix, title, star_price_units, upgrade_price_units, convert_units, total_supply, is_limited, is_upgradeable)
                 VALUES
                 (5001, 'CrystalStar', 'Crystal Star', 50, 25, 40, 10000, 1, 1),
                 (5002, 'NeonCrown', 'Neon Crown', 250, 50, 200, 1000, 1, 1),
                 (5003, 'CyberRose', 'Cyber Rose', 25, 25, 20, NULL, 0, 1)",
                [],
            )?;
        }

        // Seed official Telegram Service Notifications account (777000)
        db.execute(
            "INSERT OR IGNORE INTO users (user_id, home_dc_id, access_hash, phone, first_name, last_name, flags_bitmask, created_at)
             VALUES (777000, ?1, 777000, '777000', 'Telegram', '', 1, 0)",
            params![self.default_dc_id],
        )?;
        Ok(())
    }

    /// Import legacy `users.tsv` records (`U\tid\tphone\tfirst\tlast\taccess_hash`
    /// and `K\tkey_id\tuser_id` / `X\tkey_id`) idempotently so live accounts on
    /// `149.56.212.222` migrate seamlessly with zero data loss!
    pub fn import_legacy_tsv(&self, tsv_path: impl AsRef<Path>) -> Result<usize, StoreError> {
        let Ok(text) = std::fs::read_to_string(tsv_path) else {
            return Ok(0);
        };
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let now = now_unix_i32();
        let mut imported_users = 0usize;

        for line in text.lines() {
            let parts: Vec<&str> = line.split('\t').collect();
            match parts.first().copied() {
                Some("U") if parts.len() >= 6 => {
                    if let (Ok(id), Ok(ah)) = (parts[1].parse::<i64>(), parts[5].parse::<i64>()) {
                        tx.execute(
                            "INSERT INTO users (user_id, home_dc_id, access_hash, phone, first_name, last_name, created_at)
                             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
                             ON CONFLICT(user_id) DO UPDATE SET
                                first_name = excluded.first_name,
                                last_name  = excluded.last_name",
                            params![id, self.default_dc_id, ah, parts[2], parts[3], parts[4], now],
                        )?;
                        imported_users += 1;
                    }
                }
                Some("K") if parts.len() >= 3 => {
                    if let (Ok(kid), Ok(uid)) = (parts[1].parse::<i64>(), parts[2].parse::<i64>()) {
                        tx.execute(
                            "INSERT INTO key_bindings (auth_key_id, user_id, home_dc_id, binding_mode, updated_at)
                             VALUES (?1, ?2, ?3, 1, ?4)
                             ON CONFLICT(auth_key_id) DO UPDATE SET user_id = excluded.user_id",
                            params![kid, uid, self.default_dc_id, now],
                        )?;
                    }
                }
                Some("X") if parts.len() >= 2 => {
                    if let Ok(kid) = parts[1].parse::<i64>() {
                        tx.execute("DELETE FROM key_bindings WHERE auth_key_id = ?1", params![kid])?;
                    }
                }
                _ => {}
            }
        }
        tx.commit()?;
        Ok(imported_users)
    }

    // --- Users, Auth Keys & Profiles ----------------------------------------

    pub fn get_or_create_user(
        &self,
        phone: &str,
        first_name: Option<&str>,
        last_name: Option<&str>,
    ) -> Result<UserRow, StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let existing: Option<UserRow> = tx
            .query_row(
                "SELECT user_id, home_dc_id, dc_epoch, access_hash, phone, username, first_name, last_name, bio, flags_bitmask, pts, qts, photo_id, photo_dc_id
                 FROM users WHERE phone = ?1",
                params![phone],
                map_user_row,
            )
            .optional()?;

        if let Some(mut u) = existing {
            let mut changed = false;
            if let Some(f) = first_name.filter(|s| !s.is_empty()) {
                if u.first_name != f {
                    u.first_name = f.to_string();
                    changed = true;
                }
            }
            if let Some(l) = last_name {
                if u.last_name != l {
                    u.last_name = l.to_string();
                    changed = true;
                }
            }
            if changed {
                tx.execute(
                    "UPDATE users SET first_name = ?1, last_name = ?2 WHERE user_id = ?3",
                    params![u.first_name, u.last_name, u.user_id],
                )?;
            }
            tx.commit()?;
            return Ok(u);
        }

        let max_id: i64 = tx.query_row(
            "SELECT COALESCE(MAX(user_id), 999) FROM users WHERE user_id >= 1000",
            [],
            |r| r.get(0),
        )?;
        let user_id = max_id + 1;
        let access_hash = user_id.wrapping_mul(0x9E37_79B9_7F4A_7C15u64 as i64);
        let now = now_unix_i32();

        // Check if this phone is an assigned +888 virtual number with a target DC!
        let assigned_dc: Option<i32> = tx
            .query_row(
                "SELECT assigned_dc_id FROM virtual_numbers WHERE phone_digits = ?1",
                params![phone],
                |r| r.get(0),
            )
            .optional()?;
        let home_dc_id = assigned_dc.unwrap_or(self.default_dc_id);

        let fname = first_name.unwrap_or("ShuzaGram");
        let lname = last_name.unwrap_or("User");
        tx.execute(
            "INSERT INTO users (user_id, home_dc_id, access_hash, phone, first_name, last_name, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![user_id, home_dc_id, access_hash, phone, fname, lname, now],
        )?;
        if assigned_dc.is_some() {
            tx.execute(
                "UPDATE virtual_numbers SET owner_user_id = ?1 WHERE phone_digits = ?2",
                params![user_id, phone],
            )?;
        }
        let row = tx.query_row(
            "SELECT user_id, home_dc_id, dc_epoch, access_hash, phone, username, first_name, last_name, bio, flags_bitmask, pts, qts, photo_id, photo_dc_id
             FROM users WHERE user_id = ?1",
            params![user_id],
            map_user_row,
        )?;
        tx.commit()?;
        Ok(row)
    }

    pub fn user_by_id(&self, user_id: i64) -> Option<UserRow> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT user_id, home_dc_id, dc_epoch, access_hash, phone, username, first_name, last_name, bio, flags_bitmask, pts, qts, photo_id, photo_dc_id
             FROM users WHERE user_id = ?1",
            params![user_id],
            map_user_row,
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn user_by_phone(&self, phone: &str) -> Option<UserRow> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT user_id, home_dc_id, dc_epoch, access_hash, phone, username, first_name, last_name, bio, flags_bitmask, pts, qts, photo_id, photo_dc_id
             FROM users WHERE phone = ?1",
            params![phone],
            map_user_row,
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn user_by_username(&self, username: &str) -> Option<UserRow> {
        let clean = username.trim().trim_start_matches('@').to_ascii_lowercase();
        if clean.is_empty() {
            return None;
        }
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT user_id, home_dc_id, dc_epoch, access_hash, phone, username, first_name, last_name, bio, flags_bitmask, pts, qts, photo_id, photo_dc_id
             FROM users WHERE username_lower = ?1",
            params![clean],
            map_user_row,
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn bind_key_user(
        &self,
        auth_key_id: i64,
        user_id: i64,
        home_dc_id: i32,
        binding_mode: i32,
    ) -> Result<(), StoreError> {
        let db = self.conn.lock().unwrap();
        let now = now_unix_i32();
        db.execute(
            "INSERT INTO key_bindings (auth_key_id, user_id, home_dc_id, binding_mode, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(auth_key_id) DO UPDATE SET
                user_id = excluded.user_id,
                home_dc_id = excluded.home_dc_id,
                binding_mode = excluded.binding_mode,
                updated_at = excluded.updated_at",
            params![auth_key_id, user_id, home_dc_id, binding_mode, now],
        )?;
        Ok(())
    }

    pub fn unbind_key(&self, auth_key_id: i64) -> Result<(), StoreError> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "DELETE FROM key_bindings WHERE auth_key_id = ?1",
            params![auth_key_id],
        )?;
        Ok(())
    }

    /// Returns `(UserRow, binding_home_dc_id, binding_mode)` for `auth_key_id`.
    pub fn key_binding(&self, auth_key_id: i64) -> Option<(UserRow, i32, i32)> {
        let db = self.conn.lock().unwrap();
        let binding: Option<(i64, i32, i32)> = db
            .query_row(
                "SELECT user_id, home_dc_id, binding_mode FROM key_bindings WHERE auth_key_id = ?1",
                params![auth_key_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .ok()
            .flatten();
        let (uid, hdc, mode) = binding?;
        let user = db
            .query_row(
                "SELECT user_id, home_dc_id, dc_epoch, access_hash, phone, username, first_name, last_name, bio, flags_bitmask, pts, qts, photo_id, photo_dc_id
                 FROM users WHERE user_id = ?1",
                params![uid],
                map_user_row,
            )
            .optional()
            .ok()
            .flatten()?;
        Some((user, hdc, mode))
    }

    pub fn update_profile(
        &self,
        user_id: i64,
        first_name: Option<&str>,
        last_name: Option<&str>,
        about: Option<&str>,
    ) -> Result<UserRow, StoreError> {
        let db = self.conn.lock().unwrap();
        if let Some(f) = first_name {
            db.execute(
                "UPDATE users SET first_name = ?1 WHERE user_id = ?2",
                params![f.trim(), user_id],
            )?;
        }
        if let Some(l) = last_name {
            db.execute(
                "UPDATE users SET last_name = ?1 WHERE user_id = ?2",
                params![l.trim(), user_id],
            )?;
        }
        if let Some(b) = about {
            db.execute(
                "UPDATE users SET bio = ?1 WHERE user_id = ?2",
                params![b.trim(), user_id],
            )?;
        }
        db.query_row(
            "SELECT user_id, home_dc_id, dc_epoch, access_hash, phone, username, first_name, last_name, bio, flags_bitmask, pts, qts, photo_id, photo_dc_id
             FROM users WHERE user_id = ?1",
            params![user_id],
            map_user_row,
        )
        .optional()?
        .ok_or(StoreError::NotFound)
    }

    pub fn is_username_available(&self, username: &str, requester_id: Option<i64>) -> Result<bool, StoreError> {
        let clean = validate_username(username)?;
        let lower = clean.to_ascii_lowercase();
        let db = self.conn.lock().unwrap();
        let user_owner: Option<i64> = db
            .query_row(
                "SELECT user_id FROM users WHERE username_lower = ?1",
                params![lower],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(uid) = user_owner {
            return Ok(Some(uid) == requester_id);
        }
        let chan_owner: Option<i64> = db
            .query_row(
                "SELECT channel_id FROM channels WHERE username_lower = ?1",
                params![lower],
                |r| r.get(0),
            )
            .optional()?;
        Ok(chan_owner.is_none())
    }

    pub fn update_username(&self, user_id: i64, username: &str) -> Result<UserRow, StoreError> {
        let trimmed = username.trim().trim_start_matches('@');
        if trimmed.is_empty() {
            let db = self.conn.lock().unwrap();
            db.execute(
                "UPDATE users SET username = NULL, username_lower = NULL WHERE user_id = ?1",
                params![user_id],
            )?;
            return self.user_by_id(user_id).ok_or(StoreError::NotFound);
        }
        let clean = validate_username(trimmed)?;
        let lower = clean.to_ascii_lowercase();
        if !self.is_username_available(clean, Some(user_id))? {
            return Err(StoreError::UsernameOccupied);
        }
        let db = self.conn.lock().unwrap();
        db.execute(
            "UPDATE users SET username = ?1, username_lower = ?2 WHERE user_id = ?3",
            params![clean, lower, user_id],
        )?;
        drop(db);
        self.user_by_id(user_id).ok_or(StoreError::NotFound)
    }

    pub fn set_user_photo(&self, user_id: i64, photo_id: Option<i64>, photo_dc_id: Option<i32>) -> Result<(), StoreError> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "UPDATE users SET photo_id = ?1, photo_dc_id = ?2 WHERE user_id = ?3",
            params![photo_id, photo_dc_id, user_id],
        )?;
        Ok(())
    }

    pub fn set_user_badges(&self, user_id: i64, flags_bitmask: i64) -> Result<UserRow, StoreError> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "UPDATE users SET flags_bitmask = ?1 WHERE user_id = ?2",
            params![flags_bitmask, user_id],
        )?;
        drop(db);
        self.user_by_id(user_id).ok_or(StoreError::NotFound)
    }

    pub fn migrate_user_home_dc(&self, user_id: i64, new_dc_id: i32) -> Result<UserRow, StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        tx.execute(
            "UPDATE users SET home_dc_id = ?1, dc_epoch = dc_epoch + 1 WHERE user_id = ?2",
            params![new_dc_id, user_id],
        )?;
        tx.execute(
            "UPDATE key_bindings SET home_dc_id = ?1, dc_epoch = dc_epoch + 1 WHERE user_id = ?2",
            params![new_dc_id, user_id],
        )?;
        tx.commit()?;
        drop(db);
        self.user_by_id(user_id).ok_or(StoreError::NotFound)
    }

    pub fn search_users(&self, query: &str, limit: usize) -> Vec<UserRow> {
        let q = query.trim().trim_start_matches('@').to_ascii_lowercase();
        let lim = limit.clamp(1, 100) as i64;
        let db = self.conn.lock().unwrap();
        if q.is_empty() {
            let mut stmt = db
                .prepare(
                    "SELECT user_id, home_dc_id, dc_epoch, access_hash, phone, username, first_name, last_name, bio, flags_bitmask, pts, qts, photo_id, photo_dc_id
                     FROM users ORDER BY user_id ASC LIMIT ?1",
                )
                .unwrap();
            return stmt
                .query_map(params![lim], map_user_row)
                .unwrap()
                .filter_map(Result::ok)
                .collect();
        }
        let pattern = format!("%{q}%");
        let mut stmt = db
            .prepare(
                "SELECT user_id, home_dc_id, dc_epoch, access_hash, phone, username, first_name, last_name, bio, flags_bitmask, pts, qts, photo_id, photo_dc_id
                 FROM users
                 WHERE username_lower LIKE ?1
                    OR LOWER(first_name) LIKE ?1
                    OR LOWER(last_name) LIKE ?1
                    OR phone LIKE ?1
                    OR CAST(user_id AS TEXT) = ?2
                 ORDER BY user_id ASC
                 LIMIT ?3",
            )
            .unwrap();
        stmt.query_map(params![pattern, q, lim], map_user_row)
            .unwrap()
            .filter_map(Result::ok)
            .collect()
    }

    // --- Contacts -----------------------------------------------------------

    pub fn add_contact(
        &self,
        owner_user_id: i64,
        contact_user_id: i64,
        first_name: &str,
        last_name: &str,
        phone: &str,
    ) -> Result<(), StoreError> {
        let db = self.conn.lock().unwrap();
        let now = now_unix_i32();
        db.execute(
            "INSERT INTO contacts (owner_user_id, contact_user_id, first_name, last_name, phone, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(owner_user_id, contact_user_id) DO UPDATE SET
                first_name = excluded.first_name,
                last_name  = excluded.last_name,
                phone      = excluded.phone",
            params![owner_user_id, contact_user_id, first_name, last_name, phone, now],
        )?;
        Ok(())
    }

    pub fn delete_contacts(&self, owner_user_id: i64, contact_ids: &[i64]) -> Result<(), StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        for &cid in contact_ids {
            tx.execute(
                "DELETE FROM contacts WHERE owner_user_id = ?1 AND contact_user_id = ?2",
                params![owner_user_id, cid],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Returns `(contact_user, is_mutual)` for `owner_user_id`.
    pub fn list_contacts(&self, owner_user_id: i64) -> Vec<(UserRow, bool)> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT u.user_id, u.home_dc_id, u.dc_epoch, u.access_hash, u.phone, u.username,
                        u.first_name, u.last_name, u.bio, u.flags_bitmask, u.pts, u.qts, u.photo_id, u.photo_dc_id,
                        EXISTS(SELECT 1 FROM contacts r WHERE r.owner_user_id = c.contact_user_id AND r.contact_user_id = c.owner_user_id)
                 FROM contacts c
                 JOIN users u ON u.user_id = c.contact_user_id
                 WHERE c.owner_user_id = ?1
                 ORDER BY c.created_at DESC",
            )
            .unwrap();
        stmt.query_map(params![owner_user_id], |r| {
            let user = map_user_row(r)?;
            let mutual: bool = r.get(14)?;
            Ok((user, mutual))
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    }

    // --- Direct 1:1 & Saved Messages + Monotonic `pts` Engine ---------------

    #[allow(clippy::too_many_arguments)]
    pub fn send_direct_message(
        &self,
        sender_id: i64,
        recipient_id: i64,
        random_id: i64,
        text: &str,
        reply_to_msg_id: Option<i32>,
        media_tl: Option<&[u8]>,
        entities_tl: Option<&[u8]>,
        ttl_period: Option<i32>,
    ) -> Result<DirectDeliveryOutcome, StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let now = now_unix_i32();

        // Idempotent deduplication by `(sender_id, random_id)`
        if random_id != 0 {
            let existing: Option<(MessageRow, i32)> = tx
                .query_row(
                    "SELECT owner_user_id, msg_id, peer_kind, peer_id, sender_user_id, random_id, is_out,
                            date_unix, edit_date_unix, reply_to_msg_id, message_text, media_tl, entities_tl, ttl_period,
                            (SELECT pts FROM users WHERE user_id = ?1)
                     FROM messages WHERE owner_user_id = ?1 AND random_id = ?2 AND deleted = 0 LIMIT 1",
                    params![sender_id, random_id],
                    |r| Ok((map_message_row(r)?, r.get(14)?)),
                )
                .optional()?;
            if let Some((msg, pts)) = existing {
                tx.commit()?;
                return Ok(DirectDeliveryOutcome {
                    deduplicated: true,
                    sender_msg: msg,
                    sender_pts: pts,
                    recipient_msg: None,
                });
            }
        }

        // Allocate sender msg_id & pts
        let (sender_msg_id, sender_pts): (i32, i32) = tx.query_row(
            "UPDATE users SET next_msg_id = next_msg_id + 1, pts = pts + 1
             WHERE user_id = ?1
             RETURNING next_msg_id - 1, pts",
            params![sender_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        let is_self = sender_id == recipient_id;
        let mut recip_info: Option<(i32, i32)> = None;

        if !is_self {
            let exists: Option<(i32, i32)> = tx
                .query_row(
                    "UPDATE users SET next_msg_id = next_msg_id + 1, pts = pts + 1
                     WHERE user_id = ?1
                     RETURNING next_msg_id - 1, pts",
                    params![recipient_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let Some(pair) = exists else {
                return Err(StoreError::NotFound);
            };
            recip_info = Some(pair);
        }

        let recip_mid_opt = recip_info.map(|(m, _)| m);

        tx.execute(
            "INSERT INTO messages (owner_user_id, msg_id, peer_kind, peer_id, sender_user_id, random_id,
                                   counterpart_uid, counterpart_mid, is_out, date_unix, reply_to_msg_id,
                                   message_text, media_tl, entities_tl, ttl_period)
             VALUES (?1, ?2, ?3, ?4, ?1, ?5, ?6, ?7, 1, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                sender_id,
                sender_msg_id,
                PEER_USER,
                recipient_id,
                random_id,
                if is_self { None::<i64> } else { Some(recipient_id) },
                recip_mid_opt,
                now,
                reply_to_msg_id,
                text,
                media_tl,
                entities_tl,
                ttl_period
            ],
        )?;

        tx.execute(
            "INSERT INTO dialogs (user_id, peer_kind, peer_id, top_message_id, read_outbox_max_id, updated_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5)
             ON CONFLICT(user_id, peer_kind, peer_id) DO UPDATE SET
                top_message_id = excluded.top_message_id,
                updated_at     = excluded.updated_at",
            params![sender_id, PEER_USER, recipient_id, sender_msg_id, now],
        )?;

        append_pts_event_tx(
            &tx,
            sender_id,
            sender_pts,
            now,
            PTS_KIND_NEW_MESSAGE,
            sender_msg_id,
            PEER_USER,
            recipient_id,
            0,
        )?;

        let sender_msg = MessageRow {
            owner_user_id: sender_id,
            msg_id: sender_msg_id,
            peer_kind: PEER_USER,
            peer_id: recipient_id,
            sender_user_id: sender_id,
            random_id,
            is_out: true,
            date_unix: now,
            edit_date_unix: None,
            reply_to_msg_id,
            message_text: text.to_string(),
            media_tl: media_tl.map(|b| b.to_vec()),
            entities_tl: entities_tl.map(|b| b.to_vec()),
            ttl_period,
        };

        let mut recipient_msg = None;
        if let Some((r_msg_id, r_pts)) = recip_info {
            tx.execute(
                "INSERT INTO messages (owner_user_id, msg_id, peer_kind, peer_id, sender_user_id, random_id,
                                       counterpart_uid, counterpart_mid, is_out, date_unix, reply_to_msg_id,
                                       message_text, media_tl, entities_tl, ttl_period)
                 VALUES (?1, ?2, ?3, ?4, ?4, 0, ?4, ?5, 0, ?6, NULL, ?7, ?8, ?9, ?10)",
                params![
                    recipient_id,
                    r_msg_id,
                    PEER_USER,
                    sender_id,
                    sender_msg_id,
                    now,
                    text,
                    media_tl,
                    entities_tl,
                    ttl_period
                ],
            )?;

            tx.execute(
                "INSERT INTO dialogs (user_id, peer_kind, peer_id, top_message_id, unread_count, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)
                 ON CONFLICT(user_id, peer_kind, peer_id) DO UPDATE SET
                    top_message_id = excluded.top_message_id,
                    unread_count   = dialogs.unread_count + 1,
                    updated_at     = excluded.updated_at",
                params![recipient_id, PEER_USER, sender_id, r_msg_id, now],
            )?;

            append_pts_event_tx(
                &tx,
                recipient_id,
                r_pts,
                now,
                PTS_KIND_NEW_MESSAGE,
                r_msg_id,
                PEER_USER,
                sender_id,
                0,
            )?;

            recipient_msg = Some((
                MessageRow {
                    owner_user_id: recipient_id,
                    msg_id: r_msg_id,
                    peer_kind: PEER_USER,
                    peer_id: sender_id,
                    sender_user_id: sender_id,
                    random_id: 0,
                    is_out: false,
                    date_unix: now,
                    edit_date_unix: None,
                    reply_to_msg_id: None,
                    message_text: text.to_string(),
                    media_tl: media_tl.map(|b| b.to_vec()),
                    entities_tl: entities_tl.map(|b| b.to_vec()),
                    ttl_period,
                },
                r_pts,
            ));
        }

        tx.commit()?;
        Ok(DirectDeliveryOutcome {
            deduplicated: false,
            sender_msg,
            sender_pts,
            recipient_msg,
        })
    }

    pub fn edit_direct_message(
        &self,
        actor_id: i64,
        msg_id: i32,
        new_text: &str,
    ) -> Result<EditMessageOutcome, StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let now = now_unix_i32();

        struct EditMeta {
            peer_kind: i32,
            peer_id: i64,
            c_uid: Option<i64>,
            c_mid: Option<i32>,
            is_out: i32,
        }

        let meta: Option<EditMeta> = tx
            .query_row(
                "SELECT peer_kind, peer_id, counterpart_uid, counterpart_mid, is_out
                 FROM messages WHERE owner_user_id = ?1 AND msg_id = ?2 AND deleted = 0",
                params![actor_id, msg_id],
                |r| {
                    Ok(EditMeta {
                        peer_kind: r.get(0)?,
                        peer_id: r.get(1)?,
                        c_uid: r.get(2)?,
                        c_mid: r.get(3)?,
                        is_out: r.get(4)?,
                    })
                },
            )
            .optional()?;
        let Some(EditMeta {
            peer_kind,
            peer_id,
            c_uid,
            c_mid,
            is_out,
        }) = meta
        else {
            return Err(StoreError::NotFound);
        };
        if is_out == 0 {
            return Err(StoreError::PermissionDenied);
        }

        tx.execute(
            "UPDATE messages SET message_text = ?1, edit_date_unix = ?2 WHERE owner_user_id = ?3 AND msg_id = ?4",
            params![new_text, now, actor_id, msg_id],
        )?;
        let actor_pts: i32 = tx.query_row(
            "UPDATE users SET pts = pts + 1 WHERE user_id = ?1 RETURNING pts",
            params![actor_id],
            |r| r.get(0),
        )?;
        append_pts_event_tx(
            &tx,
            actor_id,
            actor_pts,
            now,
            PTS_KIND_EDIT_MESSAGE,
            msg_id,
            peer_kind,
            peer_id,
            0,
        )?;

        let actor_msg = tx.query_row(
            "SELECT owner_user_id, msg_id, peer_kind, peer_id, sender_user_id, random_id, is_out,
                    date_unix, edit_date_unix, reply_to_msg_id, message_text, media_tl, entities_tl, ttl_period
             FROM messages WHERE owner_user_id = ?1 AND msg_id = ?2",
            params![actor_id, msg_id],
            map_message_row,
        )?;

        let mut peer_updated = None;
        if let (Some(ruid), Some(rmid)) = (c_uid, c_mid) {
            let changed = tx.execute(
                "UPDATE messages SET message_text = ?1, edit_date_unix = ?2 WHERE owner_user_id = ?3 AND msg_id = ?4 AND deleted = 0",
                params![new_text, now, ruid, rmid],
            )?;
            if changed > 0 {
                let r_pts: i32 = tx.query_row(
                    "UPDATE users SET pts = pts + 1 WHERE user_id = ?1 RETURNING pts",
                    params![ruid],
                    |r| r.get(0),
                )?;
                append_pts_event_tx(
                    &tx,
                    ruid,
                    r_pts,
                    now,
                    PTS_KIND_EDIT_MESSAGE,
                    rmid,
                    PEER_USER,
                    actor_id,
                    0,
                )?;
                let r_msg = tx.query_row(
                    "SELECT owner_user_id, msg_id, peer_kind, peer_id, sender_user_id, random_id, is_out,
                            date_unix, edit_date_unix, reply_to_msg_id, message_text, media_tl, entities_tl, ttl_period
                     FROM messages WHERE owner_user_id = ?1 AND msg_id = ?2",
                    params![ruid, rmid],
                    map_message_row,
                )?;
                peer_updated = Some((r_msg, r_pts));
            }
        }

        tx.commit()?;
        Ok(EditMessageOutcome {
            actor_msg,
            actor_pts,
            peer_updated,
        })
    }

    /// Delete messages for `actor_id` (and revoke counterpart copies if `revoke == true`).
    pub fn delete_messages(
        &self,
        actor_id: i64,
        msg_ids: &[i32],
        revoke: bool,
    ) -> Result<DeleteMessagesOutcome, StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let now = now_unix_i32();

        let mut actor_deleted = Vec::new();
        let mut peer_deletes: std::collections::HashMap<i64, Vec<i32>> =
            std::collections::HashMap::new();

        for &mid in msg_ids {
            let counterpart: Option<(Option<i64>, Option<i32>)> = tx
                .query_row(
                    "SELECT counterpart_uid, counterpart_mid FROM messages
                     WHERE owner_user_id = ?1 AND msg_id = ?2 AND deleted = 0",
                    params![actor_id, mid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((cuid, cmid)) = counterpart {
                tx.execute(
                    "UPDATE messages SET deleted = 1 WHERE owner_user_id = ?1 AND msg_id = ?2",
                    params![actor_id, mid],
                )?;
                actor_deleted.push(mid);
                if revoke {
                    if let (Some(u), Some(m)) = (cuid, cmid) {
                        let c = tx.execute(
                            "UPDATE messages SET deleted = 1 WHERE owner_user_id = ?1 AND msg_id = ?2 AND deleted = 0",
                            params![u, m],
                        )?;
                        if c > 0 {
                            peer_deletes.entry(u).or_default().push(m);
                        }
                    }
                }
            }
        }

        let cur_pts: i32 = tx.query_row(
            "SELECT pts FROM users WHERE user_id = ?1",
            params![actor_id],
            |r| r.get(0),
        )?;
        if actor_deleted.is_empty() {
            tx.commit()?;
            return Ok(DeleteMessagesOutcome {
                actor_pts: cur_pts,
                deleted_count: 0,
                peer_batches: vec![],
            });
        }

        let delta = actor_deleted.len() as i32;
        let mut new_actor_pts = cur_pts;
        for &mid in &actor_deleted {
            new_actor_pts += 1;
            append_pts_event_tx(
                &tx,
                actor_id,
                new_actor_pts,
                now,
                PTS_KIND_DELETE_MESSAGES,
                mid,
                0,
                0,
                0,
            )?;
        }
        tx.execute(
            "UPDATE users SET pts = ?1 WHERE user_id = ?2",
            params![new_actor_pts, actor_id],
        )?;

        let mut peer_batches = Vec::new();
        for (puid, mids) in peer_deletes {
            let p_cur: i32 = tx.query_row(
                "SELECT pts FROM users WHERE user_id = ?1",
                params![puid],
                |r| r.get(0),
            )?;
            let mut p_pts = p_cur;
            for &pm in &mids {
                p_pts += 1;
                append_pts_event_tx(
                    &tx,
                    puid,
                    p_pts,
                    now,
                    PTS_KIND_DELETE_MESSAGES,
                    pm,
                    0,
                    0,
                    0,
                )?;
            }
            tx.execute(
                "UPDATE users SET pts = ?1 WHERE user_id = ?2",
                params![p_pts, puid],
            )?;
            peer_batches.push(PeerDeleteBatch {
                user_id: puid,
                msg_ids: mids,
                pts: p_pts,
            });
        }

        tx.commit()?;
        Ok(DeleteMessagesOutcome {
            actor_pts: new_actor_pts,
            deleted_count: delta,
            peer_batches,
        })
    }

    /// Delete dialog history up to `max_id` (and optionally remove dialog row if `!just_clear`).
    pub fn delete_history(
        &self,
        actor_id: i64,
        peer_kind: i32,
        peer_id: i64,
        max_id: i32,
        just_clear: bool,
        revoke: bool,
    ) -> Result<DeleteMessagesOutcome, StoreError> {
        let effective_max = if max_id <= 0 { i32::MAX } else { max_id };
        let ids: Vec<i32> = {
            let db = self.conn.lock().unwrap();
            let mut stmt = db.prepare(
                "SELECT msg_id FROM messages
                 WHERE owner_user_id = ?1 AND peer_kind = ?2 AND peer_id = ?3 AND deleted = 0 AND msg_id <= ?4",
            )?;
            let rows = stmt
                .query_map(params![actor_id, peer_kind, peer_id, effective_max], |r| r.get(0))?
                .filter_map(Result::ok)
                .collect();
            rows
        };
        let outcome = self.delete_messages(actor_id, &ids, revoke)?;
        let db = self.conn.lock().unwrap();
        if !just_clear {
            db.execute(
                "DELETE FROM dialogs WHERE user_id = ?1 AND peer_kind = ?2 AND peer_id = ?3",
                params![actor_id, peer_kind, peer_id],
            )?;
            if revoke && peer_kind == PEER_USER && peer_id != actor_id {
                db.execute(
                    "DELETE FROM dialogs WHERE user_id = ?1 AND peer_kind = ?2 AND peer_id = ?3",
                    params![peer_id, PEER_USER, actor_id],
                )?;
            }
        } else {
            db.execute(
                "UPDATE dialogs SET top_message_id = 0, unread_count = 0
                 WHERE user_id = ?1 AND peer_kind = ?2 AND peer_id = ?3",
                params![actor_id, peer_kind, peer_id],
            )?;
        }
        Ok(outcome)
    }

    /// Mark history read up to `max_id` in `(reader_id, peer_kind, peer_id)`.
    pub fn read_history(
        &self,
        reader_id: i64,
        peer_kind: i32,
        peer_id: i64,
        max_id: i32,
    ) -> Result<ReadHistoryOutcome, StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let now = now_unix_i32();

        let effective_max = if max_id <= 0 { i32::MAX } else { max_id };
        let top_in_peer: i32 = tx.query_row(
            "SELECT COALESCE(MAX(msg_id), 0) FROM messages
             WHERE owner_user_id = ?1 AND peer_kind = ?2 AND peer_id = ?3 AND deleted = 0 AND msg_id <= ?4",
            params![reader_id, peer_kind, peer_id, effective_max],
            |r| r.get(0),
        )?;
        let still_unread: i32 = tx.query_row(
            "SELECT COUNT(*) FROM messages
             WHERE owner_user_id = ?1 AND peer_kind = ?2 AND peer_id = ?3 AND is_out = 0 AND deleted = 0 AND msg_id > ?4",
            params![reader_id, peer_kind, peer_id, top_in_peer],
            |r| r.get(0),
        )?;

        tx.execute(
            "UPDATE dialogs SET read_inbox_max_id = MAX(read_inbox_max_id, ?1), unread_count = ?2
             WHERE user_id = ?3 AND peer_kind = ?4 AND peer_id = ?5",
            params![top_in_peer, still_unread, reader_id, peer_kind, peer_id],
        )?;

        let reader_pts: i32 = tx.query_row(
            "UPDATE users SET pts = pts + 1 WHERE user_id = ?1 RETURNING pts",
            params![reader_id],
            |r| r.get(0),
        )?;
        append_pts_event_tx(
            &tx,
            reader_id,
            reader_pts,
            now,
            PTS_KIND_READ_INBOX,
            top_in_peer,
            peer_kind,
            peer_id,
            still_unread,
        )?;

        let mut outbox_peer = None;
        if peer_kind == PEER_USER && peer_id != reader_id {
            let sender_max: Option<i32> = tx
                .query_row(
                    "SELECT MAX(counterpart_mid) FROM messages
                     WHERE owner_user_id = ?1 AND peer_kind = ?2 AND peer_id = ?3
                       AND is_out = 0 AND msg_id <= ?4 AND counterpart_mid IS NOT NULL",
                    params![reader_id, PEER_USER, peer_id, top_in_peer],
                    |r| r.get(0),
                )
                .optional()?
                .flatten();
            if let Some(smax) = sender_max {
                tx.execute(
                    "UPDATE dialogs SET read_outbox_max_id = MAX(read_outbox_max_id, ?1)
                     WHERE user_id = ?2 AND peer_kind = ?3 AND peer_id = ?4",
                    params![smax, peer_id, PEER_USER, reader_id],
                )?;
                let p_pts: i32 = tx.query_row(
                    "UPDATE users SET pts = pts + 1 WHERE user_id = ?1 RETURNING pts",
                    params![peer_id],
                    |r| r.get(0),
                )?;
                append_pts_event_tx(
                    &tx,
                    peer_id,
                    p_pts,
                    now,
                    PTS_KIND_READ_OUTBOX,
                    smax,
                    PEER_USER,
                    reader_id,
                    0,
                )?;
                outbox_peer = Some((peer_id, smax, p_pts));
            }
        }

        tx.commit()?;
        Ok(ReadHistoryOutcome {
            reader_pts,
            outbox_peer,
        })
    }

    pub fn read_channel_history(
        &self,
        user_id: i64,
        channel_id: i64,
        max_id: i32,
    ) -> Result<(), StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let effective_max = if max_id <= 0 { i32::MAX } else { max_id };
        let top_msg: i32 = tx.query_row(
            "SELECT COALESCE(MAX(msg_id), 0) FROM channel_messages
             WHERE channel_id = ?1 AND deleted = 0 AND msg_id <= ?2",
            params![channel_id, effective_max],
            |r| r.get(0),
        )?;
        let still_unread: i32 = tx.query_row(
            "SELECT COUNT(*) FROM channel_messages
             WHERE channel_id = ?1 AND deleted = 0 AND msg_id > ?2 AND sender_user_id != ?3",
            params![channel_id, top_msg, user_id],
            |r| r.get(0),
        )?;
        tx.execute(
            "UPDATE channel_members SET read_max_id = MAX(read_max_id, ?1)
             WHERE channel_id = ?2 AND user_id = ?3",
            params![top_msg, channel_id, user_id],
        )?;
        tx.execute(
            "UPDATE dialogs SET read_inbox_max_id = MAX(read_inbox_max_id, ?1), unread_count = ?2
             WHERE user_id = ?3 AND peer_kind = ?4 AND peer_id = ?5",
            params![top_msg, still_unread, user_id, PEER_CHANNEL, channel_id],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_dialogs(&self, user_id: i64, limit: usize) -> Vec<DialogRow> {
        let db = self.conn.lock().unwrap();
        let lim = limit.clamp(1, 200) as i64;
        let mut stmt = db
            .prepare(
                "SELECT user_id, peer_kind, peer_id, top_message_id, read_inbox_max_id,
                        read_outbox_max_id, unread_count, pinned, updated_at
                 FROM dialogs
                 WHERE user_id = ?1
                 ORDER BY pinned DESC, updated_at DESC
                 LIMIT ?2",
            )
            .unwrap();
        stmt.query_map(params![user_id, lim], |r| {
            Ok(DialogRow {
                user_id: r.get(0)?,
                peer_kind: r.get(1)?,
                peer_id: r.get(2)?,
                top_message_id: r.get(3)?,
                read_inbox_max_id: r.get(4)?,
                read_outbox_max_id: r.get(5)?,
                unread_count: r.get(6)?,
                pinned: r.get::<_, i32>(7)? != 0,
                updated_at: r.get(8)?,
            })
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    }

    pub fn get_dialog(&self, user_id: i64, peer_kind: i32, peer_id: i64) -> Option<DialogRow> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT user_id, peer_kind, peer_id, top_message_id, read_inbox_max_id,
                    read_outbox_max_id, unread_count, pinned, updated_at
             FROM dialogs WHERE user_id = ?1 AND peer_kind = ?2 AND peer_id = ?3",
            params![user_id, peer_kind, peer_id],
            |r| {
                Ok(DialogRow {
                    user_id: r.get(0)?,
                    peer_kind: r.get(1)?,
                    peer_id: r.get(2)?,
                    top_message_id: r.get(3)?,
                    read_inbox_max_id: r.get(4)?,
                    read_outbox_max_id: r.get(5)?,
                    unread_count: r.get(6)?,
                    pinned: r.get::<_, i32>(7)? != 0,
                    updated_at: r.get(8)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn get_message(&self, owner_user_id: i64, msg_id: i32) -> Option<MessageRow> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT owner_user_id, msg_id, peer_kind, peer_id, sender_user_id, random_id, is_out,
                    date_unix, edit_date_unix, reply_to_msg_id, message_text, media_tl, entities_tl, ttl_period
             FROM messages WHERE owner_user_id = ?1 AND msg_id = ?2 AND deleted = 0",
            params![owner_user_id, msg_id],
            map_message_row,
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn get_history(
        &self,
        owner_user_id: i64,
        peer_kind: i32,
        peer_id: i64,
        offset_id: i32,
        limit: usize,
    ) -> Vec<MessageRow> {
        let db = self.conn.lock().unwrap();
        let lim = limit.clamp(1, 100) as i64;
        let upper = if offset_id <= 0 { i32::MAX } else { offset_id };
        let mut stmt = db
            .prepare(
                "SELECT owner_user_id, msg_id, peer_kind, peer_id, sender_user_id, random_id, is_out,
                        date_unix, edit_date_unix, reply_to_msg_id, message_text, media_tl, entities_tl, ttl_period
                 FROM messages
                 WHERE owner_user_id = ?1 AND peer_kind = ?2 AND peer_id = ?3
                   AND deleted = 0 AND msg_id < ?4
                 ORDER BY msg_id DESC
                 LIMIT ?5",
            )
            .unwrap();
        stmt.query_map(
            params![owner_user_id, peer_kind, peer_id, upper, lim],
            map_message_row,
        )
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    }

    pub fn user_state(&self, user_id: i64) -> (i32, i32, i32) {
        let db = self.conn.lock().unwrap();
        let (pts, qts): (i32, i32) = db
            .query_row(
                "SELECT pts, qts FROM users WHERE user_id = ?1",
                params![user_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap_or((1, 0));
        let unread: i32 = db
            .query_row(
                "SELECT COALESCE(SUM(unread_count), 0) FROM dialogs WHERE user_id = ?1",
                params![user_id],
                |r| r.get(0),
            )
            .unwrap_or(0);
        (pts, qts, unread)
    }

    pub fn get_pts_difference(&self, user_id: i64, from_pts: i32, limit: usize) -> (i32, Vec<PtsEventRow>) {
        let db = self.conn.lock().unwrap();
        let current_pts: i32 = db
            .query_row(
                "SELECT pts FROM users WHERE user_id = ?1",
                params![user_id],
                |r| r.get(0),
            )
            .unwrap_or(1);
        if from_pts >= current_pts {
            return (current_pts, vec![]);
        }
        let lim = limit.clamp(1, 2048) as i64;
        let mut stmt = db
            .prepare(
                "SELECT pts, pts_count, date_unix, update_kind, msg_id, peer_kind, peer_id, extra_i32
                 FROM pts_updates
                 WHERE user_id = ?1 AND pts > ?2
                 ORDER BY pts ASC
                 LIMIT ?3",
            )
            .unwrap();
        let events = stmt
            .query_map(params![user_id, from_pts, lim], |r| {
                Ok(PtsEventRow {
                    pts: r.get(0)?,
                    pts_count: r.get(1)?,
                    date_unix: r.get(2)?,
                    update_kind: r.get(3)?,
                    msg_id: r.get(4)?,
                    peer_kind: r.get(5)?,
                    peer_id: r.get(6)?,
                    extra_i32: r.get(7)?,
                })
            })
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        (current_pts, events)
    }

    // --- Basic Groups (`chats`) ---------------------------------------------

    pub fn create_chat(
        &self,
        creator_id: i64,
        title: &str,
        member_ids: &[i64],
    ) -> Result<ChatRow, StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let now = now_unix_i32();
        let max_cid: i64 = tx.query_row(
            "SELECT COALESCE(MAX(chat_id), 10000) FROM chats",
            [],
            |r| r.get(0),
        )?;
        let chat_id = max_cid + 1;
        tx.execute(
            "INSERT INTO chats (chat_id, creator_id, title, date_unix, version)
             VALUES (?1, ?2, ?3, ?4, 1)",
            params![chat_id, creator_id, title, now],
        )?;

        let mut all_members = vec![creator_id];
        for &m in member_ids {
            if m != 0 && !all_members.contains(&m) {
                all_members.push(m);
            }
        }
        for &uid in &all_members {
            tx.execute(
                "INSERT OR IGNORE INTO chat_members (chat_id, user_id, joined_at) VALUES (?1, ?2, ?3)",
                params![chat_id, uid, now],
            )?;
            tx.execute(
                "INSERT INTO dialogs (user_id, peer_kind, peer_id, top_message_id, updated_at)
                 VALUES (?1, ?2, ?3, 0, ?4)
                 ON CONFLICT(user_id, peer_kind, peer_id) DO UPDATE SET updated_at = excluded.updated_at",
                params![uid, PEER_CHAT, chat_id, now],
            )?;
        }
        let pcount = all_members.len() as i32;
        tx.commit()?;
        Ok(ChatRow {
            chat_id,
            creator_id,
            title: title.to_string(),
            date_unix: now,
            version: 1,
            participants_count: pcount,
        })
    }

    pub fn chat_by_id(&self, chat_id: i64) -> Option<ChatRow> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT c.chat_id, c.creator_id, c.title, c.date_unix, c.version,
                    (SELECT COUNT(*) FROM chat_members m WHERE m.chat_id = c.chat_id)
             FROM chats c WHERE c.chat_id = ?1",
            params![chat_id],
            |r| {
                Ok(ChatRow {
                    chat_id: r.get(0)?,
                    creator_id: r.get(1)?,
                    title: r.get(2)?,
                    date_unix: r.get(3)?,
                    version: r.get(4)?,
                    participants_count: r.get(5)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn send_chat_message(
        &self,
        sender_id: i64,
        chat_id: i64,
        random_id: i64,
        text: &str,
        reply_to_msg_id: Option<i32>,
        media_tl: Option<&[u8]>,
    ) -> Result<GroupDeliveryOutcome, StoreError> {
        let chat = self.chat_by_id(chat_id).ok_or(StoreError::NotFound)?;
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let now = now_unix_i32();

        let members: Vec<i64> = {
            let mut stmt = tx.prepare("SELECT user_id FROM chat_members WHERE chat_id = ?1")?;
            let rows = stmt
                .query_map(params![chat_id], |r| r.get(0))?
                .filter_map(Result::ok)
                .collect();
            rows
        };
        if !members.contains(&sender_id) {
            return Err(StoreError::PermissionDenied);
        }

        let (sender_msg_id, sender_pts): (i32, i32) = tx.query_row(
            "UPDATE users SET next_msg_id = next_msg_id + 1, pts = pts + 1
             WHERE user_id = ?1 RETURNING next_msg_id - 1, pts",
            params![sender_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        tx.execute(
            "INSERT INTO messages (owner_user_id, msg_id, peer_kind, peer_id, sender_user_id, random_id,
                                   is_out, date_unix, reply_to_msg_id, message_text, media_tl)
             VALUES (?1, ?2, ?3, ?4, ?1, ?5, 1, ?6, ?7, ?8, ?9)",
            params![sender_id, sender_msg_id, PEER_CHAT, chat_id, random_id, now, reply_to_msg_id, text, media_tl],
        )?;
        tx.execute(
            "INSERT INTO dialogs (user_id, peer_kind, peer_id, top_message_id, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(user_id, peer_kind, peer_id) DO UPDATE SET
                top_message_id = excluded.top_message_id,
                updated_at     = excluded.updated_at",
            params![sender_id, PEER_CHAT, chat_id, sender_msg_id, now],
        )?;
        append_pts_event_tx(
            &tx,
            sender_id,
            sender_pts,
            now,
            PTS_KIND_NEW_MESSAGE,
            sender_msg_id,
            PEER_CHAT,
            chat_id,
            0,
        )?;

        let sender_msg = MessageRow {
            owner_user_id: sender_id,
            msg_id: sender_msg_id,
            peer_kind: PEER_CHAT,
            peer_id: chat_id,
            sender_user_id: sender_id,
            random_id,
            is_out: true,
            date_unix: now,
            edit_date_unix: None,
            reply_to_msg_id,
            message_text: text.to_string(),
            media_tl: media_tl.map(|b| b.to_vec()),
            entities_tl: None,
            ttl_period: None,
        };

        let mut deliveries = Vec::new();
        for uid in members {
            if uid == sender_id {
                continue;
            }
            let Some((m_id, m_pts)): Option<(i32, i32)> = tx
                .query_row(
                    "UPDATE users SET next_msg_id = next_msg_id + 1, pts = pts + 1
                     WHERE user_id = ?1 RETURNING next_msg_id - 1, pts",
                    params![uid],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?
            else {
                continue;
            };
            tx.execute(
                "INSERT INTO messages (owner_user_id, msg_id, peer_kind, peer_id, sender_user_id, random_id,
                                       is_out, date_unix, message_text, media_tl)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0, 0, ?6, ?7, ?8)",
                params![uid, m_id, PEER_CHAT, chat_id, sender_id, now, text, media_tl],
            )?;
            tx.execute(
                "INSERT INTO dialogs (user_id, peer_kind, peer_id, top_message_id, unread_count, updated_at)
                 VALUES (?1, ?2, ?3, ?4, 1, ?5)
                 ON CONFLICT(user_id, peer_kind, peer_id) DO UPDATE SET
                    top_message_id = excluded.top_message_id,
                    unread_count   = dialogs.unread_count + 1,
                    updated_at     = excluded.updated_at",
                params![uid, PEER_CHAT, chat_id, m_id, now],
            )?;
            append_pts_event_tx(
                &tx,
                uid,
                m_pts,
                now,
                PTS_KIND_NEW_MESSAGE,
                m_id,
                PEER_CHAT,
                chat_id,
                0,
            )?;
            deliveries.push((
                uid,
                MessageRow {
                    owner_user_id: uid,
                    msg_id: m_id,
                    peer_kind: PEER_CHAT,
                    peer_id: chat_id,
                    sender_user_id: sender_id,
                    random_id: 0,
                    is_out: false,
                    date_unix: now,
                    edit_date_unix: None,
                    reply_to_msg_id: None,
                    message_text: text.to_string(),
                    media_tl: media_tl.map(|b| b.to_vec()),
                    entities_tl: None,
                    ttl_period: None,
                },
                m_pts,
            ));
        }

        tx.commit()?;
        Ok(GroupDeliveryOutcome {
            chat,
            sender_msg,
            sender_pts,
            member_deliveries: deliveries,
        })
    }

    // --- Channels & Supergroups (`channels`) --------------------------------

    pub fn create_channel(
        &self,
        creator_id: i64,
        title: &str,
        about: &str,
        is_broadcast: bool,
        is_megagroup: bool,
        is_forum: bool,
    ) -> Result<ChannelRow, StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let now = now_unix_i32();
        let max_id: i64 = tx.query_row(
            "SELECT COALESCE(MAX(channel_id), 1000000) FROM channels",
            [],
            |r| r.get(0),
        )?;
        let channel_id = max_id + 1;
        let access_hash = channel_id.wrapping_mul(0x517C_C1B7_2722_0A95u64 as i64);

        tx.execute(
            "INSERT INTO channels (channel_id, origin_dc_id, creator_id, access_hash, title, about,
                                   is_broadcast, is_megagroup, is_forum, participants_count, channel_pts, next_msg_id, date_unix)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1, 1, 2, ?10)",
            params![
                channel_id,
                self.default_dc_id,
                creator_id,
                access_hash,
                title,
                about,
                is_broadcast as i32,
                is_megagroup as i32,
                is_forum as i32,
                now
            ],
        )?;
        tx.execute(
            "INSERT INTO channel_members (channel_id, user_id, is_admin, read_max_id, joined_at)
             VALUES (?1, ?2, 1, 1, ?3)",
            params![channel_id, creator_id, now],
        )?;
        tx.execute(
            "INSERT INTO dialogs (user_id, peer_kind, peer_id, top_message_id, read_inbox_max_id, read_outbox_max_id, updated_at)
             VALUES (?1, ?2, ?3, 1, 1, 1, ?4)
             ON CONFLICT(user_id, peer_kind, peer_id) DO UPDATE SET updated_at = excluded.updated_at",
            params![creator_id, PEER_CHANNEL, channel_id, now],
        )?;
        tx.commit()?;
        drop(db);
        self.channel_by_id(channel_id).ok_or(StoreError::NotFound)
    }

    pub fn channel_by_id(&self, channel_id: i64) -> Option<ChannelRow> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT channel_id, origin_dc_id, creator_id, access_hash, title, username, about,
                    is_broadcast, is_megagroup, is_forum, participants_count, channel_pts, date_unix
             FROM channels WHERE channel_id = ?1",
            params![channel_id],
            map_channel_row,
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn channel_by_username(&self, username: &str) -> Option<ChannelRow> {
        let clean = username.trim().trim_start_matches('@').to_ascii_lowercase();
        if clean.is_empty() {
            return None;
        }
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT channel_id, origin_dc_id, creator_id, access_hash, title, username, about,
                    is_broadcast, is_megagroup, is_forum, participants_count, channel_pts, date_unix
             FROM channels WHERE username_lower = ?1",
            params![clean],
            map_channel_row,
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn update_channel_username(
        &self,
        actor_id: i64,
        channel_id: i64,
        username: &str,
    ) -> Result<ChannelRow, StoreError> {
        let chan = self.channel_by_id(channel_id).ok_or(StoreError::NotFound)?;
        if chan.creator_id != actor_id {
            return Err(StoreError::PermissionDenied);
        }
        let trimmed = username.trim().trim_start_matches('@');
        if trimmed.is_empty() {
            let db = self.conn.lock().unwrap();
            db.execute(
                "UPDATE channels SET username = NULL, username_lower = NULL WHERE channel_id = ?1",
                params![channel_id],
            )?;
            return self.channel_by_id(channel_id).ok_or(StoreError::NotFound);
        }
        let clean = validate_username(trimmed)?;
        let lower = clean.to_ascii_lowercase();
        if !self.is_username_available(clean, None)? && chan.username.as_deref() != Some(clean) {
            return Err(StoreError::UsernameOccupied);
        }
        let db = self.conn.lock().unwrap();
        db.execute(
            "UPDATE channels SET username = ?1, username_lower = ?2 WHERE channel_id = ?3",
            params![clean, lower, channel_id],
        )?;
        drop(db);
        self.channel_by_id(channel_id).ok_or(StoreError::NotFound)
    }

    pub fn join_channel(&self, user_id: i64, channel_id: i64) -> Result<ChannelRow, StoreError> {
        let chan = self.channel_by_id(channel_id).ok_or(StoreError::NotFound)?;
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let now = now_unix_i32();
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO channel_members (channel_id, user_id, is_admin, read_max_id, joined_at)
             VALUES (?1, ?2, 0, 0, ?3)",
            params![channel_id, user_id, now],
        )?;
        if inserted > 0 {
            tx.execute(
                "UPDATE channels SET participants_count = participants_count + 1 WHERE channel_id = ?1",
                params![channel_id],
            )?;
        }
        let top_msg: i32 = tx.query_row(
            "SELECT COALESCE(MAX(msg_id), 1) FROM channel_messages WHERE channel_id = ?1 AND deleted = 0",
            params![channel_id],
            |r| r.get(0),
        )?;
        tx.execute(
            "INSERT INTO dialogs (user_id, peer_kind, peer_id, top_message_id, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(user_id, peer_kind, peer_id) DO UPDATE SET updated_at = excluded.updated_at",
            params![user_id, PEER_CHANNEL, channel_id, top_msg, now],
        )?;
        tx.commit()?;
        drop(db);
        Ok(self.channel_by_id(channel_id).unwrap_or(chan))
    }

    pub fn leave_channel(&self, user_id: i64, channel_id: i64) -> Result<ChannelRow, StoreError> {
        let chan = self.channel_by_id(channel_id).ok_or(StoreError::NotFound)?;
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let removed = tx.execute(
            "DELETE FROM channel_members WHERE channel_id = ?1 AND user_id = ?2",
            params![channel_id, user_id],
        )?;
        if removed > 0 {
            tx.execute(
                "UPDATE channels SET participants_count = MAX(0, participants_count - 1) WHERE channel_id = ?1",
                params![channel_id],
            )?;
        }
        tx.execute(
            "DELETE FROM dialogs WHERE user_id = ?1 AND peer_kind = ?2 AND peer_id = ?3",
            params![user_id, PEER_CHANNEL, channel_id],
        )?;
        tx.commit()?;
        drop(db);
        Ok(self.channel_by_id(channel_id).unwrap_or(chan))
    }

    pub fn get_channel_members(
        &self,
        channel_id: i64,
        offset: usize,
        limit: usize,
    ) -> Vec<(i64, bool, i32)> {
        let db = self.conn.lock().unwrap();
        let mut stmt = match db.prepare(
            "SELECT user_id, is_admin, joined_at
             FROM channel_members
             WHERE channel_id = ?1
             ORDER BY is_admin DESC, joined_at ASC
             LIMIT ?2 OFFSET ?3",
        ) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let rows = stmt
            .query_map(params![channel_id, limit as i64, offset as i64], |r| {
                Ok((r.get(0)?, r.get::<_, i32>(1)? != 0, r.get(2)?))
            })
            .ok();
        rows.into_iter().flatten().filter_map(Result::ok).collect()
    }

    pub fn get_or_inc_message_views(
        &self,
        peer_kind: i32,
        peer_id: i64,
        msg_ids: &[i32],
        increment: bool,
    ) -> Vec<i32> {
        let db = self.conn.lock().unwrap();
        let mut out = Vec::with_capacity(msg_ids.len());
        for &mid in msg_ids {
            let v = if increment {
                db.query_row(
                    "INSERT INTO message_views (peer_kind, peer_id, msg_id, views)
                     VALUES (?1, ?2, ?3, 1)
                     ON CONFLICT (peer_kind, peer_id, msg_id)
                     DO UPDATE SET views = views + 1
                     RETURNING views",
                    params![peer_kind, peer_id, mid],
                    |r| r.get(0),
                )
                .unwrap_or(1)
            } else {
                db.query_row(
                    "SELECT views FROM message_views WHERE peer_kind = ?1 AND peer_id = ?2 AND msg_id = ?3",
                    params![peer_kind, peer_id, mid],
                    |r| r.get(0),
                )
                .unwrap_or(1)
            };
            out.push(v);
        }
        out
    }

    pub fn send_channel_message(
        &self,
        sender_id: i64,
        channel_id: i64,
        random_id: i64,
        text: &str,
        reply_to_msg_id: Option<i32>,
        media_tl: Option<&[u8]>,
    ) -> Result<ChannelMessageDelivery, StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let now = now_unix_i32();

        let (msg_id, c_pts): (i32, i32) = tx
            .query_row(
                "UPDATE channels SET next_msg_id = next_msg_id + 1, channel_pts = channel_pts + 1
                 WHERE channel_id = ?1 RETURNING next_msg_id - 1, channel_pts",
                params![channel_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;

        tx.execute(
            "INSERT INTO channel_messages (channel_id, msg_id, sender_user_id, random_id, date_unix,
                                           reply_to_msg_id, message_text, media_tl, pts)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![channel_id, msg_id, sender_id, random_id, now, reply_to_msg_id, text, media_tl, c_pts],
        )?;

        let subscribers: Vec<i64> = {
            let mut stmt = tx.prepare("SELECT user_id FROM channel_members WHERE channel_id = ?1")?;
            let rows = stmt
                .query_map(params![channel_id], |r| r.get(0))?
                .filter_map(Result::ok)
                .collect();
            rows
        };

        for &uid in &subscribers {
            let inc_unread = if uid == sender_id { 0 } else { 1 };
            tx.execute(
                "INSERT INTO dialogs (user_id, peer_kind, peer_id, top_message_id, unread_count, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(user_id, peer_kind, peer_id) DO UPDATE SET
                    top_message_id = excluded.top_message_id,
                    unread_count   = dialogs.unread_count + ?5,
                    updated_at     = excluded.updated_at",
                params![uid, PEER_CHANNEL, channel_id, msg_id, inc_unread, now],
            )?;
        }

        let channel = tx.query_row(
            "SELECT channel_id, origin_dc_id, creator_id, access_hash, title, username, about,
                    is_broadcast, is_megagroup, is_forum, participants_count, channel_pts, date_unix
             FROM channels WHERE channel_id = ?1",
            params![channel_id],
            map_channel_row,
        )?;
        tx.commit()?;

        let msg = MessageRow {
            owner_user_id: 0,
            msg_id,
            peer_kind: PEER_CHANNEL,
            peer_id: channel_id,
            sender_user_id: sender_id,
            random_id,
            is_out: false,
            date_unix: now,
            edit_date_unix: None,
            reply_to_msg_id,
            message_text: text.to_string(),
            media_tl: media_tl.map(|b| b.to_vec()),
            entities_tl: None,
            ttl_period: None,
        };
        Ok(ChannelMessageDelivery {
            channel,
            msg,
            channel_pts: c_pts,
            subscriber_ids: subscribers,
        })
    }

    pub fn get_channel_history(
        &self,
        channel_id: i64,
        offset_id: i32,
        limit: usize,
        viewer_id: i64,
    ) -> Vec<MessageRow> {
        let db = self.conn.lock().unwrap();
        let lim = limit.clamp(1, 100) as i64;
        let upper = if offset_id <= 0 { i32::MAX } else { offset_id };
        let mut stmt = db
            .prepare(
                "SELECT msg_id, sender_user_id, random_id, date_unix, edit_date_unix,
                        reply_to_msg_id, message_text, media_tl, entities_tl
                 FROM channel_messages
                 WHERE channel_id = ?1 AND deleted = 0 AND msg_id < ?2
                 ORDER BY msg_id DESC
                 LIMIT ?3",
            )
            .unwrap();
        stmt.query_map(params![channel_id, upper, lim], |r| {
            let sender_uid: i64 = r.get(1)?;
            Ok(MessageRow {
                owner_user_id: viewer_id,
                msg_id: r.get(0)?,
                peer_kind: PEER_CHANNEL,
                peer_id: channel_id,
                sender_user_id: sender_uid,
                random_id: r.get(2)?,
                is_out: sender_uid == viewer_id,
                date_unix: r.get(3)?,
                edit_date_unix: r.get(4)?,
                reply_to_msg_id: r.get(5)?,
                message_text: r.get(6)?,
                media_tl: r.get(7)?,
                entities_tl: r.get(8)?,
                ttl_period: None,
            })
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    }

    pub fn get_channel_message(&self, channel_id: i64, msg_id: i32, viewer_id: i64) -> Option<MessageRow> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT msg_id, sender_user_id, random_id, date_unix, edit_date_unix,
                    reply_to_msg_id, message_text, media_tl, entities_tl
             FROM channel_messages
             WHERE channel_id = ?1 AND msg_id = ?2 AND deleted = 0",
            params![channel_id, msg_id],
            |r| {
                let sender_uid: i64 = r.get(1)?;
                Ok(MessageRow {
                    owner_user_id: viewer_id,
                    msg_id: r.get(0)?,
                    peer_kind: PEER_CHANNEL,
                    peer_id: channel_id,
                    sender_user_id: sender_uid,
                    random_id: r.get(2)?,
                    is_out: sender_uid == viewer_id,
                    date_unix: r.get(3)?,
                    edit_date_unix: r.get(4)?,
                    reply_to_msg_id: r.get(5)?,
                    message_text: r.get(6)?,
                    media_tl: r.get(7)?,
                    entities_tl: r.get(8)?,
                    ttl_period: None,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn get_channel_difference(
        &self,
        channel_id: i64,
        from_pts: i32,
        limit: usize,
        viewer_id: i64,
    ) -> Result<(i32, Vec<MessageRow>), StoreError> {
        let chan = self.channel_by_id(channel_id).ok_or(StoreError::NotFound)?;
        if from_pts >= chan.channel_pts {
            return Ok((chan.channel_pts, vec![]));
        }
        let db = self.conn.lock().unwrap();
        let lim = limit.clamp(1, 200) as i64;
        let mut stmt = db.prepare(
            "SELECT msg_id, sender_user_id, random_id, date_unix, edit_date_unix,
                    reply_to_msg_id, message_text, media_tl, entities_tl
             FROM channel_messages
             WHERE channel_id = ?1 AND deleted = 0 AND pts > ?2
             ORDER BY pts ASC
             LIMIT ?3",
        )?;
        let msgs = stmt
            .query_map(params![channel_id, from_pts, lim], |r| {
                let sender_uid: i64 = r.get(1)?;
                Ok(MessageRow {
                    owner_user_id: viewer_id,
                    msg_id: r.get(0)?,
                    peer_kind: PEER_CHANNEL,
                    peer_id: channel_id,
                    sender_user_id: sender_uid,
                    random_id: r.get(2)?,
                    is_out: sender_uid == viewer_id,
                    date_unix: r.get(3)?,
                    edit_date_unix: r.get(4)?,
                    reply_to_msg_id: r.get(5)?,
                    message_text: r.get(6)?,
                    media_tl: r.get(7)?,
                    entities_tl: r.get(8)?,
                    ttl_period: None,
                })
            })?
            .filter_map(Result::ok)
            .collect();
        Ok((chan.channel_pts, msgs))
    }

    pub fn search_channels(&self, query: &str, limit: usize) -> Vec<ChannelRow> {
        let q = query.trim().trim_start_matches('@').to_ascii_lowercase();
        if q.is_empty() {
            return vec![];
        }
        let lim = limit.clamp(1, 50) as i64;
        let pattern = format!("%{q}%");
        let db = self.conn.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT channel_id, origin_dc_id, creator_id, access_hash, title, username, about,
                        is_broadcast, is_megagroup, is_forum, participants_count, channel_pts, date_unix
                 FROM channels
                 WHERE username_lower LIKE ?1 OR LOWER(title) LIKE ?1
                 ORDER BY participants_count DESC
                 LIMIT ?2",
            )
            .unwrap();
        stmt.query_map(params![pattern, lim], map_channel_row)
            .unwrap()
            .filter_map(Result::ok)
            .collect()
    }

    // --- Media Blobs (`gram-media`) -----------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn store_media_blob(
        &self,
        file_id: i64,
        storage_dc_id: i32,
        access_hash: i64,
        owner_user_id: i64,
        mime_type: &str,
        file_name: &str,
        sha256_hex: &str,
        data_bytes: &[u8],
    ) -> Result<(), StoreError> {
        let db = self.conn.lock().unwrap();
        let now = now_unix_i32();
        db.execute(
            "INSERT INTO media_blobs (file_id, storage_dc_id, access_hash, owner_user_id, mime_type,
                                      file_name, byte_size, sha256_hex, data_bytes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(file_id) DO UPDATE SET
                data_bytes = excluded.data_bytes,
                byte_size  = excluded.byte_size,
                sha256_hex = excluded.sha256_hex",
            params![
                file_id,
                storage_dc_id,
                access_hash,
                owner_user_id,
                mime_type,
                file_name,
                data_bytes.len() as i64,
                sha256_hex,
                data_bytes,
                now
            ],
        )?;
        Ok(())
    }

    pub fn get_media_blob(&self, file_id: i64) -> Option<MediaBlobRow> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT file_id, storage_dc_id, access_hash, owner_user_id, mime_type, file_name,
                    byte_size, sha256_hex, data_bytes, created_at
             FROM media_blobs WHERE file_id = ?1",
            params![file_id],
            |r| {
                Ok(MediaBlobRow {
                    file_id: r.get(0)?,
                    storage_dc_id: r.get(1)?,
                    access_hash: r.get(2)?,
                    owner_user_id: r.get(3)?,
                    mime_type: r.get(4)?,
                    file_name: r.get(5)?,
                    byte_size: r.get(6)?,
                    sha256_hex: r.get(7)?,
                    data_bytes: r.get(8)?,
                    created_at: r.get(9)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn save_file_part(&self, file_id: i64, file_part: i32, bytes: &[u8]) -> Result<(), StoreError> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "INSERT INTO file_parts (file_id, file_part, bytes)
             VALUES (?1, ?2, ?3)
             ON CONFLICT (file_id, file_part) DO UPDATE SET bytes = excluded.bytes",
            params![file_id, file_part, bytes],
        )?;
        Ok(())
    }

    pub fn assemble_file_parts(&self, file_id: i64, _total_parts: usize) -> Result<Vec<u8>, StoreError> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db.prepare(
            "SELECT bytes FROM file_parts WHERE file_id = ?1 ORDER BY file_part ASC",
        )?;
        let rows = stmt
            .query_map(params![file_id], |r| r.get::<_, Vec<u8>>(0))?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        if rows.is_empty() {
            return Err(StoreError::NotFound);
        }
        let total_bytes = rows.iter().map(|b| b.len()).sum();
        let mut assembled = Vec::with_capacity(total_bytes);
        for chunk in rows {
            assembled.extend_from_slice(&chunk);
        }
        let _ = db.execute("DELETE FROM file_parts WHERE file_id = ?1", params![file_id]);
        Ok(assembled)
    }

    pub fn update_user_photo(&self, user_id: i64, photo_id: Option<i64>, photo_dc_id: Option<i32>) -> Result<(), StoreError> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "UPDATE users SET photo_id = ?1, photo_dc_id = ?2 WHERE user_id = ?3",
            params![photo_id, photo_dc_id, user_id],
        )?;
        Ok(())
    }

    // --- Stars Wallet, Double-Entry Ledger, Collectible Gifts & +888 --------

    pub fn get_stars_wallet(&self, user_id: i64) -> StarsWalletRow {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT user_id, balance_units, lifetime_minted, lifetime_spent
             FROM stars_wallets WHERE user_id = ?1",
            params![user_id],
            |r| {
                Ok(StarsWalletRow {
                    user_id: r.get(0)?,
                    balance_units: r.get(1)?,
                    lifetime_minted: r.get(2)?,
                    lifetime_spent: r.get(3)?,
                })
            },
        )
        .optional()
        .ok()
        .flatten()
        .unwrap_or(StarsWalletRow {
            user_id,
            balance_units: 0,
            lifetime_minted: 0,
            lifetime_spent: 0,
        })
    }

    pub fn ensure_user_stars_balance(&self, user_id: i64, initial_grant: i64) -> StarsWalletRow {
        let mut wallet = self.get_stars_wallet(user_id);
        if wallet.balance_units == 0 && wallet.lifetime_minted == 0 {
            if let Ok(w) = self.adjust_stars(
                &format!("welcome_grant_{user_id}"),
                user_id,
                None,
                "welcome_grant",
                initial_grant,
                "Welcome Bonus",
            ) {
                wallet = w;
            }
        }
        wallet
    }

    pub fn adjust_stars(
        &self,
        idempotency_key: &str,
        user_id: i64,
        counterparty_id: Option<i64>,
        tx_kind: &str,
        delta_units: i64,
        title: &str,
    ) -> Result<StarsWalletRow, StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let now = now_unix_i32();

        // Idempotent check
        let dup: Option<i64> = tx
            .query_row(
                "SELECT balance_after FROM stars_ledger WHERE idempotency_key = ?1",
                params![idempotency_key],
                |r| r.get(0),
            )
            .optional()?;
        if dup.is_some() {
            tx.commit()?;
            drop(db);
            return Ok(self.get_stars_wallet(user_id));
        }

        tx.execute(
            "INSERT OR IGNORE INTO stars_wallets (user_id, balance_units, lifetime_minted, lifetime_spent, updated_at)
             VALUES (?1, 0, 0, 0, ?2)",
            params![user_id, now],
        )?;

        let cur: i64 = tx.query_row(
            "SELECT balance_units FROM stars_wallets WHERE user_id = ?1",
            params![user_id],
            |r| r.get(0),
        )?;
        let new_bal = cur + delta_units;
        if new_bal < 0 {
            return Err(StoreError::InsufficientBalance);
        }

        let minted_inc = if delta_units > 0 { delta_units } else { 0 };
        let spent_inc = if delta_units < 0 { -delta_units } else { 0 };
        tx.execute(
            "UPDATE stars_wallets
             SET balance_units = ?1,
                 lifetime_minted = lifetime_minted + ?2,
                 lifetime_spent  = lifetime_spent + ?3,
                 updated_at      = ?4
             WHERE user_id = ?5",
            params![new_bal, minted_inc, spent_inc, now, user_id],
        )?;

        let tx_id = format!("tx_{user_id}_{now}_{idempotency_key}");
        tx.execute(
            "INSERT INTO stars_ledger (tx_id, idempotency_key, user_id, counterparty_id, tx_kind, delta_units, balance_after, title, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![tx_id, idempotency_key, user_id, counterparty_id, tx_kind, delta_units, new_bal, title, now],
        )?;
        tx.commit()?;
        drop(db);
        Ok(self.get_stars_wallet(user_id))
    }

    pub fn list_stars_transactions(&self, user_id: Option<i64>, limit: usize) -> Vec<StarsTxRow> {
        let db = self.conn.lock().unwrap();
        let lim = limit.clamp(1, 200) as i64;
        let sql = if user_id.is_some() {
            "SELECT tx_id, user_id, counterparty_id, tx_kind, delta_units, balance_after, title, created_at
             FROM stars_ledger WHERE user_id = ?1 ORDER BY created_at DESC LIMIT ?2"
        } else {
            "SELECT tx_id, user_id, counterparty_id, tx_kind, delta_units, balance_after, title, created_at
             FROM stars_ledger WHERE 1 = ?1 ORDER BY created_at DESC LIMIT ?2"
        };
        let p1 = user_id.unwrap_or(1);
        let mut stmt = db.prepare(sql).unwrap();
        stmt.query_map(params![p1, lim], |r| {
            Ok(StarsTxRow {
                tx_id: r.get(0)?,
                user_id: r.get(1)?,
                counterparty_id: r.get(2)?,
                tx_kind: r.get(3)?,
                delta_units: r.get(4)?,
                balance_after: r.get(5)?,
                title: r.get(6)?,
                created_at: r.get(7)?,
            })
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    }

    pub fn list_gift_catalog(&self) -> Vec<GiftCatalogRow> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT gift_id, slug_prefix, title, star_price_units, upgrade_price_units,
                        convert_units, total_supply, minted_count, is_limited, is_upgradeable
                 FROM gifts_catalog WHERE active = 1 ORDER BY gift_id ASC",
            )
            .unwrap();
        stmt.query_map([], |r| {
            Ok(GiftCatalogRow {
                gift_id: r.get(0)?,
                slug_prefix: r.get(1)?,
                title: r.get(2)?,
                star_price_units: r.get(3)?,
                upgrade_price_units: r.get(4)?,
                convert_units: r.get(5)?,
                total_supply: r.get(6)?,
                minted_count: r.get(7)?,
                is_limited: r.get::<_, i32>(8)? != 0,
                is_upgradeable: r.get::<_, i32>(9)? != 0,
            })
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    }

    pub fn upsert_gift_catalog(&self, row: &GiftCatalogRow) -> Result<(), StoreError> {
        let db = self.conn.lock().unwrap();
        db.execute(
            "INSERT INTO gifts_catalog (gift_id, slug_prefix, title, star_price_units, upgrade_price_units,
                                        convert_units, total_supply, minted_count, is_limited, is_upgradeable, active)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1)
             ON CONFLICT(gift_id) DO UPDATE SET
                title = excluded.title,
                star_price_units = excluded.star_price_units,
                upgrade_price_units = excluded.upgrade_price_units,
                total_supply = excluded.total_supply,
                is_limited = excluded.is_limited,
                is_upgradeable = excluded.is_upgradeable",
            params![
                row.gift_id,
                row.slug_prefix,
                row.title,
                row.star_price_units,
                row.upgrade_price_units,
                row.convert_units,
                row.total_supply,
                row.minted_count,
                row.is_limited as i32,
                row.is_upgradeable as i32
            ],
        )?;
        Ok(())
    }

    /// Atomically purchase a Star Gift for `recipient_id`, deducting `star_price_units`
    /// from `buyer_id`'s wallet and checking `total_supply`.
    pub fn purchase_star_gift(
        &self,
        buyer_id: i64,
        recipient_id: i64,
        gift_id: i64,
        message: &str,
    ) -> Result<UserGiftRow, StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let now = now_unix_i32();

        let (slug_prefix, title, price, supply, minted): (String, String, i64, Option<i32>, i32) = tx
            .query_row(
                "SELECT slug_prefix, title, star_price_units, total_supply, minted_count
                 FROM gifts_catalog WHERE gift_id = ?1 AND active = 1",
                params![gift_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let _ = slug_prefix;

        if let Some(cap) = supply {
            if minted >= cap {
                return Err(StoreError::SoldOut);
            }
        }

        let cur_bal: i64 = tx
            .query_row(
                "SELECT balance_units FROM stars_wallets WHERE user_id = ?1",
                params![buyer_id],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(0);
        if cur_bal < price {
            return Err(StoreError::InsufficientBalance);
        }

        let new_bal = cur_bal - price;
        tx.execute(
            "UPDATE stars_wallets SET balance_units = ?1, lifetime_spent = lifetime_spent + ?2, updated_at = ?3
             WHERE user_id = ?4",
            params![new_bal, price, now, buyer_id],
        )?;
        tx.execute(
            "UPDATE gifts_catalog SET minted_count = minted_count + 1 WHERE gift_id = ?1",
            params![gift_id],
        )?;
        tx.execute(
            "INSERT INTO user_gifts (gift_id, owner_user_id, sender_user_id, is_upgraded, message, minted_at)
             VALUES (?1, ?2, ?3, 0, ?4, ?5)",
            params![gift_id, recipient_id, buyer_id, message, now],
        )?;
        let instance_id = tx.last_insert_rowid();
        let tx_key = format!("gift_buy_{instance_id}");
        tx.execute(
            "INSERT INTO stars_ledger (tx_id, idempotency_key, user_id, counterparty_id, tx_kind, delta_units, balance_after, title, created_at)
             VALUES (?1, ?1, ?2, ?3, 'gift_purchase', ?4, ?5, ?6, ?7)",
            params![tx_key, buyer_id, recipient_id, -price, new_bal, title, now],
        )?;
        tx.commit()?;
        Ok(UserGiftRow {
            instance_id,
            gift_id,
            owner_user_id: recipient_id,
            sender_user_id: Some(buyer_id),
            serial_number: None,
            collectible_slug: None,
            is_upgraded: false,
            message: message.to_string(),
            minted_at: now,
        })
    }

    /// Atomically upgrade an owned Star Gift into a unique Collectible (`Slug-Serial`)!
    pub fn upgrade_star_gift(&self, owner_id: i64, instance_id: i64) -> Result<UserGiftRow, StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let now = now_unix_i32();

        let (gift_id, cur_owner, already): (i64, i64, i32) = tx
            .query_row(
                "SELECT gift_id, owner_user_id, is_upgraded FROM user_gifts WHERE instance_id = ?1",
                params![instance_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        if cur_owner != owner_id {
            return Err(StoreError::PermissionDenied);
        }
        if already != 0 {
            let row = query_user_gift_tx(&tx, instance_id)?;
            tx.commit()?;
            return Ok(row);
        }

        let (slug_prefix, upgrade_price): (String, i64) = tx.query_row(
            "SELECT slug_prefix, upgrade_price_units FROM gifts_catalog WHERE gift_id = ?1",
            params![gift_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        if upgrade_price > 0 {
            let cur_bal: i64 = tx
                .query_row(
                    "SELECT balance_units FROM stars_wallets WHERE user_id = ?1",
                    params![owner_id],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or(0);
            if cur_bal < upgrade_price {
                return Err(StoreError::InsufficientBalance);
            }
            let new_bal = cur_bal - upgrade_price;
            tx.execute(
                "UPDATE stars_wallets SET balance_units = ?1, lifetime_spent = lifetime_spent + ?2, updated_at = ?3
                 WHERE user_id = ?4",
                params![new_bal, upgrade_price, now, owner_id],
            )?;
            let tx_key = format!("gift_upg_{instance_id}");
            tx.execute(
                "INSERT INTO stars_ledger (tx_id, idempotency_key, user_id, counterparty_id, tx_kind, delta_units, balance_after, title, created_at)
                 VALUES (?1, ?1, ?2, NULL, 'gift_upgrade', ?3, ?4, ?5, ?6)",
                params![tx_key, owner_id, -upgrade_price, new_bal, slug_prefix, now],
            )?;
        }

        let next_serial: i32 = tx.query_row(
            "SELECT COALESCE(MAX(serial_number), 0) + 1 FROM user_gifts WHERE gift_id = ?1",
            params![gift_id],
            |r| r.get(0),
        )?;
        let slug = format!("{slug_prefix}-{next_serial}");
        tx.execute(
            "UPDATE user_gifts SET is_upgraded = 1, serial_number = ?1, collectible_slug = ?2 WHERE instance_id = ?3",
            params![next_serial, slug, instance_id],
        )?;
        let row = query_user_gift_tx(&tx, instance_id)?;
        tx.commit()?;
        Ok(row)
    }

    pub fn transfer_star_gift(
        &self,
        owner_id: i64,
        instance_id: i64,
        new_owner_id: i64,
    ) -> Result<UserGiftRow, StoreError> {
        let mut db = self.conn.lock().unwrap();
        let tx = db.transaction()?;
        let cur_owner: i64 = tx
            .query_row(
                "SELECT owner_user_id FROM user_gifts WHERE instance_id = ?1",
                params![instance_id],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        if cur_owner != owner_id {
            return Err(StoreError::PermissionDenied);
        }
        tx.execute(
            "UPDATE user_gifts SET owner_user_id = ?1 WHERE instance_id = ?2",
            params![new_owner_id, instance_id],
        )?;
        let row = query_user_gift_tx(&tx, instance_id)?;
        tx.commit()?;
        Ok(row)
    }

    pub fn list_user_gifts(&self, owner_user_id: i64) -> Vec<UserGiftRow> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT instance_id, gift_id, owner_user_id, sender_user_id, serial_number,
                        collectible_slug, is_upgraded, message, minted_at
                 FROM user_gifts WHERE owner_user_id = ?1 ORDER BY instance_id DESC",
            )
            .unwrap();
        stmt.query_map(params![owner_user_id], |r| {
            Ok(UserGiftRow {
                instance_id: r.get(0)?,
                gift_id: r.get(1)?,
                owner_user_id: r.get(2)?,
                sender_user_id: r.get(3)?,
                serial_number: r.get(4)?,
                collectible_slug: r.get(5)?,
                is_upgraded: r.get::<_, i32>(6)? != 0,
                message: r.get(7)?,
                minted_at: r.get(8)?,
            })
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    }

    pub fn issue_virtual_number(
        &self,
        phone_digits: &str,
        owner_user_id: Option<i64>,
        assigned_dc_id: i32,
        price_units: i64,
    ) -> Result<VirtualNumberRow, StoreError> {
        let clean: String = phone_digits.chars().filter(|c| c.is_ascii_digit()).collect();
        let db = self.conn.lock().unwrap();
        let now = now_unix_i32();
        db.execute(
            "INSERT INTO virtual_numbers (phone_digits, owner_user_id, assigned_dc_id, price_units, is_locked, issued_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5)
             ON CONFLICT(phone_digits) DO UPDATE SET
                owner_user_id  = excluded.owner_user_id,
                assigned_dc_id = excluded.assigned_dc_id,
                price_units    = excluded.price_units",
            params![clean, owner_user_id, assigned_dc_id, price_units, now],
        )?;
        Ok(VirtualNumberRow {
            phone_digits: clean,
            owner_user_id,
            assigned_dc_id,
            price_units,
            is_locked: false,
            issued_at: now,
        })
    }

    pub fn lookup_phone_dc(&self, phone_digits: &str) -> Option<i32> {
        let db = self.conn.lock().unwrap();
        if let Some(dc) = db
            .query_row(
                "SELECT home_dc_id FROM users WHERE phone = ?1",
                params![phone_digits],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
        {
            return Some(dc);
        }
        db.query_row(
            "SELECT assigned_dc_id FROM virtual_numbers WHERE phone_digits = ?1",
            params![phone_digits],
            |r| r.get(0),
        )
        .optional()
        .ok()
        .flatten()
    }

    pub fn list_virtual_numbers(&self) -> Vec<VirtualNumberRow> {
        let db = self.conn.lock().unwrap();
        let mut stmt = db
            .prepare(
                "SELECT phone_digits, owner_user_id, assigned_dc_id, price_units, is_locked, issued_at
                 FROM virtual_numbers ORDER BY issued_at DESC, phone_digits ASC",
            )
            .unwrap();
        stmt.query_map([], |r| {
            Ok(VirtualNumberRow {
                phone_digits: r.get(0)?,
                owner_user_id: r.get(1)?,
                assigned_dc_id: r.get(2)?,
                price_units: r.get(3)?,
                is_locked: r.get::<_, i32>(4)? != 0,
                issued_at: r.get(5)?,
            })
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    }

    pub fn user_count(&self) -> usize {
        let db = self.conn.lock().unwrap();
        db.query_row("SELECT COUNT(*) FROM users", [], |r| r.get::<_, i64>(0))
            .unwrap_or(0) as usize
    }

    pub fn record_audit(
        &self,
        operator_name: &str,
        action_code: &str,
        target_entity: &str,
        detail_json: &str,
    ) {
        let db = self.conn.lock().unwrap();
        let _ = db.execute(
            "INSERT INTO admin_audit_log (operator_name, action_code, target_entity, detail_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![operator_name, action_code, target_entity, detail_json, now_unix_i32()],
        );
    }

    pub fn list_audit_log(&self, limit: usize) -> Vec<AuditLogRow> {
        let db = self.conn.lock().unwrap();
        let lim = limit.clamp(1, 500) as i64;
        let mut stmt = db
            .prepare(
                "SELECT audit_id, operator_name, action_code, target_entity, detail_json, created_at
                 FROM admin_audit_log ORDER BY audit_id DESC LIMIT ?1",
            )
            .unwrap();
        stmt.query_map(params![lim], |r| {
            Ok(AuditLogRow {
                audit_id: r.get(0)?,
                operator_name: r.get(1)?,
                action_code: r.get(2)?,
                target_entity: r.get(3)?,
                detail_json: r.get(4)?,
                created_at: r.get(5)?,
            })
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    }

    pub fn get_setting(&self, key: &str) -> Option<String> {
        let db = self.conn.lock().unwrap();
        db.query_row(
            "SELECT setting_val FROM server_settings WHERE setting_key = ?1",
            params![key],
            |r| r.get(0),
        ).ok()
    }

    pub fn set_setting(&self, key: &str, val: &str) -> Result<(), StoreError> {
        let db = self.conn.lock().unwrap();
        let now = now_unix_i32();
        db.execute(
            "INSERT INTO server_settings (setting_key, setting_val, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(setting_key) DO UPDATE SET setting_val = excluded.setting_val, updated_at = excluded.updated_at",
            params![key, val, now],
        )?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
fn append_pts_event_tx(
    tx: &rusqlite::Transaction<'_>,
    user_id: i64,
    pts: i32,
    date_unix: i32,
    update_kind: i32,
    msg_id: i32,
    peer_kind: i32,
    peer_id: i64,
    extra_i32: i32,
) -> Result<(), rusqlite::Error> {
    tx.execute(
        "INSERT INTO pts_updates (user_id, pts, pts_count, date_unix, update_kind, msg_id, peer_kind, peer_id, extra_i32)
         VALUES (?1, ?2, 1, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![user_id, pts, date_unix, update_kind, msg_id, peer_kind, peer_id, extra_i32],
    )?;
    // Keep ring bounded to the latest 2,048 pts events per user!
    if pts > 2048 && (pts & 63) == 0 {
        tx.execute(
            "DELETE FROM pts_updates WHERE user_id = ?1 AND pts <= ?2",
            params![user_id, pts - 2048],
        )?;
    }
    Ok(())
}

fn query_user_gift_tx(
    tx: &rusqlite::Transaction<'_>,
    instance_id: i64,
) -> Result<UserGiftRow, rusqlite::Error> {
    tx.query_row(
        "SELECT instance_id, gift_id, owner_user_id, sender_user_id, serial_number,
                collectible_slug, is_upgraded, message, minted_at
         FROM user_gifts WHERE instance_id = ?1",
        params![instance_id],
        |r| {
            Ok(UserGiftRow {
                instance_id: r.get(0)?,
                gift_id: r.get(1)?,
                owner_user_id: r.get(2)?,
                sender_user_id: r.get(3)?,
                serial_number: r.get(4)?,
                collectible_slug: r.get(5)?,
                is_upgraded: r.get::<_, i32>(6)? != 0,
                message: r.get(7)?,
                minted_at: r.get(8)?,
            })
        },
    )
}

fn map_user_row(r: &rusqlite::Row<'_>) -> Result<UserRow, rusqlite::Error> {
    Ok(UserRow {
        user_id: r.get(0)?,
        home_dc_id: r.get(1)?,
        dc_epoch: r.get(2)?,
        access_hash: r.get(3)?,
        phone: r.get(4)?,
        username: r.get(5)?,
        first_name: r.get(6)?,
        last_name: r.get(7)?,
        bio: r.get(8)?,
        flags_bitmask: r.get(9)?,
        pts: r.get(10)?,
        qts: r.get(11)?,
        photo_id: r.get(12)?,
        photo_dc_id: r.get(13)?,
    })
}

fn map_message_row(r: &rusqlite::Row<'_>) -> Result<MessageRow, rusqlite::Error> {
    Ok(MessageRow {
        owner_user_id: r.get(0)?,
        msg_id: r.get(1)?,
        peer_kind: r.get(2)?,
        peer_id: r.get(3)?,
        sender_user_id: r.get(4)?,
        random_id: r.get(5)?,
        is_out: r.get::<_, i32>(6)? != 0,
        date_unix: r.get(7)?,
        edit_date_unix: r.get(8)?,
        reply_to_msg_id: r.get(9)?,
        message_text: r.get(10)?,
        media_tl: r.get(11)?,
        entities_tl: r.get(12)?,
        ttl_period: r.get(13)?,
    })
}

fn map_channel_row(r: &rusqlite::Row<'_>) -> Result<ChannelRow, rusqlite::Error> {
    Ok(ChannelRow {
        channel_id: r.get(0)?,
        origin_dc_id: r.get(1)?,
        creator_id: r.get(2)?,
        access_hash: r.get(3)?,
        title: r.get(4)?,
        username: r.get(5)?,
        about: r.get(6)?,
        is_broadcast: r.get::<_, i32>(7)? != 0,
        is_megagroup: r.get::<_, i32>(8)? != 0,
        is_forum: r.get::<_, i32>(9)? != 0,
        participants_count: r.get(10)?,
        channel_pts: r.get(11)?,
        date_unix: r.get(12)?,
    })
}

fn validate_username(raw: &str) -> Result<&str, StoreError> {
    let s = raw.trim().trim_start_matches('@');
    if !(3..=32).contains(&s.len()) {
        return Err(StoreError::UsernameInvalid);
    }
    let first = s.as_bytes()[0];
    if !first.is_ascii_alphabetic() {
        return Err(StoreError::UsernameInvalid);
    }
    if s.ends_with('_') || s.contains("__") {
        return Err(StoreError::UsernameInvalid);
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return Err(StoreError::UsernameInvalid);
    }
    Ok(s)
}

fn now_unix_i32() -> i32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i32)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_and_lua_scripts_are_embedded_and_nonempty() {
        assert_eq!(MIGRATIONS.len(), 8);
        for (name, sql) in MIGRATIONS {
            assert!(!sql.is_empty(), "{name} must not be empty");
            assert!(sql.contains("CREATE TABLE"), "{name} must define tables");
        }
        assert!(ALLOC_PTS_AND_APPEND_LUA.contains("ZADD"));
        assert!(CONSUME_EXPORT_AUTH_LUA.contains("TICKET_ALREADY_USED"));
    }

    #[test]
    fn direct_messaging_edit_delete_read_and_pts_difference_work() {
        let store = AcidStore::open_in_memory(2).unwrap();
        let alice = store
            .get_or_create_user("88800000001", Some("Alice"), Some(""))
            .unwrap();
        let bob = store
            .get_or_create_user("88800000002", Some("Bob"), Some(""))
            .unwrap();

        let d1 = store
            .send_direct_message(alice.user_id, bob.user_id, 777001, "Hello Bob!", None, None, None, None)
            .unwrap();
        assert!(!d1.deduplicated);
        assert_eq!(d1.sender_pts, 2);
        let (bob_msg, bob_pts) = d1.recipient_msg.unwrap();
        assert_eq!(bob_pts, 2);
        assert_eq!(bob_msg.message_text, "Hello Bob!");

        // Idempotent retry with same random_id
        let dup = store
            .send_direct_message(alice.user_id, bob.user_id, 777001, "Hello Bob!", None, None, None, None)
            .unwrap();
        assert!(dup.deduplicated);
        assert_eq!(dup.sender_pts, 2);

        // Edit message
        let edit_out = store
            .edit_direct_message(alice.user_id, d1.sender_msg.msg_id, "Hello Bob (edited)!")
            .unwrap();
        assert_eq!(edit_out.actor_pts, 3);
        assert_eq!(edit_out.actor_msg.message_text, "Hello Bob (edited)!");
        assert_eq!(edit_out.peer_updated.unwrap().1, 3);

        // Read history by Bob -> updates Alice's outbox max id
        let read_out = store
            .read_history(bob.user_id, PEER_USER, alice.user_id, bob_msg.msg_id)
            .unwrap();
        assert_eq!(read_out.reader_pts, 4);
        let (auid, max_out, a_pts4) = read_out.outbox_peer.unwrap();
        assert_eq!(auid, alice.user_id);
        assert_eq!(max_out, d1.sender_msg.msg_id);
        assert_eq!(a_pts4, 4);

        // Bob fetches getDifference from pts=1 -> sees [new_msg(2), edit(3), read_inbox(4)]!
        let (latest_b, events) = store.get_pts_difference(bob.user_id, 1, 100);
        assert_eq!(latest_b, 4);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].update_kind, PTS_KIND_NEW_MESSAGE);
        assert_eq!(events[1].update_kind, PTS_KIND_EDIT_MESSAGE);
        assert_eq!(events[2].update_kind, PTS_KIND_READ_INBOX);
    }

    #[test]
    fn stars_wallet_and_collectible_gift_upgrade_invariants() {
        let store = AcidStore::open_in_memory(2).unwrap();
        let alice = store.get_or_create_user("88800000010", Some("Alice"), None).unwrap();
        let bob = store.get_or_create_user("88800000011", Some("Bob"), None).unwrap();

        store
            .adjust_stars("mint1", alice.user_id, None, "admin_mint", 500, "Initial grant")
            .unwrap();
        let gift = store
            .purchase_star_gift(alice.user_id, bob.user_id, 5001, "Congrats!")
            .unwrap();
        assert_eq!(store.get_stars_wallet(alice.user_id).balance_units, 450);

        store
            .adjust_stars("mint2", bob.user_id, None, "admin_mint", 100, "Upgrade budget")
            .unwrap();
        let upgraded = store.upgrade_star_gift(bob.user_id, gift.instance_id).unwrap();
        assert!(upgraded.is_upgraded);
        assert_eq!(upgraded.collectible_slug.as_deref(), Some("CrystalStar-1"));
        assert_eq!(store.get_stars_wallet(bob.user_id).balance_units, 75);
    }
}

-- 0004_dialogs_messages_updates.up.sql
CREATE TABLE dialogs (
    dc_id                   SMALLINT NOT NULL,
    user_id                 BIGINT NOT NULL,
    peer_kind               SMALLINT NOT NULL,
    peer_id                 BIGINT NOT NULL,
    folder_id               SMALLINT NOT NULL DEFAULT 0,
    pinned_order            SMALLINT,
    top_message_id          INTEGER NOT NULL DEFAULT 0,
    read_inbox_max_id       INTEGER NOT NULL DEFAULT 0,
    read_outbox_max_id      INTEGER NOT NULL DEFAULT 0,
    unread_count            INTEGER NOT NULL DEFAULT 0,
    unread_mentions_count   INTEGER NOT NULL DEFAULT 0,
    unread_reactions_count  INTEGER NOT NULL DEFAULT 0,
    notify_settings_json    JSONB NOT NULL DEFAULT '{}'::jsonb,
    draft_tl                BYTEA,
    pts_checkpoint          INTEGER NOT NULL DEFAULT 0,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (dc_id, user_id, peer_kind, peer_id)
) PARTITION BY LIST (dc_id);

CREATE TABLE dialogs_dc1 PARTITION OF dialogs FOR VALUES IN (1);
CREATE TABLE dialogs_dc2 PARTITION OF dialogs FOR VALUES IN (2);
CREATE TABLE dialogs_dc3 PARTITION OF dialogs FOR VALUES IN (3);
CREATE TABLE dialogs_dc4 PARTITION OF dialogs FOR VALUES IN (4);
CREATE TABLE dialogs_dc5 PARTITION OF dialogs FOR VALUES IN (5);

CREATE TABLE messages (
    dc_id               SMALLINT NOT NULL,
    owner_user_id       BIGINT NOT NULL,
    msg_id              INTEGER NOT NULL,
    peer_kind           SMALLINT NOT NULL,
    peer_id             BIGINT NOT NULL,
    sender_user_id      BIGINT NOT NULL,
    random_id           BIGINT NOT NULL,
    is_out              BOOLEAN NOT NULL,
    flags_bitmask       BIGINT NOT NULL DEFAULT 0,
    date_unix           INTEGER NOT NULL,
    edit_date_unix      INTEGER,
    message_text        TEXT NOT NULL DEFAULT '',
    entities_tl         BYTEA,
    media_tl            BYTEA,
    reply_header_tl     BYTEA,
    fwd_header_tl       BYTEA,
    reactions_json      JSONB,
    grouped_id          BIGINT,
    ttl_period          INTEGER,
    expire_at           TIMESTAMPTZ,
    PRIMARY KEY (dc_id, owner_user_id, msg_id)
) PARTITION BY LIST (dc_id);

CREATE TABLE messages_dc1 PARTITION OF messages FOR VALUES IN (1);
CREATE TABLE messages_dc2 PARTITION OF messages FOR VALUES IN (2);
CREATE TABLE messages_dc3 PARTITION OF messages FOR VALUES IN (3);
CREATE TABLE messages_dc4 PARTITION OF messages FOR VALUES IN (4);
CREATE TABLE messages_dc5 PARTITION OF messages FOR VALUES IN (5);

CREATE INDEX idx_messages_dialog_history ON messages (dc_id, owner_user_id, peer_kind, peer_id, msg_id DESC);
CREATE UNIQUE INDEX idx_messages_dedup_random ON messages (dc_id, owner_user_id, random_id) WHERE random_id <> 0;

CREATE TABLE pts_updates (
    dc_id               SMALLINT NOT NULL,
    user_id             BIGINT NOT NULL,
    pts                 INTEGER NOT NULL,
    pts_count           INTEGER NOT NULL DEFAULT 1,
    date_unix           INTEGER NOT NULL,
    update_kind         SMALLINT NOT NULL,
    update_tl           BYTEA NOT NULL,
    PRIMARY KEY (dc_id, user_id, pts)
) PARTITION BY LIST (dc_id);

CREATE TABLE pts_updates_dc1 PARTITION OF pts_updates FOR VALUES IN (1);
CREATE TABLE pts_updates_dc2 PARTITION OF pts_updates FOR VALUES IN (2);
CREATE TABLE pts_updates_dc3 PARTITION OF pts_updates FOR VALUES IN (3);
CREATE TABLE pts_updates_dc4 PARTITION OF pts_updates FOR VALUES IN (4);
CREATE TABLE pts_updates_dc5 PARTITION OF pts_updates FOR VALUES IN (5);

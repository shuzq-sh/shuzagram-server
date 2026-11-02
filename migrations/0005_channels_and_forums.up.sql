-- 0005_channels_and_forums.up.sql
CREATE TABLE channels (
    origin_dc_id        SMALLINT NOT NULL,
    channel_id          BIGINT NOT NULL,
    access_hash_seed    BIGINT NOT NULL,
    title               VARCHAR(255) NOT NULL,
    username            VARCHAR(64),
    about               VARCHAR(255) NOT NULL DEFAULT '',
    flags_bitmask       BIGINT NOT NULL DEFAULT 0,
    participants_count  INTEGER NOT NULL DEFAULT 1,
    channel_pts         INTEGER NOT NULL DEFAULT 1,
    photo_json          JSONB,
    slowmode_seconds    INTEGER NOT NULL DEFAULT 0,
    linked_chat_id      BIGINT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (origin_dc_id, channel_id)
) PARTITION BY LIST (origin_dc_id);

CREATE TABLE channels_dc1 PARTITION OF channels FOR VALUES IN (1);
CREATE TABLE channels_dc2 PARTITION OF channels FOR VALUES IN (2);
CREATE TABLE channels_dc3 PARTITION OF channels FOR VALUES IN (3);
CREATE TABLE channels_dc4 PARTITION OF channels FOR VALUES IN (4);
CREATE TABLE channels_dc5 PARTITION OF channels FOR VALUES IN (5);

CREATE TABLE channel_pts_updates (
    origin_dc_id        SMALLINT NOT NULL,
    channel_id          BIGINT NOT NULL,
    pts                 INTEGER NOT NULL,
    pts_count           INTEGER NOT NULL DEFAULT 1,
    date_unix           INTEGER NOT NULL,
    msg_id              INTEGER,
    update_tl           BYTEA NOT NULL,
    PRIMARY KEY (origin_dc_id, channel_id, pts)
) PARTITION BY LIST (origin_dc_id);

CREATE TABLE channel_pts_updates_dc1 PARTITION OF channel_pts_updates FOR VALUES IN (1);
CREATE TABLE channel_pts_updates_dc2 PARTITION OF channel_pts_updates FOR VALUES IN (2);
CREATE TABLE channel_pts_updates_dc3 PARTITION OF channel_pts_updates FOR VALUES IN (3);
CREATE TABLE channel_pts_updates_dc4 PARTITION OF channel_pts_updates FOR VALUES IN (4);
CREATE TABLE channel_pts_updates_dc5 PARTITION OF channel_pts_updates FOR VALUES IN (5);

-- 0002_users_and_routing.up.sql
CREATE TABLE global_directory_routing (
    lookup_kind         SMALLINT NOT NULL, -- 1=user_id, 2=phone_e164, 3=username_lower, 4=channel_id
    lookup_key          TEXT NOT NULL,
    entity_id           BIGINT NOT NULL,
    home_dc_id          SMALLINT NOT NULL REFERENCES dc_clusters(dc_id),
    dc_epoch            BIGINT NOT NULL DEFAULT 1,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (lookup_kind, lookup_key)
);

CREATE INDEX idx_global_routing_entity ON global_directory_routing (entity_id, lookup_kind);

CREATE TABLE users (
    dc_id               SMALLINT NOT NULL,
    user_id             BIGINT NOT NULL,
    dc_epoch            BIGINT NOT NULL DEFAULT 1,
    access_hash_seed    BIGINT NOT NULL,
    phone               VARCHAR(32),
    username            VARCHAR(64),
    first_name          VARCHAR(128) NOT NULL DEFAULT '',
    last_name           VARCHAR(128) NOT NULL DEFAULT '',
    bio                 VARCHAR(256) NOT NULL DEFAULT '',
    flags_bitmask       BIGINT NOT NULL DEFAULT 0,
    emoji_status_doc_id BIGINT,
    emoji_status_until  TIMESTAMPTZ,
    profile_photo_json  JSONB,
    privacy_rules_json  JSONB NOT NULL DEFAULT '{}'::jsonb,
    password_srp_json   JSONB,
    pts                 INTEGER NOT NULL DEFAULT 1,
    qts                 INTEGER NOT NULL DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (dc_id, user_id)
) PARTITION BY LIST (dc_id);

CREATE TABLE users_dc1 PARTITION OF users FOR VALUES IN (1);
CREATE TABLE users_dc2 PARTITION OF users FOR VALUES IN (2);
CREATE TABLE users_dc3 PARTITION OF users FOR VALUES IN (3);
CREATE TABLE users_dc4 PARTITION OF users FOR VALUES IN (4);
CREATE TABLE users_dc5 PARTITION OF users FOR VALUES IN (5);

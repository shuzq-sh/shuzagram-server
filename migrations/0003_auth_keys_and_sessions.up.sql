-- 0003_auth_keys_and_sessions.up.sql
CREATE TABLE auth_keys (
    dc_id               SMALLINT NOT NULL,
    auth_key_id         BIGINT NOT NULL,
    auth_key_bytes      BYTEA NOT NULL CHECK (octet_length(auth_key_bytes) = 256),
    is_temp_key         BOOLEAN NOT NULL DEFAULT FALSE,
    perm_auth_key_id    BIGINT,
    bound_user_id       BIGINT,
    user_home_dc_id     SMALLINT,
    binding_mode        SMALLINT NOT NULL DEFAULT 0,
    expires_at          TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (dc_id, auth_key_id)
) PARTITION BY LIST (dc_id);

CREATE TABLE auth_keys_dc1 PARTITION OF auth_keys FOR VALUES IN (1);
CREATE TABLE auth_keys_dc2 PARTITION OF auth_keys FOR VALUES IN (2);
CREATE TABLE auth_keys_dc3 PARTITION OF auth_keys FOR VALUES IN (3);
CREATE TABLE auth_keys_dc4 PARTITION OF auth_keys FOR VALUES IN (4);
CREATE TABLE auth_keys_dc5 PARTITION OF auth_keys FOR VALUES IN (5);

CREATE INDEX idx_auth_keys_user ON auth_keys (dc_id, bound_user_id) WHERE bound_user_id IS NOT NULL;

CREATE TABLE user_authorizations (
    dc_id               SMALLINT NOT NULL,
    user_id             BIGINT NOT NULL,
    session_hash        BIGINT NOT NULL,
    auth_key_id         BIGINT NOT NULL,
    api_id              INTEGER NOT NULL,
    app_name            VARCHAR(64) NOT NULL,
    app_version         VARCHAR(64) NOT NULL,
    device_model        VARCHAR(128) NOT NULL,
    platform            VARCHAR(64) NOT NULL,
    system_version      VARCHAR(64) NOT NULL,
    client_layer        SMALLINT NOT NULL DEFAULT 232,
    ip_address          INET NOT NULL,
    country_iso2        CHAR(2) NOT NULL DEFAULT 'ZZ',
    edge_node_id        VARCHAR(64),
    is_official_app     BOOLEAN NOT NULL DEFAULT FALSE,
    is_password_pending BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    active_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (dc_id, user_id, session_hash)
) PARTITION BY LIST (dc_id);

CREATE TABLE user_authorizations_dc1 PARTITION OF user_authorizations FOR VALUES IN (1);
CREATE TABLE user_authorizations_dc2 PARTITION OF user_authorizations FOR VALUES IN (2);
CREATE TABLE user_authorizations_dc3 PARTITION OF user_authorizations FOR VALUES IN (3);
CREATE TABLE user_authorizations_dc4 PARTITION OF user_authorizations FOR VALUES IN (4);
CREATE TABLE user_authorizations_dc5 PARTITION OF user_authorizations FOR VALUES IN (5);

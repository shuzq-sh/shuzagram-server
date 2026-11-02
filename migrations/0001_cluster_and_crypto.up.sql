-- 0001_cluster_and_crypto.up.sql
CREATE TABLE dc_clusters (
    dc_id               SMALLINT PRIMARY KEY CHECK (dc_id BETWEEN 1 AND 32000),
    region_code         VARCHAR(32) NOT NULL,
    display_name        VARCHAR(64) NOT NULL,
    status              VARCHAR(16) NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'draining', 'readonly', 'offline')),
    is_default_entry    BOOLEAN NOT NULL DEFAULT FALSE,
    is_media_only       BOOLEAN NOT NULL DEFAULT FALSE,
    is_cdn              BOOLEAN NOT NULL DEFAULT FALSE,
    endpoints_json      JSONB NOT NULL DEFAULT '[]'::jsonb,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE rsa_keys (
    fingerprint         BIGINT PRIMARY KEY,
    public_pem          TEXT NOT NULL,
    private_pem_enc     BYTEA NOT NULL,
    status              VARCHAR(16) NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'deprecated', 'revoked')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ
);

CREATE TABLE dh_configs (
    version             INTEGER PRIMARY KEY,
    prime_p             BYTEA NOT NULL CHECK (octet_length(prime_p) = 256),
    generator_g         INTEGER NOT NULL CHECK (generator_g IN (2, 3, 4, 5, 6, 7)),
    is_current          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

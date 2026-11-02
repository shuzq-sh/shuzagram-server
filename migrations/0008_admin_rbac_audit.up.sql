-- 0008_admin_rbac_audit.up.sql
CREATE TABLE admin_operators (
    operator_id         UUID PRIMARY KEY,
    username            VARCHAR(64) NOT NULL UNIQUE,
    password_argon2id   TEXT NOT NULL,
    permissions         TEXT[] NOT NULL DEFAULT '{}',
    is_superadmin       BOOLEAN NOT NULL DEFAULT FALSE,
    is_disabled         BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login_at       TIMESTAMPTZ
);

CREATE TABLE admin_audit_log (
    audit_id            BIGSERIAL PRIMARY KEY,
    operator_id         UUID NOT NULL REFERENCES admin_operators(operator_id),
    action_code         VARCHAR(64) NOT NULL,
    target_entity       VARCHAR(128) NOT NULL,
    before_json         JSONB,
    after_json          JSONB,
    client_ip           INET NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

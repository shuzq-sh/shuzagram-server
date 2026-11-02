-- 0007_economy_stars_gifts.up.sql
CREATE TABLE stars_wallets (
    user_id             BIGINT PRIMARY KEY,
    balance_units       BIGINT NOT NULL DEFAULT 0 CHECK (balance_units >= 0),
    escrow_units        BIGINT NOT NULL DEFAULT 0 CHECK (escrow_units >= 0),
    lifetime_minted     BIGINT NOT NULL DEFAULT 0,
    lifetime_spent      BIGINT NOT NULL DEFAULT 0,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE stars_ledger (
    tx_id               UUID PRIMARY KEY,
    idempotency_key     VARCHAR(128) NOT NULL UNIQUE,
    user_id             BIGINT NOT NULL REFERENCES stars_wallets(user_id),
    counterparty_id     BIGINT,
    tx_kind             VARCHAR(32) NOT NULL
                        CHECK (tx_kind IN ('admin_mint', 'admin_burn', 'gift_purchase', 'gift_upgrade',
                                           'gift_transfer_fee', 'miniapp_invoice', 'refund', 'giveaway')),
    delta_units         BIGINT NOT NULL,
    balance_after       BIGINT NOT NULL CHECK (balance_after >= 0),
    commission_units    BIGINT NOT NULL DEFAULT 0,
    metadata_json       JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_stars_ledger_user_time ON stars_ledger (user_id, created_at DESC);

CREATE TABLE gifts_catalog (
    gift_id             BIGINT PRIMARY KEY,
    slug_prefix         VARCHAR(64) NOT NULL UNIQUE,
    title               VARCHAR(128) NOT NULL,
    sticker_file_id     BIGINT NOT NULL,
    sticker_dc_id       SMALLINT NOT NULL,
    star_price_units    BIGINT NOT NULL CHECK (star_price_units > 0),
    upgrade_price_units BIGINT,
    convert_resale_units BIGINT NOT NULL DEFAULT 0,
    total_supply        INTEGER,
    minted_count        INTEGER NOT NULL DEFAULT 0,
    is_limited          BOOLEAN NOT NULL DEFAULT FALSE,
    is_upgradeable      BOOLEAN NOT NULL DEFAULT FALSE,
    upgrade_pool_json   JSONB NOT NULL DEFAULT '{"models":[],"backdrops":[],"symbols":[]}'::jsonb,
    active              BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE user_gifts (
    instance_id         BIGINT PRIMARY KEY,
    gift_id             BIGINT NOT NULL REFERENCES gifts_catalog(gift_id),
    owner_user_id       BIGINT NOT NULL,
    sender_user_id      BIGINT,
    serial_number       INTEGER,
    collectible_slug    VARCHAR(96) UNIQUE,
    is_upgraded         BOOLEAN NOT NULL DEFAULT FALSE,
    is_pinned_profile   BOOLEAN NOT NULL DEFAULT FALSE,
    is_hidden_sender    BOOLEAN NOT NULL DEFAULT FALSE,
    chosen_model_json   JSONB,
    chosen_backdrop_json JSONB,
    chosen_symbol_json  JSONB,
    withdrawal_state    VARCHAR(24) NOT NULL DEFAULT 'offchain'
                        CHECK (withdrawal_state IN ('offchain', 'pending_withdrawal', 'withdrawn', 'listed')),
    asking_price_units  BIGINT,
    minted_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    upgraded_at         TIMESTAMPTZ
);

CREATE INDEX idx_user_gifts_owner ON user_gifts (owner_user_id, is_pinned_profile DESC, minted_at DESC);

CREATE TABLE virtual_numbers (
    phone_digits        VARCHAR(24) PRIMARY KEY,
    owner_user_id       BIGINT,
    assigned_dc_id      SMALLINT NOT NULL REFERENCES dc_clusters(dc_id),
    acquisition_kind    VARCHAR(24) NOT NULL CHECK (acquisition_kind IN ('admin_issued', 'auction', 'direct_sale')),
    price_units         BIGINT NOT NULL DEFAULT 0,
    is_locked           BOOLEAN NOT NULL DEFAULT FALSE,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

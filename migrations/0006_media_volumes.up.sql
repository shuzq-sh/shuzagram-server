-- 0006_media_volumes.up.sql
CREATE TABLE media_blobs (
    storage_dc_id       SMALLINT NOT NULL,
    file_id             BIGINT NOT NULL,
    access_hash         BIGINT NOT NULL,
    volume_id           BIGINT NOT NULL,
    s3_bucket           VARCHAR(64) NOT NULL,
    s3_object_key       VARCHAR(255) NOT NULL,
    sha256_digest       BYTEA NOT NULL CHECK (octet_length(sha256_digest) = 32),
    mime_type           VARCHAR(128) NOT NULL,
    byte_size           BIGINT NOT NULL,
    thumbs_json         JSONB NOT NULL DEFAULT '[]'::jsonb,
    attributes_tl       BYTEA,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (storage_dc_id, file_id)
) PARTITION BY LIST (storage_dc_id);

CREATE TABLE media_blobs_dc1 PARTITION OF media_blobs FOR VALUES IN (1);
CREATE TABLE media_blobs_dc2 PARTITION OF media_blobs FOR VALUES IN (2);
CREATE TABLE media_blobs_dc3 PARTITION OF media_blobs FOR VALUES IN (3);
CREATE TABLE media_blobs_dc4 PARTITION OF media_blobs FOR VALUES IN (4);
CREATE TABLE media_blobs_dc5 PARTITION OF media_blobs FOR VALUES IN (5);

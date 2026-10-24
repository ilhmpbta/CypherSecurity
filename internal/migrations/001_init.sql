CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE personal_records (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    data_type  TEXT NOT NULL,
    payload    JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_records_owner ON personal_records(owner_id);

CREATE TABLE stored_files (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    storage_key     TEXT NOT NULL UNIQUE,
    original_name   TEXT NOT NULL,
    content_type    TEXT NOT NULL,
    plaintext_size  BIGINT NOT NULL,
    ciphertext_size BIGINT NOT NULL,
    alg_id          TEXT NOT NULL DEFAULT 'aes-256-gcm-siv-stream-v1',
    wrapped_dek     BYTEA NOT NULL,
    nonce_prefix    BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_files_owner ON stored_files(owner_id);

CREATE TABLE audit_events (
    id         BIGSERIAL PRIMARY KEY,
    actor_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    action     TEXT NOT NULL,
    target_id  TEXT,
    metadata   JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_audit_actor ON audit_events(actor_id);

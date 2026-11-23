CREATE TABLE user_keypairs (
    user_id               UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    algorithm             TEXT NOT NULL,
    public_key            BYTEA NOT NULL,
    private_key_encrypted BYTEA NOT NULL,
    private_key_nonce     BYTEA NOT NULL,
    fingerprint           TEXT NOT NULL,
    certificate           BYTEA,
    cert_expires_at       TIMESTAMPTZ,
    kdf_salt              BYTEA NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_keypairs_fp ON user_keypairs(fingerprint);

-- KEKs encrypted with the master key. The highest version is active.
CREATE TABLE keks (
    version     INT PRIMARY KEY,
    wrapped_key BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE secrets (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    type        SMALLINT NOT NULL,
    name        TEXT NOT NULL,
    metadata    JSONB NOT NULL DEFAULT '{}',
    -- Encrypted data; NULL once the secret is deleted.
    ciphertext  BYTEA,
    wrapped_dek BYTEA,
    kek_version INT REFERENCES keks (version),
    version     BIGINT NOT NULL DEFAULT 1,
    revision    BIGINT NOT NULL,
    deleted     BOOLEAN NOT NULL DEFAULT false,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX secrets_user_revision_idx ON secrets (user_id, revision);

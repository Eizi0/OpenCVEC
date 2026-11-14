-- Plugins signés, éditeurs de confiance et canaris fichier déposés sur les assets.

CREATE TABLE publishers (
    id         BIGSERIAL PRIMARY KEY,
    name       TEXT NOT NULL,
    public_key TEXT NOT NULL UNIQUE,
    key_id     TEXT NOT NULL UNIQUE,
    builtin    BOOLEAN NOT NULL DEFAULT false,
    added_by   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE plugins (
    id           TEXT PRIMARY KEY,
    version      TEXT NOT NULL,
    name         TEXT NOT NULL,
    content      BYTEA NOT NULL,
    signature    TEXT NOT NULL DEFAULT '',
    sha256       TEXT NOT NULL,
    publisher    TEXT NOT NULL DEFAULT '',
    signed       BOOLEAN NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT true,
    source       TEXT NOT NULL DEFAULT '',
    installed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    installed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Canari fichier : un jeton par asset, déposé par l'entreprise au chemin indiqué.
-- Lu hors d'un check, il signale une compromission réelle (jeton piège).
CREATE TABLE asset_canaries (
    asset_id   BIGINT PRIMARY KEY REFERENCES assets(id) ON DELETE CASCADE,
    token      TEXT NOT NULL UNIQUE,
    path       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE callbacks DROP CONSTRAINT callbacks_status_check;
ALTER TABLE callbacks ADD CONSTRAINT callbacks_status_check
    CHECK (status IN ('correlated', 'duplicate', 'expired', 'replay', 'unknown', 'selftest', 'honeytoken'));
ALTER TABLE callbacks ADD COLUMN asset_id BIGINT REFERENCES assets(id) ON DELETE SET NULL;

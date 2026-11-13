-- Schéma initial d'OpenCVEC.

CREATE TABLE users (
    id                BIGSERIAL PRIMARY KEY,
    email             TEXT NOT NULL UNIQUE,
    name              TEXT NOT NULL DEFAULT '',
    role              TEXT NOT NULL CHECK (role IN ('admin', 'analyst', 'viewer')),
    password_hash     TEXT NOT NULL,
    totp_secret       TEXT NOT NULL DEFAULT '',
    totp_enabled      BOOLEAN NOT NULL DEFAULT false,
    totp_last_counter BIGINT NOT NULL DEFAULT 0,
    disabled          BOOLEAN NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at     TIMESTAMPTZ
);

CREATE TABLE sessions (
    token_hash BYTEA PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE mfa_challenges (
    token_hash BYTEA PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    attempts   INT NOT NULL DEFAULT 0
);

CREATE TABLE rate_limits (
    bucket   TEXT NOT NULL,
    key_hash BYTEA NOT NULL,
    hits     INT NOT NULL,
    reset_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (bucket, key_hash)
);

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value JSONB NOT NULL
);

-- Plages réseau autorisées par un administrateur (réseau interne, labo).
CREATE TABLE allowlist (
    id         BIGSERIAL PRIMARY KEY,
    cidr       CIDR NOT NULL UNIQUE,
    reason     TEXT NOT NULL,
    added_by   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    review_at  TIMESTAMPTZ NOT NULL
);

CREATE TABLE assets (
    id                  BIGSERIAL PRIMARY KEY,
    host                TEXT NOT NULL UNIQUE,
    kind                TEXT NOT NULL CHECK (kind IN ('domain', 'ip', 'cidr')),
    tags                TEXT[] NOT NULL DEFAULT '{}',
    scheme              TEXT NOT NULL DEFAULT 'https' CHECK (scheme IN ('http', 'https')),
    port                INT NOT NULL DEFAULT 0,
    proof_method        TEXT NOT NULL CHECK (proof_method IN ('dns_txt', 'well_known', 'allowlist')),
    proof_token         TEXT NOT NULL,
    proof_token_expires TIMESTAMPTZ NOT NULL,
    proof_status        TEXT NOT NULL DEFAULT 'pending' CHECK (proof_status IN ('pending', 'valid', 'failed')),
    proof_detail        TEXT NOT NULL DEFAULT '',
    proof_checked_at    TIMESTAMPTZ,
    proof_valid_until   TIMESTAMPTZ,
    resolved_ips        TEXT[] NOT NULL DEFAULT '{}',
    created_by          BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE campaigns (
    id         BIGSERIAL PRIMARY KEY,
    asset_id   BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_url TEXT NOT NULL,
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    cancelled  BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE checks (
    id          BIGSERIAL PRIMARY KEY,
    campaign_id BIGINT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    asset_id    BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    checker     TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'waiting', 'done', 'error', 'cancelled')),
    verdict     TEXT CHECK (verdict IN ('proved', 'probable', 'exposed', 'patched', 'inconclusive', 'error')),
    summary     TEXT NOT NULL DEFAULT '',
    detail      JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at  TIMESTAMPTZ,
    sent_at     TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);
CREATE INDEX checks_campaign ON checks (campaign_id);
CREATE INDEX checks_asset_created ON checks (asset_id, created_at);

-- Un canari par check : jeton à usage unique, lié à l'asset et au check par HMAC.
CREATE TABLE canaries (
    token       TEXT PRIMARY KEY,
    check_id    BIGINT NOT NULL UNIQUE REFERENCES checks(id) ON DELETE CASCADE,
    asset_id    BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ
);

CREATE TABLE callbacks (
    id             BIGSERIAL PRIMARY KEY,
    received_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    proto          TEXT NOT NULL,
    qtype          TEXT NOT NULL DEFAULT '',
    qname          TEXT NOT NULL,
    point          TEXT NOT NULL DEFAULT '',
    source_ip      TEXT NOT NULL,
    raw            TEXT NOT NULL DEFAULT '',
    token          TEXT NOT NULL DEFAULT '',
    check_id       BIGINT REFERENCES checks(id) ON DELETE SET NULL,
    status         TEXT NOT NULL CHECK (status IN ('correlated', 'duplicate', 'expired', 'replay', 'unknown', 'selftest')),
    source_matches BOOLEAN
);
CREATE INDEX callbacks_received ON callbacks (received_at DESC);
CREATE INDEX callbacks_check ON callbacks (check_id);

-- Journal d'audit en ajout seul, chaîné par empreinte SHA-256.
CREATE TABLE audit_log (
    id        BIGSERIAL PRIMARY KEY,
    at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id   BIGINT,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    detail    TEXT NOT NULL DEFAULT '',
    ip        TEXT NOT NULL DEFAULT '',
    prev_hash BYTEA NOT NULL,
    hash      BYTEA NOT NULL
);

-- Interdit la modification et la suppression des lignes du journal d'audit.
CREATE FUNCTION audit_log_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'le journal d''audit est en ajout seul';
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER audit_log_no_update BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

CREATE TABLE reports (
    id         BIGSERIAL PRIMARY KEY,
    title      TEXT NOT NULL,
    summary    TEXT NOT NULL DEFAULT '',
    format     TEXT NOT NULL CHECK (format IN ('html', 'json')),
    content    BYTEA NOT NULL,
    sha256     TEXT NOT NULL,
    created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Jetons d'API personnels et checks programmés.

CREATE TABLE api_tokens (
    id           BIGSERIAL PRIMARY KEY,
    user_id      BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    token_hash   BYTEA NOT NULL UNIQUE,
    prefix       TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ
);

CREATE TABLE schedules (
    id               BIGSERIAL PRIMARY KEY,
    asset_id         BIGINT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_url       TEXT NOT NULL,
    checkers         TEXT[] NOT NULL,
    every_days       INT NOT NULL CHECK (every_days BETWEEN 1 AND 365),
    next_run_at      TIMESTAMPTZ NOT NULL,
    enabled          BOOLEAN NOT NULL DEFAULT true,
    created_by       BIGINT REFERENCES users(id) ON DELETE SET NULL,
    last_campaign_id BIGINT REFERENCES campaigns(id) ON DELETE SET NULL,
    last_run_at      TIMESTAMPTZ,
    last_error       TEXT NOT NULL DEFAULT '',
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX schedules_due ON schedules (next_run_at) WHERE enabled;

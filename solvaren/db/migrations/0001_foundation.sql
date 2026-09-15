-- SOLVAREN migration 0001 — Foundation: tenancy, identity, authority.
--
-- Everything here is Zone 1 (Identity) and Zone 2 (Authority): organizations, users,
-- credentials, devices, sessions, recovery, conflict-of-interest registry, and the
-- dynamic permission engine's persistence (permission_overrides + policy versions).

CREATE TABLE organizations (
  id            UUID PRIMARY KEY,
  slug          TEXT NOT NULL UNIQUE,
  name          TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'ACTIVE'
                CHECK (status IN ('ACTIVE', 'SUSPENDED', 'CLOSED')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT organizations_slug_format CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$')
);

CREATE TABLE policies (
  organization_id               UUID PRIMARY KEY REFERENCES organizations(id),
  max_instruction_amount_cents  BIGINT NOT NULL,
  max_batch_total_cents         BIGINT NOT NULL,
  max_batch_instructions        INTEGER NOT NULL CHECK (max_batch_instructions BETWEEN 1 AND 20000),
  high_value_threshold_cents    BIGINT NOT NULL CHECK (high_value_threshold_cents >= 0),
  cooling_off_seconds           INTEGER NOT NULL CHECK (cooling_off_seconds BETWEEN 0 AND 86400),
  blocking_risk_band            TEXT NOT NULL DEFAULT 'CRITICAL'
                                CHECK (blocking_risk_band IN ('NEVER', 'HIGH', 'CRITICAL')),
  allow_l1_failed_export        BOOLEAN NOT NULL DEFAULT TRUE,
  allow_l1_retry                BOOLEAN NOT NULL DEFAULT TRUE,
  max_export_rows               INTEGER NOT NULL CHECK (max_export_rows BETWEEN 100 AND 100000),
  daily_disbursement_ceiling_cents BIGINT NOT NULL DEFAULT 0,
  release_cutoff_local_time     TEXT NOT NULL DEFAULT ''
                                CHECK (release_cutoff_local_time = '' OR release_cutoff_local_time ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'),
  holiday_dates                 TEXT[] NOT NULL DEFAULT '{}',
  updated_by_user_id            UUID,
  created_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT policies_limits_sane CHECK (
    max_instruction_amount_cents BETWEEN 1000 AND 25000000
    AND max_batch_total_cents >= max_instruction_amount_cents
    AND high_value_threshold_cents <= max_batch_total_cents
  )
);

CREATE TABLE users (
  id                        UUID PRIMARY KEY,
  organization_id           UUID NOT NULL REFERENCES organizations(id),
  email                     TEXT NOT NULL UNIQUE,
  full_name                 TEXT NOT NULL CHECK (char_length(full_name) BETWEEN 1 AND 140),
  authority_level           TEXT NOT NULL CHECK (authority_level IN ('L1', 'L2', 'L3')),
  status                    TEXT NOT NULL DEFAULT 'PENDING_ENROLMENT'
                            CHECK (status IN ('ACTIVE', 'DISABLED', 'LOCKED', 'PENDING_ENROLMENT')),
  password_hash             TEXT NOT NULL,
  authorization_pin_hash    TEXT,
  authorization_pin_updated_at TIMESTAMPTZ,
  failed_login_count        INTEGER NOT NULL DEFAULT 0,
  locked_until              TIMESTAMPTZ,
  last_login_at             TIMESTAMPTZ,
  created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- A privileged officer cannot act without an FPAC PIN: the PIN is one of the release
  -- gates, so an L2/L3 account without one must not be activatable.
  CONSTRAINT users_privileged_requires_pin CHECK (
    authority_level = 'L1' OR authorization_pin_hash IS NOT NULL OR status <> 'ACTIVE'
  )
);

CREATE INDEX users_org_level_idx   ON users (organization_id, authority_level) WHERE status = 'ACTIVE';
CREATE INDEX users_org_status_idx  ON users (organization_id, status);

-- A fresh organization begins with exactly one L3 account; governance (spec §4.3)
-- requires at least one executive authority to exist and never zero.
CREATE TABLE organization_l3_guarantee (
  organization_id UUID PRIMARY KEY REFERENCES organizations(id),
  enforced_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE webauthn_credentials (
  id                UUID PRIMARY KEY,
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  user_id           UUID NOT NULL REFERENCES users(id),
  credential_id     TEXT NOT NULL UNIQUE,
  public_key        BYTEA NOT NULL,
  signature_counter BIGINT NOT NULL DEFAULT 0 CHECK (signature_counter >= 0),
  transports        TEXT[] NOT NULL DEFAULT '{}',
  device_type       TEXT NOT NULL DEFAULT 'UNKNOWN'
                    CHECK (device_type IN ('PLATFORM', 'CROSS_PLATFORM', 'UNKNOWN')),
  backed_up         BOOLEAN NOT NULL DEFAULT FALSE,
  friendly_name     TEXT NOT NULL DEFAULT 'Security key',
  aaguid            UUID,
  status            TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'REVOKED')),
  revoked_at        TIMESTAMPTZ,
  revoked_reason    TEXT,
  last_used_at      TIMESTAMPTZ,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX webauthn_user_idx ON webauthn_credentials (user_id) WHERE status = 'ACTIVE';

CREATE TABLE trusted_devices (
  id                      UUID PRIMARY KEY,
  organization_id         UUID NOT NULL REFERENCES organizations(id),
  user_id                 UUID NOT NULL REFERENCES users(id),
  device_fingerprint      TEXT NOT NULL,
  friendly_name           TEXT,
  webauthn_credential_id  UUID REFERENCES webauthn_credentials(id),
  trust_status            TEXT NOT NULL DEFAULT 'REVIEW'
                          CHECK (trust_status IN ('TRUSTED', 'REVIEW', 'BLOCKED', 'REVOKED')),
  first_seen_ip           INET,
  last_seen_ip            INET,
  user_agent              TEXT,
  registered_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_activity_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at              TIMESTAMPTZ,
  revoked_reason          TEXT,
  CONSTRAINT trusted_devices_user_unique UNIQUE (user_id, device_fingerprint)
);

CREATE INDEX trusted_devices_user_idx ON trusted_devices (user_id, trust_status);

CREATE TABLE sessions (
  id                    UUID PRIMARY KEY,
  organization_id       UUID NOT NULL REFERENCES organizations(id),
  user_id               UUID NOT NULL REFERENCES users(id),
  token_hash            TEXT NOT NULL UNIQUE,
  trusted_device_id     UUID REFERENCES trusted_devices(id),
  authenticated_at      TIMESTAMPTZ NOT NULL,
  webauthn_verified_at  TIMESTAMPTZ,
  issued_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at            TIMESTAMPTZ NOT NULL,
  last_seen_at          TIMESTAMPTZ,
  revoked_at            TIMESTAMPTZ,
  revocation_reason     TEXT,
  ip                    INET,
  user_agent            TEXT,
  CONSTRAINT sessions_expiry_after_issue CHECK (expires_at > issued_at)
);

CREATE INDEX sessions_user_active_idx ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expiry_idx      ON sessions (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE recovery_codes (
  id                UUID PRIMARY KEY,
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  user_id           UUID NOT NULL REFERENCES users(id),
  code_hash         TEXT NOT NULL,
  consumed_at       TIMESTAMPTZ,
  consumed_ip       INET,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX recovery_codes_user_idx ON recovery_codes (user_id) WHERE consumed_at IS NULL;

CREATE TABLE conflict_registrations (
  id                UUID PRIMARY KEY,
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  user_id           UUID NOT NULL REFERENCES users(id),
  scope_type        TEXT NOT NULL CHECK (scope_type IN ('RECIPIENT', 'DEPARTMENT', 'ORGANIZATION')),
  scope_id          UUID,
  reason            TEXT NOT NULL CHECK (char_length(reason) BETWEEN 3 AND 500),
  registered_by_user_id UUID NOT NULL REFERENCES users(id),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  withdrawn_at      TIMESTAMPTZ,
  CONSTRAINT conflict_scope_id_present CHECK (
    (scope_type = 'ORGANIZATION' AND scope_id IS NULL)
    OR (scope_type <> 'ORGANIZATION' AND scope_id IS NOT NULL)
  )
);

CREATE INDEX conflict_user_idx ON conflict_registrations (organization_id, user_id) WHERE withdrawn_at IS NULL;

-- ---------------------------------------------------------------------------
-- Dynamic permission engine (spec AC-17): versioned overrides with immutable ceilings.
-- Ceilings themselves are NOT data — they are compiled into @solvaren/core and applied
-- after every override, so no row here can pierce one. The table records only what L3
-- decided, when, why, and by whom.
-- ---------------------------------------------------------------------------

CREATE TABLE permission_policy_versions (
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  version           BIGINT NOT NULL,
  created_by_user_id UUID NOT NULL REFERENCES users(id),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  note              TEXT,
  PRIMARY KEY (organization_id, version)
);

CREATE TABLE permission_overrides (
  id                UUID PRIMARY KEY,
  organization_id   UUID NOT NULL REFERENCES organizations(id),
  level             TEXT NOT NULL CHECK (level IN ('L1', 'L2')),
  permission        TEXT NOT NULL,
  effect            TEXT NOT NULL CHECK (effect IN ('GRANT', 'REVOKE')),
  version           BIGINT NOT NULL,
  reason            TEXT NOT NULL CHECK (char_length(reason) BETWEEN 3 AND 500),
  granted_by_user_id UUID NOT NULL REFERENCES users(id),
  superseded_by_id  UUID,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT override_fk_version FOREIGN KEY (organization_id, version)
    REFERENCES permission_policy_versions (organization_id, version)
);

CREATE INDEX permission_overrides_live_idx
  ON permission_overrides (organization_id, level, permission)
  WHERE superseded_by_id IS NULL;

CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER organizations_updated_at BEFORE UPDATE ON organizations
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();
CREATE TRIGGER users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

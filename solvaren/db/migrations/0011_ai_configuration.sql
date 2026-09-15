-- 0011: Organisation-level AI assistant configuration (spec §11).
--
-- The AI advisory layer is org-configured: the L3 chooses a provider (Anthropic or any
-- OpenAI-compatible endpoint — including self-hosted models), the base URL, the model
-- and the API key. The key lives in the secret store; this table holds only the
-- non-secret wiring plus the test state. Without a row, the layer falls back to the
-- platform environment default (AI_API_KEY / AI_MODEL), and without either it is off —
-- the deterministic risk engine stands alone either way.

CREATE TABLE ai_configurations (
  organization_id     UUID PRIMARY KEY REFERENCES organizations(id),
  provider            TEXT NOT NULL CHECK (provider IN ('anthropic', 'openai-compatible')),
  base_url            TEXT NOT NULL
                      CONSTRAINT ai_base_url_https CHECK (base_url LIKE 'https://%'),
  model               TEXT NOT NULL CHECK (char_length(model) BETWEEN 1 AND 200),
  api_key_secret_ref  TEXT NOT NULL,
  api_key_last_four   TEXT,
  status              TEXT NOT NULL DEFAULT 'TESTING'
                      CHECK (status IN ('TESTING', 'ENABLED', 'ERROR', 'DISABLED')),
  last_test_at        TIMESTAMPTZ,
  last_test_ok        BOOLEAN,
  last_test_message   TEXT,
  created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

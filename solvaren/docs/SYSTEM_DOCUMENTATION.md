# SOLVAREN — Full System Documentation

**Institutional disbursement control plane for M-PESA B2C (Daraja) payroll and vendor payments.**
Edition: 2026-09-15 — post full-system audit, all subsystems verified in production.

---

## 1. What SOLVAREN is

SOLVAREN is a multi-tenant, audit-first disbursement platform that sits between an
organisation's payroll/vendor list and Safaricom's M-PESA Daraja B2C API. Its defining
property is that **money never moves on the operator's intent alone**: every batch passes a
draft → validate → review → authorise lifecycle, privileged actions require a hardware
security key (passkey/FIDO2) plus a numeric authorisation PIN, every state change is
written to an immutable audit ledger, and no transaction is ever left untracked — a
reconciliation sweeper chases Daraja for the final word on anything ambiguous.

Core guarantees:

| Guarantee | Mechanism |
|---|---|
| Dual control over money | L1 prepare / L2 review / L3 approve permission matrix; per-instruction authorisation ceremonies |
| Phishing-resistant admin access | WebAuthn mandatory for privileged accounts; password alone cannot act |
| Non-repudiation | Immutable audit events (DB triggers reject UPDATE/DELETE); correlation IDs end-to-end |
| No hanging transactions | B2C result + timeout callbacks, per-request inline ResultURL/QueueTimeOutURL, reconciliation sweeps, Transaction Status queries |
| Secrets never in plaintext at rest | AES-256-GCM envelope encryption keyed by purpose; API keys/Daraja credentials encrypted before storage |
| Explainable money | Reports engine, transaction explorer, reconciliation console, financial/statistical exports |

---

## 2. System topology

### 2.1 Monorepo layout

```
solvaren/
├── apps/
│   ├── api/            Hono API + workers + scheduler (Node, TypeScript, ESM)
│   └── web/            React 19 + Vite operator console (hash routing, no CORS surface)
├── packages/
│   ├── core/           Domain primitives: money, MSISDN, CSV, errors, reports catalogue, permissions
│   ├── daraja/         Daraja client: OAuth, B2C, SecurityCredential (RSA/X.509), callbacks
│   ├── crypto/         AES-GCM envelopes, signing, key derivation
│   └── storage/        S3-compatible object store client (SigV4, path-style & vhost)
├── db/migrations/      0001–0011 SQL migrations (checksummed, forward-only)
├── scripts/            migrate.mjs (run on deploy), utilities
├── docs/               specification-coverage.md, threat-model.md, deployment.md, runbooks/
└── Dockerfile.combined Single image: API + built console served same-origin at ./console
```

### 2.2 Production deployment (Railway)

Project **splendid-determination** (`199800c5-8577-4e3a-a676-e5bbac2be2a5`), region us-east-1:

| Service | Image / source | Role |
|---|---|---|
| **solvaren** | Tarball build, `Dockerfile.combined` | API + console + workers + scheduler, single origin |
| **Postgres** | Railway template | OLTP + job queue (SKIP LOCKED) + audit ledger |
| **minio** | `quay.io/minio/minio` via 2-line Dockerfile wrapper | S3 object store: backups, staged exports |

- **Application URL:** https://solvaren-production.up.railway.app
- **Health:** `GET /health` (liveness), `GET /health/ready` (DB latency probe)
- Deploys are tarball uploads via Railway MCP/CLI from `F:\SOLVAREN 2\solvaren`
  (repo mirror: github.com/kedwin38/SOLVAREN-2, branch `main`).
- Pre-deploy command runs `node scripts/migrate.mjs` — schema is always current before boot.

### 2.3 Same-origin design decision

The console is built into the API image and served from `./console` with an SPA fallback.
One origin means: zero CORS surface, WebAuthn has a single stable RP ID
(`solvaren-production.up.railway.app`), and cookies stay first-party.

---

## 3. Security model

### 3.1 Authority levels

| Level | Role | Representative permissions |
|---|---|---|
| L0 | Read-only auditor | View transactions, reports, audit trail |
| L1 | Payment preparer | Create batches, upload CSV, validate, submit for review |
| L2 | Payment operations | Review/approve batches, trigger reconciliation, manage recipients |
| L3 | Organisation administrator | Full: Daraja credentials, policies, users, AI config, backups, releases |

The effective permission matrix is computed per request (`permissionMatrix` in context) from
level + organisation policy overrides — never trusted from the client.

### 3.2 Authentication stages

1. **Password stage** — argon2-class verification; rate-limited per account and IP.
   - Privileged users (L2/L3) without an enrolled security key are placed in a
     **PENDING_ENROLMENT** flow: login succeeds structurally, returns
     `ENROLMENT_REQUIRED` plus a 15-minute enrolment-only session
     (`webauthn_verified_at` NULL). They must enrol a passkey in that window; the
     session can do nothing else. If it lapses, an admin must reactivate.
2. **WebAuthn stage** — FIDO2 passkey ceremony (platform authenticators, cross-device
   hybrid via QR/phone supported). Passkeys are attached to a **stable user handle**
   (the account UUID) — re-enrolling devices, changing roles, or reissuing sessions never
   orphans the credential, and the handle is identical across every registration.
3. **Step-up (passkey confirmation)** — privileged mutations demand authentication
   fresher than five minutes (`STEP_UP_REQUIRED`). The relief valve is a **two-phase
   passkey ceremony, no password**: `POST /api/auth/step-up/options` issues a
   server-held single-use challenge+ticket; `POST /api/auth/step-up` verifies the
   assertion, advances the authenticator signature counter (cloned-key detection), and
   refreshes `authenticated_at` AND `webauthn_verified_at` **in place**. The console
   intercepts `STEP_UP_REQUIRED`/`WEBAUTHN_REQUIRED` globally: one passkey dialog
   appears, and the blocked operation retries itself — no logout, on any page.
4. **Authorisation PIN** — separate numeric PIN demanded at the moment of privileged
   mutation (releasing payments, editing Daraja credentials, AI configuration, exports).
5. **Recovery codes** — generated at enrolment; single-use, audited.

### 3.3 Secrets architecture

- `SECRET_ENCRYPTION_KEY` (32-byte base64) derives **purpose-scoped keys**: a ciphertext
  written under purpose `daraja.credential` cannot be decrypted as `ai.api_key`. The
  `SecretStore` contract is `put(ref, plaintext, purpose)` / `get(ref, purpose)` — one
  encryption, one purpose, integrity-bound (`SECRET_TAMPERED` on mismatch).
- Daraja passwords/API keys/MinIO root secrets never appear in SQL — only envelope
  references (`secret_ref` columns).
- `SESSION_SIGNING_KEY` signs session tokens; sessions carry level, WebAuthn-verified
  timestamp, and expiry.

### 3.4 Audit immutability

Migration `0003` installs triggers that reject UPDATE/DELETE on audit events. Migration
`0010` relaxes *instruction* immutability to a status-only lifecycle transition
(guarded: only permitted status moves, never amount/payload edits) so the callback and
reconciliation paths can record final Daraja outcomes without weakening history.

### 3.5 Callback ingress (the only session-less route)

`/api/daraja/*` authenticates by a shared secret embedded in the path issued per
organisation. Callbacks are received, persisted raw, verified, then processed
asynchronously through the `callbacks` queue — Daraja never blocks on our processing.

---

## 4. Functional modules (operator console)

| Page (route) | Function |
|---|---|
| **Dashboard** (`#/`) | KPIs: today's disbursement volume, success/timeout rates, open authorisations, queue depth |
| **Payment batches** (`#/batches`) | Full lifecycle: create, upload CSV (validated row-by-row), validate, submit, review (L2), authorise (L3 ceremony), release, track per-instruction outcomes. **Download CSV template** in header + per-batch workflow |
| **Transactions** (`#/transactions`) | Explorer over every instruction/transaction with filters, drill-down to callbacks, receipt codes (M-PESA transaction refs), export |
| **Approvals** (`#/approvals`) | Authorisation queue: pending ceremonies, approve/reject with PIN, ceremony history |
| **Recipients** (`#/recipients`) | Directory of payees, MSISDN-normalised, department tagging |
| **Reconciliation** (`#/reconciliation`) | B2C ledger vs Daraja truth: sweeps, per-transaction status queries, account balance refresh |
| **Reports** (`#/reports`) | Catalogue-driven generation (12 report families), async jobs, history, download (inline or staged to S3) |
| **Analytics** (`#/analytics`) | Volumes, failure-reason Pareto, department spend, latency |
| **Backups** (`#/backups`) | Encrypted logical backups to MinIO, retention enforcement, restore-point catalogue |
| **Security** (`#/security`) | Security keys per user, recovery codes, active sessions, audit trail browser |
| **Users** (`#/users`) | L3 user administration: create (returns enrolment instructions), deactivate, reset |
| **Settings** (`#/settings`) | Tabs: **Daraja** · **AI assistant** · **Policies** · **Permissions** · **Templates** |

---

## 5. Daraja B2C integration

### 5.1 Configuration (Settings → Daraja, L3)

- Environment (production/sandbox), consumer key/secret, shortcode, initiator name,
  B2C password, **SecurityCredential** — accepted as either:
  - the raw initiator password (system encrypts it with the organisation's downloaded
    **official M-Pesa X.509 certificate** — upload `.cer`/`.der` or paste PEM; or
  - the **precomputed credential from the Daraja portal** (detected automatically:
    ≥150 chars of base64 after whitespace-stripping — line-wrapped pastes are cleaned).
- **No callback registration is required**: per Daraja's actual B2C behaviour, the
  `ResultURL` and `QueueTimeOutURL` are supplied **inline on every payment request**,
  built from the organisation's base callback URL + path secret. (The console correctly
  does *not* tell operators to register callbacks on the portal.)
- Credentials support full **edit** and **delete** (destroys envelope + reference).
- **Test payment**: send from KES 10 (Daraja minimum) to any number; the system tracks
  the test transaction to a terminal state and surfaces the **M-PESA receipt code** —
  nothing is ever left hanging; timeout callbacks trigger status queries.

### 5.2 Payment flow

```
CSV upload ─▶ parse (row-level errors, duplicate warnings, formula rejection)
           ─▶ DRAFT      validate (policy engine: limits, holidays, departments)
           ─▶ VALIDATED  submit → L2 review
           ─▶ REVIEWED   L3 authorisation ceremony (WebAuthn-fresh session + PIN)
           ─▶ AUTHORIZED release → payments queue
           ─▶ per-instruction B2C call (inline Result/QueueTimeOut URLs)
           ─▶ callback → SUCCESS/FAILED/timeout → status query if ambiguous
           ─› reconciliation sweeper (periodic, org-scoped) — final word
```

Amount invariants: whole shillings only, per-txn KES 10–150,000, batch ceiling from
policy, 20,000 rows / 8 MB per upload.

### 5.3 Official CSV template

Ships at `apps/web/public/templates/solvaren-batch-template.csv`, downloadable from the
Batches page header and the batch workflow. Canonical header (aliases also recognised —
see `packages/core/src/csv.ts`):

```csv
Recipient Name,Phone,Amount,Department,Reference,Remarks
```

Parser: RFC 4180 (quoted fields, embedded commas/newlines/escaped quotes), BOM-tolerant,
comma/semicolon/tab delimiters, header matching case/whitespace/underscore-insensitive,
formula-injection rejection in amounts, 2547/07…/＋254… MSISDN normalisation.

---

## 6. AI assistant layer

### 6.1 Design posture

AI in SOLVAREN is **advisory only**: read-only prompts over already-authorised data,
**no tools, no state mutation** — `ai_interactions.caused_state_change` is pinned FALSE
by contract. When no provider is configured, the deterministic engine answers alone; AI
failures degrade silently to it.

### 6.2 Provider resolution (per organisation)

```
organisation ai_configurations row (status ≠ DISABLED, key present)
  → else platform default: env AI_API_KEY (+ optional AI_MODEL, Anthropic)
  → else OFF (deterministic engine only)
```

- **Providers:** `anthropic` (Messages API, `x-api-key` + `anthropic-version`) and
  `openai-compatible` (any `/chat/completions` endpoint — OpenAI, Groq, OpenRouter,
  vLLM, Ollama-over-TLS, …; Bearer auth).
- **Base URL tolerance:** a trailing `/v1` is detected either way —
  `https://api.anthropic.com` and `https://api.anthropic.com/v1` both resolve to the
  Messages endpoint; the same holds for OpenAI-compatible bases (OpenAI, Groq's
  `/openai/v1`, OpenRouter's `/api/v1`). `max_tokens` is sent only to Anthropic
  (where it is required); it is omitted for OpenAI-compatible providers because newer
  OpenAI models reject it and every compatible server applies its own default cap.
- Org config fields: provider, HTTPS-only base URL, model (1–200 chars), API key
  (encrypted envelope, purpose `ai`; only last four digits ever redisplayed).

### 6.3 L3 configuration module (Settings → AI assistant)

- **Current configuration card** — provider, base URL, model, masked key, status
  (`TESTING → ENABLED / ERROR / DISABLED`), last-test telemetry; **Test provider**
  (live probe call; success promotes to ENABLED) and **Remove** (destroys key envelope).
- **Configure form** — provider select swaps default base URL
  (`https://api.anthropic.com` ↔ provider-specific), model, key, **authorisation PIN**.
- Guard: L3 + fresh session + WebAuthn + PIN (same stack as Daraja credentials).
- API: `GET /api/admin/ai` · `PUT /api/admin/ai` · `POST /api/admin/ai/test` ·
  `DELETE /api/admin/ai`.
- Advisory endpoints under `/api/ai/*` resolve the provider per organisation and record
  every interaction for audit.

---

## 7. API surface (spec §18)

| Group | Mount | Auth | Highlights |
|---|---|---|---|
| auth | `/api/auth` | session / stage-gated | login (3 stages), enrolment flow, WebAuthn register/verify/options, recovery |
| payment-batches | `/api/payment-batches` | session + matrix | CRUD, CSV upload, validate/submit/review/authorise/release, detail+instructions |
| transactions | `/api/transactions` | session + matrix | explorer, filters, drill-down |
| exports | `/api/exports` | session + PIN-class | CSV/parquet-class exports, staged to S3 |
| approvals | `/api/approvals` | session + matrix | authorisation queue, ceremonies |
| analytics | `/api/analytics` | session | aggregates, Pareto, latency |
| admin | `/api/admin` | L3 stacks | users, policies, Daraja config + test-payment, backups, **AI config** |
| ai | `/api/ai` | session | advisory Q&A, insights (provider-aware) |
| security | `/api/security` | session | keys, sessions, audit browser |
| recipients / departments | `/api/recipients`, `/api/departments` | session + matrix | directory CRUD |
| reconciliation | `/api/reconciliation` | session + matrix | sweeps, status queries, balance |
| reports | `/api/reports` | session + matrix | catalogue, queue (202), history, download |
| daraja callbacks | `/api/daraja/*` | path secret | B2C result/timeout, transaction status, account balance |

Error envelope is uniform: `{ error: { code, category, message, correlationId } }`,
with Zod validation surfaced as `VALIDATION_ERROR` + field detail.

---

## 8. Data platform

### 8.1 Migrations (forward-only, checksummed)

| # | Name | Effect |
|---|---|---|
| 0001 | foundation | orgs, users, sessions, keys, recovery |
| 0002 | payments | batches, instructions, transactions, callbacks |
| 0003 | audit immutability | triggers locking the audit ledger |
| 0004 | backups & exports | backup attempts, export staging, ai_interactions, security events |
| 0005 | seed failure reasons | canonical Daraja failure taxonomy |
| 0006 | views | reporting/ops views |
| 0007 | job queue | SKIP LOCKED queue tables |
| 0009 | UUID defaults | id defaults for the entity tables |
| 0010 | instruction status lifecycle | guarded status-only updates (callback/recon write-back) |
| 0011 | AI configuration | `ai_configurations` (provider, base_url, model, key ref, status, last_test_*) |
| 0012 | UUID defaults completion | the two tables 0009 missed: `ai_interactions`, `backup_attempts` |

(0008 was reserved/never shipped — numbering intentionally skips. The rate-limit and
scheduler-marker tables were audited in the same pass: natural primary keys, no id
column, nothing needed.)

### 8.2 Queues and workers

Postgres-backed job queue (`SKIP LOCKED`), six lanes: `payments`, `callbacks`,
`reconciliation`, `backups`, `reports`, `notifications`. In-process workers consume in
the combined service; the scheduler issues periodic reconciliation sweeps and backup
retention runs. Report generation is queue-isolated so a 20k-row export can never stall
payment callbacks (verified live: financial report queued 202 → COMPLETED in 640 ms).

### 8.3 Known platform quirk

`postgres` driver with `fetch_types: false` returns `TEXT[]` columns as flat strings —
all array-typed SELECTs cast through `to_jsonb` (root cause of the historical Policies
422). Recorded here so it is never reintroduced.

---

## 9. Environment contract

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL` / `DATABASE_PRIVATE_URL` | yes | Postgres (template exposes private URL — reference the private one) |
| `SESSION_SIGNING_KEY` | yes | Session token signing (32-byte base64) |
| `SECRET_ENCRYPTION_KEY` | yes | Envelope encryption root (32-byte base64) |
| `MINIO_*` / S3 vars (endpoint, region, bucket, access/secret) | yes | Object store for backups/staged exports |
| `CALLBACK_SHARED_SECRET` | per-org | Path-secret issuance for Daraja callbacks |
| `AI_API_KEY` | no | Platform-default AI provider (Anthropic) |
| `AI_MODEL` | no | Override default model (`claude-sonnet-5`) |
| `ENVIRONMENT`, `APP_ORIGIN`, `API_BASE_URL` | yes | Runtime identity |
| `WEBAUTHN_RP_ID`, `WEBAUTHN_RP_NAME` | yes | RP binding — must equal the serving origin's host |
| `PORT` | yes | Railway injects |

---

## 10. Testing & quality

- **176 automated tests, 176 passing** (vitest, 10 suites) across core, daraja, crypto,
  storage, API integration — including server-style SigV4 signature re-derivation tests,
  SecurityCredential detection tests, CSV parser property tests, and envelope
  purpose-isolation tests.
- The full suite is runnable locally: `pnpm -w test` from `solvaren/`.
- UI/UX independently vision-audited (2026-09-15): institutional-grade split-screen
  login, cohesive navy/teal fintech identity, Inter/Source Serif 4/JetBrains Mono type
  system, theme-aware rail, zero visual defects.

---

## 11. Operations runbook (condensed)

**Deploy:** package `solvaren/` → Railway MCP `deploy` (service `solvaren`) →
pre-deploy runs `node scripts/migrate.mjs` → watch build logs via CLI
`railway logs --build`. Console bundle lands under `./console`; verify a new
`index-*.js` hash before judging UI changes live.

**Logs:** Railway CLI (MCP log tooling drops filters):
`railway logs -d --lines 200` · HTTP: `--http --status 422` · correlate with `cor_…` IDs.

**Database access:** open a TCP proxy on the Postgres service, connect with the
credentials below, **close the proxy when done**. Schema state:
`SELECT * FROM schema_migrations;`

**MinIO:** root credentials below; buckets managed by the app (backups/exports).

**Rotation:** rotate `SESSION_SIGNING_KEY` (logs everyone out) or
`SECRET_ENCRYPTION_KEY` (**destroys all envelopes** — re-enter Daraja/AI credentials
afterwards) only with a maintenance window.

---

## 12. Production credentials

Credentials (admin bootstrap, database, object store, signing keys) are held in the
operator vault and the deployment platform variable store. They are deliberately
absent from this public copy. Rotate the bootstrap administrator credentials
immediately after first login in any fresh deployment.

## 13. Audit & incident log (what was found and fixed — 2026-09-15)

| Symptom | Root cause | Fix |
|---|---|---|
| SecurityCredential rejected (line-wrapped paste) | whitespace-sensitive validation | strip-all-whitespace precomputed detection (≥150 b64 chars) |
| "M-PESA portal passwords must not contain…" rule | unverified invented rule | removed; only verified Daraja rules enforced |
| `SECRET_TAMPERED` on credential reads | stale MinIO secret + double-encryption purpose mismatch | rotated secret both sides; canonical `put(plaintext, purpose)` store contract |
| SigV4 `SignatureDoesNotMatch` | path-style canonical URI missing bucket prefix; vhost host missing bucket | `hostAndBase` canonical prefix + 3 signature re-derivation tests |
| Policies tab 422 | `TEXT[]` as flat string under `fetch_types:false` | `to_jsonb` casts |
| **Every AI feature 500** (`cor_22DE9ADDEACC73F64D31` et al.) | `ai_interactions.id` had no default (0009 never covered it); the audit insert crashed *after* the model call | migration 0012 (`ai_interactions` + `backup_attempts` defaults) — verified live: all AI features 200 with real narratives |
| **Policy change 500** `malformed array literal: ""` | `sql.array([])` serialises as `''` under `fetch_types:false` | escaped array-literal parameter + `::uuid[]`/`::text[]` cast for ALL array bindings (holiday dates, `ANY()` set filters) |
| **Privileged ops forced a full re-login** | step-up verified against a challenge the client never received (generated + verified in one cycle — could never succeed); password-first UX | two-phase passkey step-up (`/step-up/options` + `/step-up`), server-held single-use tickets, session refreshed in place, global UI intercept + automatic retry — no password involved |
| Step-up options 422 | Zod parsed the Hono `json()` *promise* | removed the pointless empty-body parse |
| Test payment 500 | audit-immutability trigger blocked status write-backs | migration 0010 guarded lifecycle |
| New L2 users `INVALID_CREDENTIALS` at first login | PENDING_ENROLMENT refused stage 1 | enrolment-session flow (`ENROLMENT_REQUIRED`, 15-min window) |
| "Something went wrong" at passkey enrolment | transports serialised as JS `${[]}` | `sql`'{}'::text[]`` literal |
| Passkey orphaned across re-registration | RP-scoped handle | stable user handle = account UUID |
| False instruction to register callbacks on portal | doc error vs real Daraja behaviour | inline per-request Result/QueueTimeOut URLs; UI corrected |
| Deployed build "looked old" | judged mid-BUILDING | verify build completion + bundle hash first |

**Final verified state (2026-09-15, end of day):** 176/176 tests · reports catalogue (12
families), async generation (202 → COMPLETED 640 ms), download verified · policies
change verified live with empty **and** populated holiday dates (200) · **all AI
features verified live — batch analysis, failure explanation and executive briefing
return 200 with real model narratives** (`ai_interactions` recording, degraded:false) ·
step-up options issues real challenge+ticket (200); bad ticket refused cleanly (401) ·
first-login enrolment flow verified · stable WebAuthn handle verified · UI/UX
vision-audited clean.

---

## 14. Future-proofing notes

- Organisation-scoped tenancy is already enforced end-to-end; new orgs onboard via L3
  provisioning with their own Daraja + AI configuration.
- Adding an AI provider = one dispatch branch in `services/ai-config.ts` + one enum +
  one default base URL in the Settings tab.
- Adding a report family = one catalogue entry in `packages/core` (permission, columns,
  filters) — queue, worker, download UI are generic.
- Migrations are forward-only and checksummed; never edit an applied file (add a new one).

*End of documentation.*

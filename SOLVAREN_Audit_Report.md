# SOLVAREN (slvrn-main) — Full Project Audit vs CARACAL Payments Specification

**Date:** 14 September 2026
**Scope:** Every source file of `slvrn-main` (API, workers, domain kernel, Daraja package, DB schema, web console, CI, deployment, docs) read and cross-checked against the attached *CARACAL Payments Software Specification v1.0* (13 Sep 2026) and the repo's own `docs/specification-coverage.md` / `docs/threat-model.md`.
**Context:** Internal-use system → priorities are **usability, efficiency, reliability** (not SEO/marketing).

---

## 1. Executive Verdict

The hypothesis "this system is 20% built with major services missing and poor UI/UX" is **wrong about the core and right about the edges**.

This is a **two-speed codebase**:

| Layer | Completeness | Verdict |
|---|---|---|
| Security kernel (`packages/core`: RBAC, SoD, manifest, state machines, policy, risk, money, CSV) | **~95%** | Best-in-class for a system at this stage; pure, tested, default-deny |
| Payment execution correctness (idempotency, queue, reconciliation, callbacks, failure dictionary) | **~85%** | Genuinely safe-by-design; untested only against live Safaricom |
| Auth (Argon2id, WebAuthn, sessions, device trust) | **~80%** | Strong, but recovery and step-up flows are broken/missing (§3.1, §3.2) |
| Data model (34 tables, 5 views, immutability triggers) | **~90%** | Matches the spec's canonical model; 2 tables are dead schema |
| API surface vs spec §17 | **~55–60%** | Money-path APIs done; **user mgmt, recipients, devices, reports, retry, reconciliation resolution, cancel/hold-release are missing** |
| Web console vs spec §21 | **~30%** | 4 screens of ~14 needed; **L1 (prepare) and L2 (review) have no UI at all** |
| Operational readiness (live Daraja, deployment, edge, load) | **~40%** | Never deployed, never run against Safaricom, no WAF/DDoS layer |

**Whole-product estimate: ~60% of the specification's scope, correctly weighted in the wrong direction for go-live.** The hardest 60% (moving money safely) is built to an unusually high standard; the *operating* surface that a real finance team touches daily — batch preparation UI, finance review UI, user administration, recipient management, reporting, retry, reconciliation resolution — is largely missing. **As shipped, a payroll cannot be run end-to-end through the web console; it can only be run through curl.**

The repo is also honest: `README.md` and `docs/specification-coverage.md` admit most of this ("Not verified against production Daraja", "There is no edge any more", "Coverage is 63.6%... uneven"). What the docs do *not* admit are the four new defects found in this audit (§3.1–3.4).

> Naming note: the attached spec brands the product CARACAL v1.0; the repo implements "SOLVAREN v2.0" (a later revision — it contains §6 transaction-tracking/TRK requirements and AC-16–20 that don't exist in the v1.0 document). Coverage claims below are evaluated against the union of both.

---

## 2. Verified Strengths (things that are genuinely built and tested)

1. **The release ceremony is real, not theatre.** Ten independent gates in `services/authorization.ts`: L3 permission → L2 approval bound to current batch version → SoD (creator/editor/approver ≠ authorizer, re-checked at release) → conflict-of-interest registry → manifest **rebuilt from live rows** and hash-compared → fresh-auth → **real WebAuthn signature over the manifest digest** (verified in `routes/authorization.ts:167-189` against the stored credential public key, `requireUserVerification: true`) → SPAC PIN (Argon2id, user-id-bound) → policy limits + risk gate → state machine. Challenge is single-use (conditional UPDATE burn), 5-min TTL, user-bound, partial-unique-index per batch.
2. **Auth:** Argon2id with OWASP 2024 params (`crypto.ts`), timing-equalized login against a dummy hash, 5-failure account lockout, WebAuthn **mandatory** for L2/L3 (session refused without it, `auth.ts:172-178`), cloned-authenticator counter detection (CRITICAL security event), session tokens stored only as HMAC digests, device-trust status re-checked on every request, `logout-all`.
3. **Ledger immutability at the DB layer:** `audit_events` UPDATE/DELETE refused by trigger for every role; hash-chained (SHA-256, sequence assigned by trigger); `SUCCESS` requires an M-PESA receipt (state machine precondition **and** CHECK constraint **and** SYSTEM-source refusal); `FAILED` requires a reason; settled rows never rewritten — a contradicting callback opens a human discrepancy case instead. 53 DB assertions attack this directly (`db/tests/immutability.sql`).
4. **Exactly-once payment execution:** idempotency claim transitions to SUBMITTED **and commits before** the provider call; queue messages carry a fingerprint re-derived from live rows in the executor; `OriginatorConversationID` unique; the Daraja client **never retries B2C** at any level; ambiguous outcomes (timeout/5xx/duplicate-originator) open reconciliation cases instead of resending.
5. **Postgres-backed queue with the right semantics:** `FOR UPDATE SKIP LOCKED`, per-queue policies, leases with expiry recovery, DLQ with mandatory reason, **transactional enqueue** (release + claims + jobs commit atomically).
6. **Secrets handling:** Daraja credentials AES-GCM envelope-encrypted before leaving the process, stored in an S3/R2-backed secret store keyed by reference; the initiator password is **never persisted** (encrypted once against the M-PESA X.509 cert via a hand-rolled, OpenSSL-verified RSA PKCS#1 v1.5 implementation, or a pre-computed credential is accepted); API responses are masked-only, verified by tests.
7. **RBAC/SoD as code AND as schema:** permission matrix default-deny (`rbac.ts`), forbidden-to-all capabilities list, self-approval/self-authorization blocked in code **and** as CHECK constraints on `payment_batches`; cooling-off; conflict registry; approval-pair concentration signal.
8. **Backups:** async worker, STARTED→terminal lifecycle (CHECK constraints refuse fake SUCCESS), read-back verification, retention only after commit with honest PARTIAL status, 5-failure suspension, MISSED-window detection, restore round-trip tested with audit-chain verification.
9. **CI:** gitleaks + custom invariant script (verified to *fail*), type-aware lint, 350 tests + 53 DB assertions against **real PostgreSQL**, coverage gate, bundle-size budget, Docker builds, generated-seed drift check. This is above typical startup CI.
10. **WebAuthn ceremony UX:** amount as the largest element, per-sentence acknowledgement checkboxes, live expiry countdown, disabled-state that names the missing gate, PIN cleared on failure, focus trap.

---

## 3. Security Gaps Found in This Audit (new, not admitted in the repo's own docs)

### 3.1 🔴 P0 — No step-up re-authentication exists: privileged actions die 5 minutes after login
`STEP_UP_MAX_AGE_MS = 5 min` (`services/auth.ts:32`). `assertFreshAuthentication` gates **payment release**, Daraja configure/enable, policy changes and backup-target config. But `sessions.authenticated_at` is written **once, at login**, and no endpoint anywhere updates it (verified by grep across `apps/api/src`). Consequences:
- Any L3 release attempt more than 5 minutes after login throws `STEP_UP_REQUIRED` — the error says "confirm your identity again", but **there is no way to confirm again** short of full logout/login.
- The ceremony modal renders the error with no recovery path; `ApiError.requiresReauthentication` is unused on that screen.
- This also violates spec §5.4 ("Complete fresh step-up authentication") — the step-up *gate* exists, the step-up *flow* does not.

**Fix:** add `POST /auth/step-up` (password + WebAuthn assertion → update `sessions.authenticated_at`), and have the ceremony UI offer it on `STEP_UP_REQUIRED`.

### 3.2 🔴 P0 — Live Daraja callbacks can never authenticate (stored callback URLs are missing the secret segment)
- Route contract: `POST /integrations/daraja/callback/:organizationId/:secret` (`routes/callbacks.ts:198`), secret from the path (or `X-Solvaren-Callback-Token`, which Safaricom will never send).
- But `configureDaraja` stores `resultUrl = API_BASE_URL + "/integrations/daraja/callback/" + organizationId` — **no `/:secret` segment** (`services/daraja-config.ts:241-242`), and the generated callback secret (`daraja-config.ts:224`) is never returned to the administrator by any endpoint.
- Therefore in a live deployment Safaricom's ResultURL deliveries arrive secret-less → `CALLBACK_AUTH_FAILED` → **every real payment outcome would be lost** and fall into Transaction-Status reconciliation (correct but expensive), or `UNMATCHED` handling.
- Related brittleness: reconciliation rewrites the URL by string replace (`result_url.replace('/callback/', '/status-callback/')`, `reconciliation-worker.ts:213,310`).

This is the concrete shape of "not verified against production Daraja": the happy path is broken today. **Fix:** embed the secret in the stored URLs (or accept header auth + build the URLs at submit time), and surface the callback URL once to the configuring L3.

### 3.3 🟠 P1 — Documented rate-limiting controls do not exist in code
The threat model (`docs/threat-model.md` §8) claims "Ten sign-in attempts per minute per IP" and "Twenty [exports] per five minutes". The only rate limiter call site in the entire API is the payment executor's Daraja TPS bucket (`payment-executor.ts:112`). `/auth/login` and the unauthenticated callback ingest have **no rate limiting** — only body-size caps and per-account lockout. An attacker can hammer login (Argon2id costs ~50ms CPU per attempt, unauthenticated) and the callback endpoint (each attempt performs a DB read) without limit. **Fix:** wire `PostgresRateLimiter` (it exists and is correct) into `/auth/login`, `/exports/*`, and callback ingest.

### 3.4 🟠 P1 — IP capture is Cloudflare-only; on Railway every IP is null
`requestContext` reads `CF-Connecting-IP` / `CF-IPCountry` exclusively (`middleware/security.ts:35-37`). Since the platform moved off Cloudflare, `securityContext.ip` is `null` on every request → login events, security events, sessions, provider callbacks and audit events all record **no source IP**. Combined with 3.3 this destroys the forensic value the audit trail promises and makes any future IP-based control dead on arrival. **Fix:** read `X-Forwarded-For` (right-most trusted proxy) / Railway's `X-Real-IP` with the CF header as override.

### 3.5 🟠 P1 — Account-recovery dead end (admitted, but it is a security *and* availability hole)
Recovery codes can be generated (`/auth/recovery-codes`) but **redeemed nowhere** (no endpoint; `docs/specification-coverage.md` admits "the redemption flow is not built"). There is also **no admin recovery path** (no user-management API at all, §4.1). An L2/L3 officer who loses their authenticator is permanently locked out; the only remedy is direct database surgery — for a system whose selling point is that nobody touches the database. WebAuthn enrolment also has **no UI** (§5.2), so a new officer cannot even get to a working state without curl.

### 3.6 🟡 P2 — Encryption-key lifecycle
`SECRET_ENCRYPTION_KEY` derives AES-GCM keys via plain SHA-256 (no HKDF/salt/iteration), has no versioning, and no rotation path for existing envelopes; key equality with `SESSION_SIGNING_KEY` is checked, which is good. A leaked master key decrypts every Daraja/backup secret ever stored, with no re-wrap procedure. Also the secret store is the **same S3 bucket family** as backups (separate key, but same credential scope on the bucket).

### 3.7 🟡 P2 — Accepted-but-real edge gaps
- No WAF / DDoS / TLS-terminating proxy in front (Railway bare). README says "put a proxy in front" — that is a to-do, not a control.
- The SPA itself has only `frame-ancestors 'none'` from nginx; no full CSP with `script-src` for the console bundle (the API's strict CSP doesn't apply to the web origin).
- WebAuthn login challenges are stored inside `security_events.detail` JSON and queried via `detail->>'ticket'` (no index; append-heavy table) — works, but fragile under load.
- Session token lives in JS memory only (excellent XSS posture, and CSP mitigates) — but every page refresh logs the officer out; for a daily-driver internal tool this will be resented (see §6).

### 3.8 🟡 P2 — Doc rot that misleads auditors
Multiple code comments reference infrastructure that no longer exists: "Cloudflare Secrets Store" (`daraja-config.ts:104`), "WAF restricts this route to Safaricom's published source ranges (see infra/terraform)" (`callbacks.ts:14`, no `infra/` in repo), "Cloudflare Access policy on `/health/*`" (`index.ts:71-72`). For a system "written to be read by an auditor", stale security claims in comments are a finding of their own.

---

## 4. Development Gaps vs the Specification (the "major services missing" list)

### 4.1 Missing entirely (API **and** UI)

| Spec area | Requirement | Status |
|---|---|---|
| §4/§17 User administration (`/admin/users/*`) | L3 creates/disables/unlocks users, assigns levels; permission `admin:users` exists | **No endpoint, no UI.** Bootstrap only via `scripts/create-user.mjs`. Cannot offboard an officer, unlock a locked account, or enrol the second L2/L3 without CLI+DB access. |
| §4.1 Recipients master data (`/recipients/*`) | Recipient CRUD, deactivate/reactivate, history | **No endpoint, no UI.** Recipients are auto-upserted only by CSV upload; a BLOCKED recipient can never be re-activated through the product; `recipients:write` permission is granted to all levels with nothing behind it. |
| §7.1 Device trust management (`/security/devices/*`) | List devices, set TRUSTED/REVIEW/BLOCKED/REVOKED | Rows are written at login; **no list/revoke API or UI.** Device revocation is only effective because `resolveSession` checks it — but you can only revoke via SQL. |
| §9 Batch scheduling & recurring templates | Cron-like windows, templates, cut-off times, holiday calendar, priority queues | **Dead schema.** `batch_templates` and `payment_calendar` tables exist (migration 0004) and are even included in backups, but zero application code references them. Scheduler runs only reconciliation/backups/housekeeping. No priority lanes. |
| §11.1 Reports (`/reports/*`) | 12 report families (executive, financial, payroll, audit, reconciliation, risk, department, user activity, Daraja…) | **No `/reports` endpoints.** Only dashboards + the failed-transactions CSV. `reports:operational/management/executive` permissions exist unbacked. TRK-010 full export: partial. |
| §9.3/§4.1 Eligible retry | `transactions:retry` permission + `retryEligible` computed per row | **No retry endpoint.** A transiently-failed payment can only be re-paid by manually rebuilding a new batch/CSV. |
| §9.5/§22 Reconciliation case resolution | `reconciliation:resolve` permission; ESCALATED cases say "resolve manually" | **No manual-resolution endpoint or UI.** ESCALATED cases are a dead end (only the runbook tells you to check the M-PESA portal). |
| §5.1 Cancel / hold-release / return | State machine defines `CANCEL`, `RELEASE_HOLD`, `RETURN_TO_L1` (`batch-state.ts:53-74`) | **No routes invoke them.** → A batch placed on **HELD is stuck forever**; drafts can't be cancelled and accumulate; `batch:cancel` permission unbacked. |
| Notifications/alerting (BAK-009 etc.) | Backup-failure and security alerts reach an administrator | Everything lands in `security_events`/audit rows; **no email/webhook/in-app alert delivery exists.** |
| Queue observability (§9 "operator-visible queue status and stuck-job diagnostics") | DLQ inspection, stuck jobs | **No API or UI** for `job_queue` (which even has a dead-letter index). |

### 4.2 Built at the API layer but missing a UI (the L3/admin surfaces)

- **Daraja configuration** (`/admin/daraja*`): configure/test/enable/disable endpoints exist; **zero UI**. The first production Daraja setup is a curl exercise.
- **Policies** (`/admin/policies`): GET/PATCH exist; **no UI.**
- **Audit search & chain verification** (`/admin/audit*`): exist; **no UI.** For a "financial command center", not being able to read your own tamper-evident log without curl is a significant miss.
- **AI assistant** (`/ai/*` — batch analysis, failure explain, expenditure Q&A, executive briefing): built, degrades gracefully, boundary enforced by CHECK constraint; **no UI calls any of it.**
- **Financial & executive analytics** (`/analytics/financial`, `/analytics/executive/briefing`): built; **no UI** (only operational + balance + recent-transactions panels are rendered).
- **WebAuthn enrolment, authorization-PIN set/change, recovery-code generation, logout-all**: endpoints exist; **no UI.**

### 4.3 Partial / thin

- **Batch detail cap:** `GET /batches/:id` returns max **1000** instructions (`batches.ts:696`) while policy allows 5,000 per batch → large payrolls are partially invisible in the API view.
- **Daraja rotation PIN:** the route comment says the PIN is "verified by the caller supplying it through the rotation confirmation step below" (`admin.ts:66-67`) — no such step exists; rotation enforces fresh-auth + WebAuthn but **not the PIN**, contra spec §9.1.
- **Risk signals declared but never raised:** `DEPARTMENT_VARIANCE` and `ROUND_NUMBER_CLUSTER` exist as types (`risk.ts:31,40`) with no detection logic; "unusual frequency" is only a business-hours check.
- **Backup schedule:** only a fixed daily cadence actually executes (`next_scheduled_run_at = now()+1day`, `index.ts:204`) — a stored weekly cron would silently run daily.
- **Backups are logical JSON snapshots** (all tables `SELECT *` into memory under REPEATABLE READ) — point-in-time consistent and restore-tested, but memory-bound and slow at scale; no engine-level snapshot option.
- **Executor token efficiency:** `loadDarajaClient` constructs a **new `DarajaClient` per instruction** (`payment-executor.ts:433`), so the in-client token cache never helps — every payment costs an OAuth token request + a B2C request. The client's "200 callers → 1 token request" design is defeated by its own call site (spike-arrest risk at Daraja).

### 4.4 Spec §23 security-test checklist — status
Attempt-insufficient-role, self-approval block, manifest-tamper block, replay block, forged-SUCCESS block, duplicate-callback dedupe, forced-timeout no-resend, backup success/failure/retention/schedule-disable: **all implemented and tested** (this is real). Rotate-credential old-ref reuse, revoke-device effect: implemented at DB/session level but **not operable in the product** (no device-revoke or user API). Live-provider rows: not possible yet (§3.2).

---

## 5. UI/UX Assessment (spec §21, internal tool lens)

**Screens that exist (good quality):** Login (two-stage, WebAuthn), Dashboard (operational + L3 balance/recent panels), Payment Batches **list + release ceremony only**, Transactions Explorer (filters, server sort/pagination, failure summary, failed-CSV export, on-demand refresh, detail view with activity trail & reconciliation cases), Backups (status, run-now, history).

**The decisive finding:** `Batches.tsx` renders **no action buttons for create / upload CSV / validate / submit / approve / reject / hold** — line 119 literally reads *"Payment Operations creates a batch by uploading a CSV of recipients and amounts"* while no upload UI exists anywhere; `api.batches.approve/reject` are defined in `api.ts` and **never called**. The web console implements the **L3 slice** (watch, release) of the product; **the entire L1 preparation and L2 finance-review experience is missing.** In the console as shipped, a batch can only ever appear if someone created it via the API.

Missing screens vs §21: Employees/Recipients, Analytics (financial/payroll/executive/briefing), Security Center (devices, security events, audit viewer), Settings (Daraja, organization, policies, notifications), Users, Reconciliation queue, Reports, batch **detail/review** screen (instructions table, approval history, risk findings — all served by the API, none rendered outside the ceremony modal), AI assistant.

Quality of what exists is **high, not "poor"**: bespoke design system with light/dark themes, focus management and traps, aria labels, status never by colour alone, money rendered with screen-reader labels, live countdowns, errors that keep server shape (code + message + correlation id), 120KB gzip bundle budget, `ui:check` smoke-driving Chromium. The problem is **coverage, not craft**.

Internal-tool usability notes: in-memory session token (refresh = re-login) will hurt daily use; no keyboard shortcuts or bulk actions; explorer caps at 200 rows/page (fine); no polling/live updates (transaction status changes require manual refresh — an operator watching a payroll run will refresh obsessively; SSE/polling is absent).

---

## 6. Reliability & Operations Assessment

- **Provider risk:** never run against Safaricom sandbox/production (admitted) **and** the callback URL defect (§3.2) means the first live test will fail until fixed.
- **Never deployed end-to-end** (admitted). No staging story, no smoke test against a deployed environment.
- **No load testing** (admitted) + memory-bound JSON backups + per-instruction OAuth token fetch are the three most likely first-scaling incidents.
- **No edge protection** (admitted): DoS exhausts the app before any application control applies.
- **Observability:** structured JSON logs + health endpoints only. No metrics, no alerting, no dashboards; `/health/ready` gated by an Access policy that doesn't exist anymore.
- **RPO/RTO undefined**; restore is tested by script only.
- **Runbooks:** 3 of the spec's 10 required runbooks exist (payment-stuck, credential rotation, backup-restore) — the good news is they're the three most likely to be needed; missing: callback outage sweep, compromised user/device, fraud incident, DB failover, backup-target outage, audit preservation, rollback.

---

## 7. Scorecard

| Area | Score | One-liner |
|---|---|---|
| Domain/security kernel | **A−** | Pure, default-deny, exhaustively tested; 2 dead risk signals |
| Payment correctness & idempotency | **A−** | Commit-before-call, no blind retry, honest ambiguity |
| AuthN/AuthZ | **B** | Strong foundations; step-up flow missing, recovery dead end, no user admin |
| Secrets | **B+** | Envelope-encrypted, masked, never-returned; no key rotation |
| DB & immutability | **A−** | Triggers + chain + 53 attacking assertions; 2 dead tables |
| API breadth vs spec | **C+** | Money path done; ~9 spec service groups absent |
| Web console | **D+** | 4 screens, beautiful; L1/L2 workflows and every admin screen missing |
| CI/CD | **A−** | Gitleaks, invariants, real-Postgres tests, budgets |
| Deployment/ops readiness | **D** | Never deployed, no edge, no observability, runbooks 3/10 |
| **Overall vs spec scope** | **~60%** | **The right 60% — but it is not an operable product yet** |

---

## 8. Prioritized Roadmap

### P0 — before any live money (blocks correctness/operations)
1. Fix callback URLs to include the auth secret; surface the callback URL/secret at configuration (§3.2).
2. Build `POST /auth/step-up` (password+WebAuthn → refresh `authenticated_at`) and wire the ceremony UI to it (§3.1).
3. L1 console workflow: batch create → CSV upload → validation report → submit; L2 console workflow: review (instructions, risk findings, approval history), approve/reject/hold (§5) — the API already exists.
4. `/admin/users` API + UI: create user, set level, disable, unlock, admin-initiated re-enrolment; closes the recovery dead end (§3.5, §4.1).
5. Wire rate limiting into login/exports/callback ingest; fix IP capture for Railway (§3.3, §3.4).
6. Add routes for `CANCEL` / `RELEASE_HOLD` (un-strand HELD batches).

### P1 — before daily-driver status
7. Daraja config UI + rotation PIN step; policy editor UI; audit viewer UI (with chain-verify button); devices UI (list/revoke).
8. Retry endpoint for retry-eligible failures; reconciliation case queue + manual resolution UI; queue/DLQ diagnostics view.
9. Recipients management (search, deactivate/reactivate, history).
10. Transaction auto-refresh (polling/SSE) on explorer & batch views; session persistence strategy (e.g., silent re-auth via WebAuthn conditional mediation) to survive page refresh.
11. Reporting endpoints + exports (audit, reconciliation, department, payroll); AI panel in the UI.
12. Fix per-instruction token fetch (cache one `DarajaClient` per org/config with token reuse).
13. Executor connection-test against Daraja **sandbox** and a staged end-to-end payroll run; put Cloudflare (or any WAF proxy) in front per README's own advice.

### P2 — hardening & scale
14. Key rotation/re-wrap for secret envelopes (HKDF + key ids); batch-detail pagination past 1000; implement the two dead risk signals; real cron support for backup schedules; engine-level backup option; metrics + alerting; remaining 7 runbooks; load test at spec volume; clean up Cloudflare doc-rot comments.

---

## 9. Addendum — Daraja Knowledge-File Cross-Check (`mpesa-daraja-api-knowledge.md` vs implementation)

Cross-verified the knowledge file (captured 2026-09-13) against `packages/daraja` and `failure-reasons.ts` code-by-code.

### 9.1 Verified correct (exact match with the documented contract)

| Knowledge file | Implementation | Status |
|---|---|---|
| §1.1/1.2 Hosts + OAuth GET path | `types.ts:14-24` — sandbox/api hosts, `/oauth/v1/generate?grant_type=client_credentials` | ✓ |
| §1.1 Token 1h lifetime | `client.ts` refresh at 80% of advertised lifetime | ✓ |
| §5.1–5.4 Endpoint paths (B2C v3, TS v1, Balance v1) | `DARAJA_PATHS` | ✓ exact |
| §5.1 `Occassion` misspelling; §5.3 correctly-spelled `Occasion` | preserved + commented in `types.ts:41,109` | ✓ both |
| §5.3 Transaction lifecycle (`Initiated→Authorized/Pending Authorized→Completed/Cancelled/Declined/Expired`) | `DarajaTransactionStatus` union, `types.ts:124-131` | ✓ exact 7 states |
| §1.6 SecurityCredential = RSA **PKCS#1 v1.5, not OAEP** | hand-rolled RFC 8017 EME-PKCS1-v1_5, OpenSSL-verified | ✓ |
| §4.5 Portal password rules (8–30 chars, only `#&%$`, no `@`/`.`) | `validateInitiatorPassword` | ✓ |
| §1.3 **Daraja never retries failed callbacks** | always-200 ingress, raw payload persisted first | ✓ |
| §1.5 Duplicate `OriginatorConversationID` (`500.002.1001`) | unique constraint + mapped AMBIGUOUS *"do not resend, query status"* — the exactly-right semantic | ✓ |
| §5.1 Limits (min 10, max 250,000; customer 500K daily/balance) | `DARAJA_B2C_MIN_CENTS/MAX_CENTS`, codes 4/8 mapped | ✓ |
| §3 B2C debits **Utility** account (not Working) | code-1 operator action says verbatim "move funds from Working (MMF) to Utility" | ✓ |
| §5.1 Success callback carries account balances | harvested into `account_balance_snapshots` | ✓ |
| §5.5 B2C reversals impossible via API | ceremony warning says "handled on the M-PESA organisation portal" | ✓ |
| §5.1 B2C ResultCodes (all 14: 0,1,2,3,4,8,11,21,2001,2006,2028,2040,8006,SFC_IC0003) | all mapped in `failure-reasons.ts` | ✓ 14/14 |

### 9.2 Dictionary gaps (unmapped codes — graceful fallback covers them, but they should be mapped)

- **`100000000`** — "Request cached, waiting for resend" (an *in-flight* signal; deserves AMBIGUOUS/`transient:true`, not the generic unmapped sentence)
- **`100000005`** — "Invalid input value: %1"; **`100000007`** — "Service status abnormal"; **`100000009`** — "API status abnormal"
- **`404.003.01`** (wrong endpoint) and **`405.001`** (method not allowed) — engineering-fault codes; mapping them speeds diagnosis (`401.001` is Pull-API-only — irrelevant here)

### 9.3 The callback-secret defect (§3.2 above) is now **confirmed live-breaking**

Knowledge §1.3: Safaricom POSTs the result to the **ResultURL exactly as configured**, performs **no retries**, and adds **no custom headers**. Since `configureDaraja` stores URLs *without* the `/:secret` segment and Safaricom will never send `X-Solvaren-Callback-Token`, **every production B2C result, queue-timeout, status and balance callback will fail authentication in the current code.** The `QueueTimeOutURL` has the same defect.

### 9.4 Unverified assumptions & unexploited capabilities the knowledge file reveals

1. **Whole-shillings rule is an assumption.** `csv.ts` rejects cent amounts ("M-PESA B2C pays whole shillings only") — the knowledge file documents no such constraint (`Amount` is plain numeric). Probably harmless for payroll; **verify in sandbox** before it rejects a legitimate 10.50 amount.
2. **No pre-release Utility-balance gate.** The knowledge file's biggest operational pitfall (§3: B2C debits Utility; funds sitting in MMF/Working → mass code-1 failures) is half-mitigated: balances already land in `account_balance_snapshots` via callbacks, but `assertReleasePolicy` never checks them. A one-line-ish gate — *Utility balance ≥ batch total + estimated fees, else require acknowledgement* — would prevent the classic first-payroll failure mode. (Data may be stale; treat as an acknowledgement trigger, not a hard block.)
3. **B2C Account Top Up (`BusinessPayToBulk`) not integrated** — funding the Utility account is a manual portal task; worth a runbook note even if never automated.
4. **B2C Hakikisha (§5.7) not integrated** — pre-payout masked-name verification would directly serve spec §5.3 ("verify recipient identity" at L2 review) and shrink the `2040`/wrong-number failure class. Requires Safaricom onboarding; a strong Phase-2 candidate.
5. **Sandbox simulator** only works with sandbox test shortcodes (§7) — the connection test + a scripted small-value B2C run in sandbox must be the first live-validation step after fixing §3.2/§3.3.

### 9.5 Revised P0 list (post-cross-check)

1. Fix callback/timeout URLs to carry the auth secret (§3.2/§9.3) — *nothing else can be validated live until this is fixed.*
2. Step-up re-auth endpoint (§3.1).
3. Map the 6 missing codes in `failure-reasons.ts` + regenerate the seed (`pnpm db:generate-seed`).
4. Add the Utility-balance acknowledgement gate to the release ceremony (§9.4.2).
5. Then: sandbox connection test → scripted B2C acceptance/rejection/timeout/callback run (the repo's scripted provider already models these paths — replay them against the real sandbox).

---

*Audit artifacts: the extracted spec is at `F:\SOLVAREN 2\caracal_spec.md` (extracted via `extract_docx.ps1`; both helper files can be deleted).*

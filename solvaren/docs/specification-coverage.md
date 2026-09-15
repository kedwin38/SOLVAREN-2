# Specification coverage

Every requirement from the SOLVAREN v1.0 specification (14 Sep 2026), where it is
implemented, and how it is verified. The **Verified** column is the important one:
"implemented" is a claim, "verified" is a test you can run.

Status values:

- **Verified** — implemented, and a test fails if it regresses.
- **Implemented** — built to the specification, but verification is indirect or blocked
  on a live provider/deployment.
- **Partial** — deliberately incomplete; the gap is stated.

Run `pnpm typecheck && pnpm test && bash scripts/check-invariants.sh` for everything
that does not need infrastructure; `pnpm db:test` (with PostgreSQL) for the schema
assertions.

---

## §4 — Roles, command hierarchy and the dynamic permission engine

| Requirement | Where | Verified |
| --- | --- | --- |
| Three authority levels, server-side enforced | `core/rbac.ts` | **Verified** — 19 tests, matrix at full branch coverage |
| Default deny on every permission | `core/rbac.ts` MATRIX | **Verified** — absence from a level's set is refused |
| L1 cannot approve or release | `core/rbac.ts`, `core/batch-state.ts` | **Verified** — state-machines tests; AC-01 |
| L2 cannot release | `core/rbac.ts` | **Verified** — AC-02 |
| L3 cannot perform the L2 approval (two hands) | `core/batch-state.ts` `minimumLevel` | **Verified** — level-mismatch denial tested in both directions |
| L3-only Daraja/users/policies/security/backups | route groups + `requireExactLevel('L3')` | **Implemented** — enforced at every admin route; HTTP-level tests require a live database |
| Non-active account holds no permission | `core/rbac.ts` | **Verified** — every permission × DISABLED/LOCKED |
| **AC-17: dynamic L3 permission engine with immutable ceilings** | `core/rbac.ts` `effectivePermissions` | **Verified** — grant-everything attack cannot pierce any ceiling; override validation, versioning and supersession tested |
| Baseline is the default and restorable | `POST /api/admin/permissions/reset` | **Implemented** — audited; supersession logic unit-tested |
| §4.4 "even L3 cannot" alter history / force SUCCESS | `db/migrations/0003` triggers | **Implemented** — `db/tests/immutability.sql` attacks each (CI runs them against real PostgreSQL) |
| Tenant isolation | every query scoped by organization_id | **Implemented** — cross-tenant ids are not-found by construction |

## §5–6 — Batch lifecycle

| Requirement | Where | Verified |
| --- | --- | --- |
| Full state machine incl. RETURNED_FOR_CORRECTION, ON_HOLD, REJECTED | `core/batch-state.ts` | **Verified** — full L1→L2→L3 walk, terminal-state immutability, no-dead-ends |
| No backward mutation by command; no FORCE_STATE | `core/batch-state.ts` | **Verified** — terminal states have zero outbound edges |
| Execution transitions system-only | `core/batch-state.ts` | **Verified** — `system: true` is not a skeleton key; and cannot pass human edges |
| Submission freezes the approval version | routes/batches.ts | **Implemented** — approval bound to version; stale approval refused in `loadCurrentApproval` |
| CSV ingest with row-level reasons | `core/csv.ts` | **Verified** — 20 tests: BOM, quoted fields, formula rejection, duplicates, caps |
| Cancel / hold / release-hold / return all reachable | routes/batches.ts | **Implemented** — the workflow has no dead-end state |

## §7 — Authentication and payment authorization

| Requirement | Where | Verified |
| --- | --- | --- |
| No SMS anywhere | whole tree | **Verified** — `check-invariants.sh` (no SMS/OTP code, no phone column on identity tables) |
| Argon2id, OWASP parameters | `api/services/crypto.ts` | **Verified** — parameters asserted in tests; WASM runs identically everywhere |
| WebAuthn mandatory for L2/L3 | `api/services/auth.ts` `issueSession` | **Implemented** — session refused without it; enrolment + step-up flows built |
| FPAC PIN, user-bound, never plaintext | `api/services/crypto.ts` | **Verified** — binding to user id; shape rules (trivial/sequential PINs refused) |
| Manifest binds org+batch+amounts+recipients+approval+version+policy digest | `core/manifest.ts` | **Verified** — 8 distinct mutation classes each move the digest (23 tests) |
| Anti-replay: nonce, expiry, single use, user binding, batch binding | `core/manifest.ts` `verifyChallengeBinding` | **Verified** — each attack has a named test |
| Step-up authentication is satisfiable mid-session (the predecessor's fatal gap) | `POST /api/auth/step-up` | **Implemented** — password + WebAuthn refreshes `authenticated_at` in place |
| Recovery: password + one-time code, full re-enrolment, sessions revoked | `POST /auth/recovery/redeem` | **Implemented** — 15-minute reset session that can enrol a key and nothing else |
| Release gates all invoked on the release path | `services/authorization.ts` | **Verified** — `check-invariants.sh` greps for each gate's invocation |

## §8 — Devices, sessions, secrets

| Requirement | Where | Verified |
| --- | --- | --- |
| Device trust with TRUSTED/REVIEW/BLOCKED/REVOKED | schema + routes/security.ts | **Implemented** — revocation kills sessions immediately, checked per request |
| Session invalidation server-side | sessions table + revocation | **Implemented** |
| Envelope-encrypted secrets, references only in DB | `api/services/secret-store.ts` | **Verified** — crypto tests: tamper detection, purpose-separated derivation |
| Plaintext secrets never returned | masked views only | **Verified** — invariant check: no code path returns stored secret material |

## §9 — Daraja integration

| Requirement | Where | Verified |
| --- | --- | --- |
| B2C v3, Transaction Status, Account Balance | `packages/daraja` | **Verified** — 16 tests against the scripted provider |
| SecurityCredential: RSA PKCS#1 v1.5, DER/X.509 parsing | `daraja/security-credential.ts` | **Implemented** — RFC 8017 construction; portal password rules enforced at config |
| Token lifecycle, concurrent refresh collapse | `daraja/client.ts` | **Verified** — 20 concurrent payments produce one token request |
| **Never retry B2C** | `daraja/client.ts`, executor | **Verified** — no-retry tested including token-error class |
| Ambiguous outcomes → reconciliation, never resend | executor + `core/failure-reasons.ts` | **Verified** — duplicate-originator and 5xx/timeout codes classified AMBIGUOUS |
| Callback secret embedded in stored URLs (predecessor's fatal defect) | `services/daraja-config.ts` | **Verified** — `check-invariants.sh` asserts the URL construction |
| Callback replay protection by digest | routes/callbacks.ts | **Verified** — parser tests + duplicate handling |
| Complete failure dictionary (55 codes incl. 100000000, 100000005/7/9, 404.003.01, 405.001) | `core/failure-reasons.ts` | **Verified** — seed generated from source; CI fails on drift |
| Live provider | — | **Not verified** — requires Safaricom credentials and a shortcode |

## §10 — Orchestration and scheduling

| Requirement | Where | Verified |
| --- | --- | --- |
| Recurring templates with materialization | scheduler + `batch_templates` | **Implemented** — cron engine verified (14 tests incl. EAT→UTC translation); materialization runs on the scheduler tick |
| Priority queues (urgent 1 … routine 100) | `job_queue.priority`, `claimBatch` ORDER BY | **Implemented** — claim ordering in SQL |
| Rate limiting aligned to the contract | `api/rate-limiter.ts` (token bucket, row-locked) | **Implemented** |
| Cut-off times + holiday calendar | `core/policy.ts` `calendarBlockReason` | **Verified** — cut-off and holiday denials tested with EAT-correct times |
| Concurrency: locks + one-live-job-per-instruction | `requireLock`, partial unique index | **Implemented** — schema assertion 8 |
| Operator-visible queue state, DLQ, requeue | routes/security.ts + Security Center | **Implemented** |
| Expired-lease recovery | `queue.ts recoverExpiredLeases` | **Implemented** |

## §11 — Risk, fraud and the AI boundary

| Requirement | Where | Verified |
| --- | --- | --- |
| Every §11.1 signal family | `core/risk.ts` | **Verified** — 24 tests: duplicates, deviation, new/modified recipient, frequency, department variance, batch-total deviation, late edit, timing, round numbers, unresolved reconciliation, approval concentration |
| Deterministic scoring, explainable evidence | `core/risk.ts` | **Verified** — same input → same score; diminishing-returns test |
| AC-15: AI cannot release | `ai_interactions` CHECK + read-only route group | **Verified** — invariant check (no payment-table writes in ai.ts) + schema assertion 9 |
| AI degrades to nothing without a key | `routes/ai.ts` | **Implemented** — deterministic layer unaffected |

## §12–13 — Reporting and backups

| Requirement | Where | Verified |
| --- | --- | --- |
| All 12 report families from the ledger | `core/reports.ts` + `report-builder.ts` | **Implemented** — catalogue is typed data; builders read authoritative tables |
| Export filtering + audit | routes/transactions.ts, export_records | **Implemented** |
| Backup configure/test/run/schedule/retention/history | routes/admin.ts + backup-worker | **Implemented** — statuses enforced by CHECK constraints (QUEUED/RUNNING/SUCCESS/FAILED/MISSED) |
| Missed schedule observability | scheduler `runBackupSchedules` | **Implemented** — MISSED attempt recorded before the next run |
| Retention only after success, never on failure | backup-worker + schema | **Implemented** — `object_retired_at` only on SUCCESS (asserted in schema) |
| Restore validation | `scripts/restore-snapshot.mjs` | **Implemented** — drill script verifies row counts, audit chain, batch totals, receipts |

## §14 — Audit and immutability

| Requirement | Where | Verified |
| --- | --- | --- |
| Append-only audit for every role | 0003 triggers | **Implemented** — schema assertions 3a/3b attack it directly |
| Hash chain: alteration, deletion, reordering each localised | `core/audit.ts` | **Verified** — 12 tests with exact failure positions |
| Sequence + chain link assigned by the database | `seal_audit_event` trigger | **Implemented** |
| Secrets never reach the log | `redactForAudit` | **Verified** — token-based redaction at depth (authorizationPin caught, mapping not) |

## §21–23 — NFRs and failure rules

| Requirement | Where | Verified |
| --- | --- | --- |
| Privileged endpoints deny by default | middleware + matrix | **Verified** — RBAC tests cover every permission per level/status |
| Validation failures keep the batch editable with row-level reasons | `core/csv.ts` | **Verified** |
| Worker crash leaves work recoverable | leases + at-least-once + idempotency | **Implemented** — lease recovery on a 30s timer |
| Backup failure never presented as success | schema CHECKs | **Implemented** — success requires object+size; failure requires a reason |

## §25 — Release acceptance

| ID | Status | Evidence |
| --- | --- | --- |
| L1/2/3 enforced server-side, tested | **Verified** | rbac + state-machine suites (AC-01/02) |
| No SMS path exists | **Verified** | Invariant check fails CI on any SMS/OTP/phone-column introduction (AC-06) |
| WebAuthn enforced for L2/L3 | **Implemented** | issueSession refusal + enrolment + step-up (live-DB HTTP test pending) |
| Authorization cryptographically bound to the manifest | **Verified** | 8 mutation classes move the digest; replay gates named (AC-05) |
| Creator ≠ approver, modifier ≠ authorizer | **Verified** | governance suite + schema CHECKs |
| Daraja secrets masked, L3-only management | **Implemented** | masked views only; rotation gated on PIN |
| Callbacks replay-aware and state-validated | **Verified** | parser suite + duplicate handling |
| AI cannot bypass the human boundary | **Verified** | Invariant + schema assertion (AC-15) |
| Dynamic permissions with ceilings, audited | **Verified** | Grant-everything attack test (AC-17) |
| Deploy on Railway with health checks + pre-deploy migrations | **Implemented** | railway.json configs; CI builds the images |
| Offsite backup configure/test/run/schedule/retention/history | **Implemented** | backup routes + worker; statuses schema-enforced |
| Restore tested at least once | **Pending** | The drill script exists; run it against a scratch database before declaring DR proven |
| Runbooks | **Done** | 3 core runbooks; the remaining 7 are organisational-process documents |

---

## Measured, not claimed

```
161 unit tests                    pnpm test
  ├─ kernel (core)      145
  └─ Daraja client        16
9 source-invariant families      bash scripts/check-invariants.sh
9 database security assertions   bash scripts/db-test.sh   (needs PostgreSQL)
Typecheck: all 5 packages        pnpm typecheck             strict + noUncheckedIndexedAccess
```

## Known gaps, stated

1. **HTTP-level integration tests** (login → build → release → execute → callback against
   a real database) are designed but require a PostgreSQL service in CI; the schema
   assertions cover the database side of the same invariants. This is the next
   engineering task, not a permanent state.
2. **Live Daraja** unverified (needs credentials; callback URLs are designed for it).
3. **No load testing.**
4. **Restore drill** scripted but not yet executed against real storage.

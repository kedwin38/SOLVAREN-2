# SOLVAREN Payment Solutions

**Move money with certainty.**

An enterprise business-disbursement control plane for Safaricom M-PESA Daraja B2C.
SOLVAREN prepares payment instructions, subjects them to layered finance review, requires
cryptographic authorization at the highest authority level, executes through Daraja B2C,
reconciles ambiguous outcomes, and keeps a tamper-evident record of what happened.

It is not a "send money" application. Its design objective is **controlled financial
execution**, and most of what follows is about the things it refuses to do.

Implementation baseline: *SOLVAREN Payment Solutions Software Specification v1.0 (14 Sep 2026)*.

---

## The properties everything else serves

**1. No single thing can release money.**
Releasing a payment requires L3 authority (checked against the live effective permission
matrix), an intact approval chain bound to the current batch version, separation of
duties, no declared conflict of interest, a manifest rebuilt from live database rows
that hashes identically to the one authorized — including the policy digest — fresh
authentication (satisfiable mid-session via step-up), a WebAuthn signature over the
manifest digest, the Frontier Authorization PIN, organization policy limits, the
financial-calendar gates (cut-off, holidays), the risk gate and a valid state transition.

By organizational decision, L3 — the chief/executive authority and overall superior of
the system — is exempt from the creator/editor/approver separation-of-duties checks
(`packages/core/src/sod.ts`) and may prepare, review, approve and authorize a batch alone,
start to finish. L1 and L2 remain fully bound by separation of duties with no exemption.
Every other gate on this list — fresh authentication, WebAuthn, the FPAC PIN, policy
limits, the risk gate, a valid state transition — still applies to L3 unchanged.

There is no override, no parameter that disables a check, and no branch that skips one.
`apps/api/src/services/authorization.ts` is written to be read start to finish by an
auditor.

**2. An unknown outcome is never resolved by guessing.**
If SOLVAREN cannot tell whether a payment reached M-PESA, it does not retry — retrying
pays someone twice, and B2C payments cannot be reversed through the API. It does not
assume failure either, because that leaves someone unpaid. It queries the Transaction
Status API until Safaricom gives a definitive answer, and escalates to a human when it
cannot get one.

**3. No failure is invisible or unexplained.**
Every failed transaction carries a provider code, a human-readable reason from a
complete dictionary (all documented B2C, core-numeric and gateway codes — 56 entries),
and a concrete operator action. The database refuses to store a FAILED transaction
without a reason and a SUCCESS without a provider receipt.

**4. Authority is data, audited, with immutable ceilings.**
The Level 3 executive can grant or revoke specific L1/L2 capabilities at runtime
(AC-17). Every change is versioned and audited as a high-severity event, effective on
the very next request. The engine applies **immutable ceilings** after every override:
no override combination — ever — can grant L1 or L2 payment release, Daraja
administration, or any capability forbidden to all levels. The baseline matrix is the
default and can always be restored.

---

## What is here

```
packages/core/       Domain and security kernel — pure, no I/O, exhaustively tested
packages/daraja/     M-PESA Daraja B2C, Transaction Status, Account Balance + scripted provider
packages/storage/    S3-compatible object store client (SigV4, dependency-free)
apps/api/            Node service: HTTP API, six queue consumers, the scheduler
apps/web/            The console — React, bespoke design system, no UI framework
db/migrations/       PostgreSQL schema. The immutability guarantees live here.
db/tests/            Security assertions that attack the schema directly
docs/                Deployment, runbooks, threat model, specification coverage
scripts/             Migrations, bootstrap, invariant checks, database assertions
```

### The security kernel is pure

`packages/core` has no database, no network and no platform bindings. The rules that
decide whether money may move are provable in isolation: the RBAC matrix and the dynamic
permission engine with its ceilings, the batch and transaction state machines, the
manifest and challenge hashing, separation of duties and the conflict registry, the risk
engine with every spec §11.1 signal family, the policy engine with the financial
calendar (cut-off times, holiday dates), the audit hash chain, idempotency
fingerprinting, the failure dictionary, the cron engine, and the twelve-family report
catalogue.

### The database is the last line of defence

Application logic can be bypassed. The schema cannot:

- A `SUCCESS` transaction without an M-PESA receipt is refused by CHECK constraint.
- A `FAILED` transaction without a reason is refused by CHECK constraint.
- `UPDATE` and `DELETE` on `audit_events` are refused by trigger, for every role.
- A settled transaction cannot be re-settled; a receipt cannot be overwritten.
- A batch creator cannot be recorded as its own approver or authorizer — unless the
  acting approver/authorizer holds L3 authority (organizational decision; L1 and L2 have
  no exemption).
- Two concurrent authorization ceremonies on one batch are refused by a partial unique index.
- An AI interaction claiming to have changed state is refused by CHECK constraint.
- A job's body cannot change after enqueue; a queue message cannot redirect a payment.
- Instructions freeze once a batch leaves the editable states; financial columns freeze after release.

`scripts/db-test.sh` attacks each of these against a real PostgreSQL instance.

### The console covers the full workflow

Every screen the specification's information architecture calls for: Dashboard (with the
L3-only balance and recent-transactions panels), Payment Batches (create → upload CSV →
validate → submit → review → approve/reject/return/hold → authorize & release, with the
state timeline, risk findings and approval history), the release Ceremony, the
Transactions Explorer (every filter family, retry, status refresh, payment detail with
the immutable activity trail), Recipients with payment history, Analytics
(operational/financial/executive), all twelve Report families, Reconciliation case
resolution, the Security Center (audit viewer with chain verification, security events,
trusted devices, live queue diagnostics), Users, Settings (Daraja, policies, the dynamic
permission engine, templates) and Backups.

---

## Running it

```bash
pnpm install

# PostgreSQL is required for the database assertion suite. The guarantees under test are
# enforced by triggers and constraints, so a mocked database proves nothing.
docker run -d --name solvaren-pg -p 5433:5432 -e POSTGRES_PASSWORD=postgres postgres:16
export DATABASE_URL=postgres://postgres:postgres@localhost:5433/postgres

node scripts/migrate.mjs
pnpm typecheck          # all packages
pnpm test               # 161 tests: kernel, Daraja client, callback parsing
bash scripts/check-invariants.sh   # source-level security properties
bash scripts/db-test.sh localhost 5433 postgres   # schema attacks
```

### Starting the API locally

```bash
export DATABASE_URL=postgres://postgres:postgres@localhost:5433/postgres
export SESSION_SIGNING_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")
export SECRET_ENCRYPTION_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))")
export APP_ORIGIN=http://localhost:5173
export API_BASE_URL=http://localhost:8080
export WEBAUTHN_RP_ID=localhost
export S3_BUCKET=local-dev-bucket   # development uses a file-backed secret store
export S3_ACCESS_KEY_ID=dev
export S3_SECRET_ACCESS_KEY=dev

pnpm --filter @solvaren/api dev
pnpm --filter @solvaren/web dev     # console on :5173, proxying /api to :8080
```

### The first organization and L3 account

```bash
node scripts/create-user.mjs \
  --org "Acme Ltd" --slug acme \
  --email chief@acme.co.ke --name "Jane Chief" \
  --password '<temporary-12+-chars>' --pin 482913
```

The L3 account signs in, enrols a security key (mandatory — L2/L3 cannot sign in without
one), and activates.

---

## Deployment

Railway: `solvaren-web` (public web/API), `solvaren-worker` (private, queue consumers +
scheduler), `solvaren-postgres`, plus offsite backups to any S3-compatible bucket.
Cloudflare may sit in front as the optional edge/WAF layer.

See [`docs/deployment.md`](docs/deployment.md). In short: PostgreSQL → object storage →
secrets as Railway variables → `pnpm verify` → deploy → the first L3 account → Daraja →
a backup **and a restore**.

Runbooks for the situations that actually occur:

- [A payment is stuck in PROCESSING or TIMEOUT](docs/runbooks/payment-stuck.md)
- [Daraja credential rotation and emergency disablement](docs/runbooks/daraja-credential-rotation.md)
- [Backup restoration and disaster-recovery test](docs/runbooks/backup-restore.md)

---

## What this implementation does not do

Stated plainly.

**Not verified against production Daraja.** The integration is built to the documented
contract (verified against the consolidated Daraja knowledge base, 2026-09-13) and
exercised against a scripted provider covering acceptance, rejection, timeout,
duplicate-identifier, callback, duplicate-callback and contradicting-callback paths. It
has not been run against Safaricom's sandbox or production — that needs credentials and
a shortcode. The `SecurityCredential` implementation (RSA PKCS#1 v1.5 per RFC 8017) is
verified by round-trip construction.

**Not run against a live deployment.** The server builds and typechecks clean across all
packages; 161 unit tests pass; the schema assertions attack a real PostgreSQL. What has
*not* happened is a running deployment observed end to end: no payment has been released
against a live database behind a real domain. The deployment checklist exists to close
exactly this gap.

**The edge is optional.** The specification places Cloudflare in front of Railway as an
optional WAF/DDoS layer. Without it, everything at the edge is application-level
(login rate limiting, callback ingress rate limiting, body caps, strict CORS). Put the
edge in front before production exposure; the threat model says so too.

**No load testing.** The architecture is built for volume — bounded queue concurrency,
a token-bucket rate limiter aligned to the Daraja contract, server-side pagination,
indexes matching every sort column — but 10,000 concurrent transactions have not been
run through it.

**Open decisions remain open** (specification §30): PostgreSQL region, the exact S3
provider and its object-lock policy, AI provider and data residency, RPO/RTO targets and
restore-testing cadence. The deployment guide marks which of them block go-live.

---

## Verification summary

| Gate | What runs |
| --- | --- |
| `pnpm typecheck` | Every package, strict mode, noUncheckedIndexedAccess |
| `pnpm test` | 161 tests: kernel (145) + Daraja client and parsing (16) |
| `bash scripts/check-invariants.sh` | Source-level security properties (no-SMS, release gates, AI boundary, secrets hygiene, ceilings) |
| `bash scripts/db-test.sh` | Direct schema attacks against real PostgreSQL |
| CI (`.github/workflows/ci.yml`) | gitleaks → invariants → types → tests + coverage → database assertions → build + bundle budget → container images |

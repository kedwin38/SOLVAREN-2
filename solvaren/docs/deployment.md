# Deployment (Railway)

The order below matters. Each step produces the thing the next step assumes exists.

## Architecture

| Railway service | Role |
| --- | --- |
| `solvaren-web` | Public API + console hosting. `PORT` listener; healthcheck `/health`. Optionally `RUN_WORKERS=false` for a web-only replica. |
| `solvaren-worker` | Private service: `RUN_WORKERS=true`, no public port. The six queue consumers + the scheduler. |
| `solvaren-postgres` | Managed PostgreSQL. **Private networking only** — no public database URL. |

Cloudflare (optional, recommended): DNS + proxy + WAF + rate limiting in front of
`solvaren-web`. The application is correct without it; the edge absorbs volumetric
attacks the application cannot.

## 1. PostgreSQL

Create a PostgreSQL service. Use the **private** URL (`postgres://…@postgres.railway.internal:5432/railway`) for the application. A public proxy URL exists for migrations from your workstation; do not configure the app with it.

## 2. Object storage

Any S3-compatible bucket (AWS S3, Cloudflare R2, MinIO). Create a dedicated bucket and
an access key scoped to it (four operations only: put/get/head/delete/list). This bucket
holds:
- `secrets/…` — AES-GCM envelope-encrypted Daraja/backup credentials
- `solvaren/backups/…` — the logical database snapshots
- `reports/…` — large staged report exports

## 3. Secrets (Railway service variables)

Generate locally; never commit:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

| Variable | Notes |
| --- | --- |
| `DATABASE_URL` | Private Postgres URL (Railway reference variable) |
| `SESSION_SIGNING_KEY` | ≥32 chars high entropy. HMACs session tokens. |
| `SECRET_ENCRYPTION_KEY` | ≥32 chars. Must differ from the session key — boot refuses equality. |
| `APP_ORIGIN` | The console's public https origin (WebAuthn relies on exact match). |
| `API_BASE_URL` | The API's public https origin — **callback URLs are built from this, so it must be the URL Safaricom can reach.** |
| `WEBAUTHN_RP_ID` | The domain the credentials are scoped to (e.g. `payments.acme.co.ke`). |
| `WEBAUTHN_RP_NAME` | Optional; defaults to "SOLVAREN Payment Solutions". |
| `S3_ENDPOINT` | Required for R2/MinIO; omit for AWS. |
| `S3_REGION` / `S3_BUCKET` / `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` | The bucket from step 2. |
| `S3_FORCE_PATH_STYLE` | `true` for R2/MinIO. |
| `ENVIRONMENT` | `production` — boot refuses `localhost` URLs and a `production` Daraja environment under a non-production ENVIRONMENT. |
| `AI_API_KEY` | Optional. Without it the AI layer is simply off and the deterministic risk engine stands alone. |
| `PORT` | Railway injects. |

Production boot checks (see `apps/api/src/config.ts`): required keys present and ≥32
chars; signing ≠ encryption key; https origins; production DATABASE_URL sanity.

## 4. Deploy

1. Connect the repo; create the two services.
2. Pre-deploy command (API): `node scripts/migrate.mjs` — migrations are in the image.
3. Deploy `solvaren-web` (public) and `solvaren-worker` (private, `RUN_WORKERS=true`).
4. Healthchecks: `/health` (liveness) and `/health/ready` (checks the database).

The API refuses to start against a database that is missing tables or the audit
immutability trigger — a process that accepts payment requests before confirming it can
write to the ledger is a process that loses payments.

## 5. First organization and L3 account

From your workstation with `DATABASE_URL` pointed at the database:

```bash
node scripts/create-user.mjs --org "Acme Ltd" --slug acme \
  --email chief@acme.co.ke --name "Jane Chief" \
  --password '<temporary>' --pin 482913
```

The officer signs in, enrols a security key, and the account activates. L3 accounts
cannot act without WebAuthn + the FPAC PIN — this is not configurable.

## 6. Daraja

Settings → Daraja (L3 only). Provide consumer key/secret, shortcode, initiator name,
and either the initiator password **plus the M-PESA public certificate** or a
pre-computed SecurityCredential from the portal. Configure **requires** fresh
authentication, WebAuthn and your FPAC PIN.

The response shows the **callback URLs (with embedded secret) exactly once** — register
them on the Daraja portal immediately. They are also stored in the configuration for
reference. Then: **Test connection** → **Enable**. An untested integration cannot be
enabled — the database refuses it.

## 7. Backup, and then a restore

Settings → Backups: configure the bucket, **Test connection**, enable the schedule,
**Run backup now**. Then perform one restore drill (see the runbook) and record the
measured RTO. A backup that has never been restore-validated is not disaster-recovery
proven.

## Go-live checklist

- [ ] All CI gates green on the release commit
- [ ] `ENVIRONMENT=production`; origins are https and exact
- [ ] Session and encryption keys differ, are ≥32 chars, and exist only as Railway variables
- [ ] Database reachable only via private networking
- [ ] Edge (Cloudflare or equivalent) in front of the public service — WAF + rate limiting on `/api/auth/*`, `/api/daraja/*`, `/api/exports/*`
- [ ] First L3 account enrolled (security key + PIN)
- [ ] Daraja: connection test passed; integration enabled; callback URLs registered on the portal
- [ ] One successful sandbox payment, one rejected, one timed-out (reconciliation case opened and resolved)
- [ ] Backup configured, tested, run — and restore-validated once
- [ ] Organization policies reviewed (limits, cooling-off, cut-off time, holidays)
- [ ] Operators briefed on the runbooks

## Rollback

Railway retains previous deployments; redeploy the prior build. Migrations are
append-only by policy — a rollback of the application never requires a rollback of the
schema. If a migration itself must be reverted, write a new forward migration; the
runner refuses modified, already-applied files.

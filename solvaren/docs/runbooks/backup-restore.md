# Runbook: Backup restoration and disaster-recovery test

A backup that has never been restore-validated is not disaster-recovery proven. Run this
drill once before go-live and at your organisation's chosen cadence thereafter, and
record the measured timings.

## What a backup contains

A point-in-time logical snapshot (`logical-json-v1`) of one organisation's rows, taken
under `REPEATABLE READ` — every table from the same database instant. Deliberately
excluded: session tokens (a restore must not resurrect live sessions) and credential
hashes (passwords, FPAC PINs, recovery-code hashes — they must be re-established, not
restored). Secret envelopes live in the `secrets/` prefix of the same bucket, encrypted
under `SECRET_ENCRYPTION_KEY`, which is a Railway variable and is never in the bucket.

## The drill

1. **Take a fresh backup** (Settings → Backups → Run backup now) and note its attempt
   reference and checksum.
2. **Create a scratch PostgreSQL** (local Docker or a staging database — never
   production). Apply migrations: `DATABASE_URL=<scratch> node scripts/migrate.mjs`.
3. **Restore** the snapshot:
   ```bash
   DATABASE_URL=<scratch> S3_*=<same bucket> SECRET_ENCRYPTION_KEY=<prod key> \
     node scripts/restore-snapshot.mjs --attempt-reference <BAK-…>
   ```
4. **Verify** (the restore script performs these checks and reports each):
   - Row counts per table match the snapshot metadata.
   - The audit chain verifies from genesis (`verifyChainAsync` over the restored events).
   - Batch totals reconcile against their instructions.
   - Settled transactions retain receipts and failure reasons.
   - The restored policy matches the recorded digest.
5. **Record the measurements**: time to provision the database, time to restore, total
   RTO; backup age at restore = RPO. Keep these with the incident procedures.

## What the drill proves — and what it does not

Proves: the object is retrievable, internally consistent, and becomes a working
database whose immutability guarantees re-arm (the restore path re-applies the
triggers by running migrations first).

Does not prove: the organisation's people can execute it at 03:00. That is why the
timings are recorded, and why the drill is repeated.

## Retention note

Retention deletes only after a **new successful** backup commits; a failed backup never
advances retention (schema-enforced). Deleted objects keep their attempt rows as
evidence, marked retired.

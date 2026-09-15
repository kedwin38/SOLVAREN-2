-- 0009: UUID id defaults for all entity tables.
--
-- The application's insert paths for sessions, security events, audit events,
-- notifications and queue rows rely on a database-side default for the primary
-- key (they supply explicit ids only for some entities). The original
-- foundation migration omitted DEFAULT gen_random_uuid(), which made every
-- such insert fail with a not-null violation. Adding the default is backwards
-- compatible: inserts that already supply an id are unaffected.

ALTER TABLE organizations            ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE users                    ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE webauthn_credentials     ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE trusted_devices          ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE sessions                 ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE recovery_codes           ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE conflict_registrations   ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE permission_overrides     ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE departments              ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE recipients               ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE payment_batches          ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE payment_instructions     ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE approvals                ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE authorization_challenges ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE provider_callbacks       ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE reconciliation_cases     ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE risk_findings            ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE account_balance_snapshots ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE payment_calendar         ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE audit_events             ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE daraja_configurations    ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE backup_configurations    ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE export_records           ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE report_jobs              ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE security_events          ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE notification_channels    ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE notifications            ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE notification_deliveries  ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE job_queue                ALTER COLUMN id SET DEFAULT gen_random_uuid();

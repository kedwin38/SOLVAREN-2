-- 0012: UUID id defaults for the last two tables missing them.
--
-- 0009 added gen_random_uuid() defaults to the entity tables but omitted two created
-- in 0004: ai_interactions and backup_attempts. Both are inserted into without an
-- explicit id, so the insert fails with a not-null violation — observed in production
-- as a 500 on every AI feature ("null value in column "id" of relation
-- "ai_interactions" violates not-null constraint"). The rate-limit and scheduler
-- marker tables were audited too: they have natural primary keys and no id column,
-- so they need nothing here.

ALTER TABLE ai_interactions ALTER COLUMN id SET DEFAULT gen_random_uuid();
ALTER TABLE backup_attempts ALTER COLUMN id SET DEFAULT gen_random_uuid();

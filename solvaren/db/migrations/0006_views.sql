-- SOLVAREN migration 0006 — Reporting views.
--
-- The views are the reporting layer's single source of truth: the explorer, roll-ups,
-- recipient history and department baselines used by dashboards, exports and the risk
-- engine all read from here, so every surface shows identical numbers.

CREATE OR REPLACE VIEW transaction_explorer AS
SELECT t.id AS transaction_id,
       pi.id AS instruction_id,
       b.id AS batch_id,
       b.batch_reference,
       r.id AS recipient_id,
       pi.recipient_name_snapshot AS recipient_name,
       pi.msisdn_snapshot AS msisdn,
       d.id AS department_id,
       d.name AS department_name,
       pi.amount_cents,
       t.status,
       t.failure_code,
       t.failure_reason,
       t.failure_class,
       t.provider_result_description,
       t.mpesa_receipt_number,
       t.conversation_id,
       t.originator_conversation_id,
       t.status_source,
       t.last_status_check_at,
       t.created_at,
       t.submitted_at,
       t.completed_at,
       t.updated_at
  FROM transactions t
  JOIN payment_instructions pi ON pi.id = t.instruction_id
  JOIN payment_batches b       ON b.id = t.batch_id
  JOIN recipients r            ON r.id = pi.recipient_id
  LEFT JOIN departments d      ON d.id = pi.department_id;

CREATE OR REPLACE VIEW batch_outcome_rollup AS
SELECT b.id AS batch_id,
       b.organization_id,
       b.batch_reference,
       b.state,
       b.instruction_count,
       b.total_amount_cents,
       COUNT(t.id) AS transaction_count,
       COUNT(t.id) FILTER (WHERE t.status = 'SUCCESS')  AS success_count,
       COUNT(t.id) FILTER (WHERE t.status = 'FAILED')   AS failed_count,
       COUNT(t.id) FILTER (WHERE t.status = 'TIMEOUT')  AS timeout_count,
       COUNT(t.id) FILTER (WHERE t.status IN
         ('PENDING', 'SUBMITTED', 'AWAITING_CALLBACK', 'PROCESSING', 'RECONCILING')) AS in_flight_count,
       COALESCE(SUM(pi.amount_cents) FILTER (WHERE t.status = 'SUCCESS'), 0) AS disbursed_cents,
       COALESCE(SUM(pi.amount_cents) FILTER (WHERE t.status IN ('FAILED', 'TIMEOUT')), 0) AS failed_cents
  FROM payment_batches b
  LEFT JOIN transactions t ON t.batch_id = b.id
  LEFT JOIN payment_instructions pi ON pi.id = t.instruction_id
 GROUP BY b.id;

CREATE OR REPLACE VIEW recipient_payment_history AS
WITH paid_sequence AS (
  SELECT pi.organization_id,
         pi.recipient_id,
         pi.amount_cents,
         t.completed_at,
         LAG(t.completed_at) OVER (
           PARTITION BY pi.organization_id, pi.recipient_id
           ORDER BY t.completed_at
         ) AS previous_paid_at
    FROM transactions t
    JOIN payment_instructions pi ON pi.id = t.instruction_id
   WHERE t.status = 'SUCCESS'
),
intervals AS (
  SELECT organization_id,
         recipient_id,
         amount_cents,
         completed_at,
         CASE WHEN previous_paid_at IS NULL THEN NULL
              ELSE EXTRACT(EPOCH FROM (completed_at - previous_paid_at)) / 3600.0
         END AS interval_hours
    FROM paid_sequence
)
SELECT i.organization_id,
       i.recipient_id,
       ROUND(AVG(i.amount_cents)) AS mean_amount_cents,
       COUNT(*) AS successful_payment_count,
       percentile_cont(0.5) WITHIN GROUP (ORDER BY interval_hours) AS median_interval_hours,
       MIN(i.completed_at) AS first_paid_at,
       MAX(i.completed_at) AS last_paid_at,
       MIN(r.created_at) AS recipient_created_at,
       MAX(r.updated_at) AS payment_details_modified_at
  FROM intervals i
  JOIN recipients r ON r.id = i.recipient_id
 GROUP BY i.organization_id, i.recipient_id;

CREATE OR REPLACE VIEW daily_disbursement_totals AS
SELECT b.organization_id,
       (t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE AS disbursement_date,
       SUM(t.amount_cents) AS total_cents
  FROM transactions t
  JOIN payment_batches b ON b.id = t.batch_id
 WHERE t.status = 'SUCCESS' AND t.completed_at IS NOT NULL
 GROUP BY b.organization_id, (t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE;

CREATE OR REPLACE VIEW department_expenditure AS
SELECT pi.organization_id,
       COALESCE(d.name, 'Unassigned') AS department_name,
       date_trunc('month', t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE AS period_month,
       SUM(pi.amount_cents) AS paid_cents,
       COUNT(*) FILTER (WHERE t.status = 'SUCCESS') AS paid_count,
       COUNT(*) FILTER (WHERE t.status IN ('FAILED', 'TIMEOUT')) AS failed_count
  FROM transactions t
  JOIN payment_instructions pi ON pi.id = t.instruction_id
  LEFT JOIN departments d ON d.id = pi.department_id
 WHERE t.completed_at IS NOT NULL
 GROUP BY pi.organization_id, COALESCE(d.name, 'Unassigned'),
          date_trunc('month', t.completed_at AT TIME ZONE 'Africa/Nairobi')::DATE;

-- Trailing per-department baseline consumed by the risk engine's DEPARTMENT_VARIANCE
-- signal: mean total disbursed to the department per settled batch over the last 6.
CREATE OR REPLACE VIEW department_batch_baseline AS
WITH dept_batch_totals AS (
  SELECT pi.organization_id,
         pi.department_id,
         b.id AS batch_id,
         b.settled_at,
         SUM(pi.amount_cents) AS batch_total_cents
    FROM payment_instructions pi
    JOIN payment_batches b ON b.id = pi.batch_id
   WHERE pi.department_id IS NOT NULL AND b.settled_at IS NOT NULL
   GROUP BY pi.organization_id, pi.department_id, b.id, b.settled_at
),
ranked AS (
  SELECT *,
         ROW_NUMBER() OVER (PARTITION BY organization_id, department_id ORDER BY settled_at DESC) AS rn
    FROM dept_batch_totals
)
SELECT organization_id,
       department_id,
       ROUND(AVG(batch_total_cents)) AS mean_batch_total_cents,
       COUNT(*) AS settled_batch_count
  FROM ranked
 WHERE rn <= 6
 GROUP BY organization_id, department_id;

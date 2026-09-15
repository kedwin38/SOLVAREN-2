# Runbook: A payment is stuck in PROCESSING or TIMEOUT

The design premise: an unknown outcome is never resolved by guessing. This runbook
exists for the case where the automatic machinery needs a human decision.

## Symptoms

- A batch sits in `PROCESSING` or `TIMEOUT` with transactions in
  `AWAITING_CALLBACK` / `TIMEOUT` / `RECONCILING`.
- A reconciliation case is `ESCALATED` (the automatic status queries were exhausted —
  8 attempts — without a definitive provider answer).

## Automatic behaviour (verify it is working before intervening)

1. The scheduler sweeps every 5 minutes per organisation: anything in flight older than
   10 minutes gets a reconciliation case and a Transaction Status query.
2. The provider's answer arrives on the status callback and is applied through the same
   validated state machine as an ordinary result.
3. After 8 unanswered queries the case escalates: a CRITICAL security event, an operator
   notification, and the transaction stays visible as unresolved.

Diagnostics: **Security Center → Queue diagnostics** shows the `reconciliation` queue;
**Reconciliation** shows the cases with their attempt counts and evidence.

## Manual resolution (L2/L3, spec §23)

1. Open **Reconciliation** → the escalated case.
2. Check the M-PESA organisation portal (org.ke.m-pesa.com) for the
   `OriginatorConversationID` (shown on the payment detail page).
3. Record the outcome:
   - **Confirmed paid** → resolve as `RESOLVED_SUCCESS` with the portal receipt number.
   - **Confirmed not paid** → resolve as `RESOLVED_FAILED`.
   - **Established manually, no provider confirmation** → `RESOLVED_MANUAL` with evidence.
4. The ledger is never rewritten by a manual resolution. If the provider's own status
   query later disagrees, a discrepancy case opens automatically.

## If payment needs to be re-issued

Only for a transaction resolved as **not paid**. Use **Retry** on the transaction (L2/L3
or policy-enabled L1): it creates a **new instruction in a correction batch** that must
travel the full approval chain again. Never resubmit an ambiguous outcome — that is the
double-payment scenario the whole architecture exists to prevent.

## The system will never do (by design)

- Resend a payment whose outcome is unknown.
- Mark a transaction SUCCESS without a provider receipt.
- Rewrite a settled transaction because a later message disagrees.

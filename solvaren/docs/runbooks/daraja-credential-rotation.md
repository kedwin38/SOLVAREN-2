# Runbook: Daraja credential rotation and emergency disablement

## Rotation (planned)

Level 3 only. Requires fresh authentication, WebAuthn and the FPAC PIN.

1. Obtain the new credentials from the Daraja portal (My Apps). Note the M-PESA public
   certificate if you will supply the initiator password rather than a pre-computed
   SecurityCredential.
2. **Settings → Daraja → Rotate credentials.** Fill the form; confirm with password,
   security key and PIN.
3. The integration resets to `TESTING` — it cannot keep processing payments on
   credentials that have not been proven to work (schema-enforced).
4. The callback URLs (with the embedded secret) are displayed **exactly once**. If the
   callback secret changed (first configuration; it is preserved on rotation), register
   the new URLs on the Daraja portal.
5. **Test connection** → must pass → **Enable**.

Effects (all audited):
- `credential_version` increments; the client cache is invalidated immediately.
- Payments in flight continue to report their outcomes; no new payments are submitted
  while the integration is TESTING/DISABLED.

## Emergency disablement

**Settings → Daraja → Disable** (reason required, audited). Immediate effects:

- The payment executor marks queued-but-unsubmitted instructions
  `SLV_INTEGRATION_DISABLED` (no money moved — they can be re-issued after re-enabling).
- In-flight payments still report their outcomes via callbacks.
- Reconciliation status queries stop until re-enable (the runbook for stuck payments
  covers portal verification in the interim).

## Post-rotation verification

- [ ] Connection test passed
- [ ] One sandbox payment accepted (if in sandbox)
- [ ] A callback was received and applied (Transactions shows a receipt)
- [ ] Old credentials confirmed dead on the portal (Safaricom password expiry is 90 days)

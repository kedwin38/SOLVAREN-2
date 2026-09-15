# Threat model

Organised by what an attacker is trying to achieve, not by OWASP category, because the
question that matters for a disbursement platform is "can they move money, and would we
know". Each control says where it lives. Controls that exist only in application code
are marked as such — they are the ones a bug can bypass, which is why the most important
ones are duplicated in the schema.

---

## 1. Move money to an account the attacker controls

### 1.1 Compromise a Level 3 account

**Attack.** Phish or steal an L3 officer's password and release a batch.

**Why it fails.** A password alone cannot produce a session: WebAuthn is mandatory for
L2 and L3, and `issueSession` refuses to issue a usable session without it. Even with a
live session, release additionally requires fresh authentication (five minutes,
satisfiable only through `/api/auth/step-up`, which itself requires the password and a
WebAuthn assertion), a WebAuthn signature over the manifest digest, and the FPAC PIN —
a separate credential, Argon2id-hashed and bound to the user id, never transmitted or
stored reversibly.

**Residual risk.** An attacker with the officer's security key *and* their PIN *and*
physical presence during an authenticated session can release. That is the intended
floor: the design makes remote compromise insufficient, not physical coercion.

### 1.2 Alter a batch after it has been approved

**Attack.** Get a clean batch approved, then change an amount or add a recipient before
release.

**Why it fails.** Four independent layers:
1. The approval is bound to a batch *version*; any material edit increments it and
   `loadCurrentApproval` refuses a stale version.
2. The manifest is rebuilt from live rows at release and must hash identically to the
   one the ceremony opened against — amount, MSISDN, recipient set, approval id, batch
   version **and the policy digest** are all in the digest.
3. The database refuses the edit outright once the batch leaves the editable states
   (`instructions_guard_update`).
4. A settled batch's financial columns are frozen by trigger.

### 1.3 Alter a payment message in the queue

**Attack.** Modify an `EXECUTE_INSTRUCTION` message to redirect a payment.

**Why it fails.** The message carries an idempotency fingerprint derived from the
organisation, batch, instruction, batch version, MSISDN, amount and manifest hash. The
executor re-derives it from live rows and refuses any mismatch, writing a
`payment.execution.fingerprint_mismatch` denial to the audit log. The job body itself is
immutable after enqueue (schema-enforced).

**Residual risk.** An attacker who can write to the queue *and* the database can make
both agree — at which point they own the database, and the audit chain is the remaining
control.

### 1.4 Self-approval or collusion

**Attack.** Create a batch and approve or authorize it yourself, or two officers
quietly running everything.

**Why it fails.** Creator ≠ approver, modifier ≠ approver, submitter ≠ approver,
approver ≠ authorizer, creator/editor ≠ authorizer — enforced in `sod.ts` at every
workflow boundary **and** as CHECK constraints on `payment_batches`. A cooling-off window
blocks an edit immediately before submission. A conflict-of-interest registry blocks a
named officer for a recipient, department or the organisation. Repeated approval by one
pair surfaces as a risk finding (deliberately a signal, not a block: the legitimate and
illegitimate versions are indistinguishable from inside the data).

### 1.5 Dynamic-permission escalation (AC-17)

**Attack.** A compromised L3 grants `payment:release` to L1 and releases through the L1
account.

**Why it fails.** The engine applies **immutable ceilings after every override**:
`effectivePermissions` computes `(baseline ∪ grants) − revokes − ceilings − forbidden`.
No row in `permission_overrides` — and no future code that forgets the rule — can
produce a ceiling-protected permission for L1 or L2, because the subtraction is
unconditional. `validateOverride` additionally refuses to *store* a ceiling-piercing
override, and L3 is not overridable at all. Every override is versioned and audited as
a high-severity AUTHORITY event with the full effective-matrix diff.

---

## 2. Get paid twice

Not an external attack so much as a systems failure, and the more likely of the two.

**The scenario.** A payment is submitted to M-PESA, the worker dies before recording the
response, and the queue redelivers the message.

**Why it fails.** The idempotency claim transitions to SUBMITTED and **commits before**
the provider call. A redelivered message finds that claim and takes the
RECONCILE_FIRST branch — it queries the Transaction Status API rather than resubmitting.
Daraja's duplicate-`OriginatorConversationID` rejection is the backstop, not the
control. The Daraja client additionally never retries a B2C submission, at any level,
for any reason — including token errors. The queue's `one_live_payment_per_instruction`
unique index prevents a duplicate live job from even existing.

**Verified by.** The `RECONCILE_FIRST` decision table (`idempotency.ts`), the duplicate
B2C code path (`500.002.1001` classified AMBIGUOUS — "do not resend"), and the
no-retry client tests.

---

## 3. Forge an outcome

**Attack.** Make a payment that failed appear successful, or vice versa.

**Why it fails.** SUCCESS requires a provider receipt — as a state-machine precondition,
a CHECK constraint, and a refusal of SYSTEM-sourced SUCCESS transitions outright.
FAILED requires a failure code, likewise. A settled transaction cannot be re-settled; a
receipt cannot be overwritten; the amount is frozen. A later callback or status query
that contradicts a settled outcome opens a discrepancy case for a human and leaves the
ledger untouched.

---

## 4. Forge or replay a provider callback

**Attack.** POST a success callback for a payment that did not happen.

**Why it fails, in layers:**
1. **The secret is in the URL.** Safaricom POSTs to the ResultURL exactly as configured
   and sends no custom headers, so the callback URLs carry a per-organisation,
   per-credential-version secret path segment. (This was the fatal defect of the
   predecessor system — its stored URLs lacked the segment, so every production
   callback would have failed authentication. Fixed structurally here, and asserted by
   the invariant checker.)
2. **Constant-time comparison.** A wrong secret returns 200 — indistinguishable from
   success, so probing learns nothing — and writes a CRITICAL security event.
3. **Replay protection by content digest.** Identical bodies (canonicalised, so
   whitespace differences still match) are recorded as duplicates, never reprocessed.
4. **An unmatched callback invents nothing.** It is retained as evidence and marked
   UNMATCHED; the endpoint cannot create a transaction.
5. **Rate-limited by source IP**; body-size capped before parsing; always 200 (Daraja
   does not retry, so a non-200 loses the result permanently).

**Residual risk.** An attacker with the shared secret *and* a valid in-flight
`OriginatorConversationID` could settle it early with a forged receipt. Mitigated by the
reconciliation sweep, which independently queries the Transaction Status API and raises
a discrepancy when the provider disagrees.

---

## 5. Steal the Daraja credentials

**Attack.** Read the consumer secret or SecurityCredential and pay directly from the
shortcode, bypassing SOLVAREN entirely.

**Why it fails.** No code path returns a plaintext Daraja secret to any caller at any
authority level — the configuration API deals exclusively in masked views, and viewing
plaintext is forbidden even to L3 by the specification. Secrets are AES-GCM
envelope-encrypted (purpose-separated key derivation, versioned envelopes) before they
leave the process, stored in the bucket's `secrets/` prefix; the database holds only
reference names. The initiator password is never persisted — it exists long enough to
produce the SecurityCredential against the M-PESA certificate, or an operator supplies a
pre-computed credential so SOLVAREN never sees the password at all.

Compromising the bucket alone yields nothing usable: `SECRET_ENCRYPTION_KEY` is a
Railway variable, never in the bucket it protects. Rotating credentials requires fresh
auth + WebAuthn + the FPAC PIN, resets the integration to TESTING, and invalidates the
client cache.

---

## 6. Erase the evidence

**Attack.** Move money, then delete or alter the audit trail.

**Why it fails.** UPDATE and DELETE on `audit_events` are refused by trigger for every
role. Each event commits to its predecessor with SHA-256 (the digest is computed by the
application over deterministic key-sorted JSON; the database assigns the sequence and
chain link). Removal, reordering and alteration each break verification at a known
index — `verifyChainAsync` names the exact event. The audit write happens inside the
same transaction as the state change it records, so there is no window in which money
moved without a record.

**Residual risk.** A database superuser can disable the triggers. The chain makes the
resulting gap *detectable*, which is the property an auditor needs; the deployment
guide requires the application role not to own the tables.

---

## 7. Exfiltrate payroll data

**Attack.** Use a compromised session to enumerate the ledger.

**Why it fails, partially.** Every export is role-scoped and audited with actor, filter
and row count (L1 export access is organisation-configurable). Exports and the explorer
are rate-limited; the explorer caps at 200 rows/page and exports at the organisation's
limit. The failed-transaction export's status filter is fixed server-side, so it can
never be repurposed to export everything.

**Residual risk.** A legitimate L2/L3 session can export the failed set — that is the
point. The control is detective: every export leaves an audit record naming who took
what.

---

## 8. Denial of service

| Vector | Control |
| --- | --- |
| Volumetric | **Edge-dependent.** Put Cloudflare (or any WAF/proxy) in front of Railway; without it, the application absorbs the flood. |
| Credential stuffing | 10 sign-ins/minute/IP (token bucket in PostgreSQL, correct across replicas); 5 failures lock the account 15 minutes |
| Callback flooding | 20 requests/minute/IP; 64 KB body cap before parsing; constant cost per request |
| Export flooding | 5/5min per actor; row caps |
| Expensive queries | Server-side pagination; an index per sort column; statement timeouts |
| Oversized bodies | Checked before parsing: 8 MB CSV, 64 KB callbacks, 16 KB auth |
| Memory-hard hashing abuse | Password length bounded before Argon2 is invoked |
| Provider rate limits | PostgreSQL token bucket per organisation, aligned to the Daraja contract |
| Queue starvation | One live payment job per instruction (unique partial index); bounded concurrency; expired-lease recovery |

---

## What is not defended against

Stated rather than implied.

**A compromised Railway account.** Whoever controls the project controls the
application and its variables — every secret. Mitigations are organisational: hardware
MFA on the account, scoped deploy tokens, the audit chain as the detective control.

**Volumetric denial of service without an edge.** Every control in the table above is
application-level; an attacker can exhaust the service before any of it applies. Put
the proxy in front; until then this is an accepted gap.

**A malicious database superuser.** They can disable the immutability triggers. The
chain makes it detectable; nothing in software makes it impossible.

**A coerced Level 3 officer.** Two-person control makes a single compromised officer
insufficient for approval *and* authorization, but a genuinely coerced officer with
their key and PIN can release a payment. The controls are detective: the audit record,
the risk findings, the executive dashboard.

**Supply chain.** Dependencies are pinned and the lockfile committed; CI runs gitleaks.
There is no reproducible-build guarantee and no vendored dependency tree.

**Safaricom-side compromise.** SOLVAREN trusts M-PESA's word on whether a payment
succeeded; there is no independent settlement source, and the specification does not
contemplate one.


CARACAL
PAYMENTS
Control every payout. Prove every release.
PRODUCT POSITIONING
Caracal is a commercial, security-first intelligent payment management platform for organizations that need controlled business disbursements, precise records, financial intelligence, fraud/risk controls, and auditable payment release.

Document type: Software Requirements & Technical Specification
Status: Implementation baseline / Draft v1.0
Date: 13 September 2026
Primary payment rail: Safaricom M-PESA Daraja B2C
Deployment direction: Cloudflare-first production architecture
Security posture: No SMS authentication or payment authorization
Brand rationale: “Caracal” is drawn from a real-world animal known for alertness, precision and fast, controlled movement. The brand is intentionally not built around generic technology naming conventions.

Document Control
Field
Value
Product
CARACAL Payments
Version
1.0 baseline
Audience
Product owner, software engineers, security engineers, DevOps, QA, finance stakeholders
Source basis
User-provided PAYMENT SYSTEM concept document, including command hierarchy, security model, and payment-processing extras
Added requirements in this specification
Cloudflare deployment architecture and administrator-configurable backup system
Requirement notation
FR = functional; SEC = security; NFR = non-functional; DAT = data; INT = integration; OPS = operations; AI = intelligence; BAK = backup
Priority
P0 critical, P1 high, P2 secondary

SOURCE DISCIPLINE
The uploaded concept document is the authoritative source for the product intent, 3-level permissions, no-SMS security model, cryptographic payment authorization, idempotency/reconciliation requirements, separation of duties, and batch orchestration. Cloudflare architecture details in this specification are implementation requirements added to satisfy the stated deployment direction.

1. Executive Summary
CARACAL Payments is a business disbursement control plane for payroll, suppliers and contractors. It is not a simple “send money” application. Its primary design objective is controlled financial execution: the platform prepares payment instructions, subjects them to layered validation and financial review, requires final authorization at the highest authority level, executes approved payments through Safaricom Daraja B2C, reconciles ambiguous outcomes, and preserves an auditable record of what happened.
The platform combines payment operations, finance control, fraud and anomaly detection, financial analytics, reporting, batch scheduling, cryptographic authorization, device trust, immutable audit history, and administrator-managed backups in one governed system.
The security model is deliberately stronger than ordinary 2FA. Login authentication establishes identity; financial authorization is a separate security boundary. Payment release requires the correct authority level, an intact approval chain, a transaction manifest bound to the exact batch, fresh authentication, cryptographic authorization, risk-policy approval and a valid payment state.
2. Product Goals and Success Criteria
Enable large organizations to prepare and execute recurring and ad-hoc business payouts without losing financial control.
Make every payment traceable to a recipient, batch, instruction, approval chain, transaction/reference identifiers, outcome and audit history.
Prevent unauthorized payment release, silent payment modification, self-approval and privilege escalation.
Reduce operational error through CSV validation, duplicate detection, historical comparison and risk signals.
Provide precise operational, financial, payroll, departmental, audit, reconciliation and executive reporting.
Support asynchronous, resilient payment processing with callbacks, reconciliation and dead-letter handling.
Deploy the platform behind Cloudflare controls with secrets protected outside ordinary application records.
Provide administrator-configurable full-database backups using any S3-compatible object storage, with schedules, retention and attempt logging.
3. Scope
3.1 In Scope
Organization and user administration
Three-level payment command hierarchy
Employee/recipient master data
CSV ingestion and batch creation
Batch validation, correction and submission
Finance review, approval, rejection and hold
Level 3 final payment authorization
Daraja B2C credential management
Payment execution and callback processing
Reconciliation and ambiguous-state handling
Fraud/anomaly detection and risk scoring
Operational, financial and executive analytics
AI-assisted analysis and reporting
Audit and security event logging
Batch scheduling and recurring templates
Cloudflare production deployment architecture
Administrator-configurable S3-compatible database backups
3.2 Explicitly Out of Scope for Baseline
SMS-based authentication, OTP, MFA or recovery
Direct alteration of historical payment results by any role
Plaintext exposure of stored Daraja secrets
Uncontrolled direct database manipulation to force payment states
Replacing Daraja with another payment rail in the baseline release
Consumer checkout or marketplace functionality
4. User Roles and Command Hierarchy
The platform uses three operational authority levels. Permissions are enforced server-side and are not merely a user-interface convention.
Level
Name
Primary mandate
Key powers
Key prohibitions
L1
Payment Operations
Prepare, validate, submit and monitor
CSV upload; draft batches; validation; recipients; operational analytics; permitted retries; operational reports; AI batch analysis
No payment release; no approval; no Daraja credentials; no policy changes; no audit deletion; no override of L2/L3 decisions
L2
Finance Control & Review
Verify financial accuracy, risk, reconciliation and readiness
Review; approve for L3; reject; hold; reconcile; advanced analytics; financial reports; AI financial analysis
No final release; no Daraja credential management; no policy bypass; no audit deletion
L3
Chief / Executive Payment Authority
Final payment authority and critical administration
Final release; high-value authorization; Daraja config; organization/security policy; user admin; executive intelligence; complete reporting
Cannot modify immutable audit history, alter historical transactions, fabricate transaction codes, force success, bypass ledger or bypass required authorization

HARD CONTROL
The backend must independently enforce authorization. A hidden button or disabled menu item is not an access control. Every privileged API operation must verify organization, user, role, authority level, object state and command-specific policy before executing.

4.1 Permission Matrix
Capability
L1
L2
L3
Upload CSV
Yes
Yes
Yes
Create/edit draft batch
Yes
Yes
Yes
Submit batch to next level
Yes
No
No
Review batch
Limited
Yes
Yes
Reject batch
No
Yes
Yes
Approve for next level
No
Yes
No
Final payment authorization
No
No
Yes
Release payments
No
No
Yes
View transaction history/codes
Yes
Yes
Yes
Eligible retry
Limited
Yes
Yes
Reconciliation
Limited
Yes
Yes
Basic analytics
Yes
Yes
Yes
Advanced analytics
No
Yes
Yes
AI batch analysis
Yes
Yes
Yes
AI financial analysis
No
Yes
Yes
AI executive intelligence
No
Limited
Yes
User management
No
Limited
Yes
Payment/approval/security policy
No
No
Yes
MFA/security administration
No
No
Yes
Daraja configuration/rotation
No
No
Yes
Audit-log access
Limited
Yes
Full
Delete audit logs
No
No
No
Alter transaction history
No
No
No
View plaintext Daraja secrets
No
No
No

5. Core Business Workflows
5.1 Payment Batch Lifecycle
DRAFT → VALIDATED → SUBMITTED_TO_L2 → L2_REVIEW → L3_READY → AUTHORIZATION_PENDING → AUTHORIZED → QUEUED → SUBMITTED → PROCESSING → SUCCESS / FAILED / TIMEOUT / HELD / CANCELLED
A batch cannot move backward by direct mutation. State transitions occur only through defined commands, with the current state, previous state, actor, timestamp, reason and correlation identifiers recorded.
5.2 Level 1 Preparation
• Upload a CSV using the approved schema.
• Create a draft batch and assign a business purpose, department/category and payment period.
• Validate mandatory fields, phone-number format, amount rules, duplicates, inactive recipients and organizational policy limits.
• Correct invalid records or remove/add recipients while the batch remains editable.
• Run AI-assisted duplicate and anomaly screening.
• Submit the batch to Level 2; submission freezes the relevant approval version.
5.3 Level 2 Financial Review
• Inspect the batch and individual payment instructions.
• Verify recipient identity and payment amount.
• Compare current instructions to historical payments and expected payroll patterns.
• Review AI risk findings and anomalies.
• Approve to Level 3, reject, return for correction, or place on hold.
• Initiate reconciliation for failed, pending or ambiguous transactions.
5.4 Level 3 Final Authorization
• Open the exact approval version and payment manifest.
• Review Level 2 decision, risk assessment and key anomalies.
• Complete fresh step-up authentication.
• Complete WebAuthn cryptographic challenge signing and Frontier authorization PIN verification.
• Revalidate the transaction manifest and applicable limits/policies.
• Allow release only when all security, risk and state conditions pass.
6. Authentication and Payment Authorization
CARACAL separates identity authentication from financial authorization. Being logged in is never treated as sufficient authority to release money.
6.1 No-SMS Rule
No SMS OTP.
No SMS password reset.
No SMS payment approval.
No SMS MFA.
No SMS credential recovery.
6.2 Frontier Identity
Frontier Identity├── User ID├── Organization ID├── Role / Authority Level├── Password credential (Argon2id)├── WebAuthn credential(s)├── Authorization PIN├── Trusted device bindings├── Recovery credentials└── Security state
Sensitive credential material must not be stored in plaintext. Passwords use a modern password hashing design such as Argon2id with production-appropriate parameters.
6.3 Level 3 Login
Username / Email + Frontier Password + WebAuthn → Authenticated Session
WebAuthn/FIDO2 is mandatory for Level 2 and Level 3 accounts in the baseline security profile.
6.4 Payment Authorization Credential (FPAC)
The platform shall maintain a dedicated Frontier Payment Authorization Credential concept, separate from the ordinary login credential. Implementation should use a device-backed or hardened cryptographic key derivation design; the credential itself must never be transmitted or stored as plaintext.
6.5 Transaction Manifest and Signature
Challenge = HASH(organization + batch + amount + recipients + approval + manifest + nonce + expiry)
The manifest is a deterministic representation of the exact payment authorization payload. A change to amount, recipient set, approval chain or other signed material produces a different digest and therefore invalidates the prior authorization. The platform must require a new approval path and new authorization for materially changed batches.
PAYMENT RELEASE RULE
No single password, session, API request, database record or user-interface action is sufficient to release money. Payment release requires valid identity, correct authority, valid approval chain, intact manifest, fresh authentication, cryptographic authorization, risk-policy pass and valid payment state.

7. Device Trust, Sessions and Recovery
7.1 Trusted Device
Attribute
Requirement
Device ID
Unique platform identifier
User binding
Associated with one Frontier Identity
WebAuthn binding
Credential ID recorded
Trust status
TRUSTED / REVIEW / BLOCKED / REVOKED
Registration/last activity
Timestamped
Revocation
Immediate invalidation for future privileged use
Security events
Registration, verification failure, suspicious change and revocation logged

7.2 Session Security
Short-lived access credentials and renewable sessions with rotation controls.
Server-side session invalidation for logout, device revocation and security events.
Privileged actions require recent authentication context.
Risk-based session restrictions for suspicious device, IP, geography or behavior changes.
No authorization decision may depend solely on a client-provided role value.
7.3 Recovery
Recovery → strong identity verification → existing recovery credential OR controlled admin recovery → security hold / elevated review → authenticator re-enrollment
Level 3 recovery is especially restrictive, fully audited and must not disable the financial authorization boundary without completing the defined recovery policy.
7.4 Secrets
Daraja secrets, encryption keys and system service secrets are handled through a secrets-management mechanism. Application tables store metadata and references, not plaintext credentials.
8. Safaricom Daraja B2C Integration
Daraja is the baseline payment execution rail. Safaricom currently describes Daraja 3.0 as the platform providing access to Safaricom/M-PESA APIs, including Transaction Status functionality. The final integration must follow the current production contract and approved credentials rather than hard-coding assumptions from a historical sample implementation.
8.1 Level 3 Daraja Configuration
• Add/configure production or sandbox environment.
• Store required credentials securely and masked.
• Configure permitted payment account details.
• Configure callback/webhook endpoints and required validation parameters.
• Test connection before enabling production processing.
• Rotate/replace credentials through a re-authenticated privileged workflow.
• Record all configuration changes in the audit trail.
8.2 Execution State Machine
PENDING → SUBMITTED → PROCESSING → SUCCESS                             ↘ FAILED                             ↘ TIMEOUT → RECONCILIATION
8.3 Idempotency and Duplicate Execution Controls
Generate a unique application-level idempotency record for every intended payment instruction/batch submission.
Use the provider’s OriginatorConversationID/correlation identifier where applicable, but do not assume provider retries alone guarantee exactly-once behavior.
Persist request fingerprint, provider identifiers, state and response metadata.
Before every retry, check the internal transaction state and reconciliation result.
Ambiguous provider outcomes must enter a controlled reconciliation state rather than being blindly retried.
8.4 Callback Handling
Accept callbacks only on a dedicated endpoint.
Validate expected source/network policy where provider-supported, plus cryptographic/shared-secret verification where applicable.
Apply replay protection using timestamp/nonce or equivalent request uniqueness controls.
Queue callback processing for asynchronous handling.
Persist the raw callback payload in protected audit evidence where policy allows.
Update the transaction through a validated state transition only.
Expose an “awaiting callback confirmation” operational state.
9. Batch Orchestration and Scheduling
Cron-like scheduler for recurring payment windows.
Recurring batch templates for repeatable payroll/vendor cycles.
Priority queues for urgent versus routine processing.
Rate limiting aligned to the active Daraja contract and operational safety thresholds.
Cut-off times and holiday calendar controls.
Concurrency limits and locking to prevent the same batch from executing twice.
Operator-visible queue status and stuck-job diagnostics.
Dead-letter handling for messages that exceed retry policy.
10. Intelligence, Risk and Fraud Detection
Intelligence is a decision-support layer, not an uncontrolled authorization engine. AI may recommend, explain or flag; deterministic policy and human authority decide whether money can be released.
10.1 Detection Signals
Duplicate recipient/instruction detection.
Unusual payment amount relative to recipient history.
Unusual frequency or timing.
Unexpected department/payroll variance.
New recipient or recently modified recipient data.
High-risk approval-chain patterns.
Repeated small-group approval chains suggesting collusion risk.
Batch changes shortly before submission or authorization.
Unresolved reconciliation anomalies.
10.2 Risk Decision Model
Input evidence → deterministic policy checks → statistical / AI analysis → risk score + reasons → human review / policy decision → auditable action
10.3 AI Assistant Capabilities
Analyze uploaded batches.
Explain validation and payment failures.
Identify duplicates or anomalous amounts.
Analyze expenditure trends.
Compare payroll cycles.
Generate management summaries.
Generate executive briefing drafts.
Answer natural-language questions against permitted organizational data.
AI CONTROL
The AI layer must not directly issue a payment release command. AI output is advisory unless converted into an explicit, policy-approved state transition by an authorized human workflow.

11. Analytics and Reporting
Audience
Required outputs
L1 Operations
Batch counts, success/failure rates, processing time, operational trends, warnings
L2 Finance
Department expenditure, payroll analytics, period comparison, forecasts, anomalies, reconciliation, management reports
L3 Executive
Organization-wide intelligence, executive briefing, forecasts, risk overview, payment anomalies, department performance, payroll trends, efficiency, historical comparison, recommendations

Reports must support filtering by date/period, department/category, employee/recipient, batch, status and payment type where applicable. Export is controlled by role and report policy.
11.1 Report Families
Executive reports
Financial reports
Payroll reports
Payment reports
Audit reports
Reconciliation reports
Risk reports
AI intelligence reports
Department reports
User activity reports
System activity reports
Daraja integration reports
12. Administrator-Configurable Backup System
BACKUP OBJECTIVE
CARACAL includes a built-in, administrator-configurable backup system so the organization can create full database snapshots on demand, schedule recurring backups, enforce retention, and see every backup attempt and its result from the administration interface.

12.1 Administrator Flow
Admin → Settings → Backups → Connect S3-Compatible Storage → Test Connection → Configure Schedule/Retention → Run Backup / Observe History
12.2 Storage Configuration
An authorized administrator connects an S3-compatible storage service once by entering the storage endpoint and required access details. Examples include a cloud storage bucket or another S3-compatible object store. Credentials are encrypted/protected and must be masked after successful storage.
Setting
Requirement
Provider type
S3-compatible object storage
Endpoint
Required where non-default
Region
Optional/required according to provider
Bucket
Required
Path/prefix
Configurable
Access key ID
Protected secret
Secret access key
Protected secret
Encryption mode
Application/provider-side as configured
Connection test
Required before enabling schedule
Status
CONNECTED / ERROR / DISABLED

12.3 On-Demand Snapshot
• Administrator selects “Run Backup Now”.
• System creates a point-in-time consistent full database snapshot according to the database engine’s supported backup mechanism.
• Backup job is executed asynchronously so the browser request is not responsible for holding the full operation open.
• The UI immediately acknowledges that the job was accepted and then displays live/refreshable state.
• On completion, the result is recorded with status, started/finished timestamps, size, storage object identifier and checksum where available.
• The most recent result remains visible on the Backups screen.
12.4 Recurring Schedule
Administrators can enable a recurring schedule, for example daily, and select the execution time/timezone supported by the scheduler. The job must run automatically without staff remembering to trigger it. A missed execution must be observable as a failed or missed backup event rather than silently disappearing.
12.5 Retention
Administrators set a maximum retained backup count. After a new successful backup is committed, the retention worker identifies the oldest eligible backup records beyond the configured limit and deletes their remote objects and local metadata according to the retention policy. Deletion events are audited.
12.6 Backup Attempt Logging
Field
Example / requirement
Attempt ID
BAK-2026-000184
Trigger
MANUAL / SCHEDULED
Started / ended
Timestamped
Status
STARTED / SUCCESS / FAILED / PARTIAL
Target
Provider + bucket + prefix, with secrets masked
Backup object
Remote key / object identifier
Size
Bytes
Checksum
Recorded where available
Error
Sanitized error code/message
Actor
Administrator for manual runs; system for scheduled runs
Retention action
Count deleted / retained
Correlation
Job ID and scheduler/queue correlation ID

12.7 Backup Security Requirements
Backup credentials must be stored as secrets, never in plaintext application tables.
Backup archives should be encrypted in transit and at rest.
Remote object naming must not expose confidential payroll information.
Only authorized administrators may configure or manually initiate backups.
Backup configuration changes must require privileged authentication and be audited.
A failed backup must never be presented as successful.
The UI must clearly distinguish “backup requested”, “in progress”, “success” and “failed”.
Production backup jobs should use a dedicated queue/worker path with bounded concurrency.
Restore procedures must be tested separately; a backup that has never been restore-validated is not treated as fully disaster-recovery proven.
12.8 Backup Requirements
ID
Priority
Requirement
BAK-001
P0
Administrator can connect an S3-compatible target from Settings → Backups.
BAK-002
P0
Storage credentials are masked after save and protected by a secrets mechanism.
BAK-003
P0
System supports an on-demand full database snapshot.
BAK-004
P0
Backup operation is asynchronous and observable.
BAK-005
P0
Every attempt is persisted as success, failure or applicable terminal state.
BAK-006
P1
Administrator can enable/disable recurring backup scheduling.
BAK-007
P1
Administrator can configure a retention count and system removes oldest eligible backups beyond the limit.
BAK-008
P0
Most recent backup result is always visible on the Backups screen.
BAK-009
P1
Backup failures produce an administrative alert/event.
BAK-010
P1
Backup configuration changes and retention deletions are audited.

13. Audit, Evidence and Immutability
The audit layer is a security boundary, not a convenience log. Critical actions must be append-only from the application perspective, tamper-evident where required by the selected storage design, and queryable by authorized reviewers.
Event class
Examples
Identity
Login, WebAuthn, failed verification, device registration, recovery
Authority
Role assignment, permission change, privileged elevation attempt
Payment
Batch creation/edit/submission, approval/rejection/hold, authorization, release
Integration
Daraja credential change, connection test, callback, response, reconciliation
Security
Suspicious activity, policy denial, rate-limit event, blocked device
Backup
Configuration, manual run, scheduled run, failure, retention deletion
Administration
Organization policy, limits, notification/report settings changes

At minimum each audit event should include event ID, organization ID, actor ID or system actor, action, object type, object ID, timestamp, previous/new state where applicable, request/correlation ID, security context metadata, and outcome.
14. Canonical Data Model
The following entities form the baseline logical model. Physical schema and partitioning may change by database engine, but the business semantics must remain stable.
Entity
Purpose
Key fields / controls
Organization
Tenant/business boundary
ID, name, status, settings
User
Human identity
ID, organization, role, authority, status
WebAuthnCredential
Cryptographic authenticator
Credential ID, public key, counters, status, timestamps
TrustedDevice
Device trust
Device ID, user, credential, trust/revocation state
Recipient/Employee
Payment beneficiary
Name, phone/account identifier, department, status, metadata
Department/Category
Reporting and policy scope
Name, status, limits/policy association
PaymentBatch
Group of payment instructions
Batch ID, creator, state, totals, version, manifest hash
PaymentInstruction
Individual payout intent
Recipient, amount, currency, purpose, status, idempotency key
Approval
Workflow decision
Batch version, actor, level, action, reason, timestamp
Transaction
Provider execution record
Instruction ID, provider IDs, request fingerprint, state, timestamps
ReconciliationCase
Ambiguous/failed resolution
Transaction, case state, evidence, resolution actor
RiskFinding
Fraud/anomaly signal
Type, severity, score, evidence, disposition
AuditEvent
Immutable activity evidence
Event ID, actor, action, object, before/after, correlation
BackupConfiguration
S3-compatible target metadata
Target metadata, schedule, retention, status; secrets referenced separately
BackupAttempt
Backup execution record
Attempt ID, trigger, status, object key, size, checksum, error
Policy
Organization configuration
Limits, thresholds, approval rules, recovery/security rules

15. Technical Architecture
The recommended baseline is a modular monolith at the application/domain layer, with asynchronous workers for payment execution, callbacks, reconciliation, analytics jobs and backups. This preserves implementation speed while keeping financial-control boundaries explicit. Individual workers/services can scale independently when transaction volume requires it.
Users / Browsers      │      ▼Cloudflare Edge / DNS / WAF / DDoS / Rate Limits      │      ▼CARACAL Web + API      │      ├── Identity & WebAuthn      ├── RBAC / SoD / Policy Engine      ├── Payment Batch & Ledger      ├── Risk / AI Orchestration      ├── Reporting / Analytics      ├── Backup Control Plane      │      ├──────────────► PostgreSQL (system of record)      │                    ▲      │                 Hyperdrive      │      ├──────────────► Queue / Worker Layer      │                    ├── Payment Executor → Daraja B2C      │                    ├── Callback Processor      │                    ├── Reconciliation      │                    ├── Scheduler      │                    └── Backup Worker → S3-Compatible Storage      │      ├──────────────► Secrets Store / Secret bindings      └──────────────► Object storage for permitted artifacts / exports
16. Cloudflare Production Deployment Requirements
DEPLOYMENT DECISION
CARACAL is intended to be deployed with Cloudflare as the internet-facing security and application platform. Cloudflare is the primary edge/perimeter layer; application-level authorization remains mandatory inside CARACAL.

Current Cloudflare documentation supports Workers applications connecting to existing PostgreSQL/MySQL databases through Hyperdrive, and Cloudflare Queues supports asynchronous workers, retries and dead-letter queues. Cloudflare documents encrypted Worker Secrets for sensitive values and Cloudflare Access for protecting Workers/applications behind additional identity policy. These capabilities align with the platform’s payment-worker, callback, secrets and administrative-control requirements.
Layer
Preferred direction
Purpose
DNS/Edge
Cloudflare DNS + proxy
Single controlled public edge
Application runtime
Cloudflare Workers / supported frontend hosting pattern
API and web application execution
Edge security
Cloudflare WAF + managed/custom rules + rate limits + DDoS controls
Attack mitigation and traffic policy
Administrative perimeter
Cloudflare Access where appropriate
Restrict sensitive administrative surfaces
Primary data
Managed PostgreSQL outside Worker runtime
Durable financial system of record
DB connectivity
Cloudflare Hyperdrive
Worker-to-PostgreSQL connectivity/performance
Async processing
Cloudflare Queues + consumer Workers
Payment jobs, callbacks, reconciliation, backup jobs
Secrets
Cloudflare Worker Secrets / Secrets Store or equivalent enterprise vault
Credentials and key material
Object storage
S3-compatible storage; optionally Cloudflare R2
Backups and permitted large artifacts
Observability
Cloudflare + application audit/metrics stack
Security, reliability and performance visibility

16.1 Origin Protection
Do not expose the database directly to the public internet.
For any non-Cloudflare application origin, accept traffic only through controlled Cloudflare paths/firewalls where the hosting architecture supports it.
Do not place private payment credentials in client-side code.
Restrict administrative endpoints through application authorization and, where adopted, Cloudflare Access policies.
Apply WAF and rate limiting to authentication, webhook, export and other abuse-prone routes.
16.2 Cloudflare Security Mapping
CARACAL concern
Cloudflare role
CARACAL responsibility
Network/application DDoS
Edge mitigation
Maintain safe origin architecture and application rate limits
WAF/traffic filtering
Managed/custom rules
Define business-specific allow/deny patterns
Admin perimeter
Access
Maintain Frontier identity, WebAuthn and RBAC; Access is an additional layer, not a replacement
Secrets
Worker Secrets / Secrets Store
Control secret retrieval and rotation workflow
Async execution
Queues
Ensure job idempotency and state transitions
Database connectivity
Hyperdrive
Preserve DB authorization and transaction semantics
Backup storage
R2 or external S3
Apply encryption, retention and credential isolation

17. Application API Surface (Logical)
Exact URL paths may be finalized during implementation. The following command groups define the required API contract shape.
Domain
Logical API group
Primary purpose
Auth
/auth/login, /auth/logout, /auth/webauthn/*, /auth/recovery/*
Identity authentication; no SMS
Devices
/security/devices/*
Register, verify, revoke, trust decisions
Users
/admin/users/*
L3 user administration
Recipients
/recipients/*
Employee/recipient master data
Batches
/batches/*
Create, upload, validate, submit, review, hold, approve
Payments
/payments/*
Inspect transactions, retry eligible items, status
Authorization
/authorization/*
Manifest preview, step-up auth, transaction signing, release
Daraja
/admin/daraja/*
L3-only configuration, connection test, rotation
Callbacks
/integrations/daraja/callback
Provider callback ingress
Reconciliation
/reconciliation/*
Cases, status checks, resolutions
Analytics
/analytics/*
Operational/financial/executive dashboards
AI
/ai/*
Risk analysis, explanations, natural-language analysis
Reports
/reports/*
Generate and export permitted reports
Backups
/admin/backups/*
Configure target, run, schedule, retention, history
Audit
/audit/*
Controlled audit/event search
Policies
/admin/policies/*
Limits, approval thresholds, security policy

18. Security Zones and Trust Boundaries
Zone
Boundary
Controls
1. Identity
Authentication and credential material
Password hashing, WebAuthn, recovery controls, device trust
2. Authority
Role and command permissions
RBAC, server-side authorization, SoD
3. Financial Control
Approval, limits and risk
Thresholds, risk policies, conflict registry, cooling-off
4. Transaction Authorization
Signed payment intent
Manifest hash, fresh challenge, WebAuthn signature, anti-replay
5. Payment Execution
Async processing + provider
Queue, idempotency, locks, retries, reconciliation
6. Secrets
Provider/system credentials
Secret store, masking, rotation, least privilege
7. Audit
Immutable evidence
Append-only/tamper-evident events and controlled read access

19. Separation of Duties and Collusion Controls
Creator ≠ approver.
Modifier ≠ final authorizer.
No self-approval of own payment batch.
Cooling-off period between material batch edit and submission, according to organization policy.
Conflict-of-interest registry for L3 approvers.
Repeated approval by a small group is surfaced as a collusion-risk signal.
Changes after Level 2 approval invalidate the affected approval version and require re-review.
Final authorization is bound to the exact batch manifest.
20. Non-Functional Requirements
ID
Requirement
NFR-SEC-001
All privileged endpoints enforce server-side authorization and deny by default.
NFR-SEC-002
Transport encryption is mandatory for all external connections.
NFR-SEC-003
Sensitive secrets are never written to plaintext logs, client bundles or ordinary database columns.
NFR-SEC-004
Critical authorization events are auditable and correlated end-to-end.
NFR-REL-001
Payment execution is asynchronous and resilient to transient provider failures.
NFR-REL-002
Ambiguous outcomes enter reconciliation rather than unsafe automatic duplication.
NFR-REL-003
Queues/workers must tolerate retry without creating duplicate payment intents.
NFR-DATA-001
Historical financial records are append-only from the application perspective.
NFR-DATA-002
Exports are generated from authoritative stored records and preserve traceable identifiers.
NFR-PERF-001
Long-running jobs never depend on an open browser request.
NFR-OPS-001
Operators can see queued, processing, failed, timeout and reconciliation states.
NFR-BAK-001
Every backup attempt has a durable outcome record.
NFR-BAK-002
Retention execution is deterministic and auditable.
NFR-UX-001
Critical financial actions require explicit confirmation and clear display of amount, recipient count, batch ID and authorization state.
NFR-A11Y-001
Core workflows should meet a practical accessible web experience, including keyboard navigation, readable contrast and clear error states.

21. UX and Information Architecture
The interface should feel like a financial command center, not a generic admin dashboard. The design must make control state visible at a glance and reduce ambiguity before irreversible actions.
Dashboard: operational status, pending approvals, failed/ambiguous transactions, risk indicators, recent activity.
Payment Batches: filters, state timeline, totals, recipient count, validation/risk findings, approval history.
Payment Detail: exact instruction, transaction identifiers, provider state and immutable activity trail.
Authorization Review: amount, recipient count, departments, manifest fingerprint, Level 2 approval evidence, risk decision, fresh authentication action.
Employees/Recipients: master records and payment history with role-appropriate access.
Analytics: operational, financial, payroll and executive views.
Security Center: authentication, devices, suspicious activity, audit logs and policy events.
Settings: Daraja, organization, policies, notifications, reports and Backups.
Backups: connection status, schedule, retention, last success/failure, run-now action, attempt history.
22. Failure, Retry and Recovery Rules
Failure
Default handling
Validation failure
Keep batch in editable state; expose row-level reasons
Policy violation
Block transition; require authorized correction or policy decision
Daraja request rejected before execution
Mark FAILED with provider response; retry only if policy allows
Timeout / ambiguous provider state
Move to TIMEOUT and reconciliation; no blind retry
Callback missing
Show awaiting callback; reconciliation job/authorized manual workflow
Worker failure
Retry message within bounded policy; use dead-letter queue when exhausted
Database transaction conflict
Rollback; retry safe internal transaction only
Backup target unavailable
Mark backup FAILED; preserve prior successful backup; raise admin-visible alert
Backup credential failure
Disable repeated attempts after threshold and require admin correction
Retention deletion failure
Record partial result; do not claim retention complete

23. Security and Functional Test Requirements
Attempt every privileged command with insufficient roles and confirm denial server-side.
Attempt self-approval and creator/approver conflicts; confirm hard block.
Change a payment amount after Level 3 review and confirm the prior signature is invalid.
Replay a previous authorization request and confirm nonce/expiry prevents reuse.
Attempt to forge a SUCCESS status through an API or database mutation path; confirm application cannot perform it.
Rotate Daraja credentials and confirm old credential references cannot be reused unintentionally.
Submit duplicate callback payloads and confirm transaction state remains correct.
Force a provider timeout and confirm the system does not blindly resend the payment.
Run backup with valid S3 configuration and verify object creation plus attempt record.
Run backup with invalid credentials and verify failed status is immediately visible.
Set a retention count and verify oldest eligible objects are removed only after the new successful backup is committed.
Disable the schedule and verify no scheduled jobs continue.
Revoke a trusted device and confirm privileged actions require a valid device/authenticator.
Confirm plaintext secrets never appear in UI, API responses, client source, logs or exports.
Verify exports reflect authoritative transaction states and preserve provider reference identifiers.
24. Release Acceptance Criteria
ID
Priority
Acceptance condition
AC-01
P0
A Level 1 user can create and submit a valid batch but cannot authorize or release it.
AC-02
P0
A Level 2 user can review and approve a batch for Level 3 but cannot release it.
AC-03
P0
Only Level 3 can perform final payment authorization and Daraja administration.
AC-04
P0
WebAuthn is enforced for Level 2/3 privileged access.
AC-05
P0
Payment authorization signs the exact transaction manifest and rejects changed manifests.
AC-06
P0
No SMS path exists for login MFA, payment approval or recovery.
AC-07
P0
Daraja credentials are masked and protected by secrets management.
AC-08
P0
Provider callbacks and ambiguous transactions are reconciled safely.
AC-09
P0
Audit events cover all critical identity, approval, authorization, payment, credential and backup actions.
AC-10
P0
Full database backup can be run manually to a configured S3-compatible target.
AC-11
P1
Daily (or equivalent recurring) backups can be enabled and observed.
AC-12
P1
Retention removes oldest eligible backups beyond the configured count and records the action.
AC-13
P0
Latest backup result is visible with correct success/failure status.
AC-14
P1
Executive, finance and operational reports can be generated from authoritative payment data.
AC-15
P0
An AI recommendation can never directly bypass the human authorization boundary.

25. Recommended Implementation Sequence
Phase
Scope
Phase 0 — Foundation
Repository, environments, CI/CD, Cloudflare zone, database, secrets, logging, base UI shell, organizational tenancy.
Phase 1 — Identity & Authority
Frontier Identity, Argon2id, WebAuthn, devices, sessions, RBAC, policy engine, audit foundation.
Phase 2 — Payment Operations
Recipients, CSV schema/validation, batches, workflow states, L1/L2 interfaces, exports.
Phase 3 — Daraja Execution
L3 credential configuration, payment executor, queues, idempotency, callback processing, reconciliation.
Phase 4 — Financial Control
Limits, approval thresholds, SoD, conflict registry, cooling-off, signed manifests, FPAC and L3 authorization.
Phase 5 — Intelligence
Anomaly detection, fraud signals, historical comparison, analytics, AI assistant and management summaries.
Phase 6 — Backup & Resilience
S3-compatible storage connection, on-demand snapshots, schedules, retention, attempt history, restore validation workflow.
Phase 7 — Hardening & Go-Live
Security testing, failure injection, performance/load testing, production credentials, operational runbooks and controlled go-live.

26. Major Engineering Risks and Controls
Risk
Control
Duplicate financial execution
Idempotency ledger, provider correlation identifiers, locks, state machine and reconciliation
Credential leakage
Secret store, masked UI, log redaction, no client exposure
Privilege escalation
Default-deny server authorization and role-specific command APIs
Authorization tampering
Manifest hashing/signing and re-approval on material change
Collusion/self-approval
SoD rules, conflict registry, approval-chain analytics
Callback spoofing/replay
Signature/shared-secret validation where applicable, replay protection, dedupe
Data loss
Automated S3-compatible backups, retention, backup attempt monitoring, restore validation
AI hallucination / unsafe automation
AI advisory boundary, evidence display, deterministic policy enforcement
Provider outage
Queue buffering, retry policy, dead-letter handling and reconciliation
Operator confusion
State-centric UI, explicit confirmation, clear irreversible-action warnings

27. Operational Runbooks Required Before Production
Daraja credential rotation and emergency disablement.
Payment stuck in PROCESSING/TIMEOUT.
Callback outage and reconciliation sweep.
Compromised user/device response and session revocation.
High-risk/fraud incident review.
Database outage and failover.
Backup target outage or credential rotation.
Backup restoration and disaster-recovery test.
Audit evidence preservation during incident response.
Production rollback / application release rollback.
28. Reference Basis
Primary product source: user-provided PAYMENT SYSTEM concept document. Its key requirements are the three-level command hierarchy, strict permission matrix, no-SMS security model, Frontier Identity, WebAuthn, separate payment authorization, FPAC, signed transaction manifests, device trust, secrets isolation, security zones, idempotency, asynchronous callbacks/reconciliation, separation of duties and batch scheduling.
Cloudflare implementation verification, checked 13 September 2026:
Ref
Basis
CF-01
Cloudflare Workers Secrets documentation — encrypted secrets and secret bindings for sensitive values.
CF-02
Cloudflare Hyperdrive documentation — Workers connectivity to PostgreSQL/MySQL and supported hosted databases.
CF-03
Cloudflare Queues documentation — asynchronous messaging, retries, batching and dead-letter queues.
CF-04
Cloudflare Access documentation — policy-based restriction of applications/Workers.
CF-05
Cloudflare DDoS Protection documentation — managed protection at network and application layers.
CF-06
Safaricom Daraja Developer Portal — current Daraja 3.0 API portal and Transaction Status API documentation.

29. Decisions Still Requiring Product/Engineering Confirmation
Exact PostgreSQL hosting provider and region.
Exact Cloudflare Workers/frontend split and whether administrative surfaces will be additionally protected by Cloudflare Access.
Chosen secrets/vault implementation where Cloudflare-native secret storage is insufficient for the required key lifecycle.
Exact Daraja production contract, credential fields and provider-specific limits in the approved business account.
Backup snapshot mechanism for the selected PostgreSQL service and whether snapshots are streamed/exported to object storage directly or generated by a controlled worker/job.
Organization-specific approval thresholds, payment limits, holiday calendar and cooling-off durations.
Exact AI model/provider, data-retention boundary and whether any financial data may leave the selected execution environment.
Required RPO/RTO targets and restore-testing cadence.
BASELINE PRINCIPLE
The first production release should optimize for correctness, authority separation, auditability and recoverability before adding breadth. A smaller payment control plane that cannot silently bypass its security model is preferable to a feature-rich release with weak financial invariants.


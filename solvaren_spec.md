
SOLVAREN
PAYMENT SOLUTIONS
Move money with certainty.
PRODUCT POSITIONINGEnterprise payment management, financial control, intelligent risk analysis and auditable disbursement execution for payroll, suppliers and contractors.

Property
Value
Document type
Software Requirements & Technical Specification
Status
Commercial implementation baseline / Draft v1.0
Date
14 September 2026
Primary payment rail
Safaricom M-PESA Daraja B2C
Primary deployment platform
Railway
Edge / DNS option
Cloudflare may be used in front of Railway as an optional edge-control layer
Security posture
No SMS authentication, MFA, payment approval or recovery
Backup posture
Administrator-configurable offsite full-database backup to S3-compatible storage


Document Control
Version
Date
Status
Change
1.0
14 Sep 2026
Baseline
Rebranded to SOLVAREN Payment Solutions; deployment target changed to Railway; backup subsystem formalized.

Table of Contents
1. Executive Summary
2. Product Goals and Success Criteria
3. Scope and Boundaries
4. User Roles and Command Hierarchy
5. Functional Requirements
6. Payment Batch Lifecycle
7. Authentication and Payment Authorization
8. Device Trust, Sessions and Recovery
9. Daraja B2C Integration
10. Batch Orchestration and Scheduling
11. Intelligence, Risk and Fraud Detection
12. Analytics and Reporting
13. Administrator-Configurable Backup System
14. Audit, Evidence and Immutability
15. Data Model
16. Technical Architecture
17. Railway Production Deployment Architecture
18. Application API Surface
19. Security Zones and Trust Boundaries
20. Separation of Duties and Collusion Controls
21. Non-Functional Requirements
22. UX and Information Architecture
23. Failure, Retry and Recovery Rules
24. Test and Verification Requirements
25. Release Acceptance Criteria
26. Implementation Sequence
27. Operational Runbooks
28. Major Engineering Risks and Controls
29. Reference Basis
30. Decisions Requiring Confirmation
1. Executive Summary
SOLVAREN Payment Solutions is an enterprise business-disbursement control platform for payroll, supplier payments and contractor payouts. It is intentionally not designed as a simple payment form or payment-only portal. The product is a controlled financial workflow in which preparation, finance review, final authorization, execution, reconciliation, intelligence and evidence are separate concerns.
The platform preserves a three-level command hierarchy. Level 1 performs operational preparation and monitoring. Level 2 performs financial review, verification, reconciliation and management analysis. Level 3 is the final payment authority and administrator for critical payment infrastructure. No role can bypass the state machine or convert an unauthorized transaction into a successful payment by directly manipulating status data.
Financial authorization is deliberately stronger than ordinary login authentication. A valid session does not imply payment authority. Privileged payment release requires the correct authority, valid approval chain, an unmodified transaction manifest, fresh WebAuthn authentication, a Frontier Payment Authorization Credential (FPAC), risk-policy approval and a valid payment state.
The primary execution rail is Safaricom M-PESA Daraja B2C. Processing is asynchronous and designed around idempotency, callbacks, reconciliation, ambiguity handling and dead-letter recovery. AI is a decision-support layer: it can detect anomalies, explain failures, compare historical behavior and draft intelligence, but it cannot independently authorize or release funds.
2. Product Goals and Success Criteria
Enable large organizations to prepare and execute recurring and ad-hoc business payouts while preserving separation of duties.
Maintain a complete financial chain from recipient record to batch, instruction, approval, provider identifiers, outcome and audit evidence.
Prevent unauthorized release, silent payment modification, self-approval, privilege escalation and unsafe retries.
Reduce operational error using schema validation, duplicate detection, historical comparisons, anomaly scoring and explicit risk reasons.
Produce precise operational, financial, payroll, departmental, audit, reconciliation, risk and executive reporting.
Provide resilient asynchronous processing with queues, bounded retries, dead-letter handling, callbacks and reconciliation jobs.
Run production workloads on Railway using isolated application services, managed PostgreSQL/Redis, private networking, health checks and controlled secrets/configuration.
Provide an administrator-configurable offsite database backup capability using an S3-compatible storage target, with one-click execution, scheduling, retention and a visible attempt history.
SUCCESS PRINCIPLEThe system must make it easier to prove that every release was legitimate than to hide or bypass an illegitimate release.

3. Scope and Boundaries
3.1 In Scope
Organization and user administration
Three-level command hierarchy
Employee / supplier / contractor recipient master data
CSV ingestion and batch creation
Batch validation, correction and submission
Finance review, approval, rejection and hold
Level 3 final payment authorization
Daraja B2C credential management
Payment execution and callback handling
Reconciliation and ambiguous-state handling
Fraud/anomaly detection and risk scoring
Operational, financial and executive analytics
AI-assisted analysis and reporting
Audit and security event logging
Batch scheduling and recurring templates
Railway production deployment architecture
Administrator-configurable S3-compatible database backup
Retention and backup attempt monitoring
3.2 Explicit Baseline Boundaries
SMS OTP, SMS MFA, SMS password reset, SMS payment approval or SMS recovery
Plaintext exposure of Daraja or backup access secrets
Direct user-driven database manipulation to force transaction success
Deleting or rewriting immutable transaction history or audit evidence
Consumer checkout or marketplace functionality
Replacing Daraja as the baseline payment rail before the core architecture is stable
4. User Roles and Command Hierarchy
Authorization must be enforced server-side. UI visibility is not a security boundary. Every privileged command must evaluate organization, role, authority level, object state, approval history, authentication context and applicable policy.
4.1 Level 1 — Payment Operations
Purpose: prepare, validate, submit and monitor payment batches.
Upload CSV files; create payment batches; edit drafts; validate records; correct invalid records; add/remove recipients before submission; view payment history; submit completed batches to Level 2; monitor processing; view successful/failed payments; retry eligible failures subject to policy; view provider references; export permitted reports.
Maintain employee/recipient records within scope; deactivate recipients; manage permitted departments/categories.
View operational dashboards, batch statistics, payment success/failure, processing times, payment trends and AI-generated operational warnings.
Ask the AI operational assistant questions and analyze uploaded batches.
Level 1 cannot authorize payment release, approve its own batch, change Daraja credentials, change limits/policies, create Level 3 users, delete transactions or audit logs, or override Level 2/3 decisions.
4.2 Level 2 — Finance Control & Review
Purpose: verify financial accuracy, review risk, reconcile payments and prepare batches for final authorization.
Review all Level 1 submissions and individual instructions; verify recipients and amounts; compare against history; approve to Level 3; reject; return for correction; hold batches; review failed/pending transactions; initiate reconciliation.
View organization-wide expenditure, payroll, department and employee spending; compare periods; monitor volumes; review anomalies.
Use advanced analytics, forecasts, anomaly reports, reconciliation reports and management reporting.
Use AI financial analysis, anomaly detection, risk assessment, expenditure analysis, forecasting and management summaries.
Level 2 cannot release payments, give final payment authorization, change Daraja credentials, bypass Level 3, change core payment limits, delete immutable history or audit logs.
4.3 Level 3 — Chief / Executive Payment Authority
Purpose: final financial authority and administrator for critical payment infrastructure.
View all batches and instructions; review Level 2 recommendations; inspect AI risk findings and anomalies; approve/reject final release; hold/cancel eligible unreleased batches; authorize high-value and normal payroll batches; monitor all disbursements; view complete history.
Configure, rotate and replace Daraja credentials; configure environment, payment account details, callbacks and integration status; test connectivity.
Create/disable/reactivate users; assign roles; configure organization, payment limits, approval thresholds, notifications, reporting and security policies.
Manage MFA/WebAuthn policy, privileged access, security events, audit logs, login activity, suspicious activity, trusted devices and executive intelligence.
4.4 Permission Matrix
Capability
L1
L2
L3
Upload CSV
Yes
Yes
Yes
Create batch
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
Retry eligible failures
Policy-limited
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
Management reports
No
Yes
Yes
User management
No
Limited
Yes
Payment limits / approval policies
No
No
Yes
Security policies / MFA administration
No
No
Yes
Daraja configuration
No
No
Yes
Change / rotate Daraja credentials
No
No
Yes only
View plaintext secrets
No
No
No
Test Daraja connection
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

5. Functional Requirements
ID
Area
Requirement
FR-AUTH-001
Identity authentication
System shall authenticate users using username/email + password, with WebAuthn mandatory for Level 2 and Level 3 in the baseline profile.
FR-AUTH-002
No SMS
System shall not use SMS for login MFA, payment approval, credential recovery or password reset.
FR-PAY-001
Batch preparation
System shall support CSV ingestion, draft batches, validation, correction and recipient management before submission.
FR-PAY-002
Approval chain
System shall enforce Level 1 -> Level 2 -> Level 3 progression and prevent unauthorized state jumps.
FR-PAY-003
Transaction authorization
System shall bind final authorization to a deterministic manifest of the exact payment instructions.
FR-PAY-004
Execution state machine
System shall use explicit payment states and durable transitions; clients cannot set authoritative states directly.
FR-DARAJA-001
Daraja configuration
Only Level 3 shall configure, test, rotate or disable the Daraja integration.
FR-INTEL-001
Risk analysis
System shall expose risk signals with reasons and evidence, not only an opaque score.
FR-REPORT-001
Reporting
System shall support date, department, recipient, batch, status and payment-type filtering with role-based exports.
FR-BACKUP-001
Backup configuration
Authorized administrators shall configure an S3-compatible backup target from Settings -> Backups.
FR-BACKUP-002
On-demand backup
Authorized administrators shall trigger a full database backup on demand and receive an immediate accepted/in-progress/result status.
FR-BACKUP-003
Scheduled backup
Authorized administrators shall enable a recurring schedule such as daily; execution shall be automatic.
FR-BACKUP-004
Retention
System shall enforce a configurable maximum retained backup count and remove the oldest eligible backup after a new successful backup is committed.
FR-BACKUP-005
Attempt history
Every backup attempt, success or failure, shall be recorded and the latest result shall always be visible.
FR-AUD-001
Audit evidence
Critical privileged actions and state transitions shall be append-only from the application perspective and tamper-evident where implemented.

6. Payment Batch Lifecycle
DRAFT  -> VALIDATED  -> SUBMITTED_TO_L2  -> L2_REVIEW      -> RETURNED_FOR_CORRECTION -> DRAFT/REVALIDATE      -> REJECTED      -> ON_HOLD      -> L3_READY  -> AUTHORIZATION_PENDING  -> AUTHORIZED  -> QUEUED  -> SUBMITTED  -> PROCESSING      -> SUCCESS      -> FAILED      -> TIMEOUT -> RECONCILIATION
A batch state must never be changed by direct database update from the application UI. Commands are validated against the current state, expected version, actor authority and security policy. Material edits after approval create a new approval version and invalidate earlier authorization evidence.
6.1 Level 1 Preparation
Upload approved CSV schema.
Create a draft batch with business purpose, payment period and department/category.
Validate mandatory fields, phone format, amount rules, recipient activity and policy limits.
Detect duplicate recipients/instructions and flag anomalous amounts.
Add/remove/correct recipients while editable.
Submit to Level 2; submission freezes the approval version.
6.2 Level 2 Review
Verify recipients, amounts and historical context.
Review risk and anomaly findings.
Approve to Level 3, reject, return or hold.
Initiate reconciliation for failed, pending or ambiguous transactions.
6.3 Level 3 Authorization
Open the exact approval version.
Review manifest fingerprint, totals, recipient count, risk evidence and Level 2 approval.
Perform fresh WebAuthn authentication plus Frontier authorization PIN verification.
Revalidate limits, approval chain, state and manifest.
Authorize only if every required gate passes.
7. Authentication and Payment Authorization
Login authentication establishes identity. Financial authorization is a separate security boundary. Being logged in does not create payment authority.
7.1 No-SMS Rule
No SMS OTP
No SMS password reset
No SMS payment approval
No SMS MFA
No SMS credential recovery
7.2 Frontier Identity
Frontier Identity├── User ID / Organization ID├── Role / Authority Level├── Password credential (Argon2id or equivalent modern KDF)├── WebAuthn credential(s)├── Authorization PIN / FPAC reference├── Trusted devices├── Recovery credentials└── Security state
7.3 Level 3 Login
Username / Email + Frontier Password + WebAuthn                         -> Authenticated Session
7.4 Payment Authorization Credential (FPAC)
The Frontier Payment Authorization Credential is separate from the ordinary login credential. It is never stored or transmitted as plaintext. The implementation may use a hardened derivation design and/or device-backed key material, subject to final cryptographic review.
7.5 Transaction Manifest Signing
Challenge = HASH(organization + batch + amount + recipients + approval + manifest + nonce + expiry)
The manifest is deterministic. Any change to amount, recipient set, approval evidence, policy context or other signed fields invalidates the authorization and requires a new approval path. Anti-replay uses nonce and expiry checks, plus durable authorization state.
7.6 Fundamental Release Rule
Valid user + Correct authority level + Valid approval chain + Exact transaction manifest + Fresh authentication + Cryptographic authorization + Risk policy pass + Valid payment state = PAYMENT RELEASE
8. Device Trust, Sessions and Recovery
8.1 Trusted Device
Trusted Device├── Device ID├── User ID├── WebAuthn Credential ID├── Registration timestamp├── Last activity├── Trust status└── Revocation status
8.2 Session Security
Use short-lived access credentials and renewable sessions with rotation controls.
Allow server-side session invalidation for logout, device revocation and security events.
Require recent authentication context for privileged actions.
Apply risk-based restrictions to unusual device, network, geography or behavioral changes.
Never trust a client-provided role or authority value.
8.3 Recovery
Recovery must not become a bypass around payment security. The baseline flow is: strong identity verification -> existing recovery credential or controlled administrative recovery -> security hold / elevated review -> new authenticator enrollment. Level 3 recovery requires the strongest review and full audit evidence.
8.4 Secrets
Application tables may store secret metadata and encrypted ciphertext where necessary, but not plaintext Daraja credentials, backup access keys or cryptographic master secrets. Railway service variables are used for deployment configuration and root application secrets; per-organization external credentials should be encrypted before persistence using an application-controlled key hierarchy.
9. Safaricom Daraja B2C Integration
Daraja 3.0 is the primary M-PESA integration platform. SOLVAREN shall integrate only against the approved production contract and credentials issued for the organization. The exact credential fields, account limits and provider-side requirements must be taken from the organization's live Daraja onboarding and current Safaricom documentation.
9.1 Level 3 Daraja Administration
Configure sandbox/production environment as permitted.
Store credentials securely and display them masked after storage.
Configure permitted payment account details.
Configure callback/webhook endpoints and validation controls.
Test the connection before production processing.
Rotate/replace credentials through privileged re-authentication.
Audit every configuration change.
9.2 Execution State Machine
PENDING -> SUBMITTED -> PROCESSING -> SUCCESS                              -> FAILED                              -> TIMEOUT -> RECONCILIATION
9.3 Idempotency and Duplicate Execution
Create an application-level idempotency record for every intended payment instruction and batch submission.
Persist request fingerprint, provider correlation identifiers, state and response metadata.
Use the provider correlation identifier such as OriginatorConversationID where applicable, but do not assume provider retries create business-level exactly-once semantics.
Before retrying, consult internal state and reconciliation outcome.
Do not blindly resend ambiguous outcomes.
9.4 Callback Handling
Accept callbacks on a dedicated endpoint.
Validate provider/network controls supported by the current contract and apply application-level authentication/verification where applicable.
Use request uniqueness/replay protection.
Queue callback processing asynchronously.
Persist protected callback evidence according to retention/privacy policy.
Advance transaction state only through validated state transitions.
Expose an operational “awaiting callback confirmation” state.
10. Batch Orchestration and Scheduling
Recurring batch templates for payroll/vendor cycles.
Priority queues for urgent versus routine jobs.
Rate limiting aligned with the approved provider contract and internal safety thresholds.
Cut-off times and configurable holiday calendars.
Concurrency controls and distributed locking.
Operator-visible queue state, retry count and stuck-job diagnostics.
Dead-letter queue for jobs that exceed retry policy.
Railway Cron Jobs for short-lived scheduled control tasks such as backup triggers, reconciliation sweeps and housekeeping; application workers remain long-running for queue processing.
11. Intelligence, Risk and Fraud Detection
AI and statistical intelligence are decision-support mechanisms. Deterministic policy, role authority and human approval remain controlling gates for financial release.
11.1 Detection Signals
Duplicate recipient/instruction patterns
Unusual amount relative to recipient history
Unusual frequency or timing
Unexpected payroll/department variance
New or recently modified recipient
High-risk approval-chain patterns
Repeated small-group approval chains suggesting collusion
Batch changes shortly before submission or final authorization
Unresolved reconciliation anomalies
11.2 Decision Model
Input evidence   -> deterministic policy checks   -> statistical / AI analysis   -> risk score + reasons + evidence   -> human / policy decision   -> audited action
11.3 AI Assistant Capabilities
Analyze uploaded batches
Explain validation and payment failures
Identify duplicates and anomalous amounts
Compare payroll cycles
Analyze expenditure trends
Generate management summaries
Draft executive briefings
Answer natural-language questions against permitted organizational data
12. Analytics and Reporting
Reports shall support filters appropriate to the requesting role, including date/period, department/category, recipient, batch, transaction status and payment type. Export must be authorized by role and should preserve authoritative provider references.
12.1 Report Families
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
12.2 Executive Intelligence
Example: “September disbursements increased compared with August; Engineering contributed the largest increase; three transactions were flagged as anomalous and reviewed; no unresolved duplicate-payment alerts remain.” The system must distinguish computed facts from AI-generated narrative.
13. Administrator-Configurable Backup System
SOLVAREN includes a built-in administrator-configurable backup subsystem. From Admin -> Settings -> Backups, an authorized administrator connects an S3-compatible storage service once, configures the schedule and retention policy, and can manually run a backup without staff needing to remember routine disaster-recovery tasks.
BACKUP CONTROL PRINCIPLEA backup record is not considered successful until the database snapshot has been created, the resulting artifact has been successfully committed to the configured object store, and the success event has been durably recorded.

13.1 Administrator Flow
Admin -> Settings -> Backups     -> Connect S3-compatible storage     -> Test connection     -> Save encrypted configuration     -> Configure schedule + retention     -> Run Backup Now / monitor history
13.2 S3-Compatible Storage Configuration
Endpoint URL / provider identifier as required by the storage service.
Bucket/container name.
Region or endpoint configuration where applicable.
Access key ID / equivalent identifier.
Secret access key / equivalent credential.
Optional prefix/path policy.
Encryption-at-rest mode supported by the target, where applicable.
Connection test result and last verified timestamp.
The configured credential material must be encrypted at rest and never returned in plaintext by APIs or UI. Object names must not contain confidential payroll details; use opaque backup IDs and timestamps.
13.3 On-Demand Snapshot
Administrator selects Run Backup Now.
Application creates a backup job record and returns an immediate accepted status.
A dedicated backup worker/cron service performs the database snapshot using the supported PostgreSQL backup mechanism.
The worker uploads the resulting artifact to the configured S3-compatible target.
The system verifies successful object creation and records backup metadata.
The Backups screen displays the current status and most recent result without requiring a long-held browser request.
13.4 Recurring Schedule
Administrators can enable a recurring schedule, for example daily. The schedule is stored as policy data and materialized into a Railway Cron trigger or equivalent scheduler invocation that enqueues a backup job. Because Railway Cron schedules use UTC and may vary by a few minutes, SOLVAREN should store the organization's intended local time plus timezone and translate it to UTC at scheduling time. Exact execution time is not used as a financial deadline.
13.5 Retention
The administrator sets a maximum retained backup count. After a new successful backup is committed, the system selects the oldest eligible backup records beyond the limit and deletes their corresponding remote objects. A failed backup never advances retention as though it were successful. Deletion events are audited.
13.6 Backup Attempt History
Field
Required behavior
Attempt ID
Unique immutable backup attempt identifier
Status
QUEUED / RUNNING / SUCCESS / FAILED
Requested by
Human administrator or SYSTEM
Trigger
MANUAL / SCHEDULED
Started / finished
UTC timestamps
Database snapshot
Method + logical identifier
Artifact
Remote object identifier / URI-safe reference
Size
Artifact size when available
Checksum
Stored/verified where supported
Error summary
Sanitized failure reason
Retention action
Objects deleted/retained after success

13.7 Backup Security Requirements
Only authorized administrators may configure or manually initiate backups.
Backup credentials are secrets and are never logged or returned plaintext.
Backup transfers use TLS to the object store.
Backup archives are encrypted at rest where supported by the storage service and/or archive format.
Remote object naming must not expose employee names, payroll identifiers or payment details.
The UI clearly separates REQUESTED, RUNNING, SUCCESS and FAILED.
Backup jobs use bounded concurrency to prevent resource exhaustion.
Restore procedures are tested separately. A backup that has never been restore-validated is not treated as fully disaster-recovery proven.
Backup failures produce visible operational warnings and an audit event.
13.8 Railway Backup Architecture
Railway PostgreSQL      |      | pg_dump / supported logical backup      vBackup Job Service (short-lived Cron invocation)      |      +--> S3-compatible object storage      |      +--> PostgreSQL: backup_attempt + backup_config metadata      |      +--> Audit Event
13.9 Backup Acceptance Rules
Valid S3 configuration -> successful test connection is recorded.
Run Backup Now -> immediate accepted status, followed by final SUCCESS/FAILED result.
Invalid S3 credentials -> FAILED result and reason visible to authorized administrator.
Scheduled daily backup -> job is created automatically according to stored schedule.
Retention limit N -> oldest eligible objects are deleted only after successful creation of a new retained backup.
Schedule disabled -> no further scheduled backup invocations are created.
Credential rotation -> future jobs use the new secret without exposing the old credential.
Restore drill -> RTO/RPO observations are recorded for the tested backup.
14. Audit, Evidence and Immutability
The audit layer is a security boundary. Critical events must be append-only from the application perspective and protected against unauthorized modification.
Event ID, organization ID, actor/system actor, action, object type, object ID, timestamp, previous/current state references.
Authentication events, device registration/revocation, privileged actions, authorization attempts, policy changes, credential changes and backup events.
Payment provider correlation IDs and callback evidence linked to the authoritative transaction.
No delete operation exposed to normal application roles for audit events.
Tamper-evident design may include hash chaining or an external append-only evidence sink, subject to implementation review.
15. Data Model
Entity
Purpose
Organization
Tenant boundary and organization-level configuration
User
Identity, role, authority level, security state
Device
Trusted-device and authenticator metadata
WebAuthnCredential
Public-key credential and lifecycle
Recipient
Employee/supplier/contractor master record
Department
Organizational grouping
PaymentBatch
Batch metadata, approval version and state
PaymentInstruction
Individual recipient amount and authoritative status
Approval
Level-specific approval evidence
Authorization
Final cryptographic authorization record
PaymentTransaction
Provider request/result identifiers and state history
CallbackEvent
Protected callback evidence and processing state
ReconciliationCase
Ambiguous/pending transaction investigation
RiskSignal
Risk event, score, reasons and evidence links
ReportJob
Generated report request and result metadata
AuditEvent
Append-only activity evidence
BatchTemplate
Recurring payroll/vendor batch template
Schedule
Recurring execution policy
BackupConfig
Encrypted S3-compatible target metadata and schedule
BackupAttempt
Immutable backup execution result
BackupObject
Remote artifact reference, checksum and retention metadata

16. Technical Architecture
The recommended baseline is a modular monolith at the domain/application layer, separated into logical modules and supported by dedicated worker processes. This avoids premature microservice complexity while isolating long-running and privileged workloads.
Users / Browsers       |       vRailway Public Web/API Service       |       +--> Identity + WebAuthn       +--> RBAC / Authority       +--> Payment Domain       +--> Finance Review       +--> Risk / AI       +--> Reporting       +--> Admin / Security       +--> Backup Control       |       +---- Private Network ----> PostgreSQL       |       +---- Private Network ----> Redis       |       +---- Queue / jobs -------> Worker Service                                  |                                  +--> Daraja B2C                                  +--> Reconciliation                                  +--> Backup / S3                                  +--> Notifications / reporting jobs
16.1 Core Infrastructure
Application/API service
Background worker service
Backup/reconciliation short-lived job service
Railway PostgreSQL
Railway Redis
External S3-compatible object storage for offsite backups
Optional Cloudflare DNS/WAF/rate limiting in front of Railway public service
17. Railway Production Deployment Architecture
Railway is the primary deployment platform for the production baseline. The architecture shall keep databases and workers private and expose only the required public web/API entry point. Railway documents private networking between services, managed PostgreSQL and Redis, service variables/reference variables, health checks, pre-deploy commands and Cron Jobs for short-lived scheduled tasks.
17.1 Recommended Railway Services
Service
Role
Deployment behavior
solvaren-web
Public web/API
Handles authenticated browser/API traffic; listens on Railway PORT; healthcheck /health
solvaren-worker
Long-running worker
Consumes queue jobs: payment execution, callbacks, reconciliation, report generation, risk jobs
solvaren-backup-job
Cron / short-lived
Creates database dump, uploads to S3, records backup result; must exit after task
solvaren-postgres
Managed PostgreSQL
Authoritative transactional database
solvaren-redis
Managed Redis
Queue, locks, rate-control and ephemeral coordination

17.2 Private Networking
Web-to-Postgres, web-to-Redis, worker-to-Postgres, worker-to-Redis and backup-job-to-Postgres communications should use Railway private networking. Databases must not be given public access for ordinary runtime operation.
17.3 Environment Separation
Development environment
Staging / pre-production environment
Production environment
Each environment has separate variables and database instances. Production credentials must never be reused in development or staging. Production data should not be copied into non-production environments without an approved anonymization/sanitization process.
17.4 Variables and Secrets
Use Railway service variables for runtime configuration and root deployment secrets.
Use Railway reference variables for DATABASE_URL and REDIS_URL between services.
Store high-impact application master keys separately from business records.
Never commit production secrets to source control.
Never expose secrets in logs, error responses or client bundles.
17.5 Health and Deployment Controls
Expose an application health endpoint returning 2xx only when the service is ready.
Configure Railway health checks before production promotion.
Use a pre-deploy migration command such as the project ORM migration deploy command.
Configure crash restart policy.
Use staged/reviewed variable changes for sensitive configuration.
Use Git-based deployment with protected production branches and reviewed changes.
17.6 Railway Deployment Topology
Internet   |   +--> Optional Cloudflare DNS/WAF/Rate Limit             |             v      Railway solvaren-web (public)             |\             | \ private network             |  \--> solvaren-worker             |      |\             |      | +--> Daraja B2C             |      | +--> Reconciliation             |      | +--> Report / AI jobs             |             +------> solvaren-postgres (private)             +------> solvaren-redis (private)Railway Cron -> solvaren-backup-job -> Postgres dump -> S3-compatible storage
17.7 Railway Backups vs SOLVAREN Offsite Backups
Railway native PostgreSQL/volume backup capabilities can provide platform-level recovery, but SOLVAREN must still implement its product-level offsite backup feature because the administrator requirement explicitly calls for configurable S3-compatible storage, a visible application backup history and retention controls. Production should use layered recovery: Railway-native recovery where enabled plus independent logical dumps to external object storage.
18. Application API Surface
Domain
Logical API group
Purpose
Auth
/api/auth/*
Login, WebAuthn, session lifecycle
Users
/api/admin/users/*
User administration
Devices
/api/security/devices/*
Trusted device registration/revocation
Recipients
/api/recipients/*
Recipient master data
Batches
/api/payment-batches/*
Create, validate, edit, submit, review
Approvals
/api/approvals/*
Level 2 approvals and Level 3 authorization
Transactions
/api/transactions/*
Payment state/history
Daraja
/api/admin/daraja/*
Level 3 integration management
Callbacks
/api/daraja/callbacks/*
Provider callback intake
Reconciliation
/api/reconciliation/*
Status checks and investigations
Risk
/api/risk/*
Risk findings and explanations
Reports
/api/reports/*
Report generation/export
Backups
/api/admin/backups/*
Backup config, run-now, history, retention
Security
/api/security/*
Audit/security center
Health
/health
Railway deployment health endpoint

Exact URL paths, HTTP methods and payload schemas are implementation details. All privileged endpoints must re-check authorization server-side and enforce state/approval invariants.
19. Security Zones and Trust Boundaries
Zone
Name
Responsibilities
ZONE 1
Identity
Authentication, WebAuthn, credentials, devices
ZONE 2
Authority
RBAC, L1/L2/L3 policy
ZONE 3
Financial Control
Approval, limits, risk, SoD
ZONE 4
Transaction Authorization
Manifest, challenge, signature, anti-replay
ZONE 5
Payment Execution
Queue, worker, Daraja B2C
ZONE 6
Secrets
Daraja credentials, encryption keys, service secrets
ZONE 7
Audit
Immutable events, authorization history, transaction history, backup evidence

The architecture must prevent a compromise of a single UI action, session, endpoint or database record from being sufficient to release money. Cross-zone boundaries must be enforced with server-side policy and cryptographic evidence where relevant.
20. Separation of Duties and Collusion Controls
Creator != approver.
Modifier != final authorizer.
No self-approval of own payment batch.
Cooling-off period between material batch edit and submission according to organization policy.
Conflict-of-interest registry for Level 3 approvers.
Repeated approval by a small group is surfaced as a collusion-risk signal.
Changes after Level 2 approval invalidate the affected approval version.
Final authorization is bound to the exact batch manifest.
21. Non-Functional Requirements
Attribute
Requirement
Security
Defense in depth; secure headers; CSRF protection where session architecture requires it; rate limiting; input validation; least privilege; secret minimization; WebAuthn; immutable evidence.
Availability
Service restart/recovery procedures; managed database; worker isolation; queue durability; health checks.
Integrity
Transactional database writes; state machine invariants; optimistic locking/versioning; signed manifest; idempotency.
Performance
Queue-based execution; paginated tables; indexed reporting dimensions; asynchronous reports and backups.
Scalability
Horizontal scaling for web/worker services; queue-backed workloads; database connection pooling; bounded concurrent provider requests.
Observability
Structured logs; metrics; job state; security events; payment latency; callback latency; reconciliation backlog; backup success/failure metrics.
Privacy
Role-scoped access; minimum necessary data exposure; protected exports; retention policies; sanitized non-production data.
Maintainability
Modular domain boundaries, typed APIs, migration discipline, automated tests, architecture decisions and runbooks.

22. UX and Information Architecture
The interface should resemble a financial command center rather than a generic admin dashboard. The user should always be able to answer: what is waiting, what is blocked, what is risky, who owns the decision, what will happen next and what evidence exists.
Dashboard: operational status, pending approvals, failed/ambiguous transactions, risk indicators, recent activity.
Payment Batches: filters, state timeline, totals, recipient count, validation/risk findings, approval history.
Payment Detail: exact instruction, provider identifiers, current authoritative state and immutable activity trail.
Authorization Review: amount, recipients, departments, manifest fingerprint, Level 2 evidence, risk decision and fresh authentication action.
Recipients: master records and payment history.
Analytics: operational, financial, payroll and executive views.
Security Center: authentication, devices, suspicious activity, audit logs and policies.
Settings: Daraja, organization, policies, notifications, reports and Backups.
Backups: connection status, schedule, retention, last success/failure, Run Backup Now, attempt history and artifact metadata.
23. Failure, Retry and Recovery Rules
Condition
Required behavior
Validation failure
Keep batch in editable state; show field-level errors.
Approval rejection
Preserve decision evidence; return only through explicit workflow.
Daraja transport failure
Classify as retryable/non-retryable before retry.
Provider timeout
Move to TIMEOUT/RECONCILIATION; do not blindly resend.
Duplicate callback
Ignore as duplicate after validation while retaining evidence.
Worker crash
Job remains recoverable through durable queue state and idempotency records.
Database connectivity failure
Retry with bounded backoff; do not acknowledge durable payment work before persistence.
Backup target failure
Mark FAILED; do not count failed artifact toward retention; keep last successful backup visible.
Backup credential rotation
Validate new credentials before enabling them; preserve audit evidence of change.
Unauthorized privileged command
Reject server-side and record a security event where appropriate.

24. Test and Verification Requirements
Attempt every privileged command with insufficient roles and confirm server-side denial.
Attempt self-approval and creator/approver conflict and confirm hard block.
Change a payment amount after Level 3 review and confirm the prior signature becomes invalid.
Replay an authorization request and confirm nonce/expiry/state checks prevent reuse.
Attempt to forge SUCCESS through an API path and confirm it is rejected.
Rotate Daraja credentials and confirm prior credential references are no longer used for new requests.
Submit duplicate callback payloads and confirm state correctness.
Force a provider timeout and confirm the system enters controlled reconciliation rather than blind retry.
Run backup with valid S3 configuration and verify object creation plus immutable attempt evidence.
Run backup with invalid credentials and verify FAILED status is visible and no false success occurs.
Set a retention count and verify only the oldest eligible successful backups are removed after a new success.
Disable backup scheduling and verify no future scheduled jobs are triggered.
Revoke a trusted device and confirm privileged operations require valid authentication again.
Confirm secrets never appear in UI, API responses, client bundles, logs or exports.
Verify reports use authoritative transaction states and provider identifiers.
Execute a restore drill from an offsite logical backup and record actual recovery measurements.
25. Release Acceptance Criteria
All Level 1/2/3 permissions are enforced server-side and tested.
No SMS path exists in authentication, approval or recovery.
Level 2 and Level 3 WebAuthn enforcement is active.
Payment authorization is cryptographically bound to the exact approval manifest.
Creator != approver and modifier != final authorizer are enforced.
Daraja secrets are masked and protected; only Level 3 can manage them.
Payment transactions use durable states, idempotency and reconciliation.
Callbacks are asynchronous, replay-aware and state-validated.
Operational, financial and executive reporting produces reproducible numbers from authoritative records.
AI outputs are explainable as decision support and cannot independently release payments.
Production services deploy on Railway with private DB/Redis networking, health checks, variables and pre-deploy migrations.
Offsite S3-compatible backup feature supports configure/test/run/schedule/retention/history.
Backup restoration has been tested at least once before declaring disaster recovery proven.
Production observability, alerting, runbooks and rollback procedures exist.
26. Implementation Sequence
Phase
Area
Deliverables
Phase 0
Project foundation
Repository, environments, CI, Railway project, domain, secure variable strategy, coding standards.
Phase 1
Identity & authority
Users, roles, WebAuthn, devices, sessions, recovery, RBAC/SoD.
Phase 2
Payment domain
Recipients, CSV ingestion, validation, batches, state machine, approval versions.
Phase 3
Daraja execution
Credential configuration, provider client, queues, idempotency, callbacks, reconciliation.
Phase 4
Finance & intelligence
Analytics, risk engine, AI assistant, reports, anomaly/collusion signals.
Phase 5
Backup & DR
S3 configuration, backup jobs, retention, restore drill, backup observability.
Phase 6
Hardening & go-live
Pen testing, security review, load/failure tests, runbooks, production release.

27. Operational Runbooks
Daraja credential rotation and emergency disablement.
Payment stuck in PROCESSING or TIMEOUT.
Callback outage and reconciliation sweep.
Compromised user/device response and session revocation.
High-risk/fraud incident review.
Database outage/failover.
Backup target outage or credential rotation.
Backup restore and disaster-recovery test.
Audit evidence preservation during incident response.
Production rollback and application release rollback.
28. Major Engineering Risks and Controls
Risk
Primary controls
Double payment
Idempotency, durable state, provider correlation, reconciliation before retry.
Privilege escalation
Server-side RBAC, deny-by-default policy, separate privileged endpoints.
Authorization bypass
Fresh WebAuthn, FPAC, manifest signing, nonce/expiry, state validation.
Secret leakage
Masked UI, encrypted persistence, Railway variables for service secrets, logging scrubbers.
Callback spoof/replay
Dedicated endpoint, verification, uniqueness checks, queue and state machine.
AI false positive/negative
AI as advisory layer; deterministic controls and human approval remain authoritative.
Database loss
Railway-native recovery plus independent S3-compatible logical backups and restore drills.
Backup compromise
Least-privilege bucket credentials, encryption, opaque object keys, separate storage account where feasible.
Queue duplication
Job IDs, locking, idempotent handlers, bounded retry and DLQ.
Operational complexity
Modular monolith, explicit state machines, runbooks, staged release and strong observability.

29. Reference Basis
Primary product source: user-provided Intelligent Payment Management System concept document. Its requirements establish the three-level hierarchy, permission boundaries, no-SMS security model, WebAuthn and cryptographic authorization approach, Daraja B2C integration, idempotency/reconciliation, separation of duties, analytics, AI and audit requirements.
Railway verification checked 14 September 2026:
Reference
URL
Use
Railway PostgreSQL
https://docs.railway.com/databases/postgresql
Managed PostgreSQL, high availability, backup/recovery guidance.
Railway Redis
https://docs.railway.com/databases/redis
Managed Redis service and private-by-default database behavior.
Railway Private Networking
https://docs.railway.com/networking/private-networking
Private service-to-service networking and encrypted internal traffic.
Railway Healthchecks
https://docs.railway.com/deployments/healthchecks
Readiness health checks for deployment promotion.
Railway Variables
https://docs.railway.com/variables
Service variables, secret/configuration handling and reference variables.
Railway Cron Jobs
https://docs.railway.com/cron-jobs
Short-lived scheduled jobs, UTC scheduling and execution caveats.
Railway SaaS Backend Guide
https://docs.railway.com/guides/saas-backend
API + worker + Postgres + Redis production pattern.
Railway Postgres Backup/Restore Guide
https://docs.railway.com/guides/postgres-backups-restores
Layered backup strategy and offsite logical dump guidance.
Safaricom Daraja 3.0 B2C
https://developer.safaricom.co.ke/apis/BusinessToCustomer
Current Safaricom developer portal reference for Business to Customer API.
Safaricom Daraja APIs
https://developer.safaricom.co.ke/apis
Current Daraja API catalog and developer portal.

30. Decisions Requiring Confirmation
Final application framework and ORM/database driver.
Exact Railway production region and scaling profile.
Whether Cloudflare will sit in front of the Railway public service for DNS/WAF/rate limiting.
Exact Daraja production contract, callback requirements and approved limits for the customer organization.
Exact S3-compatible provider, bucket ownership model, object-lock/versioning policy and encryption method.
Backup cadence, retention count and organization-specific RPO/RTO targets.
Whether backup encryption is provider-managed, application-encrypted, or both.
Final cryptographic design for FPAC and transaction signing after security review.
Exact AI model/provider, data-residency requirements and whether financial data may leave the chosen execution environment.
Organization-specific approval thresholds, cut-off times, holiday calendars and cooling-off periods.
BASELINE DECISIONSOLVAREN Payment Solutions shall be implemented as a controlled payment-management platform on Railway, with external S3-compatible offsite backups, layered authentication and cryptographic payment authorization. The product must favor verifiable financial integrity over convenience wherever the two conflict.


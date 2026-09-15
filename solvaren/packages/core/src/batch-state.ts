/**
 * Payment batch lifecycle state machine (spec §6).
 *
 *   DRAFT → VALIDATED → SUBMITTED_TO_L2 → L2_REVIEW → L3_READY
 *         → AUTHORIZATION_PENDING → AUTHORIZED → QUEUED → SUBMITTED → PROCESSING
 *         → SUCCESS / PARTIAL_SUCCESS / FAILED / TIMEOUT
 *   Side states: RETURNED_FOR_CORRECTION, ON_HOLD, REJECTED, CANCELLED
 *
 * The machine is closed: `assertTransition` is the only way a batch changes state, it is
 * called inside the same database transaction that writes the new row, and every edge
 * names the permission and authority level required to traverse it. There is deliberately
 * no FORCE_STATE command — not even L3 can force a batch to SUCCESS.
 */

import { authorizationError, stateError } from './errors.js';
import type { AuthorityLevel, Permission } from './rbac.js';

export const BATCH_STATES = [
  'DRAFT',
  'VALIDATED',
  'SUBMITTED_TO_L2',
  'L2_REVIEW',
  'RETURNED_FOR_CORRECTION',
  'L3_READY',
  'AUTHORIZATION_PENDING',
  'AUTHORIZED',
  'QUEUED',
  'SUBMITTED',
  'PROCESSING',
  'SUCCESS',
  'PARTIAL_SUCCESS',
  'FAILED',
  'TIMEOUT',
  'ON_HOLD',
  'REJECTED',
  'CANCELLED',
] as const;

export type BatchState = (typeof BATCH_STATES)[number];

/** States in which the instruction set may still be edited by its owners. */
export const EDITABLE_STATES: readonly BatchState[] = [
  'DRAFT',
  'VALIDATED',
  'RETURNED_FOR_CORRECTION',
];

/** Terminal states — no outbound edges at all. */
export const TERMINAL_STATES: readonly BatchState[] = [
  'SUCCESS',
  'PARTIAL_SUCCESS',
  'FAILED',
  'CANCELLED',
];

export const BATCH_COMMANDS = [
  'VALIDATE',
  'INVALIDATE',
  'SUBMIT_TO_L2',
  'BEGIN_L2_REVIEW',
  'APPROVE_TO_L3',
  'REJECT',
  'RETURN_TO_L1',
  'HOLD',
  'RELEASE_HOLD',
  'BEGIN_AUTHORIZATION',
  'ABANDON_AUTHORIZATION',
  'AUTHORIZE',
  'ENQUEUE',
  'MARK_SUBMITTED',
  'MARK_PROCESSING',
  'SETTLE_SUCCESS',
  'SETTLE_PARTIAL',
  'SETTLE_FAILED',
  'SETTLE_TIMEOUT',
  'CANCEL',
] as const;

export type BatchCommand = (typeof BATCH_COMMANDS)[number];

export interface BatchEdge {
  readonly from: BatchState;
  readonly command: BatchCommand;
  readonly to: BatchState;
  /** Permission the actor must hold. `null` = system-driven only. */
  readonly permission: Permission | null;
  readonly minimumLevel: AuthorityLevel | null;
  readonly systemOnly: boolean;
  /** Human-readable purpose, surfaced in the batch state timeline UI. */
  readonly describes: string;
}

const E = (
  from: BatchState,
  command: BatchCommand,
  to: BatchState,
  permission: Permission | null,
  minimumLevel: AuthorityLevel | null,
  describes: string,
  systemOnly = false,
): BatchEdge => ({ from, command, to, permission, minimumLevel, systemOnly, describes });

export const BATCH_EDGES: readonly BatchEdge[] = [
  // ---- Level 1 preparation -------------------------------------------------
  E('DRAFT', 'VALIDATE', 'VALIDATED', 'batch:validate', 'L1', 'All instructions passed validation'),
  E('VALIDATED', 'INVALIDATE', 'DRAFT', 'batch:edit', 'L1', 'Batch edited after validation; revalidation required'),
  E('RETURNED_FOR_CORRECTION', 'INVALIDATE', 'DRAFT', 'batch:edit', 'L1', 'Returned batch edited; back to draft'),
  E('VALIDATED', 'SUBMIT_TO_L2', 'SUBMITTED_TO_L2', 'batch:submit_to_l2', 'L1', 'Submitted to Finance Control; approval version frozen'),
  E('RETURNED_FOR_CORRECTION', 'SUBMIT_TO_L2', 'SUBMITTED_TO_L2', 'batch:submit_to_l2', 'L1', 'Corrected and resubmitted to Finance Control'),
  E('DRAFT', 'CANCEL', 'CANCELLED', 'batch:cancel', 'L1', 'Draft abandoned'),
  E('VALIDATED', 'CANCEL', 'CANCELLED', 'batch:cancel', 'L1', 'Validated batch abandoned before submission'),
  E('RETURNED_FOR_CORRECTION', 'CANCEL', 'CANCELLED', 'batch:cancel', 'L1', 'Returned batch abandoned'),

  // ---- Level 2 financial review -------------------------------------------
  E('SUBMITTED_TO_L2', 'BEGIN_L2_REVIEW', 'L2_REVIEW', 'batch:review', 'L2', 'Finance review opened'),
  E('L2_REVIEW', 'APPROVE_TO_L3', 'L3_READY', 'batch:approve_to_l3', 'L2', 'Approved and forwarded for executive authorization'),
  E('L2_REVIEW', 'REJECT', 'REJECTED', 'batch:reject', 'L2', 'Rejected; evidence preserved'),
  E('L2_REVIEW', 'RETURN_TO_L1', 'RETURNED_FOR_CORRECTION', 'batch:reject', 'L2', 'Returned for correction'),
  E('L2_REVIEW', 'HOLD', 'ON_HOLD', 'batch:hold', 'L2', 'Placed on hold pending clarification'),
  E('SUBMITTED_TO_L2', 'HOLD', 'ON_HOLD', 'batch:hold', 'L2', 'Placed on hold pending clarification'),
  E('SUBMITTED_TO_L2', 'REJECT', 'REJECTED', 'batch:reject', 'L2', 'Rejected before review'),

  // ---- Level 3 authorization -----------------------------------------------
  E('L3_READY', 'HOLD', 'ON_HOLD', 'batch:hold', 'L3', 'Executive hold'),
  E('L3_READY', 'REJECT', 'REJECTED', 'batch:reject', 'L3', 'Rejected by executive authority'),
  E('L3_READY', 'CANCEL', 'CANCELLED', 'batch:cancel', 'L3', 'Cancelled before release'),
  E('L3_READY', 'BEGIN_AUTHORIZATION', 'AUTHORIZATION_PENDING', 'payment:authorize', 'L3', 'Authorization ceremony opened; manifest challenge issued'),
  E('AUTHORIZATION_PENDING', 'ABANDON_AUTHORIZATION', 'L3_READY', 'payment:authorize', 'L3', 'Authorization ceremony abandoned or challenge expired'),
  E('AUTHORIZATION_PENDING', 'AUTHORIZE', 'AUTHORIZED', 'payment:release', 'L3', 'Manifest signed; payment release authorized'),
  E('AUTHORIZATION_PENDING', 'CANCEL', 'CANCELLED', 'batch:cancel', 'L3', 'Cancelled during authorization'),

  // ---- Hold handling ---------------------------------------------------------
  E('ON_HOLD', 'RELEASE_HOLD', 'L2_REVIEW', 'batch:release_hold', 'L2', 'Hold lifted; returned to the review queue'),
  E('ON_HOLD', 'CANCEL', 'CANCELLED', 'batch:cancel', 'L3', 'Held batch cancelled'),

  // ---- Execution (system-driven only) ---------------------------------------
  E('AUTHORIZED', 'ENQUEUE', 'QUEUED', null, null, 'Dispatched to the payment execution queue', true),
  E('QUEUED', 'MARK_SUBMITTED', 'SUBMITTED', null, null, 'Instructions submitted to Daraja', true),
  E('QUEUED', 'MARK_PROCESSING', 'PROCESSING', null, null, 'Provider acknowledged; awaiting results', true),
  E('SUBMITTED', 'MARK_PROCESSING', 'PROCESSING', null, null, 'Provider acknowledged; awaiting results', true),
  E('PROCESSING', 'SETTLE_SUCCESS', 'SUCCESS', null, null, 'All instructions succeeded', true),
  E('PROCESSING', 'SETTLE_PARTIAL', 'PARTIAL_SUCCESS', null, null, 'Batch settled with one or more failures', true),
  E('PROCESSING', 'SETTLE_FAILED', 'FAILED', null, null, 'All instructions failed', true),
  E('PROCESSING', 'SETTLE_TIMEOUT', 'TIMEOUT', null, null, 'Provider outcome unresolved; reconciliation engaged', true),
  E('SUBMITTED', 'SETTLE_TIMEOUT', 'TIMEOUT', null, null, 'No provider acknowledgement; reconciliation engaged', true),
  E('TIMEOUT', 'SETTLE_SUCCESS', 'SUCCESS', null, null, 'Reconciliation resolved every instruction as successful', true),
  E('TIMEOUT', 'SETTLE_PARTIAL', 'PARTIAL_SUCCESS', null, null, 'Reconciliation resolved the batch with failures', true),
  E('TIMEOUT', 'SETTLE_FAILED', 'FAILED', null, null, 'Reconciliation resolved every instruction as failed', true),
];

const EDGE_INDEX = new Map<string, BatchEdge>();
for (const edge of BATCH_EDGES) EDGE_INDEX.set(`${edge.from}::${edge.command}`, edge);

export interface TransitionActor {
  level: AuthorityLevel;
  permissions: ReadonlySet<Permission>;
}

export interface TransitionOptions {
  system?: boolean;
  actor?: TransitionActor;
}

/**
 * Validate and resolve a transition. Throws rather than returning a boolean so that a
 * caller cannot accidentally ignore the result and write the row anyway.
 */
export function assertTransition(
  from: BatchState,
  command: BatchCommand,
  options: TransitionOptions = {},
): BatchEdge {
  const edge = EDGE_INDEX.get(`${from}::${command}`);
  if (!edge) {
    throw stateError('BATCH_TRANSITION_INVALID', `Command ${command} is not valid for a batch in state ${from}`, {
      from,
      command,
      allowed: allowedCommands(from),
    });
  }

  if (edge.systemOnly) {
    if (!options.system) {
      throw authorizationError(
        'BATCH_TRANSITION_SYSTEM_ONLY',
        `Command ${command} may only be issued by the payment execution system`,
        { command },
      );
    }
    return edge;
  }

  // A human-driven edge always requires a human actor; `system: true` must not be a
  // skeleton key that lets a worker bypass the approval chain.
  if (!options.actor) {
    throw authorizationError('BATCH_TRANSITION_ACTOR_REQUIRED', `Command ${command} requires an authenticated actor`, {
      command,
    });
  }
  // The edge names the authority level that owns it. An actor holding the permission
  // through some other level's grant still may not traverse a level-specific edge:
  // approval belongs to L2 alone, authorization to L3 alone.
  if (edge.minimumLevel && options.actor.level !== edge.minimumLevel) {
    throw authorizationError(
      'BATCH_TRANSITION_LEVEL_MISMATCH',
      `Command ${command} belongs to ${edge.minimumLevel} authority; ${options.actor.level} may not perform it`,
      { command, requiredLevel: edge.minimumLevel, actorLevel: options.actor.level },
    );
  }
  if (edge.permission && !options.actor.permissions.has(edge.permission)) {
    throw authorizationError(
      'BATCH_TRANSITION_PERMISSION_DENIED',
      `Command ${command} requires the ${edge.permission} permission`,
      { command, permission: edge.permission },
    );
  }
  return edge;
}

export function canTransition(from: BatchState, command: BatchCommand): boolean {
  return EDGE_INDEX.has(`${from}::${command}`);
}

export function allowedCommands(from: BatchState): BatchCommand[] {
  return BATCH_EDGES.filter((e) => e.from === from).map((e) => e.command);
}

export function isEditable(state: BatchState): boolean {
  return EDITABLE_STATES.includes(state);
}

export function isTerminal(state: BatchState): boolean {
  return TERMINAL_STATES.includes(state);
}

/** States at or beyond which money may already have moved. */
export function hasLeftTheBuilding(state: BatchState): boolean {
  return (
    state === 'QUEUED' ||
    state === 'SUBMITTED' ||
    state === 'PROCESSING' ||
    state === 'SUCCESS' ||
    state === 'PARTIAL_SUCCESS' ||
    state === 'FAILED' ||
    state === 'TIMEOUT'
  );
}

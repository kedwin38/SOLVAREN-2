/**
 * Parsing and interpretation of Daraja result callbacks.
 *
 * Daraja's callback shape is inconsistent in ways that break naive parsers:
 *   - `ResultParameter` is an array for multi-value results and a bare object for one;
 *   - `ResultCode` arrives as a number on some endpoints and a string on others;
 *   - amounts arrive as numbers, strings, or pipe-delimited account strings;
 *   - `TransactionCompletedDateTime` is `dd.MM.yyyy HH:mm:ss` while `TransCompletedTime`
 *     on other endpoints is a 14-digit `yyyyMMddHHmmss`.
 *
 * Every one of those is handled here, once, so the rest of the platform sees clean data.
 * East Africa Time is UTC+3 year-round — Kenya observes no daylight saving.
 */

import { resultCallbackSchema, type DarajaResultCallback, type DarajaTransactionStatus, type OrganizationAccountBalance } from './types.js';

export interface NormalizedResultParameters {
  [key: string]: string | number | undefined;
}

/** Collapse Daraja's object-or-array shapes into a plain record. */
export function normalizeResultParameters(callback: DarajaResultCallback): NormalizedResultParameters {
  const out: NormalizedResultParameters = {};
  const collect = (
    entry: { Key: string; Value?: string | number } | { Key: string; Value?: string | number }[],
  ) => {
    const list = Array.isArray(entry) ? entry : [entry];
    for (const item of list) {
      if (item && typeof item.Key === 'string') out[item.Key] = item.Value;
    }
  };
  const params = callback.Result.ResultParameters?.ResultParameter;
  if (params) collect(params);
  const reference = callback.Result.ReferenceData?.ReferenceItem;
  if (reference) collect(reference);
  return out;
}

export interface ParsedB2cResult {
  /** `0` means the payout succeeded. */
  resultCode: string;
  resultDescription: string;
  originatorConversationId: string | null;
  conversationId: string | null;
  /** M-PESA receipt, e.g. `SG632NMUAB`. Present only on success. */
  transactionReceipt: string | null;
  transactionAmountCents: number | null;
  receiverPartyPublicName: string | null;
  /** Parsed from `dd.MM.yyyy HH:mm:ss`, as an ISO-8601 UTC string. */
  completedAt: string | null;
  recipientIsRegistered: boolean | null;
  utilityAccountBalanceCents: number | null;
  workingAccountBalanceCents: number | null;
  chargesPaidAccountBalanceCents: number | null;
  succeeded: boolean;
  raw: DarajaResultCallback;
}

function toStringValue(value: string | number | undefined): string | null {
  if (value === undefined || value === null) return null;
  const s = String(value).trim();
  return s === '' ? null : s;
}

/** Convert a Daraja money value ("12000", 12000, "12,000.00") to integer cents. */
export function toCents(value: string | number | undefined): number | null {
  const s = toStringValue(value);
  if (s === null) return null;
  const cleaned = s.replace(/,/g, '');
  const numeric = Number(cleaned);
  if (!Number.isFinite(numeric)) return null;
  return Math.round(numeric * 100);
}

/** Parse `dd.MM.yyyy HH:mm:ss` (B2C) or `yyyyMMddHHmmss` (balance/top-up) into ISO-8601. */
export function parseDarajaTimestamp(value: string | number | undefined): string | null {
  const s = toStringValue(value);
  if (s === null) return null;

  const dotted = s.match(/^(\d{2})\.(\d{2})\.(\d{4})\s+(\d{2}):(\d{2}):(\d{2})$/);
  if (dotted) {
    const [, dd, MM, yyyy, HH, mm, ss] = dotted;
    return eatToIso(Number(yyyy), Number(MM), Number(dd), Number(HH), Number(mm), Number(ss));
  }

  const compact = s.match(/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$/);
  if (compact) {
    const [, yyyy, MM, dd, HH, mm, ss] = compact;
    return eatToIso(Number(yyyy), Number(MM), Number(dd), Number(HH), Number(mm), Number(ss));
  }

  const parsed = Date.parse(s);
  return Number.isNaN(parsed) ? null : new Date(parsed).toISOString();
}

function eatToIso(y: number, m: number, d: number, h: number, min: number, s: number): string | null {
  const ms = Date.UTC(y, m - 1, d, h - 3, min, s);
  if (Number.isNaN(ms)) return null;
  return new Date(ms).toISOString();
}

export function parseB2cResult(payload: unknown): ParsedB2cResult {
  const callback = resultCallbackSchema.parse(payload);
  const params = normalizeResultParameters(callback);
  const result = callback.Result;
  const resultCode = String(result.ResultCode).trim();

  return {
    resultCode,
    resultDescription: result.ResultDesc ?? '',
    originatorConversationId: result.OriginatorConversationID ?? null,
    conversationId: result.ConversationID ?? null,
    transactionReceipt: toStringValue(params.TransactionReceipt),
    transactionAmountCents: toCents(params.TransactionAmount),
    receiverPartyPublicName: toStringValue(params.ReceiverPartyPublicName),
    completedAt: parseDarajaTimestamp(params.TransactionCompletedDateTime),
    recipientIsRegistered: flag(params.B2CRecipientIsRegisteredCustomer),
    utilityAccountBalanceCents: toCents(params.B2CUtilityAccountAvailableFunds),
    workingAccountBalanceCents: toCents(params.B2CWorkingAccountAvailableFunds),
    chargesPaidAccountBalanceCents: toCents(params.B2CChargesPaidAccountAvailableFunds),
    succeeded: resultCode === '0',
    raw: callback,
  };
}

function flag(value: string | number | undefined): boolean | null {
  const s = toStringValue(value);
  if (s === null) return null;
  if (s === 'Y' || s === 'y' || s === 'true' || s === '1') return true;
  if (s === 'N' || s === 'n' || s === 'false' || s === '0') return false;
  return null;
}

// ---------------------------------------------------------------------------
// Transaction Status results
// ---------------------------------------------------------------------------

export interface ParsedTransactionStatusResult {
  resultCode: string;
  resultDescription: string;
  originatorConversationId: string | null;
  conversationId: string | null;
  /** M-PESA receipt number, when the transaction reached completion. */
  receiptNumber: string | null;
  /** Provider lifecycle status, e.g. "Completed", "Declined". */
  transactionStatus: DarajaTransactionStatus | string | null;
  amountCents: number | null;
  initiatedTime: string | null;
  finalisedTime: string | null;
}

export function parseTransactionStatusResult(payload: unknown): ParsedTransactionStatusResult {
  const callback = resultCallbackSchema.parse(payload);
  const params = normalizeResultParameters(callback);
  const result = callback.Result;

  return {
    resultCode: String(result.ResultCode).trim(),
    resultDescription: result.ResultDesc ?? '',
    originatorConversationId: result.OriginatorConversationID ?? null,
    conversationId: result.ConversationID ?? null,
    receiptNumber: toStringValue(params.ReceiptNo),
    transactionStatus: toStringValue(params.TransactionStatus),
    amountCents: toCents(params.Amount),
    initiatedTime: parseDarajaTimestamp(params.InitiatedTime),
    finalisedTime: parseDarajaTimestamp(params.FinalisedTime),
  };
}

export type StatusOutcome = 'SUCCESS' | 'FAILED' | 'PENDING' | 'UNKNOWN';

/** Map the provider lifecycle vocabulary onto our four-way outcome. */
export function interpretTransactionStatus(status: DarajaTransactionStatus | string | null): StatusOutcome {
  switch (status) {
    case 'Completed':
      return 'SUCCESS';
    case 'Cancelled':
    case 'Declined':
    case 'Expired':
      return 'FAILED';
    case 'Initiated':
    case 'Authorized':
    case 'Pending Authorized':
      return 'PENDING';
    default:
      return 'UNKNOWN';
  }
}

// ---------------------------------------------------------------------------
// Account Balance results
// ---------------------------------------------------------------------------

export interface ParsedAccountBalanceResult {
  resultCode: string;
  /** Parsed from the pipe-delimited `&`-separated `AccountBalance` parameter. */
  accounts: OrganizationAccountBalance[];
  completedAt: string | null;
}

export function parseAccountBalanceResult(payload: unknown): ParsedAccountBalanceResult {
  const callback = resultCallbackSchema.parse(payload);
  const params = normalizeResultParameters(callback);
  const raw = toStringValue(params.AccountBalance) ?? '';
  const accounts: OrganizationAccountBalance[] = [];

  for (const entry of raw.split('&')) {
    if (entry.trim() === '') continue;
    // Format per account: AccountType|Currency|AvailableBalance|UnclearedFunds|ReservedFunds|...
    const parts = entry.split('|');
    if (parts.length < 3) continue;
    accounts.push({
      accountType: parts[0]!.trim(),
      currency: parts[1]?.trim() || 'KES',
      availableBalanceCents: toCents(parts[2]) ?? 0,
      unclearedBalanceCents: toCents(parts[3]) ?? 0,
      reservedBalanceCents: toCents(parts[4]) ?? 0,
    });
  }

  return {
    resultCode: String(callback.Result.ResultCode).trim(),
    accounts,
    completedAt: parseDarajaTimestamp(params.BOCompletedTime),
  };
}

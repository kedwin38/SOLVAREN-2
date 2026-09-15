/**
 * Money.
 *
 * Two rules govern the entire platform:
 *   1. Amounts exist as integer **minor units** (cents) everywhere — database, memory,
 *      manifest, exports. Floating point never touches an amount.
 *   2. Formatting is a presentation concern, performed exactly once, at the edge.
 *
 * M-PESA B2C constraints (per the Daraja contract): minimum KES 10, maximum KES 250,000
 * per transaction; whole-shilling amounts are enforced at ingestion as an explicit,
 * documented policy choice (payroll amounts with cents are rejected with a clear reason
 * rather than silently rounded).
 */

export const CURRENCY = 'KES' as const;

export const DARAJA_B2C_MIN_CENTS = 1_000; // KES 10
export const DARAJA_B2C_MAX_CENTS = 25_000_000; // KES 250,000

/** Add integer cents, refusing to run past IEEE-754 integer safety. */
export function sumCents(values: readonly number[]): number {
  let total = 0;
  for (const v of values) {
    if (!Number.isSafeInteger(v)) {
      throw new Error(`sumCents: ${v} is not a safe integer amount`);
    }
    total += v;
  }
  if (!Number.isSafeInteger(total)) {
    throw new Error('sumCents: total exceeds safe integer range');
  }
  return total;
}

/**
 * Parse a human amount ("12000", "12,000.00", "12 000", "KES 1,200") into integer cents.
 * Throws a VALIDATION SolvarenError with a field-ready message on anything ambiguous.
 */
export function parseAmountToCents(raw: string): number {
  const trimmed = raw.trim();
  if (trimmed === '') {
    throw amountError('An amount is required');
  }
  const cleaned = trimmed
    .replace(/^kes/i, '')
    .replace(/[,\s_]/g, '')
    .trim();
  if (!/^\d+(\.\d{1,2})?$/.test(cleaned)) {
    throw amountError(`"${raw.trim()}" is not a valid amount`);
  }
  const cents = Math.round(Number(cleaned) * 100);
  if (!Number.isSafeInteger(cents)) {
    throw amountError(`"${raw.trim()}" is too large`);
  }
  return cents;
}

function amountError(message: string): Error & { code: string } {
  const err = new Error(message) as Error & { code: string };
  err.name = 'AmountInvalid';
  err.code = 'AMOUNT_INVALID';
  return err;
}

/** "12,345.50" — grouping by thousands, always two decimals, no currency symbol. */
export function formatCents(cents: number): string {
  if (!Number.isSafeInteger(cents)) {
    throw new Error(`formatCents: ${cents} is not an integer amount of cents`);
  }
  const negative = cents < 0;
  const abs = Math.abs(cents);
  const whole = Math.floor(abs / 100);
  const frac = abs % 100;
  const grouped = whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return `${negative ? '-' : ''}${grouped}.${frac.toString().padStart(2, '0')}`;
}

/** "12000.00" — Daraja's `Amount` field: no separators, always two decimals. */
export function centsToDarajaAmount(cents: number): string {
  return (cents / 100).toFixed(2);
}

/** Whole-shilling policy: M-PESA payroll disbursements are whole shillings. */
export function isWholeShillings(cents: number): boolean {
  return cents % 100 === 0;
}

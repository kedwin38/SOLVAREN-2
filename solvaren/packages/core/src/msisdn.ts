/**
 * Kenyan MSISDN handling.
 *
 * The canonical form everywhere in SOLVAREN is the 12-digit international format without
 * `+`: `2547XXXXXXXX` or `2541XXXXXXXX` (the 2541x range is Safaricom's expanded
 * numbering). The database enforces this shape with a CHECK constraint; this module is
 * where user input becomes that shape, with exact reasons when it cannot.
 */

import { validationError } from './errors.js';

export const MSISDN_PATTERN = /^254(7|1)\d{8}$/;

export type MsisdnResult = { ok: true; msisdn: string } | { ok: false; reason: string };

/** Lenient parse: accepts 07…, +2547…, 2547…, and 7… with or without spaces/dashes. */
export function tryNormalizeMsisdn(raw: string): MsisdnResult {
  const cleaned = raw.replace(/[\s\-().]/g, '');
  if (cleaned === '') return { ok: false, reason: 'A phone number is required' };

  let digits = cleaned.replace(/^\+/, '');

  if (digits.startsWith('0')) {
    digits = `254${digits.slice(1)}`;
  } else if (/^7\d{8}$/.test(digits) || /^1\d{8}$/.test(digits)) {
    digits = `254${digits}`;
  }

  if (!/^\d+$/.test(digits)) {
    return { ok: false, reason: `"${raw.trim()}" contains characters other than digits` };
  }
  if (!MSISDN_PATTERN.test(digits)) {
    if (digits.length < 12) {
      return { ok: false, reason: `"${raw.trim()}" is too short for a Kenyan mobile number` };
    }
    if (digits.length > 12) {
      return { ok: false, reason: `"${raw.trim()}" is too long for a Kenyan mobile number` };
    }
    return {
      ok: false,
      reason: `"${raw.trim()}" is not a valid Safaricom number (expected 07…, 01…, 2547… or 2541… format)`,
    };
  }
  return { ok: true, msisdn: digits };
}

/** Throwing variant for paths that have already promised a valid number. */
export function normalizeMsisdn(raw: string): string {
  const result = tryNormalizeMsisdn(raw);
  if (!result.ok) {
    throw validationError('MSISDN_INVALID', result.reason);
  }
  return result.msisdn;
}

export function isValidMsisdn(raw: string): boolean {
  return tryNormalizeMsisdn(raw).ok;
}

/** "•••• ••• 456" — list views never show a full payroll of numbers to a broad audience. */
export function maskMsisdn(msisdn: string): string {
  if (!MSISDN_PATTERN.test(msisdn)) return '••••';
  return `•••• ••• ${msisdn.slice(-3)}`;
}

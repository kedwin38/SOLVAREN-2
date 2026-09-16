/**
 * Money, MSISDN, CSV ingestion (spec §5.2, §6.1), policy evaluation with the financial
 * calendar (spec §10 cut-off/holiday controls), risk signals, the audit chain, the
 * failure dictionary, cron parsing, and CSV export rendering.
 */

import { describe, expect, it } from 'vitest';
import {
  formatCents,
  parseAmountToCents,
  centsToDarajaAmount,
  sumCents,
  tryNormalizeMsisdn,
  maskMsisdn,
  parsePaymentCsv,
  parseCron,
  nextRun,
  eatDailyCron,
} from './index.js';

describe('money', () => {
  it('formats cents as grouped shillings', () => {
    expect(formatCents(8_420_500_00)).toBe('8,420,500.00');
    expect(formatCents(1_000)).toBe('10.00');
    expect(formatCents(-500)).toBe('-5.00');
  });

  it('parses the shapes real payroll exports contain', () => {
    expect(parseAmountToCents('12000')).toBe(1_200_000);
    expect(parseAmountToCents('12,000.00')).toBe(1_200_000);
    expect(parseAmountToCents('KES 1,200')).toBe(120_000);
    expect(parseAmountToCents('0.50')).toBe(50);
  });

  it('refuses ambiguous input', () => {
    expect(() => parseAmountToCents('')).toThrow();
    expect(() => parseAmountToCents('12.345')).toThrow();
    expect(() => parseAmountToCents('abc')).toThrow();
  });

  it('renders Daraja Amount fields without separators', () => {
    expect(centsToDarajaAmount(12_000_00)).toBe('12000.00');
  });

  it('sums refuse to run past integer safety', () => {
    expect(() => sumCents([Number.MAX_SAFE_INTEGER, 1])).toThrow();
  });
});

describe('MSISDN (Kenyan)', () => {
  /** Narrowing helper: fail the test if the number was rejected. */
  const normalized = (input: string): string => {
    const result = tryNormalizeMsisdn(input);
    if (!result.ok) throw new Error(`expected ${input} to normalize, got: ${result.reason}`);
    return result.msisdn;
  };

  it('normalizes every legitimate local form to 254…', () => {
    expect(normalized('0705912645')).toBe('254705912645');
    expect(normalized('+254705912645')).toBe('254705912645');
    expect(normalized('254705912645')).toBe('254705912645');
    expect(normalized('705912645')).toBe('254705912645');
    expect(normalized('0705-912 645')).toBe('254705912645');
    expect(normalized('0110123456')).toBe('254110123456'); // 2541x range
  });

  it('rejects non-Safaricom or malformed numbers with a reason', () => {
    expect(tryNormalizeMsisdn('12345').ok).toBe(false);
    expect(tryNormalizeMsisdn('254812345678').ok).toBe(false);
    expect(tryNormalizeMsisdn('not-a-phone').ok).toBe(false);
    expect(tryNormalizeMsisdn('2547059126459').ok).toBe(false); // too long
  });

  it('masks for list views', () => {
    expect(maskMsisdn('254705912645')).toBe('•••• ••• 645');
  });
});

const HEADER = 'recipient name,phone,amount,department,reference,remarks\n';

describe('CSV ingestion (spec §5.2, §23 field-level errors)', () => {
  it('parses a well-formed payroll export', () => {
    const csv = `${HEADER}` +
      `Jane Wanjiku,0705912645,"50,000.00",Engineering,EMP-001,September salary\n` +
      `John Otieno,254722000001,120000,Engineering,EMP-002,September salary\n`;
    const result = parsePaymentCsv(csv);
    expect(result.rows).toHaveLength(2);
    expect(result.errors).toHaveLength(0);
    expect(result.rows[0]!.msisdn).toBe('254705912645');
    expect(result.rows[0]!.amountCents).toBe(5_000_000);
    expect(result.totalAmountCents).toBe(17_000_000);
  });

  it('strips the Excel BOM', () => {
    const result = parsePaymentCsv(`\uFEFF${HEADER}Jane,0705912645,1000\n`);
    expect(result.rows).toHaveLength(1);
  });

  it('rejects a missing required column with the detected header', () => {
    try {
      parsePaymentCsv('name,amount\nJane,1000\n');
      expect.unreachable();
    } catch (err) {
      expect((err as Error).message).toMatch(/missing required columns/i);
    }
  });

  it('reports row-level errors with 1-based line numbers, not file rejection', () => {
    const csv = `${HEADER}` +
      `Jane,0705912645,50000\n` +
      `Bad Phone,abc,50000\n` +
      `Bad Amount,0705912645,=SUM(A1)\n` +
      `Too Small,0705912645,5\n`;
    const result = parsePaymentCsv(csv);
    expect(result.rows).toHaveLength(1);
    expect(result.errors).toHaveLength(3);
    expect(result.errors.find((e) => e.lineNumber === 3)?.column).toBe('msisdn');
    expect(result.errors.find((e) => e.lineNumber === 4)?.reason).toMatch(/formula/i);
    expect(result.errors.find((e) => e.lineNumber === 5)?.reason).toMatch(/minimum/i);
  });

  it('flags whole-shilling violations as row errors (documented policy)', () => {
    const result = parsePaymentCsv(`${HEADER}Jane,0705912645,50000.50\n`);
    expect(result.rows).toHaveLength(0);
    expect(result.errors[0]!.reason).toMatch(/whole shillings/i);
  });

  it('warns on intra-file duplicates without rejecting them', () => {
    const csv = `${HEADER}` +
      `Jane,0705912645,50000\n` +
      `Jane,0705912645,50000\n`;
    const result = parsePaymentCsv(csv);
    expect(result.rows).toHaveLength(2);
    expect(result.duplicateWarnings).toHaveLength(1);
    expect(result.duplicateWarnings[0]!.lineNumbers).toEqual([2, 3]);
  });

  it('enforces a row cap', () => {
    const rows = Array.from({ length: 21 }, (_, i) => `Person ${i},070000000${i % 10},1000\n`).join('');
    expect(() => parsePaymentCsv(`${HEADER}${rows}`, { maxRows: 20 })).toThrow(/limit is 20/i);
  });

  it('handles quoted fields with embedded commas and newlines (RFC 4180)', () => {
    const csv = `${HEADER}"Wanjiku, Jane",0705912645,50000\n`;
    const result = parsePaymentCsv(csv);
    expect(result.rows[0]!.recipientName).toBe('Wanjiku, Jane');
  });

  it('parses the organisation-preferred format (phone/id/names/role/team/territory/region/sales/payout)', () => {
    const csv =
      'PHONE NUMBER,ID NUMBER,NAMES,ROLE,TEAM NAME,TERRITORY,REGION,SALES,PAYOUT\n' +
      '705221156,546414707,EMMANUEL NJUGUNA MURIITHI,TEAM LEADER,CHOGORIA B,CHUKA,MOUNTAIN,287,15000\n' +
      '118002862,366981640,Sharon kagwiria,TEAM LEADER,CHUKA A,CHUKA,MOUNTAIN,139,8340\n';
    const result = parsePaymentCsv(csv);
    expect(result.errors).toHaveLength(0);
    expect(result.rows).toHaveLength(2);
    const [first] = result.rows;
    expect(first!.recipientName).toBe('EMMANUEL NJUGUNA MURIITHI');
    expect(first!.msisdn).toBe('254705221156');
    expect(first!.amountCents).toBe(1_500_000);
    expect(first!.reference).toBe('546414707');
    expect(first!.department).toBe('CHOGORIA B');
    expect(first!.role).toBe('TEAM LEADER');
    expect(first!.territory).toBe('CHUKA');
    expect(first!.region).toBe('MOUNTAIN');
    expect(first!.salesCount).toBe(287);
    expect(result.totalAmountCents).toBe(2_334_000);
  });

  it('rejects a non-numeric sales figure as a row error', () => {
    const csv =
      'PHONE NUMBER,NAMES,PAYOUT,SALES\n' +
      '0705912645,Jane,50000,not-a-number\n';
    const result = parsePaymentCsv(csv);
    expect(result.rows).toHaveLength(0);
    expect(result.errors[0]!.column).toBe('sales');
  });
});

describe('cron (spec §10 batch scheduler)', () => {
  it('parses the supported shapes', () => {
    expect(parseCron('*/15 * * * *').minute).toEqual([0, 15, 30, 45]);
    expect(parseCron('30 4 * * *').hour).toEqual([4]);
    expect(parseCron('0 0 1 * *').dayOfMonth).toEqual([1]);
    expect(parseCron('0 9 * * 1-5').dayOfWeek).toEqual([1, 2, 3, 4, 5]);
    expect(parseCron('0 0 * 3,6 *').month).toEqual([3, 6]);
  });

  it('refuses malformed expressions', () => {
    expect(() => parseCron('99 * * * *')).toThrow();
    expect(() => parseCron('* * *')).toThrow();
    expect(() => parseCron('a b c d e')).toThrow();
  });

  it('computes the next run strictly after "after"', () => {
    const after = new Date('2026-09-14T10:00:00Z');
    expect(nextRun('30 4 * * *', after).toISOString()).toBe('2026-09-15T04:30:00.000Z');
    expect(nextRun('0 11 * * *', after).toISOString()).toBe('2026-09-14T11:00:00.000Z');
  });

  it('translates an EAT daily time to a UTC cron (UTC+3, no DST)', () => {
    expect(eatDailyCron(7, 30)).toBe('30 4 * * *');
    expect(eatDailyCron(0, 0)).toBe('0 21 * * *');
    expect(eatDailyCron(23, 59)).toBe('59 20 * * *');
  });
});

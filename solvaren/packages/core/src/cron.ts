/**
 * Cron parsing and schedule computation (spec §10: batch scheduler with cron-like rules,
 * recurring templates, cut-off times, holiday calendars).
 *
 * A dependency-free 5-field cron parser supporting the shapes a payment platform needs:
 * `*`, star-slash-n steps, ranges `a-b`, lists `a,b,c`, and plain values — in the fields
 * minute, hour, day-of-month, month, day-of-week.
 * `nextRun` returns the next firing time strictly after `after`, in UTC.
 *
 * The financial clock is East Africa Time (UTC+3, no DST): schedules are stored in the
 * organization's local time and translated to UTC here, exactly once, at computation
 * time (spec §13.4 note applies to schedules generally).
 */

import { validationError } from './errors.js';

export interface CronSpec {
  minute: number[];
  hour: number[];
  dayOfMonth: number[];
  month: number[];
  dayOfWeek: number[];
}

const FIELD_RANGES: Record<keyof Omit<CronSpec, never>, { min: number; max: number }> = {
  minute: { min: 0, max: 59 },
  hour: { min: 0, max: 23 },
  dayOfMonth: { min: 1, max: 31 },
  month: { min: 1, max: 12 },
  dayOfWeek: { min: 0, max: 6 },
};

function parseField(field: string, name: keyof typeof FIELD_RANGES): number[] {
  const range = FIELD_RANGES[name];
  const values = new Set<number>();

  for (const part of field.split(',')) {
    const pieces = part.split('/');
    const selector = pieces[0] ?? '';
    const stepRaw = pieces.length > 1 ? pieces[1] : undefined;
    const step = stepRaw !== undefined ? Number(stepRaw) : 1;
    if (!Number.isInteger(step) || step < 1) {
      throw validationError('CRON_INVALID', `Invalid step in the ${name} field: "${part}"`);
    }

    let start: number;
    let end: number;
    if (selector === '*') {
      start = range.min;
      end = range.max;
    } else if (selector.includes('-')) {
      const [a, b] = selector.split('-');
      start = Number(a);
      end = Number(b);
    } else {
      start = Number(selector);
      end = stepRaw !== undefined ? range.max : start;
    }
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < range.min || end > range.max || start > end) {
      throw validationError('CRON_INVALID', `Invalid ${name} field: "${field}"`);
    }
    for (let v = start; v <= end; v += step) values.add(v);
  }
  return [...values].sort((a, b) => a - b);
}

export function parseCron(expression: string): CronSpec {
  const fields = expression.trim().split(/\s+/);
  if (fields.length !== 5) {
    throw validationError('CRON_INVALID', 'A schedule needs exactly five fields: minute hour day-of-month month day-of-week');
  }
  return {
    minute: parseField(fields[0]!, 'minute'),
    hour: parseField(fields[1]!, 'hour'),
    dayOfMonth: parseField(fields[2]!, 'dayOfMonth'),
    month: parseField(fields[3]!, 'month'),
    dayOfWeek: parseField(fields[4]!, 'dayOfWeek'),
  };
}

export function isValidCron(expression: string): boolean {
  try {
    parseCron(expression);
    return true;
  } catch {
    return false;
  }
}

/**
 * Next firing time strictly after `after` (ms epoch). Searches minute-by-minute over the
 * next 366 days; a cron that never fires (e.g. `0 0 31 2 *`) throws CRON_NEVER.
 */
export function nextRun(expression: string, after: Date = new Date()): Date {
  const spec = parseCron(expression);
  const minuteSet = new Set(spec.minute);
  const hourSet = new Set(spec.hour);
  const domSet = new Set(spec.dayOfMonth);
  const monthSet = new Set(spec.month);
  const dowSet = new Set(spec.dayOfWeek);

  // Start at the next whole minute strictly after `after`.
  const cursor = new Date(after.getTime());
  cursor.setSeconds(0, 0);
  cursor.setUTCMinutes(cursor.getUTCMinutes() + 1);

  const limit = cursor.getTime() + 366 * 24 * 60 * 60 * 1000;
  while (cursor.getTime() <= limit) {
    if (
      monthSet.has(cursor.getUTCMonth() + 1) &&
      hourSet.has(cursor.getUTCHours()) &&
      minuteSet.has(cursor.getUTCMinutes()) &&
      dayMatches(cursor, domSet, dowSet)
    ) {
      return new Date(cursor.getTime());
    }
    cursor.setUTCMinutes(cursor.getUTCMinutes() + 1);
  }
  throw validationError('CRON_NEVER', `The schedule "${expression}" never fires within a year`);
}

function dayMatches(cursor: Date, domSet: Set<number>, dowSet: Set<number>): boolean {
  const domRestricted = !domSet.has(cursor.getUTCDate());
  const dow = cursor.getUTCDay();
  const dowNormalized = dow === 0 ? 7 : dow; // treat Sunday as 7 for range friendliness
  const dowMatches = dowSet.has(dow) || dowSet.has(dowNormalized);
  const dowRestricted = !dowMatches;
  // Standard cron semantics: if both DOM and DOW are restricted, either may match (OR).
  if (domSet.size === 31 && dowSet.size === 7) return true;
  if (domSet.size !== 31 && dowSet.size === 7) return !domRestricted;
  if (domSet.size === 31 && dowSet.size !== 7) return !dowRestricted;
  return !domRestricted || !dowRestricted;
}

/** East Africa Time is UTC+3 year-round. */
export const EAT_OFFSET_MINUTES = 180;

/**
 * Translate a local EAT wall-clock time into a cron expression in UTC fields.
 * Example: daily at 07:30 Nairobi → "30 4 * * *".
 */
export function eatDailyCron(localHour: number, localMinute: number): string {
  const utcHour = ((localHour - 3) + 24) % 24;
  return `${localMinute} ${utcHour} * * *`;
}

/** Human description of a cron expression for the settings screen. */
export function describeCron(expression: string): string {
  const spec = parseCron(expression);
  const every = (values: number[], unit: string) =>
    values.length === 1 ? `${unit} ${values[0]}` : `every ${unit} in {${values.join(',')}}`;
  return [every(spec.minute, 'minute'), every(spec.hour, 'hour'), `days ${spec.dayOfMonth.join(',') || '*'}`, `months ${spec.month.join(',') || '*'}`, `weekdays ${spec.dayOfWeek.join(',') || '*'}`].join(' · ');
}

/**
 * PostgreSQL access: one pool, transaction helpers, advisory locks.
 *
 * `withConnection` borrows a connection for read work; `inTransaction` opens a
 * transaction with a sane statement timeout; `requireLock` takes a transaction-scoped
 * advisory lock so two ceremonies (or two executors) serialise on the same batch or
 * instruction instead of racing.
 */

import postgres from 'postgres';
import type { Env } from '../env.js';

export type Sql = postgres.Sql<{}>;

export function createPool(databaseUrl: string): Sql {
  return postgres(databaseUrl, {
    max: 20,
    idle_timeout: 30,
    connect_timeout: 10,
    // fetch_types costs a round trip per parameter type on first use; disabling it
    // speeds every query, and we cast types explicitly in SQL anyway ($1::uuid etc).
    fetch_types: false,
    onnotice: () => {},
  }) as Sql;
}

export async function withConnection<T>(env: { sql: Sql }, work: (sql: Sql) => Promise<T>): Promise<T> {
  return work(env.sql);
}

export async function inTransaction<T>(sql: Sql, work: (tx: Sql) => Promise<T>): Promise<T> {
  return (sql.begin(async (tx) => {
    await tx`SET LOCAL statement_timeout = '15s'`;
    return work(tx as unknown as Sql);
  }) as unknown) as Promise<T>;
}

/**
 * Transaction-scoped advisory lock, namespaced by kind. The hash of the id is used so
 * any UUID/string works; transaction scope means the lock releases with the commit or
 * rollback — no leak window.
 */
export async function requireLock(tx: Sql, kind: 'batch' | 'instruction' | 'transaction' | 'organization' | `custom:${string}`, id: string): Promise<void> {
  await tx`SELECT pg_advisory_xact_lock(hashtext(${`${kind}:${id}`}))`;
}

/**
 * Array binding, the deterministic way.
 *
 * The driver's sql.array() relies on type introspection to serialise arrays; with
 * fetch_types disabled it emits an empty string for an empty list, which Postgres
 * rejects as "malformed array literal". Binding the array *literal* as a plain text
 * parameter with an explicit cast is immune: the value travels as data (no injection
 * surface), and '{ }' casts cleanly for empty and populated lists alike.
 */
function arrayLiteralValue(values: readonly (string | number)[]): string {
  return `{${values
    .map((v) => `"${String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`)
    .join(',')}}`;
}

/** Any postgres sql template tag — pool or transaction; only the tagged-template call is needed. */
type TemplateSql = (strings: TemplateStringsArray, ...values: unknown[]) => unknown;

/** Set helper: build a Postgres uuid[] parameter from a list of UUIDs. */
export function uuidSet(sql: TemplateSql, ids: readonly string[]): postgres.Parameter {
  return sql`${arrayLiteralValue(ids)}::uuid[]` as unknown as postgres.Parameter;
}

export function uuidArrayValue(tx: TemplateSql, ids: readonly string[]): postgres.Parameter {
  return tx`${arrayLiteralValue(ids)}::uuid[]` as unknown as postgres.Parameter;
}

/** text[] parameter (policy holiday dates, credential transports, …). */
export function textArrayParam(sql: TemplateSql, values: readonly string[]): postgres.Parameter {
  return sql`${arrayLiteralValue(values)}::text[]` as unknown as postgres.Parameter;
}

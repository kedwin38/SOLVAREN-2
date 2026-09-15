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

/** Set helper: build a Postgres array parameter from a list of UUIDs. */
export function uuidSet(sql: Sql, ids: readonly string[]): postgres.Parameter {
  return sql.array([...ids] as (string | number)[]) as unknown as postgres.Parameter;
}

export function uuidArrayValue(tx: Sql, ids: readonly string[]): postgres.Parameter {
  return tx.array([...ids]) as unknown as postgres.Parameter;
}

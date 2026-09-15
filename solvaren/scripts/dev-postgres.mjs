#!/usr/bin/env node
/**
 * Cross-platform development PostgreSQL helper (delegates to Docker).
 * Usage: node scripts/dev-postgres.mjs up|down|psql
 */

import { execSync, spawn } from 'node:child_process';

const NAME = 'solvaren-pg';
const PORT = process.env.SOLVAREN_PG_PORT ?? '5433';
const command = process.argv[2] ?? 'up';

function docker(...args) {
  return execSync(`docker ${args.join(' ')}`, { encoding: 'utf8' }).trim();
}

switch (command) {
  case 'up': {
    const running = docker('ps', '--format', '{{.Names}}');
    if (running.split('\n').some((n) => n === NAME)) {
      console.log(`Already running on :${PORT}`);
    } else {
      docker(
        'run', '-d', '--name', NAME, '-p', `${PORT}:5432`,
        '-e', 'POSTGRES_PASSWORD=postgres', 'postgres:16',
        '>/dev/null',
      );
      console.log(`Started ${NAME} on :${PORT}`);
    }
    console.log(`  export DATABASE_URL=postgres://postgres:postgres@localhost:${PORT}/postgres`);
    break;
  }
  case 'down':
    try {
      docker('rm', '-f', NAME);
    } catch {
      /* not running */
    }
    console.log(`Stopped ${NAME}`);
    break;
  case 'psql':
    spawn('docker', ['exec', '-it', NAME, 'psql', '-U', 'postgres'], { stdio: 'inherit' });
    break;
  default:
    console.error('Usage: node scripts/dev-postgres.mjs up|down|psql');
    process.exit(1);
}

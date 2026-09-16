/**
 * Configuration: every environment variable validated at boot, before the port opens.
 *
 * A misconfigured payment service must fail loudly at startup, not discover its missing
 * key halfway through a payroll run. `loadConfigOrExit` is the only way configuration
 * enters the process; nothing else reads `process.env`.
 */

import {
  internalError,
  validationError,
} from '@solvaren/core';

export interface Config {
  PORT: number;
  DATABASE_URL: string;
  RUN_WORKERS: boolean;
  RUN_SCHEDULER: boolean;

  SESSION_SIGNING_KEY: string;
  SECRET_ENCRYPTION_KEY: string;
  CALLBACK_SHARED_SECRET?: string;
  AI_API_KEY?: string;
  AI_MODEL?: string;

  ENVIRONMENT: 'development' | 'staging' | 'production';
  APP_ORIGIN: string;
  API_BASE_URL: string;
  WEBAUTHN_RP_ID: string;
  WEBAUTHN_RP_NAME: string;

  S3_ENDPOINT?: string;
  S3_REGION: string;
  S3_BUCKET: string;
  S3_ACCESS_KEY_ID: string;
  S3_SECRET_ACCESS_KEY: string;
  S3_FORCE_PATH_STYLE: boolean;

  /**
   * Whether Cloudflare is verified to be the sole edge in front of this deployment.
   * `CF-Connecting-IP` is client-suppliable and only trustworthy when a proxy the
   * client cannot bypass actually sets it — off by default, since Cloudflare is an
   * optional layer (spec §deployment) and most environments run on Railway's edge
   * alone, which sets `X-Real-IP` instead.
   */
  TRUST_CF_CONNECTING_IP: boolean;
}

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    fail(`The required variable ${name} is not set.`);
  }
  return value;
}

function optional(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

function requiredKey(name: string): string {
  const value = required(name);
  if (value.length < 32) {
    fail(`${name} must be at least 32 characters of high-entropy material (generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))").`);
  }
  return value;
}

function requiredUrl(name: string): string {
  const value = required(name);
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' && !value.startsWith('http://localhost')) {
      fail(`${name} must be an https:// URL in production (got ${value}).`);
    }
  } catch {
    fail(`${name} is not a valid URL (got ${value}).`);
  }
  return value.replace(/\/$/, '');
}

function fail(message: string): never {
  console.error('');
  console.error('  SOLVAREN cannot start: configuration error.');
  console.error(`  ${message}`);
  console.error('');
  process.exit(1);
}

export function loadConfigOrExit(): Config {
  const ENVIRONMENT = (optional('ENVIRONMENT') ?? 'development') as Config['ENVIRONMENT'];
  if (!['development', 'staging', 'production'].includes(ENVIRONMENT)) {
    fail(`ENVIRONMENT must be development, staging or production (got ${ENVIRONMENT}).`);
  }

  const config: Config = {
    PORT: Number(optional('PORT') ?? '8080'),
    DATABASE_URL: required('DATABASE_URL'),
    RUN_WORKERS: (optional('RUN_WORKERS') ?? 'true').toLowerCase() === 'true',
    RUN_SCHEDULER: (optional('RUN_SCHEDULER') ?? 'true').toLowerCase() === 'true',
    TRUST_CF_CONNECTING_IP: (optional('TRUST_CF_CONNECTING_IP') ?? 'false').toLowerCase() === 'true',

    SESSION_SIGNING_KEY: requiredKey('SESSION_SIGNING_KEY'),
    SECRET_ENCRYPTION_KEY: requiredKey('SECRET_ENCRYPTION_KEY'),
    CALLBACK_SHARED_SECRET: optional('CALLBACK_SHARED_SECRET'),
    AI_API_KEY: optional('AI_API_KEY'),
    AI_MODEL: optional('AI_MODEL'),

    ENVIRONMENT,
    APP_ORIGIN: requiredUrl('APP_ORIGIN'),
    API_BASE_URL: requiredUrl('API_BASE_URL'),
    WEBAUTHN_RP_ID: required('WEBAUTHN_RP_ID'),
    WEBAUTHN_RP_NAME: optional('WEBAUTHN_RP_NAME') ?? 'SOLVAREN Payment Solutions',

    S3_ENDPOINT: optional('S3_ENDPOINT'),
    S3_REGION: optional('S3_REGION') ?? 'auto',
    S3_BUCKET: required('S3_BUCKET'),
    S3_ACCESS_KEY_ID: required('S3_ACCESS_KEY_ID'),
    S3_SECRET_ACCESS_KEY: required('S3_SECRET_ACCESS_KEY'),
    S3_FORCE_PATH_STYLE: (optional('S3_FORCE_PATH_STYLE') ?? 'true').toLowerCase() === 'true',
  };

  // A key reused across concerns doubles the blast radius of one leak.
  if (config.SESSION_SIGNING_KEY === config.SECRET_ENCRYPTION_KEY) {
    fail('SESSION_SIGNING_KEY and SECRET_ENCRYPTION_KEY must be different values.');
  }

  // Production refuses to boot on obviously non-production settings.
  if (ENVIRONMENT === 'production') {
    if (config.APP_ORIGIN.startsWith('http://localhost')) {
      fail('APP_ORIGIN must be the public https origin in production.');
    }
    if (config.DATABASE_URL.includes('localhost') && !config.DATABASE_URL.includes('railway')) {
      fail('DATABASE_URL points at localhost in production.');
    }
  }

  if (Number.isNaN(config.PORT) || config.PORT < 1 || config.PORT > 65535) {
    throw validationError('CONFIG_INVALID', `PORT is not a valid port number`);
  }
  return config;
}

export { internalError };

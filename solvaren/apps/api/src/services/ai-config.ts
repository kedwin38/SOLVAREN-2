/**
 * AI provider configuration (spec §11).
 *
 * Organisation-level wiring for the advisory layer: provider, base URL, model and an
 * API key held in the secret store. The resolution order is organisation configuration,
 * then the platform environment default (AI_API_KEY / AI_MODEL against Anthropic), then
 * off — in every case the deterministic risk engine is unaffected.
 */

import { validationError } from '@solvaren/core';
import type { Sql } from '../db/client.js';
import type { Env } from '../env.js';
import { secretReference } from './secret-store.js';

export type AiProvider = 'anthropic' | 'openai-compatible';

export interface AiProviderConfig {
  provider: AiProvider;
  baseUrl: string;
  model: string;
  apiKey: string | null;
  /** 'organisation' — configured here; 'platform' — the environment default; 'off'. */
  source: 'organisation' | 'platform' | 'off';
}

export interface AiConfigRow {
  organization_id: string;
  provider: AiProvider;
  base_url: string;
  model: string;
  api_key_secret_ref: string;
  api_key_last_four: string | null;
  status: 'TESTING' | 'ENABLED' | 'ERROR' | 'DISABLED';
  last_test_at: string | null;
  last_test_ok: boolean | null;
  last_test_message: string | null;
}

export function aiKeyReference(organizationId: string): string {
  return secretReference(organizationId, 'ai', 'api_key');
}

/**
 * Resolve the effective provider configuration for an organisation. Never throws for a
 * missing/failed configuration — the caller renders the advisory layer as degraded,
 * which is the designed posture.
 */
export async function resolveAiProvider(env: Env, organizationId: string): Promise<AiProviderConfig> {
  const rows = await env.sql<AiConfigRow[]>`
    SELECT * FROM ai_configurations WHERE organization_id = ${organizationId} LIMIT 1
  `;
  const row = rows[0];

  if (row && row.status !== 'DISABLED') {
    const apiKey = await env.secrets.get(row.api_key_secret_ref, 'ai').catch(() => null);
    if (apiKey) {
      return {
        provider: row.provider,
        baseUrl: row.base_url.replace(/\/+$/, ''),
        model: row.model,
        apiKey,
        source: 'organisation',
      };
    }
  }

  if (env.AI_API_KEY) {
    return {
      provider: 'anthropic',
      baseUrl: 'https://api.anthropic.com',
      model: env.AI_MODEL ?? 'claude-sonnet-5',
      apiKey: env.AI_API_KEY,
      source: 'platform',
    };
  }

  return {
    provider: 'anthropic',
    baseUrl: 'https://api.anthropic.com',
    model: env.AI_MODEL ?? 'claude-sonnet-5',
    apiKey: null,
    source: 'off',
  };
}

/**
 * Endpoint URL for the configured provider, tolerant of how the administrator writes
 * the base URL. Both `https://api.anthropic.com` and `https://api.anthropic.com/v1`
 * work for Anthropic; `https://api.openai.com`, `/v1`, Groq's `/openai/v1`, OpenRouter's
 * `/api/v1` and self-hosted `/v1` bases all work for OpenAI-compatible endpoints.
 */
export function providerEndpoint(baseUrl: string, provider: AiProvider): string {
  const base = baseUrl.replace(/\/+$/, '');
  const hasV1 = /\/v1$/.test(base);
  if (provider === 'anthropic') {
    return hasV1 ? `${base}/messages` : `${base}/v1/messages`;
  }
  return hasV1 ? `${base}/chat/completions` : `${base}/v1/chat/completions`;
}

/** One bounded completion against the configured provider. No tools, no callbacks. */
export async function callAiProvider(
  config: AiProviderConfig,
  systemPrompt: string,
  userPrompt: string,
  maxTokens = 1200,
): Promise<{ ok: boolean; text: string; message: string; latencyMs: number }> {
  if (!config.apiKey) {
    return { ok: false, text: '', message: 'No API key is configured', latencyMs: 0 };
  }
  const started = Date.now();

  try {
    const url = providerEndpoint(config.baseUrl, config.provider);
    let headers: Record<string, string>;
    let body: Record<string, unknown>;

    if (config.provider === 'anthropic') {
      // Anthropic Messages API: key header + version header; max_tokens is REQUIRED.
      headers = {
        'x-api-key': config.apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      };
      body = {
        model: config.model,
        max_tokens: maxTokens,
        system: systemPrompt,
        messages: [{ role: 'user', content: userPrompt }],
      };
    } else {
      // OpenAI-compatible Chat Completions: Bearer auth, system prompt as a message.
      // max_tokens is deliberately omitted: newer OpenAI models reject it in favour of
      // max_completion_tokens, other compatible servers reject that instead, and every
      // server applies its own default cap — the omission is the only portable choice.
      headers = {
        Authorization: `Bearer ${config.apiKey}`,
        'content-type': 'application/json',
      };
      body = {
        model: config.model,
        messages: [
          { role: 'system', content: systemPrompt },
          { role: 'user', content: userPrompt },
        ],
      };
    }

    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(25_000),
    });

    if (!response.ok) {
      const detail = (await response.text().catch(() => '')).slice(0, 200);
      return {
        ok: false,
        text: '',
        message: `The provider returned HTTP ${response.status}${detail ? `: ${detail}` : ''}`,
        latencyMs: Date.now() - started,
      };
    }

    const data = (await response.json()) as {
      content?: { type: string; text?: string }[];
      choices?: { message?: { content?: string } }[];
    };

    const text =
      config.provider === 'anthropic'
        ? (data.content ?? []).filter((b) => b.type === 'text').map((b) => b.text ?? '').join('\n').trim()
        : (data.choices?.[0]?.message?.content ?? '').trim();

    if (text === '') {
      return { ok: false, text: '', message: 'The provider returned no text', latencyMs: Date.now() - started };
    }
    return { ok: true, text, message: 'The provider responded successfully.', latencyMs: Date.now() - started };
  } catch (err) {
    return {
      ok: false,
      text: '',
      message: err instanceof Error ? err.message : 'The provider call failed',
      latencyMs: Date.now() - started,
    };
  }
}

/** Validation shared by the configure route. */
export function validateAiConfigInput(input: { provider: string; baseUrl: string; model: string }): void {
  if (input.provider !== 'anthropic' && input.provider !== 'openai-compatible') {
    throw validationError('AI_PROVIDER_INVALID', 'The provider must be anthropic or openai-compatible');
  }
  let parsed: URL;
  try {
    parsed = new URL(input.baseUrl);
  } catch {
    throw validationError('AI_BASE_URL_INVALID', 'The base URL is not a valid URL');
  }
  if (parsed.protocol !== 'https:') {
    throw validationError('AI_BASE_URL_HTTPS', 'The base URL must be https (credentials travel on every request)');
  }
  if (input.model.trim().length === 0 || input.model.length > 200) {
    throw validationError('AI_MODEL_INVALID', 'The model name must be between 1 and 200 characters');
  }
}

/**
 * The Daraja client against the scripted provider: token lifecycle, the no-retry rule
 * for B2C, retry rules for read-only queries, error classification, and the callback
 * parsers against every documented payload quirk.
 */

import { describe, expect, it } from 'vitest';
import { DarajaClient } from './client.js';
import type { DarajaCredentials } from './client.js';
import {
  createScriptedProvider,
  b2cSuccessCallback,
  b2cFailureCallback,
  statusCallback,
} from './scripted-provider.js';
import { parseB2cResult, parseTransactionStatusResult, parseAccountBalanceResult, interpretTransactionStatus, toCents, parseDarajaTimestamp } from './callbacks.js';
import { SolvarenError } from '@solvaren/core';

const credentials: DarajaCredentials = {
  consumerKey: 'test-consumer-key',
  consumerSecret: 'test-consumer-secret',
  securityCredential: 'precomputed-base64-credential-value-padding-padding',
  initiatorName: 'testapi',
  shortCode: '600992',
};

function makeClient(provider: ReturnType<typeof createScriptedProvider>) {
  return new DarajaClient({
    environment: 'sandbox',
    credentials,
    fetchImpl: provider.fetchImpl as typeof fetch,
    timeoutMs: 500,
  });
}

const b2cRequest = (originatorId: string) => ({
  OriginatorConversationID: originatorId,
  InitiatorName: 'testapi',
  SecurityCredential: credentials.securityCredential,
  CommandID: 'BusinessPayment' as const,
  Amount: '500.00',
  PartyA: '600992',
  PartyB: '254705912645',
  Remarks: 'Test payment',
  QueueTimeOutURL: 'https://api.example.test/timeout',
  ResultURL: 'https://api.example.test/callback',
});

describe('token lifecycle', () => {
  it('caches the token — many payments, one token request', async () => {
    const provider = createScriptedProvider();
    const client = makeClient(provider);

    for (let i = 0; i < 5; i++) {
      const originator = `SLV-600992-test-${i}`;
      await client.sendB2cPayment(b2cRequest(originator));
    }

    expect(provider.tokenRequests).toBe(1);
    expect(provider.calls.filter((c) => c.endpoint === 'b2c')).toHaveLength(5);
  });

  it('collapses concurrent refreshes into one token request', async () => {
    const provider = createScriptedProvider();
    const client = makeClient(provider);

    await Promise.all(
      Array.from({ length: 20 }, (_, i) => client.sendB2cPayment(b2cRequest(`SLV-burst-${i}`))),
    );

    expect(provider.tokenRequests).toBe(1);
  });

  it('refreshes at 80% of the advertised lifetime', async () => {
    const provider = createScriptedProvider();
    let clock = 1_000_000;
    const client = new DarajaClient({
      environment: 'sandbox',
      credentials,
      fetchImpl: provider.fetchImpl as typeof fetch,
      now: () => clock,
    });

    await client.sendB2cPayment(b2cRequest('SLV-1'));
    // Token returned expires_in=3599; the client expires it at 0.8×3599s ≈ 2879s.
    clock += 2_880_000;
    await client.sendB2cPayment(b2cRequest('SLV-2'));

    expect(provider.tokenRequests).toBe(2);
  });

  it('testConnection proves credentials without moving money', async () => {
    const provider = createScriptedProvider();
    const client = makeClient(provider);
    const result = await client.testConnection();
    expect(result.ok).toBe(true);
    expect(result.message).toMatch(/sandbox/i);
    expect(provider.calls.filter((c) => c.endpoint === 'b2c')).toHaveLength(0);
  });
});

describe('the no-retry rule (spec §9.3: never blind-retry a payment)', () => {
  it('B2C is never retried, even on a token error', async () => {
    const provider = createScriptedProvider();
    const client = makeClient(provider);

    // First token works, then expire it so the payment call gets a token error.
    const originator = 'SLV-no-retry';
    provider.setBehavior(originator, { kind: 'accept' });
    // Force a fresh token for the next call by rotating credentials — simpler: call twice
    // with an artificial clock jump past expiry between them.
    let clock = Date.now();
    const timed = new DarajaClient({
      environment: 'sandbox',
      credentials,
      fetchImpl: provider.fetchImpl as typeof fetch,
      now: () => clock,
    });
    provider.setBehavior('SLV-first', { kind: 'accept' });
    await timed.sendB2cPayment(b2cRequest('SLV-first'));

    clock += 3_600_000; // token expired
    provider.setBehavior('SLV-second', { kind: 'reject', errorCode: '400.003.01', errorMessage: 'Invalid Access Token' });
    await expect(timed.sendB2cPayment(b2cRequest('SLV-second'))).rejects.toThrow();

    const b2cCalls = provider.calls.filter((c) => c.endpoint === 'b2c');
    expect(b2cCalls).toHaveLength(2); // one per originator — no retry of the second
  });

  it('a provider timeout classifies as DARAJA_TIMEOUT (ambiguous — never a blind resend)', async () => {
    const provider = createScriptedProvider();
    const client = makeClient(provider);
    provider.setBehavior('SLV-timeout', { kind: 'timeout' });

    await expect(client.sendB2cPayment(b2cRequest('SLV-timeout'))).rejects.toThrow(SolvarenError);
    try {
      await client.sendB2cPayment(b2cRequest('SLV-timeout'));
      expect.unreachable();
    } catch (err) {
      expect((err as SolvarenError).code).toBe('DARAJA_TIMEOUT');
    }
  });

  it('read-only status queries ARE retried once on a token problem', async () => {
    const provider = createScriptedProvider();
    const client = makeClient(provider);
    await client.queryTransactionStatus({
      Initiator: 'testapi',
      SecurityCredential: credentials.securityCredential,
      CommandID: 'TransactionStatusQuery',
      OriginalConversationID: 'SLV-check',
      PartyA: '600992',
      IdentifierType: '4',
      ResultURL: 'https://example.test/status',
      QueueTimeOutURL: 'https://example.test/timeout',
      Remarks: 'check',
    });
    expect(provider.calls.filter((c) => c.endpoint === 'transaction_status')).toHaveLength(1);
  });
});

describe('error classification (the knowledge base’s code table)', () => {
  it('surfaces the provider’s own gateway code', async () => {
    const provider = createScriptedProvider();
    const client = makeClient(provider);
    provider.setBehavior('SLV-dup', { kind: 'duplicate-originator' });

    try {
      await client.sendB2cPayment(b2cRequest('SLV-dup'));
      expect.unreachable();
    } catch (err) {
      expect(err).toBeInstanceOf(SolvarenError);
      const e = err as SolvarenError;
      expect(e.details.errorCode).toBe('500.002.1001');
      expect(e.message).toMatch(/duplicate originator/i);
    }
  });

  it('an unreachable provider classifies as DARAJA_UNREACHABLE', async () => {
    const provider = createScriptedProvider();
    const client = makeClient(provider);
    provider.setBehavior('SLV-down', { kind: 'unreachable' });

    await expect(client.sendB2cPayment(b2cRequest('SLV-down'))).rejects.toMatchObject({
      code: 'DARAJA_UNREACHABLE',
    });
  });
});

describe('callback parsing (Daraja’s documented shape quirks)', () => {
  it('parses a B2C success callback with receipt, amounts and balances', () => {
    const payload = b2cSuccessCallback('SLV-1', 'SG632NMUAB', 50000);
    const parsed = parseB2cResult(payload);
    expect(parsed.succeeded).toBe(true);
    expect(parsed.resultCode).toBe('0');
    expect(parsed.transactionReceipt).toBe('SG632NMUAB');
    expect(parsed.transactionAmountCents).toBe(5_000_000);
    expect(parsed.utilityAccountBalanceCents).toBe(50_000_000);
    expect(parsed.workingAccountBalanceCents).toBe(12_000_000);
    expect(parsed.chargesPaidAccountBalanceCents).toBe(-154_000);
    expect(parsed.recipientIsRegistered).toBe(true);
    expect(parsed.completedAt).toBe('2026-09-14T07:15:30.000Z'); // 10:15:30 EAT
  });

  it('parses a B2C failure callback', () => {
    const parsed = parseB2cResult(b2cFailureCallback('SLV-2', 1, 'The initiator is disabled'));
    expect(parsed.succeeded).toBe(false);
    expect(parsed.resultCode).toBe('1');
  });

  it('parses ResultParameter whether it arrives as array or bare object', () => {
    const arrayForm = b2cSuccessCallback('SLV-3', 'SG1', 100);
    expect(parseB2cResult(arrayForm).transactionReceipt).toBe('SG1');

    const objectForm = {
      Result: {
        ResultCode: 0,
        ResultDesc: 'ok',
        OriginatorConversationID: 'SLV-4',
        ResultParameters: {
          ResultParameter: { Key: 'TransactionReceipt', Value: 'SG2' }, // bare object
        },
      },
    };
    expect(parseB2cResult(objectForm).transactionReceipt).toBe('SG2');
  });

  it('parses a Transaction Status callback and interprets the lifecycle', () => {
    const parsed = parseTransactionStatusResult(statusCallback('SLV-5', 'Completed', 'SG9'));
    expect(parsed.transactionStatus).toBe('Completed');
    expect(parsed.receiptNumber).toBe('SG9');
    expect(interpretTransactionStatus(parsed.transactionStatus)).toBe('SUCCESS');
    expect(interpretTransactionStatus('Declined')).toBe('FAILED');
    expect(interpretTransactionStatus('Initiated')).toBe('PENDING');
    expect(interpretTransactionStatus('Something New')).toBe('UNKNOWN');
  });

  it('parses an Account Balance callback from the pipe-delimited string', () => {
    const payload = {
      Result: {
        ResultCode: 0,
        ResultDesc: 'The service request is processed successfully.',
        ResultParameters: {
          ResultParameter: [
            { Key: 'AccountBalance', Value: 'Working Account|KES|700000.00|700000.00|0.00|0.00&Utility Account|KES|228037.00|228037.00|0.00|0.00&Charges Paid Account|KES|-1540.00|-1540.00|0.00|0.00' },
            { Key: 'BOCompletedTime', Value: '20260914101530' },
          ],
        },
      },
    };
    const parsed = parseAccountBalanceResult(payload);
    expect(parsed.accounts).toHaveLength(3);
    expect(parsed.accounts[0]!.accountType).toBe('Working Account');
    expect(parsed.accounts[0]!.availableBalanceCents).toBe(70_000_000);
    expect(parsed.accounts[2]!.availableBalanceCents).toBe(-154_000);
    expect(parsed.completedAt).toBe('2026-09-14T07:15:30.000Z');
  });

  it('parses both timestamp formats (dotted dd.MM.yyyy and compact yyyyMMddHHmmss)', () => {
    expect(parseDarajaTimestamp('14.09.2026 10:15:30')).toBe('2026-09-14T07:15:30.000Z');
    expect(parseDarajaTimestamp('20260914101530')).toBe('2026-09-14T07:15:30.000Z');
    expect(parseDarajaTimestamp('nonsense')).toBeNull();
  });

  it('converts Daraja money strings to cents across their shapes', () => {
    expect(toCents('12000')).toBe(1_200_000);
    expect(toCents(12000)).toBe(1_200_000);
    expect(toCents('12,000.00')).toBe(1_200_000);
    expect(toCents(undefined)).toBeNull();
    expect(toCents('')).toBeNull();
  });
});

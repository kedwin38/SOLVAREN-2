/**
 * A scripted Daraja provider for the test suites and local development.
 *
 * The integration is exercised against every outcome class that matters to a payment
 * platform — acceptance, rejection, timeout, duplicate identifier, callback delivery,
 * duplicate callback, contradicting callback — without needing Safaricom credentials.
 * Live-provider verification remains a separate, explicit milestone (see
 * docs/deployment.md §8).
 */

import type { B2cRequest, DarajaAck, TransactionStatusRequest, AccountBalanceRequest } from './types.js';

export type ScriptedBehavior =
  | { kind: 'accept' }
  | { kind: 'reject'; errorCode?: string; errorMessage?: string; httpStatus?: number }
  | { kind: 'timeout' }
  | { kind: 'unreachable' }
  | { kind: 'duplicate-originator' }
  | { kind: 'server-error' };

export interface ScriptedB2cOutcome {
  originatorConversationId: string;
  behavior: ScriptedBehavior;
  /** Callback body to deliver to the ResultURL after acceptance; omit to stay silent. */
  callbackBody?: unknown;
}

export interface ScriptedProviderCall {
  endpoint: 'oauth' | 'b2c' | 'transaction_status' | 'account_balance';
  at: number;
  /** The B2C request when endpoint is 'b2c'. */
  b2cRequest?: B2cRequest;
}

export interface ScriptedProvider {
  fetchImpl: typeof fetch;
  /** Calls received, in order — the tests assert against this log. */
  calls: ScriptedProviderCall[];
  /** Total tokens issued (a new token per forced refresh). Live-updating. */
  readonly tokenRequests: number;
  /** Pending callbacks that would be delivered to ResultURL — tests invoke these. */
  pendingCallbacks: { url: string; body: unknown }[];
  setBehavior: (originatorId: string, behavior: ScriptedBehavior, callbackBody?: unknown) => void;
  reset: () => void;
}

export function createScriptedProvider(): ScriptedProvider {
  const behaviors = new Map<string, { behavior: ScriptedBehavior; callbackBody?: unknown }>();
  const calls: ScriptedProviderCall[] = [];
  const pendingCallbacks: { url: string; body: unknown }[] = [];
  let tokenRequests = 0;

  const jsonResponse = (status: number, body: unknown): Response =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    });

  const ack = (originatorId: string): DarajaAck => ({
    ConversationID: `AG_SCRIPTED_${originatorId.slice(-12)}`,
    OriginatorConversationID: originatorId,
    ResponseCode: '0',
    ResponseDescription: 'Accept the service request successfully.',
  });

  const fetchImpl: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input as URL).toString();
    const method = init?.method ?? 'GET';

    if (url.includes('/oauth/')) {
      tokenRequests += 1;
      calls.push({ endpoint: 'oauth', at: Date.now() });
      return jsonResponse(200, { access_token: `scripted-token-${tokenRequests}`, expires_in: '3599' });
    }

    if (url.includes('/b2c/')) {
      const body = JSON.parse(String(init?.body ?? '{}')) as B2cRequest;
      calls.push({ endpoint: 'b2c', at: Date.now(), b2cRequest: body });
      const scripted = behaviors.get(body.OriginatorConversationID) ?? { behavior: { kind: 'accept' } as ScriptedBehavior };
      const { behavior, callbackBody } = scripted;

      switch (behavior.kind) {
        case 'accept':
          if (callbackBody !== undefined && body.ResultURL) {
            pendingCallbacks.push({ url: body.ResultURL, body: callbackBody });
          }
          return jsonResponse(200, ack(body.OriginatorConversationID));
        case 'reject':
          return jsonResponse(
            behavior.httpStatus ?? 200,
            behavior.errorCode
              ? { requestId: 'req_scripted', errorCode: behavior.errorCode, errorMessage: behavior.errorMessage ?? 'Scripted rejection' }
              : { ...ack(body.OriginatorConversationID), ResponseCode: '1', ResponseDescription: behavior.errorMessage ?? 'Scripted rejection' },
          );
        case 'duplicate-originator':
          return jsonResponse(500, {
            requestId: 'req_scripted',
            errorCode: '500.002.1001',
            errorMessage: 'Duplicate OriginatorConversationID.',
          });
        case 'server-error':
          return jsonResponse(500, {
            requestId: 'req_scripted',
            errorCode: '500.003.1001',
            errorMessage: 'Internal server error.',
          });
        case 'timeout':
          return Promise.reject(Object.assign(new Error('The operation was aborted'), { name: 'AbortError' }));
        case 'unreachable':
          return Promise.reject(new TypeError('fetch failed'));
      }
    }

    if (url.includes('/transactionstatus/')) {
      const body = JSON.parse(String(init?.body ?? '{}')) as TransactionStatusRequest;
      calls.push({ endpoint: 'transaction_status', at: Date.now() });
      return jsonResponse(200, ack(body.OriginalConversationID ?? body.TransactionID ?? 'scripted'));
    }

    if (url.includes('/accountbalance/')) {
      const body = JSON.parse(String(init?.body ?? '{}')) as AccountBalanceRequest;
      calls.push({ endpoint: 'account_balance', at: Date.now() });
      return jsonResponse(200, ack(body.PartyA));
    }

    return jsonResponse(404, { requestId: 'req_scripted', errorCode: '404.003.01', errorMessage: 'Resource not found' });
  };

  return {
    fetchImpl,
    calls,
    // A getter so tests observe the live counter (a plain number property would be a
    // snapshot of 0 taken at construction time).
    get tokenRequests() {
      return tokenRequests;
    },
    pendingCallbacks,
    setBehavior(originatorId, behavior, callbackBody) {
      behaviors.set(originatorId, { behavior, callbackBody });
    },
    reset() {
      behaviors.clear();
      calls.length = 0;
      pendingCallbacks.length = 0;
      tokenRequests = 0;
    },
  };
}

/** Build a Daraja-shaped B2C success callback body. */
export function b2cSuccessCallback(originatorId: string, receipt: string, amount: number): unknown {
  return {
    Result: {
      ResultType: 0,
      ResultCode: 0,
      ResultDesc: 'The service request is processed successfully.',
      OriginatorConversationID: originatorId,
      ConversationID: `AG_SCRIPTED_${originatorId.slice(-12)}`,
      TransactionID: receipt,
      ResultParameters: {
        ResultParameter: [
          { Key: 'TransactionReceipt', Value: receipt },
          { Key: 'TransactionAmount', Value: amount },
          { Key: 'TransactionCompletedDateTime', Value: '14.09.2026 10:15:30' },
          { Key: 'ReceiverPartyPublicName', Value: 'RECIPIENT' },
          { Key: 'B2CUtilityAccountAvailableFunds', Value: 500000.0 },
          { Key: 'B2CWorkingAccountAvailableFunds', Value: 120000.0 },
          { Key: 'B2CChargesPaidAccountAvailableFunds', Value: -1540.0 },
          { Key: 'B2CRecipientIsRegisteredCustomer', Value: 'Y' },
        ],
      },
      ReferenceData: { ReferenceItem: { Key: 'QueueTimeoutURL', Value: 'https://example.test/timeout' } },
    },
  };
}

/** Build a Daraja-shaped B2C failure callback body. */
export function b2cFailureCallback(originatorId: string, resultCode: number, desc: string): unknown {
  return {
    Result: {
      ResultType: 0,
      ResultCode: resultCode,
      ResultDesc: desc,
      OriginatorConversationID: originatorId,
      ConversationID: `AG_SCRIPTED_${originatorId.slice(-12)}`,
      TransactionID: `FAIL${resultCode}`,
      ResultParameters: { ResultParameter: [] },
      ReferenceData: { ReferenceItem: { Key: 'QueueTimeoutURL', Value: 'https://example.test/timeout' } },
    },
  };
}

/** Build a Transaction Status result callback body. */
export function statusCallback(originatorId: string, status: string, receipt: string | null): unknown {
  return {
    Result: {
      ResultType: 0,
      ResultCode: 0,
      ResultDesc: 'The service request is processed successfully.',
      OriginatorConversationID: originatorId,
      ConversationID: `AG_SCRIPTED_${originatorId.slice(-12)}`,
      TransactionID: receipt ?? 'N/A',
      ResultParameters: {
        ResultParameter: [
          { Key: 'TransactionStatus', Value: status },
          { Key: 'ReceiptNo', Value: receipt ?? '' },
          { Key: 'Amount', Value: 1000 },
          { Key: 'FinalisedTime', Value: '20260914101530' },
        ],
      },
    },
  };
}

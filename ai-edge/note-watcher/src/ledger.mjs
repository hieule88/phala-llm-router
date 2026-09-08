/**
 * auth-service client — the two watcher endpoints, bearer-authenticated
 * with ONCHAIN_WATCHER_TOKEN. fetch is injectable for tests.
 *
 * Every call is time-bounded twice: an AbortSignal so a real fetch
 * tears down its socket, AND withTimeout so even a fetchImpl that
 * ignores the signal (tests, exotic polyfills) cannot hang the tick.
 */

import { withTimeout } from './util.mjs';

const DEFAULT_TIMEOUT_MS = 30_000;

export function makeLedger({ authUrl, token, fetchImpl = fetch,
                             timeoutMs = DEFAULT_TIMEOUT_MS }) {
  const base = authUrl.replace(/\/+$/, '');
  const headers = {
    authorization: `Bearer ${token}`,
    'content-type': 'application/json',
  };

  const timedFetch = (url, opts, label) => withTimeout(
    fetchImpl(url, {
      ...opts,
      // AbortSignal.timeout exists on Node 18+; guard anyway so a bare
      // test fake without it keeps working (withTimeout still bounds us).
      ...(typeof AbortSignal?.timeout === 'function'
        ? { signal: AbortSignal.timeout(timeoutMs) } : {}),
    }),
    timeoutMs, label);

  return {
    /** The matching table + rail config. Throws on any failure — the
     *  tick is skipped rather than run against a stale/partial table. */
    async fetchPendingIntents() {
      const res = await timedFetch(
        `${base}/v1/onchain/pending-intents`, { headers }, 'pending-intents');
      if (!res.ok) {
        throw new Error(`pending-intents returned ${res.status}`);
      }
      return await res.json();
    },

    /** Report one payment. Never throws on HTTP errors — returns the
     *  status so the caller applies the documented retry contract
     *  (4xx dead-letter, 5xx retry). Network errors and timeouts DO
     *  throw and are treated as retry by the caller. */
    async report(payload) {
      const res = await timedFetch(`${base}/v1/webhooks/onchain`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
      }, 'webhook report');
      let body = null;
      try { body = await res.json(); } catch { /* non-JSON error body */ }
      return { status: res.status, body };
    },
  };
}

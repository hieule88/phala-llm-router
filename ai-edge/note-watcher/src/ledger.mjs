/**
 * auth-service client — the two watcher endpoints, bearer-authenticated
 * with ONCHAIN_WATCHER_TOKEN. fetch is injectable for tests.
 */

export function makeLedger({ authUrl, token, fetchImpl = fetch }) {
  const base = authUrl.replace(/\/+$/, '');
  const headers = {
    authorization: `Bearer ${token}`,
    'content-type': 'application/json',
  };

  return {
    /** The matching table + rail config. Throws on any failure — the
     *  tick is skipped rather than run against a stale/partial table. */
    async fetchPendingIntents() {
      const res = await fetchImpl(`${base}/v1/onchain/pending-intents`, { headers });
      if (!res.ok) {
        throw new Error(`pending-intents returned ${res.status}`);
      }
      return await res.json();
    },

    /** Report one payment. Never throws on HTTP errors — returns the
     *  status so the caller applies the documented retry contract
     *  (4xx dead-letter, 5xx retry). Network errors DO throw and are
     *  treated as retry by the caller. */
    async report(payload) {
      const res = await fetchImpl(`${base}/v1/webhooks/onchain`, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
      });
      let body = null;
      try { body = await res.json(); } catch { /* non-JSON error body */ }
      return { status: res.status, body };
    },
  };
}

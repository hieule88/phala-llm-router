/**
 * Docker healthcheck: exit 0 while the watcher is making progress.
 *
 * "Progress" is the heartbeat file's freshness — touched per table
 * fetch, per drained report and per scanned page (and every 30s in the
 * deliberate not-yet-configured idle). A hung process stops touching it
 * long before the in-process watchdog exits, so ops see `unhealthy` in
 * `docker ps` first, then the watchdog recycles the process.
 *
 * Max age must cover one full poll interval plus a worst-case call
 * timeout with slack: default 180s against a 10s poll + 60s RPC bound.
 */

import { promises as fs } from 'node:fs';

const file = process.env.HEARTBEAT_FILE ?? '/state/heartbeat';
const maxAgeSec = Number(process.env.HEALTHCHECK_MAX_AGE_SEC ?? 180);

try {
  const raw = await fs.readFile(file, 'utf8');
  const ageMs = Date.now() - Number(raw);
  if (!Number.isFinite(ageMs) || ageMs < 0) {
    console.error(`heartbeat unreadable: ${JSON.stringify(raw.slice(0, 64))}`);
    process.exit(1);
  }
  if (ageMs > maxAgeSec * 1000) {
    console.error(`heartbeat stale: ${Math.round(ageMs / 1000)}s > ${maxAgeSec}s`);
    process.exit(1);
  }
  process.exit(0);
} catch (err) {
  // No heartbeat yet (container just started) counts as unhealthy;
  // docker's own start_period suppresses the early failures.
  console.error(`no heartbeat: ${err}`);
  process.exit(1);
}

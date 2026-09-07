/**
 * Watcher state — one JSON file on a volume, written atomically
 * (tmp + rename) so a crash mid-write can't corrupt the cursor.
 *
 * Shape:
 *   cursor        next block to scan (advances to blockTo()+1 per page,
 *                 never to the tip — truncation-safe pagination)
 *   pending       {noteId: {payload, memo, firstSeenAt}} matched but not
 *                 yet acknowledged by the ledger (5xx/network → retried
 *                 every tick; survives restarts)
 *   reported      {noteId: memo} acknowledged (2xx, incl. deduplicated)
 *   deadLettered  {noteId: reason} permanently refused (4xx) — also
 *                 appended to the dead-letter JSONL for ops
 *   unmatched     {noteId: {amount, sender, firstSeenAt}} qualified
 *                 notes with no (or several) matching intents — retried
 *                 against a fresh table every tick until UNMATCHED_TTL
 */

import { promises as fs } from 'node:fs';
import path from 'node:path';

const EMPTY = {
  cursor: null,
  pending: {},
  reported: {},
  deadLettered: {},
  unmatched: {},
};

export async function loadState(file) {
  try {
    const raw = await fs.readFile(file, 'utf8');
    return { ...EMPTY, ...JSON.parse(raw) };
  } catch (err) {
    if (err.code === 'ENOENT') return { ...EMPTY };
    // A corrupt state file must not silently restart the scan from
    // nothing — that would re-report everything (harmless, the server
    // dedups) but more importantly lose the dead-letter memory.
    throw new Error(`cannot read state file ${file}: ${err}`);
  }
}

export async function saveState(file, state) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(state, null, 1));
  await fs.rename(tmp, file);
}

export async function appendDeadLetter(file, entry) {
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.appendFile(file, JSON.stringify(entry) + '\n');
}

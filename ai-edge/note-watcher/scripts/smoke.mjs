/**
 * Live smoke test for chain.mjs — the one module the unit tests cannot
 * cover (it is the WASM boundary). Run it against the real testnet
 * BEFORE enabling the rail:
 *
 *   NODE_RPC_URL=http://178.63.134.75:57291 \
 *   ONCHAIN_GATEWAY_ADDRESS=mtst1... \
 *   ONCHAIN_FAUCET_ID=mtst1azftenneus72ugqqsj9rk7cveqk0eraz \
 *   npm run smoke
 *
 * Exercises: RPC connectivity, tip fetch, bech32 decoding, one real
 * syncNotes/getNotesById page over the last N blocks, and script-root
 * classification. Prints what a tick would see; changes nothing.
 */

import { makeChain } from '../src/chain.mjs';

const need = (name) => {
  const v = process.env[name];
  if (!v) { console.error(`set ${name}`); process.exit(2); }
  return v;
};

const rpcUrl = need('NODE_RPC_URL');
const gateway = need('ONCHAIN_GATEWAY_ADDRESS');
const faucet = need('ONCHAIN_FAUCET_ID');
const lookback = Number(process.env.SMOKE_LOOKBACK_BLOCKS ?? 200);

const chain = makeChain({ rpcUrl });

const gwHex = chain.bech32ToHex(gateway);
const fcHex = chain.bech32ToHex(faucet);
console.log(`gateway ${gateway} -> ${gwHex}`);
console.log(`faucet  ${faucet} -> ${fcHex}`);
if (!gwHex || !fcHex) { console.error('bech32 decode failed'); process.exit(1); }

const tip = await chain.tip();
const from = Math.max(0, tip - lookback);
console.log(`tip=${tip}, scanning [${from}, ${tip}] ...`);

let cursor = from;
let pages = 0;
let total = 0;
while (cursor <= tip) {
  const { notes, blockTo } = await chain.scan(cursor, tip, gateway, faucet);
  pages += 1;
  total += notes.length;
  for (const n of notes) {
    console.log(`  note=${n.noteId} kind=${n.kind} targetOk=${n.targetOk} `
      + `amount=${n.amount} sender=${n.sender}`);
  }
  if (blockTo + 1 <= cursor) break;
  cursor = blockTo + 1;
}
console.log(`OK: ${pages} page(s), ${total} tag-matching note(s).`);

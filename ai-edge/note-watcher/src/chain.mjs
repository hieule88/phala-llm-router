/**
 * The only module that touches @miden-sdk/miden-sdk (WASM, node build).
 * Wraps the raw RPC surface into plain-JS values so watcher.mjs and the
 * tests never handle WASM objects.
 *
 * API facts this leans on (verified against leviathan-client sources):
 *  - new RpcClient(new Endpoint(url)); getBlockHeaderByNumber() with no
 *    arg returns the latest header.
 *  - syncNotes(from, to, [tag]) returns NoteSyncInfo; blockTo() is "the
 *    last block checked by the node — used as a cursor for pagination",
 *    so the next scan starts at blockTo()+1, NEVER at the tip (the node
 *    may truncate a large window).
 *  - NoteTag.withAccountTarget CONSUMES its AccountId — derive a fresh
 *    one per call from the bech32 string.
 *  - getNotesById returns full note details for PUBLIC notes only; a
 *    private note yields no `note` and is skipped (a private payment
 *    cannot be observed by the watcher — documented client rule).
 *  - P2ID note storage layout is [account_id_suffix, account_id_prefix]
 *    (miden-standards p2id.rs), recombined via AccountId.fromPrefixSuffix.
 */

import {
  AccountId,
  Address,
  Endpoint,
  NoteScript,
  NoteTag,
  RpcClient,
} from '@miden-sdk/miden-sdk';

import { withTimeout } from './util.mjs';

const DEFAULT_RPC_TIMEOUT_MS = 60_000;

export function makeChain({ rpcUrl, timeoutMs = DEFAULT_RPC_TIMEOUT_MS }) {
  const rpc = new RpcClient(new Endpoint(rpcUrl));
  // Every RPC await is time-bounded: a hung gRPC stream would otherwise
  // park the tick forever with no error and no restart. On timeout the
  // WASM call may still be wedged underneath (not cancellable from JS)
  // — repeated failures then trip the process watchdog, which exits so
  // docker hands us a fresh process and a fresh client.
  const timed = (p, label) => withTimeout(p, timeoutMs, label);
  let roots; // lazily resolved: the scripts come from the WASM module

  function scriptRoots() {
    roots ??= {
      p2id: NoteScript.p2id().root().toHex(),
      p2ide: NoteScript.p2ide().root().toHex(),
    };
    return roots;
  }

  function classifyRoot(rootHex) {
    const r = scriptRoots();
    if (rootHex === r.p2id) return 'p2id';
    if (rootHex === r.p2ide) return 'p2ide';
    return 'other';
  }

  return {
    /** bech32 address → canonical hex account id (or null). Used to
     *  pre-decode sender_accounts so all comparisons are hex-vs-hex. */
    bech32ToHex(bech32) {
      try {
        return Address.fromBech32(bech32).accountId().toString();
      } catch {
        return null;
      }
    },

    async tip() {
      return (await timed(rpc.getBlockHeaderByNumber(), 'getBlockHeaderByNumber'))
        .blockNum();
    },

    /**
     * One pagination page: committed notes tag-matching the gateway
     * account in [from, to], reduced to plain objects. Returns
     * { notes, blockTo } — the caller persists blockTo()+1 as cursor.
     */
    async scan(from, to, gatewayBech32, faucetBech32) {
      const gatewayHex = Address.fromBech32(gatewayBech32).accountId().toString();
      const faucetHex = Address.fromBech32(faucetBech32).accountId().toString();
      const tag = NoteTag.withAccountTarget(
        Address.fromBech32(gatewayBech32).accountId());

      const info = await timed(rpc.syncNotes(from, to, [tag]), 'syncNotes');
      const notes = [];
      for (const block of info.blocks()) {
        // The block's own timestamp anchors the note in CHAIN time, not
        // watcher time: after downtime (or the first-run lookback) a
        // wall-clock "first seen" would be hours late, loosening the
        // time-order filter exactly while nobody was watching.
        const header = block.blockHeader();
        const blockTimeMs = header.timestamp() * 1000;
        for (const committed of block.notes()) {
          const noteId = committed.noteId();
          const noteIdHex = noteId.toString();
          const fetched = await timed(rpc.getNotesById([noteId]), 'getNotesById');
          const note = fetched[0]?.note;
          if (!note) continue; // private note — unobservable, skip

          let kind = 'other';
          let targetOk = false;
          let sender = null;
          let amount = 0n;
          try {
            const recipient = note.recipient();
            kind = classifyRoot(recipient.script().root().toHex());
            const items = recipient.storage().items();
            if (items.length === 2) {
              // storage layout: [suffix, prefix]
              const target = AccountId.fromPrefixSuffix(items[1], items[0]);
              targetOk = target.toString() === gatewayHex;
            }
            for (const asset of note.assets().fungibleAssets()) {
              if (asset.faucetId().toString() === faucetHex) {
                amount += asset.amount();
              }
            }
            sender = note.metadata().sender().toString();
          } catch {
            // Unparseable pieces leave the note disqualified rather than
            // crashing the scan — one weird note must not stall the rail.
          }
          notes.push({
            noteId: noteIdHex,
            kind,
            targetOk,
            amount: amount.toString(),
            sender,
            blockTimeMs,
          });
        }
      }
      return { notes, blockTo: info.blockTo() };
    },
  };
}

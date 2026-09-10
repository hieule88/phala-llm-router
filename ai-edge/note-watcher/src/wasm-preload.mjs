/**
 * Node-compat preload for @miden-sdk/miden-sdk. MUST be imported before
 * the SDK (chain.mjs lists it first; ESM executes imports in order).
 *
 * The SDK ships one dist for browser and node, and its Cargo chunk does
 * two browser-shaped things at module top level (verified empirically
 * against 0.15.0-node.5e72c326 — see scripts/smoke-attachment.mjs):
 *
 *  1. wasm-bindgen-rayon's inlined worker helper references `self` and
 *     worker messaging. Shimming them as no-ops parks the helper
 *     waiting for a worker-init message that never comes — correct,
 *     since the watcher never calls initThreadPool.
 *  2. `__wbg_init` resolves the .wasm via fetch(new URL(file://...)),
 *     which Node's fetch refuses. `globalThis.__wbgInitArg` is the
 *     loader's own escape hatch (the wallet's rayon workers use it):
 *     hand it the wasm bytes read from disk and init skips the fetch.
 */

import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

globalThis.self ??= globalThis;
globalThis.addEventListener ??= () => {};
globalThis.removeEventListener ??= () => {};
globalThis.postMessage ??= () => {};

if (!globalThis.__wbgInitArg) {
  const require = createRequire(import.meta.url);
  const pkgMain = require.resolve('@miden-sdk/miden-sdk');
  const wasmPath = path.join(path.dirname(pkgMain), 'assets', 'miden_client_web.wasm');
  globalThis.__wbgInitArg = { module_or_path: readFileSync(wasmPath) };
}

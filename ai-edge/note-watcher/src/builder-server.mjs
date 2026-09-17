/**
 * note-builder — internal HTTP front for builder.mjs.
 *
 * Runs from the note-watcher image as a SECOND process (compose service
 * `note-builder`, `node src/builder-server.mjs`): same SDK build, same
 * codec module, but a separate process so the watcher stays a pure pull
 * loop and a build storm can never stall a scan tick.
 *
 *   GET  /health   200 {ok:true, wasm:'ready'} once the SDK is loaded,
 *                  503 while loading / if loading failed. auth-service
 *                  preflights this BEFORE committing an on-chain intent,
 *                  so a broken builder costs the user nothing.
 *   POST /build    body: {sender_address, pay_to_address, faucet_id,
 *                         token_amount (decimal string), memo}
 *                  200: {address, recipientAddress, transactionRequest, note_id}
 *                  400: validation (specific reason in `error`)
 *                  401: bearer missing/wrong when BUILDER_TOKEN is set
 *                  500: SDK failure
 *
 * Not publicly routed — compose-internal only. Inputs are all public
 * values and the output can only ever pay the gateway, so the bearer
 * (BUILDER_TOKEN, optional) is defence in depth, not the security line.
 *
 * Builds are serialised through one promise chain: wasm-bindgen objects
 * are not safe under concurrent use ("recursive use of an object …"),
 * and a build is ~milliseconds, so a queue costs nothing.
 */

import http from 'node:http';

import { BuildError, buildTopupPayload, loadWasm, validateBuildRequest } from './builder.mjs';
import { withTimeout } from './util.mjs';

const MAX_BODY_BYTES = 16 * 1024;
const BUILD_TIMEOUT_MS = 30_000;

/** Run async jobs strictly one after another (see header). */
export function makeSerialQueue() {
  let tail = Promise.resolve();
  return (job) => {
    const run = tail.then(job, job);
    tail = run.catch(() => {});   // a failed job must not poison the chain
    return run;
  };
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        reject(new BuildError(`body exceeds ${MAX_BODY_BYTES} bytes`, 413));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || 'null'));
      } catch {
        reject(new BuildError('body must be valid JSON'));
      }
    });
    req.on('error', reject);
  });
}

function send(res, status, body) {
  const data = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json',
    'content-length': Buffer.byteLength(data),
  });
  res.end(data);
}

/**
 * @param {object} deps
 * @param {(req) => Promise<object>} deps.build   validated request → payload
 * @param {() => {ok: boolean, wasm: string}} deps.health
 * @param {string} [deps.token]                   required bearer, '' = none
 * @param {{info, warn, error}} [deps.log]
 */
export function createBuilderServer({ build, health, token = '', log = console }) {
  const serial = makeSerialQueue();

  return http.createServer(async (req, res) => {
    try {
      if (req.method === 'GET' && req.url === '/health') {
        const h = health();
        return send(res, h.ok ? 200 : 503, h);
      }
      if (req.method !== 'POST' || req.url !== '/build') {
        return send(res, 404, { error: 'not found' });
      }
      if (token) {
        const got = (req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
        // Length-independent compare is overkill for an internal hop, but
        // it costs one line and never has to be revisited.
        if (got.length !== token.length
            || !got.split('').every((ch, i) => ch === token[i])) {
          return send(res, 401, { error: 'invalid builder token' });
        }
      }
      const body = await readJson(req);
      const validated = validateBuildRequest(body);
      const payload = await serial(() => withTimeout(
        Promise.resolve().then(() => build(validated)), BUILD_TIMEOUT_MS, 'build'));
      log.info(`built memo=${validated.memo} note=${payload.note_id} `
        + `sender=${validated.senderAddress} amount=${validated.tokenAmount}`);
      return send(res, 200, payload);
    } catch (e) {
      if (e instanceof BuildError) return send(res, e.status, { error: e.message });
      log.error(`build failed: ${e?.stack ?? e}`);
      return send(res, 500, { error: `build failed: ${e?.message ?? e}` });
    }
  });
}

async function main() {
  const port = Number(process.env.BUILDER_PORT ?? 8090);
  const token = process.env.BUILDER_TOKEN ?? '';
  const log = {
    info: (m) => console.log(`[builder] ${m}`),
    warn: (m) => console.warn(`[builder] WARN ${m}`),
    error: (m) => console.error(`[builder] ERROR ${m}`),
  };

  // Load the SDK eagerly so /health tells the truth from the first probe
  // and the first real build does not pay the 17 MB init.
  let wasm = null;
  let wasmState = 'loading';
  loadWasm().then((w) => { wasm = w; wasmState = 'ready'; log.info('SDK WASM ready'); })
    .catch((e) => { wasmState = 'failed'; log.error(`SDK WASM failed to load: ${e?.stack ?? e}`); });

  const server = createBuilderServer({
    token,
    log,
    health: () => ({ ok: wasmState === 'ready', wasm: wasmState }),
    build: async (req) => {
      if (!wasm) throw new BuildError(`SDK not ready (${wasmState})`, 503);
      return buildTopupPayload(wasm, req);
    },
  });
  server.listen(port, '0.0.0.0', () => log.info(`listening on :${port}`
    + (token ? ' (bearer required)' : ' (no bearer configured)')));

  const stop = () => { log.info('shutting down'); server.close(() => process.exit(0)); };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => { console.error(`[builder] fatal: ${e?.stack ?? e}`); process.exit(1); });
}

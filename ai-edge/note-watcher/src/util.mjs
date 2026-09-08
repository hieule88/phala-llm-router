/**
 * withTimeout — bound any promise in time.
 *
 * The watcher is a PULL loop: unlike Stripe's push-and-retry model,
 * nobody notices when we stop pulling. A single hung fetch or RPC call
 * would park runTick forever with the process still "alive", so
 * `restart: always` never fires and no ALERT is ever printed. Every
 * outbound await therefore goes through this wrapper.
 *
 * Note the sharp edge: JS cannot cancel an arbitrary promise. On
 * timeout the LOSING call may still be running underneath (a wedged
 * WASM RPC client stays wedged) — the wrapper only guarantees the tick
 * fails fast and loudly instead of hanging. The in-process watchdog in
 * watcher.mjs is the backstop for the truly-wedged case: no tick
 * progress for WATCHDOG_STALL_SECONDS → exit(1) → docker restarts us
 * with a fresh process (and a fresh WASM client).
 */
export function withTimeout(promise, ms, label) {
  let timer;
  const bomb = new Promise((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, bomb]).finally(() => clearTimeout(timer));
}

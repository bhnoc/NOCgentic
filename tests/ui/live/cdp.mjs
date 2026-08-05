// Minimal CDP helper, shared by the live-UI sweep scripts. Same no-npm-deps
// pattern as tests/ui/*.mjs: raw WebSocket to a headless Chrome instance.
export async function connect(base, cdpPort = 9222) {
  const targets = await (
    await fetch(`http://127.0.0.1:${cdpPort}/json/new?` + encodeURIComponent(base), { method: 'PUT' })
  ).json();
  const ws = new WebSocket(targets.webSocketDebuggerUrl);
  let id = 0;
  const pending = new Map();

  ws.addEventListener('message', (e) => {
    const msg = JSON.parse(e.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
    }
  });
  await new Promise((r) => ws.addEventListener('open', r));

  const send = (method, params = {}) =>
    new Promise((resolve, reject) => {
      const mid = ++id;
      pending.set(mid, { resolve, reject });
      ws.send(JSON.stringify({ id: mid, method, params }));
    });

  const evaluate = async (expr) => {
    const r = await send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error('page threw: ' + JSON.stringify(r.exceptionDetails));
    return r.result.value;
  };

  await send('Page.enable');
  return { ws, send, evaluate, targetId: targets.id };
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function makeCheck() {
  let failures = 0;
  const results = [];
  const check = (name, ok, extra = '') => {
    console.log((ok ? 'PASS  ' : 'FAIL  ') + name + (extra ? '  -> ' + extra : ''));
    results.push({ name, ok, extra });
    if (!ok) failures++;
  };
  check.failures = () => failures;
  check.results = () => results;
  return check;
}

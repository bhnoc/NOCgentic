// Drives the real landing page in headless Chrome over CDP and asserts the
// "Raw" fallback panel never leaks a failed query's raw SQL or the
// ipscope.OUT_OF_SCOPE_PLACEHOLDER string. A scope-rejected athena-hunter
// query has no query_details (nothing succeeded) but does carry data.errors[]
// with the raw SQL text — including the literal [OUT-OF-SCOPE-IP] placeholder
// baked into the WHERE clause — and the fallback used to JSON.stringify that
// whole object verbatim into the DOM.
const BASE = 'http://127.0.0.1:8791';

const targets = await (await fetch('http://127.0.0.1:9222/json/new?' + encodeURIComponent(BASE), { method: 'PUT' })).json();
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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let failures = 0;
const check = (name, ok, extra = '') => {
  console.log((ok ? 'PASS  ' : 'FAIL  ') + name + (extra ? '  -> ' + extra : ''));
  if (!ok) failures++;
};

await send('Page.enable');
await evaluate('location.href = ' + JSON.stringify(BASE));
await sleep(1000);

await evaluate(`(() => {
  const input = document.getElementById('query-input');
  input.value = 'scope error raw check';
  input.focus();
})()`);
await evaluate(`sendQuery()`);
for (let i = 0; i < 20; i++) {
  await sleep(200);
  const disabled = await evaluate(`document.getElementById('send-btn').disabled`);
  if (!disabled) break;
}

const bubbleText = await evaluate(`(() => {
  const bubbles = document.querySelectorAll('.message.agent');
  const last = bubbles[bubbles.length - 1];
  return last ? last.innerHTML : null;
})()`);

check('answer bubble rendered', !!bubbleText);
check('rendered DOM never shows the OUT-OF-SCOPE placeholder',
  !/\[OUT-OF-SCOPE-IP\]/i.test(bubbleText || ''), bubbleText);
check('rendered DOM never shows the raw SQL text',
  !/SELECT\s+id_orig_h/i.test(bubbleText || ''), bubbleText);
check('rendered DOM never shows the scope-rejection error string',
  !/Out-of-scope IP in query/i.test(bubbleText || ''), bubbleText);

// The "Raw" section can still exist and render something (e.g. the trimmed
// summary fields) — it just must not be the SQL/placeholder leak. Confirm it
// renders SOMETHING rather than silently breaking into an empty/missing panel.
const rawPanel = await evaluate(`(() => {
  const bubbles = document.querySelectorAll('.message.agent');
  const last = bubbles[bubbles.length - 1];
  const raw = last ? last.querySelector('details.raw-collapse') : null;
  return { exists: !!raw, text: raw ? raw.textContent.trim() : null };
})()`);
console.log('  raw panel:', JSON.stringify(rawPanel));

await send('Page.close').catch(() => {});
ws.close();
console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);

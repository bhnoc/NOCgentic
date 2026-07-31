// Drives the real landing page in headless Chrome over CDP (no npm deps) and
// asserts a quick-pick chip click auto-submits the query.
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
await sleep(1500);

const chip = await evaluate(`(() => {
  const c = document.querySelectorAll('.example-chip');
  return { count: c.length, first: c[0] ? c[0].textContent.trim() : null };
})()`);
check('landing renders quick-pick chips', chip.count === 5, 'count=' + chip.count);

await evaluate(`document.querySelectorAll('.example-chip')[0].click()`);
await sleep(300);

const afterClick = await evaluate(`(() => ({
  inputValue: document.getElementById('query-input').value,
  userBubbles: [...document.querySelectorAll('.message.user')].map(e => e.textContent),
  bannerGone: !document.getElementById('welcome-banner'),
  sendDisabled: document.getElementById('send-btn').disabled,
}))()`);

check('input cleared (submitted, not just filled)', afterClick.inputValue === '', JSON.stringify(afterClick.inputValue));
check('user message appended', afterClick.userBubbles.length === 1 && afterClick.userBubbles[0].includes(chip.first),
  JSON.stringify(afterClick.userBubbles));
check('welcome banner removed', afterClick.bannerGone === true);
check('send button disabled while in flight', afterClick.sendDisabled === true);

const posted = await (await fetch(BASE + '/__received')).json();
check('server received exactly one POST', posted.length === 1, JSON.stringify(posted));
check('POST body carries chip text', posted[0] && posted[0].query === chip.first,
  JSON.stringify(posted[0] && posted[0].query) + ' vs ' + JSON.stringify(chip.first));

// Chips live only in the welcome banner, which is gone after the first submit,
// so re-entrancy is checked by calling fillQuery directly while in flight.
const reentrant = await evaluate(`(() => {
  const b = document.createElement('button');
  b.textContent = 'should be ignored while in flight';
  fillQuery(b);
  return document.getElementById('query-input').value;
})()`);
await sleep(300);
const posted2 = await (await fetch(BASE + '/__received')).json();
check('click ignored while a query is in flight', posted2.length === 1 && reentrant === '',
  'posts=' + posted2.length + ' inputValue=' + JSON.stringify(reentrant));

await sleep(2500);
const settled = await evaluate(`(() => ({
  agentBubbles: [...document.querySelectorAll('.message.agent')].map(e => e.textContent.replace(/\\s+/g, ' ').trim()),
  sendDisabled: document.getElementById('send-btn').disabled,
}))()`);
check('answer rendered', settled.agentBubbles.some(t => t.includes('stub answer')), JSON.stringify(settled.agentBubbles));
check('send button re-enabled after completion', settled.sendDisabled === false);

await send('Page.close').catch(() => {});
ws.close();
console.log(failures === 0 ? '\nALL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);

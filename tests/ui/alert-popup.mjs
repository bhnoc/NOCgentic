// Drives the real landing page in headless Chrome over CDP and asserts the
// alert-detail popup: clicking a feed card opens it, it carries the alert's
// fields and its hunt chips, it drags by the header and stays inside the
// viewport, it closes three ways (X, backdrop, Escape), and a hunt chip sends a
// real query.
//
// Unit tests cover the hint text itself (packages/web-server/test/alertHints.test.ts);
// only a real DOM can prove the card is clickable, that pointer capture drag
// math lands where the pointer did, and that the backdrop click closes rather
// than swallowing the click.
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

const pageErrors = [];
await send('Runtime.enable');
await send('Log.enable');
ws.addEventListener('message', (e) => {
  const msg = JSON.parse(e.data);
  if (msg.method === 'Runtime.exceptionThrown') pageErrors.push(JSON.stringify(msg.params));
  const entry = msg.method === 'Log.entryAdded' ? msg.params?.entry : null;
  if (entry && entry.level === 'error' && entry.source === 'javascript') pageErrors.push(entry.text);
});

await send('Page.enable');
await evaluate('location.href = ' + JSON.stringify(BASE));
await sleep(1500);

// The stub has no alert routes; feed the page the same shape the WebSocket does.
const ALERTS = `[
  { id:'t1', severity:'critical', source:'paloalto',
    description:'C2 beacon detected -- high frequency TCP/4444',
    srcIp:'45.83.193.150', dstIp:'8.8.4.4', dstPort:4444, action:'allow',
    timestamp:'2026-08-04T18:22:10.000Z' },
  { id:'t2', severity:'high', source:'corelight',
    description:'Port scan -- 1,247 SYN packets in 10s',
    srcIp:'10.220.152.9', timestamp:'2026-08-04T18:20:00.000Z' }
]`;
// Evaluated as a JS literal, NOT JSON.parse'd: the fixture above uses unquoted keys
// and single quotes, so JSON.parse threw SyntaxError on line 2 and the whole popup
// gate died before its first check. It failed loudly rather than silently, but a gate
// that always errors is a gate nobody reads.
await evaluate(`renderAlerts(${ALERTS})`);

const feed = await evaluate(`(() => ({
  cards: document.querySelectorAll('.alert-card').length,
  clickable: document.querySelector('.alert-card[data-id="t1"]')?.getAttribute('role') || null,
  modalHidden: document.getElementById('alert-modal').hidden,
}))()`);
check('feed rendered both alerts', feed.cards === 2, 'cards=' + feed.cards);
check('cards announce themselves as clickable', feed.clickable === 'button', JSON.stringify(feed.clickable));
check('popup starts hidden', feed.modalHidden === true);

// ---- open by clicking the card ----
await evaluate(`document.querySelector('.alert-card[data-id="t1"]').click()`);
await sleep(150);

const opened = await evaluate(`(() => {
  const modal = document.getElementById('alert-modal');
  const chips = [...modal.querySelectorAll('.hint-chip')].map(c => c.getAttribute('data-hint'));
  const r = modal.getBoundingClientRect();
  return {
    hidden: modal.hidden,
    backdropHidden: document.getElementById('alert-modal-backdrop').hidden,
    sevClass: modal.className,
    text: modal.textContent.replace(/\\s+/g, ' ').trim(),
    chips,
    onScreen: r.left >= 0 && r.top >= 0 && r.right <= window.innerWidth + 1 && r.bottom <= window.innerHeight + 1,
    focusIsClose: document.activeElement === document.getElementById('alert-modal-close'),
  };
})()`);
check('clicking a card opens the popup', opened.hidden === false && opened.backdropHidden === false);
check('popup wears the alert severity', /sev-card-critical/.test(opened.sevClass), opened.sevClass);
check('popup shows the description', /C2 beacon detected/.test(opened.text));
check('popup shows source, addresses, port and action',
  ['paloalto', '45.83.193.150', '8.8.4.4', '4444', 'allow'].every(s => opened.text.includes(s)),
  JSON.stringify(opened.text));
check('popup opens fully inside the viewport', opened.onScreen === true);
check('focus moves into the dialog', opened.focusIsClose === true);
check('hunt chips rendered, capped at five',
  opened.chips.length > 0 && opened.chips.length <= 5, 'chips=' + JSON.stringify(opened.chips));
check('hunt chips are anchored on this alert',
  opened.chips.some(c => c.includes('45.83.193.150')) && opened.chips.some(c => c.includes('4444')),
  JSON.stringify(opened.chips));

// ---- drag by the header ----
// Let the 0.16s modalIn animation finish first. It ends on translateY(-6px) -> 0, so
// a getBoundingClientRect taken while it is still running is 6px above where left/top
// actually put the panel, and every drag and clamp assertion below is then off by
// that much for reasons that have nothing to do with the drag code.
await sleep(400);
const dragged = await evaluate(`(() => {
  const modal = document.getElementById('alert-modal');
  const head = document.getElementById('alert-modal-head');
  const r0 = modal.getBoundingClientRect();
  const mk = (type, px, py) => new PointerEvent(type, {
    bubbles: true, cancelable: true, pointerId: 1, pointerType: 'mouse', button: 0, buttons: 1,
    clientX: px, clientY: py,
  });
  const sx = r0.left + 40, sy = r0.top + 8;
  head.dispatchEvent(mk('pointerdown', sx, sy));
  head.dispatchEvent(mk('pointermove', sx + 60, sy + 40));
  const mid = modal.getBoundingClientRect();
  head.dispatchEvent(mk('pointerup', sx + 60, sy + 40));
  // A move after pointerup must not keep dragging.
  head.dispatchEvent(mk('pointermove', sx + 300, sy + 300));
  const after = modal.getBoundingClientRect();
  return {
    dx: Math.round(mid.left - r0.left), dy: Math.round(mid.top - r0.top),
    stuckAfterUp: Math.round(after.left - mid.left) === 0 && Math.round(after.top - mid.top) === 0,
    dragClass: modal.classList.contains('dragging'),
  };
})()`);
check('header drag moves the popup with the pointer', dragged.dx === 60 && dragged.dy === 40,
  'dx=' + dragged.dx + ' dy=' + dragged.dy);
check('drag ends on pointerup', dragged.stuckAfterUp === true && dragged.dragClass === false);

const clamped = await evaluate(`(() => {
  const modal = document.getElementById('alert-modal');
  const head = document.getElementById('alert-modal-head');
  const mk = (type, px, py) => new PointerEvent(type, {
    bubbles: true, cancelable: true, pointerId: 1, pointerType: 'mouse', button: 0, buttons: 1,
    clientX: px, clientY: py,
  });
  const r0 = modal.getBoundingClientRect();
  head.dispatchEvent(mk('pointerdown', r0.left + 40, r0.top + 8));
  head.dispatchEvent(mk('pointermove', 99999, 99999));
  head.dispatchEvent(mk('pointerup', 99999, 99999));
  const far = modal.getBoundingClientRect();
  head.dispatchEvent(mk('pointerdown', far.left + 40, far.top + 8));
  head.dispatchEvent(mk('pointermove', -99999, -99999));
  head.dispatchEvent(mk('pointerup', -99999, -99999));
  const near = modal.getBoundingClientRect();
  return {
    farInside: far.right <= window.innerWidth + 1 && far.bottom <= window.innerHeight + 1,
    nearInside: near.left >= -1 && near.top >= -1,
  };
})()`);
check('dragging past the bottom-right keeps the popup on screen', clamped.farInside === true);
check('dragging past the top-left keeps the popup on screen', clamped.nearInside === true);

// ---- close: the X ----
await evaluate(`document.getElementById('alert-modal-close').click()`);
await sleep(120);
let state = await evaluate(`(() => ({
  hidden: document.getElementById('alert-modal').hidden,
  backdropHidden: document.getElementById('alert-modal-backdrop').hidden,
  body: document.getElementById('alert-modal-body').innerHTML.trim(),
}))()`);
check('X closes the popup', state.hidden === true && state.backdropHidden === true);
check('closing clears the popup body', state.body === '');

// ---- close: a click anywhere else ----
await evaluate(`document.querySelector('.alert-card[data-id="t1"]').click()`);
await sleep(120);
await evaluate(`document.getElementById('alert-modal-backdrop').click()`);
await sleep(120);
state = await evaluate(`(() => ({ hidden: document.getElementById('alert-modal').hidden }))()`);
check('clicking outside closes the popup', state.hidden === true);

// ---- close: Escape ----
await evaluate(`document.querySelector('.alert-card[data-id="t1"]').click()`);
await sleep(120);
await evaluate(`document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))`);
await sleep(120);
state = await evaluate(`(() => ({ hidden: document.getElementById('alert-modal').hidden }))()`);
check('Escape closes the popup', state.hidden === true);

// A click inside the panel must NOT close it (the backdrop is a sibling, not a wrapper).
await evaluate(`document.querySelector('.alert-card[data-id="t1"]').click()`);
await sleep(120);
await evaluate(`document.querySelector('.alert-detail-desc').click()`);
await sleep(120);
state = await evaluate(`(() => ({ hidden: document.getElementById('alert-modal').hidden }))()`);
check('clicking inside the popup keeps it open', state.hidden === false);

// Reopening re-centres rather than leaving the panel where it was dragged.
await evaluate(`document.getElementById('alert-modal-close').click()`);
await sleep(120);
await evaluate(`document.querySelector('.alert-card[data-id="t1"]').click()`);
await sleep(120);
const recentred = await evaluate(`(() => {
  const r = document.getElementById('alert-modal').getBoundingClientRect();
  return Math.abs((window.innerWidth - r.width) / 2 - r.left) <= 1;
})()`);
check('reopening re-centres the popup', recentred === true);

// ---- a hunt chip sends a real query ----
const chipText = await evaluate(`document.querySelector('.alert-modal .hint-chip').getAttribute('data-hint')`);
await evaluate(`document.querySelector('.alert-modal .hint-chip').click()`);
await sleep(2600);
const afterChip = await evaluate(`(() => ({
  hidden: document.getElementById('alert-modal').hidden,
  lastUser: [...document.querySelectorAll('.message.user .message-bubble')].pop()?.textContent.trim() || null,
}))()`);
const received = await (await fetch(BASE + '/__received')).json();
check('clicking a hunt chip closes the popup', afterChip.hidden === true);
check('clicking a hunt chip sends that exact query',
  received.some(r => r.query === chipText), JSON.stringify({ chipText, received }));
check('the sent query is echoed in the transcript', afterChip.lastUser === chipText,
  JSON.stringify(afterChip.lastUser));

// ---- restricted-subnet alert: displayed, never turned into a question ----
await evaluate(`document.querySelector('.alert-card[data-id="t2"]').click()`);
await sleep(150);
const restricted = await evaluate(`(() => {
  const modal = document.getElementById('alert-modal');
  return {
    shownIp: modal.textContent.includes('10.220.152.9'),
    chips: [...modal.querySelectorAll('.hint-chip')].map(c => c.getAttribute('data-hint')),
  };
})()`);
check('a restricted address still shows in the detail body', restricted.shownIp === true);
check('no hunt chip is built around a restricted address',
  restricted.chips.length > 0 && restricted.chips.every(c => !c.includes('10.220.152.9')),
  JSON.stringify(restricted.chips));

// ---- the Triage button sends a guardrail-safe query about this alert ----
// t2 is the restricted-subnet alert and the popup is already open on it, which is the
// case worth checking: the button has to submit something, and it must not be the
// address or the vendor prose in the description.
const triageText = await evaluate(`(() => {
  const btn = document.querySelector('.alert-modal .alert-triage-btn');
  if (!btn) return null;
  btn.click();
  return true;
})()`);
await sleep(2600);
const afterTriage = await evaluate(`(() => ({
  hidden: document.getElementById('alert-modal').hidden,
  lastUser: [...document.querySelectorAll('.message.user .message-bubble')].pop()?.textContent.trim() || null,
}))()`);
check('the Triage button exists', triageText === true);
check('Triage closes the popup', afterTriage.hidden === true);
check('Triage sent a query', typeof afterTriage.lastUser === 'string' && afterTriage.lastUser.length > 0,
  JSON.stringify(afterTriage.lastUser));
check('the Triage query carries no restricted address',
  !(afterTriage.lastUser || '').includes('10.220.152.9'), JSON.stringify(afterTriage.lastUser));
check('the Triage query carries no vendor prose from the description',
  !/corelight|paloalto|suricata/i.test(afterTriage.lastUser || ''),
  JSON.stringify(afterTriage.lastUser));

check('no uncaught page errors', pageErrors.length === 0, pageErrors.join(' | '));

await send('Page.close').catch(() => {});
ws.close();
console.log(failures === 0 ? '\nALL ALERT POPUP CHECKS PASSED' : `\n${failures} ALERT POPUP CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);

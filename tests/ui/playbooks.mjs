// Drives the real landing page in headless Chrome over CDP and asserts the
// Playbooks tab: the tab opens the catalog view and hides chat, results render
// from /api/v1/catalog/search, typing filters them, clicking one renders its
// markdown (escaped: a literal <script> in the fixture body must come out as
// text), "Hunt this live" hands the playbook's question to chat as a real
// query, an alert popup carries a Playbooks row that opens the tab on the
// right entry, and #playbooks/PB-nn deep links resolve.
//
// Indexing and ranking are unit-tested (packages/web-server/test/huntCatalog.test.ts);
// this gate covers what only a DOM can: the three-way view switch, the hash
// routing, and the click paths between the alert feed, the catalog and chat.
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
const waitFor = async (expr, ms = 3000) => {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (await evaluate(expr)) return true;
    await sleep(50);
  }
  return false;
};

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

// ---- the tab switches views ----
const before = await evaluate(`(() => ({
  tab: !!document.getElementById('tab-catalog'),
  view: document.getElementById('catalog-view')?.hidden,
  main: document.querySelector('main').hidden,
}))()`);
check('Playbooks tab is in the header', before.tab === true);
check('catalog view starts hidden', before.view === true);

await evaluate(`document.getElementById('tab-catalog').click()`);
const listed = await waitFor(`document.querySelectorAll('.catalog-result').length === 2`);
const opened = await evaluate(`(() => ({
  view: document.getElementById('catalog-view').hidden,
  main: document.querySelector('main').hidden,
  sidebar: document.querySelector('.sidebar').hidden,
  hunt: document.getElementById('hunt-view').hidden,
  tabActive: document.getElementById('tab-catalog').classList.contains('active'),
  chatActive: document.getElementById('tab-chat').classList.contains('active'),
  hash: location.hash,
  facets: document.querySelectorAll('#catalog-sections .catalog-chip').length,
  sources: document.querySelectorAll('#catalog-sources .catalog-chip').length,
  welcome: !!document.querySelector('#catalog-detail .catalog-welcome'),
}))()`);
check('clicking the tab shows the catalog and hides chat + sidebar', !opened.view && opened.main && opened.sidebar && opened.hunt, JSON.stringify(opened));
check('tab active states follow the view', opened.tabActive && !opened.chatActive);
check('hash becomes #playbooks', opened.hash === '#playbooks', opened.hash);
check('results list renders every fixture entry', listed === true);
check('section and data-source facets render', opened.facets >= 2 && opened.sources >= 2, JSON.stringify([opened.facets, opened.sources]));
check('detail pane opens on the welcome text', opened.welcome === true);

// ---- typing filters ----
await evaluate(`(() => {
  const q = document.getElementById('catalog-q');
  q.value = 'dns';
  q.dispatchEvent(new Event('input', { bubbles: true }));
})()`);
const filtered = await waitFor(`document.querySelectorAll('.catalog-result').length === 1 && document.querySelector('.catalog-result').getAttribute('data-id') === 'PB-02'`);
check('typing in the search box narrows the list (debounced fetch)', filtered === true);
await evaluate(`(() => {
  const q = document.getElementById('catalog-q');
  q.value = '';
  q.dispatchEvent(new Event('input', { bubbles: true }));
})()`);
await waitFor(`document.querySelectorAll('.catalog-result').length === 2`);

// ---- open an entry ----
await evaluate(`document.querySelector('.catalog-result[data-id="PB-01"]').click()`);
await waitFor(`!!document.querySelector('#catalog-detail .catalog-md')`);
const detail = await evaluate(`(() => {
  const d = document.getElementById('catalog-detail');
  const md = d.querySelector('.catalog-md');
  return {
    title: d.querySelector('.catalog-detail-title')?.textContent,
    badge: d.querySelector('.catalog-id-badge')?.textContent,
    h3: md.querySelector('h3')?.textContent,
    table: !!md.querySelector('table th'),
    pre: md.querySelector('pre code')?.textContent,
    lang: md.querySelector('pre')?.getAttribute('data-lang'),
    li: md.querySelectorAll('ul li').length,
    scriptTags: md.querySelectorAll('script').length,
    escapedText: md.textContent.includes('<script>alert(1)</script>'),
    huntBtn: !!document.getElementById('catalog-hunt-btn'),
    hash: location.hash,
    active: document.querySelector('.catalog-result.active')?.getAttribute('data-id'),
    techniqueChip: !!d.querySelector('[data-technique="T1071"]'),
  };
})()`);
check('entry title and id badge render', detail.title === 'C2 Beaconing Detection' && detail.badge === 'PB-01', JSON.stringify([detail.title, detail.badge]));
check('markdown headings demote one level (## -> h3)', detail.h3 === 'Hypothesis', detail.h3);
check('markdown table, fenced code and list render', detail.table && detail.pre === 'rita show-beacons ds' && detail.lang === 'bash' && detail.li === 2, JSON.stringify(detail));
check('a <script> in the body is text, not a tag', detail.scriptTags === 0 && detail.escapedText === true);
check('hash deep-links the open entry', detail.hash === '#playbooks/PB-01', detail.hash);
check('the open entry is highlighted in the list', detail.active === 'PB-01');
check('ATT&CK chip renders for the entry', detail.techniqueChip === true);
check('Hunt this live button is present for a playbook', detail.huntBtn === true);

// ---- technique chip filters the list ----
await evaluate(`document.querySelector('#catalog-detail [data-technique="T1071"]').click()`);
const techFilter = await waitFor(`!document.getElementById('catalog-active-filter').hidden && document.getElementById('catalog-active-filter').textContent.includes('T1071')`);
check('clicking a technique chip sets an active technique filter', techFilter === true);
await evaluate(`document.querySelector('#catalog-active-filter [data-clear-technique]').click()`);
await sleep(100);

// ---- hunt this live hands off to chat ----
await evaluate(`document.getElementById('catalog-hunt-btn').click()`);
await sleep(400);
const afterHunt = await evaluate(`(() => ({
  main: document.querySelector('main').hidden,
  view: document.getElementById('catalog-view').hidden,
  hash: location.hash,
}))()`);
const received = await (await fetch(BASE + '/__received')).json();
check('Hunt this live returns to the chat view', afterHunt.main === false && afterHunt.view === true, JSON.stringify(afterHunt));
check('Hunt this live sends the playbook question as a real query',
  received.some((r) => r.query === 'STUB HUNT: any hosts beaconing on a regular interval today?'), JSON.stringify(received));

// ---- alert popup carries a Playbooks row ----
await evaluate(`renderAlerts([
  { id:'p1', severity:'critical', source:'suricata',
    description:'C2 beacon detected -- high frequency TCP/4444',
    srcIp:'45.83.193.150', dstIp:'8.8.4.4', dstPort:4444, timestamp:'2026-08-04T18:22:10.000Z' },
  { id:'p2', severity:'low', source:'notice',
    description:'Nothing the topic map knows about',
    srcIp:'45.83.193.151', timestamp:'2026-08-04T18:22:10.000Z' }
])`);
await evaluate(`document.querySelector('.alert-card[data-id="p1"]').click()`);
await sleep(200);
const popup = await evaluate(`(() => {
  const modal = document.getElementById('alert-modal');
  const chips = [...modal.querySelectorAll('.playbook-chip')].map(c => c.getAttribute('data-playbook'));
  const hintChips = modal.querySelectorAll('.hint-chip').length;
  return { hidden: modal.hidden, chips, hintChips, label: modal.querySelector('.playbook-row .hints-label')?.textContent };
})()`);
// The topic map names PB-01 and PB-10; the stub index only carries PB-01, so
// the unknown id is dropped rather than rendered as a dead chip.
check('a C2 alert popup shows a Playbooks row from the topic map', !popup.hidden && popup.label === 'Playbooks' && popup.chips.join(',') === 'PB-01', JSON.stringify(popup));
check('hunt hint chips still render alongside', popup.hintChips > 0);

await evaluate(`document.querySelector('.alert-modal .playbook-chip[data-playbook="PB-01"]').click()`);
const viaPopup = await waitFor(`!document.getElementById('catalog-view').hidden && document.querySelector('#catalog-detail .catalog-id-badge')?.textContent === 'PB-01'`);
const popupClosed = await evaluate(`document.getElementById('alert-modal').hidden`);
check('clicking the chip closes the popup and opens that playbook', viaPopup === true && popupClosed === true);

// An alert with no known topic gets no row, not a wrong one.
await evaluate(`document.getElementById('tab-chat').click()`);
await sleep(100);
await evaluate(`document.querySelector('.alert-card[data-id="p2"]').click()`);
await sleep(200);
const noRow = await evaluate(`document.querySelectorAll('#alert-modal .playbook-row').length`);
check('an alert with no mapped topic shows no Playbooks row', noRow === 0);
await evaluate(`document.getElementById('alert-modal-close').click()`);

// ---- deep link ----
await evaluate(`location.hash = '#playbooks/PB-02'`);
const deep = await waitFor(`!document.getElementById('catalog-view').hidden && document.querySelector('#catalog-detail .catalog-id-badge')?.textContent === 'PB-02'`);
check('#playbooks/PB-02 deep link opens that entry', deep === true);

// ---- the logo resets to chat ----
await evaluate(`resetToHome()`);
await sleep(200);
const home = await evaluate(`(() => ({ main: document.querySelector('main').hidden, view: document.getElementById('catalog-view').hidden, hash: location.hash }))()`);
check('logo reset leaves the catalog and returns to chat', home.main === false && home.view === true && home.hash === '', JSON.stringify(home));

// Filter out the stub's missing routes (/ws, threat-hunt scripts) which the
// other gates tolerate too; anything else thrown by the page is a failure.
const realErrors = pageErrors.filter((e) => !/threat-hunt|reportIssue|html2canvas|WebSocket|\/ws/.test(e));
check('no page errors', realErrors.length === 0, realErrors.join(' | '));

ws.close();
process.exit(failures ? 1 : 0);

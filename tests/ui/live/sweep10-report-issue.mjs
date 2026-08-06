// Sweep 10: verify sweep 7 (mobile overflow) and sweep 8 (threat-hunt
// double-click) fixes still hold, and probe the new report-issue button
// (packages/web-server/static/reportIssue.js) for the same classes of bug:
// mobile overflow/collision and double-click re-entrancy.
import { connect, sleep, makeCheck } from './cdp.mjs';

const BASE = process.env.QA_BASE || 'https://ng.bhnoc.com';
const CDP_PORT = Number(process.env.CDP_PORT || 9225);
const check = makeCheck();

const { evaluate, send, ws } = await connect(BASE, CDP_PORT);
const pageErrors = [];
await send('Runtime.enable');
ws.addEventListener('message', (e) => {
  const msg = JSON.parse(e.data);
  if (msg.method === 'Runtime.exceptionThrown') pageErrors.push(msg.params.exceptionDetails.text);
});

// Force a 390px mobile viewport regardless of window size.
await send('Emulation.setDeviceMetricsOverride', {
  width: 390, height: 844, deviceScaleFactor: 2, mobile: true,
});

console.log('=== 1. Mobile overflow: main chat view ===');
await evaluate('location.href = ' + JSON.stringify(BASE));
await sleep(2500);
let overflow = await evaluate(`(() => ({
  scrollWidth: document.body.scrollWidth,
  innerWidth: window.innerWidth,
}))()`);
console.log('  chat view:', JSON.stringify(overflow));
check('no horizontal overflow on chat view at 390px', overflow.scrollWidth <= overflow.innerWidth, JSON.stringify(overflow));

console.log('=== 2. Report-issue button presence + geometry at mobile width ===');
let btnBox = await evaluate(`(() => {
  const b = document.getElementById('report-issue-btn');
  if (!b) return null;
  const r = b.getBoundingClientRect();
  return { visible: !b.hidden && r.width > 0, rect: { top: r.top, left: r.left, right: r.right, bottom: r.bottom } };
})()`);
console.log('  report-issue-btn box:', JSON.stringify(btnBox));
check('report-issue button present and visible on chat view (mobile)', !!(btnBox && btnBox.visible), JSON.stringify(btnBox));

// Check for overlap with any other visible fixed/interactive control near
// the bottom-right corner (e.g. send button, alert feed controls).
let collision = await evaluate(`(() => {
  const btn = document.getElementById('report-issue-btn');
  if (!btn) return { checked: false };
  const r = btn.getBoundingClientRect();
  const cx = r.left + r.width / 2, cy = r.top + r.height / 2;
  const els = document.elementsFromPoint(cx, cy);
  const others = els.filter(el => el !== btn && !btn.contains(el) && el.tagName !== 'HTML' && el.tagName !== 'BODY');
  return { checked: true, topElement: els[0] ? els[0].id || els[0].className : null, stack: others.map(el => el.id || el.tagName) };
})()`);
console.log('  collision probe at button center:', JSON.stringify(collision));
check('report-issue button is the topmost element at its own center point',
  collision.checked && (collision.topElement === 'report-issue-btn'), JSON.stringify(collision));

console.log('=== 3. Open report-issue panel at mobile width, re-check overflow ===');
await evaluate(`document.getElementById('report-issue-btn')?.click()`);
await sleep(1200); // allow html2canvas capture
overflow = await evaluate(`(() => ({ scrollWidth: document.body.scrollWidth, innerWidth: window.innerWidth }))()`);
console.log('  with panel open:', JSON.stringify(overflow));
check('no horizontal overflow with report-issue panel open at 390px', overflow.scrollWidth <= overflow.innerWidth, JSON.stringify(overflow));

let panelBox = await evaluate(`(() => {
  const p = document.getElementById('report-issue-panel');
  if (!p || p.hidden) return null;
  const r = p.getBoundingClientRect();
  return { left: r.left, right: r.right, top: r.top, bottom: r.bottom, viewportW: window.innerWidth, viewportH: window.innerHeight };
})()`);
console.log('  panel box:', JSON.stringify(panelBox));
check('report-issue panel stays within viewport bounds at 390px',
  !!panelBox && panelBox.left >= 0 && panelBox.right <= panelBox.viewportW && panelBox.bottom <= panelBox.viewportH,
  JSON.stringify(panelBox));

// close panel
await evaluate(`document.getElementById('report-issue-close')?.click()`);
await sleep(400);

console.log('=== 4. Report-issue button double-click re-entrancy (chat view) ===');
await evaluate(`(() => {
  const b = document.getElementById('report-issue-btn');
  if (b) { b.click(); b.click(); }
})()`);
await sleep(1500);
let dblState = await evaluate(`(() => ({
  panelHidden: document.getElementById('report-issue-panel')?.hidden,
  backdropHidden: document.getElementById('report-issue-backdrop')?.hidden,
  panelCount: document.querySelectorAll('#report-issue-panel').length,
  previewImgCount: document.querySelectorAll('#report-issue-preview img').length,
}))()`);
console.log('  after double-click open:', JSON.stringify(dblState));
check('double-clicking report-issue button does not duplicate the preview image (single screenshot capture)',
  dblState.previewImgCount <= 1, JSON.stringify(dblState));

// Now test double-click on submit -> should not fire two uploads.
let fetchCount = { n: 0 };
await evaluate(`(() => {
  window.__reportIssueFetchCount = 0;
  const origFetch = window.fetch;
  window.fetch = function (...args) {
    if (String(args[0]).includes('/api/v1/report-issue')) window.__reportIssueFetchCount++;
    return origFetch.apply(this, args);
  };
})()`);
await evaluate(`(() => {
  const note = document.getElementById('report-issue-note');
  if (note) note.value = 'qa sweep 10 double-click probe';
})()`);
await evaluate(`(() => {
  const btn = document.getElementById('report-issue-submit');
  if (btn) { btn.click(); btn.click(); }
})()`);
await sleep(1500);
const submitFetchCount = await evaluate(`window.__reportIssueFetchCount`);
console.log('  fetches fired by double-clicking submit:', submitFetchCount);
check('double-clicking Send fires at most one /api/v1/report-issue request',
  submitFetchCount <= 1, 'count=' + submitFetchCount);

await evaluate(`document.getElementById('report-issue-close')?.click()`).catch(() => {});
await sleep(400);

console.log('=== 5. Threat Hunt: mobile overflow + report-issue button presence ===');
await evaluate(`document.getElementById('tab-hunt')?.click()`);
await sleep(1200);
overflow = await evaluate(`(() => ({ scrollWidth: document.body.scrollWidth, innerWidth: window.innerWidth }))()`);
console.log('  hunt picker view:', JSON.stringify(overflow));
check('no horizontal overflow on Threat Hunt picker at 390px', overflow.scrollWidth <= overflow.innerWidth, JSON.stringify(overflow));

btnBox = await evaluate(`(() => {
  const b = document.getElementById('report-issue-btn');
  if (!b) return null;
  const r = b.getBoundingClientRect();
  return { visible: !b.hidden && r.width > 0 };
})()`);
check('report-issue button present on Threat Hunt picker view', !!(btnBox && btnBox.visible), JSON.stringify(btnBox));

async function enterHunt(index = 0) {
  await evaluate(`document.querySelectorAll('.hunt-picker-item')[${index}]?.click()`);
  await sleep(600);
  await evaluate(`document.getElementById('hunt-start-btn')?.click()`);
  await sleep(800);
}
await enterHunt(0);

overflow = await evaluate(`(() => ({ scrollWidth: document.body.scrollWidth, innerWidth: window.innerWidth }))()`);
console.log('  in-hunt view:', JSON.stringify(overflow));
check('no horizontal overflow inside a Threat Hunt scenario at 390px', overflow.scrollWidth <= overflow.innerWidth, JSON.stringify(overflow));

// Check report-issue button doesn't overlap hunt controls (exit buttons / actions box).
let huntCollision = await evaluate(`(() => {
  const btn = document.getElementById('report-issue-btn');
  const exitBtn = document.querySelector('.hunt-exit button:not([disabled])');
  if (!btn || !exitBtn) return { checked: false, hasExitBtn: !!exitBtn };
  const a = btn.getBoundingClientRect();
  const b = exitBtn.getBoundingClientRect();
  const overlap = !(a.right < b.left || a.left > b.right || a.bottom < b.top || a.top > b.bottom);
  return { checked: true, overlap, btnRect: a, exitRect: b };
})()`);
console.log('  report-issue vs exit-button overlap check:', JSON.stringify(huntCollision));
check('report-issue button does not overlap an active hunt exit button at 390px',
  !(huntCollision.checked && huntCollision.overlap), JSON.stringify(huntCollision));

console.log('=== 6. Threat Hunt double-click regressions (sweep 8) re-check ===');
const beforeDoubleClick = await evaluate(`(() => ({
  feedLineCount: document.querySelectorAll('#hunt-feed > *').length,
}))()`);
await evaluate(`(() => {
  const btn = document.querySelector('.hunt-exit button:not([disabled])');
  if (btn) { btn.click(); btn.click(); }
})()`);
await sleep(900);
const feedLinesAfter = await evaluate(`(() => [...document.querySelectorAll('#hunt-feed > *')].map(el => el.textContent.trim()))()`);
const dupeLines = feedLinesAfter.filter((line, i) => feedLinesAfter.indexOf(line) !== i && line.length > 10);
console.log('  before:', JSON.stringify(beforeDoubleClick), ' feed lines after:', feedLinesAfter.length, ' dupes:', dupeLines.length);
check('double-clicking an exit does not duplicate a narration line (regression check, 390px)',
  dupeLines.length === 0, JSON.stringify(dupeLines));

// Walk to decision node.
for (let i = 0; i < 8; i++) {
  const state = await evaluate(`(() => {
    const box = document.getElementById('hunt-actions');
    const exitBtns = [...document.querySelectorAll('.hunt-exit button')].filter(b => !b.disabled);
    const isDecision = exitBtns.length === 0 && box && box.querySelectorAll('button').length > 0;
    return { isDecision, hasExit: exitBtns.length > 0 };
  })()`);
  if (state.isDecision) break;
  if (!state.hasExit) break;
  await evaluate(`(() => {
    const btn = document.querySelector('.hunt-exit button:not([disabled])');
    if (btn) btn.click();
  })()`);
  await sleep(500);
}
const atDecision = await evaluate(`(() => {
  const box = document.getElementById('hunt-actions');
  return !!box && box.querySelectorAll('button').length > 0 && document.querySelectorAll('.hunt-exit').length === 0;
})()`);
check('reached the decision node before double-click regression check', atDecision);

if (atDecision) {
  await evaluate(`(() => {
    const box = document.getElementById('hunt-actions');
    const btn = box ? box.querySelector('button') : null;
    if (btn) { btn.click(); btn.click(); }
  })()`);
  await sleep(1000);
  const dialogCount = await evaluate(`document.querySelectorAll('.hunt-dialog-overlay').length`);
  check('double-clicking a decision action opens exactly one end dialog (regression check, 390px)',
    dialogCount === 1, 'count=' + dialogCount);

  // While the end dialog is up, check report-issue button doesn't collide with it
  // and z-index ordering holds (dialog overlay should be reachable/clickable, i.e.
  // report-issue should NOT sit on top of the dialog's buttons).
  const dialogVsBtn = await evaluate(`(() => {
    const dlgBtn = document.querySelector('.hunt-dialog-overlay button, .hunt-dialog-footer button');
    if (!dlgBtn) return { checked: false };
    const r = dlgBtn.getBoundingClientRect();
    const cx = r.left + r.width/2, cy = r.top + r.height/2;
    const top = document.elementFromPoint(cx, cy);
    return { checked: true, topIsDialogBtn: top === dlgBtn || dlgBtn.contains(top) || top.contains(dlgBtn) };
  })()`);
  console.log('  end-dialog button topmost check:', JSON.stringify(dialogVsBtn));
  check('end-dialog buttons remain clickable (not obscured by report-issue button)',
    !dialogVsBtn.checked || dialogVsBtn.topIsDialogBtn, JSON.stringify(dialogVsBtn));
}

check('no uncaught page errors during sweep', pageErrors.length === 0, JSON.stringify(pageErrors));

await send('Page.close').catch(() => {});
ws.close();
console.log(check.failures() === 0 ? '\nALL CHECKS PASSED' : `\n${check.failures()} CHECK(S) FAILED`);
process.exit(check.failures() === 0 ? 0 : 1);

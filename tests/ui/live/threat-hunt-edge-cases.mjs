// Edge cases the two prior threat-hunt scripts don't cover: leaving mid-hunt
// (before the decision node), and rapid double-clicks on exits/actions (the
// same click-flood class of bug found in sweep 1's chat hint chips).
import { connect, sleep, makeCheck } from './cdp.mjs';

const BASE = process.env.QA_BASE || 'https://ng.bhnoc.com';
const CDP_PORT = Number(process.env.CDP_PORT || 9222);
const check = makeCheck();

const { evaluate, send, ws } = await connect(BASE, CDP_PORT);
const pageErrors = [];
await send('Runtime.enable');
ws.addEventListener('message', (e) => {
  const msg = JSON.parse(e.data);
  if (msg.method === 'Runtime.exceptionThrown') pageErrors.push(msg.params.exceptionDetails.text);
});

async function enterHunt(index = 0) {
  await evaluate('location.href = ' + JSON.stringify(BASE));
  await sleep(3000);
  await evaluate(`document.getElementById('tab-hunt').click()`);
  await sleep(1000);
  await evaluate(`document.querySelectorAll('.hunt-picker-item')[${index}]?.click()`);
  await sleep(600);
  await evaluate(`document.getElementById('hunt-start-btn')?.click()`);
  await sleep(800);
}

// --- 1. Leave mid-hunt (before decision) ------------------------------------
await enterHunt(0);
const midHuntState = await evaluate(`(() => ({
  inHunt: !!document.getElementById('hunt-feed'),
  hasLeaveBtn: !!document.getElementById('hunt-leave-btn'),
}))()`);
check('mid-hunt view has a leave-hunt control', midHuntState.hasLeaveBtn);

if (midHuntState.hasLeaveBtn) {
  await evaluate(`document.getElementById('hunt-leave-btn')?.click()`);
  await sleep(600);
  const afterLeave = await evaluate(`(() => ({
    backAtPicker: !!document.querySelector('.hunt-picker-item'),
    huntFeedGone: !document.getElementById('hunt-feed'),
  }))()`);
  check('leaving mid-hunt returns to the picker', afterLeave.backAtPicker, JSON.stringify(afterLeave));

  // Re-enter the SAME scenario and confirm it starts fresh (no leftover
  // evidence/timer from the abandoned run) rather than resuming stale state.
  await evaluate(`document.querySelectorAll('.hunt-picker-item')[0]?.click()`);
  await sleep(500);
  await evaluate(`document.getElementById('hunt-start-btn')?.click()`);
  await sleep(800);
  const freshState = await evaluate(`(() => ({
    evidenceCount: document.getElementById('hunt-evidence-count')?.textContent.trim(),
    timerText: document.getElementById('hunt-timer')?.textContent.trim(),
  }))()`);
  check('re-entering after leaving starts with zero evidence', /^0\b/.test(freshState.evidenceCount || ''),
    JSON.stringify(freshState.evidenceCount));
  console.log('  fresh state after re-entry:', JSON.stringify(freshState));
}

// --- 2. Rapid double-click on an exit button (click-flood class of bug) ----
await enterHunt(0);
const beforeDoubleClick = await evaluate(`(() => ({
  evidenceCount: document.getElementById('hunt-evidence-count')?.textContent.trim(),
  feedLineCount: document.querySelectorAll('#hunt-feed > *').length,
}))()`);

// Fire two rapid clicks on the same exit button in the same tick, the same
// way sweep 1 found chat hint-chips could fire twice before a lock caught up.
await evaluate(`(() => {
  const btn = document.querySelector('.hunt-exit button:not([disabled])');
  if (btn) { btn.click(); btn.click(); }
})()`);
await sleep(800);

const afterDoubleClick = await evaluate(`(() => ({
  evidenceCount: document.getElementById('hunt-evidence-count')?.textContent.trim(),
  feedLineCount: document.querySelectorAll('#hunt-feed > *').length,
  feedText: document.getElementById('hunt-feed')?.textContent.replace(/\\s+/g,' ').trim().slice(0, 400),
}))()`);
console.log('  before double-click:', JSON.stringify(beforeDoubleClick));
console.log('  after double-click:', JSON.stringify(afterDoubleClick));
// A double-click on ONE exit should move through that node's narration once,
// not twice — check the feed didn't duplicate the same narration line.
const feedLinesAfter = await evaluate(`(() => [...document.querySelectorAll('#hunt-feed > *')].map(el => el.textContent.trim()))()`);
const dupeLines = feedLinesAfter.filter((line, i) => feedLinesAfter.indexOf(line) !== i && line.length > 10);
check('double-clicking one exit does not duplicate a narration line in the feed',
  dupeLines.length === 0, JSON.stringify(dupeLines));

// --- 3. Rapid double-click on a decision action (higher stakes: does it
// fire the outcome/toast twice, or open two end dialogs?) -------------------
// Walk to the decision node first.
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
check('reached the decision node before the double-click test', atDecision);

if (atDecision) {
  await evaluate(`(() => {
    const box = document.getElementById('hunt-actions');
    const btn = box ? box.querySelector('button') : null;
    if (btn) { btn.click(); btn.click(); }
  })()`);
  await sleep(1000);
  const dialogCount = await evaluate(`document.querySelectorAll('.hunt-dialog-overlay').length`);
  check('double-clicking a decision action opens exactly one end dialog, not two',
    dialogCount === 1, 'count=' + dialogCount);
}

check('no uncaught page errors during edge-case probing', pageErrors.length === 0, JSON.stringify(pageErrors));

await send('Page.close').catch(() => {});
ws.close();
console.log(check.failures() === 0 ? '\nALL CHECKS PASSED' : `\n${check.failures()} CHECK(S) FAILED`);
process.exit(check.failures() === 0 ? 0 : 1);

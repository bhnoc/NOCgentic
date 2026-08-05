// Probes three specific UX promises from docs/threat-hunt-mud/threat-hunt-mud.md
// that the playthrough driver doesn't exercise: glossary hover tips, the
// requiresEvidence gate's stated reason, and the timeline strip revealing/
// opening captures. Drives the reference scenario (index 0, fakecorp-cleartext-mcp).
import { connect, sleep, makeCheck } from './cdp.mjs';

const BASE = process.env.QA_BASE || 'https://ng.bhnoc.com';
const CDP_PORT = Number(process.env.CDP_PORT || 9222);
const check = makeCheck();

const { evaluate, send, ws } = await connect(BASE, CDP_PORT);

const pageErrors = [];
await send('Runtime.enable');
ws.addEventListener('message', (e) => {
  const msg = JSON.parse(e.data);
  if (msg.method === 'Runtime.exceptionThrown') {
    pageErrors.push(msg.params.exceptionDetails.text);
  }
});

await evaluate('location.href = ' + JSON.stringify(BASE));
await sleep(3000);
await evaluate(`document.getElementById('tab-hunt').click()`);
await sleep(1000);
await evaluate(`document.querySelectorAll('.hunt-picker-item')[0]?.click()`);
await sleep(800);
await evaluate(`document.getElementById('hunt-start-btn')?.click()`);
await sleep(1000);

// --- Glossary hover tips ----------------------------------------------------
const glossaryState = await evaluate(`(() => {
  const terms = [...document.querySelectorAll('.hunt-term')];
  return {
    termCount: terms.length,
    firstTermText: terms[0]?.textContent,
    firstTermTip: terms[0]?.getAttribute('data-tip'),
    isFocusable: terms[0] ? terms[0].tabIndex >= 0 : null,
  };
})()`);
check('glossary terms render as .hunt-term spans on the start node', glossaryState.termCount > 0, 'count=' + glossaryState.termCount);
if (glossaryState.termCount > 0) {
  check('glossary term carries a data-tip', !!glossaryState.firstTermTip, JSON.stringify(glossaryState.firstTermTip));
  check('glossary term is keyboard-focusable (tabindex, not hover-only)', glossaryState.isFocusable === true);
  console.log('  first term:', JSON.stringify(glossaryState.firstTermText), '-> tip:', JSON.stringify(glossaryState.firstTermTip));
}

// The design doc says "first occurrence per node underlines" — check a
// SECOND occurrence of the same term (if any) does NOT also get the tip,
// which would be visual noise for an established term.
const glossaryDupeCheck = await evaluate(`(() => {
  const terms = [...document.querySelectorAll('.hunt-term')];
  const byText = {};
  terms.forEach(t => { byText[t.textContent] = (byText[t.textContent] || 0) + 1; });
  const dupes = Object.entries(byText).filter(([,n]) => n > 1);
  return dupes;
})()`);
console.log('  glossary terms appearing more than once on this node:', JSON.stringify(glossaryDupeCheck));

// --- requiresEvidence gate: stated reason on a locked exit ------------------
const gateState = await evaluate(`(() => {
  const locked = [...document.querySelectorAll('.hunt-exit')].find(w => w.querySelector('button')?.disabled);
  if (!locked) return { found: false };
  return {
    found: true,
    buttonText: locked.querySelector('button')?.textContent.trim(),
    reasonText: locked.querySelector('.hunt-hint')?.textContent.trim() || locked.textContent.replace(/\\s+/g,' ').trim(),
  };
})()`);
if (gateState.found) {
  check('a gated (locked) exit states WHY it is locked, not just disabled',
    /needs?\s+\d+\s+evidence/i.test(gateState.reasonText || ''), JSON.stringify(gateState));
  console.log('  locked exit reason:', JSON.stringify(gateState.reasonText));
} else {
  console.log('  (no locked exit visible on the start node — nothing to test here yet)');
}

// --- Timeline strip: does it exist, and does clicking a revealed marker
// open the correlated node's captures with the hint highlighted? ------------
let timelineSeen = await evaluate(`(() => {
  const strip = document.getElementById('hunt-timeline');
  return {
    exists: !!strip,
    hidden: strip ? strip.hidden : null,
    revealedDotCount: strip ? strip.querySelectorAll('.hunt-timeline-revealed').length : 0,
    totalDotCount: strip ? strip.querySelectorAll('.hunt-timeline-dot').length : 0,
  };
})()`);
check('timeline strip element exists', timelineSeen.exists);
console.log('  timeline at start:', JSON.stringify(timelineSeen));

// Walk a couple of exits to reveal more timeline markers, then try clicking one.
for (let i = 0; i < 3; i++) {
  const clicked = await evaluate(`(() => {
    const exits = [...document.querySelectorAll('.hunt-exit button')].filter(b => !b.disabled);
    if (exits[0]) { exits[0].click(); return true; }
    return false;
  })()`);
  if (!clicked) break;
  await sleep(600);
}

timelineSeen = await evaluate(`(() => {
  const strip = document.getElementById('hunt-timeline');
  return {
    hidden: strip ? strip.hidden : null,
    revealedDotCount: strip ? strip.querySelectorAll('.hunt-timeline-revealed').length : 0,
  };
})()`);
check('timeline strip becomes visible as nodes are visited', timelineSeen.hidden === false, JSON.stringify(timelineSeen));
console.log('  timeline after 3 pivots:', JSON.stringify(timelineSeen));

if (timelineSeen.revealedDotCount > 0) {
  await evaluate(`(() => {
    const dot = document.querySelector('.hunt-timeline-revealed');
    if (dot) dot.click();
  })()`);
  await sleep(400);
  const captionState = await evaluate(`(() => {
    const caption = document.getElementById('hunt-timeline-caption');
    return { text: caption ? caption.textContent.trim() : null };
  })()`);
  check('clicking a revealed timeline marker shows a caption', (captionState.text || '').length > 0,
    JSON.stringify(captionState));
  console.log('  timeline caption after click:', JSON.stringify(captionState.text));

  // Does clicking it ALSO try to open a logs modal, per the doc ("clicking one
  // opens the node's captures with the hint substrings highlighted")?
  await sleep(1800); // past the fake loading delay, if a modal opened
  const modalAfterTimelineClick = await evaluate(`(() => {
    const overlay = document.querySelector('.hunt-dialog-overlay');
    return { opened: !!overlay, marks: overlay ? overlay.querySelectorAll('.hunt-log-mark').length : 0 };
  })()`);
  console.log('  modal opened by timeline click:', JSON.stringify(modalAfterTimelineClick));
  if (modalAfterTimelineClick.opened) {
    check('timeline-triggered modal has hint highlighting', modalAfterTimelineClick.marks > 0,
      'marks=' + modalAfterTimelineClick.marks);
    await evaluate(`(() => document.getElementById('hunt-logs-close')?.click())()`);
  }
}

check('no uncaught page errors during the feature probe', pageErrors.length === 0, JSON.stringify(pageErrors));

await send('Page.close').catch(() => {});
ws.close();
console.log(check.failures() === 0 ? '\nALL CHECKS PASSED' : `\n${check.failures()} CHECK(S) FAILED`);
process.exit(check.failures() === 0 ? 0 : 1);

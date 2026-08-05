// Drives the LIVE Threat Hunt feature end to end, the way a real walk-up
// user would: pick a scenario, click through pivots collecting evidence,
// open a log capture, hit the decision node, choose an action, read the
// end dialog, then play again. Read-only UI clicks against prod.
import { connect, sleep, makeCheck } from './cdp.mjs';

const BASE = process.env.QA_BASE || 'https://ng.bhnoc.com';
const CDP_PORT = Number(process.env.CDP_PORT || 9222);
const SCENARIO_INDEX = Number(process.env.HUNT_INDEX || 0);
const check = makeCheck();

const { evaluate, send, ws } = await connect(BASE, CDP_PORT);

const pageErrors = [];
await send('Runtime.enable');
ws.addEventListener('message', (e) => {
  const msg = JSON.parse(e.data);
  if (msg.method === 'Runtime.exceptionThrown') {
    pageErrors.push(msg.params.exceptionDetails.text + ' ' + JSON.stringify(msg.params.exceptionDetails.exception?.description || ''));
  }
});

await evaluate('location.href = ' + JSON.stringify(BASE));
await sleep(3000);
const tabExists = await evaluate(`!!document.getElementById('tab-hunt')`);
check('Threat Hunt tab exists on the header', tabExists);
if (!tabExists) {
  console.log('\nCannot proceed without the hunt tab.');
  await send('Page.close').catch(() => {});
  ws.close();
  process.exit(1);
}
await evaluate(`document.getElementById('tab-hunt').click()`);
await sleep(1000);

const picker = await evaluate(`(() => {
  const items = [...document.querySelectorAll('.hunt-picker-item')];
  return { count: items.length, titles: items.map(i => i.querySelector('.hunt-picker-title')?.textContent.trim()) };
})()`);
check('hunt picker lists scenarios', picker.count >= 1, 'count=' + picker.count);
console.log('  scenarios:', JSON.stringify(picker.titles));

if (picker.count === 0) {
  console.log('\nNo scenarios to play — aborting.');
  process.exit(1);
}

const chosenTitle = picker.titles[SCENARIO_INDEX] || picker.titles[0];
console.log('  picking scenario:', chosenTitle);

await evaluate(`(() => {
  const items = [...document.querySelectorAll('.hunt-picker-item')];
  items[${SCENARIO_INDEX}]?.click();
})()`);
await sleep(800);

const briefing = await evaluate(`(() => ({
  hasBriefing: !!document.querySelector('.hunt-briefing-text'),
  briefingText: document.querySelector('.hunt-briefing-text')?.textContent.trim(),
  hasStartButton: !!document.querySelector('.hunt-btn'),
}))()`);
check('scenario briefing renders', briefing.hasBriefing);
console.log('  briefing:', JSON.stringify((briefing.briefingText || '').slice(0, 150)));

await evaluate(`(() => document.getElementById('hunt-start-btn')?.click())()`);
await sleep(1000);

const inHunt = await evaluate(`(() => ({
  hasLogFeed: !!document.getElementById('hunt-feed'),
  hasExits: document.querySelectorAll('.hunt-exit').length,
  timerVisible: !!document.getElementById('hunt-timer'),
}))()`);
check('hunt session starts (log feed visible)', inHunt.hasLogFeed);
console.log('  exits/pivots on start node:', inHunt.hasExits, 'timer:', inHunt.timerVisible);

// --- Walk through the hunt: click exits until we reach the decision node,
// or hit a safety cap. Prefer non-disabled exits; track evidence growth.
let steps = 0;
let reachedDecision = false;
let evidenceCounts = [];
let capturedAModal = false;

for (steps = 0; steps < 12; steps++) {
  await sleep(400);
  const state = await evaluate(`(() => {
    const exits = [...document.querySelectorAll('.hunt-exit button')];
    const enabledExits = exits.filter(b => !b.disabled);
    // #hunt-actions holds either exits (non-decision) or containment actions
    // (decision) — decision mode never renders .hunt-exit wrappers, so any
    // button directly in #hunt-actions NOT wrapped in .hunt-exit is a
    // containment action.
    const actionsBox = document.getElementById('hunt-actions');
    const decisionButtons = actionsBox ? [...actionsBox.querySelectorAll('button')].filter(b => !b.closest('.hunt-exit')) : [];
    const evidenceChips = document.querySelectorAll('.hunt-chip').length;
    return {
      exitCount: exits.length,
      enabledExitCount: enabledExits.length,
      exitLabels: exits.map(b => ({ text: b.textContent.trim(), disabled: b.disabled })),
      isDecision: exits.length === 0 && decisionButtons.length > 0,
      evidenceChips,
    };
  })()`);
  evidenceCounts.push(state.evidenceChips);

  if (state.isDecision) { reachedDecision = true; break; }
  if (state.enabledExitCount === 0) {
    console.log('  no enabled exits at step', steps, '- stuck?', JSON.stringify(state.exitLabels));
    break;
  }

  // Try clicking a linked evidence chip once, to test the log-capture modal.
  if (!capturedAModal && state.evidenceChips > 0) {
    const opened = await evaluate(`(() => {
      const chip = document.querySelector('.hunt-chip-link');
      if (chip) { chip.click(); return true; }
      return false;
    })()`);
    if (opened) {
      // The real capture content is staged behind a fake 700-1400ms "sensor
      // query" delay (threat-hunt.js logsLoadTimer) — check the loading state
      // immediately, then wait past the delay for the real content so this
      // isn't just testing the spinner.
      await sleep(200);
      const loading = await evaluate(`(() => {
        const m = document.querySelector('.hunt-dialog-overlay .hunt-logs-dialog');
        return { exists: !!m, ariaBusy: m ? m.closest('.hunt-dialog-overlay').getAttribute('aria-busy') : null };
      })()`);
      check('evidence chip opens a log capture modal (loading state)', loading.exists, JSON.stringify(loading));

      await sleep(1600);
      const modal = await evaluate(`(() => {
        const overlay = document.querySelector('.hunt-dialog-overlay');
        const m = overlay ? overlay.querySelector('.hunt-logs-dialog') : null;
        const body = document.getElementById('hunt-logs-modal-body');
        const hintBtn = document.getElementById('hunt-logs-hint');
        return {
          exists: !!m,
          stillLoading: overlay ? overlay.getAttribute('aria-busy') === 'true' : null,
          hasLogLines: body ? body.querySelectorAll('.hunt-log-pre').length : 0,
          bodyText: body ? body.textContent.slice(0, 300) : null,
          hasHintButton: !!hintBtn,
        };
      })()`);
      capturedAModal = true;
      check('log capture modal resolves past loading (aria-busy false)', modal.stillLoading === false, JSON.stringify(modal.stillLoading));
      check('log capture modal shows real log lines', modal.hasLogLines > 0, 'count=' + modal.hasLogLines);
      console.log('  capture body (first 300 chars):', JSON.stringify(modal.bodyText));

      if (modal.hasHintButton) {
        await evaluate(`(() => document.getElementById('hunt-logs-hint')?.click())()`);
        await sleep(300);
        const hinted = await evaluate(`(() => document.querySelectorAll('.hunt-log-mark').length)()`);
        check('Show hint highlights something in the log lines', hinted > 0, 'marks=' + hinted);
      } else {
        console.log('  (no hint button on this node\'s captures — nothing to test here)');
      }

      await evaluate(`(() => document.getElementById('hunt-logs-close')?.click())()`);
      await sleep(400);
    }
  }

  // Click the first enabled exit.
  await evaluate(`(() => {
    const exits = [...document.querySelectorAll('.hunt-exit button')].filter(b => !b.disabled);
    if (exits[0]) exits[0].click();
  })()`);
  await sleep(600);
}

check('hunt reaches a decision node within 12 pivots', reachedDecision, 'steps=' + steps);
console.log('  evidence chip count over time:', JSON.stringify(evidenceCounts));

if (reachedDecision) {
  const actions = await evaluate(`(() => {
    const box = document.getElementById('hunt-actions');
    const btns = box ? [...box.querySelectorAll('button')] : [];
    return btns.map(b => b.textContent.trim());
  })()`);
  check('decision node offers containment actions', actions.length >= 2, JSON.stringify(actions));
  console.log('  actions offered:', JSON.stringify(actions));

  // Deliberately pick the LAST action, not the first — the config docs say
  // exactly one action is `correct: true` and nothing about ordering, so
  // picking last is as likely to be wrong as picking first, and testing the
  // wrong-answer feedback path matters more: that's what most first-time
  // players actually see, per the design doc's "careful player wins on the
  // first run" claim (careful, not lucky).
  await evaluate(`(() => {
    const box = document.getElementById('hunt-actions');
    const btns = box ? [...box.querySelectorAll('button')] : [];
    const btn = btns[btns.length - 1];
    if (btn) btn.click();
  })()`);
  await sleep(800);

  const ending = await evaluate(`(() => {
    const dialog = document.querySelector('.hunt-dialog-overlay .hunt-dialog');
    const metaText = dialog ? dialog.querySelector('.hunt-dialog-meta')?.textContent : null;
    return {
      exists: !!dialog,
      text: dialog ? dialog.textContent.replace(/\\s+/g, ' ').trim() : null,
      metaText,
      wasCorrect: metaText ? metaText.includes('correct action') : null,
      hasAgainBtn: !!document.getElementById('hunt-again-btn'),
      hasCloseBtn: !!document.getElementById('hunt-close-btn'),
      correctFirstMoveNoteCount: [...(dialog ? dialog.querySelectorAll('.hunt-dialog-note') : [])]
        .filter(p => /Correct first move/.test(p.textContent)).length,
    };
  })()`);
  check('choosing an action shows an end dialog', ending.exists);
  console.log('  outcome:', ending.wasCorrect ? 'CORRECT' : 'INCORRECT', '-', JSON.stringify(ending.metaText));
  console.log('  end dialog text:', JSON.stringify((ending.text || '').slice(0, 500)));
  check('end dialog explains the outcome (not empty)', (ending.text || '').length > 30);
  if (ending.wasCorrect === false) {
    check('wrong-answer dialog states the correct first move (teaches, not just scores)',
      ending.correctFirstMoveNoteCount > 0);
  }

  if (ending.exists) {
    check('end dialog has a Play Again control', ending.hasAgainBtn);
    check('end dialog has a Close control', ending.hasCloseBtn);
    await evaluate(`(() => document.getElementById('hunt-again-btn')?.click())()`);
    await sleep(800);
    const afterReplay = await evaluate(`(() => ({
      backAtPicker: !!document.querySelector('.hunt-picker-item'),
      stillInHuntSession: !!document.getElementById('hunt-feed'),
    }))()`);
    check('Play Again returns to a playable state', afterReplay.backAtPicker || afterReplay.stillInHuntSession,
      JSON.stringify(afterReplay));
  }
}

check('no uncaught page errors during the full playthrough', pageErrors.length === 0, JSON.stringify(pageErrors));

await send('Page.close').catch(() => {});
ws.close();
console.log(check.failures() === 0 ? '\nALL CHECKS PASSED' : `\n${check.failures()} CHECK(S) FAILED`);
process.exit(check.failures() === 0 ? 0 : 1);

// Drives the real landing page in headless Chrome over CDP and asserts the
// lane-race swap control: the fastest lane renders by default, the second lane
// lights the button up when it lands, clicking it swaps the answer in place, and
// the async hints row survives the swap.
//
// Unit tests cover the polling and the snake->camel boundary; only a real DOM can
// prove the button is clickable, that the delegated listener survives the bar
// being re-rendered via innerHTML, and that a swap does not wipe the hints.
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

// Surfacing page errors matters more here than elsewhere: a throw inside
// renderLaneBar is caught by appendAgentMessage's fallback, which renders a
// plausible-looking bubble and would otherwise hide the break.
// Only JS faults count. The stub deliberately has no /ws and no alert routes, so
// the page logs network errors for both on every run; asserting on those would
// make the gate fail for reasons that have nothing to do with the UI.
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

// "lane race" is the stub's trigger for a raced job.
await evaluate(`(() => {
  document.getElementById('query-input').value = 'lane race port 445 scanners';
  sendQuery();
})()`);
await sleep(2600);   // one 2s poll tick + slack: winner rendered, loser not yet in

const firstRender = await evaluate(`(() => {
  const bar = document.querySelector('.lane-bar');
  const body = document.querySelector('.lane-body');
  return {
    barText: bar ? bar.textContent.replace(/\\s+/g, ' ').trim() : null,
    bodyText: body ? body.textContent.replace(/\\s+/g, ' ').trim() : null,
    swapButtons: document.querySelectorAll('.lane-swap').length,
    hasHintsRow: !!document.querySelector('.hints-row'),
  };
})()`);
check('lane bar rendered on a raced answer', firstRender.barText !== null, JSON.stringify(firstRender.barText));
check('fastest lane is what the reader sees', /CLOUD LANE/.test(firstRender.bodyText || ''),
  JSON.stringify(firstRender.bodyText));
check('pending state shown while the second lane runs',
  /second model still working/.test(firstRender.barText || '') || firstRender.swapButtons === 1,
  JSON.stringify(firstRender.barText));
check('hints row exists outside the lane body', firstRender.hasHintsRow === true);

// pollForLanes ticks every 2s; the stub hands over both lanes on its 2nd poll.
await sleep(5000);

const afterSecondLane = await evaluate(`(() => {
  const bar = document.querySelector('.lane-bar');
  return {
    barText: bar ? bar.textContent.replace(/\\s+/g, ' ').trim() : null,
    swapButtons: document.querySelectorAll('.lane-swap').length,
    swapKey: document.querySelector('.lane-swap')?.getAttribute('data-lane-key') || null,
    fastestBadges: document.querySelectorAll('.lane-badge-fastest').length,
    stillPending: !!document.querySelector('.lane-pending'),
  };
})()`);
check('swap button appears once the second lane lands', afterSecondLane.swapButtons === 1,
  'buttons=' + afterSecondLane.swapButtons + ' bar=' + JSON.stringify(afterSecondLane.barText));
check('pending state cleared', afterSecondLane.stillPending === false);
// No FASTEST badge anymore — the winner is simply whichever lane is showing
// first, which already communicates "fastest" without a redundant label.
check('no FASTEST badge (removed by design)', afterSecondLane.fastestBadges === 0,
  'badges=' + afterSecondLane.fastestBadges);
check('swap button carries its lane key', !!afterSecondLane.swapKey, JSON.stringify(afterSecondLane.swapKey));
// The swap button is icon-only now (no visible model name in the bar text)
// — the target lane is named in its title/aria-label instead.
const swapTitle = await evaluate(`document.querySelector('.lane-swap')?.getAttribute('title') || null`);
check('swap button title names the other lane as the swap target', /AQLight/.test(swapTitle || ''),
  JSON.stringify(swapTitle));

// Simulate the async follow-up-question chips having already landed for this
// job (normally via pollForHints), by writing them into laneState directly —
// a swap now legitimately RE-RENDERS the hints row (the recommended-action
// bullets are per-lane and must update), so the invariant to prove is "the
// shared hint-chip buttons survive that re-render", not "the row never
// changes" (that assumption no longer holds now that it has per-lane content
// too).
await evaluate(`(() => {
  const laneKey = document.querySelector('.lane-swap').getAttribute('data-lane-key');
  const st = laneState.get(laneKey);
  st.hintChipsHtml = '<span class="hint-chip" data-hint="HINTS-MARKER">HINTS-MARKER</span>';
  refreshHints(laneKey);
})()`);

// Real click through the delegated listener, not a direct swapLane() call.
await evaluate(`document.querySelector('.lane-swap').click()`);
await sleep(200);

const afterSwap = await evaluate(`(() => {
  const bar = document.querySelector('.lane-bar');
  const body = document.querySelector('.lane-body');
  const modelMeta = document.querySelector('.model-meta');
  return {
    barText: bar ? bar.textContent.replace(/\\s+/g, ' ').trim() : null,
    bodyText: body ? body.textContent.replace(/\\s+/g, ' ').trim() : null,
    swapButtons: document.querySelectorAll('.lane-swap').length,
    fastestBadges: document.querySelectorAll('.lane-badge-fastest').length,
    deltas: [...document.querySelectorAll('.lane-delta')].map(e => e.textContent.trim()),
    hintsText: document.querySelector('.hints-row')?.textContent.trim() || null,
    modelMetaText: modelMeta ? modelMeta.textContent.trim() : null,
  };
})()`);
check('clicking swap shows the other lane answer', /LOCAL LANE/.test(afterSwap.bodyText || ''),
  JSON.stringify(afterSwap.bodyText));
check('swapped-in answer replaced the winner (not appended)', !/CLOUD LANE/.test(afterSwap.bodyText || ''),
  JSON.stringify(afterSwap.bodyText));
// The model name lives on the message-meta line now (moved up from the
// metrics row), so a swap must update it there instead.
check('per-lane model name (message-meta line) swapped too', /AQLight/.test(afterSwap.modelMetaText || ''),
  JSON.stringify(afterSwap.modelMetaText));
check('still no FASTEST badge after swapping to the slower lane', afterSwap.fastestBadges === 0,
  'badges=' + afterSwap.fastestBadges);
check('slower lane shows a +delta', afterSwap.deltas.length === 1 && /^\+2\.2s$/.test(afterSwap.deltas[0]),
  JSON.stringify(afterSwap.deltas));
check('hints row survived the swap', afterSwap.hintsText === 'Next StepsHINTS-MARKER', JSON.stringify(afterSwap.hintsText));
check('swap button still present after re-render', afterSwap.swapButtons === 1);

// Swap back: the delegated listener must survive the bar being replaced.
await evaluate(`document.querySelector('.lane-swap').click()`);
await sleep(200);
const afterSwapBack = await evaluate(`(() => ({
  bodyText: document.querySelector('.lane-body').textContent.replace(/\\s+/g, ' ').trim(),
  fastestBadges: document.querySelectorAll('.lane-badge-fastest').length,
  hintsText: document.querySelector('.hints-row')?.textContent.trim() || null,
  modelMetaText: document.querySelector('.model-meta')?.textContent.trim() || null,
}))()`);
check('swapping back returns to the fastest lane', /CLOUD LANE/.test(afterSwapBack.bodyText),
  JSON.stringify(afterSwapBack.bodyText));
check('still no FASTEST badge back on the winner', afterSwapBack.fastestBadges === 0);
check('model name back to the winner after swapping back', /gemini/i.test(afterSwapBack.modelMetaText || ''),
  JSON.stringify(afterSwapBack.modelMetaText));
check('hints row still intact after two swaps', afterSwapBack.hintsText === 'Next StepsHINTS-MARKER',
  JSON.stringify(afterSwapBack.hintsText));

// A single-lane box must render exactly as it did before this feature: no bar,
// no orphaned control. The stub answers non-"lane race" queries with no lanes.
await evaluate(`(() => {
  document.getElementById('query-input').value = 'ordinary single lane question';
  sendQuery();
})()`);
await sleep(2800);
const singleLane = await evaluate(`(() => {
  const bubbles = [...document.querySelectorAll('.message.agent')];
  const last = bubbles[bubbles.length - 1];
  const bar = last.querySelector('.lane-bar');
  return {
    text: last.textContent.replace(/\\s+/g, ' ').trim(),
    barEmpty: !bar || bar.textContent.trim() === '',
    swapButtons: last.querySelectorAll('.lane-swap').length,
  };
})()`);
check('single-lane answer still renders', /stub answer for/.test(singleLane.text), JSON.stringify(singleLane.text));
check('no lane bar content on a single-lane answer', singleLane.barEmpty === true);
check('no swap control on a single-lane answer', singleLane.swapButtons === 0);

// A single-lane box WITH a confidence value must still show the pill — no
// lanes to swap between, but confidence is independent of the race.
await evaluate(`(() => {
  document.getElementById('query-input').value = 'confidence pill check';
  sendQuery();
})()`);
await sleep(2800);
const confPill = await evaluate(`(() => {
  const bubbles = [...document.querySelectorAll('.message.agent')];
  const last = bubbles[bubbles.length - 1];
  const pill = last.querySelector('.confidence-pill');
  return {
    text: last.textContent.replace(/\\s+/g, ' ').trim(),
    pillText: pill ? pill.textContent.trim() : null,
    swapButtons: last.querySelectorAll('.lane-swap').length,
  };
})()`);
check('single-lane confidence pill renders', confPill.pillText === '42%', JSON.stringify(confPill));
check('still no swap control alongside a bare confidence pill', confPill.swapButtons === 0);

// Raw section: default-collapsed, expands to the actual rows (not the
// summary JSON, not the SQL), and a nested "View SQL" toggle reveals the
// statement. The long single-line SQL must wrap rather than scroll sideways.
await evaluate(`(() => {
  document.getElementById('query-input').value = 'query tabs check';
  sendQuery();
})()`);
await sleep(2800);
const rawSection = await evaluate(`(() => {
  const bubbles = [...document.querySelectorAll('.message.agent')];
  const last = bubbles[bubbles.length - 1];
  // Raw is nested INSIDE Evidence, not its own top-level toggle — find the
  // answer-section whose summary reads "Evidence".
  const evidence = [...last.querySelectorAll('details.answer-section')]
    .find(d => d.querySelector('summary')?.textContent.trim().toLowerCase() === 'evidence');
  const evidenceInitiallyOpen = evidence ? evidence.hasAttribute('open') : null;
  const raw = evidence ? evidence.querySelector('details.raw-collapse') : null;
  // The 'open' attribute IS the collapse state the browser renders from —
  // verified visually via a real screenshot (headless Chrome's layout APIs
  // for closed <details> content are unreliable in this environment:
  // getBoundingClientRect/getClientRects report the content as painted even
  // though a screenshot shows only the "▶ Raw" summary line).
  const rawInitiallyOpen = raw ? raw.hasAttribute('open') : null;
  const summaryText = raw ? raw.querySelector('summary').textContent.trim() : null;
  evidence && evidence.setAttribute('open', '');
  raw && raw.setAttribute('open', '');
  const table = last.querySelector('details.raw-collapse table.data-table');
  const tableText = table ? table.textContent : '';
  const sql = last.querySelector('details.sql-collapse');
  const sqlInitiallyOpen = sql ? sql.hasAttribute('open') : null;
  const sqlSummaryText = sql ? sql.querySelector('summary').textContent.trim() : null;
  sql && sql.setAttribute('open', '');
  const pre = sql ? sql.querySelector('pre.code-block') : null;
  return {
    hasEvidenceSection: !!evidence,
    evidenceInitiallyOpen,
    hasRawSection: !!raw,
    rawIsNestedInsideEvidence: !!(evidence && raw && evidence.contains(raw)),
    rawInitiallyOpen,
    summaryText,
    tableHasSampleRow: tableText.includes('10.220.40.7') && tableText.includes('Port scan'),
    hasSqlToggle: !!sql,
    sqlInitiallyOpen,
    sqlSummaryText,
    preOverflowX: pre ? getComputedStyle(pre).overflowX : null,
    preWhiteSpace: pre ? getComputedStyle(pre).whiteSpace : null,
    preHasSql: pre ? pre.textContent.includes('SELECT') : false,
  };
})()`);
check('Evidence section is present', rawSection.hasEvidenceSection === true);
check('Evidence is collapsed by default', rawSection.evidenceInitiallyOpen === false);
check('Raw section exists nested inside Evidence', rawSection.hasRawSection === true && rawSection.rawIsNestedInsideEvidence === true, JSON.stringify(rawSection));
check('Raw is collapsed by default (independent of Evidence)', rawSection.rawInitiallyOpen === false);
check('Raw section is labeled "Raw"', rawSection.summaryText === 'Raw', rawSection.summaryText);
check('expanding Raw shows the actual rows, not the summary JSON', rawSection.tableHasSampleRow === true, JSON.stringify(rawSection));
check('a nested View SQL toggle exists inside Raw', rawSection.hasSqlToggle === true);
check('the SQL toggle is collapsed by default', rawSection.sqlInitiallyOpen === false);
check('the SQL toggle is labeled "View SQL"', rawSection.sqlSummaryText === 'View SQL', rawSection.sqlSummaryText);
check('expanding View SQL shows the actual statement', rawSection.preHasSql === true);
check('the SQL block wraps instead of scrolling sideways', rawSection.preOverflowX === 'hidden' && rawSection.preWhiteSpace === 'pre-wrap', JSON.stringify(rawSection));

// And the inverse: Raw must NOT appear at all when the answer has no
// Evidence section (RAW_PLACEHOLDER never gets substituted in). The earlier
// "confidence pill check" message has plain text with no '## Evidence'.
const noEvidenceCase = await evaluate(`(() => {
  const bubbles = [...document.querySelectorAll('.message.agent')];
  const target = bubbles.find(b => b.textContent.includes('SINGLE LANE: confidence pill check answer.'));
  return { found: !!target, hasRawAnywhere: target ? !!target.querySelector('details.raw-collapse') : null };
})()`);
check('a message with no Evidence section has no Raw toggle at all',
  noEvidenceCase.found && noEvidenceCase.hasRawAnywhere === false, JSON.stringify(noEvidenceCase));

// Right-hand cluster order: model/timing stay on the left (unmoved); the
// right side is data-source // confidence % // icon-only swap button, in
// that order, with the swap button as the absolute right-most element.
const pillAlignment = await evaluate(`(() => {
  const bars = [...document.querySelectorAll('.lane-bar')];
  const bareBar = bars.find(b => b.querySelector('.confidence-pill') && !b.querySelector('.lane-current') && !b.querySelector('.lane-swap'));
  const racedBar = bars.find(b => b.querySelector('.confidence-pill') && b.querySelector('.lane-current'));
  if (!bareBar || !racedBar) return { ok: false, hasBareBar: !!bareBar, hasRacedBar: !!racedBar };
  const barePill = bareBar.querySelector('.confidence-pill');
  const bareBarRect = bareBar.getBoundingClientRect();
  const barePillRect = barePill.getBoundingClientRect();
  const racedLabel = racedBar.querySelector('.lane-current');
  const racedPill = racedBar.querySelector('.confidence-pill');
  const racedSwap = racedBar.querySelector('.lane-swap');
  const racedSource = racedBar.querySelector('.data-source-label');
  const racedLabelRect = racedLabel.getBoundingClientRect();
  const racedPillRect = racedPill.getBoundingClientRect();
  const racedSwapRect = racedSwap.getBoundingClientRect();
  const racedSourceRect = racedSource ? racedSource.getBoundingClientRect() : null;
  return {
    ok: true,
    // A left-stranded pill (an earlier regression) would put this near 0.
    pillNearRightEdge: (bareBarRect.right - barePillRect.right) < 40,
    // Model label untouched: still the left-most element in the bar.
    labelStillOnTheLeft: racedLabelRect.left <= racedPillRect.left,
    // Order on the right: source, then confidence, then swap (right-most).
    sourceBeforePill: !racedSourceRect || racedSourceRect.right <= racedPillRect.left + 2,
    pillBeforeSwap: racedPillRect.right <= racedSwapRect.left + 2,
    swapIsRightMost: racedSwapRect.right >= racedPillRect.right,
  };
})()`);
check('confidence pill anchors to the right edge of the lane bar', pillAlignment.ok && pillAlignment.pillNearRightEdge, JSON.stringify(pillAlignment));
check('model label stays on the left, unmoved by the pill', pillAlignment.ok && pillAlignment.labelStillOnTheLeft, JSON.stringify(pillAlignment));
check('data source sits before the confidence pill', pillAlignment.ok && pillAlignment.sourceBeforePill, JSON.stringify(pillAlignment));
check('confidence pill sits before the swap button', pillAlignment.ok && pillAlignment.pillBeforeSwap, JSON.stringify(pillAlignment));
check('the icon-only swap button is the absolute right-most element', pillAlignment.ok && pillAlignment.swapIsRightMost, JSON.stringify(pillAlignment));

// Logo click: ends the investigation, not just a view switch. Several jobs
// have been sent by this point in the run, so there IS a transcript and
// per-job state (pollIntervals/laneState/renderedJobs) to actually clear.
const beforeReset = await evaluate(`(() => ({
  messageCount: document.querySelectorAll('.message').length,
  hasWelcomeBanner: !!document.getElementById('welcome-banner'),
}))()`);
check('sanity: messages exist before reset', beforeReset.messageCount > 0, JSON.stringify(beforeReset));
check('sanity: welcome banner is gone before reset (first query removed it)', beforeReset.hasWelcomeBanner === false);

await evaluate(`(() => document.getElementById('header-logo-home').click())()`);
await sleep(300);
const afterReset = await evaluate(`(() => ({
  messageCount: document.querySelectorAll('.message').length,
  hasWelcomeBanner: !!document.getElementById('welcome-banner'),
  chipCount: document.querySelectorAll('#example-queries .example-chip').length,
  view: document.getElementById('hunt-view').hidden ? 'chat' : 'hunt',
}))()`);
check('logo click clears the transcript', afterReset.messageCount === 0, JSON.stringify(afterReset));
check('logo click restores the welcome banner', afterReset.hasWelcomeBanner === true);
check('logo click restores the starter chips', afterReset.chipCount > 0, JSON.stringify(afterReset));
check('logo click lands on the chat view', afterReset.view === 'chat');

// A fresh query after reset must still work end to end — reset must not have
// left pollIntervals/renderedJobs in a state that wedges the next send.
await evaluate(`(() => {
  document.getElementById('query-input').value = 'ordinary single lane question';
  sendQuery();
})()`);
await sleep(2200);
const afterResetQuery = await evaluate(`(() => ({
  text: document.querySelector('.message.agent:last-child')?.textContent.replace(/\\s+/g, ' ').trim() || '',
}))()`);
check('sending a query after reset still works', /stub answer for/.test(afterResetQuery.text), afterResetQuery.text);

// One Next Steps section, not two: the answer's own '## Next Steps'
// (recommended-action bullets) and the async follow-up-question hint chips
// must merge into a single section — never a heading inside the answer body
// AND a second "Next Steps" label below it.
await evaluate(`(() => {
  document.getElementById('query-input').value = 'next steps merge check';
  sendQuery();
})()`);
await sleep(2200);
const beforeChips = await evaluate(`(() => {
  const bubbles = [...document.querySelectorAll('.message.agent')];
  const last = bubbles[bubbles.length - 1];
  return {
    nextStepsHeadingCount: [...last.querySelectorAll('.hints-label, .md-header')]
      .filter(el => el.textContent.trim().toLowerCase() === 'next steps').length,
    hasActionBullets: !!last.querySelector('.next-step-actions'),
    actionText: last.querySelector('.next-step-actions')?.textContent || '',
    hasChipsYet: last.querySelectorAll('.hint-chip').length > 0,
    // The inline '## Next Steps' heading must NOT also render as its own
    // answer-body header/collapsible — it was extracted, not duplicated.
    answerBodyHasNextStepsHeader: [...last.querySelectorAll('.lane-body .md-header')]
      .some(el => el.textContent.trim().toLowerCase() === 'next steps'),
  };
})()`);
check('exactly one "Next Steps" heading on the message', beforeChips.nextStepsHeadingCount === 1, JSON.stringify(beforeChips));
check('recommended-action bullets are rendered', beforeChips.hasActionBullets === true);
check('action bullets carry the real recommended actions', beforeChips.actionText.includes('Block 45.83.193.150') && beforeChips.actionText.includes('Cdemo001'), beforeChips.actionText);
check('the inline Next Steps heading does not ALSO render inside the answer body', beforeChips.answerBodyHasNextStepsHeader === false);

// Hint chips land a moment later via polling — must join the SAME section,
// not spawn a second "Next Steps" heading.
await sleep(2500);
const afterChips = await evaluate(`(() => {
  const bubbles = [...document.querySelectorAll('.message.agent')];
  const last = bubbles[bubbles.length - 1];
  return {
    nextStepsHeadingCount: [...last.querySelectorAll('.hints-label, .md-header')]
      .filter(el => el.textContent.trim().toLowerCase() === 'next steps').length,
    hasActionBullets: !!last.querySelector('.next-step-actions'),
    chipCount: last.querySelectorAll('.hint-chip').length,
    actionsAndChipsInSameSection: !!last.querySelector('.hints-row .next-step-actions') &&
      !!last.querySelector('.hints-row .hint-chip'),
  };
})()`);
check('still exactly one "Next Steps" heading after chips land', afterChips.nextStepsHeadingCount === 1, JSON.stringify(afterChips));
check('action bullets survived the chips landing', afterChips.hasActionBullets === true);
check('hint chips landed', afterChips.chipCount === 2, JSON.stringify(afterChips));
check('bullets and chips share the same Next Steps section', afterChips.actionsAndChipsInSameSection === true, JSON.stringify(afterChips));

// Data-source label: names the underlying vendor data (Corelight), distinct
// from the agent badge (Alert Triage). Lives in the lane-bar's right-hand
// cluster (.lane-bar-right) — this job also has a confidence pill after it,
// so check the CLUSTER sits at the bar's right edge and the label is the
// first item within it, not that the label itself touches the edge.
const dataSource = await evaluate(`(() => {
  const bubbles = [...document.querySelectorAll('.message.agent')];
  const last = bubbles[bubbles.length - 1];
  const meta = last.querySelector('.message-meta');
  const bar = last.querySelector('.lane-bar');
  const right = bar ? bar.querySelector('.lane-bar-right') : null;
  const label = right ? right.querySelector('.data-source-label') : null;
  const pill = right ? right.querySelector('.confidence-pill') : null;
  const badge = meta ? meta.querySelector('.agent-badge') : null;
  if (!bar || !right || !label || !badge) return { ok: false };
  const barRect = bar.getBoundingClientRect();
  const rightRect = right.getBoundingClientRect();
  const labelRect = label.getBoundingClientRect();
  const pillRect = pill ? pill.getBoundingClientRect() : null;
  return {
    ok: true,
    text: label.textContent.trim(),
    badgeText: badge.textContent.trim(),
    clusterIsFarRight: (barRect.right - rightRect.right) < 20,
    labelBeforePill: !pillRect || labelRect.right <= pillRect.left + 2,
  };
})()`);
check('data-source label shows the vendor (Corelight), not the agent name', dataSource.ok && dataSource.text === 'Corelight', JSON.stringify(dataSource));
check('data-source label is distinct from the agent badge', dataSource.ok && dataSource.badgeText !== dataSource.text, JSON.stringify(dataSource));
check('the right-hand cluster sits far right on the lane-bar line', dataSource.ok && dataSource.clusterIsFarRight, JSON.stringify(dataSource));
check('data-source label sits before the confidence pill within the cluster', dataSource.ok && dataSource.labelBeforePill, JSON.stringify(dataSource));

check('no uncaught page errors', pageErrors.length === 0, pageErrors.join(' | '));

await send('Page.close').catch(() => {});
ws.close();
console.log(failures === 0 ? '\nALL LANE CHECKS PASSED' : `\n${failures} LANE CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);

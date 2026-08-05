// Two more "80% of users" paths the golden_path script doesn't cover:
// 1. Mobile viewport (analysts checking on a phone) — does the layout still
//    work, is the alert feed reachable, does the input stay usable?
// 2. Typing a freeform question instead of clicking a chip — the other half
//    of how a real question gets asked.
import { connect, sleep, makeCheck } from './cdp.mjs';

const BASE = process.env.QA_BASE || 'https://ng.bhnoc.com';
const CDP_PORT = Number(process.env.CDP_PORT || 9222);
const check = makeCheck();

const { evaluate, send, ws } = await connect(BASE, CDP_PORT);

// --- Mobile viewport (iPhone-ish: 390x844) ----------------------------------
await send('Emulation.setDeviceMetricsOverride', {
  width: 390, height: 844, deviceScaleFactor: 2, mobile: true,
});
await evaluate('location.href = ' + JSON.stringify(BASE));
await sleep(2500);

const mobile = await evaluate(`(() => {
  const input = document.getElementById('query-input');
  const sendBtn = document.getElementById('send-btn');
  const chips = document.querySelectorAll('.example-chip');
  const feedToggle = document.querySelector('[class*="mobile"], [class*="toggle"], [class*="hamburger"]');
  const rect = input ? input.getBoundingClientRect() : null;
  return {
    inputVisible: !!(rect && rect.width > 0 && rect.height > 0),
    inputInViewport: !!(rect && rect.left >= 0 && rect.right <= 390),
    sendBtnVisible: !!(sendBtn && sendBtn.getBoundingClientRect().width > 0),
    chipCount: chips.length,
    bodyScrollWidth: document.body.scrollWidth,
    hasHorizontalOverflow: document.body.scrollWidth > 390 + 5, // small tolerance
  };
})()`);
check('query input renders on mobile viewport', mobile.inputVisible);
check('query input fits within mobile viewport width', mobile.inputInViewport, JSON.stringify(mobile));
check('send button renders on mobile viewport', mobile.sendBtnVisible);
check('starter chips render on mobile', mobile.chipCount >= 1, 'count=' + mobile.chipCount);
check('no horizontal overflow on mobile viewport', !mobile.hasHorizontalOverflow,
  'bodyScrollWidth=' + mobile.bodyScrollWidth);

// Can a mobile user actually reach the alert feed (common pattern: hidden
// behind a toggle/tab on narrow screens, or just stacked below the fold)?
const mobileFeed = await evaluate(`(() => {
  const feed = document.getElementById('alerts-feed');
  const rect = feed ? feed.getBoundingClientRect() : null;
  return {
    feedExists: !!feed,
    feedCards: feed ? feed.querySelectorAll('.alert-card').length : 0,
    feedReachableWithoutJs: !!(rect), // exists in layout at all, even if scrolled off
  };
})()`);
check('alert feed exists in mobile DOM', mobileFeed.feedExists);
check('alert feed has cards on mobile', mobileFeed.feedCards > 0, 'count=' + mobileFeed.feedCards);

// Try tapping a chip on mobile — does the same click handler work via touch-shaped click?
if (mobile.chipCount >= 1) {
  await evaluate(`document.querySelectorAll('.example-chip')[0].click()`);
  await sleep(500);
  const afterTap = await evaluate(`(() => ({
    userBubbleCount: document.querySelectorAll('.message.user').length,
  }))()`);
  check('chip tap works on mobile viewport', afterTap.userBubbleCount === 1, 'count=' + afterTap.userBubbleCount);
}

// Reset viewport before the desktop typed-query test.
await send('Emulation.clearDeviceMetricsOverride');
await evaluate('location.href = ' + JSON.stringify(BASE));
await sleep(2500);

// --- Typed freeform query (not a chip click) --------------------------------
const TYPED_QUERY = 'What is the biggest security concern on the network right now?';
await evaluate(`(() => {
  const input = document.getElementById('query-input');
  input.focus();
  input.value = ${JSON.stringify(TYPED_QUERY)};
  input.dispatchEvent(new Event('input', { bubbles: true }));
})()`);
await sleep(200);

// Real users press Enter far more often than clicking Send.
await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter' });
await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter' });
await sleep(500);

const afterType = await evaluate(`(() => ({
  inputCleared: document.getElementById('query-input').value === '',
  userBubbleText: (document.querySelector('.message.user .message-bubble') || {}).textContent || null,
  sendDisabled: document.getElementById('send-btn').disabled,
}))()`);
check('typed query + Enter submits', afterType.inputCleared);
check('submitted query text matches what was typed', afterType.userBubbleText === TYPED_QUERY,
  JSON.stringify(afterType.userBubbleText));
check('send locked while typed query in flight', afterType.sendDisabled === true);

let typedSettled = false;
for (let i = 0; i < 45; i++) {
  await sleep(2000);
  const disabled = await evaluate(`document.getElementById('send-btn').disabled`);
  if (!disabled) { typedSettled = true; break; }
}
check('typed query completes within 90s', typedSettled);

if (typedSettled) {
  const typedAnswer = await evaluate(`(() => {
    const bubbles = [...document.querySelectorAll('.message.agent')];
    const last = bubbles[bubbles.length - 1];
    return last ? last.textContent.replace(/\\s+/g, ' ').trim() : null;
  })()`);
  check('typed query gets a real answer', (typedAnswer || '').length > 20, 'len=' + (typedAnswer || '').length);
  console.log('  typed-query answer (first 200 chars):', JSON.stringify((typedAnswer || '').slice(0, 200)));
}

await send('Page.close').catch(() => {});
ws.close();
console.log(check.failures() === 0 ? '\nALL CHECKS PASSED' : `\n${check.failures()} CHECK(S) FAILED`);
process.exit(check.failures() === 0 ? 0 : 1);

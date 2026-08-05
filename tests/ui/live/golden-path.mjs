// Drives the LIVE production UI (https://ng.bhnoc.com) over CDP the way the
// 80% of users behave: land on the page, click a starter chip, read the
// answer, click a Next Steps hint, check the alert sidebar, open a card.
// Read-only chat/alert traffic against prod. No npm deps.
import { connect, sleep, makeCheck } from './cdp.mjs';

const BASE = process.env.QA_BASE || 'https://ng.bhnoc.com';
const CDP_PORT = Number(process.env.CDP_PORT || 9222);
const check = makeCheck();

const { evaluate, send, ws } = await connect(BASE, CDP_PORT);

await evaluate('location.href = ' + JSON.stringify(BASE));
await sleep(2500);

// --- 1. Landing: does the page render the starter chips at all? -----------
const landing = await evaluate(`(() => {
  const chips = document.querySelectorAll('.example-chip');
  return {
    title: document.title,
    chipCount: chips.length,
    chipTexts: [...chips].map(c => c.textContent.trim()),
    hasInput: !!document.getElementById('query-input'),
    hasSendBtn: !!document.getElementById('send-btn'),
    alertFeedCount: document.querySelectorAll('#alerts-feed .alert-card').length,
  };
})()`);
check('page loads with a title', !!landing.title, landing.title);
check('starter chips render', landing.chipCount >= 1, 'count=' + landing.chipCount);
check('query input present', landing.hasInput);
check('send button present', landing.hasSendBtn);
console.log('  chips:', JSON.stringify(landing.chipTexts));
console.log('  alert feed items visible on load:', landing.alertFeedCount);

// --- 2. The 80% path: click the FIRST starter chip like a real user -------
if (landing.chipCount >= 1) {
  await evaluate(`document.querySelectorAll('.example-chip')[0].click()`);
  await sleep(500);

  const afterClick = await evaluate(`(() => ({
    inputCleared: document.getElementById('query-input').value === '',
    userBubbleCount: document.querySelectorAll('.message.user').length,
    sendDisabled: document.getElementById('send-btn').disabled,
  }))()`);
  check('chip click submits (input cleared)', afterClick.inputCleared);
  check('user message bubble appended', afterClick.userBubbleCount === 1, 'count=' + afterClick.userBubbleCount);
  check('send button disabled while in flight', afterClick.sendDisabled === true);

  // Poll up to ~90s for a real agent answer — live queries can take a while.
  let settled = null;
  for (let i = 0; i < 45; i++) {
    await sleep(2000);
    const state = await evaluate(`(() => ({
      sendDisabled: document.getElementById('send-btn').disabled,
      agentBubbleCount: document.querySelectorAll('.message.agent').length,
      errorBubbleCount: document.querySelectorAll('.message.agent.error, .message.error').length,
    }))()`);
    if (!state.sendDisabled && state.agentBubbleCount > 0) { settled = state; break; }
  }
  check('answer arrived within 90s', !!settled, settled ? '' : 'timed out, still in flight or no bubble');

  if (settled) {
    // Hint chips populate asynchronously after settle (orchestrator computes
    // them in the background, web-server polls for up to ~20s) — give that
    // window before reading hintChipCount, or a real chip that lands 3-20s
    // late reads as "no hints" when it would actually show up for a user.
    await sleep(8000);
    const answer = await evaluate(`(() => {
      const bubbles = [...document.querySelectorAll('.message.agent')];
      const last = bubbles[bubbles.length - 1];
      return {
        text: last ? last.textContent.replace(/\\s+/g, ' ').trim() : null,
        hasNextStepsHeading: last ? /next steps/i.test(last.textContent) : false,
        hintChipCount: last ? last.querySelectorAll('.hint-chip').length : 0,
        agentBadge: last ? (last.querySelector('.agent-badge')?.textContent.trim() || null) : null,
      };
    })()`);
    check('answer bubble has real text', (answer.text || '').length > 20, 'len=' + (answer.text || '').length);
    check('answer is not a refusal/cover', !/i can.?t help|not able to assist|outside my scope/i.test(answer.text || ''),
      JSON.stringify(answer.text?.slice(0, 200)));
    console.log('  agent badge:', answer.agentBadge);
    console.log('  answer (first 200 chars):', JSON.stringify((answer.text || '').slice(0, 200)));
    console.log('  Next Steps heading present:', answer.hasNextStepsHeading);
    console.log('  hint chip count on this answer:', answer.hintChipCount);

    // --- 3. The second-most-common thing users do: click a Next Steps hint --
    if (answer.hintChipCount > 0) {
      const beforeHintClick = await evaluate(`document.querySelectorAll('.message.user').length`);
      await evaluate(`(() => {
        const bubbles = [...document.querySelectorAll('.message.agent')];
        const last = bubbles[bubbles.length - 1];
        const chip = last.querySelector('.hint-chip');
        if (chip) chip.click();
      })()`);
      await sleep(500);
      const afterHintClick = await evaluate(`(() => ({
        userBubbleCount: document.querySelectorAll('.message.user').length,
        sendDisabled: document.getElementById('send-btn').disabled,
      }))()`);
      check('hint chip click submits a new query',
        afterHintClick.userBubbleCount === beforeHintClick + 1,
        `before=${beforeHintClick} after=${afterHintClick.userBubbleCount}`);
      check('send button locked during hint-triggered query', afterHintClick.sendDisabled === true);

      let hintSettled = false;
      for (let i = 0; i < 45; i++) {
        await sleep(2000);
        const stillDisabled = await evaluate(`document.getElementById('send-btn').disabled`);
        if (!stillDisabled) { hintSettled = true; break; }
      }
      check('hint-triggered query completes within 90s', hintSettled);
    } else {
      console.log('  (no hint chips on this answer to click — skipping step 3)');
    }
  }
}

// --- 4. The alert sidebar: does it render real cards? ----------------------
const alertFeed = await evaluate(`(() => {
  const cards = document.querySelectorAll('#alerts-feed .alert-card');
  return {
    count: cards.length,
    firstCardText: cards[0] ? cards[0].textContent.replace(/\\s+/g, ' ').trim().slice(0, 150) : null,
    feedContainerExists: !!document.getElementById('alerts-feed'),
  };
})()`);
check('alert feed container exists', alertFeed.feedContainerExists);
check('alert feed has real cards', alertFeed.count > 0, 'count=' + alertFeed.count);
console.log('  first alert card text:', JSON.stringify(alertFeed.firstCardText));

// --- 5. Click an alert card, does the popup open with real data? -----------
if (alertFeed.count > 0) {
  await evaluate(`(() => {
    const card = document.querySelector('#alerts-feed .alert-card');
    if (card) card.click();
  })()`);
  await sleep(800);

  const popup = await evaluate(`(() => {
    const modal = document.getElementById('alert-modal');
    const visible = modal && !modal.hidden;
    return {
      exists: !!modal,
      visible: !!visible,
      hasCloseButton: !!document.getElementById('alert-modal-close'),
      huntChipCount: modal ? modal.querySelectorAll('.hint-chip').length : 0,
      bodyText: modal ? modal.textContent.replace(/\\s+/g, ' ').trim().slice(0, 200) : null,
    };
  })()`);
  check('clicking an alert card opens the modal', popup.exists && popup.visible, JSON.stringify(popup));
  if (popup.exists) {
    check('popup has a close button', popup.hasCloseButton);
    check('popup has Hunt From Here chips', popup.huntChipCount > 0, 'count=' + popup.huntChipCount);
    console.log('  popup text (first 200 chars):', JSON.stringify(popup.bodyText));

    // Close it the way most users would: Escape.
    await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Escape', code: 'Escape' });
    await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Escape', code: 'Escape' });
    await sleep(300);
    const afterEscape = await evaluate(`(() => {
      const modal = document.getElementById('alert-modal');
      return !modal || modal.hidden;
    })()`);
    check('Escape closes the popup', afterEscape);
  }
} else {
  console.log('  (no alert cards to click — skipping step 5)');
}

await send('Page.close').catch(() => {});
ws.close();
console.log(check.failures() === 0 ? '\nALL CHECKS PASSED' : `\n${check.failures()} CHECK(S) FAILED`);
process.exit(check.failures() === 0 ? 0 : 1);

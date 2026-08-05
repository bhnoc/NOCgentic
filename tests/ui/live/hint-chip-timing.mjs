// Follow-up probe: does the answer bubble's hint-chip count ever go from 0 to
// nonzero after settling, or is it permanently empty in the DOM even though
// the orchestrator computes hints asynchronously (per sweep-1 findings)?
import { connect, sleep, makeCheck } from './cdp.mjs';

const BASE = process.env.QA_BASE || 'https://ng.bhnoc.com';
const CDP_PORT = Number(process.env.CDP_PORT || 9222);
const check = makeCheck();

const { evaluate, send, ws } = await connect(BASE, CDP_PORT);
await evaluate('location.href = ' + JSON.stringify(BASE));
await sleep(2000);

await evaluate(`document.querySelectorAll('.example-chip')[0].click()`);

let settledAt = null;
for (let i = 0; i < 45; i++) {
  await sleep(2000);
  const disabled = await evaluate(`document.getElementById('send-btn').disabled`);
  if (!disabled) { settledAt = Date.now(); break; }
}
check('query settled', !!settledAt);

// Now sample hint-chip count every 3s for 30s AFTER settle, to see if it's
// ever populated (matches the ~20s async hint-population window from sweep 1).
const samples = [];
for (let i = 0; i < 10; i++) {
  const count = await evaluate(`(() => {
    const bubbles = [...document.querySelectorAll('.message.agent')];
    const last = bubbles[bubbles.length - 1];
    return last ? last.querySelectorAll('.hint-chip').length : -1;
  })()`);
  samples.push(count);
  await sleep(3000);
}
console.log('hint-chip count samples every 3s post-settle:', samples);
check('hint chips ever appear in the DOM after settle', samples.some(c => c > 0), JSON.stringify(samples));

await send('Page.close').catch(() => {});
ws.close();
console.log(check.failures() === 0 ? '\nALL CHECKS PASSED' : `\n${check.failures()} CHECK(S) FAILED`);
process.exit(check.failures() === 0 ? 0 : 1);

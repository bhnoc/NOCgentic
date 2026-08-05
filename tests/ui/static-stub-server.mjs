// Stub of the two /api/v1/chat endpoints so the real static index.html can be
// driven headlessly without the full agent stack.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';

const STATIC = new URL('../../packages/web-server/static/index.html', import.meta.url);
const jobs = new Map();
let n = 0;
const received = [];

// Lane-race fixtures. A raced query answers with the WINNER only (the loser is
// still in flight in the real orchestrator), so the stub must serve the winner
// first and the pair on a later poll — otherwise the swap control would appear
// fully formed on the first render and the pending state would never be tested.
const LANE_TRIGGER = 'lane race';
const CONFIDENCE_TRIGGER = 'confidence pill check';
const QUERY_TABS_TRIGGER = 'query tabs check';
const NEXT_STEPS_TRIGGER = 'next steps merge check';
const SCOPE_ERROR_TRIGGER = 'scope error raw check';
const laneOf = (name, over = {}) => ({
  lane: name,
  label: name === 'cloud' ? 'Cloud (Gemini)' : 'Local (AQLight)',
  answer: name === 'cloud'
    ? 'CLOUD LANE: 3 hosts scanning port 445.'
    : 'LOCAL LANE: three internal hosts are scanning SMB.',
  confidence: name === 'cloud' ? 0.86 : 0.71,
  agentUsed: 'athena-hunter',
  data: { llm_metrics: { model: name === 'cloud' ? 'gemini-3.5-flash-lite' : 'AQLight' } },
  elapsedMs: name === 'cloud' ? 1200 : 3400,
  winner: name === 'cloud',
  ...over,
});
const lanePolls = new Map();
const hintPolls = new Map();

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');

  if (req.method === 'POST' && url.pathname === '/api/v1/chat') {
    let raw = '';
    for await (const c of req) raw += c;
    const { query } = JSON.parse(raw || '{}');
    const jobId = 'job-' + ++n;
    received.push({ jobId, query });
    if (String(query || '').toLowerCase().includes(LANE_TRIGGER)) {
      jobs.set(jobId, {
        jobId, status: 'done', agentUsed: 'athena-hunter', hints: [],
        answer: laneOf('cloud').answer,
        confidence: 0.86,
        data: laneOf('cloud').data,
        lane: 'cloud',
        lanes: [laneOf('cloud')],
        lanesRacing: true,
      });
      lanePolls.set(jobId, 0);
    } else if (String(query || '').toLowerCase().includes(CONFIDENCE_TRIGGER)) {
      // Single-lane response (no lanes array) but WITH a confidence value —
      // the pill must still render even when there's nothing to swap between.
      jobs.set(jobId, {
        jobId, status: 'done', agentUsed: 'athena-hunter', hints: [],
        answer: 'SINGLE LANE: confidence pill check answer.',
        confidence: 0.42,
      });
    } else if (String(query || '').toLowerCase().includes(QUERY_TABS_TRIGGER)) {
      // A very long single-line SQL string, on purpose: this is what used to
      // force the box to scroll sideways instead of wrapping.
      const longSql = 'SELECT ' + Array.from({ length: 20 }, (_, i) => `col_${i}`).join(', ') +
        " FROM alerts WHERE dt = '2026-08-05' AND alert_name IS NOT NULL GROUP BY alert_name ORDER BY ts DESC LIMIT 100";
      jobs.set(jobId, {
        jobId, status: 'done', agentUsed: 'athena-hunter', hints: [],
        // Raw is nested inside Evidence now (never a top-level toggle) — the
        // answer needs a real '## Evidence' section for Raw to have
        // somewhere to attach to.
        answer: '## Answer\nQUERY TABS: answer text.\n\n## Evidence\n- 2 hosts scanning 45.83.193.150\n',
        confidence: 0.8,
        data: {
          query_details: [{
            sql: longSql, row_count: 2, time_ms: 120, scanned_mb: 4.2,
            sample_rows: [
              { orig_h: '10.220.40.7', resp_h: '45.83.193.150', alert_name: 'Port scan' },
              { orig_h: '10.220.40.9', resp_h: '45.83.193.150', alert_name: 'Port scan' },
            ],
          }],
          total_rows: 2,
        },
      });
    } else if (String(query || '').toLowerCase().includes(NEXT_STEPS_TRIGGER)) {
      // The answer carries its OWN '## Next Steps' (recommended-action
      // bullets, e.g. from alert-triage's prompt) with no hints yet — the
      // follow-up-question hint chips land later via the hints polling loop.
      // Both must end up in ONE Next Steps section, not two.
      jobs.set(jobId, {
        jobId, status: 'done', agentUsed: 'alert-triage', hints: [],
        answer: '## Answer\n7 alerts across 1204 flows.\n\n' +
          '## Next Steps\n' +
          '1. Block 45.83.193.150 at the perimeter.\n' +
          '2. Pivot on uid=Cdemo001 across other log sources.\n',
        confidence: 0.81,
      });
      hintPolls.set(jobId, 0);
    } else if (String(query || '').toLowerCase().includes(SCOPE_ERROR_TRIGGER)) {
      // Real shape from a scope-rejected athena-hunter query: no query_details
      // (every attempted SQL failed), but data.errors[] carries the raw SQL —
      // including ipscope.OUT_OF_SCOPE_PLACEHOLDER baked into the WHERE clause
      // — which the "Raw" fallback panel used to JSON.stringify verbatim.
      jobs.set(jobId, {
        jobId, status: 'done', agentUsed: 'athena-hunter', hints: [],
        answer: '## Answer\nThe lookup could not be completed because the target is out of scope.\n\n' +
          '## Evidence\n- Target IP restricted by operational scope parameters.\n',
        confidence: 0.1,
        data: {
          iocs_searched: ['[OUT-OF-SCOPE-IP]'],
          sql_queries_executed: 0,
          total_rows: 0,
          query_details: [],
          errors: [{
            sql: "SELECT id_orig_h, proto FROM conn WHERE id_resp_h = '[OUT-OF-SCOPE-IP]' LIMIT 200",
            error: 'Out-of-scope IP in query: [OUT-OF-SCOPE-IP]',
          }],
        },
      });
    } else {
      jobs.set(jobId, { jobId, status: 'done', answer: 'stub answer for: ' + query, agentUsed: 'stub', hints: [] });
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ jobId }));
  }

  if (url.pathname.startsWith('/api/v1/chat/')) {
    const jobId = url.pathname.split('/').pop();
    const job = jobs.get(jobId);
    // Second poll onwards: the loser has landed. Mirrors the web-server writing
    // both lanes into the job once GET /lanes/<id> reports done.
    if (job && lanePolls.has(jobId)) {
      const seen = lanePolls.get(jobId) + 1;
      lanePolls.set(jobId, seen);
      if (seen >= 2) {
        job.lanes = [laneOf('cloud'), laneOf('local')];
        job.lanesRacing = false;
      }
    }
    if (job && hintPolls.has(jobId)) {
      const seen = hintPolls.get(jobId) + 1;
      hintPolls.set(jobId, seen);
      if (seen >= 2) {
        job.hints = [
          'What other hosts connected to 45.83.193.150 in the last 24 hours?',
          'Has this host triggered any other alerts today?',
        ];
      }
    }
    res.writeHead(job ? 200 : 404, { 'content-type': 'application/json' });
    return res.end(JSON.stringify(job || { error: 'no such job' }));
  }

  // Starter-hint draw. Deliberately NOT the static fallback set in index.html:
  // the page must visibly replace those chips, and a test that can't tell the
  // two apart would pass with the dynamic path dead.
  if (url.pathname === '/api/v1/config') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({
      eventLabel: 'Black Hat STUB 2026',
      starterHints: [
        'STUB HINT: what is the biggest risk so far?',
        'STUB HINT: are there any attacks happening right now?',
        'STUB HINT: what is the most interesting attack?',
        'STUB HINT: how is the network quality right now?',
        'STUB HINT: is there any latency reported to AWS?',
      ],
    }));
  }

  if (url.pathname === '/__received') {
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify(received));
  }

  if (url.pathname === '/favicon.ico') {
    res.writeHead(200, { 'content-type': 'image/x-icon' });
    return res.end(await readFile(new URL('../../packages/web-server/static/favicon.ico', import.meta.url)));
  }

  if (url.pathname === '/' || url.pathname === '/index.html') {
    res.writeHead(200, { 'content-type': 'text/html' });
    return res.end(await readFile(STATIC));
  }

  // The UI's CSS and JS were inline in index.html until they were split into
  // app.css / app.js. This stub served only index.html, so app.js 404'd, nothing
  // defined fillQuery/sendQuery, and every behavioural assertion failed with
  // "fillQuery is not defined" -- which looks like the page is broken rather than
  // like the harness is missing a route. Serve the sibling assets the page asks for.
  const asset = {
    '/app.js': 'text/javascript',
    '/app.css': 'text/css',
    '/alertHints.js': 'text/javascript',
    '/assets/bhnoc-logo.png': 'image/png',
  }[url.pathname];
  if (asset) {
    res.writeHead(200, { 'content-type': asset });
    return res.end(await readFile(
      new URL(`../../packages/web-server/static${url.pathname}`, import.meta.url)));
  }

  res.writeHead(404, { 'content-type': 'application/json' });
  res.end('{}');
});

server.listen(8791, '127.0.0.1', () => console.log('stub on 8791'));

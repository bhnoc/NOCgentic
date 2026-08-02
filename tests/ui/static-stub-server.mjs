// Stub of the two /api/v1/chat endpoints so the real static index.html can be
// driven headlessly without the full agent stack.
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';

const STATIC = new URL('../../packages/web-server/static/index.html', import.meta.url);
const jobs = new Map();
let n = 0;
const received = [];

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');

  if (req.method === 'POST' && url.pathname === '/api/v1/chat') {
    let raw = '';
    for await (const c of req) raw += c;
    const { query } = JSON.parse(raw || '{}');
    const jobId = 'job-' + ++n;
    received.push({ jobId, query });
    jobs.set(jobId, { jobId, status: 'done', answer: 'stub answer for: ' + query, agentUsed: 'stub', hints: [] });
    res.writeHead(200, { 'content-type': 'application/json' });
    return res.end(JSON.stringify({ jobId }));
  }

  if (url.pathname.startsWith('/api/v1/chat/')) {
    const job = jobs.get(url.pathname.split('/').pop());
    res.writeHead(job ? 200 : 404, { 'content-type': 'application/json' });
    return res.end(JSON.stringify(job || { error: 'no such job' }));
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
  const asset = { '/app.js': 'text/javascript', '/app.css': 'text/css' }[url.pathname];
  if (asset) {
    res.writeHead(200, { 'content-type': asset });
    return res.end(await readFile(
      new URL(`../../packages/web-server/static${url.pathname}`, import.meta.url)));
  }

  res.writeHead(404, { 'content-type': 'application/json' });
  res.end('{}');
});

server.listen(8791, '127.0.0.1', () => console.log('stub on 8791'));

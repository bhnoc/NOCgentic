// Report Issue widget — floating bottom-right button in chat and threat hunt.
// Captures a viewport screenshot (html2canvas, vendored — no CDN) plus a short
// note and POSTs both to /api/v1/report-issue, which the server proxies to the
// orchestrator for an S3 upload under a separate prefix from the trace archive.
// Deliberately not present in tools/audit-monitor: that's a standalone FastAPI
// app with its own static assets, this script is never served there.
(function () {
  const MAX_NOTE_LEN = 1000;

  function els() {
    return {
      btn: document.getElementById('report-issue-btn'),
      backdrop: document.getElementById('report-issue-backdrop'),
      panel: document.getElementById('report-issue-panel'),
      close: document.getElementById('report-issue-close'),
      note: document.getElementById('report-issue-note'),
      preview: document.getElementById('report-issue-preview'),
      status: document.getElementById('report-issue-status'),
      submit: document.getElementById('report-issue-submit'),
    };
  }

  let capturedDataUrl = null;
  let opening = false;

  function setStatus(el, text, tone) {
    el.textContent = text || '';
    el.classList.remove('report-issue-status-ok', 'report-issue-status-err');
    if (tone) el.classList.add('report-issue-status-' + tone);
  }

  async function openPanel() {
    // Re-entrancy guard: a double-click fires two openPanel() calls before
    // either's html2canvas capture resolves, stacking two screenshots in
    // the preview (same click-flood class as the threat-hunt.js fixes).
    if (opening) return;
    opening = true;
    try {
      await doOpenPanel();
    } finally {
      opening = false;
    }
  }

  async function doOpenPanel() {
    const { backdrop, panel, note, preview, status, submit } = els();
    backdrop.hidden = false;
    panel.hidden = false;
    note.value = '';
    preview.hidden = true;
    preview.innerHTML = '';
    setStatus(status, '', null);
    submit.disabled = false;
    capturedDataUrl = null;

    // Capture the panel's own backdrop/panel are hidden from the shot by
    // hiding them first — html2canvas.ignoreElements below also excludes them.
    try {
      const canvas = await window.html2canvas(document.body, {
        backgroundColor: '#000000',
        logging: false,
        scale: Math.min(window.devicePixelRatio || 1, 2),
        ignoreElements: (el) =>
          el.id === 'report-issue-backdrop' ||
          el.id === 'report-issue-panel' ||
          el.id === 'report-issue-btn',
      });
      capturedDataUrl = canvas.toDataURL('image/jpeg', 0.7);
      const img = document.createElement('img');
      img.src = capturedDataUrl;
      preview.appendChild(img);
      preview.hidden = false;
    } catch (_) {
      // Screenshot failed (e.g. a cross-origin resource html2canvas can't read) —
      // still let the user send a text-only report.
      setStatus(status, 'Screenshot unavailable — note will still be sent.', null);
    }

    note.focus();
  }

  function closePanel() {
    const { backdrop, panel } = els();
    backdrop.hidden = true;
    panel.hidden = true;
    capturedDataUrl = null;
  }

  function currentSessionId() {
    try {
      return localStorage.getItem('bhnoc.client_id') || '';
    } catch (_) {
      return '';
    }
  }

  async function submitReport() {
    const { note, status, submit } = els();
    const text = note.value.trim().slice(0, MAX_NOTE_LEN);
    if (!text && !capturedDataUrl) {
      setStatus(status, 'Add a note or wait for the screenshot.', 'err');
      return;
    }

    submit.disabled = true;
    setStatus(status, 'Sending…', null);

    async function send(withImage) {
      return fetch('/api/v1/report-issue', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Client-Session': currentSessionId(),
        },
        body: JSON.stringify({
          note: text,
          image: withImage ? (capturedDataUrl || undefined) : undefined,
          view: (document.getElementById('hunt-view') && !document.getElementById('hunt-view').hidden) ? 'hunt' : 'chat',
          path: window.location.hash || window.location.pathname,
        }),
      });
    }

    try {
      let resp = await send(true);

      // A 400 means the request itself is invalid (e.g. an oversized
      // screenshot) — retrying the identical payload will fail forever.
      // If there's a screenshot to drop, retry once without it instead of
      // surfacing a "try again" message that can never succeed.
      if (resp.status === 400 && capturedDataUrl) {
        setStatus(status, 'Report too large — resending without the screenshot…', null);
        resp = await send(false);
      }

      if (!resp.ok) {
        throw new Error('status ' + resp.status);
      }

      setStatus(status, 'Sent. Thanks for the flag.', 'ok');
      setTimeout(closePanel, 1200);
    } catch (_) {
      setStatus(status, 'Could not send — try again in a moment.', 'err');
      submit.disabled = false;
    }
  }

  function init() {
    const { btn, backdrop, close, submit } = els();
    if (!btn) return;
    btn.addEventListener('click', openPanel);
    close.addEventListener('click', closePanel);
    backdrop.addEventListener('click', closePanel);
    submit.addEventListener('click', submitReport);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

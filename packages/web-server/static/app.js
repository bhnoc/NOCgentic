// ========== State ==========
  let ws = null;
  let wsReconnectTimer = null;
  let queryCount = 0;
  let totalAlerts = 0;
  let criticalAlerts = 0;
  const pollIntervals = new Map();

  // Internal source-table names → what an analyst actually recognizes. `source`
  // is athena-hunter's alert_type (lambda/derived_views.py ALERT_SOURCES),
  // which is a table name ("suricata", "ml"), not a vendor/tool label.
  const SOURCE_LABELS = {
    suricata: 'Corelight Suricata',
    notice:   'Corelight Zeek Notice',
    ml:       'Corelight ML',
    yara:     'Corelight YARA',
    anomaly:  'Corelight Anomaly',
    corelight: 'Corelight',
  };
  function sourceLabel(source) {
    return SOURCE_LABELS[String(source || '').toLowerCase()] || source || '';
  }

  // A YARA hit's alert_detail embeds "sha256=<64 hex chars>" straight into the
  // description (lambda/derived_views.py ALERT_SOURCES). At 64 chars with no
  // wrap, a card either overflows sideways or forces horizontal scroll on the
  // whole sidebar. Truncate any long hex run for DISPLAY only, with a copy
  // button carrying the full value, so the analyst can still get the exact
  // string without the card layout breaking.
  const LONG_HASH_RE = /\b([0-9a-fA-F]{20,64})\b/g;

  /** Card description with long hashes replaced by a truncated span + copy
   *  button. Returns HTML — description text itself is escaped first. */
  function renderCardDescription(description) {
    const escaped = escHtml(description || '');
    return escaped.replace(LONG_HASH_RE, (full) => {
      const short = full.slice(0, 8) + '…' + full.slice(-6);
      return `<span class="hash-chip">${short}` +
        `<button type="button" class="hash-copy-btn" data-copy="${full}" ` +
        `title="Copy full hash" aria-label="Copy full hash">⧉</button></span>`;
    });
  }

  /** Copy-to-clipboard for anything rendered by renderCardDescription /
   *  renderAlertDetail. Delegated: cards and the popup body are both
   *  re-rendered via innerHTML, so a bound per-button listener would be
   *  discarded on every re-render.
   *
   *  CAPTURE phase, not bubble: the alert card's own click-to-open listener
   *  is bound directly on the card (bubble phase). A document-level bubble
   *  listener fires AFTER the card's, since document is the outermost
   *  ancestor — by then stopPropagation() is too late and the popup opens
   *  anyway. Capture runs top-down, so this sees the click before the card
   *  does. */
  document.addEventListener('click', (ev) => {
    const btn = ev.target.closest && ev.target.closest('.hash-copy-btn');
    if (!btn) return;
    ev.preventDefault();
    ev.stopPropagation(); // do not also trigger the card's own click-to-open
    const value = btn.getAttribute('data-copy') || '';
    navigator.clipboard?.writeText(value).then(() => {
      const original = btn.textContent;
      btn.textContent = '✓';
      setTimeout(() => { btn.textContent = original; }, 1200);
    }).catch(() => {});
  }, true);

  // ========== WebSocket ==========
  function connectWS() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const url = `${proto}://${location.host}/ws`;
    ws = new WebSocket(url);
    ws.onopen = () => setWsStatus('online', 'LIVE');
    ws.onclose = () => { setWsStatus('offline', 'RECONNECT'); ws = null; wsReconnectTimer = setTimeout(connectWS, 4000); };
    ws.onerror = () => setWsStatus('offline', 'ERROR');
    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data);
        if (msg.type === 'alert_feed' && Array.isArray(msg.alerts)) renderAlerts(msg.alerts);
        // Job results arrive via HTTP polling (pollJob), not over the socket.
      } catch (_) {}
    };
  }

  function setWsStatus(state, label) {
    document.getElementById('ws-dot').className = 'status-dot ' + (state === 'online' ? 'online' : 'offline');
    document.getElementById('ws-label').textContent = label;
  }

  // ========== Alert Feed ==========
  // Built by alertHints.js, not here, so the Triage query goes through the same
  // guardrail filter as the hunt chips. It is the same hazard: text assembled from
  // live alert fields and submitted as a query, where one vendor name or zone word
  // gets it answered with a silent cover.
  function triageAlert(alert, ev) {
    if (ev) {
      ev.preventDefault();
      ev.stopPropagation();
    }
    if (document.getElementById('send-btn').disabled) return;
    const input = document.getElementById('query-input');
    // Guarded like the hint row below: if alertHints.js failed to load, ask the
    // generic question rather than throwing inside a click handler.
    input.value = typeof buildTriageQuery === 'function'
      ? buildTriageQuery(alert)
      : 'How serious is this alert and what should we check next?';
    autoResize(input);
    input.focus();
    sendQuery();
  }

  function renderAlerts(alerts) {
    if (!alerts || alerts.length === 0) return;
    const feed = document.getElementById('alerts-feed');
    const empty = feed.querySelector('.empty-feed');
    if (empty) empty.remove();

    alerts.reverse().forEach(a => {
      if (feed.querySelector(`[data-id="${CSS.escape(a.id)}"]`)) return;
      const card = document.createElement('div');
      const sev = (a.severity || 'low').toLowerCase();
      card.className = 'alert-card sev-card-' + sev;
      card.dataset.id = a.id;

      const sevClass = { critical:'sev-critical', high:'sev-high', medium:'sev-medium', low:'sev-low', informational:'sev-info' }[sev] || 'sev-low';
      const ts = new Date(a.timestamp);
      const timeStr = ts.toLocaleTimeString('en-US', { hour:'2-digit', minute:'2-digit', second:'2-digit' });

      card.innerHTML = `
        <div class="alert-top">
          <span class="sev-badge ${sevClass}">${escHtml(sev)}</span>
          <span class="alert-time">${timeStr}</span>
        </div>
        <div class="alert-desc">${renderCardDescription(a.description)}</div>
        <div class="alert-src">${escHtml(sourceLabel(a.source))}${a.srcIp?' // '+escHtml(a.srcIp):''}</div>
      `;

      // The card is the only place the full alert object exists client-side —
      // the popup reads it from here rather than re-fetching or re-parsing DOM.
      card.setAttribute('role', 'button');
      card.tabIndex = 0;
      card.addEventListener('click', () => openAlertModal(a));
      card.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); openAlertModal(a); }
      });

      feed.insertBefore(card, feed.firstChild);
      totalAlerts++;
      if (sev === 'critical') criticalAlerts++;
      document.getElementById('stat-total').textContent = totalAlerts;
      document.getElementById('stat-critical').textContent = criticalAlerts;
    });

    while (feed.children.length > 50) feed.removeChild(feed.lastChild);
    // On mobile, ensure exactly one card is visible after new arrivals
    if (mobileAlertMode) showMobileAlert();
  }

  // ========== Alert detail popup ==========
  // Draggable, closes on X / backdrop click / Escape. The panel is positioned
  // with explicit left+top (never a transform) so a drag can just write the
  // pointer position back into the same two properties.
  let alertModalDrag = null;        // { pointerId, dx, dy } while dragging
  let alertModalReturnFocus = null; // element focused before the popup opened

  function alertModalEls() {
    return {
      backdrop: document.getElementById('alert-modal-backdrop'),
      modal:    document.getElementById('alert-modal'),
      head:     document.getElementById('alert-modal-head'),
      body:     document.getElementById('alert-modal-body'),
      close:    document.getElementById('alert-modal-close'),
    };
  }

  function openAlertModal(alert) {
    const el = alertModalEls();
    if (!el.modal || !el.backdrop || !el.body || !alert) return;

    alertModalReturnFocus = document.activeElement;
    const sev = String(alert.severity || 'low').toLowerCase();
    el.body.innerHTML = renderAlertDetail(alert);
    // Reuse the feed's severity stripe so the popup reads as the same object.
    el.modal.className = 'alert-modal sev-card-' + sev;
    el.backdrop.hidden = false;
    el.modal.hidden = false;
    centerAlertModal();

    el.body.querySelectorAll('.hint-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const query = chip.getAttribute('data-hint');
        closeAlertModal();
        if (query) submitQueryText(query);
      });
    });

    const triageBtn = el.body.querySelector('.alert-triage-btn');
    if (triageBtn) triageBtn.addEventListener('click', (ev) => {
      closeAlertModal();
      triageAlert(alert, ev);
    });

    if (el.close) el.close.focus();
  }

  function closeAlertModal() {
    const el = alertModalEls();
    if (!el.modal || el.modal.hidden) return;
    if (alertModalDrag && el.head && el.head.releasePointerCapture) {
      try { el.head.releasePointerCapture(alertModalDrag.pointerId); } catch (_) {}
    }
    alertModalDrag = null;
    el.modal.classList.remove('dragging');
    el.modal.hidden = true;
    el.backdrop.hidden = true;
    el.body.innerHTML = '';
    const back = alertModalReturnFocus;
    alertModalReturnFocus = null;
    if (back && back.focus && document.contains(back)) back.focus();
  }

  function centerAlertModal() {
    const { modal } = alertModalEls();
    if (!modal) return;
    placeAlertModal((window.innerWidth - modal.offsetWidth) / 2,
                    (window.innerHeight - modal.offsetHeight) / 2);
  }

  /** Write left/top, clamped so the panel can never be dragged off-screen. */
  function placeAlertModal(left, top) {
    const { modal } = alertModalEls();
    if (!modal) return;
    const maxLeft = Math.max(0, window.innerWidth - modal.offsetWidth);
    const maxTop  = Math.max(0, window.innerHeight - modal.offsetHeight);
    modal.style.left = Math.round(Math.min(Math.max(left, 0), maxLeft)) + 'px';
    modal.style.top  = Math.round(Math.min(Math.max(top, 0), maxTop)) + 'px';
  }

  function renderAlertDetail(a) {
    const sev = String(a.severity || 'low').toLowerCase();
    const sevClass = { critical:'sev-critical', high:'sev-high', medium:'sev-medium', low:'sev-low', informational:'sev-info' }[sev] || 'sev-low';
    // Detected: the actual event time. `timestamp` is re-stamped to "now" when
    // the alert enters the feed (drives the sidebar's live-arrival ordering);
    // `observedAt` is when Athena says it happened. Showing both as "Detected"
    // + "Observed" reads as two different events for the same alert — use
    // whichever is the real one and show only that.
    const detectedRaw = a.observedAt || a.timestamp;
    const ts = new Date(detectedRaw);
    const when = isNaN(ts.getTime())
      ? String(detectedRaw || 'unknown')
      : ts.toLocaleString('en-US', { month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit' });

    const rows = [
      ['Source',      sourceLabel(a.source)],
      ['Src IP',      a.srcIp],
      ['Src Port',    a.srcPort === 0 || a.srcPort ? String(a.srcPort) : ''],
      ['Dst IP',      a.dstIp],
      ['Dst Port',    a.dstPort === 0 || a.dstPort ? String(a.dstPort) : ''],
      ['Network',     a.network],
      ['Action',      a.action],
      ['Detected',    when],
      ['Occurrences', a.occurrences != null && a.occurrences > 0 ? String(a.occurrences) : ''],
      ['UID',         a.uid],
      ['Alert ID',    a.id],
    ].filter(([, v]) => v !== undefined && v !== null && String(v).trim() !== '');

    const grid = rows.map(([label, value]) =>
      `<div class="adg-row"><dt>${escHtml(label)}</dt><dd>${escHtml(String(value))}</dd></div>`).join('');

    // Guardrail-filtered in alertHints.js: a clicked chip that trips the
    // orchestrator would answer with a silent cover, so fewer chips is correct.
    const hints = typeof buildAlertHuntHints === 'function' ? buildAlertHuntHints(a) : [];
    const hintRow = hints.length === 0 ? '' : `
      <div class="hunt-row">
        <span class="hints-label">Hunt From Here</span>
        ${hints.map(h => `<button type="button" class="hint-chip" data-hint="${escHtml(h)}">${escHtml(h)}</button>`).join('')}
      </div>`;

    return `
      <div class="alert-detail-top">
        <span class="sev-badge ${sevClass}">${escHtml(sev)}</span>
        <span class="alert-detail-time">${escHtml(when)}</span>
      </div>
      <div class="alert-detail-desc">${renderCardDescription(a.description || '')}</div>
      <dl class="alert-detail-grid">${grid}</dl>
      ${hintRow}
      <button type="button" class="alert-triage-btn">Triage</button>
    `;
  }

  // Static shell in index.html, so these bind once. app.js is loaded at the end
  // of <body>, so the elements exist by the time this runs.
  (function wireAlertModal() {
    const el = alertModalEls();
    if (!el.modal || !el.head || !el.backdrop) return;

    if (el.close) el.close.addEventListener('click', closeAlertModal);
    el.backdrop.addEventListener('click', closeAlertModal);

    el.head.addEventListener('pointerdown', (ev) => {
      if (ev.button != null && ev.button !== 0) return;
      if (ev.target.closest && ev.target.closest('.alert-modal-close')) return;
      const rect = el.modal.getBoundingClientRect();
      alertModalDrag = { pointerId: ev.pointerId, dx: ev.clientX - rect.left, dy: ev.clientY - rect.top };
      el.modal.classList.add('dragging');
      if (el.head.setPointerCapture) { try { el.head.setPointerCapture(ev.pointerId); } catch (_) {} }
      ev.preventDefault(); // suppress text selection / touch scroll while dragging
    });

    el.head.addEventListener('pointermove', (ev) => {
      if (!alertModalDrag || ev.pointerId !== alertModalDrag.pointerId) return;
      placeAlertModal(ev.clientX - alertModalDrag.dx, ev.clientY - alertModalDrag.dy);
    });

    const endDrag = (ev) => {
      if (!alertModalDrag || (ev && ev.pointerId !== alertModalDrag.pointerId)) return;
      alertModalDrag = null;
      el.modal.classList.remove('dragging');
    };
    el.head.addEventListener('pointerup', endDrag);
    el.head.addEventListener('pointercancel', endDrag);

    document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape') closeAlertModal(); });
    // A shrinking viewport must not strand a dragged panel outside it.
    window.addEventListener('resize', () => {
      if (!el.modal.hidden) placeAlertModal(el.modal.offsetLeft, el.modal.offsetTop);
    });
  })();

  // ========== Mobile single-alert rotator ==========
  const mobileMQ = window.matchMedia('(max-width: 480px)');
  let mobileAlertMode = mobileMQ.matches;
  let mobileRotateTimer = null;

  function showMobileAlert(specific) {
    const feed = document.getElementById('alerts-feed');
    if (!feed) return;
    const cards = Array.from(feed.querySelectorAll('.alert-card'));
    if (cards.length === 0) return;
    const next = specific || cards[Math.floor(Math.random() * cards.length)];
    cards.forEach(c => c.classList.remove('mobile-show'));
    next.classList.add('mobile-show');
  }

  function scheduleMobileRotate() {
    if (mobileRotateTimer) clearTimeout(mobileRotateTimer);
    if (!mobileAlertMode) return;
    const delay = 3000 + Math.random() * 2000; // 3–5 s
    mobileRotateTimer = setTimeout(() => {
      showMobileAlert();
      scheduleMobileRotate();
    }, delay);
  }

  function applyMobileAlertMode() {
    mobileAlertMode = mobileMQ.matches;
    if (mobileAlertMode) {
      showMobileAlert();
      scheduleMobileRotate();
    } else {
      if (mobileRotateTimer) clearTimeout(mobileRotateTimer);
      mobileRotateTimer = null;
      const feed = document.getElementById('alerts-feed');
      if (feed) feed.querySelectorAll('.alert-card.mobile-show')
                    .forEach(c => c.classList.remove('mobile-show'));
    }
  }
  mobileMQ.addEventListener('change', applyMobileAlertMode);

  async function loadInitialAlerts() {
    try {
      const resp = await fetch('/api/v1/alerts/recent');
      if (!resp.ok) return;
      const data = await resp.json();
      if (data.alerts && data.alerts.length > 0) renderAlerts(data.alerts);
      // No demo fallback here — the boot timer handles empty feed after grace.
    } catch (_) { /* WebSocket trickle will populate */ }
  }

  function injectDemoAlerts() {
    const now = Date.now();
    renderAlerts([
      { id:'d1', severity:'critical', source:'paloalto', description:'C2 beacon detected -- high frequency TCP/4444', srcIp:'10.220.44.88', dstIp:'185.220.101.45', srcPort:49152, dstPort:4444, uid:'Cdemo001', network:'Vendor WiFi', occurrences:12, observedAt:new Date(now-12000).toISOString(), timestamp:new Date(now-12000).toISOString() },
      { id:'d2', severity:'high', source:'corelight', description:'Port scan -- 1,247 SYN packets in 10s', srcIp:'45.83.193.150', dstIp:'10.220.40.10', dstPort:22, uid:'Cdemo002', network:'Core', occurrences:3, observedAt:new Date(now-45000).toISOString(), timestamp:new Date(now-45000).toISOString() },
      { id:'d3', severity:'high', source:'paloalto', description:'Outbound DENY -- blocked TOR exit node connection', srcIp:'10.220.42.15', dstIp:'185.220.101.99', dstPort:9001, uid:'Cdemo003', observedAt:new Date(now-90000).toISOString(), timestamp:new Date(now-90000).toISOString() },
      { id:'d4', severity:'medium', source:'corelight', description:'DNS tunneling suspected -- 63-char subdomain', srcIp:'10.220.41.22', dstIp:'8.8.8.8', dstPort:53, uid:'Cdemo004', network:'Attendee', observedAt:new Date(now-130000).toISOString(), timestamp:new Date(now-130000).toISOString() },
      { id:'d5', severity:'medium', source:'partner', description:'Threat intel match -- IP on Emerging Threats blocklist', srcIp:'185.220.101.45', dstIp:'10.220.50.2', dstPort:443, observedAt:new Date(now-200000).toISOString(), timestamp:new Date(now-200000).toISOString() },
      { id:'d6', severity:'low', source:'corelight', description:'Unusual protocol -- SSH on TCP/8022', srcIp:'10.220.65.14', dstIp:'10.220.10.5', srcPort:50222, dstPort:8022, uid:'Cdemo006', occurrences:2, observedAt:new Date(now-310000).toISOString(), timestamp:new Date(now-310000).toISOString() },
    ]);
  }

  function startDemoAlertTicker() {
    const templates = [
      { severity:'high', source:'paloalto', descriptions:['Lateral movement -- SMB to multiple hosts','Repeated auth failure -- brute force suspected','Outbound DENY to GeoIP:CN -- policy block'] },
      { severity:'medium', source:'corelight', descriptions:['Long connection -- 3600s on TCP/443','HTTP POST to suspicious URI','TLS cert mismatch on internal host'] },
      { severity:'critical', source:'partner', descriptions:['Ransomware signature in flow data','Known APT C2 domain queried','Data exfil pattern -- 50MB outbound burst'] },
      { severity:'low', source:'corelight', descriptions:['ICMP sweep across /24','Expired TLS cert observed','Cleartext creds in HTTP form-post'] },
      { severity:'high', source:'thousandeyes', descriptions:['BGP route hijack detected -- prefix withdrawn','Packet loss >15% on uplink to conference ISP','Latency spike -- 320ms avg on external probes'] },
      { severity:'medium', source:'thousandeyes', descriptions:['ThousandEyes test failure -- HTTP 503 from CDN','Path change detected -- 3 additional AS hops','Network reachability degraded -- 2 agents reporting'] },
    ];
    let counter = 100;
    setInterval(() => {
      const t = templates[Math.floor(Math.random()*templates.length)];
      renderAlerts([{
        id:'demo-'+(counter++), severity:t.severity, source:t.source,
        description:t.descriptions[Math.floor(Math.random()*t.descriptions.length)],
        srcIp:randomIp(), dstIp:randomIp(),
        srcPort:1024 + Math.floor(Math.random()*60000),
        dstPort:[22, 443, 80, 445, 3389, 53][Math.floor(Math.random()*6)],
        uid:'Cdemo' + String(counter).padStart(6, '0'),
        network:['Core', 'Vendor WiFi', 'Attendee', 'Partner'][Math.floor(Math.random()*4)],
        occurrences:1 + Math.floor(Math.random()*20),
        observedAt:new Date(Date.now() - Math.floor(Math.random()*3600000)).toISOString(),
        timestamp:new Date().toISOString(),
      }]);
    }, 8000 + Math.random()*12000);
  }

  function randomIp() {
    const p = ['45.83.','185.220.','91.108.','194.165.','80.82.'][Math.floor(Math.random()*5)];
    return p + Math.floor(Math.random()*200) + '.' + Math.floor(Math.random()*254);
  }

  // ========== Chat ==========
  function fillQuery(btn) {
    submitQueryText(btn.textContent.trim());
  }

  /** Put text in the box and send it. Shared by the welcome chips and the
   *  alert-popup hunt chips so both respect the in-flight send lock. */
  function submitQueryText(text) {
    const query = String(text || '').trim();
    if (!query) return;
    if (document.getElementById('send-btn').disabled) return;
    const input = document.getElementById('query-input');
    input.value = query;
    autoResize(input);
    input.focus();
    sendQuery();
  }

  function autoResize(el) { el.style.height = 'auto'; el.style.height = Math.min(el.scrollHeight, 140) + 'px'; }

  document.getElementById('query-input').addEventListener('input', function() { autoResize(this); });
  document.getElementById('query-input').addEventListener('keydown', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendQuery(); }
  });

  // ========== Client session tracking ==========
  // localStorage-backed stable ID so the same person is recognised across
  // refreshes / restarts / even if cookies are cleared. Server pairs this with
  // the bh_sid HttpOnly cookie; if either survives, continuity is maintained.
  function getClientSessionId() {
    try {
      let id = localStorage.getItem('bhnoc.client_id');
      if (!id) {
        id = (crypto.randomUUID && crypto.randomUUID()) ||
             ('c-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 10));
        localStorage.setItem('bhnoc.client_id', id);
      }
      return id;
    } catch (_) {
      // Private mode / storage blocked — fall back to an in-memory UUID for this tab
      if (!window.__bhnocTabId) {
        window.__bhnocTabId = 'c-tab-' + Math.random().toString(36).slice(2, 12);
      }
      return window.__bhnocTabId;
    }
  }

  async function sendQuery() {
    const input = document.getElementById('query-input');
    const query = input.value.trim();
    if (!query) return;

    const sendBtn = document.getElementById('send-btn');
    // Gate here, not just in callers: sendQuery() previously only SET disabled,
    // never CHECKED it first, so two calls landing in the same tick (before the
    // first await yields) both passed through and each fired its own POST. This
    // is the real backstop; submitQueryText()'s own check is what lets a caller
    // fail fast without touching the input box first.
    if (sendBtn.disabled) return;
    sendBtn.disabled = true;

    const banner = document.getElementById('welcome-banner');
    if (banner) banner.remove();

    appendMessage('user', query);
    input.value = '';
    input.style.height = 'auto';

    const thinkingId = 'thinking-' + Date.now();
    appendThinking(thinkingId);

    queryCount++;
    document.getElementById('stat-queries').textContent = queryCount;

    try {
      // AbortController so the fetch can't hang forever (browser default is infinite)
      const ctrl = new AbortController();
      const killer = setTimeout(() => ctrl.abort(), 30000);
      let resp;
      try {
        resp = await fetch('/api/v1/chat', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Client-Session': getClientSessionId(),
          },
          body: JSON.stringify({ query }),
          credentials: 'same-origin',
          signal: ctrl.signal,
        });
      } finally {
        clearTimeout(killer);
      }

      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        removeThinking(thinkingId);
        appendAgentMessage({ status:'error', error:err.error||`HTTP ${resp.status}`, agentUsed:'system' });
        sendBtn.disabled = false;
        return;
      }

      console.log('[sendQuery] POST ok — parsing body');
      let body;
      try { body = await resp.json(); }
      catch (jsonErr) {
        console.error('[sendQuery] JSON parse failed:', jsonErr);
        removeThinking(thinkingId);
        appendAgentMessage({ status:'error', error:'Malformed server response: ' + jsonErr.message, agentUsed:'system' });
        sendBtn.disabled = false;
        return;
      }
      const jobId = body && body.jobId;
      console.log('[sendQuery] got jobId=', jobId);
      if (!jobId) {
        removeThinking(thinkingId);
        appendAgentMessage({ status:'error', error:'Server did not return a jobId', agentUsed:'system' });
        sendBtn.disabled = false;
        return;
      }

      try {
        pollJob(jobId, thinkingId, sendBtn);
        console.log('[sendQuery] pollJob scheduled for', jobId);
      } catch (pollErr) {
        console.error('[sendQuery] pollJob threw synchronously:', pollErr);
        removeThinking(thinkingId);
        appendAgentMessage({ status:'error', error:'Failed to start polling: ' + pollErr.message, agentUsed:'system' });
        sendBtn.disabled = false;
      }
    } catch (err) {
      console.error('[sendQuery] outer catch:', err);
      removeThinking(thinkingId);
      const msg = err && err.name === 'AbortError'
        ? 'Request timed out — server may be overloaded. Please retry.'
        : (err && err.message) || 'Network error — check DevTools → Network.';
      appendAgentMessage({ status:'error', error: msg, agentUsed:'system' });
      sendBtn.disabled = false;
    }
  }

  function pollJob(jobId, thinkingId, sendBtn) {
    let attempts = 0;
    let consecFail = 0;
    const timer = setInterval(async () => {
      attempts++;
      try {
        const resp = await fetch(`/api/v1/chat/${jobId}`);
        if (!resp.ok) { clearInterval(timer); removeThinking(thinkingId); appendAgentMessage({status:'error',error:`Poll error ${resp.status}`,agentUsed:'system'}); sendBtn.disabled=false; return; }
        const job = await resp.json();
        consecFail = 0;
        if (job.status === 'done' || job.status === 'error') {
          clearInterval(timer);
          removeThinking(thinkingId);
          // If the WS job_update already rendered this job, skip
          if (renderedJobs.has(job.jobId)) { sendBtn.disabled = false; return; }
          renderedJobs.add(job.jobId);
          // Defensive render — if any later formatter throws, the bubble still appears
          // instead of the UI looking frozen on "thinking".
          try {
            appendAgentMessage(job);
          } catch (renderErr) {
            console.error('appendAgentMessage threw:', renderErr);
            try {
              const msgs = document.getElementById('chat-messages');
              const div = document.createElement('div');
              div.className = 'message agent';
              div.innerHTML =
                '<div class="message-meta"><span class="agent-badge badge-error">RENDER ERROR</span></div>' +
                '<div class="message-bubble error-bubble"><strong style="color:#ff6080;">Client render error:</strong> ' +
                escHtml(String(renderErr && renderErr.message || renderErr)) + '<br><br>' +
                '<details><summary>Raw answer</summary><pre class="code-block">' +
                escHtml(job.answer || '') + '</pre></details></div>';
              msgs.appendChild(div);
              scrollToBottom(msgs);
            } catch (_) { /* last-resort: nothing we can do */ }
          }
          sendBtn.disabled = false;
          if (job.status === 'done' && (!job.hints || job.hints.length === 0)) pollForHints(jobId);
          // The losing lane usually lands after this response; pick it up so the
          // swap control appears once there is actually something to swap to.
          if (job.status === 'done' && job.lanesRacing) pollForLanes(jobId);
        }
        else if (attempts >= 90) { clearInterval(timer); removeThinking(thinkingId); appendAgentMessage({status:'error',error:'Timeout after 180s',agentUsed:'system'}); sendBtn.disabled = false; }
      } catch (err) {
        consecFail++;
        console.warn('poll failed (' + consecFail + '):', err);
        if (consecFail >= 5) {
          clearInterval(timer);
          removeThinking(thinkingId);
          appendAgentMessage({status:'error', error:'Lost contact with server — check DevTools → Network.', agentUsed:'system'});
          sendBtn.disabled = false;
        }
      }
    }, 2000);
    pollIntervals.set(jobId, timer);
  }

  /**
   * Poll for the second lane. When it lands, update the lane bar only — the
   * displayed answer is NOT swapped out from under the reader. Defaulting to the
   * fastest lane means the winner stays on screen; the swap is opt-in.
   */
  function pollForLanes(jobId) {
    let attempts = 0;
    const timer = setInterval(async () => {
      attempts++;
      if (attempts > 30) { clearInterval(timer); return; }
      try {
        const resp = await fetch(`/api/v1/chat/${jobId}`);
        if (!resp.ok) return;
        const job = await resp.json();
        const st = laneState.get(jobId);
        if (st) {
          // Preserve `active`: the user may have already swapped manually.
          if (job.lanes && job.lanes.length) st.lanes = job.lanes;
          st.racing = job.lanesRacing === true;
        } else if (job.lanes && job.lanes.length) {
          laneState.set(jobId, {
            lanes: job.lanes,
            active: job.lane || job.lanes[0].lane,
            agentKey: (job.agentUsed || 'direct').toLowerCase().replace(/\s+/g, '-'),
            racing: job.lanesRacing === true,
          });
        }
        refreshLaneBar(jobId);
        if (!job.lanesRacing) clearInterval(timer);
      } catch (_) {}
    }, 2000);
  }

  function pollForHints(jobId) {
    let hintAttempts = 0;
    const hintTimer = setInterval(async () => {
      hintAttempts++;
      if (hintAttempts > 10) { clearInterval(hintTimer); return; }
      try {
        const resp = await fetch(`/api/v1/chat/${jobId}`);
        if (!resp.ok) return;
        const job = await resp.json();
        if (job.hints && job.hints.length > 0) {
          clearInterval(hintTimer);
          const st = laneState.get(jobId);
          if (st) st.hintChipsHtml = job.hints.map(h => `<span class="hint-chip" data-hint="${escHtml(h)}">${escHtml(h)}</span>`).join('');
          // Re-render through the shared helper so the chips land alongside
          // this lane's own recommended-action bullets in the ONE Next Steps
          // section, rather than a second one appearing here.
          refreshHints(jobId);
        }
      } catch (_) {}
    }, 2000);
  }

  // Jobs we've already rendered; guards against a double render within pollJob.
  const renderedJobs = new Set();

  // ========== Lane race (cloud vs local) ==========
  // Per-job lane results + which one is currently displayed. Held client-side so
  // the swap is instant (no refetch) and so a late-arriving second lane can light
  // up the swap button without re-rendering the whole message.
  const laneState = new Map();

  /** Render one lane's answer/metrics/data — the swappable region.
   *  Confidence moves to the lane bar (top-right, left of the model label) —
   *  see renderLaneBar — so it isn't duplicated here. */
  function renderLaneBody(src, agentKey) {
    const answer = formatAnswer(src.answer || '');
    let metricsHtml = '';
    const m = src.data?.llm_metrics;
    if (m) {
      // MODEL is not here — it moved up to the message-meta line (next to the
      // timestamp/duration), alongside the data-source label that's now on
      // the lane-bar line. See appendAgentMessage / swapLane.
      const items = [
        m.latency_ms ? `<span class="metric-item">LATENCY <strong>${(m.latency_ms/1000).toFixed(1)}s</strong></span>` : '',
        m.tok_per_sec ? `<span class="metric-item">SPEED <strong>${m.tok_per_sec} tok/s</strong></span>` : '',
        m.completion_tokens ? `<span class="metric-item">OUTPUT <strong>${m.completion_tokens} tok</strong></span>` : '',
        m.thinking_tokens ? `<span class="metric-item">THINKING <strong>${m.thinking_tokens} tok</strong></span>` : '',
        m.prompt_tokens ? `<span class="metric-item">PROMPT <strong>${m.prompt_tokens} tok</strong></span>` : '',
      ].filter(Boolean).join('');
      metricsHtml = `<div class="metrics-row">${items}</div>`;
    }
    let dataHtml = '';
    let rawHtml = '';
    if (src.data && agentKey === 'thousandeyes-analyst') {
      // ThousandEyes' summary tiles are the answer's own visualization, not
      // raw query output — shown directly, never gated behind Evidence.
      dataHtml = renderThousandEyesData(src.data);
    } else if (src.data) {
      rawHtml = renderDataTabs(src.data);
    }
    // Raw (query rows / SQL) is not a top-level toggle: it only exists once
    // the analyst has expanded Evidence, since Raw IS the evidence, one level
    // deeper. If the answer has no Evidence section (RAW_PLACEHOLDER never
    // appears — error/fallback answers, or an agent whose prompt has no
    // Evidence header), Raw does not render at all rather than floating
    // loose at the bottom.
    const html = answer.html.includes(RAW_PLACEHOLDER)
      ? answer.html.replace(RAW_PLACEHOLDER, rawHtml)
      : answer.html;
    return { html: `${html}${metricsHtml}${dataHtml}`, nextStepItems: answer.nextStepItems };
  }

  /** The one Next Steps section for a message: recommended-action bullets
   *  (pulled out of the answer's own '## Next Steps', read-only — they
   *  describe things to do in OTHER tools, not queries this chat can run)
   *  followed by the follow-up-question buttons (clickable, arrive async via
   *  pollForHints). Two different kinds of item, one section, never two
   *  separate "Next Steps" headings on the same message. */
  function renderNextStepsSection(actionItems, hintChipsHtml) {
    if ((!actionItems || actionItems.length === 0) && !hintChipsHtml) return '';
    const actionsHtml = actionItems && actionItems.length
      ? `<ul class="next-step-actions">${actionItems.map(a => `<li>${formatInline(escHtml(a))}</li>`).join('')}</ul>`
      : '';
    return (
      `<div class="hints-label">Next Steps</div>` +
      actionsHtml +
      hintChipsHtml
    );
  }

  /** Confidence pill for the lane bar: color-coded, no label — the position
   *  (top-right of the bubble) is the label. */
  function renderConfidencePill(confidence) {
    if (typeof confidence !== 'number') return '';
    const pct = Math.round(confidence * 100);
    const cls = pct >= 70 ? 'conf-high' : pct >= 40 ? 'conf-medium' : 'conf-low';
    return `<span class="confidence-pill ${cls}" title="Confidence">${pct}%</span>`;
  }

  /**
   * "Raw" collapsed section for one lane's data blob. Default-collapsed so a
   * bubble isn't dominated by machinery the analyst didn't ask for — expanding
   * it shows the actual rows Athena returned (data.query_details[].sample_rows),
   * not the summary JSON and not the SQL. Each query that ran gets its own
   * nested "View SQL" toggle showing the statement that produced its rows;
   * that toggle is what the old always-visible SQL/Raw-Data tabs collapsed
   * into — it's what the query DID, not the results, so it belongs one level
   * in from the results themselves. Falls back to the summary JSON (word-
   * wrapped, not the old overflow-x:auto box) for agent shapes with no rows
   * to show (alert-triage/thousandeyes).
   */
  function renderDataTabs(data) {
    const queries = Array.isArray(data.query_details) ? data.query_details : [];
    const hasSampleRows = queries.some(q => Array.isArray(q.sample_rows) && q.sample_rows.length > 0);

    let bodyHtml;
    if (hasSampleRows) {
      bodyHtml = queries.map((q, i) => {
        const rowsHtml = Array.isArray(q.sample_rows) && q.sample_rows.length
          ? renderData(q.sample_rows)
          : '<p class="query-item-empty">No rows returned</p>';
        const sqlId = `sql-${Math.random().toString(36).slice(2, 9)}`;
        return `
          <div class="query-item">
            ${queries.length > 1 ? `<div class="query-item-index">Query ${i + 1}</div>` : ''}
            ${rowsHtml}
            <div class="query-item-stats">
              ${q.row_count != null ? `<span>${q.row_count} rows</span>` : ''}
              ${q.time_ms != null ? `<span>${q.time_ms}ms</span>` : ''}
              ${q.scanned_mb != null ? `<span>${q.scanned_mb}MB scanned</span>` : ''}
            </div>
            <details class="sql-collapse" id="${sqlId}">
              <summary>View SQL</summary>
              <pre class="code-block">${escHtml(q.sql || '')}</pre>
            </details>
          </div>`;
      }).join('');
    } else {
      // Strip every field that can carry internal/SQL/scope-machinery rather
      // than a result an analyst asked for: errors[] carries raw SQL text
      // (table/column names, WHERE-clause shapes) AND, for a scope-rejected
      // query, the literal [OUT-OF-SCOPE-IP] placeholder baked into the WHERE
      // clause; iocs_searched echoes that same placeholder on its own. None of
      // this is a "result" — it's why there ISN'T one — so with no sample rows
      // to show, this fallback used to JSON.stringify the whole remaining
      // object and put all of it, including the placeholder, verbatim in the
      // DOM. This panel exists to show query OUTPUT; when a query produced
      // none, show nothing rather than the internals of why it didn't.
      const rawDataHtml = renderData({
        ...data,
        llm_metrics: undefined,
        query_details: undefined,
        errors: undefined,
        iocs_searched: undefined,
      });
      if (!rawDataHtml) return '';
      bodyHtml = rawDataHtml;
    }

    return `<details class="raw-collapse"><summary>Raw</summary>${bodyHtml}</details>`;
  }

  /**
   * The swap control: which lane is showing, how fast it was, and the toggle.
   *
   * Reads everything from laneState — including `racing` — so it renders the same
   * way whether it is called with a fresh job in hand (first render, poll tick) or
   * from a swap, which has no job. Taking `lanesRacing` as an argument meant the
   * pending state silently depended on the caller having one.
   */
  /** "Cloud (Gemini)" / "Local (AQLight)" / "Local (AQLight + Foundation-Sec)"
   *  → just the model name(s) — "Gemini" / "AQLight" / "AQLight + Foundation-Sec".
   *  Strips the Cloud/Local wrapper client-side rather than hardcoding the
   *  short names, since the local label is config-derived (lane_label() in
   *  the orchestrator) and can legitimately vary. */
  function shortModelName(label) {
    const m = /^(?:Cloud|Local)\s*\((.+)\)$/.exec(label || '');
    return m ? m[1] : (label || '');
  }

  function renderLaneBar(laneKey) {
    const st = laneState.get(laneKey);
    if (!st) return '';
    const confHtml = renderConfidencePill(st.confidence);
    const sourceHtml = st.dataSourceLabel
      ? `<span class="data-source-label">${escHtml(st.dataSourceLabel)}</span>` : '';
    // Right-hand cluster: data source, confidence, then (if there's a real
    // swap target) the icon-only button as the absolute right-most element.
    // Wrapped once so margin-left:auto lives here, not on individual pieces.
    const rightCluster = (swapHtml) => {
      const inner = sourceHtml + confHtml + swapHtml;
      return inner ? `<span class="lane-bar-right">${inner}</span>` : '';
    };
    if (st.lanes.length < 2) {
      if (!st.racing) return rightCluster('');
      // One lane in, the other still running: show the pending state so the user
      // knows a second opinion is coming rather than wondering if it broke.
      const only = st.lanes.length === 1 ? st.lanes[0] : null;
      return `<span class="lane-current">${escHtml(only ? shortModelName(only.label) : 'Fastest model')}</span>` +
             `<span class="lane-pending">second model still working…</span>` +
             rightCluster('');
    }
    const active = st.lanes.find(l => l.lane === st.active) || st.lanes[0];
    const other = st.lanes.find(l => l.lane !== active.lane);
    const winner = st.lanes.find(l => l.winner);
    const secs = (ms) => `${(ms / 1000).toFixed(1)}s`;
    const isWinner = active.winner === true;
    const swapHtml =
      `<button class="lane-swap" type="button" data-lane-key="${escHtml(laneKey)}" ` +
      `title="Show the answer from ${escHtml(shortModelName(other.label))}" ` +
      `aria-label="Show the answer from ${escHtml(shortModelName(other.label))}">` +
      `<span class="lane-swap-icon" aria-hidden="true">⇄</span></button>`;
    return (
      // Left: model + timing only. No FASTEST badge — the winner is simply
      // whichever lane is showing first, which already says "fastest".
      `<span class="lane-current">${escHtml(shortModelName(active.label))}</span>` +
      `<span class="lane-timing">${secs(active.elapsedMs)}` +
      (winner && !isWinner ? ` <span class="lane-delta">+${secs(active.elapsedMs - winner.elapsedMs)}</span>` : '') +
      `</span>` +
      rightCluster(swapHtml)
    );
  }

  /** Swap the displayed lane in place. The hint-CHIP buttons are shared
   *  across lanes (one hints-generation call keyed on the job, not the
   *  lane), but the recommended-action bullets come from THIS lane's own
   *  answer, so they have to be re-rendered on every swap too. */
  function swapLane(laneKey) {
    const st = laneState.get(laneKey);
    if (!st || st.lanes.length < 2) return;
    const idx = st.lanes.findIndex(l => l.lane === st.active);
    const next = st.lanes[(idx + 1) % st.lanes.length];
    st.active = next.lane;
    st.confidence = next.confidence;
    const body = document.getElementById(`lanebody-${laneKey}`);
    if (body) {
      const rendered = renderLaneBody(
        { answer: next.answer, confidence: next.confidence, data: next.data },
        st.agentKey,
      );
      body.innerHTML = rendered.html;
      st.actionItems = rendered.nextStepItems;
    }
    // The model name on the message-meta line is per-lane too.
    const modelMeta = document.getElementById(`modelmeta-${laneKey}`);
    if (modelMeta) {
      const nextModel = next.data?.llm_metrics?.model;
      if (nextModel) modelMeta.textContent = `// ${nextModel}`;
    }
    refreshLaneBar(laneKey);
    refreshHints(laneKey);
  }

  /** Re-render the Next Steps section from current laneState — used after a
   *  swap (action items change) and after pollForHints writes new chips in. */
  function refreshHints(laneKey) {
    const st = laneState.get(laneKey);
    const el = document.getElementById(`hints-${laneKey}`);
    if (!st || !el) return;
    el.innerHTML = renderNextStepsSection(st.actionItems, st.hintChipsHtml || '');
    el.querySelectorAll('.hint-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const q = chip.getAttribute('data-hint');
        if (q) submitQueryText(q);
      });
    });
  }

  /** Re-render just the lane bar (after a swap, or when the second lane lands). */
  function refreshLaneBar(laneKey) {
    const bar = document.getElementById(`lanebar-${laneKey}`);
    if (bar) bar.innerHTML = renderLaneBar(laneKey);
  }

  // Delegated: lane bars are re-rendered via innerHTML, so a bound listener on
  // the button would be discarded on every swap.
  document.addEventListener('click', (ev) => {
    const btn = ev.target.closest && ev.target.closest('.lane-swap');
    if (!btn) return;
    swapLane(btn.getAttribute('data-lane-key'));
  });

  // ========== Message rendering ==========
  function appendMessage(role, text) {
    const msgs = document.getElementById('chat-messages');
    const div = document.createElement('div');
    div.className = `message ${role}`;
    div.innerHTML = `
      <div class="message-meta">${role === 'user' ? '> YOU' : 'SYSTEM'} // ${timeNow()}</div>
      <div class="message-bubble">${escHtml(text)}</div>
    `;
    msgs.appendChild(div);
    scrollToBottom(msgs);
  }

  function appendThinking(id) {
    const msgs = document.getElementById('chat-messages');
    const div = document.createElement('div');
    div.className = 'message agent';
    div.id = id;
    div.innerHTML = `
      <div class="message-meta">AGENT // ${timeNow()}</div>
      <div class="thinking-bubble">
        <div class="thinking-dots"><span></span><span></span><span></span></div>
        Processing query...
      </div>
    `;
    msgs.appendChild(div);
    scrollToBottom(msgs);
  }

  function removeThinking(id) { const el = document.getElementById(id); if (el) el.remove(); }

  function appendAgentMessage(job) {
    const msgs = document.getElementById('chat-messages');
    const div = document.createElement('div');
    div.className = 'message agent';

    const agentKey = (job.agentUsed || 'direct').toLowerCase().replace(/\s+/g, '-');
    const agentLabel = { orchestrator:'ORCHESTRATOR', 'alert-triage':'ALERT TRIAGE', 'thousandeyes-analyst':'NET MONITOR', 'athena-hunter':'ATHENA SQL', direct:'DIRECT', 'direct-fallback':'DIRECT', system:'SYSTEM' }[agentKey] || (job.agentUsed||'AGENT').toUpperCase();
    const badgeClass = { orchestrator:'badge-orchestrator', 'alert-triage':'badge-alert-triage', 'thousandeyes-analyst':'badge-thousandeyes-analyst', 'athena-hunter':'badge-athena-hunter', direct:'badge-direct', 'direct-fallback':'badge-direct', system:'badge-error' }[agentKey] || 'badge-direct';
    // The badge names the AGENT ("Alert Triage"); this names the underlying
    // DATA the agent queried to answer — alert-triage and athena-hunter both
    // read Corelight-derived Athena logs, thousandeyes-analyst reads the live
    // ThousandEyes API directly. Distinct labels because "ALERT TRIAGE" alone
    // doesn't say whose data backs the answer.
    const dataSourceLabel = { 'alert-triage':'Corelight', 'athena-hunter':'Corelight', 'thousandeyes-analyst':'ThousandEyes' }[agentKey] || '';

    let bubbleContent = '';
    let modelMetaId = '';
    let modelName = job.data?.llm_metrics?.model || '';
    if (job.status === 'error') {
      bubbleContent = `<div class="message-bubble error-bubble"><strong style="color:#ff6080;">ERROR:</strong> ${escHtml(job.error||'Unknown error')}</div>`;
    } else {
      const laneKey = job.jobId || `anon-${Date.now()}`;
      modelMetaId = laneKey;
      // Track lanes client-side so a swap can re-render from memory with no refetch.
      // Stored even for a single-lane response so the confidence pill (lane bar,
      // top-right) has something to read without a lanes array.
      laneState.set(laneKey, {
        lanes: job.lanes && job.lanes.length ? job.lanes : [],
        active: job.lane || (job.lanes && job.lanes[0] && job.lanes[0].lane),
        agentKey,
        racing: job.lanesRacing === true,
        confidence: job.confidence,
        dataSourceLabel,
      });
      const st = laneState.get(laneKey);
      const body = renderLaneBody({
        answer: job.answer, confidence: job.confidence, data: job.data,
      }, agentKey);
      st.actionItems = body.nextStepItems;
      const hintsId = `hints-${laneKey}`;
      // Hint-chip buttons arrive asynchronously (pollForHints); the action
      // bullets are already in hand from the answer. store the chips HTML on
      // laneState so a later swap can re-render the FULL Next Steps section
      // (this lane's actions + the shared chips) rather than losing one half.
      st.hintChipsHtml = (job.hints && job.hints.length > 0)
        ? job.hints.map(h => `<span class="hint-chip" data-hint="${escHtml(h)}">${escHtml(h)}</span>`).join('')
        : '';
      // The Next Steps section sits OUTSIDE the swappable body on purpose:
      // hint chips arrive asynchronously and are written into #hints-<id> by
      // pollForHints. If it lived inside the lane body, swapping lanes after
      // the chips landed would wipe them (and a swap before they land would
      // be overwritten by them).
      const hintsHtml = `<div class="hints-row" id="${hintsId}">` +
        renderNextStepsSection(st.actionItems, st.hintChipsHtml) + `</div>`;
      bubbleContent =
        `<div class="message-bubble">` +
        `<div class="lane-bar" id="lanebar-${laneKey}">${renderLaneBar(laneKey)}</div>` +
        `<div class="lane-body" id="lanebody-${laneKey}">${body.html}</div>` +
        `${hintsHtml}</div>`;
    }

    div.innerHTML = `
      <div class="message-meta">
        <span class="agent-badge ${badgeClass}">${agentLabel}</span>
        ${timeNow()}
        ${job.completedAt ? '// ' + elapsed(job.createdAt, job.completedAt) : ''}
        ${modelName ? `<span class="model-meta" id="modelmeta-${modelMetaId}">// ${escHtml(modelName)}</span>` : ''}
      </div>
      ${bubbleContent}
    `;
    msgs.appendChild(div);
    // Wire up hint chip clicks — routed through submitQueryText() so these
    // respect the same in-flight send lock as the welcome chips and the alert
    // popup's "Hunt From Here" chips (see submitQueryText's docstring). Calling
    // sendQuery() directly here let a burst of rapid hint-chip clicks (from this
    // render AND from refreshHints()) each fire an unthrottled POST before the
    // first one's disabled state ever reached the chip itself, since only the
    // send button — not the chips — reflected "in flight".
    div.querySelectorAll('.hint-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const query = chip.getAttribute('data-hint');
        if (query) submitQueryText(query);
      });
    });
    scrollToBottom(msgs);
  }

  // Headings that render as collapsible sections. Next-Steps-shaped headings
  // are NOT here — NEXT_STEPS_HEADINGS intercepts those earlier and moves
  // them into the one unified Next Steps section at the bottom of the
  // message (see renderSections / renderNextStepsSection).
  const COLLAPSIBLE_HEADINGS = new Set(['key entities', 'evidence']);

  // Substituted with the Raw section's HTML (query rows / SQL) inside
  // Evidence — see renderSections and renderLaneBody. If the answer has no
  // Evidence section, this token never appears and Raw does not render at
  // all, by design.
  const RAW_PLACEHOLDER = ' RAW_SECTION ';

  function formatInline(s) {
    s = s.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/(?<!\*)\*([^*]+)\*(?!\*)/g, '<em>$1</em>');
    s = s.replace(/`([^`]+)`/g, '<code class="inline-code">$1</code>');
    s = s.replace(/^[\s]*[-*]\s+(.+)$/gm, '<div class="md-li">• $1</div>');
    s = s.replace(/^[\s]*(\d+)\.\s+(.+)$/gm, '<div class="md-li"><span class="md-num">$1.</span> $2</div>');
    s = s.replace(/\n/g, '<br>');
    s = s.replace(/(<\/div>)<br>/g, '$1');
    s = s.replace(/(<\/pre>)<br>/g, '$1');
    // IOC highlights
    s = s.replace(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/g, '<span class="highlight-ip">$1</span>');
    s = s.replace(/\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b/g, (m, d) => /^\d/.test(d) ? m : `<span class="highlight-domain">${d}</span>`);
    s = s.replace(/(?:TCP|UDP|port)\/?(\d{2,5})/gi, (m, p) => m.replace(p, `<span class="highlight-port">${p}</span>`));
    s = s.replace(/\b([0-9a-fA-F]{32,64})\b/g, '<span class="highlight-hash">$1</span>');
    return s;
  }

  // Headings whose body is a "Next Steps"-shaped list of recommended actions
  // (see agents/*/main.py prompts: "Numbered imperatives" / "Recommended
  // Actions"). Pulled OUT of the normal section flow and merged into the one
  // Next Steps block at the bottom of the message (see appendAgentMessage),
  // alongside the follow-up-question buttons — the two used to render as two
  // separate "Next Steps" on the same message: this text (read-only bullets,
  // things to do in OTHER tools, e.g. "Block 1.2.3.4") and a button row below
  // (clickable follow-up QUESTIONS for this chatbot). They are not
  // interchangeable — an action bullet can't be "asked" as a query — so they
  // sit in the same section as two different kinds of item, not merged into
  // one list.
  const NEXT_STEPS_HEADINGS = new Set(['next steps', 'recommended next steps', 'recommended actions']);

  /** Pull list items (markdown `- x` / `1. x` bullets, or bare lines) out of
   *  a Next-Steps-shaped section body into plain, unformatted strings. */
  function extractListItems(rawBody) {
    return rawBody
      .split('\n')
      .map(line => line.replace(/^[\s]*(?:[-*]|\d+\.)\s*/, '').trim())
      .filter(Boolean);
  }

  function renderSections(text) {
    // Split on ## headings so we can wrap select sections in <details>
    const sections = [];
    const re = /^##\s+(.+?)\s*$/gm;
    let lastEnd = 0;
    let lastHeading = null;
    let m;
    while ((m = re.exec(text)) !== null) {
      sections.push({ heading: lastHeading, body: text.slice(lastEnd, m.index) });
      lastHeading = m[1];
      lastEnd = m.index + m[0].length;
    }
    sections.push({ heading: lastHeading, body: text.slice(lastEnd) });

    let out = '';
    const nextStepItems = [];
    for (const sec of sections) {
      if (sec.heading && NEXT_STEPS_HEADINGS.has(sec.heading.toLowerCase().trim())) {
        nextStepItems.push(...extractListItems(sec.body));
        continue;
      }
      const body = formatInline(escHtml(sec.body.replace(/^\n+|\n+$/g, '')));
      if (!sec.heading) {
        if (body.trim()) out += body;
        continue;
      }
      const collapsible = COLLAPSIBLE_HEADINGS.has(sec.heading.toLowerCase().trim());
      const safeHeading = escHtml(sec.heading);
      if (collapsible) {
        // Evidence gets a placeholder for the Raw section (query rows/SQL),
        // filled in by renderLaneBody once src.data is in hand. Raw is not
        // its own top-level toggle: it only exists once the analyst has
        // already expanded Evidence, since Raw IS the evidence, one level
        // deeper (the query results the bullets above were built from).
        const isEvidence = sec.heading.toLowerCase().trim() === 'evidence';
        out += `<details class="answer-section"><summary class="md-header md-collapsible">${safeHeading}</summary>${body}` +
          (isEvidence ? RAW_PLACEHOLDER : '') + `</details>`;
      } else {
        out += `<strong class="md-header">${safeHeading}</strong>${body}`;
      }
    }
    return { html: out, nextStepItems };
  }

  function formatAnswer(text) {
    if (!text) return { html: '', nextStepItems: [] };
    const parts = text.split(/(```[\s\S]*?```)/g);
    let html = '';
    const nextStepItems = [];
    for (const part of parts) {
      if (part.startsWith('```')) {
        const inner = part.replace(/^```\w*\n?/, '').replace(/\n?```$/, '');
        html += `<pre class="code-block">${escHtml(inner)}</pre>`;
      } else {
        const sec = renderSections(part);
        html += sec.html;
        nextStepItems.push(...sec.nextStepItems);
      }
    }
    return { html, nextStepItems };
  }

  function renderThousandEyesData(data) {
    const alertCount = data.active_alert_count ?? 0;
    const testCount  = data.test_count ?? 0;
    const hasBgp     = !!data.has_bgp_data;
    const hasResults = !!data.has_test_results;
    const alertColor = alertCount > 0 ? 'color:var(--accent-red);text-shadow:0 0 10px rgba(255,48,80,0.4)' : '';
    return `
      <div class="te-summary">
        <div class="te-stat"><div class="te-stat-value" style="${alertColor}">${alertCount}</div><div class="te-stat-label">Active Alerts</div></div>
        <div class="te-stat"><div class="te-stat-value">${testCount}</div><div class="te-stat-label">Tests Checked</div></div>
        <div class="te-stat">
          <div style="display:flex;flex-direction:column;gap:4px;align-items:center;margin-top:4px;">
            <span class="te-flag ${hasBgp?'':'inactive'}">${hasBgp?'✓':'–'} BGP Data</span>
            <span class="te-flag ${hasResults?'':'inactive'}">${hasResults?'✓':'–'} Perf Results</span>
          </div>
        </div>
      </div>`;
  }

  function renderData(data) {
    if (Array.isArray(data) && data.length > 0 && typeof data[0] === 'object') {
      const keys = Object.keys(data[0]).slice(0, 6);
      let html = '<div class="data-table-wrap"><table class="data-table"><thead><tr>';
      keys.forEach(k => { html += `<th>${escHtml(k)}</th>`; });
      html += '</tr></thead><tbody>';
      data.slice(0, 20).forEach(row => {
        html += '<tr>';
        keys.forEach(k => { const v = row[k] !== undefined ? String(row[k]) : ''; html += `<td>${escHtml(v.slice(0,80))}</td>`; });
        html += '</tr>';
      });
      return html + '</tbody></table></div>';
    }
    if (typeof data === 'object') return `<pre class="code-block">${escHtml(JSON.stringify(data, null, 2))}</pre>`;
    return '';
  }

  // ========== Utilities ==========
  function escHtml(str) { return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
  function timeNow() { return new Date().toLocaleTimeString('en-US', { hour:'2-digit', minute:'2-digit', second:'2-digit' }); }
  function elapsed(start, end) { const ms = new Date(end) - new Date(start); return ms < 1000 ? `${ms}ms` : `${(ms/1000).toFixed(1)}s`; }
  function scrollToBottom(el) { el.scrollTop = el.scrollHeight; }

  // Replace the static welcome chips with the server's per-load draw. The
  // markup keeps a hand-written set as the fallback, so a failed/empty fetch
  // leaves the banner alone rather than blanking it.
  function renderStarterHints(hints) {
    if (!Array.isArray(hints) || hints.length === 0) return;
    const container = document.getElementById('example-queries');
    if (!container) return;
    container.innerHTML = '';
    hints.forEach(hint => {
      const text = String(hint).slice(0, 200);
      const btn = document.createElement('button');
      btn.className = 'example-chip';
      btn.textContent = text;   // textContent, not innerHTML: never parse server text as markup
      btn.addEventListener('click', () => fillQuery(btn));
      container.appendChild(btn);
    });
  }

  // Pull public UI config (event-edition label composed server-side, starter
  // hint draw) so re-branding is a single env change. Falls back to static markup.
  async function loadConfig() {
    try {
      const resp = await fetch('/api/v1/config', { signal: AbortSignal.timeout(3000) });
      if (!resp.ok) return;
      const { eventLabel, starterHints } = await resp.json();
      renderStarterHints(starterHints);
      if (!eventLabel) return;
      const banner = document.getElementById('event-label');
      if (banner) banner.textContent = eventLabel;
      // The banner label is inside #welcome-banner, which sendQuery() removes on
      // the first query. Without this the header is the only branding left after
      // one question, and it was hardcoded to a bare year.
      const header = document.getElementById('event-label-header');
      if (header) header.textContent = eventLabel.replace(/^Black Hat\s+/, '');
    } catch (_) { /* keep static fallback */ }
  }

  async function checkApiHealth() {
    try {
      const resp = await fetch('/health', { signal: AbortSignal.timeout(3000) });
      const dot = document.getElementById('api-dot');
      const lbl = document.getElementById('api-label');
      if (resp.ok) { dot.className = 'status-dot online'; lbl.textContent = 'API ONLINE'; }
      else { dot.className = 'status-dot offline'; lbl.textContent = 'API ERROR'; }
    } catch (_) { document.getElementById('api-dot').className = 'status-dot offline'; document.getElementById('api-label').textContent = 'API DOWN'; }
  }

  // ========== View switching (chat | threat hunt) ==========
  let currentView = 'chat';
  let activeHuntId = null;
  let activeAppId = null;

  function huntApps() {
    return window.THREAT_HUNT_APPS || [];
  }

  function renderHuntPicker() {
    const host = document.getElementById('hunt-view');
    const hunts = window.THREAT_HUNTS || [];
    const apps = huntApps();
    if (!host) return;
    activeHuntId = null;
    activeAppId = null;

    // Legacy: only one MUD hunt and no external apps → mount directly.
    if (hunts.length === 1 && apps.length === 0 && window.ThreatHunt) {
      activeHuntId = hunts[0].id;
      ThreatHunt.mount(host, hunts[0], handleHuntOutcome);
      return;
    }

    const mudCount = hunts.length;
    const appCount = apps.length;
    host.innerHTML =
      '<div class="hunt-briefing hunt-briefing-wide">' +
        '<div class="hunt-panel hunt-briefing-card hunt-picker-card">' +
          '<div class="hunt-panel-head hunt-picker-head">' +
            '<span class="hunt-picker-head-title"><span>Threat Hunt</span></span>' +
            '<span class="hunt-meta">' + mudCount + ' MUD' + (mudCount === 1 ? '' : 's') +
              (appCount ? ' · ' + appCount + ' app' + (appCount === 1 ? '' : 's') : '') +
            '</span>' +
          '</div>' +
          '<div class="hunt-panel-body">' +
            '<div class="hunt-briefing-title">Select a hunt</div>' +
            '<p class="hunt-briefing-text">Click-only MUD drills end in one BH close code.</p>' +
            '<div class="hunt-picker-section-label">MUD scenarios</div>' +
            '<div class="hunt-picker-list" id="hunt-picker-list"></div>' +
            (appCount ? '<div class="hunt-separator"></div>' : '') +
            (appCount ? '<div class="hunt-picker-section-label">Apps</div>' : '') +
            (appCount ? '<div class="hunt-picker-list" id="hunt-app-list"></div>' : '') +
          '</div>' +
        '</div>' +
      '</div>';

    const list = host.querySelector('#hunt-picker-list');
    if (list && window.ThreatHunt) {
      hunts.forEach((hunt) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'hunt-btn hunt-picker-item';
        btn.innerHTML =
          '<span class="hunt-picker-title"></span>' +
          '<span class="hunt-hint hunt-picker-meta"></span>';
        btn.querySelector('.hunt-picker-title').textContent = hunt.meta.title;
        btn.querySelector('.hunt-picker-meta').textContent =
          'target ' + Math.floor(hunt.meta.targetSeconds / 60) + ':' +
          String(hunt.meta.targetSeconds % 60).padStart(2, '0') + ' · ' + hunt.id;
        btn.addEventListener('click', () => mountHunt(hunt.id));
        list.appendChild(btn);
      });
    }

    const appList = host.querySelector('#hunt-app-list');
    if (appList) {
      apps.forEach((app) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'hunt-btn hunt-picker-item';
        btn.innerHTML =
          '<span class="hunt-picker-title"></span>' +
          '<span class="hunt-hint hunt-picker-meta"></span>';
        btn.querySelector('.hunt-picker-title').textContent = app.title;
        btn.querySelector('.hunt-picker-meta').textContent = app.subtitle || '';
        btn.addEventListener('click', () => mountHuntApp(app.id));
        appList.appendChild(btn);
      });
    }
  }

  function leaveToHuntPicker() {
    activeHuntId = null;
    activeAppId = null;
    renderHuntPicker();
  }

  // Kiosk-safe: mounted as an iframe inside our own SPA rather than a new tab
  // or top-level navigation, so the hardware/OS back button on a kiosk browser
  // lands back on the picker instead of leaving the app entirely.
  function mountHuntApp(appId) {
    const host = document.getElementById('hunt-view');
    const apps = huntApps();
    const app = apps.find((a) => a.id === appId) || apps[0];
    if (!host || !app) return;
    activeHuntId = null;
    activeAppId = app.id;

    host.innerHTML = '';
    const wrap = document.createElement('div');
    wrap.className = 'hunt-app-frame-wrap';

    const head = document.createElement('div');
    head.className = 'hunt-panel-head hunt-app-frame-head';
    const titleSpan = document.createElement('span');
    titleSpan.textContent = app.title;
    const backBtn = document.createElement('button');
    backBtn.type = 'button';
    backBtn.className = 'hunt-leave hunt-leave-head';
    backBtn.textContent = '← All hunts';
    backBtn.addEventListener('click', leaveToHuntPicker);
    head.appendChild(titleSpan);
    head.appendChild(backBtn);

    const frame = document.createElement('iframe');
    frame.className = 'hunt-app-frame';
    frame.src = String(app.url || '');
    frame.title = app.title || 'Threat hunt app';

    wrap.appendChild(head);
    wrap.appendChild(frame);
    host.appendChild(wrap);
  }

  function mountHunt(huntId) {
    const host = document.getElementById('hunt-view');
    const hunts = window.THREAT_HUNTS || [];
    const hunt = hunts.find((h) => h.id === huntId) || hunts[0];
    if (!host || !hunt || !window.ThreatHunt) return;
    activeHuntId = hunt.id;
    activeAppId = null;
    // Picker return is available on briefing, during play, and on the end dialog.
    const canLeave = hunts.length + huntApps().length >= 2;
    ThreatHunt.mount(host, hunt, handleHuntOutcome, {
      onLeave: canLeave ? leaveToHuntPicker : null,
    });
  }

  function setView(view) {
    if (view === currentView) return;
    currentView = view;
    const huntActive = view === 'hunt';
    document.querySelector('main').hidden = huntActive;
    document.querySelector('.sidebar').hidden = huntActive;
    document.getElementById('hunt-view').hidden = !huntActive;
    document.getElementById('tab-chat').classList.toggle('active', !huntActive);
    document.getElementById('tab-hunt').classList.toggle('active', huntActive);

    if (huntActive) {
      if (activeHuntId) mountHunt(activeHuntId);
      else if (activeAppId) mountHuntApp(activeAppId);
      else renderHuntPicker();
    }

    // Deep link: #threat-hunt opens the hunt directly. Use replaceState so
    // tab flips don't pollute browser history.
    const hash = huntActive ? '#threat-hunt' : '';
    history.replaceState(null, '', location.pathname + location.search + hash);
  }

  function handleHuntOutcome(kind, subject) {
    const win = kind === 'hunt-win';
    showToast(win ? 'ok' : 'critical',
      (win ? 'Hunt resolved — ' : 'Wrong call — ') + subject.src + ' // ' + subject.time + ' elapsed');
  }

  function applyHashView() {
    setView(location.hash === '#threat-hunt' ? 'hunt' : 'chat');
  }

  window.addEventListener('hashchange', applyHashView);

  /**
   * Clicking the logo: end the current investigation and start a fresh one.
   * Not just a view switch (setView('chat') alone leaves every rendered
   * message and its lane/poll state in place) — the analyst asked for this
   * specifically to get OUT of an investigation, so the transcript, the
   * per-job hint pollers, and the lane-swap state all have to go with it.
   */
  function resetToHome() {
    for (const timer of pollIntervals.values()) clearInterval(timer);
    pollIntervals.clear();
    laneState.clear();
    renderedJobs.clear();
    queryCount = 0;
    const statQueries = document.getElementById('stat-queries');
    if (statQueries) statQueries.textContent = '0';

    const msgs = document.getElementById('chat-messages');
    if (msgs) {
      msgs.innerHTML = `
        <div class="welcome" id="welcome-banner">
          <img src="/assets/bhnoc-logo.png" alt="Black Hat" style="height:48px; margin-bottom:8px; filter: brightness(1.2);" />
          <h2>BlackHat NOCGentic Operations</h2>
          <div class="tagline">AI-Powered Network Operations Center // <span id="event-label">Black Hat</span></div>
          <p>
            Query live network threats, investigate IOCs, triage firewall alerts,
            or ask about suspicious activity. AI agents analyze NOC telemetry in real time.
          </p>
          <div class="example-queries" id="example-queries">
            <button class="example-chip" onclick="fillQuery(this)">What is the biggest risk so far?</button>
            <button class="example-chip" onclick="fillQuery(this)">Are there any attacks happening right now?</button>
            <button class="example-chip" onclick="fillQuery(this)">What is the most interesting attack so far?</button>
            <button class="example-chip" onclick="fillQuery(this)">How is the network quality right now?</button>
            <button class="example-chip" onclick="fillQuery(this)">Is there any latency reported to AWS?</button>
          </div>
        </div>`;
    }
    // Re-fetch rather than re-use the fallback markup above: loadConfig() draws
    // a fresh starter-hint set from the server and re-applies the event label,
    // matching what a real page load does.
    loadConfig();
    setView('chat');
  }

  // ========== Toasts ==========
  function showToast(tone, text) {
    const stack = document.getElementById('toast-stack');
    if (!stack) return;
    const toast = document.createElement('div');
    toast.className = 'toast toast-' + tone;
    toast.textContent = text;
    stack.appendChild(toast);
    setTimeout(() => toast.classList.add('toast-out'), 4500);
    setTimeout(() => toast.remove(), 5000);
    while (stack.children.length > 4) stack.removeChild(stack.firstChild);
  }

  // ========== Boot ==========
  connectWS();
  loadConfig();
  applyHashView();
  loadInitialAlerts();
  applyMobileAlertMode();
  // Real alerts now trickle from the Athena-backed cache via WebSocket.
  // Demo ticker is kept as a fallback only if the server feed is silent.
  setTimeout(() => {
    const feed = document.getElementById('alerts-feed');
    if (feed && feed.querySelector('.empty-feed')) startDemoAlertTicker();
  }, 20000);
  checkApiHealth();
  setInterval(checkApiHealth, 30000);

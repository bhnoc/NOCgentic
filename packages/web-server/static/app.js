// ========== State ==========
  let ws = null;
  let wsReconnectTimer = null;
  let queryCount = 0;
  let totalAlerts = 0;
  let criticalAlerts = 0;
  const pollIntervals = new Map();

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
        <div class="alert-desc">${escHtml(a.description)}</div>
        <div class="alert-src">${escHtml(a.source||'')}${a.srcIp?' // '+escHtml(a.srcIp):''}</div>
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
    const ts = new Date(a.timestamp);
    const when = isNaN(ts.getTime())
      ? String(a.timestamp || 'unknown')
      : ts.toLocaleString('en-US', { month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit' });
    let observedStr = '';
    if (a.observedAt) {
      const obs = new Date(a.observedAt);
      observedStr = Number.isNaN(obs.getTime())
        ? String(a.observedAt)
        : obs.toLocaleString('en-US', { month:'short', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit' });
    }

    const rows = [
      ['Source',      a.source],
      ['Src IP',      a.srcIp],
      ['Src Port',    a.srcPort === 0 || a.srcPort ? String(a.srcPort) : ''],
      ['Dst IP',      a.dstIp],
      ['Dst Port',    a.dstPort === 0 || a.dstPort ? String(a.dstPort) : ''],
      ['Network',     a.network],
      ['Action',      a.action],
      ['Detected',    when],
      ['Observed',    observedStr],
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
      <div class="alert-detail-desc">${escHtml(a.description || '')}</div>
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
          const container = document.getElementById(`hints-${jobId}`);
          if (container) {
            container.innerHTML = `<span class="hints-label">Next Steps</span>${job.hints.map(h => `<span class="hint-chip" data-hint="${escHtml(h)}">${escHtml(h)}</span>`).join('')}`;
            container.querySelectorAll('.hint-chip').forEach(chip => {
              chip.addEventListener('click', () => {
                const q = chip.getAttribute('data-hint');
                if (q) { document.getElementById('query-input').value = q; document.getElementById('query-input').focus(); sendQuery(); }
              });
            });
          }
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

  /** Render one lane's answer/confidence/metrics/data — the swappable region. */
  function renderLaneBody(src, agentKey) {
    const answerHtml = formatAnswer(src.answer || '');
    let confHtml = '';
    if (typeof src.confidence === 'number') {
      const pct = Math.round(src.confidence * 100);
      const fillClass = pct >= 70 ? 'conf-high' : pct >= 40 ? 'conf-medium' : 'conf-low';
      confHtml = `<div class="confidence-row"><span class="confidence-label">Confidence</span><div class="confidence-bar"><div class="confidence-fill ${fillClass}" style="width:${pct}%"></div></div><span class="confidence-pct">${pct}%</span></div>`;
    }
    let metricsHtml = '';
    const m = src.data?.llm_metrics;
    if (m) {
      const items = [
        m.model ? `<span class="metric-item">MODEL <strong>${escHtml(m.model)}</strong></span>` : '',
        m.latency_ms ? `<span class="metric-item">LATENCY <strong>${(m.latency_ms/1000).toFixed(1)}s</strong></span>` : '',
        m.tok_per_sec ? `<span class="metric-item">SPEED <strong>${m.tok_per_sec} tok/s</strong></span>` : '',
        m.completion_tokens ? `<span class="metric-item">OUTPUT <strong>${m.completion_tokens} tok</strong></span>` : '',
        m.thinking_tokens ? `<span class="metric-item">THINKING <strong>${m.thinking_tokens} tok</strong></span>` : '',
        m.prompt_tokens ? `<span class="metric-item">PROMPT <strong>${m.prompt_tokens} tok</strong></span>` : '',
      ].filter(Boolean).join('');
      metricsHtml = `<div class="metrics-row">${items}</div>`;
    }
    let dataHtml = '';
    if (src.data && agentKey === 'thousandeyes-analyst') {
      dataHtml = renderThousandEyesData(src.data);
    } else if (src.data) {
      const rawDataHtml = renderData({...src.data, llm_metrics: undefined});
      dataHtml = rawDataHtml ? `<details class="data-collapse"><summary>Raw Data</summary>${rawDataHtml}</details>` : '';
    }
    return `${answerHtml}${confHtml}${metricsHtml}${dataHtml}`;
  }

  /**
   * The swap control: which lane is showing, how fast it was, and the toggle.
   *
   * Reads everything from laneState — including `racing` — so it renders the same
   * way whether it is called with a fresh job in hand (first render, poll tick) or
   * from a swap, which has no job. Taking `lanesRacing` as an argument meant the
   * pending state silently depended on the caller having one.
   */
  function renderLaneBar(laneKey) {
    const st = laneState.get(laneKey);
    // Nothing to swap between (single-lane box) — render no bar at all rather
    // than a disabled control, so the single-lane UI is unchanged.
    if (!st || st.lanes.length < 2) {
      if (!st || !st.racing) return '';
      // One lane in, the other still running: show the pending state so the user
      // knows a second opinion is coming rather than wondering if it broke.
      const only = st.lanes.length === 1 ? st.lanes[0] : null;
      return `<span class="lane-current">${escHtml(only ? only.label : 'Fastest model')}</span>` +
             `<span class="lane-pending">second model still working…</span>`;
    }
    const active = st.lanes.find(l => l.lane === st.active) || st.lanes[0];
    const other = st.lanes.find(l => l.lane !== active.lane);
    const winner = st.lanes.find(l => l.winner);
    const isWinner = active.winner === true;
    const secs = (ms) => `${(ms / 1000).toFixed(1)}s`;
    return (
      `<span class="lane-current">${escHtml(active.label)}` +
      (isWinner ? '<span class="lane-badge-fastest">FASTEST</span>' : '') +
      `</span>` +
      `<span class="lane-timing">${secs(active.elapsedMs)}` +
      (winner && !isWinner ? ` <span class="lane-delta">+${secs(active.elapsedMs - winner.elapsedMs)}</span>` : '') +
      `</span>` +
      `<button class="lane-swap" type="button" data-lane-key="${escHtml(laneKey)}" ` +
      `title="Show the answer from ${escHtml(other.label)}" ` +
      `aria-label="Show the answer from ${escHtml(other.label)}">` +
      `<span class="lane-swap-icon" aria-hidden="true">⇄</span>` +
      `<span class="lane-swap-label">${escHtml(other.label)}</span></button>`
    );
  }

  /** Swap the displayed lane in place, without refetching or re-rendering hints. */
  function swapLane(laneKey) {
    const st = laneState.get(laneKey);
    if (!st || st.lanes.length < 2) return;
    const idx = st.lanes.findIndex(l => l.lane === st.active);
    const next = st.lanes[(idx + 1) % st.lanes.length];
    st.active = next.lane;
    const body = document.getElementById(`lanebody-${laneKey}`);
    if (body) {
      body.innerHTML = renderLaneBody(
        { answer: next.answer, confidence: next.confidence, data: next.data },
        st.agentKey,
      );
    }
    refreshLaneBar(laneKey);
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

    let bubbleContent = '';
    if (job.status === 'error') {
      bubbleContent = `<div class="message-bubble error-bubble"><strong style="color:#ff6080;">ERROR:</strong> ${escHtml(job.error||'Unknown error')}</div>`;
    } else {
      const laneKey = job.jobId || `anon-${Date.now()}`;
      // Track lanes client-side so a swap can re-render from memory with no refetch.
      if (job.lanes && job.lanes.length) {
        laneState.set(laneKey, {
          lanes: job.lanes,
          active: job.lane || job.lanes[0].lane,
          agentKey,
          racing: job.lanesRacing === true,
        });
      }
      const bodyHtml = renderLaneBody({
        answer: job.answer, confidence: job.confidence, data: job.data,
      }, agentKey);
      const hintsId = `hints-${laneKey}`;
      let hintsInner = '';
      if (job.hints && job.hints.length > 0) {
        hintsInner = `<span class="hints-label">Next Steps</span>${job.hints.map(h => `<span class="hint-chip" data-hint="${escHtml(h)}">${escHtml(h)}</span>`).join('')}`;
      }
      // The hints row sits OUTSIDE the swappable body on purpose: hints arrive
      // asynchronously and are written into #hints-<id> by pollForHints. If they
      // lived inside the lane body, swapping lanes after the hints landed would
      // wipe them (and a swap before they land would be overwritten by them).
      const hintsHtml = `<div class="hints-row" id="${hintsId}">${hintsInner}</div>`;
      bubbleContent =
        `<div class="message-bubble">` +
        `<div class="lane-bar" id="lanebar-${laneKey}">${renderLaneBar(laneKey)}</div>` +
        `<div class="lane-body" id="lanebody-${laneKey}">${bodyHtml}</div>` +
        `${hintsHtml}</div>`;
    }

    div.innerHTML = `
      <div class="message-meta">
        <span class="agent-badge ${badgeClass}">${agentLabel}</span>
        ${timeNow()}
        ${job.completedAt ? '// ' + elapsed(job.createdAt, job.completedAt) : ''}
      </div>
      ${bubbleContent}
    `;
    msgs.appendChild(div);
    // Wire up hint chip clicks
    div.querySelectorAll('.hint-chip').forEach(chip => {
      chip.addEventListener('click', () => {
        const query = chip.getAttribute('data-hint');
        if (query) {
          document.getElementById('query-input').value = query;
          document.getElementById('query-input').focus();
          sendQuery();
        }
      });
    });
    scrollToBottom(msgs);
  }

  // Headings that render as collapsible sections
  const COLLAPSIBLE_HEADINGS = new Set([
    'key entities', 'next steps', 'recommended next steps', 'recommended actions', 'evidence',
  ]);

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
    for (const sec of sections) {
      const body = formatInline(escHtml(sec.body.replace(/^\n+|\n+$/g, '')));
      if (!sec.heading) {
        if (body.trim()) out += body;
        continue;
      }
      const collapsible = COLLAPSIBLE_HEADINGS.has(sec.heading.toLowerCase().trim());
      const safeHeading = escHtml(sec.heading);
      if (collapsible) {
        out += `<details class="answer-section"><summary class="md-header md-collapsible">${safeHeading}</summary>${body}</details>`;
      } else {
        out += `<strong class="md-header">${safeHeading}</strong>${body}`;
      }
    }
    return out;
  }

  function formatAnswer(text) {
    if (!text) return '';
    const parts = text.split(/(```[\s\S]*?```)/g);
    let out = '';
    for (const part of parts) {
      if (part.startsWith('```')) {
        const inner = part.replace(/^```\w*\n?/, '').replace(/\n?```$/, '');
        out += `<pre class="code-block">${escHtml(inner)}</pre>`;
      } else {
        out += renderSections(part);
      }
    }
    return out;
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

  function renderHuntPicker() {
    const host = document.getElementById('hunt-view');
    const hunts = window.THREAT_HUNTS || [];
    if (!host || !window.ThreatHunt || hunts.length === 0) return;

    // Single hunt: mount directly (legacy path).
    if (hunts.length === 1) {
      activeHuntId = hunts[0].id;
      ThreatHunt.mount(host, hunts[0], handleHuntOutcome);
      return;
    }

    host.innerHTML =
      '<div class="hunt-briefing">' +
        '<div class="hunt-panel hunt-briefing-card">' +
          '<div class="hunt-panel-head">' +
            '<span>Threat Hunt</span>' +
            '<span class="hunt-meta">' + hunts.length + ' scenarios</span>' +
          '</div>' +
          '<div class="hunt-panel-body">' +
            '<div class="hunt-briefing-title">Select a hunt</div>' +
            '<p class="hunt-briefing-text">Each drill is a short click-only investigation ending in one BH close code. Dotted terms explain on hover once a hunt starts.</p>' +
            '<div class="hunt-separator"></div>' +
            '<div class="hunt-picker-list" id="hunt-picker-list"></div>' +
          '</div>' +
        '</div>' +
      '</div>';

    const list = host.querySelector('#hunt-picker-list');
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
    activeHuntId = null;
  }

  function injectHuntBackButton() {
    const hunts = window.THREAT_HUNTS || [];
    if (hunts.length < 2) return;
    const host = document.getElementById('hunt-view');
    const card = host && host.querySelector('.hunt-briefing-card .hunt-panel-body');
    if (!card || host.querySelector('#hunt-back-picker')) return;
    const back = document.createElement('button');
    back.type = 'button';
    back.id = 'hunt-back-picker';
    back.className = 'hunt-btn';
    back.style.marginTop = '10px';
    back.textContent = '← All hunts';
    back.addEventListener('click', renderHuntPicker);
    card.appendChild(back);
  }

  function mountHunt(huntId) {
    const host = document.getElementById('hunt-view');
    const hunts = window.THREAT_HUNTS || [];
    const hunt = hunts.find((h) => h.id === huntId) || hunts[0];
    if (!host || !hunt || !window.ThreatHunt) return;
    activeHuntId = hunt.id;
    ThreatHunt.mount(host, hunt, handleHuntOutcome, injectHuntBackButton);
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

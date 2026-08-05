/**
 * Threat hunt engine — vanilla-JS port of the "MUD as code" reference
 * (docs/threat-hunt-mud/ThreatHunt.jsx). The engine is content-free: all
 * scenario text comes from the config object (window.THREAT_HUNTS entries,
 * contract in docs/threat-hunt-mud/ThreatHunt.d.ts).
 *
 * Game rules preserved from the reference: click-only (no typing), every
 * node yields evidence (no punishing dead ends), the clock warns but never
 * fails, wrong containment choices explain themselves and name the correct
 * first move, and decision buttons render with equal visual weight so
 * styling never leaks the answer.
 */
window.ThreatHunt = (function () {
  let root = null;
  let config = null;
  let onOutcome = null; // (kind, subject) => void — 'hunt-win' | 'hunt-lose'
  let onBriefing = null; // optional () => void — after briefing DOM is ready

  // Game state
  let phase = 'briefing'; // briefing | playing | ended
  let nodeId = null;
  let evidence = [];
  let elapsed = 0;
  let timer = null;
  let result = null; // { action, correct, elapsed }
  let logsLoadTimer = null;

  function esc(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function fmt(s) {
    return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
  }

  function stopTimer() {
    if (timer) { clearInterval(timer); timer = null; }
  }

  /** Escape text, then wrap glossary terms in hoverable .hunt-term spans. */
  function annotate(text) {
    const glossary = config && config.glossary ? config.glossary : null;
    const escaped = esc(text);
    if (!glossary) return escaped;
    const terms = Object.keys(glossary)
      .filter(t => t && glossary[t])
      .sort((a, b) => b.length - a.length);
    if (!terms.length) return escaped;
    const pattern = terms.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
    // Word-ish boundaries so "IR" does not match inside "FIRE", but
    // "BH close code" and hyphenated keys still match as phrases.
    const re = new RegExp('(?<![A-Za-z0-9])(' + pattern + ')(?![A-Za-z0-9])', 'gi');
    return escaped.replace(re, (match) => {
      const key = terms.find(t => t.toLowerCase() === match.toLowerCase());
      if (!key) return match;
      return '<span class="hunt-term" tabindex="0" data-tip="' + esc(glossary[key]) + '">' + match + '</span>';
    });
  }

  function glossaryTipFor(label) {
    const glossary = config && config.glossary ? config.glossary : null;
    if (!glossary) return '';
    const key = Object.keys(glossary).find(t => t.toLowerCase() === String(label).toLowerCase());
    return key ? glossary[key] : '';
  }

  function tipEl() {
    let el = document.getElementById('hunt-glossary-tip');
    if (!el) {
      el = document.createElement('div');
      el.id = 'hunt-glossary-tip';
      el.className = 'hunt-glossary-tip';
      el.setAttribute('role', 'tooltip');
      el.hidden = true;
      document.body.appendChild(el);
    }
    return el;
  }

  function hideGlossaryTip() {
    const el = document.getElementById('hunt-glossary-tip');
    if (el) el.hidden = true;
  }

  function showGlossaryTip(anchor) {
    const text = anchor.getAttribute('data-tip');
    if (!text) return;
    const el = tipEl();
    el.textContent = text;
    el.hidden = false;
    const r = anchor.getBoundingClientRect();
    const pad = 8;
    const tipW = el.offsetWidth;
    const tipH = el.offsetHeight;
    let left = r.left + r.width / 2 - tipW / 2;
    left = Math.max(pad, Math.min(left, window.innerWidth - tipW - pad));
    let top = r.top - tipH - 8;
    if (top < pad) top = r.bottom + 8;
    el.style.left = left + 'px';
    el.style.top = top + 'px';
  }

  function bindGlossaryTips(scope) {
    if (!scope) return;
    scope.querySelectorAll('.hunt-term').forEach(el => {
      if (el.dataset.tipBound) return;
      el.dataset.tipBound = '1';
      el.addEventListener('mouseenter', () => showGlossaryTip(el));
      el.addEventListener('mouseleave', hideGlossaryTip);
      el.addEventListener('focus', () => showGlossaryTip(el));
      el.addEventListener('blur', hideGlossaryTip);
    });
  }

  // ---- Briefing ----
  function renderBriefing() {
    stopTimer();
    hideGlossaryTip();
    phase = 'briefing';
    root.innerHTML = `
      <div class="hunt-briefing">
        <div class="hunt-panel hunt-briefing-card">
          <div class="hunt-panel-head">
            <span>Threat Hunt</span>
            <span class="hunt-meta">target ${esc(fmt(config.meta.targetSeconds))}</span>
          </div>
          <div class="hunt-panel-body">
            <div class="hunt-briefing-title">${annotate(config.meta.title)}</div>
            <p class="hunt-briefing-text">${annotate(config.meta.briefing)}</p>
            <div class="hunt-separator"></div>
            <p class="hunt-hint">Pivot between sources, collect evidence, then choose one close code. Dotted terms explain on hover. Every pivot is a button; no commands to type.</p>
            <button class="hunt-btn hunt-btn-primary" id="hunt-start-btn">&#9654; Start Hunt</button>
          </div>
        </div>
      </div>`;
    bindGlossaryTips(root);
    root.querySelector('#hunt-start-btn').addEventListener('click', start);
    if (typeof onBriefing === 'function') onBriefing();
  }

  // ---- Playing ----
  function renderPlaying() {
    root.innerHTML = `
      <div class="hunt-layout">
        <div class="hunt-panel hunt-feed-panel">
          <div class="hunt-panel-head">
            <span>Investigation</span>
            <span class="hunt-meta">${esc(config.meta.title)}</span>
            <span class="hunt-timer" id="hunt-timer">${esc(fmt(elapsed))} / ${esc(fmt(config.meta.targetSeconds))}</span>
          </div>
          <div class="hunt-feed" id="hunt-feed"></div>
        </div>
        <div class="hunt-rail">
          <div class="hunt-panel">
            <div class="hunt-panel-head">
              <span id="hunt-node-name"></span>
              <span class="hunt-meta" id="hunt-node-tag"></span>
            </div>
            <div class="hunt-panel-body hunt-actions" id="hunt-actions"></div>
          </div>
          <div class="hunt-panel">
            <div class="hunt-panel-head">
              <span>Evidence</span>
              <span class="hunt-meta" id="hunt-evidence-count">0 collected</span>
            </div>
            <div class="hunt-panel-body" id="hunt-evidence"></div>
            <div class="hunt-logs-bar" id="hunt-logs-panel" hidden>
              <button type="button" class="hunt-btn" id="hunt-logs-open">View logs</button>
              <span class="hunt-meta" id="hunt-logs-meta"></span>
            </div>
          </div>
        </div>
      </div>`;
  }

  function appendLine(line) {
    const feed = root.querySelector('#hunt-feed');
    if (!feed) return;
    const el = document.createElement('div');
    el.className = 'hunt-line hunt-tone-' + (line.tone || 'info');
    el.innerHTML = `
      <span class="hunt-line-time">${esc(line.time)}</span>
      <span class="hunt-line-tag">${esc(line.tag)}</span>
      <span class="hunt-line-text">${annotate(line.text)}</span>`;
    feed.appendChild(el);
    bindGlossaryTips(el);
    feed.scrollTop = feed.scrollHeight;
  }

  function renderEvidence() {
    const box = root.querySelector('#hunt-evidence');
    const count = root.querySelector('#hunt-evidence-count');
    if (!box) return;
    if (count) count.textContent = evidence.length + ' collected';
    if (evidence.length === 0) {
      box.innerHTML = '<span class="hunt-hint">No evidence yet. Evidence collects on every pivot.</span>';
      return;
    }
    box.innerHTML = '<div class="hunt-chips">' +
      evidence.map(item =>
        `<span class="hunt-chip">${annotate(item.label)}</span>`
      ).join('') +
      '</div>';
    bindGlossaryTips(box);
  }

  function renderNodePanel() {
    const node = config.nodes[nodeId];
    const nameEl = root.querySelector('#hunt-node-name');
    const tagEl = root.querySelector('#hunt-node-tag');
    const box = root.querySelector('#hunt-actions');
    if (!box) return;
    nameEl.textContent = node.name;
    tagEl.textContent = node.tag;
    box.innerHTML = '';

    if (node.isDecision) {
      // Equal visual weight on every action — no styling hint at the answer.
      (node.actions || []).forEach(action => {
        const btn = document.createElement('button');
        btn.className = 'hunt-btn';
        btn.textContent = action.label;
        btn.disabled = phase !== 'playing';
        const tip = glossaryTipFor(action.label);
        if (tip) {
          btn.classList.add('hunt-term');
          btn.setAttribute('data-tip', tip);
        }
        btn.addEventListener('click', () => choose(action));
        box.appendChild(btn);
      });
      bindGlossaryTips(box);
      return;
    }

    (node.exits || []).forEach(exit => {
      const locked = (exit.requiresEvidence || 0) > evidence.length;
      const wrap = document.createElement('div');
      wrap.className = 'hunt-exit';
      const btn = document.createElement('button');
      btn.className = 'hunt-btn';
      btn.textContent = exit.label;
      btn.disabled = locked || phase !== 'playing';
      btn.addEventListener('click', () => enterNode(exit.to));
      wrap.appendChild(btn);
      if (locked) {
        const hint = document.createElement('span');
        hint.className = 'hunt-hint';
        hint.textContent = 'Needs ' + exit.requiresEvidence + ' evidence items. Collected: ' + evidence.length + '.';
        wrap.appendChild(hint);
      }
      box.appendChild(wrap);
    });
  }

  function updateTimer() {
    const el = root.querySelector('#hunt-timer');
    if (!el) return;
    el.textContent = fmt(elapsed) + ' / ' + fmt(config.meta.targetSeconds);
    el.classList.toggle('hunt-timer-warn', elapsed > config.meta.targetSeconds);
  }

  function enterNode(id) {
    const node = config.nodes[id];
    const time = fmt(elapsed);
    nodeId = id;
    appendLine({ time, tag: node.tag, tone: node.isDecision ? 'warn' : 'info', text: node.narration });
    for (const item of node.evidence || []) {
      if (evidence.some(e => e.id === item.id)) continue;
      evidence.push(item);
      appendLine({ time, tag: '[evidence]', tone: 'ok', text: item.label + ' — ' + item.detail });
    }
    renderEvidence();
    renderLogs();
    renderNodePanel();
  }

  function closeLogsModal() {
    if (logsLoadTimer) {
      clearTimeout(logsLoadTimer);
      logsLoadTimer = null;
    }
    const overlay = root && root.querySelector('#hunt-logs-modal');
    if (overlay) overlay.remove();
    document.removeEventListener('keydown', onLogsModalKeydown);
  }

  function onLogsModalKeydown(ev) {
    if (ev.key === 'Escape') closeLogsModal();
  }

  function renderLogsBody(blocks) {
    return blocks.map((block) => {
      const title = esc(block.title || 'log capture');
      const lines = (block.lines || []).map((line) => esc(line)).join('\n');
      return '<div class="hunt-log-block">' +
        '<div class="hunt-log-title">' + title + '</div>' +
        '<pre class="hunt-log-pre">' + lines + '</pre>' +
        '</div>';
    }).join('');
  }

  function openLogsModal(blocks) {
    closeLogsModal();
    const overlay = document.createElement('div');
    overlay.id = 'hunt-logs-modal';
    overlay.className = 'hunt-dialog-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', 'Log captures');
    overlay.setAttribute('aria-busy', 'true');
    overlay.innerHTML =
      '<div class="hunt-dialog hunt-logs-dialog">' +
        '<div class="hunt-dialog-title">Log captures</div>' +
        '<div class="hunt-dialog-meta" id="hunt-logs-modal-meta">Querying sensor · Esc to cancel</div>' +
        '<div class="hunt-logs-modal-body" id="hunt-logs-modal-body">' +
          '<div class="hunt-logs-loading" aria-live="polite">' +
            '<div class="hunt-logs-spinner" aria-hidden="true"></div>' +
            '<div class="hunt-logs-loading-title">Pulling log captures…</div>' +
            '<div class="hunt-logs-loading-meta">sensor query · resolving rows</div>' +
          '</div>' +
        '</div>' +
        '<div class="hunt-dialog-footer">' +
          '<button type="button" class="hunt-btn" id="hunt-logs-close">Cancel</button>' +
        '</div>' +
      '</div>';
    overlay.addEventListener('click', (ev) => {
      if (ev.target === overlay) closeLogsModal();
    });
    overlay.querySelector('#hunt-logs-close').addEventListener('click', closeLogsModal);
    document.addEventListener('keydown', onLogsModalKeydown);
    root.appendChild(overlay);
    overlay.querySelector('#hunt-logs-close').focus();

    // Staged delay so the pull feels like a sensor query, not instant DOM.
    const delayMs = 700 + Math.floor(Math.random() * 700);
    logsLoadTimer = setTimeout(() => {
      logsLoadTimer = null;
      if (!root || !root.contains(overlay)) return;
      overlay.setAttribute('aria-busy', 'false');
      const meta = overlay.querySelector('#hunt-logs-modal-meta');
      const body = overlay.querySelector('#hunt-logs-modal-body');
      const closeBtn = overlay.querySelector('#hunt-logs-close');
      if (meta) {
        meta.textContent = blocks.length +
          (blocks.length === 1 ? ' capture' : ' captures') +
          ' · Esc or backdrop to close';
      }
      if (body) body.innerHTML = renderLogsBody(blocks);
      if (closeBtn) {
        closeBtn.textContent = 'Close';
        closeBtn.classList.add('hunt-btn-primary');
        closeBtn.focus();
      }
    }, delayMs);
  }

  function renderLogs() {
    const panel = root.querySelector('#hunt-logs-panel');
    const meta = root.querySelector('#hunt-logs-meta');
    const openBtn = root.querySelector('#hunt-logs-open');
    if (!panel || !openBtn) return;
    closeLogsModal();
    const node = config.nodes[nodeId] || {};
    const blocks = node.logs || [];
    if (!blocks.length) {
      panel.hidden = true;
      if (meta) meta.textContent = '';
      openBtn.onclick = null;
      return;
    }
    panel.hidden = false;
    if (meta) meta.textContent = blocks.length + (blocks.length === 1 ? ' capture' : ' captures');
    openBtn.onclick = () => openLogsModal(blocks);
  }

  function start() {
    phase = 'playing';
    nodeId = config.startNode;
    evidence = [];
    elapsed = 0;
    result = null;
    stopTimer();
    renderPlaying();
    appendLine({ time: '0:00', tag: '[noc]', tone: 'debug', text: 'Hunt open. Pivots are on the right, evidence collects itself, the clock is running.' });
    enterNode(config.startNode);
    timer = setInterval(() => { elapsed += 1; updateTimer(); }, 1000);
  }

  function choose(action) {
    const correct = !!action.correct;
    const time = fmt(elapsed);
    stopTimer();
    phase = 'ended';
    result = { action, correct, elapsed };
    appendLine({ time, tag: '[decision]', tone: correct ? 'ok' : 'critical', text: action.label + ' — ' + action.resultNote });
    renderNodePanel(); // disable the decision buttons
    if (onOutcome) {
      onOutcome(correct ? 'hunt-win' : 'hunt-lose', { src: action.label, id: config.meta.title, time });
    }
    renderEndDialog();
  }

  function renderEndDialog() {
    const ending = result.correct ? config.endings.win : config.endings.lose;
    const correctAction = Object.values(config.nodes)
      .flatMap(n => n.actions || [])
      .find(a => a.correct);
    const underTarget = result.correct && result.elapsed <= config.meta.targetSeconds;

    const overlay = document.createElement('div');
    overlay.className = 'hunt-dialog-overlay';
    overlay.innerHTML = `
      <div class="hunt-dialog">
        <div class="hunt-dialog-title">${annotate(ending.title)}</div>
        <div class="hunt-dialog-meta">${esc(fmt(result.elapsed))} elapsed · ${evidence.length} evidence items · ${result.correct ? 'correct action' : 'incorrect action'}</div>
        <p class="hunt-dialog-narration">${annotate(ending.narration)}</p>
        <p class="hunt-dialog-note">${annotate(result.action.label + ' — ' + result.action.resultNote)}</p>
        ${!result.correct && correctAction
          ? `<p class="hunt-dialog-note">${annotate('Correct first move: ' + correctAction.label + ' — ' + correctAction.resultNote)}</p>`
          : ''}
        ${underTarget ? '<span class="hunt-badge-ok">Under target</span>' : ''}
        <div class="hunt-dialog-footer">
          <button class="hunt-btn" id="hunt-close-btn">Close</button>
          <button class="hunt-btn hunt-btn-primary" id="hunt-again-btn">&#8635; Play Again</button>
        </div>
      </div>`;
    bindGlossaryTips(overlay);
    overlay.querySelector('#hunt-close-btn').addEventListener('click', () => {
      hideGlossaryTip();
      overlay.remove();
      renderBriefing();
    });
    overlay.querySelector('#hunt-again-btn').addEventListener('click', () => {
      hideGlossaryTip();
      overlay.remove();
      start();
    });
    root.appendChild(overlay);
  }

  // ---- Public API ----
  function mount(el, huntConfig, outcomeCb, briefingCb) {
    root = el;
    config = huntConfig;
    onOutcome = outcomeCb || null;
    onBriefing = briefingCb || null;
    renderBriefing();
  }

  function reset() {
    if (root && config) renderBriefing();
  }

  return { mount, reset };
})();

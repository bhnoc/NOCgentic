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
  let onLeave = null; // optional () => void — return to hunt picker at any time

  // Game state
  let phase = 'briefing'; // briefing | playing | ended
  let nodeId = null;
  let evidence = [];
  let elapsed = 0;
  let timer = null;
  let result = null; // { action, correct, elapsed }
  let logsLoadTimer = null;
  let lineQueue = []; // pending feed lines, revealed with a stagger
  let lineQueueTimer = null;
  let alertShown = false; // first node narration gets the alert treatment once
  let seenTerms = new Set(); // per-node glossary dedupe: first occurrence underlines
  let visitedNodes = new Set(); // reveals incident-timeline markers

  // Engine chrome copy. Any key is overridable per hunt via `config.ui`,
  // so a config alone can restyle every non-scenario string.
  const DEFAULT_UI = {
    openingTag: '[noc]',
    openingLine: 'Hunt open. Pivots are on the right, evidence collects itself, the clock is running.',
    briefingHint: 'Pivot between sources, collect evidence, then choose one close code. Dotted terms explain on hover. Every pivot is a button; no commands to type.',
    noEvidence: 'No evidence yet. Evidence collects on every pivot.',
    evidenceHint: 'Click a chip to open its captures.',
    leaveButton: '\u2190 All hunts',
    logsTitle: 'Log captures',
    logsQuerying: 'Querying sensor · Esc to cancel',
    logsLoadingTitle: 'Pulling log captures…',
    logsLoadingMeta: 'sensor query · resolving rows',
    timelineTitle: 'Incident timeline',
    timelineHint: 'assembles as sources are read',
    timelineUnobserved: 'Unobserved. Pivot to more sources.',
    timelineClickPrompt: 'Click a marker to open its rows.',
    timelineEmpty: 'This source does not speak to the wire window yet.',
  };

  function uiText(key) {
    return (config && config.ui && config.ui[key]) || DEFAULT_UI[key];
  }

  /** Console warnings for broken config references — the authoring contract
   *  is "config renders everything", so tell the author what won't render. */
  function warnConfigGaps(cfg) {
    const warn = (msg) => console.warn('[threat-hunt] ' + cfg.id + ': ' + msg);
    if (!cfg.nodes || !cfg.nodes[cfg.startNode]) {
      warn('startNode "' + cfg.startNode + '" is not a node');
      return;
    }
    for (const [id, node] of Object.entries(cfg.nodes)) {
      const blob = (node.logs || []).flatMap(l => l.lines || []).join('\n');
      for (const exit of node.exits || []) {
        if (!cfg.nodes[exit.to]) warn('node "' + id + '" exit "' + exit.label + '" → unknown node "' + exit.to + '"');
      }
      for (const ev of node.evidence || []) {
        for (const h of ev.hint || []) {
          if (!blob.includes(h)) warn('evidence "' + ev.id + '" hint not found in "' + id + '" logs: ' + h);
        }
      }
    }
    for (const e of cfg.timeline || []) {
      const nodes = e.nodes || [];
      if (!nodes.length) warn('timeline "' + e.id + '" correlates to no nodes');
      for (const n of nodes) {
        if (!cfg.nodes[n]) warn('timeline "' + e.id + '" → unknown node "' + n + '"');
      }
      const blob = nodes
        .flatMap(n => ((cfg.nodes[n] || {}).logs || []).flatMap(l => l.lines || []))
        .join('\n');
      for (const h of e.hint || []) {
        if (!blob.includes(h)) warn('timeline "' + e.id + '" hint not found in correlated logs: ' + h);
      }
    }
    for (const k of Object.keys(cfg.ui || {})) {
      if (!(k in DEFAULT_UI)) warn('unknown ui key "' + k + '"');
    }
  }

  function esc(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function prefersReducedMotion() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function fmt(s) {
    return Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
  }

  function stopTimer() {
    if (timer) { clearInterval(timer); timer = null; }
  }

  /**
   * Escape text, then wrap glossary terms in hoverable .hunt-term spans.
   * With dedupe (feed lines), only the first occurrence per node is wrapped,
   * so the feed doesn't read as a link farm.
   */
  function annotate(text, dedupe) {
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
      if (dedupe) {
        const k = key.toLowerCase();
        if (seenTerms.has(k)) return match;
        seenTerms.add(k);
      }
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

  /** Tear down play state and hand control back to the picker (if wired). */
  function leaveToPicker() {
    if (typeof onLeave !== 'function') return;
    stopTimer();
    clearLineQueueTimer();
    lineQueue = [];
    closeLogsModal();
    hideGlossaryTip();
    onLeave();
  }

  function leaveButtonHtml(extraClass) {
    if (typeof onLeave !== 'function') return '';
    const cls = 'hunt-leave' + (extraClass ? ' ' + extraClass : '');
    return '<button type="button" class="' + cls + '" id="hunt-leave-btn">' +
      esc(uiText('leaveButton')) + '</button>';
  }

  function bindLeaveButton(scope) {
    const btn = (scope || root).querySelector('#hunt-leave-btn');
    if (btn) btn.addEventListener('click', leaveToPicker);
  }

  // ---- Briefing ----
  function renderBriefing() {
    stopTimer();
    clearLineQueueTimer();
    lineQueue = [];
    closeLogsModal();
    hideGlossaryTip();
    seenTerms.clear();
    phase = 'briefing';
    root.innerHTML = `
      <div class="hunt-briefing">
        <div class="hunt-panel hunt-briefing-card">
          <div class="hunt-panel-head">
            <span>Threat Hunt</span>
            <span class="hunt-meta">target ${esc(fmt(config.meta.targetSeconds))}</span>
            ${leaveButtonHtml('hunt-leave-head')}
          </div>
          <div class="hunt-panel-body">
            <div class="hunt-briefing-title">${annotate(config.meta.title)}</div>
            <p class="hunt-briefing-text">${annotate(config.meta.briefing)}</p>
            <div class="hunt-separator"></div>
            <p class="hunt-hint">${esc(uiText('briefingHint'))}</p>
            <button class="hunt-btn hunt-btn-primary" id="hunt-start-btn">&#9654; Start Hunt</button>
          </div>
        </div>
      </div>`;
    bindGlossaryTips(root);
    bindLeaveButton(root);
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
            ${leaveButtonHtml('hunt-leave-head')}
          </div>
          <div class="hunt-timeline" id="hunt-timeline" hidden></div>
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
          </div>
        </div>
      </div>`;
    bindLeaveButton(root);
  }

  // ---- Feed streaming ----
  // Lines reveal with a short stagger so the feed reads like a live console,
  // not a pre-rendered dump. The queue accelerates when it backs up, and a
  // decision flushes it, so the stream never gets in the way of play.

  function clearLineQueueTimer() {
    if (lineQueueTimer) { clearTimeout(lineQueueTimer); lineQueueTimer = null; }
  }

  function appendLine(line) {
    lineQueue.push(line);
    if (!lineQueueTimer) pumpLineQueue(0);
  }

  function pumpLineQueue(delay) {
    lineQueueTimer = setTimeout(() => {
      lineQueueTimer = null;
      if (!lineQueue.length) return;
      revealLine(lineQueue.shift(), false);
      if (lineQueue.length) {
        // Catch up faster when the player is pivoting quicker than the stream.
        const base = prefersReducedMotion() ? 40 : 280 + Math.random() * 140;
        pumpLineQueue(lineQueue.length >= 3 ? base * 0.35 : base);
      }
    }, delay);
  }

  /** Reveal everything pending instantly (used when a decision lands). */
  function flushLineQueue() {
    clearLineQueueTimer();
    while (lineQueue.length) revealLine(lineQueue.shift(), true);
  }

  function revealLine(line, instant) {
    const feed = root.querySelector('#hunt-feed');
    if (!feed) return;
    const el = document.createElement('div');
    el.className = 'hunt-line hunt-tone-' + (line.tone || 'info') +
      (line.emphasis ? ' hunt-line-alert' : ' hunt-line-enter');
    el.innerHTML = `
      <span class="hunt-line-time">${esc(line.time)}</span>
      <span class="hunt-line-tag">${esc(line.tag)}</span>
      <span class="hunt-line-text">${annotate(line.text, true)}</span>`;
    feed.appendChild(el);
    bindGlossaryTips(el);
    feed.scrollTop = feed.scrollHeight;
    if (line.evidenceItem) {
      if (instant || prefersReducedMotion()) {
        line.evidenceItem.landed = true;
        renderEvidence();
      } else {
        flyEvidence(el, line.evidenceItem);
      }
    }
  }

  /** Fly a ghost chip from the feed line to the Evidence rail, then land it. */
  function flyEvidence(lineEl, item) {
    const evBox = root.querySelector('#hunt-evidence');
    if (!evBox || !lineEl.isConnected) {
      item.landed = true;
      renderEvidence();
      return;
    }
    const from = lineEl.getBoundingClientRect();
    const to = evBox.getBoundingClientRect();
    const ghost = document.createElement('span');
    ghost.className = 'hunt-chip hunt-chip-ghost';
    ghost.textContent = item.label;
    document.body.appendChild(ghost);
    const land = () => {
      ghost.remove();
      item.landed = true;
      renderEvidence();
      const chips = root.querySelectorAll('#hunt-evidence .hunt-chip');
      const last = chips[chips.length - 1];
      if (last) last.classList.add('hunt-chip-pop');
    };
    const anim = ghost.animate([
      { transform: 'translate(' + (from.left + 46) + 'px,' + (from.top + 2) + 'px) scale(1)', opacity: 1 },
      { transform: 'translate(' + (to.left + 14) + 'px,' + (to.top + 12) + 'px) scale(0.9)', opacity: 0.85 },
    ], { duration: 460, easing: 'cubic-bezier(0.22, 1, 0.36, 1)', fill: 'forwards' });
    anim.onfinish = land;
    anim.oncancel = land;
  }

  function renderEvidence() {
    const box = root.querySelector('#hunt-evidence');
    const count = root.querySelector('#hunt-evidence-count');
    if (!box) return;
    // Only chips that visually "landed" render; game state counts everything.
    const landed = evidence.filter(e => e.landed);
    if (count) count.textContent = landed.length + ' collected';
    if (landed.length === 0) {
      box.innerHTML = '<span class="hunt-hint">' + esc(uiText('noEvidence')) + '</span>';
      return;
    }
    const hasCaptures = landed.some(item => item.sourceLogs && item.sourceLogs.length);
    box.innerHTML =
      (hasCaptures ? '<p class="hunt-hint hunt-evidence-hint">' + esc(uiText('evidenceHint')) + '</p>' : '') +
      '<div class="hunt-chips">' +
      landed.map((item, i) => {
        // Captures open from the evidence chip — no separate View logs control.
        if (item.sourceLogs && item.sourceLogs.length) {
          return `<button type="button" class="hunt-chip hunt-chip-link" data-ev="${i}" title="Open supporting log captures">${annotate(item.label)}</button>`;
        }
        return `<span class="hunt-chip">${annotate(item.label)}</span>`;
      }).join('') +
      '</div>';
    box.querySelectorAll('.hunt-chip-link').forEach(btn => {
      btn.addEventListener('click', () => {
        const item = landed[Number(btn.getAttribute('data-ev'))];
        if (item) openLogsModal(item.sourceLogs, { label: item.label, hints: item.hint });
      });
    });
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

  // ---- Incident timeline ----
  // Markers are positioned proportionally across the incident window. Each
  // stays dim ("unobserved") until one of its correlated nodes is visited,
  // highlights while a correlated node is active, and — once revealed —
  // clicking it opens that node's captures with the event rows highlighted.

  function parseClock(t) {
    const parts = String(t).split(':').map(Number);
    return (parts[0] || 0) * 3600 + (parts[1] || 0) * 60 + (parts[2] || 0);
  }

  function timelineTipHandlers(el) {
    el.addEventListener('mouseenter', () => showGlossaryTip(el));
    el.addEventListener('mouseleave', hideGlossaryTip);
    el.addEventListener('focus', () => showGlossaryTip(el));
    el.addEventListener('blur', hideGlossaryTip);
  }

  function renderTimeline() {
    const strip = root.querySelector('#hunt-timeline');
    if (!strip) return;
    const events = config.timeline || [];
    if (!events.length) {
      strip.hidden = true;
      return;
    }
    strip.hidden = false;
    const secs = events.map(e => parseClock(e.t));
    const min = Math.min(...secs);
    const span = Math.max(1, Math.max(...secs) - min);
    const ordered = events.slice().sort((a, b) => parseClock(a.t) - parseClock(b.t));
    const rangeLabel = ordered[0].t.slice(0, 5) + '\u2013' + ordered[ordered.length - 1].t.slice(0, 5);

    const revealed = e => (e.nodes || []).some(n => visitedNodes.has(n));
    const active = e => (e.nodes || []).includes(nodeId);
    const activeEvents = ordered.filter(e => active(e) && revealed(e));

    strip.innerHTML =
      '<div class="hunt-timeline-head">' +
        '<span>' + esc(uiText('timelineTitle')) + '</span>' +
        '<span class="hunt-meta">' + esc(rangeLabel) + ' \u00b7 ' + esc(uiText('timelineHint')) + '</span>' +
      '</div>' +
      '<div class="hunt-timeline-track">' +
        events.map((e, i) => {
          const left = 4 + ((parseClock(e.t) - min) / span) * 92;
          const isRev = revealed(e);
          const cls = 'hunt-timeline-dot hunt-timeline-' + (e.tone || 'info') +
            (isRev ? ' hunt-timeline-revealed' : '') +
            (isRev && active(e) ? ' hunt-timeline-active' : '');
          const tip = isRev
            ? e.t + ' \u00b7 ' + e.label
            : uiText('timelineUnobserved');
          return '<button type="button" class="' + cls + '" style="left:' + left.toFixed(2) + '%"' +
            ' data-idx="' + i + '" data-tip="' + esc(tip) + '"' +
            (isRev ? '' : ' disabled') +
            ' aria-label="' + esc(tip) + '"></button>';
        }).join('') +
      '</div>' +
      '<div class="hunt-timeline-caption" id="hunt-timeline-caption"></div>';

    const caption = strip.querySelector('#hunt-timeline-caption');
    if (activeEvents.length) {
      caption.innerHTML = activeEvents.map(e =>
        '<span class="hunt-timeline-caption-t">' + esc(e.t) + '</span> ' + esc(e.label)
      ).join('<br>');
    } else if (events.some(revealed)) {
      caption.textContent = uiText('timelineClickPrompt');
    } else {
      caption.textContent = uiText('timelineEmpty');
    }

    strip.querySelectorAll('.hunt-timeline-dot').forEach(dot => {
      timelineTipHandlers(dot);
      dot.addEventListener('click', () => {
        const e = events[Number(dot.getAttribute('data-idx'))];
        if (!e || !revealed(e)) return;
        const srcNode = (e.nodes || []).map(n => config.nodes[n]).find(n => n && n.logs && n.logs.length);
        if (!srcNode) return;
        hideGlossaryTip();
        openLogsModal(srcNode.logs, { label: e.t + ' \u00b7 ' + e.label, hints: e.hint, autoHint: true });
      });
    });
  }

  function enterNode(id) {
    const node = config.nodes[id];
    const time = fmt(elapsed);
    nodeId = id;
    visitedNodes.add(id);
    seenTerms.clear(); // glossary underlines reset per node
    const emphasis = !alertShown;
    alertShown = true;
    appendLine({ time, tag: node.tag, tone: node.isDecision ? 'warn' : 'info', text: node.narration, emphasis });
    for (const item of node.evidence || []) {
      if (evidence.some(e => e.id === item.id)) continue;
      // Clone so the visual `landed` flag never mutates the config object.
      // sourceLogs pins the captures of the node where this was collected,
      // so the chip can reopen them from anywhere in the hunt.
      const collected = Object.assign({}, item, { landed: false, sourceLogs: node.logs || [] });
      evidence.push(collected);
      appendLine({ time, tag: '[evidence]', tone: 'ok', text: item.label + ' — ' + item.detail, evidenceItem: collected });
    }
    renderEvidence();
    renderTimeline();
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

  /** Render capture blocks; with hints, wrap matching substrings in <mark>. */
  function renderLogsBody(blocks, hints) {
    const escapedHints = (hints || []).map(h => esc(h)).filter(Boolean);
    return blocks.map((block) => {
      const title = esc(block.title || 'log capture');
      let lines = (block.lines || []).map((line) => esc(line)).join('\n');
      for (const hint of escapedHints) {
        lines = lines.split(hint).join('<mark class="hunt-log-mark">' + hint + '</mark>');
      }
      return '<div class="hunt-log-block">' +
        '<div class="hunt-log-title">' + title + '</div>' +
        '<pre class="hunt-log-pre">' + lines + '</pre>' +
        '</div>';
    }).join('');
  }

  /**
   * opts.label — evidence label the modal was opened from (scopes the title).
   * opts.hints — substrings the "Show hint" button highlights in the capture.
   */
  function openLogsModal(blocks, opts) {
    closeLogsModal();
    const label = opts && opts.label ? String(opts.label) : '';
    const hints = (opts && opts.hints) || [];
    const overlay = document.createElement('div');
    overlay.id = 'hunt-logs-modal';
    overlay.className = 'hunt-dialog-overlay';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', 'Log captures');
    overlay.setAttribute('aria-busy', 'true');
    overlay.innerHTML =
      '<div class="hunt-dialog hunt-logs-dialog">' +
        '<div class="hunt-dialog-title">' + (label ? 'Evidence · ' + esc(label) : esc(uiText('logsTitle'))) + '</div>' +
        '<div class="hunt-dialog-meta" id="hunt-logs-modal-meta">' + esc(uiText('logsQuerying')) + '</div>' +
        '<div class="hunt-logs-modal-body" id="hunt-logs-modal-body">' +
          '<div class="hunt-logs-loading" aria-live="polite">' +
            '<div class="hunt-logs-spinner" aria-hidden="true"></div>' +
            '<div class="hunt-logs-loading-title">' + esc(uiText('logsLoadingTitle')) + '</div>' +
            '<div class="hunt-logs-loading-meta">' + esc(uiText('logsLoadingMeta')) + '</div>' +
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
      const footer = overlay.querySelector('.hunt-dialog-footer');
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
      if (hints.length && footer && body) {
        let hintsOn = false;
        const hintBtn = document.createElement('button');
        hintBtn.type = 'button';
        hintBtn.className = 'hunt-btn';
        hintBtn.id = 'hunt-logs-hint';
        hintBtn.textContent = 'Show hint';
        const applyHints = (on) => {
          hintsOn = on;
          body.innerHTML = renderLogsBody(blocks, on ? hints : null);
          hintBtn.textContent = on ? 'Hide hint' : 'Show hint';
          if (on) {
            const first = body.querySelector('.hunt-log-mark');
            if (first) {
              first.scrollIntoView({
                block: 'center',
                behavior: prefersReducedMotion() ? 'auto' : 'smooth',
              });
            }
          } else {
            body.scrollTop = 0;
          }
        };
        hintBtn.addEventListener('click', () => applyHints(!hintsOn));
        footer.insertBefore(hintBtn, closeBtn);
        // Timeline markers open straight onto their rows.
        if (opts && opts.autoHint) applyHints(true);
      }
    }, delayMs);
  }

  function start() {
    phase = 'playing';
    nodeId = config.startNode;
    evidence = [];
    elapsed = 0;
    result = null;
    alertShown = false;
    visitedNodes = new Set();
    lineQueue = [];
    clearLineQueueTimer();
    closeLogsModal();
    stopTimer();
    renderPlaying();
    appendLine({ time: '0:00', tag: uiText('openingTag'), tone: 'debug', text: uiText('openingLine') });
    enterNode(config.startNode);
    timer = setInterval(() => { elapsed += 1; updateTimer(); }, 1000);
  }

  function choose(action) {
    const correct = !!action.correct;
    const time = fmt(elapsed);
    stopTimer();
    flushLineQueue();
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
          ${leaveButtonHtml()}
          <button class="hunt-btn" id="hunt-close-btn">Close</button>
          <button class="hunt-btn hunt-btn-primary" id="hunt-again-btn">&#8635; Play Again</button>
        </div>
      </div>`;
    bindGlossaryTips(overlay);
    bindLeaveButton(overlay);
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
  /**
   * Fourth arg may be a legacy onBriefing function, or an options object:
   * { onBriefing?, onLeave? }. onLeave renders "← All hunts" on briefing,
   * play, and end screens so the picker is always one click away.
   */
  function mount(el, huntConfig, outcomeCb, briefingOrOpts) {
    root = el;
    config = huntConfig;
    onOutcome = outcomeCb || null;
    onBriefing = null;
    onLeave = null;
    if (typeof briefingOrOpts === 'function') {
      onBriefing = briefingOrOpts;
    } else if (briefingOrOpts && typeof briefingOrOpts === 'object') {
      onBriefing = briefingOrOpts.onBriefing || null;
      onLeave = briefingOrOpts.onLeave || null;
    }
    warnConfigGaps(config);
    renderBriefing();
  }

  function reset() {
    if (root && config) renderBriefing();
  }

  return { mount, reset };
})();

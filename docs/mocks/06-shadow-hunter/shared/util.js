/* Shared helpers for NOCgentic UX mocks */
(function () {
  function esc(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function facts() {
    if (!window.NOC_FACTS) throw new Error("NOC_FACTS not loaded — include shared/facts.js");
    return window.NOC_FACTS;
  }

  function makeLogger(el) {
    return {
      clear() {
        el.innerHTML = "";
      },
      write(html, cls) {
        const d = document.createElement("div");
        d.className = "line " + (cls || "narr");
        d.innerHTML = html;
        el.appendChild(d);
        el.scrollTop = el.scrollHeight;
      },
    };
  }

  function setActions(container, btns) {
    container.innerHTML = "";
    btns.forEach((b) => {
      const btn = document.createElement("button");
      btn.className = "btn" + (b.primary ? " primary" : "") + (b.danger ? " danger" : "") + (b.warn ? " warn" : "");
      btn.textContent = b.label;
      if (b.disabled) btn.disabled = true;
      btn.onclick = b.onClick;
      container.appendChild(btn);
    });
  }

  function pinStore() {
    const items = [];
    return {
      items,
      add(item) {
        if (items.some((x) => x.key === item.key && x.value === item.value)) return false;
        items.push(item);
        return true;
      },
      hosts() {
        return [...new Set(items.filter((i) => i.host).map((i) => i.host))];
      },
      render(el) {
        if (!items.length) {
          el.innerHTML =
            '<div class="chip"><div class="k">EMPTY</div><div class="v">No evidence pinned</div></div>';
          return;
        }
        el.innerHTML = items
          .map(
            (i) =>
              `<div class="chip"><div class="k">${esc(i.key)}</div>` +
              `<div class="v ${esc(i.cls || "")}">${esc(i.value)}</div>` +
              (i.note ? `<div class="note">${esc(i.note)}</div>` : "") +
              `</div>`
          )
          .join("");
      },
    };
  }

  function mb(n) {
    return (Number(n) / 1e6).toFixed(2);
  }

  window.NocMock = { esc, facts, makeLogger, setActions, pinStore, mb };
})();

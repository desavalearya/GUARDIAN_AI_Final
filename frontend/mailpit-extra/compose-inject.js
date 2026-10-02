/* PhishProof — Compose + Inbox/Sent for Mailpit. Injected before app.js. */
(function () {
  /* ── 1. FETCH INTERCEPTOR: filter messages by sender domain ─────────── */
  const SENT_DOMAIN = "@company-b.test";

  function isSentMsg(msg) {
    const addr = (msg && msg.From && (msg.From.Address || msg.From.Email)) || "";
    return addr.toLowerCase().endsWith(SENT_DOMAIN);
  }

  const _fetch = window.fetch.bind(window);
  window.fetch = function (input, init) {
    const url = (typeof input === "string" ? input : (input || {}).url) || "";
    const isListing =
      /\/api\/v1\/messages(\?|$)/.test(url) ||
      /\/api\/v1\/search(\?|$)/.test(url);

    return _fetch(input, init).then(async (res) => {
      if (!isListing || !res.ok) return res;
      let body;
      try { body = await res.clone().json(); } catch (_) { return res; }
      if (!body || !Array.isArray(body.messages)) return res;

      const view = sessionStorage.getItem("mp-view") || "inbox";
      body.messages = body.messages.filter(
        (m) => view === "sent" ? isSentMsg(m) : !isSentMsg(m)
      );
      body.total = body.messages.length;
      body.unread = body.messages.filter((m) => !m.Read).length;
      body.messages_count = body.messages.length;
      body.count = body.messages.length;

      const h = new Headers(res.headers);
      h.delete("content-length");
      return new Response(JSON.stringify(body), {
        status: res.status,
        statusText: res.statusText,
        headers: h,
      });
    });
  };

  /* ── 2. UI INJECTION: wait for Mailpit's navbar to exist ─────────────── */
  const CSS = `
    #pp-bar {
      display: flex;
      align-items: center;
      gap: 6px;
      padding: 4px 8px;
      background: #1e293b;
      border-bottom: 1px solid #334155;
      position: relative;
      z-index: 9999;
    }
    #pp-bar button, #pp-bar .pp-sep {
      font: 600 13px/1 "Segoe UI", system-ui, sans-serif;
      border: 0;
      border-radius: 5px;
      padding: 6px 12px;
      cursor: pointer;
    }
    #pp-bar .pp-sep { background: none; color: #94a3b8; cursor: default; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
    #pp-bar .pp-view  { background: #334155; color: #e2e8f0; }
    #pp-bar .pp-view.active { background: #3b82f6; color: #fff; }
    #pp-bar .pp-compose { background: #10b981; color: #fff; margin-left: auto; }
    #pp-modal {
      position: fixed; inset: 0; z-index: 99999;
      background: rgba(0,0,0,.6);
      display: none; place-items: center;
    }
    #pp-modal.open { display: grid; }
    #pp-form {
      width: min(560px, 96vw);
      background: #1e293b; color: #e2e8f0;
      border: 1px solid #334155;
      border-radius: 12px; padding: 20px;
      display: grid; gap: 10px;
      font: 14px/1.4 "Segoe UI", system-ui, sans-serif;
    }
    #pp-form h2 { margin: 0; font-size: 17px; }
    #pp-form p  { margin: 0; color: #94a3b8; font-size: 12px; }
    #pp-form input, #pp-form textarea {
      width: 100%; box-sizing: border-box;
      border: 1px solid #334155; border-radius: 6px;
      background: #0f172a; color: #e2e8f0;
      padding: 8px 10px; font: inherit;
    }
    #pp-form input:focus, #pp-form textarea:focus { outline: 1px solid #3b82f6; }
    #pp-form .pp-row { display: flex; gap: 8px; }
    #pp-form .pp-row button { border: 0; border-radius: 6px; padding: 8px 16px; cursor: pointer; font-weight: 700; }
    #pp-send { background: #3b82f6; color: #fff; }
    #pp-cancel { background: #334155; color: #e2e8f0; }
    #pp-status { font-size: 12px; min-height: 1em; }
    #pp-status.ok { color: #34d399; }
    #pp-status.err { color: #f87171; }
  `;

  function inject() {
    if (document.getElementById("pp-bar")) return; // already done

    /* Look for any rendered navbar — Mailpit uses Bootstrap .navbar */
    const nav = document.querySelector(".navbar, nav, #app > div > div:first-child");
    if (!nav) return; /* not mounted yet, MutationObserver will retry */

    /* Insert our bar BEFORE the Mailpit navbar so it's always visible at top */
    const style = document.createElement("style");
    style.textContent = CSS;
    document.head.appendChild(style);

    const bar = document.createElement("div");
    bar.id = "pp-bar";

    const view = sessionStorage.getItem("mp-view") || "inbox";

    bar.innerHTML = `
      <span class="pp-sep">Company B</span>
      <button class="pp-view${view === "inbox" ? " active" : ""}" data-view="inbox">Inbox</button>
      <button class="pp-view${view === "sent"  ? " active" : ""}" data-view="sent">Sent</button>
      <button class="pp-compose" id="pp-open-compose">✎ Compose</button>
    `;

    bar.querySelectorAll(".pp-view").forEach((b) =>
      b.addEventListener("click", () => {
        sessionStorage.setItem("mp-view", b.dataset.view);
        location.reload();
      })
    );

    /* Insert bar at very top of body (above Mailpit app) */
    document.body.insertBefore(bar, document.body.firstChild);

    /* ── Modal ──────────────────────────────────────────────────── */
    const modal = document.createElement("div");
    modal.id = "pp-modal";
    modal.innerHTML = `
      <form id="pp-form">
        <h2>Compose — Company B → Guardian</h2>
        <p>Saves a copy here (visible under Sent), then releases via PhishProof SMTP gateway.</p>
        <input id="pp-from"    value="receiver@company-b.test" required />
        <input id="pp-to"      value="user@example.com"        required />
        <input id="pp-subject" value="Hello from Company B"    required />
        <textarea id="pp-body" rows="9">Hi Guardian team — this message was composed in the Company B Mailpit UI and scanned by PhishProof before delivery.</textarea>
        <div class="pp-row">
          <button type="submit" id="pp-send">Send</button>
          <button type="button" id="pp-cancel">Cancel</button>
        </div>
        <div id="pp-status"></div>
      </form>`;
    document.body.appendChild(modal);

    document.getElementById("pp-open-compose").addEventListener("click", () =>
      modal.classList.add("open")
    );
    document.getElementById("pp-cancel").addEventListener("click", () =>
      modal.classList.remove("open")
    );
    modal.addEventListener("click", (e) => {
      if (e.target === modal) modal.classList.remove("open");
    });

    document.getElementById("pp-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const status = document.getElementById("pp-status");
      status.className = "pp-status";
      status.textContent = "Sending to Mailpit…";

      const from    = document.getElementById("pp-from").value.trim();
      const to      = document.getElementById("pp-to").value.trim();
      const subject = document.getElementById("pp-subject").value.trim();
      const text    = document.getElementById("pp-body").value;

      try {
        const sRes  = await _fetch("/api/v1/send", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            From: { Email: from, Name: "Company B" },
            To:   [{ Email: to }],
            Subject: subject,
            Text: text,
          }),
        });
        const sText = await sRes.text();
        if (!sRes.ok) throw new Error("Mailpit /send: " + sText);
        const parsed = JSON.parse(sText);
        const id = parsed.ID || parsed.Id || parsed.id;
        if (!id) throw new Error("No message ID returned: " + sText);

        status.textContent = "Releasing through Guardian…";

        /* Try capitalized key first (Mailpit v1.20+) then lowercase */
        let rRes = await _fetch(`/api/v1/message/${encodeURIComponent(id)}/release`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ To: [to] }),
        });
        if (!rRes.ok) {
          rRes = await _fetch(`/api/v1/message/${encodeURIComponent(id)}/release`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ to: [to] }),
          });
        }
        if (!rRes.ok) throw new Error("Release failed: " + await rRes.text());

        status.className = "pp-status ok";
        status.textContent = "Sent! Switching to Sent view…";
        sessionStorage.setItem("mp-view", "sent");
        setTimeout(() => location.reload(), 700);
      } catch (err) {
        status.className = "pp-status err";
        status.textContent = String(err.message || err);
      }
    });
  }

  /* Run immediately (in case DOM already ready) and watch for Mailpit to mount */
  const obs = new MutationObserver(inject);
  obs.observe(document.documentElement, { childList: true, subtree: true });
  inject();
})();

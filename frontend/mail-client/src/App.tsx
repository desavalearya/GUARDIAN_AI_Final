import { FormEvent, useEffect, useMemo, useState } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";
const DEMO_RECIPIENT = import.meta.env.VITE_DEMO_RECIPIENT || "receiver@company-b.test";
const MAILPIT_URL = import.meta.env.VITE_MAILPIT_URL || "http://localhost:8025";

type Msg = {
  id: string;
  received_at: string;
  sender_address: string;
  recipient_address: string;
  subject: string;
  direction?: string;
  decision?: string | null;
  fused_risk_score?: number | null;
  ingestion_path?: string | null;
};

type Detail = Msg & {
  body_plain: string;
  raw_headers?: string;
  confidence_state?: string | null;
  urls?: string[];
  attachments?: string[];
};

type ViewTab = "html" | "text" | "headers" | "raw";

async function api(path: string, token: string, init?: RequestInit) {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(init?.headers || {}),
    },
  });
  if (res.status === 401) {
    localStorage.removeItem("mail_token");
    throw new Error("AUTH_401");
  }
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function chipClass(decision?: string | null) {
  if (!decision) return "tag";
  if (decision === "PASS" || decision === "SOFT_PASS") return "tag ok";
  if (decision === "HUMAN_REVIEW" || decision === "QUARANTINE") return "tag warn";
  return "tag bad";
}

function fmtTime(iso: string) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export default function App() {
  const [email, setEmail] = useState("user@example.com");
  const [password, setPassword] = useState("changeme1");
  const [token, setToken] = useState(localStorage.getItem("mail_token") || "");
  const [folder, setFolder] = useState("all");
  const [items, setItems] = useState<Msg[]>([]);
  const [open, setOpen] = useState<Detail | null>(null);
  const [err, setErr] = useState("");
  const [status, setStatus] = useState("");
  const [compose, setCompose] = useState(false);
  const [to, setTo] = useState(DEMO_RECIPIENT);
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [q, setQ] = useState("");
  const [viewTab, setViewTab] = useState<ViewTab>("text");
  const [selected, setSelected] = useState<Record<string, boolean>>({});
  const [autoRefresh, setAutoRefresh] = useState(true);

  const folders = useMemo(
    () => [
      { id: "all", label: "Mailbox", hint: "All traffic" },
      { id: "inbox", label: "Inbox", hint: "Delivered PASS" },
      { id: "sent", label: "Sent", hint: "Outbound" },
      { id: "quarantine", label: "Quarantine", hint: "Held" },
    ],
    []
  );

  const filtered = items.filter((m) => {
    if (!q) return true;
    const hay = `${m.subject} ${m.sender_address} ${m.recipient_address} ${m.decision || ""}`.toLowerCase();
    return hay.includes(q.toLowerCase());
  });

  const selectedCount = Object.values(selected).filter(Boolean).length;

  async function login(e: FormEvent) {
    e.preventDefault();
    setErr("");
    try {
      const data = await fetch(`${API}/api/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
      }).then((r) => r.json());
      if (!data.access_token) throw new Error(JSON.stringify(data.detail || data));
      localStorage.setItem("mail_token", data.access_token);
      setToken(data.access_token);
    } catch (ex) {
      setErr(String(ex));
    }
  }

  async function load(keepOpen = false) {
    if (!token) return;
    const data = await api(`/api/v1/mailbox/folders/${folder}`, token);
    setItems(data);
    if (!keepOpen) setOpen(null);
    setStatus(`${data.length} messages`);
  }

  useEffect(() => {
    if (!token) return;
    load().catch((ex) => {
      const msg = String(ex);
      if (msg.includes("AUTH_401")) {
        setToken("");
        setErr("Session expired — sign in again.");
        return;
      }
      setErr(msg);
    });
  }, [token, folder]);

  useEffect(() => {
    if (!token || !autoRefresh) return;
    const id = window.setInterval(() => {
      load(true).catch(() => undefined);
    }, 5000);
    return () => window.clearInterval(id);
  }, [token, folder, autoRefresh]);

  if (!token) {
    return (
      <div className="login-wrap">
        <form className="login-card" onSubmit={login}>
          <div className="brand">
            <div className="brand-mark">G</div>
            <div>
              <h1>Guardian Mail</h1>
              <p>Mailpit-style mailbox · scanned by PhishProof</p>
            </div>
          </div>
          <label>Email</label>
          <input value={email} onChange={(e) => setEmail(e.target.value)} />
          <label>Password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          {err && <p className="error">{err}</p>}
          <button className="btn btn-primary" type="submit">
            Sign in
          </button>
          <p className="hint">Demo: user@example.com / changeme1</p>
          <p className="hint">
            Company B: <a href={MAILPIT_URL} target="_blank" rel="noreferrer">Inbox</a>
            {" · "}
            <a href={`${MAILPIT_URL}/compose`} target="_blank" rel="noreferrer">Send</a>
          </p>
        </form>
      </div>
    );
  }

  async function sendCompose(e: FormEvent) {
    e.preventDefault();
    setErr("");
    setStatus("");
    try {
      const created = await api("/api/v1/mailbox/compose", token, {
        method: "POST",
        body: JSON.stringify({ recipient: to, subject, body }),
      });
      const decision = created.decision || "PASS";
      setStatus(`Sent to ${to}: ${decision}`);
      setCompose(false);
      setSubject("");
      setBody("");
      setFolder(decision === "PASS" || decision === "SOFT_PASS" ? "sent" : "quarantine");
      await load();
    } catch (ex) {
      const msg = String(ex);
      if (msg.includes("AUTH_401")) {
        setToken("");
        setErr("Session expired — sign in again.");
        return;
      }
      setErr(msg);
    }
  }

  return (
    <div className="mp-app">
      <aside className="mp-side">
        <div className="mp-brand">
          <div className="brand-mark">G</div>
          <div>
            <strong>Guardian Mail</strong>
            <small>PhishProof SMTP demo</small>
          </div>
        </div>

        <button
          className="mp-compose"
          onClick={() => {
            setCompose(true);
            setOpen(null);
            setTo(DEMO_RECIPIENT);
          }}
        >
          Compose
        </button>

        <div className="mp-nav-label">Mailbox</div>
        {folders.map((f) => (
          <button
            key={f.id}
            className={`mp-folder ${folder === f.id ? "active" : ""}`}
            onClick={() => {
              setFolder(f.id);
              setCompose(false);
              setSelected({});
            }}
          >
            <span>{f.label}</span>
            <em>{f.hint}</em>
          </button>
        ))}

        <div className="mp-nav-label">Tags</div>
        <div className="mp-tags">
          {["PASS", "QUARANTINE", "HARD_BLOCK", "HUMAN_REVIEW"].map((tag) => (
            <button key={tag} className={chipClass(tag)} onClick={() => setQ(tag)}>
              {tag}
            </button>
          ))}
        </div>

        <div className="mp-side-foot">
          <a href={MAILPIT_URL} target="_blank" rel="noreferrer">
            Company B inbox
          </a>
          <a href={`${MAILPIT_URL}/compose`} target="_blank" rel="noreferrer">
            Send from Company B
          </a>
          <a href="http://localhost:5174" target="_blank" rel="noreferrer">
            Open SOC
          </a>
          <button
            className="linkish"
            onClick={() => {
              localStorage.removeItem("mail_token");
              setToken("");
            }}
          >
            Sign out
          </button>
        </div>
      </aside>

      <section className="mp-main">
        <header className="mp-toolbar">
          <div className="mp-search">
            <span>⌕</span>
            <input
              placeholder="Search from, to, subject, decision…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
          <label className="mp-check">
            <input type="checkbox" checked={autoRefresh} onChange={(e) => setAutoRefresh(e.target.checked)} />
            Live
          </label>
          <button className="btn ghost" onClick={() => load(true)}>
            Refresh
          </button>
          <button
            className="btn ghost"
            disabled={!selectedCount}
            onClick={() => {
              setSelected({});
              setStatus(`Cleared selection (${selectedCount})`);
            }}
          >
            Clear ({selectedCount})
          </button>
          <div className="mp-status">{status}</div>
        </header>

        <div className="mp-split">
          <div className="mp-list">
            <div className="mp-list-head">
              <span>From</span>
              <span>Subject</span>
              <span>To</span>
              <span>When</span>
            </div>
            {filtered.map((m) => (
              <div
                key={m.id}
                className={`mp-row ${open?.id === m.id ? "on" : ""}`}
                onClick={async () => {
                  setCompose(false);
                  setViewTab("text");
                  setOpen(await api(`/api/v1/mailbox/messages/${m.id}`, token));
                }}
              >
                <input
                  type="checkbox"
                  checked={!!selected[m.id]}
                  onClick={(e) => e.stopPropagation()}
                  onChange={(e) => setSelected((s) => ({ ...s, [m.id]: e.target.checked }))}
                />
                <div className="col from" title={m.sender_address}>
                  {m.sender_address}
                </div>
                <div className="col subject">
                  <strong>{m.subject || "(no subject)"}</strong>
                  {m.decision && <span className={chipClass(m.decision)}>{m.decision}</span>}
                  {m.direction && <span className="tag dim">{m.direction}</span>}
                </div>
                <div className="col to" title={m.recipient_address}>
                  {m.recipient_address}
                </div>
                <div className="col when">{fmtTime(m.received_at)}</div>
              </div>
            ))}
            {!filtered.length && <div className="empty">No messages match this mailbox view.</div>}
          </div>

          <div className="mp-read">
            {compose ? (
              <form className="compose-pane" onSubmit={sendCompose}>
                <div className="read-title">
                  <h2>New message</h2>
                </div>
                <p className="meta">
                  From {email}. Scanned by Guardian, then sent through Postfix. Use Company B’s own compose at{" "}
                  <a href={`${MAILPIT_URL}/compose`} target="_blank" rel="noreferrer">
                    {MAILPIT_URL}/compose
                  </a>{" "}
                  to send the other way.
                </p>
                <label>To</label>
                <input value={to} onChange={(e) => setTo(e.target.value)} required />
                <label>Subject</label>
                <input value={subject} onChange={(e) => setSubject(e.target.value)} required />
                <label>Message</label>
                <textarea rows={14} value={body} onChange={(e) => setBody(e.target.value)} required />
                <div className="row-actions">
                  <button className="btn btn-primary" type="submit">
                    Send
                  </button>
                  <button className="btn ghost" type="button" onClick={() => setCompose(false)}>
                    Cancel
                  </button>
                </div>
              </form>
            ) : open ? (
              <>
                <div className="read-title">
                  <h2>{open.subject || "(no subject)"}</h2>
                  {open.decision && <span className={chipClass(open.decision)}>{open.decision}</span>}
                </div>
                <div className="meta-grid">
                  <div><span>From</span><strong>{open.sender_address}</strong></div>
                  <div><span>To</span><strong>{open.recipient_address}</strong></div>
                  <div><span>Date</span><strong>{fmtTime(open.received_at)}</strong></div>
                  <div><span>Path</span><strong>{open.ingestion_path || "—"} · {open.direction}</strong></div>
                  <div><span>Risk</span><strong>{open.fused_risk_score ?? "—"} · {open.confidence_state || "—"}</strong></div>
                </div>

                <div className="mp-tabs">
                  {(["html", "text", "headers", "raw"] as ViewTab[]).map((tab) => (
                    <button key={tab} className={viewTab === tab ? "on" : ""} onClick={() => setViewTab(tab)}>
                      {tab === "html" ? "HTML" : tab === "text" ? "Text" : tab === "headers" ? "Headers" : "Raw"}
                    </button>
                  ))}
                </div>

                <div className="mp-view">
                  {viewTab === "html" && (
                    <iframe
                      title="html-preview"
                      sandbox=""
                      srcDoc={`<pre style="font:14px/1.5 ui-sans-serif,system-ui;white-space:pre-wrap;padding:16px;color:#111">${(open.body_plain || "")
                        .replace(/&/g, "&amp;")
                        .replace(/</g, "&lt;")
                        .replace(/>/g, "&gt;")}</pre>`}
                    />
                  )}
                  {viewTab === "text" && <pre className="body-text">{open.body_plain || "(empty)"}</pre>}
                  {viewTab === "headers" && <pre className="body-text">{open.raw_headers || "(no headers stored)"}</pre>}
                  {viewTab === "raw" && (
                    <pre className="body-text">
                      {`${open.raw_headers || ""}\n\n${open.body_plain || ""}`}
                    </pre>
                  )}
                </div>

                {(open.urls?.length || open.attachments?.length) ? (
                  <div className="mp-extra">
                    {!!open.urls?.length && (
                      <div>
                        <span className="eyebrow">Links</span>
                        <ul>{open.urls.map((u) => <li key={u}>{u}</li>)}</ul>
                      </div>
                    )}
                    {!!open.attachments?.length && (
                      <div>
                        <span className="eyebrow">Attachments</span>
                        <ul>{open.attachments.map((a) => <li key={a}>{a}</li>)}</ul>
                      </div>
                    )}
                  </div>
                ) : null}
              </>
            ) : (
              <div className="empty center">
                <h3>Select a message</h3>
                <p>
                  One Compose button sends from Guardian. To send the other way, open{" "}
                  <a href={`${MAILPIT_URL}/compose`} target="_blank" rel="noreferrer">
                    Company B Compose
                  </a>
                  .
                </p>
              </div>
            )}
            {err && <p className="error">{err}</p>}
          </div>
        </div>
      </section>
    </div>
  );
}

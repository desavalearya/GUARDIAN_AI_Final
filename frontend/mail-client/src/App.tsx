import { FormEvent, useEffect, useMemo, useState } from "react";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

type Msg = {
  id: string;
  received_at: string;
  sender_address: string;
  recipient_address: string;
  subject: string;
  decision?: string | null;
  fused_risk_score?: number | null;
};

type Detail = Msg & {
  body_plain: string;
  confidence_state?: string | null;
};

async function api(path: string, token: string, init?: RequestInit) {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(init?.headers || {}),
    },
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function chipClass(decision?: string | null) {
  if (!decision) return "chip";
  if (decision === "PASS" || decision === "SOFT_PASS") return "chip ok";
  if (decision === "HUMAN_REVIEW" || decision === "QUARANTINE") return "chip warn";
  return "chip bad";
}

export default function App() {
  const [email, setEmail] = useState("user@example.com");
  const [password, setPassword] = useState("changeme1");
  const [token, setToken] = useState(localStorage.getItem("mail_token") || "");
  const [folder, setFolder] = useState("inbox");
  const [items, setItems] = useState<Msg[]>([]);
  const [open, setOpen] = useState<Detail | null>(null);
  const [err, setErr] = useState("");
  const [compose, setCompose] = useState(false);
  const [to, setTo] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [q, setQ] = useState("");

  const folders = useMemo(
    () => [
      { id: "inbox", label: "Inbox" },
      { id: "sent", label: "Sent" },
      { id: "quarantine", label: "Quarantine" },
    ],
    []
  );

  const filtered = items.filter(
    (m) =>
      !q ||
      m.subject.toLowerCase().includes(q.toLowerCase()) ||
      m.sender_address.toLowerCase().includes(q.toLowerCase())
  );

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

  async function load() {
    if (!token) return;
    const data = await api(`/api/v1/mailbox/folders/${folder}`, token);
    setItems(data);
    setOpen(null);
  }

  useEffect(() => {
    if (token) load().catch((ex) => setErr(String(ex)));
  }, [token, folder]);

  if (!token) {
    return (
      <div className="login-wrap">
        <form className="login-card" onSubmit={login}>
          <div className="brand">
            <div className="brand-mark" />
            <div>
              <h1>Guardian Mail</h1>
              <p>Secure workspace mail</p>
            </div>
          </div>
          <label>Email</label>
          <input value={email} onChange={(e) => setEmail(e.target.value)} />
          <label>Password</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          {err && <p className="error">{err}</p>}
          <p style={{ marginTop: 18 }}>
            <button className="btn btn-primary" type="submit">
              Sign in
            </button>
          </p>
          <p style={{ color: "var(--muted)", fontSize: 12 }}>Demo: user@example.com / changeme1</p>
        </form>
      </div>
    );
  }

  const initial = (email[0] || "U").toUpperCase();

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand" style={{ margin: 0 }}>
          <div className="brand-mark" />
          <strong>Guardian Mail</strong>
        </div>
        <div className="search">
          <span style={{ color: "var(--muted)" }}>⌕</span>
          <input placeholder="Search mail" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <button
          className="btn btn-ghost"
          onClick={() => {
            localStorage.removeItem("mail_token");
            setToken("");
          }}
        >
          Sign out
        </button>
        <div className="avatar">{initial}</div>
      </header>

      <div className="body">
        <aside className="nav">
          <button
            className="compose-btn"
            onClick={() => {
              setCompose(true);
              setOpen(null);
            }}
          >
            ✎ Compose
          </button>
          {folders.map((f) => (
            <button
              key={f.id}
              className={`folder ${folder === f.id ? "active" : ""}`}
              onClick={() => {
                setFolder(f.id);
                setCompose(false);
              }}
            >
              {f.label}
            </button>
          ))}
        </aside>

        <section className="list">
          {filtered.map((m) => (
            <div
              key={m.id}
              className={open?.id === m.id ? "list-item on" : "list-item"}
              onClick={async () => {
                setCompose(false);
                setOpen(await api(`/api/v1/mailbox/messages/${m.id}`, token));
              }}
            >
              <div className="row1">
                <span>{m.sender_address}</span>
                {m.decision && <span className={chipClass(m.decision)}>{m.decision}</span>}
              </div>
              <div className="sub">{m.subject || "(no subject)"}</div>
            </div>
          ))}
          {!filtered.length && <div className="empty">No messages in {folder}.</div>}
        </section>

        <section className="read">
          {compose ? (
            <form
              className="compose-pane"
              onSubmit={async (e) => {
                e.preventDefault();
                setErr("");
                try {
                  await api("/api/v1/mailbox/compose", token, {
                    method: "POST",
                    body: JSON.stringify({ recipient: to, subject, body }),
                  });
                  setCompose(false);
                  setSubject("");
                  setBody("");
                  setFolder("sent");
                } catch (ex) {
                  setErr(String(ex));
                }
              }}
            >
              <h2>New message</h2>
              <p className="meta">Scanned by Guardian, then submitted through Postfix (DKIM-signed).</p>
              <input value={to} onChange={(e) => setTo(e.target.value)} placeholder="To (e.g. you@gmail.com)" required />
              <input value={subject} onChange={(e) => setSubject(e.target.value)} placeholder="Subject" required />
              <textarea rows={14} value={body} onChange={(e) => setBody(e.target.value)} placeholder="Write your message" required />
              <div>
                <button className="btn btn-primary" type="submit">
                  Send
                </button>
              </div>
            </form>
          ) : open ? (
            <>
              <h2>{open.subject}</h2>
              <div className="meta">
                <strong>{open.sender_address}</strong>
                <div>
                  To {open.recipient_address} · {open.decision} · risk {open.fused_risk_score ?? "—"} ·{" "}
                  {open.confidence_state}
                </div>
              </div>
              <div className="body-text">{open.body_plain}</div>
            </>
          ) : (
            <div className="empty">Select a conversation. Quarantined mail stays out of Inbox until an analyst releases it.</div>
          )}
          {err && <p className="error">{err}</p>}
        </section>
      </div>
    </div>
  );
}

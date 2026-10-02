import { FormEvent, useEffect, useMemo, useState } from "react";
import { type Lang, LANGUAGES, getTranslations } from "./i18n";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

type Item = {
  id: string;
  received_at: string;
  sender_address: string;
  recipient_address?: string;
  subject: string;
  direction?: string;
  ingestion_path?: string | null;
  decision?: string | null;
  fused_risk_score?: number | null;
  confidence_state?: string | null;
  review_queue?: string | null;
};

type Detail = Item & {
  body_plain: string;
  detectors: { detector_name: string; raw_score: number; verdict: string; explanation: string; evidence?: Record<string, unknown> }[];
  agreement_metric?: number | null;
  evidence_sha256?: string;
  secret_flags?: Record<string, boolean>;
  case_ref?: string | null;
  vault_preserved?: boolean;
  custody?: { action: string; role: string; at: string }[];
  analysis_mode?: string;
  fast_path_ms?: number;
  deep_path_ms?: number;
  total_analysis_ms?: number;
  deep_status?: string;
  models_run?: string[];
  siem_status?: string;
  unlock_status?: string | null;
  fraud_dna?: {
    fuzzy_hash: string;
    embedding_version: string;
    technique_tags: string[];
    infrastructure_keys: string[];
    nearest_email_id?: string | null;
    similarity: number;
  } | null;
};

type CaseRow = {
  id: string;
  case_ref: string;
  email_id: string;
  subject: string;
  sender_address: string;
  decision?: string | null;
  bank: string;
  amount_lost: string;
  district: string;
};

type Campaign = {
  id: string;
  name: string;
  keys: string[];
  email_count: number;
  subjects: string[];
  dna_summary?: Record<string, unknown>;
  growth_rate_flag?: boolean;
};
type MapPoint = { id: string; lat: number; lon: number; label: string; asn: string; class: string; decision?: string | null };
type CampaignGraph = {
  nodes: { id: string; kind: "campaign" | "email"; label: string; decision?: string; count?: number; growth_rate_flag?: boolean }[];
  edges: { source: string; target: string; kind: string; weight?: number }[];
};

async function api(path: string, token: string, init?: RequestInit) {
  const res = await fetch(`${API}${path}`, {
    ...init,
    headers: { Authorization: `Bearer ${token}`, ...(init?.headers || {}) },
  });
  if (res.status === 401) throw new Error("AUTH_401");
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function pill(decision?: string | null) {
  if (!decision) return "pill";
  if (decision === "PASS" || decision === "SOFT_PASS") return "pill ok";
  if (decision === "HUMAN_REVIEW" || decision === "QUARANTINE") return "pill warn";
  return "pill bad";
}

function CampaignGraphView({ graph }: { graph: CampaignGraph }) {
  const nodes = graph.nodes.slice(0, 24);
  const width = 760;
  const height = 360;
  const positions = new Map(
    nodes.map((node, index) => {
      const angle = (index / Math.max(nodes.length, 1)) * Math.PI * 2;
      const radius = node.kind === "campaign" ? 95 : 145;
      return [
        node.id,
        {
          x: width / 2 + Math.cos(angle) * radius,
          y: height / 2 + Math.sin(angle) * radius,
        },
      ] as const;
    })
  );
  if (!nodes.length) {
    return <div className="empty-state">Upload related suspicious emails to build the Fraud DNA graph.</div>;
  }
  return (
    <svg className="campaign-svg" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="Fraud DNA campaign graph">
      {graph.edges.map((edge, index) => {
        const from = positions.get(edge.source);
        const to = positions.get(edge.target);
        if (!from || !to) return null;
        return (
          <line
            key={`${edge.source}-${edge.target}-${index}`}
            x1={from.x}
            y1={from.y}
            x2={to.x}
            y2={to.y}
            className={edge.kind === "dna_similarity" ? "dna-edge" : "member-edge"}
          />
        );
      })}
      {nodes.map((node) => {
        const pos = positions.get(node.id)!;
        return (
          <g key={node.id} transform={`translate(${pos.x},${pos.y})`}>
            <circle r={node.kind === "campaign" ? 26 : 18} className={`graph-circle ${node.kind}`} />
            <text y={node.kind === "campaign" ? 40 : 31} textAnchor="middle">
              {node.label.slice(0, 22)}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

export default function App() {
  const [email, setEmail] = useState("analyst@example.com");
  const [password, setPassword] = useState("changeme1");
  const [token, setToken] = useState(localStorage.getItem("soc_token") || "");
  const [tab, setTab] = useState<"threats" | "high" | "uncertain" | "cases" | "map" | "mail" | "sent" | "lab">("threats");
  const [rows, setRows] = useState<Item[]>([]);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [err, setErr] = useState("");
  const [alerts, setAlerts] = useState<{ count: number; items: { id: string; subject: string; decision?: string; from: string }[] }>({ count: 0, items: [] });
  const [cases, setCases] = useState<CaseRow[]>([]);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [campaignGraph, setCampaignGraph] = useState<CampaignGraph>({ nodes: [], edges: [] });
  const [points, setPoints] = useState<MapPoint[]>([]);
  const [reportOut, setReportOut] = useState("");
  const [intake, setIntake] = useState({ victim_mobile: "", amount_lost: "", bank: "", incident_date: "", district: "MH" });
  const [labText, setLabText] = useState("Urgent: verify your account and click here");
  const [labOut, setLabOut] = useState("");
  const [lang, setLang] = useState<Lang>(
    (localStorage.getItem("soc_lang") as Lang) || "en"
  );

  const t = getTranslations(lang);

  function switchLang(l: Lang) {
    setLang(l);
    localStorage.setItem("soc_lang", l);
  }

  const stats = useMemo(() => {
    const total = rows.length;
    const blocked = rows.filter((r) => r.decision === "BLOCK" || r.decision === "HARD_BLOCK").length;
    const review = rows.filter((r) => r.decision === "HUMAN_REVIEW" || r.decision === "QUARANTINE").length;
    const avg =
      total === 0 ? 0 : Math.round(rows.reduce((s, r) => s + (r.fused_risk_score || 0), 0) / total);
    return { total, blocked, review, avg };
  }, [rows]);

  async function login(e: FormEvent) {
    e.preventDefault();
    setErr("");
    const data = await fetch(`${API}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    }).then((r) => r.json());
    if (!data.access_token) return setErr(JSON.stringify(data));
    localStorage.setItem("soc_token", data.access_token);
    setToken(data.access_token);
  }

  async function load() {
    setErr("");
    try {
      setAlerts(await api("/api/v1/soc/alerts", token));
      if (tab === "cases") {
        setCases(await api("/api/v1/soc/cases", token));
        setDetail(null);
        return;
      }
      if (tab === "map") {
        setCampaigns(await api("/api/v1/soc/campaigns", token));
        setCampaignGraph(await api("/api/v1/soc/campaigns/graph", token));
        setPoints(await api("/api/v1/soc/map-points", token));
        setDetail(null);
        return;
      }
      const path =
        tab === "high"
          ? "/api/v1/soc/queues/HIGH_RISK"
          : tab === "uncertain"
            ? "/api/v1/soc/queues/UNCERTAIN"
            : "/api/v1/soc/emails";
      setRows(await api(path, token));
      setDetail(null);
    } catch (e) {
      const msg = String(e || "");
      if (msg.includes("AUTH_401")) {
        localStorage.removeItem("soc_token");
        setToken("");
        setErr(t.errSessionExpired);
        return;
      }
      setErr(msg);
    }
  }

  useEffect(() => {
    if (token && tab !== "lab") load();
  }, [token, tab]);

  useEffect(() => {
    if (tab !== "map" || !points.length) return;
    const L = (window as unknown as { L?: any }).L;
    const el = document.getElementById("pp-map");
    if (!L || !el) return;
    el.innerHTML = "";
    const map = L.map(el).setView([points[0].lat, points[0].lon], 3);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: "&copy; OpenStreetMap",
    }).addTo(map);
    points.forEach((p) => {
      L.marker([p.lat, p.lon])
        .addTo(map)
        .bindPopup(`${p.label}<br/>${p.asn || ""}<br/>${p.class} · ${p.decision || ""}<br/>Infrastructure hop, not attacker home.`);
    });
    return () => {
      map.remove();
    };
  }, [tab, points]);

  if (!token) {
    return (
      <div className="login-wrap">
        <form className="login-card" onSubmit={login}>
          <div className="lang-switcher login-lang">
            {LANGUAGES.map((l) => (
              <button
                key={l.code}
                type="button"
                className={`lang-btn${lang === l.code ? " active" : ""}`}
                onClick={() => switchLang(l.code)}
              >
                {l.label}
              </button>
            ))}
          </div>
          <h1>{t.appTitle}</h1>
          <p>{t.appSubtitle}</p>
          <label>{t.labelEmail}</label>
          <input value={email} onChange={(e) => setEmail(e.target.value)} />
          <label>{t.labelPassword}</label>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          <p style={{ marginTop: 16 }}>
            <button className="btn btn-primary" type="submit">
              {t.btnSignIn}
            </button>
          </p>
          <p style={{ color: "var(--muted)", fontSize: 12 }}>{t.demoHint}</p>
          {err && <p className="err">{err}</p>}
        </form>
      </div>
    );
  }

  return (
    <div className="shell">
      <aside className="side">
        <h3>{t.sidebarTitle}</h3>
        {(
          [
            ["threats", t.navThreats],
            ["high", t.navHighRisk],
            ["uncertain", t.navUncertain],
            ["cases", t.navCases],
            ["map", t.navMap],
            ["mail", "Inbox"],
            ["sent", "Sent"],
            ["lab", t.navModelLab],
          ] as const
        ).map(([id, label]) => (
          <button key={id} className={tab === id ? "on" : ""} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
        <button
          onClick={() => {
            localStorage.removeItem("soc_token");
            setToken("");
          }}
        >
          {t.btnSignOut}
        </button>

        <div className="lang-switcher side-lang">
          {LANGUAGES.map((l) => (
            <button
              key={l.code}
              type="button"
              className={`lang-btn${lang === l.code ? " active" : ""}`}
              onClick={() => switchLang(l.code)}
            >
              {l.label}
            </button>
          ))}
        </div>
      </aside>

      <main className="main">
        <div className="hero">
          <div>
            <h1>
              {tab === "lab"
                ? t.heroTitleLab
                : tab === "mail"
                  ? "Inbox"
                  : tab === "sent"
                    ? "Sent"
                    : t.heroTitleThreats}
            </h1>
            <p>
              {tab === "mail"
                ? "Received mail only. Messages composed in Mailpit are listed under Sent."
                : tab === "sent"
                  ? "Mail sent from Company B (Mailpit) through Guardian."
                  : t.heroSubtitle}
            </p>
          </div>
        </div>

        {alerts.count > 0 && tab !== "lab" && (
          <div className="banner">
            {t.alertBanner}: {alerts.items.map((a) => `${a.decision} · ${a.subject}`).join(" | ")}
          </div>
        )}

        {tab !== "lab" && (
          <div className="cards">
            <div className="stat"><div className="k">{t.statVisible}</div><div className="v">{stats.total}</div></div>
            <div className="stat"><div className="k">{t.statBlocked}</div><div className="v">{stats.blocked}</div></div>
            <div className="stat"><div className="k">{t.statReview}</div><div className="v">{stats.review}</div></div>
            <div className="stat"><div className="k">{t.statAvgRisk}</div><div className="v">{stats.avg}</div></div>
          </div>
        )}

        <div className="panel">
          {tab === "cases" ? (
            <table>
              <thead>
                <tr>
                  <th>Case</th>
                  <th>{t.thFrom}</th>
                  <th>{t.thSubject}</th>
                  <th>{t.thDecision}</th>
                  <th>Bank</th>
                </tr>
              </thead>
              <tbody>
                {cases.map((c) => (
                  <tr
                    key={c.id}
                    onClick={async () => {
                      setTab("threats");
                      setReportOut("");
                      setDetail(await api(`/api/v1/soc/emails/${c.email_id}`, token));
                    }}
                  >
                    <td>{c.case_ref}</td>
                    <td>{c.sender_address}</td>
                    <td>{c.subject}</td>
                    <td><span className={pill(c.decision)}>{c.decision}</span></td>
                    <td>{c.bank || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : tab === "map" ? (
            <div className="intel-layout">
              <section className="intel-card">
                <div className="section-heading">
                  <div><span className="eyebrow">Infrastructure intelligence</span><h3>Probable relay origin</h3></div>
                  <span className="status-chip">{points.length} mapped</span>
                </div>
                <div id="pp-map" className="map-box" />
                <p className="section-note">{t.originDisclaimer}</p>
              </section>
              <section className="intel-card">
                <div className="section-heading">
                  <div><span className="eyebrow">Fraud DNA</span><h3>Campaign relationships</h3></div>
                  <span className="status-chip">{campaignGraph.edges.length} links</span>
                </div>
                <CampaignGraphView graph={campaignGraph} />
                <div className="campaign-list">
                  {campaigns.map((c) => (
                    <article key={c.id} className="campaign-row">
                      <div>
                        <strong>{c.name}</strong>
                        <span>{c.email_count} messages · {(c.keys || []).slice(0, 3).join(" · ")}</span>
                      </div>
                      {c.growth_rate_flag && <span className="pill bad">Growing</span>}
                    </article>
                  ))}
                </div>
              </section>
            </div>
          ) : tab === "mail" || tab === "sent" ? (
            <div>
              <div className="section-heading" style={{ marginBottom: 12 }}>
                <div>
                  <span className="eyebrow">Guardian ↔ Company B</span>
                  <h3>{tab === "sent" ? "Sent from Company B" : "Inbox"}</h3>
                </div>
                <span className="status-chip">
                  {(tab === "sent"
                    ? rows.filter((r) => (r.sender_address || "").toLowerCase().endsWith("@company-b.test"))
                    : rows.filter((r) => !(r.sender_address || "").toLowerCase().endsWith("@company-b.test"))
                  ).length}{" "}
                  messages
                </span>
              </div>
              <p className="section-note" style={{ marginBottom: 16 }}>
                {tab === "sent"
                  ? "These were composed in Mailpit and released through Guardian. They stay out of the Mailpit inbox."
                  : "Received mail. Company B messages you send from Mailpit appear under Sent."}
              </p>
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Direction</th>
                    <th>From</th>
                    <th>To</th>
                    <th>Subject</th>
                    <th>Path</th>
                    <th>Decision</th>
                  </tr>
                </thead>
                <tbody>
                  {(tab === "sent"
                    ? rows.filter((r) => (r.sender_address || "").toLowerCase().endsWith("@company-b.test"))
                    : rows.filter((r) => !(r.sender_address || "").toLowerCase().endsWith("@company-b.test"))
                  ).map((r) => (
                    <tr
                      key={r.id}
                      onClick={async () => {
                        setTab("threats");
                        setReportOut("");
                        setDetail(await api(`/api/v1/soc/emails/${r.id}`, token));
                      }}
                    >
                      <td>{r.received_at?.slice(0, 19).replace("T", " ")}</td>
                      <td><span className="status-chip">{r.direction || "—"}</span></td>
                      <td>{r.sender_address}</td>
                      <td>{r.recipient_address || "—"}</td>
                      <td>{r.subject}</td>
                      <td>{r.ingestion_path || "—"}</td>
                      <td><span className={pill(r.decision)}>{r.decision}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : tab === "lab" ? (
            <div className="lab">
              <h3>{t.labHeading}</h3>
              <p style={{ color: "var(--muted)", marginBottom: 24 }}>{t.labSubtitle}</p>

              <div className="lab-section">
                <h4>{t.labTextTitle}</h4>
                <p style={{ fontSize: 14, color: "var(--muted)" }}>{t.labTextDesc}</p>
                <textarea
                  rows={3}
                  value={labText}
                  onChange={(e) => setLabText(e.target.value)}
                  placeholder={t.labTextPlaceholder}
                />
                <button
                  className="btn btn-primary"
                  onClick={async () => {
                    try {
                      setLabOut(t.labAnalyzing);
                      const out = await api("/api/v1/lab/scan/text", token, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ text: labText }),
                      });
                      setLabOut(JSON.stringify(out, null, 2));
                    } catch (e) {
                      setLabOut(`Error: ${e}`);
                    }
                  }}
                >
                  {t.btnAnalyzeText}
                </button>
              </div>

              <div className="lab-section">
                <h4>{t.labOfficeTitle}</h4>
                <p style={{ fontSize: 14, color: "var(--muted)" }}>{t.labOfficeDesc}</p>
                <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 8 }}>{t.labOfficeUploadHint}</p>
                <input
                  type="file"
                  accept=".doc,.docx,.xls,.xlsx,.ppt,.pptx"
                  onChange={async (e) => {
                    const file = e.target.files?.[0];
                    if (!file) return;
                    try {
                      setLabOut(`${t.labScanning} ${file.name}...`);
                      const fd = new FormData();
                      fd.append("file", file);
                      const res = await fetch(`${API}/api/v1/lab/scan/office`, {
                        method: "POST",
                        headers: { Authorization: `Bearer ${token}` },
                        body: fd,
                      });
                      if (res.status === 401) throw new Error("AUTH_401");
                      if (!res.ok) throw new Error(await res.text());
                      const result = await res.json();
                      setLabOut(JSON.stringify(result, null, 2));
                    } catch (e) {
                      const msg = String(e);
                      if (msg.includes("AUTH_401")) {
                        localStorage.removeItem("soc_token");
                        setToken("");
                      }
                      setLabOut(`Error: ${e}`);
                    }
                  }}
                />
              </div>

              <div className="lab-section">
                <h4>{t.labPdfTitle}</h4>
                <p style={{ fontSize: 14, color: "var(--muted)" }}>{t.labPdfDesc}</p>
                <p style={{ fontSize: 13, color: "var(--muted)", marginBottom: 8 }}>{t.labPdfUploadHint}</p>
                <input
                  type="file"
                  accept=".pdf"
                  onChange={async (e) => {
                    const file = e.target.files?.[0];
                    if (!file) return;
                    try {
                      setLabOut(`${t.labScanning} ${file.name}...`);
                      const fd = new FormData();
                      fd.append("file", file);
                      const res = await fetch(`${API}/api/v1/lab/scan/pdf`, {
                        method: "POST",
                        headers: { Authorization: `Bearer ${token}` },
                        body: fd,
                      });
                      if (res.status === 401) throw new Error("AUTH_401");
                      if (!res.ok) throw new Error(await res.text());
                      const result = await res.json();
                      setLabOut(JSON.stringify(result, null, 2));
                    } catch (e) {
                      const msg = String(e);
                      if (msg.includes("AUTH_401")) {
                        localStorage.removeItem("soc_token");
                        setToken("");
                      }
                      setLabOut(`Error: ${e}`);
                    }
                  }}
                />
              </div>

              <pre>{labOut || t.labResultsPlaceholder}</pre>
            </div>
          ) : (
            <>
              <div style={{ marginBottom: 16 }}>
                <label className="btn btn-primary" style={{ cursor: "pointer" }}>
                  {t.btnUploadEml}
                  <input
                    type="file"
                    accept=".eml,.txt"
                    style={{ display: "none" }}
                    onChange={async (e) => {
                      const file = e.target.files?.[0];
                      e.target.value = "";
                      if (!file) return;
                      setErr("");
                      try {
                        const fd = new FormData();
                        fd.append("file", file);
                        const res = await fetch(`${API}/api/v1/soc/upload-eml`, {
                          method: "POST",
                          headers: { Authorization: `Bearer ${token}` },
                          body: fd,
                        });
                        if (res.status === 401) throw new Error("AUTH_401");
                        if (!res.ok) throw new Error(await res.text());
                        const created = await res.json();
                        await load();
                        setReportOut("");
                        setDetail(created);
                      } catch (err) {
                        const msg = String(err || "");
                        if (msg.includes("AUTH_401")) {
                          localStorage.removeItem("soc_token");
                          setToken("");
                          setErr(t.errSessionExpired);
                          return;
                        }
                        setErr(msg);
                      }
                    }}
                  />
                </label>
                <p style={{ color: "var(--muted)", fontSize: 13, marginTop: 8 }}>{t.uploadEmlHint}</p>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>{t.thTime}</th>
                    <th>{t.thFrom}</th>
                    <th>{t.thSubject}</th>
                    <th>{t.thRisk}</th>
                    <th>{t.thAuthConf}</th>
                    <th>{t.thDecision}</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id} onClick={async () => {
                      setReportOut("");
                      setDetail(await api(`/api/v1/soc/emails/${r.id}`, token));
                    }}>
                      <td>{r.received_at?.slice(0, 19).replace("T", " ")}</td>
                      <td>{r.sender_address}</td>
                      <td>{r.subject}</td>
                      <td>{r.fused_risk_score ?? "—"}</td>
                      <td>{r.confidence_state}</td>
                      <td><span className={pill(r.decision)}>{r.decision}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {detail && (
                <div className="detail">
                  <div className="detail-heading">
                    <div>
                      <span className="eyebrow">Message investigation</span>
                      <h2>{detail.subject}</h2>
                      <p>{detail.sender_address}</p>
                    </div>
                    <div className="decision-stack">
                      <span className={pill(detail.decision)}>{detail.decision}</span>
                      <strong>{detail.fused_risk_score ?? "—"} <small>evidence score</small></strong>
                    </div>
                  </div>
                  <div className="pipeline-strip">
                    <div><span>Analysis</span><strong>{detail.analysis_mode || "full"}</strong></div>
                    <div><span>Fast path</span><strong>{detail.fast_path_ms ?? 0} ms</strong></div>
                    <div><span>Deep path</span><strong>{detail.deep_path_ms ?? 0} ms</strong></div>
                    <div><span>Total</span><strong>{detail.total_analysis_ms ?? 0} ms</strong></div>
                    <div><span>Deep status</span><strong>{detail.deep_status || "complete"}</strong></div>
                    <div><span>SIEM</span><strong>{detail.siem_status || "disabled"}</strong></div>
                  </div>
                  <section className="message-preview">
                    <span className="eyebrow">Redacted message body</span>
                    <p>{detail.body_plain}</p>
                  </section>
                  <div className="report-actions" style={{ display: "flex", flexWrap: "wrap", gap: 8, margin: "12px 0 16px" }}>
                    <button
                      className="btn btn-primary"
                      type="button"
                      onClick={async () => {
                        try {
                          setErr("");
                          setReportOut("Loading forensic report…");
                          const out = await api(`/api/v1/soc/emails/${detail.id}/report`, token);
                          setReportOut(out.report_text || JSON.stringify(out, null, 2));
                        } catch (e) {
                          const msg = String(e);
                          if (msg.includes("AUTH_401")) {
                            localStorage.removeItem("soc_token");
                            setToken("");
                          }
                          setReportOut("");
                          setErr(msg);
                        }
                      }}
                    >
                      {t.btnReport}
                    </button>
                    <button
                      className="btn btn-soft"
                      type="button"
                      onClick={async () => {
                        setDetail(await api(`/api/v1/soc/emails/${detail.id}/preserve`, token, { method: "POST" }));
                      }}
                    >
                      {t.btnPreserve}
                    </button>
                    {!detail.unlock_status && (
                      <button
                        className="btn btn-soft"
                        type="button"
                        onClick={async () => {
                          try {
                            await api(`/api/v1/soc/emails/${detail.id}/unlock/request`, token, {
                              method: "POST",
                              headers: { "Content-Type": "application/json" },
                              body: JSON.stringify({ justification: "Forensic review of preserved exhibit" }),
                            });
                            setDetail(await api(`/api/v1/soc/emails/${detail.id}`, token));
                          } catch (e) { setErr(String(e)); }
                        }}
                      >
                        Request raw access
                      </button>
                    )}
                    {detail.unlock_status === "pending" && (
                      <button
                        className="btn btn-soft"
                        type="button"
                        onClick={async () => {
                          try {
                            await api(`/api/v1/soc/emails/${detail.id}/unlock/approve`, token, { method: "POST" });
                            setDetail(await api(`/api/v1/soc/emails/${detail.id}`, token));
                          } catch (e) { setErr(String(e)); }
                        }}
                      >
                        Approve as second analyst
                      </button>
                    )}
                    {detail.unlock_status === "approved" && (
                      <button
                        className="btn btn-danger"
                        type="button"
                        onClick={async () => {
                          try {
                            const out = await api(`/api/v1/soc/emails/${detail.id}/unlock`, token, { method: "POST" });
                            setReportOut(
                              JSON.stringify(
                                { unlocked: true, warning: out.warning, preview: String(out.raw_message || "").slice(0, 400) },
                                null,
                                2
                              )
                            );
                            setDetail(await api(`/api/v1/soc/emails/${detail.id}`, token));
                          } catch (e) { setErr(String(e)); }
                        }}
                      >
                        {t.btnUnlock}
                      </button>
                    )}
                    <button
                      className="btn btn-soft"
                      type="button"
                      onClick={async () => {
                        setDetail(
                          await api(`/api/v1/soc/emails/${detail.id}/release`, token, {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ notes: "released from SOC" }),
                          })
                        );
                        load();
                      }}
                    >
                      {t.btnRelease}
                    </button>
                    <button
                      className="btn btn-danger"
                      type="button"
                      onClick={async () => {
                        setDetail(
                          await api(`/api/v1/soc/emails/${detail.id}/block`, token, {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ notes: "blocked from SOC" }),
                          })
                        );
                        load();
                      }}
                    >
                      {t.btnBlock}
                    </button>
                  </div>
                  {reportOut && (
                    <pre
                      className="forensic-report"
                      style={{
                        maxHeight: 480,
                        overflow: "auto",
                        whiteSpace: "pre-wrap",
                        fontSize: 12,
                        background: "var(--panel, #0f1419)",
                        border: "1px solid var(--border, #333)",
                        padding: 12,
                        marginBottom: 16,
                      }}
                    >
                      {reportOut}
                    </pre>
                  )}
                  <div className="evidence-summary">
                    <section className="summary-card">
                      <span className="eyebrow">Models actually executed</span>
                      <div className="tag-list">
                        {(detail.models_run || []).map((model) => <span key={model}>{model}</span>)}
                        {!detail.models_run?.length && <em>No model metadata</em>}
                      </div>
                    </section>
                    <section className="summary-card">
                      <span className="eyebrow">Fraud DNA</span>
                      {detail.fraud_dna ? (
                        <>
                          <strong>{Math.round((detail.fraud_dna.similarity || 0) * 100)}% nearest-case similarity</strong>
                          <div className="tag-list">
                            {(detail.fraud_dna.technique_tags || []).map((tag) => <span key={tag}>{tag}</span>)}
                          </div>
                          <small>Fingerprint {detail.fraud_dna.fuzzy_hash} · {detail.fraud_dna.embedding_version}</small>
                        </>
                      ) : (
                        <p>Generated asynchronously for review/quarantine/block decisions.</p>
                      )}
                    </section>
                  </div>
                  {(() => {
                    const origin = detail.detectors.find((d) => d.detector_name === "origin_infra");
                    const ev = (origin?.evidence || {}) as Record<string, unknown>;
                    const geo = (ev.geo || {}) as Record<string, unknown>;
                    if (!origin) return null;
                    return (
                      <div className="det" style={{ marginBottom: 16 }}>
                        <strong>{t.originTitle}</strong>
                        <div>
                          {origin.verdict} · {origin.raw_score}
                        </div>
                        <div style={{ marginTop: 6 }}>{origin.explanation}</div>
                        {ev.earliest_public_ip && (
                          <div style={{ color: "var(--muted)", marginTop: 6 }}>
                            {ev.earliest_public_ip}
                            {ev.asn ? ` · AS${String(ev.asn)}` : ""}
                            {ev.aso ? ` ${String(ev.aso)}` : ""}
                            {ev.infra_class ? ` · ${String(ev.infra_class)}` : ""}
                            {geo.city || geo.country
                              ? ` · ${[geo.city, geo.region, geo.country].filter(Boolean).join(", ")}`
                              : ""}
                          </div>
                        )}
                        <div style={{ color: "var(--muted)", marginTop: 8, fontSize: 13 }}>{t.originDisclaimer}</div>
                      </div>
                    );
                  })()}
                  <div className="section-heading compact">
                    <div><span className="eyebrow">Explainability</span><h3>Detector evidence</h3></div>
                    <span className="status-chip">{detail.detectors.length} signals</span>
                  </div>
                  <div className="grid">
                    {detail.detectors.map((d) => (
                      <div className="det" key={d.detector_name}>
                        <strong>{d.detector_name}</strong>
                        <div>
                          {d.verdict} · {d.raw_score}
                        </div>
                        <div style={{ color: "var(--muted)", marginTop: 6 }}>{d.explanation}</div>
                      </div>
                    ))}
                  </div>
                  <div className="section-heading compact">
                    <div><span className="eyebrow">Cyber Cell workflow</span><h3>Complaint intake</h3></div>
                    {detail.case_ref && <span className="status-chip">{detail.case_ref}</span>}
                  </div>
                  <div className="intake">
                    <input placeholder="Victim mobile" value={intake.victim_mobile} onChange={(e) => setIntake({ ...intake, victim_mobile: e.target.value })} />
                    <input placeholder="Amount lost" value={intake.amount_lost} onChange={(e) => setIntake({ ...intake, amount_lost: e.target.value })} />
                    <input placeholder="Bank" value={intake.bank} onChange={(e) => setIntake({ ...intake, bank: e.target.value })} />
                    <input placeholder="Date" value={intake.incident_date} onChange={(e) => setIntake({ ...intake, incident_date: e.target.value })} />
                    <input placeholder="District" value={intake.district} onChange={(e) => setIntake({ ...intake, district: e.target.value })} />
                    <button
                      className="btn btn-soft"
                      onClick={async () => {
                        await api(`/api/v1/soc/emails/${detail.id}/intake`, token, {
                          method: "POST",
                          headers: { "Content-Type": "application/json" },
                          body: JSON.stringify(intake),
                        });
                        setDetail(await api(`/api/v1/soc/emails/${detail.id}`, token));
                      }}
                    >
                      {t.btnIntake}
                    </button>
                  </div>
                  {detail.case_ref && <p>Case {detail.case_ref} · evidence {detail.evidence_sha256?.slice(0, 16)}…</p>}
                  {detail.secret_flags && Object.values(detail.secret_flags).some(Boolean) && (
                    <p style={{ color: "var(--muted)" }}>Secrets tokenised (flags only, no digits stored).</p>
                  )}
                  {!!detail.custody?.length && (
                    <section className="custody">
                      <span className="eyebrow">Chain of custody</span>
                      <div className="custody-list">
                        {detail.custody.slice().reverse().slice(0, 8).map((event, index) => (
                          <div key={`${event.action}-${event.at}-${index}`}>
                            <strong>{event.action.replaceAll("_", " ")}</strong>
                            <span>{event.role || "system"} · {new Date(event.at).toLocaleString()}</span>
                          </div>
                        ))}
                      </div>
                    </section>
                  )}
                </div>
              )}
            </>
          )}
        </div>
        {err && <p className="err">{err}</p>}
      </main>
    </div>
  );
}

import { FormEvent, useEffect, useMemo, useState } from "react";
import { type Lang, LANGUAGES, getTranslations } from "./i18n";

const API = import.meta.env.VITE_API_URL || "http://localhost:8000";

type Item = {
  id: string;
  received_at: string;
  sender_address: string;
  subject: string;
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

type Campaign = { id: string; name: string; keys: string[]; email_count: number; subjects: string[] };
type MapPoint = { id: string; lat: number; lon: number; label: string; asn: string; class: string; decision?: string | null };

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

export default function App() {
  const [email, setEmail] = useState("analyst@example.com");
  const [password, setPassword] = useState("changeme1");
  const [token, setToken] = useState(localStorage.getItem("soc_token") || "");
  const [tab, setTab] = useState<"threats" | "high" | "uncertain" | "cases" | "map" | "lab">("threats");
  const [rows, setRows] = useState<Item[]>([]);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [err, setErr] = useState("");
  const [alerts, setAlerts] = useState<{ count: number; items: { id: string; subject: string; decision?: string; from: string }[] }>({ count: 0, items: [] });
  const [cases, setCases] = useState<CaseRow[]>([]);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
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
            <h1>{tab === "lab" ? t.heroTitleLab : t.heroTitleThreats}</h1>
            <p>{t.heroSubtitle}</p>
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
            <div>
              <div id="pp-map" className="map-box" />
              <div style={{ padding: 14 }}>
                <h3>Campaign graph</h3>
                {campaigns.map((c) => (
                  <div key={c.id} style={{ marginBottom: 10 }}>
                    <span className="graph-node">{c.name} · {c.email_count} mails</span>
                    <div style={{ color: "var(--muted)", fontSize: 12, marginTop: 4 }}>{(c.keys || []).join(" · ")}</div>
                  </div>
                ))}
                <p style={{ color: "var(--muted)", fontSize: 13 }}>{t.originDisclaimer}</p>
              </div>
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
                      const result = await res.json();
                      setLabOut(JSON.stringify(result, null, 2));
                    } catch (e) {
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
                      const result = await res.json();
                      setLabOut(JSON.stringify(result, null, 2));
                    } catch (e) {
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
                    accept=".eml,.txt,.msg"
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
                    <tr key={r.id} onClick={async () => setDetail(await api(`/api/v1/soc/emails/${r.id}`, token))}>
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
                  <h2 style={{ marginTop: 0 }}>{detail.subject}</h2>
                  <p style={{ color: "var(--muted)" }}>{detail.body_plain}</p>
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
                  {reportOut && <pre style={{ maxHeight: 220, overflow: "auto" }}>{reportOut}</pre>}
                  <p style={{ marginTop: 14 }}>
                    <button
                      className="btn btn-soft"
                      onClick={async () => setReportOut(JSON.stringify(await api(`/api/v1/soc/emails/${detail.id}/report`, token), null, 2))}
                    >
                      {t.btnReport}
                    </button>{" "}
                    <button
                      className="btn btn-soft"
                      onClick={async () => {
                        setDetail(await api(`/api/v1/soc/emails/${detail.id}/preserve`, token, { method: "POST" }));
                      }}
                    >
                      {t.btnPreserve}
                    </button>{" "}
                    <button
                      className="btn btn-danger"
                      onClick={async () => {
                        const out = await api(`/api/v1/soc/emails/${detail.id}/unlock`, token, { method: "POST" });
                        setReportOut(JSON.stringify({ unlocked: true, warning: out.warning, preview: String(out.raw_message || "").slice(0, 400) }, null, 2));
                      }}
                    >
                      {t.btnUnlock}
                    </button>{" "}
                    <button
                      className="btn btn-primary"
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
                    </button>{" "}
                    <button
                      className="btn btn-danger"
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
                  </p>
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

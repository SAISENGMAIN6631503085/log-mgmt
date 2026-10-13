import { useRef, useState } from "react";
import { api, IngestResult, SOURCES, User } from "../api";
import { Icon } from "../components/Icon";
import { fmtNum, go, sourceLabel } from "../util";

// One page that answers "how do I get logs in?": upload a file here, or copy a ready-made
// command for an app (HTTP API) or a device (syslog). Same endpoints as the docs describe.

const MAX_MB = 50;

/** Pre-select the log type from the file name, so most uploads are just "choose file, upload".
 *  The user can still change it. */
function guessSource(name: string): string {
  const n = name.toLowerCase();
  if (/cloudtrail|aws/.test(n)) return "aws";
  if (/m365|o365|office|azure|entra|unified/.test(n)) return "m365";
  if (/crowdstrike|falcon|edr/.test(n)) return "crowdstrike";
  if (/(^|[^a-z])ad([^a-z]|$)|active.?dir|windows|security|evtx/.test(n) || n.endsWith(".csv")) return "ad";
  if (/network|router|switch/.test(n)) return "network";
  if (/firewall|fw|syslog/.test(n) || n.endsWith(".log") || n.endsWith(".txt")) return "firewall";
  if (n.endsWith(".ndjson")) return "crowdstrike";
  return "api";
}

function CodeBlock({ label, code }: { label: string; code: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () =>
    navigator.clipboard?.writeText(code).then(() => {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    });
  return (
    <div className="codeblock">
      <div className="codeblock-head">
        <span>{label}</span>
        <button className="sm ghost" onClick={copy} aria-label={`Copy: ${label}`}>
          <Icon name={copied ? "check" : "copy"} size={14} />{copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre><code>{code}</code></pre>
    </div>
  );
}

function Upload({ user, tenant, tenantName }: { user: User; tenant: string | undefined; tenantName: string }) {
  const [file, setFile] = useState<File | null>(null);
  const [source, setSource] = useState("aws");
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [result, setResult] = useState<{ r: IngestResult; source: string } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const input = useRef<HTMLInputElement>(null);
  const canUpload = user.role === "admin";

  function pick(f: File | undefined) {
    if (!f) return;
    setResult(null);
    setError(f.size > MAX_MB * 1024 * 1024 ? `That file is over ${MAX_MB} MB.` : null);
    setFile(f);
    setSource(guessSource(f.name));
  }

  async function upload() {
    if (!file) return;
    setBusy(true);
    setError(null);
    const form = new FormData();
    form.append("source", source);
    form.append("file", file);
    try {
      const r = await api<IngestResult>("/api/ingest/upload", { method: "POST", body: form, params: { tenant } });
      setResult({ r, source });
      setFile(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>Upload a log file</h2>
          <div className="sub">Exports from AWS CloudTrail, Microsoft 365, Active Directory, CrowdStrike or a firewall.</div>
        </div>
      </div>
      <div className="card-body">
        {!canUpload ? (
          <div className="note"><Icon name="lock" size={16} />Only admins can upload files. You can still view and search everything in {tenantName}.</div>
        ) : (
          <>
            <div
              className={`dropzone ${dragging ? "dragging" : ""} ${file ? "has-file" : ""}`}
              onClick={() => input.current?.click()}
              onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
              onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => { e.preventDefault(); setDragging(false); pick(e.dataTransfer.files[0]); }}
              role="button" tabIndex={0} aria-label="Choose a log file"
            >
              <Icon name={file ? "file" : "upload"} size={26} />
              {file ? (
                <><strong>{file.name}</strong><span>{fmtNum(Math.ceil(file.size / 1024))} KB · click to choose another</span></>
              ) : (
                <><strong>Drop a file here, or click to choose</strong><span>.json, .ndjson, .csv or .log · up to {MAX_MB} MB</span></>
              )}
              <input ref={input} type="file" accept=".json,.ndjson,.jsonl,.csv,.log,.txt" hidden
                     onChange={(e) => { pick(e.target.files?.[0]); e.target.value = ""; }} />
            </div>

            {file && (
              <div className="upload-row">
                <label className="inline-select">
                  <span>Log type</span>
                  <select value={source} onChange={(e) => setSource(e.target.value)} aria-label="Log type">
                    {SOURCES.map((s) => <option key={s} value={s}>{sourceLabel(s)}</option>)}
                  </select>
                </label>
                <span className="muted small">Goes into <strong>{tenantName}</strong></span>
                <button className="primary" onClick={upload} disabled={busy || !!error}>
                  <Icon name="upload" size={16} />{busy ? "Uploading…" : "Upload"}
                </button>
              </div>
            )}
          </>
        )}

        {error && <div className="error-banner" role="alert"><Icon name="alert" size={16} />{error}</div>}

        {result && (
          <div className="upload-result" role="status">
            <div className="upload-result-head">
              <span className={`ok-mark ${result.r.accepted > 0 ? "" : "neutral"}`}><Icon name={result.r.accepted > 0 ? "check" : "info"} size={16} /></span>
              <div>
                <strong>
                  {result.r.accepted > 0
                    ? `${fmtNum(result.r.accepted)} ${sourceLabel(result.source)} ${result.r.accepted === 1 ? "event" : "events"} added to ${tenantName}`
                    : result.r.duplicates > 0
                      ? "Nothing new: this file was already uploaded"
                      : "No events could be read from this file"}
                </strong>
                <div className="muted small">
                  {[
                    result.r.duplicates > 0 && `${fmtNum(result.r.duplicates)} already stored (skipped)`,
                    result.r.time_adjusted > 0 && `${fmtNum(result.r.time_adjusted)} too old for the 7-day window, so stored as "now"`,
                    result.r.rejected_count > 0 && `${fmtNum(result.r.rejected_count)} couldn't be read`,
                  ].filter(Boolean).join(" · ") || "Every line was read and stored."}
                </div>
              </div>
              <button className="sm" onClick={() => go("events", { source: result.source, range: "1h" })}>
                <Icon name="search" size={14} />See them
              </button>
            </div>
            {result.r.rejected.length > 0 && (
              <ul className="rejected-list">
                {result.r.rejected.slice(0, 3).map((x) => <li key={x.index}>Line {x.index + 1}: {x.error}</li>)}
              </ul>
            )}
          </div>
        )}
      </div>
    </section>
  );
}

export function AddLogs({ user, tenant, tenantName }: { user: User; tenant: string | undefined; tenantName: string }) {
  const origin = window.location.origin;
  const host = window.location.hostname;
  const apiExample = `curl ${origin}/ingest \\
  -H "X-API-Key: YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"event_type": "app_login_failed", "user": "alice", "ip": "203.0.113.7"}'`;
  const syslogExample = `echo "<134>$(date '+%b %d %H:%M:%S') fw01 action=deny src=10.0.1.10 dst=8.8.8.8 dpt=53 proto=udp" \\
  | nc -u -w1 ${host} 514`;

  return (
    <>
      <header className="page-header">
        <div>
          <h1>Add logs</h1>
          <p>Three ways to send logs into <strong>{tenantName}</strong>. New events show up in Search within seconds.</p>
        </div>
      </header>
      <div className="page-body">
        <Upload user={user} tenant={tenant} tenantName={tenantName} />
        <div className="grid-2">
          <section className="card">
            <div className="card-head">
              <div>
                <h2><Icon name="code" size={16} /> From an application</h2>
                <div className="sub">Send JSON over HTTPS. One event or a list.</div>
              </div>
            </div>
            <div className="card-body">
              <CodeBlock label="Terminal" code={apiExample} />
              <p className="small muted">
                The API key decides the tenant, so each tenant has its own key. Keys are created by an administrator
                and are never shown in the website.
              </p>
            </div>
          </section>
          <section className="card">
            <div className="card-head">
              <div>
                <h2><Icon name="router" size={16} /> From a firewall or router</h2>
                <div className="sub">Point the device's syslog at this server, port 514 (UDP or TCP).</div>
              </div>
            </div>
            <div className="card-body">
              <CodeBlock label="Terminal (macOS / Linux)" code={syslogExample} />
              <p className="small muted">
                The tenant is picked from the device's IP address. Syslog has no password, so on servers open to the
                internet port 514 stays closed and only listed networks may send.
              </p>
            </div>
          </section>
        </div>
      </div>
    </>
  );
}

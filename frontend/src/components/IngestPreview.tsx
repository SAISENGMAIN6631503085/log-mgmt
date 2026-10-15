import { useEffect, useState } from "react";
import { countryFlag } from "../util";

// The login page's picture of what the product does, as a short scripted loop:
// raw logs arrive in their own vendor formats, each snaps into the one common row, and failed
// sign-ins from one address (sent by four different systems) add up to a brute-force alert.
// Decorative only (aria-hidden); the events are made up and labelled as such.

type Row = {
  raw: string;          // the log as the source sends it
  time: string;
  source: string;
  action: string;
  who: string;
  ip: string;
  country: string | null;
  failed?: boolean;     // counts toward the brute-force rule
};

const ATTACKER = "185.107.80.9";

// Private (company-internal) addresses belong to no country, so they get a quiet "internal" tag
// where public addresses get a flag. Region and port names aren't addresses and get neither.
const isInternal = (ip: string) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);

// Ordinary traffic already on screen when the page opens, so the panel never starts empty.
const PRELUDE: Row[] = [
  { raw: '{"event_type":"order_created","user":"shop-web","ip":"10.0.4.12","status":201}',
    time: "09:11:49", source: "Your app", action: "created", who: "shop-web", ip: "10.0.4.12", country: null },
  { raw: '{"eventName":"RunInstances","awsRegion":"ap-southeast-1","userIdentity":{"userName":"deploy-bot"}}',
    time: "09:11:52", source: "AWS", action: "created", who: "deploy-bot", ip: "ap-southeast-1", country: null },
  { raw: "<132>Oct 14 09:11:55 fw01 action=deny src=113.160.10.118 dst=10.0.1.10 dpt=22 policy=Block-SSH",
    time: "09:11:55", source: "Firewall", action: "deny", who: "Block-SSH", ip: "113.160.10.118", country: "VN" },
  { raw: '{"Operation":"FileDownloaded","UserId":"carol@contoso.com","ClientIP":"1.46.22.81","Workload":"SharePoint"}',
    time: "09:11:58", source: "Microsoft 365", action: "file opened", who: "carol@contoso.com", ip: "1.46.22.81", country: "TH" },
  { raw: "2026-10-14T09:12:01Z,4624,DC01.corp.local,alice,10.0.1.24,52144",
    time: "09:12:01", source: "Windows AD", action: "signed in", who: "alice", ip: "10.0.1.24", country: null },
];

const SCRIPT: Row[] = [
  { raw: "<134>Oct 14 09:12:03 fw01 action=accept src=10.0.1.24 dst=10.0.2.10 dpt=443 proto=tcp",
    time: "09:12:03", source: "Firewall", action: "allow", who: "10.0.1.24", ip: "10.0.2.10:443", country: null },
  { raw: "2026-10-14T09:12:05Z,4625,DC01.corp.local,administrator,185.107.80.9,51001",
    time: "09:12:05", source: "Windows AD", action: "sign-in failed", who: "administrator", ip: ATTACKER, country: "NL", failed: true },
  { raw: '{"Operation":"UserLoggedIn","UserId":"erin@contoso.com","ClientIP":"1.46.10.5","ResultStatus":"Succeeded"}',
    time: "09:12:06", source: "Microsoft 365", action: "signed in", who: "erin@contoso.com", ip: "1.46.10.5", country: "TH" },
  { raw: '{"Operation":"UserLoginFailed","UserId":"admin@contoso.com","ClientIP":"185.107.80.9:51515"}',
    time: "09:12:08", source: "Microsoft 365", action: "sign-in failed", who: "admin@contoso.com", ip: ATTACKER, country: "NL", failed: true },
  { raw: '{"eventName":"ConsoleLogin","responseElements":{"ConsoleLogin":"Failure"},"sourceIPAddress":"185.107.80.9"}',
    time: "09:12:10", source: "AWS", action: "sign-in failed", who: "root", ip: ATTACKER, country: "NL", failed: true },
  { raw: "<187>Oct 14 09:12:11 core-sw01 %LINK-3-UPDOWN: Interface Gi1/0/17, changed state to down",
    time: "09:12:11", source: "Network", action: "link down", who: "core-sw01", ip: "Gi1/0/17", country: null },
  { raw: '{"event_type":"login_failed","user":"dave","ip":"185.107.80.9","service":"payments-api"}',
    time: "09:12:13", source: "Your app", action: "sign-in failed", who: "dave", ip: ATTACKER, country: "NL", failed: true },
  { raw: "2026-10-14T09:12:14Z,4625,DC01.corp.local,administrator,185.107.80.9,51007",
    time: "09:12:14", source: "Windows AD", action: "sign-in failed", who: "administrator", ip: ATTACKER, country: "NL", failed: true },
];

const ALL = [...PRELUDE, ...SCRIPT];
const START = PRELUDE.length + 1; // the first scripted log is arriving as the page opens
const VISIBLE = 7;       // rows kept on screen (the list clips and fades the oldest at the top)
const STEP_MS = 1900;    // a new log every step
const SETTLE_MS = 750;   // how long a log shows as raw text before it's converted
const HOLD_MS = 5200;    // how long the alert stays before the loop starts over
const THRESHOLD = 5;

const reducedMotion = () =>
  typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

export function IngestPreview() {
  // `shown` = how many script rows have arrived; the newest stays raw until `settled`.
  const still = reducedMotion();
  const [shown, setShown] = useState(still ? ALL.length : START);
  const [settled, setSettled] = useState(still);

  useEffect(() => {
    if (still) return;
    setSettled(false);
    const settle = window.setTimeout(() => setSettled(true), SETTLE_MS);
    const next = window.setTimeout(
      () => setShown((n) => (n >= ALL.length ? START : n + 1)),
      shown >= ALL.length ? HOLD_MS : STEP_MS,
    );
    return () => { window.clearTimeout(settle); window.clearTimeout(next); };
  }, [shown, still]);

  const arrived = ALL.slice(0, shown);
  const first = Math.max(0, arrived.length - VISIBLE);
  const rows = arrived.slice(first);
  const failures = arrived.filter((r) => r.failed && (r !== arrived[arrived.length - 1] || settled)).length;
  const alert = failures >= THRESHOLD;

  return (
    <div className="ingest-preview" aria-hidden="true">
      <div className="ip-head">
        <span className="ip-live" />
        <span>Incoming logs, each converted to one format</span>
        <span className="ip-sim">Simulated events</span>
      </div>

      <ol className="ip-rows">
        {rows.map((r, i) => {
          const newest = i === rows.length - 1;
          const raw = newest && !settled;
          return (
            <li key={first + i} className={`ip-row${raw ? " is-raw" : ""}${r.failed ? " is-failed" : ""}`}>
              <code className="ip-raw">{r.raw}</code>
              <div className="ip-fields">
                <span className="ip-time">{r.time}</span>
                <span className="ip-source">{r.source}</span>
                <span className="ip-action">{r.action}</span>
                <span className="ip-who">{r.who}</span>
                <span className="ip-addr">
                  {r.country && <span className="ip-flag">{countryFlag(r.country)}</span>}
                  {!r.country && isInternal(r.ip) && <span className="ip-internal">internal</span>}
                  {r.ip}
                </span>
              </div>
            </li>
          );
        })}
      </ol>

      <div className={`ip-watch${alert ? " is-alert" : ""}`}>
        <div className="ip-meter" role="presentation">
          {Array.from({ length: THRESHOLD }, (_, i) => <span key={i} className={i < failures ? "on" : ""} />)}
        </div>
        {alert ? (
          <p><strong>Alert: brute-force login</strong> {failures} failed sign-ins from {ATTACKER}, across 4 systems</p>
        ) : (
          <p>Failed sign-ins from {ATTACKER}: <strong>{failures} of {THRESHOLD}</strong> before an alert</p>
        )}
      </div>
    </div>
  );
}

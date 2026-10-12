import { severityLevel } from "../util";

/** Severity as a dot plus the word, so it never relies on colour alone. */
export function SeverityBadge({ severity }: { severity: number | null }) {
  const level = severityLevel(severity);
  return (
    <span className={`pill sev-${level}`} title={severity === null ? "no severity" : `severity ${severity}/10`}>
      <span className="dot" />
      {level[0].toUpperCase() + level.slice(1)}
      {severity !== null && <span className="num">{severity}</span>}
    </span>
  );
}

export function StatusPill({ status }: { status: "open" | "acknowledged" }) {
  return (
    <span className={`pill status-${status}`}>
      <span className="dot" />
      {status === "open" ? "Open" : "Acknowledged"}
    </span>
  );
}

export function Empty({ icon, title, children }: { icon: React.ReactNode; title: string; children?: React.ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-icon">{icon}</div>
      <strong>{title}</strong>
      {children && <div>{children}</div>}
    </div>
  );
}

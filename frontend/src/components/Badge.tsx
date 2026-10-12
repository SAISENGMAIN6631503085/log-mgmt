import { severityLevel } from "../util";

/** Severity shown as a coloured dot plus the word, so it never relies on colour alone. */
export function SeverityBadge({ severity }: { severity: number | null }) {
  const level = severityLevel(severity);
  return (
    <span className={`badge ${level}`} title={severity === null ? "no severity" : `severity ${severity}/10`}>
      {level}
      {severity !== null && <span className="muted">{severity}</span>}
    </span>
  );
}

import { ReactNode, useState } from "react";

type Column<T> = { key: keyof T & string; label: string; num?: boolean; format?: (v: T[keyof T]) => string };

/** A chart with a "Table" toggle: every chart's numbers are also readable as plain text
 *  (for screen readers, colour-blind readers, and anyone who wants exact values). */
export function ChartCard<T extends Record<string, unknown>>(props: {
  title: string;
  rows: T[];
  columns: Column<T>[];
  children: ReactNode;
  empty?: boolean;
}) {
  const [asTable, setAsTable] = useState(false);
  return (
    <section className="card">
      <div className="card-head">
        <h2>{props.title}</h2>
        <button className="link" onClick={() => setAsTable(!asTable)} aria-pressed={asTable}>
          {asTable ? "Chart" : "Table"}
        </button>
      </div>
      {props.empty ? (
        <p className="muted">No events in this time range.</p>
      ) : asTable ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>{props.columns.map((c) => <th key={c.key} className={c.num ? "num" : ""}>{c.label}</th>)}</tr>
            </thead>
            <tbody>
              {props.rows.map((r, i) => (
                <tr key={i}>
                  {props.columns.map((c) => (
                    <td key={c.key} className={c.num ? "num" : ""}>{c.format ? c.format(r[c.key]) : String(r[c.key] ?? "")}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        props.children
      )}
    </section>
  );
}

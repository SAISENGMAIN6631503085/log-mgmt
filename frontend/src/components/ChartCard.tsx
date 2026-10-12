import { ReactNode, useState } from "react";
import { Empty } from "./Badge";
import { Icon } from "./Icon";

type Column<T> = { key: keyof T & string; label: string; num?: boolean; format?: (v: T[keyof T]) => string };

/** A chart with a "Table" toggle: every chart's numbers are also readable as plain text
 *  (for screen readers, colour-blind readers, and anyone who wants exact values). */
export function ChartCard<T extends Record<string, unknown>>(props: {
  title: string;
  subtitle?: string;
  rows: T[];
  columns: Column<T>[];
  children: ReactNode;
  empty?: boolean;
}) {
  const [asTable, setAsTable] = useState(false);
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>{props.title}</h2>
          {props.subtitle && <div className="sub">{props.subtitle}</div>}
        </div>
        {!props.empty && (
          <button className="ghost sm" onClick={() => setAsTable(!asTable)} aria-pressed={asTable}>
            {asTable ? "Show chart" : "Show table"}
          </button>
        )}
      </div>
      {props.empty ? (
        <Empty icon={<Icon name="inbox" />} title="No events">Nothing in this time range.</Empty>
      ) : asTable ? (
        <div className="card-body flush table-wrap">
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
        <div className="card-body">{props.children}</div>
      )}
    </section>
  );
}

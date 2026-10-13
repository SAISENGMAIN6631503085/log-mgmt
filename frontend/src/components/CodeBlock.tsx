import { useState } from "react";
import { Icon } from "./Icon";

/** A command or secret with a one-click Copy button (Add logs page, new API keys). */
export function CodeBlock({ label, code }: { label: string; code: string }) {
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

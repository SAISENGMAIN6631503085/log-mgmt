import { countryFlag, countryName } from "../util";

/** Flag + name ("🇹🇭 Thailand"), or just the flag with the name as a tooltip (compact). */
export function Country({ code, compact }: { code: string | null | undefined; compact?: boolean }) {
  if (!code) return null;
  const name = countryName(code);
  return compact
    ? <span className="flag" title={name} aria-label={name}>{countryFlag(code)}</span>
    : <span className="country"><span className="flag" aria-hidden="true">{countryFlag(code)}</span>{name}</span>;
}

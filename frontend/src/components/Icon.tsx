// Small inline SVG icon set (24x24 grid, 2px strokes): no icon library needed.
const PATHS: Record<string, string> = {
  logo: "M12 3 4.5 6v5.5c0 4.6 3.1 8.4 7.5 9.5 4.4-1.1 7.5-4.9 7.5-9.5V6L12 3Z M8.5 12.5l2.3 2.3 4.7-4.8",
  dashboard: "M4 4h7v7H4z M13 4h7v4h-7z M13 10h7v10h-7z M4 13h7v7H4z",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14Z M20 20l-4-4",
  bell: "M6 16V11a6 6 0 1 1 12 0v5l1.5 2h-15L6 16Z M10 21h4",
  activity: "M3 12h4l3-8 4 16 3-8h4",
  lock: "M6 11h12v9H6z M8.5 11V8a3.5 3.5 0 0 1 7 0v3",
  flame: "M12 3c1 3.5 5 5.5 5 10a5 5 0 0 1-10 0c0-2.4 1.2-3.8 2.3-5 .3 1.6 1 2.6 2.2 3C11 8.5 11.2 5.5 12 3Z",
  alert: "M12 4 2.8 19.5h18.4L12 4Z M12 10v4.5 M12 17.3v.2",
  sun: "M12 7.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9Z M12 2v2 M12 20v2 M4.93 4.93l1.41 1.41 M17.66 17.66l1.41 1.41 M2 12h2 M20 12h2 M4.93 19.07l1.41-1.41 M17.66 6.34l1.41-1.41",
  moon: "M20.5 14.2A8.5 8.5 0 1 1 9.8 3.5a6.6 6.6 0 0 0 10.7 10.7Z",
  monitor: "M3.5 5h17v11h-17z M9 20h6 M12 16v4",
  logout: "M15 4h4v16h-4 M10 8l-4 4 4 4 M6 12h10",
  x: "M6 6l12 12 M18 6 6 18",
  check: "M5 12.5l4.5 4.5L19 7.5",
  inbox: "M3.5 13.5 6 5h12l2.5 8.5v5.5h-17z M3.5 13.5H9l1 2.5h4l1-2.5h5.5",
  filter: "M4 5h16l-6.2 7.5V19l-3.6-2v-4.5L4 5Z",
  external: "M14 4h6v6 M20 4l-9 9 M18 14v6H4V6h6",
  user: "M12 4a4 4 0 1 0 0 8 4 4 0 0 0 0-8Z M4.5 20a7.5 7.5 0 0 1 15 0",
  chevron: "M6 9l6 6 6-6",
  info: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z M12 11v5 M12 7.6v.2",
  up: "M12 19V5 M6 11l6-6 6 6",
  down: "M12 5v14 M6 13l6 6 6-6",
  building: "M5 20V5h9v15 M14 9h5v11 M3 20h18 M8 8.5h3 M8 12h3 M8 15.5h3",
};

export type IconName = keyof typeof PATHS;

export function Icon({ name, size = 18, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}
         strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className={className}>
      <path d={PATHS[name]} />
    </svg>
  );
}

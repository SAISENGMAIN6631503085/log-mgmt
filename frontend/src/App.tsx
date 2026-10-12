import { useEffect, useState } from "react";

type Health = { status: string; database: string };

export default function App() {
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Relative URL: Caddy serves the SPA and the API on the same origin, so no CORS needed.
    fetch("/health")
      .then((r) => r.json())
      .then(setHealth)
      .catch((e) => setError(String(e)));
  }, []);

  return (
    <main style={{ fontFamily: "system-ui, sans-serif", padding: "2rem" }}>
      <h1>Log Management</h1>
      {error && <p>Backend unreachable: {error}</p>}
      {health && (
        <p>
          Backend: <strong>{health.status}</strong> · Database: <strong>{health.database}</strong>
        </p>
      )}
      {!health && !error && <p>Checking backend…</p>}
    </main>
  );
}

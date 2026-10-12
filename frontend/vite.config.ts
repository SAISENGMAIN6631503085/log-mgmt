import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    // For `npm run dev` outside Docker: forward API calls to a locally running backend.
    proxy: { "/api": "http://localhost:8000", "/health": "http://localhost:8000" },
  },
});

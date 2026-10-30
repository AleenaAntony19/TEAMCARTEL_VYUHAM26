import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev: the API runs on 127.0.0.1:8000 (python -m shield.api); prod: FastAPI serves web/dist itself.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { "/api": "http://127.0.0.1:8000" } },
  build: { chunkSizeWarningLimit: 900 }, // three.js / 3d-force-graph are large but lazy-loaded
});

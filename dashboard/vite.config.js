import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev server proxies /api/* to the FastAPI backend so the dashboard
// can call relative paths without worrying about CORS or hardcoded hosts.
// Change target if main.py runs on a different host/port.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
});

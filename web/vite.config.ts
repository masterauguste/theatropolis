import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import fs from "node:fs";
import path from "node:path";

const distDir = path.resolve(__dirname, "../internal/webui/dist");

const preserveGitkeep = {
  name: "preserve-gitkeep",
  closeBundle() {
    fs.writeFileSync(path.join(distDir, ".gitkeep"), "");
  },
};

export default defineConfig({
  plugins: [react(), preserveGitkeep],
  base: "/",
  build: {
    outDir: distDir,
    emptyOutDir: true,
    assetsDir: "assets",
    sourcemap: false,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8080",
      "/session": "http://127.0.0.1:8080",
      "/language": "http://127.0.0.1:8080",
      "/servers": "http://127.0.0.1:8080",
      "/proxy-nodes": "http://127.0.0.1:8080",
      "/users": "http://127.0.0.1:8080",
      "/subscriptions": "http://127.0.0.1:8080",
      "/pool": "http://127.0.0.1:8080",
      "/settings": "http://127.0.0.1:8080",
      "/master-update": "http://127.0.0.1:8080",
      "/login": "http://127.0.0.1:8080",
      "/logout": "http://127.0.0.1:8080",
      "/portal": "http://127.0.0.1:8080",
      "/claim": "http://127.0.0.1:8080",
    },
  },
});

/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  // 开发时经代理访问本机 API，保持同源（Cookie 为 SameSite=Strict）
  server: { proxy: { "/api": "http://127.0.0.1:8000" } },
  build: {
    outDir: "dist",
    assetsDir: "assets",
    chunkSizeWarningLimit: 900, // 入口块约 800 KB（未压缩）；超过说明有新的大依赖混进了首屏
    rollupOptions: {
      output: {
        // 只把 React 运行时单独成块以便长期缓存；antd 等其余依赖按页面自然拆分，
        // 只在个别页面用到的组件不进首屏（合成一大块时登录页要多下载约 200 KB）。
        manualChunks: (id) =>
          /node_modules[\\/](react|react-dom|scheduler|react-router)[\\/]/.test(id) ? "react" : undefined,
      },
    },
  },
  test: { maxWorkers: 2, testTimeout: 15000, environment: "jsdom", globals: true, setupFiles: ["src/test/setup.ts"], css: false },
});

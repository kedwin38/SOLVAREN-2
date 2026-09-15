import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

export default defineConfig({
  plugins: [react()],
  // Dev freshness: resolve the workspace packages at their sources so console
  // development sees kernel changes without a rebuild.
  resolve: {
    alias: {
      '@solvaren/core': resolve(__dirname, '../../packages/core/src/index.ts'),
      '@solvaren/daraja': resolve(__dirname, '../../packages/daraja/src/index.ts'),
      '@solvaren/storage': resolve(__dirname, '../../packages/storage/src/index.ts'),
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL ?? 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
});

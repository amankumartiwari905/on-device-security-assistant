import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';

// Build 1: popup, warning, options (HTML entries) + background service worker (ES module).
// The content script is built separately (vite.content.config.ts) as a single IIFE.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(import.meta.dirname, 'popup.html'),
        warning: resolve(import.meta.dirname, 'warning.html'),
        options: resolve(import.meta.dirname, 'options.html'),
        background: resolve(import.meta.dirname, 'src/background/index.ts'),
      },
      output: {
        entryFileNames: (chunk) =>
          chunk.name === 'background' ? 'background.js' : 'assets/[name]-[hash].js',
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
});
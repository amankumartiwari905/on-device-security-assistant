import { defineConfig } from 'vite';
import { resolve } from 'path';

// Build 2: content scripts cannot be ES modules in MV3, so bundle to one IIFE file.
export default defineConfig({
  build: {
    outDir: 'dist',
    emptyOutDir: false,
    lib: {
      entry: resolve(import.meta.dirname, 'src/content/index.ts'),
      formats: ['iife'],
      name: 'AiGuardContent',
      fileName: () => 'content.js',
    },
  },
});
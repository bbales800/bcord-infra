import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:9100',
      '/captcha': 'http://localhost:5280'
    }
  },
  build: {
    outDir: '../site',
    emptyOutDir: true
  }
});


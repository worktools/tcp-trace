import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';

// During development the Rust server runs on 9330 and serves the API.
export default defineConfig({
  plugins: [preact()],
  server: { proxy: { '/api': 'http://127.0.0.1:9330' } },
  build: { outDir: 'dist', emptyOutDir: true },
});

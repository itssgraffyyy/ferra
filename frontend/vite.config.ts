import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The dashboard talks to a local FastAPI process. In development Vite proxies
// /api to it so the browser sees one origin and no CORS configuration is needed.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: process.env.FERA_API ?? 'http://127.0.0.1:8000',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ''),
      },
    },
  },
  build: { outDir: 'dist', sourcemap: true },
})

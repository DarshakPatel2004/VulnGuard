/* -----------------------------------------------------------
   VulnForge – Precision Threat Intelligence Platform
Made by Darshak Patel
   [dp-watermark-2026]
   ----------------------------------------------------------- */

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/cves': 'http://localhost:8000',
      '/assets': 'http://localhost:8000',
      '/fetch': 'http://localhost:8000',
      '/rules': 'http://localhost:8000',
      '/auth': 'http://localhost:8000',
    }
  },
  build: {
    outDir: '../backend/static',
    emptyOutDir: true,
  }
})


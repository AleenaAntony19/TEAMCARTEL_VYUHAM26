import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Dev: the API runs on 127.0.0.1:8000 (python -m shield.api); prod: FastAPI serves web/dist itself.
export default defineConfig({
  plugins: [vue()],
  server: { port: 5173, proxy: { '/api': 'http://127.0.0.1:8000' } }
})

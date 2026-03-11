import path from 'path';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', '');
  const devHost = env.VITE_DEV_HOST || '127.0.0.1';
  const devPort = Number(env.VITE_DEV_PORT || 5173);
  const hmrHost = env.VITE_HMR_HOST || devHost;
  const hmrPort = Number(env.VITE_HMR_PORT || devPort);
  const hmrClientPort = Number(env.VITE_HMR_CLIENT_PORT || hmrPort);
  return {
    server: {
      port: devPort,
      host: devHost,
      hmr: {
        host: hmrHost,
        port: hmrPort,
        clientPort: hmrClientPort,
        protocol: 'ws'
      },
      watch: {
        ignored: [
          '**/backend/**',
          '**/ares_engine/**',
          '**/*.sqlite3*',
          '**/*.db',
          '**/history/**',
          '**/loot/**',
          '**/__pycache__/**',
          '**/.venv/**',
        ]
      }
    },
    plugins: [react()],
    define: {
      'process.env.API_KEY': JSON.stringify(env.GEMINI_API_KEY),
      'process.env.GEMINI_API_KEY': JSON.stringify(env.GEMINI_API_KEY)
    },
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      }
    },
    build: {
      chunkSizeWarningLimit: 900,
      rollupOptions: {
        output: {
          manualChunks(id: string) {
            if (!id.includes('node_modules')) {
              return undefined;
            }
            if (id.includes('recharts') || id.includes('d3')) {
              return 'vendor-charts';
            }
            if (id.includes('jspdf') || id.includes('html2canvas')) {
              return 'vendor-pdf';
            }
            if (id.includes('@google/genai')) {
              return 'vendor-genai';
            }
            return 'vendor';
          }
        }
      }
    },
    test: {
      environment: 'jsdom',
      globals: true,
      setupFiles: './vitest.setup.ts'
    }
  };
});

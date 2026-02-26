import React from 'react';
import ReactDOM from 'react-dom/client';
import * as Sentry from '@sentry/react';
import App from './App';
import { AuthProvider } from './components/AuthContext';
import ErrorBoundary from './components/ErrorBoundary';

const sentryDsn = import.meta.env.VITE_SENTRY_DSN as string | undefined;
if (sentryDsn) {
  const scrub = (value: any): any => {
    if (Array.isArray(value)) return value.map(scrub);
    if (value && typeof value === 'object') {
      const out: Record<string, any> = {};
      for (const [k, v] of Object.entries(value)) {
        const key = k.toLowerCase();
        if (key.includes('authorization') || key.includes('cookie') || key.includes('token') || key.includes('password') || key.includes('secret')) {
          out[k] = '***REDACTED***';
        } else {
          out[k] = scrub(v);
        }
      }
      return out;
    }
    if (typeof value === 'string') {
      return value
        .replace(/([?&](token|access_token|password|secret)=[^&]+)/gi, '$1=***REDACTED***')
        .replace(/(authorization:\s*bearer\s+)[^\s]+/gi, '$1***REDACTED***');
    }
    return value;
  };
  Sentry.init({
    dsn: sentryDsn,
    environment: import.meta.env.MODE,
    tracesSampleRate: Number(import.meta.env.VITE_SENTRY_TRACES_SAMPLE_RATE || 0.2),
    beforeSend(event) {
      return scrub(event);
    },
  });
}

const rootElement = document.getElementById('root');
if (!rootElement) {
  throw new Error("Could not find root element to mount to");
}

const root = ReactDOM.createRoot(rootElement);
root.render(
  <ErrorBoundary>
    <AuthProvider>
      <App />
    </AuthProvider>
  </ErrorBoundary>
);

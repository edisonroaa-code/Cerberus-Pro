const trimTrailingSlash = (value: string) => value.replace(/\/+$/, '');

const safeUrl = (value: string) => {
  try {
    return trimTrailingSlash(new URL(value).toString());
  } catch {
    return trimTrailingSlash(value);
  }
};

const resolveDefaultApiBase = () => {
  if (typeof window === 'undefined') {
    return 'http://127.0.0.1:8011';
  }

  const protocol = window.location.protocol || 'http:';
  const host = window.location.hostname || '127.0.0.1';
  return `${protocol}//${host}:8011`;
};

const API_BASE_URL = safeUrl(
  import.meta.env.VITE_API_URL || resolveDefaultApiBase()
);

const WS_BASE_URL = safeUrl(
  import.meta.env.VITE_WS_URL || API_BASE_URL.replace(/^http/i, 'ws')
);

export { API_BASE_URL, WS_BASE_URL };

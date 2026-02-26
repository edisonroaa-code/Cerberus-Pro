type BackendHealthOptions = {
  apiBaseUrl: string;
  timeoutMs?: number;
};

const trimTrailingSlash = (value: string) => value.replace(/\/+$/, '');

const fetchWithTimeout = async (url: string, timeoutMs: number) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { method: 'GET', signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
};

const isReachable = async (url: string, timeoutMs: number) => {
  try {
    const response = await fetchWithTimeout(url, timeoutMs);
    if (response.ok) return true;
    if (response.status === 401 || response.status === 403) return true;
    return false;
  } catch {
    return false;
  }
};

export const checkBackendReady = async ({
  apiBaseUrl,
  timeoutMs = 1500,
}: BackendHealthOptions): Promise<boolean> => {
  const base = trimTrailingSlash(apiBaseUrl);

  if (await isReachable(`${base}/health`, timeoutMs)) return true;
  if (await isReachable(`${base}/status`, timeoutMs)) return true;
  return false;
};

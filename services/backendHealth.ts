type BackendHealthOptions = {
  apiBaseUrl: string;
  timeoutMs?: number;
  cacheTtlMs?: number;
};

const trimTrailingSlash = (value: string) => value.replace(/\/+$/, '');
const backendReadyCache = new Map<string, { value: boolean; ts: number }>();
const backendReadyInflight = new Map<string, Promise<boolean>>();

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
  cacheTtlMs = 5000,
}: BackendHealthOptions): Promise<boolean> => {
  const base = trimTrailingSlash(apiBaseUrl);
  const now = Date.now();
  const cached = backendReadyCache.get(base);
  if (cached && now - cached.ts < Math.max(0, cacheTtlMs)) {
    return cached.value;
  }
  const inflight = backendReadyInflight.get(base);
  if (inflight) return inflight;

  const probe = (async () => {
    let ok = false;
    if (await isReachable(`${base}/health`, timeoutMs)) {
      ok = true;
    } else if (await isReachable(`${base}/status`, timeoutMs)) {
      ok = true;
    }
    backendReadyCache.set(base, { value: ok, ts: Date.now() });
    return ok;
  })();

  backendReadyInflight.set(base, probe);
  try {
    return await probe;
  } finally {
    backendReadyInflight.delete(base);
  }
};

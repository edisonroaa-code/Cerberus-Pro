import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AttackProfile, type LogEntry } from '../types';
import { analyzeWafResponse, generateExecutiveReport } from './geminiService';

describe('geminiService', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
    localStorage.clear();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('calls backend AI endpoint with credentials and bearer token', async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({
        source: 'gemini',
        reasoning: 'ok',
        action: 'retry',
        params: { profile: 'safe' },
        confidence: 0.9
      })
    } as any);

    const entry: LogEntry = {
      id: '1',
      timestamp: '12:00:00',
      component: 'CERBERUS_PRO',
      level: 'WARN',
      message: 'WAF 403'
    };

    await analyzeWafResponse(entry, AttackProfile.STEALTH_CORPORATE, 'token-123');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/ai\/analyze-waf$/);
    expect(options.credentials).toBe('include');
    expect((options.headers as Record<string, string>).Authorization).toBe('Bearer token-123');
  });

  it('falls back to local analysis when backend request fails', async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValue({ ok: false } as any);

    const entry: LogEntry = {
      id: '2',
      timestamp: '12:01:00',
      component: 'SISTEMA',
      level: 'ERROR',
      message: 'forbidden 403 waf blocked request'
    };

    const output = await analyzeWafResponse(entry, AttackProfile.CRAWLER_LEGIT);
    expect(output).toContain('ANÁLISIS LOCAL');
  });

  it('uses backend narrative endpoint with include credentials', async () => {
    const fetchMock = fetch as unknown as ReturnType<typeof vi.fn>;
    fetchMock.mockResolvedValue({
      ok: true,
      json: async () => ({ narrative: 'reporte' })
    } as any);

    const logs: LogEntry[] = [{
      id: '3',
      timestamp: '12:02:00',
      component: 'ORQUESTADOR',
      level: 'SUCCESS',
      message: 'scan complete'
    }];

    await generateExecutiveReport(logs);
    const [url, options] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toMatch(/\/ai\/generate-narrative$/);
    expect(options.credentials).toBe('include');
  });
});

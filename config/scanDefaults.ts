/**
 * ARCH-001: Extracted from App.tsx
 * Attack profile constants, mock fingerprints, and default scan configuration.
 */
import { AttackProfile, FingerprintData, TargetConfig } from '../types';

// Expanded Mock Fingerprints with Profile-Specific Tags
export const MOCK_FINGERPRINTS: FingerprintData[] = [
    // Corporate / Desktop
    { name: 'Chrome 120 (Win10)', score: 98, userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36', ja3Hash: 'e7d705a3286e19...', httpVersion: '3', tags: ['Escritorio', 'Corp', 'Sigilo'] },
    { name: 'Edge 119 (Enterprise)', score: 92, userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0', ja3Hash: 'a0b9c8d7...', httpVersion: '3', tags: ['Escritorio', 'Corp'] },
    { name: 'Firefox 121 (Linux)', score: 88, userAgent: 'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0', ja3Hash: 'c123456...', httpVersion: '2', tags: ['Escritorio'] },

    // Mobile
    { name: 'Safari 17 (iPhone)', score: 95, userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1', ja3Hash: 'b32309a2695...', httpVersion: '2', tags: ['Móvil'] },
    { name: 'Chrome (Android 14)', score: 90, userAgent: 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36', ja3Hash: 'd41d8cd98f...', httpVersion: '3', tags: ['Móvil'] },

    // Crawler / Bots
    { name: 'GoogleBot (Smartphone)', score: 85, userAgent: 'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.71 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', ja3Hash: '123908adf...', httpVersion: '1.1', tags: ['Crawler'] },
    { name: 'BingBot 2.0', score: 82, userAgent: 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)', ja3Hash: '987654321...', httpVersion: '1.1', tags: ['Crawler'] },
];

// Profile Rules Definition
export const PROFILE_RULES: Record<AttackProfile, { rpsMult: number, tags: string[], threadCap: number, desc: string }> = {
    [AttackProfile.STEALTH_CORPORATE]: {
        rpsMult: 0.5,
        tags: ['Corp', 'Escritorio'],
        threadCap: 4,
        desc: 'Emulación de tráfico de oficina. Headers de Outlook/Teams inyectados.'
    },
    [AttackProfile.MOBILE_5G]: {
        rpsMult: 1.2,
        tags: ['Móvil'],
        threadCap: 12,
        desc: 'Alta varianza de latencia. Rotación rápida de IP (CGNAT).'
    },
    [AttackProfile.CRAWLER_LEGIT]: {
        rpsMult: 2.0,
        tags: ['Crawler'],
        threadCap: 20,
        desc: 'Comportamiento de indexación. Respeta parcialmente robots.txt.'
    },
    [AttackProfile.AGGRESSIVE_BURST]: {
        rpsMult: 5.0,
        tags: ['Escritorio', 'Móvil'],
        threadCap: 50,
        desc: 'Saturación controlada. Sin evasión semántica.'
    }
};

export const DEFAULT_CONFIG: TargetConfig = {
    url: 'https://banco-vulnerable.corp/api/login',
    profile: AttackProfile.STEALTH_CORPORATE,
    aggressionLevel: 3,
    useSmartEvasion: true,
    sqlMap: {
        technique: 'BEUSTQ',
        threads: 4,
        level: 3,
        risk: 2,
        tamper: 'space2comment,randomcase',
        randomAgent: true,
        hpp: false,
        hex: false,
        getDbs: false,
        getTables: false,
        getColumns: false,
        dumpAll: false,
        currentUser: true,
        currentDb: true
    },
    autoPilot: true
};

export const LOG_RING_MAX = 500;
export const ACTIVE_JOB_STATUSES = new Set(['queued', 'running']);
export const TERMINAL_JOB_STATUSES = new Set(['completed', 'failed', 'stopped', 'interrupted', 'timeout', 'cancelled', 'canceled', 'partial']);

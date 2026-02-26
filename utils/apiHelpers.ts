/**
 * ARCH-001: Extracted from App.tsx
 * Shared utility functions for API response handling and job status normalization.
 */

export const parseJson = async (response: Response) => {
    try {
        return await response.json();
    } catch {
        return {};
    }
};

export const normalizeJobStatus = (value: unknown): string =>
    String(value ?? 'unknown').toLowerCase().trim();

export const extractApiErrorMessage = (payload: any, fallback = 'Error desconocido'): string => {
    if (!payload) return fallback;
    if (typeof payload === 'string') {
        try {
            payload = JSON.parse(payload);
        } catch {
            return payload || fallback;
        }
    }
    return (
        payload?.detail ||
        payload?.message ||
        payload?.error ||
        payload?.msg ||
        (typeof payload === 'string' ? payload : null) ||
        fallback
    );
};

# Deprecations V1

Date: 2026-02-17

## API / Route Surface

### Removed client fallbacks
- Frontend no longer falls back to legacy endpoints:
  - `/start`
  - `/stop`
- Canonical endpoints are:
  - `POST /scan/start`
  - `POST /scan/stop`

### Router path normalization
- Legacy module status path changed to avoid collision:
  - from: `GET /scan/status` (via modular router)
  - to: `GET /scan/module/status`
- Canonical runtime status endpoint remains:
  - `GET /scan/status` (ares core)

## Runtime entrypoint

- Canonical uvicorn target:
  - `backend.ares_api:app`
- Compatibility facade remains available:
  - `backend.cerberus_pro_api_secure:app`
- Deprecated runtime targets removed from operational scripts:
  - Dockerfile / docker-compose / launcher now use `backend.ares_api:app`

## Legacy scripts

Archived to `backend/archive/legacy_tools/`:
- `diagnostic_v4.py`
- `inject_endpoint.py`
- `patch_api.py`
- `patch_api_2026.py`
- `patch_api_stability.py`
- `tmp_cors_patch.py`
- `verify_2026_evasion.py`
- `verify_v4_omni.py`

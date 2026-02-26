# 🐺 CERBERUS Pro (v4 Omni-Surface)

Orquestador local de scans **autorizados** basado en FastAPI + React, con **motor unificado multi-vector** + **Jobs** (cola/historial), hardening y auditoria.

## Estado (Feb-2026)
- Backend y UI operativos en modo unificado.
- Runtime backend canónico consolidado en `backend/ares_api.py` (compatibilidad vía `backend/cerberus_pro_api_secure.py`).
- Jobs API operativa: `GET /jobs`, `GET /jobs/{scan_id}`, `POST /jobs/{scan_id}/stop`, `POST /jobs/{scan_id}/retry`.
- Hardening aplicado: anti-traversal en historial, kill de arbol de procesos, watchdog de timeout global, policy de scope (allowlist host/IP/CIDR + DNS + redirects), JWT con `iss/aud`, Sentry scrub, auditoria con hash-chain en SQLite.
- Observabilidad/testing base: `/metrics` + Pytest/Vitest.

## Requisitos
- Python 3.9+ (en este workspace: 3.12)
- Node 18+ (en este workspace: 22)

## Inicio rapido (DEV)
```bash
pip install -r backend/requirements_secure.txt
npm install
cp .env.example .env

# Arranque "inteligente": si algun puerto ya esta ocupado, no tumba todo.
npm run dev:all
```

URLs por defecto:
- UI: `http://127.0.0.1:5173`
- API: `http://127.0.0.1:8011`
- WS API: `ws://127.0.0.1:8011/ws`
- WS bridge (agentes): `ws://localhost:8000/ws`
- Agent runner: `http://localhost:3001`

## Scripts utiles
- `npm run dev:all`: inicia lo necesario para DEV, tolerante a puertos ya en uso (no rompe todo por `EADDRINUSE`).
- `npm run dev:all:full`: variante fail-fast (si algo falla, cae todo).
- `npm run dev:agents`: solo ws-bridge + agent-runner.
- `npm test`: Vitest.
- `npm run guard:recall`: valida guardrails del recall/rebranding (rutas, entrypoint canonico, archivos legacy).
- `npm run guard:deprecations`: bloquea patrones deprecados en backend runtime (`datetime.utcnow`, `@validator`, `class Config`).
- `python -m pytest -q` (en venv): Pytest.

## Puertos (evitar caidas por conflictos)
Si ya tenes algun proceso ocupando puertos, `dev:all` los detecta y **no** intenta levantar otro.

Variables relevantes:
- `API_PORT` (default `8011`)
- `WS_BRIDGE_PORT` (default `8000`)
- `AGENT_RUNNER_PORT` (default `3001`)
- `VITE_DEV_PORT` (default `5173`)

## Seguridad operativa (resumen tecnico)
- Auth “cookie-first”: `credentials: include` en frontend; access token en memoria; refresh via cookie HttpOnly.
- Scope control: allowlist por host/IP/CIDR + bloqueo de redes peligrosas por defecto (si esta configurado en policy).
- Ejecucion segura de motor: args en lista, `shell=False`, kill de grupo/arbol, timeout global.
- Chain sandbox (Fase 3):
  - `CERBERUS_CHAIN_SANDBOX_MODE=auto|docker|local`
  - `CERBERUS_CHAIN_SANDBOX_IMAGE=cerberus-chain-runner:latest` (recomendado)
  - Dockerfile base: `backend/sandbox/Dockerfile.chain-runner`
- Historial:
  - `.json` (segun politica) + `.enc` (AES-GCM) si `ENCRYPTION_KEY` esta configurada.
  - Si `ENCRYPTION_KEY` no esta seteada, se usa key efimera y los `.enc` no se podran desencriptar tras reinicio (ver logs).

## Notas de dependencias opcionales
El backend deshabilita automaticamente capacidades si faltan libs:
- `dnslib` (DNS OOB) y `scapy` (ICMP) pueden no estar instaladas en Windows o requerir setup adicional.

## Smoke tests manuales
- WS: `python tools/ws_smoke.py` (requiere backend arriba).
- Jobs (in-process): `python tools/smoke_jobs.py`.

## Legal
Usar solo sobre targets con autorizacion explicita.

## Recall / Rebranding
- Manifiesto de recall: `backend/RECALL_MANIFEST_V1.md`
- Progreso del roadmap: `backend/RECALL_ROADMAP_PROGRESS_V1.md`
- Matriz/organigrama de integracion real: `backend/INTEGRATION_MATRIX_ORGANIGRAMA_V1.md`
- Arquitectura rebrand v1: `backend/REBRAND_ARCHITECTURE_V1.md`
- Deprecaciones v1: `backend/DEPRECATIONS_V1.md`

## Sistema Activo (Scope V1)
- Frontend activo: `App.tsx`, `components/`, `services/`, `utils/`
- Backend activo: `backend/ares_api.py`, `backend/core/`, `backend/routers/`, `backend/engines/`, `backend/db/`, `backend/worker/`, `backend/services/`
- Runtime scripts activos: `package.json` scripts (`backend.ares_api:app`), `tools/dev-all.mjs`, `start_ares.py`, `docker-compose.yml`, `backend/Dockerfile`
- Guardrails activos: `tools/recall_guard.py`, `tools/deprecation_guard.py`
- Endpoints canónicos de ejecución: `POST /scan/start`, `POST /scan/stop`, `GET /scan/status`, `GET /scan/capabilities` (hard break: sin `/scan/omni/*`).
- Contrato canónico de jobs: `kind="unified"`.
- Contrato canónico de config: `config.unified` (hard break: `config.omni` no soportado).

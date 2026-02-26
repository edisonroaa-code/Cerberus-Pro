# Chain Sandbox Runner (Phase 3)

Este contenedor se usa para ejecutar pasos de `chain_orchestrator` en aislamiento.

## Build

```bash
docker build -f backend/sandbox/Dockerfile.chain-runner -t cerberus-chain-runner:latest .
```

## Variables de entorno

- `CERBERUS_CHAIN_SANDBOX_MODE`: `auto` | `docker` | `local` (default: `auto`)
- `CERBERUS_CHAIN_SANDBOX_IMAGE`: imagen Docker (default: `python:3.12-slim`)
- `CERBERUS_CHAIN_SANDBOX_TIMEOUT_SEC`: timeout por comando (default: `120`)
- `CERBERUS_CHAIN_SANDBOX_NETWORK`: `bridge` o `none` (default: `bridge`)
- `CERBERUS_CHAIN_SANDBOX_READ_ONLY`: `true`/`false` (default: `true`)

## Recomendado en dev

```bash
set CERBERUS_CHAIN_SANDBOX_MODE=auto
set CERBERUS_CHAIN_SANDBOX_IMAGE=cerberus-chain-runner:latest
```

En `auto`, si Docker falla, el runner cae a modo local para no interrumpir jobs.


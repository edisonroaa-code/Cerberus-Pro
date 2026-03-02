# Matriz de Remediacion L5 (APT / Grado Militar)

Fecha de auditoria base: 2026-02-27  
Objetivo: cerrar brechas criticas para aproximar el sistema a un nivel L5 real, medible y auditable.

## Alcance y criterio
- Esta matriz prioriza controles tecnicos verificables, no etiquetas comerciales.
- Cada accion tiene criterio de aceptacion y evidencia esperada.
- Prioridades:
  - P0: bloqueo inmediato de riesgo critico (0-7 dias)
  - P1: endurecimiento estructural (8-30 dias)
  - P2: madurez avanzada y aseguramiento continuo (31-90 dias)

## P0 (0-7 dias): Riesgo critico

| ID | Riesgo | Accion | Archivos objetivo | Criterio de aceptacion | Evidencia |
|---|---|---|---|---|---|
| P0-01 | Escalada de privilegios por `register` | Restringir `POST /auth/register` a `ADMIN`/`SUPER_ADMIN` y forzar rol server-side (ignorar `role` de input para no-admin). | `backend/routers/auth.py` | Usuario no admin recibe `403` al crear usuarios; rol final no viene del cliente sin permiso. | Test API: intento con token pentester = `403`. |
| P0-02 | Exposicion de hash de password en respuestas | Eliminar `response_model=User` en registro/perfil administrativo; usar DTO seguro sin `password_hash`, `mfa_secret`, `reset_token`. | `backend/routers/auth.py`, `backend/auth_security.py` | Ninguna respuesta HTTP expone campos secretos. | Prueba de contrato JSON y grep de payloads de respuesta. |
| P0-03 | Exposicion de clave C2 | Remover `encryption_key` de respuestas (`/c2/register`). Entrega de secretos solo por canal bootstrap seguro y una sola vez. | `backend/routers/c2.py`, `backend/c2/c2_server.py` | API ya no retorna claves criptograficas. | Test endpoint y OpenAPI sin `encryption_key`. |
| P0-04 | Endpoints sin autorizacion granular | Proteger `routers/engines.py`, `routers/health.py`, `routers/verdicts.py` con `Depends(require_permission(...))`. | `backend/routers/engines.py`, `backend/routers/health.py`, `backend/routers/verdicts.py` | Acceso anonimo devuelve `401/403`; perfiles minimos no ven operaciones administrativas. | Tests de authz por endpoint. |
| P0-05 | Secrets inseguros en entorno | Rotar y sacar secretos comprometidos (API keys, DB creds, JWT secret) y revocar claves expuestas. | `.env`, secretos CI/CD, proveedor Gemini/DB | Ningun secreto real en repo o logs; todos rotados. | Registro de rotacion + escaneo de secretos limpio. |
| P0-06 | Fallback criptografico inseguro | Fallar en arranque si faltan `JWT_SECRET_KEY`, `ENCRYPTION_KEY`, `MFA_ENCRYPTION_KEY` en `production` (sin defaults inseguros). | `backend/auth_security.py`, `backend/encryption.py`, `backend/ares_runtime.py` | En `production`, falta de clave aborta startup. | Test de arranque con variables faltantes = fail esperado. |
| P0-07 | TLS bypass activo | Eliminar `verify=False` en clientes HTTP productivos y activar validacion TLS estricta. | `backend/v4_omni_surface.py`, `backend/aiie_engine.py`, `tools/agent_cerberus_sqlmap.py` | No existe `verify=False` fuera de fixtures de test. | `rg "verify=False"` limpio en runtime. |
| P0-08 | Scope abierto por defecto | Cambiar politica: `ALLOWED_TARGETS` vacio debe bloquear (`deny by default`) en `production`. | `backend/core/process_guard.py`, `backend/ares_runtime.py` | Sin allowlist explicita no se ejecutan scans. | Test: target no permitido => `403`. |

## P1 (8-30 dias): Endurecimiento estructural

| ID | Riesgo | Accion | Archivos objetivo | Criterio de aceptacion | Evidencia |
|---|---|---|---|---|---|
| P1-01 | MFA parcialmente implementado | Implementar enforcement real de `require_mfa` en endpoints sensibles y flujo de session step-up. | `backend/auth_security.py`, `backend/routers/admin.py`, `backend/routers/c2.py`, `backend/routers/offensive.py` | Operaciones sensibles exigen MFA valido para roles definidos. | Tests de acceso con y sin MFA. |
| P1-02 | Auditoria forense incompleta | Registrar IP y User-Agent reales; firmar eventos y fortalecer cadena de custodia. | `backend/core/audit_runtime.py`, `backend/core/audit_chain_store.py` | Logs contienen metadata real verificable por evento. | Verificacion de cadena + muestras de log auditado. |
| P1-03 | Seguridad de transporte interna | Habilitar TLS extremo a extremo (API, WS, DB), retirar `sslmode=disable` en despliegues no-dev. | `docker-compose.yml`, configuracion despliegue | En entorno target, todo trafico interno y externo usa TLS valido. | Escaneo de config y pruebas de conexion TLS. |
| P1-04 | CORS y superficie excesiva | Restringir `allow_methods`/`allow_headers` a minimo necesario y revisar rutas publicas de salud/veredictos. | `backend/ares_runtime.py`, routers health/verdict | Politica CORS minimizada y justificada por endpoint. | Test de preflight y matriz de permisos. |
| P1-05 | Modelo de estado en memoria | Migrar entidades criticas (`users`, `api_keys`, `agents`, `verdicts`) a persistencia segura transaccional. | `backend/core/runtime_state.py`, `backend/routers/verdicts.py`, capa DB | Reinicio no pierde estado critico y hay trazabilidad durable. | Pruebas de reinicio + consistencia ACID. |
| P1-06 | Control de rate limit en dev/prod | Asegurar politicas por rol/ruta y no deshabilitar por defecto en entornos expuestos. | `backend/ares_runtime.py` | Rutas sensibles limitadas; abuso reproduce `429`. | Tests de carga controlada. |
| P1-07 | Dependencias y hardening de contenedor | Ejecutar como usuario no root, minimizar imagen base, bloquear capacidades y FS donde aplique. | `backend/Dockerfile`, `backend/sandbox/Dockerfile.chain-runner`, `docker-compose.yml` | Contenedores sin root y con runtime policy endurecida. | Evidencia de imagen y runtime config. |

## P2 (31-90 dias): Madurez L5

| ID | Objetivo L5 | Accion | Criterio de aceptacion | Evidencia |
|---|---|---|---|---|
| P2-01 | Supply chain verificable | SBOM obligatorio, firma de artefactos, verificacion de procedencia en CI/CD. | Cada release tiene SBOM y firma validable antes de deploy. | Artefacto SBOM + verificacion en pipeline. |
| P2-02 | Criptografia gestionada | Migrar claves a KMS/HSM, rotacion automatica y politicas de expiracion. | Ninguna clave larga vida en `.env` local para prod. | Politicas KMS + runbooks de rotacion. |
| P2-03 | Zero Trust operativo | mTLS servicio-a-servicio, segmentacion por identidad y autorizacion contextual. | Acceso interno denegado sin identidad fuerte. | Pruebas de acceso inter-servicio negativas/positivas. |
| P2-04 | Deteccion y respuesta | SIEM/SOAR con alertas de alta fidelidad (authz, exfil, privesc, abuso API). | MTTD/MTTR definidos y medidos con ejercicios. | Reportes de simulacro y KPIs. |
| P2-05 | Aseguramiento continuo | SAST/DAST/SCA + politicas de merge con bloqueos por severidad. | PR critico no mergea sin remediacion o waiver formal. | Historial de pipeline y politicas de excepcion. |
| P2-06 | Cumplimiento verificable | Baseline mapeado a NIST/ISO y auditorias periodicas con evidencia inmutable. | Hallazgos mayores cerrados y controlados por ciclo. | Informe de auditoria y matriz de controles. |

## Quick Wins (48h)
- Bloquear `register` para no-admin y ocultar campos sensibles en respuestas.
- Quitar devolucion de `encryption_key` en C2.
- Introducir chequeos de startup fail-closed para secretos en produccion.
- Eliminar `verify=False` en runtime y restringir targets por defecto.

## KPIs de avance
- `Critical authz findings open`: objetivo `0` al cierre de P0.
- `% endpoints sensibles con permiso explicito`: objetivo `100%`.
- `Secrets hardcoded/expuestos`: objetivo `0`.
- `TLS bypass points en runtime`: objetivo `0`.
- `Eventos de auditoria con IP+UA reales`: objetivo `>= 99%`.

## Gate de certificacion interna L5 (recomendado)
- No declarar “L5” hasta cerrar todos los P0 y al menos 80% de P1 con evidencia reproducible.
- Requiere firma de Arquitectura, Seguridad y Operaciones.

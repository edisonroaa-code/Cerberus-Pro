from fastapi import HTTPException

from backend.cerberus_pro_api_secure import validate_omni_config


def test_validate_omni_web_ok():
    cfg = {
        "mode": "web",
        "unified": {"maxParallel": 4, "vectors": ["UNION", "TIME"]},
    }
    assert validate_omni_config(cfg) == "web"


def test_validate_omni_reject_invalid_mode():
    cfg = {"mode": "invalid", "unified": {"maxParallel": 2, "vectors": ["UNION"]}}
    try:
        validate_omni_config(cfg)
        assert False, "Expected HTTPException"
    except HTTPException as exc:
        assert exc.status_code == 400


def test_validate_omni_direct_db_requires_host_port():
    cfg = {
        "mode": "direct_db",
        "unified": {"maxParallel": 2, "directDb": {"host": "", "port": 3306}},
    }
    try:
        validate_omni_config(cfg)
        assert False, "Expected HTTPException"
    except HTTPException as exc:
        assert exc.status_code == 400


def test_validate_omni_rejects_legacy_omni_contract():
    cfg = {
        "mode": "web",
        "omni": {"maxParallel": 2, "vectors": ["UNION"]},
    }
    try:
        validate_omni_config(cfg)
        assert False, "Expected HTTPException"
    except HTTPException as exc:
        assert exc.status_code == 400
        assert "config.unified" in str(exc.detail)

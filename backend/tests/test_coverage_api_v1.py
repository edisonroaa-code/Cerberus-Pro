from backend.cerberus_pro_api_secure import _fallback_coverage_response_from_job


def test_fallback_coverage_defaults_to_inconclusive():
    job = {
        "status": "queued",
        "kind": "unified",
        "config": {"mode": "web"},
        "vulnerable": None,
    }
    response = _fallback_coverage_response_from_job(job, "scan_test_1", limit=50, cursor=0)
    assert response.version == "coverage.v1"
    assert response.scan_id == "scan_test_1"
    assert response.verdict == "INCONCLUSIVE"
    assert response.conclusive is False
    assert response.vulnerable is False
    assert response.vector_records_page.limit == 50


def test_fallback_coverage_marks_vulnerable_when_job_has_confirmed_flag():
    job = {
        "status": "completed",
        "kind": "unified",
        "config": {"mode": "web"},
        "vulnerable": True,
    }
    response = _fallback_coverage_response_from_job(job, "scan_test_2", limit=10, cursor=0)
    assert response.verdict == "VULNERABLE"
    assert response.conclusive is True
    assert response.vulnerable is True

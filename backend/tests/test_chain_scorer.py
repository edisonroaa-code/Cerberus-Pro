from backend.core.chain_scorer import compute_chain_score, score_chain_template


def test_compute_chain_score_ranges():
    s1 = compute_chain_score(0.0)
    s2 = compute_chain_score(10.0)
    assert 0.0 <= s1 <= 100.0
    assert 0.0 <= s2 <= 100.0
    assert s2 > s1


def test_score_chain_template_prefers_higher_cvss(tmp_path):
    # create two templates with different base_cvss
    tpl_low = {"base_cvss": 3.0, "temporal": 0.0, "environmental": 0.0}
    tpl_high = {"base_cvss": 9.0, "temporal": 0.0, "environmental": 0.0}
    s_low = score_chain_template(tpl_low)
    s_high = score_chain_template(tpl_high)
    assert s_high > s_low

"""
Autopilot Utilities - Defense Detection & Analysis
"""

def detect_defensive_measures(log_output: str) -> dict:
    """
    Analyze scan output for WAF/IDS/IPS signatures, rate limiting,
    connection resets, and honeypot indicators.

    Returns:
        dict with keys: waf_detected, rate_limited, rate_limit_count,
        connection_issues, honeypot_probability, signatures, recommended_action
    """
    result = {
        "waf_detected": False,
        "rate_limited": False,
        "rate_limit_count": 0,
        "connection_issues": False,
        "honeypot_probability": 0.0,
        "signatures": [],
        "recommended_action": "continue",  # continue | reduce_aggression | abort
    }

    if not log_output:
        return result

    lines = log_output.lower().split("\n")

    # WAF signatures
    waf_sigs = [
        "waf/ips/ids", "cloudflare", "akamai", "modsecurity",
        "imperva", "f5 big-ip", "barracuda", "sucuri",
        "incapsula", "fortiweb", "wallarm", "aws waf",
        "azure front door", "citrix", "securesphere",
    ]
    for line in lines:
        for sig in waf_sigs:
            if sig in line:
                result["waf_detected"] = True
                if sig not in result["signatures"]:
                    result["signatures"].append(sig)

    # Rate limiting / defensive HTTP behavior (429 / 403 / 502 / 503)
    rate_limit_count = 0
    forbidden_count = 0
    bad_gateway_count = 0
    service_unavail_count = 0
    for line in lines:
        if "429" in line and ("too many" in line or "error code" in line):
            rate_limit_count += 1
        if "403" in line and ("forbidden" in line or "error code" in line or "access denied" in line):
            forbidden_count += 1
        if "502" in line and ("bad gateway" in line or "error code" in line):
            bad_gateway_count += 1
        if "503" in line and ("service unavailable" in line or "error code" in line):
            service_unavail_count += 1

    result["rate_limit_count"] = rate_limit_count
    if rate_limit_count >= 2:
        result["rate_limited"] = True
    if forbidden_count >= 2:
        result["waf_detected"] = True
        if "http_403_forbidden" not in result["signatures"]:
            result["signatures"].append("http_403_forbidden")
    if bad_gateway_count >= 2:
        result["connection_issues"] = True
    if service_unavail_count >= 2:
        result["connection_issues"] = True

    # Connection issues
    conn_issue_sigs = ["connection reset", "connection refused", "connection timed out",
                       "connection dropped", "proxy error"]
    for line in lines:
        if any(sig in line for sig in conn_issue_sigs):
            result["connection_issues"] = True
            break

    # Honeypot detection: identical responses to different payloads
    honeypot_indicators = 0
    for line in lines:
        if "identical content" in line:
            honeypot_indicators += 1
        if "monitored" in line and ("identical" in line or "honeypot" in line):
            honeypot_indicators += 2

    if honeypot_indicators >= 3:
        result["honeypot_probability"] = 0.85
    elif honeypot_indicators >= 2:
        result["honeypot_probability"] = 0.6
    elif honeypot_indicators >= 1:
        result["honeypot_probability"] = 0.3

    # Determine recommended action
    if result["honeypot_probability"] >= 0.7:
        result["recommended_action"] = "abort"
    elif result["waf_detected"] and result["rate_limited"]:
        result["recommended_action"] = "abort"
    elif result["rate_limited"]:
        result["recommended_action"] = "reduce_aggression"
    elif result["waf_detected"] and result["connection_issues"]:
        result["recommended_action"] = "reduce_aggression"
    elif result["honeypot_probability"] >= 0.5:
        result["recommended_action"] = "reduce_aggression"

    return result

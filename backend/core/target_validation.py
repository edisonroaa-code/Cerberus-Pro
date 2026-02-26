"""
Target validation helpers extracted from ares_api.py.
"""

from __future__ import annotations

from typing import Any, Callable, Sequence, Set
from urllib.parse import urljoin, urlparse

import httpx


def validate_target(
    url: str,
    user: Any,
    *,
    allowed_web_schemes: Set[str],
    allow_local_targets: bool,
    environment: str,
    allowed_targets: Sequence[str],
    validate_redirect_chain: bool,
    host_allowed_fn: Callable[[str], bool],
    resolve_and_validate_fn: Callable[[str, bool], Any],
    logger: Any,
) -> bool:
    """Validate scan target with DNS resolution and redirect checks."""
    try:
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in allowed_web_schemes:
            logger.warning("🚫 Blocked scheme: %s for %s", scheme, url)
            return False
        hostname = parsed.hostname or ""
        if not hostname:
            logger.warning("🚫 Missing hostname in target: %s", url)
            return False
        if not host_allowed_fn(hostname):
            username = str(getattr(user, "username", "unknown"))
            logger.warning("🚫 Target host not in strict allowlist: %s by %s", hostname, username)
            return False
    except Exception:
        return False

    try:
        allow_private = bool(allow_local_targets) or (
            str(environment).lower() == "development"
            and "localhost" in [str(a).lower() for a in allowed_targets]
        )

        resolved_ip = resolve_and_validate_fn(url, allow_private)
        logger.info("✅ Target resolved: %s -> %s", url, resolved_ip)

        if validate_redirect_chain:
            with httpx.Client(follow_redirects=False, timeout=5.0) as client:
                current = url
                for _ in range(5):
                    try:
                        response = client.head(current)
                        if response.status_code in (405, 501):
                            response = client.get(current)
                    except Exception:
                        break

                    if response.status_code not in (301, 302, 303, 307, 308):
                        break

                    location = response.headers.get("location")
                    if not location:
                        break

                    nxt = urljoin(current, location)
                    parsed_nxt = urlparse(nxt)
                    if (parsed_nxt.scheme or "").lower() not in allowed_web_schemes:
                        logger.warning("🚫 Redirect blocked by scheme: %s", nxt)
                        return False
                    host = parsed_nxt.hostname or ""
                    if not host or not host_allowed_fn(host):
                        logger.warning("🚫 Redirect blocked by allowlist: %s", nxt)
                        return False
                    try:
                        resolve_and_validate_fn(nxt, allow_private)
                    except Exception:
                        logger.warning("🚫 Redirect blocked by DNS policy: %s", nxt)
                        return False
                    current = nxt
        return True

    except ValueError as exc:
        username = str(getattr(user, "username", "unknown"))
        logger.warning("🚫 Blocked target resolution: %s -> %s by %s", url, exc, username)
        return False
    except Exception as exc:
        logger.error("❌ DNS validation error: %s -> %s", url, exc)
        return False


def validate_network_host(
    host: str,
    *,
    host_allowed_fn: Callable[[str], bool],
    resolve_and_validate_fn: Callable[[str, bool], Any],
) -> bool:
    if not host_allowed_fn(host):
        return False
    try:
        resolve_and_validate_fn(host, False)
        return True
    except Exception:
        return False

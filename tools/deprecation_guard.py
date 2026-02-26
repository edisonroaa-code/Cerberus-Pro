#!/usr/bin/env python3
"""
Deprecation guardrails.

Fails if known deprecated patterns are reintroduced in runtime backend code.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"

EXCLUDE_PARTS = {"archive", "tests", "__pycache__"}

RULES = (
    (re.compile(r"\bdatetime\.utcnow\("), "Use timezone-aware datetime.now(timezone.utc) instead of datetime.utcnow()"),
    (re.compile(r"\bdatetime\.now\(\s*\)"), "Use timezone-aware datetime.now(timezone.utc) instead of naive datetime.now()"),
    (re.compile(r"\bdatetime\.datetime\.now\(\s*\)"), "Use timezone-aware datetime.datetime.now(datetime.timezone.utc) instead of naive datetime.datetime.now()"),
    (re.compile(r"@validator\("), "Use Pydantic v2 @field_validator instead of @validator"),
    (re.compile(r"^\s*class\s+Config\s*:", re.MULTILINE), "Use Pydantic v2 model_config = ConfigDict(...) instead of class Config"),
)


def should_scan(path: Path) -> bool:
    rel = path.relative_to(ROOT)
    return not any(part in EXCLUDE_PARTS for part in rel.parts)


def main() -> int:
    errors: list[str] = []
    for py in BACKEND.rglob("*.py"):
        if not should_scan(py):
            continue
        text = py.read_text(encoding="utf-8", errors="ignore")
        rel = py.relative_to(ROOT)
        for pattern, message in RULES:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                errors.append(f"{rel}:{line}: {message}")

    if errors:
        print("Deprecation guard failed:")
        for e in errors:
            print(f"- {e}")
        return 1

    print("Deprecation guard passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

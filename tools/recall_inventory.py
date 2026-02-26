#!/usr/bin/env python3
"""
Recall inventory helper.

Generates a quick runtime-oriented inventory for backend files:
- import reference count
- route declaration count
- test reference count
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List


ROOT = Path(__file__).resolve().parents[1]


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def collect_files(base: Path) -> List[Path]:
    return sorted([p for p in base.rglob("*.py") if p.is_file()])


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate recall inventory")
    parser.add_argument("--json", dest="as_json", action="store_true", help="Print JSON")
    args = parser.parse_args()

    backend_dir = ROOT / "backend"
    files = collect_files(backend_dir)

    corpus_paths = collect_files(backend_dir) + collect_files(ROOT / "tools")
    corpus = {p: read_text(p) for p in corpus_paths}

    out: List[Dict[str, object]] = []
    for f in files:
        rel = f.relative_to(ROOT).as_posix()
        mod_name = rel.replace("/", ".").removesuffix(".py")
        filename = f.name
        txt = read_text(f)

        route_count = len(re.findall(r"@app\.(get|post|put|delete|patch)\(", txt))
        import_refs = 0
        test_refs = 0
        for p, c in corpus.items():
            if p == f:
                continue
            if mod_name in c or filename in c:
                import_refs += 1
                if "tests/" in p.as_posix():
                    test_refs += 1

        out.append(
            {
                "file": rel,
                "routes": route_count,
                "refs": import_refs,
                "test_refs": test_refs,
            }
        )

    # Highest value first
    out.sort(key=lambda x: (int(x["routes"]), int(x["refs"]), int(x["test_refs"])), reverse=True)

    if args.as_json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 0

    print("file,routes,refs,test_refs")
    for row in out:
        print(f"{row['file']},{row['routes']},{row['refs']},{row['test_refs']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


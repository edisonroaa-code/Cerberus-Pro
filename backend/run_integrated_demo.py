#!/usr/bin/env python3
"""
Integrated operational runner.

Delegates to the real safe SQLMap execution flow.
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--sqlmap-path", default=None, help="Path to sqlmap.py")
    parser.add_argument("--timeout", type=int, default=600, help="Runtime timeout in seconds")
    parser.add_argument("--level", type=int, default=5)
    parser.add_argument("--risk", type=int, default=3)
    parser.add_argument("--allow-non-local", action="store_true", help="Sets ALLOW_LOCAL_TARGETS=1 for this run")
    args = parser.parse_args()

    runner = os.path.join(os.path.dirname(__file__), "run_sqlmap_safe.py")
    cmd = [
        sys.executable,
        runner,
        "--target",
        args.target,
        "--timeout",
        str(args.timeout),
        "--level",
        str(args.level),
        "--risk",
        str(args.risk),
        "--confirm-local-run",
    ]
    if args.sqlmap_path:
        cmd.extend(["--sqlmap-path", args.sqlmap_path])

    env = dict(os.environ)
    if args.allow_non_local:
        env["ALLOW_LOCAL_TARGETS"] = "1"

    print("Executing integrated operational flow:")
    print(" ".join(shlex.quote(part) for part in cmd))
    proc = subprocess.run(cmd, env=env)
    return int(proc.returncode)


if __name__ == "__main__":
    raise SystemExit(main())

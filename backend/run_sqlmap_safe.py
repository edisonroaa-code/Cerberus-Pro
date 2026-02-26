"""Safe end-to-end SQLMap validator (local-only).

This script is intentionally conservative:
- Only allows localhost targets (127.0.0.1, localhost, ::1) unless ALLOW_LOCAL_TARGETS=1
- Requires explicit `--confirm-local-run` flag to execute
- Enforces a runtime timeout and CPU/AS limits on Unix
- Captures output, synthesizes structured findings, and writes a short history JSON

Usage (example):
  set PYTHONPATH=%CD%&& python backend\run_sqlmap_safe.py --target http://127.0.0.1:8080/ --confirm-local-run

DO NOT run this against remote or third-party targets.
"""
import argparse
import json
import os
import shlex
import signal
import subprocess
import sys
import time
from urllib.parse import urlparse

from v4_intelligence import synthesize_structured_findings

DEFAULT_TIMEOUT = 600
DEFAULT_SQLMAP = os.environ.get("CERBERUS_SQLMAP_PATH", os.path.join(os.path.dirname(__file__), '..', 'ares_engine', 'sqlmap.py'))


def _is_localhost(hostname: str) -> bool:
    hn = (hostname or "").lower()
    return hn in ("localhost", "127.0.0.1", "::1")


def _set_limits_unix(cpu_seconds: int, as_mb: int):
    try:
        import resource

        soft_cpu = cpu_seconds
        hard_cpu = cpu_seconds + 5
        resource.setrlimit(resource.RLIMIT_CPU, (soft_cpu, hard_cpu))
        max_bytes = as_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (max_bytes, max_bytes))
    except Exception:
        pass


def build_sqlmap_cmd(python_exec: str, sqlmap_path: str, target: str, extra_args: list) -> list:
    cmd = [python_exec, sqlmap_path, "-u", target]
    cmd += [
        "--batch",
        "--disable-coloring",
        "--answers=follow=Y,redirect=Y,resend=Y,form=Y,blank=Y,quit=N",
    ]
    cmd += extra_args
    return cmd


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--target", required=True, help="Target URL (must be localhost)")
    p.add_argument("--sqlmap-path", default=DEFAULT_SQLMAP, help="Path to sqlmap.py or executable")
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Max runtime seconds")
    p.add_argument("--confirm-local-run", action="store_true", help="Confirm you intend to run against localhost")
    p.add_argument("--level", type=int, default=5)
    p.add_argument("--risk", type=int, default=3)
    args = p.parse_args()

    parsed = urlparse(args.target)
    host = parsed.hostname or ""

    allow_local = os.environ.get("ALLOW_LOCAL_TARGETS", "0") in ("1", "true", "yes")
    if (not _is_localhost(host)) and (not allow_local):
        print("Refusing to run: target is not localhost. Set ALLOW_LOCAL_TARGETS=1 to override.")
        sys.exit(2)

    if not args.confirm_local_run and (not allow_local):
        print("Refusing to run: please pass --confirm-local-run to acknowledge local execution.")
        sys.exit(2)

    python_exec = sys.executable or "python"
    extra = [f"--level={int(args.level)}", f"--risk={int(args.risk)}", "--threads=3", "--random-agent", "--hex", "--hpp"]
    cmd = build_sqlmap_cmd(python_exec, args.sqlmap_path, args.target, extra)

    print("Running safe SQLMap against localhost target (timeout {}s):".format(args.timeout))
    print(" ".join(shlex.quote(x) for x in cmd))

    try:
        kwargs = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if os.name != "nt":
            kwargs["preexec_fn"] = lambda: _set_limits_unix(cpu_seconds=min(args.timeout, 300), as_mb=512)

        proc = subprocess.Popen(cmd, **kwargs)
        start = time.time()
        out_lines = []
        try:
            while True:
                line = proc.stdout.readline()
                if not line and proc.poll() is not None:
                    break
                if line:
                    txt = line.rstrip('\n')
                    print(txt)
                    out_lines.append(txt)
                if time.time() - start > args.timeout:
                    try:
                        if os.name == 'nt':
                            proc.send_signal(signal.CTRL_BREAK_EVENT)
                        else:
                            proc.kill()
                    except Exception:
                        pass
                    break
        except KeyboardInterrupt:
            try:
                proc.terminate()
            except Exception:
                pass

        exit_code = proc.wait(timeout=5)
        results = [
            {
                "vector": "ENGINE_SQLMAP",
                "vulnerable": any("is vulnerable" in l.lower() or "parece ser vulnerable" in l.lower() or "es vulnerable" in l.lower() for l in out_lines),
                "evidence": out_lines[-20:],
                "exit_code": int(exit_code),
                "command": cmd,
            }
        ]

        structured = synthesize_structured_findings(args.target, results)
        summary = {
            "target": args.target,
            "timestamp": time.strftime("%Y%m%d_%H%M%S"),
            "results": results,
            "structured_findings": structured,
        }
        outfile = os.path.join(os.path.dirname(__file__), f"safe_run_{int(time.time())}.json")
        with open(outfile, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        print("\nStructured findings:\n", json.dumps(structured, indent=2, ensure_ascii=False))
        print(f"History saved to: {outfile}")
        sys.exit(0 if exit_code == 0 else 1)
    except FileNotFoundError:
        print(f"sqlmap not found at {args.sqlmap_path}; install sqlmap or set --sqlmap-path")
        sys.exit(3)


if __name__ == "__main__":
    main()

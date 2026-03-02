"""Benchmark runner for vector prioritization.

This tool supports two modes:
- baseline: iterate vectors in input order
- ml: score vectors with `backend/ml/vector_predictor.py` and prioritize high-score vectors

Detection is operational-only: you must provide `--scan-cmd`, formatted with
`{endpoint}`, `{method}`, `{param_name}` and executed per-vector.
"""
from __future__ import annotations

import argparse
import json
import time
import subprocess
from typing import Any, Dict, List, Optional

from pathlib import Path


def load_vectors(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_labels(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def run_scan_cmd(cmd_template: str, vector: Dict[str, Any], timeout: Optional[int] = 30) -> subprocess.CompletedProcess:
    cmd = cmd_template.format(**{k: str(v) for k, v in vector.items()})
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)


def benchmark(vectors_file: str, labels_file: str, use_ml: bool = False, model_path: Optional[str] = None, scan_cmd: Optional[str] = None) -> Dict[str, Any]:
    if not scan_cmd:
        raise ValueError("scan_cmd is required for operational benchmark runs")

    vectors = load_vectors(vectors_file)
    labels = load_labels(labels_file)

    order = list(range(len(vectors)))

    if use_ml and model_path:
        # import predictor dynamically
        from backend.ml.vector_predictor import extract_features, joblib

        model = joblib.load(model_path)
        scores = [model.predict_proba([extract_features(v)])[0][1] for v in vectors]
        order = sorted(range(len(vectors)), key=lambda i: scores[i], reverse=True)

    start = time.time()
    first_found_index: Optional[int] = None
    steps = 0

    for idx in order:
        vec = vectors[idx]
        steps += 1
        detected = False
        try:
            res = run_scan_cmd(scan_cmd, vec)
            # user can define detection heuristics via exit code or stdout parsing
            detected = res.returncode == 0 and ("VULN" in (res.stdout or "") or "vuln" in (res.stdout or "").lower())
        except Exception:
            detected = False

        if detected:
            first_found_index = steps
            break

    elapsed = time.time() - start
    return {
        "use_ml": bool(use_ml),
        "vectors": len(vectors),
        "steps_to_first_vuln": first_found_index,
        "time_seconds": elapsed,
        "steps_executed": steps,
    }


def _cli():
    p = argparse.ArgumentParser()
    p.add_argument("--vectors", required=True)
    p.add_argument("--labels", required=True)
    p.add_argument("--mode", choices=["baseline", "ml"], default="baseline")
    p.add_argument("--model", help="Path to trained model (required for ml mode)")
    p.add_argument("--scan-cmd", required=True, help="Command template to run per vector")
    args = p.parse_args()

    if args.mode == "ml" and not args.model:
        p.error("--model is required in ml mode")

    result = benchmark(args.vectors, args.labels, use_ml=(args.mode=="ml"), model_path=args.model, scan_cmd=args.scan_cmd)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _cli()

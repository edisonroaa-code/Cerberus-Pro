"""MVP vector predictor: simple feature extraction + sklearn RandomForest.

Usage (training):
  python -m backend.ml.vector_predictor train --data-file data.json --model-out model.joblib

Usage (predict):
  python -m backend.ml.vector_predictor predict --model model.joblib --vectors vectors.json

The module expects vectors as dicts with keys like: endpoint, method, param_name, content_type, server_header
This is an MVP: replace or extend model with XGBoost/LightGBM later.
"""
from __future__ import annotations

import argparse
import json
import os
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score


def extract_features(v: Dict[str, Any]) -> List[float]:
    # Simple, robust feature extraction for MVP
    features: List[float] = []
    method = v.get("method", "GET").upper()
    features.append(1.0 if method == "GET" else 0.0)
    features.append(1.0 if method == "POST" else 0.0)

    endpoint = v.get("endpoint", "").count("/")
    features.append(float(min(endpoint, 10)))

    content_type = v.get("content_type", "").lower()
    features.append(1.0 if "json" in content_type else 0.0)
    features.append(1.0 if "xml" in content_type else 0.0)

    server = v.get("server", "").lower()
    features.append(1.0 if "nginx" in server else 0.0)
    features.append(1.0 if "apache" in server else 0.0)

    name = v.get("param_name", "").lower()
    features.append(1.0 if "id" in name else 0.0)
    features.append(1.0 if "user" in name else 0.0)

    # numeric heuristics: length of param and value
    features.append(float(min(len(name), 64)))
    val = v.get("sample_value", "")
    features.append(float(min(len(str(val)), 256)))

    return features


def fit_model(X: List[List[float]], y: List[int]) -> RandomForestClassifier:
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X, y)
    return clf


def train_from_file(data_file: str, model_out: str) -> None:
    with open(data_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    X = [extract_features(item["vector"]) for item in data]
    y = [1 if item.get("vuln_found") else 0 for item in data]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = fit_model(X_train, y_train)

    y_probs = clf.predict_proba(X_test)[:, 1]
    try:
        auc = roc_auc_score(y_test, y_probs)
    except Exception:
        auc = 0.0

    os.makedirs(os.path.dirname(model_out) or ".", exist_ok=True)
    joblib.dump(clf, model_out)
    print(f"Trained model saved to {model_out}; AUC={auc:.3f}")


def predict_from_file(model_path: str, vectors_file: str) -> None:
    clf = joblib.load(model_path)
    with open(vectors_file, "r", encoding="utf-8") as f:
        items = json.load(f)

    X = [extract_features(v) for v in items]
    probs = clf.predict_proba(X)[:, 1]
    out = [{"vector": v, "score": float(p)} for v, p in zip(items, probs)]
    print(json.dumps(out, indent=2))


def _cli():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")

    t = sub.add_parser("train")
    t.add_argument("--data-file", required=True)
    t.add_argument("--model-out", required=True)

    pr = sub.add_parser("predict")
    pr.add_argument("--model", required=True)
    pr.add_argument("--vectors", required=True)

    args = p.parse_args()
    if args.cmd == "train":
        train_from_file(args.data_file, args.model_out)
    elif args.cmd == "predict":
        predict_from_file(args.model, args.vectors)
    else:
        p.print_help()


if __name__ == "__main__":
    _cli()

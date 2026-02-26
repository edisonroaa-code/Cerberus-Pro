# Benchmark runner

This folder contains a small benchmark harness to compare `baseline` vs `ml` vector prioritization.

Quick demo (uses the provided synthetic data and the MVP model):

```bash
python -m backend.bench.runner --vectors ../ml/sample_vectors.json --labels ../ml/sample_training_data.json --mode baseline

python -m backend.bench.runner --vectors ../ml/sample_vectors.json --labels ../ml/sample_training_data.json --mode ml --model ../ml/model.joblib
```

Notes:
- By default the runner uses a simulated detection (matches labels in `sample_training_data.json`).
- For real runs, prepare a `--scan-cmd` that executes an engine for a vector, e.g.: 
  `--scan-cmd "python tools/run_scan.py --target {endpoint} --param {param_name} --method {method}"`
- Provide a real training dataset and a production model (XGBoost/LightGBM recommended) for accurate results.

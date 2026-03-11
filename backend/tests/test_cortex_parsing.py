import sys
import os
import json
from typing import Dict, Any, Optional

# Add the root directory to sys.path to import backend modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

try:
    from backend.core.cortex_ai import _extract_json
except ImportError as e:
    print(f"Error importing _extract_json: {e}")
    sys.exit(1)

def test_extract_json():
    test_cases = [
        {
            "name": "Perfect JSON",
            "input": '{"status": "vulnerable", "confidence": 0.9}',
            "expected": {"status": "vulnerable", "confidence": 0.9}
        },
        {
            "name": "Markdown Wrapped",
            "input": '```json\n{"status": "safe", "confidence": 0.1}\n```',
            "expected": {"status": "safe", "confidence": 0.1}
        },
        {
            "name": "Text + JSON",
            "input": 'Analizando... aquí está el resultado: {"status": "inconclusive", "confidence": 0.5} y eso es todo.',
            "expected": {"status": "inconclusive", "confidence": 0.5}
        },
        {
            "name": "Nested Braces in Text (Tricky)",
            "input": 'Random text with { curly } and then {"real": "json"}',
            "expected": {"real": "json"}
        },
        {
            "name": "Empty Input",
            "input": "",
            "expected": None
        },
        {
            "name": "Malformed JSON",
            "input": '{"broken": "json"',
            "expected": None
        },
        {
            "name": "Non-JSON Text",
            "input": "This is just plain text with no json objects.",
            "expected": None
        }
    ]

    passed = 0
    failed = 0

    print("--- Running Cortex AI JSON Parsing Tests ---")
    for case in test_cases:
        result = _extract_json(case["input"])
        if result == case["expected"]:
            print(f"[PASS] {case['name']}")
            passed += 1
        else:
            print(f"[FAIL] {case['name']}")
            print(f"       Expected: {case['expected']}")
            print(f"       Got:      {result}")
            failed += 1

    print(f"\nSummary: {passed} passed, {failed} failed.")
    return failed == 0

if __name__ == "__main__":
    if test_extract_json():
        sys.exit(0)
    else:
        sys.exit(1)

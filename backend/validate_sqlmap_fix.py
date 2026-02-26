"""Lightweight validator for SQLMap adapter command generation and synthesis.
This script does NOT execute sqlmap; it builds the commands used by the orchestrator
and demonstrates the `synthesize_structured_findings` output using a sample result.
"""
import json
from urllib.parse import urlparse
from v4_omni_surface import build_vector_commands, PolymorphicEvasionEngine
from v4_intelligence import synthesize_structured_findings
import sys

TARGET = "http://example.com/test?id=1"
PYTHON = sys.executable or "python"
SQLMAP_PATH = "sqlmap.py"

def demo_build():
    vectors = ["UNION", "ERROR", "TIME", "BOOLEAN"]
    polymorphic = PolymorphicEvasionEngine("general_strong")
    sql_config = {"threads": 3, "level": 5, "risk": 3, "tamper": "space2comment,between"}
    stealth_args = []
    commands = build_vector_commands(
        python_exec=PYTHON,
        sqlmap_path=SQLMAP_PATH,
        target_url=TARGET,
        sql_config=sql_config,
        stealth_args=stealth_args,
        polymorphic=polymorphic,
        vectors=vectors,
        omni_cfg={}
    )
    out = []
    for vec, cmd in commands:
        out.append({"vector": vec, "command": cmd})
    print(json.dumps(out, indent=2, ensure_ascii=False))

def demo_synthesize():
    sample_results = [
        {
            "vector": "UNION",
            "vulnerable": True,
            "evidence": ["parameter 'id' (get) appears to be injectable", "back-end DBMS is PostgreSQL"],
            "exit_code": 0,
            "command": [PYTHON, SQLMAP_PATH, "-u", TARGET]
        }
    ]
    structured = synthesize_structured_findings(TARGET, sample_results)
    print("\nStructured findings:\n")
    print(json.dumps(structured, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    print("Building SQLMap vector commands (no execution):")
    demo_build()
    demo_synthesize()

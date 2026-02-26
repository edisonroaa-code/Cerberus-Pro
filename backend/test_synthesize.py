import json
from backend.v4_intelligence import synthesize_structured_findings
sample = [
    {
        'vector': 'UNION',
        'vulnerable': True,
        'evidence': ["parameter 'id' (get) appears to be injectable", 'back-end DBMS is MySQL'],
        'exit_code': 0,
        'command': ['python','sqlmap.py','-u','http://example.com?id=1']
    }
]
res = synthesize_structured_findings('http://example.com', sample)
print(json.dumps(res, indent=2, ensure_ascii=False))

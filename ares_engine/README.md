This folder is a compatibility shim for Cerberus Pro engine.

It preserves the original sqlmap code under `sqlmap-master`. Do NOT delete `sqlmap-master/LICENSE`.

To use the original sqlmap entrypoint from this shim the backend points to `cerberus_engine/sqlmap.py` which will launch the original script.

#!/usr/bin/env python3
# Shim that launches the original sqlmap.py from sqlmap-master with proper path setup
import os
import sys

SCRIPT_DIR = os.path.dirname(__file__)
SQLMAP_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, '..', 'sqlmap-master'))
ORIG = os.path.normpath(os.path.join(SQLMAP_DIR, 'sqlmap.py'))

if not os.path.exists(ORIG):
    sys.exit("[!] Original sqlmap not found at %s" % ORIG)

# Add sqlmap directory to path so it can import lib, plugins, etc.
if SQLMAP_DIR not in sys.path:
    sys.path.insert(0, SQLMAP_DIR)

# Execute the original script
with open(ORIG, 'rb') as f:
    code = compile(f.read(), ORIG, 'exec')
    globals()['__name__'] = '__main__'
    globals()['__file__'] = ORIG
    exec(code, globals())

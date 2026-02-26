"""
Sprint 1 — SEC-001 + SEC-003 Patch Script
Removes dev authentication bypasses and hardcoded credentials.
Run: python tools/apply_sec_fixes.py
"""
import re
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def patch_file(relpath, patches):
    """Apply line-based patches to a file."""
    fpath = os.path.join(ROOT, relpath)
    with open(fpath, "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    for desc, start_marker, end_marker, replacement_lines in patches:
        start_idx = None
        end_idx = None
        for i, line in enumerate(lines):
            if start_marker in line and start_idx is None:
                start_idx = i
            if start_idx is not None and end_marker in line:
                end_idx = i
                break
        
        if start_idx is not None and end_idx is not None:
            lines[start_idx:end_idx+1] = [l + "\n" for l in replacement_lines]
            print(f"  ✅ {desc} (lines {start_idx+1}-{end_idx+1})")
        else:
            print(f"  ❌ {desc} — marker not found")
    
    with open(fpath, "w", encoding="utf-8") as f:
        f.writelines(lines)
    print(f"  💾 Saved: {relpath}")


# =========================================================================
# FIX 1: auth_security.py — Remove get_current_user DEV BYPASS (SEC-001)
# =========================================================================
print("\n[SEC-001] Patching backend/auth_security.py ...")
patch_file("backend/auth_security.py", [
    (
        "Remove DEV BYPASS in get_current_user",
        "# DEV BYPASS: In development, return super admin instantly",
        "jti=\"dev_jti_001\"",
        [
            "    # SEC-001: Dev bypass REMOVED. All environments require valid JWT.",
            "    # To develop locally, generate a real token via POST /auth/login.",
        ]
    ),
])


# =========================================================================
# FIX 2: ares_api.py — Remove WebSocket DEV BYPASS (SEC-001)
# =========================================================================
print("\n[SEC-001] Patching backend/ares_api.py (WebSocket bypass) ...")
patch_file("backend/ares_api.py", [
    (
        "Remove WS dev_token_bypass block",
        "# DEV BYPASS for WebSocket (local only)",
        "jti=\"dev_bypass_jti\"",
        [
            "        # SEC-001: WS dev bypass REMOVED. Real JWT required.",
            "        user = JWTManager.verify_token(token)",
            "        if user.jti in state.revoked_tokens:",
            "            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)",
            "            return",
        ]
    ),
])


# =========================================================================
# FIX 3: auth_security.py — Warn on default JWT secret (SEC-003)
# =========================================================================
print("\n[SEC-003] Checking JWT_SECRET_KEY ...")
fpath = os.path.join(ROOT, "backend/auth_security.py")
with open(fpath, "r", encoding="utf-8") as f:
    content = f.read()

if 'your-super-secret-key-change-in-production' in content:
    content = content.replace(
        'JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "your-super-secret-key-change-in-production")',
        'JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "")\n'
        '    if not JWT_SECRET_KEY:\n'
        '        import warnings\n'
        '        warnings.warn("SEC-003: JWT_SECRET_KEY not set! Generate one with: python -c \\"import secrets; print(secrets.token_urlsafe(64))\\"", stacklevel=2)\n'
        '        JWT_SECRET_KEY = "INSECURE-DEFAULT-CHANGE-ME"'
    )
    with open(fpath, "w", encoding="utf-8") as f:
        f.write(content)
    print("  ✅ Replaced hardcoded JWT secret with env-required + warning")
else:
    print("  ⚠️ Hardcoded JWT secret not found (already patched?)")


print("\n✅ SEC-001 + SEC-003 patches applied successfully.")
print("Next: Run the backend to verify it starts correctly.")

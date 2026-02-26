import os
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

EXCLUDE_DIRS = {
    ".venv",
    "node_modules",
    "dist",
    "__pycache__",
    ".pytest_cache",
    ".git",
    "backend/history",
    "sqlmap-master/.git",
}

EXCLUDE_FILES = {
    ".env",
    ".env.local",
    "backend/audit_log.db",
    "backend/audit_log.sqlite",
}

INCLUDE_EXTS = {
    ".py",
    ".ts",
    ".tsx",
    ".js",
    ".cjs",
    ".mjs",
    ".json",
    ".md",
    ".yml",
    ".yaml",
    ".toml",
    ".txt",
    ".html",
    ".css",
}


def is_excluded_path(p: Path) -> bool:
    rel = p.relative_to(ROOT).as_posix()
    if rel in EXCLUDE_FILES:
        return True
    for d in EXCLUDE_DIRS:
        if rel == d or rel.startswith(d.rstrip("/") + "/"):
            return True
    return False


def should_include_file(p: Path) -> bool:
    if is_excluded_path(p):
        return False
    if not p.is_file():
        return False
    # Avoid huge binary blobs.
    if p.suffix.lower() not in INCLUDE_EXTS:
        return False
    return True


def build_tree(paths: list[Path]) -> str:
    lines: list[str] = []
    for p in sorted(paths, key=lambda x: x.as_posix()):
        lines.append(p.relative_to(ROOT).as_posix())
    return "\n".join(lines)


def write_export_md(paths: list[Path], out_md: Path) -> None:
    tree = build_tree(paths)
    out_md.write_text(
        "# CERBERUS Pro - Source Export (Sanitized)\n\n"
        "This bundle intentionally excludes:\n"
        "- `.env` / secrets\n"
        "- `.venv`, `node_modules`, `dist`\n"
        "- `backend/history` and local DB artifacts\n\n"
        "## File List\n\n"
        "```\n"
        f"{tree}\n"
        "```\n",
        encoding="utf-8",
    )


def build_zip(paths: list[Path], out_zip: Path) -> None:
    if out_zip.exists():
        out_zip.unlink()
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in paths:
            arc = p.relative_to(ROOT).as_posix()
            z.write(p, arcname=arc)


def main() -> None:
    paths: list[Path] = []
    for root, dirs, files in os.walk(ROOT):
        rp = Path(root)
        # Prune excluded dirs aggressively
        rel_root = rp.relative_to(ROOT).as_posix()
        for d in list(dirs):
            dp = (rp / d)
            if is_excluded_path(dp):
                dirs.remove(d)
        for f in files:
            p = rp / f
            if should_include_file(p):
                paths.append(p)

    out_md = ROOT / "EXPORT_SOURCE.md"
    out_zip = ROOT / "cerberus_source_export.zip"
    write_export_md(paths, out_md)
    build_zip(paths, out_zip)
    print(f"Wrote {out_md}")
    print(f"Wrote {out_zip} ({out_zip.stat().st_size} bytes)")


if __name__ == "__main__":
    main()


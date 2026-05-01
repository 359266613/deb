from __future__ import annotations

from pathlib import Path
from typing import Any


def parse_control_text(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in text.splitlines():
        if not line:
            continue
        if line.startswith((" ", "\t")) and current:
            fields[current] += "\n" + line.strip()
            continue
        if ":" in line:
            key, value = line.split(":", 1)
            current = key.strip()
            fields[current] = value.strip()
    return fields


def parse_lines_file(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]


def analyze_metadata(control_dir: Path) -> dict[str, Any]:
    control_path = control_dir / "control"
    fields = parse_control_text(control_path.read_text(encoding="utf-8", errors="replace")) if control_path.exists() else {}
    scripts = []
    for name in ["preinst", "postinst", "prerm", "postrm", "config"]:
        script = control_dir / name
        if script.exists():
            scripts.append({"name": name, "path": str(script), "size": script.stat().st_size})
    return {
        "fields": fields,
        "package": fields.get("Package"),
        "version": fields.get("Version"),
        "architecture": fields.get("Architecture"),
        "depends": fields.get("Depends", ""),
        "pre_depends": fields.get("Pre-Depends", ""),
        "provides": fields.get("Provides", ""),
        "conflicts": fields.get("Conflicts", ""),
        "replaces": fields.get("Replaces", ""),
        "conffiles": parse_lines_file(control_dir / "conffiles"),
        "md5sums_count": len(parse_lines_file(control_dir / "md5sums")),
        "maintainer_scripts": scripts,
    }